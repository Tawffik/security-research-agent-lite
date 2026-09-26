"""
Bounded HTTP Executor.

Pipeline for every target-affecting action:
  ActionRequest → Scope → Identity → Risk → Budget → Execute → HttpObservation

No credentials in observations. Fail-closed. Sequential only.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from urllib.parse import urlencode, urlparse, urlunparse

from agent_lite.budget.guard import BudgetGuard
from agent_lite.http.models import ActionRequest, HttpObservation
from agent_lite.http.redaction import (
    parse_host_path,
    redact_headers,
    safe_body_for_storage,
)
from agent_lite.identity.resolver import IdentityResolver
from agent_lite.scope.guard import ScopeDecision, ScopeGuard

# Optional transport: real requests or injectable for tests
try:
    import urllib.request
    import urllib.error
    import ssl

    _HAS_URLLIB = True
except ImportError:  # pragma: no cover
    _HAS_URLLIB = False


TransportFn = Callable[[ActionRequest, dict], tuple[int, dict, str, float]]


class HttpExecutor:
    """
    Minimal bounded executor.

    - ScopeGuard required
    - BudgetGuard required
    - IdentityResolver optional (identity_id may be empty for unauthenticated probes)
    - transport can be injected for synthetic/mock tests
    """

    def __init__(
        self,
        *,
        scope: ScopeGuard,
        budget: BudgetGuard,
        identities: Optional[IdentityResolver] = None,
        allowed_schemes: Optional[set[str]] = None,
        max_body_store: int = 4096,
        transport: Optional[TransportFn] = None,
        risk_policy: Optional[Callable[[ActionRequest], tuple[bool, str]]] = None,
    ):
        self.scope = scope
        self.budget = budget
        self.identities = identities or IdentityResolver()
        self.allowed_schemes = allowed_schemes or {"https", "http"}
        self.max_body_store = max_body_store
        self.transport = transport
        self.risk_policy = risk_policy or self._default_risk

    def _default_risk(self, req: ActionRequest) -> tuple[bool, str]:
        m = (req.method or "GET").upper()
        if m in ("GET", "HEAD", "OPTIONS"):
            return True, "low_risk_read"
        # Mutations require explicit allow_mutations in scope; still marked higher risk
        return True, "elevated_method"

    def _make_observation(
        self,
        req: ActionRequest,
        *,
        blocked: bool = False,
        block_reason: str = "",
        status: int = 0,
        headers: Optional[dict] = None,
        body: str = "",
        duration_ms: float = 0.0,
        scope_decision: str = "",
        error: str = "",
        request_headers_for_meta: Optional[dict] = None,
    ) -> HttpObservation:
        scheme, host, path = parse_host_path(req.url)
        meta_headers = request_headers_for_meta if request_headers_for_meta is not None else req.headers
        return HttpObservation(
            observation_id=f"obs_{uuid.uuid4().hex[:12]}",
            experiment_id=req.experiment_id or "",
            timestamp=datetime.now(timezone.utc).isoformat(),
            identity_id=req.identity_id or "",
            method=(req.method or "GET").upper(),
            host=host,
            path=path,
            request_metadata={
                "scheme": scheme,
                "purpose": req.purpose,
                "timeout_seconds": req.timeout_seconds,
                # always redacted; never raw secrets
                "request_headers_redacted": redact_headers(meta_headers or {}),
            },
            response_status=status,
            response_headers=redact_headers(headers or {}),
            response_body_metadata={
                "size_bytes": len(body or ""),
                "stored_bytes": min(len(body or ""), self.max_body_store),
            },
            response_body=safe_body_for_storage(body, max_store=self.max_body_store),
            request_count=0 if blocked else 1,
            duration_ms=duration_ms,
            scope_decision=scope_decision or block_reason,
            blocked=blocked,
            block_reason=block_reason,
            error=error,
        )

    def execute(self, req: ActionRequest) -> HttpObservation:
        """Run the full safety pipeline. Never raises for policy blocks."""
        method = (req.method or "GET").upper()
        scheme, host, path = parse_host_path(req.url)

        # 1) Scheme
        if scheme not in self.allowed_schemes:
            return self._make_observation(
                req, blocked=True, block_reason="scheme_not_allowed", scope_decision="BLOCK"
            )

        # 2) Host present
        if not host:
            return self._make_observation(
                req, blocked=True, block_reason="missing_host", scope_decision="BLOCK"
            )

        # 3) Scope
        sr = self.scope.check(host, method)
        if sr.decision != ScopeDecision.ALLOW:
            return self._make_observation(
                req,
                blocked=True,
                block_reason=sr.reason,
                scope_decision=sr.decision.value,
            )

        # 4) Identity (if required by request)
        session_headers: dict[str, str] = {}
        if req.identity_id:
            sess = self.identities.resolve_session(req.identity_id)
            if sess is None and req.identity_id not in ("", "anonymous", "public"):
                # Missing credentials for named identity → BLOCK (fail-closed)
                return self._make_observation(
                    req,
                    blocked=True,
                    block_reason="missing_authorization",
                    scope_decision="BLOCK",
                )
            if sess:
                session_headers.update(sess.headers)

        # 5) Risk
        ok_risk, risk_reason = self.risk_policy(req)
        if not ok_risk:
            return self._make_observation(
                req, blocked=True, block_reason=risk_reason, scope_decision="BLOCK"
            )

        # 6) Budget
        ok_b, b_reason = self.budget.check_request()
        if not ok_b:
            return self._make_observation(
                req, blocked=True, block_reason=b_reason, scope_decision="BLOCK"
            )

        # 7) Rate delay
        delay = self.budget.state.min_delay_seconds
        if delay > 0:
            time.sleep(delay)

        # 8) Merge headers (session first, request may override non-secret)
        final_headers = {**session_headers, **(req.headers or {})}
        # Build URL with query
        url = req.url
        if req.query:
            parsed = urlparse(url)
            q = urlencode(req.query)
            url = urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, q, parsed.fragment)
            )

        exec_req = ActionRequest(
            method=method,
            url=url,
            headers=final_headers,
            query={},
            body=req.body,
            identity_id=req.identity_id,
            timeout_seconds=req.timeout_seconds or self.budget.state.timeout_seconds,
            experiment_id=req.experiment_id,
            purpose=req.purpose,
        )

        # 9) Transport
        try:
            if self.transport is not None:
                status, resp_headers, body, duration_ms = self.transport(exec_req, final_headers)
            else:
                status, resp_headers, body, duration_ms = self._urllib_transport(exec_req, final_headers)
        except Exception as exc:  # network / timeout — record, do not crash pipeline
            self.budget.state.record_request(0)
            return self._make_observation(
                req,
                blocked=False,
                scope_decision="ALLOW",
                error=f"transport_error:{type(exc).__name__}",
                duration_ms=0.0,
            )

        self.budget.state.record_request(len(body or ""))
        return self._make_observation(
            req,
            blocked=False,
            status=status,
            headers=resp_headers,
            body=body,
            duration_ms=duration_ms,
            scope_decision="ALLOW",
            request_headers_for_meta=final_headers,
        )

    def _urllib_transport(
        self, req: ActionRequest, headers: dict
    ) -> tuple[int, dict, str, float]:
        """
        Real transport. Does NOT follow redirects automatically.

        A 3xx is returned as an observation (status + Location). The pipeline /
        scope layer must never chase a Location host outside allowed scope.
        """
        if not _HAS_URLLIB:
            raise RuntimeError("urllib unavailable")
        data = None
        if req.body is not None and req.method.upper() not in ("GET", "HEAD"):
            data = req.body.encode("utf-8")
        r = urllib.request.Request(
            req.url,
            data=data,
            headers={k: str(v) for k, v in headers.items()},
            method=req.method.upper(),
        )
        ctx = ssl.create_default_context()
        # Fail-closed: no automatic redirect following (scope-confusing hosts)
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPHandler(),
            _NoRedirectHandler(),
        )
        t0 = time.perf_counter()
        try:
            with opener.open(r, timeout=req.timeout_seconds) as resp:
                body_bytes = resp.read(self.budget.state.max_response_bytes + 1)
                if len(body_bytes) > self.budget.state.max_response_bytes:
                    body_bytes = body_bytes[: self.budget.state.max_response_bytes]
                body = body_bytes.decode("utf-8", errors="replace")
                status = getattr(resp, "status", 200) or 200
                resp_headers = {k: v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            body_bytes = e.read(self.budget.state.max_response_bytes) if e.fp else b""
            body = body_bytes.decode("utf-8", errors="replace")
            status = e.code
            resp_headers = {k: v for k, v in (e.headers.items() if e.headers else [])}
        duration_ms = (time.perf_counter() - t0) * 1000.0
        return status, resp_headers, body, duration_ms


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler if _HAS_URLLIB else object):  # type: ignore[misc]
    """Record redirects as final responses; never chase Location automatically."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None  # causes HTTPError with the 3xx response
