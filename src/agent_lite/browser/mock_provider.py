"""
Deterministic mock BrowserSessionProvider for tests.

Simulates authorized lab bootstrap + two identity sessions without network.
Does not emit vulnerability verdicts.
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlparse

from agent_lite.browser.provider import BrowserActionResult, LabBootstrapContext
from agent_lite.http.engagement import EngagementConfig
from agent_lite.identity.resolver import IdentityResolver, SessionMaterial


class MockBrowserSessionProvider:
    """
    In-memory only. Navigation limited to engagement target origin.
    """

    def __init__(
        self,
        *,
        max_actions: int = 10,
        simulate_page_injection: str = "",
    ):
        self.max_actions = max_actions
        self._actions_used = 0
        self._sessions: dict[str, dict[str, str]] = {}
        self._context: Optional[LabBootstrapContext] = None
        self.simulate_page_injection = simulate_page_injection

    def _budget_ok(self) -> bool:
        return self._actions_used < self.max_actions

    def _origin(self, url: str) -> str:
        p = urlparse(url or "")
        if not p.scheme or not p.hostname:
            return ""
        return f"{p.scheme}://{p.hostname}".lower()

    def _host_in_scope(self, engagement: EngagementConfig, host: str) -> bool:
        host = (host or "").lower()
        for rule in engagement.scope_rules.get("in_scope") or []:
            pat = rule if isinstance(rule, str) else str(rule.get("host") or "")
            pat = pat.lower().strip()
            if pat.startswith("*."):
                if host.endswith(pat[1:]) or host == pat[2:]:
                    return True
            elif host == pat:
                return True
        return False

    def bootstrap_lab(self, engagement: EngagementConfig) -> LabBootstrapContext:
        self._actions_used += 1
        errs: list[str] = []
        if not self._budget_ok():
            errs.append("browser_budget_exceeded")
        # Reuse engagement authorization gate
        errs.extend(engagement.authorization_errors())
        origin = self._origin(engagement.base_url)
        host = urlparse(engagement.base_url).hostname or ""
        if engagement.base_url and not origin:
            errs.append("missing_target")
        if host and not self._host_in_scope(engagement, host):
            errs.append("out_of_scope_origin")

        if errs:
            ctx = LabBootstrapContext(
                provider="mock_browser",
                lab_id=engagement.engagement_id,
                lab_url=engagement.base_url,
                target_origin=origin,
                known_object_path=engagement.object_path,
                authorization_state="unauthorized",
                bootstrap_status="blocked",
                block_reasons=errs,
                notes="fail_closed_bootstrap",
            )
            self._context = ctx
            return ctx

        # Optional untrusted page noise — must not become instructions
        notes = "mock_bootstrap_ok"
        if self.simulate_page_injection:
            notes = f"untrusted_page_data:{self.simulate_page_injection[:80]}"

        ctx = LabBootstrapContext(
            provider="mock_browser",
            lab_id=engagement.engagement_id,
            lab_url=engagement.base_url,
            target_origin=origin,
            known_object_path=engagement.object_path,
            identity_context={
                engagement.owner_identity: "owner",
                engagement.non_owner_identity: "non_owner",
            },
            session_reference={
                engagement.owner_identity: f"ref:{engagement.owner_identity}",
                engagement.non_owner_identity: f"ref:{engagement.non_owner_identity}",
            },
            authorization_state="authorized",
            bootstrap_status="ok",
            evidence_refs=[f"bootstrap:{engagement.engagement_id}"],
            notes=notes,
        )
        self._context = ctx
        return ctx

    def establish_session(
        self,
        engagement: EngagementConfig,
        identity_id: str,
        context: LabBootstrapContext,
    ) -> BrowserActionResult:
        self._actions_used += 1
        if not self._budget_ok():
            return BrowserActionResult(
                status="blocked",
                action="establish_session",
                block_reasons=["browser_budget_exceeded"],
            )
        if context.bootstrap_status != "ok":
            return BrowserActionResult(
                status="blocked",
                action="establish_session",
                block_reasons=["bootstrap_not_ok"],
            )
        if identity_id not in engagement.identities:
            return BrowserActionResult(
                status="blocked",
                action="establish_session",
                block_reasons=["identity_ambiguous"],
            )
        if not identity_id:
            return BrowserActionResult(
                status="blocked",
                action="establish_session",
                block_reasons=["identity_ambiguous"],
            )
        # Mock cookie — runtime only; public context keeps opaque ref
        self._sessions[identity_id] = {"Cookie": f"sid={identity_id}; mock=1"}
        if context._session_headers is not None:
            context._session_headers[identity_id] = dict(self._sessions[identity_id])
        return BrowserActionResult(
            status="ok",
            action="establish_session",
            detail=f"session_ready:{identity_id}",
            page_excerpt_untrusted=self.simulate_page_injection or "",
        )

    def collect_lab_context(self, engagement: EngagementConfig) -> LabBootstrapContext:
        if self._context is None:
            return self.bootstrap_lab(engagement)
        return self._context

    def close_session(self) -> BrowserActionResult:
        self._sessions.clear()
        if self._context:
            self._context._session_headers.clear()
        return BrowserActionResult(status="ok", action="close_session", detail="cleared")

    def apply_sessions_to_resolver(
        self, resolver: IdentityResolver, context: LabBootstrapContext
    ) -> None:
        """Transfer in-memory session headers into IdentityResolver (not artifacts)."""
        for iid, headers in (context._session_headers or {}).items():
            resolver.inject_session(
                iid, SessionMaterial(identity_id=iid, headers=dict(headers))
            )

    def attempt_navigate(self, engagement: EngagementConfig, url: str) -> BrowserActionResult:
        """
        Bounded navigation check — not a public unrestricted navigate API.
        Used by tests to prove out-of-scope / redirect targets are blocked.
        """
        self._actions_used += 1
        if not self._budget_ok():
            return BrowserActionResult(
                status="blocked",
                action="navigate",
                block_reasons=["browser_budget_exceeded"],
            )
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return BrowserActionResult(
                status="blocked", action="navigate", block_reasons=["missing_target"]
            )
        if not self._host_in_scope(engagement, host):
            return BrowserActionResult(
                status="blocked",
                action="navigate",
                block_reasons=["out_of_scope_navigation"],
                detail=host,
            )
        allowed_origin = self._origin(engagement.base_url)
        nav_origin = self._origin(url)
        if allowed_origin and nav_origin and nav_origin != allowed_origin:
            return BrowserActionResult(
                status="blocked",
                action="navigate",
                block_reasons=["origin_mismatch"],
                detail=nav_origin,
            )
        return BrowserActionResult(status="ok", action="navigate", detail=url)
