"""Two-identity auth orchestration + resumable WAITING_FOR_AUTH checkpoint.

Works with any MailboxProvider implementation (Mock, MailSlurp, Temp).
Only Mock injects synthetic OTP emails.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from agent_lite.auth.auth_provider import MockAuthProvider
from agent_lite.auth.identity_provider import MockIdentityProvider
from agent_lite.auth.mailbox import MockMailboxProvider
from agent_lite.auth.models import AuthState, AuthTraceEvent, SessionHandle
from agent_lite.identity.resolver import IdentityResolver


@dataclass
class AuthOrchestratorResult:
    status: str  # ok | WAITING_FOR_AUTH | blocked | error
    state: str = AuthState.NOT_AUTHENTICATED
    sessions: list[dict[str, Any]] = field(default_factory=list)
    identities: list[dict[str, Any]] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    checkpoint: dict[str, Any] = field(default_factory=dict)
    provider_kind: str = "mock"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuthOrchestrator:
    """
    provision A/B → mailbox → (mock inject OTP | wait real mail) → auth → sessions

    provider_kind:
      mock  → may inject_otp_email
      real  → never inject; waits on mailbox; registration requires browser capability
    """

    def __init__(
        self,
        *,
        identity_provider: Any = None,
        mailbox: Any = None,
        auth: Any = None,
        target: str = "https://lab.test",
        provider_kind: str = "mock",
        allow_registration: bool = False,
        browser: Any = None,
    ):
        self.identities = identity_provider or MockIdentityProvider()
        self.mailbox = mailbox or MockMailboxProvider()
        # Auth must share the same mailbox instance for OTP wait path
        if auth is not None:
            self.auth = auth
        else:
            self.auth = MockAuthProvider(mailbox=self.mailbox, require_otp=True)
        self.target = target
        self.provider_kind = provider_kind
        self.allow_registration = allow_registration
        self.browser = browser
        self.trace: list[AuthTraceEvent] = []
        self._checkpoint: dict[str, Any] = {}

    def _log(self, step: str, identity_id: str = "", status: str = "", detail: str = "") -> None:
        self.trace.append(
            AuthTraceEvent(step=step, identity_id=identity_id, status=status, detail=detail)
        )

    def _is_mock_mailbox(self) -> bool:
        # provider_kind wins: real profiles never inject synthetic OTP
        if self.provider_kind in ("mailslurp", "temp", "real"):
            return False
        return self.provider_kind == "mock" or isinstance(self.mailbox, MockMailboxProvider)

    def run_two_users(
        self,
        *,
        identity_a: str = "user_a",
        identity_b: str = "user_b",
        inject_otps: Optional[bool] = None,
    ) -> AuthOrchestratorResult:
        # Default: inject only for mock mailbox
        if inject_otps is None:
            inject_otps = self._is_mock_mailbox()

        # Real providers cannot complete registration without browser
        if self.provider_kind in ("mailslurp", "temp", "real") and not self.allow_registration:
            self._checkpoint = {
                "pause": AuthState.WAITING_FOR_AUTH,
                "reason": "BROWSER_UNAVAILABLE",
                "provider_kind": self.provider_kind,
            }
            self._log("registration", "", "BROWSER_UNAVAILABLE", "registration requires browser runtime")
            return AuthOrchestratorResult(
                status="WAITING_FOR_AUTH",
                state=AuthState.WAITING_FOR_AUTH,
                reason="BROWSER_UNAVAILABLE",
                identities=self.identities.list_public() if hasattr(self.identities, "list_public") else [],
                trace=[e.to_dict() for e in self.trace],
                checkpoint=dict(self._checkpoint),
                provider_kind=self.provider_kind,
            )

        sessions: list[SessionHandle] = []
        for iid in (identity_a, identity_b):
            ident = self.identities.provision_identity(iid)
            ok, reason = self.identities.validate_identity(iid)
            if not ok:
                self._log("validate", iid, "blocked", reason)
                return AuthOrchestratorResult(
                    status="blocked",
                    state=AuthState.WAITING_FOR_IDENTITY,
                    reason=reason,
                    identities=self.identities.list_public(),
                    trace=[e.to_dict() for e in self.trace],
                    provider_kind=self.provider_kind,
                )

            box = self.mailbox.create_mailbox(iid)
            self._log("mailbox", iid, str(box.get("status") or ""), str(box.get("provider") or ""))
            status = str(box.get("status") or "")
            if status in ("MAILBOX_UNSUPPORTED", "MAILBOX_UNAVAILABLE"):
                self._checkpoint = {
                    "pause": AuthState.WAITING_FOR_AUTH,
                    "identity_id": iid,
                    "reason": status,
                    "provider_kind": self.provider_kind,
                }
                return AuthOrchestratorResult(
                    status="WAITING_FOR_AUTH",
                    state=AuthState.WAITING_FOR_IDENTITY,
                    reason=status,
                    identities=self.identities.list_public(),
                    trace=[e.to_dict() for e in self.trace],
                    checkpoint=dict(self._checkpoint),
                    provider_kind=self.provider_kind,
                )

            # Optional Fake/Real browser path: register → OTP → login → SessionHandle
            if self.browser is not None and hasattr(self.browser, "register_verify_login"):
                self._log("browser", iid, "register_verify_login", "")
                bres = self.browser.register_verify_login(iid, target=self.target)
                self._log("browser", iid, str(bres.get("status") or ""), "")
                if bres.get("status") != "ok":
                    self._checkpoint = {
                        "pause": AuthState.WAITING_FOR_AUTH,
                        "identity_id": iid,
                        "reason": bres.get("status"),
                        "provider_kind": self.provider_kind,
                    }
                    return AuthOrchestratorResult(
                        status="WAITING_FOR_AUTH",
                        state=AuthState.WAITING_FOR_AUTH,
                        reason=str(bres.get("status")),
                        identities=self.identities.list_public(),
                        trace=[e.to_dict() for e in self.trace],
                        checkpoint=dict(self._checkpoint),
                        provider_kind=self.provider_kind,
                    )
                handle = self.browser.session_handle(iid)
                if handle:
                    sessions.append(handle)
                    # mirror into auth provider session map for apply_sessions compatibility
                    if hasattr(self.auth, "_sessions"):
                        self.auth._sessions[iid] = handle
                    if hasattr(self.auth, "_material") and hasattr(self.browser, "_material"):
                        mat = self.browser._material.get(iid)
                        if mat is not None:
                            self.auth._material[iid] = mat
                continue

            # Mock-only synthetic OTP injection — never on real providers
            if inject_otps and self._is_mock_mailbox() and hasattr(self.mailbox, "inject_otp_email"):
                self.mailbox.inject_otp_email(iid, f"{100000 + abs(hash(iid)) % 900000}")
                self._log("otp_inject", iid, "mock_only", "synthetic")
            elif inject_otps and not self._is_mock_mailbox():
                self._log("otp_inject", iid, "skipped", "real_provider_no_inject")

            auth_res = self.auth.authenticate(ident, self.target)
            self._log("authenticate", iid, auth_res.get("status", ""), auth_res.get("state", ""))
            if auth_res.get("status") == "OTP_REQUIRED":
                otp_res = self.auth.complete_otp(ident, self.target)
                self._log("otp", iid, otp_res.get("status", ""), otp_res.get("state", ""))
                if otp_res.get("status") != "ok":
                    self._checkpoint = {
                        "pause": AuthState.WAITING_FOR_AUTH,
                        "identity_id": iid,
                        "reason": otp_res.get("status"),
                        "provider_kind": self.provider_kind,
                    }
                    return AuthOrchestratorResult(
                        status="WAITING_FOR_AUTH",
                        state=otp_res.get("state") or AuthState.WAITING_FOR_OTP,
                        reason=str(otp_res.get("status")),
                        identities=self.identities.list_public(),
                        trace=[e.to_dict() for e in self.trace],
                        checkpoint=dict(self._checkpoint),
                        provider_kind=self.provider_kind,
                    )
                sessions.append(self.auth._sessions[iid])
            elif auth_res.get("status") == "ok":
                sessions.append(self.auth._sessions[iid])
            else:
                return AuthOrchestratorResult(
                    status="blocked",
                    state=auth_res.get("state") or AuthState.AUTH_FAILED,
                    reason=str(auth_res.get("status")),
                    identities=self.identities.list_public(),
                    trace=[e.to_dict() for e in self.trace],
                    provider_kind=self.provider_kind,
                )

        return AuthOrchestratorResult(
            status="ok",
            state=AuthState.AUTHENTICATED,
            sessions=[s.to_public_dict() for s in sessions],
            identities=self.identities.list_public(),
            trace=[e.to_dict() for e in self.trace],
            provider_kind=self.provider_kind,
        )

    def apply_sessions(self, resolver: IdentityResolver) -> None:
        self.auth.apply_to_resolver(resolver)

    def save_checkpoint(self, path: Path, research_state: Optional[dict] = None) -> None:
        payload = {
            "auth_checkpoint": self._checkpoint,
            "trace": [e.to_dict() for e in self.trace],
            "research_state": research_state or {},
            "provider_kind": self.provider_kind,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2))

    def load_checkpoint(self, path: Path) -> dict[str, Any]:
        if not path.is_file():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))
