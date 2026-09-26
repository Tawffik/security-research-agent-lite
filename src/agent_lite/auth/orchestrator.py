"""Two-identity auth orchestration + resumable WAITING_FOR_AUTH checkpoint."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from agent_lite.auth.auth_provider import MockAuthProvider
from agent_lite.auth.identity_provider import MockIdentityProvider
from agent_lite.auth.mailbox import MockMailboxProvider
from agent_lite.auth.models import AuthState, AuthTraceEvent, SessionHandle, TestIdentity
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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuthOrchestrator:
    """
    auth_profile=two_test_users:
      provision A/B → mailbox → OTP → sessions → IdentityResolver
    Preserves checkpoint for resume without restarting research from zero.
    """

    def __init__(
        self,
        *,
        identity_provider: Optional[MockIdentityProvider] = None,
        mailbox: Optional[MockMailboxProvider] = None,
        auth: Optional[MockAuthProvider] = None,
        target: str = "https://lab.test",
    ):
        self.identities = identity_provider or MockIdentityProvider()
        self.mailbox = mailbox or MockMailboxProvider()
        self.auth = auth or MockAuthProvider(mailbox=self.mailbox, require_otp=True)
        self.target = target
        self.trace: list[AuthTraceEvent] = []
        self._checkpoint: dict[str, Any] = {}

    def _log(self, step: str, identity_id: str = "", status: str = "", detail: str = "") -> None:
        self.trace.append(
            AuthTraceEvent(step=step, identity_id=identity_id, status=status, detail=detail)
        )

    def run_two_users(
        self,
        *,
        identity_a: str = "user_a",
        identity_b: str = "user_b",
        inject_otps: bool = True,
    ) -> AuthOrchestratorResult:
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
                )

            box = self.mailbox.create_mailbox(iid)
            if box.get("status") == "MAILBOX_UNSUPPORTED":
                self._log("mailbox", iid, "MAILBOX_UNSUPPORTED")
                self._checkpoint = {
                    "pause": AuthState.WAITING_FOR_AUTH,
                    "identity_id": iid,
                    "reason": "MAILBOX_UNSUPPORTED",
                }
                return AuthOrchestratorResult(
                    status="WAITING_FOR_AUTH",
                    state=AuthState.WAITING_FOR_IDENTITY,
                    reason="MAILBOX_UNSUPPORTED",
                    identities=self.identities.list_public(),
                    trace=[e.to_dict() for e in self.trace],
                    checkpoint=dict(self._checkpoint),
                )

            if inject_otps:
                self.mailbox.inject_otp_email(iid, f"{100000 + hash(iid) % 900000}")

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
                    }
                    return AuthOrchestratorResult(
                        status="WAITING_FOR_AUTH",
                        state=otp_res.get("state") or AuthState.WAITING_FOR_OTP,
                        reason=str(otp_res.get("status")),
                        identities=self.identities.list_public(),
                        trace=[e.to_dict() for e in self.trace],
                        checkpoint=dict(self._checkpoint),
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
                )

        return AuthOrchestratorResult(
            status="ok",
            state=AuthState.AUTHENTICATED,
            sessions=[s.to_public_dict() for s in sessions],
            identities=self.identities.list_public(),
            trace=[e.to_dict() for e in self.trace],
        )

    def apply_sessions(self, resolver: IdentityResolver) -> None:
        self.auth.apply_to_resolver(resolver)

    def save_checkpoint(self, path: Path, research_state: Optional[dict] = None) -> None:
        payload = {
            "auth_checkpoint": self._checkpoint,
            "trace": [e.to_dict() for e in self.trace],
            "research_state": research_state or {},
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2))

    def load_checkpoint(self, path: Path) -> dict[str, Any]:
        if not path.is_file():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))
