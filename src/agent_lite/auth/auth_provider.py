"""AuthProvider — password/browser OTP; returns SessionHandle, keeps secrets private."""

from __future__ import annotations

from typing import Any, Optional, Protocol

from agent_lite.auth.mailbox import MockMailboxProvider, OtpResult
from agent_lite.auth.models import (
    AuthChallenge,
    AuthState,
    SessionHandle,
    TestIdentity,
    new_challenge_id,
    new_session_id,
)
from agent_lite.identity.resolver import IdentityResolver, SessionMaterial


class AuthProvider(Protocol):
    def authenticate(self, identity: TestIdentity, target: str) -> dict[str, Any]:
        ...

    def establish_session(self, identity: TestIdentity, target: str) -> SessionHandle:
        ...

    def refresh_session(self, session: SessionHandle) -> SessionHandle:
        ...

    def logout(self, session: SessionHandle) -> SessionHandle:
        ...


class MockAuthProvider:
    """
    Deterministic auth for tests.
    Supports password-only and EMAIL_OTP via MockMailboxProvider.
    """

    def __init__(
        self,
        mailbox: Optional[MockMailboxProvider] = None,
        *,
        require_otp: bool = True,
        fail_login: bool = False,
        wrong_otp: bool = False,
    ):
        self.mailbox = mailbox or MockMailboxProvider()
        self.require_otp = require_otp
        self.fail_login = fail_login
        self.wrong_otp = wrong_otp
        self._states: dict[str, str] = {}
        self._sessions: dict[str, SessionHandle] = {}
        self._material: dict[str, SessionMaterial] = {}
        self._challenges: dict[str, AuthChallenge] = {}
        self._pending_otp: dict[str, str] = {}  # runtime only

    def state_of(self, identity_id: str) -> str:
        return self._states.get(identity_id, AuthState.NOT_AUTHENTICATED)

    def authenticate(self, identity: TestIdentity, target: str) -> dict[str, Any]:
        iid = identity.identity_id
        if self.fail_login:
            self._states[iid] = AuthState.AUTH_FAILED
            return {"status": "LOGIN_FAILED", "state": AuthState.AUTH_FAILED, "identity_id": iid}

        self._states[iid] = AuthState.AUTHENTICATING
        if not self.require_otp:
            handle = self._mint_session(identity, target, method="password")
            self._states[iid] = AuthState.AUTHENTICATED
            return {
                "status": "ok",
                "state": AuthState.AUTHENTICATED,
                "session": handle.to_public_dict(),
            }

        # OTP path
        self._states[iid] = AuthState.OTP_REQUIRED
        chal = AuthChallenge(
            challenge_id=new_challenge_id(),
            identity_id=iid,
            target=target,
            challenge_type="EMAIL_OTP",
            status="pending",
            provider="mock",
        )
        self._challenges[chal.challenge_id] = chal
        # Ensure mailbox exists; lab injects OTP separately or we inject default
        box = self.mailbox.get_mailbox(iid) or self.mailbox.create_mailbox(iid)
        if box.get("status") == "MAILBOX_UNSUPPORTED":
            self._states[iid] = AuthState.WAITING_FOR_IDENTITY
            return {
                "status": "MAILBOX_UNSUPPORTED",
                "state": AuthState.WAITING_FOR_IDENTITY,
                "challenge": chal.to_public_dict(),
            }
        self._states[iid] = AuthState.WAITING_FOR_OTP
        return {
            "status": "OTP_REQUIRED",
            "state": AuthState.WAITING_FOR_OTP,
            "challenge": chal.to_public_dict(),
        }

    def complete_otp(self, identity: TestIdentity, target: str, *, otp: str = "") -> dict[str, Any]:
        iid = identity.identity_id
        self._states[iid] = AuthState.VERIFYING_OTP
        if not otp:
            msg = self.mailbox.wait_for_message(iid, max_poll_attempts=3, timeout_seconds=0.05)
            if not msg:
                self._states[iid] = AuthState.WAITING_FOR_OTP
                return {"status": "OTP_NOT_FOUND", "state": AuthState.WAITING_FOR_OTP}
            extracted = self.mailbox.extract_otp(msg)
            if extracted.status != "ok":
                self._states[iid] = (
                    AuthState.WAITING_FOR_IDENTITY
                    if extracted.status == "OTP_EXPIRED"
                    else AuthState.WAITING_FOR_OTP
                )
                return {"status": extracted.status, "state": self._states[iid]}
            otp = extracted._otp
            # discard from public path
            extracted._otp = ""

        if self.wrong_otp:
            self._states[iid] = AuthState.AUTH_FAILED
            return {"status": "OTP_INVALID", "state": AuthState.AUTH_FAILED}

        handle = self._mint_session(identity, target, method="browser_otp")
        self._states[iid] = AuthState.AUTHENTICATED
        return {
            "status": "ok",
            "state": AuthState.AUTHENTICATED,
            "session": handle.to_public_dict(),
        }

    def establish_session(self, identity: TestIdentity, target: str) -> SessionHandle:
        result = self.authenticate(identity, target)
        if result.get("status") == "OTP_REQUIRED":
            result = self.complete_otp(identity, target)
        if result.get("status") != "ok":
            return SessionHandle(
                session_id="",
                identity_id=identity.identity_id,
                target=target,
                status="failed",
                provider="mock",
            )
        return self._sessions[identity.identity_id]

    def refresh_session(self, session: SessionHandle) -> SessionHandle:
        if session.status != "active":
            session.status = "expired"
            self._states[session.identity_id] = AuthState.SESSION_EXPIRED
            return session
        return session

    def logout(self, session: SessionHandle) -> SessionHandle:
        session.status = "revoked"
        self._states[session.identity_id] = AuthState.NOT_AUTHENTICATED
        self._sessions.pop(session.identity_id, None)
        self._material.pop(session.identity_id, None)
        return session

    def expire_session(self, identity_id: str) -> None:
        s = self._sessions.get(identity_id)
        if s:
            s.status = "expired"
        self._states[identity_id] = AuthState.SESSION_EXPIRED
        self._material.pop(identity_id, None)

    def apply_to_resolver(self, resolver: IdentityResolver) -> None:
        for iid, mat in self._material.items():
            resolver.inject_session(iid, mat)

    def _mint_session(self, identity: TestIdentity, target: str, method: str) -> SessionHandle:
        sid = new_session_id()
        handle = SessionHandle(
            session_id=sid,
            identity_id=identity.identity_id,
            target=target,
            status="active",
            provider="mock",
            auth_method=method,
        )
        self._sessions[identity.identity_id] = handle
        # runtime secret material — never in handle public form
        self._material[identity.identity_id] = SessionMaterial(
            identity_id=identity.identity_id,
            headers={"Cookie": f"sid={sid}; mock=1"},
        )
        identity.session_reference = sid
        identity.status = "authenticated"
        return handle
