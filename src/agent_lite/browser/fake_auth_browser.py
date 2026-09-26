"""
Fake browser for offline auth integration tests.

Simulates register → OTP verify → login for two identities.
Does NOT invent BOLA verdicts or bypass ScopeGuard.
Uses the same BrowserSessionProvider-compatible surface + auth helpers.
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlparse

from agent_lite.auth.mailbox import MockMailboxProvider
from agent_lite.auth.models import SessionHandle, new_session_id
from agent_lite.browser.provider import BrowserActionResult, LabBootstrapContext
from agent_lite.identity.resolver import IdentityResolver, SessionMaterial


class FakeAuthBrowserProvider:
    """
    Deterministic browser for:
      AuthOrchestrator → Fake Browser → Mailbox OTP → Session A/B → BOLA labs
    """

    def __init__(self, mailbox: Optional[MockMailboxProvider] = None, *, max_actions: int = 40):
        self.mailbox = mailbox or MockMailboxProvider()
        self.max_actions = max_actions
        self._actions = 0
        self._sessions: dict[str, SessionHandle] = {}
        self._material: dict[str, SessionMaterial] = {}
        self._registered: set[str] = set()
        self._context: Optional[LabBootstrapContext] = None

    def capability(self) -> str:
        return "BROWSER_AVAILABLE"

    def bootstrap_lab(self, engagement: Any) -> LabBootstrapContext:
        self._actions += 1
        base = getattr(engagement, "base_url", None) or "https://lab.test"
        host = urlparse(base).hostname or "lab.test"
        ctx = LabBootstrapContext(
            provider="fake_auth_browser",
            lab_id=getattr(engagement, "engagement_id", "lab"),
            lab_url=base,
            target_origin=f"https://{host}",
            known_object_path=getattr(engagement, "object_path", "/api/orders/1001"),
            authorization_state="authorized",
            bootstrap_status="ok",
            notes="fake_browser_bootstrap",
        )
        self._context = ctx
        return ctx

    def establish_session(
        self, engagement: Any, identity_id: str, context: LabBootstrapContext
    ) -> BrowserActionResult:
        self._actions += 1
        if self._actions > self.max_actions:
            return BrowserActionResult(
                status="blocked", action="establish_session", block_reasons=["browser_budget_exceeded"]
            )
        # Full register+verify+login path
        result = self.register_verify_login(identity_id, target=context.target_origin or "https://lab.test")
        if result.get("status") != "ok":
            return BrowserActionResult(
                status="blocked",
                action="establish_session",
                block_reasons=[str(result.get("status") or "auth_failed")],
                detail=str(result.get("reason") or ""),
            )
        return BrowserActionResult(status="ok", action="establish_session", detail=identity_id)

    def collect_lab_context(self, engagement: Any) -> LabBootstrapContext:
        return self._context or self.bootstrap_lab(engagement)

    def close_session(self) -> BrowserActionResult:
        self._sessions.clear()
        self._material.clear()
        return BrowserActionResult(status="ok", action="close_session")

    def register_verify_login(self, identity_id: str, *, target: str) -> dict[str, Any]:
        """Simulate registration + OTP from mailbox + login. Isolated per identity."""
        self._actions += 1
        box = self.mailbox.get_mailbox(identity_id) or self.mailbox.create_mailbox(identity_id)
        if box.get("status") in ("MAILBOX_UNSUPPORTED", "MAILBOX_UNAVAILABLE"):
            return {"status": "MAILBOX_UNAVAILABLE", "identity_id": identity_id}

        # Simulate app sending OTP email
        otp = f"{200000 + abs(hash(identity_id)) % 700000}"
        if hasattr(self.mailbox, "inject_otp_email"):
            self.mailbox.inject_otp_email(identity_id, otp, sender="noreply@lab.test")
        msg = self.mailbox.wait_for_message(identity_id, max_poll_attempts=3, timeout_seconds=0.05)
        if not msg:
            return {"status": "OTP_TIMEOUT", "identity_id": identity_id}
        extracted = self.mailbox.extract_otp(msg)
        if extracted.status != "ok":
            return {"status": extracted.status, "identity_id": identity_id}
        # discard otp from public path
        extracted._otp = ""

        self._registered.add(identity_id)
        sid = new_session_id()
        handle = SessionHandle(
            session_id=sid,
            identity_id=identity_id,
            target=target,
            status="active",
            provider="fake_auth_browser",
            auth_method="browser_otp",
        )
        self._sessions[identity_id] = handle
        # Isolated material — different sid per identity
        self._material[identity_id] = SessionMaterial(
            identity_id=identity_id,
            headers={"Cookie": f"sid={sid}; identity={identity_id}"},
        )
        return {"status": "ok", "session": handle.to_public_dict()}

    def session_handle(self, identity_id: str) -> Optional[SessionHandle]:
        return self._sessions.get(identity_id)

    def apply_to_resolver(self, resolver: IdentityResolver) -> None:
        for iid, mat in self._material.items():
            resolver.inject_session(iid, mat)

    def assert_isolation(self) -> bool:
        ids = list(self._sessions.keys())
        if len(ids) < 2:
            return True
        a, b = ids[0], ids[1]
        return self._sessions[a].session_id != self._sessions[b].session_id
