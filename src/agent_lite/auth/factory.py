"""Select mailbox/auth providers from auth_profile — no silent mock fallback for real profiles."""

from __future__ import annotations

import os
from typing import Any, Optional

from agent_lite.auth.auth_provider import MockAuthProvider
from agent_lite.auth.identity_provider import MockIdentityProvider
from agent_lite.auth.mailbox import MockMailboxProvider
from agent_lite.auth.mailslurp import MailSlurpMailboxProvider
from agent_lite.auth.orchestrator import AuthOrchestrator
from agent_lite.auth.temp_mailbox import TempMailboxProvider


PROFILES = {
    "two_test_users": "mock",
    "two_test_users_mock": "mock",
    "two_test_users_mailslurp": "mailslurp",
    "two_test_users_temp": "temp",
    "manual": "manual",
    "mock": "mock",
    "mailslurp": "mailslurp",
    "temp": "temp",
}


def resolve_provider_kind(auth_profile: str) -> str:
    return PROFILES.get((auth_profile or "").strip(), "unknown")


def build_orchestrator(
    auth_profile: str,
    *,
    target: str = "lab://synthetic",
    allow_mock_for_unknown: bool = False,
) -> tuple[Optional[AuthOrchestrator], dict[str, Any]]:
    """
    Returns (orchestrator|None, status_meta).
    Real profiles without credentials → WAITING_FOR_AUTH, not mock success.
    """
    kind = resolve_provider_kind(auth_profile)
    meta: dict[str, Any] = {"auth_profile": auth_profile, "provider_kind": kind}

    if kind == "unknown":
        if allow_mock_for_unknown and not auth_profile:
            kind = "mock"
        else:
            return None, {
                **meta,
                "status": "WAITING_FOR_AUTH",
                "reason": "unknown_auth_profile",
            }

    if kind == "manual":
        return None, {
            **meta,
            "status": "WAITING_FOR_AUTH",
            "reason": "manual_authentication_required",
        }

    if kind == "mock":
        mb = MockMailboxProvider()
        auth = MockAuthProvider(mailbox=mb, require_otp=True)
        orch = AuthOrchestrator(
            identity_provider=MockIdentityProvider(),
            mailbox=mb,
            auth=auth,
            target=target,
        )
        return orch, {**meta, "status": "ok", "reason": "mock_ready"}

    if kind == "mailslurp":
        mb = MailSlurpMailboxProvider()
        if not mb.available():
            return None, {
                **meta,
                "status": "WAITING_FOR_AUTH",
                "reason": "missing_mailslurp_api_key",
            }
        # Real registration/browser not available in default GHA → still can create mailboxes;
        # AuthProvider remains mock login against lab unless browser wired.
        # Fail closed for full auto-register: browser unavailable.
        if not os.environ.get("BROWSER_MCP_ENABLED"):
            return None, {
                **meta,
                "status": "WAITING_FOR_AUTH",
                "reason": "BROWSER_UNAVAILABLE",
                "mailbox_provider": "mailslurp",
                "detail": "MailSlurp key present but real browser registration not enabled",
            }
        auth = MockAuthProvider(mailbox=mb, require_otp=True)
        orch = AuthOrchestrator(
            identity_provider=MockIdentityProvider(),
            mailbox=mb,
            auth=auth,
            target=target,
        )
        return orch, {**meta, "status": "ok", "reason": "mailslurp_browser_enabled"}

    if kind == "temp":
        mb = TempMailboxProvider()
        if not mb.available():
            return None, {
                **meta,
                "status": "WAITING_FOR_AUTH",
                "reason": "missing_temp_mail_base_url",
            }
        if not os.environ.get("BROWSER_MCP_ENABLED"):
            return None, {
                **meta,
                "status": "WAITING_FOR_AUTH",
                "reason": "BROWSER_UNAVAILABLE",
                "mailbox_provider": "temp",
            }
        auth = MockAuthProvider(mailbox=mb, require_otp=True)
        orch = AuthOrchestrator(
            identity_provider=MockIdentityProvider(),
            mailbox=mb,
            auth=auth,
            target=target,
        )
        return orch, {**meta, "status": "ok", "reason": "temp_browser_enabled"}

    return None, {**meta, "status": "WAITING_FOR_AUTH", "reason": "unsupported_provider"}
