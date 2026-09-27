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
from agent_lite.browser.factory import build_browser_provider


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
    force_allow_registration: bool = False,
) -> tuple[Optional[AuthOrchestrator], dict[str, Any]]:
    """
    Returns (orchestrator|None, status_meta).

    Real profiles:
      - missing credentials → WAITING_FOR_AUTH (not mock)
      - credentials present but no browser → orchestrator built with
        provider_kind=real and allow_registration=False so run_two_users
        returns WAITING_FOR_AUTH / BROWSER_UNAVAILABLE (wiring proven, no fake sessions)
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
        browser, bmeta = build_browser_provider(force_runtime=os.environ.get("BROWSER_RUNTIME", "fake") if os.environ.get("BROWSER_RUNTIME") else "fake")
        orch = AuthOrchestrator(
            identity_provider=MockIdentityProvider(),
            mailbox=mb,
            auth=auth,
            target=target,
            provider_kind="mock",
            allow_registration=True,
            browser=browser,
        )
        return orch, {**meta, "status": "ok", "reason": "mock_ready", "browser": bmeta}

    if kind == "mailslurp":
        mb = MailSlurpMailboxProvider()
        if not mb.available():
            return None, {
                **meta,
                "status": "WAITING_FOR_AUTH",
                "reason": "missing_mailslurp_api_key",
            }
        browser_ok = bool(os.environ.get("BROWSER_MCP_ENABLED") or os.environ.get("MCP_BROWSER_URL") or os.environ.get("BROWSER_RUNTIME") in ("playwright", "mcp", "fake")) or force_allow_registration
        auth = MockAuthProvider(mailbox=mb, require_otp=True)
        orch = AuthOrchestrator(
            identity_provider=MockIdentityProvider(),
            mailbox=mb,  # REAL MailSlurp instance wired here
            auth=auth,
            target=target,
            provider_kind="mailslurp",
            allow_registration=browser_ok,
        )
        return orch, {
            **meta,
            "status": "ok" if browser_ok else "mailbox_ready_browser_blocked",
            "reason": "mailslurp_wired",
            "browser_enabled": browser_ok,
            "mailbox_class": type(mb).__name__,
        }

    if kind == "temp":
        mb = TempMailboxProvider()
        if not mb.available():
            return None, {
                **meta,
                "status": "WAITING_FOR_AUTH",
                "reason": "missing_temp_mail_base_url",
            }
        browser_ok = bool(os.environ.get("BROWSER_MCP_ENABLED") or os.environ.get("MCP_BROWSER_URL") or os.environ.get("BROWSER_RUNTIME") in ("playwright", "mcp", "fake")) or force_allow_registration
        auth = MockAuthProvider(mailbox=mb, require_otp=True)
        orch = AuthOrchestrator(
            identity_provider=MockIdentityProvider(),
            mailbox=mb,  # REAL Temp provider wired here
            auth=auth,
            target=target,
            provider_kind="temp",
            allow_registration=browser_ok,
        )
        return orch, {
            **meta,
            "status": "ok" if browser_ok else "mailbox_ready_browser_blocked",
            "reason": "temp_wired",
            "browser_enabled": browser_ok,
            "mailbox_class": type(mb).__name__,
        }

    return None, {**meta, "status": "WAITING_FOR_AUTH", "reason": "unsupported_provider"}
