"""
Browser password login → SessionMaterial (runtime only).

Uses Playwright when available. Email/password from env refs — never logged.
Optional: MailSlurp creates inbox when EMAIL env missing and MAILSLURP_API_KEY set.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from agent_lite.identity.resolver import IdentityResolver, SessionMaterial


@dataclass
class LoginResult:
    status: str  # ok | blocked | error
    identity_id: str = ""
    reason: str = ""
    session_id: str = ""
    # public only
    def to_public_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "identity_id": self.identity_id,
            "reason": self.reason,
            "session_id": self.session_id,
        }


def _env_cred(ref: str) -> tuple[str, str]:
    ref = ref.upper()
    email = (
        os.environ.get(f"{ref}_EMAIL")
        or os.environ.get(f"{ref}_USERNAME")
        or os.environ.get(f"{ref}_USER")
        or ""
    ).strip()
    password = (os.environ.get(f"{ref}_PASSWORD") or os.environ.get(f"{ref}_PASS") or "").strip()
    return email, password


def _maybe_mailslurp_email(identity_id: str) -> tuple[str, str]:
    """Create MailSlurp inbox if API key present. Returns (email, reason)."""
    key = (os.environ.get("MAILSLURP_API_KEY") or "").strip()
    if not key:
        return "", "no_mailslurp"
    try:
        from agent_lite.auth.mailslurp import MailSlurpMailboxProvider

        mb = MailSlurpMailboxProvider(api_key=key)
        meta = mb.create_mailbox(identity_id)
        if meta.get("status") != "ready":
            return "", str(meta.get("reason") or meta.get("status"))
        return str(meta.get("email_address") or ""), "mailslurp_ok"
    except Exception as e:  # noqa: BLE001
        return "", type(e).__name__


def login_with_playwright(
    *,
    identity_id: str,
    credential_ref: str,
    login_url: str,
    allowed_hosts: Optional[set[str]] = None,
) -> tuple[LoginResult, Optional[SessionMaterial]]:
    email, password = _env_cred(credential_ref)
    if not email:
        email, why = _maybe_mailslurp_email(identity_id)
        if not email:
            return LoginResult(status="blocked", identity_id=identity_id, reason=f"missing_email:{why}"), None
    if not password:
        return LoginResult(status="blocked", identity_id=identity_id, reason="missing_password"), None

    host = urlparse(login_url).hostname or ""
    if allowed_hosts and host not in allowed_hosts and not any(
        host.endswith(h.lstrip("*.")) for h in allowed_hosts if h.startswith("*.") or True
    ):
        # simple allow: exact or suffix match for domain
        ok = False
        for h in allowed_hosts:
            h = h.lower().removeprefix("*.")
            if host == h or host.endswith("." + h):
                ok = True
                break
        if not ok and allowed_hosts:
            return (
                LoginResult(status="blocked", identity_id=identity_id, reason="BROWSER_SCOPE_BLOCKED"),
                None,
            )

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return LoginResult(status="blocked", identity_id=identity_id, reason="playwright_not_installed"), None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.goto(login_url, wait_until="domcontentloaded", timeout=30000)

            # Heuristic selectors — common login forms
            email_sel = (
                'input[type="email"], input[name="email"], input[name="username"], '
                'input[id="email"], input[id="username"], input[name="user"]'
            )
            pass_sel = 'input[type="password"], input[name="password"], input[id="password"]'
            submit_sel = (
                'button[type="submit"], input[type="submit"], button:has-text("Log"), '
                'button:has-text("Sign"), button:has-text("Login")'
            )

            if page.locator(email_sel).count() == 0:
                browser.close()
                return (
                    LoginResult(status="blocked", identity_id=identity_id, reason="login_form_not_found"),
                    None,
                )
            page.locator(email_sel).first.fill(email)
            if page.locator(pass_sel).count() > 0:
                page.locator(pass_sel).first.fill(password)
            if page.locator(submit_sel).count() > 0:
                page.locator(submit_sel).first.click()
            else:
                page.keyboard.press("Enter")
            page.wait_for_load_state("domcontentloaded", timeout=20000)

            cookies = context.cookies()
            cookie_hdr = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            browser.close()

            if not cookie_hdr:
                return (
                    LoginResult(status="blocked", identity_id=identity_id, reason="no_cookies_after_login"),
                    None,
                )
            mat = SessionMaterial(
                identity_id=identity_id,
                headers={"Cookie": cookie_hdr},
            )
            # Do not return email/password
            return (
                LoginResult(status="ok", identity_id=identity_id, session_id=f"pw_{identity_id}"),
                mat,
            )
    except Exception as e:  # noqa: BLE001
        return (
            LoginResult(status="error", identity_id=identity_id, reason=f"login_failed:{type(e).__name__}"),
            None,
        )


def establish_password_sessions(
    resolver: IdentityResolver,
    *,
    pairs: list[tuple[str, str]],
    login_url: str,
    allowed_hosts: Optional[set[str]] = None,
) -> dict[str, Any]:
    """
    pairs: [(identity_id, credential_ref), ...]
    Injects SessionMaterial into resolver on success.
    """
    trace = []
    for iid, ref in pairs:
        res, mat = login_with_playwright(
            identity_id=iid,
            credential_ref=ref,
            login_url=login_url,
            allowed_hosts=allowed_hosts,
        )
        trace.append(res.to_public_dict())
        if res.status != "ok" or mat is None:
            return {"status": "blocked", "reason": res.reason, "trace": trace}
        resolver.register(
            __import__("agent_lite.identity.resolver", fromlist=["Identity"]).Identity(
                identity_id=iid, credential_ref=ref
            )
        )
        resolver.inject_session(iid, mat)
    return {"status": "ok", "trace": trace}
