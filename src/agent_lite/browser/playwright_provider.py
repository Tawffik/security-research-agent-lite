"""PlaywrightBrowserProvider — optional real browser; lazy import; no secrets in artifacts."""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlparse

from agent_lite.auth.models import SessionHandle, new_session_id
from agent_lite.browser.capability import detect_browser_capability
from agent_lite.browser.provider import BrowserActionResult, LabBootstrapContext
from agent_lite.identity.resolver import IdentityResolver, SessionMaterial


class PlaywrightBrowserProvider:
    """
    Isolated Chromium contexts per identity.
    Must not be imported at package top-level in a way that requires playwright.
    """

    def __init__(self, *, headless: bool = True, allowed_origins: Optional[set[str]] = None):
        self.headless = headless
        self.allowed_origins = allowed_origins or {"http://127.0.0.1", "http://localhost"}
        self._playwright = None
        self._browser = None
        self._contexts: dict[str, Any] = {}
        self._pages: dict[str, Any] = {}
        self._sessions: dict[str, SessionHandle] = {}
        self._material: dict[str, SessionMaterial] = {}
        self._context_meta: Optional[LabBootstrapContext] = None

    def available(self) -> bool:
        return detect_browser_capability().runtime == "playwright"

    def _ensure_browser(self) -> str:
        if self._browser is not None:
            return "ok"
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return "BROWSER_UNAVAILABLE"
        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=self.headless)
            return "ok"
        except Exception as e:  # noqa: BLE001
            self.close_session()
            return f"BROWSER_LAUNCH_FAILED:{type(e).__name__}"

    def _origin_allowed(self, url: str) -> bool:
        p = urlparse(url)
        origin = f"{p.scheme}://{p.hostname}"
        if p.port and p.port not in (80, 443):
            origin = f"{origin}:{p.port}"
        # also allow host without port match against allowed set prefixes
        for allowed in self.allowed_origins:
            if origin == allowed or origin.startswith(allowed + ":"):
                return True
            # http://127.0.0.1:PORT
            if allowed in ("http://127.0.0.1", "http://localhost") and p.hostname in (
                "127.0.0.1",
                "localhost",
            ):
                return True
        return False

    def bootstrap_lab(self, engagement: Any) -> LabBootstrapContext:
        base = getattr(engagement, "base_url", None) or "http://127.0.0.1:8765"
        status = self._ensure_browser()
        if status != "ok":
            return LabBootstrapContext(
                provider="playwright",
                lab_url=base,
                target_origin=base,
                bootstrap_status="blocked",
                block_reasons=[status],
                authorization_state="blocked",
            )
        if not self._origin_allowed(base):
            return LabBootstrapContext(
                provider="playwright",
                lab_url=base,
                target_origin=base,
                bootstrap_status="blocked",
                block_reasons=["BROWSER_SCOPE_BLOCKED"],
                authorization_state="blocked",
            )
        ctx = LabBootstrapContext(
            provider="playwright",
            lab_id=getattr(engagement, "engagement_id", "browser_lab"),
            lab_url=base,
            target_origin=base,
            known_object_path=getattr(engagement, "object_path", "/"),
            authorization_state="authorized",
            bootstrap_status="ok",
            notes="playwright_bootstrap",
        )
        self._context_meta = ctx
        return ctx

    def establish_session(
        self, engagement: Any, identity_id: str, context: LabBootstrapContext
    ) -> BrowserActionResult:
        if context.bootstrap_status != "ok":
            return BrowserActionResult(
                status="blocked",
                action="establish_session",
                block_reasons=list(context.block_reasons) or ["bootstrap_not_ok"],
            )
        status = self._ensure_browser()
        if status != "ok":
            return BrowserActionResult(
                status="blocked", action="establish_session", block_reasons=[status]
            )
        base = context.lab_url or context.target_origin
        if not self._origin_allowed(base):
            return BrowserActionResult(
                status="blocked",
                action="establish_session",
                block_reasons=["BROWSER_SCOPE_BLOCKED"],
            )
        try:
            assert self._browser is not None
            # Isolated context per identity
            ctx = self._browser.new_context()
            page = ctx.new_page()
            self._contexts[identity_id] = ctx
            self._pages[identity_id] = page
            # Deterministic synthetic login page
            login_url = base.rstrip("/") + f"/login?user={identity_id}"
            page.goto(login_url, wait_until="domcontentloaded", timeout=15000)
            # Click login if button exists
            if page.locator("button#login").count() > 0:
                page.click("button#login")
                page.wait_for_load_state("domcontentloaded", timeout=10000)
            sid = new_session_id()
            handle = SessionHandle(
                session_id=sid,
                identity_id=identity_id,
                target=base,
                status="active",
                provider="playwright",
                auth_method="browser_form",
            )
            self._sessions[identity_id] = handle
            # Runtime-only cookie jar — not written to artifacts by provider
            cookies = ctx.cookies()
            cookie_hdr = "; ".join(f"{c['name']}={c['value']}" for c in cookies) if cookies else f"sid={sid}"
            self._material[identity_id] = SessionMaterial(
                identity_id=identity_id,
                headers={"Cookie": cookie_hdr},
            )
            return BrowserActionResult(status="ok", action="establish_session", detail=identity_id)
        except Exception as e:  # noqa: BLE001
            return BrowserActionResult(
                status="blocked",
                action="establish_session",
                block_reasons=[f"BROWSER_SESSION_FAILED:{type(e).__name__}"],
                detail=str(type(e).__name__),
            )

    def collect_lab_context(self, engagement: Any) -> LabBootstrapContext:
        return self._context_meta or self.bootstrap_lab(engagement)

    def close_session(self) -> BrowserActionResult:
        for page in list(self._pages.values()):
            try:
                page.close()
            except Exception:  # noqa: BLE001
                pass
        for ctx in list(self._contexts.values()):
            try:
                ctx.close()
            except Exception:  # noqa: BLE001
                pass
        self._pages.clear()
        self._contexts.clear()
        if self._browser is not None:
            try:
                self._browser.close()
            except Exception:  # noqa: BLE001
                pass
            self._browser = None
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:  # noqa: BLE001
                pass
            self._playwright = None
        self._sessions.clear()
        self._material.clear()
        return BrowserActionResult(status="ok", action="close_session")

    def session_handle(self, identity_id: str) -> Optional[SessionHandle]:
        return self._sessions.get(identity_id)

    def apply_to_resolver(self, resolver: IdentityResolver) -> None:
        for iid, mat in self._material.items():
            resolver.inject_session(iid, mat)

    def assert_isolation(self) -> bool:
        if len(self._contexts) < 2:
            return True
        # Distinct context objects
        vals = list(self._contexts.values())
        return vals[0] is not vals[1]
