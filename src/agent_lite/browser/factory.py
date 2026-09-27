"""Select browser provider: fake | playwright | mcp — no silent real→fake in real mode."""

from __future__ import annotations

import os
from typing import Any, Optional

from agent_lite.browser.capability import detect_browser_capability


def resolve_browser_runtime() -> str:
    """
    Explicit BROWSER_RUNTIME wins: fake | playwright | mcp
    Else capability detection.
    """
    forced = (os.environ.get("BROWSER_RUNTIME") or "").strip().lower()
    if forced in ("fake", "playwright", "mcp", "none"):
        return forced
    cap = detect_browser_capability()
    if cap.runtime in ("playwright", "mcp", "fake"):
        return cap.runtime
    return "none"


def build_browser_provider(
    *,
    allowed_origins: Optional[set[str]] = None,
    force_runtime: str = "",
) -> tuple[Optional[Any], dict[str, Any]]:
    runtime = (force_runtime or resolve_browser_runtime()).lower()
    meta: dict[str, Any] = {"browser_runtime": runtime}

    if runtime in ("", "none"):
        return None, {**meta, "status": "BROWSER_UNAVAILABLE", "reason": "no_runtime"}

    if runtime == "fake":
        from agent_lite.browser.fake_auth_browser import FakeAuthBrowserProvider

        return FakeAuthBrowserProvider(), {**meta, "status": "ok", "provider": "fake"}

    if runtime == "playwright":
        try:
            from agent_lite.browser.playwright_provider import PlaywrightBrowserProvider
        except Exception as e:  # noqa: BLE001
            return None, {
                **meta,
                "status": "BROWSER_UNAVAILABLE",
                "reason": f"import_failed:{type(e).__name__}",
            }
        from agent_lite.browser.capability import detect_browser_capability

        cap = detect_browser_capability()
        if cap.runtime != "playwright":
            return None, {
                **meta,
                "status": "BROWSER_UNAVAILABLE",
                "reason": "playwright_not_installed",
            }
        return (
            PlaywrightBrowserProvider(allowed_origins=allowed_origins),
            {**meta, "status": "ok", "provider": "playwright"},
        )

    if runtime == "mcp":
        from agent_lite.browser.mcp_provider import McpBrowserProvider

        p = McpBrowserProvider(allowed_origins=allowed_origins or set())
        if not p.available():
            return None, {
                **meta,
                "status": "BROWSER_UNAVAILABLE",
                "reason": "missing_MCP_BROWSER_URL",
            }
        return p, {**meta, "status": "ok", "provider": "mcp"}

    return None, {**meta, "status": "BROWSER_UNAVAILABLE", "reason": "unknown_runtime"}
