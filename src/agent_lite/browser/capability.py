"""Browser runtime capability detection — fail closed, no fake sessions in real mode."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class BrowserCapability:
    status: str  # BROWSER_AVAILABLE | BROWSER_UNAVAILABLE | BROWSER_MISCONFIGURED | BROWSER_BLOCKED
    runtime: str = ""  # none | fake | playwright | mcp
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def detect_browser_capability(*, prefer_fake: bool = False) -> BrowserCapability:
    if prefer_fake or os.environ.get("BROWSER_FORCE_FAKE") == "1":
        return BrowserCapability(status="BROWSER_AVAILABLE", runtime="fake", detail="test_only")
    if os.environ.get("MCP_BROWSER_URL") or os.environ.get("BROWSER_MCP_ENABLED"):
        if os.environ.get("MCP_BROWSER_URL"):
            return BrowserCapability(
                status="BROWSER_AVAILABLE",
                runtime="mcp",
                detail="MCP_BROWSER_URL configured",
            )
        return BrowserCapability(
            status="BROWSER_MISCONFIGURED",
            runtime="mcp",
            detail="BROWSER_MCP_ENABLED set but MCP_BROWSER_URL missing",
        )
    try:
        import playwright  # type: ignore  # noqa: F401

        return BrowserCapability(status="BROWSER_AVAILABLE", runtime="playwright", detail="import_ok")
    except ImportError:
        pass
    return BrowserCapability(
        status="BROWSER_UNAVAILABLE",
        runtime="none",
        detail="no_playwright_no_mcp",
    )
