"""Bounded browser bootstrap provider — not a research engine."""

from agent_lite.browser.provider import (
    BrowserSessionProvider,
    LabBootstrapContext,
    BrowserActionResult,
)
from agent_lite.browser.mock_provider import MockBrowserSessionProvider

__all__ = [
    "BrowserSessionProvider",
    "LabBootstrapContext",
    "BrowserActionResult",
    "MockBrowserSessionProvider",
]
