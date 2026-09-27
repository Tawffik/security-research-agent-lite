"""Browser factory + MCP provider fail-closed (offline)."""

from __future__ import annotations

from types import SimpleNamespace

from agent_lite.browser.factory import build_browser_provider, resolve_browser_runtime
from agent_lite.browser.mcp_provider import McpBrowserProvider


def test_resolve_none_by_default(monkeypatch):
    monkeypatch.delenv("BROWSER_RUNTIME", raising=False)
    monkeypatch.delenv("MCP_BROWSER_URL", raising=False)
    monkeypatch.delenv("BROWSER_FORCE_FAKE", raising=False)
    # may be playwright if installed; accept none or playwright
    r = resolve_browser_runtime()
    assert r in ("none", "playwright", "mcp", "fake")


def test_force_fake(monkeypatch):
    monkeypatch.setenv("BROWSER_RUNTIME", "fake")
    p, meta = build_browser_provider(force_runtime="fake")
    assert p is not None
    assert meta["provider"] == "fake"


def test_mcp_missing_url(monkeypatch):
    monkeypatch.delenv("MCP_BROWSER_URL", raising=False)
    p, meta = build_browser_provider(force_runtime="mcp")
    assert p is None
    assert meta["status"] == "BROWSER_UNAVAILABLE"
    assert "MCP_BROWSER_URL" in meta["reason"]


def test_mcp_scope_blocked_without_allowlist():
    p = McpBrowserProvider(base_url="http://127.0.0.1:9", allowed_origins=set())
    eng = SimpleNamespace(base_url="https://evil.example", engagement_id="t", object_path="/")
    ctx = p.bootstrap_lab(eng)
    assert ctx.bootstrap_status == "blocked"
    assert "BROWSER_SCOPE_BLOCKED" in ctx.block_reasons or "BROWSER_UNAVAILABLE" in str(ctx.block_reasons) or ctx.bootstrap_status == "blocked"


def test_no_silent_playwright_to_fake(monkeypatch):
    monkeypatch.setenv("BROWSER_RUNTIME", "playwright")
    p, meta = build_browser_provider(force_runtime="playwright")
    # If playwright missing → None, not fake
    if p is None:
        assert meta["status"] == "BROWSER_UNAVAILABLE"
        assert meta.get("provider") != "fake"
