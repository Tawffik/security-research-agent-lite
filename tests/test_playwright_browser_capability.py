"""Playwright capability tests — skipped when playwright not installed."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from agent_lite.browser.capability import detect_browser_capability

pytest.importorskip("playwright")


@pytest.fixture(scope="module")
def local_lab():
    from tests.browser_lab.synthetic_app import serve

    server = serve("127.0.0.1", 8765)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:8765"
    server.shutdown()


def test_playwright_import_and_capability():
    cap = detect_browser_capability()
    assert cap.runtime == "playwright"
    assert cap.status == "BROWSER_AVAILABLE"


def test_playwright_launch_navigate_close(local_lab):
    from agent_lite.browser.playwright_provider import PlaywrightBrowserProvider

    eng = SimpleNamespace(
        base_url=local_lab,
        engagement_id="browser_lab",
        object_path="/login",
    )
    p = PlaywrightBrowserProvider(headless=True)
    try:
        ctx = p.bootstrap_lab(eng)
        assert ctx.bootstrap_status == "ok"
        r_a = p.establish_session(eng, "user_a", ctx)
        r_b = p.establish_session(eng, "user_b", ctx)
        assert r_a.status == "ok"
        assert r_b.status == "ok"
        assert p.assert_isolation()
        sa = p.session_handle("user_a")
        sb = p.session_handle("user_b")
        assert sa and sb and sa.session_id != sb.session_id
        # public handles have no raw cookie field
        assert "Cookie" not in sa.to_public_dict()
    finally:
        p.close_session()


def test_playwright_out_of_scope_blocked():
    from agent_lite.browser.playwright_provider import PlaywrightBrowserProvider

    eng = SimpleNamespace(
        base_url="https://evil.example.test",
        engagement_id="oos",
        object_path="/",
    )
    p = PlaywrightBrowserProvider(headless=True)
    try:
        ctx = p.bootstrap_lab(eng)
        assert ctx.bootstrap_status == "blocked"
        assert "BROWSER_SCOPE_BLOCKED" in ctx.block_reasons
    finally:
        p.close_session()
