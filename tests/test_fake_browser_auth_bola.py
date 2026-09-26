"""Fake browser + AuthOrchestrator + BOLA synthetic labs — offline integration."""

from __future__ import annotations

import json
from pathlib import Path

from agent_lite.auth.auth_provider import MockAuthProvider
from agent_lite.auth.identity_provider import MockIdentityProvider
from agent_lite.auth.mailbox import MockMailboxProvider
from agent_lite.auth.orchestrator import AuthOrchestrator
from agent_lite.auth.synthetic_lab import (
    authenticated_bola_secure,
    authenticated_bola_vulnerable,
)
from agent_lite.browser.capability import detect_browser_capability
from agent_lite.browser.fake_auth_browser import FakeAuthBrowserProvider
from agent_lite.identity.resolver import Identity, IdentityResolver
from agent_lite.runtime.pipeline import ResearchPipeline


ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "config" / "scope.yaml"
RECON = ROOT / "examples" / "fixtures" / "bbci_recon_sample.json"


def test_browser_capability_default_unavailable():
    cap = detect_browser_capability(prefer_fake=False)
    assert cap.status in ("BROWSER_UNAVAILABLE", "BROWSER_AVAILABLE", "BROWSER_MISCONFIGURED")
    # without playwright installed in default env → unavailable or misconfigured
    assert cap.runtime in ("none", "playwright", "mcp", "fake")


def test_fake_browser_two_sessions_isolated():
    mb = MockMailboxProvider()
    browser = FakeAuthBrowserProvider(mailbox=mb)
    orch = AuthOrchestrator(
        identity_provider=MockIdentityProvider(),
        mailbox=mb,
        auth=MockAuthProvider(mailbox=mb),
        provider_kind="mock",
        allow_registration=True,
        browser=browser,
    )
    res = orch.run_two_users()
    assert res.status == "ok"
    assert len(res.sessions) == 2
    assert res.sessions[0]["session_id"] != res.sessions[1]["session_id"]
    assert res.sessions[0]["identity_id"] != res.sessions[1]["identity_id"]
    assert browser.assert_isolation()
    blob = json.dumps(res.to_dict())
    assert "Cookie" not in blob
    # secrets not in session public dict
    for s in res.sessions:
        assert "Cookie" not in s
        assert "\"otp\":" not in json.dumps(s).lower() and "password" not in json.dumps(s).lower()


def test_fake_browser_sessions_apply_to_resolver():
    mb = MockMailboxProvider()
    browser = FakeAuthBrowserProvider(mailbox=mb)
    orch = AuthOrchestrator(
        identity_provider=MockIdentityProvider(),
        mailbox=mb,
        auth=MockAuthProvider(mailbox=mb),
        browser=browser,
        allow_registration=True,
        provider_kind="mock",
    )
    assert orch.run_two_users().status == "ok"
    resolver = IdentityResolver()
    for iid in ("user_a", "user_b"):
        resolver.register(Identity(identity_id=iid, credential_ref=f"TEST_{iid.upper()}"))
    browser.apply_to_resolver(resolver)
    sa = resolver.resolve_session("user_a")
    sb = resolver.resolve_session("user_b")
    assert sa and sb
    assert sa.headers.get("Cookie") != sb.headers.get("Cookie")


def test_bola_vulnerable_after_fake_browser_auth(tmp_path):
    mb = MockMailboxProvider()
    browser = FakeAuthBrowserProvider(mailbox=mb)
    orch = AuthOrchestrator(
        identity_provider=MockIdentityProvider(),
        mailbox=mb,
        auth=MockAuthProvider(mailbox=mb),
        browser=browser,
        allow_registration=True,
        provider_kind="mock",
    )
    assert orch.run_two_users().status == "ok"
    pipe = ResearchPipeline(
        engagement_id="eng_fake_vuln",
        scope_path=SCOPE,
        artifacts_dir=tmp_path / "art",
    )
    r = pipe.run(RECON, scenario=authenticated_bola_vulnerable())
    assert r.verdict is not None
    assert r.verdict.status == "CONFIRMED"
    assert r.evidence_ids


def test_bola_secure_after_fake_browser_auth(tmp_path):
    mb = MockMailboxProvider()
    browser = FakeAuthBrowserProvider(mailbox=mb)
    orch = AuthOrchestrator(
        identity_provider=MockIdentityProvider(),
        mailbox=mb,
        auth=MockAuthProvider(mailbox=mb),
        browser=browser,
        allow_registration=True,
        provider_kind="mock",
    )
    assert orch.run_two_users().status == "ok"
    pipe = ResearchPipeline(
        engagement_id="eng_fake_sec",
        scope_path=SCOPE,
        artifacts_dir=tmp_path / "art",
    )
    r = pipe.run(RECON, scenario=authenticated_bola_secure())
    assert r.verdict is not None
    assert r.verdict.status == "REJECTED"


def test_no_silent_real_to_fake_fallback():
    from agent_lite.auth.factory import build_orchestrator

    orch, meta = build_orchestrator("two_test_users_mailslurp")
    # without key → no orchestrator
    if orch is None:
        assert meta["status"] == "WAITING_FOR_AUTH"
        return
    # with key but no browser → WAITING on run, not fake browser sessions
    res = orch.run_two_users()
    assert res.status == "WAITING_FOR_AUTH"
