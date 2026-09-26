"""Mailbox providers + auth profile selection — offline / fail-closed."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from agent_lite.auth.factory import build_orchestrator, resolve_provider_kind
from agent_lite.auth.mailslurp import MailSlurpMailboxProvider
from agent_lite.auth.temp_mailbox import TempMailboxProvider


def test_profile_mapping():
    assert resolve_provider_kind("two_test_users") == "mock"
    assert resolve_provider_kind("two_test_users_mock") == "mock"
    assert resolve_provider_kind("two_test_users_mailslurp") == "mailslurp"
    assert resolve_provider_kind("two_test_users_temp") == "temp"
    assert resolve_provider_kind("manual") == "manual"


def test_mock_profile_builds_and_runs():
    orch, meta = build_orchestrator("two_test_users_mock")
    assert orch is not None
    assert meta["status"] == "ok"
    res = orch.run_two_users()
    assert res.status == "ok"
    blob = json.dumps(res.to_dict())
    assert "Cookie" not in blob


def test_mailslurp_missing_key_waits():
    with patch.dict("os.environ", {}, clear=False):
        import os

        os.environ.pop("MAILSLURP_API_KEY", None)
        os.environ.pop("BROWSER_MCP_ENABLED", None)
        orch, meta = build_orchestrator("two_test_users_mailslurp")
        assert orch is None
        assert meta["status"] == "WAITING_FOR_AUTH"
        assert meta["reason"] == "missing_mailslurp_api_key"


def test_mailslurp_key_wires_provider_but_run_waits_without_browser():
    with patch.dict("os.environ", {"MAILSLURP_API_KEY": "test-key-not-real"}):
        import os

        os.environ.pop("BROWSER_MCP_ENABLED", None)
        orch, meta = build_orchestrator("two_test_users_mailslurp")
        assert orch is not None
        assert meta["mailbox_class"] == "MailSlurpMailboxProvider"
        assert orch.provider_kind == "mailslurp"
        assert isinstance(orch.mailbox, __import__("agent_lite.auth.mailslurp", fromlist=["MailSlurpMailboxProvider"]).MailSlurpMailboxProvider)
        res = orch.run_two_users()
        assert res.status == "WAITING_FOR_AUTH"
        assert res.reason == "BROWSER_UNAVAILABLE"
        # must NOT inject mock OTP path
        assert not any(e.get("step") == "otp_inject" and e.get("status") == "mock_only" for e in res.trace)


def test_temp_missing_base_url():
    with patch.dict("os.environ", {}, clear=False):
        import os

        os.environ.pop("TEMP_MAIL_BASE_URL", None)
        orch, meta = build_orchestrator("two_test_users_temp")
        assert orch is None
        assert "missing_temp_mail" in meta["reason"]


def test_manual_waits():
    orch, meta = build_orchestrator("manual")
    assert orch is None
    assert meta["reason"] == "manual_authentication_required"


def test_mailslurp_create_mailbox_http_mock():
    provider = MailSlurpMailboxProvider(api_key="k")
    fake_resp = MagicMock()
    fake_resp.status = 201
    fake_resp.read.return_value = json.dumps(
        {"id": "inbox-1", "emailAddress": "a@mailslurp.test"}
    ).encode()
    fake_resp.__enter__.return_value = fake_resp
    fake_resp.__exit__.return_value = None
    with patch("urllib.request.urlopen", return_value=fake_resp):
        meta = provider.create_mailbox("user_a")
    assert meta["status"] == "ready"
    assert meta["mailbox_id"] == "inbox-1"
    assert meta["provider"] == "mailslurp"
    assert "api_key" not in json.dumps(meta)


def test_temp_create_mailbox_http_mock():
    provider = TempMailboxProvider(base_url="https://temp.example.test", api_key="t")
    fake_resp = MagicMock()
    fake_resp.status = 201
    fake_resp.read.return_value = json.dumps(
        {"id": "mb-9", "email": "b@temp.example.test"}
    ).encode()
    fake_resp.__enter__.return_value = fake_resp
    fake_resp.__exit__.return_value = None
    with patch("urllib.request.urlopen", return_value=fake_resp):
        meta = provider.create_mailbox("user_b")
    assert meta["status"] == "ready"
    assert meta["email_address"].endswith("temp.example.test")


def test_no_silent_fallback_from_real_to_mock():
    orch, meta = build_orchestrator("two_test_users_mailslurp")
    # without key → not mock orchestrator
    assert orch is None
    assert meta.get("provider_kind") == "mailslurp"


def test_orchestrator_never_injects_on_real_kind():
    from agent_lite.auth.orchestrator import AuthOrchestrator
    from agent_lite.auth.mailbox import MockMailboxProvider
    from agent_lite.auth.auth_provider import MockAuthProvider
    from agent_lite.auth.identity_provider import MockIdentityProvider

    mb = MockMailboxProvider()
    # force provider_kind real while using mock mailbox object — inject must still be off
    orch = AuthOrchestrator(
        identity_provider=MockIdentityProvider(),
        mailbox=mb,
        auth=MockAuthProvider(mailbox=mb),
        provider_kind="mailslurp",
        allow_registration=True,
    )
    # even with allow_registration, inject_otps default False for non-mock kind
    res = orch.run_two_users(inject_otps=None)
    # without injected OTP, wait finds nothing → WAITING or OTP_NOT_FOUND
    assert res.status in ("WAITING_FOR_AUTH", "blocked", "ok")
    inject_steps = [e for e in res.trace if e.get("step") == "otp_inject" and e.get("status") == "mock_only"]
    assert inject_steps == []
