"""T0/T1: scope, redaction, budget, identity, HTTP observation."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from agent_lite.budget.guard import BudgetGuard, BudgetState
from agent_lite.http.executor import HttpExecutor
from agent_lite.http.models import ActionRequest
from agent_lite.http.redaction import redact_headers, safe_body_for_storage
from agent_lite.identity.resolver import Identity, IdentityResolver, SessionMaterial
from agent_lite.scope.guard import ScopeGuard


def _scope(tmp_path: Path, hosts: list | None = None) -> ScopeGuard:
    data = {
        "in_scope": hosts
        or [{"host": "lab.example.test", "methods": ["GET", "HEAD"]}],
        "out_of_scope": ["evil.example"],
        "allow_mutations": False,
    }
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.dump(data))
    return ScopeGuard.from_file(p)


def _mock_transport_factory(status: int = 200, body: str = '{"ok":true}', headers: dict | None = None):
    def transport(req: ActionRequest, hdrs: dict):
        return status, headers or {"Content-Type": "application/json"}, body, 12.5

    return transport


def test_redact_headers_strips_secrets():
    h = {
        "Authorization": "Bearer SECRET",
        "Cookie": "sid=abc",
        "Content-Type": "application/json",
        "X-Api-Key": "k",
    }
    r = redact_headers(h)
    assert r["Authorization"] == "[REDACTED]"
    assert r["Cookie"] == "[REDACTED]"
    assert r["X-Api-Key"] == "[REDACTED]"
    assert r["Content-Type"] == "application/json"


def test_safe_body_truncates_and_flags_sensitive():
    body = '{"password":"x","data":"' + ("a" * 5000) + '"}'
    stored = safe_body_for_storage(body, max_store=200)
    assert len(stored) <= 200
    assert "password" not in stored or "[REDACTED" in stored


def test_scope_blocks_unknown_host(tmp_path):
    ex = HttpExecutor(
        scope=_scope(tmp_path),
        budget=BudgetGuard(BudgetState(max_requests=5)),
        transport=_mock_transport_factory(),
    )
    obs = ex.execute(
        ActionRequest(method="GET", url="https://unknown.test/api/x", identity_id="")
    )
    assert obs.blocked is True
    assert "unknown_host" in obs.block_reason or obs.scope_decision == "BLOCK"
    assert obs.request_count == 0


def test_scope_blocks_out_of_scope(tmp_path):
    ex = HttpExecutor(
        scope=_scope(tmp_path),
        budget=BudgetGuard(BudgetState(max_requests=5)),
        transport=_mock_transport_factory(),
    )
    obs = ex.execute(ActionRequest(method="GET", url="https://evil.example/x"))
    assert obs.blocked is True
    assert obs.request_count == 0


def test_scheme_blocks_file(tmp_path):
    ex = HttpExecutor(
        scope=_scope(tmp_path),
        budget=BudgetGuard(BudgetState(max_requests=5)),
        transport=_mock_transport_factory(),
    )
    obs = ex.execute(ActionRequest(method="GET", url="file:///etc/passwd"))
    assert obs.blocked is True
    assert "scheme" in obs.block_reason


def test_budget_blocks_after_limit(tmp_path):
    budget = BudgetGuard(BudgetState(max_requests=1))
    ex = HttpExecutor(
        scope=_scope(tmp_path),
        budget=budget,
        transport=_mock_transport_factory(),
    )
    o1 = ex.execute(ActionRequest(method="GET", url="https://lab.example.test/a"))
    assert o1.blocked is False
    o2 = ex.execute(ActionRequest(method="GET", url="https://lab.example.test/b"))
    assert o2.blocked is True
    assert "budget" in o2.block_reason


def test_missing_identity_blocks(tmp_path):
    idr = IdentityResolver()
    idr.register(Identity(identity_id="user_a", credential_ref="TEST_USER_A"))
    ex = HttpExecutor(
        scope=_scope(tmp_path),
        budget=BudgetGuard(BudgetState(max_requests=5)),
        identities=idr,
        transport=_mock_transport_factory(),
    )
    obs = ex.execute(
        ActionRequest(
            method="GET",
            url="https://lab.example.test/api/orders/1",
            identity_id="user_a",
        )
    )
    assert obs.blocked is True
    assert "missing_authorization" in obs.block_reason


def test_identity_with_injected_session_allows(tmp_path):
    idr = IdentityResolver()
    idr.register(Identity(identity_id="user_a", credential_ref="TEST_USER_A"))
    idr.inject_session(
        "user_a",
        SessionMaterial(identity_id="user_a", headers={"Cookie": "sid=secret"}),
    )
    captured = {}

    def transport(req: ActionRequest, hdrs: dict):
        captured["headers"] = dict(hdrs)
        return 200, {"Content-Type": "text/plain"}, "ok", 5.0

    ex = HttpExecutor(
        scope=_scope(tmp_path),
        budget=BudgetGuard(BudgetState(max_requests=5)),
        identities=idr,
        transport=transport,
    )
    obs = ex.execute(
        ActionRequest(
            method="GET",
            url="https://lab.example.test/api/orders/1",
            identity_id="user_a",
            experiment_id="EXP-T",
        )
    )
    assert obs.blocked is False
    assert obs.response_status == 200
    assert obs.identity_id == "user_a"
    assert "secret" not in obs.response_body
    # Cookie must be redacted in stored request metadata
    assert obs.request_metadata["request_headers_redacted"].get("Cookie") == "[REDACTED]"
    # transport did receive the real cookie (runtime only)
    assert captured["headers"].get("Cookie") == "sid=secret"


def test_observation_never_contains_raw_auth_header(tmp_path):
    idr = IdentityResolver()
    idr.register(Identity(identity_id="user_b", credential_ref="TEST_USER_B"))
    idr.inject_session(
        "user_b",
        SessionMaterial(identity_id="user_b", headers={"Authorization": "Bearer SUPERSECRET"}),
    )

    def transport(req, hdrs):
        return 200, {"Set-Cookie": "new=1", "Content-Type": "application/json"}, '{"x":1}', 1.0

    ex = HttpExecutor(
        scope=_scope(tmp_path),
        budget=BudgetGuard(BudgetState(max_requests=5)),
        identities=idr,
        transport=transport,
    )
    obs = ex.execute(
        ActionRequest(method="GET", url="https://lab.example.test/x", identity_id="user_b")
    )
    blob = str(obs.to_dict())
    assert "SUPERSECRET" not in blob
    assert obs.response_headers.get("Set-Cookie") == "[REDACTED]"


def test_mutation_blocked_when_not_allowed(tmp_path):
    ex = HttpExecutor(
        scope=_scope(tmp_path),
        budget=BudgetGuard(BudgetState(max_requests=5)),
        transport=_mock_transport_factory(),
    )
    obs = ex.execute(ActionRequest(method="DELETE", url="https://lab.example.test/x"))
    assert obs.blocked is True
