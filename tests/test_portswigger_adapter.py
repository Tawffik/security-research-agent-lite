"""
PortSwigger adapter — deterministic safety tests (no live Academy target).

Adapter produces observations only. Verdict remains ResearchPipeline's job.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from agent_lite.budget.guard import BudgetGuard, BudgetState
from agent_lite.http.engagement import EngagementConfig, load_engagement
from agent_lite.http.executor import HttpExecutor
from agent_lite.http.models import ActionRequest
from agent_lite.identity.resolver import Identity, IdentityResolver, SessionMaterial
from agent_lite.labs.portswigger import PortSwiggerAdapter
from agent_lite.scope.guard import ScopeGuard


def _write_engagement(tmp: Path, **overrides) -> Path:
    data = {
        "schema_version": "1.0",
        "engagement": {
            "id": "eng_ps_test",
            "type": "portswigger",
            "mode": "live_lab",
            "authorized": True,
        },
        "target": {"base_url": "https://lab.web-security-academy.net"},
        "scope": {
            "allowed_hosts": [
                {"host": "lab.web-security-academy.net", "methods": ["GET", "HEAD"]}
            ],
            "allowed_schemes": ["https"],
            "allow_mutations": False,
        },
        "identities": {
            "user_a": {"credential_ref": "TEST_USER_A", "role": "owner"},
            "user_b": {"credential_ref": "TEST_USER_B", "role": "non_owner"},
        },
        "experiment": {
            "max_requests": 4,
            "max_experiments": 1,
            "max_response_bytes": 100000,
            "timeout_seconds": 5,
            "allowed_methods": ["GET"],
            "object_path": "/my-account",
            "owner_identity": "user_a",
            "non_owner_identity": "user_b",
        },
    }
    # top-level overrides replace; nested dicts merge unless empty replacement intended
    for k, v in overrides.items():
        if isinstance(v, dict) and isinstance(data.get(k), dict) and v:
            data[k] = {**data[k], **v}
        else:
            data[k] = v
    p = tmp / "eng.yaml"
    p.write_text(yaml.dump(data))
    return p


def test_missing_authorization_blocks(tmp_path):
    p = _write_engagement(tmp_path, engagement={"authorized": False})
    eng = load_engagement(p)
    r = PortSwiggerAdapter(eng).validate()
    assert r.status == "BLOCKED"
    assert "engagement_not_authorized" in r.block_reasons


def test_missing_base_url_blocks(tmp_path):
    p = _write_engagement(tmp_path, target={"base_url": ""})
    eng = load_engagement(p)
    r = PortSwiggerAdapter(eng).validate()
    assert r.status == "BLOCKED"
    assert "missing_base_url" in r.block_reasons


def test_host_not_in_scope_blocks(tmp_path):
    p = _write_engagement(
        tmp_path,
        target={"base_url": "https://evil.example.test"},
    )
    eng = load_engagement(p)
    r = PortSwiggerAdapter(eng).validate()
    assert r.status == "BLOCKED"
    assert "host_not_in_scope" in r.block_reasons


def test_invalid_scheme_blocks(tmp_path):
    p = _write_engagement(
        tmp_path,
        target={"base_url": "http://lab.web-security-academy.net"},  # http not in https-only
    )
    eng = load_engagement(p)
    r = PortSwiggerAdapter(eng).validate()
    assert r.status == "BLOCKED"
    assert "scheme_not_allowed" in r.block_reasons


def test_missing_identities_blocks(tmp_path):
    p = _write_engagement(tmp_path, identities={})
    eng = load_engagement(p)
    r = PortSwiggerAdapter(eng).validate()
    assert r.status == "BLOCKED"
    assert any("identity" in e for e in r.block_reasons)


def test_valid_config_builds_action_requests(tmp_path):
    p = _write_engagement(tmp_path)
    eng = load_engagement(p)
    r = PortSwiggerAdapter(eng).build_bola_action_requests()
    assert r.status == "READY"
    assert len(r.action_requests) == 2
    assert r.action_requests[0]["identity_id"] == "user_a"
    assert r.action_requests[1]["identity_id"] == "user_b"
    assert r.action_requests[0]["url"].endswith("/my-account")
    assert r.action_requests[0]["method"] == "GET"
    # no secrets in request dict
    blob = str(r.action_requests)
    assert "password" not in blob.lower()
    assert "Bearer" not in blob


def test_method_not_allowed_blocks(tmp_path):
    p = _write_engagement(tmp_path)
    eng = load_engagement(p)
    r = PortSwiggerAdapter(eng).build_bola_action_requests(method="DELETE")
    assert r.status == "BLOCKED"
    assert "method_not_allowed" in r.block_reasons


def test_execute_uses_http_executor_mock(tmp_path):
    p = _write_engagement(tmp_path)
    eng = load_engagement(p)

    captured = []

    def transport(req: ActionRequest, hdrs: dict):
        captured.append((req.identity_id, req.url, dict(hdrs)))
        body = '{"id":1,"owner":"user_a"}' if req.identity_id == "user_a" else '{"error":"forbidden"}'
        status = 200 if req.identity_id == "user_a" else 403
        return status, {"Content-Type": "application/json"}, body, 3.0

    idr = IdentityResolver()
    for iid in ("user_a", "user_b"):
        idr.register(Identity(identity_id=iid, credential_ref=f"TEST_{iid.upper()}"))
        idr.inject_session(
            iid, SessionMaterial(identity_id=iid, headers={"Cookie": f"sid={iid}-SECRET"})
        )

    ex = HttpExecutor(
        scope=eng.build_scope(),
        budget=eng.build_budget(),
        identities=idr,
        allowed_schemes=eng.allowed_schemes,
        transport=transport,
    )
    result = PortSwiggerAdapter(eng, executor=ex).execute_bola_differential()
    assert result.status == "EXECUTED"
    assert len(result.observations) == 2
    assert result.observations[0]["response_status"] == 200
    assert result.observations[1]["response_status"] == 403
    assert result.notes == "observations_only_no_verdict"
    # secrets redacted in observations
    blob = str(result.observations)
    assert "SECRET" not in blob
    assert "[REDACTED]" in blob or "Cookie" not in blob or "REDACTED" in blob


def test_execute_without_executor_blocks(tmp_path):
    p = _write_engagement(tmp_path)
    eng = load_engagement(p)
    r = PortSwiggerAdapter(eng, executor=None).execute_bola_differential()
    assert r.status == "BLOCKED"
    assert "missing_http_executor" in r.block_reasons


def test_out_of_scope_host_blocked_by_executor(tmp_path):
    """Even if adapter somehow built a request, executor still fail-closes."""
    p = _write_engagement(tmp_path)
    eng = load_engagement(p)
    # Force a bad URL after validate by using a custom request path via transport scope
    idr = eng.build_identities()
    idr.inject_session(
        "user_a", SessionMaterial(identity_id="user_a", headers={"Cookie": "sid=user_a"})
    )
    idr.inject_session(
        "user_b", SessionMaterial(identity_id="user_b", headers={"Cookie": "sid=user_b"})
    )
    ex = HttpExecutor(
        scope=eng.build_scope(),
        budget=BudgetGuard(BudgetState(max_requests=5)),
        identities=idr,
        allowed_schemes={"https"},
        transport=lambda req, h: (200, {}, "ok", 1.0),
    )
    obs = ex.execute(
        ActionRequest(method="GET", url="https://evil.example.test/x", identity_id="user_a")
    )
    assert obs.blocked is True


def test_template_file_loads_unauthorized(tmp_path):
    root = Path(__file__).resolve().parents[1]
    tpl = root / "config" / "engagements" / "portswigger_bola_template.yaml"
    eng = load_engagement(tpl)
    assert eng.engagement_type == "portswigger"
    assert eng.authorized is False
    r = PortSwiggerAdapter(eng).validate()
    assert r.status == "BLOCKED"
    assert "engagement_not_authorized" in r.block_reasons


def test_adapter_does_not_emit_verdict_fields(tmp_path):
    p = _write_engagement(tmp_path)
    eng = load_engagement(p)

    def transport(req, hdrs):
        return 200, {}, '{"x":1}', 1.0

    idr = eng.build_identities()
    for iid in eng.identities:
        idr.inject_session(iid, SessionMaterial(identity_id=iid, headers={"Cookie": f"sid={iid}"}))
    ex = HttpExecutor(
        scope=eng.build_scope(),
        budget=eng.build_budget(),
        identities=idr,
        allowed_schemes=eng.allowed_schemes,
        transport=transport,
    )
    result = PortSwiggerAdapter(eng, executor=ex).execute_bola_differential()
    d = result.to_dict()
    assert "verdict" not in d
    assert "is_vulnerable" not in d
    assert "CONFIRMED" not in str(d)
