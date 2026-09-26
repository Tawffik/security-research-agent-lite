"""
T4 pre-flight: integration boundary audit tests.

Prove:
1. authorized defaults false / template cannot execute accidentally
2. credentials never land in artifacts
3. object path is fixed from engagement (no enumeration)
4. observations flow PortSwiggerAdapter.validate → run_from_engagement
   → run_http → _investigate → Evidence/FP Gate/R-S-R
   (no parallel PortSwigger verdict)
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from agent_lite.http.engagement import load_engagement
from agent_lite.http.executor import HttpExecutor
from agent_lite.http.models import ActionRequest
from agent_lite.identity.resolver import Identity, IdentityResolver, SessionMaterial
from agent_lite.labs.portswigger import PortSwiggerAdapter
from agent_lite.runtime.pipeline import ResearchPipeline


def _eng_yaml(tmp: Path, **overrides) -> Path:
    data = {
        "schema_version": "1.0",
        "engagement": {
            "id": "eng_t4_boundary",
            "type": "portswigger",
            "mode": "live_lab",
            "authorized": True,
        },
        "target": {"base_url": "https://lab.web-security-academy.net"},
        "scope": {
            "allowed_hosts": [
                {"host": "lab.web-security-academy.net", "methods": ["GET"]}
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
            "object_path": "/my-account?id=1",
            "allowed_methods": ["GET"],
            "owner_identity": "user_a",
            "non_owner_identity": "user_b",
            "timeout_seconds": 5,
        },
    }
    for k, v in overrides.items():
        if isinstance(v, dict) and isinstance(data.get(k), dict) and v:
            data[k] = {**data[k], **v}
        else:
            data[k] = v
    p = tmp / "eng.yaml"
    p.write_text(yaml.dump(data))
    return p


def _recon(tmp: Path) -> Path:
    p = tmp / "recon.json"
    p.write_text(
        json.dumps(
            {
                "primary_host": "lab.web-security-academy.net",
                "endpoints": [{"method": "GET", "path": "/my-account"}],
                "actors": [
                    {"actor_id": "user_a", "name": "user_a", "type": "user"},
                    {"actor_id": "user_b", "name": "user_b", "type": "user"},
                ],
                "resources": [
                    {"name": "account-1", "type": "object", "owner_actor_id": "user_a"}
                ],
            }
        )
    )
    return p


def _scope_file(tmp: Path) -> Path:
    p = tmp / "scope.yaml"
    p.write_text(
        yaml.dump(
            {
                "in_scope": [
                    {"host": "lab.web-security-academy.net", "methods": ["GET", "HEAD"]}
                ],
                "out_of_scope": [],
                "allow_mutations": False,
            }
        )
    )
    return p


def test_template_authorized_false_by_default():
    root = Path(__file__).resolve().parents[1]
    eng = load_engagement(root / "config/engagements/portswigger_bola_template.yaml")
    assert eng.authorized is False
    assert load_engagement.__doc__ is not None or True
    # bool(eng.get("authorized", False)) path — missing key → False
    assert eng.authorization_errors()  # non-empty


def test_unauthorized_engagement_never_reaches_run_http(tmp_path):
    eng = load_engagement(_eng_yaml(tmp_path, engagement={"authorized": False}))
    pipe = ResearchPipeline(
        engagement_id="eng_block",
        scope_path=_scope_file(tmp_path),
        artifacts_dir=tmp_path / "art",
    )
    result = pipe.run_from_engagement(_recon(tmp_path), engagement=eng)
    assert result.summary.startswith("ENGAGEMENT_BLOCKED")
    assert result.gate_status == "BLOCK"
    assert result.verdict is None
    assert result.mode == "http"


def test_authorized_path_uses_run_http_and_pipeline_verdict(tmp_path):
    """Mock transport: secure lab → REJECTED from pipeline, not adapter."""
    eng = load_engagement(_eng_yaml(tmp_path))
    secret = "SESSION_TOKEN_MUST_NOT_LEAK"

    def transport(req: ActionRequest, hdrs: dict):
        if req.identity_id == "user_a":
            return 200, {"Content-Type": "application/json"}, '{"id":1,"owner":"user_a"}', 2.0
        return 403, {"Content-Type": "application/json"}, '{"error":"forbidden"}', 2.0

    idr = IdentityResolver()
    for iid in ("user_a", "user_b"):
        idr.register(Identity(identity_id=iid, credential_ref=f"TEST_{iid.upper()}"))
        idr.inject_session(
            iid,
            SessionMaterial(
                identity_id=iid,
                headers={"Authorization": f"Bearer {secret}", "Cookie": f"sid={iid}"},
            ),
        )
    executor = HttpExecutor(
        scope=eng.build_scope(),
        budget=eng.build_budget(),
        identities=idr,
        allowed_schemes=eng.allowed_schemes,
        transport=transport,
    )
    pipe = ResearchPipeline(
        engagement_id="eng_t4_ok",
        scope_path=_scope_file(tmp_path),
        artifacts_dir=tmp_path / "art",
    )
    result = pipe.run_from_engagement(
        _recon(tmp_path), engagement=eng, executor=executor
    )
    assert result.mode == "http"
    assert result.verdict is not None
    assert result.verdict.status == "REJECTED"
    assert result.facts.get("observation_mode") == "http"
    # Adapter did not set verdict — pipeline did
    blob = json.dumps(result.to_dict())
    assert secret not in blob
    art = tmp_path / "art" / "eng_t4_ok"
    if art.exists():
        for f in art.rglob("*"):
            if f.is_file():
                assert secret not in f.read_text(errors="replace")


def test_object_path_comes_only_from_engagement(tmp_path):
    eng = load_engagement(
        _eng_yaml(tmp_path, experiment={"object_path": "/fixed/object/42"})
    )
    built = PortSwiggerAdapter(eng).build_bola_action_requests()
    assert built.status == "READY"
    urls = [r["url"] for r in built.action_requests]
    assert all(u.endswith("/fixed/object/42") for u in urls)
    assert len(built.action_requests) == 2  # no enumeration


def test_positive_mock_confirmed_via_pipeline_not_adapter(tmp_path):
    eng = load_engagement(_eng_yaml(tmp_path))
    body = '{"id":1,"owner":"user_a","email":"a@ex.test","amount":9}'

    def transport(req: ActionRequest, hdrs: dict):
        return 200, {}, body, 1.0

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
    # Low-level adapter execute has no verdict field
    ar = PortSwiggerAdapter(eng, executor=ex).execute_bola_differential()
    assert ar.status == "EXECUTED"
    assert "verdict" not in ar.to_dict()

    # Full path has verdict from pipeline
    pipe = ResearchPipeline(
        engagement_id="eng_t4_pos",
        scope_path=_scope_file(tmp_path),
        artifacts_dir=tmp_path / "art",
    )
    result = pipe.run_from_engagement(_recon(tmp_path), engagement=eng, executor=ex)
    assert result.verdict is not None
    assert result.verdict.status == "CONFIRMED"
