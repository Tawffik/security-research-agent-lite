"""
T2 integration: ResearchPipeline.run_http against a real local HTTP server.

Observations come from actual TCP/HTTP (HttpExecutor + urllib).
Verdict still derived from evidence — not from scenario labels.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from agent_lite.budget.guard import BudgetGuard, BudgetState
from agent_lite.http.executor import HttpExecutor
from agent_lite.identity.resolver import Identity, IdentityResolver, SessionMaterial
from agent_lite.runtime.pipeline import ResearchPipeline
from agent_lite.scope.guard import ScopeGuard
from agent_lite.http_lab.bola_local_server import BolaLocalServer


def _write_scope(tmp: Path, host: str = "127.0.0.1") -> Path:
    data = {
        "in_scope": [{"host": host, "methods": ["GET", "HEAD"]}],
        "out_of_scope": [],
        "allow_mutations": False,
    }
    p = tmp / "scope_http.yaml"
    p.write_text(yaml.dump(data))
    return p


def _write_recon(tmp: Path, host: str = "127.0.0.1") -> Path:
    data = {
        "primary_host": host,
        "technologies": ["local-http-lab"],
        "endpoints": [{"method": "GET", "path": "/api/orders/{id}"}],
        "actors": [
            {"actor_id": "user_a", "name": "user_a", "type": "user"},
            {"actor_id": "user_b", "name": "user_b", "type": "user"},
        ],
        "resources": [
            {"name": "order-1001", "type": "object", "owner_actor_id": "user_a"}
        ],
        "notes": "local http lab recon",
    }
    p = tmp / "recon_http.json"
    p.write_text(json.dumps(data))
    return p


def _executor(scope_path: Path) -> HttpExecutor:
    idr = IdentityResolver()
    for iid in ("user_a", "user_b"):
        idr.register(Identity(identity_id=iid, credential_ref=f"TEST_{iid.upper()}"))
        # session material stays in executor boundary
        idr.inject_session(
            iid, SessionMaterial(identity_id=iid, headers={"Cookie": f"sid={iid}"})
        )
    return HttpExecutor(
        scope=ScopeGuard.from_file(scope_path),
        budget=BudgetGuard(BudgetState(max_requests=10, timeout_seconds=5)),
        identities=idr,
        allowed_schemes={"http", "https"},
        # real urllib transport (default)
        transport=None,
    )


def _run(tmp: Path, scenario: str):
    scope = _write_scope(tmp)
    recon = _write_recon(tmp)
    with BolaLocalServer(scenario) as server:
        pipe = ResearchPipeline(
            engagement_id=f"eng_http_{scenario}",
            scope_path=scope,
            artifacts_dir=tmp / "artifacts",
        )
        result = pipe.run_http(
            recon,
            base_url=server.base_url,
            object_path=server.object_path,
            executor=_executor(scope),
        )
    return result


def test_http_mode_positive_confirmed(tmp_path):
    r = _run(tmp_path, "positive")
    assert r.mode == "http"
    assert r.scope_allowed is True
    assert r.verdict is not None
    assert r.verdict.status == "CONFIRMED"
    assert r.facts.get("private_fields") is True
    assert r.facts.get("observation_mode") == "http"
    # evidence provenance must be http, not lab label
    assert any("http" in (e or "") for e in r.evidence_ids) or len(r.evidence_ids) >= 2
    exp = r.experiments[0]
    assert exp.result == "executed"
    assert exp.request_count == 2


def test_http_mode_secure_rejected(tmp_path):
    r = _run(tmp_path, "secure")
    assert r.mode == "http"
    assert r.verdict is not None
    assert r.verdict.status == "REJECTED"
    assert r.facts.get("non_owner_status", 0) >= 400


def test_http_mode_public_rejected(tmp_path):
    r = _run(tmp_path, "public")
    assert r.verdict is not None
    assert r.verdict.status == "REJECTED"
    assert r.facts.get("public_marker") is True


def test_http_mode_shared_rejected(tmp_path):
    r = _run(tmp_path, "shared")
    assert r.verdict is not None
    assert r.verdict.status == "REJECTED"
    assert r.facts.get("shared_acl") is True


def test_http_mode_ambiguous_never_confirmed(tmp_path):
    r = _run(tmp_path, "ambiguous")
    assert r.verdict is not None
    assert r.verdict.status != "CONFIRMED"
    assert r.verdict.status in ("REJECTED", "NEED_MORE_EVIDENCE")
    assert r.facts.get("private_fields") is False


def test_http_mode_scope_blocks_unknown_host(tmp_path):
    """Executor must not hit network when host is out of scope."""
    scope = _write_scope(tmp_path, host="127.0.0.1")
    recon = _write_recon(tmp_path, host="127.0.0.1")
    # Scope allows 127.0.0.1 but we point URL at evil host → action-level block
    pipe = ResearchPipeline(
        engagement_id="eng_http_oos",
        scope_path=scope,
        artifacts_dir=tmp_path / "artifacts",
    )
    result = pipe.run_http(
        recon,
        base_url="http://evil.example.test",
        object_path="/api/orders/1001",
        executor=_executor(scope),
    )
    assert result.summary.startswith("EXPERIMENT_BLOCKED")
    assert result.gate_status == "BLOCK"
    assert result.verdict is None


def test_synthetic_path_still_works(tmp_path):
    """Regression: default synthetic run must remain intact."""
    from agent_lite.skills.authz_bola import bola_positive_lab

    # use repo fixtures relative to package
    root = Path(__file__).resolve().parents[1]
    recon = root / "examples" / "fixtures" / "sample_recon.json"
    scope = root / "config" / "scope.yaml"
    pipe = ResearchPipeline(
        engagement_id="eng_synth_reg",
        scope_path=scope,
        artifacts_dir=tmp_path / "artifacts",
    )
    r = pipe.run(recon, scenario=bola_positive_lab())
    assert r.mode == "synthetic"
    assert r.verdict is not None
    assert r.verdict.status == "CONFIRMED"
