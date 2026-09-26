"""BBCI-shaped recon → adapter fidelity → BOLA pipeline (no new skills)."""

from __future__ import annotations

import json
from pathlib import Path

from agent_lite.recon.adapter import ReconAdapter
from agent_lite.runtime.pipeline import ResearchPipeline
from agent_lite.skills.authz_bola import bola_positive_lab, bola_negative_secure


ROOT = Path(__file__).resolve().parents[1]
BBCI = ROOT / "examples" / "fixtures" / "bbci_recon_sample.json"
SCOPE = ROOT / "config" / "scope.yaml"


def test_bbci_adapter_preserves_fields():
    n = ReconAdapter().from_file(BBCI)
    assert n.primary_host == "api.acme-demo.test"
    assert "api.acme-demo.test" in n.hosts
    assert "www.acme-demo.test" in n.hosts
    assert "nginx" in n.technologies
    assert any(e["method"] == "GET" and "/api/orders" in e["path"] for e in n.endpoints)
    # parameters preserved
    order_eps = [e for e in n.endpoints if "orders" in e["path"]]
    assert order_eps
    assert "id" in (order_eps[0].get("parameters") or {})
    # URL preserved when provided
    assert any(e.get("url") for e in n.endpoints)
    # HTTP observations preserved
    assert n.observations
    assert n.observations[0].get("status") == 200
    # actors / resources
    assert len(n.actors) >= 2
    assert n.resources
    assert n.schema_version == "bbci_recon_v1"


def test_bbci_nested_bundle_unwrap():
    raw = {
        "bundle": {
            "primary_host": "api.acme-demo.test",
            "endpoints": [{"method": "GET", "path": "/x", "parameters": {"q": "1"}}],
            "technologies": ["go"],
        }
    }
    n = ReconAdapter().adapt(raw)
    assert n.primary_host == "api.acme-demo.test"
    assert n.endpoints[0]["parameters"].get("q") == "1"
    assert "go" in n.technologies


def test_bbci_recon_through_bola_pipeline(tmp_path):
    pipe = ResearchPipeline(
        engagement_id="eng_bbci_bola",
        scope_path=SCOPE,
        artifacts_dir=tmp_path / "art",
    )
    r = pipe.run(BBCI, scenario=bola_positive_lab())
    assert r.scope_allowed is True
    assert r.verdict is not None
    assert r.verdict.status == "CONFIRMED"
    assert r.hypotheses
    art = tmp_path / "art" / "eng_bbci_bola"
    assert (art / "normalized_recon.json").exists()
    norm = json.loads((art / "normalized_recon.json").read_text())
    assert norm.get("hosts")
    assert norm.get("observations") is not None
    assert (art / "research_episode.json").exists()


def test_bbci_secure_not_false_positive(tmp_path):
    pipe = ResearchPipeline(
        engagement_id="eng_bbci_secure",
        scope_path=SCOPE,
        artifacts_dir=tmp_path / "art",
    )
    r = pipe.run(BBCI, scenario=bola_negative_secure())
    assert r.verdict is not None
    assert r.verdict.status == "REJECTED"
