"""E2E: verdicts from observations only — no scenario answer keys in reasoning."""

from pathlib import Path

from agent_lite.runtime.pipeline import ResearchPipeline
from agent_lite.skills.authz_bola import (
    bola_ambiguous_status_only,
    bola_negative_public,
    bola_negative_secure,
    bola_negative_shared,
    bola_positive_lab,
)

ROOT = Path(__file__).resolve().parents[1]
RECON = ROOT / "examples" / "fixtures" / "sample_recon.json"
SCOPE = ROOT / "config" / "scope.yaml"


def test_positive_bola_confirmed_from_observations(tmp_path):
    r = ResearchPipeline(engagement_id="eng_pos", scope_path=SCOPE, artifacts_dir=tmp_path).run(
        RECON, scenario=bola_positive_lab()
    )
    assert r.scope_allowed
    assert r.opportunities
    assert r.hypotheses
    assert r.experiments
    assert r.verdict is not None
    assert r.verdict.status == "CONFIRMED"
    assert "suggests_authz" not in str(r.facts)
    assert r.facts.get("private_fields") is True
    assert (tmp_path / "eng_pos" / "ledger.db").exists()
    assert (tmp_path / "eng_pos" / "opportunities.json").exists()


def test_secure_rejected(tmp_path):
    r = ResearchPipeline(engagement_id="eng_sec", scope_path=SCOPE, artifacts_dir=tmp_path).run(
        RECON, scenario=bola_negative_secure()
    )
    assert r.verdict.status == "REJECTED"


def test_public_rejected(tmp_path):
    r = ResearchPipeline(engagement_id="eng_pub", scope_path=SCOPE, artifacts_dir=tmp_path).run(
        RECON, scenario=bola_negative_public()
    )
    assert r.verdict.status == "REJECTED"


def test_shared_rejected(tmp_path):
    r = ResearchPipeline(engagement_id="eng_share", scope_path=SCOPE, artifacts_dir=tmp_path).run(
        RECON, scenario=bola_negative_shared()
    )
    assert r.verdict.status == "REJECTED"


def test_ambiguous_need_more_or_reject(tmp_path):
    r = ResearchPipeline(engagement_id="eng_amb", scope_path=SCOPE, artifacts_dir=tmp_path).run(
        RECON, scenario=bola_ambiguous_status_only()
    )
    assert r.verdict.status in ("NEED_MORE_EVIDENCE", "REJECTED")
    assert r.verdict.status != "CONFIRMED"


def test_out_of_scope_blocked(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"primary_host":"evil.example.com","endpoints":[{"method":"GET","path":"/api/orders/{id}"}]}')
    r = ResearchPipeline(engagement_id="eng_oos", scope_path=SCOPE, artifacts_dir=tmp_path).run(bad)
    assert r.scope_allowed is False
