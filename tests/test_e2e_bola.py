"""Acceptance: positive BOLA confirmed; secure/public rejected."""

from pathlib import Path

from agent_lite.runtime.pipeline import ResearchPipeline
from agent_lite.skills.authz_bola import (
    bola_negative_public,
    bola_negative_secure,
    bola_positive_lab,
)

ROOT = Path(__file__).resolve().parents[1]
RECON = ROOT / "examples" / "fixtures" / "sample_recon.json"
SCOPE = ROOT / "config" / "scope.yaml"


def test_positive_bola_confirmed(tmp_path):
    r = ResearchPipeline(
        engagement_id="eng_pos",
        scope_path=SCOPE,
        artifacts_dir=tmp_path,
    ).run(RECON, scenario=bola_positive_lab())
    assert r.scope_allowed
    assert r.verdict is not None
    assert r.verdict.status == "CONFIRMED"
    assert r.evidence_ids
    assert (tmp_path / "eng_pos" / "final-report.md").exists()
    assert (tmp_path / "eng_pos" / "evidence.jsonl").exists()


def test_secure_rejected(tmp_path):
    r = ResearchPipeline(
        engagement_id="eng_sec",
        scope_path=SCOPE,
        artifacts_dir=tmp_path,
    ).run(RECON, scenario=bola_negative_secure())
    assert r.verdict.status == "REJECTED"


def test_public_resource_rejected(tmp_path):
    r = ResearchPipeline(
        engagement_id="eng_pub",
        scope_path=SCOPE,
        artifacts_dir=tmp_path,
    ).run(RECON, scenario=bola_negative_public())
    assert r.verdict.status == "REJECTED"
    assert "public" in r.verdict.reason or "shared" in r.verdict.reason or r.gate_status in ("BLOCK", "PASS")


def test_out_of_scope_blocked(tmp_path):
    # write recon with bad host
    bad = tmp_path / "bad.json"
    bad.write_text('{"primary_host":"evil.example.com","endpoints":[{"method":"GET","path":"/x"}]}')
    r = ResearchPipeline(
        engagement_id="eng_oos",
        scope_path=SCOPE,
        artifacts_dir=tmp_path,
    ).run(bad)
    assert r.scope_allowed is False
