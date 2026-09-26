"""Mobile runtime: recon resolve + free model router (no live API required)."""

from __future__ import annotations

import json
from pathlib import Path

from agent_lite.llm.provider import create_llm_from_profile
from agent_lite.llm.router import load_free_registry, select_provider
from agent_lite.recon.resolve import resolve_recon


ROOT = Path(__file__).resolve().parents[1]


def test_resolve_explicit_artifact():
    r = resolve_recon(
        repo_root=ROOT,
        recon_artifact="examples/fixtures/bbci_recon_sample.json",
    )
    assert r.status == "ok"
    assert r.source == "explicit"
    assert Path(r.recon_path).is_file()


def test_resolve_engagement_lookup():
    r = resolve_recon(repo_root=ROOT, engagement_id="eng_demo")
    assert r.status == "ok"
    assert r.source == "engagement_index"
    assert "bbci_recon" in r.recon_path


def test_resolve_missing_recon():
    r = resolve_recon(repo_root=ROOT, recon_artifact="does/not/exist.json")
    assert r.status == "blocked"
    assert r.reason == "missing_or_invalid_recon"


def test_resolve_unknown_engagement():
    r = resolve_recon(repo_root=ROOT, engagement_id="eng_unknown_xyz")
    assert r.status == "blocked"
    assert r.reason == "unknown_engagement_id"


def test_free_registry_loads():
    models, max_fb = load_free_registry(ROOT / "config/models/free_registry.yaml")
    assert models
    assert max_fb >= 1
    assert all(m.free for m in models)


def test_mock_profile_no_key():
    res = select_provider(model_profile="mock", allow_mock=True)
    assert res.status == "ok"
    assert res.model_id == "mock-lite"


def test_require_key_blocks_without_secret(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    res = select_provider(model_profile="free", require_key=True, allow_mock=False)
    assert res.status == "blocked"
    assert res.reason == "missing_llm_api_key"


def test_cli_engagement_analysis_mock(tmp_path):
    from agent_lite.cli import main

    code = main(
        [
            "--engagement-id",
            "eng_demo",
            "--repo-root",
            str(ROOT),
            "--model-profile",
            "mock",
            "--mode",
            "analysis",
            "--scenario",
            "positive",
            "--artifacts-dir",
            str(tmp_path / "art"),
        ]
    )
    assert code == 0
    art = tmp_path / "art" / "eng_demo"
    assert (art / "final-report.md").exists() or (art / "model_trace.json").exists()
    # model_trace written by CLI
    assert (art / "model_trace.json").exists()
    trace = json.loads((art / "model_trace.json").read_text())
    assert "recon_resolution" in trace
