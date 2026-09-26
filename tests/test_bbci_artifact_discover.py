"""BBCI artifact discovery — offline, no network."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from agent_lite.recon.bbci_artifact import discover_recon_json, extract_zip


def test_discover_prefers_recon_shaped_json(tmp_path):
    extract = tmp_path / "ex"
    extract.mkdir()
    (extract / "noise.txt").write_text("x")
    (extract / "misc.json").write_text(json.dumps({"hello": 1}))
    good = extract / "results" / "recon.json"
    good.parent.mkdir(parents=True)
    good.write_text(
        json.dumps(
            {
                "primary_host": "example.test",
                "hosts": ["example.test"],
                "endpoints": [{"method": "GET", "path": "/api/x"}],
                "urls": ["https://example.test/api/x"],
            }
        )
    )
    path, cands = discover_recon_json(extract)
    assert path is not None
    assert path.name == "recon.json"
    assert any("recon.json" in c for c in cands)


def test_extract_and_discover_from_zip(tmp_path):
    zpath = tmp_path / "a.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr(
            "out/hosts_recon.json",
            json.dumps({"host": "acme.test", "endpoints": [{"path": "/a"}]}),
        )
    dest = tmp_path / "out"
    extract_zip(zpath, dest)
    path, _ = discover_recon_json(dest)
    assert path is not None
    assert "acme.test" in path.read_text()


def test_missing_token_blocked():
    from agent_lite.recon.bbci_artifact import resolve_bbci_artifact

    r = resolve_bbci_artifact(run_id="1", token="")
    assert r.status == "blocked"
    assert "token" in r.reason
