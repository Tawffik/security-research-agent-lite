from pathlib import Path
import json

from agent_lite.runtime.live_http import pick_base_url, pick_object_path


def test_pick_from_composed(tmp_path):
    recon = tmp_path / "bbci_composed_recon.json"
    recon.write_text(
        json.dumps(
            {
                "primary_host": "example.test",
                "hosts": ["example.test"],
                "endpoints": [
                    {"method": "GET", "path": "/api/users/1", "host": "example.test"},
                ],
            }
        )
    )
    assert pick_base_url(recon) == "https://example.test"
    assert "/api/users/1" in pick_object_path(recon)
