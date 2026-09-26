from pathlib import Path

from agent_lite.ledger.sqlite_ledger import SQLiteLedger


def test_checkpoint_roundtrip(tmp_path):
    db = tmp_path / "ledger.db"
    led = SQLiteLedger(db, "run1", "eng1")
    led.record("step_a", "ok")
    cp = led.checkpoint("cp1", "step_a", {"n": 1})
    loaded = led.load_checkpoint("cp1")
    assert loaded is not None
    assert loaded.payload["n"] == 1
    assert loaded.last_completed_step == "step_a"
