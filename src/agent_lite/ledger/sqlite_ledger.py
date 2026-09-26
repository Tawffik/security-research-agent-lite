"""SQLite ledger + simple checkpoint/resume."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class Checkpoint:
    run_id: str
    checkpoint_id: str
    last_completed_step: str
    payload: dict

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "checkpoint_id": self.checkpoint_id,
            "last_completed_step": self.last_completed_step,
            "payload": self.payload,
        }


class SQLiteLedger:
    def __init__(self, path: Path, run_id: str, engagement_id: str):
        self.path = Path(path)
        self.run_id = run_id
        self.engagement_id = engagement_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.path))

    def _init(self) -> None:
        with self._conn() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                  run_id TEXT PRIMARY KEY,
                  engagement_id TEXT,
                  started_at TEXT,
                  status TEXT
                );
                CREATE TABLE IF NOT EXISTS steps (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  run_id TEXT,
                  step TEXT,
                  status TEXT,
                  detail TEXT,
                  ts TEXT
                );
                CREATE TABLE IF NOT EXISTS checkpoints (
                  checkpoint_id TEXT PRIMARY KEY,
                  run_id TEXT,
                  last_completed_step TEXT,
                  payload_json TEXT,
                  ts TEXT
                );
                """
            )
            c.execute(
                "INSERT OR REPLACE INTO runs(run_id, engagement_id, started_at, status) VALUES (?,?,?,?)",
                (self.run_id, self.engagement_id, datetime.now(timezone.utc).isoformat(), "running"),
            )

    def record(self, step: str, status: str, detail: str = "") -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO steps(run_id, step, status, detail, ts) VALUES (?,?,?,?,?)",
                (self.run_id, step, status, detail, datetime.now(timezone.utc).isoformat()),
            )

    def checkpoint(self, checkpoint_id: str, last_step: str, payload: dict) -> Checkpoint:
        cp = Checkpoint(self.run_id, checkpoint_id, last_step, payload)
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO checkpoints(checkpoint_id, run_id, last_completed_step, payload_json, ts) VALUES (?,?,?,?,?)",
                (
                    cp.checkpoint_id,
                    cp.run_id,
                    cp.last_completed_step,
                    json.dumps(payload),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        return cp

    def load_checkpoint(self, checkpoint_id: str) -> Optional[Checkpoint]:
        with self._conn() as c:
            row = c.execute(
                "SELECT checkpoint_id, run_id, last_completed_step, payload_json FROM checkpoints WHERE checkpoint_id=?",
                (checkpoint_id,),
            ).fetchone()
        if not row:
            return None
        return Checkpoint(row[1], row[0], row[2], json.loads(row[3] or "{}"))

    def finish(self, status: str = "completed") -> None:
        with self._conn() as c:
            c.execute("UPDATE runs SET status=? WHERE run_id=?", (status, self.run_id))
