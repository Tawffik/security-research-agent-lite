"""Simple SQLite-ish JSON ledger for resume (file-based for MVP)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class LedgerEntry:
    step: str
    status: str
    detail: str = ""
    timestamp: str = ""
    data: dict[str, Any] = field(default_factory=dict)


class Ledger:
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self.entries: list[LedgerEntry] = []

    def record(self, step: str, status: str, detail: str = "", **data: Any) -> None:
        self.entries.append(
            LedgerEntry(
                step=step,
                status=status,
                detail=detail,
                timestamp=datetime.now(timezone.utc).isoformat(),
                data=data,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "entries": [asdict(e) for e in self.entries],
        }

    def write(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))
        return path
