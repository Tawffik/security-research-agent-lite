"""Traceable evidence with polarity (positive/negative/neutral)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class EvidenceRecord:
    evidence_id: str
    engagement_id: str
    target: str
    source: str
    action: str
    timestamp: str
    observation: str
    artifact_ref: str = ""
    content_hash: str = ""
    hypothesis_id: str = ""
    finding_id: str = ""
    provenance: str = "lab"
    polarity: str = "neutral"  # positive | negative | neutral

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EvidenceStore:
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self._n = 0
        self._items: list[EvidenceRecord] = []

    def add(
        self,
        *,
        target: str,
        source: str,
        action: str,
        observation: str,
        polarity: str = "neutral",
        hypothesis_id: str = "",
        finding_id: str = "",
        artifact_ref: str = "",
        provenance: str = "lab",
    ) -> EvidenceRecord:
        self._n += 1
        body = observation or ""
        h = hashlib.sha256(body.encode()).hexdigest()[:16]
        rec = EvidenceRecord(
            evidence_id=f"E-{self._n:03d}",
            engagement_id=self.engagement_id,
            target=target,
            source=source,
            action=action,
            timestamp=datetime.now(timezone.utc).isoformat(),
            observation=body[:8000],
            artifact_ref=artifact_ref,
            content_hash=h,
            hypothesis_id=hypothesis_id,
            finding_id=finding_id,
            provenance=provenance,
            polarity=polarity,
        )
        self._items.append(rec)
        return rec

    def list_all(self) -> list[EvidenceRecord]:
        return list(self._items)

    def ids(self) -> list[str]:
        return [e.evidence_id for e in self._items]

    def write_jsonl(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            for e in self._items:
                f.write(json.dumps(e.to_dict()) + "\n")
        return path
