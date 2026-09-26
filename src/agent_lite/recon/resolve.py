"""Resolve recon path from engagement id or explicit artifact — no recon engine."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

import yaml


@dataclass
class ReconResolution:
    status: str  # ok | blocked
    recon_path: str = ""
    scope_path: str = "config/scope.yaml"
    engagement_id: str = ""
    reason: str = ""
    source: str = ""  # explicit | engagement_index

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "recon_path": self.recon_path,
            "scope_path": self.scope_path,
            "engagement_id": self.engagement_id,
            "reason": self.reason,
            "source": self.source,
        }


def resolve_recon(
    *,
    repo_root: Union[str, Path] = ".",
    engagement_id: str = "",
    recon_artifact: str = "",
    index_path: str = "config/engagements/index.yaml",
) -> ReconResolution:
    root = Path(repo_root)
    if recon_artifact:
        path = Path(recon_artifact)
        if not path.is_absolute():
            path = root / path
        if not path.is_file():
            return ReconResolution(
                status="blocked",
                engagement_id=engagement_id,
                reason="missing_or_invalid_recon",
                source="explicit",
            )
        return ReconResolution(
            status="ok",
            recon_path=str(path),
            engagement_id=engagement_id or "eng_explicit",
            source="explicit",
        )

    if not engagement_id:
        return ReconResolution(status="blocked", reason="missing_or_invalid_recon")

    idx = root / index_path
    if not idx.is_file():
        return ReconResolution(
            status="blocked",
            engagement_id=engagement_id,
            reason="missing_engagement_index",
        )
    data = yaml.safe_load(idx.read_text(encoding="utf-8")) or {}
    eng = (data.get("engagements") or {}).get(engagement_id)
    if not isinstance(eng, dict):
        return ReconResolution(
            status="blocked",
            engagement_id=engagement_id,
            reason="unknown_engagement_id",
        )
    recon = str(eng.get("recon") or "")
    scope = str(eng.get("scope") or "config/scope.yaml")
    path = root / recon if recon and not Path(recon).is_absolute() else Path(recon)
    if not recon or not path.is_file():
        return ReconResolution(
            status="blocked",
            engagement_id=engagement_id,
            reason="missing_or_invalid_recon",
            source="engagement_index",
        )
    return ReconResolution(
        status="ok",
        recon_path=str(path),
        scope_path=str(root / scope) if not Path(scope).is_absolute() else scope,
        engagement_id=engagement_id,
        source="engagement_index",
    )
