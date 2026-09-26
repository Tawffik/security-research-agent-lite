"""Minimal extensible target context (not full Target Graph)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from agent_lite.recon.adapter import NormalizedRecon


@dataclass
class TargetContext:
    engagement_id: str
    primary_host: str
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    actors: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def multi_identity(self) -> bool:
        return len(self.actors) >= 2

    @property
    def object_endpoints(self) -> list[dict[str, Any]]:
        out = []
        for ep in self.endpoints:
            path = str(ep.get("path") or "")
            if "{id}" in path or "{user" in path.lower() or "id" in path.lower():
                out.append(ep)
        return out


def build_target_context(engagement_id: str, recon: NormalizedRecon) -> TargetContext:
    return TargetContext(
        engagement_id=engagement_id,
        primary_host=recon.primary_host,
        endpoints=list(recon.endpoints),
        actors=list(recon.actors),
        resources=list(recon.resources),
        technologies=list(recon.technologies),
        hosts=list(getattr(recon, "hosts", None) or [recon.primary_host]),
        observations=list(getattr(recon, "observations", None) or []),
        notes=recon.notes,
    )
