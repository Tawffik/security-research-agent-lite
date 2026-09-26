"""BugBountyCI → Normalized recon. Does not implement recon itself."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Union


@dataclass
class NormalizedRecon:
    primary_host: str
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    actors: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    notes: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReconAdapter:
    def adapt(self, raw: dict[str, Any]) -> NormalizedRecon:
        if not isinstance(raw, dict):
            raise ValueError("recon artifact must be a JSON object")

        data = dict(raw)
        for key in ("recon", "result", "data", "artifact"):
            if key in data and isinstance(data[key], dict) and "primary_host" not in data:
                data = {**data[key], **{k: v for k, v in data.items() if k != key}}
                break

        host = str(
            data.get("primary_host")
            or data.get("host")
            or data.get("target")
            or data.get("domain")
            or ""
        ).strip()
        if not host and isinstance(data.get("domains"), list) and data["domains"]:
            host = str(data["domains"][0])
        if not host:
            raise ValueError("primary_host/host/target required")

        endpoints: list[dict[str, Any]] = []
        for item in data.get("endpoints") or data.get("urls") or []:
            if isinstance(item, str):
                endpoints.append({"method": "GET", "path": item if item.startswith("/") else f"/{item}"})
            elif isinstance(item, dict):
                path = str(item.get("path") or item.get("url") or "")
                method = str(item.get("method") or "GET").upper()
                if path.startswith("http"):
                    from urllib.parse import urlparse
                    path = urlparse(path).path or "/"
                if path:
                    endpoints.append({"method": method, "path": path})

        actors = []
        for a in data.get("actors") or data.get("identities") or []:
            if isinstance(a, str):
                actors.append({"actor_id": a, "name": a, "type": "user"})
            elif isinstance(a, dict):
                aid = str(a.get("actor_id") or a.get("id") or a.get("name") or "")
                if aid:
                    actors.append({"actor_id": aid, "name": str(a.get("name") or aid), "type": str(a.get("type") or "user")})

        resources = []
        for r in data.get("resources") or []:
            if isinstance(r, dict):
                name = str(r.get("name") or r.get("id") or "")
                if name:
                    resources.append({
                        "name": name,
                        "type": str(r.get("type") or "object"),
                        "owner_actor_id": r.get("owner_actor_id") or r.get("owner"),
                    })

        return NormalizedRecon(
            primary_host=host,
            endpoints=endpoints,
            actors=actors,
            resources=resources,
            technologies=[str(t) for t in (data.get("technologies") or [])],
            notes=str(data.get("notes") or ""),
            provenance={"adapter": "agent_lite.recon", "contract": "bbci_recon_v1"},
        )

    def from_file(self, path: Union[str, Path]) -> NormalizedRecon:
        path = Path(path)
        with path.open(encoding="utf-8") as f:
            return self.adapt(json.load(f))
