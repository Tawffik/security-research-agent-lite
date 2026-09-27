"""BugBountyCI → Normalized recon. Does not implement recon itself."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Union
from urllib.parse import urlparse, parse_qs


@dataclass
class NormalizedRecon:
    primary_host: str
    hosts: list[str] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    actors: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    notes: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)
    schema_version: str = "bbci_recon_v1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _host_token(value: str) -> str:
    """Normalize host strings that may be full URLs."""
    s = (value or "").strip().lower()
    if not s:
        return ""
    if s.startswith("http://") or s.startswith("https://"):
        p = urlparse(s)
        return (p.hostname or "").lower()
    # strip path if accidental
    if "/" in s:
        s = s.split("/", 1)[0]
    if ":" in s and not s.count(":") > 1:
        # host:port
        return s.split(":", 1)[0]
    return s


def _unwrap(raw: dict[str, Any]) -> dict[str, Any]:
    data = dict(raw)
    for key in ("recon", "result", "data", "artifact", "bbci", "bundle"):
        nested = data.get(key)
        if isinstance(nested, dict) and "primary_host" not in data:
            merged = {**nested}
            for k, v in data.items():
                if k != key and k not in merged:
                    merged[k] = v
            data = merged
            break
    return data


def _parse_endpoint(item: Any) -> dict[str, Any] | None:
    if isinstance(item, str):
        s = item.strip()
        if not s:
            return None
        if s.startswith("http"):
            p = urlparse(s)
            path = p.path or "/"
            params = {k: (v[0] if len(v) == 1 else v) for k, v in parse_qs(p.query).items()}
            return {
                "method": "GET",
                "path": path,
                "url": s,
                "host": p.hostname or "",
                "parameters": params,
            }
        path = s if s.startswith("/") else f"/{s}"
        return {"method": "GET", "path": path, "parameters": {}}

    if not isinstance(item, dict):
        return None

    method = str(item.get("method") or "GET").upper()
    path = str(item.get("path") or "")
    url = str(item.get("url") or item.get("uri") or "")
    host = str(item.get("host") or "")
    params: dict[str, Any] = {}

    if isinstance(item.get("parameters"), dict):
        params = dict(item["parameters"])
    elif isinstance(item.get("params"), dict):
        params = dict(item["params"])
    elif isinstance(item.get("query"), dict):
        params = dict(item["query"])

    if url.startswith("http"):
        p = urlparse(url)
        path = path or p.path or "/"
        host = host or (p.hostname or "")
        if not params and p.query:
            params = {k: (v[0] if len(v) == 1 else v) for k, v in parse_qs(p.query).items()}
    elif path.startswith("http"):
        p = urlparse(path)
        path = p.path or "/"
        host = host or (p.hostname or "")
        if not params and p.query:
            params = {k: (v[0] if len(v) == 1 else v) for k, v in parse_qs(p.query).items()}

    if not path and not url:
        return None
    if not path:
        path = "/"
    if not path.startswith("/") and not path.startswith("http"):
        path = f"/{path}"

    out: dict[str, Any] = {"method": method, "path": path, "parameters": params}
    if url:
        out["url"] = url
    if host:
        out["host"] = host
    if item.get("technology"):
        out["technology"] = item["technology"]
    if item.get("status") is not None:
        out["status"] = item["status"]
    return out


class ReconAdapter:
    """Normalize BugBountyCI-shaped recon. Never invents fields. Never runs recon."""

    def adapt(self, raw: dict[str, Any]) -> NormalizedRecon:
        if not isinstance(raw, dict):
            raise ValueError("recon artifact must be a JSON object")

        data = _unwrap(raw)
        schema = str(data.get("schema_version") or data.get("version") or "bbci_recon_v1")

        hosts: list[str] = []
        for h in data.get("hosts") or data.get("domains") or []:
            if isinstance(h, str) and h.strip():
                tok = _host_token(h)
                if tok:
                    hosts.append(tok)
            elif isinstance(h, dict):
                name = str(h.get("host") or h.get("name") or h.get("domain") or h.get("url") or "").strip()
                tok = _host_token(name)
                if tok:
                    hosts.append(tok)

        host = str(
            data.get("primary_host")
            or data.get("host")
            or data.get("target")
            or data.get("domain")
            or (hosts[0] if hosts else "")
            or ""
        ).strip()
        host_l = _host_token(host)
        if not host_l:
            raise ValueError("primary_host/host/target required")
        # de-dupe hosts preserve order
        seen_h: set[str] = set()
        hosts_u: list[str] = []
        for h in hosts:
            if h and h not in seen_h:
                seen_h.add(h)
                hosts_u.append(h)
        hosts = hosts_u
        if host_l not in hosts:
            hosts.insert(0, host_l)

        endpoints: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for src_key in ("endpoints", "urls", "paths", "api_endpoints"):
            for item in data.get(src_key) or []:
                ep = _parse_endpoint(item)
                if not ep:
                    continue
                key = (ep["method"], ep["path"])
                if key in seen:
                    continue
                seen.add(key)
                endpoints.append(ep)

        actors: list[dict[str, Any]] = []
        for a in data.get("actors") or data.get("identities") or data.get("users") or []:
            if isinstance(a, str):
                actors.append({"actor_id": a, "name": a, "type": "user"})
            elif isinstance(a, dict):
                aid = str(a.get("actor_id") or a.get("id") or a.get("name") or "").strip()
                if aid:
                    actors.append(
                        {
                            "actor_id": aid,
                            "name": str(a.get("name") or aid),
                            "type": str(a.get("type") or "user"),
                        }
                    )

        resources: list[dict[str, Any]] = []
        for r in data.get("resources") or data.get("objects") or []:
            if isinstance(r, dict):
                name = str(r.get("name") or r.get("id") or "").strip()
                if name:
                    resources.append(
                        {
                            "name": name,
                            "type": str(r.get("type") or "object"),
                            "owner_actor_id": r.get("owner_actor_id") or r.get("owner"),
                        }
                    )

        technologies: list[str] = []
        for t in data.get("technologies") or data.get("tech") or data.get("stack") or []:
            if isinstance(t, str) and t.strip():
                technologies.append(t.strip())
            elif isinstance(t, dict):
                name = str(t.get("name") or t.get("technology") or "").strip()
                if name:
                    technologies.append(name)

        observations: list[dict[str, Any]] = []
        for obs in data.get("observations") or data.get("http_observations") or data.get("http") or []:
            if not isinstance(obs, dict):
                continue
            observations.append(
                {
                    "method": str(obs.get("method") or "GET").upper(),
                    "url": str(obs.get("url") or ""),
                    "path": str(obs.get("path") or ""),
                    "host": str(obs.get("host") or ""),
                    "status": obs.get("status") or obs.get("status_code"),
                    "headers": obs.get("headers") if isinstance(obs.get("headers"), dict) else {},
                    "note": str(obs.get("note") or obs.get("notes") or ""),
                    "has_body": bool(obs.get("body") or obs.get("response_body")),
                }
            )

        return NormalizedRecon(
            primary_host=host_l,
            hosts=hosts,
            endpoints=endpoints,
            actors=actors,
            resources=resources,
            technologies=technologies,
            observations=observations,
            notes=str(data.get("notes") or data.get("description") or ""),
            provenance={
                "adapter": "agent_lite.recon",
                "contract": schema,
                "source_keys": sorted(str(k) for k in data.keys()),
            },
            schema_version=schema,
        )

    def from_file(self, path: Union[str, Path]) -> NormalizedRecon:
        path = Path(path)
        with path.open(encoding="utf-8") as f:
            return self.adapt(json.load(f))
