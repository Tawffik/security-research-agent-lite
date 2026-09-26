"""Opportunity layer: recon signals → research investment sites (not findings)."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from agent_lite.target.context import TargetContext

_PATH_ID_PATTERNS = [
    re.compile(r"\{[^}]*id[^}]*\}", re.I),
    re.compile(r"/:([A-Za-z_][A-Za-z0-9_]*id)", re.I),
    re.compile(r"/\{([A-Za-z_][A-Za-z0-9_]*)\}"),
]
_QUERY_ID_KEYS = (
    "user_id", "userid", "object_id", "resource_id", "order_id",
    "account_id", "accountId", "id",
)


def detect_object_reference(path: str, parameters: Optional[list] = None) -> bool:
    path = path or ""
    for pat in _PATH_ID_PATTERNS:
        if pat.search(path):
            return True
    params = [str(p).lower() for p in (parameters or [])]
    for k in _QUERY_ID_KEYS:
        if k.lower() in params:
            return True
    if "?" in path:
        q = path.split("?", 1)[1].lower()
        if any(k.lower() in q for k in _QUERY_ID_KEYS):
            return True
    return False


@dataclass
class Opportunity:
    opportunity_id: str
    target: str
    signals: list = field(default_factory=list)
    security_property: str = ""
    related_assets: list = field(default_factory=list)
    related_endpoints: list = field(default_factory=list)
    related_identities: list = field(default_factory=list)
    related_resources: list = field(default_factory=list)
    provenance: str = "opportunity_engine"
    priority_reason: str = ""
    status: str = "open"
    invariant_id: str = "INV-AUTHZ-001"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class OpportunityEngine:
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self._n = 0

    def extract(self, ctx: TargetContext) -> list:
        opps = []
        identities = [str(a.get("actor_id") or a.get("name") or "") for a in ctx.actors]
        resources = [str(r.get("name") or r.get("resource_id") or "") for r in ctx.resources]
        multi = len([i for i in identities if i]) >= 2

        for ep in ctx.endpoints:
            method = str(ep.get("method") or "GET")
            path = str(ep.get("path") or "")
            params = list(ep.get("parameters") or [])
            if not detect_object_reference(path, params):
                continue
            signals = ["object_reference"]
            if multi:
                signals.append("multi_identity")
            if resources:
                signals.append("resource_model_present")
            if method.upper() in ("GET", "HEAD"):
                signals.append("read_method")
            else:
                signals.append("mutate_method")

            self._n += 1
            opps.append(
                Opportunity(
                    opportunity_id=f"OPP-{self._n:03d}",
                    target=f"{method} {path} @ {ctx.primary_host}",
                    signals=signals,
                    security_property="Object-level authorization binds actor to resource",
                    related_assets=[ctx.primary_host],
                    related_endpoints=[f"{method} {path}"],
                    related_identities=identities,
                    related_resources=resources,
                    priority_reason=(
                        "Object-keyed endpoint with multiple identities — candidate for INV-AUTHZ-001"
                        if multi
                        else "Object-keyed endpoint — limited without second identity"
                    ),
                    status="open" if multi else "blocked_insufficient_identity",
                )
            )
        return opps
