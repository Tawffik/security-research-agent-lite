
"""Minimal live HTTP bootstrap from recon + env session secrets."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from agent_lite.budget.guard import BudgetGuard
from agent_lite.http.executor import HttpExecutor
from agent_lite.identity.resolver import Identity, IdentityResolver
from agent_lite.recon.adapter import ReconAdapter
from agent_lite.scope.guard import ScopeGuard


def pick_object_path(recon_path: str | Path, override: str = "") -> str:
    if override and override != "/api/orders/1001":
        return override if override.startswith("/") else f"/{override}"
    if override == "/api/orders/1001":
        # default lab path — try recon first
        pass
    n = ReconAdapter().from_file(recon_path)
    for ep in n.endpoints:
        path = str(ep.get("path") or "")
        if not path or path == "/":
            continue
        # prefer paths that look like object access
        if any(x in path for x in ("{", "id", "user", "order", "account", "profile", "api")):
            return path if path.startswith("/") else f"/{path}"
    for ep in n.endpoints:
        path = str(ep.get("path") or "")
        if path and path != "/":
            return path if path.startswith("/") else f"/{path}"
    return override or "/api/orders/1001"


def pick_base_url(recon_path: str | Path, override: str = "") -> str:
    if override:
        return override.rstrip("/")
    n = ReconAdapter().from_file(recon_path)
    host = n.primary_host or (n.hosts[0] if n.hosts else "")
    if not host:
        return ""
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    # prefer https
    return f"https://{host}".rstrip("/")


def build_executor_from_env(
    *,
    scope_path: str | Path,
    budget_path: str | Path = "config/budget.yaml",
    owner_id: str = "user_a",
    non_owner_id: str = "user_b",
) -> tuple[Optional[HttpExecutor], dict[str, Any]]:
    """
    Identity secrets (any of):
      TEST_USER_A_TOKEN / TEST_USER_A_COOKIE / USER_A_TOKEN / USER_A_COOKIE
      same for B / user_b
    """
    meta: dict[str, Any] = {"owner": owner_id, "non_owner": non_owner_id}
    idr = IdentityResolver()
    for iid, prefixes in (
        (owner_id, ["TEST_USER_A", "USER_A", "TEST_IDENTITY_A", owner_id.upper()]),
        (non_owner_id, ["TEST_USER_B", "USER_B", "TEST_IDENTITY_B", non_owner_id.upper()]),
    ):
        ref = ""
        for pref in prefixes:
            if os.environ.get(f"{pref}_TOKEN") or os.environ.get(f"{pref}_COOKIE") or os.environ.get(f"{pref}_ACCESS_TOKEN"):
                ref = pref
                break
        if not ref:
            meta["missing_identity"] = iid
            return None, {**meta, "status": "blocked", "reason": f"missing_session_secret_for_{iid}"}
        idr.register(Identity(identity_id=iid, credential_ref=ref, role="user"))
        # ensure resolve works: IdentityResolver expects env PREFIX_TOKEN
        meta[f"{iid}_ref"] = ref

    scope = ScopeGuard.from_file(scope_path)
    budget = BudgetGuard.from_file(Path(budget_path)) if Path(budget_path).is_file() else BudgetGuard.from_file(Path("config/budget.yaml"))
    ex = HttpExecutor(scope=scope, budget=budget, identities=idr, allowed_schemes={"http", "https"})
    return ex, {**meta, "status": "ok"}
