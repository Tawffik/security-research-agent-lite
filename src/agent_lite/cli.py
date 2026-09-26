"""CLI entrypoint for agent-lite."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_lite.runtime.pipeline import ResearchPipeline
from agent_lite.skills.authz_bola import (
    bola_ambiguous_status_only,
    bola_negative_public,
    bola_negative_secure,
    bola_negative_shared,
    bola_positive_lab,
)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Security Research Agent Lite")
    p.add_argument("--recon", required=True)
    p.add_argument("--scope", default="config/scope.yaml")
    p.add_argument("--engagement-id", default="eng_cli")
    p.add_argument(
        "--mode",
        choices=["synthetic", "http"],
        default="synthetic",
        help="synthetic = LabScenario fixtures (default); http = HttpExecutor path",
    )
    p.add_argument(
        "--scenario",
        choices=["positive", "secure", "public", "shared", "ambiguous"],
        default="positive",
        help="Synthetic lab scenario (mode=synthetic only)",
    )
    p.add_argument("--artifacts-dir", default="artifacts")
    # HTTP mode options (local/authorized targets only; no implicit live)
    p.add_argument("--http-base-url", default="", help="Base URL for mode=http")
    p.add_argument("--http-object-path", default="/api/orders/1001")
    p.add_argument("--http-owner", default="user_a")
    p.add_argument("--http-non-owner", default="user_b")
    p.add_argument(
        "--http-engagement",
        default="",
        help="Optional engagement YAML (scope/budget/identities) for mode=http",
    )
    args = p.parse_args(argv)

    pipe = ResearchPipeline(
        engagement_id=args.engagement_id,
        scope_path=args.scope,
        artifacts_dir=Path(args.artifacts_dir),
    )

    if args.mode == "synthetic":
        scenarios = {
            "positive": bola_positive_lab(),
            "secure": bola_negative_secure(),
            "public": bola_negative_public(),
            "shared": bola_negative_shared(),
            "ambiguous": bola_ambiguous_status_only(),
        }
        result = pipe.run(args.recon, scenario=scenarios[args.scenario])
    else:
        if not args.http_base_url:
            print("error: --http-base-url required for mode=http", file=sys.stderr)
            return 2
        # Build executor from scope + optional engagement; sessions via env credential_ref
        from agent_lite.budget.guard import BudgetGuard
        from agent_lite.http.engagement import load_engagement
        from agent_lite.http.executor import HttpExecutor
        from agent_lite.identity.resolver import Identity, IdentityResolver
        from agent_lite.scope.guard import ScopeGuard

        scope = ScopeGuard.from_file(args.scope)
        budget = BudgetGuard.from_file(Path("config/budget.yaml"))
        idr = IdentityResolver()
        if args.http_engagement:
            eng = load_engagement(args.http_engagement)
            scope = eng.build_scope()
            budget = eng.build_budget()
            idr = eng.build_identities()
        else:
            for iid in (args.http_owner, args.http_non_owner):
                idr.register(
                    Identity(identity_id=iid, credential_ref=f"TEST_{iid.upper()}")
                )
        executor = HttpExecutor(
            scope=scope,
            budget=budget,
            identities=idr,
            allowed_schemes={"http", "https"},
        )
        result = pipe.run_http(
            args.recon,
            base_url=args.http_base_url,
            object_path=args.http_object_path,
            executor=executor,
            owner_identity=args.http_owner,
            non_owner_identity=args.http_non_owner,
        )

    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
