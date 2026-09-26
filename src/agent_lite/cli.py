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
        choices=["synthetic", "http", "engagement"],
        default="synthetic",
        help=(
            "synthetic = LabScenario (default); "
            "http = HttpExecutor with explicit base URL; "
            "engagement = PortSwiggerAdapter.validate → run_from_engagement"
        ),
    )
    p.add_argument(
        "--scenario",
        choices=["positive", "secure", "public", "shared", "ambiguous"],
        default="positive",
        help="Synthetic lab scenario (mode=synthetic only)",
    )
    p.add_argument("--artifacts-dir", default="artifacts")
    # HTTP mode options
    p.add_argument("--http-base-url", default="", help="Base URL for mode=http")
    p.add_argument("--http-object-path", default="/api/orders/1001")
    p.add_argument("--http-owner", default="user_a")
    p.add_argument("--http-non-owner", default="user_b")
    p.add_argument(
        "--http-engagement",
        default="",
        help="Optional engagement YAML for mode=http executor config",
    )
    # Engagement mode (T4 path)
    p.add_argument(
        "--engagement",
        default="",
        help="Engagement YAML path (required for mode=engagement)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="mode=engagement: validate authorization only; no HTTP",
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
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    if args.mode == "engagement":
        from agent_lite.http.engagement import load_engagement
        from agent_lite.http.executor import HttpExecutor
        from agent_lite.labs.portswigger import PortSwiggerAdapter

        if not args.engagement:
            print("error: --engagement required for mode=engagement", file=sys.stderr)
            return 2
        eng = load_engagement(args.engagement)
        adapter = PortSwiggerAdapter(eng)
        gate = adapter.validate()
        if args.dry_run:
            print(
                json.dumps(
                    {
                        "dry_run": True,
                        "engagement_id": eng.engagement_id,
                        "authorized": eng.authorized,
                        "validation": gate.to_dict(),
                        "object_path": eng.object_path,
                        "base_url": eng.base_url,
                        "note": "no HTTP performed",
                    },
                    indent=2,
                )
            )
            return 0 if gate.status == "READY" else 3

        # Live path: still uses run_from_engagement → run_http (no parallel verdict)
        idr = eng.build_identities()
        # Sessions resolved from env (TEST_USER_*_COOKIE / _TOKEN) inside executor
        executor = HttpExecutor(
            scope=eng.build_scope(),
            budget=eng.build_budget(),
            identities=idr,
            allowed_schemes=set(eng.allowed_schemes),
        )
        result = pipe.run_from_engagement(
            args.recon, engagement=eng, executor=executor
        )
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    # mode=http
    if not args.http_base_url:
        print("error: --http-base-url required for mode=http", file=sys.stderr)
        return 2
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
            idr.register(Identity(identity_id=iid, credential_ref=f"TEST_{iid.upper()}"))
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
