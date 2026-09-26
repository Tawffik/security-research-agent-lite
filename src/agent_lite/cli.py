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
        choices=["synthetic", "http", "engagement", "analysis"],
        default="synthetic",
        help="synthetic|http|engagement|analysis (LLM+recon, no live HTTP by default)",
    )
    p.add_argument(
        "--scenario",
        choices=["positive", "secure", "public", "shared", "ambiguous"],
        default="positive",
        help="Synthetic lab scenario (mode=synthetic)",
    )
    p.add_argument("--artifacts-dir", default="artifacts")
    p.add_argument("--http-base-url", default="")
    p.add_argument("--http-object-path", default="/api/orders/1001")
    p.add_argument("--http-owner", default="user_a")
    p.add_argument("--http-non-owner", default="user_b")
    p.add_argument("--http-engagement", default="")
    p.add_argument("--engagement", default="", help="Engagement YAML for mode=engagement")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--use-llm", action="store_true", help="Enable LLM hypothesis proposals")
    p.add_argument(
        "--require-llm",
        action="store_true",
        help="Fail if LLM_API_KEY missing (no mock)",
    )
    args = p.parse_args(argv)

    llm = None
    llm_status = "llm_disabled"
    if args.use_llm or args.mode == "analysis" or args.require_llm:
        from agent_lite.llm.provider import create_llm_provider

        llm, llm_status = create_llm_provider(
            require_key=args.require_llm,
            allow_mock=not args.require_llm,
        )
        if args.require_llm and llm is None:
            print(
                json.dumps(
                    {
                        "status": "BLOCKED",
                        "reason": "missing_llm_api_key",
                        "message": "Set repository secret LLM_API_KEY (and optional LLM_BASE_URL, LLM_MODEL)",
                    },
                    indent=2,
                )
            )
            return 4

    pipe = ResearchPipeline(
        
        engagement_id=args.engagement_id,
        scope_path=args.scope,
        artifacts_dir=Path(args.artifacts_dir),
        llm_provider=llm,
        require_llm=args.require_llm,
    )

    if args.mode in ("synthetic", "analysis"):
        scenarios = {
            "positive": bola_positive_lab(),
            "secure": bola_negative_secure(),
            "public": bola_negative_public(),
            "shared": bola_negative_shared(),
            "ambiguous": bola_ambiguous_status_only(),
        }
        # analysis uses secure scenario by default unless scenario set — still runs BOLA loop on recon
        scen = scenarios.get(args.scenario, bola_positive_lab())
        if args.mode == "analysis":
            # Prefer positive local discrimination when multi-identity present; still evidence-driven
            scen = scenarios.get(args.scenario, bola_positive_lab())
        result = pipe.run(args.recon, scenario=scen)
        out = result.to_dict()
        out["llm_status"] = llm_status
        out["llm_notes"] = list(getattr(pipe, "llm_notes", []) or [])
        print(json.dumps(out, indent=2))
        return 0

    if args.mode == "engagement":
        from agent_lite.http.engagement import load_engagement
        from agent_lite.http.executor import HttpExecutor
        from agent_lite.labs.portswigger import PortSwiggerAdapter

        if not args.engagement:
            print("error: --engagement required", file=sys.stderr)
            return 2
        eng = load_engagement(args.engagement)
        adapter = PortSwiggerAdapter(eng)
        gate = adapter.validate()
        if args.dry_run:
            print(json.dumps({"dry_run": True, "validation": gate.to_dict()}, indent=2))
            return 0 if gate.status == "READY" else 3
        idr = eng.build_identities()
        executor = HttpExecutor(
            scope=eng.build_scope(),
            budget=eng.build_budget(),
            identities=idr,
            allowed_schemes=set(eng.allowed_schemes),
        )
        result = pipe.run_from_engagement(args.recon, engagement=eng, executor=executor)
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    # http
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
        scope=scope, budget=budget, identities=idr, allowed_schemes={"http", "https"}
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
