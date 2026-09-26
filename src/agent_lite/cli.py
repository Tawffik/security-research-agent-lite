"""CLI entrypoint for agent-lite — mobile/GHA friendly."""

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
    p.add_argument("--recon", default="", help="Explicit recon JSON path")
    p.add_argument("--engagement-id", default="eng_demo")
    p.add_argument("--scope", default="")
    p.add_argument(
        "--mode",
        choices=["synthetic", "http", "engagement", "analysis"],
        default="analysis",
    )
    p.add_argument(
        "--scenario",
        choices=["positive", "secure", "public", "shared", "ambiguous"],
        default="positive",
    )
    p.add_argument("--artifacts-dir", default="artifacts")
    p.add_argument("--http-base-url", default="")
    p.add_argument("--http-object-path", default="/api/orders/1001")
    p.add_argument("--http-owner", default="user_a")
    p.add_argument("--http-non-owner", default="user_b")
    p.add_argument("--http-engagement", default="")
    p.add_argument("--engagement", default="")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--use-llm", action="store_true", default=True)
    p.add_argument("--no-llm", action="store_true")
    p.add_argument("--require-llm", action="store_true")
    p.add_argument(
        "--model-profile",
        default="free",
        help="free | mock | offline | or explicit model id",
    )
    p.add_argument("--model", default="", help="Override model id")
    p.add_argument("--health-check", action="store_true")
    p.add_argument("--auth-profile", default="", help="two_test_users | empty")
    p.add_argument("--repo-root", default=".")
    args = p.parse_args(argv)

    from agent_lite.recon.resolve import resolve_recon

    resolution = resolve_recon(
        repo_root=args.repo_root,
        engagement_id=args.engagement_id,
        recon_artifact=args.recon,
    )
    if resolution.status != "ok":
        print(
            json.dumps(
                {
                    "status": "BLOCKED",
                    "reason": resolution.reason or "missing_or_invalid_recon",
                    "resolution": resolution.to_dict(),
                    "hint": "Pass --recon path or use engagement_id listed in config/engagements/index.yaml",
                },
                indent=2,
            )
        )
        return 5

    recon_path = resolution.recon_path
    scope_path = args.scope or resolution.scope_path or "config/scope.yaml"
    engagement_id = args.engagement_id or resolution.engagement_id

    llm = None
    llm_status = "llm_disabled"
    router_trace: dict = {}
    use_llm = args.use_llm and not args.no_llm
    if use_llm or args.mode == "analysis" or args.require_llm:
        from agent_lite.llm.provider import create_llm_from_profile

        result = create_llm_from_profile(
            model_profile=args.model_profile,
            model_override=args.model,
            require_key=args.require_llm,
            allow_mock=not args.require_llm,
            do_health_check=args.health_check,
        )
        router_trace = result.to_trace()
        if result.status == "blocked":
            print(
                json.dumps(
                    {
                        "status": "BLOCKED",
                        "reason": result.reason,
                        "message": (
                            "Set GitHub Secret OPENROUTER_API_KEY or LLM_API_KEY "
                            "(Settings → Secrets and variables → Actions)"
                        ),
                        "model_trace": router_trace,
                    },
                    indent=2,
                )
            )
            return 4
        if result.status != "ok" or result.provider is None:
            print(
                json.dumps(
                    {
                        "status": "ERROR",
                        "reason": result.reason,
                        "model_trace": router_trace,
                    },
                    indent=2,
                )
            )
            return 6
        llm = result.provider
        llm_status = result.reason or result.model_id

    pipe = ResearchPipeline(
        engagement_id=engagement_id,
        scope_path=scope_path,
        artifacts_dir=Path(args.artifacts_dir),
        llm_provider=llm,
        require_llm=args.require_llm,
    )

    auth_meta = {}
    if getattr(args, "auth_profile", "") == "two_test_users":
        from agent_lite.auth.orchestrator import AuthOrchestrator
        import json as _json
        orch = AuthOrchestrator(target="lab://synthetic")
        auth_res = orch.run_two_users()
        auth_meta = auth_res.to_dict()
        art0 = Path(args.artifacts_dir) / engagement_id
        art0.mkdir(parents=True, exist_ok=True)
        (art0 / "auth_trace.json").write_text(
            _json.dumps(
                {
                    "status": auth_res.status,
                    "state": auth_res.state,
                    "identities": auth_res.identities,
                    "sessions": auth_res.sessions,
                    "trace": auth_res.trace,
                    "reason": auth_res.reason,
                },
                indent=2,
            )
        )
        (art0 / "identities.json").write_text(_json.dumps(auth_res.identities, indent=2))
        if auth_res.status != "ok":
            print(_json.dumps({"status": auth_res.status, "auth": auth_meta}, indent=2))
            return 7 if auth_res.status == "WAITING_FOR_AUTH" else 8

    if args.mode in ("synthetic", "analysis"):
        scenarios = {
            "positive": bola_positive_lab(),
            "secure": bola_negative_secure(),
            "public": bola_negative_public(),
            "shared": bola_negative_shared(),
            "ambiguous": bola_ambiguous_status_only(),
        }
        result = pipe.run(recon_path, scenario=scenarios[args.scenario])
        # model_trace artifact
        art = Path(args.artifacts_dir) / engagement_id
        art.mkdir(parents=True, exist_ok=True)
        (art / "model_trace.json").write_text(
            json.dumps(
                {
                    **router_trace,
                    "llm_status": llm_status,
                    "recon_resolution": resolution.to_dict(),
                },
                indent=2,
            )
        )
        out = result.to_dict()
        out["llm_status"] = llm_status
        out["llm_notes"] = list(getattr(pipe, "llm_notes", []) or [])
        out["model_trace"] = router_trace
        out["recon_resolution"] = resolution.to_dict()
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
        executor = HttpExecutor(
            scope=eng.build_scope(),
            budget=eng.build_budget(),
            identities=eng.build_identities(),
            allowed_schemes=set(eng.allowed_schemes),
        )
        result = pipe.run_from_engagement(recon_path, engagement=eng, executor=executor)
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    if not args.http_base_url:
        print("error: --http-base-url required", file=sys.stderr)
        return 2
    from agent_lite.budget.guard import BudgetGuard
    from agent_lite.http.executor import HttpExecutor
    from agent_lite.identity.resolver import Identity, IdentityResolver
    from agent_lite.scope.guard import ScopeGuard

    scope = ScopeGuard.from_file(scope_path)
    budget = BudgetGuard.from_file(Path("config/budget.yaml"))
    idr = IdentityResolver()
    for iid in (args.http_owner, args.http_non_owner):
        idr.register(Identity(identity_id=iid, credential_ref=f"TEST_{iid.upper()}"))
    executor = HttpExecutor(
        scope=scope, budget=budget, identities=idr, allowed_schemes={"http", "https"}
    )
    result = pipe.run_http(
        recon_path,
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
