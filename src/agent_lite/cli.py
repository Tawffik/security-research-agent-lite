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
        "--scenario",
        choices=["positive", "secure", "public", "shared", "ambiguous"],
        default="positive",
    )
    p.add_argument("--artifacts-dir", default="artifacts")
    args = p.parse_args(argv)

    scenarios = {
        "positive": bola_positive_lab(),
        "secure": bola_negative_secure(),
        "public": bola_negative_public(),
        "shared": bola_negative_shared(),
        "ambiguous": bola_ambiguous_status_only(),
    }
    pipe = ResearchPipeline(
        engagement_id=args.engagement_id,
        scope_path=args.scope,
        artifacts_dir=Path(args.artifacts_dir),
    )
    result = pipe.run(args.recon, scenario=scenarios[args.scenario])
    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
