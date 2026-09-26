"""Route hypotheses to skills — metadata driven, no parallel engines."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from agent_lite.skills.registry import SkillMeta, SkillRegistry


class SkillRouter:
    def __init__(self, registry: Optional[SkillRegistry] = None, repo_root: Optional[Path] = None):
        self.registry = registry or SkillRegistry()
        root = repo_root or Path(__file__).resolve().parents[3]
        self.registry.load_builtin(root)
        for sub in (
            "authentication-session",
            "api-business-logic",
            "client-side-js",
            "web-anomaly",
        ):
            meta = root / "skills" / sub / "metadata.yaml"
            if meta.exists():
                self.registry.load_from_yaml(meta)

    def resolve(self, skill_id: str) -> Optional[SkillMeta]:
        return self.registry.get(skill_id)

    def default_skill(self) -> str:
        return "authz-bola"

    def from_llm_hypotheses(self, structured: dict[str, Any]) -> list[dict[str, Any]]:
        """Normalize LLM hypothesis list; force known skill ids only."""
        allowed = set(self.registry.list_ids()) or {
            "authz-bola",
            "authentication-session",
            "api-business-logic",
            "client-side-js",
            "web-anomaly",
        }
        out = []
        for h in structured.get("hypotheses") or []:
            if not isinstance(h, dict):
                continue
            sid = str(h.get("skill_id") or self.default_skill())
            if sid not in allowed:
                sid = self.default_skill()
            out.append(
                {
                    "skill_id": sid,
                    "security_property": str(h.get("security_property") or ""),
                    "claim": str(h.get("claim") or ""),
                    "priority": int(h.get("priority") or 99),
                }
            )
        out.sort(key=lambda x: x["priority"])
        return out
