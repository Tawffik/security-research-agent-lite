"""Lightweight Skill Registry — metadata only; skills produce candidates+evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class SkillMeta:
    skill_id: str
    version: str = "0.1.0"
    capability: str = ""
    required_inputs: list = field(default_factory=list)
    outputs: list = field(default_factory=list)
    allowed_tools: list = field(default_factory=list)
    scope_requirements: list = field(default_factory=list)
    identity_requirements: list = field(default_factory=list)
    risk: str = "low"
    expected_evidence: list = field(default_factory=list)
    stop_conditions: list = field(default_factory=list)
    known_false_positives: list = field(default_factory=list)
    dependencies: list = field(default_factory=list)
    provenance: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SkillRegistry:
    def __init__(self) -> None:
        self._skills: dict[str, SkillMeta] = {}

    def register(self, meta: SkillMeta) -> None:
        self._skills[meta.skill_id] = meta

    def get(self, skill_id: str) -> Optional[SkillMeta]:
        return self._skills.get(skill_id)

    def list_ids(self) -> list[str]:
        return sorted(self._skills.keys())

    def load_from_yaml(self, path: Path) -> SkillMeta:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        meta = SkillMeta(
            skill_id=str(data.get("skill_id") or path.parent.name),
            version=str(data.get("version") or "0.1.0"),
            capability=str(data.get("capability") or ""),
            required_inputs=list(data.get("required_inputs") or []),
            outputs=list(data.get("outputs") or []),
            allowed_tools=list(data.get("allowed_tools") or []),
            scope_requirements=list(data.get("scope_requirements") or []),
            identity_requirements=list(data.get("identity_requirements") or []),
            risk=str(data.get("risk") or "low"),
            expected_evidence=list(data.get("expected_evidence") or []),
            stop_conditions=list(data.get("stop_conditions") or []),
            known_false_positives=list(data.get("known_false_positives") or []),
            dependencies=list(data.get("dependencies") or []),
            provenance=str(data.get("provenance") or ""),
        )
        self.register(meta)
        return meta

    def load_builtin(self, repo_root: Optional[Path] = None) -> None:
        root = repo_root or Path(__file__).resolve().parents[3]
        skills_dir = root / "skills"
        if skills_dir.is_dir():
            for meta_path in sorted(skills_dir.glob("*/metadata.yaml")):
                self.load_from_yaml(meta_path)
        if "authz-bola" not in self._skills:
            self.register(
                SkillMeta(
                    skill_id="authz-bola",
                    capability="authorization_object_level",
                    outputs=["candidates", "evidence_refs"],
                    risk="low",
                )
            )
