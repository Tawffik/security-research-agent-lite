"""Experiment is the unit of research — not a finding."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Experiment:
    experiment_id: str
    hypothesis_ids: list
    objective: str
    action: str
    expected_observation: str
    risk: str = "low"
    cost: float = 0.2
    provenance: str = "experiment_designer"
    actual_observation: str = ""
    information_gained: str = ""
    evidence_produced: list = field(default_factory=list)
    target_interactions: int = 0
    request_count: int = 0
    tool_calls: int = 0
    result: str = "pending"
    next_decision: str = ""
    scope_decision: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExperimentResult:
    experiment: Experiment
    observations: list = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"experiment": self.experiment.to_dict(), "observations": self.observations}
