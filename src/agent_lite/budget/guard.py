"""Request/response budgets. Fail-closed when exhausted."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union

import yaml


@dataclass
class BudgetState:
    max_requests: int = 20
    max_experiments: int = 5
    max_response_bytes: int = 1_000_000
    timeout_seconds: float = 15.0
    min_delay_seconds: float = 0.0
    requests_used: int = 0
    experiments_used: int = 0
    response_bytes_used: int = 0

    def remaining_requests(self) -> int:
        return max(0, self.max_requests - self.requests_used)

    def can_request(self) -> bool:
        return self.requests_used < self.max_requests

    def can_experiment(self) -> bool:
        return self.experiments_used < self.max_experiments

    def record_request(self, response_bytes: int = 0) -> None:
        self.requests_used += 1
        self.response_bytes_used += max(0, response_bytes)

    def record_experiment(self) -> None:
        self.experiments_used += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_requests": self.max_requests,
            "max_experiments": self.max_experiments,
            "max_response_bytes": self.max_response_bytes,
            "timeout_seconds": self.timeout_seconds,
            "min_delay_seconds": self.min_delay_seconds,
            "requests_used": self.requests_used,
            "experiments_used": self.experiments_used,
            "response_bytes_used": self.response_bytes_used,
        }


class BudgetGuard:
    def __init__(self, state: BudgetState | None = None):
        self.state = state or BudgetState()

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "BudgetGuard":
        path = Path(path)
        data: dict = {}
        if path.exists():
            with path.open(encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        st = BudgetState(
            max_requests=int(data.get("max_requests", 20)),
            max_experiments=int(data.get("max_experiments", 5)),
            max_response_bytes=int(data.get("max_response_bytes", 1_000_000)),
            timeout_seconds=float(data.get("timeout_seconds", 15.0)),
            min_delay_seconds=float(data.get("min_delay_seconds", 0.0)),
        )
        return cls(st)

    def check_request(self) -> tuple[bool, str]:
        if not self.state.can_request():
            return False, "budget_max_requests_exceeded"
        if self.state.response_bytes_used >= self.state.max_response_bytes:
            return False, "budget_max_response_bytes_exceeded"
        return True, "ok"

    def check_experiment(self) -> tuple[bool, str]:
        if not self.state.can_experiment():
            return False, "budget_max_experiments_exceeded"
        return True, "ok"
