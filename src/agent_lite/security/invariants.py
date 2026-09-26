"""Security invariants — properties under test (not findings)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Invariant:
    invariant_id: str
    statement: str
    domain: str
    severity_if_violated: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class InvariantRegistry:
    def __init__(self) -> None:
        self._items = {
            "INV-AUTHZ-001": Invariant(
                invariant_id="INV-AUTHZ-001",
                statement=(
                    "For a protected object owned by Actor A, Actor B must not read "
                    "or mutate the object unless an explicit authorization relationship permits it."
                ),
                domain="authorization",
                severity_if_violated="high",
            ),
        }

    def get(self, invariant_id: str) -> Invariant | None:
        return self._items.get(invariant_id)

    def authz_object(self) -> Invariant:
        return self._items["INV-AUTHZ-001"]
