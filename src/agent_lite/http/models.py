"""ActionRequest and structured HttpObservation contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class ActionRequest:
    """Unit of target-affecting work. Must pass Policy→Scope→Identity→Risk→Budget before execute."""

    method: str
    url: str
    headers: dict = field(default_factory=dict)
    query: dict = field(default_factory=dict)
    body: Optional[str] = None
    identity_id: str = ""
    timeout_seconds: float = 15.0
    experiment_id: str = ""
    purpose: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # never serialize secrets; headers already expected redacted upstream
        return d


@dataclass
class HttpObservation:
    """Structured observation returned by the executor. No credentials."""

    observation_id: str
    experiment_id: str
    timestamp: str
    identity_id: str
    method: str
    host: str
    path: str
    request_metadata: dict = field(default_factory=dict)
    response_status: int = 0
    response_headers: dict = field(default_factory=dict)  # redacted
    response_body_metadata: dict = field(default_factory=dict)
    response_body: str = ""  # truncated / redacted
    request_count: int = 1
    duration_ms: float = 0.0
    scope_decision: str = ""
    blocked: bool = False
    block_reason: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
