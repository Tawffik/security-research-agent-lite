"""Bounded HTTP execution boundary. Research engine never opens sockets directly."""

from agent_lite.http.models import ActionRequest, HttpObservation
from agent_lite.http.executor import HttpExecutor
from agent_lite.http.redaction import redact_headers, redact_body_metadata

__all__ = [
    "ActionRequest",
    "HttpObservation",
    "HttpExecutor",
    "redact_headers",
    "redact_body_metadata",
]
