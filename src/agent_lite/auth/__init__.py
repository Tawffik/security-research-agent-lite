"""Authenticated testing layer — identities, mailbox, OTP, sessions (provider-agnostic)."""

from agent_lite.auth.models import (
    AuthChallenge,
    AuthState,
    SessionHandle,
    TestIdentity,
)
from agent_lite.auth.orchestrator import AuthOrchestrator, AuthOrchestratorResult

__all__ = [
    "AuthChallenge",
    "AuthState",
    "SessionHandle",
    "TestIdentity",
    "AuthOrchestrator",
    "AuthOrchestratorResult",
]
