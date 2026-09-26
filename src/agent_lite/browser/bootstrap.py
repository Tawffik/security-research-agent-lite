"""
Wire LabBootstrapContext into existing IdentityResolver + ResearchPipeline.

Does not create a parallel verdict path.
"""

from __future__ import annotations

from typing import Any, Optional

from agent_lite.browser.provider import LabBootstrapContext
from agent_lite.browser.mock_provider import MockBrowserSessionProvider
from agent_lite.http.engagement import EngagementConfig
from agent_lite.http.executor import HttpExecutor
from agent_lite.identity.resolver import IdentityResolver


def bootstrap_sessions_for_engagement(
    engagement: EngagementConfig,
    provider: Optional[Any] = None,
) -> tuple[LabBootstrapContext, IdentityResolver]:
    """
    Run browser provider bootstrap + establish sessions for owner/non-owner.
    Returns public context + resolver with in-memory sessions injected.
    """
    provider = provider or MockBrowserSessionProvider()
    ctx = provider.bootstrap_lab(engagement)
    idr = engagement.build_identities()
    if ctx.bootstrap_status != "ok":
        return ctx, idr

    for iid in (engagement.owner_identity, engagement.non_owner_identity):
        provider.establish_session(engagement, iid, ctx)
    if hasattr(provider, "apply_sessions_to_resolver"):
        provider.apply_sessions_to_resolver(idr, ctx)
    return ctx, idr


def build_executor_after_bootstrap(
    engagement: EngagementConfig,
    provider: Optional[Any] = None,
) -> tuple[LabBootstrapContext, Optional[HttpExecutor]]:
    """
    If bootstrap blocked → (ctx, None).
    If ok → (ctx, HttpExecutor with sessions from provider).
    Caller still must use ResearchPipeline.run_from_engagement for research.
    """
    ctx, idr = bootstrap_sessions_for_engagement(engagement, provider=provider)
    if ctx.bootstrap_status != "ok":
        return ctx, None
    executor = HttpExecutor(
        scope=engagement.build_scope(),
        budget=engagement.build_budget(),
        identities=idr,
        allowed_schemes=set(engagement.allowed_schemes),
    )
    return ctx, executor
