"""Free model router with bounded fallback — provider-agnostic research engine."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

import yaml

from agent_lite.llm.provider import (
    LLMProvider,
    LLMResponse,
    MockLLMProvider,
    OpenAICompatibleProvider,
    _extract_json,
)


# Failures that may trigger fallback to another model
TRANSIENT = {
    "timeout",
    "rate_limit",
    "http_429",
    "http_500",
    "http_502",
    "http_503",
    "http_504",
    "model_unavailable",
    "upstream_unavailable",
    "temporary_provider_error",
    "http_error",
}

# Failures that must NOT fallback
FATAL = {
    "missing_llm_api_key",
    "invalid_api_key",
    "http_401",
    "http_403",
    "invalid_configuration",
    "scope_violation",
    "policy_rejection",
}


@dataclass
class ModelEntry:
    model_id: str
    provider: str = "openrouter"
    free: bool = True
    context_length: int = 8192
    capabilities: list[str] = field(default_factory=list)
    status: str = "candidate"
    priority: int = 100
    last_checked: str = ""
    failure_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModelAttempt:
    provider: str
    model: str
    success: bool
    latency_ms: float = 0.0
    reason: str = ""
    attempt: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RouterResult:
    status: str  # ok | blocked | error
    provider: Optional[LLMProvider] = None
    model_id: str = ""
    attempts: list[ModelAttempt] = field(default_factory=list)
    reason: str = ""

    def to_trace(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "selected_model": self.model_id,
            "reason": self.reason,
            "attempts": [a.to_dict() for a in self.attempts],
        }


def load_free_registry(path: Optional[str | Path] = None) -> tuple[list[ModelEntry], int]:
    root = Path(__file__).resolve().parents[3]
    p = Path(path) if path else root / "config" / "models" / "free_registry.yaml"
    if not p.is_file():
        return [], 3
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    max_fb = int(data.get("max_fallback_attempts") or 3)
    models = []
    for m in data.get("models") or []:
        if not isinstance(m, dict):
            continue
        models.append(
            ModelEntry(
                model_id=str(m.get("model_id") or ""),
                provider=str(m.get("provider") or data.get("provider") or "openrouter"),
                free=bool(m.get("free", True)),
                context_length=int(m.get("context_length") or 8192),
                capabilities=list(m.get("capabilities") or []),
                status=str(m.get("status") or "candidate"),
                priority=int(m.get("priority") or 100),
            )
        )
    models = [m for m in models if m.model_id and m.free]
    models.sort(key=lambda x: x.priority)
    return models, max_fb


def _classify_http(code: int) -> str:
    if code == 401:
        return "invalid_api_key"
    if code == 403:
        return "http_403"
    if code == 429:
        return "http_429"
    if code in (500, 502, 503, 504):
        return f"http_{code}"
    if code == 404:
        return "model_unavailable"
    return f"http_{code}"


def resolve_api_credentials() -> tuple[str, str, str]:
    """
    Prefer OpenRouter secrets, fall back to generic LLM_* .
    Returns (api_key, base_url, default_model).
    """
    or_key = (os.environ.get("OPENROUTER_API_KEY") or "").strip()
    llm_key = (os.environ.get("LLM_API_KEY") or "").strip()
    key = or_key or llm_key
    base = (
        os.environ.get("OPENROUTER_BASE_URL")
        or os.environ.get("LLM_BASE_URL")
        or "https://openrouter.ai/api/v1"
    ).strip()
    if or_key and not os.environ.get("LLM_BASE_URL") and not os.environ.get("OPENROUTER_BASE_URL"):
        base = "https://openrouter.ai/api/v1"
    model = (os.environ.get("LLM_MODEL") or "").strip()
    return key, base.rstrip("/"), model


def discover_openrouter_free_models(api_key: str, base_url: str, timeout: float = 15.0) -> list[ModelEntry]:
    """Lightweight discovery — not called on every research request by default."""
    if not api_key:
        return []
    url = f"{base_url.rstrip('/')}/models"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {api_key}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
    except Exception:  # noqa: BLE001
        return []
    out: list[ModelEntry] = []
    for item in data.get("data") or []:
        if not isinstance(item, dict):
            continue
        mid = str(item.get("id") or "")
        pricing = item.get("pricing") or {}
        # free if prompt+completion price is 0 when present
        try:
            prompt_p = float(pricing.get("prompt") or 0)
            comp_p = float(pricing.get("completion") or 0)
            is_free = prompt_p == 0 and comp_p == 0
        except (TypeError, ValueError):
            is_free = ":free" in mid or mid.endswith("/free")
        if not is_free and ":free" not in mid:
            continue
        ctx = int(item.get("context_length") or item.get("top_provider", {}).get("context_length") or 8192)
        out.append(
            ModelEntry(
                model_id=mid,
                provider="openrouter",
                free=True,
                context_length=ctx,
                capabilities=["chat"],
                status="discovered",
                priority=50,
            )
        )
    return out


class RoutingLLMProvider:
    """Wraps a fixed model; used after router selection."""

    def __init__(self, inner: LLMProvider, model_id: str, trace: list[ModelAttempt]):
        self.inner = inner
        self.model_id = model_id
        self.trace = trace

    def generate(self, *, system: str, user: str, max_tokens: int = 1200) -> LLMResponse:
        t0 = time.time()
        resp = self.inner.generate(system=system, user=user, max_tokens=max_tokens)
        latency = (time.time() - t0) * 1000
        self.trace.append(
            ModelAttempt(
                provider="openrouter",
                model=self.model_id or resp.model,
                success=resp.status == "ok",
                latency_ms=round(latency, 1),
                reason=resp.reason or resp.status,
                attempt=len(self.trace) + 1,
            )
        )
        if resp.model == "":
            resp.model = self.model_id
        return resp


def select_provider(
    *,
    model_profile: str = "free",
    model_override: str = "",
    allow_mock: bool = True,
    require_key: bool = False,
    registry_path: Optional[str] = None,
    do_health_check: bool = False,
) -> RouterResult:
    """
    Select LLM provider for a run.
    model_profile=free → free registry + fallback.
    model_profile=mock → MockLLMProvider.
    model_override → force that model id.
    """
    attempts: list[ModelAttempt] = []

    if model_profile == "mock" or (allow_mock and model_profile == "offline"):
        return RouterResult(
            status="ok",
            provider=MockLLMProvider(),
            model_id="mock-lite",
            reason="using_mock_llm",
            attempts=attempts,
        )

    key, base, env_model = resolve_api_credentials()
    if not key:
        if require_key:
            return RouterResult(status="blocked", reason="missing_llm_api_key", attempts=attempts)
        if allow_mock:
            return RouterResult(
                status="ok",
                provider=MockLLMProvider(),
                model_id="mock-lite",
                reason="using_mock_llm",
                attempts=attempts,
            )
        return RouterResult(status="blocked", reason="missing_llm_api_key", attempts=attempts)

    # Fixed override or explicit LLM_MODEL
    if model_override or (model_profile not in ("free", "auto") and model_profile not in ("", "default")):
        mid = model_override or (model_profile if model_profile not in ("free", "auto", "default") else env_model)
        if not mid:
            mid = env_model or "openrouter/free"
        inner = OpenAICompatibleProvider(key, base_url=base, model=mid)
        if do_health_check:
            ok, reason = _health(inner)
            attempts.append(
                ModelAttempt(provider="openrouter", model=mid, success=ok, reason=reason, attempt=1)
            )
            if not ok and reason in FATAL:
                return RouterResult(status="blocked", reason=reason, attempts=attempts)
            if not ok:
                return RouterResult(status="error", reason=reason, attempts=attempts)
        return RouterResult(
            status="ok",
            provider=RoutingLLMProvider(inner, mid, attempts),
            model_id=mid,
            reason="fixed_model",
            attempts=attempts,
        )

    if env_model and model_profile in ("default", ""):
        inner = OpenAICompatibleProvider(key, base_url=base, model=env_model)
        return RouterResult(
            status="ok",
            provider=RoutingLLMProvider(inner, env_model, attempts),
            model_id=env_model,
            reason="env_llm_model",
            attempts=attempts,
        )

    # free profile
    models, max_fb = load_free_registry(registry_path)
    if not models:
        models = [
            ModelEntry(model_id="openrouter/free", free=True, priority=1),
        ]
    tried = 0
    last_reason = "no_models"
    for entry in models:
        if tried >= max_fb:
            break
        tried += 1
        inner = OpenAICompatibleProvider(key, base_url=base, model=entry.model_id)
        t0 = time.time()
        if do_health_check:
            ok, reason = _health(inner)
        else:
            # Defer real check to first generate; mark candidate
            ok, reason = True, "selected_without_probe"
        latency = (time.time() - t0) * 1000
        attempts.append(
            ModelAttempt(
                provider=entry.provider,
                model=entry.model_id,
                success=ok,
                latency_ms=round(latency, 1),
                reason=reason,
                attempt=tried,
            )
        )
        if ok:
            return RouterResult(
                status="ok",
                provider=RoutingLLMProvider(inner, entry.model_id, attempts),
                model_id=entry.model_id,
                reason="free_router",
                attempts=attempts,
            )
        last_reason = reason
        if reason in FATAL:
            return RouterResult(status="blocked", reason=reason, attempts=attempts)
        if reason not in TRANSIENT and not reason.startswith("http_"):
            # non-transient unknown — stop
            if reason not in TRANSIENT:
                continue
    return RouterResult(status="error", reason=f"exhausted_fallback:{last_reason}", attempts=attempts)


def _health(provider: OpenAICompatibleProvider) -> tuple[bool, str]:
    resp = provider.generate(
        system='Reply with JSON {"ok":true} only.',
        user="ping",
        max_tokens=32,
    )
    if resp.status == "ok":
        return True, "healthy"
    reason = resp.reason or "provider_error"
    # map common patterns
    if "401" in reason:
        return False, "invalid_api_key"
    if "429" in reason:
        return False, "http_429"
    return False, reason


# Fix typing import for load_free_registry
from typing import Union  # noqa: E402
