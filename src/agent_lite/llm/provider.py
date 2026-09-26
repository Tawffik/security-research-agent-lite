"""Bounded LLM provider — proposes reasoning, never executes HTTP/browser."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Optional, Protocol


@dataclass
class LLMResponse:
    status: str  # ok | blocked | error
    text: str = ""
    structured: dict[str, Any] = field(default_factory=dict)
    model: str = ""
    reason: str = ""
    tokens_est: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LLMProvider(Protocol):
    def generate(
        self,
        *,
        system: str,
        user: str,
        max_tokens: int = 1200,
    ) -> LLMResponse:
        ...


def _extract_json(text: str) -> dict[str, Any]:
    text = (text or "").strip()
    if not text:
        return {}
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else {"value": obj}
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            return {}
        try:
            obj = json.loads(m.group(0))
            return obj if isinstance(obj, dict) else {}
        except json.JSONDecodeError:
            return {}


class MockLLMProvider:
    """Deterministic offline provider for tests and no-key runs."""

    def __init__(self, model: str = "mock-lite"):
        self.model = model

    def generate(self, *, system: str, user: str, max_tokens: int = 1200) -> LLMResponse:
        # Heuristic structured output from user payload markers
        lower = (user + system).lower()
        hyps = []
        if "orders" in lower or "id" in lower or "object" in lower:
            hyps.append(
                {
                    "skill_id": "authz-bola",
                    "security_property": "INV-AUTHZ-001",
                    "claim": "Object-level authorization may fail across identities",
                    "priority": 1,
                }
            )
        if "login" in lower or "session" in lower or "auth" in lower:
            hyps.append(
                {
                    "skill_id": "authentication-session",
                    "security_property": "INV-AUTHN-001",
                    "claim": "Session handling may be weak or replayable",
                    "priority": 2,
                }
            )
        if "api" in lower or "json" in lower:
            hyps.append(
                {
                    "skill_id": "api-business-logic",
                    "security_property": "INV-BIZ-001",
                    "claim": "API business rules may lack server-side checks",
                    "priority": 3,
                }
            )
        if not hyps:
            hyps.append(
                {
                    "skill_id": "web-anomaly",
                    "security_property": "INV-ANOMALY-001",
                    "claim": "Surface anomalies need evidence-backed investigation",
                    "priority": 5,
                }
            )
        payload = {
            "opportunities": ["multi_identity_object_access", "api_surface"],
            "unknowns": ["ownership_binding", "session_binding"],
            "hypotheses": hyps[:3],
            "notes": "mock_llm_deterministic",
        }
        return LLMResponse(
            status="ok",
            text=json.dumps(payload),
            structured=payload,
            model=self.model,
            tokens_est=min(max_tokens, 400),
        )


class OpenAICompatibleProvider:
    """
    Generic OpenAI-compatible Chat Completions API.
    Env: LLM_API_KEY, LLM_BASE_URL (default https://api.openai.com/v1), LLM_MODEL
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        timeout: float = 60.0,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def generate(self, *, system: str, user: str, max_tokens: int = 1200) -> LLMResponse:
        url = f"{self.base_url}/chat/completions"
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:300]
            reason = f"http_{e.code}"
            if e.code == 401:
                reason = "invalid_api_key"
            elif e.code == 429:
                reason = "http_429"
            elif e.code in (500, 502, 503, 504):
                reason = f"http_{e.code}"
            elif e.code == 404:
                reason = "model_unavailable"
            return LLMResponse(
                status="error",
                reason=reason,
                text=detail,
                model=self.model,
            )
        except TimeoutError:
            return LLMResponse(status="error", reason="timeout", model=self.model)
        except Exception as e:  # noqa: BLE001
            name = type(e).__name__
            reason = "timeout" if "timeout" in name.lower() or "Timeout" in name else name
            return LLMResponse(status="error", reason=reason, model=self.model)

        try:
            parsed = json.loads(raw)
            text = (
                parsed.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )
        except Exception:  # noqa: BLE001
            return LLMResponse(status="error", reason="malformed_llm_response", text=raw[:500], model=self.model)

        structured = _extract_json(text)
        return LLMResponse(
            status="ok",
            text=text or "",
            structured=structured,
            model=self.model,
            tokens_est=max_tokens,
        )


def create_llm_provider(
    *,
    require_key: bool = False,
    allow_mock: bool = True,
) -> tuple[Optional[LLMProvider], str]:
    """
    Returns (provider, status_reason).
    Missing key → mock if allow_mock else (None, missing_llm_api_key).
    """
    key = (os.environ.get("LLM_API_KEY") or "").strip()
    base = (os.environ.get("LLM_BASE_URL") or "https://api.openai.com/v1").strip()
    model = (os.environ.get("LLM_MODEL") or "gpt-4o-mini").strip()
    if not key:
        if require_key and not allow_mock:
            return None, "missing_llm_api_key"
        if allow_mock:
            return MockLLMProvider(model="mock-lite"), "using_mock_llm"
        return None, "missing_llm_api_key"
    return (
        OpenAICompatibleProvider(key, base_url=base, model=model),
        f"provider_ready:{model}",
    )


def create_llm_from_profile(
    *,
    model_profile: str = "free",
    model_override: str = "",
    require_key: bool = False,
    allow_mock: bool = True,
    do_health_check: bool = False,
):
    """Preferred entry for mobile/GHA runs."""
    from agent_lite.llm.router import select_provider

    return select_provider(
        model_profile=model_profile,
        model_override=model_override,
        require_key=require_key,
        allow_mock=allow_mock,
        do_health_check=do_health_check,
    )
