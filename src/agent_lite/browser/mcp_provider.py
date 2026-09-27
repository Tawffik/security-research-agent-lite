"""
MCP Browser provider — optional remote MCP/browser bridge.

Requires MCP_BROWSER_URL (HTTP bridge). No silent fake fallback in real mode.
Does not invent an MCP server; fail-closed when unreachable.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Optional
from urllib.parse import urlparse

from agent_lite.auth.models import SessionHandle, new_session_id
from agent_lite.browser.provider import BrowserActionResult, LabBootstrapContext
from agent_lite.identity.resolver import IdentityResolver, SessionMaterial


class McpBrowserProvider:
    """
    Calls a remote MCP browser bridge:
      POST {MCP_BROWSER_URL}/tools/call
      body: {"name": "browser_navigate"|"browser_snapshot"|..., "arguments": {...}}

    Session material stays runtime-only.
    """

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        allowed_origins: Optional[set[str]] = None,
        timeout: float = 60.0,
    ):
        self.base_url = (
            base_url or os.environ.get("MCP_BROWSER_URL") or ""
        ).strip().rstrip("/")
        self.token = (token or os.environ.get("MCP_BROWSER_TOKEN") or "").strip()
        self.allowed_origins = allowed_origins or set()
        self.timeout = timeout
        self._sessions: dict[str, SessionHandle] = {}
        self._material: dict[str, SessionMaterial] = {}
        self._context: Optional[LabBootstrapContext] = None

    def available(self) -> bool:
        return bool(self.base_url)

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> tuple[str, Any]:
        if not self.base_url:
            return "BROWSER_UNAVAILABLE", {"reason": "missing_MCP_BROWSER_URL"}
        url = f"{self.base_url}/tools/call"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "security-research-agent-lite",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        body = json.dumps({"name": name, "arguments": arguments}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return "ok", json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            return f"BROWSER_MCP_HTTP_{e.code}", {"error": e.code}
        except Exception as e:  # noqa: BLE001
            return f"BROWSER_MCP_ERROR:{type(e).__name__}", {}

    def _origin_allowed(self, url: str) -> bool:
        if not self.allowed_origins:
            # fail closed if no explicit allow list for MCP
            return False
        p = urlparse(url)
        origin = f"{p.scheme}://{p.hostname}"
        if p.port and p.port not in (80, 443):
            origin = f"{origin}:{p.port}"
        for allowed in self.allowed_origins:
            if origin == allowed or (p.hostname and allowed.endswith(p.hostname or "")):
                return True
            if p.hostname and (p.hostname == allowed or p.hostname.endswith("." + allowed.lstrip("*."))):
                return True
        return False

    def bootstrap_lab(self, engagement: Any) -> LabBootstrapContext:
        base = getattr(engagement, "base_url", None) or ""
        if not self.available():
            return LabBootstrapContext(
                provider="mcp",
                lab_url=base,
                target_origin=base,
                bootstrap_status="blocked",
                block_reasons=["BROWSER_UNAVAILABLE"],
                authorization_state="blocked",
                notes="MCP_BROWSER_URL not set",
            )
        if base and self.allowed_origins and not self._origin_allowed(base):
            return LabBootstrapContext(
                provider="mcp",
                lab_url=base,
                target_origin=base,
                bootstrap_status="blocked",
                block_reasons=["BROWSER_SCOPE_BLOCKED"],
                authorization_state="blocked",
            )
        status, _ = self._call_tool("browser_navigate", {"url": base or "about:blank"})
        if status != "ok":
            return LabBootstrapContext(
                provider="mcp",
                lab_url=base,
                target_origin=base,
                bootstrap_status="blocked",
                block_reasons=[status],
                authorization_state="blocked",
            )
        ctx = LabBootstrapContext(
            provider="mcp",
            lab_id=getattr(engagement, "engagement_id", "mcp"),
            lab_url=base,
            target_origin=base,
            known_object_path=getattr(engagement, "object_path", "/"),
            authorization_state="authorized",
            bootstrap_status="ok",
            notes="mcp_browser_bootstrap",
        )
        self._context = ctx
        return ctx

    def establish_session(
        self, engagement: Any, identity_id: str, context: LabBootstrapContext
    ) -> BrowserActionResult:
        if context.bootstrap_status != "ok":
            return BrowserActionResult(
                status="blocked",
                action="establish_session",
                block_reasons=list(context.block_reasons) or ["bootstrap_not_ok"],
            )
        # Minimal login probe via MCP tools — target-specific selectors not assumed
        status, data = self._call_tool(
            "browser_snapshot",
            {"identity_id": identity_id},
        )
        if status != "ok":
            return BrowserActionResult(
                status="blocked",
                action="establish_session",
                block_reasons=[status],
                detail="mcp_session_failed",
            )
        sid = new_session_id()
        handle = SessionHandle(
            session_id=sid,
            identity_id=identity_id,
            target=context.target_origin or "",
            status="active",
            provider="mcp",
            auth_method="browser_mcp",
        )
        self._sessions[identity_id] = handle
        # Do not persist raw cookies from MCP payload into artifacts
        self._material[identity_id] = SessionMaterial(
            identity_id=identity_id,
            headers={"Cookie": f"mcp_sid={sid}"},
        )
        return BrowserActionResult(status="ok", action="establish_session", detail=identity_id)

    def collect_lab_context(self, engagement: Any) -> LabBootstrapContext:
        return self._context or self.bootstrap_lab(engagement)

    def close_session(self) -> BrowserActionResult:
        self._call_tool("browser_close", {})
        self._sessions.clear()
        self._material.clear()
        return BrowserActionResult(status="ok", action="close_session")

    def session_handle(self, identity_id: str) -> Optional[SessionHandle]:
        return self._sessions.get(identity_id)

    def apply_to_resolver(self, resolver: IdentityResolver) -> None:
        for iid, mat in self._material.items():
            resolver.inject_session(iid, mat)
