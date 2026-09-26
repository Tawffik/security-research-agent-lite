"""Fail-closed ScopeGuard. Unknown host = BLOCK."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union

import yaml


class ScopeDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


@dataclass
class ScopeResult:
    decision: ScopeDecision
    reason: str
    host: str = ""
    method: str = ""


class ScopeGuard:
    def __init__(self, rules: dict[str, Any]):
        self.rules = rules or {}
        self.in_scope = list(self.rules.get("in_scope") or [])
        self.out_of_scope = list(self.rules.get("out_of_scope") or [])
        self.allow_mutations = bool(self.rules.get("allow_mutations", False))

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "ScopeGuard":
        path = Path(path)
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(data)

    def _host_match(self, pattern: str, host: str) -> bool:
        host = (host or "").lower().strip()
        pattern = (pattern or "").lower().strip()
        if not host or not pattern:
            return False
        if pattern.startswith("*."):
            suffix = pattern[1:]  # .example.com
            return host.endswith(suffix) or host == pattern[2:]
        return host == pattern

    def check(self, host: str, method: str = "GET") -> ScopeResult:
        host = (host or "").strip()
        method = (method or "GET").upper()
        if not host:
            return ScopeResult(ScopeDecision.BLOCK, "missing_host", host, method)

        for rule in self.out_of_scope:
            pat = rule if isinstance(rule, str) else str(rule.get("host") or rule)
            if self._host_match(pat, host):
                return ScopeResult(ScopeDecision.BLOCK, "explicit_out_of_scope", host, method)

        matched = False
        allowed_methods: list[str] = []
        for rule in self.in_scope:
            if isinstance(rule, str):
                pat, methods = rule, ["GET", "HEAD", "OPTIONS"]
            else:
                pat = str(rule.get("host") or "")
                methods = [m.upper() for m in (rule.get("methods") or ["GET"])]
            if self._host_match(pat, host):
                matched = True
                allowed_methods.extend(methods)

        if not matched:
            return ScopeResult(ScopeDecision.BLOCK, "unknown_host_fail_closed", host, method)

        if method not in set(allowed_methods) and method not in ("GET", "HEAD", "OPTIONS"):
            if not self.allow_mutations:
                return ScopeResult(ScopeDecision.BLOCK, "method_not_allowed", host, method)

        if method in ("POST", "PUT", "PATCH", "DELETE") and not self.allow_mutations:
            return ScopeResult(ScopeDecision.BLOCK, "mutations_disabled", host, method)

        return ScopeResult(ScopeDecision.ALLOW, "in_scope", host, method)
