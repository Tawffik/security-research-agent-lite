"""Target-controlled content is UNTRUSTED_DATA — never instructions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class UntrustedBlob:
    trust: str = "UNTRUSTED_DATA"
    instructions_allowed: bool = False
    source: str = "target"
    content: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "trust": self.trust,
            "instructions_allowed": self.instructions_allowed,
            "source": self.source,
            "content": self.content[:4000],
        }


def wrap_untrusted(content: str, *, source: str = "target") -> UntrustedBlob:
    text = content or ""
    # Strip obvious injection markers from *influence* — keep as data observation only
    return UntrustedBlob(source=source, content=text)
