"""Lab-specific adapters. Thin wrappers over HttpExecutor — not parallel engines."""

from agent_lite.labs.portswigger import PortSwiggerAdapter, AdapterResult

__all__ = ["PortSwiggerAdapter", "AdapterResult"]
