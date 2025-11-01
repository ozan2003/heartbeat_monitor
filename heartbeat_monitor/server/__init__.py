# ruff: noqa: PLC0415
"""
Server package for heartbeat_monitor.

Provides lazy exports to avoid importing submodules with side effects
at package import time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__all__: list[str] = ["ICMPServer"]

# Make names visible to type checkers without importing at runtime
if TYPE_CHECKING:
    from .server import ICMPServer


def __getattr__(name: str) -> Any:
    if name == "ICMPServer":
        from .server import ICMPServer  # lazy import

        return ICMPServer
    raise AttributeError(name)
