# ruff: noqa: PLC0415
"""
Client package for heartbeat_monitor.

Provides lazy exports to avoid importing submodules with side effects
at package import time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__all__: list[str] = ["ICMPClient", "db"]

# Make names visible to type checkers without importing at runtime
if TYPE_CHECKING:
    from .client import ICMPClient


def __getattr__(name: str) -> Any:
    if name == "ICMPClient":
        from .client import ICMPClient  # lazy import

        return ICMPClient
    if name == "db":
        from . import db as db_module  # lazy import

        return db_module
    raise AttributeError(name)
