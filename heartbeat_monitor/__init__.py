"""Top-level package for heartbeat_monitor.

Re-exports commonly used interfaces for convenient imports.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from .health_stats import HealthData, get_basic_health
from .icmp_utils import ICMPError, ICMPTypes
from .logging_utils import configure_logging, get_logger, logger

try:
    __version__ = version("heartbeat-monitor")
except PackageNotFoundError:
    # Fallback when running from source without an installed distribution
    __version__ = "0"


__all__: list[str] = [
    "HealthData",
    "ICMPError",
    "ICMPTypes",
    "__version__",
    "configure_logging",
    "get_basic_health",
    "get_logger",
    "logger",
]
