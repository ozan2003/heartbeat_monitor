"""
Gather system health metrics from the OS.

It does:

    - Get system stats.

    - Abstracts OS differences (psutil handles cross-platform)

    - Returns current health metrics
"""

from typing import Any

import psutil


def get_cpu_percent() -> float:
    """Get current CPU usage percentage."""
    return psutil.cpu_percent(interval=1)


def get_memory_info() -> dict[str, Any]:
    """Get memory usage information."""
    memory = psutil.virtual_memory()
    return {
        "total": memory.total,
        "available": memory.available,
        "percent": memory.percent,
        "used": memory.used,
    }


def get_disk_info() -> dict[str, Any]:
    """Get disk usage information for root partition."""
    disk = psutil.disk_usage("/")
    return {
        "total": disk.total,
        "used": disk.used,
        "free": disk.free,
        "percent": (disk.used / disk.total) * 100,
    }


def get_basic_health() -> dict[str, Any]:
    """
    Get basic system health metrics.

    Returns:
        Dict containing CPU, memory, and disk usage information.
    """
    return {
        "cpu_percent": get_cpu_percent(),
        "memory": get_memory_info(),
        "disk": get_disk_info(),
    }
