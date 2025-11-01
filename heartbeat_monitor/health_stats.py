"""
Gather system health metrics from the OS.

It does:
    - Get system stats.
    - Abstracts OS differences (psutil handles cross-platform)
    - Returns current health metrics
"""

from typing import Any, NamedTuple

import psutil


class HealthData(NamedTuple):
    """System health metrics.

    Attributes:
        timestamp: Time when metrics were gathered (epoch seconds)
        cpu_percent: CPU usage percentage
        memory_percent: Memory usage percentage
        memory_available_mb: Available memory in megabytes
        disk_percent: Disk usage percentage for root partition
    """

    timestamp: float
    cpu_percent: float
    memory_percent: float
    memory_available_mb: float
    disk_percent: float


def get_cpu_percent() -> float:
    """
    Get current CPU usage percentage without blocking.

    Returns:
        CPU usage percentage (0.0 to 100.0)
    """
    # interval=0.0 returns the current value immediately (no 1s sleep)
    # On the very first call it may return 0.0 which is acceptable for a heartbeat.
    return float(psutil.cpu_percent(interval=0.0))


def get_memory_info() -> dict[str, int | float]:
    """
    Get memory usage information.

    Returns:
        Dict containing total, available, used memory in bytes and usage percent.
    """
    memory = psutil.virtual_memory()
    return {
        "total": memory.total,
        "available": memory.available,
        "percent": memory.percent,
        "used": memory.used,
    }


def get_disk_info() -> dict[str, int | float]:
    """
    Get disk usage information for root partition.

    Returns:
        Dict containing total, used, free space in bytes and usage percent.
    """
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
