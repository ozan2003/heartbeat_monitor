"""Gather system health metrics with psutil.

psutil hides the differences between operating systems. The functions return
CPU, memory, and disk usage, and a snapshot that groups all three.
"""

from typing import NamedTuple, TypedDict

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


class MemoryInfo(TypedDict):
    """Memory usage reported by `get_memory_info`."""

    total: int
    available: int
    percent: float
    used: int


class DiskInfo(TypedDict):
    """Disk usage reported by `get_disk_info`."""

    total: int
    used: int
    free: int
    percent: float


class HealthSnapshot(TypedDict):
    """Aggregated health metrics produced by `get_basic_health`."""

    cpu_percent: float
    memory: MemoryInfo
    disk: DiskInfo


def get_cpu_percent() -> float:
    """Get current CPU usage percentage without blocking.

    Returns:
        CPU usage percentage (0.0 to 100.0)
    """
    # interval=0.0 returns the current value immediately (no 1s sleep)
    # On the very first call it may return 0.0 which is acceptable for a heartbeat.
    return psutil.cpu_percent(interval=0.0)


def get_memory_info() -> MemoryInfo:
    """Get memory usage information.

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


def get_disk_info() -> DiskInfo:
    """Get disk usage information for root partition.

    Returns:
        Dict containing total, used, free space in bytes and usage percent.
    """
    disk = psutil.disk_usage("/")
    return {
        "total": disk.total,
        "used": disk.used,
        "free": disk.free,
        "percent": disk.percent,
    }


def get_basic_health() -> HealthSnapshot:
    """Get basic system health metrics.

    Returns:
        Dict containing CPU, memory, and disk usage information.
    """
    return {
        "cpu_percent": get_cpu_percent(),
        "memory": get_memory_info(),
        "disk": get_disk_info(),
    }
