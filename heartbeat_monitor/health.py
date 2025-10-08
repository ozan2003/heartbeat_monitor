"""
Gather system health metrics from the OS.

It does:

    - Get system stats.

    - Abstracts OS differences (psutil handles cross-platform)

    - Returns current health metrics
"""
