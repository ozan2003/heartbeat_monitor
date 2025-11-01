"""
Logging utilities for both client and server.
"""

from __future__ import annotations

import logging
import sys

LOGGER_NAME = "heartbeat_monitor"

# Shared logger instance for the entire project
logger = logging.getLogger(LOGGER_NAME)


def configure_logging(level: str) -> logging.Logger:
    """Configure the shared project logger to log to stdout.

    The configuration is idempotent and updates the existing stdout handler
    if present.

    Args:
        level: Log level as a string (e.g., "INFO", "DEBUG").

    Returns:
        logging.Logger: The configured shared logger.
    """
    fmt = "%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%S"

    logging.basicConfig(
        format=fmt,
        level=level.upper(),
        datefmt=datefmt,
        stream=sys.stdout,
        force=True,
    )

    logger.propagate = True

    return logger


def get_logger() -> logging.Logger:
    """Return the shared `heartbeat_monitor` logger instance.

    Returns:
        logging.Logger: Shared logger instance.
    """
    return logger


__all__ = ["configure_logging", "get_logger", "logger"]
