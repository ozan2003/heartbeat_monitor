"""
Logging utilities for both client and server.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOGGER_NAME = "heartbeat_monitor"

# Shared logger instance for the entire project
logger = logging.getLogger(LOGGER_NAME)


def configure_logging(
    level: str,
    *,
    file: str | None = None,
    max_size_mb: int = 10,
    backup_count: int = 5,
) -> logging.Logger:
    """Configure the shared project logger.

    Logs to stdout by default. If `file` is provided, adds a rotating file
    handler with the given size and retention.

    Args:
        level: Log level as a string (e.g., "INFO", "DEBUG").
        file: Optional log file path for rotating file handler.
        max_size_mb: Max size per log file before rotation.
        backup_count: Number of rotated files to keep.

    Returns:
        logging.Logger: The configured shared logger.
    """
    fmt = "%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%S"

    logging.basicConfig(
        format=fmt,
        level=level.upper(),
        datefmt=datefmt,
        stream=sys.stdout if not file else None,
        force=True,
    )

    if file:
        # Add a rotating file handler so logs are persisted and rotated by size.
        handler = RotatingFileHandler(
            filename=str(Path(file).expanduser()),
            maxBytes=max_size_mb * 1024 * 1024,
            backupCount=backup_count,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
        # Attach handler to the root so all loggers propagate to the file.
        root = logging.getLogger()
        root.addHandler(handler)

    logger.propagate = True

    return logger


def get_logger() -> logging.Logger:
    """Return the shared `heartbeat_monitor` logger instance.

    Returns:
        logging.Logger: Shared logger instance.
    """
    return logger


__all__ = ["configure_logging", "get_logger", "logger"]
