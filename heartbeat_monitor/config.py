"""
Typed configuration loader for the heartbeat monitor.

Loads configuration exclusively from a TOML file.

If a config file path is not explicitly provided, discovery checks these
locations in order:
  - `$HEARTBEAT_MONITOR_CONFIG`
  - `./config.toml`
  - `~/.config/heartbeat_monitor/config.toml`
  - `/etc/heartbeat_monitor/config.toml`
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

DEFAULT_TIMEOUT = 1.0  # Per-request timeout in seconds
DEFAULT_INTERVAL = 5.0  # Default probe interval in seconds


class DatabaseConfig(BaseModel):
    """Database settings."""

    path: str | None = None
    cleanup_days: int | None = 30


class MonitoringConfig(BaseModel):
    """Global monitoring behavior."""

    interval: float = DEFAULT_INTERVAL
    timeout: float = DEFAULT_TIMEOUT


class ServerConfig(BaseModel):
    """A single server to probe."""

    ip: str
    hostname: str | None = None
    description: str | None = None


class AlertsConfig(BaseModel):
    """Alert thresholds and rules."""

    enabled: bool = True
    cpu_threshold: int = 90
    memory_threshold: int = 95
    disk_threshold: int = 90
    consecutive_timeouts: int = 3


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    file: str | None = None
    max_size_mb: int = 10
    backup_count: int = 5


class ClientConfig(BaseModel):
    """Top-level configuration schema."""

    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    servers: list[ServerConfig] = Field(default_factory=list)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


def discover_config_path(explicit: str | None = None) -> Path | None:
    """
    Find the first existing config path based on precedence.

    Precedence:
      - Explicit argument
      - Environment variable `$HEARTBEAT_MONITOR_CONFIG`
      - XDG config home `$XDG_CONFIG_HOME/heartbeat_monitor/config.toml`
      - User config `~/.config/heartbeat_monitor/config.toml`
      - Local project directory `./config.toml`
      - System-wide `/etc/heartbeat_monitor/config.toml`

    Args:
        explicit: Optional explicit path to a config file.

    Returns:
        The first existing config path or None if no config file is found.

    Raises:
        SystemExit: If the config file is invalid or unreadable.
    """

    candidate_paths: list[Path] = []

    # 1) explicit
    if explicit:
        candidate_paths.append(Path(explicit).expanduser())

    # 2) env variable
    env_path = os.environ.get("HEARTBEAT_MONITOR_CONFIG")
    if env_path:
        candidate_paths.append(Path(env_path).expanduser())

    # 3) XDG config home
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        candidate_paths.append(
            Path(xdg_config_home).expanduser()
            / "heartbeat_monitor"
            / "config.toml"
        )

    candidate_paths.extend(
        [
            # 4) user config (~/.config)
            Path.home() / ".config" / "heartbeat_monitor" / "config.toml",
            # 5) local project directory
            Path("./config.toml").resolve(),
            # 6) system-wide
            Path("/etc/heartbeat_monitor/config.toml"),
        ]
    )

    for path in candidate_paths:
        if path.is_file():
            return path

    return None


def _load_toml(path: Path) -> dict[str, Any]:
    """
    Load a TOML file into a dictionary.

    Args:
        path: The path to the TOML file.

    Returns:
        The dictionary of the TOML file.
    """
    with path.open("rb") as f:
        return tomllib.load(f)


def load_config(explicit_path: str | None = None) -> ClientConfig:
    """Load configuration from TOML file.

    Args:
        explicit_path: Optional absolute or `~` path to a config file.

    Returns:
        A validated `ClientConfig` instance.

    Raises:
        SystemExit: If the config file is invalid or unreadable.
    """

    path = discover_config_path(explicit_path)
    if not path:
        msg = "No config file found"
        raise FileNotFoundError(msg)
    try:
        toml_config = _load_toml(path)
    except FileNotFoundError as exc:
        msg = f"Failed to read config file at {path}"
        exc.add_note(msg)
        raise
    return ClientConfig.model_validate(toml_config)


__all__ = [
    "AlertsConfig",
    "ClientConfig",
    "DatabaseConfig",
    "LoggingConfig",
    "MonitoringConfig",
    "ServerConfig",
    "discover_config_path",
    "load_config",
]
