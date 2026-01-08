# ruff: noqa: N805
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
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, Literal, cast

from pydantic import BaseModel, Field, field_validator

DEFAULT_TIMEOUT: Final[float] = 1.0  # Per-request timeout in seconds
DEFAULT_INTERVAL: Final[float] = 5.0  # Default probe interval in seconds


class DatabaseConfig(BaseModel):
    """Database settings."""

    path: str | None = None
    cleanup_days: int | None = Field(30, ge=0)


class MonitoringConfig(BaseModel):
    """Global monitoring behavior."""

    interval: float = Field(DEFAULT_INTERVAL, gt=0)
    timeout: float = Field(DEFAULT_TIMEOUT, gt=0)

    @field_validator("interval")
    def validate_interval(cls, v: float) -> float:
        """Validate the interval."""
        if v <= 0:
            msg = "Interval must be greater than 0"
            raise ValueError(msg)
        return v

    @field_validator("timeout")
    def validate_timeout(cls, v: float) -> float:
        """Validate the timeout."""
        if v <= 0:
            msg = "Timeout must be greater than 0"
            raise ValueError(msg)
        return v


class ServerConfig(BaseModel):
    """A single server to probe."""

    ip: str
    hostname: str | None = None
    description: str | None = None


class EmailConfig(BaseModel):
    """Email alert delivery settings."""

    enabled: bool = False
    smtp_host: str | None = None
    smtp_port: int = Field(587, gt=0)
    username: str | None = None
    password: str | None = None
    use_tls: bool = True
    use_ssl: bool = False
    from_address: str | None = None
    recipients: list[str] = Field(default_factory=list)
    timeout_seconds: float = Field(10.0, gt=0)

    @field_validator("recipients")
    def validate_recipients(cls, value: list[str]) -> list[str]:
        """Ensure recipient list is not empty when enabled and entries are non-blank."""
        cleaned = [addr.strip() for addr in value if addr.strip()]
        if len(cleaned) != len(value):
            msg = "Recipients must not contain blank addresses"
            raise ValueError(msg)
        return cleaned

    @field_validator("smtp_port")
    def validate_port(cls, value: int) -> int:
        """Validate SMTP port."""
        if value <= 0 or value > 65535:
            msg = "SMTP port must be in range 1-65535"
            raise ValueError(msg)
        return value

    @field_validator("from_address")
    def validate_from_address(cls, value: str | None) -> str | None:
        """Ensure from address is non-empty when provided."""
        if value is not None and not value.strip():
            msg = "from_address must not be blank"
            raise ValueError(msg)
        return value

    @field_validator("smtp_host")
    def validate_host(cls, value: str | None) -> str | None:
        """Ensure SMTP host is non-empty when provided."""
        if value is not None and not value.strip():
            msg = "smtp_host must not be blank"
            raise ValueError(msg)
        return value

    def model_post_init(self, __context: Any) -> None:
        """Validate cross-field requirements when email alerts are enabled."""
        if self.use_ssl and self.use_tls:
            msg = "use_ssl and use_tls cannot both be true"
            raise ValueError(msg)

        if self.password and not self.username:
            msg = (
                "password set without username; set username or clear password"
            )
            raise ValueError(msg)

        if not self.enabled:
            return

        missing: list[str] = []
        if not self.smtp_host:
            missing.append("smtp_host")
        if not self.from_address:
            missing.append("from_address")
        if not self.recipients:
            missing.append("recipients")

        if missing:
            fields = ", ".join(missing)
            msg = f"Email alerts enabled but missing required fields: {fields}"
            raise ValueError(msg)

    def is_configured(self) -> bool:
        """Return True when email alerts are enabled and minimally configured."""
        return (
            self.enabled
            and bool(self.smtp_host)
            and bool(self.from_address)
            and bool(self.recipients)
        )


class AlertsConfig(BaseModel):
    """Alert thresholds and rules."""

    enabled: bool = True
    cpu_threshold: int = Field(90, ge=0, le=100)
    memory_threshold: int = Field(95, ge=0, le=100)
    disk_threshold: int = Field(90, ge=0, le=100)
    consecutive_timeouts: int = Field(3, gt=0)
    email: EmailConfig = Field(
        default_factory=cast(Callable[[], EmailConfig], EmailConfig)
    )

    @field_validator("cpu_threshold", "memory_threshold", "disk_threshold")
    def validate_threshold(cls, v: int) -> int:
        """Validate the thresholds."""
        if v < 0 or v > 100:
            msg = "Threshold must be between 0 and 100"
            raise ValueError(msg)
        return v

    @field_validator("consecutive_timeouts")
    def validate_consecutive_timeouts(cls, v: int) -> int:
        """Validate the consecutive timeouts."""
        if v <= 0:
            msg = "Consecutive timeouts must be greater than 0"
            raise ValueError(msg)
        return v


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    file: str | None = None
    max_size_mb: int = Field(10, ge=0)
    backup_count: int = Field(5, ge=0)

    @field_validator("max_size_mb", "backup_count")
    def validate_size(cls, v: int) -> int:
        """Validate the size."""
        if v < 0:
            msg = "Size must be greater than 0"
            raise ValueError(msg)
        return v


class ClientConfig(BaseModel):
    """Top-level configuration schema."""

    database: DatabaseConfig = Field(
        default_factory=cast(Callable[[], DatabaseConfig], DatabaseConfig)
    )
    monitoring: MonitoringConfig = Field(
        default_factory=cast(Callable[[], MonitoringConfig], MonitoringConfig)
    )
    servers: list[ServerConfig] = Field(default_factory=list[ServerConfig])
    alerts: AlertsConfig = Field(
        default_factory=cast(Callable[[], AlertsConfig], AlertsConfig)
    )
    logging: LoggingConfig = Field(
        default_factory=cast(Callable[[], LoggingConfig], LoggingConfig)
    )


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
    """

    path = discover_config_path(explicit_path)
    if not path:
        return ClientConfig()

    toml_config = _load_toml(path)
    return ClientConfig.model_validate(toml_config)


__all__ = [
    "AlertsConfig",
    "ClientConfig",
    "DatabaseConfig",
    "EmailConfig",
    "LoggingConfig",
    "MonitoringConfig",
    "ServerConfig",
    "discover_config_path",
    "load_config",
]
