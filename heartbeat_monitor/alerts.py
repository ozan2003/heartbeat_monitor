from __future__ import annotations

import logging
import smtplib
from datetime import UTC, datetime
from email.message import EmailMessage
from logging import Logger
from typing import Any

from heartbeat_monitor.config import AlertsConfig
from heartbeat_monitor.health_stats import HealthData


class AlertManager:
    """Evaluate thresholds and dispatch email alerts."""

    def __init__(self, config: AlertsConfig, logger: logging.Logger) -> None:
        self.config: AlertsConfig = config
        self.logger: Logger = logger
        self._timeout_counters: dict[str, int] = {}
        self._active_alerts: dict[str, set[str]] = {}

    def handle_measurement(
        self, host: str, ip_address: str, health: HealthData
    ) -> None:
        """Process a successful measurement and send alerts when breached."""
        if not self._email_enabled:
            self._reset_timeout(host)
            return

        self._reset_timeout(host)
        self._clear_alert(host, "timeout")

        checks = [
            ("cpu", health.cpu_percent, self.config.cpu_threshold),
            ("memory", health.memory_percent, self.config.memory_threshold),
            ("disk", health.disk_percent, self.config.disk_threshold),
        ]

        for metric, value, threshold in checks:
            if value >= float(threshold):
                self._raise_alert(
                    host=host,
                    ip_address=ip_address,
                    metric=metric,
                    observed=value,
                    threshold=float(threshold),
                    observed_ts=health.timestamp,
                )
            else:
                self._clear_alert(host, metric)

    def handle_timeout(self, host: str, ip_address: str) -> None:
        """Track consecutive timeouts and alert when threshold is reached."""
        if not self._email_enabled:
            return

        count = self._timeout_counters.get(host, 0) + 1
        self._timeout_counters[host] = count

        if count >= self.config.consecutive_timeouts:
            self._raise_alert(
                host=host,
                ip_address=ip_address,
                metric="timeout",
                observed=float(count),
                threshold=float(self.config.consecutive_timeouts),
                observed_ts=datetime.now(tz=UTC).timestamp(),
            )

    @property
    def _email_enabled(self) -> bool:
        """Returns True if alerts and email are enabled and configured."""
        email_cfg = self.config.email
        return self.config.enabled and email_cfg.is_configured()

    def _reset_timeout(self, host: str) -> None:
        """Reset timeout counter for a host."""
        self._timeout_counters.pop(host, None)

    def _clear_alert(self, host: str, metric: str) -> None:
        """Clear active alert marker for a metric/host pair."""
        active = self._active_alerts.get(host)
        if active and metric in active:
            active.discard(metric)
            if not active:
                self._active_alerts.pop(host, None)

    def _raise_alert(
        self,
        *,
        host: str,
        ip_address: str,
        metric: str,
        observed: float,
        threshold: float,
        observed_ts: float,
    ) -> None:
        """Send an alert email if not already active for this metric/host."""
        active = self._active_alerts.setdefault(host, set())
        if metric in active:
            return

        active.add(metric)
        subject = self._build_subject(host, ip_address, metric)
        body = self._build_body(
            host=host,
            ip_address=ip_address,
            metric=metric,
            observed=observed,
            threshold=threshold,
            observed_ts=observed_ts,
        )

        try:
            self._send_email(subject, body)
        except Exception:
            # Do not crash the monitoring loop because of email issues
            self.logger.exception("Failed to send alert email for %s", host)

    def _build_subject(self, host: str, ip_address: str, metric: str) -> str:
        """Compose email subject line."""
        return f"Heartbeat alert for {host} ({ip_address}) - {metric}"

    def _build_body(
        self,
        *,
        host: str,
        ip_address: str,
        metric: str,
        observed: float,
        threshold: float,
        observed_ts: float,
    ) -> str:
        """Compose a plain-text alert body."""
        timestamp = datetime.fromtimestamp(observed_ts, tz=UTC).isoformat()
        lines = [
            f"Host: {host}",
            f"IP: {ip_address}",
            f"Metric: {metric}",
            f"Observed: {observed:.2f}",
            f"Threshold: {threshold:.2f}",
            f"Timestamp: {timestamp}",
        ]
        if metric == "timeout":
            lines.append(
                "Condition: consecutive timeouts exceeded threshold and host is unreachable."
            )
        else:
            lines.append(
                "Condition: metric value is at or above the configured threshold."
            )
        return "\n".join(lines)

    def _send_email(self, subject: str, body: str) -> None:
        """Send the email using configured SMTP settings."""
        email_cfg = self.config.email
        # assert email_cfg.smtp_host is not None
        # assert email_cfg.from_address is not None
        # assert email_cfg.recipients

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = email_cfg.from_address
        message["To"] = ", ".join(email_cfg.recipients)
        message.set_content(body)

        smtp_kwargs: dict[str, Any] = {
            "host": email_cfg.smtp_host,
            "port": email_cfg.smtp_port,
            "timeout": email_cfg.timeout_seconds,
        }

        smtp_class = smtplib.SMTP_SSL if email_cfg.use_ssl else smtplib.SMTP

        with smtp_class(**smtp_kwargs) as server:
            server.ehlo()
            if email_cfg.use_tls:
                server.starttls()
                server.ehlo()

            if email_cfg.username:
                server.login(email_cfg.username, email_cfg.password or "")

            server.send_message(message)
            self.logger.info(
                "Alert email sent to %s for %s",
                ",".join(email_cfg.recipients),
                subject,
            )


__all__ = ["AlertManager"]
