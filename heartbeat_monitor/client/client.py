"""
The monitoring client that probes servers and displays results.

Reads server list from config (or hardcoded initially)
and opens raw ICMP socket.

In a loop:
    - Sends ICMP Echo Request to each server
    - Waits for reply with timeout
    - Parses reply to extract health metrics
    - Displays current status (or saves to file/db)
    - Sleeps for poll interval
    - Handles ICMP errors (unreachable, time exceeded, etc)


It also handles timeouts (server down/unreachable).
"""

from __future__ import annotations

import argparse
import contextlib
import os
import select
import socket
import struct
import time
from logging import Logger, getLevelName
from pathlib import Path
from textwrap import dedent
from typing import Final

from heartbeat_monitor.alerts import AlertManager
from heartbeat_monitor.client.db import (
    cleanup_old_data,
    close_thread_connection,
    init_database,
    insert_health_measurement,
    insert_icmp_event,
    set_db_path,
)
from heartbeat_monitor.config import (
    DEFAULT_INTERVAL,
    DEFAULT_TIMEOUT,
    load_config,
)
from heartbeat_monitor.health_stats import HealthData
from heartbeat_monitor.icmp_utils import (
    ICMP_PROTO,
    ICMPError,
    ICMPTypes,
    create_echo_request,
    decode_health_data,
    extract_quoted_echo_identifiers,
    parse_icmp_packet,
    strip_ipv4_header_if_present,
)
from heartbeat_monitor.logging_utils import configure_logging

DEFAULT_DATABASE_PATH: Final[str] = str(
    Path(__file__).resolve().parent / "heartbeat_monitor.db"
)


class ICMPClient:
    """ICMP monitoring client that probes servers and prints health metrics."""

    def __init__(
        self, logger: Logger, timeout: float = DEFAULT_TIMEOUT
    ) -> None:
        """
        Initialize ICMP client.

        Args:
            logger: Logger instance to use for logging
            timeout: Per-request timeout in seconds
        """
        self.logger = logger
        self.logger.debug("Initializing ICMP client")

        self.timeout = timeout
        # Raw ICMP socket (requires root or CAP_NET_RAW)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_PROTO)
        # Some platforms support setting receive timeout on socket
        self.sock.settimeout(self.timeout)
        # use current process ID as identifier
        # identifier is unsigned 16-bit int, any excess bits are shaved off
        self.pid = os.getpid() & 0xFFFF
        self.seq = 0

    def close(self) -> None:
        """Close the underlying socket and database connection."""
        with contextlib.suppress(OSError):
            self.sock.close()
            self.logger.debug("Client socket closed")
        close_thread_connection()

    def _next_seq(self) -> int:
        """
        Get the next sequence number (16-bit unsigned int).

        Wraps around to 0 after reaching 65535.

        Returns:
            int: Next sequence number
        """
        self.seq = (self.seq + 1) & 0xFFFF  # truncate to 16 bits
        return self.seq

    def ping_once(self, host: str) -> tuple[float, HealthData]:
        """
        Send one Echo Request to host and wait for Echo Reply.

        Args:
            host: Target hostname or IP address to ping.

        Returns:
            tuple[float, HealthData]: Round-trip time in seconds and decoded health data.

        Raises:
            TimeoutError: If no reply is received within the timeout period.
            ICMPError: If an ICMP error message is received.
        """
        seq = self._next_seq()
        # Without payload
        packet = create_echo_request(self.pid, seq)
        self.logger.debug(
            "Echo request built for id %s and seq %s",
            self.pid,
            seq,
        )
        addr = (socket.gethostbyname(host), 0)
        self.logger.debug("Address resolved for %s: %s", host, addr)
        start = time.monotonic()
        self.logger.debug("Sending echo request to %s (seq: %s)", host, seq)
        self.sock.sendto(packet, addr)
        deadline = start + self.timeout
        self.logger.debug("Deadline set for %s seconds", self.timeout)

        def is_icmp_error_type(header_type: int) -> bool:
            return header_type in (
                ICMPTypes.DESTINATION_UNREACHABLE.value,
                ICMPTypes.REDIRECT.value,
                ICMPTypes.TIME_EXCEEDED.value,
                ICMPTypes.PARAMETER_PROBLEM.value,
            )

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # True timeout - we've exceeded our deadline
                msg = "Request timed out"
                raise TimeoutError(msg)

            # Wait for socket to become readable
            ready = select.select([self.sock], [], [], remaining)[0]
            if not ready:
                # select() timed out (shouldn't happen if remaining > 0, but just in case)
                msg = "Request timed out"
                raise TimeoutError(msg)

            # Socket is readable, receive data
            try:
                data, src = self.sock.recvfrom(65535)
            except OSError:
                self.logger.error("Socket error", exc_info=True)
                continue

            # Strip IP header if present
            data = strip_ipv4_header_if_present(data)
            if len(data) < 8:
                continue

            # Parse the packet
            try:
                header, payload = parse_icmp_packet(data)
            except (ValueError, struct.error):
                self.logger.error("Malformed packet received", exc_info=True)
                continue

            if is_icmp_error_type(header.type):
                # Check if the quoted packet from the error payload
                # were ours (same pid and seq)
                quoted = extract_quoted_echo_identifiers(payload)
                if (
                    quoted is not None
                    and quoted[0] == self.pid
                    and quoted[1] == seq
                ):
                    self.logger.debug(
                        "ICMP error type %s detected", header.type
                    )
                    err = header.build_icmp_error()
                    if err is not None:
                        raise err
                continue

            # For Echo replies, ensure they come from the destination host
            # and check if it's our Echo Reply
            if src[0] == addr[0] and header.type == ICMPTypes.ECHO_REPLY.value:
                idents = header.try_extract_echo_identifiers()

                if (
                    idents is not None
                    and idents[0] == self.pid
                    and idents[1] == seq
                ):
                    # Valid reply
                    self.logger.debug(
                        "Valid echo reply received from %s:%s", src[0], seq
                    )

                    rtt = time.monotonic() - start
                    hd = decode_health_data(payload)
                    return rtt, hd

    def loop(
        self,
        hosts: list[str],
        *,
        interval: float,
        count: int | None,
        alert_manager: AlertManager | None = None,
    ) -> None:
        """
        Continuously ping provided hosts with an interval.

        Args:
            hosts: List of target hostnames or IP addresses to ping.
            interval: Seconds to wait between each round of pings. If 0, pings continuously without delay.
            count: Number of ping rounds to perform. If None, runs indefinitely until interrupted.
            alert_manager: Optional alert manager used to dispatch notifications.
        """
        pings_sent = 0
        try:
            while True:
                if count is not None and pings_sent >= count:
                    self.logger.debug("Ping count reached, stopping")
                    break

                for host in hosts:
                    # Resolve hostname to IP address for database storage
                    try:
                        ip_address = socket.gethostbyname(host)
                    except socket.gaierror:
                        self.logger.error("%s DNS resolution failed", host)
                        continue

                    try:
                        rtt, health_data = self.ping_once(host)
                    except TimeoutError:
                        self.logger.warning("%s request timed out", host)
                        insert_icmp_event(
                            ip_address=ip_address,
                            event_type="timeout",
                            details="Request timed out",
                        )
                        self.logger.debug("Inserted ICMP event for %s", host)
                        if alert_manager:
                            alert_manager.handle_timeout(host, ip_address)
                        continue
                    except ICMPError as e:
                        self.logger.error("ICMP error: %s", e)
                        # Extract ICMP type/code from the error if available
                        icmp_type = getattr(e, "icmp_type", None)
                        icmp_code = getattr(e, "icmp_code", None)
                        insert_icmp_event(
                            ip_address=ip_address,
                            event_type="icmp_error",
                            icmp_type=icmp_type,
                            icmp_code=icmp_code,
                            details=str(e),
                        )
                        self.logger.debug("Inserted ICMP event for %s", host)
                        continue
                    else:
                        cpu = health_data.cpu_percent
                        mem = health_data.memory_percent
                        disk = health_data.disk_percent
                        rtt_ms = rtt * 1000.0  # convert to milliseconds

                        insert_health_measurement(
                            ip_address=ip_address,
                            rtt_ms=rtt_ms,
                            cpu_percent=cpu,
                            memory_percent=mem,
                            memory_available_mb=health_data.memory_available_mb,
                            disk_percent=disk,
                            server_timestamp=None,
                        )
                        self.logger.debug(
                            "Inserted health measurement for %s", host
                        )
                        if alert_manager:
                            alert_manager.handle_measurement(
                                host, ip_address, health_data
                            )
                    finally:
                        time.sleep(0.01)  # tiny spacing between hosts

                pings_sent += 1
                if interval > 0:
                    time.sleep(interval)
        except KeyboardInterrupt:
            self.logger.debug("Keyboard interrupt received, stopping")
        finally:
            self.logger.debug("Closing ICMP client")
            self.close()


def parse_args() -> argparse.Namespace:
    """
    Parse CLI args for the ICMP client.

    Returns:
        argparse.Namespace: Parsed arguments
    """

    class HelpFormatter(
        argparse.ArgumentDefaultsHelpFormatter,
        argparse.RawDescriptionHelpFormatter,
    ):
        pass

    parser = argparse.ArgumentParser(
        description="ICMP health monitoring client",
        formatter_class=HelpFormatter,
        epilog=dedent(
            """
            Requires root privileges.

            Configuration:
            - If --config is not provided, discovery checks in order:
              1) $HEARTBEAT_MONITOR_CONFIG
              2) ./config.toml
              3) ~/.config/heartbeat_monitor/config.toml
              4) /etc/heartbeat_monitor/config.toml

            - Precedence: CLI arguments > config file > built-in defaults.
            """
        ),
    )
    parser.add_argument(
        "hosts", nargs="*", default=["127.0.0.1"], help="Target hosts/IPs"
    )
    parser.add_argument(
        "--config",
        help="Path to TOML config file (overrides discovery)",
        default=None,
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help="Probe interval seconds",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of probe rounds (0=infinite)",
    )
    parser.add_argument(
        "-W",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Per-request timeout seconds",
    )
    parser.add_argument(
        "-log",
        "--loglevel",
        default="info",
        help="Provide logging level",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for the ICMP client."""
    args = parse_args()

    # Load configuration (file or discovery) and configure logging
    config = load_config(explicit_path=args.config)
    config.database.path = config.database.path or DEFAULT_DATABASE_PATH

    # Determine logging level precedence: CLI overrides config only if set
    level = config.logging.level if args.loglevel is None else args.loglevel
    logger = configure_logging(
        level,
        file=config.logging.file,
        max_size_mb=config.logging.max_size_mb,
        backup_count=config.logging.backup_count,
    )
    logger.debug("Logging now set up to %s", getLevelName(logger.level))

    # Database path, init and optional cleanup
    set_db_path(config.database.path)
    init_database(logger=logger)
    logger.info("Database initialized at %s", config.database.path)
    if config.database.cleanup_days is not None:
        cleanup_old = config.database.cleanup_days
        stats = cleanup_old_data(days=cleanup_old)
        logger.debug("Cleanup executed: %s", stats)

    # Determine hosts: CLI overrides config if explicitly provided
    default_hosts = ["127.0.0.1"]
    cli_hosts = list(args.hosts)
    config_hosts = [server.hostname or server.ip for server in config.servers]
    hosts = (
        cli_hosts
        if cli_hosts != default_hosts
        else (config_hosts or cli_hosts)
    )

    # Determine monitoring parameters with precedence (CLI > config > default)
    interval = (
        config.monitoring.interval if args.interval is None else args.interval
    )
    timeout = (
        config.monitoring.timeout
        if args.timeout == DEFAULT_TIMEOUT
        else args.timeout
    )
    count = None if args.count == 0 else max(0, args.count)

    client = ICMPClient(logger=logger, timeout=timeout)
    alert_manager = AlertManager(config.alerts, logger)
    logger.debug("ICMP client started")
    logger.debug("Probing: %s", ", ".join(hosts))

    client.loop(
        hosts, interval=interval, count=count, alert_manager=alert_manager
    )


if __name__ == "__main__":
    main()
