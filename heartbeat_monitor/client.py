#!/usr/bin/env python
"""
The monitoring client that probes servers and displays results.

Reads server list from config (or hardcoded initially)
and opens raw ICMP socket.

In a loop:
    - Sends ICMP Echo Request to each server
    - Waits for reply with timeout
    - Parses reply to extract health metrics
    - Displays current status (or saves to file/db)
    - Sleeps for poll interval (like 10 seconds)


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
from typing import Any

from icmp_utils import (
    create_echo_request,
    decode_health_data,
    parse_icmp_packet,
    strip_ipv4_header_if_present,
)

ICMP_PROTO = socket.IPPROTO_ICMP
ICMP_ECHO_REPLY = 0
DEFAULT_TIMEOUT = 1.0  # Per-request timeout in seconds


class ICMPClient:
    """ICMP monitoring client that probes servers and prints health metrics."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout
        # Raw ICMP socket (requires root or CAP_NET_RAW)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_PROTO)
        # Some platforms support setting receive timeout on socket
        self.sock.settimeout(self.timeout)
        # pid is unsigned 16-bit int, any excess bits are shaved off
        self.pid = os.getpid() & 0xFFFF
        self.seq = 0

    def close(self) -> None:
        """Close the underlying socket."""
        with contextlib.suppress(OSError):
            self.sock.close()

    def _next_seq(self) -> int:
        """
        Get the next sequence number (16-bit unsigned int).

        Wraps around to 0 after reaching 65535.

        Returns:
            int: Next sequence number
        """
        self.seq = (self.seq + 1) & 0xFFFF  # truncate to 16 bits
        return self.seq

    def ping_once(self, host: str) -> tuple[bool, float | None, dict[str, Any]]:
        """
        Send one Echo Request to host and wait for Echo Reply.

        Args:
            host: Target hostname or IP address to ping.

        Returns:
            tuple: `(ok, rtt_sec, metrics_dict)`
            - ok: True if we got a valid reply, False on timeout or error
            - rtt_sec: Round-trip time in seconds, or None on timeout/error
            - metrics_dict: Parsed health metrics from the reply payload, empty if none
        """
        seq = self._next_seq()
        # Without payload
        packet = create_echo_request(self.pid, seq)

        addr = (socket.gethostbyname(host), 0)
        start = time.monotonic()
        self.sock.sendto(packet, addr)

        deadline = start + self.timeout  # Absolute deadline

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # True timeout - we've exceeded our deadline
                return False, None, {}

            # Wait for socket to become readable
            ready = select.select([self.sock], [], [], remaining)[0]
            if not ready:
                # select() timed out (shouldn't happen if remaining > 0, but just in case)
                return False, None, {}

            # Socket is readable, receive data
            try:
                data, src = self.sock.recvfrom(65535)
            except OSError:
                continue  # Ignore socket errors, keep trying until deadline

            # Filter by source IP
            if src[0] != addr[0]:
                continue

            # Strip IP header if present
            data = strip_ipv4_header_if_present(data)
            if len(data) < 8:
                continue

            # Parse ICMP packet
            try:
                header, payload = parse_icmp_packet(data)
            except (ValueError, struct.error):
                continue

            # Check if it's our Echo Reply
            if header.type != ICMP_ECHO_REPLY:
                continue
            if header.id != self.pid or header.sequence != seq:
                continue

            # Valid reply, calculate RTT
            rtt = time.monotonic() - start

            # Decode health data
            hd = decode_health_data(payload)

            metrics: dict[str, Any] = {
                "cpu_percent": hd.cpu_percent,
                "memory": {
                    "percent": hd.memory_percent,
                    "available_mb": hd.memory_available_mb,
                },
                "disk": {"percent": hd.disk_percent},
            }
            return True, rtt, metrics

    def loop(self, hosts: list[str], interval: float, count: int | None) -> None:
        """Continuously ping provided hosts with an interval and print results.

        Args:
            hosts: List of target hostnames or IP addresses to ping.
            interval: Seconds to wait between each round of pings. If 0, pings continuously without delay.
            count: Number of ping rounds to perform. If None, runs indefinitely until interrupted.
        """
        pings_sent = 0
        try:
            while True:
                if count is not None and pings_sent >= count:
                    break
                for host in hosts:
                    ok, rtt, metrics = self.ping_once(host)
                    if ok:
                        cpu = metrics.get("cpu_percent")
                        mem = (
                            metrics.get("memory", {}).get("percent")
                            if isinstance(metrics.get("memory"), dict)
                            else None
                        )
                        disk = (
                            metrics.get("disk", {}).get("percent")
                            if isinstance(metrics.get("disk"), dict)
                            else None
                        )
                        rtt = f"{(rtt or 0) * 1000:.2f}ms"
                        print(
                            f"{host} reply: {rtt=} {cpu=:.6f}% {mem=:.6f}% {disk=:.6f}%"
                        )
                    else:
                        print(f"{host} request timed out")
                    time.sleep(0.01)  # tiny spacing between hosts
                pings_sent += 1
                if interval > 0:
                    time.sleep(interval)
        except KeyboardInterrupt:
            pass
        finally:
            self.close()


def parse_args() -> argparse.Namespace:
    """
    Parse CLI args for the ICMP client.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="ICMP health monitoring client",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="This program requires root privileges to run.",
    )
    parser.add_argument(
        "hosts", nargs="*", default=["127.0.0.1"], help="Target hosts/IPs"
    )
    parser.add_argument(
        "-i", "--interval", type=float, default=5.0, help="Probe interval seconds"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0, help="Number of probe rounds (0=infinite)"
    )
    parser.add_argument(
        "-W",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Per-request timeout seconds",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for the ICMP client."""
    args = parse_args()

    count = None if args.count == 0 else max(0, int(args.count))

    client = ICMPClient(timeout=float(args.timeout))
    print("ICMP client started\nProbing:", ", ".join(args.hosts))

    client.loop(args.hosts, float(args.interval), count)


if __name__ == "__main__":
    main()
