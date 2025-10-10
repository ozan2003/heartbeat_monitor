#!/usr/bin/env python
"""
The monitoring client that probes servers and displays results.

Reads server list from config (or hardcoded initially)
and opens raw ICMP socket.

In a loop:

    - Sends ICMP Echo Request to each server

    - Waits for reply with timeout

    - Parses reply to extract health metrics

    - Displays current status (console output initially)

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
DEFAULT_TIMEOUT = 1.0


class ICMPClient:
    """ICMP monitoring client that probes servers and prints health metrics."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout
        # Raw ICMP socket (requires root or CAP_NET_RAW)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_PROTO)
        # Some platforms support setting receive timeout on socket
        self.sock.settimeout(self.timeout)
        self.pid = os.getpid() & 0xFFFF
        self.seq = 0

    def close(self) -> None:
        """Close the underlying socket."""
        with contextlib.suppress(OSError):
            self.sock.close()

    def _next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0xFFFF
        return self.seq

    def ping_once(self, host: str) -> tuple[bool, float | None, dict[str, Any]]:
        """Send one Echo Request to host and wait for Echo Reply.

        Returns (ok, rtt_sec, metrics_dict)
        """
        seq = self._next_seq()
        payload = b""  # server fills health metrics in the reply payload
        packet = create_echo_request(self.pid, seq, payload=payload)

        addr = (socket.gethostbyname(host), 0)
        start = time.monotonic()
        self.sock.sendto(packet, addr)

        # Wait for reply using select to support per-packet timeout
        while True:
            remaining = self.timeout - (time.monotonic() - start)
            if remaining <= 0:
                return False, None, {}
            r, _, _ = select.select([self.sock], [], [], remaining)
            if not r:
                return False, None, {}

            data, src = self.sock.recvfrom(65535)
            if src[0] != addr[0]:
                # Not from our target host
                continue

            data = strip_ipv4_header_if_present(data)
            if len(data) < 8:
                continue

            # Parse ICMP header/payload (be strict about structure only)
            try:
                header, payload = parse_icmp_packet(data)
            except (ValueError, struct.error):
                continue

            if header.type != ICMP_ECHO_REPLY:
                continue
            if header.id != self.pid or header.sequence != seq:
                continue

            rtt = time.monotonic() - start
            try:
                hd = decode_health_data(payload)
            except ValueError:
                # Kernel echo reply without our payload: treat as liveness (no metrics)
                return True, rtt, {}
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
        """Continuously ping provided hosts with an interval and print results."""
        sent = 0
        try:
            while True:
                if count is not None and sent >= count:
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
                        rtt_ms = f"{(rtt or 0) * 1000:.1f}ms"
                        print(f"{host} reply: rtt={rtt_ms} {cpu=}% {mem=}% {disk=}%")
                    else:
                        print(f"{host} request timed out")
                    time.sleep(0.01)  # tiny spacing between hosts
                sent += 1
                if interval > 0:
                    time.sleep(interval)
        except KeyboardInterrupt:
            pass
        finally:
            self.close()


def parse_args() -> argparse.Namespace:
    """Parse CLI args for the ICMP client."""
    p = argparse.ArgumentParser(description="ICMP health monitoring client")
    p.add_argument("hosts", nargs="*", default=["127.0.0.1"], help="Target hosts/IPs")
    p.add_argument(
        "-i", "--interval", type=float, default=5.0, help="Probe interval seconds"
    )
    p.add_argument(
        "-c", "--count", type=int, default=0, help="Number of probe rounds (0=infinite)"
    )
    p.add_argument(
        "-W",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Per-request timeout seconds",
    )
    return p.parse_args()


def main() -> None:
    """Entry point for the ICMP client."""
    args = parse_args()
    count = None if args.count == 0 else max(0, int(args.count))
    client = ICMPClient(timeout=float(args.timeout))
    print("ICMP client started (requires root). Probing:", ", ".join(args.hosts))
    client.loop(args.hosts, float(args.interval), count)


if __name__ == "__main__":
    main()
