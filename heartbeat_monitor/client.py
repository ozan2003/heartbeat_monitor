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

from health_stats import HealthData
from icmp_utils import (
    ICMP_PROTO,
    ICMPError,
    ICMPTypes,
    create_echo_request,
    decode_health_data,
    extract_quoted_echo_identifiers,
    parse_icmp_packet,
    strip_ipv4_header_if_present,
)

DEFAULT_TIMEOUT = 1.0  # Per-request timeout in seconds


class ICMPClient:
    """ICMP monitoring client that probes servers and prints health metrics."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
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

        addr = (socket.gethostbyname(host), 0)
        start = time.monotonic()
        self.sock.sendto(packet, addr)

        deadline = start + self.timeout  # Absolute deadline

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # True timeout - we've exceeded our deadline
                raise TimeoutError("Request timed out")

            # Wait for socket to become readable
            ready = select.select([self.sock], [], [], remaining)[0]
            if not ready:
                # select() timed out (shouldn't happen if remaining > 0, but just in case)
                raise TimeoutError("Request timed out")

            # Socket is readable, receive data
            try:
                data, src = self.sock.recvfrom(65535)
            except OSError:
                continue  # Ignore socket errors, keep trying until deadline

            # Strip IP header if present
            data = strip_ipv4_header_if_present(data)
            if len(data) < 8:
                continue

            # Parse ICMP packet
            try:
                header, payload = parse_icmp_packet(data)
            except (ValueError, struct.error):
                continue

            # Handle ICMP error types (may come from routers).
            if header.type in (
                ICMPTypes.DESTINATION_UNREACHABLE.value,
                ICMPTypes.REDIRECT.value,
                ICMPTypes.TIME_EXCEEDED.value,
                ICMPTypes.PARAMETER_PROBLEM.value,
            ):
                # Check if the quoted packet from the error payload
                # were ours (same pid and seq)
                quoted = extract_quoted_echo_identifiers(payload)
                if quoted is None:
                    continue
                quoted_id, quoted_seq = quoted
                if quoted_id == self.pid and quoted_seq == seq:
                    err = header.build_icmp_error()
                    if err is not None:
                        raise err
                continue

            # For Echo replies, ensure they come from the destination host
            if src[0] != addr[0]:
                continue

            # Check if it's our Echo Reply
            if header.type != ICMPTypes.ECHO_REPLY.value:
                continue

            ids = header.try_extract_echo_identifiers()
            if ids is None:
                continue
            rep_id, rep_seq = ids

            if rep_id != self.pid or rep_seq != seq:
                continue

            # Valid reply, calculate RTT
            rtt = time.monotonic() - start

            # Decode health data
            hd = decode_health_data(payload)

            return rtt, hd

    def loop(self, hosts: list[str], *, interval: float, count: int | None) -> None:
        """
        Continuously ping provided hosts with an interval.

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
                    try:
                        rtt, health_data = self.ping_once(host)
                    except TimeoutError:
                        print(f"{host} request timed out")
                        continue
                    except ICMPError as e:
                        print(f"{host} ICMP error: {e}")
                        continue
                    else:
                        cpu = health_data.cpu_percent
                        mem = health_data.memory_percent
                        disk = health_data.disk_percent
                        rtt *= 1000.0  # convert to milliseconds
                        print(
                            f"{host} reply: {rtt=:.3f}ms {cpu=:.3f}% {mem=:.3f}% {disk=:.3f}%"
                        )
                    finally:
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

    client.loop(args.hosts, interval=float(args.interval), count=count)


if __name__ == "__main__":
    main()
