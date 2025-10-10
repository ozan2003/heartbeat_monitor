#!/usr/bin/env python
"""
An ICMP server that listens and responds with health data.

It opens a ICMP socket, listens in an infinite loop for
incoming ICMP Echo Request packets.

When it receives a request:
    - Parses the packet (extract id, sequence number, any payload)
    - Gathers system health metrics (calls functions from health.py)
    - Builds ICMP Echo Reply with health data in payload (uses icmp_packet.py)
    - Sends reply back to client

It also handles errors (malformed packets, socket errors).
"""

from __future__ import annotations

import argparse
import contextlib
import socket
from typing import Any

from health import get_basic_health
from icmp_utils import (
    create_echo_reply,
    encode_health_data,
    parse_icmp_packet,
    strip_ipv4_header_if_present,
    verify_checksum,
)

ICMP_PROTO = socket.IPPROTO_ICMP
ICMP_ECHO_REQUEST = 8


class ICMPServer:
    """Simple ICMP echo server that replies with encoded health metrics."""

    def __init__(self, bind_addr: str | None = None) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_PROTO)
        # Binding on raw sockets filters received packets by dst IP on some OSes.
        if bind_addr:
            with contextlib.suppress(OSError):
                self.sock.bind((bind_addr, 0))

    def close(self) -> None:
        """Close underlying socket, suppressing OS errors."""
        with contextlib.suppress(OSError):
            self.sock.close()

    def serve_forever(self) -> None:
        """Main loop: receive echo requests and send echo replies with health data."""
        try:
            while True:
                try:
                    data, src = self.sock.recvfrom(65535)
                except KeyboardInterrupt:
                    raise
                except OSError:
                    # Socket error; continue listening
                    continue

                src_ip = src[0]
                frame = strip_ipv4_header_if_present(data)
                if len(frame) < 8:
                    continue
                if not verify_checksum(frame):
                    continue

                try:
                    header, _payload = parse_icmp_packet(frame)
                except (ValueError, OSError):
                    continue

                if header.type != ICMP_ECHO_REQUEST:
                    # Not an echo request
                    continue

                # Collect metrics and encode into payload
                metrics: dict[str, Any] = get_basic_health()
                payload = encode_health_data(metrics)

                # Build echo reply mirroring id/sequence
                reply = create_echo_reply(header.id, header.sequence, payload=payload)

                # Send back to the source of the request
                # Any OSError here (e.g. network unreachable) is ignored
                with contextlib.suppress(OSError):
                    self.sock.sendto(reply, (src_ip, 0))
        finally:
            self.close()


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for the ICMP server."""
    p = argparse.ArgumentParser(description="ICMP health server (requires root)")
    p.add_argument("--bind", default=None, help="Bind to specific IP (optional)")
    return p.parse_args()


def main() -> None:
    """Start the ICMP health server and run forever."""
    args = parse_args()

    server = ICMPServer(bind_addr=args.bind)

    print("ICMP server listening; run with root privileges.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
