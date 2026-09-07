"""An ICMP server that listens and responds with health data.

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
from logging import getLevelName
from typing import TYPE_CHECKING

from heartbeat_monitor.health_stats import get_basic_health
from heartbeat_monitor.icmp_utils import (
    ICMP_PROTO,
    ICMPTypes,
    create_echo_reply,
    encode_health_data,
    parse_icmp_packet,
    strip_ipv4_header_if_present,
    verify_checksum,
)
from heartbeat_monitor.logging_utils import configure_logging

if TYPE_CHECKING:
    from logging import Logger


class ICMPServer:
    """Simple ICMP echo server that replies with encoded health metrics."""

    def __init__(self, logger: Logger, bind_addr: str | None = None) -> None:
        """Initialize ICMP server socket.

        Args:
            logger: Logger instance to use for logging
            bind_addr: Optional IP address to bind to (default: all interfaces)
        """
        self.logger: Logger = logger
        self.logger.debug("Initializing ICMP server")
        self.sock: socket.socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, ICMP_PROTO
        )
        # Binding on raw sockets filters received packets by dst IP on some OSes.
        if bind_addr is not None:
            with contextlib.suppress(OSError):
                self.sock.bind((bind_addr, 0))
                self.logger.debug("Server socket bound to %s", bind_addr)

    def close(self) -> None:
        """Close underlying socket, suppressing OS errors."""
        with contextlib.suppress(OSError):
            self.sock.close()
            self.logger.debug("Server socket closed")

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
                    self.logger.exception("Socket error")
                    continue

                src_ip: str = src[0]
                frame = strip_ipv4_header_if_present(data)
                if len(frame) < 8:
                    self.logger.debug("Frame too short from %s", src_ip)
                    continue
                if not verify_checksum(frame):
                    self.logger.debug("Checksum verification failed from %s", src_ip)
                    continue

                try:
                    header, _payload = parse_icmp_packet(frame)
                except (ValueError, OSError):
                    self.logger.exception(
                        "Malformed packet received from %s",
                        src_ip,
                    )
                    continue  # Malformed packet, ignore

                if header.type != ICMPTypes.ECHO_REQUEST.value:
                    # Not an echo request (could be error/control); ignore
                    self.logger.debug("Non-echo request received, ignoring")
                    continue
                self.logger.debug("Echo request received from %s", src_ip)

                ids = header.try_extract_echo_identifiers()
                if ids is None:
                    # Echo without id/seq? ignore
                    self.logger.debug("Echo without id/seq, ignoring")
                    continue
                req_id, req_seq = ids

                # Collect metrics and encode into payload
                metrics = get_basic_health()
                payload = encode_health_data(metrics)
                self.logger.debug("Health data encoded for %s:%s", req_id, req_seq)

                # Build echo reply mirroring id/sequence
                reply = create_echo_reply(req_id, req_seq, payload=payload)
                self.logger.debug("Echo reply built for %s:%s", req_id, req_seq)

                # Send back to the source of the request
                # Any OSError here (e.g. network unreachable) is ignored
                with contextlib.suppress(OSError):
                    self.sock.sendto(reply, (src_ip, 0))
                    self.logger.debug("Echo reply sent to %s", src_ip)
        finally:
            self.logger.debug("Server is shutting down")
            self.close()


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for the ICMP server.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="ICMP health server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="This program requires root privileges to run.",
    )

    parser.add_argument("--bind", default=None, help="Bind to specific IP (optional)")

    parser.add_argument(
        "-log",
        "--loglevel",
        default="info",
        help="Provide logging level",
    )

    return parser.parse_args()


def main() -> None:
    """Entry point for the script."""
    args = parse_args()
    logger = configure_logging(args.loglevel)
    logger.debug("Logging now set up to %s", getLevelName(logger.level))

    server = ICMPServer(logger=logger, bind_addr=args.bind)

    print("ICMP server listening.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")


if __name__ == "__main__":
    main()
