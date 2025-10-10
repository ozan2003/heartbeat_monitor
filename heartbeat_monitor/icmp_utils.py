"""
Shared utilities for ICMP packet manipulation.

It contains:
    - Functions to build ICMP packets (header + payload)
    - Functions to parse received ICMP packets
    - Calculate ICMP checksum (critical - packets rejected if wrong)
    - Encode/decode custom payload format
"""

import struct
import time
from typing import Any, NamedTuple

from health import HealthData

VERSION = 1
MAGIC = b"HBM1"  # Magic bytes to identify our protocol in payload


class ICMPHeader(NamedTuple):
    """Parsed ICMP header information."""

    type: int
    code: int
    checksum: int
    id: int
    sequence: int


def calculate_checksum(data: bytes) -> int:
    """
    Calculate the ICMP checksum for the given data using one's-complement
    16-bit summation with proper carry folding.

    Args:
        data (bytes): The data over which to calculate the checksum.

    Returns:
        int: The computed checksum as a 16-bit integer.
    """
    # If odd length, pad with one zero byte for 16-bit processing
    if len(data) % 2 == 1:
        data += b"\x00"

    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
        # fold carry at each step to avoid overflow
        s = (s & 0xFFFF) + (s >> 16)

    # final fold in case a carry remains
    s = (s & 0xFFFF) + (s >> 16)

    return (~s) & 0xFFFF


def create_icmp_packet(
    icmp_type: int, icmp_code: int, _id: int, seq_num: int, *, payload: bytes = b""
) -> bytes:
    """
    Create an ICMP packet with the given parameters.

    Args:
        icmp_type (int): ICMP type (e.g., 8 for echo request, 0 for echo reply).
        icmp_code (int): ICMP code (usually 0 for echo requests/replies).
        _id (int): Identifier to match requests and replies.
        seq_num (int): Sequence number to match requests and replies.
        payload (bytes): Optional payload data.

    Returns:
        bytes: The complete ICMP packet (header + payload).
    """
    checksum = 0  # To be filled in later.

    # Pack header: type, code, checksum, id, seq
    header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, _id, seq_num)

    # Calculate checksum over header + payload
    packet = header + payload
    checksum = calculate_checksum(packet)

    # Rebuild the packet with correct checksum
    header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, _id, seq_num)
    return header + payload


def create_echo_request(_id: int, seq: int, *, payload: bytes = b"") -> bytes:
    """
    Create an ICMP Echo Request packet.

    Args:
        _id (int): Identifier to match requests and replies.
        seq (int): Sequence number to match requests and replies.
        payload (bytes): Payload data to include in the packet.

    Returns:
        bytes: The complete ICMP Echo Request packet (header + payload).
    """
    return create_icmp_packet(8, 0, _id, seq, payload=payload)


def create_echo_reply(_id: int, seq: int, *, payload: bytes) -> bytes:
    """
    Create an ICMP Echo Reply packet.

    Args:
        _id (int): Identifier to match requests and replies.
        seq (int): Sequence number to match requests and replies.
        payload (bytes): Payload data to include in the packet.

    Returns:
        bytes: The complete ICMP Echo Reply packet (header + payload).
    """
    return create_icmp_packet(0, 0, _id, seq, payload=payload)


def parse_icmp_packet(packet: bytes) -> tuple[ICMPHeader, bytes]:
    """
    Parse an ICMP packet into header and payload.

    Args:
        packet (bytes): The raw ICMP packet data.

    Returns:
        tuple[ICMPHeader, bytes]: Parsed header and payload data.

    Raises:
        struct.error: If packet is too short or malformed.
    """
    if len(packet) < 8:
        raise ValueError("ICMP packet too short")

    # Unpack the header: type, code, checksum, id, sequence
    icmp_type, code, checksum, packet_id, sequence = struct.unpack("!BBHHH", packet[:8])

    header = ICMPHeader(icmp_type, code, checksum, packet_id, sequence)
    payload = packet[8:]

    return header, payload


def verify_checksum(packet: bytes) -> bool:
    """
    Verify the checksum of an ICMP packet by zeroing the checksum field
    and recomputing over the whole ICMP message.

    Args:
        packet (bytes): The raw ICMP packet data.

    Returns:
        bool: True if checksum is valid, False otherwise.
    """
    if len(packet) < 8:
        return False

    try:
        _t, _c, original, _id, _seq = struct.unpack("!BBHHH", packet[:8])
    except struct.error:
        return False

    zeroed = packet[:2] + b"\x00\x00" + packet[4:]
    calc = calculate_checksum(zeroed)
    return calc == original


def encode_health_data(
    health_dict: dict[str, Any], *, timestamp: float | None = None
) -> bytes:
    """
    Encode health metrics into binary payload format using struct.pack.

    Binary format (29 bytes total):
        - Magic bytes (4 bytes): 'HBM1' - identifies our protocol
        - Version (1 byte): Protocol version (currently 1)
        - Timestamp (8 bytes double): Unix timestamp when data was gathered
        - CPU percent (4 bytes float): CPU usage percentage
        - Memory percent (4 bytes float): Memory usage percentage
        - Memory available MB (4 bytes float): Available memory in MB
        - Disk percent (4 bytes float): Disk usage percentage

    Format string: '!4sBdffff'
        - ! = network byte order (big-endian)
        - 4s = 4 bytes string (magic)
        - B = 1 byte unsigned char (version)
        - d = 8 bytes double (timestamp)
        - f = 4 bytes float (cpu)
        - f = 4 bytes float (memory percent)
        - f = 4 bytes float (memory available)
        - f = 4 bytes float (disk)

    Args:
        health_dict: Dictionary containing health metrics from `get_basic_health()`
        timestamp: Optional timestamp (uses current time if `None`)

    Returns:
        bytes: Binary encoded health data
    """

    if timestamp is None:
        timestamp = time.time()

    cpu_percent = health_dict["cpu_percent"]
    memory_percent = health_dict["memory"]["percent"]
    memory_available_mb = health_dict["memory"]["available"] / (1024 * 1024)
    disk_percent = health_dict["disk"]["percent"]

    # Pack: magic(4s) + version(B) + timestamp(d) + 4 floats(ffff)
    payload = struct.pack(
        "!4sBdffff",
        MAGIC,
        VERSION,
        timestamp,
        cpu_percent,
        memory_percent,
        memory_available_mb,
        disk_percent,
    )

    return payload


def decode_health_data(payload: bytes) -> HealthData:
    """
    Decode health metrics from binary payload.

    Args:
        payload: Binary payload from ICMP packet

    Returns:
        HealthData namedtuple with metrics

    Raises:
        ValueError: If payload is invalid (wrong size, magic bytes, or version)
    """
    expected_size = struct.calcsize("!4sBdffff")

    # Check minimum size
    if len(payload) < expected_size:
        raise ValueError("Invalid payload size")

    # Unpack the binary data
    magic, version, timestamp, cpu, mem_percent, mem_avail_mb, disk = struct.unpack(
        "!4sBdffff", payload[:expected_size]
    )

    # Verify magic bytes and version
    if magic != MAGIC or version != VERSION:
        raise ValueError("Invalid magic bytes or version")

    return HealthData(
        timestamp=timestamp,
        cpu_percent=cpu,
        memory_percent=mem_percent,
        memory_available_mb=mem_avail_mb,
        disk_percent=disk,
    )


def strip_ipv4_header_if_present(data: bytes) -> bytes:
    """
    Return the ICMP segment, stripping an IPv4 header if one is present.

    Why:
        On many Linux kernels, reading from a raw ICMP socket (AF_INET, SOCK_RAW,
        IPPROTO_ICMP) yields the entire IPv4 packet (IP header + ICMP). Other
        platforms or socket types (e.g., datagram "ping" sockets) return only
        the ICMP message. This helper normalizes both cases so downstream code
        can always parse a bare ICMP header.

    How:
        - Detect IPv4 by checking the version nibble (data[0] >> 4 == 4).
        - Compute the Internet Header Length (IHL) from the low nibble and
          convert it to bytes (ihl = (data[0] & 0x0F) * 4).
        - If the buffer is at least IHL + 8 bytes (enough for IP + ICMP header),
          slice off the IP header and return data[ihl:].
        - Otherwise, or if not IPv4, return the input unchanged.

    Notes:
        - No IPv4 checksum or total-length validation is performed—only a
          minimal structural check.
        - IPv6 frames (version 6) and already-ICMP-only buffers are untouched.

    Args:
        data: Bytes received from a socket (potentially IP+ICMP).

    Returns:
        Bytes that begin at the ICMP header (type/code) if an IPv4 header was
        present and could be stripped; otherwise the original data.
    """
    if len(data) >= 20 and (data[0] >> 4) == 4:
        ihl = (data[0] & 0x0F) * 4
        if len(data) >= ihl + 8:  # at least IP + ICMP header
            return data[ihl:]
    return data
