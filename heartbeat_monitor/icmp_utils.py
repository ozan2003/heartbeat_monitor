"""
Shared utilities for ICMP packet manipulation.

It contains:

    - Functions to build ICMP packets (header + payload)

    - Functions to parse received ICMP packets

    - Calculate ICMP checksum (critical - packets rejected if wrong)

    - Encode/decode custom payload format
"""

import struct
from typing import NamedTuple


class ICMPHeader(NamedTuple):
    """Parsed ICMP header information."""
    type: int
    code: int
    checksum: int
    id: int
    sequence: int


def calculate_checksum(data: bytes) -> int:
    """
    Calculate the ICMP checksum for the given data.

    Args:
        data (bytes): The data over which to calculate the checksum.

    Returns:
        int: The calculated checksum as a 16-bit integer.
    """
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        s = s + w
    s = (s >> 16) + (s & 0xFFFF)
    s = ~s & 0xFFFF
    return s


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
    Verify the checksum of an ICMP packet.

    Args:
        packet (bytes): The complete ICMP packet.

    Returns:
        bool: True if checksum is valid, False otherwise.
    """
    if len(packet) < 8:
        return False

    # Extract the checksum from the packet
    _, _, original_checksum, _, _ = struct.unpack("!BBHHH", packet[:8])

    # Zero out the checksum field and recalculate
    zeroed_packet = packet[:2] + b'\x00\x00' + packet[4:]
    calculated_checksum = calculate_checksum(zeroed_packet)

    return original_checksum == calculated_checksum
