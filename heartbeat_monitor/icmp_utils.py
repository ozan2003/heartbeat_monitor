"""
Shared utilities for ICMP packet manipulation.

It contains:
    - Functions to build ICMP packets (header + payload)
    - Functions to parse received ICMP packets
    - Calculate ICMP checksum (critical - packets rejected if wrong)
    - Encode/decode health metrics into/from binary format

Binary health monitoring format:
    - Magic bytes (3 bytes): 'HBM' - identifies our protocol
    - Version (1 byte): Protocol version (currently 1)
    - Timestamp (8 bytes double): Unix timestamp when data was gathered
    - CPU percent (4 bytes float): CPU usage percentage
    - Memory percent (4 bytes float): Memory usage percentage
    - Memory available MB (4 bytes float): Available memory in MB
    - Disk percent (4 bytes float): Disk usage percentage

Format string: '!B3sdffff'
    - ! = network byte order (big-endian)
    - B = 1 byte unsigned char (version)
    - 3s = 3 bytes string (magic)
    - d = 8 bytes double (timestamp)
    - f = 4 bytes float (cpu)
    - f = 4 bytes float (memory percent)
    - f = 4 bytes float (memory available)
    - f = 4 bytes float (disk)
"""

from __future__ import annotations

import socket
import struct
import time
from enum import IntEnum
from typing import Any, Final, NamedTuple

from heartbeat_monitor.health_stats import HealthData

# Constants for health data encoding/decoding
HEALTH_FMT: Final[str] = "!B3sdffff"
HEALTH_STRUCT: Final[struct.Struct] = struct.Struct(HEALTH_FMT)
HEALTH_SIZE: Final[int] = HEALTH_STRUCT.size

VERSION: Final[int] = 2  # Protocol version for payload format
MAGIC: Final[bytes] = b"HBM"  # Magic bytes to identify our protocol in payload

"""
ICMP packet format: type (1 byte), code (1 byte), checksum (2 bytes),
                    rest-of-header (4 bytes)

Checksum, ID and sequence numbers matter for echo requests/replies.
Other message types use the 4-byte rest-of-header interpreted differently.

See RFC 792 for details.
"""
ICMP_FMT: Final[str] = "!BBH4s"
ICMP_STRUCT: Final[struct.Struct] = struct.Struct(ICMP_FMT)
ICMP_SIZE: Final[int] = ICMP_STRUCT.size

# TODO: We can take IHL into account if we want to be more precise
_IPV4_MIN_HEADER_SIZE: Final[int] = 20  # 20 is assumed default
_IPV4_PACKET_MAX_TOTAL_LENGTH: Final[int] = 2**16 - 1

# Constants for ICMP
ICMP_PROTO: Final[int] = socket.IPPROTO_ICMP
"""
IPv4 sizing assumptions:
- _IPV4_MIN_HEADER_SIZE is 20 bytes when no IP options are present (IHL = 5).

- ICMP_MAX_SEGMENT_NO_IP_OPTIONS is the maximum ICMP bytes (header + payload)
  that still fit under the IPv4 Total Length limit (65535) with a 20-byte IP header.

- ICMP_MAX_PAYLOAD_NO_IP_OPTIONS is just the payload limit; equals 65535 - 20 - 8.

- ICMP_ERROR_MAX_SIZE comes from RFC 1812 and refers to the entire IP packet size;
  our validation subtracts the IP header to compare against the ICMP segment.
"""
ICMP_MAX_SEGMENT_NO_IP_OPTIONS: Final[int] = (
    _IPV4_PACKET_MAX_TOTAL_LENGTH - _IPV4_MIN_HEADER_SIZE
)
ICMP_MAX_PAYLOAD_NO_IP_OPTIONS: Final[int] = (
    ICMP_MAX_SEGMENT_NO_IP_OPTIONS - ICMP_SIZE
)
ICMP_ERROR_MAX_SIZE: Final[int] = 576  # As stated in RFC 1812


def ipv4_header_len_from_options_len(options_len: int) -> int:
    """Compute IPv4 header length in bytes given options length.

    Args:
        options_len: Length of IPv4 options in bytes (0..40).

    Returns:
        The IPv4 header length in bytes (20..60), padded to a multiple of 4.
    """
    options_len = max(options_len, 0)
    options_len = min(options_len, 40)
    padded = (options_len + 3) & ~3
    return _IPV4_MIN_HEADER_SIZE + padded


def icmp_max_payload_for_ip_header(ip_header_bytes: int) -> int:
    """Return maximum ICMP payload for a given IPv4 header length.

    Args:
        ip_header_bytes: IPv4 header length in bytes (must be 20..60 and multiple of 4).

    Returns:
        Maximum payload size in bytes that fits within IPv4 Total Length limits.
    """
    if not (20 <= ip_header_bytes <= 60) or (ip_header_bytes % 4 != 0):
        msg = "ip_header_bytes must be in [20, 60] and a multiple of 4"
        raise ValueError(msg)
    return _IPV4_PACKET_MAX_TOTAL_LENGTH - ip_header_bytes - ICMP_SIZE


class ICMPTypes(IntEnum):
    """
    Types for ICMP headers.
    """

    ECHO_REPLY = 0
    DESTINATION_UNREACHABLE = 3
    REDIRECT = 5
    ECHO_REQUEST = 8
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM = 12


# Human-readable descriptions for ICMP codes
DESTINATION_UNREACHABLE_DESC: dict[int, str] = {
    0: "Network unreachable",
    1: "Host unreachable",
    2: "Protocol unreachable",
    3: "Port unreachable",
    4: "Fragmentation needed and DF set",
    5: "Source route failed",
    6: "Destination network unknown",
    7: "Destination host unknown",
    8: "Source host isolated",
    9: "Network administratively prohibited",
    10: "Host administratively prohibited",
    11: "Network unreachable for TOS",
    12: "Host unreachable for TOS",
    13: "Communication administratively prohibited",
    14: "Host precedence violation",
    15: "Precedence cutoff in effect",
}

REDIRECT_DESC: dict[int, str] = {
    0: "Redirect for network",
    1: "Redirect for host",
    2: "Redirect for TOS and network",
    3: "Redirect for TOS and host",
}

TIME_EXCEEDED_DESC: dict[int, str] = {
    0: "TTL exceeded in transit",
    1: "Fragment reassembly time exceeded",
}

PARAMETER_PROBLEM_DESC: dict[int, str] = {
    0: "Pointer indicates the error",
    1: "Missing a required option",
    2: "Bad length",
}


class ICMPHeader(NamedTuple):
    """Parsed ICMP header information (generic).

    The last 4 bytes ("rest") are type-specific:
      - Echo (request/reply): identifier (2 bytes), sequence (2 bytes)
      - Dest Unreachable (code=4): unused(2), next-hop MTU(2); others: unused(4)
      - Redirect: gateway IPv4 address (4 bytes)
      - Time Exceeded: unused(4)
      - Parameter Problem: pointer(1), unused(3)
    """

    type: int
    code: int
    checksum: int
    rest: bytes  # 4-byte type-specific data

    def is_echo(self) -> bool:
        """
        Check if the ICMP header is for an Echo Request or Echo Reply.

        Returns:
            bool: True if Echo Request or Reply; otherwise False.
        """
        return self.type in (
            ICMPTypes.ECHO_REQUEST.value,
            ICMPTypes.ECHO_REPLY.value,
        )

    def try_extract_echo_identifiers(self) -> tuple[int, int] | None:
        """
        Try to extract the identifier and sequence number from an ICMP Echo header.

        Returns:
            tuple[int, int] | None: (_id, sequence) if Echo; otherwise None.
        """
        if not self.is_echo() or len(self.rest) != 4:
            return None
        _id, seq = struct.unpack("!HH", self.rest)
        return _id, seq

    def decode_icmp_rest(self) -> dict[str, Any]:
        """
        Decode the 4-byte rest-of-header into a dict of type-specific fields.

        Supported types:
        - Echo (request/reply): `{"id": int, "sequence": int}`
        - Dest Unreachable (code=4): `{"next_hop_mtu": int}` else: `{}`
        - Redirect: `{"gateway": "x.x.x.x"}`
        - Time Exceeded: `{}`
        - Parameter Problem: `{"pointer": int}`

        Returns:
            dict[str, Any]: Decoded fields; empty if type is unrecognized or has no fields.
        """
        t = self.type
        c = self.code
        rest = self.rest

        fields = {}

        if (
            t in (ICMPTypes.ECHO_REQUEST.value, ICMPTypes.ECHO_REPLY.value)
            and len(rest) == 4
        ):
            _id, seq = struct.unpack("!HH", rest)
            fields = {"id": _id, "sequence": seq}
        elif t == ICMPTypes.DESTINATION_UNREACHABLE.value and len(rest) == 4:
            # For code 4 (fragmentation needed), low 16 bits are next-hop MTU
            if c == 4:
                _, mtu = struct.unpack("!HH", rest)
                fields = {"next_hop_mtu": mtu}
        elif t == ICMPTypes.REDIRECT.value and len(rest) == 4:
            fields = {"gateway": socket.inet_ntoa(rest)}
        elif t == ICMPTypes.PARAMETER_PROBLEM.value and len(rest) == 4:
            pointer = rest[0]
            fields = {"pointer": pointer}
        # For TIME_EXCEEDED and unrecognized types, result stays empty
        elif t == ICMPTypes.TIME_EXCEEDED.value:
            pass
        else:
            pass

        return fields

    def build_icmp_error(self) -> ICMPError | None:
        """Convert an ICMP error header (non-echo) into an exception instance.

        Returns:
            ICMPError subclass instance if the type is recognized; otherwise None.
        """
        t = self.type
        c = self.code
        fields = self.decode_icmp_rest()

        if t == ICMPTypes.DESTINATION_UNREACHABLE.value:
            mtu = fields.get("next_hop_mtu")
            return DestinationUnreachableError(c, next_hop_mtu=mtu)

        if t == ICMPTypes.REDIRECT.value:
            gw = fields.get("gateway", "<unknown>")
            return RedirectError(c, gateway=gw)

        if t == ICMPTypes.TIME_EXCEEDED.value:
            return TimeExceededError(c)

        if t == ICMPTypes.PARAMETER_PROBLEM.value:
            ptr = fields.get("pointer")
            return ParameterProblemError(c, pointer=ptr)

        return None


# ------------------- ICMP error exceptions -------------------
class ICMPError(Exception):
    """Base class for ICMP errors received from the network."""

    def __init__(self, message: str, *, icmp_type: int, code: int) -> None:
        super().__init__(message)
        self.icmp_type = icmp_type
        self.code = code


class DestinationUnreachableError(ICMPError):
    """ICMP Destination Unreachable error.

    Attributes:
        next_hop_mtu: When code==4, the MTU of the next hop if provided.
    """

    def __init__(self, code: int, *, next_hop_mtu: int | None = None) -> None:
        desc = DESTINATION_UNREACHABLE_DESC.get(
            code, f"Destination unreachable (code {code})"
        )
        if code == 4 and next_hop_mtu:
            desc = f"{desc} (next-hop MTU {next_hop_mtu})"
        super().__init__(
            desc, icmp_type=ICMPTypes.DESTINATION_UNREACHABLE.value, code=code
        )
        self.next_hop_mtu = next_hop_mtu


class RedirectError(ICMPError):
    """ICMP Redirect message indicating a better gateway to use."""

    def __init__(self, code: int, *, gateway: str) -> None:
        desc = REDIRECT_DESC.get(code, f"Redirect (code {code})")
        msg = f"{desc}: use gateway {gateway}"
        super().__init__(msg, icmp_type=ICMPTypes.REDIRECT.value, code=code)
        self.gateway = gateway


class TimeExceededError(ICMPError):
    """ICMP Time Exceeded error (TTL expired or reassembly timeout)."""

    def __init__(self, code: int) -> None:
        desc = TIME_EXCEEDED_DESC.get(code, f"Time exceeded (code {code})")
        super().__init__(
            desc, icmp_type=ICMPTypes.TIME_EXCEEDED.value, code=code
        )


class ParameterProblemError(ICMPError):
    """ICMP Parameter Problem error indicating an issue in the IP header."""

    def __init__(self, code: int, *, pointer: int | None = None) -> None:
        base = PARAMETER_PROBLEM_DESC.get(
            code, f"Parameter problem (code {code})"
        )
        msg = f"{base}" if pointer is None else f"{base} at byte {pointer}"
        super().__init__(
            msg, icmp_type=ICMPTypes.PARAMETER_PROBLEM.value, code=code
        )
        self.pointer = pointer


# -------------------------------------------------------------


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
    icmp_type: int,
    icmp_code: int,
    rest: bytes,
    *,
    payload: bytes = b"",
    ip_header_bytes: int = _IPV4_MIN_HEADER_SIZE,
) -> bytes:
    """
    Create an ICMP packet with the given parameters.

    Args:
        icmp_type (int): ICMP type (e.g., 8 for echo request, 0 for echo reply).
        icmp_code (int): ICMP code (varies per type).
        rest (bytes): 4-byte type-specific data for the ICMP header.
        payload (bytes): Optional payload data.
        ip_header_bytes (int): IPv4 header size in bytes (20..60, multiple of 4).

    Returns:
        bytes: The complete ICMP packet (header + payload).

    Raises:
        ValueError: If the packet is too large or the rest-of-header is not 4 bytes.
    """

    def is_error(icmp_type: int) -> bool:
        """
        Check if the ICMP header is for an error.

        Args:
            icmp_type (int): The ICMP type to check.

        Returns:
            bool: True if Error; otherwise False.
        """
        return icmp_type in (
            ICMPTypes.DESTINATION_UNREACHABLE.value,
            ICMPTypes.REDIRECT.value,
            ICMPTypes.TIME_EXCEEDED.value,
            ICMPTypes.PARAMETER_PROBLEM.value,
        )

    if len(rest) != 4:
        msg = "ICMP rest-of-header must be exactly 4 bytes"
        raise ValueError(msg)

    # Validate IPv4 header size constraint if caller specifies non-defaults
    if not (20 <= ip_header_bytes <= 60) or (ip_header_bytes % 4 != 0):
        msg = "ip_header_bytes must be in [20, 60] and a multiple of 4"
        raise ValueError(msg)

    # Build header with zero checksum
    header = ICMP_STRUCT.pack(icmp_type, icmp_code, 0, rest)
    packet = header + payload
    segment_len = len(packet)

    if is_error(icmp_type):
        # Absolute IPv4 total-length bound
        abs_limit = _IPV4_PACKET_MAX_TOTAL_LENGTH - ip_header_bytes
        if segment_len > abs_limit:
            msg = "ICMP error packet too large for IPv4"
            raise ValueError(msg)
        # RFC 1812 limit (576-byte), compare ICMP segment only
        rfc_limit = ICMP_ERROR_MAX_SIZE - ip_header_bytes
        if segment_len > rfc_limit:
            msg = "ICMP error packet too large"
            raise ValueError(msg)
    else:
        max_payload = icmp_max_payload_for_ip_header(ip_header_bytes)
        if len(payload) > max_payload:
            msg = f"ICMP payload too large for IPv4: {len(payload)} > {max_payload}"
            raise ValueError(msg)

    checksum = calculate_checksum(packet)

    # Rebuild the packet with correct checksum
    header = ICMP_STRUCT.pack(icmp_type, icmp_code, checksum, rest)
    return header + payload


def _echo_rest(_id: int, seq_num: int) -> bytes:
    """
    Helper to build the 4-byte rest-of-header for ICMP Echo messages.

    Args:
        _id (int): Identifier for the Echo message.
        seq_num (int): Sequence number for the Echo message.

    Returns:
        bytes: 4-byte packed identifier and sequence number.
    """
    # Clamp to 16 bits
    return struct.pack("!HH", _id & 0xFFFF, seq_num & 0xFFFF)


def create_echo_request(
    _id: int,
    seq: int,
    *,
    payload: bytes = b"",
    ip_header_bytes: int | None = None,
) -> bytes:
    """
    Create an ICMP Echo Request packet.

    Args:
        _id (int): Identifier to match requests and replies.
        seq (int): Sequence number to match requests and replies.
        payload (bytes): Payload data to include in the packet.
        ip_header_bytes (int | None): Optional IPv4 header size override.

    Returns:
        bytes: The complete ICMP Echo Request packet (header + payload).
    """
    effective_ihl = (
        ip_header_bytes
        if ip_header_bytes is not None
        else _IPV4_MIN_HEADER_SIZE
    )
    return create_icmp_packet(
        ICMPTypes.ECHO_REQUEST.value,
        0,
        _echo_rest(_id, seq),
        payload=payload,
        ip_header_bytes=effective_ihl,
    )


def create_echo_reply(
    _id: int,
    seq: int,
    *,
    payload: bytes,
    ip_header_bytes: int | None = None,
) -> bytes:
    """
    Create an ICMP Echo Reply packet.

    Args:
        _id (int): Identifier to match requests and replies.
        seq (int): Sequence number to match requests and replies.
        payload (bytes): Payload data to include in the packet.
        ip_header_bytes (int | None): Optional IPv4 header size override.

    Returns:
        bytes: The complete ICMP Echo Reply packet (header + payload).
    """
    effective_ihl = (
        ip_header_bytes
        if ip_header_bytes is not None
        else _IPV4_MIN_HEADER_SIZE
    )
    return create_icmp_packet(
        ICMPTypes.ECHO_REPLY.value,
        0,
        _echo_rest(_id, seq),
        payload=payload,
        ip_header_bytes=effective_ihl,
    )


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
    if len(packet) < ICMP_SIZE:
        msg = "ICMP packet too short"
        raise ValueError(msg)

    # Unpack the header: type, code, checksum, rest-of-header (4 bytes)
    icmp_type, code, checksum, rest = ICMP_STRUCT.unpack(packet[:ICMP_SIZE])

    header = ICMPHeader(icmp_type, code, checksum, rest)
    payload = packet[ICMP_SIZE:]

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
    if len(packet) < ICMP_SIZE:
        return False

    try:
        _t, _c, original, _rest = ICMP_STRUCT.unpack(packet[:ICMP_SIZE])
    except struct.error:
        return False

    zeroed = packet[:2] + b"\x00\x00" + packet[4:]
    calc = calculate_checksum(zeroed)
    return calc == int(original)


# ------------------- Health payload encode/decode -------------------


def encode_health_data(
    health_dict: dict[str, Any], *, timestamp: float | None = None
) -> bytes:
    """
    Encode health metrics into binary payload format using struct.pack.

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

    return HEALTH_STRUCT.pack(
        VERSION,
        MAGIC,
        timestamp,
        cpu_percent,
        memory_percent,
        memory_available_mb,
        disk_percent,
    )


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
    # Check minimum size
    if len(payload) < HEALTH_SIZE:
        msg = "Invalid payload size"
        raise ValueError(msg)

    # Unpack the binary data
    version, magic, timestamp, cpu, mem_percent, mem_avail_mb, disk = (
        HEALTH_STRUCT.unpack(payload[:HEALTH_SIZE])
    )

    # Verify magic bytes and version
    if magic != MAGIC:
        msg = f"Invalid magic bytes: got {magic!r}, expected {MAGIC!r}"
        raise ValueError(msg)
    if version != VERSION:
        msg = f"Invalid version: got {version!r}, expected {VERSION!r}"
        raise ValueError(msg)

    return HealthData(
        timestamp=timestamp,
        cpu_percent=cpu,
        memory_percent=mem_percent,
        memory_available_mb=mem_avail_mb,
        disk_percent=disk,
    )


def build_rest_for_redirect(gateway_ip: str) -> bytes:
    """
    Build the 4-byte rest-of-header for an ICMP Redirect message for the given gateway.

    Args:
        gateway_ip: The IPv4 address of the gateway to redirect to.

    Returns:
        bytes: 4-byte binary representation of the gateway IP.
    """
    return socket.inet_aton(gateway_ip)


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
    ip_version = data[0] >> 4  # high nibble of the first byte

    if len(data) >= _IPV4_MIN_HEADER_SIZE and ip_version == 4:
        # exctract the lower nibble
        ihl_bytes = (data[0] & 0x0F) * 4  # in bytes, multiply by 32 for bits
        if len(data) >= ihl_bytes + ICMP_SIZE:  # at least IP + ICMP header
            return data[ihl_bytes:]
    return data


def extract_quoted_echo_identifiers(payload: bytes) -> tuple[int, int] | None:
    """
    From an ICMP error payload, extract the original Echo (id, seq) if present.

    ICMP errors embed the original IP header + at least 8 bytes of the
    original payload (RFC 792). For our echo probes, that includes the
    original ICMP header (8 bytes), from which we can read id/seq.

    Args:
        payload: The ICMP error payload, potentially starting with an IPv4 header.

    Returns:
        `(_id, seq)` if present and refers to an echo message; otherwise None.
    """
    idents = None

    ip_version = payload[0] >> 4

    # Must at least contain an IPv4 header
    if len(payload) >= _IPV4_MIN_HEADER_SIZE and ip_version == 4:
        # in bytes, multiply by 32 for bits
        ihl_bytes = (payload[0] & 0x0F) * 4

        if (
            ihl_bytes >= _IPV4_MIN_HEADER_SIZE
            and len(payload) >= ihl_bytes + 8
        ):
            inner = payload[ihl_bytes : ihl_bytes + 8]

            try:
                t, _c, _chk, rest = ICMP_STRUCT.unpack(inner)
                if len(rest) == 4 and t in (
                    ICMPTypes.ECHO_REQUEST.value,
                    ICMPTypes.ECHO_REPLY.value,
                ):
                    _id, seq = struct.unpack("!HH", rest)
                    idents = (_id, seq)
            except struct.error:
                pass

    return idents
