# Heartbeat Monitor (HBM) ICMP Payload Specification

This document specifies the binary format used by Heartbeat Monitor for encoding health telemetry inside ICMP Echo packets. The payload is a fixed-size binary struct carried as ICMP data (following the ICMP header).

## Overview

- **Transport**: ICMP Echo (Request/Reply)
- **Byte order**: Network byte order (big-endian)
- **Struct format string**: `!B3sdffff`
- **Total payload size**: 28 bytes
- **Magic**: ASCII `HBM` to identify the protocol
- **Version**: 1 (as of this document)

## Field Layout

All multi-byte fields are big-endian.

```text
 0                   1                   2                   3  
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |      b'H'     |      b'B'     |      b'M'     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                           Timestamp                           +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         CPU Percentage                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Memory Percentage                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Memory Available MB                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Disk Percentage                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Notes:

- Sizes are in bytes; totals to 28 bytes.
- Timestamp is a floating-point in seconds since the Unix epoch.

## Validation Rules

Receivers must perform the following checks before trusting the data:

- Verify payload length is exactly 28 bytes.
- Unpack using `!B3sdffff` and check:
  - `magic == b"HBM"`
  - `version == 1` (reject or handle via compatibility policy if different)
- Treat NaN/Inf floats as invalid data.
- Percent fields are logically in [0, 100]; implementations may clamp or reject out-of-range values.

## Versioning and Compatibility

- `version` is the first byte to allow early gating.
- Version `1` is defined by this document.
- Future versions must retain the `magic` and use a distinct `version`. Backward compatibility is not guaranteed unless explicitly stated.

## ICMP Integration

- The payload defined here is placed verbatim as the ICMP Echo data.
- ICMP header checksum covers both header and this payload; there is no additional checksum inside the payload.
- Echo identifiers (`id`, `sequence`) live in the ICMP header, not in this payload.

## Reference Implementation (Encode/Decode)

```python
import struct, time

HEALTH_FMT = "!B3sdffff"
MAGIC = b"HBM"
VERSION = 1

def encode_health_data(health: dict, timestamp: float | None = None) -> bytes:
    if timestamp is None:
        timestamp = time.time()
    return struct.pack(
        HEALTH_FMT,
        VERSION,
        MAGIC,
        timestamp,
        float(health["cpu_percent"]),
        float(health["memory"]["percent"]),
        float(health["memory"]["available"]) / (1024 * 1024),
        float(health["disk"]["percent"]),
    )

def decode_health_data(payload: bytes):
    if len(payload) < struct.calcsize(HEALTH_FMT):
        raise ValueError("Invalid payload size")
    version, magic, ts, cpu, mem_pct, mem_avail_mb, disk = struct.unpack(
        HEALTH_FMT, payload[: struct.calcsize(HEALTH_FMT)]
    )
    if magic != MAGIC:
        raise ValueError(f"Invalid magic: {magic!r}")
    if version != VERSION:
        raise ValueError(f"Invalid version: {version}")
    return {
        "timestamp": ts,
        "cpu_percent": cpu,
        "memory_percent": mem_pct,
        "memory_available_mb": mem_avail_mb,
        "disk_percent": disk,
    }
```

### Example Usage with ICMP Echo

The payload can be carried within an ICMP Echo Request/Reply.

```python
from heartbeat_monitor.icmp_utils import create_echo_request, ICMPTypes

_id, seq = 0x1234, 1
payload = encode_health_data({
    "cpu_percent": 12.5,
    "memory": {"percent": 47.0, "available": 8_589_934_592},
    "disk": {"percent": 73.0},
})
packet = create_echo_request(_id, seq, payload=payload)
```
