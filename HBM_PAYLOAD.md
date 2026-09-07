# Heartbeat Monitor Payload Format

This document defines the binary format that Heartbeat Monitor uses to send health data in ICMP echo packets. The payload is 28 bytes and follows the ICMP header.

## Overview

- **Transport**: ICMP echo request and reply
- **Byte order**: big-endian (network order)
- **Format string**: `!B3sdffff`
- **Payload size**: 28 bytes
- **Magic**: `HBM` (identifies the protocol)
- **Version**: 2

## Field layout

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

- Sizes are in bytes. The total is 28 bytes.
- The timestamp is a float in seconds since the Unix epoch.

## Validation

Before a receiver trusts the data, it must:

1. Check that the payload is at least 28 bytes.
2. Unpack with `!B3sdffff` and check:
   - `magic == b"HBM"`
   - `version == 2`
3. Reject NaN and infinite values.
4. Reject percentages outside [0, 100].

## Versioning

- `version` is the first byte. A receiver can reject an old format early.
- A future version must keep the magic bytes and use a new version number. Backward compatibility is not guaranteed.

## ICMP integration

- The payload is the ICMP echo data. It follows the ICMP header.
- The ICMP header checksum covers the header and the payload. The payload has no checksum of its own.
- The echo `id` and `sequence` live in the ICMP header, not in the payload.

## Reference implementation

```python
import math
import struct
import time

from heartbeat_monitor.health_stats import HealthData, HealthSnapshot

HEALTH_FMT = "!B3sdffff"
HEALTH_STRUCT = struct.Struct(HEALTH_FMT)
HEALTH_SIZE = HEALTH_STRUCT.size
MAGIC = b"HBM"
VERSION = 2


def encode_health_data(
    health_dict: HealthSnapshot, *, timestamp: float | None = None
) -> bytes:
    if timestamp is None:
        timestamp = time.time()
    return HEALTH_STRUCT.pack(
        VERSION,
        MAGIC,
        timestamp,
        health_dict["cpu_percent"],
        health_dict["memory"]["percent"],
        health_dict["memory"]["available"] / (1024 * 1024),
        health_dict["disk"]["percent"],
    )


def decode_health_data(payload: bytes) -> HealthData:
    if len(payload) < HEALTH_SIZE:
        raise ValueError("Invalid payload size")
    version, magic, ts, cpu, mem_pct, mem_avail_mb, disk = HEALTH_STRUCT.unpack(
        payload[:HEALTH_SIZE]
    )
    if magic != MAGIC:
        raise ValueError(f"Invalid magic: {magic!r}")
    if version != VERSION:
        raise ValueError(f"Invalid version: {version!r}")
    floats = (ts, cpu, mem_pct, mem_avail_mb, disk)
    if not all(math.isfinite(value) for value in floats):
        raise ValueError("Invalid payload: NaN or infinite value")
    for label, percent in (("cpu", cpu), ("memory", mem_pct), ("disk", disk)):
        if not 0.0 <= percent <= 100.0:
            raise ValueError(f"{label} percent out of range [0, 100]: {percent!r}")
    return HealthData(
        timestamp=ts,
        cpu_percent=cpu,
        memory_percent=mem_pct,
        memory_available_mb=mem_avail_mb,
        disk_percent=disk,
    )
```

## Example

The payload travels inside an ICMP echo request or reply.

```python
from heartbeat_monitor.icmp_utils import create_echo_request, ICMPTypes

_id, seq = 0x1234, 1
payload = encode_health_data(
    {
        "cpu_percent": 12.5,
        "memory": {"percent": 47.0, "available": 8_589_934_592},
        "disk": {"percent": 73.0},
    }
)
packet = create_echo_request(_id, seq, payload=payload)
```
