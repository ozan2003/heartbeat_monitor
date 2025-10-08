"""
Shared utilities for ICMP packet manipulation.

It contains:

    - Functions to build ICMP packets (header + payload)

    - Functions to parse received ICMP packets

    - Calculate ICMP checksum (critical - packets rejected if wrong)

    - Encode/decode custom payload format
"""
