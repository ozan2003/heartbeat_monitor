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
