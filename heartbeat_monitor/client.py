"""
The monitoring client that probes servers and displays results.

Reads server list from config (or hardcoded initially)
and opens raw ICMP socket.

In a loop:

    - Sends ICMP Echo Request to each server (uses icmp_packet.py)

    - Waits for reply with timeout

    - Parses reply to extract health metrics

    - Displays current status (console output initially)

    - Sleeps for poll interval (like 10 seconds)


It also handles timeouts (server down/unreachable).

"""
