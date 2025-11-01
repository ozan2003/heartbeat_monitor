# Heartbeat Monitor

A simple client-server heartbeat monitoring tool for system analytics using ICMP packets.

## Overview

This project provides a lightweight way to monitor system health metrics
(CPU, memory, disk usage) over a network using custom ICMP echo requests and replies. It consists of:

- **ICMP Server**: Listens for ICMP echo requests and responds with encoded system health data.
- **ICMP Client**: Periodically sends ICMP echo requests to servers, parses replies, and displays health metrics.

## Features

- Uses raw ICMP sockets for communication.
- Encodes system health metrics in ICMP payloads.
- Cross-platform system stats via `psutil`.
- Handles timeouts and ICMP errors gracefully.

## Database

The app saves a small database file so you can look back at past checks.

- **What is stored**: A list of servers, recent health checks (speed and usage), and any ICMP connection problems.
- **Where it is**: Its located in the same directory as the client script.
- **Do I need to set it up?** No. The file is created automatically when you run the client.
- **Time zone**: All times are in UTC.
- **Start fresh**: Close the app and delete the database file.
- **Back up**: Copy that `.db` file while the app is closed; restore by replacing it with your copy.

## Requirements

- Python 3.12+
- `psutil` library
- SQLite

## Usage

For Linux systems, you may need to enable ICMP echo requests if they are disabled by default.
You can do this by running: `sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1`

### Server

Run the server with root privileges:

```bash
sudo server.py
```

### Client

Run the client with root privileges, specifying the server IP address:

```bash
sudo client.py <server_ip>
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
