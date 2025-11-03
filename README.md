# Heartbeat Monitor

Lightweight ICMP-based client–server system monitor with configurable probes, network-wide coverage, and local storage.

## Overview

This project provides a lightweight way to monitor system health metrics of multiple servers
(CPU, memory, disk usage) over a network using custom ICMP echo requests and replies. It consists of:

- **ICMP Server**: Listens for ICMP echo requests and responds with encoded system health data.
- **ICMP Client**: Periodically sends ICMP echo requests to servers, parses replies and saves the results to a database.

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

- Python 3.11+
- `psutil` library
- SQLite

## Usage

For Linux systems, you may need to disable kernel ICMP echo requests so
the server client can receive echo requests with the correct payload.
You can do so by running: `sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1`

Note: Opening raw ICMP sockets requires elevated privileges (root/admin) or the `CAP_NET_RAW` capability on Linux.

### Server

Run the server with root privileges:

```bash
sudo python -m heartbeat_monitor.server.server
```

### Client

Run the client with root privileges, specifying the config file:

```bash
sudo python -m heartbeat_monitor.client.client --config ./config.toml
```

## Configuration

- Config file discovery (if `--config` is not provided):
  1. `$HEARTBEAT_MONITOR_CONFIG`
  2. `./config.toml`
  3. `~/.config/heartbeat_monitor/config.toml`
  4. `/etc/heartbeat_monitor/config.toml`

- Environment overrides: set variables with `HBM_` prefix and double underscores for nesting, e.g.:
  - `HBM_MONITORING__INTERVAL=2.5`
  - `HBM_SERVERS__0__HOSTNAME=web-1`
  - `HBM_DATABASE__PATH=/var/lib/heartbeat/heartbeat_monitor.db`

- Precedence: CLI > environment overrides (`HBM_*`) > config file > built-in defaults.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
