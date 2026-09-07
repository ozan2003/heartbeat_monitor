# Heartbeat Monitor

<!-- badges -->

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![SQLite](https://img.shields.io/badge/SQLite-%2307405e.svg?logo=sqlite&logoColor=white)](https://www.sqlite.org/index.html)
[![Stars](https://img.shields.io/github/stars/ozan2003/heartbeat_monitor)](https://github.com/ozan2003/heartbeat_monitor/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/ozan2003/heartbeat_monitor)](https://github.com/ozan2003/heartbeat_monitor/commits/master)
[![Lines of Code](https://tokei.rs/b1/github/ozan2003/heartbeat_monitor?style=flat)](https://github.com/ozan2003/heartbeat_monitor?style=flat)
[![Code Size](https://img.shields.io/github/languages/code-size/ozan2003/heartbeat_monitor)](https://github.com/ozan2003/heartbeat_monitor)

A small ICMP client-server system monitor. It probes servers over the network, reads their CPU, memory, and disk usage, and stores the results in a local database.

## Overview

The system has two parts:

- **ICMP Server**: Listens for ICMP echo requests. It replies with the health data of the host it runs on.
- **ICMP Client**: Sends an ICMP echo request to each server at an interval. It reads the reply and stores the result.

The client and server exchange health data in the payload of ICMP echo packets. The format is defined in `HBM_PAYLOAD.md`.

## Features

- Raw ICMP sockets
- Health data encoded in ICMP payloads
- Cross-platform metrics with `psutil`
- Timeout and ICMP error handling

## Database

The client stores its results in a SQLite database file named `heartbeat_monitor.db`.

- **Stored data**: servers, health measurements, and ICMP events.
- **Location**: next to the client module. You can change it with `database.path` in the config file.
- **Setup**: none. The client creates the file on the first run.
- **Time zone**: UTC.
- **Reset**: stop the client and delete the file.
- **Backup**: copy the file while the client is stopped.

## Requirements

- Python 3.12+
- `psutil`
- SQLite

## Usage

The client and server open raw ICMP sockets. They need root privileges on Linux and administrator privileges on Windows.

On Linux, the kernel can reply to echo requests before your server does. Disable that reply:

```bash
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
```

### Run the server

```bash
sudo python -m heartbeat_monitor.server.server
```

### Run the client

```bash
sudo python -m heartbeat_monitor.client.client --config ./config.toml
```

If you omit `--config`, the client looks for the config file in this order:

1. `$HEARTBEAT_MONITOR_CONFIG`
2. `$XDG_CONFIG_HOME/heartbeat_monitor/config.toml`
3. `~/.config/heartbeat_monitor/config.toml`
4. `./config.toml`
5. `/etc/heartbeat_monitor/config.toml`

Command-line options override the config file. The config file overrides the built-in defaults.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
