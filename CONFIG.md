# Heartbeat Monitor - Config File

This document defines the TOML config file for Heartbeat Monitor.

## Config file locations

If you do not give a path, the application looks for the config file in this order. It uses the first file that exists:

1. The path you give with `--config`
2. `$HEARTBEAT_MONITOR_CONFIG` (an environment variable)
3. `$XDG_CONFIG_HOME/heartbeat_monitor/config.toml`
4. `~/.config/heartbeat_monitor/config.toml`
5. `./config.toml`
6. `/etc/heartbeat_monitor/config.toml`

Set the environment variable like this:

```bash
export HEARTBEAT_MONITOR_CONFIG="/absolute/path/to/config.toml"
```

The file must be valid TOML.

## Quick start

```toml
# config.toml (minimal)

[monitoring]
interval = 5.0   # seconds, > 0
timeout = 1.0    # seconds, > 0

[[servers]]
ip = "192.0.2.10"
hostname = "app-1"

[[servers]]
ip = "192.0.2.11"
hostname = "app-2"
```

## Full example

```toml
# config.toml (full)

[database]
path = "/var/lib/heartbeat/monitor.db"
cleanup_days = 10

[monitoring]
interval = 2.0
timeout = 0.5

[[servers]]
ip = "203.0.113.5"
hostname = "edge-1"
description = "Edge gateway, rack A3"

[[servers]]
ip = "203.0.113.6"
hostname = "edge-2"
description = "Edge gateway, rack A4"

[logging]
# One of: "DEBUG", "INFO", "WARNING", "ERROR". Default: "INFO"
level = "INFO"
file = "/var/log/heartbeat/monitor.log"
max_size_mb = 10
backup_count = 5
```

## Options

### [database]

- `path` (string, optional): the path to the database file.
- `cleanup_days` (integer, optional): the number of days to keep data. Default: 30.

### [monitoring]

- `interval` (float, optional): the probe interval in seconds. Default: 5.0.
- `timeout` (float, optional): the per-request timeout in seconds. Default: 1.0.

### [[servers]]

Repeat this table to declare more than one server.

- `ip` (string): the IP address of the server.
- `hostname` (string, optional): the hostname of the server.
- `description` (string, optional): a note about the server.

### [logging]

- `level` (string, optional): the logging level. Default: `"INFO"`.
- `file` (string, optional): the path to the log file.
- `max_size_mb` (integer, optional): the maximum size of one log file in megabytes. Default: 10.
- `backup_count` (integer, optional): the number of rotated log files to keep. Default: 5.

## Validation

The application checks these rules when it loads the config file. A bad value stops the application.

- Intervals and timeouts must be greater than 0.
- Counts and sizes must be 0 or more. Negative values are invalid.
- Each server entry must have an `ip` value.

## Notes

- Options that you omit use the documented defaults.
