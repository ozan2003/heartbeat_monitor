# Heartbeat Monitor - TOML Configuration

This document describes the TOML configuration format for the Heartbeat Monitor.

The application reads configuration from a TOML file. If an explicit path is not provided, the file is discovered using the following precedence (first match wins):

1) Explicit path provided by the user
2) Environment variable `HEARTBEAT_MONITOR_CONFIG`
3) `$XDG_CONFIG_HOME/heartbeat_monitor/config.toml`
4) `~/.config/heartbeat_monitor/config.toml`
5) `./config.toml` (current working directory)
6) `/etc/heartbeat_monitor/config.toml`

Note: The file must be valid TOML.

## Quick start (minimal example)

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

[alerts]
enabled = true
# Integer percentages 0..100
cpu_threshold = 70        
memory_threshold = 80     
disk_threshold = 85       
consecutive_timeouts = 2

[alerts.email]
enabled = true
smtp_host = "smtp.example.com"
smtp_port = 587
username = "monitor"
password = "changeme"
use_tls = true
use_ssl = false
from_address = "heartbeat@example.com"
recipients = ["ops@example.com", "oncall@example.com"]
timeout_seconds = 10.0

[logging]
# One of: "DEBUG", "INFO", "WARNING", "ERROR". Default: "INFO"
level = "INFO"
file = "/var/log/heartbeat/monitor.log"
max_size_mb = 10
backup_count = 5
```

## Schema reference

### [database]

- path (string, optional): path to the database file
- cleanup_days (integer, optional): number of days to keep old data (default: 30)

### [monitoring]

- interval (float, optional): probe interval in seconds (default: 5.0)
- timeout (float, optional): per-request timeout in seconds (default: 1.0)

### [[servers]] (array of tables)

- ip (string): IP address of the server
- hostname (string, optional): hostname of the server
- description (string, optional): description of the server

Repeat `[[servers]]` to declare multiple servers.

### [alerts]

- enabled (boolean, optional): enable/disable alerts (default: true)
- cpu_threshold (integer, optional): CPU usage threshold in percentage (default: 90)
- memory_threshold (integer, optional): memory usage threshold in percentage (default: 95)
- disk_threshold (integer, optional): disk usage threshold in percentage (default: 90)
- consecutive_timeouts (integer, optional): number of consecutive timeouts before alerting (default: 3)

### [alerts.email]

- enabled (boolean, optional): enable/disable email delivery (default: false)
- smtp_host (string, required when enabled): SMTP server hostname
- smtp_port (integer, optional): SMTP port (default: 587)
- username (string, optional): SMTP username for authentication
- password (string, optional): SMTP password (requires username)
- use_tls (boolean, optional): enable STARTTLS (default: true)
- use_ssl (boolean, optional): use implicit TLS/SSL instead of STARTTLS (default: false)
- from_address (string, required when enabled): email address to send from
- recipients (array of strings, required when enabled): recipient email addresses
- timeout_seconds (float, optional): SMTP connect/send timeout in seconds (default: 10.0)

### [logging]

- level (string, optional): logging level (default: "INFO")
- file (string, optional): path to the log file
- max_size_mb (integer, optional): maximum size of the log file in megabytes (default: 10)
- backup_count (integer, optional): number of backup files to keep (default: 5)

## Configuration file locations and precedence

The application looks for the configuration in this order:

1) Explicit path (if the user supplies one)
2) `$HEARTBEAT_MONITOR_CONFIG` (environment variable)
3) `$XDG_CONFIG_HOME/heartbeat_monitor/config.toml`
4) `~/.config/heartbeat_monitor/config.toml`
5) `./config.toml`
6) `/etc/heartbeat_monitor/config.toml`

To set an explicit path via environment variable:

```bash
export HEARTBEAT_MONITOR_CONFIG="/absolute/path/to/config.toml"
```

## Validation rules

- All numeric constraints are enforced at load time; invalid values cause a failure to load the configuration.
- Intervals and timeouts must be strictly greater than 0.
- Alert thresholds must be between 0 and 100 (inclusive).
- Counts and sizes that are documented as ">= 0" accept zero; negative values are invalid.
- Server entries require an `ip` value.

## Notes

- Omitted sections/fields use their documented defaults.
