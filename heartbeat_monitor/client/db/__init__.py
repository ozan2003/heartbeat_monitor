"""SQLite persistence for the client.

The client stores its monitoring results in a database file named
`heartbeat_monitor.db`. This package re-exports the public API from `db.py`,
so you can import it from `heartbeat_monitor.client.db` directly.

Public API:
- Connection helpers: `get_thread_connection`, `get_db_connection`, `close_thread_connection`
- Lifecycle: `init_database`, `verify_database`, `cleanup_old_data`
- Entities: `get_or_create_server`
- Writes: `insert_health_measurement`, `insert_icmp_event`, `insert_timestamp_measurement`
- Reads: `get_recent_measurements`, `get_server_stats`, `get_all_servers`
"""

from .db import (
    cleanup_old_data,
    close_thread_connection,
    db_path,
    get_all_servers,
    get_db_connection,
    get_or_create_server,
    get_recent_measurements,
    get_server_stats,
    get_thread_connection,
    init_database,
    insert_health_measurement,
    insert_icmp_event,
    insert_timestamp_measurement,
    set_db_path,
    verify_database,
)

__all__: list[str] = [
    "cleanup_old_data",
    "close_thread_connection",
    "db_path",
    "get_all_servers",
    "get_db_connection",
    "get_or_create_server",
    "get_recent_measurements",
    "get_server_stats",
    "get_thread_connection",
    "init_database",
    "insert_health_measurement",
    "insert_icmp_event",
    "insert_timestamp_measurement",
    "set_db_path",
    "verify_database",
]
