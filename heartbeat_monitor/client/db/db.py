"""Client database services.

This module implements the SQLite persistence layer used by the client to store
monitoring results:
- Health measurements (latency and resource usage)
- ICMP events (timeouts and errors)
- Timestamp measurements (for clock skew tracking)

Design:
- One connection per thread via thread-local storage for safe concurrent writes
- WAL journaling mode with autocommit for balanced durability and performance
- Schema defined in `db_schema.sql` (same directory), applied by `init_database()`

Example usage:
    >>> from heartbeat_monitor.client.db import (
    >>>     init_database,
    >>>     insert_health_measurement,
    >>>     get_recent_measurements,
    >>> )
    >>> init_database()
    >>> insert_health_measurement(
    >>>     ip_address="192.0.2.10",
    >>>     rtt_ms=12.3,
    >>>     cpu_percent=4.2,
    >>>     memory_percent=37.5,
    >>>     memory_available_mb=1024.0,
    >>>     disk_percent=51.8,
    >>>     server_timestamp=None,
    >>> )
    >>> rows = get_recent_measurements("192.0.2.10", limit=10)
"""

import json
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from logging import Logger
from pathlib import Path
from typing import Any, Final

from heartbeat_monitor.logging_utils import logger

# Database file path (default to module directory)
CLIENT_DIR: Final[Path] = Path(__file__).resolve().parent
db_path = str(CLIENT_DIR / "heartbeat_monitor.db")

# Thread-local storage for database connections
_thread_local = threading.local()


def get_thread_connection() -> sqlite3.Connection:
    """Get a database connection for the current thread.

    Each thread gets its own connection stored in thread-local storage.
    This is thread-safe and efficient for concurrent writes.

    Returns:
        sqlite3.Connection: Database connection for this thread
    """
    if not hasattr(_thread_local, "conn") or _thread_local.conn is None:
        _thread_local.conn = sqlite3.connect(
            db_path,
            timeout=30.0,  # Wait up to 30s for locks
            isolation_level=None,  # Autocommit mode for better concurrency
            check_same_thread=False,  # We handle thread safety
        )
        _thread_local.conn.row_factory = sqlite3.Row  # Access columns by name
        # Ensure constraints and per-connection performance settings
        _thread_local.conn.execute("PRAGMA foreign_keys=ON")
        _thread_local.conn.execute("PRAGMA journal_mode=WAL")
        _thread_local.conn.execute("PRAGMA synchronous=NORMAL")
        _thread_local.conn.execute("PRAGMA cache_size=-64000")
        _thread_local.conn.execute("PRAGMA temp_store=MEMORY")
        _thread_local.conn.execute("PRAGMA mmap_size=268435456")

    conn: sqlite3.Connection = _thread_local.conn
    return conn


@contextmanager
def get_db_connection() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for database operations.

    Usage:
    >>> with get_db_connection() as conn:
    >>>     conn.execute("INSERT INTO ...")

    Yields:
        sqlite3.Connection: Database connection
    """
    conn = get_thread_connection()
    yield conn


def init_database(logger: Logger) -> None:
    """Initialize database and create tables from schema file.

    This should be called once when the application starts.
    Loads schema from db_schema.sql and enables WAL mode.

    Args:
        logger: Logger instance to use for logging

    Raises:
        FileNotFoundError: If db_schema.sql is not found
    """
    # Load schema from external file
    schema_path = Path(__file__).parent / "db_schema.sql"

    if not schema_path.exists():
        logger.error("Database schema not found at %s", schema_path)
        msg = (
            f"Schema file not found: {schema_path}\n"
            f"Please ensure db_schema.sql is in the same directory as db.py"
        )
        raise FileNotFoundError(msg)

    schema_sql = schema_path.read_text(encoding="utf-8")

    # Create/open database
    logger.debug("Connecting to database: %s", db_path)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys=ON")

    # Enable WAL mode (persists in database file)
    result = conn.execute("PRAGMA journal_mode=WAL").fetchone()
    wal_mode = result[0] if result else "unknown"

    # Performance tuning
    conn.execute("PRAGMA synchronous=NORMAL")  # Balance safety/speed with WAL
    conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
    conn.execute("PRAGMA temp_store=MEMORY")  # Keep temp tables in RAM
    conn.execute("PRAGMA mmap_size=268435456")  # 256MB memory-mapped I/O

    # Execute schema
    logger.debug("Executing schema")
    conn.executescript(schema_sql)
    logger.debug("Committing changes")
    conn.commit()
    logger.debug("Closing database connection")
    conn.close()

    logger.debug(
        "Database initialized: path=%s, journal_mode=%s, schema=%s",
        db_path,
        wal_mode,
        schema_path.name,
    )


def verify_database() -> dict[str, Any]:
    """Verify database setup and return info.

    Returns:
        dict: Database information (mode, tables, indexes)
    """
    with get_db_connection() as conn:
        # Check journal mode
        journal_mode: str = conn.execute("PRAGMA journal_mode").fetchone()[0]

        # Get table list
        tables: list[str] = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        ]

        # Get index list
        indexes: list[str] = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' ORDER BY name"
            ).fetchall()
        ]

        # Get row counts
        counts: dict[str, int] = {}
        known_tables = {
            "servers": "SELECT COUNT(*) FROM servers",
            "health_measurements": "SELECT COUNT(*) FROM health_measurements",
            "icmp_events": "SELECT COUNT(*) FROM icmp_events",
            "timestamp_measurements": "SELECT COUNT(*) FROM timestamp_measurements",
        }
        for table in tables:
            sql = known_tables.get(table)
            if sql is None:
                continue
            row = conn.execute(sql).fetchone()
            count: int = row[0] if row is not None else 0
            counts[table] = count

        return {
            "database_path": db_path,
            "journal_mode": journal_mode,
            "tables": tables,
            "indexes": indexes,
            "row_counts": counts,
        }


# --------------------------- Write operations ---------------------------
def get_or_create_server(ip_address: str, hostname: str | None = None) -> int:
    """Get server ID by IP address, create if doesn't exist.

    Args:
        ip_address: Server IP address
        hostname: Optional hostname

    Returns:
        int: Server ID
    """
    with get_db_connection() as conn:
        # Try to insert (ignores if already exists due to UNIQUE constraint)
        conn.execute(
            "INSERT OR IGNORE INTO servers (ip_address, hostname) VALUES (?, ?)",
            (ip_address, hostname),
        )

        # Get the ID (works whether we just inserted or it existed)
        result = conn.execute(
            "SELECT id FROM servers WHERE ip_address = ?", (ip_address,)
        ).fetchone()

        # Update last_seen timestamp
        conn.execute(
            "UPDATE servers SET last_seen = CURRENT_TIMESTAMP WHERE ip_address = ?",
            (ip_address,),
        )

        server_id: int = result["id"]
        return server_id


def insert_health_measurement(
    ip_address: str,
    rtt_ms: float,
    cpu_percent: float,
    memory_percent: float,
    memory_available_mb: float,
    disk_percent: float,
    server_timestamp: float | None = None,
) -> None:
    """Insert a health measurement into the database.

    Args:
        ip_address: Server IP address
        rtt_ms: Round-trip time in milliseconds
        cpu_percent: CPU usage percentage
        memory_percent: Memory usage percentage
        memory_available_mb: Available memory in MB
        disk_percent: Disk usage percentage
        server_timestamp: Optional timestamp from server
    """
    server_id = get_or_create_server(ip_address)

    with get_db_connection() as conn:
        try:
            conn.execute(
                """
                INSERT INTO health_measurements (
                    server_id, server_timestamp, rtt_ms,
                    cpu_percent, memory_percent, memory_available_mb, disk_percent
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    server_id,
                    server_timestamp,
                    rtt_ms,
                    cpu_percent,
                    memory_percent,
                    memory_available_mb,
                    disk_percent,
                ),
            )
        except sqlite3.Error:
            logger.exception("DB write failed: health_measurement ip=%s", ip_address)


def insert_icmp_event(
    ip_address: str,
    event_type: str,
    icmp_type: int | None = None,
    icmp_code: int | None = None,
    details: dict[str, Any] | str | None = None,
) -> None:
    """Insert an ICMP event (error, timeout, etc.) into the database.

    Args:
        ip_address: Server IP address
        event_type: Type of event ('timeout', 'dest_unreachable', etc.)
        icmp_type: ICMP type code
        icmp_code: ICMP code
        details: Additional details (dict will be JSON-encoded, str stored as-is)
    """
    server_id = get_or_create_server(ip_address)

    # Convert dict to JSON string
    if isinstance(details, dict):
        details = json.dumps(details)

    with get_db_connection() as conn:
        try:
            conn.execute(
                """
                INSERT INTO icmp_events (
                    server_id, event_type, icmp_type, icmp_code, details
                ) VALUES (?, ?, ?, ?, ?)
            """,
                (server_id, event_type, icmp_type, icmp_code, details),
            )
        except sqlite3.Error:
            logger.exception("DB write failed: icmp_event ip=%s", ip_address)


def insert_timestamp_measurement(
    ip_address: str,
    originate_ts: int,
    receive_ts: int,
    transmit_ts: int,
    clock_offset_ms: float,
) -> None:
    """Insert timestamp measurement for clock skew tracking.

    Args:
        ip_address: Server IP address
        originate_ts: Client originate timestamp
        receive_ts: Server receive timestamp
        transmit_ts: Server transmit timestamp
        clock_offset_ms: Calculated clock offset in milliseconds
    """
    server_id = get_or_create_server(ip_address)

    with get_db_connection() as conn:
        try:
            conn.execute(
                """
                INSERT INTO timestamp_measurements (
                    server_id, originate_ts, receive_ts, transmit_ts, clock_offset_ms
                ) VALUES (?, ?, ?, ?, ?)
            """,
                (
                    server_id,
                    originate_ts,
                    receive_ts,
                    transmit_ts,
                    clock_offset_ms,
                ),
            )
        except sqlite3.Error:
            logger.exception("DB write failed: timestamp_measurement ip=%s", ip_address)


# --------------------------- Read operations ---------------------------
def get_recent_measurements(ip_address: str, limit: int = 100) -> list[dict[str, Any]]:
    """Get recent health measurements for a server.

    Args:
        ip_address: Server IP address
        limit: Maximum number of measurements to return

    Returns:
        list[dict]: List of measurement records
    """
    with get_db_connection() as conn:
        cursor = conn.execute(
            """
            SELECT
                h.timestamp,
                h.server_timestamp,
                h.rtt_ms,
                h.cpu_percent,
                h.memory_percent,
                h.memory_available_mb,
                h.disk_percent
            FROM health_measurements h
            JOIN servers s ON h.server_id = s.id
            WHERE s.ip_address = ?
            ORDER BY h.timestamp DESC
            LIMIT ?
        """,
            (ip_address, limit),
        )

        return [dict(row) for row in cursor.fetchall()]


def get_server_stats(ip_address: str, hours: int = 24) -> dict[str, Any]:
    """Get statistics for a server over the last N hours.

    Args:
        ip_address: Server IP address
        hours: Number of hours to look back

    Returns:
        dict: Statistics including uptime %, avg RTT, avg CPU, etc.
    """
    with get_db_connection() as conn:
        # Get server ID
        result = conn.execute(
            "SELECT id FROM servers WHERE ip_address = ?", (ip_address,)
        ).fetchone()

        if not result:
            return {}

        server_id: int = result["id"]

        # Count successful measurements
        row = conn.execute(
            """
            SELECT COUNT(*) as count
            FROM health_measurements
            WHERE server_id = ?
              AND timestamp >= datetime('now', '-' || ? || ' hours')
        """,
            (server_id, hours),
        ).fetchone()
        measurement_count: int = row["count"] if row is not None else 0

        # Count timeouts
        row = conn.execute(
            """
            SELECT COUNT(*) as count
            FROM icmp_events
            WHERE server_id = ?
              AND event_type = 'timeout'
              AND timestamp >= datetime('now', '-' || ? || ' hours')
        """,
            (server_id, hours),
        ).fetchone()
        timeout_count: int = row["count"] if row is not None else 0

        # Calculate averages
        stats = conn.execute(
            """
            SELECT
                AVG(rtt_ms) as avg_rtt,
                MIN(rtt_ms) as min_rtt,
                MAX(rtt_ms) as max_rtt,
                AVG(cpu_percent) as avg_cpu,
                AVG(memory_percent) as avg_memory,
                AVG(disk_percent) as avg_disk
            FROM health_measurements
            WHERE server_id = ?
              AND timestamp >= datetime('now', '-' || ? || ' hours')
        """,
            (server_id, hours),
        ).fetchone()

        total_probes = measurement_count + timeout_count
        uptime_percent = (
            (measurement_count / total_probes * 100) if total_probes > 0 else 0
        )

        return {
            "ip_address": ip_address,
            "hours": hours,
            "total_probes": total_probes,
            "successful_probes": measurement_count,
            "timeouts": timeout_count,
            "uptime_percent": uptime_percent,
            "avg_rtt_ms": stats["avg_rtt"],
            "min_rtt_ms": stats["min_rtt"],
            "max_rtt_ms": stats["max_rtt"],
            "avg_cpu_percent": stats["avg_cpu"],
            "avg_memory_percent": stats["avg_memory"],
            "avg_disk_percent": stats["avg_disk"],
        }


def get_all_servers() -> list[dict[str, Any]]:
    """Get list of all monitored servers.

    Returns:
        list[dict]: Server information
    """
    with get_db_connection() as conn:
        cursor = conn.execute("""
            SELECT
                ip_address,
                hostname,
                first_seen,
                last_seen,
                description
            FROM servers
            ORDER BY last_seen DESC
        """)

        return [dict(row) for row in cursor.fetchall()]


# --------------------------- Maintenance operations ---------------------------
def cleanup_old_data(days: int) -> dict[str, int]:
    """Delete measurements and events older than N days.

    Args:
        days: Keep data newer than this many days

    Returns:
        dict: Number of rows deleted from each table
    """
    with get_db_connection() as conn:
        # Delete old health measurements
        before = conn.total_changes
        conn.execute(
            """
            DELETE FROM health_measurements
            WHERE timestamp < datetime('now', '-' || ? || ' days')
        """,
            (days,),
        )
        health_deleted = conn.total_changes - before

        # Delete old events
        before = conn.total_changes
        conn.execute(
            """
            DELETE FROM icmp_events
            WHERE timestamp < datetime('now', '-' || ? || ' days')
        """,
            (days,),
        )
        events_deleted = conn.total_changes - before

        # Delete old timestamp measurements
        before = conn.total_changes
        conn.execute(
            """
            DELETE FROM timestamp_measurements
            WHERE timestamp < datetime('now', '-' || ? || ' days')
        """,
            (days,),
        )
        timestamp_deleted = conn.total_changes - before

        # Reclaim disk space
        conn.execute("VACUUM")

        return {
            "health_measurements": health_deleted,
            "icmp_events": events_deleted,
            "timestamp_measurements": timestamp_deleted,
        }


def close_thread_connection() -> None:
    """Close the database connection for the current thread."""
    if hasattr(_thread_local, "conn") and _thread_local.conn:
        _thread_local.conn.close()
        _thread_local.conn = None


def set_db_path(path: str) -> None:
    """Override the SQLite database file path.

    Call this before any database access/initialization in the process.
    It closes any existing thread-local connection and updates the global path.

    Args:
        path: Filesystem path to the SQLite database file.
    """
    global db_path  # noqa: PLW0603
    # Ensure no thread holds an old connection
    close_thread_connection()
    db_path = str(Path(path).expanduser().resolve())
