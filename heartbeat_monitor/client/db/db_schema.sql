-- Database schema for Health Monitor

-- Enable WAL mode (must be done at connection level, not in .sql file)
-- See init_database() in db.py

-- Server registry
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    hostname TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,
    description TEXT
);

-- Health metric measurements (time-series data)
CREATE TABLE IF NOT EXISTS health_measurements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    server_timestamp REAL,        -- Timestamp from server's health payload
    rtt_ms REAL,                   -- Round-trip time in milliseconds
    cpu_percent REAL,
    memory_percent REAL,
    memory_available_mb REAL,
    disk_percent REAL,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

-- ICMP events (errors, timeouts, etc.)
CREATE TABLE IF NOT EXISTS icmp_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,      -- 'timeout', 'dest_unreachable', 'time_exceeded', etc.
    icmp_type INTEGER,             -- ICMP type code
    icmp_code INTEGER,             -- ICMP code
    details TEXT,                  -- JSON or text description
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

-- Timestamp measurements (for clock skew tracking)
CREATE TABLE IF NOT EXISTS timestamp_measurements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    originate_ts INTEGER,          -- Client's originate timestamp
    receive_ts INTEGER,            -- Server's receive timestamp
    transmit_ts INTEGER,           -- Server's transmit timestamp
    clock_offset_ms REAL,          -- Calculated clock offset
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

-- Indexes for query performance
CREATE INDEX IF NOT EXISTS idx_health_server_time 
    ON health_measurements(server_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_events_server_time 
    ON icmp_events(server_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_timestamp_server_time 
    ON timestamp_measurements(server_id, timestamp DESC);