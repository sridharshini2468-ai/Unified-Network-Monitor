-- ═══════════════════════════════════════════════════════════════════
-- UNM (Unified Network Monitor) — Database Schema
-- Every CREATE TABLE uses IF NOT EXISTS, so running this on an
-- existing database never deletes or overwrites existing data.
-- ═══════════════════════════════════════════════════════════════════

-- devices: ONE row per physical device. MAC address is the identity —
-- if the same MAC shows up again with a different IP, we UPDATE the
-- existing row instead of creating a duplicate.
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_name TEXT,
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL UNIQUE,
    vendor TEXT,
    status TEXT DEFAULT 'unknown',
    risk_score INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'LOW',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

-- scan_history: ONE row per scan attempt (successful or failed).
-- This is what powers the "previous scans" list on the History page.
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_time TEXT NOT NULL,
    subnet TEXT,
    devices_detected INTEGER DEFAULT 0,
    scan_status TEXT DEFAULT 'completed'
);

-- device_history: a running log — ONE row EVERY time a device is seen
-- in a scan, even if it was already seen before. This is what lets us
-- show "how a device changed over time".
CREATE TABLE IF NOT EXISTS device_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    ip_address TEXT,
    mac_address TEXT,
    hostname TEXT,
    status TEXT,
    risk_score INTEGER,
    detected_at TEXT NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- security_alerts: security-relevant events tied to a device
-- (new device detected, risky port found, status changed, etc.)
CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT,
    description TEXT,
    evidence TEXT,
    risk_score INTEGER,
    alert_time TEXT NOT NULL,
    alert_status TEXT DEFAULT 'open',
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- traffic_records: periodic traffic snapshots per device
CREATE TABLE IF NOT EXISTS traffic_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    ip_address TEXT,
    upload_bytes INTEGER DEFAULT 0,
    download_bytes INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- activity_logs: general action log — "Network scan started",
-- "Device discovered", "Risk score calculated", etc. This is what the
-- Logs page will show (it was previously just fake hardcoded rows).
CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    device TEXT,
    result TEXT,
    severity TEXT
);