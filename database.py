"""
database.py
────────────
All SQLite database logic for UNM lives here, separate from the Flask
routes in neet.py. This file is responsible for:

  - Creating the database and tables (from schema.sql) on first run
  - Safely adding new columns to an already-existing database
  - Saving scanned devices, scan history, and device history
  - Writing to the activity log

Nothing in this file ever deletes existing rows or tables.
"""

import sqlite3
import time


DB_NAME = "unms.db"
SCHEMA_FILE = "schema.sql"


def get_connection():
    """Open a connection to unms.db with foreign key checks turned on."""
    conn = sqlite3.connect(DB_NAME)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """
    Sets up the database. Safe to call every time the app starts:
      1. Runs schema.sql, which uses CREATE TABLE IF NOT EXISTS for
         every table — so on a brand new database, all tables get
         created; on an existing database, nothing is touched.
      2. Runs _migrate_existing_tables(), which adds any NEW columns
         (like 'vendor' or 'risk_score') to tables that already existed
         from an older version of this project — without deleting any
         existing rows.
    """
    conn = get_connection()

    with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit() 

    _migrate_existing_tables(conn)
    _ensure_extra_tables(conn)

    

    conn.close()
    print("[DB] unms.db ready — schema checked/created.")


def _migrate_existing_tables(conn):
    """
    CREATE TABLE IF NOT EXISTS only creates a table the FIRST time —
    it will not add a new column to a table that already exists from
    before. So if you already had unms.db from an earlier version of
    this project, this function adds the missing columns on top of it,
    without touching any existing rows.

    Each ALTER TABLE is wrapped in try/except because SQLite has no
    "ADD COLUMN IF NOT EXISTS" — if the column is already there, SQLite
    raises an error, which we simply ignore.
    """
    cursor = conn.cursor()

    migrations = [
        ("devices", "vendor", "TEXT"),
        ("devices", "risk_score", "INTEGER DEFAULT 0"),
        ("devices", "risk_level", "TEXT DEFAULT 'LOW'"),
        ("scan_history", "subnet", "TEXT"),
        ("device_history", "hostname", "TEXT"),
        ("device_history", "risk_score", "INTEGER"),
        ("security_alerts", "title", "TEXT"),
        ("security_alerts", "evidence", "TEXT"),
        ("security_alerts", "risk_score", "INTEGER"),
    ]

    for table, column, col_type in migrations:
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type};")
            print(f"[DB] migrated: added '{column}' column to '{table}'")
        except sqlite3.OperationalError:
            pass  # column already exists — nothing to do

    conn.commit()


# ─── Save Scanned Devices ────────────────────────────────────────────
def save_devices_to_db(devices):
    """
    Takes the list of device dicts returned by arp_scan() and saves
    each one into the 'devices' table.

    Logic per device (MAC address is the identity):
      - If a device with this MAC already exists -> UPDATE its ip,
        hostname, vendor, status, last_seen. first_seen is left alone.
      - If not found -> INSERT a new row, first_seen == last_seen.
    """
    now = time.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()

    for device in devices:
        ip = device.get("ip")
        mac = device.get("mac")
        hostname = device.get("hostname")
        vendor = device.get("vendor")
        status = device.get("status")

        cursor.execute("SELECT id FROM devices WHERE mac_address = ?;", (mac,))
        existing = cursor.fetchone()

        if existing:
            cursor.execute(
                """
                UPDATE devices
                SET ip_address = ?, device_name = ?, vendor = ?, status = ?, last_seen = ?
                WHERE mac_address = ?;
                """,
                (ip, hostname, vendor, status, now, mac)
            )
        else:
            cursor.execute(
                """
                INSERT INTO devices
                    (device_name, ip_address, mac_address, vendor, status, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (hostname, ip, mac, vendor, status, now, now)
            )

    conn.commit()
    conn.close()


# ─── Save Scan History ───────────────────────────────────────────────
def save_device_history(devices):
    """
    Inserts one row into device_history for every device
    found in the current scan.
    """

    now = time.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()

    for device in devices:
        ip = device.get("ip")
        mac = device.get("mac")
        hostname = device.get("hostname")
        status = device.get("status")

        cursor.execute(
            "SELECT id, risk_score FROM devices WHERE mac_address = ?;",
            (mac,)
        )

        row = cursor.fetchone()

        if row:
            device_id = row[0]
            risk_score = row[1]
        else:
            device_id = None
            risk_score = 0

        cursor.execute(
            """
            INSERT INTO device_history
                (device_id, ip_address, mac_address, hostname, status, risk_score, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                device_id,
                ip,
                mac,
                hostname,
                status,
                risk_score,
                now
            )
        )

    conn.commit()
    conn.close()
# ─── Save Scan History ───────────────────────────────────────────────
def save_scan_history(devices_detected, scan_status):
    """Save one record for each network scan."""

    now = time.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO scan_history
            (scan_time, devices_detected, scan_status)
        VALUES (?, ?, ?);
        """,
        (now, devices_detected, scan_status)
    )

    conn.commit()
    conn.close()

# ─── Activity Log ─────────────────────────────────────────────────────
def log_activity(action, device=None, result=None, severity=None):
    """
    Writes one row to activity_logs. Call this for things like:
      log_activity("Network scan started")
      log_activity("Device discovered", device="192.168.1.5", result="success")
      log_activity("Network scan failed", result="error", severity="HIGH")
    """
    now = time.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO activity_logs (timestamp, action, device, result, severity)
        VALUES (?, ?, ?, ?, ?);
        """,
        (now, action, device, result, severity)
    )

    conn.commit()
    conn.close()

    # ─── Read Scan History ────────────────────────────────────────────────
def get_scan_history(limit=100):
    """Return the latest scan history records."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            scan_time,
            subnet,
            devices_detected,
            scan_status
        FROM scan_history
        ORDER BY id DESC
        LIMIT ?;
        """,
        (limit,)
    )

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "scan_time": row[1],
            "subnet": row[2],
            "devices_detected": row[3],
            "scan_status": row[4]
        }
        for row in rows
    ]


# ─── Read Device History ─────────────────────────────────────────────
def get_device_history(limit=200):
    """Return the latest device observations."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            device_id,
            ip_address,
            mac_address,
            hostname,
            status,
            risk_score,
            detected_at
        FROM device_history
        ORDER BY id DESC
        LIMIT ?;
        """,
        (limit,)
    )

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "device_id": row[1],
            "ip_address": row[2],
            "mac_address": row[3],
            "hostname": row[4],
            "status": row[5],
            "risk_score": row[6],
            "detected_at": row[7]
        }
        for row in rows
    ]


# ─── Read Activity Logs ──────────────────────────────────────────────
def get_activity_logs(limit=200):
    """Return the latest activity logs."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            timestamp,
            action,
            device,
            result,
            severity
        FROM activity_logs
        ORDER BY id DESC
        LIMIT ?;
        """,
        (limit,)
    )

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "timestamp": row[1],
            "action": row[2],
            "device": row[3],
            "result": row[4],
            "severity": row[5]
        }
        for row in rows
    ]

def _rows_to_dicts(cursor, rows):
    """Turn sqlite3 rows into a list of dicts using the column names."""
    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in rows]
 
 
# ─── Ensure the ports table exists (safe to call every time) ─────────
def _ensure_extra_tables(conn):
    """
    Creates device_ports if it doesn't already exist.
    Uses CREATE TABLE IF NOT EXISTS, same as schema.sql — never deletes data.
    Call this once from init_db(), right after _migrate_existing_tables(conn).
    """
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            port INTEGER,
            protocol TEXT,
            state TEXT,
            service TEXT,
            scanned_at TEXT,
            FOREIGN KEY (device_id) REFERENCES devices (id)
        );
    """)
    conn.commit()
 
 
# ─── Read All Devices ─────────────────────────────────────────────────
def get_devices_from_db():
    """Return every device as a list of dicts, most recently seen first."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC;")
    rows = cursor.fetchall()
    result = _rows_to_dicts(cursor, rows)
    conn.close()
    return result
 
 
# ─── Read One Device ───────────────────────────────────────────────────
def get_device_by_ip(ip_address):
    """Return one device dict by current IP address, or None."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE ip_address = ?;", (ip_address,))
    row = cursor.fetchone()
    if row is None:
        conn.close()
        return None
    result = _rows_to_dicts(cursor, [row])[0]
    conn.close()
    return result
 
 
def get_device_by_mac(mac_address):
    """Return one device dict by MAC address, or None."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE mac_address = ?;", (mac_address,))
    row = cursor.fetchone()
    if row is None:
        conn.close()
        return None
    result = _rows_to_dicts(cursor, [row])[0]
    conn.close()
    return result
 
 
# ─── Read History For One Device ───────────────────────────────────────
def get_device_history_for_device(device_id, limit=100):
    """
    Return history rows for ONE device (used by the Device Details page's
    History/Timeline section). Your existing get_device_history() is
    unchanged and still returns the global log.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM device_history
        WHERE device_id = ?
        ORDER BY id ASC
        LIMIT ?;
        """,
        (device_id, limit)
    )
    rows = cursor.fetchall()
    result = _rows_to_dicts(cursor, rows)
    conn.close()
    return result
 
 
# ─── Ports ──────────────────────────────────────────────────────────────
def save_port_scan(device_id, ports):
    """
    Replace stored port results for a device with a fresh scan.
    'ports' is a list of dicts: {"port": 80, "protocol": "TCP",
                                  "state": "open", "service": "HTTP"}
    """
    now = time.strftime("%Y-%m-%d %H:%M:%S")
 
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM device_ports WHERE device_id = ?;", (device_id,))
 
    for p in ports:
        cursor.execute(
            """
            INSERT INTO device_ports (device_id, port, protocol, state, service, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (device_id, p.get("port"), p.get("protocol"),
             p.get("state"), p.get("service"), now)
        )
 
    conn.commit()
    conn.close()
 
 
def get_ports_for_device(device_id):
    """Return the most recently stored port scan results for one device."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT port, protocol, state, service, scanned_at
        FROM device_ports
        WHERE device_id = ?
        ORDER BY port ASC;
        """,
        (device_id,)
    )
    rows = cursor.fetchall()
    result = _rows_to_dicts(cursor, rows)
    conn.close()
    return result
 
 
# ─── Security Alerts (reads what your migrations already write columns for) ──
def get_alert_count_for_device(device_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM security_alerts
        WHERE device_id = ?
        AND alert_status = 'open'
        """,
        (device_id,)
    )

    count = cursor.fetchone()[0]

    conn.close()

    return count
    alerts = []

    for row in rows:
        alerts.append({
            "id": row[0],
            "alert_type": row[1],
            "severity": row[2],
            "title": row[3],
            "description": row[4],
            "evidence": row[5],
            "risk_score": row[6],
            "alert_time": row[7],
            "alert_status": row[8]
        })
    return alerts

def update_device_risk(device_id, risk_score, risk_level):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE devices
        SET risk_score = ?, risk_level = ?
        WHERE id = ?
        """,
        (risk_score, risk_level, device_id)
    )

    conn.commit()
    conn.close()


def save_security_alert(
    device_id,
    alert_type,
    severity,
    title,
    description,
    evidence,
    risk_score
):
    conn = get_connection()
    cursor = conn.cursor()

    # Check whether the same open alert already exists
    cursor.execute(
        """
        SELECT id
        FROM security_alerts
        WHERE device_id = ?
        AND alert_type = ?
        AND title = ?
        AND evidence = ?
        AND alert_status = 'open'
        LIMIT 1
        """,
        (
            device_id,
            alert_type,
            title,
            evidence
        )
    )

    existing = cursor.fetchone()

    if existing:
        # Update the existing alert instead of creating a duplicate
        cursor.execute(
            """
            UPDATE security_alerts
            SET severity = ?,
                description = ?,
                risk_score = ?,
                alert_time = datetime('now')
            WHERE id = ?
            """,
            (
                severity,
                description,
                risk_score,
                existing[0]
            )
        )
    else:
        # Create a new alert only if it does not already exist
        cursor.execute(
            """
            INSERT INTO security_alerts
            (
                device_id,
                alert_type,
                severity,
                title,
                description,
                evidence,
                risk_score,
                alert_time,
                alert_status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), 'open')
            """,
            (
                device_id,
                alert_type,
                severity,
                title,
                description,
                evidence,
                risk_score
            )
        )

    conn.commit()
    conn.close()

def get_security_alerts_for_device(device_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            alert_type,
            severity,
            title,
            description,
            evidence,
            risk_score,
            alert_time,
            alert_status
        FROM security_alerts
        WHERE device_id = ?
        AND alert_status = 'open'
        ORDER BY alert_time DESC
        """,
        (device_id,)
    )

    rows = cursor.fetchall()
    conn.close()

    alerts = []

    for row in rows:
        alerts.append({
            "id": row[0],
            "alert_type": row[1],
            "severity": row[2],
            "title": row[3],
            "description": row[4],
            "evidence": row[5],
            "risk_score": row[6],
            "alert_time": row[7],
            "alert_status": row[8]
        })

    return alerts
  
 