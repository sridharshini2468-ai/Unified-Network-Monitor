import sqlite3

conn = sqlite3.connect("unms.db")
cursor = conn.cursor()

rows = cursor.execute("""
SELECT id, device_id, alert_type, title, evidence
FROM security_alerts
WHERE device_id = 1
""").fetchall()

for row in rows:
    print(row)

conn.close()