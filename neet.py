"""
NetPulse - Local Network Scanner Backend
Requirements: pip install flask flask-cors scapy psutil requests
Run with: sudo python app.py  (sudo needed for ARP + traffic sniffing)
"""

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
import subprocess
import socket
import struct
import re
import threading
import time
import json
import requests
from collections import defaultdict
from database import (
    init_db,
    save_devices_to_db,
    save_scan_history,
    save_device_history,
    log_activity,
    get_devices_from_db,
    get_device_by_ip,
    get_device_by_mac,
    get_device_history_for_device,
    get_ports_for_device,
    save_port_scan,
    get_security_alerts_for_device,
    update_device_risk,
    save_security_alert,
    get_alert_count_for_device,
    get_connection,
    _rows_to_dicts
)
# ─── Database Config ─────────────────────────────────────────────────────────
DB_NAME = "unms.db"

# Try importing scapy (needed for ARP scan & traffic monitoring)
try:
    from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not installed. Install with: pip install scapy")

# Try importing psutil for traffic stats
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not installed. Install with: pip install psutil")

app = Flask(__name__)
CORS(app)

@app.route("/")
def home():
    return render_template("index.html")

# ─── Global Traffic Store ────────────────────────────────────────────────────
traffic_data = defaultdict(lambda: {"sent": 0, "recv": 0, "packets": 0, "last_seen": None})
traffic_lock = threading.Lock()
sniff_thread = None
sniffing = False

# ─── Utility: Get Local IP & Subnet ─────────────────────────────────────────
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "192.168.3.1"

def get_subnet(ip):
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

# ─── MAC Vendor Lookup ───────────────────────────────────────────────────────
def lookup_mac_vendor(mac):
    try:
        mac_clean = mac.upper().replace(":", "").replace("-", "")[:6]
        url = f"https://api.macvendors.com/{mac}"
        resp = requests.get(url, timeout=3)
        if resp.status_code == 200:
            return resp.text.strip()
    except:
        pass
    # Fallback offline OUI table (common vendors)
    oui_table = {
        "000C29": "VMware",
        "001A2B": "Cisco",
        "0050F2": "Microsoft",
        "BC5FF4": "Apple",
        "F4F5E8": "Google",
        "1C61B4": "Samsung",
        "AC:DE:48": "Apple",
        "00:1B:44": "SanDisk",
        "DC:A6:32": "Raspberry Pi",
        "B8:27:EB": "Raspberry Pi",
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
    }
    mac_prefix = mac.upper()[:8]
    for prefix, vendor in oui_table.items():
        if mac_prefix.startswith(prefix.upper()):
            return vendor
    return "Unknown Vendor"

# ─── Resolve Hostname ────────────────────────────────────────────────────────
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

# ─── ARP Scan ────────────────────────────────────────────────────────────────
def arp_scan(subnet):
    devices = []
    if not SCAPY_AVAILABLE:
        # Fallback: use arp -a system command
        return arp_scan_fallback()
    
    try:
        conf.verb = 0
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            ip = received.psrc
            mac = received.hwsrc
            hostname = resolve_hostname(ip)
            vendor = lookup_mac_vendor(mac)
            devices.append({
                "ip": ip,
                "mac": mac.upper(),
                "hostname": hostname,
                "vendor": vendor,
                "status": "online"
            })
    except Exception as e:
        print(f"ARP scan error: {e}")
        return arp_scan_fallback()
    
    return devices

def arp_scan_fallback():
    """Use system arp -a command as fallback"""
    devices = []
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, timeout=10)
        for line in output.splitlines():
            # Match IP and MAC from arp -a output
            ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
            mac_match = re.search(r'([0-9a-fA-F]{1,2}[:\-]){5}[0-9a-fA-F]{1,2}', line)
            if ip_match and mac_match:
                ip = ip_match.group(1)
                mac = mac_match.group(0).upper()
                # Normalize MAC format
                mac = ":".join(part.zfill(2) for part in mac.replace("-", ":").split(":"))
                hostname = resolve_hostname(ip)
                vendor = lookup_mac_vendor(mac)
                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "vendor": vendor,
                    "status": "online"
                })
    except Exception as e:
        print(f"ARP fallback error: {e}")
    return devices

# ─── Port Scanner ────────────────────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 6379: "Redis", 5432: "PostgreSQL"
}

def scan_ports(ip, ports=None):
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                open_ports.append({"port": port, "service": service, "state": "open"})
            s.close()
        except:
            pass
    return open_ports

# ─── Traffic Monitoring ──────────────────────────────────────────────────────
def packet_callback(packet):
    if not SCAPY_AVAILABLE:
        return
    try:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            size = len(packet)
            with traffic_lock:
                traffic_data[src]["sent"] += size
                traffic_data[src]["packets"] += 1
                traffic_data[src]["last_seen"] = time.strftime("%H:%M:%S")
                traffic_data[dst]["recv"] += size
                traffic_data[dst]["last_seen"] = time.strftime("%H:%M:%S")
    except:
        pass

def start_sniffing():
    global sniffing
    if SCAPY_AVAILABLE:
        try:
            sniff(prn=packet_callback, store=False, stop_filter=lambda x: not sniffing, timeout=300)
        except Exception as e:
            print(f"Sniff error: {e}")

def get_interface_traffic():
    """Get overall interface traffic using psutil"""
    if not PSUTIL_AVAILABLE:
        return {}
    try:
        stats = psutil.net_io_counters(pernic=True)
        result = {}
        for iface, data in stats.items():
            result[iface] = {
                "bytes_sent": data.bytes_sent,
                "bytes_recv": data.bytes_recv,
                "packets_sent": data.packets_sent,
                "packets_recv": data.packets_recv,
            }
        return result
    except:
        return {}

# ─── Database Setup ──────────────────────────────────────────────────────────

# ─── Save Scanned Devices ────────────────────────────────────────────────────

# ─── Save Scan History ───────────────────────────────────────────────────────

# ─── Save Device History ─────────────────────────────────────────────────────

# ─── API Routes ──────────────────────────────────────────────────────────────

@app.route("/api/info", methods=["GET"])
def get_info():
    local_ip = get_local_ip()
    subnet = get_subnet(local_ip)
    return jsonify({
        "local_ip": local_ip,
        "subnet": subnet,
        "hostname": socket.gethostname(),
        "scapy_available": SCAPY_AVAILABLE,
        "psutil_available": PSUTIL_AVAILABLE
    })

@app.route("/api/scan", methods=["GET"])
@app.route("/api/scan", methods=["GET"])
def scan_network():
    local_ip = get_local_ip()
    subnet = get_subnet(local_ip)

    try:
        devices = arp_scan(subnet)
    except Exception:
        # The scan itself blew up -> log it as failed, not completed,
        # then let the error propagate exactly like it did before Step 3.
        save_scan_history(0, "failed")
        raise

    save_devices_to_db(devices)
    save_scan_history(len(devices), "completed")
    save_device_history(devices)

        # Add current risk information to every scanned device
    for device in devices:
        db_device = get_device_by_ip(device["ip"])

        if db_device:
            device["risk_score"] = db_device.get("risk_score") or 0
            device["risk_level"] = db_device.get("risk_level") or "LOW"
            device["risk"] = device["risk_level"]
        else:
            device["risk_score"] = 0
            device["risk_level"] = "LOW"
            device["risk"] = "LOW"

    return jsonify({
    "subnet": subnet,
    "device_count": len(devices),
    "devices": devices
})

@app.route("/api/ports/<ip>", methods=["GET"])
def get_ports(ip):

    device = get_device_by_ip(ip)

    if not device:
        return jsonify({
            "error": "Device not found"
        }), 404

    ports = scan_ports(ip)

    save_port_scan(
        device["id"],
        ports
    )

    return jsonify({
        "ip": ip,
        "open_ports": ports,
        "total_open": len(ports)
    })
@app.route("/api/traffic", methods=["GET"])
def get_traffic():
    interface_stats = get_interface_traffic()
    with traffic_lock:
        per_device = dict(traffic_data)
    return jsonify({
        "interface_stats": interface_stats,
        "per_device_traffic": per_device
    })

@app.route("/api/traffic/start", methods=["POST"])
def start_traffic_monitor():
    global sniff_thread, sniffing
    if not sniffing:
        sniffing = True
        sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        sniff_thread.start()
        return jsonify({"status": "started"})
    return jsonify({"status": "already_running"})

@app.route("/api/traffic/stop", methods=["POST"])
def stop_traffic_monitor():
    global sniffing
    sniffing = False
    return jsonify({"status": "stopped"})

@app.route("/api/device/<ip>")
def device_details(ip):

    device = get_device_by_ip(ip)

    if not device:
        return jsonify({
            "error": "Device not found"
        }), 404

    device_id = device["id"]

    history = get_device_history_for_device(device_id)

    ports = get_ports_for_device(device_id)

    alerts = get_security_alerts_for_device(device_id)

    risk_score = device.get("risk_score") or 0
    risk_level = device.get("risk_level") or "LOW"

    # Build a simple investigation story from real information
    story = []

    story.append(
        f"Device was first seen on {device.get('first_seen', '—')}."
    )

    if device.get("last_seen"):
        story.append(
            f"Last detected on {device['last_seen']}."
        )

    if device.get("vendor"):
        story.append(
            f"Vendor identified as {device['vendor']}."
        )

    story.append(
        f"Current risk level is {risk_level} with a risk score of {risk_score}."
    )

    if ports:
        story.append(
            f"{len(ports)} stored open-port result(s) are available."
        )
    else:
        story.append(
            "No stored open-port results are available yet."
        )

    if alerts:
        story.append(
            f"{len(alerts)} security alert(s) are associated with this device."
        )
    else:
        story.append(
            "No security alerts are currently recorded for this device."
        )

 # Timeline from real device history
 
    # Timeline from real device history
    timeline = []

# Device detection history
   # Device detection history
    if history:
        first = history[-1]
        last = history[0]

        timeline.append({
            "time": first.get("detected_at"),
            "title": "Device first detected",
            "text": (
                f"Device was first observed at "
                f"{first.get('ip_address', '—')} "
                f"with status "
                f"{first.get('status', '—')}."
            )
        })

        if last.get("detected_at") != first.get("detected_at"):
            timeline.append({
                "time": last.get("detected_at"),
                "title": "Device last detected",
                "text": (
                    f"Device was last observed at "
                    f"{last.get('ip_address', '—')} "
                    f"with status "
                    f"{last.get('status', '—')}."
                )
            })

# Security alerts
    for alert in alerts:
      timeline.append({
        "time": alert.get("alert_time"),
        "title": alert.get("title") or "Security alert",
        "text": (
            alert.get("description")
            or alert.get("evidence")
            or "Security issue detected."
        )
    })

# Open-port findings
    for port in ports:
      if str(port.get("state", "")).lower() == "open":
        timeline.append({
            "time": port.get("scanned_at"),
            "title": "Open port detected",
            "text": (
                f"Port {port.get('port', '—')} "
                f"({port.get('service', 'Unknown service')}) "
                f"is open."
            )
        })

# Show newest events first
        timeline.sort(
    key=lambda x: x.get("time") or "",
    reverse=True
)

    device_traffic = traffic_data.get(
        ip,
        {
            "sent": 0,
            "recv": 0,
            "packets": 0,
            "last_seen": None
        }
    )

    sent = device_traffic.get("sent", 0)
    recv = device_traffic.get("recv", 0)

    total = sent + recv

    incoming_pct = round(
        (recv / total) * 100, 1
    ) if total else 0

    outgoing_pct = round(
        (sent / total) * 100, 1
    ) if total else 0

    traffic = {
        "incoming": recv,
        "outgoing": sent,
        "packets": device_traffic.get("packets", 0),
        "last_activity": device_traffic.get("last_seen") or "No activity",
        "monitoring": "Active" if sniffing else "Stopped",
        "incoming_pct": incoming_pct,
        "outgoing_pct": outgoing_pct
    }

    return jsonify({
        "id": device.get("id"),
        "device_id": device_id,

        "hostname": device.get("device_name"),
        "device_name": device.get("device_name"),

        "ip": device.get("ip_address"),
        "ip_address": device.get("ip_address"),

        "mac": device.get("mac_address"),
        "mac_address": device.get("mac_address"),

        "vendor": device.get("vendor"),

        "status": device.get("status"),

        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk": risk_level,

        "first_seen": device.get("first_seen"),
        "last_seen": device.get("last_seen"),

        "open_ports": ports,
        "open_ports_count": len(ports),

        "alerts": alerts,
        "alerts_count": len(alerts),

        "history": history,

        "story": story,
        "timeline": timeline,

        "traffic": traffic_data.get(
            ip,
            {
                "sent": 0,
                "recv": 0,
                "packets": 0,
                "last_seen": None
            }
        )
    })


    # Save alerts for actual security-relevant findings
    for finding in findings:

        save_security_alert(
            device_id=device_id,
            alert_type="OPEN_PORT",
            severity=finding["severity"],
            title=finding["title"],
            description=finding["description"],
            evidence=f"Port {finding['port']} ({finding['service']}) is open.",
            risk_score=risk_score
        )

    alert_count = get_alert_count_for_device(device_id)

    return jsonify({
        "status": risk_level,
        "risk_level": risk_level,
        "risk_score": risk_score,

        "findings": findings,
        "open_port_findings": open_port_findings,

        "critical": severity_counts["CRITICAL"],
        "high": severity_counts["HIGH"],
        "medium": severity_counts["MEDIUM"],
        "low": severity_counts["LOW"],

        "alerts_count": alert_count,

        "message": (
            "Security assessment completed using the "
            "stored port-scan results."
        )
    })
@app.route("/api/log-history")
def get_log_history():

    ip = request.args.get("ip")

    if not ip:
        return jsonify({
            "history": [],
            "message": "No device IP provided."
        })

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            hostname,
            ip_address,
            mac_address,
            status,
            detected_at
        FROM device_history
        WHERE ip_address = ?
        ORDER BY id DESC
        LIMIT 10;
        """,
        (ip,)
    )

    rows = cursor.fetchall()
    history = _rows_to_dicts(cursor, rows)

    conn.close()

    return jsonify({
        "history": history
    })
# ─── Run ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  NetPulse - Network Scanner Backend")
    print("  Running at: http://localhost:5000")
    print("  NOTE: Run with sudo for full scanning features")
    print("=" * 50)
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)