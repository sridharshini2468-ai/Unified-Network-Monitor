# Unified Network Monitoring System (UNMS)

A Python-based network monitoring application developed as a final-year academic project.

## About the Project

Unified Network Monitoring System (UNMS) is designed to monitor devices connected to a local network.

The application can scan the network, identify connected devices, display device details, monitor open ports, and maintain device history.

## Features

- Network device scanning
- Device IP and MAC address detection
- Hostname and vendor information
- Device details
- Open port scanning
- Device history
- Network traffic information
- Scan status and device count
- Logs and activity history

## Technologies Used

- Python
- Flask
- SQLite
- HTML
- CSS
- JavaScript
- Scapy
- Psutil

## Project Structure

```text
UNMS/
├── neet.py
├── database.py
├── schema.sql
├── check_alerts.py
├── cleanup_alerts.py
├── templates/
│   └── index.html
├── static/
│   ├── net.js
│   ├── script.js
│   ├── style.css
│   ├── net.css
│   └── image.png
└── .gitignore
