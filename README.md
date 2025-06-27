#  Network Packet Sniffer (Python + Scapy + Flet)

A lightweight, real-time **network packet sniffer** with a modern GUI built using **Python**, **Scapy**, and **Flet**. It captures and displays live packets with filtering options and can export results to CSV.

---

## Features

- Real-time packet sniffing
- IP and Protocol-based filtering (TCP, UDP, ICMP, ARP, DNS, HTTP)
- Export captured logs to CSV
- Modern cross-platform desktop GUI (Flet)
- Minimal setup, easy to use

---

##  Requirements

- Python 3.10 or later
- Internet connection (to download dependencies)

###  Installation
bash
pip install flet scapy

### How to Run the Project
Option 1: Run via Batch File (Recommended for Windows)
Right-click on run_sniffer_admin.bat

Select Run as Administrator

This opens the GUI with full permissions for raw socket capture (required by Scapy)

Option 2: Run Manually via Terminal
bash
Copy
Edit
python gui.py
GUI will open

(Optional) Enter an IP or protocol filter
(Leave it blank if you want to analyse the packet traffic of all the protocols and IP

Click Start Sniffing to capture packets

Click Export CSV to save logs to packet_logs.csv

### Project files
| File Name               | Purpose                                                       |
| ----------------------- | ------------------------------------------------------------- |
| `gui.py`                | Main GUI application for packet sniffing                      |
| `run_sniffer_admin.bat` | Launches `gui.py` with admin privileges (Windows only)        |
| `packet_logs.csv`       | Exported log file containing sniffed packets (auto-generated) |
| `README.md`             | Complete documentation and project report                     |
| `alert logs`            | Documentation of alerts generated when packet flooding happens|
