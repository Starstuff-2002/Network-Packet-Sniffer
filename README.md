# Network Packet Sniffer (Python + Scapy + Flet)

This project is a lightweight, real-time network packet sniffer with a GUI built using Flet and Scapy.

##  Features

- Real-time packet sniffing
- Protocol and IP-based filtering
- Export logs to CSV
- Modern desktop UI (cross-platform)

##  Requirements

- Python 3.10+
- Install required packages:
  ```bash
  pip install flet scapy

▶ How to Run
Clone this repository or download the files.

Run the main file:

bash
Copy
Edit
python gui.py
The GUI will open. Enter optional filters and click "Start Sniffing".

After sniffing, click "Export CSV" to save the logs.

Files
gui.py: Main application
network packet sniffer (the file with the logic)
run_sniffer_admin.bat (batch file which gives packet sniffing (via Scapy), access to raw sockets
packet_logs.csv: Exported logs (generated after sniffing)
