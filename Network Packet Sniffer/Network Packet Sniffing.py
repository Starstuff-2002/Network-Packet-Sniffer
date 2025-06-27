import sqlite3, time, csv
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS
from scapy.layers.http import HTTPRequest
from datetime import datetime

protocol_filter = input("Protocol (TCP/UDP/ICMP/ARP/HTTP/DNS, blank=all): ").strip().upper()
ip_filter = input("IP filter (blank=all): ").strip()
export_csv = input("Export to CSV? (y/n): ").strip().lower() == 'y'

conn = sqlite3.connect("packet_logs.db")
cursor = conn.cursor()
cursor.execute("""CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY, src_ip TEXT, dst_ip TEXT, protocol TEXT, length INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
conn.commit()

counts = {}

def get_proto(packet):
    if HTTPRequest in packet:
        return "HTTP"
    if DNS in packet:
        return "DNS"
    if ARP in packet:
        return "ARP"
    if IP in packet:
        if TCP in packet:
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif ICMP in packet:
            return "ICMP"
        else:
            return f"IP_PROTO_{packet[IP].proto}"
    return "Unknown"

def packet_callback(pkt):
    proto = get_proto(pkt)
    if protocol_filter and proto.upper() != protocol_filter:
        return

    if ip_filter:
        if IP in pkt and ip_filter not in [pkt[IP].src, pkt[IP].dst]:
            return
        if ARP in pkt and ip_filter not in [pkt[ARP].psrc, pkt[ARP].pdst]:
            return

    if HTTPRequest in pkt:
        try:
            host = pkt[HTTPRequest].Host.decode(errors='ignore')
            path = pkt[HTTPRequest].Path.decode(errors='ignore')
            print(f"HTTP: {host}{path}")
        except:
            pass
    elif DNS in pkt and pkt[DNS].qd:
        print(f"DNS Query: {pkt[DNS].qd.qname.decode()}")

    if ARP in pkt:
        src, dst = pkt[ARP].psrc, pkt[ARP].pdst
    elif IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    else:
        return

    print(f"{src} → {dst} | {proto} | {len(pkt)} bytes")
    cursor.execute("INSERT INTO packets (src_ip, dst_ip, protocol, length) VALUES (?, ?, ?, ?)", (src, dst, proto, len(pkt)))
    conn.commit()

    now = time.time()
    counts.setdefault(src, []).append(now)
    counts[src] = [t for t in counts[src] if now - t < 10]
    if len(counts[src]) > 30:
        with open("alerts.log", "a") as f:
            f.write(f"[{datetime.now()}] ALERT: {src} sent {len(counts[src])} packets in 10s\n")

def export_to_csv():
    rows = cursor.execute("SELECT * FROM packets").fetchall()
    with open("packet_logs.csv", "w", newline="") as f:
        csv.writer(f).writerows([["ID", "Source IP", "Destination IP", "Protocol", "Length", "Timestamp"]] + rows)
    print("✅ Exported to packet_logs.csv")

sniff(prn=packet_callback, store=False, count=50)
if export_csv:
    export_to_csv()
