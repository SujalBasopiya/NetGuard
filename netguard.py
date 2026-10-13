#!/usr/bin/env python3
"""
NetGuard - Network Security Scanner & Intrusion Detection Tool
For authorized use on your own lab/network only.

Usage:
  python netguard.py scan 192.168.1.10 -p 1-1024
  python netguard.py discover 192.168.1.0/24
  sudo python netguard.py sniff -i eth0 --duration 60
"""
import argparse
import csv
import ipaddress
import socket
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
}
RISKY_PORTS = {21: "FTP sends data unencrypted", 23: "Telnet is unencrypted",
               445: "SMB often targeted by exploits", 3389: "RDP exposed to network"}


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


# ---------------------------------------------------------------- scanner
def grab_banner(ip, port, timeout=1.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8000, 8080):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(128).decode(errors="ignore").strip().splitlines()
            return data[0][:80] if data else ""
    except Exception:
        return ""


def check_port(ip, port, timeout=0.7):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port
    except Exception:
        return None


def scan_host(ip, ports, threads=200):
    print(f"[{now()}] Scanning {ip} ({len(ports)} ports)...")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        open_ports = sorted(p for p in ex.map(lambda p: check_port(ip, p), ports) if p)
    rows = []
    for p in open_ports:
        service = COMMON_SERVICES.get(p, "unknown")
        banner = grab_banner(ip, p)
        risk = RISKY_PORTS.get(p, "")
        rows.append({"time": now(), "host": ip, "port": p, "service": service,
                     "banner": banner, "note": risk})
        flag = f"  [!] {risk}" if risk else ""
        print(f"  {p:<6}open   {service:<12}{banner}{flag}")
    if not open_ports:
        print("  No open ports found.")
    return rows


def discover(network, ports=(22, 80, 443, 445, 3389), timeout=0.5):
    net = ipaddress.ip_network(network, strict=False)
    hosts = [str(h) for h in net.hosts()]
    print(f"[{now()}] Discovering live hosts in {network} ({len(hosts)} addresses)...")

    def alive(ip):
        return ip if any(check_port(ip, p, timeout) for p in ports) else None

    with ThreadPoolExecutor(max_workers=200) as ex:
        live = [h for h in ex.map(alive, hosts) if h]
    for h in live:
        print(f"  [+] {h} is up")
    print(f"Found {len(live)} live host(s).")
    return live


# --------------------------------------------------------------- detector
def sniff(iface, duration, scan_threshold, flood_threshold, window):
    try:
        from scapy.all import sniff as scapy_sniff, IP, TCP
    except ImportError:
        sys.exit("Scapy not installed. Run: pip install scapy")

    ports_seen = defaultdict(set)     # src -> distinct dst ports in window
    syn_count = defaultdict(int)      # src -> SYN count in window
    alerts, alerted = [], set()
    state = {"start": time.time()}

    def alert(kind, src, detail, severity):
        key = (kind, src)
        if key in alerted:
            return
        alerted.add(key)
        alerts.append({"time": now(), "type": kind, "source_ip": src,
                       "detail": detail, "severity": severity})
        print(f"[ALERT][{severity}] {kind} from {src} - {detail}")

    def handle(pkt):
        if time.time() - state["start"] > window:      # reset sliding window
            ports_seen.clear(); syn_count.clear(); state["start"] = time.time()
        if IP in pkt and TCP in pkt and pkt[TCP].flags & 0x02 and not pkt[TCP].flags & 0x10:
            src, dport = pkt[IP].src, pkt[TCP].dport
            ports_seen[src].add(dport)
            syn_count[src] += 1
            if len(ports_seen[src]) >= scan_threshold:
                alert("Port Scan", src, f"{len(ports_seen[src])} ports probed in {window}s", "MEDIUM")
            if syn_count[src] >= flood_threshold:
                alert("SYN Flood", src, f"{syn_count[src]} SYN packets in {window}s", "HIGH")

    print(f"[{now()}] Sniffing on {iface or 'default interface'} for {duration}s "
          f"(scan>={scan_threshold} ports, flood>={flood_threshold} SYNs / {window}s)")
    scapy_sniff(iface=iface, filter="tcp", prn=handle, store=False, timeout=duration)
    print(f"Done. {len(alerts)} alert(s).")
    return alerts


# ----------------------------------------------------------------- report
def save_csv(rows, path):
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader(); w.writerows(rows)
    print(f"Report saved: {path}")


def main():
    ap = argparse.ArgumentParser(description="NetGuard - scanner & IDS (authorized use only)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="port scan + banner grab")
    s.add_argument("host"); s.add_argument("-p", "--ports", default="1-1024")
    s.add_argument("-o", "--output", default="scan_report.csv")

    d = sub.add_parser("discover", help="find live hosts in a subnet")
    d.add_argument("network")

    n = sub.add_parser("sniff", help="detect port scans / SYN floods (needs root)")
    n.add_argument("-i", "--iface"); n.add_argument("--duration", type=int, default=60)
    n.add_argument("--scan-threshold", type=int, default=15)
    n.add_argument("--flood-threshold", type=int, default=100)
    n.add_argument("--window", type=int, default=10)
    n.add_argument("-o", "--output", default="alerts_report.csv")

    a = ap.parse_args()
    print("NetGuard - use only on systems you own or have written permission to test.\n")
    if a.cmd == "scan":
        save_csv(scan_host(a.host, parse_ports(a.ports)), a.output)
    elif a.cmd == "discover":
        discover(a.network)
    elif a.cmd == "sniff":
        save_csv(sniff(a.iface, a.duration, a.scan_threshold, a.flood_threshold, a.window), a.output)


if __name__ == "__main__":
    main()
