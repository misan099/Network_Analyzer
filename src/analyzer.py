import argparse
from datetime import datetime
from collections import defaultdict, Counter
import csv
from pathlib import Path

# Scapy is the library that helps us capture packets
from scapy.all import sniff, IP, TCP, UDP


# Some ports are “commonly risky” or interesting in security (basic list)
SUSPICIOUS_PORTS = {
    21: "FTP",
    23: "TELNET",
    3389: "RDP",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL"
}

# We keep simple counters so we can print a summary at the end
dst_counter = defaultdict(int)      # counts how many times we see each destination IP
port_counter = Counter()            # counts how many times we see each destination port

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def resolve_path(path_str):
    """Resolve relative paths from project root so runs are stable from any cwd."""
    path = Path(path_str)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def display_path(path):
    """Pretty-print path relative to project root when possible."""
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def load_whitelist(path):
    """
    Reads a whitelist file (trusted IPs) so we can ignore them.
    File format: one IP per line.
    Lines starting with # are comments.
    """
    if not path.exists():
        return set()

    items = set()
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()

            # skip blank lines and comment lines
            if not ip or ip.startswith("#"):
                continue

            items.add(ip)

    return items


def write_line(file_path, text):
    """Append one line of text to a file."""
    with file_path.open("a", encoding="utf-8") as f:
        f.write(text + "\n")


def append_csv(csv_path, row):
    """
    Adds one row to the CSV file.
    If the file doesn't exist yet, we write a header first.
    """
    file_exists = csv_path.exists()
    with csv_path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow(["timestamp", "protocol", "src_ip", "dst_ip", "dst_port", "flag"])

        writer.writerow(row)


def init_csv(csv_path):
    """Create CSV with header so report exists even when no packets are captured."""
    if csv_path.exists():
        return
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "protocol", "src_ip", "dst_ip", "dst_port", "flag"])


def parse_args():
    """Handles command line arguments like --count 100 --proto tcp"""
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer (Python + Scapy) - beginner SOC-style tool"
    )

    parser.add_argument("--count", type=int, default=100, help="How many packets to capture")
    parser.add_argument("--iface", type=str, default=None, help="Network interface (optional)")
    parser.add_argument("--proto", choices=["any", "tcp", "udp"], default="any", help="Filter by protocol")
    parser.add_argument("--threshold", type=int, default=20, help="Alert if same dst IP shows up a lot")

    # output files
    parser.add_argument("--log", type=str, default="reports/traffic_log.txt", help="Log file path")
    parser.add_argument("--alerts", type=str, default="reports/alerts.txt", help="Alerts file path")
    parser.add_argument("--csv", type=str, default="reports/traffic.csv", help="CSV file path")

    # whitelist
    parser.add_argument("--whitelist", type=str, default="config/whitelist.txt", help="Whitelist file path")

    return parser.parse_args()


def check_suspicious(packet, threshold):
    """
    This function checks if a packet looks suspicious using SIMPLE rules.
    It's not perfect detection, just basic signals for a student project.
    """
    reasons = []

    # If packet doesn't even have an IP layer, we ignore it
    if not packet.haslayer(IP):
        return reasons

    dst_ip = packet[IP].dst

    # track how often we see the same destination IP
    dst_counter[dst_ip] += 1

    # If we keep seeing same destination too much, we raise a flag
    if dst_counter[dst_ip] >= threshold:
        reasons.append(f"High-frequency destination: {dst_ip} seen {dst_counter[dst_ip]} times")

    # If TCP layer exists, check the destination port
    if packet.haslayer(TCP):
        dport = int(packet[TCP].dport)
        if dport in SUSPICIOUS_PORTS:
            reasons.append(f"Suspicious TCP port {dport} ({SUSPICIOUS_PORTS[dport]})")

    return reasons


def handle_packet(packet, args, whitelist):
    """
    This function runs for EACH packet captured.
    It prints it, logs it, and adds alerts if needed.
    """
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Ignore trusted IPs (so logs aren’t messy)
    if src_ip in whitelist or dst_ip in whitelist:
        return

    # Protocol filters (if user chooses tcp or udp)
    if args.proto == "tcp" and not packet.haslayer(TCP):
        return
    if args.proto == "udp" and not packet.haslayer(UDP):
        return

    # timestamp for logs
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # figure out protocol + port for printing
    proto = "IP"
    dport = "-"

    if packet.haslayer(TCP):
        proto = "TCP"
        dport = str(packet[TCP].dport)
        port_counter[int(packet[TCP].dport)] += 1
    elif packet.haslayer(UDP):
        proto = "UDP"
        dport = str(packet[UDP].dport)
        port_counter[int(packet[UDP].dport)] += 1

    # normal log line
    line = f"[{ts}] {proto} {src_ip} -> {dst_ip} dport={dport}"
    print(line)
    write_line(args.log, line)

    # default label for CSV
    flag = "normal"

    # check suspicious rules
    reasons = check_suspicious(packet, args.threshold)
    if reasons:
        flag = "ALERT"
        alert_text = f"[ALERT {ts}] {src_ip} -> {dst_ip} dport={dport} | " + " | ".join(reasons)
        print(alert_text)
        write_line(args.alerts, alert_text)

    # CSV output (nice for “reporting”)
    append_csv(args.csv, [ts, proto, src_ip, dst_ip, dport, flag])


def print_summary(top_n=10):
    """Prints a quick summary at the end like a mini-report."""
    print("\n=== Summary (simple) ===")

    if dst_counter:
        print(f"Top {top_n} destination IPs:")
        sorted_ips = sorted(dst_counter.items(), key=lambda x: x[1], reverse=True)[:top_n]
        for ip, count in sorted_ips:
            print(f"  {ip}: {count}")
    else:
        print("No destination IPs captured.")

    if port_counter:
        print(f"\nTop {top_n} destination ports:")
        for port, count in port_counter.most_common(top_n):
            print(f"  {port}: {count}")
    else:
        print("\nNo ports captured.")


def main():
    args = parse_args()

    args.log = resolve_path(args.log)
    args.alerts = resolve_path(args.alerts)
    args.csv = resolve_path(args.csv)
    args.whitelist = resolve_path(args.whitelist)

    # Make sure parent folders exist (so files can be created)
    args.log.parent.mkdir(parents=True, exist_ok=True)
    args.alerts.parent.mkdir(parents=True, exist_ok=True)
    args.csv.parent.mkdir(parents=True, exist_ok=True)
    args.whitelist.parent.mkdir(parents=True, exist_ok=True)
    init_csv(args.csv)

    # Load whitelist IPs
    whitelist = load_whitelist(args.whitelist)

    print("=== Network Traffic Analyzer ===")
    print(f"Capturing {args.count} packets | protocol={args.proto} | interface={args.iface or 'default'}")
    print(f"Log file: {display_path(args.log)}")
    print(f"Alerts file: {display_path(args.alerts)}")
    print(f"CSV file: {display_path(args.csv)}")
    print(f"Whitelist loaded: {len(whitelist)} IP(s)")
    print("Tip: On macOS you usually need sudo to sniff packets.\n")

    # sniff() will capture packets and call handle_packet() for each one
    sniff(
        prn=lambda pkt: handle_packet(pkt, args, whitelist),
        count=args.count,
        iface=args.iface,
        store=False
    )

    print_summary()
    print("\nDone. Check the reports/ folder.")


if __name__ == "__main__":
    main()
