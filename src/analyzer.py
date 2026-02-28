import argparse
from datetime import datetime
from collections import defaultdict, Counter
import os
import csv
import json

# Scapy helps us sniff packets (live) and also read .pcap files (offline)
from scapy.all import sniff, IP, TCP, UDP, rdpcap


# If rules.json is missing or broken, we fallback to these defaults
DEFAULT_RULES = {
    "threshold": 20,  # how many times we see same dst IP before we say "this is a lot"
    "suspicious_ports": [21, 23, 3389, 445, 1433, 3306],
    "score_weights": {
        "high_frequency": 1,
        "suspicious_port": 2
    }
}

# Just to make alerts easier to read (instead of only numbers)
PORT_NAMES = {
    21: "FTP",
    23: "TELNET",
    3389: "RDP",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL"
}

# These are like mini stats we track while sniffing
dst_counter = defaultdict(int)       # how many times each destination IP appears
src_counter = defaultdict(int)       # how many times each source IP appears (top talkers)
port_counter = Counter()             # which ports show up the most
pair_counter = Counter()             # tracks src -> dst pairs (who talks to who)
suspicious_score = defaultdict(int)  # simple "risk score" for each destination IP


def load_whitelist(path: str) -> set:
    """
    Whitelist is basically "ignore these IPs" (trusted stuff).
    Example: your router IP, or your own device IP.
    """
    if not os.path.exists(path):
        return set()

    items = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()

            # skip blank lines and comments
            if not ip or ip.startswith("#"):
                continue

            items.add(ip)

    return items


def load_rules(path: str) -> dict:
    """
    rules.json lets us change settings without editing code.
    If file isn't there (or JSON is broken), we just use DEFAULT_RULES.
    """
    if not os.path.exists(path):
        return DEFAULT_RULES.copy()

    try:
        with open(path, "r", encoding="utf-8") as f:
            rules = json.load(f)
    except Exception:
        # If JSON is messed up, just fallback (so app still runs)
        return DEFAULT_RULES.copy()

    # Combine what user provided + what we need by default
    out = DEFAULT_RULES.copy()

    # For top-level keys like threshold and suspicious_ports
    out.update({k: rules.get(k, out[k]) for k in out.keys()})

    # Make sure score_weights exists and merges properly
    if "score_weights" in rules and isinstance(rules["score_weights"], dict):
        out["score_weights"] = DEFAULT_RULES["score_weights"].copy()
        out["score_weights"].update(rules["score_weights"])

    return out


def write_line(path: str, text: str) -> None:
    """Simple helper to append one line to a text file."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(text + "\n")


def append_csv(path: str, row: list) -> None:
    """
    Writes packet info to a CSV file.
    If file doesn't exist yet, we write a header first.
    """
    file_exists = os.path.exists(path)

    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow(["timestamp", "protocol", "src_ip", "dst_ip", "dst_port", "flag"])

        writer.writerow(row)


def reset_counters():
    """
    Reset counters so if we run it multiple times, old results don't mix with new ones.
    """
    dst_counter.clear()
    src_counter.clear()
    port_counter.clear()
    pair_counter.clear()
    suspicious_score.clear()


def parse_args():
    """
    These arguments let us run the tool in different ways:
    - Live sniffing: sudo python3 analyzer.py --iface en0 --count 200
    - PCAP mode: python3 analyzer.py --pcap capture.pcap
    """
    p = argparse.ArgumentParser(
        description="Network Traffic Analyzer (Python + Scapy) - Live capture + PCAP mode + Reports"
    )

    # Live capture
    p.add_argument("--count", type=int, default=200, help="Packets to capture (live mode)")
    p.add_argument("--iface", type=str, default=None, help="Interface (macOS Wi-Fi usually en0)")
    p.add_argument("--proto", choices=["any", "tcp", "udp"], default="any", help="Protocol filter (live/pcap)")

    # PCAP (offline) mode
    p.add_argument("--pcap", type=str, default=None, help="Path to a .pcap file (offline mode, no sudo needed)")

    # Config
    p.add_argument("--whitelist", type=str, default="config/whitelist.txt", help="Whitelist IPs file")
    p.add_argument("--rules", type=str, default="config/rules.json", help="Rules JSON file")

    # Output locations
    p.add_argument("--log", type=str, default="reports/traffic_log.txt", help="TXT log output")
    p.add_argument("--alerts", type=str, default="reports/alerts.txt", help="Alerts TXT output")
    p.add_argument("--csv", type=str, default="reports/traffic.csv", help="CSV output")
    p.add_argument("--summary_txt", type=str, default="reports/summary.txt", help="Summary TXT output")
    p.add_argument("--summary_json", type=str, default="reports/summary.json", help="Summary JSON output")

    return p.parse_args()


def build_reasons_and_score(packet, rules: dict) -> list:
    """
    This is the "detection part".
    We keep it simple (not a real IDS, just a student-friendly detector):
    - Lots of hits to same destination IP
    - Suspicious TCP ports
    Also we increase a score so we can rank suspicious destinations.
    """
    reasons = []

    if not packet.haslayer(IP):
        return reasons

    dst_ip = packet[IP].dst

    # count destination hits
    dst_counter[dst_ip] += 1

    # pull values from rules (or defaults)
    threshold = int(rules.get("threshold", 20))
    w_high = int(rules.get("score_weights", {}).get("high_frequency", 1))
    w_port = int(rules.get("score_weights", {}).get("suspicious_port", 2))

    # Rule 1: destination IP keeps showing up a lot
    if dst_counter[dst_ip] >= threshold:
        reasons.append(f"High-frequency destination: {dst_ip} seen {dst_counter[dst_ip]} times")
        suspicious_score[dst_ip] += w_high

    # Rule 2: suspicious port (TCP only)
    suspicious_ports = set(rules.get("suspicious_ports", []))
    if packet.haslayer(TCP):
        dport = int(packet[TCP].dport)
        if dport in suspicious_ports:
            port_name = PORT_NAMES.get(dport, "Unknown")
            reasons.append(f"Suspicious TCP port {dport} ({port_name})")
            suspicious_score[dst_ip] += w_port

    return reasons


def passes_proto_filter(packet, proto_choice: str) -> bool:
    """Quick filter so user can choose tcp-only or udp-only if they want."""
    if proto_choice == "any":
        return True
    if proto_choice == "tcp":
        return packet.haslayer(TCP)
    if proto_choice == "udp":
        return packet.haslayer(UDP)
    return True


def process_packet(packet, args, whitelist: set, rules: dict):
    """
    This runs for every packet.
    It prints to console, saves logs, and creates alerts if needed.
    """
    if not packet.haslayer(IP):
        return

    if not passes_proto_filter(packet, args.proto):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Ignore any traffic that includes trusted IPs (whitelist)
    if src_ip in whitelist or dst_ip in whitelist:
        return

    # Update counters so we can show top talkers later
    src_counter[src_ip] += 1
    pair_counter[f"{src_ip} -> {dst_ip}"] += 1

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Detect protocol + destination port
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

    # Normal packet log line
    line = f"[{ts}] {proto} {src_ip} -> {dst_ip} dport={dport}"
    print(line)
    write_line(args.log, line)

    # Default flag for csv
    flag = "normal"

    # Run our basic detection checks
    reasons = build_reasons_and_score(packet, rules)

    # If we found anything suspicious, print + log an alert
    if reasons:
        flag = "ALERT"
        alert = f"[ALERT {ts}] {src_ip} -> {dst_ip} dport={dport} | " + " | ".join(reasons)
        print(alert)
        write_line(args.alerts, alert)

    # Save to CSV so it looks more "reporting" like
    append_csv(args.csv, [ts, proto, src_ip, dst_ip, dport, flag])


def top_items_from_dict(d: dict, n=10):
    """Helper to sort a dict by value and get top N items."""
    return sorted(d.items(), key=lambda x: x[1], reverse=True)[:n]


def print_summary(top_n=10):
    """
    Prints a quick summary like a mini SOC report.
    This is good for demos + README screenshots.
    """
    print("\n=== Summary (internship version) ===")

    if src_counter:
        print(f"Top {top_n} source IPs:")
        for ip, count in top_items_from_dict(src_counter, top_n):
            print(f"  {ip}: {count}")
    else:
        print("No source IPs captured.")

    if dst_counter:
        print(f"\nTop {top_n} destination IPs:")
        for ip, count in top_items_from_dict(dst_counter, top_n):
            print(f"  {ip}: {count}")
    else:
        print("\nNo destination IPs captured.")

    if port_counter:
        print(f"\nTop {top_n} destination ports:")
        for port, count in port_counter.most_common(top_n):
            print(f"  {port}: {count}")
    else:
        print("\nNo ports captured.")

    if pair_counter:
        print(f"\nTop {top_n} src->dst pairs:")
        for pair, count in pair_counter.most_common(top_n):
            print(f"  {pair}: {count}")

    if suspicious_score:
        print("\nTop suspicious destinations (score):")
        for ip, score in top_items_from_dict(suspicious_score, top_n):
            print(f"  {ip}: {score}")
    else:
        print("\nNo suspicious scores calculated.")


def save_summary_txt(path: str, top_n=10):
    """Writes the summary to a text file so we have a 'report' output."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("=== Traffic Summary ===\n\n")

        f.write(f"Top {top_n} source IPs:\n")
        for ip, count in top_items_from_dict(src_counter, top_n):
            f.write(f"  {ip}: {count}\n")

        f.write(f"\nTop {top_n} destination IPs:\n")
        for ip, count in top_items_from_dict(dst_counter, top_n):
            f.write(f"  {ip}: {count}\n")

        f.write(f"\nTop {top_n} destination ports:\n")
        for port, count in port_counter.most_common(top_n):
            f.write(f"  {port}: {count}\n")

        f.write(f"\nTop {top_n} src->dst pairs:\n")
        for pair, count in pair_counter.most_common(top_n):
            f.write(f"  {pair}: {count}\n")

        f.write(f"\nTop {top_n} suspicious destinations (score):\n")
        for ip, score in top_items_from_dict(suspicious_score, top_n):
            f.write(f"  {ip}: {score}\n")


def save_summary_json(path: str, top_n=10, meta=None):
    """
    JSON summary is nice because it is structured (looks more professional).
    Also in real security jobs, a lot of tools export JSON.
    """
    if meta is None:
        meta = {}

    data = {
        "meta": meta,
        "top_source_ips": top_items_from_dict(src_counter, top_n),
        "top_destination_ips": top_items_from_dict(dst_counter, top_n),
        "top_destination_ports": port_counter.most_common(top_n),
        "top_src_dst_pairs": pair_counter.most_common(top_n),
        "top_suspicious_destinations": top_items_from_dict(suspicious_score, top_n),
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def run_live_capture(args, whitelist, rules):
    """Live sniffing (macOS usually needs sudo)."""
    print("Running LIVE capture mode (may require sudo on macOS).")

    sniff(
        prn=lambda pkt: process_packet(pkt, args, whitelist, rules),
        count=args.count,
        iface=args.iface,
        store=False
    )


def run_pcap_mode(args, whitelist, rules):
    """Offline mode: reads a .pcap file and processes packets like live sniffing."""
    print(f"Running PCAP mode (offline): {args.pcap}")

    packets = rdpcap(args.pcap)

    # just loop through the packets from the pcap file
    for pkt in packets:
        process_packet(pkt, args, whitelist, rules)


def main():
    args = parse_args()

    # Make sure folders exist so the program can write output files
    os.makedirs("reports", exist_ok=True)
    os.makedirs("config", exist_ok=True)

    whitelist = load_whitelist(args.whitelist)
    rules = load_rules(args.rules)

    # Clear old stats
    reset_counters()

    print("=== Network Traffic Analyzer ===")
    print(f"Mode: {'PCAP' if args.pcap else 'LIVE'} | proto={args.proto}")
    print(f"Interface: {args.iface or 'default'} (live only)")
    print(f"Whitelist loaded: {len(whitelist)} IP(s)")
    print(f"Rules: threshold={rules.get('threshold')} suspicious_ports={rules.get('suspicious_ports')}")
    print(f"Outputs -> log: {args.log}, alerts: {args.alerts}, csv: {args.csv}")
    print("Tip: On macOS, live sniffing usually needs sudo.\n")

    # Run the selected mode
    if args.pcap:
        run_pcap_mode(args, whitelist, rules)
    else:
        run_live_capture(args, whitelist, rules)

    # Print summary + export reports
    print_summary(top_n=10)
    save_summary_txt(args.summary_txt, top_n=10)
    save_summary_json(args.summary_json, top_n=10, meta={
        "mode": "pcap" if args.pcap else "live",
        "proto_filter": args.proto,
        "iface": args.iface,
        "count": args.count if not args.pcap else None,
        "rules_file": args.rules,
        "whitelist_file": args.whitelist
    })

    print(f"\nSaved: {args.summary_txt}")
    print(f"Saved: {args.summary_json}")
    print("\nDone. Check the reports/ folder.")


if __name__ == "__main__":
    main()