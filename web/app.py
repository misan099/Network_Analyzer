import os
import uuid
import json
import socket
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, send_file, flash

# Force Scapy cache into the project so import does not fail on locked ~/.cache.
WEB_DIR = os.path.dirname(__file__)
LOCAL_CACHE_ROOT = os.path.join(WEB_DIR, ".cache")
os.makedirs(LOCAL_CACHE_ROOT, exist_ok=True)
os.environ.setdefault("XDG_CACHE_HOME", LOCAL_CACHE_ROOT)

# We will use scapy to read pcap
from scapy.all import rdpcap, IP, TCP, UDP

app = Flask(__name__)
app.secret_key = "dev-secret"  # ok for student project (don’t use in real prod)

UPLOAD_FOLDER = os.path.join(WEB_DIR, "uploads")
REPORTS_FOLDER = os.path.join(WEB_DIR, "reports")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)


def analyze_pcap(pcap_path):
    """
    Simple PCAP analyzer (web demo):
    - top source IPs
    - top destination IPs
    - top destination ports
    - top src->dst pairs
    """

    from collections import defaultdict, Counter

    src_counter = defaultdict(int)
    dst_counter = defaultdict(int)
    port_counter = Counter()
    pair_counter = Counter()

    packets = rdpcap(pcap_path)

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst

        src_counter[src] += 1
        dst_counter[dst] += 1
        pair_counter[f"{src} -> {dst}"] += 1

        if pkt.haslayer(TCP):
            port_counter[int(pkt[TCP].dport)] += 1
        elif pkt.haslayer(UDP):
            port_counter[int(pkt[UDP].dport)] += 1

    def top_dict(d, n=10):
        return sorted(d.items(), key=lambda x: x[1], reverse=True)[:n]

    summary = {
        "top_source_ips": top_dict(src_counter, 10),
        "top_destination_ips": top_dict(dst_counter, 10),
        "top_destination_ports": port_counter.most_common(10),
        "top_src_dst_pairs": pair_counter.most_common(10),
        "total_packets": len(packets),
    }

    return summary


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if "pcap" not in request.files:
        flash("No file uploaded.")
        return redirect(url_for("home"))

    file = request.files["pcap"]

    if file.filename == "":
        flash("Please select a file.")
        return redirect(url_for("home"))

    # only allow .pcap or .pcapng
    filename_lower = file.filename.lower()
    if not (filename_lower.endswith(".pcap") or filename_lower.endswith(".pcapng")):
        flash("Only .pcap or .pcapng files are supported.")
        return redirect(url_for("home"))

    # Save uploaded file with safe random name
    run_id = str(uuid.uuid4())[:8]
    saved_path = os.path.join(UPLOAD_FOLDER, f"{run_id}_{file.filename}")
    file.save(saved_path)

    # Analyze it
    summary = analyze_pcap(saved_path)

    # Save summary files for download
    json_path = os.path.join(REPORTS_FOLDER, f"{run_id}_summary.json")
    txt_path = os.path.join(REPORTS_FOLDER, f"{run_id}_summary.txt")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=== PCAP Summary ===\n\n")
        f.write(f"Total packets: {summary['total_packets']}\n\n")

        f.write("Top source IPs:\n")
        for ip, c in summary["top_source_ips"]:
            f.write(f"  {ip}: {c}\n")

        f.write("\nTop destination IPs:\n")
        for ip, c in summary["top_destination_ips"]:
            f.write(f"  {ip}: {c}\n")

        f.write("\nTop destination ports:\n")
        for port, c in summary["top_destination_ports"]:
            f.write(f"  {port}: {c}\n")

        f.write("\nTop src->dst pairs:\n")
        for pair, c in summary["top_src_dst_pairs"]:
            f.write(f"  {pair}: {c}\n")

    # Show results page
    return render_template(
        "results.html",
        summary=summary,
        run_id=run_id,
        original_filename=file.filename,
        analyzed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@app.route("/download/<run_id>/<filetype>")
def download(run_id, filetype):
    if filetype == "json":
        path = os.path.join(REPORTS_FOLDER, f"{run_id}_summary.json")
        return send_file(path, as_attachment=True)
    elif filetype == "txt":
        path = os.path.join(REPORTS_FOLDER, f"{run_id}_summary.txt")
        return send_file(path, as_attachment=True)

    return "Invalid file type", 400


# Render uses PORT environment variable
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    if "PORT" not in os.environ:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                port = 5001
                print("Port 5000 is busy. Falling back to port 5001.")
    app.run(host="0.0.0.0", port=port, debug=True)
