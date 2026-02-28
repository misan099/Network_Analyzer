# Network Traffic Analyzer (Python + Scapy)
A beginner cybersecurity project that captures and analyzes network traffic using Python and Scapy.  
The tool detects suspicious ports, logs packets, and generates summary reports.
## Project Overview

This project is a Python-based network traffic analyzer designed to simulate a simple SOC (Security Operations Center) monitoring tool.

It captures network packets in real time and generates logs and reports that help identify unusual or suspicious network activity.

The goal of this project is to learn practical cybersecurity skills such as packet analysis, network monitoring, and security logging.
## Features

- Real-time packet capture using Scapy
- TCP and UDP packet filtering
- Suspicious port detection
- TXT log generation
- CSV report generation
- Traffic summary reports
- Command-line options
## Technologies Used

- Python
- Scapy
- VS Code
- Git & GitHub
## How to Run

Clone the repository:

```bash
git clone https://github.com/misan099/Network_Analyzer.git

cd Network-Traffic-Analyzer
In Terminal:(Step by step)
python3 -m venv venv
source venv/bin/activate

python3 -m venv venv
source venv/bin/activate

sudo python3 src/analyzer.py --iface en0 --count 200 --proto tcp

Output:
=== Summary (simple) ===
Top 10 destination IPs:
192.168.1.238: 18
20.42.65.89: 8
104.18.37.228: 8

Top 10 destination ports:
443: 22
57576: 8
57368: 7

## Ethical Notice

This project is for educational purposes only.

Only run this tool on networks you own or have permission to test.
