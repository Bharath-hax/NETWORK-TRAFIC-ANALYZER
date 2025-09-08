# NETWORK-TRAFIC-ANALYZER
# 🕵️‍♂️ Python Network Traffic Analyzer

A lightweight Python-based tool for capturing and analyzing network traffic.  
It helps monitor packets, extract useful insights (like protocols, source/destination IPs, ports), and generate basic statistics for network debugging, research, or security analysis.

---

## 🚀 Features
- Capture live network packets in real-time
- Display protocol (TCP, UDP, ICMP, etc.) details
- Extract source & destination IP addresses and ports
- Track packet count and size statistics
- Save captured logs to a file (CSV/JSON/TXT)
- Filter traffic by protocol or IP
- Simple CLI interface for quick analysis

---

## 🛠️ Requirements
- Python 3.8+
- [Scapy](https://scapy.net/) (`pip install scapy`)
- [psutil](https://pypi.org/project/psutil/) *(optional: for system info)*

Install all dependencies with:
```bash
pip install -r requirements.txt
