# CodeAlpha_NetworkSniffer
Python-based network packet sniffer for cybersecurity analysis

# 🔍 CodeAlpha Network Packet Sniffer

## 📌 Project Overview
This is a network packet sniffer developed during my cybersecurity internship at **CodeAlpha**. It captures and analyzes live network traffic to understand how data flows through networks.

## 📁 Project Files

| File | Description |
|------|-------------|
| `network_sniffer.py` | Main sniffer with detailed packet analysis |
| `savesniffer.py` | Saves captured packets to PCAP file |
| `captured_packets.pcap` | Live captured network traffic (proof of work) |

## 🛠️ Technologies Used
- Python 3.x
- Scapy library
- PCAP format for packet storage

## 📦 Installation & Setup

```bash
# Install required library
pip install scapy

# Run the main sniffer (requires admin privileges)
sudo python3 network_sniffer.py

# Run the save version
sudo python3 savesniffer.py
