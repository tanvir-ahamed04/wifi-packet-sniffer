# Wi-Fi Packet Sniffer

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Scapy](https://img.shields.io/badge/Scapy-2.4.5-green)
![License](https://img.shields.io/badge/License-MIT-orange)

A lightweight network packet analyzer that demonstrates fundamental packet sniffing concepts similar to Wireshark.

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Understanding the Output](#understanding-the-output)
- [How It Works](#how-it-works)
- [Contributing](#contributing)
- [Learning Resources](#learning-resources)
- [Disclaimer](#disclaimer)

## Features ✨

- **Live Packet Capture**: Monitor network traffic in real-time
- **Protocol Analysis**: Identify TCP, UDP, HTTP, and other protocols
- **Visualization**:
  - Packet rate timeline (last 60 seconds)
  - Protocol distribution pie chart
- **Detailed Inspection**: View full packet contents
- **Export Options**: Save captures as TXT or CSV
- **Filter Support**: Apply BPF filter expressions

## Prerequisites 📋

- Python 3.8 or later
- Nmap (for interface detection) - [Download Here](https://nmap.org/download.html#windows)
- Administrator privileges (required for packet capture)

## Installation 🛠️

1. Clone the repository:
```bash
git clone https://github.com/tanvir-ahamed04/wifi-packet-sniffer.git
cd wifi-packet-sniffer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage 🚀

Run the application:
```bash
python main.py
```

### Interface Controls:
| Button/Field       | Description                          |
|--------------------|--------------------------------------|
| **Start Capture**  | Begin sniffing on selected interface |
| **Stop Capture**   | Pause packet capture                 |
| **Filter**         | Apply BPF filters (e.g., "tcp port 80") |

### Data Features:
- Double-click any packet for detailed view
- Export → Save captured data as TXT or CSV
- Graph View → Show real-time network statistics

## Understanding the Output 🔍

The main display shows:

| Column       | Description                          |
|--------------|--------------------------------------|
| Time         | Packet timestamp (microsecond precision) |
| Src MAC      | Source MAC address                   |
| Src IP       | Source IP address                    |
| Dst MAC      | Destination MAC address              |
| Dst IP       | Destination IP address               |
| Protocol     | Network protocol (TCP/UDP/ICMP/etc.) |
| Length       | Packet size in bytes                 |
| Info         | Summary of packet contents           |

## How It Works ⚙️

This implementation demonstrates:

1. **Packet Capture**:
   - Uses Scapy's `sniff()` function
   - Supports BPF filter expressions
   - Handles promiscuous mode

2. **Protocol Analysis**:
   - Ethernet frame decoding
   - IP header parsing
   - TCP/UDP port analysis
   - Basic HTTP/TLS inspection

3. **Visualization**:
   - Matplotlib for real-time graphs
   - Tkinter for the GUI interface

## Contributing 🤝

We welcome contributions! Here's how:

1. Fork the repository
2. Create your feature branch:
```bash
git checkout -b feature/your-feature-name
```
3. Commit your changes:
```bash
git commit -m 'Add some feature'
```
4. Push to the branch:
```bash
git push origin feature/your-feature-name
```
5. Open a pull request

## Learning Resources 📚

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [BPF Filter Syntax](https://biot.com/capstats/bpf.html)
- [Network Protocol Basics](https://www.cloudflare.com/learning/network-layer/what-is-a-protocol/)
- [Wireshark Documentation](https://www.wireshark.org/docs/)

## Disclaimer ⚠️

**Important**: This tool is for educational purposes only.  
- Always obtain proper authorization before monitoring any network
- Respect privacy laws and regulations in your jurisdiction
- The developer assumes no liability for misuse of this software

---

Developed by [Tanvir Ahamed](https://github.com/tanvir-ahamed04)  
For educational use in network protocol analysis
```

This README includes:

1. **Visual Badges** - For quick identification of tech stack
2. **Table of Contents** - Easy navigation
3. **Feature Tables** - Clear presentation of capabilities
4. **Code Blocks** - For commands and configurations
5. **Contributing Guide** - Standard GitHub workflow
6. **Responsive Design** - Properly formats on all devices
7. **Legal Notice** - Promotes ethical usage
