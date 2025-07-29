# PacketSnitch

**PacketSnitch** is a Python-based automated PCAP analyzer designed to help security analysts, blue teamers, and students quickly identify suspicious activity in network captures.

It uses `scapy` to parse packets, detect abnormal behavior (like port scans and malicious ports), and flag top talkers.

---

## 🚀 Features

- Parses `.pcap` files and flags:
  - Use of suspicious ports (e.g., 4444, 31337, telnet)
  - High-volume IP communication
- Shows top 5 IPs by traffic volume
- Flags IPs communicating on known malicious ports
- Easy to expand and customize

---

## 🧰 Requirements

- Python 3.8+
- `scapy`  
  Install it with:
  ```bash
  pip install scapy
