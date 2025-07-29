#!/usr/bin/env python3

from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict

SUSPICIOUS_PORTS = [4444, 31337, 6666, 23, 2323]
PCAP_FILE = "example.pcap"

def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    ip_count = defaultdict(int)
    flagged = set()

    for pkt in packets:
        if IP in pkt:
            ip = pkt[IP].src
            ip_count[ip] += 1

            if TCP in pkt or UDP in pkt:
                sport = pkt.sport
                dport = pkt.dport

                if dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS:
                    flagged.add(ip)

    print("\n[+] IPs communicating the most:")
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"   {ip}: {count} packets")

    print("\n[!] IPs using suspicious ports:")
    for ip in flagged:
        print(f"   {ip}")

if __name__ == "__main__":
    analyze_pcap(PCAP_FILE)
