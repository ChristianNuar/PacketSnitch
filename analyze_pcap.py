#!/usr/bin/env python3

import argparse
from collections import defaultdict
from pathlib import Path

from scapy.all import IP, TCP, UDP, rdpcap

SUSPICIOUS_PORTS = {23, 2323, 4444, 6666, 31337}
DEFAULT_PCAP = Path(__file__).with_name("example.pcap.cap")


def analyze_pcap(pcap_file):
    packets = rdpcap(str(pcap_file))
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
    for ip, count in sorted(ip_count.items(), key=lambda item: item[1], reverse=True)[:5]:
        print(f"   {ip}: {count} packets")

    print("\n[!] IPs using suspicious ports:")
    for ip in sorted(flagged):
        print(f"   {ip}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Analyze a PCAP for suspicious ports and top talkers.")
    parser.add_argument(
        "pcap",
        nargs="?",
        type=Path,
        default=DEFAULT_PCAP,
        help="PCAP file to analyze (default: bundled example.pcap.cap)",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not args.pcap.is_file():
        raise SystemExit(f"PCAP file not found: {args.pcap}")
    analyze_pcap(args.pcap)


if __name__ == "__main__":
    main()
