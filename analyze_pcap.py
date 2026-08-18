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
    flagged_flows = set()

    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            ip_count[ip_layer.src] += 1

            if TCP in pkt:
                protocol = "TCP"
                transport_layer = pkt[TCP]
            elif UDP in pkt:
                protocol = "UDP"
                transport_layer = pkt[UDP]
            else:
                continue

            if (
                transport_layer.dport in SUSPICIOUS_PORTS
                or transport_layer.sport in SUSPICIOUS_PORTS
            ):
                flagged_flows.add(
                    (
                        protocol,
                        ip_layer.src,
                        transport_layer.sport,
                        ip_layer.dst,
                        transport_layer.dport,
                    )
                )

    print("\n[+] IPs communicating the most:")
    for ip, count in sorted(ip_count.items(), key=lambda item: item[1], reverse=True)[:5]:
        print(f"   {ip}: {count} packets")

    print("\n[!] Flows using monitored ports:")
    for protocol, source, sport, destination, dport in sorted(flagged_flows):
        print(f"   {protocol} {source}:{sport} -> {destination}:{dport}")


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
