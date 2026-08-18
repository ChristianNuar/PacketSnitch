# PacketSnitch

**PacketSnitch** is a Python-based PCAP analyzer for quickly identifying monitored ports and high-volume source IPs in a network capture.

## Features

- Parses IPv4 TCP and UDP traffic from `.pcap` files
- Reports the five source IPs with the highest packet counts
- Reports complete flows when either endpoint uses port `23`, `2323`, `4444`, `6666`, or `31337`
- Accepts a capture path from the command line

PacketSnitch prints the protocol, both IP addresses, both ports, and the packet direction for each matched flow. This context distinguishes traffic sent to a monitored service from reply traffic sourced by that service.

## Requirements

- Python 3.8+
- Scapy

Install the dependency:

```bash
python -m pip install scapy
```

## Usage

Analyze the bundled sample capture:

```bash
python analyze_pcap.py
```

Analyze another capture:

```bash
python analyze_pcap.py /path/to/capture.pcap
```

If the supplied path does not exist, PacketSnitch exits with the path it could not find instead of producing a Scapy traceback.

## Interpreting results

A port match is a triage lead, not proof of malicious activity. Legitimate Telnet administration, lab tools, or custom applications can use the monitored ports.

Tune `SUSPICIOUS_PORTS` to the services approved in your environment. Validate a matched flow against asset roles, connection timing, and surrounding packets before escalating it.

## Tests

Run the regression tests without requiring a live capture:

```bash
python -m unittest -v
```
