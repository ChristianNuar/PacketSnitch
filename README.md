# PacketSnitch

**PacketSnitch** is a Python-based PCAP analyzer for quickly identifying suspicious ports and high-volume source IPs in a network capture.

## Features

- Parses TCP and UDP traffic from `.pcap` files
- Reports the five source IPs with the highest packet counts
- Flags source IPs communicating over ports `23`, `2323`, `4444`, `6666`, or `31337`
- Accepts a capture path from the command line

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

## Tests

Run the regression tests without requiring a live capture:

```bash
python -m unittest -v
```
