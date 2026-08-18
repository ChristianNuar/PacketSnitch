import contextlib
import importlib
import io
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


class Layer:
    pass


IP = type("IP", (Layer,), {})
TCP = type("TCP", (Layer,), {})
UDP = type("UDP", (Layer,), {})

scapy_all = types.ModuleType("scapy.all")
scapy_all.IP = IP
scapy_all.TCP = TCP
scapy_all.UDP = UDP
scapy_all.rdpcap = lambda _: []
scapy = types.ModuleType("scapy")
scapy.all = scapy_all
sys.modules.setdefault("scapy", scapy)
sys.modules.setdefault("scapy.all", scapy_all)

analyze_pcap = importlib.import_module("analyze_pcap")


class Packet:
    def __init__(self, source, destination, sport, dport, transport=TCP):
        self.layers = {
            IP: types.SimpleNamespace(src=source, dst=destination),
            transport: types.SimpleNamespace(sport=sport, dport=dport),
        }

    def __contains__(self, layer):
        return layer in self.layers

    def __getitem__(self, layer):
        return self.layers[layer]


class AnalyzePcapTests(unittest.TestCase):
    def test_default_capture_matches_bundled_filename(self):
        self.assertEqual(analyze_pcap.DEFAULT_PCAP.name, "example.pcap.cap")

    def test_reports_destination_port_flow_and_top_talker(self):
        packets = [
            Packet("10.0.0.5", "10.0.0.23", 51000, 4444),
            Packet("10.0.0.5", "10.0.0.8", 51001, 443),
            Packet("10.0.0.8", "10.0.0.53", 53000, 53, UDP),
        ]
        output = io.StringIO()

        with patch.object(analyze_pcap, "rdpcap", return_value=packets):
            with contextlib.redirect_stdout(output):
                analyze_pcap.analyze_pcap(Path("capture.pcap"))

        report = output.getvalue()
        self.assertIn("10.0.0.5: 2 packets", report)
        self.assertIn("TCP 10.0.0.5:51000 -> 10.0.0.23:4444", report)

    def test_reports_both_endpoints_when_source_port_matches(self):
        packets = [Packet("10.0.0.23", "10.0.0.5", 23, 51000)]
        output = io.StringIO()

        with patch.object(analyze_pcap, "rdpcap", return_value=packets):
            with contextlib.redirect_stdout(output):
                analyze_pcap.analyze_pcap(Path("capture.pcap"))

        report = output.getvalue()
        self.assertIn("TCP 10.0.0.23:23 -> 10.0.0.5:51000", report)

    def test_missing_capture_exits_with_actionable_error(self):
        with patch.object(Path, "is_file", return_value=False):
            with self.assertRaisesRegex(SystemExit, "PCAP file not found: missing.pcap"):
                analyze_pcap.main(["missing.pcap"])


if __name__ == "__main__":
    unittest.main()
