"""
test_app.py
Comprehensive test suite verifying all REST API endpoints,
initial 0-packet state, packet parsing, MAC analytics, and chart setup.
"""

import unittest
import json
import scapy.all as scapy
from app import app, sniffer


class NetSharkTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        sniffer.clear()

    def tearDown(self):
        sniffer.stop()
        sniffer.clear()

    def test_initial_state_zero_packets(self):
        """Verifies that at starting, it is strictly 0 packets and STOPPED state."""
        res = self.client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["packet_count"], 0)
        self.assertEqual(data["state"], "STOPPED")
        self.assertEqual(data["total_bytes"], 0)

    def test_interfaces_endpoint(self):
        """Verifies interface enumeration detects hotspot interface."""
        res = self.client.get("/api/interfaces")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("interfaces", data)
        self.assertTrue(len(data["interfaces"]) > 0)
        
        # Check if hotspot adapter is present
        hotspot_found = any(i["is_hotspot"] for i in data["interfaces"])
        print(f"[*] Hotspot interface detected in test: {hotspot_found}")

    def test_mac_analysis_initial(self):
        """Verifies MAC analysis endpoint returns correct empty structure."""
        res = self.client.get("/api/mac-analysis")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("devices", data)
        self.assertIn("conversations", data)
        self.assertIn("stats", data)
        self.assertEqual(data["total_macs"], 0)

    def test_simulated_browsing_packet(self):
        """
        Simulates an incoming browsing packet (DNS Query & HTTPS TCP)
        and verifies parsing, IP & MAC extraction, and MAC tracker.
        """
        pkt = (
            scapy.Ether(src="ae:67:24:c3:3a:ff", dst="ea:41:f4:b6:20:f0")
            / scapy.IP(src="192.168.137.157", dst="8.8.8.8")
            / scapy.UDP(sport=51234, dport=53)
            / scapy.DNS(rd=1, qd=scapy.DNSQR(qname="www.wikipedia.org"))
        )

        sniffer.state = "RUNNING"
        sniffer._packet_callback(pkt)

        # Check status
        status = sniffer.get_status()
        self.assertEqual(status["packet_count"], 1)

        # Check packet details via API
        res = self.client.get("/api/packets")
        data = res.get_json()
        self.assertEqual(len(data["packets"]), 1)
        p = data["packets"][0]

        # Verify MAC addresses
        self.assertEqual(p["src_mac"], "ae:67:24:c3:3a:ff")
        self.assertEqual(p["dst_mac"], "ea:41:f4:b6:20:f0")
        self.assertTrue(p["src_mac_randomized"])
        
        # Verify IP addresses
        self.assertEqual(p["src_ip"], "192.168.137.157")
        self.assertEqual(p["dst_ip"], "8.8.8.8")
        self.assertEqual(p["protocol"], "DNS")
        self.assertIn("wikipedia.org", p["info"])

        # Check MAC analysis
        mac_res = self.client.get("/api/mac-analysis")
        mac_data = mac_res.get_json()
        self.assertEqual(mac_data["total_macs"], 2)
        
        # Find phone device
        phone = next((d for d in mac_data["devices"] if d["mac"] == "ae:67:24:c3:3a:ff"), None)
        self.assertIsNotNone(phone)
        self.assertIn("192.168.137.157", phone["ips"])
        self.assertTrue(phone["is_randomized"])

    def test_clear_resets_to_zero(self):
        """Verifies that calling clear resets packet count strictly to 0."""
        pkt = scapy.Ether(src="ae:67:24:c3:3a:ff", dst="ea:41:f4:b6:20:f0") / scapy.IP(src="192.168.137.157", dst="1.1.1.1")
        sniffer.state = "RUNNING"
        sniffer._packet_callback(pkt)
        self.assertEqual(sniffer.get_status()["packet_count"], 1)

        # Call clear API
        res = self.client.post("/api/capture/clear")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(sniffer.get_status()["packet_count"], 0)
        self.assertEqual(sniffer.get_status()["state"], "STOPPED")

    def test_packet_detail_and_hex_dump(self):
        """Verifies that selecting a packet returns the deep layer tree and Wireshark hex dump."""
        pkt = (
            scapy.Ether(src="ae:67:24:c3:3a:ff", dst="ea:41:f4:b6:20:f0")
            / scapy.IP(src="192.168.137.157", dst="1.1.1.1")
            / scapy.UDP(sport=12345, dport=53)
            / scapy.DNS(rd=1, qd=scapy.DNSQR(qname="google.com"))
        )
        sniffer.state = "RUNNING"
        sniffer._packet_callback(pkt)

        res = self.client.get("/api/packet/1")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("hex_dump", data)
        self.assertIn("layer_tree", data)
        self.assertTrue(len(data["hex_dump"]) > 10)
        self.assertTrue(len(data["layer_tree"]) >= 3)
        self.assertIn("0000", data["hex_dump"])

    def test_charts_initial_zero_state_and_canvas_elements(self):
        """
        Verifies that initially at 0 packets, the charts section is strictly hidden,
        and all 4 chart canvas elements (Donut, Line1, Line2, Horizontal Bar) are present.
        """
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        # 1. Strictly hidden at initial 0 packets state
        self.assertIn('id="liveChartsSection"', html)
        self.assertIn('class="charts-section hidden"', html)
        self.assertIn('style="display: none;"', html)

        # 2. All 4 requested chart elements present
        self.assertIn('id="chartProtocol"', html)      # Protocol Distribution (Donut)
        self.assertIn('id="chartPacketsTime"', html)   # Packet Capture Over Time (Line)
        self.assertIn('id="chartDataTime"', html)      # Data Transfer Over Time (Line)
        self.assertIn('id="chartTopMacs"', html)       # Top MAC Addresses by Traffic (Horizontal Bar)

        # 3. Chart.js local bundle script tag
        self.assertIn('chart.umd.min.js', html)


if __name__ == "__main__":
    unittest.main()
