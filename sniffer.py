"""
sniffer.py
Background packet capture engine using Scapy AsyncSniffer.
Provides thread-safe state management, preset filtering,
PCAP / CSV export, and MAC analytics integration.
"""

import os
import io
import csv
import time
import threading
from typing import List, Dict, Any, Optional
import scapy.all as scapy
from scapy.arch.windows import get_windows_if_list

from mac_analyzer import MACAddressTracker, normalize_mac
from packet_parser import extract_packet_summary, extract_packet_details


class PacketSniffer:
    """
    Manages live packet sniffing on a chosen network interface.
    Initial state has strictly 0 packets.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.state = "STOPPED"  # STOPPED, RUNNING, PAUSED
        self.async_sniffer: Optional[scapy.AsyncSniffer] = None
        self.start_time: float = 0.0
        self.captured_packets: List[Dict[str, Any]] = []
        self.raw_packets: List[scapy.Packet] = []
        self.raw_packet_map: Dict[int, scapy.Packet] = {}
        self.current_interface: Optional[str] = None
        self.current_filter_preset: str = "phone_all"
        self.current_bpf_filter: str = ""
        self.mac_tracker = MACAddressTracker()
        self.packet_counter = 0

        # Discover hotspot info if available
        self.discover_hotspot_defaults()

    def discover_hotspot_defaults(self):
        """Auto-detects Mobile Hotspot Virtual Adapter IP & MAC."""
        try:
            for iface in scapy.conf.ifaces.values():
                ip = getattr(iface, "ip", "")
                desc = getattr(iface, "description", "")
                if ip == "192.168.137.1" or "Wi-Fi Direct" in desc:
                    mac = getattr(iface, "mac", "")
                    self.mac_tracker.set_hotspot_info("192.168.137.1", mac)
                    break
        except Exception:
            pass

    def _is_hotspot_interface(self, interface: Optional[str]) -> bool:
        if not interface:
            return False
        ifaces = self.get_available_interfaces()
        for i in ifaces:
            if i["name"] == interface and i["is_hotspot"]:
                return True
        return False

    @staticmethod
    def get_available_interfaces() -> List[Dict[str, Any]]:
        """
        Enumerates all network interfaces and identifies
        the Mobile Hotspot interface for the user.
        """
        interfaces = []
        try:
            win_if_map = {item.get("guid"): item for item in get_windows_if_list()}
        except Exception:
            win_if_map = {}

        for key, iface in scapy.conf.ifaces.items():
            name = getattr(iface, "name", str(key))
            desc = getattr(iface, "description", "")
            ip = getattr(iface, "ip", "")
            mac = getattr(iface, "mac", "")
            guid = getattr(iface, "guid", "")

            win_meta = win_if_map.get(guid, {})
            win_name = win_meta.get("name", name)

            # Check if this interface is the Windows Mobile Hotspot adapter
            is_hotspot = False
            if (
                ip == "192.168.137.1"
                or "192.168.137." in str(win_meta.get("ips", []))
                or "Wi-Fi Direct" in desc
                or "Hotspot" in desc
            ):
                is_hotspot = True

            # Friendly display name
            display_title = f"{desc or name} ({ip or 'No IP'})"
            if is_hotspot:
                display_title = f"[HOTSPOT] {desc} - {ip}"

            interfaces.append({
                "id": name,
                "name": name,
                "description": desc,
                "display_name": display_title,
                "ip": ip,
                "mac": normalize_mac(mac),
                "is_hotspot": is_hotspot,
            })

        # Put hotspot interfaces at the top
        interfaces.sort(key=lambda x: (not x["is_hotspot"], x["name"]))
        return interfaces

    def get_default_interface(self) -> str:
        """Finds the best default interface (preferring Mobile Hotspot)."""
        ifaces = self.get_available_interfaces()
        for iface in ifaces:
            if iface["is_hotspot"]:
                return iface["name"]
        # Fallback to interface with non-loopback IP
        for iface in ifaces:
            if iface["ip"] and not iface["ip"].startswith("127.") and not iface["ip"].startswith("169.254."):
                return iface["name"]
        return ifaces[0]["name"] if ifaces else "Wi-Fi"

    def _packet_callback(self, pkt: scapy.Packet):
        """Invoked asynchronously on every incoming packet."""
        try:
            now_time = self.start_time or time.time()
            self.packet_counter += 1
            pkt_id = self.packet_counter

            # Extract fast lightweight summary
            parsed = extract_packet_summary(pkt, pkt_id, now_time)

            with self.lock:
                if self.state != "RUNNING":
                    return

                # Store in buffer (cap at 10,000 packets to conserve RAM)
                if len(self.captured_packets) >= 10000:
                    oldest = self.captured_packets.pop(0)
                    self.raw_packet_map.pop(oldest["id"], None)
                    if self.raw_packets:
                        self.raw_packets.pop(0)

                self.captured_packets.append(parsed)
                self.raw_packets.append(pkt)
                self.raw_packet_map[pkt_id] = pkt

                # Track in MAC analyzer
                self.mac_tracker.record_packet(
                    src_mac=parsed["src_mac"],
                    dst_mac=parsed["dst_mac"],
                    src_ip=parsed["src_ip"],
                    dst_ip=parsed["dst_ip"],
                    protocol=parsed["protocol"],
                    length=parsed["length"],
                    timestamp=parsed["raw_time"],
                )
        except Exception:
            pass

    def start(self, interface: Optional[str] = None, filter_preset: str = "phone_all", custom_bpf: str = ""):
        """Starts packet sniffing."""
        with self.lock:
            if self.state == "RUNNING":
                return True

            if not interface:
                interface = self.get_default_interface()

            self.current_interface = interface
            self.current_filter_preset = filter_preset

            # Determine BPF filter string
            if filter_preset == "phone_all":
                # Captures EVERYTHING from phone (browsing, apps, WhatsApp, YouTube, gaming, push, calls, streaming)
                # On the Hotspot interface, all traffic is between the Laptop Hotspot and the Phone
                if self._is_hotspot_interface(interface):
                    bpf_filter = ""
                else:
                    bpf_filter = "ip host 192.168.137.157 or net 192.168.137.0/24 or arp"
            elif filter_preset == "browsing":
                # Web Browsing only: DNS, HTTP, HTTPS
                bpf_filter = "tcp port 80 or tcp port 443 or port 53"
            elif filter_preset == "all":
                bpf_filter = ""
            elif filter_preset == "custom":
                bpf_filter = custom_bpf.strip()
            else:
                bpf_filter = ""

            self.current_bpf_filter = bpf_filter

            # Find matching Scapy interface object
            dev = None
            try:
                dev = scapy.conf.ifaces.dev_from_name(interface)
            except Exception:
                dev = interface

            if not self.start_time:
                self.start_time = time.time()

            # Start AsyncSniffer
            filter_arg = bpf_filter if bpf_filter else None
            self.async_sniffer = scapy.AsyncSniffer(
                iface=dev,
                filter=filter_arg,
                prn=self._packet_callback,
                store=False,
            )
            self.async_sniffer.start()
            self.state = "RUNNING"
            return True

    def pause(self):
        """Pauses packet ingestion."""
        with self.lock:
            if self.state == "RUNNING":
                self.state = "PAUSED"
                return True
            return False

    def resume(self):
        """Resumes packet ingestion."""
        with self.lock:
            if self.state == "PAUSED":
                self.state = "RUNNING"
                return True
            return False

    def stop(self):
        """Stops live capture."""
        with self.lock:
            if self.async_sniffer and self.async_sniffer.running:
                try:
                    self.async_sniffer.stop()
                except Exception:
                    pass
            self.async_sniffer = None
            self.state = "STOPPED"
            return True

    def clear(self):
        """Completely clears all captured packets and resets count to strictly 0."""
        with self.lock:
            if self.async_sniffer and self.async_sniffer.running:
                try:
                    self.async_sniffer.stop()
                except Exception:
                    pass
                self.async_sniffer = None

            self.captured_packets.clear()
            self.raw_packets.clear()
            self.raw_packet_map.clear()
            self.mac_tracker.clear()
            self.packet_counter = 0
            self.start_time = 0.0
            self.state = "STOPPED"
            return True

    def get_status(self) -> Dict[str, Any]:
        """Returns current live status and counters."""
        with self.lock:
            elapsed = 0.0
            if self.start_time and self.state in ("RUNNING", "PAUSED"):
                elapsed = round(time.time() - self.start_time, 1)

            total_bytes = sum(p["length"] for p in self.captured_packets)

            return {
                "state": self.state,
                "interface": self.current_interface or "Auto-Detect",
                "filter_preset": self.current_filter_preset,
                "bpf_filter": self.current_bpf_filter,
                "packet_count": len(self.captured_packets),
                "total_bytes": total_bytes,
                "elapsed_seconds": elapsed,
            }

    def get_packets(
        self,
        since_id: int = 0,
        limit: int = 200,
        search_query: str = "",
        protocol_filter: str = "",
    ) -> List[Dict[str, Any]]:
        """Retrieves packets, supporting incremental streaming and client filtering."""
        with self.lock:
            if since_id > 0:
                # Return only packets newer than since_id
                subset = [p for p in self.captured_packets if p["id"] > since_id]
            else:
                subset = self.captured_packets

            if protocol_filter and protocol_filter.upper() != "ALL":
                pf = protocol_filter.upper()
                subset = [p for p in subset if pf in p["protocol"].upper()]

            if search_query:
                sq = search_query.lower()
                subset = [
                    p
                    for p in subset
                    if (
                        sq in p["src_mac"].lower()
                        or sq in p["dst_mac"].lower()
                        or sq in p["src_ip"].lower()
                        or sq in p["dst_ip"].lower()
                        or sq in p["protocol"].lower()
                        or sq in p["info"].lower()
                        or sq in p["src_mac_vendor"].lower()
                        or sq in p["dst_mac_vendor"].lower()
                    )
                ]

            return subset[-limit:] if limit > 0 else subset

    def get_packet_by_id(self, pkt_id: int) -> Optional[Dict[str, Any]]:
        """Finds full packet details and hex dump on-demand by ID in O(1)."""
        with self.lock:
            raw_pkt = self.raw_packet_map.get(pkt_id)
            if raw_pkt is not None:
                return extract_packet_details(raw_pkt, pkt_id, self.start_time)

            for p in reversed(self.captured_packets):
                if p["id"] == pkt_id:
                    return p
            return None

    def export_pcap_bytes(self) -> bytes:
        """Exports raw captured packets to PCAP byte stream."""
        with self.lock:
            if not self.raw_packets:
                return b""
            bio = io.BytesIO()
            scapy.wrpcap(bio, self.raw_packets)
            return bio.getvalue()

    def export_csv_string(self) -> str:
        """Exports parsed packets to CSV format."""
        with self.lock:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "No.",
                "Time",
                "Relative Time (s)",
                "Source MAC",
                "Source Vendor",
                "Source MAC Type",
                "Destination MAC",
                "Destination Vendor",
                "Destination MAC Type",
                "Source IP",
                "Destination IP",
                "Protocol",
                "Length",
                "Info",
            ])
            for p in self.captured_packets:
                writer.writerow([
                    p["id"],
                    p["time"],
                    p["rel_time"],
                    p["src_mac"],
                    p["src_mac_vendor"],
                    p["src_mac_type"],
                    p["dst_mac"],
                    p["dst_mac_vendor"],
                    p["dst_mac_type"],
                    p["src_ip"],
                    p["dst_ip"],
                    p["protocol"],
                    p["length"],
                    p["info"],
                ])
            return output.getvalue()
