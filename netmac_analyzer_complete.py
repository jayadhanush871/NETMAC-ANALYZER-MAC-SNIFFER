# ==============================================================================
# PROJECT: NETMAC ANALYZER: MAC ADDRESS SNIFFER & PRIVACY CLASSIFIER
# TEAM NUMBER: Team 23 | SLOT: F1 + TF1
# COURSE: Computer Networks (Project Review 2)
# GUIDE: A. Suresh Sir (Assistant Professor)
# TEAM MEMBERS:
#   1. CH. SUMANTH
#   2. K. NANI BABU
#   3. J. JAYA DHANUSH
# ==============================================================================
# DESCRIPTION:
# Complete all-in-one consolidated Python codebase for NetMAC Analyzer.
# Integrates packet sniffing, IEEE 802 bitwise MAC analysis (LAA vs. UAA),
# two-stage multi-layer protocol dissection, 16-byte hex dump viewer,
# Flask RESTful API server, and auto-launcher in a single executable script.
# ==============================================================================


# ==============================================================================
# PART 1: IEEE 802 MAC ADDRESS & PRIVACY ANALYSIS ENGINE (mac_analyzer.py)
# ==============================================================================
"""
mac_analyzer.py
Specialized MAC Address Analysis and Vendor/OUI Lookup Engine.
Provides classification:
- Unicast vs Multicast vs Broadcast
- Locally Administered Address (LAA - Randomized MAC) vs Universally Administered Address (UAA)
- Vendor / OUI identification
- Hotspot Device Role detection (Laptop Hotspot Gateway, Connected Phone, etc.)
- Flow conversation matrix tracking
"""

import re
from typing import Dict, Any, Optional, List, Tuple

# Comprehensive OUI prefix database (normalized lowercase without colons or with first 3 bytes)
COMMON_OUIs: Dict[str, str] = {
    # Apple
    "00:17:f2": "Apple, Inc.",
    "00:1c:b3": "Apple, Inc.",
    "00:26:08": "Apple, Inc.",
    "00:88:65": "Apple, Inc.",
    "04:0c:ce": "Apple, Inc.",
    "04:15:52": "Apple, Inc.",
    "04:26:65": "Apple, Inc.",
    "18:af:61": "Apple, Inc.",
    "28:cf:e9": "Apple, Inc.",
    "3c:07:54": "Apple, Inc.",
    "40:6c:8f": "Apple, Inc.",
    "48:d7:05": "Apple, Inc.",
    "60:f8:1d": "Apple, Inc.",
    "70:ec:e4": "Apple, Inc.",
    "78:4f:43": "Apple, Inc.",
    "8c:85:90": "Apple, Inc.",
    "9c:20:7b": "Apple, Inc.",
    "a4:83:e7": "Apple, Inc.",
    "ac:bc:32": "Apple, Inc.",
    "bc:d0:74": "Apple, Inc.",
    "c8:69:cd": "Apple, Inc.",
    "dc:a9:04": "Apple, Inc.",
    "f0:18:98": "Apple, Inc.",
    "f4:5c:89": "Apple, Inc.",
    
    # Samsung Electronics
    "00:12:47": "Samsung Electronics",
    "00:1a:8a": "Samsung Electronics",
    "00:23:d7": "Samsung Electronics",
    "00:26:37": "Samsung Electronics",
    "08:fc:88": "Samsung Electronics",
    "14:bb:6e": "Samsung Electronics",
    "24:4b:fe": "Samsung Electronics",
    "30:07:4d": "Samsung Electronics",
    "34:23:87": "Samsung Electronics",
    "40:40:a7": "Samsung Electronics",
    "50:85:69": "Samsung Electronics",
    "5c:0a:5b": "Samsung Electronics",
    "78:40:e4": "Samsung Electronics",
    "84:25:19": "Samsung Electronics",
    "94:63:72": "Samsung Electronics",
    "98:0d:2e": "Samsung Electronics",
    "a8:06:00": "Samsung Electronics",
    "b8:57:d8": "Samsung Electronics",
    "c0:bd:d1": "Samsung Electronics",
    "cc:07:ab": "Samsung Electronics",
    "d0:03:df": "Samsung Electronics",
    "e4:7c:f9": "Samsung Electronics",
    
    # Google
    "3c:5a:37": "Google LLC",
    "54:60:09": "Google LLC",
    "94:eb:2c": "Google LLC",
    "a4:77:33": "Google LLC",
    "d8:6c:63": "Google LLC",
    "f4:03:04": "Google LLC",
    "f4:f5:e8": "Google LLC",
    
    # Xiaomi / POCO / Redmi
    "04:cf:4b": "Xiaomi Communications",
    "14:ab:c5": "Xiaomi Communications",
    "18:59:36": "Xiaomi Communications",
    "28:6c:07": "Xiaomi Communications",
    "34:ce:00": "Xiaomi Communications",
    "50:64:2b": "Xiaomi Communications",
    "64:cc:2e": "Xiaomi Communications",
    "74:23:44": "Xiaomi Communications",
    "7c:1d:d9": "Xiaomi Communications",
    "88:c3:97": "Xiaomi Communications",
    "9c:99:a0": "Xiaomi Communications",
    "a4:45:19": "Xiaomi Communications",
    "ac:c1:ee": "Xiaomi Communications",
    "c8:bf:4c": "Xiaomi Communications",
    "d4:97:0b": "Xiaomi Communications",
    "ec:d0:9f": "Xiaomi Communications",
    
    # OnePlus / Oppo / Realme / Vivo (BBK Electronics)
    "1c:52:16": "OnePlus Technology",
    "2c:57:31": "OnePlus Technology",
    "9c:28:bf": "OnePlus Technology",
    "c0:ee:fb": "OnePlus Technology",
    "24:df:6a": "OPPO Mobile Telecommunications",
    "44:04:44": "OPPO Mobile Telecommunications",
    "5c:c3:07": "OPPO Mobile Telecommunications",
    "70:89:cc": "OPPO Mobile Telecommunications",
    "84:55:a5": "OPPO Mobile Telecommunications",
    "a0:bb:3e": "OPPO Mobile Telecommunications",
    "c8:79:32": "Vivo Mobile Communication",
    "ec:2f:80": "Vivo Mobile Communication",
    "f8:84:f2": "Vivo Mobile Communication",
    
    # Intel
    "00:1b:21": "Intel Corporate",
    "00:1e:67": "Intel Corporate",
    "00:21:6a": "Intel Corporate",
    "00:23:14": "Intel Corporate",
    "34:13:e8": "Intel Corporate",
    "48:51:b7": "Intel Corporate",
    "68:05:ca": "Intel Corporate",
    "80:86:f2": "Intel Corporate",
    "84:a9:38": "Intel Corporate",
    "94:e6:f7": "Intel Corporate",
    "a4:bb:6d": "Intel Corporate",
    "dc:fb:48": "Intel Corporate",
    
    # Realtek & AzureWave (Laptop Wi-Fi / NICs)
    "00:e0:4c": "Realtek Semiconductor",
    "2c:58:b9": "Realtek Semiconductor",
    "4c:ed:fb": "Realtek Semiconductor",
    "54:04:a6": "Realtek Semiconductor",
    "70:85:c2": "Realtek Semiconductor",
    "80:3f:5d": "Realtek Semiconductor",
    "a8:41:f4": "AzureWave Technology",
    "b0:25:aa": "AzureWave Technology",
    "dc:85:de": "AzureWave Technology",
    "e0:06:e6": "AzureWave Technology",
    "ea:41:f4": "Microsoft / Virtual Wi-Fi Direct",
    "aa:41:f4": "Microsoft / Virtual Wi-Fi Direct",
    
    # Microsoft
    "00:15:5d": "Microsoft Corporation (Hyper-V)",
    "00:50:f2": "Microsoft Corporation",
    "28:18:78": "Microsoft Corporation",
    "70:6e:6d": "Microsoft Corporation",
    "dc:98:40": "Microsoft Corporation",
    
    # Cisco & Networking Vendors
    "00:00:0c": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:0c:29": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "0a:00:27": "Oracle VirtualBox",
    "00:ff:f4": "TAP-Windows Virtual NIC",
    "00:14:d1": "TP-Link Corporation",
    "14:cf:92": "TP-Link Corporation",
    "50:c7:bf": "TP-Link Corporation",
    "ec:08:6b": "TP-Link Corporation",
    "c0:06:c3": "Netgear Inc.",
    "28:80:88": "Netgear Inc.",
    "00:18:e7": "Cameo Communications / D-Link",
    "1c:7e:e5": "D-Link International",
    
    # Espressif (IoT) & Raspberry Pi
    "24:0a:c4": "Espressif Inc.",
    "24:6f:28": "Espressif Inc.",
    "30:ae:a4": "Espressif Inc.",
    "84:0d:8e": "Espressif Inc.",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Foundation",
}


def normalize_mac(mac: str) -> str:
    """Normalize MAC address string to lower-case colon-separated xx:xx:xx:xx:xx:xx."""
    if not mac:
        return ""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(clean) == 12:
        return ":".join(clean[i : i + 2] for i in range(0, 12, 2))
    return mac.lower().strip()


def analyze_mac_address(mac: str) -> Dict[str, Any]:
    """
    Performs in-depth Layer-2 analysis on a MAC address:
    - Normalization
    - Cast type: Unicast, Multicast, or Broadcast
    - Administration type: LAA (Locally Administered / Randomized) vs UAA (Universally Administered)
    - Vendor / OUI lookup
    - Privacy status explanation
    """
    norm_mac = normalize_mac(mac)
    if not norm_mac or len(norm_mac) != 17:
        return {
            "mac": mac,
            "normalized": mac,
            "is_valid": False,
            "cast_type": "Unknown",
            "admin_type": "Unknown",
            "is_randomized": False,
            "vendor": "Invalid / Unknown MAC",
            "oui": "",
            "details": "Malformed MAC address",
        }

    # Broadcast check
    if norm_mac == "ff:ff:ff:ff:ff:ff":
        return {
            "mac": mac,
            "normalized": norm_mac,
            "is_valid": True,
            "cast_type": "Broadcast",
            "admin_type": "Broadcast",
            "is_randomized": False,
            "vendor": "Broadcast Destination (All Devices)",
            "oui": "FF:FF:FF",
            "details": "Ethernet Layer-2 Broadcast frame addressed to all stations on the subnet.",
        }

    try:
        first_byte = int(norm_mac.split(":")[0], 16)
    except ValueError:
        first_byte = 0

    # Bit 0 (LSB of 1st octet): 0 = Unicast, 1 = Multicast
    is_multicast = bool(first_byte & 0x01)
    cast_type = "Multicast" if is_multicast else "Unicast"

    # Bit 1 (second LSB of 1st octet): 0 = UAA (Universal), 1 = LAA (Local / Randomized)
    is_laa = bool(first_byte & 0x02)
    admin_type = "Locally Administered (LAA)" if is_laa else "Universally Administered (UAA)"
    is_randomized = is_laa and not is_multicast

    # OUI prefix (first 3 octets)
    oui_prefix = ":".join(norm_mac.split(":")[:3])
    vendor = "Unknown Vendor"

    if is_randomized:
        # Note: Android 10+ and iOS 14+ use randomized MACs by default when connecting to Wi-Fi/Hotspots
        vendor = "Randomized / Private MAC (Phone Privacy Active)"
        details = (
            "This device is using a Locally Administered Address (LAA). "
            "Modern smartphones (Android, iPhone) randomize their MAC address to prevent tracking."
        )
    elif is_multicast:
        if norm_mac.startswith("01:00:5e"):
            vendor = "IPv4 Multicast (RFC 1112)"
        elif norm_mac.startswith("33:33"):
            vendor = "IPv6 Multicast (RFC 2464)"
        elif norm_mac.startswith("01:80:c2"):
            vendor = "Spanning Tree / LLDP Multicast"
        else:
            vendor = "Multicast Group"
        details = "Ethernet Multicast destination frame."
    else:
        # Check known OUI dictionary
        if oui_prefix in COMMON_OUIs:
            vendor = COMMON_OUIs[oui_prefix]
        else:
            vendor = f"Unknown Vendor (OUI {oui_prefix.upper()})"
        details = "Universally Administered hardware MAC burned into the Network Interface Card."

    return {
        "mac": mac,
        "normalized": norm_mac,
        "is_valid": True,
        "cast_type": cast_type,
        "admin_type": admin_type,
        "is_randomized": is_randomized,
        "vendor": vendor,
        "oui": oui_prefix.upper(),
        "details": details,
    }


class MACAddressTracker:
    """
    Aggregates and tracks MAC address statistics, active devices,
    IP-to-MAC associations, and flow conversation matrices.
    """

    def __init__(self):
        self.devices: Dict[str, Dict[str, Any]] = {}
        self.conversations: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.hotspot_gateway_ip = "192.168.137.1"
        self.hotspot_gateway_mac = "ea:41:f4:b6:20:f0"

    def clear(self):
        """Reset all tracking data."""
        self.devices.clear()
        self.conversations.clear()

    def set_hotspot_info(self, gateway_ip: str, gateway_mac: str):
        if gateway_ip:
            self.hotspot_gateway_ip = gateway_ip
        if gateway_mac:
            self.hotspot_gateway_mac = normalize_mac(gateway_mac)

    def record_packet(
        self,
        src_mac: str,
        dst_mac: str,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        protocol: str,
        length: int,
        timestamp: float,
    ):
        """Records packet statistics for MAC addresses and conversation pairs."""
        src_norm = normalize_mac(src_mac)
        dst_norm = normalize_mac(dst_mac)
        if not src_norm or not dst_norm:
            return

        # Ensure devices tracked
        for mac, role_hint, ip_hint in [
            (src_norm, "sender", src_ip),
            (dst_norm, "receiver", dst_ip),
        ]:
            if mac not in self.devices:
                analysis = analyze_mac_address(mac)
                
                # Determine device role
                role = "Unknown Station"
                if mac == self.hotspot_gateway_mac or ip_hint == self.hotspot_gateway_ip:
                    role = "💻 Laptop Hotspot Gateway"
                elif mac == "ff:ff:ff:ff:ff:ff":
                    role = "📢 Broadcast Address"
                elif analysis["cast_type"] == "Multicast":
                    role = "👥 Multicast Group"
                elif (
                    ip_hint
                    and ip_hint.startswith("192.168.137.")
                    and ip_hint != self.hotspot_gateway_ip
                ):
                    role = "📱 Connected Phone / Client"
                elif analysis["is_randomized"]:
                    role = "📱 Client Device (Randomized MAC)"

                self.devices[mac] = {
                    "mac": mac,
                    "vendor": analysis["vendor"],
                    "cast_type": analysis["cast_type"],
                    "admin_type": analysis["admin_type"],
                    "is_randomized": analysis["is_randomized"],
                    "role": role,
                    "ips": set(),
                    "packets_sent": 0,
                    "packets_received": 0,
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "protocols": set(),
                }

        # Update sender device
        s_dev = self.devices[src_norm]
        s_dev["packets_sent"] += 1
        s_dev["bytes_sent"] += length
        s_dev["last_seen"] = timestamp
        if protocol:
            s_dev["protocols"].add(protocol)
        if src_ip and src_ip != "-":
            s_dev["ips"].add(src_ip)
            if (
                src_ip.startswith("192.168.137.")
                and src_ip != self.hotspot_gateway_ip
                and s_dev["role"] == "Unknown Station"
            ):
                s_dev["role"] = "📱 Connected Phone / Client"

        # Update receiver device
        d_dev = self.devices[dst_norm]
        d_dev["packets_received"] += 1
        d_dev["bytes_received"] += length
        d_dev["last_seen"] = timestamp
        if protocol:
            d_dev["protocols"].add(protocol)
        if dst_ip and dst_ip != "-":
            d_dev["ips"].add(dst_ip)
            if (
                dst_ip.startswith("192.168.137.")
                and dst_ip != self.hotspot_gateway_ip
                and d_dev["role"] == "Unknown Station"
            ):
                d_dev["role"] = "📱 Connected Phone / Client"

        # Track conversation pair (ordered key for bidirectional pairing)
        pair_key = tuple(sorted([src_norm, dst_norm]))
        if pair_key not in self.conversations:
            self.conversations[pair_key] = {
                "mac_a": pair_key[0],
                "mac_b": pair_key[1],
                "packets": 0,
                "bytes": 0,
                "protocols": set(),
                "first_seen": timestamp,
                "last_seen": timestamp,
            }
        conv = self.conversations[pair_key]
        conv["packets"] += 1
        conv["bytes"] += length
        conv["last_seen"] = timestamp
        if protocol:
            conv["protocols"].add(protocol)

    def get_summary(self) -> Dict[str, Any]:
        """Returns structured MAC analysis data for dashboard rendering."""
        devices_list = []
        for dev in self.devices.values():
            devices_list.append(
                {
                    "mac": dev["mac"],
                    "vendor": dev["vendor"],
                    "cast_type": dev["cast_type"],
                    "admin_type": dev["admin_type"],
                    "is_randomized": dev["is_randomized"],
                    "role": dev["role"],
                    "ips": sorted(list(dev["ips"])),
                    "packets_sent": dev["packets_sent"],
                    "packets_received": dev["packets_received"],
                    "total_packets": dev["packets_sent"] + dev["packets_received"],
                    "bytes_sent": dev["bytes_sent"],
                    "bytes_received": dev["bytes_received"],
                    "total_bytes": dev["bytes_sent"] + dev["bytes_received"],
                    "first_seen": dev["first_seen"],
                    "last_seen": dev["last_seen"],
                    "protocols": sorted(list(dev["protocols"])),
                }
            )

        # Sort devices by total packets descending
        devices_list.sort(key=lambda x: x["total_packets"], reverse=True)

        conversations_list = []
        for conv in self.conversations.values():
            dev_a = self.devices.get(conv["mac_a"], {})
            dev_b = self.devices.get(conv["mac_b"], {})
            conversations_list.append(
                {
                    "mac_a": conv["mac_a"],
                    "mac_a_role": dev_a.get("role", "Device"),
                    "mac_a_vendor": dev_a.get("vendor", "Unknown"),
                    "mac_b": conv["mac_b"],
                    "mac_b_role": dev_b.get("role", "Device"),
                    "mac_b_vendor": dev_b.get("vendor", "Unknown"),
                    "packets": conv["packets"],
                    "bytes": conv["bytes"],
                    "protocols": sorted(list(conv["protocols"])),
                    "first_seen": conv["first_seen"],
                    "last_seen": conv["last_seen"],
                }
            )
        conversations_list.sort(key=lambda x: x["packets"], reverse=True)

        # Cast & Admin Distribution
        unicast_count = sum(1 for d in devices_list if d["cast_type"] == "Unicast")
        multicast_count = sum(1 for d in devices_list if d["cast_type"] == "Multicast")
        broadcast_count = sum(1 for d in devices_list if d["cast_type"] == "Broadcast")
        laa_count = sum(1 for d in devices_list if d["is_randomized"])
        uaa_count = sum(1 for d in devices_list if not d["is_randomized"] and d["cast_type"] == "Unicast")

        return {
            "total_macs": len(devices_list),
            "devices": devices_list,
            "conversations": conversations_list,
            "stats": {
                "unicast": unicast_count,
                "multicast": multicast_count,
                "broadcast": broadcast_count,
                "randomized_laa": laa_count,
                "hardware_uaa": uaa_count,
            },
        }

# ==============================================================================
# PART 2: TWO-STAGE PROTOCOL PARSER & HEX DUMP ENGINE (packet_parser.py)
# ==============================================================================
"""
packet_parser.py
Deep packet dissection, metadata extraction, Wireshark-like formatting,
and hex dump generation for network packets.
Split into high-speed summary extraction (for live table)
and on-demand deep layer/hex extraction (for inspection pane).
"""

import time
import datetime
from typing import Dict, Any, Optional, Tuple, List
import scapy.all as scapy


def extract_sni_from_payload(payload: bytes) -> Optional[str]:
    """
    Extracts the Server Name Indication (SNI) from a TLS Client Hello packet payload.
    Enables displaying visited domain names (e.g. google.com, wikipedia.org, instagram.com)
    without needing heavy third-party TLS libraries.
    """
    try:
        # TLS record: ContentType 0x16 (Handshake), Version 0x0301/0x0303
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        # Handshake Type == 1 (Client Hello)
        if len(payload) < 9 or payload[5] != 0x01:
            return None
        
        # Skip record header (5) + handshake type (1) + length (3) + version (2) + random (32) = 43 bytes
        pos = 43
        if pos >= len(payload):
            return None
        
        # Session ID length
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(payload):
            return None
        
        # Cipher suites length
        cipher_suites_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2 + cipher_suites_len
        if pos + 1 > len(payload):
            return None
        
        # Compression methods length
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None
        
        # Extensions length
        extensions_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2
        end_pos = min(pos + extensions_len, len(payload))
        
        while pos + 4 <= end_pos:
            ext_type = int.from_bytes(payload[pos : pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2 : pos + 4], "big")
            pos += 4
            if ext_type == 0:  # Server Name Indication extension
                if pos + 5 <= end_pos:
                    sni_name_len = int.from_bytes(payload[pos + 3 : pos + 5], "big")
                    name_bytes = payload[pos + 5 : pos + 5 + sni_name_len]
                    return name_bytes.decode("utf-8", errors="ignore")
            pos += ext_len
    except Exception:
        pass
    return None


def format_hex_dump(raw_bytes: bytes) -> str:
    """
    Produces standard Wireshark-style hex dump:
    0000   00 1a 2b 3c 4d 5e 6f ...  ..+<M^o.
    """
    if not raw_bytes:
        return "0000   -- Empty payload --"
    lines = []
    for i in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex part to 48 chars (16 * 2 + 15 spaces + 1)
        hex_part = hex_part.ljust(48)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_part}   {ascii_part}")
    return "\n".join(lines)


def extract_packet_summary(pkt: scapy.Packet, pkt_id: int, start_time: float) -> Dict[str, Any]:
    """
    High-speed metadata extraction for live packet table streaming.
    Only extracts essential columns (no hex dump, no layer tree)
    to keep JSON payload tiny (~90 bytes) and execution under 15 microseconds.
    """
    now = float(getattr(pkt, "time", time.time()))
    rel_time = max(0.0, now - start_time)
    dt_str = datetime.datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3]
    wire_len = len(pkt)

    # Layer 2 Ethernet
    src_mac = "-"
    dst_mac = "-"
    if pkt.haslayer(scapy.Ether):
        eth = pkt[scapy.Ether]
        src_mac = normalize_mac(eth.src)
        dst_mac = normalize_mac(eth.dst)

    src_mac_analysis = analyze_mac_address(src_mac)
    dst_mac_analysis = analyze_mac_address(dst_mac)

    # Layer 3 / 4 variables
    src_ip = "-"
    dst_ip = "-"
    src_port = None
    dst_port = None
    protocol = "Ethernet"
    info = ""

    # ARP
    if pkt.haslayer(scapy.ARP):
        arp = pkt[scapy.ARP]
        protocol = "ARP"
        src_ip = getattr(arp, "psrc", "-")
        dst_ip = getattr(arp, "pdst", "-")
        if arp.op == 1:
            info = f"Who has {dst_ip}? Tell {src_ip}"
        elif arp.op == 2:
            info = f"{src_ip} is at {getattr(arp, 'hwsrc', '-')}"
        else:
            info = f"ARP Opcode {arp.op}"

    # IPv4
    elif pkt.haslayer(scapy.IP):
        ip = pkt[scapy.IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto_num = getattr(ip, "proto", 0)
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 47: "GRE"}
        protocol = proto_map.get(proto_num, f"IP-{proto_num}")

    # IPv6
    elif pkt.haslayer(scapy.IPv6):
        ip6 = pkt[scapy.IPv6]
        src_ip = ip6.src
        dst_ip = ip6.dst
        nh = getattr(ip6, "nh", 0)
        nh_map = {6: "TCP", 17: "UDP", 58: "ICMPv6"}
        protocol = nh_map.get(nh, f"IPv6-{nh}")

    # ICMP
    if pkt.haslayer(scapy.ICMP):
        icmp = pkt[scapy.ICMP]
        protocol = "ICMP"
        icmp_type_names = {0: "Echo Reply", 3: "Destination Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
        t_name = icmp_type_names.get(icmp.type, f"Type {icmp.type}")
        info = f"ICMP {t_name}"

    # TCP
    if pkt.haslayer(scapy.TCP):
        tcp = pkt[scapy.TCP]
        src_port = tcp.sport
        dst_port = tcp.dport

        flags = []
        if getattr(tcp.flags, "F", False): flags.append("FIN")
        if getattr(tcp.flags, "S", False): flags.append("SYN")
        if getattr(tcp.flags, "R", False): flags.append("RST")
        if getattr(tcp.flags, "P", False): flags.append("PSH")
        if getattr(tcp.flags, "A", False): flags.append("ACK")
        if getattr(tcp.flags, "U", False): flags.append("URG")
        flag_str = "[" + ", ".join(flags) + "]" if flags else "[None]"

        payload_bytes = bytes(tcp.payload) if tcp.payload else b""

        if src_port == 80 or dst_port == 80 or payload_bytes.startswith(b"GET ") or payload_bytes.startswith(b"POST ") or payload_bytes.startswith(b"HTTP/"):
            protocol = "HTTP"
            first_line = payload_bytes.split(b"\r\n")[0].decode("utf-8", errors="ignore") if payload_bytes else ""
            info = f"HTTP {first_line}" if first_line else f"{src_port} -> {dst_port} {flag_str}"
        elif src_port == 443 or dst_port == 443:
            protocol = "HTTPS"
            sni = extract_sni_from_payload(payload_bytes)
            if sni:
                info = f"TLS Client Hello (SNI: {sni})"
            elif payload_bytes.startswith(b"\x16\x03"):
                info = f"TLS Handshake {flag_str} Len={len(payload_bytes)}"
            elif payload_bytes.startswith(b"\x17\x03"):
                info = f"TLS Application Data {flag_str} Len={len(payload_bytes)}"
            else:
                info = f"{src_port} -> {dst_port} {flag_str} Seq={tcp.seq} Ack={tcp.ack}"
        elif src_port in (5228, 5229, 5230) or dst_port in (5228, 5229, 5230):
            protocol = "Google FCM"
            info = f"Push Notification Stream {src_port} -> {dst_port} {flag_str}"
        elif src_port == 853 or dst_port == 853:
            protocol = "DoT"
            info = f"DNS over TLS {src_port} -> {dst_port} {flag_str}"
        elif src_port in (8080, 8443, 8000) or dst_port in (8080, 8443, 8000):
            protocol = "HTTP-Alt"
            info = f"Web App Stream {src_port} -> {dst_port} {flag_str}"
        else:
            protocol = "TCP"
            info = f"{src_port} -> {dst_port} {flag_str} Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"

    # UDP & DNS
    elif pkt.haslayer(scapy.UDP):
        udp = pkt[scapy.UDP]
        src_port = udp.sport
        dst_port = udp.dport
        udp_len = getattr(udp, "len", None) or len(bytes(udp))

        if pkt.haslayer(scapy.DNS):
            protocol = "DNS"
            dns = pkt[scapy.DNS]
            qname = ""
            try:
                if dns.qd:
                    qd_item = dns.qd[0] if hasattr(dns.qd, "__getitem__") else dns.qd
                    if hasattr(qd_item, "qname") and qd_item.qname:
                        qname = qd_item.qname.decode("utf-8", errors="ignore").rstrip(".") if isinstance(qd_item.qname, bytes) else str(qd_item.qname).rstrip(".")
            except Exception:
                pass

            if getattr(dns, "qr", 0) == 0:
                info = f"Standard query A {qname}"
            else:
                an_count = getattr(dns, "ancount", 0)
                info = f"Standard query response ({an_count} answers)" + (f" for {qname}" if qname else "")
        elif src_port == 443 or dst_port == 443:
            protocol = "QUIC"
            info = f"QUIC App/Media Stream: {src_port} -> {dst_port} Len={udp_len}"
        elif src_port in (3478, 3479) or dst_port in (3478, 3479):
            protocol = "STUN/VoIP"
            info = f"Voice/Video Call Stream: {src_port} -> {dst_port} Len={udp_len}"
        elif src_port == 53 or dst_port == 53:
            protocol = "DNS"
            info = f"DNS raw packet {src_port} -> {dst_port} Len={udp_len}"
        elif src_port in (67, 68) or dst_port in (67, 68):
            protocol = "DHCP"
            info = f"DHCP message {src_port} -> {dst_port}"
        elif src_port == 5353 or dst_port == 5353:
            protocol = "mDNS"
            info = f"Multicast DNS {src_port} -> {dst_port}"
        elif src_port == 1900 or dst_port == 1900:
            protocol = "SSDP"
            info = f"Simple Service Discovery Protocol {src_port} -> {dst_port}"
        elif src_port == 123 or dst_port == 123:
            protocol = "NTP"
            info = f"Network Time Protocol {src_port} -> {dst_port}"
        else:
            protocol = "UDP"
            info = f"{src_port} -> {dst_port} Len={udp_len}"

    if not info:
        info = f"{protocol} frame ({wire_len} bytes)"

    return {
        "id": pkt_id,
        "time": dt_str,
        "rel_time": f"{rel_time:.4f}",
        "raw_time": now,
        "length": wire_len,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "src_mac_vendor": src_mac_analysis["vendor"],
        "dst_mac_vendor": dst_mac_analysis["vendor"],
        "src_mac_type": src_mac_analysis["cast_type"],
        "dst_mac_type": dst_mac_analysis["cast_type"],
        "src_mac_admin": src_mac_analysis["admin_type"],
        "dst_mac_admin": dst_mac_analysis["admin_type"],
        "src_mac_randomized": src_mac_analysis["is_randomized"],
        "dst_mac_randomized": dst_mac_analysis["is_randomized"],
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "info": info,
    }


def extract_packet_details(pkt: scapy.Packet, pkt_id: int, start_time: float) -> Dict[str, Any]:
    """
    On-demand full layer tree dissection and hex dump generation.
    Only invoked when the user selects a packet in the UI.
    """
    summary = extract_packet_summary(pkt, pkt_id, start_time)
    wire_len = summary["length"]
    now = summary["raw_time"]
    rel_time = float(summary["rel_time"])
    dt_str = summary["time"]

    layer_tree: List[Dict[str, Any]] = []

    # 1. Frame Layer
    layer_tree.append({
        "name": f"Frame {pkt_id}: {wire_len} bytes on wire ({wire_len * 8} bits)",
        "fields": {
            "Arrival Time": dt_str,
            "Epoch Time": f"{now:.6f}",
            "Relative Time": f"{rel_time:.4f} seconds",
            "Frame Length": f"{wire_len} bytes",
        }
    })

    # 2. Ethernet II Layer
    if pkt.haslayer(scapy.Ether):
        eth = pkt[scapy.Ether]
        eth_type = hex(eth.type)
        layer_tree.append({
            "name": f"Ethernet II, Src: {summary['src_mac']} ({summary['src_mac_vendor']}), Dst: {summary['dst_mac']} ({summary['dst_mac_vendor']})",
            "fields": {
                "Source MAC Address": f"{summary['src_mac']} ({summary['src_mac_vendor']})",
                "Source MAC Classification": f"{summary['src_mac_type']} | {summary['src_mac_admin']}",
                "Destination MAC Address": f"{summary['dst_mac']} ({summary['dst_mac_vendor']})",
                "Destination MAC Classification": f"{summary['dst_mac_type']} | {summary['dst_mac_admin']}",
                "EtherType": eth_type,
            }
        })

    # 3. ARP Layer
    if pkt.haslayer(scapy.ARP):
        arp = pkt[scapy.ARP]
        op_name = "Request" if arp.op == 1 else "Reply" if arp.op == 2 else f"Opcode {arp.op}"
        layer_tree.append({
            "name": f"Address Resolution Protocol ({op_name})",
            "fields": {
                "Hardware Type": arp.hwtype,
                "Protocol Type": hex(arp.ptype),
                "Hardware Size": arp.hwlen,
                "Protocol Size": arp.plen,
                "Opcode": f"{arp.op} ({op_name})",
                "Sender MAC Address": arp.hwsrc,
                "Sender IP Address": arp.psrc,
                "Target MAC Address": arp.hwdst,
                "Target IP Address": arp.pdst,
            }
        })

    # 4. IPv4 Layer
    elif pkt.haslayer(scapy.IP):
        ip = pkt[scapy.IP]
        ihl = getattr(ip, "ihl", 5) or 5
        layer_tree.append({
            "name": f"Internet Protocol Version 4, Src: {ip.src}, Dst: {ip.dst}",
            "fields": {
                "Version": getattr(ip, "version", 4) or 4,
                "Header Length": f"{ihl * 4} bytes",
                "Type of Service (ToS)": hex(getattr(ip, "tos", 0) or 0),
                "Total Length": f"{getattr(ip, 'len', wire_len)} bytes",
                "Identification": f"{hex(getattr(ip, 'id', 0) or 0)} ({getattr(ip, 'id', 0) or 0})",
                "Flags": str(getattr(ip, "flags", "")),
                "Fragment Offset": getattr(ip, "frag", 0) or 0,
                "Time to Live (TTL)": getattr(ip, "ttl", 64) or 64,
                "Protocol": f"{summary['protocol']} ({getattr(ip, 'proto', 0)})",
                "Header Checksum": hex(getattr(ip, "chksum", 0) or 0),
                "Source IP Address": ip.src,
                "Destination IP Address": ip.dst,
            }
        })

    # 5. IPv6 Layer
    elif pkt.haslayer(scapy.IPv6):
        ip6 = pkt[scapy.IPv6]
        layer_tree.append({
            "name": f"Internet Protocol Version 6, Src: {ip6.src}, Dst: {ip6.dst}",
            "fields": {
                "Version": getattr(ip6, "version", 6),
                "Traffic Class": hex(getattr(ip6, "tc", 0)),
                "Flow Label": hex(getattr(ip6, "fl", 0)),
                "Payload Length": getattr(ip6, "plen", 0),
                "Next Header": f"{summary['protocol']} ({getattr(ip6, 'nh', 0)})",
                "Hop Limit": getattr(ip6, "hlim", 64),
                "Source IP Address": ip6.src,
                "Destination IP Address": ip6.dst,
            }
        })

    # 6. ICMP Layer
    if pkt.haslayer(scapy.ICMP):
        icmp = pkt[scapy.ICMP]
        layer_tree.append({
            "name": f"Internet Control Message Protocol (Type {icmp.type})",
            "fields": {
                "Type": icmp.type,
                "Code": icmp.code,
                "Checksum": hex(getattr(icmp, "chksum", 0) or 0),
            }
        })

    # 7. TCP Layer
    if pkt.haslayer(scapy.TCP):
        tcp = pkt[scapy.TCP]
        dataofs = getattr(tcp, "dataofs", 5) or 5
        payload_bytes = bytes(tcp.payload) if tcp.payload else b""
        layer_tree.append({
            "name": f"Transmission Control Protocol, Src Port: {tcp.sport}, Dst Port: {tcp.dport}, Seq: {tcp.seq}, Ack: {tcp.ack}",
            "fields": {
                "Source Port": tcp.sport,
                "Destination Port": tcp.dport,
                "Sequence Number": tcp.seq,
                "Acknowledgment Number": tcp.ack,
                "Header Length": f"{dataofs * 4} bytes",
                "Flags": hex(int(tcp.flags)),
                "Window Size": tcp.window,
                "Checksum": hex(getattr(tcp, "chksum", 0) or 0),
                "Payload Length": f"{len(payload_bytes)} bytes",
            }
        })

    # 8. UDP Layer
    elif pkt.haslayer(scapy.UDP):
        udp = pkt[scapy.UDP]
        udp_len = getattr(udp, "len", None) or len(bytes(udp))
        layer_tree.append({
            "name": f"User Datagram Protocol, Src Port: {udp.sport}, Dst Port: {udp.dport}",
            "fields": {
                "Source Port": udp.sport,
                "Destination Port": udp.dport,
                "Length": f"{udp_len} bytes",
                "Checksum": hex(getattr(udp, "chksum", 0) or 0),
            }
        })

    # 9. DNS Layer
    if pkt.haslayer(scapy.DNS):
        dns = pkt[scapy.DNS]
        qr_str = "response" if getattr(dns, "qr", 0) == 1 else "query"
        layer_tree.append({
            "name": f"Domain Name System ({qr_str})",
            "fields": {
                "Transaction ID": f"0x{getattr(dns, 'id', 0):04x}",
                "Flags": f"0x{getattr(dns, 'qr', 0):x}",
                "Questions": getattr(dns, "qdcount", 0),
                "Answer RRs": getattr(dns, "ancount", 0),
                "Authority RRs": getattr(dns, "nscount", 0),
                "Additional RRs": getattr(dns, "arcount", 0),
            }
        })

    # Generate Wireshark-style Hex Dump
    raw_packet_bytes = bytes(pkt)
    hex_dump = format_hex_dump(raw_packet_bytes)

    result = dict(summary)
    result["layer_tree"] = layer_tree
    result["hex_dump"] = hex_dump
    return result


def parse_packet(pkt: scapy.Packet, pkt_id: int, start_time: float) -> Dict[str, Any]:
    """Backward compatibility wrapper that returns full dissection and hex dump."""
    return extract_packet_details(pkt, pkt_id, start_time)

# ==============================================================================
# PART 3: PACKET SNIFFER & THREAD-SAFE QUEUE MANAGER (sniffer.py)
# ==============================================================================
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

# ==============================================================================
# PART 4: FLASK REST API SERVER & ENDPOINTS (app.py)
# ==============================================================================
"""
app.py
Flask web server for the Network MAC & IP Analysis Tool.
Provides real-time packet streaming, MAC address analytics,
filter management, and PCAP/CSV export.
"""

import os
import sys
from flask import Flask, render_template, jsonify, request, Response, send_file
import io


app = Flask(__name__)
sniffer = PacketSniffer()


@app.route("/")
def index():
    """Serves the main application interface."""
    return render_template("index.html")


@app.route("/api/interfaces", methods=["GET"])
def get_interfaces():
    """Returns available network interfaces with the hotspot interface highlighted."""
    interfaces = sniffer.get_available_interfaces()
    default_iface = sniffer.get_default_interface()
    return jsonify({
        "interfaces": interfaces,
        "default": default_iface,
    })


@app.route("/api/status", methods=["GET"])
def get_status():
    """Returns the current capture status and metrics."""
    return jsonify(sniffer.get_status())


@app.route("/api/capture/start", methods=["POST"])
def start_capture():
    """Starts live packet capture on the specified interface and filter preset."""
    data = request.get_json() or {}
    interface = data.get("interface")
    filter_preset = data.get("filter_preset", "phone_all")
    custom_bpf = data.get("custom_bpf", "")

    success = sniffer.start(interface=interface, filter_preset=filter_preset, custom_bpf=custom_bpf)
    return jsonify({
        "success": success,
        "status": sniffer.get_status(),
    })


@app.route("/api/capture/pause", methods=["POST"])
def pause_capture():
    """Pauses capturing without losing packets."""
    success = sniffer.pause()
    return jsonify({"success": success, "status": sniffer.get_status()})


@app.route("/api/capture/resume", methods=["POST"])
def resume_capture():
    """Resumes packet capturing."""
    success = sniffer.resume()
    return jsonify({"success": success, "status": sniffer.get_status()})


@app.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    """Stops packet capture."""
    success = sniffer.stop()
    return jsonify({"success": success, "status": sniffer.get_status()})


@app.route("/api/capture/clear", methods=["POST"])
def clear_capture():
    """Clears all captured packets, resetting packet count strictly to 0."""
    success = sniffer.clear()
    return jsonify({"success": success, "status": sniffer.get_status()})


@app.route("/api/packets", methods=["GET"])
def get_packets():
    """
    Returns list of captured packets.
    Supports incremental polling using since_id, search query, and protocol filtering.
    """
    since_id = request.args.get("since_id", default=0, type=int)
    limit = request.args.get("limit", default=200, type=int)
    search_query = request.args.get("search", default="", type=str)
    protocol_filter = request.args.get("protocol", default="", type=str)

    packets = sniffer.get_packets(
        since_id=since_id,
        limit=limit,
        search_query=search_query,
        protocol_filter=protocol_filter,
    )

    return jsonify({
        "packets": packets,
        "count": len(packets),
        "total_captured": sniffer.packet_counter,
    })


@app.route("/api/packet/<int:pkt_id>", methods=["GET"])
def get_packet_detail(pkt_id):
    """Returns deep layer breakdown and hex dump for a single packet."""
    packet = sniffer.get_packet_by_id(pkt_id)
    if not packet:
        return jsonify({"error": "Packet not found"}), 404
    return jsonify(packet)


@app.route("/api/mac-analysis", methods=["GET"])
def get_mac_analysis():
    """Returns aggregated MAC analysis, devices list, vendors, and conversations matrix."""
    summary = sniffer.mac_tracker.get_summary()
    return jsonify(summary)


@app.route("/api/export/pcap", methods=["GET"])
def export_pcap():
    """Exports and downloads captured packets as a standard Wireshark PCAP file."""
    pcap_data = sniffer.export_pcap_bytes()
    if not pcap_data:
        return jsonify({"error": "No packets captured to export"}), 400

    return Response(
        pcap_data,
        mimetype="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": "attachment; filename=capture.pcap"},
    )


@app.route("/api/export/csv", methods=["GET"])
def export_csv():
    """Exports and downloads packet summary as CSV."""
    csv_str = sniffer.export_csv_string()
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=capture.csv"},
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"[*] Starting MAC & IP Network Analysis Tool on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)

# ==============================================================================
# PART 5: APPLICATION LAUNCHER & BROWSER AUTOMATION (main.py)
# ==============================================================================
"""
main.py
One-click Launcher for NetShark MAC & IP Network Analysis Tool.
Automatically initializes the server, detects interfaces, and launches the browser UI.
"""

import os
import sys
import time
import socket
import webbrowser
import threading

DEFAULT_PORT = 8080


def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def find_available_port(start_port: int = 8080) -> int:
    port = start_port
    while port < start_port + 50:
        if not is_port_in_use(port):
            return port
        port += 1
    return start_port


def open_browser_delayed(url: str, delay: float = 1.2):
    time.sleep(delay)
    print(f"[*] Opening NetShark Dashboard in default browser: {url}")
    webbrowser.open(url)


def main():
    print("=" * 70)
    print("  NetShark - MAC Address & IP Network Analyzer (Wireshark-Alternative)")
    print("=" * 70)
    print("[*] Detecting network interfaces...")
    
    ifaces = sniffer.get_available_interfaces()
    hotspot_iface = next((i for i in ifaces if i["is_hotspot"]), None)
    
    if hotspot_iface:
        print(f"[+] Detected Mobile Hotspot Interface: {hotspot_iface['display_name']}")
    else:
        print("[!] Note: If Mobile Hotspot is not yet turned on, enable it in Windows Settings.")

    port = find_available_port(DEFAULT_PORT)
    url = f"http://127.0.0.1:{port}"

    print(f"[+] Starting local web dashboard at: {url}")
    print("[+] Packet counter initially initialized to strictly 0 packets.")
    print("[+] Default Filter Preset: 'All Phone Activity (Apps, Social Media, Streaming, Browsing)'")
    print("    -> While phone is idle, 0 packets are generated.")
    print("    -> Using phone (WhatsApp, Instagram, YouTube, apps, browsing) generates real-time packets!")
    print("=" * 70)
    print("[*] Press Ctrl+C in this terminal to stop the application.")
    print("=" * 70)

    # Launch browser in a background thread
    threading.Thread(target=open_browser_delayed, args=(url,), daemon=True).start()

    # Start Flask server
    try:
        app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n[*] Stopping NetShark sniffer and shutting down cleanly...")
        sniffer.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
