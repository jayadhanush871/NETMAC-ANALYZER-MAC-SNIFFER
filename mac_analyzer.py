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
