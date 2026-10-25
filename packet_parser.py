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
from mac_analyzer import analyze_mac_address, normalize_mac


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
