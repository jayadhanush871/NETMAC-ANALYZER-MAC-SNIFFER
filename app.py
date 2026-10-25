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

from sniffer import PacketSniffer

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
