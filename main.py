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
from app import app, sniffer

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
