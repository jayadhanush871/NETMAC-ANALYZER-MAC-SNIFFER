# NetMAC Analyzer: MAC Address Sniffer & Privacy Classifier

**NetMAC Analyzer** is an automated, real-time Layer-2 and Layer-3 network packet capture and hardware address analysis framework developed in Python. Engineered specifically for **targeted virtual hotspot adapter monitoring**, it enforces a strict **zero-packet idle baseline**, performs **bitwise link-layer MAC privacy classification (LAA vs. UAA)**, resolves **hardware manufacturer OUIs**, and correlates multi-layer flows with a **Wireshark-style interactive web dashboard**.

## 🌟 Key Features

1. **Zero-Packet Baseline (`0 Packets` at Startup)**:
   - Initial state starts strictly at **0 packets**.
   - Binds to the designated virtual hotspot interface (`Microsoft Wi-Fi Direct Virtual Adapter #2` on `192.168.137.0/24`), eliminating background broadcast chatter (mDNS, SSDP, LLMNR).
   - Clear button resets packet counts and tables strictly back to 0.

2. **Automated Link-Layer Bitwise MAC Decomposition**:
   - Decodes the 48-bit MAC address at the bit level:
     - **Bit 0 (I/G Bit)**: Classifies transmission scope (Unicast vs. Multicast/Broadcast).
     - **Bit 1 (U/L Bit)**: Evaluates administrative authority:
       - **Locally Administered Address (LAA)**: Automatically flags Randomized Private MAC addresses used by modern mobile devices (Android 10+, iOS 14+).
       - **Universally Administered Address (UAA)**: Factory burned-in hardware addresses.

3. **Hardware Provenance & OUI Vendor Mapping**:
   - Matches the 24-bit OUI prefix against an offline IEEE manufacturer database (Apple, Samsung, Google, Xiaomi, OnePlus, Intel, Realtek, AzureWave, etc.).

4. **Multi-Layer Protocol Correlation**:
   - Seamlessly extracts and correlates Layer-2 Source/Destination MAC addresses with Layer-3 Source/Destination IP addresses and Layer-4 transport protocols (TCP, UDP, ARP, ICMP, DNS, TLS/HTTPS, QUIC).

5. **Interactive Wireshark-Style Tri-Pane Web Dashboard**:
   - **Virtualized Packet Table**: Streamlined packet view with DOM virtualization to prevent browser lag.
   - **Hierarchical Protocol Layer Tree**: Deep inspection of Frame, Ethernet II, IPv4, TCP/UDP, and application headers.
   - **16-Byte Hexadecimal & ASCII Memory Dump**: Byte-accurate low-level memory inspection.
   - **PCAP & CSV Export**: Download captures directly as standard `.pcap` files readable in Wireshark.

---

## 🏗️ System Architecture

```
+---------------------------------------------------------------------------------------+
|                                  APPLICATION LAYER                                    |
|                       Database Storage, Analysis Engine, Web UI                       |
+---------------------------------------------------------------------------------------+
|                               NETWORK ANALYSIS LAYER                                  |
|                 Packet Parsing, Frame Classification, Bitwise LAA/UAA                 |
+---------------------------------------------------------------------------------------+
|                                  DATA LINK LAYER                                      |
|                       802.11 / Ethernet II Frames, 48-bit MACs                        |
+---------------------------------------------------------------------------------------+
|                                   PHYSICAL LAYER                                      |
|                     Wireless Interface, Antenna, Npcap Kernel Driver                  |
+---------------------------------------------------------------------------------------+
```

---

## 🚀 How to Run

### Method 1: One-Click Windows Launcher
Double-click `run.bat` or run in terminal:
```powershell
.\run.bat
```

### Method 2: Python Command
```powershell
python main.py
```
This automatically initializes the server, detects the hotspot adapter, and launches the web interface at:
`http://127.0.0.1:8080`

### Method 3: All-In-One Standalone File
```powershell
python netmac_analyzer_complete.py
```

### Running the Automated Unit Test Suite
```powershell
python test_app.py
```
*(All 6 unit tests cover endpoints, bitwise classification, parsing, and hex dumps).*

---

## 📁 Repository Structure

```
├── app.py                      # Flask REST API Controller & Endpoints
├── sniffer.py                  # Asynchronous Packet Sniffer (Scapy AsyncSniffer)
├── mac_analyzer.py             # Bitwise MAC Engine & OUI Manufacturer Lookup
├── packet_parser.py            # Two-Stage Protocol Parser & Hex Dump Viewer
├── main.py                     # Auto-Launcher & Port Discovery
├── netmac_analyzer_complete.py # Consolidated All-in-One Standalone Script
├── test_app.py                 # Automated Test Suite (6 Test Cases)
├── run.bat                     # Windows Batch Launcher Script
├── templates/
│   └── index.html              # Tri-Pane Web Interface Template
└── static/
    ├── js/app.js               # Frontend Streaming & Virtualization Logic
    └── css/style.css           # Responsive Custom Dark Theme Styling
```
