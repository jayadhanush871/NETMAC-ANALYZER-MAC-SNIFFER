# NetMAC Analyzer: MAC Address Sniffer & Privacy Classifier

**NetMAC Analyzer** is an automated, real-time Layer-2 and Layer-3 network packet capture and hardware address analysis framework developed in Python. Engineered specifically for **targeted virtual hotspot adapter monitoring**, it enforces a strict **zero-packet idle baseline**, performs **bitwise link-layer MAC privacy classification (LAA vs. UAA)**, resolves **hardware manufacturer OUIs**, and correlates multi-layer flows with a **Wireshark-style interactive web dashboard**.

----
## 📥 Installation & Requirements Setup Guide

Follow these steps when setting up the project on a new computer or after downloading from GitHub.

### Step 1: Install Python
Ensure Python 3.10 or higher is installed:
* Download from: [https://www.python.org/downloads/](https://www.python.org/downloads/)
* **Important:** During installation, check the box **"Add Python to PATH"**.

---

### Step 2: Install Npcap (Required for Windows Packet Capture)
On Windows, packet sniffers require the **Npcap kernel driver** to capture raw network frames:
1. Download the free installer from: **[https://npcap.com/#download](https://npcap.com/#download)**
2. Run the installer.
3. **Crucial:** During setup, make sure to check the box:  
   ☑ **"Install Npcap in WinPcap API-compatible Mode"**
4. Complete the installation and restart your terminal if prompted.

---

### Step 3: Download / Clone the Repository
Open PowerShell or Command Prompt and clone the repository:
```powershell
git clone https://github.com/jayadhanush871/NETMAC-ANALYZER-MAC-SNIFFER.git
cd NETMAC-ANALYZER-MAC-SNIFFER
```
*(Or download the ZIP from GitHub and extract it to a folder).*

---

### Step 4: Install Required Python Libraries
Inside the project folder, install all required dependencies using `pip`:

```powershell
pip install -r requirements.txt
```

*Or install them directly:*
```powershell
pip install flask scapy
```

> **Note on `ModuleNotFoundError: No module named 'flask'`:**  
> If you see this error when running `run.bat` or `main.py`, it means Step 4 was skipped. Running `pip install -r requirements.txt` will immediately resolve it.

---

## 🚀 How to Run

### Option 1: One-Click Windows Launcher (Recommended)
Double-click `run.bat` or run in terminal:
```powershell
.\run.bat
```
*(The launcher checks dependencies, automatically installs any missing libraries, starts the server, and opens your browser).*

---

### Option 2: Python Command
```powershell
python main.py
```
This initializes the sniffer, binds to the virtual hotspot adapter, and launches the dashboard in your default browser at:  
👉 **`http://127.0.0.1:8080`**

---

### Option 3: All-In-One Standalone File
To run the entire consolidated system from a single script:
```powershell
python netmac_analyzer_complete.py
```

---

### Option 4: Run the Automated Unit Test Suite
To verify that all endpoints, bitwise classification logic, and hex formatting are working:
```powershell
python test_app.py
```
*(Executes 6 automated test cases with 100% pass rate).*

---

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

## 📁 Repository Structure

```
├── app.py                      # Flask REST API Controller & Endpoints
├── sniffer.py                  # Asynchronous Packet Sniffer (Scapy AsyncSniffer)
├── mac_analyzer.py             # Bitwise MAC Engine & OUI Manufacturer Lookup
├── packet_parser.py            # Two-Stage Protocol Parser & Hex Dump Viewer
├── main.py                     # Auto-Launcher & Port Discovery
├── netmac_analyzer_complete.py # Consolidated All-in-One Standalone Script
├── test_app.py                 # Automated Test Suite (6 Test Cases)
├── requirements.txt            # Python Dependencies (flask, scapy)
├── run.bat                     # Windows Batch Launcher Script with Auto-Installer
├── templates/
│   └── index.html              # Tri-Pane Web Interface Template
└── static/
    ├── js/app.js               # Frontend Streaming & Virtualization Logic
    └── css/style.css           # Responsive Custom Dark Theme Styling
```
