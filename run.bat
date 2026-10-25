@echo off
title NetMAC Analyzer - MAC Address Sniffer
cd /d "%~dp0"
echo ======================================================================
echo    Starting NetMAC Analyzer: MAC Address Sniffer (Team 23)
echo ======================================================================

echo [*] Checking dependencies...
python -c "import flask, scapy" 2>nul
if %errorlevel% neq 0 (
    echo [!] Missing required Python libraries. Installing automatically...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        pip install flask scapy
    )
    echo [+] Dependencies installed successfully!
    echo ======================================================================
)

python main.py
pause
