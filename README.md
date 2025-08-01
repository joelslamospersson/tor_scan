# tor_scan
Tor routation, scans an reachable webserver for weaknesses + has option to test those attacks on the network if permission yes is input.

# Legal Disclaimer: Responsibility and permission
```
In order to scan, attack or test weaknesses/exploits, you are acknowledging that you yourself
 are responsible for obtaining explicit permission from the target owner to perform any tests on their system.
If you skip this warning, you may face legal issues. All weaknesses found must be reported to the target owner.
```

# Tested system
```
This has been performed on a Ubuntu 24.04 system.
```

# Setup
```
1. System Update & Core Packages
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
    python3 python3-venv python3-pip \
    tor torsocks \
    nmap nikto whatweb wafw00f dirb \
    snapd git build-essential libssl-dev libffi-dev

2. Install OWASP Amass
sudo snap install amass
or
sudo apt install -y amass

3. Configure & Start Tor
1) Enable ControlPort
Edit /etc/tor/torrc and add:

2) restart tor
sudo systemctl restart tor
sudo systemctl enable tor

3) Verify status
netstat -tnlp | grep 9050   # SOCKS proxy
netstat -tnlp | grep 9051   # ControlPort

4) Create the script and paste
sudo nano tor_scan.py
# Give permissions
chmod +x tor_scan.py

5) If you want AbuseIPDB, Shodan, SecurityTrails or VirusTotal checks, edit the top of tor_scan.py and fill in:
SHODAN_API_KEY      = "YOUR_SHODAN_KEY"
ABUSEIPDB_API_KEY   = "YOUR_ABUSEIPDB_KEY"
SECURITYTRAILS_API_KEY = "YOUR_SECURITYTRAILS_KEY"
VT_API_KEY          = "YOUR_VIRUSTOTAL_KEY"

6. Python Virtual Environment (Recommended)
python3 -m venv venv
source venv/bin/activate
pip install -U pip
pip install stem requests

7) Run the scanner
# If using venv:
source venv/bin/activate

# Launch:
./tor_scan.py

# Input target
http:// or https://example.com
```

# What it does
```
You’ll be prompted for:

    Target (domain or IPv4)

    SQLi permission (yes/no)

    Exploitation permission (yes/no)

Then it will:

    Rotate your Tor IP

    Enumerate DNS & subdomains (+ real IPs)

    Reverse-DNS, GeoIP lookups

    Nmap, Nikto, WhatWeb, WAFW00F, dirb scans

    Optional SQLMap + exploit scripts

    AbuseIPDB & Shodan checks

    Log everything to TARGET_YYYYMMDD_HHMMSS.log

    Export structured JSON to TARGET_YYYYMMDD_HHMMSS_summary.json
```
