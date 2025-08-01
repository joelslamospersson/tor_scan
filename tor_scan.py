#!/usr/bin/env python3
import subprocess
import requests
import json
import os
import time
from datetime import datetime
import shlex
import socket
from collections import defaultdict

# ─── USER INPUT ─────────────────────────────────────────────────────────────
from urllib.parse import urlparse

raw_input = input("Enter the domain or IPv4 address to scan: ").strip()
if not raw_input:
    print("No target specified. Exiting.")
    exit(1)

# Normalize target: strip protocol and paths
if raw_input.startswith("http://") or raw_input.startswith("https://"):
    raw_input = raw_input.split("://", 1)[1]
raw_input = raw_input.split('/', 1)[0]
DOMAIN = raw_input.lower()
# Derive root domain for enumeration (e.g., 'example.com' from 'sub.example.com')
parts = DOMAIN.split('.')
ROOT_DOMAIN = '.'.join(parts[-2:]) if len(parts) >= 2 else DOMAIN

# ─── CONFIG ────────────────────────────────────────────────────────────────
# Legal Disclaimer: Responsibility and permission
print("""
[!] DISCLAIMER:
In order to scan, attack or test weaknesses/exploits, you are acknowledging that you yourself are responsible for obtaining explicit permission from the target owner to perform any tests on their system.
If you skip this warning, you may face legal issues. All weaknesses found must be reported to the target owner.
""")
if input("[*] Do you acknowledge and accept this disclaimer? (yes/no): ").strip().lower() != "yes":
    print("Disclaimer not accepted. Exiting.")
    exit(1)


TOR_PROXY = "socks5h://127.0.0.1:9050"
# Log files named by domain/IP and timestamp
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_FILE = f"{DOMAIN.replace('.', '_')}_{timestamp}.log"
SUMMARY_JSON = f"{DOMAIN.replace('.', '_')}_{timestamp}_summary.json"
REPEAT_INTERVAL = 15  # minutes
RUN_FOREVER = False
ENABLE_SQLMAP = True
ENABLE_EXPLOITATION = False
SHODAN_API_KEY = ""    # Optional
ABUSEIPDB_API_KEY = "" # Optional
SECURITYTRAILS_API_KEY = "" # Optional
VT_API_KEY = ""        # Optional

# ─── LOGGING AND TRACKING ───────────────────────────────────────────────────
found_ips = set()
found_issues = defaultdict(list)
reverse_dns = {}
cdn_providers = {}
web_tech_stack = {}
blacklist_flags = {}
honeypot_flags = {}
shodan_info = {}
geoip_info = {}

# ─── UTILITIES ──────────────────────────────────────────────────────────────
def log(msg):
    ts = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    print(f"{ts} {msg}")
    with open(OUTPUT_FILE, "a") as f:
        f.write(f"{ts} {msg}\n")

def log_critical(issue, location):
    found_issues[location].append(issue)
    log(f"[!] CRITICAL: {issue} at {location}")

def run_command(command, log_output=True):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        if log_output and result.stdout:
            log(result.stdout)
        return result.stdout
    except FileNotFoundError:
        log(f"[-] Command not found: {command[0]}")
        return ""
    except subprocess.CalledProcessError as e:
        log(f"[-] Command failed: {e}")
        return ""

# ─── TOR IP ROTATION ────────────────────────────────────────────────────────
def rotate_tor_ip():
    try:
        subprocess.run([
            "sudo", "python3", "-c",
            "from stem import Signal; from stem.control import Controller; "
            "c = Controller.from_port(port=9051); c.authenticate(); "
            "c.signal(Signal.NEWNYM); print('✅ Tor IP rotated.')"
        ], check=True)
    except Exception as e:
        log(f"[-] Failed to rotate Tor IP: {e}")

# ─── TOR IP CHECK ────────────────────────────────────────────────────────────
def get_tor_ip():
    try:
        r = requests.get("https://icanhazip.com", proxies={"http": TOR_PROXY, "https": TOR_PROXY}, timeout=10)
        ip = r.text.strip()
        log(f"[+] Current Tor IP: {ip}")
    except Exception:
        log("[-] Could not fetch current Tor IP.")

# ─── SQLMAP / EXPLOITATION PROMPTS ───────────────────────────────────────────
def sql_prompt_check():
    global ENABLE_SQLMAP, ENABLE_EXPLOITATION
    print("\n[!] Active scanning including optional SQLi and exploitation.")
    print("[!] Permission from target owner is required.")
    if input("[*] Permission for SQL injection tests? (yes/no): ").strip().lower() != "yes":
        ENABLE_SQLMAP = False
        log("[!] SQLi tests skipped.")
    if input("[*] Permission for exploitation tests? (yes/no): ").strip().lower() == "yes":
        ENABLE_EXPLOITATION = True
        log("[+] Exploitation enabled.")
    else:
        log("[!] Exploitation skipped.")

# ─── PASSIVE DNS LOOKUP ──────────────────────────────────────────────────────
def fetch_dns_history():
    # Use root domain for passive DNS history
    log(f"[i] Fetching DNS history for {ROOT_DOMAIN} from HackerTarget...")
    url = f"https://api.hackertarget.com/hostsearch/?q={ROOT_DOMAIN}"
    try:
        r = requests.get(url, proxies={"http": TOR_PROXY, "https": TOR_PROXY}, timeout=15)
        log(r.text)
        for line in r.text.splitlines():
            parts = line.split(',')
            if len(parts) == 2:
                _, ip = parts
                found_ips.add(ip.strip())
    except Exception:
        log("[-] DNS history fetch failed.")

# ─── REVERSE DNS LOOKUP ──────────────────────────────────────────────────────
def reverse_dns_lookup():
    log("[i] Performing reverse DNS lookups...")
    for ip in list(found_ips):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            reverse_dns[ip] = hostname
            log(f"[+] {ip} -> {hostname}")
        except Exception:
            reverse_dns[ip] = None
            log(f"[-] Reverse DNS failed for {ip}")

# ─── GEOIP LOOKUP ────────────────────────────────────────────────────────────
def geoip_lookup():
    log("[i] Performing GeoIP lookups...")
    for ip in list(found_ips):
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp", timeout=10)
            data = r.json()
            geoip_info[ip] = data
            log(f"[+] GeoIP {ip}: {data}")
        except Exception as e:
            log(f"[-] GeoIP error {ip}: {e}")

# ─── SUBDOMAIN SCAN ──────────────────────────────────────────────────────────
def enumerate_subdomains():
    # Enumerate subdomains for the root domain
    log(f"[i] Running amass enum -ip on {ROOT_DOMAIN}...")
    try:
        output = subprocess.check_output(["amass", "enum", "-d", ROOT_DOMAIN, "-ip"], text=True)
        subs = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2 and ('.' in parts[1] or ':' in parts[1]):
                host = parts[0]
                ips = parts[1].split(',')
                subs.append(host)
                for ip in ips:
                    ip = ip.strip()
                    if '/' in ip or not any(c.isdigit() for c in ip):
                        continue
                    found_ips.add(ip)
        log(f"[+] {len(subs)} subdomains enumerated.")
        return subs
    except Exception as e:
        log(f"[-] Amass error: {e}")
        return []

# ─── EXTRA ANALYSIS ─────────────────────────────────────────────────────────
def extra_analysis():
    log("[i] AbuseIPDB & Shodan checks...")
    for ip in list(found_ips):
        if ABUSEIPDB_API_KEY:
            try:
                r = requests.get("https://api.abuseipdb.com/api/v2/check",
                                 params={"ipAddress": ip},
                                 headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"})
                if r.ok:
                    d = r.json()['data']
                    if d['abuseConfidenceScore'] > 0:
                        blacklist_flags[ip] = d
                        log_critical(f"AbuseIPDB {d['abuseConfidenceScore']}%", ip)
            except Exception as e:
                log(f"[-] AbuseIPDB {ip}: {e}")
        if SHODAN_API_KEY:
            try:
                r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}")
                if r.ok:
                    shodan_info[ip] = r.json()
                    log(f"[+] Shodan {ip}: {shodan_info[ip].get('hostnames')}")
            except Exception as e:
                log(f"[-] Shodan {ip}: {e}")

# ─── VULNERABILITY SCANS ────────────────────────────────────────────────────
def scan_host(host):
    log(f"[>] Nmap scan {host}...")
    scripts = "vuln,http-title,ssl-cert" + (",exploit" if ENABLE_EXPLOITATION else "")
    nmap_out = run_command(["nmap", "-Pn", "-p", "1-65535", "--script", scripts, host])
    for line in nmap_out.splitlines():
        if "VULNERABLE" in line.upper():
            log_critical(line.strip(), host)

    log(f"[>] Nikto scan {host}...")
    nikto_out = run_command(["nikto", "-h", f"https://{host}"])
    for line in nikto_out.splitlines():
        if "OSVDB" in line or "+" in line:
            log_critical(line.strip(), host)

    log(f"[>] WhatWeb fingerprint {host}...")
    whatweb_out = run_command(["whatweb", f"https://{host}"])
    web_tech_stack[host] = whatweb_out.strip()
    if "Outdated" in whatweb_out:
        log_critical("Outdated software", host)
    if any(cd in whatweb_out.lower() for cd in ["cloudflare","akamai"]):
        cdn_providers[host] = True
        log(f"[+] CDN detected: {host}")

    log(f"[>] WAFW00F on {host}...")
    run_command(["wafw00f", f"https://{host}"])

    log(f"[>] Dirb brute on {host}...")
    run_command(["dirb", f"https://{host}"])

# ─── SQLMAP SCAN ────────────────────────────────────────────────────────────
def try_sqlmap():
    if not ENABLE_SQLMAP:
        return
    log("[!] SQLMap test on userinfo.php?uid=1...")
    cmd = f"sqlmap -u https://{DOMAIN}/userinfo.php?uid=1 --random-agent --level=5 --risk=3 --tamper=space2comment --text-only --tor --tor-type=SOCKS5 --check-tor"
    out = run_command(shlex.split(cmd))
    for line in out.splitlines():
        if any(x in line.lower() for x in ["is vulnerable","parameter"]):
            log_critical(line.strip(), f"{DOMAIN}/userinfo.php")

# ─── SUMMARY ────────────────────────────────────────────────────────────────
def write_summary():
    log("\n=== SCAN SUMMARY ===")
    log("Unique IPs:")
    for ip in found_ips:
        ptr = reverse_dns.get(ip)
        geo = geoip_info.get(ip)
        log(f" - {ip} PTR: {ptr}, Geo: {geo}")
    log("Critical issues:")
    for t, iss in found_issues.items():
        for i in iss:
            log(f" - {t}: {i}")
    log("CDN hosts:")
    for h in cdn_providers:
        log(f" - {h}")
    log("Technologies:")
    for h, wt in web_tech_stack.items():
        log(f" - {h}: {wt}")
    if blacklist_flags:
        log("Blacklist:")
        for ip, d in blacklist_flags.items():
            log(f" - {ip}: AbuseIPDB {d.get('abuseConfidenceScore')}%")
    log("Report findings to the system owner.")

    summary = {
        "target": DOMAIN,
        "ips": list(found_ips),
        "reverse_dns": reverse_dns,
        "geoip": geoip_info,
        "cdn": list(cdn_providers.keys()),
        "tech": web_tech_stack,
        "issues": dict(found_issues),
        "blacklist": blacklist_flags,
        "shodan": shodan_info,
        "timestamp": datetime.now().isoformat(),
        "note": "Responsible disclosure only."
    }
    with open(SUMMARY_JSON, "w") as f:
        json.dump(summary, f, indent=2)

# ─── MAIN ───────────────────────────────────────────────────────────────────
def run_once():
    rotate_tor_ip()
    get_tor_ip()
    sql_prompt_check()
    fetch_dns_history()
    reverse_dns_lookup()
    geoip_lookup()
    # Enumerate subdomains of the root and always include the target itself
    subs = enumerate_subdomains()
    if DOMAIN not in subs:
        subs.append(DOMAIN)
    if not subs:
        subs = [DOMAIN]
    for h in subs:
        scan_host(h)
    try_sqlmap()
    extra_analysis()
    write_summary()

if __name__ == "__main__":
    log("[~] Starting TOR vulnerability scanner...")
    while True:
        run_once()
        if not RUN_FOREVER:
            break
        log(f"Sleeping {REPEAT_INTERVAL} minutes...")
        time.sleep(REPEAT_INTERVAL * 60)
