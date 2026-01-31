 ## Disclaimer & Intended Use
 
 This project is provided for **educational and defensive purposes only**.
 
 By using this software, you agree that:
 
 - You will **only use it on systems you own or have explicit permission to test**.
 - You will **not use it for unauthorized access, abuse, or malicious activities**.
 - You understand that **you are solely responsible for any actions taken using this software**.
 
 The authors and contributors assume **no liability** for misuse, damage, or legal consequences resulting from the use of this project.
 
 # Defensive Exposure & Protection Validation Framework
 
 A **defensive-only**, **non-exploitative** security validation framework for **authorized testing** of servers and web applications.
 
 This tool answers one core question:
 
 > **“If this system were abused in the real world, would its defensive controls actually stop it?”**
 
 It does **not** exploit systems, inject payloads, extract data, or bypass protections.
 
 Release: **Defensive Validation — CDN-Aware**
 
 ---
 
 ## Authorization Required
 
 This tool **must only be used on systems you own or have explicit permission to test**.
 
 By running this tool, you confirm that:
 
 - You are authorized by the system owner.
 - You accept full responsibility for its use.
 - All findings will be responsibly disclosed and remediated.
 
 ---
 
 ## What This Tool Is
 
 - A **defensive security validation framework**.
 - A way to test **rate limiting, bans, throttling, and protections**.
 - A tool for **hardening systems before public exposure**.
 - Designed to be safe for **production use when used responsibly** (conservative caps, no exploits).
 
 ---
 
 ## What This Tool Is NOT
 
 This tool is **NOT**:
 
 - An exploit framework.
 - A penetration testing toolkit.
 - A payload injection tool.
 - A vulnerability exploitation scanner.
 - A DDoS / flood / stress-testing tool.
 
 There is **no SQL injection, no XSS, no RCE, no fuzzing, and no bypass logic**.
 
 ---
 
 ## What It Does
 
 ### Network & Service Discovery
 
 - Resolves target IP addresses.
 - Scans **all TCP ports (1–65535)** using safe TCP connect scans.
 - Identifies exposed services (web, auth, DB, game/custom, unknown).
 
 ### Web Enumeration
 
 - Safely crawls web pages and endpoints.
 - Discovers forms, APIs, and static assets.
 - Classifies endpoints by cost and risk.
 
 ### Defensive Validation (safe abuse simulation)
 
 Simulates abuse-like patterns **without exploitation**:
 
 - Rate-limited login failures.
 - Increased HTTP request rates.
 - Repeated TCP connections.
 
 **No exploits are performed.**
 
 ---
 
 ## How Findings Work
 
 A finding is marked **CRITICAL** when:
 
 - A publicly exposed service or endpoint receives abuse-like traffic.
 - **No defensive response is observed**.
 
 Defensive responses include:
 
 - HTTP 429 (rate limiting).
 - HTTP 403 (blocking).
 - Connection resets.
 - Throttling.
 - Significant slowdowns.
 
 When escalation is enabled and protections do not trigger, findings may be labeled as:
 
 - **“Abuse path demonstrated safely”**
 
 This indicates that abuse-like pressure was demonstrated without exploitation or harm.
 
 ---
 
 ## Defensive CVSS-Style Scoring
 
 CRITICAL findings receive a **defensive impact score (0.0–10.0)** based on:
 
 - Public exposure.
 - Service criticality.
 - Absence of rate limiting or blocking.
 
 This is **not exploit CVSS** — it measures **defensive failure severity only**.
 
 ---
 
 ## Tor Support (Optional & Safe)
 
 - HTTP/HTTPS traffic can be routed through Tor.
 - Raw TCP scans remain direct.
 - Tor IP rotates **only between phases**.
 - Tor is **never used to bypass bans or blocks**.
 
 Tor usage provides **origin variance**, not evasion.
 
 ---
 
 ## Compliance Mode
 
 Enable ultra-conservative testing (reduced rates/attempts; escalation disabled):
 
 ```bash
 python3 torscan.py example.com --compliance
 ```
 
 ---
 
 ## How to use (fresh system)
 
 ```bash
 git clone https://github.com/yourname/yourrepo.git
 cd yourrepo
 python3 -m venv venv
 source venv/bin/activate
 pip install --upgrade pip
 pip install requests
 
 # Verify the installation
 python3 torscan.py --help
 
 # Run a safe default scan (prints JSON to stdout)
 python3 torscan.py example.com
 
 # Write reports to the current directory
 python3 torscan.py example.com --write-reports
 
 # Dry-run (no network traffic)
 python3 torscan.py example.com --dry-run
 
 # Compliance mode (ultra-conservative; escalation disabled)
 python3 torscan.py example.com --compliance
 ```
 
 ## Outputs
 
 - **JSON (stdout)**: the authoritative report output.
 - **Markdown/HTML (optional)**: `report.md` and `report.html` via `--write-reports`.
 - **Append-only audit log**: `scan.log` by default (configurable via `--log-file`).
 
 The JSON output includes a clear **ports tested** summary and per-port test results.
 
 ## Safety controls and constraints
 
 This repository includes multiple guardrails to keep behavior defensive-only:
 
 - Conservative, explicit rate caps (including compliance mode caps).
 - Runtime aborts if caps would be exceeded.
 - No `Host` header overrides (the tool will abort if attempted).
 - No raw sockets.
 
 ## CDN-aware validation and passive origin discovery
 
 This tool is CDN-aware in a defensive, non-evasive way:
 
 - If a hostname resolves to known CDN IP ranges (for example: Cloudflare, Akamai, Fastly, CloudFront) and no open TCP web ports are observed, the tool will still perform HTTP/HTTPS validation against:
   - `http://<hostname>`
   - `https://<hostname>`
 
 This fallback does not rely on TCP-connect success and is intended to validate defensive controls at the HTTP layer.
 
 For passive origin discovery:
 
 - If DNS resolution returns any non-CDN IPs, those IPs are treated as potential origins and validated defensively.
 - The tool does **not** attempt to bypass CDN protections.
 - The tool does **not** override `Host` headers, and will abort if a Host override is attempted.
 
 ## CI guardrails
 
 This repository includes:
 
 - A GitHub Actions workflow that runs a static safety check and compiles `torscan.py`.
 - A pre-commit configuration that runs the same guardrails locally.
 
 These checks are intended to prevent unsafe changes from being introduced over time.
