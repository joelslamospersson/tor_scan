# Defensive Exposure & Protection Validation Framework

A **defensive-only**, **non-exploitative** security validation framework for **authorized testing** of servers and web applications.

This tool answers one core question:

> **“If this system were abused in the real world, would its defensive controls actually stop it?”**

It does **not** exploit systems, inject payloads, extract data, or bypass protections.

---

## 🚨 Authorization Required

This tool **must only be used on systems you own or have explicit permission to test**.

By running this tool, you confirm that:
- You are authorized by the system owner
- You accept full responsibility for its use
- All findings will be responsibly disclosed and remediated

---

## 🎯 What This Tool Is

✔ A **defensive security validation framework**  
✔ A way to test **rate limiting, bans, throttling, and protections**  
✔ A tool for **hardening systems before public exposure**  
✔ Safe for **production use when used responsibly**

---

## ❌ What This Tool Is NOT

This tool is **NOT**:

- ❌ An exploit framework  
- ❌ A penetration testing toolkit  
- ❌ A payload injection tool  
- ❌ A vulnerability exploitation scanner  
- ❌ A DDoS / flood / stress-testing tool  

There is **no SQL injection, no XSS, no RCE, no fuzzing, and no bypass logic**.

---

## 🔍 What It Does

### Network & Service Discovery
- Resolves target IP addresses
- Scans **all TCP ports (1–65535)** using safe TCP connect scans
- Identifies exposed services:
  - web
  - authentication services
  - databases / caches
  - game / custom protocols
  - unknown / high-risk services

### Web Enumeration
- Safely crawls web pages and endpoints
- Discovers forms, APIs, static assets
- Classifies endpoints as:
  - authentication
  - API
  - expensive / DB-backed
  - public / static

### Defensive Validation (“Safe Attacks”)
When escalation is enabled, the tool simulates **realistic abuse patterns**:

- Repeated invalid login attempts (rate-limited)
- Increased HTTP request rates (RFC-compliant)
- Repeated TCP connections on exposed ports

⚠️ **No exploits are performed.**

---

## 🧠 How Findings Work

A finding is marked **CRITICAL** when:

> A publicly exposed service or endpoint  
> receives abuse-like traffic  
> **and no defensive response is observed**

Defensive responses include:
- HTTP 429 (rate limiting)
- HTTP 403 (blocking)
- connection resets
- throttling
- significant slowdowns

If no defense activates → **CRITICAL**, because a real attacker could abuse it.

---

## 🧮 Defensive CVSS-Style Scoring

CRITICAL findings receive a **defensive impact score** (0.0–10.0) based on:
- Public exposure
- Service criticality (auth, API, DB, etc.)
- Absence of rate limiting or blocking

⚠️ This is **not exploit CVSS** — it measures **defensive failure severity only**.

---

## 🧅 Tor Support (Optional & Safe)

- HTTP/HTTPS traffic can be routed through Tor
- Raw TCP scans remain direct (for accuracy)
- Tor IP rotates **only between phases**
- Tor is **never used to bypass blocks or bans**
- Exit IPs are logged per phase

Tor usage provides **origin variance**, not evasion.

---

## 🛡️ Compliance Mode

Enable ultra-conservative testing:

```bash
--compliance
