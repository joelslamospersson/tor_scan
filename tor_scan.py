#!/usr/bin/env python3
import argparse
import asyncio
import ipaddress
import html
import json
import os
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlparse, urlsplit, urlunsplit

import requests

# --- USER INPUT -------------------------------------------------------------
# --- CONFIG ----------------------------------------------------------------
DEFAULT_USER_AGENT = "DefensiveExposureValidator/1.0"
TOR_SOCKS_PROXY_DEFAULT = "socks5h://127.0.0.1:9050"
TOR_CONTROL_HOST_DEFAULT = "127.0.0.1"
TOR_CONTROL_PORT_DEFAULT = 9051
TOR_ROTATION_COOLDOWN_S_DEFAULT = 12.0

COMPLIANCE_ENDPOINT_RATE_CAPS: Dict[str, Dict[str, float]] = {
    "authentication": {"max_rps": 0.05, "max_attempts": 5},
    "API": {"max_rps": 0.15, "max_attempts": 8},
    "expensive or DB-backed": {"max_rps": 0.05, "max_attempts": 4},
    "public/static": {"max_rps": 0.25, "max_attempts": 8},
}
COMPLIANCE_PORT_RATE_CAPS: Dict[str, Dict[str, float]] = {
    "auth service": {"max_rps": 0.05, "max_attempts": 5},
    "API": {"max_rps": 0.10, "max_attempts": 6},
    "database/cache": {"max_rps": 0.05, "max_attempts": 4},
    "game/custom protocol": {"max_rps": 0.10, "max_attempts": 6},
    "unknown/high-risk": {"max_rps": 0.05, "max_attempts": 4},
}

ENDPOINT_RATE_CAPS: Dict[str, Dict[str, float]] = {
    "authentication": {"max_rps": 0.25, "max_attempts": 15},
    "API": {"max_rps": 0.75, "max_attempts": 25},
    "expensive or DB-backed": {"max_rps": 0.20, "max_attempts": 10},
    "public/static": {"max_rps": 1.50, "max_attempts": 25},
}
PORT_RATE_CAPS: Dict[str, Dict[str, float]] = {
    "auth service": {"max_rps": 0.25, "max_attempts": 15},
    "API": {"max_rps": 0.50, "max_attempts": 20},
    "database/cache": {"max_rps": 0.20, "max_attempts": 10},
    "game/custom protocol": {"max_rps": 0.50, "max_attempts": 20},
    "unknown/high-risk": {"max_rps": 0.20, "max_attempts": 10},
}

# --- LOGGING AND TRACKING ---------------------------------------------------
# --- UTILITIES --------------------------------------------------------------
def log(msg: str) -> None:
    ts = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    print(f"{ts} {msg}")


def _apply_rate_caps(policy: Dict[str, Dict[str, float]], key: str, desired_rps: float, desired_attempts: int) -> Tuple[float, int]:
    caps = policy.get(key)
    if not caps:
        return desired_rps, desired_attempts
    capped_rps = min(desired_rps, float(caps["max_rps"]))
    capped_attempts = min(desired_attempts, int(caps["max_attempts"]))
    return capped_rps, capped_attempts


def _build_http_session(use_tor: bool, tor_proxy_url: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": DEFAULT_USER_AGENT})
    if use_tor:
        s.proxies.update({"http": tor_proxy_url, "https": tor_proxy_url})
    return s


def _tor_control_send(host: str, port: int, lines: List[str], timeout_s: float) -> List[str]:
    out: List[str] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        sock.connect((host, port))
        for line in lines:
            sock.sendall(line.encode("ascii", errors="ignore") + b"\r\n")
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n" in data:
                    break
            out.append(data.decode("utf-8", errors="replace").strip())
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return out


def _tor_rotate_circuit(
    host: str,
    port: int,
    password: Optional[str],
    cooldown_s: float,
    timeout_s: float,
) -> Tuple[bool, List[str]]:
    auth_line = "AUTHENTICATE" if not password else f"AUTHENTICATE \"{password}\""
    lines = [auth_line, "SIGNAL NEWNYM", "QUIT"]
    try:
        responses = _tor_control_send(host, port, lines, timeout_s=timeout_s)
    except OSError as e:
        return False, [str(e)]

    ok = any(r.startswith("250") for r in responses)
    if ok:
        time.sleep(max(0.0, cooldown_s))
    return ok, responses


def _get_tor_exit_ip(session: requests.Session, timeout_s: float) -> Optional[str]:
    try:
        r = session.get("https://icanhazip.com/", timeout=timeout_s, allow_redirects=False)
        if r.ok and r.text:
            return r.text.strip()
    except requests.RequestException:
        return None
    return None


def defensive_score_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def defensive_score_for_finding(finding: Dict[str, Any]) -> Tuple[float, str]:
    exposure_class = str(finding.get("exposure_class") or "").lower()
    endpoint_class = str(finding.get("endpoint_class") or "").lower()

    service_criticality = 1.5
    if exposure_class in {"database/cache"}:
        service_criticality = 3.5
    elif exposure_class in {"auth service"}:
        service_criticality = 3.0
    elif exposure_class in {"api"}:
        service_criticality = 2.5
    elif exposure_class in {"unknown/high-risk"}:
        service_criticality = 3.0
    elif exposure_class in {"game/custom protocol"}:
        service_criticality = 1.8
    elif exposure_class in {"web"}:
        if endpoint_class == "authentication":
            service_criticality = 3.0
        elif endpoint_class == "expensive or db-backed":
            service_criticality = 2.5
        elif endpoint_class == "api":
            service_criticality = 2.5
        else:
            service_criticality = 1.5

    public_exposure = 2.0
    protection_failure = 4.5
    score = min(10.0, public_exposure + service_criticality + protection_failure)
    return round(score, 1), defensive_score_label(score)


def _as_markdown_table(headers: List[str], rows: List[List[str]]) -> str:
    out: List[str] = []
    out.append("| " + " | ".join(headers) + " |")
    out.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for r in rows:
        out.append("| " + " | ".join(r) + " |")
    return "\n".join(out)


def render_markdown_report(report: Dict[str, Any]) -> str:
    ts = str(report.get("timestamp") or "")
    target = str(report.get("target") or "")
    ips = report.get("ips") or []
    tor = report.get("tor") or {}
    caps = report.get("rate_cap_policy") or {}
    findings = report.get("findings") or []
    exposures = report.get("port_exposures") or []

    lines: List[str] = []
    lines.append("# Defensive Exposure & Protection Validation Report")
    lines.append("")
    lines.append(f"**Target:** `{target}`")
    lines.append(f"**Timestamp:** `{ts}`")
    lines.append("")
    lines.append("> Authorized defensive testing only. You must have explicit permission from the system owner.")
    lines.append("")

    lines.append("## Summary")
    lines.append(f"- Target IPs: `{', '.join(ips)}`")
    lines.append(f"- Total exposures: `{len(exposures)}`")
    lines.append(f"- Total findings: `{len(findings)}`")
    lines.append(f"- CRITICAL findings: `{sum(1 for f in findings if f.get('severity') == 'CRITICAL')}`")
    lines.append("")

    lines.append("## Tor usage")
    lines.append(f"- Enabled: `{bool(tor.get('enabled'))}`")
    if tor.get("enabled"):
        lines.append(f"- Proxy: `{tor.get('proxy')}`")
        lines.append(f"- Phase exit IPs: `{tor.get('phase_exit_ip')}`")
        lines.append(f"- Rotation policy: `{tor.get('rotation_policy')}`")
        lines.append(f"- Rotation intent: `{tor.get('rotation_intent')}`")
    lines.append("")

    lines.append("## Rate-cap policy")
    lines.append("```json")
    lines.append(json.dumps(caps, indent=2))
    lines.append("```")
    lines.append("")

    lines.append("## Discovered exposures")
    exp_rows: List[List[str]] = []
    for e in exposures:
        exp_rows.append([
            str(e.get("ip")),
            str(e.get("port")),
            str(e.get("service")),
            str(e.get("exposure_class")),
        ])
    if exp_rows:
        lines.append(_as_markdown_table(["IP", "Port", "Service", "Class"], exp_rows))
    else:
        lines.append("No exposures recorded.")
    lines.append("")

    lines.append("## Findings")
    find_rows: List[List[str]] = []
    for f in findings:
        sev = str(f.get("severity"))
        score = f.get("defensive_score")
        score_label = f.get("defensive_score_label")
        score_s = "" if score is None else f"{score} ({score_label})"
        title = str(f.get("service_or_endpoint"))
        if sev == "CRITICAL":
            title = f"**{title}**"
        find_rows.append([
            sev,
            str(f.get("port")),
            title,
            str(f.get("test_performed")),
            str(f.get("expected_defense")),
            str(f.get("observed_behavior")),
            score_s,
        ])
    if find_rows:
        lines.append(_as_markdown_table(["Severity", "Port", "Service/Endpoint", "Test", "Expected", "Observed", "Score"], find_rows))
    else:
        lines.append("No findings.")
    lines.append("")
    return "\n".join(lines)


def render_html_report(report: Dict[str, Any]) -> str:
    md = render_markdown_report(report)
    return "\n".join(
        [
            "<!doctype html>",
            "<html lang=\"en\">",
            "<head>",
            "  <meta charset=\"utf-8\" />",
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />",
            "  <title>Defensive Exposure & Protection Validation Report</title>",
            "  <style>",
            "    body{font-family:system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin:24px; line-height:1.4}",
            "    pre{background:#f6f8fa; padding:16px; border-radius:8px; overflow:auto}",
            "  </style>",
            "</head>",
            "<body>",
            "<pre>",
            html.escape(md),
            "</pre>",
            "</body>",
            "</html>",
        ]
    )


@dataclass(frozen=True)
class PortExposure:
    ip: str
    port: int
    transport: str
    service: str
    banner: str
    exposure_class: str


@dataclass(frozen=True)
class WebEndpoint:
    base_url: str
    url: str
    endpoint_class: str
    parameters: List[str]


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    return raw.lower()


def derive_root_domain(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def is_ip_literal(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def resolve_ips(domain: str) -> Set[str]:
    ips: Set[str] = set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
            if family == socket.AF_INET:
                ips.add(sockaddr[0])
    except Exception:
        pass
    return ips


def safe_url(base: str, maybe_url: str) -> Optional[str]:
    try:
        u = urljoin(base, maybe_url)
        parsed = urlparse(u)
        if parsed.scheme not in {"http", "https"}:
            return None
        if not parsed.netloc:
            return None
        cleaned = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        return cleaned
    except Exception:
        return None


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: Set[str] = set()

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        for k, v in attrs:
            if not v:
                continue
            if k in {"href", "src", "action"}:
                self.links.add(v)


def classify_port(service: str, banner: str) -> str:
    s = service.lower()
    b = banner.lower()
    if s in {"http", "https"}:
        return "web"
    if s in {"ssh", "rdp", "telnet", "ftp", "imap", "pop3", "smtp"}:
        return "auth service"
    if s in {"redis", "memcached", "mysql", "postgres", "mongodb"}:
        return "database/cache"
    if s in {"http_api", "grpc", "graphql"}:
        return "API"
    if any(x in b for x in ["minecraft", "source engine", "valve", "gamespy"]):
        return "game/custom protocol"
    return "unknown/high-risk"


def _banner_from_bytes(data: bytes) -> str:
    if not data:
        return ""
    try:
        return data[:256].decode("utf-8", errors="replace").strip()
    except Exception:
        return repr(data[:128])


async def _tcp_connect(ip: str, port: int, timeout_s: float) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
    try:
        return await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout_s)
    except Exception:
        return None


async def scan_tcp_ports(ip: str, ports: range, concurrency: int, timeout_s: float) -> List[int]:
    q: asyncio.Queue[Optional[int]] = asyncio.Queue()
    open_ports: List[int] = []

    for p in ports:
        q.put_nowait(p)
    for _ in range(max(1, concurrency)):
        q.put_nowait(None)

    async def _worker() -> None:
        while True:
            p = await q.get()
            if p is None:
                return
            conn = await _tcp_connect(ip, p, timeout_s)
            if conn:
                _reader, writer = conn
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                open_ports.append(p)

    workers = [asyncio.create_task(_worker()) for _ in range(max(1, concurrency))]
    await asyncio.gather(*workers)
    return sorted(open_ports)


async def detect_service(ip: str, port: int, sni_host: Optional[str], timeout_s: float) -> Tuple[str, str]:
    banner = ""
    service = "unknown"

    conn = await _tcp_connect(ip, port, timeout_s)
    if conn:
        reader, writer = conn
        try:
            await asyncio.sleep(0.05)
            data = b""
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=0.15)
            except Exception:
                data = b""

            banner = _banner_from_bytes(data)
            low = banner.lower()

            if low.startswith("ssh-"):
                service = "ssh"
            elif low.startswith("rdp") or "cookie: mstshash" in low:
                service = "rdp"
            elif "smtp" in low and ("esmtp" in low or low.startswith("220")):
                service = "smtp"
            elif "ftp" in low and low.startswith("220"):
                service = "ftp"
            elif "imap" in low and low.startswith("*"):
                service = "imap"
            elif "pop" in low and low.startswith("+"):
                service = "pop3"

            if service == "unknown":
                http_probe = (
                    f"HEAD / HTTP/1.1\r\nHost: {sni_host or ip}\r\nUser-Agent: {DEFAULT_USER_AGENT}\r\nConnection: close\r\n\r\n"
                ).encode("ascii", errors="ignore")
                writer.write(http_probe)
                await writer.drain()
                resp = b""
                try:
                    resp = await asyncio.wait_for(reader.read(512), timeout=0.4)
                except Exception:
                    resp = b""
                resp_s = _banner_from_bytes(resp)
                if resp_s.startswith("HTTP/"):
                    service = "http"
                    banner = resp_s

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    if service != "unknown":
        return service, banner

    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ssl_ctx, server_hostname=sni_host), timeout=timeout_s
        )
        try:
            https_probe = (
                f"HEAD / HTTP/1.1\r\nHost: {sni_host or ip}\r\nUser-Agent: {DEFAULT_USER_AGENT}\r\nConnection: close\r\n\r\n"
            ).encode("ascii", errors="ignore")
            writer.write(https_probe)
            await writer.drain()
            resp = b""
            try:
                resp = await asyncio.wait_for(reader.read(512), timeout=0.6)
            except Exception:
                resp = b""
            resp_s = _banner_from_bytes(resp)
            if resp_s.startswith("HTTP/"):
                return "https", resp_s
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        pass

    return "unknown", banner


async def discover_port_exposures(
    ip: str,
    sni_host: Optional[str],
    port_concurrency: int,
    port_timeout_s: float,
    service_concurrency: int,
    service_timeout_s: float,
) -> List[PortExposure]:
    open_ports = await scan_tcp_ports(ip, range(1, 65536), port_concurrency, port_timeout_s)
    sem = asyncio.Semaphore(max(1, service_concurrency))
    out: List[PortExposure] = []

    async def _detect(p: int) -> None:
        async with sem:
            service, banner = await detect_service(ip, p, sni_host, service_timeout_s)
            out.append(
                PortExposure(
                    ip=ip,
                    port=p,
                    transport="tcp",
                    service=service,
                    banner=banner,
                    exposure_class=classify_port(service, banner),
                )
            )

    await asyncio.gather(*[asyncio.create_task(_detect(p)) for p in open_ports])
    return sorted(out, key=lambda e: e.port)


def validate_port_protection(
    ip: str,
    port: int,
    attempts: int,
    rps: float,
    timeout_s: float,
    dry_run: bool,
    stop_on_trigger: bool,
) -> Dict[str, Any]:
    errors: List[str] = []
    elapsed: List[float] = []

    if dry_run:
        return {
            "attempts": attempts,
            "observed_errors": [],
            "defense_triggered": False,
            "defense_summary": "dry-run",
        }

    delay_s = 1.0 / max(0.1, rps)
    for _ in range(attempts):
        start = time.monotonic()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        try:
            s.connect((ip, port))
            errors.append("")
        except OSError as e:
            errors.append(str(e))
        finally:
            try:
                s.close()
            except Exception:
                pass
        elapsed.append(max(0.0, time.monotonic() - start))

        triggered, summary = observed_defense([], errors, elapsed)
        if triggered:
            return {
                "attempts": len(elapsed),
                "observed_errors": [e for e in errors if e],
                "defense_triggered": True,
                "defense_summary": summary,
            }
        time.sleep(delay_s)

    triggered, summary = observed_defense([], errors, elapsed)
    return {
        "attempts": attempts,
        "observed_errors": [e for e in errors if e],
        "defense_triggered": triggered,
        "defense_summary": summary,
    }


def classify_endpoint(url: str, response: Optional[requests.Response], elapsed_s: Optional[float]) -> str:
    path = urlsplit(url).path.lower()
    if any(x in path for x in ["/login", "/signin", "/sign-in", "/auth", "/oauth", "/account", "/session"]):
        return "authentication"
    if path.startswith("/api") or any(x in path for x in ["/graphql", "/v1/", "/v2/"]):
        return "API"
    if any(path.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2"]):
        return "public/static"

    if any(x in path for x in ["/search", "/query", "/report", "/export", "/download", "/admin"]):
        return "expensive or DB-backed"

    if response is not None:
        ctype = (response.headers.get("content-type") or "").lower()
        if "application/json" in ctype:
            return "API"
    if elapsed_s is not None and elapsed_s >= 2.0:
        return "expensive or DB-backed"
    return "public/static"


def observed_defense(http_statuses: List[Optional[int]], errors: List[str], elapsed_s: List[float]) -> Tuple[bool, str]:
    if any(s in {403, 429} for s in http_statuses if s is not None):
        return True, "HTTP 403/429 observed"
    if any("timeout" in e.lower() or "reset" in e.lower() or "refused" in e.lower() for e in errors):
        return True, "connection throttling or disconnect observed"
    if len(elapsed_s) >= 6:
        base = sum(elapsed_s[:3]) / 3
        tail = sum(elapsed_s[-3:]) / 3
        if base > 0 and tail >= (base * 2.5):
            return True, "significant slowdown observed"
    return False, "no defensive response detected"


def validate_defense(
    session: requests.Session,
    url: str,
    method: str,
    headers: Dict[str, str],
    data: Optional[Dict[str, str]],
    attempts: int,
    rps: float,
    timeout_s: float,
    dry_run: bool,
    stop_on_trigger: bool,
) -> Dict[str, Any]:
    statuses: List[Optional[int]] = []
    errors: List[str] = []
    elapsed: List[float] = []

    if dry_run:
        return {
            "attempts": attempts,
            "observed_statuses": [],
            "observed_errors": [],
            "defense_triggered": False,
            "defense_summary": "dry-run",
        }

    delay_s = 1.0 / max(0.1, rps)
    for _ in range(attempts):
        start = time.monotonic()
        try:
            resp = session.request(method, url, headers=headers, data=data, timeout=timeout_s, allow_redirects=False)
            statuses.append(resp.status_code)
            errors.append("")
        except requests.RequestException as e:
            statuses.append(None)
            errors.append(str(e))
        elapsed.append(max(0.0, time.monotonic() - start))

        triggered, _summary = observed_defense(statuses, errors, elapsed)
        if triggered:
            break
        time.sleep(delay_s)

    triggered, summary = observed_defense(statuses, errors, elapsed)
    return {
        "attempts": len(elapsed),
        "observed_statuses": [s for s in statuses if s is not None],
        "observed_errors": [e for e in errors if e],
        "defense_triggered": triggered,
        "defense_summary": summary,
    }


# --- MAIN -------------------------------------------------------------------
def run_once():
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Defensive Exposure & Protection Validation Framework")
    parser.add_argument("target", help="Domain or IPv4 address")
    parser.add_argument("--dry-run", action="store_true", help="Plan actions without sending network traffic")
    parser.add_argument("--compliance", action="store_true", help="Ultra-conservative mode (reduced rates/attempts; escalation disabled unless explicitly enabled)")
    parser.add_argument("--escalate", choices=["yes", "no"], default=None, help="Enable safe escalation validation")
    parser.add_argument("--stop-on-trigger", action="store_true", help="Stop the escalation phase when a defensive response is observed")
    parser.add_argument("--write-reports", action="store_true", help="Write report.md and report.html to the current directory")
    parser.add_argument("--port-concurrency", type=int, default=300)
    parser.add_argument("--port-timeout", type=float, default=0.35)
    parser.add_argument("--service-timeout", type=float, default=1.2)
    parser.add_argument("--web-timeout", type=float, default=10.0)
    parser.add_argument("--web-max-pages", type=int, default=60)
    parser.add_argument("--rate", type=float, default=1.0, help="Default requests per second during validation")
    parser.add_argument("--tor", action="store_true", help="Route HTTP/HTTPS traffic through Tor SOCKS proxy")
    parser.add_argument("--tor-proxy", default=TOR_SOCKS_PROXY_DEFAULT)
    parser.add_argument("--tor-control-host", default=TOR_CONTROL_HOST_DEFAULT)
    parser.add_argument("--tor-control-port", type=int, default=TOR_CONTROL_PORT_DEFAULT)
    parser.add_argument("--tor-control-password", default=os.environ.get("TOR_CONTROL_PASSWORD"))
    parser.add_argument("--tor-rotation-cooldown", type=float, default=TOR_ROTATION_COOLDOWN_S_DEFAULT)
    parser.add_argument("--tor-timeout", type=float, default=15.0)
    args = parser.parse_args()

    target = normalize_target(args.target)
    root_domain = derive_root_domain(target)

    print(
        """
[!] AUTHORIZED DEFENSIVE TESTING ONLY
This tool enumerates exposed services and validates whether defensive controls activate under safe, HTTP-compliant escalation.
You must have explicit permission from the system owner.
""".strip()
    )
    if input("[*] Do you acknowledge and accept this authorization requirement? (yes/no): ").strip().lower() != "yes":
        print("Authorization not accepted. Exiting.")
        raise SystemExit(1)

    if args.escalate is None:
        if args.compliance:
            escalation_enabled = False
        else:
            escalation_answer = input("[*] Enable escalation validation (safe) to check protections? (yes/no): ").strip().lower()
            escalation_enabled = escalation_answer == "yes"
    else:
        escalation_enabled = args.escalate == "yes"

    if args.compliance and args.escalate != "yes":
        escalation_enabled = False

    endpoint_caps = COMPLIANCE_ENDPOINT_RATE_CAPS if args.compliance else ENDPOINT_RATE_CAPS
    port_caps = COMPLIANCE_PORT_RATE_CAPS if args.compliance else PORT_RATE_CAPS

    session = _build_http_session(use_tor=args.tor, tor_proxy_url=args.tor_proxy)
    tor_phase_exit_ip: Dict[str, Optional[str]] = {"discovery": None, "validation": None, "escalation": None}
    tor_rotation_events: List[Dict[str, Any]] = []

    if args.tor and not args.dry_run:
        exit_ip = _get_tor_exit_ip(session, timeout_s=args.tor_timeout)
        tor_phase_exit_ip["discovery"] = exit_ip
        if exit_ip:
            log(f"[tor] Using Tor proxy {args.tor_proxy} exit_ip={exit_ip} (HTTP/HTTPS only)")
        else:
            log("[tor] Tor requested but exit IP could not be verified. Ensure Tor is running and requests has SOCKS support.")
            raise SystemExit(3)

    ips: Set[str] = set()
    if is_ip_literal(target):
        ips.add(target)
    else:
        ips |= resolve_ips(target)
    if not ips:
        log("[-] Could not resolve any IPv4 addresses for target.")
        raise SystemExit(2)

    log(f"[i] Discovered IPs: {', '.join(sorted(ips))}")

    exposures: List[PortExposure] = []
    endpoints: List[WebEndpoint] = []
    findings: List[Dict[str, Any]] = []

    protection_triggered_global = False

    log("[phase] discovery")
    for ip in sorted(ips):
        log(f"[i] Scanning TCP ports 1-65535 on {ip} (connect scan)")
        if args.dry_run:
            continue
        ip_exposures = asyncio.run(
            discover_port_exposures(
                ip=ip,
                sni_host=target if not is_ip_literal(target) else None,
                port_concurrency=args.port_concurrency,
                port_timeout_s=args.port_timeout,
                service_concurrency=min(300, max(1, args.port_concurrency // 2)),
                service_timeout_s=args.service_timeout,
            )
        )
        exposures.extend(ip_exposures)
        log(f"[+] Open TCP ports on {ip}: {len(ip_exposures)}")

    if args.tor and not args.dry_run:
        ok, resp = _tor_rotate_circuit(
            host=args.tor_control_host,
            port=args.tor_control_port,
            password=args.tor_control_password,
            cooldown_s=args.tor_rotation_cooldown,
            timeout_s=args.tor_timeout,
        )
        exit_ip = _get_tor_exit_ip(session, timeout_s=args.tor_timeout)
        tor_phase_exit_ip["validation"] = exit_ip
        tor_rotation_events.append(
            {
                "from_phase": "discovery",
                "to_phase": "validation",
                "rotation_attempted": True,
                "rotation_ok": ok,
                "control_responses": resp,
                "exit_ip": exit_ip,
            }
        )
        log(f"[tor] Phase-boundary rotation: discovery->validation ok={ok} exit_ip={exit_ip}")

    log("[phase] classification")
    if args.dry_run:
        log("[i] Dry-run enabled: skipping active port scanning and web enumeration.")

    web_exposures = [e for e in exposures if e.exposure_class == "web"]
    base_url_ports: Dict[str, int] = {}
    log("[phase] validation")
    for e in web_exposures:
        scheme = "https" if e.service == "https" else "http"
        base_url = f"{scheme}://{target}:{e.port}" if (scheme == "http" and e.port != 80) or (scheme == "https" and e.port != 443) else f"{scheme}://{target}"
        base_url_ports[base_url] = e.port
        start_url = f"{base_url}/"

        log(f"[i] Web enumeration: {start_url}")
        if args.dry_run:
            discovered_urls = [start_url]
        else:
            discovered_urls = []
            queue: List[str] = [start_url]
            seen: Set[str] = set()

            while queue and len(discovered_urls) < args.web_max_pages:
                u = queue.pop(0)
                if u in seen:
                    continue
                seen.add(u)
                try:
                    t0 = time.monotonic()
                    resp = session.get(u, timeout=args.web_timeout, allow_redirects=False)
                    dt = time.monotonic() - t0
                    discovered_urls.append(u)

                    if resp.status_code in {403, 429}:
                        protection_triggered_global = True
                        if args.stop_on_trigger:
                            break

                    params = [k for k, _v in parse_qsl(urlsplit(u).query, keep_blank_values=True)]
                    eclass = classify_endpoint(u, resp, dt)
                    endpoints.append(WebEndpoint(base_url=base_url, url=u, endpoint_class=eclass, parameters=params))

                    ctype = (resp.headers.get("content-type") or "").lower()
                    if "text/html" in ctype and resp.text:
                        parser2 = _LinkExtractor()
                        try:
                            parser2.feed(resp.text)
                        except Exception:
                            pass
                        for link in list(parser2.links)[:200]:
                            su = safe_url(base_url, link)
                            if not su:
                                continue
                            if urlparse(su).netloc != urlparse(base_url).netloc:
                                continue
                            queue.append(su)

                except requests.RequestException:
                    discovered_urls.append(u)

                if protection_triggered_global and args.stop_on_trigger:
                    break

            for extra in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]:
                u = safe_url(base_url, extra)
                if u and u not in seen and len(discovered_urls) < args.web_max_pages:
                    if not (protection_triggered_global and args.stop_on_trigger):
                        discovered_urls.append(u)
                        params = [k for k, _v in parse_qsl(urlsplit(u).query, keep_blank_values=True)]
                        endpoints.append(
                            WebEndpoint(base_url=base_url, url=u, endpoint_class=classify_endpoint(u, None, None), parameters=params)
                        )

        if protection_triggered_global and args.stop_on_trigger:
            break

    if escalation_enabled:
        if args.tor and not args.dry_run and not protection_triggered_global:
            ok, resp = _tor_rotate_circuit(
                host=args.tor_control_host,
                port=args.tor_control_port,
                password=args.tor_control_password,
                cooldown_s=args.tor_rotation_cooldown,
                timeout_s=args.tor_timeout,
            )
            exit_ip = _get_tor_exit_ip(session, timeout_s=args.tor_timeout)
            tor_phase_exit_ip["escalation"] = exit_ip
            tor_rotation_events.append(
                {
                    "from_phase": "validation",
                    "to_phase": "escalation",
                    "rotation_attempted": True,
                    "rotation_ok": ok,
                    "control_responses": resp,
                    "exit_ip": exit_ip,
                }
            )
            log(f"[tor] Phase-boundary rotation: validation->escalation ok={ok} exit_ip={exit_ip}")
        elif args.tor and not args.dry_run and protection_triggered_global:
            tor_rotation_events.append(
                {
                    "from_phase": "validation",
                    "to_phase": "escalation",
                    "rotation_attempted": False,
                    "rotation_ok": False,
                    "control_responses": [],
                    "exit_ip": tor_phase_exit_ip.get("validation"),
                    "note": "rotation skipped because protective controls were observed during validation",
                }
            )

        log("[phase] escalation")
        for ep in endpoints:
            expected = "rate limiting (HTTP 429), blocking (HTTP 403), or throttling"
            port_for_ep = base_url_ports.get(ep.base_url)
            if port_for_ep is None:
                continue

            if ep.endpoint_class == "authentication":
                test = "repeated invalid credentials"
                form_data = {"username": "invalid", "password": "invalid"}
                desired_rps = max(0.2, args.rate)
                desired_attempts = 30
                eff_rps, eff_attempts = _apply_rate_caps(endpoint_caps, ep.endpoint_class, desired_rps, desired_attempts)
                result = validate_defense(
                    session=session,
                    url=ep.url,
                    method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data=form_data,
                    attempts=eff_attempts,
                    rps=eff_rps,
                    timeout_s=args.web_timeout,
                    dry_run=args.dry_run,
                    stop_on_trigger=args.stop_on_trigger,
                )
            else:
                test = "increased request rate"
                desired_rps = max(0.5, args.rate)
                desired_attempts = 25
                eff_rps, eff_attempts = _apply_rate_caps(endpoint_caps, ep.endpoint_class, desired_rps, desired_attempts)
                result = validate_defense(
                    session=session,
                    url=ep.url,
                    method="GET",
                    headers={},
                    data=None,
                    attempts=eff_attempts,
                    rps=eff_rps,
                    timeout_s=args.web_timeout,
                    dry_run=args.dry_run,
                    stop_on_trigger=args.stop_on_trigger,
                )

            if (not args.dry_run) and (not result["defense_triggered"]):
                severity = "CRITICAL"
                observed = result["defense_summary"]
            else:
                severity = "INFO" if args.dry_run else "WARN"
                observed = result["defense_summary"]

            findings.append(
                {
                    "service_or_endpoint": ep.url,
                    "port": port_for_ep,
                    "exposure_class": "web",
                    "endpoint_class": ep.endpoint_class,
                    "test_performed": test,
                    "expected_defense": expected,
                    "observed_behavior": observed,
                    "severity": severity,
                    "effective_rps": eff_rps if not args.dry_run else None,
                    "effective_attempts": result.get("attempts"),
                }
            )

            if (not args.dry_run) and result.get("defense_triggered"):
                protection_triggered_global = True
                if args.stop_on_trigger:
                    break

    if escalation_enabled and (not protection_triggered_global or not args.stop_on_trigger):
        for e in [x for x in exposures if x.exposure_class != "web"]:
            expected = "connection throttling, temporary blocks, or forced disconnects"
            desired_rps = max(0.5, args.rate)
            desired_attempts = 30
            eff_rps, eff_attempts = _apply_rate_caps(port_caps, e.exposure_class, desired_rps, desired_attempts)
            result = validate_port_protection(
                ip=e.ip,
                port=e.port,
                attempts=eff_attempts,
                rps=eff_rps,
                timeout_s=max(0.2, args.port_timeout),
                dry_run=args.dry_run,
                stop_on_trigger=args.stop_on_trigger,
            )
            if (not args.dry_run) and (not result["defense_triggered"]):
                severity = "CRITICAL"
                observed = result["defense_summary"]
            else:
                severity = "INFO" if args.dry_run else "WARN"
                observed = result["defense_summary"]

            findings.append(
                {
                    "service_or_endpoint": f"{e.ip}:{e.port} ({e.service})",
                    "port": e.port,
                    "exposure_class": e.exposure_class,
                    "endpoint_class": None,
                    "test_performed": "repeated TCP connections",
                    "expected_defense": expected,
                    "observed_behavior": observed,
                    "severity": severity,
                    "effective_rps": eff_rps if not args.dry_run else None,
                    "effective_attempts": result.get("attempts"),
                }
            )

            if (not args.dry_run) and result.get("defense_triggered"):
                protection_triggered_global = True
                if args.stop_on_trigger:
                    break

    for f in findings:
        if f.get("severity") == "CRITICAL":
            score, score_label = defensive_score_for_finding(f)
            f["defensive_score"] = score
            f["defensive_score_label"] = score_label
        else:
            f["defensive_score"] = None
            f["defensive_score_label"] = None

    if findings:
        log("\n=== FINDINGS ===")
        for f in findings:
            log(
                f"{f['severity']}: {f['service_or_endpoint']} (port {f['port']}) | test={f['test_performed']} | expected={f['expected_defense']} | observed={f['observed_behavior']}"
            )

    recovery_helpers = {
        "cooldown": "If you triggered temporary blocks, wait for the cooldown window to expire (often 5-60 minutes) before re-testing.",
        "fail2ban": "If using fail2ban on your own infrastructure: check bans with 'sudo fail2ban-client status' and unban with 'sudo fail2ban-client set <jail> unbanip <your_ip>'.",
        "firewall": "If you blocked yourself via a firewall rule on your own infrastructure, review recent rules and remove only the specific rule you added; avoid flushing tables.",
    }

    output = {
        "target": target,
        "root_domain": root_domain,
        "ips": sorted(ips),
        "tor": {
            "enabled": bool(args.tor),
            "proxy": args.tor_proxy if args.tor else None,
            "applies_to": "HTTP/HTTPS only (requests.Session)",
            "does_not_apply_to": "raw TCP connect scanning",
            "rotation_policy": "phase-boundary-only (discovery -> validation -> escalation)",
            "rotation_intent": "origin variance only (not used to circumvent protections)",
            "phase_exit_ip": tor_phase_exit_ip,
            "rotation_events": tor_rotation_events,
        },
        "rate_cap_policy": {
            "compliance": bool(args.compliance),
            "endpoint_caps": endpoint_caps,
            "port_caps": port_caps,
            "note": "Caps are conservative maximums and override higher user-provided rates/attempts.",
        },
        "port_exposures": [
            {
                "ip": e.ip,
                "port": e.port,
                "transport": e.transport,
                "service": e.service,
                "exposure_class": e.exposure_class,
                "banner": e.banner,
            }
            for e in exposures
        ],
        "web_endpoints": [
            {
                "base_url": ep.base_url,
                "url": ep.url,
                "endpoint_class": ep.endpoint_class,
                "parameters": ep.parameters,
            }
            for ep in endpoints
        ],
        "findings": findings,
        "escalation_enabled": escalation_enabled,
        "dry_run": args.dry_run,
        "timestamp": datetime.now().isoformat(),
        "recovery_helpers": recovery_helpers,
    }

    log("\n=== JSON OUTPUT ===")
    print(json.dumps(output, indent=2))

    if args.write_reports:
        md = render_markdown_report(output)
        html_doc = render_html_report(output)
        with open("report.md", "w", encoding="utf-8") as f:
            f.write(md)
        with open("report.html", "w", encoding="utf-8") as f:
            f.write(html_doc)
        log("[i] Wrote report.md and report.html")
