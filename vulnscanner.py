#!/usr/bin/env python3
"""
=============================================================================
 VulnScanner - A Lightweight Vulnerability Scanner
=============================================================================
 Author  : Muhammad Hamza Khan
 Type    : Personal cybersecurity project (self-directed / hands-on practice)
 License : For educational and authorised testing use only.

 A single-file network vulnerability scanner written in pure Python.
 No external dependencies. Scans ports, fingerprints services, checks
 for known weaknesses, and produces reports in four formats.

 Usage:
   python vulnscanner.py -t 192.168.1.1 -p 22,80,443 --web --ssl
   python vulnscanner.py -t example.com --full -o report.html
   python vulnscanner.py -t 10.0.0.5 -p 1-1024 -y

 WARNING: Only scan systems you own or have explicit written permission
          to test. Unauthorised scanning is illegal in most countries.
=============================================================================
"""

import argparse
import concurrent.futures
import csv
import html
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable
from urllib.parse import urlparse


# =============================================================================
# SECTION 1 : Configuration & Constants
# =============================================================================

VERSION = "1.0.0"
USER_AGENT = "VulnScanner/1.0"

TOP_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 81, 110, 111, 113, 119, 123, 135,
    137, 138, 139, 143, 161, 162, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993,
    995, 1025, 1026, 1027, 1028, 1029, 1080, 1433, 1434, 1521, 1701, 1723,
    1755, 1812, 1900, 2000, 2049, 2121, 2222, 2375, 2376, 2483, 3000, 3128,
    3260, 3306, 3389, 4443, 4444, 5000, 5060, 5222, 5357, 5432, 5555, 5601,
    5632, 5900, 5984, 6000, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8088,
    8443, 8888, 9000, 9090, 9200, 9443, 10000, 11211, 27017, 27018,
]

PORT_SERVICE_MAP = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 69: "tftp", 80: "http", 110: "pop3",
    111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 514: "shell", 548: "afp",
    554: "rtsp", 587: "smtp", 631: "ipp", 636: "ldaps", 873: "rsync",
    990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    2121: "ftp", 2181: "zookeeper", 2222: "ssh", 2375: "docker",
    2376: "docker", 3000: "http", 3306: "mysql", 3389: "rdp",
    4444: "unknown", 5000: "http", 5060: "sip", 5432: "postgresql",
    5555: "adb", 5601: "kibana", 5632: "pcanywhere", 5900: "vnc",
    5984: "couchdb", 6379: "redis", 6443: "kubernetes", 7001: "weblogic",
    8000: "http", 8008: "http", 8080: "http", 8081: "http",
    8088: "http", 8443: "https", 8888: "http", 9000: "http",
    9090: "http", 9200: "elasticsearch", 9300: "elasticsearch",
    9443: "https", 10000: "webmin", 11211: "memcached",
    27017: "mongodb", 27018: "mongodb",
}

HTTP_PORTS = {80, 81, 3000, 5000, 5601, 7001, 8000, 8008, 8080,
              8081, 8088, 8888, 9000, 9090, 9200, 10000}
TLS_PORTS  = {443, 465, 636, 990, 993, 995, 2376, 5986, 8443, 9443}


# =============================================================================
# SECTION 2 : Embedded Vulnerability Database
# =============================================================================

VULN_DB = {
    "service_rules": {
        "ssh": [
            {
                "id": "VS-SSH-001", "title": "Outdated OpenSSH version",
                "severity": "HIGH", "pattern": r"OpenSSH_[0-7]\.",
                "cvss": 7.5,
                "description": "OpenSSH 7.x and earlier contain multiple publicly disclosed flaws including user enumeration (CVE-2018-15473).",
                "remediation": "Upgrade OpenSSH to the latest stable release.",
                "references": ["https://www.openssh.com/security.html"],
            },
            {
                "id": "VS-SSH-002", "title": "SSH protocol v1 supported",
                "severity": "CRITICAL", "pattern": r"SSH-1\.",
                "cvss": 9.0,
                "description": "SSH protocol version 1 is cryptographically broken and vulnerable to MITM attacks.",
                "remediation": "Force SSH protocol 2 only (Protocol 2 in sshd_config).",
                "references": [],
            },
        ],
        "ftp": [
            {
                "id": "VS-FTP-001", "title": "Outdated vsftpd version",
                "severity": "HIGH", "pattern": r"vsFTPd_[12]\.",
                "cvss": 8.1,
                "description": "vsftpd 2.x contains a well-known backdoor (CVE-2011-2523) that opens a root shell on port 6200.",
                "remediation": "Upgrade to the latest vsftpd and audit the host for compromise.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
            },
        ],
        "smtp": [
            {
                "id": "VS-SMTP-001", "title": "Exim likely vulnerable (CVE-2019-10149)",
                "severity": "CRITICAL", "pattern": r"Exim 4\.(8[0-9]|9[0-1])",
                "cvss": 9.8,
                "description": "Exim 4.87-4.91 allow remote command execution via the deliver_message() function.",
                "remediation": "Upgrade Exim to 4.92 or later immediately.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-10149"],
            },
        ],
        "http": [
            {
                "id": "VS-HTTP-001", "title": "Outdated Apache HTTP Server",
                "severity": "HIGH", "pattern": r"Apache/2\.[0-2]\.",
                "cvss": 7.5,
                "description": "Apache 2.0-2.2 branches are end-of-life and receive no security updates.",
                "remediation": "Upgrade to a supported Apache 2.4.x release.",
                "references": [],
            },
            {
                "id": "VS-HTTP-002", "title": "Outdated nginx version",
                "severity": "MEDIUM", "pattern": r"nginx/1\.(1[0-7]|0)\.",
                "cvss": 6.1,
                "description": "The nginx version in use predates several security fixes in the 1.18+ branches.",
                "remediation": "Upgrade nginx to the latest stable release.",
                "references": [],
            },
            {
                "id": "VS-HTTP-003", "title": "Outdated PHP runtime",
                "severity": "HIGH", "pattern": r"PHP/5\.|PHP/7\.[0-3]\.",
                "cvss": 7.3,
                "description": "End-of-life PHP versions no longer receive security patches.",
                "remediation": "Upgrade to PHP 8.1 or newer.",
                "references": [],
            },
        ],
        "mysql": [
            {
                "id": "VS-MYSQL-001", "title": "Legacy MySQL / MariaDB version",
                "severity": "HIGH", "pattern": r"5\.[0-6]\.[0-9]+",
                "cvss": 7.5,
                "description": "MySQL 5.x is end-of-life. Multiple privilege-escalation and RCE flaws exist in this branch.",
                "remediation": "Upgrade to MySQL 8.x or a supported MariaDB 10.x.",
                "references": [],
            },
        ],
        "redis": [
            {
                "id": "VS-REDIS-001", "title": "Redis responds to unauthenticated PING",
                "severity": "CRITICAL", "pattern": r"\+PONG",
                "cvss": 9.8,
                "description": "Unauthenticated Redis allows arbitrary key access and often leads to RCE via crafted RDB files.",
                "remediation": "Enable requirepass, bind to a private interface, keep protected-mode on.",
                "references": [],
            },
        ],
    },

    "port_rules": [
        {
            "id": "VS-PORT-001", "port": 23, "title": "Telnet service exposed",
            "severity": "HIGH", "cvss": 7.5,
            "description": "Telnet transmits credentials in cleartext and can be trivially intercepted.",
            "remediation": "Disable Telnet. Migrate to SSH.",
            "references": [],
        },
        {
            "id": "VS-PORT-002", "port": 445, "title": "SMB service exposed",
            "severity": "HIGH", "cvss": 8.1,
            "description": "SMB reachable from untrusted networks is a top ransomware vector (WannaCry, NotPetya).",
            "remediation": "Block TCP/445 at the perimeter. Disable SMBv1 internally.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
        },
        {
            "id": "VS-PORT-003", "port": 3389, "title": "RDP service exposed",
            "severity": "HIGH", "cvss": 8.1,
            "description": "Internet-facing RDP is a primary ransomware entry point.",
            "remediation": "Place RDP behind a VPN, enable NLA and MFA.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
        },
        {
            "id": "VS-PORT-004", "port": 2375,
            "title": "Unauthenticated Docker API exposed",
            "severity": "CRITICAL", "cvss": 9.8,
            "description": "Anyone who can reach this port can start privileged containers and gain root on the host.",
            "remediation": "Disable the Docker TCP socket or protect it with TLS client certs.",
            "references": [],
        },
        {
            "id": "VS-PORT-005", "port": 11211, "title": "Memcached exposed",
            "severity": "HIGH", "cvss": 7.5,
            "description": "Open memcached instances can be abused for data theft and UDP amplification DDoS.",
            "remediation": "Bind to localhost and disable UDP.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-1000115"],
        },
    ],
}


# =============================================================================
# SECTION 3 : Data Models
# =============================================================================

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def rank(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2,
                "HIGH": 3, "CRITICAL": 4}[self.value]

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        try:
            return cls(str(value).strip().upper())
        except ValueError:
            return cls.INFO


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    description: str
    target: str
    port: int = 0
    service: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list = field(default_factory=list)
    cvss: float = 0.0
    category: str = "general"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ServiceInfo:
    port: int
    service: str = "unknown"
    banner: str = ""
    signature: str = ""
    is_http: bool = False
    is_tls: bool = False


# =============================================================================
# SECTION 4 : Target Validation & Port Parsing
# =============================================================================

class ValidationError(ValueError):
    """Raised when user input is malformed."""


HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_hostname(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    return bool(HOSTNAME_RE.match(value.rstrip(".")))


def normalise_target(target: str) -> str:
    if not target or not target.strip():
        raise ValidationError("Target must not be empty.")
    target = target.strip()

    if "://" in target:
        host = urlparse(target).hostname
        if not host:
            raise ValidationError(f"Could not extract hostname from '{target}'.")
        return host

    if target.count(":") == 1 and not is_valid_ip(target):
        host, _, port = target.partition(":")
        if port.isdigit():
            return host

    if target.startswith("[") and target.endswith("]"):
        return target[1:-1]

    return target


def resolve_target(target: str) -> list:
    host = normalise_target(target)
    if is_valid_ip(host):
        return [host]
    if not is_valid_hostname(host):
        raise ValidationError(f"'{target}' is not a valid IP or hostname.")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValidationError(f"DNS resolution failed for '{host}': {exc}") from exc
    seen = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.append(ip)
    if not seen:
        raise ValidationError(f"No addresses returned for '{host}'.")
    return seen


def parse_ports(spec) -> list:
    if spec is None:
        return []
    if not isinstance(spec, str):
        ports = {int(p) for p in spec}
        _check_port_range(ports)
        return sorted(ports)

    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, _, b = chunk.partition("-")
            try:
                start, end = int(a), int(b)
            except ValueError as exc:
                raise ValidationError(f"Bad port range '{chunk}'.") from exc
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            try:
                ports.add(int(chunk))
            except ValueError as exc:
                raise ValidationError(f"Bad port '{chunk}'.") from exc

    if not ports:
        raise ValidationError("No valid ports were supplied.")
    _check_port_range(ports)
    return sorted(ports)


def _check_port_range(ports: Iterable[int]) -> None:
    for p in ports:
        if not (1 <= p <= 65535):
            raise ValidationError(f"Port {p} is out of range (1-65535).")


# =============================================================================
# SECTION 5 : Port Scanner
# =============================================================================

class PortScanner:
    """Multithreaded TCP connect scanner."""

    def __init__(self, target: str, ports: list,
                 timeout: float = 1.0, threads: int = 200):
        self.target = target
        self.ports = sorted(set(ports))
        self.timeout = max(0.05, float(timeout))
        self.threads = max(1, min(int(threads), 500))

    def _scan_port(self, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                if s.connect_ex((self.target, port)) == 0:
                    return port
        except (socket.timeout, OSError):
            pass
        return None

    def scan(self) -> list:
        if not self.ports:
            return []
        print(f"  [*] Scanning {self.target} across {len(self.ports)} port(s) "
              f"with {self.threads} thread(s)...")
        started = time.time()
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._scan_port, p): p for p in self.ports}
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                if result is not None:
                    open_ports.append(result)
        open_ports.sort()
        print(f"  [+] Port scan complete in {time.time()-started:.2f}s - "
              f"{len(open_ports)} open port(s).")
        return open_ports


# =============================================================================
# SECTION 6 : Service Detector (banner grabbing)
# =============================================================================

HTTP_PROBE = (b"HEAD / HTTP/1.0\r\n"
              b"Host: scanner.local\r\n"
              b"User-Agent: VulnScanner/1.0\r\n"
              b"Connection: close\r\n\r\n")

SERVER_RE  = re.compile(r"^Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
POWERED_RE = re.compile(r"^X-Powered-By:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


class ServiceDetector:
    def __init__(self, target: str, timeout: float = 2.5):
        self.target = target
        self.timeout = max(0.5, float(timeout))

    def detect(self, port: int) -> ServiceInfo:
        service = PORT_SERVICE_MAP.get(port, "unknown")
        is_tls  = port in TLS_PORTS
        is_http = port in HTTP_PORTS or service.startswith("http")

        banner = self._grab_banner(port, service, is_tls)
        signature = self._extract_signature(banner, service)

        if service == "unknown" and banner:
            service = self._guess_service(banner) or service

        return ServiceInfo(
            port=port, service=service, banner=banner,
            signature=signature,
            is_http=is_http or service.startswith("http"),
            is_tls=is_tls,
        )

    def detect_many(self, ports: list) -> dict:
        return {p: self.detect(p) for p in ports}

    def _grab_banner(self, port: int, service: str, is_tls: bool) -> str:
        try:
            raw = socket.create_connection((self.target, port),
                                            timeout=self.timeout)
        except OSError:
            return ""

        sock = raw
        try:
            if is_tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw, server_hostname=self.target)
            sock.settimeout(self.timeout)

            probe = self._build_probe(service)
            if probe:
                try:
                    sock.sendall(probe)
                except OSError:
                    pass

            return self._read_banner(sock)
        except Exception:
            return ""
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _read_banner(self, sock: socket.socket, limit: int = 4096) -> str:
        chunks, total = [], 0
        try:
            while total < limit:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if b"\r\n\r\n" in b"".join(chunks):
                    break
        except (socket.timeout, OSError):
            pass
        return b"".join(chunks).decode("utf-8", errors="replace").strip()

    @staticmethod
    def _build_probe(service: str):
        if service.startswith("http"):
            return HTTP_PROBE
        if service in {"smtp"}:
            return b"EHLO scanner.local\r\n"
        if service in {"imap", "imaps"}:
            return b"a1 CAPABILITY\r\n"
        if service in {"pop3", "pop3s"}:
            return b"CAPA\r\n"
        if service == "redis":
            return b"PING\r\n"
        if service in {"ftp", "ssh", "telnet", "vnc", "mysql"}:
            return None
        return b"\r\n"

    @staticmethod
    def _extract_signature(banner: str, service: str) -> str:
        if not banner:
            return ""
        if service.startswith("http"):
            parts = []
            m1 = SERVER_RE.search(banner)
            m2 = POWERED_RE.search(banner)
            if m1:
                parts.append(f"Server: {m1.group(1).strip()}")
            if m2:
                parts.append(f"X-Powered-By: {m2.group(1).strip()}")
            if parts:
                return " | ".join(parts)
        return banner.splitlines()[0].strip()[:200]

    @staticmethod
    def _guess_service(banner: str) -> str:
        b = banner.lower()
        table = {
            "ssh-": "ssh", "220 ": "ftp", "220-": "ftp",
            "smtp": "smtp", "http/": "http", "redis": "redis",
            "-err": "redis", "mysql": "mysql", "mongodb": "mongodb",
            "memcached": "memcached", "elastic": "elasticsearch",
            "amqp": "amqp", "rtsp": "rtsp",
        }
        for needle, name in table.items():
            if needle in b:
                return name
        return ""


# =============================================================================
# SECTION 7 : Vulnerability Rule Engine
# =============================================================================

class VulnChecker:
    def __init__(self, target: str):
        self.target = target
        self._compiled = {}

    def _rules_for(self, service: str):
        if service in self._compiled:
            return self._compiled[service]
        compiled = []
        for rule in VULN_DB["service_rules"].get(service, []):
            try:
                compiled.append((rule, re.compile(rule["pattern"], re.IGNORECASE)))
            except re.error:
                continue
        self._compiled[service] = compiled
        return compiled

    def check_service(self, svc: ServiceInfo) -> list:
        findings = []
        haystack = f"{svc.signature}\n{svc.banner}".strip()

        for rule, pattern in self._rules_for(svc.service):
            if pattern.search(haystack):
                findings.append(self._make(rule, svc))

        for rule in VULN_DB["port_rules"]:
            if int(rule.get("port", -1)) == svc.port:
                if not rule.get("pattern") or re.search(
                        rule["pattern"], haystack, re.IGNORECASE):
                    findings.append(self._make(rule, svc))

        findings.extend(self._heuristics(svc))
        return findings

    def check_all(self, services: dict) -> list:
        out = []
        for port in sorted(services):
            out.extend(self.check_service(services[port]))
        return out

    def _make(self, rule: dict, svc: ServiceInfo) -> Finding:
        return Finding(
            id=rule.get("id", "VS-?"),
            title=rule.get("title", "Unspecified issue"),
            severity=Severity.from_string(rule.get("severity", "INFO")),
            description=rule.get("description", ""),
            target=self.target,
            port=svc.port,
            service=svc.service,
            evidence=svc.signature or svc.banner[:200],
            remediation=rule.get("remediation", ""),
            references=list(rule.get("references", [])),
            cvss=float(rule.get("cvss", 0.0)),
            category=rule.get("category", "service"),
        )

    def _heuristics(self, svc: ServiceInfo) -> list:
        out = []

        plaintext = {
            21:  ("FTP sends credentials in cleartext",  Severity.HIGH,   "VS-GEN-001"),
            23:  ("Telnet sends data in cleartext",      Severity.HIGH,   "VS-GEN-002"),
            110: ("POP3 without TLS is cleartext",       Severity.MEDIUM, "VS-GEN-003"),
            143: ("IMAP without TLS is cleartext",       Severity.MEDIUM, "VS-GEN-004"),
            80:  ("HTTP without TLS is cleartext",       Severity.LOW,    "VS-GEN-005"),
        }
        if svc.port in plaintext:
            title, sev, rid = plaintext[svc.port]
            out.append(Finding(
                id=rid, title=title, severity=sev,
                description=f"Port {svc.port} ({svc.service}) is reachable "
                            f"and the protocol does not encrypt traffic.",
                target=self.target, port=svc.port, service=svc.service,
                evidence=svc.signature,
                remediation="Replace with an encrypted equivalent "
                            "(SSH, HTTPS, FTPS, IMAPS, POP3S).",
                category="transport",
            ))

        exposed = {
            6379:  ("Redis exposed",          Severity.CRITICAL, "VS-GEN-101"),
            27017: ("MongoDB exposed",        Severity.CRITICAL, "VS-GEN-102"),
            9200:  ("Elasticsearch exposed",  Severity.CRITICAL, "VS-GEN-103"),
            11211: ("Memcached exposed",      Severity.HIGH,     "VS-GEN-104"),
            5984:  ("CouchDB exposed",        Severity.HIGH,     "VS-GEN-105"),
            2375:  ("Docker API exposed",     Severity.CRITICAL, "VS-GEN-106"),
            5432:  ("PostgreSQL reachable",   Severity.MEDIUM,   "VS-GEN-107"),
            3306:  ("MySQL reachable",        Severity.MEDIUM,   "VS-GEN-108"),
            1433:  ("MSSQL reachable",        Severity.MEDIUM,   "VS-GEN-109"),
        }
        if svc.port in exposed:
            title, sev, rid = exposed[svc.port]
            out.append(Finding(
                id=rid, title=title, severity=sev,
                description=f"The {svc.service} service on port {svc.port} "
                            f"is reachable from the scanned network.",
                target=self.target, port=svc.port, service=svc.service,
                evidence=svc.signature,
                remediation="Bind to a private interface, enforce authentication, "
                            "and add firewall rules restricting access.",
                category="exposure",
            ))
        return out


# =============================================================================
# SECTION 8 : Web Security Checks
# =============================================================================

SECURITY_HEADERS = [
    {"header": "strict-transport-security", "id": "VS-WEB-001",
     "title": "Missing Strict-Transport-Security header",
     "severity": Severity.MEDIUM, "tls_only": True,
     "description": "HSTS forces browsers to use HTTPS, preventing downgrade attacks.",
     "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"},

    {"header": "content-security-policy", "id": "VS-WEB-002",
     "title": "Missing Content-Security-Policy header",
     "severity": Severity.MEDIUM, "tls_only": False,
     "description": "A CSP mitigates XSS and data injection attacks.",
     "remediation": "Define a restrictive Content-Security-Policy."},

    {"header": "x-content-type-options", "id": "VS-WEB-003",
     "title": "Missing X-Content-Type-Options header",
     "severity": Severity.LOW, "tls_only": False,
     "description": "Without nosniff, browsers may MIME-sniff responses.",
     "remediation": "Add: X-Content-Type-Options: nosniff"},

    {"header": "x-frame-options", "id": "VS-WEB-004",
     "title": "Missing X-Frame-Options header",
     "severity": Severity.LOW, "tls_only": False,
     "description": "Page may be framed by a third-party site (clickjacking).",
     "remediation": "Add: X-Frame-Options: DENY"},

    {"header": "referrer-policy", "id": "VS-WEB-005",
     "title": "Missing Referrer-Policy header",
     "severity": Severity.LOW, "tls_only": False,
     "description": "URL parameters may leak to third parties via Referer.",
     "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin"},
]

SENSITIVE_PATHS = [
    {"path": "/.git/HEAD",   "id": "VS-WEB-101",
     "title": "Exposed Git repository",  "severity": "HIGH",
     "signature": r"^ref:\s"},
    {"path": "/.env",        "id": "VS-WEB-104",
     "title": "Exposed .env file",       "severity": "CRITICAL",
     "signature": r"[A-Z0-9_]+\s*="},
    {"path": "/.htpasswd",   "id": "VS-WEB-105",
     "title": "Exposed .htpasswd",       "severity": "HIGH",
     "signature": r":\$"},
    {"path": "/backup.sql",  "id": "VS-WEB-107",
     "title": "Exposed SQL backup",      "severity": "CRITICAL",
     "signature": r"(INSERT INTO|CREATE TABLE)"},
    {"path": "/phpinfo.php", "id": "VS-WEB-109",
     "title": "PHP info page exposed",   "severity": "MEDIUM",
     "signature": r"phpinfo\(\)"},
    {"path": "/server-status", "id": "VS-WEB-110",
     "title": "Apache server-status exposed", "severity": "MEDIUM",
     "signature": r"Apache Server Status"},
    {"path": "/actuator/env", "id": "VS-WEB-111",
     "title": "Spring Actuator /env exposed", "severity": "HIGH",
     "signature": r"propertySources|activeProfiles"},
    {"path": "/web.config",  "id": "VS-WEB-114",
     "title": "IIS web.config exposed",  "severity": "HIGH",
     "signature": r"<configuration"},
]


class WebScanner:
    def __init__(self, target: str, port: int, use_tls: bool,
                 timeout: float = 6.0):
        self.target  = target
        self.port    = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.scheme  = "https" if use_tls else "http"
        self.host_header = (target if port in (80, 443)
                            else f"{target}:{port}")

    def scan(self) -> list:
        status, headers, body = self._request("GET", "/")
        if status == 0:
            return []

        findings = []
        findings += self._check_headers(headers)
        findings += self._check_disclosure(headers)
        findings += self._check_cookies(headers)
        findings += self._check_cors()
        findings += self._check_methods()
        findings += self._check_sensitive()
        return findings

    def _connection(self):
        if self.use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(
                self.target, self.port, timeout=self.timeout, context=ctx)
        return http.client.HTTPConnection(
            self.target, self.port, timeout=self.timeout)

    def _request(self, method="GET", path="/", extra=None):
        headers = {"User-Agent": USER_AGENT, "Host": self.host_header,
                   "Accept": "*/*", "Connection": "close"}
        if extra:
            headers.update(extra)
        conn = self._connection()
        try:
            conn.request(method, path, headers=headers)
            resp = conn.getresponse()
            return resp.status, list(resp.getheaders()), resp.read(65536)
        except Exception:
            return 0, [], b""
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _header(headers, name):
        name = name.lower()
        for k, v in headers:
            if k.lower() == name:
                return v
        return None

    @staticmethod
    def _header_values(headers, name):
        name = name.lower()
        return [v for k, v in headers if k.lower() == name]

    def _check_headers(self, headers):
        out = []
        for rule in SECURITY_HEADERS:
            if rule["tls_only"] and not self.use_tls:
                continue
            if self._header(headers, rule["header"]) is None:
                out.append(Finding(
                    id=rule["id"], title=rule["title"],
                    severity=rule["severity"],
                    description=rule["description"],
                    target=self.target, port=self.port, service=self.scheme,
                    evidence=f"Header '{rule['header']}' absent",
                    remediation=rule["remediation"],
                    references=["https://owasp.org/www-project-secure-headers/"],
                    category="web"))
        return out

    def _check_disclosure(self, headers):
        details = []
        for name in ("server", "x-powered-by", "x-aspnet-version"):
            v = self._header(headers, name)
            if v:
                details.append(f"{name}: {v}")
        if not details:
            return []
        return [Finding(
            id="VS-WEB-301", title="Technology and version info disclosed",
            severity=Severity.LOW,
            description="The server advertises software versions that aid "
                        "attackers in targeting known vulnerabilities.",
            target=self.target, port=self.port, service=self.scheme,
            evidence="; ".join(details),
            remediation="Suppress Server, X-Powered-By, X-AspNet-Version headers.",
            category="web")]

    def _check_cookies(self, headers):
        out = []
        for cookie in self._header_values(headers, "set-cookie"):
            name = cookie.split("=", 1)[0].strip() or "<unnamed>"
            low = cookie.lower()
            missing = []
            if "httponly" not in low: missing.append("HttpOnly")
            if "secure"   not in low: missing.append("Secure")
            if "samesite" not in low: missing.append("SameSite")
            if missing:
                out.append(Finding(
                    id="VS-WEB-401",
                    title=f"Cookie '{name}' missing: {', '.join(missing)}",
                    severity=Severity.MEDIUM if "HttpOnly" in missing else Severity.LOW,
                    description="Cookies without these flags can be stolen via "
                                "XSS or transmitted over cleartext.",
                    target=self.target, port=self.port, service=self.scheme,
                    evidence=f"Set-Cookie: {cookie[:150]}",
                    remediation=f"Set {', '.join(missing)} on '{name}'.",
                    category="web"))
        return out

    def _check_cors(self):
        status, headers, _ = self._request(
            "GET", "/", {"Origin": "https://vulnscanner.invalid"})
        if status == 0:
            return []
        origin = self._header(headers, "access-control-allow-origin")
        creds  = self._header(headers, "access-control-allow-credentials")
        if origin == "*" and (creds or "").lower() == "true":
            return [Finding(
                id="VS-WEB-501",
                title="Permissive CORS with credentials",
                severity=Severity.HIGH,
                description="Wildcard origin + credentials allows any site to "
                            "read authenticated responses.",
                target=self.target, port=self.port, service=self.scheme,
                evidence=f"ACAO: {origin}; ACAC: {creds}",
                remediation="Restrict ACAO to an explicit allow-list; "
                            "never combine '*' with credentials.",
                category="web")]
        if origin == "https://vulnscanner.invalid":
            return [Finding(
                id="VS-WEB-502", title="CORS origin reflection",
                severity=Severity.MEDIUM,
                description="The server reflects any Origin header supplied.",
                target=self.target, port=self.port, service=self.scheme,
                evidence=f"ACAO: {origin}",
                remediation="Validate Origin against an allow-list.",
                category="web")]
        return []

    def _check_methods(self):
        out = []
        status, headers, _ = self._request("OPTIONS", "/")
        if status != 0:
            allowed = (self._header(headers, "allow")
                       or self._header(headers, "access-control-allow-methods"))
            if allowed:
                risky = [m.strip().upper() for m in allowed.split(",")
                         if m.strip().upper() in {"PUT", "DELETE", "TRACE"}]
                if risky:
                    out.append(Finding(
                        id="VS-WEB-601",
                        title=f"Risky HTTP methods advertised: {', '.join(risky)}",
                        severity=Severity.MEDIUM,
                        description="State-changing or debugging methods are allowed.",
                        target=self.target, port=self.port, service=self.scheme,
                        evidence=f"Allow: {allowed}",
                        remediation="Disable unneeded HTTP methods at the server.",
                        category="web"))
        trace_status, _, trace_body = self._request("TRACE", "/")
        if trace_status == 200 and b"TRACE" in trace_body.upper():
            out.append(Finding(
                id="VS-WEB-602", title="HTTP TRACE method enabled",
                severity=Severity.MEDIUM,
                description="TRACE can be abused for Cross-Site Tracing (XST).",
                target=self.target, port=self.port, service=self.scheme,
                evidence="TRACE / returned 200 OK",
                remediation="Disable TRACE at the web server.",
                category="web"))
        return out

    def _check_sensitive(self):
        out = []
        for entry in SENSITIVE_PATHS:
            status, _, body = self._request("GET", entry["path"])
            if status != 200 or not body:
                continue
            try:
                if not re.search(entry["signature"],
                                 body.decode("utf-8", errors="replace"),
                                 re.IGNORECASE):
                    continue
            except re.error:
                continue
            out.append(Finding(
                id=entry["id"], title=entry["title"],
                severity=Severity.from_string(entry["severity"]),
                description=f"The path {entry['path']} is publicly accessible.",
                target=self.target, port=self.port, service=self.scheme,
                evidence=f"GET {entry['path']} -> HTTP 200",
                remediation="Remove from the web root or restrict access.",
                category="web"))
        return out


# =============================================================================
# SECTION 9 : TLS / SSL Checks
# =============================================================================

class SSLChecker:
    def __init__(self, target: str, port: int = 443, timeout: float = 6.0,
                 warn_days: int = 30, crit_days: int = 7):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.warn_days = warn_days
        self.crit_days = crit_days

    def check(self) -> list:
        info = self._fetch_cert()
        if info is None:
            return [Finding(
                id="VS-SSL-001", title="TLS handshake failed",
                severity=Severity.INFO,
                description="A TLS handshake could not be completed on this port.",
                target=self.target, port=self.port, service="tls",
                remediation="Verify the endpoint is configured for TLS.",
                category="tls")]
        findings = []
        findings += self._check_cert(info)
        findings += self._check_cipher(info)
        findings += self._check_legacy()
        return findings

    def _fetch_cert(self):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.target, self.port),
                                          timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.target) as s:
                    return {"cert": s.getpeercert(), "cipher": s.cipher(),
                            "trusted": True}
        except ssl.SSLCertVerificationError as exc:
            verify_err = str(exc)
        except Exception:
            return None
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target, self.port),
                                          timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.target) as s:
                    return {"cert": {}, "cipher": s.cipher(),
                            "trusted": False, "error": verify_err}
        except Exception:
            return None

    def _check_cert(self, info):
        out = []
        if not info.get("trusted"):
            out.append(Finding(
                id="VS-SSL-101", title="TLS certificate not trusted",
                severity=Severity.HIGH,
                description="Certificate failed validation against the system "
                            "trust store. Possibly self-signed or expired.",
                target=self.target, port=self.port, service="tls",
                evidence=info.get("error", "verification failed"),
                remediation="Install a trusted CA certificate.",
                category="tls"))

        cert = info.get("cert") or {}
        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                exp = exp.replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    sev, title = Severity.CRITICAL, "TLS certificate has expired"
                elif days <= self.crit_days:
                    sev = Severity.HIGH
                    title = f"TLS certificate expires in {days} day(s)"
                elif days <= self.warn_days:
                    sev = Severity.MEDIUM
                    title = f"TLS certificate expires in {days} day(s)"
                else:
                    return out
                out.append(Finding(
                    id="VS-SSL-102", title=title, severity=sev,
                    description="Certificate expiry affects availability and "
                                "browser trust.",
                    target=self.target, port=self.port, service="tls",
                    evidence=f"notAfter = {not_after}",
                    remediation="Renew the certificate and automate renewal.",
                    category="tls"))
            except ValueError:
                pass
        return out

    def _check_cipher(self, info):
        cipher = info.get("cipher")
        if not cipher:
            return []
        name = cipher[0]
        bits = cipher[2] if len(cipher) > 2 else 0
        weak = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5")
        if any(w in name.upper() for w in weak) or (bits and bits < 128):
            return [Finding(
                id="VS-SSL-201", title=f"Weak TLS cipher negotiated: {name}",
                severity=Severity.HIGH,
                description="The negotiated cipher is considered weak.",
                target=self.target, port=self.port, service="tls",
                evidence=f"{name} ({bits} bits)",
                remediation="Restrict to modern AEAD ciphers.",
                category="tls")]
        return []

    def _check_legacy(self):
        out = []
        for label, version in [("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
                               ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None))]:
            if version is None:
                continue
            if self._supports(version):
                out.append(Finding(
                    id="VS-SSL-301", title=f"Legacy protocol supported: {label}",
                    severity=Severity.HIGH,
                    description=f"The server still accepts {label}. These are "
                                f"deprecated by RFC 8996.",
                    target=self.target, port=self.port, service="tls",
                    evidence=f"{label} handshake succeeded",
                    remediation="Set the minimum protocol to TLS 1.2 (or 1.3).",
                    references=["https://datatracker.ietf.org/doc/rfc8996/"],
                    category="tls"))
        return out

    def _supports(self, tls_version) -> bool:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
        except (ValueError, OSError):
            return False
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        try:
            with socket.create_connection((self.target, self.port),
                                          timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.target):
                    return True
        except Exception:
            return False


# =============================================================================
# SECTION 10 : Reporter
# =============================================================================

C = {
    "RESET":  "\033[0m", "BOLD": "\033[1m",
    "RED":    "\033[91m", "ORANGE": "\033[38;5;208m",
    "YELLOW": "\033[93m", "BLUE": "\033[94m",
    "GREY":   "\033[90m", "GREEN": "\033[92m", "CYAN": "\033[96m",
}

SEV_COLOR = {
    "CRITICAL": C["RED"], "HIGH": C["ORANGE"], "MEDIUM": C["YELLOW"],
    "LOW": C["BLUE"], "INFO": C["GREY"],
}

SEV_HEX = {
    "CRITICAL": "#b3001b", "HIGH": "#e05c00", "MEDIUM": "#c9a227",
    "LOW": "#2b6cb0", "INFO": "#6b7280",
}


class Reporter:
    def __init__(self, target: str, ip: str, open_ports: list,
                 services: dict, findings: list, duration: float,
                 use_color: bool = True):
        self.target = target
        self.ip = ip
        self.open_ports = open_ports
        self.services = services
        self.findings = sorted(findings,
                               key=lambda f: f.severity.rank, reverse=True)
        self.duration = duration
        self.use_color = use_color
        self.started = datetime.now(timezone.utc)

    def _c(self, text, color):
        return f"{color}{text}{C['RESET']}" if self.use_color else text

    def counts(self):
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def has_critical_or_high(self) -> bool:
        return any(f.severity.value in ("CRITICAL", "HIGH")
                   for f in self.findings)

    def to_console(self):
        line = "=" * 72
        print()
        print(self._c(line, C["CYAN"]))
        print(self._c("  VULNERABILITY SCAN REPORT", C["BOLD"] + C["CYAN"]))
        print(self._c(line, C["CYAN"]))
        print(f"  Target        : {self.target} ({self.ip})")
        print(f"  Started (UTC) : {self.started.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Duration      : {self.duration:.2f}s")
        print(f"  Open ports    : {len(self.open_ports)}")
        print(f"  Findings      : {len(self.findings)}")
        print(self._c(line, C["CYAN"]))

        print()
        print(self._c("  [ OPEN PORTS & SERVICES ]", C["BOLD"]))
        if not self.open_ports:
            print("    (none)")
        for port in self.open_ports:
            svc = self.services.get(port)
            desc = (f"{svc.service:<18} {svc.signature[:52]}"
                    if svc else "unknown")
            print(f"    {port:>5}/tcp  {desc}")

        print()
        print(self._c("  [ FINDINGS ]", C["BOLD"]))
        if not self.findings:
            print(self._c("    No issues detected.", C["GREEN"]))
        for i, f in enumerate(self.findings, 1):
            color = SEV_COLOR.get(f.severity.value, C["GREY"])
            tag = self._c(f"[{f.severity.value:^8}]", color)
            loc = f"{f.target}:{f.port}" if f.port else f.target
            print()
            print(f"  {i:>3}. {tag} {self._c(f.title, C['BOLD'])}")
            print(f"       ID       : {f.id}")
            print(f"       Location : {loc}  ({f.service or '-'})")
            if f.cvss:
                print(f"       CVSS     : {f.cvss}")
            if f.evidence:
                print(f"       Evidence : {f.evidence.replace(chr(10),' ')[:100]}")
            if f.description:
                print(f"       Details  : {f.description}")
            if f.remediation:
                print(f"       Fix      : {f.remediation}")

        counts = self.counts()
        print()
        print(self._c(line, C["CYAN"]))
        print(self._c("  SUMMARY", C["BOLD"]))
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            print(f"    {self._c(f'{sev:<9}', SEV_COLOR[sev])}: {counts[sev]}")
        print(self._c(line, C["CYAN"]))
        print()

    def to_json(self, path: str):
        data = {
            "meta": {
                "tool": "VulnScanner", "version": VERSION,
                "target": self.target, "resolved_ip": self.ip,
                "started_utc": self.started.isoformat(),
                "duration_seconds": round(self.duration, 3),
            },
            "summary": {
                "open_ports": len(self.open_ports),
                "findings": len(self.findings),
                "by_severity": self.counts(),
            },
            "open_ports": [
                {"port": p,
                 "service": self.services[p].service if p in self.services else "unknown",
                 "signature": self.services[p].signature if p in self.services else ""}
                for p in self.open_ports
            ],
            "findings": [f.to_dict() for f in self.findings],
        }
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        print(f"  [+] JSON report: {path}")

    def to_csv(self, path: str):
        fields = ["id", "severity", "title", "target", "port", "service",
                  "cvss", "category", "evidence", "description",
                  "remediation", "references"]
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            for f in self.findings:
                row = f.to_dict()
                row["references"] = " | ".join(row.get("references") or [])
                w.writerow({k: row.get(k, "") for k in fields})
        print(f"  [+] CSV report : {path}")

    def to_html(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self._render_html())
        print(f"  [+] HTML report: {path}")

    def _render_html(self) -> str:
        c = self.counts()
        esc = html.escape

        port_rows = "".join(
            f"<tr><td>{p}/tcp</td>"
            f"<td>{esc(self.services[p].service if p in self.services else 'unknown')}</td>"
            f"<td class='mono'>{esc(self.services[p].signature if p in self.services else '')}</td></tr>"
            for p in self.open_ports
        ) or "<tr><td colspan='3'>No open ports detected.</td></tr>"

        blocks = []
        for f in self.findings:
            color = SEV_HEX.get(f.severity.value, "#6b7280")
            refs = "".join(f"<li><a href='{esc(r)}'>{esc(r)}</a></li>"
                           for r in f.references)
            blocks.append(f"""
            <article class="finding" style="border-left:6px solid {color}">
              <header>
                <span class="badge" style="background:{color}">{esc(f.severity.value)}</span>
                <h3>{esc(f.title)}</h3>
                <span class="fid">{esc(f.id)}</span>
              </header>
              <table class="meta">
                <tr><th>Location</th><td>{esc(f.target)}{':' + str(f.port) if f.port else ''}</td></tr>
                <tr><th>Service</th><td>{esc(f.service or '-')}</td></tr>
                <tr><th>CVSS</th><td>{f.cvss or '-'}</td></tr>
                <tr><th>Evidence</th><td class="mono">{esc(f.evidence or '-')}</td></tr>
              </table>
              <p>{esc(f.description)}</p>
              <p class="fix"><strong>Remediation:</strong> {esc(f.remediation or 'N/A')}</p>
              {f"<ul class='refs'>{refs}</ul>" if refs else ""}
            </article>""")

        findings_html = "\n".join(blocks) or (
            "<p class='clean'>No issues were detected during this scan.</p>")

        return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnScanner Report - {esc(self.target)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
          Arial, sans-serif; margin:0; background:#f6f8fa; color:#1f2328; }}
  header.page {{ background:#0d1117; color:#e6edf3; padding:2rem 3rem; }}
  header.page h1 {{ margin:0 0 .4rem; font-size:1.6rem; }}
  header.page p {{ margin:.15rem 0; color:#9da7b3; font-size:.9rem; }}
  main {{ max-width:1000px; margin:0 auto; padding:2rem 1.5rem; }}
  .cards {{ display:flex; flex-wrap:wrap; gap:1rem; margin-bottom:2rem; }}
  .card {{ flex:1 1 130px; background:#fff; border:1px solid #d1d9e0;
           border-radius:10px; padding:1rem; text-align:center; }}
  .card .n {{ font-size:1.9rem; font-weight:700; display:block; }}
  .card .l {{ font-size:.72rem; text-transform:uppercase; color:#59636e; }}
  table {{ width:100%; border-collapse:collapse; background:#fff;
           border:1px solid #d1d9e0; border-radius:10px; overflow:hidden; }}
  th,td {{ padding:.6rem .8rem; border-bottom:1px solid #eaeef2;
           text-align:left; font-size:.9rem; }}
  th {{ background:#f0f3f6; }}
  .mono {{ font-family: ui-monospace, monospace; font-size:.82rem; }}
  h2 {{ margin-top:2.5rem; font-size:1.15rem;
        border-bottom:2px solid #d1d9e0; padding-bottom:.4rem; }}
  .finding {{ background:#fff; border:1px solid #d1d9e0; border-radius:10px;
              padding:1rem 1.25rem; margin-bottom:1.25rem; }}
  .finding header {{ display:flex; align-items:center; gap:.6rem; flex-wrap:wrap; }}
  .finding h3 {{ margin:0; font-size:1rem; }}
  .badge {{ color:#fff; font-size:.68rem; font-weight:700;
            padding:.15rem .5rem; border-radius:999px; }}
  .fid {{ margin-left:auto; font-family:monospace; font-size:.75rem; color:#59636e; }}
  table.meta {{ margin:.75rem 0; border:none; background:transparent; }}
  table.meta th {{ width:110px; background:transparent; border:none;
                   color:#59636e; font-size:.8rem; padding:.2rem .5rem .2rem 0; }}
  table.meta td {{ border:none; padding:.2rem 0; font-size:.85rem; }}
  .fix {{ background:#eefbf3; border-radius:6px; padding:.6rem .8rem; font-size:.88rem; }}
  .clean {{ background:#eefbf3; border-radius:8px; padding:1rem; color:#0f5132; }}
  footer {{ text-align:center; color:#59636e; font-size:.8rem; margin-top:3rem; }}
</style></head><body>
<header class="page">
  <h1>Vulnerability Scan Report</h1>
  <p><strong>Target:</strong> {esc(self.target)} ({esc(self.ip)})</p>
  <p><strong>Generated:</strong> {self.started.strftime('%Y-%m-%d %H:%M:%S')} UTC
     &nbsp;|&nbsp; <strong>Duration:</strong> {self.duration:.2f}s</p>
</header>
<main>
  <div class="cards">
    <div class="card"><span class="n">{len(self.open_ports)}</span><span class="l">Open Ports</span></div>
    <div class="card"><span class="n" style="color:{SEV_HEX['CRITICAL']}">{c['CRITICAL']}</span><span class="l">Critical</span></div>
    <div class="card"><span class="n" style="color:{SEV_HEX['HIGH']}">{c['HIGH']}</span><span class="l">High</span></div>
    <div class="card"><span class="n" style="color:{SEV_HEX['MEDIUM']}">{c['MEDIUM']}</span><span class="l">Medium</span></div>
    <div class="card"><span class="n" style="color:{SEV_HEX['LOW']}">{c['LOW']}</span><span class="l">Low</span></div>
    <div class="card"><span class="n" style="color:{SEV_HEX['INFO']}">{c['INFO']}</span><span class="l">Info</span></div>
  </div>
  <h2>Open Ports &amp; Services</h2>
  <table><thead><tr><th>Port</th><th>Service</th><th>Signature</th></tr></thead>
  <tbody>{port_rows}</tbody></table>
  <h2>Findings ({len(self.findings)})</h2>
  {findings_html}
</main>
<footer>Generated by VulnScanner v{VERSION} &middot; For authorised testing only.</footer>
</body></html>
"""


# =============================================================================
# SECTION 11 : CLI & Main Workflow
# =============================================================================

BANNER = r"""
 __     __     _        ____
 \ \   / /   _| |_ __  / ___|  ___ __ _ _ __  _ __   ___ _ __
  \ \ / / | | | | '_ \ \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
   \ V /| |_| | | | | | ___) | (_| (_| | | | | | | |  __/ |
    \_/  \__,_|_|_| |_||____/ \___\__,_|_| |_|_| |_|\___|_|
                                                    v{version}
"""


def print_banner():
    print(BANNER.format(version=VERSION))
    print("  [!] Only scan systems you own or have WRITTEN permission to test.\n")


def build_parser():
    p = argparse.ArgumentParser(
        prog="vulnscanner",
        description="VulnScanner - lightweight network vulnerability scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Examples:\n"
                "  python vulnscanner.py -t 192.168.1.10\n"
                "  python vulnscanner.py -t example.com -p 22,80,443 --web --ssl\n"
                "  python vulnscanner.py -t 10.0.0.5 --full -o report.html -y\n"))
    p.add_argument("-t", "--target", required=True,
                   help="Target IP, hostname or URL.")
    p.add_argument("-p", "--ports", default=None,
                   help="Port spec, e.g. '22,80,443,8000-8100'. Default: top 100.")
    p.add_argument("--full", action="store_true",
                   help="Scan all 65535 TCP ports (slow).")
    p.add_argument("--timeout", type=float, default=1.0,
                   help="Per-connection timeout (default 1.0).")
    p.add_argument("--threads", type=int, default=200,
                   help="Worker threads (default 200, max 500).")
    p.add_argument("--web", action="store_true",
                   help="Enable HTTP/HTTPS checks.")
    p.add_argument("--ssl", action="store_true",
                   help="Enable TLS/SSL checks.")
    p.add_argument("-o", "--output", default=None,
                   help="Report path (.json, .html or .csv).")
    p.add_argument("--format", choices=["json", "html", "csv"], default=None,
                   help="Force report format.")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI colours.")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip authorisation prompt.")
    return p


def confirm(target: str) -> bool:
    print(f"\n  You are about to scan: {target}")
    print("  Confirm that you own it or have explicit written permission.\n")
    try:
        return input("  Continue? [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def run(args) -> int:
    try:
        ips = resolve_target(args.target)
    except ValidationError as exc:
        print(f"  Error: {exc}", file=sys.stderr)
        return 2
    ip = ips[0]

    try:
        if args.full:
            ports = list(range(1, 65536))
        elif args.ports:
            ports = parse_ports(args.ports)
        else:
            ports = list(TOP_PORTS)
    except ValidationError as exc:
        print(f"  Error: {exc}", file=sys.stderr)
        return 2

    started = time.time()

    scanner = PortScanner(ip, ports, timeout=args.timeout,
                          threads=args.threads)
    try:
        open_ports = scanner.scan()
    except KeyboardInterrupt:
        print("\n  Interrupted by user.")
        return 2

    detector = ServiceDetector(ip, timeout=max(args.timeout * 2, 2.0))
    services = detector.detect_many(open_ports)

    findings = VulnChecker(ip).check_all(services)

    if args.web:
        web_ports = [p for p, s in services.items() if s.is_http]
        if not web_ports:
            print("  [i] No HTTP services detected - skipping web checks.")
        for p in web_ports:
            wscanner = WebScanner(ip, port=p, use_tls=services[p].is_tls,
                                  timeout=max(args.timeout * 6, 6.0))
            findings.extend(wscanner.scan())

    if args.ssl:
        tls_ports = [p for p, s in services.items() if s.is_tls]
        if not tls_ports:
            print("  [i] No TLS services detected - skipping SSL checks.")
        for p in tls_ports:
            findings.extend(SSLChecker(ip, port=p,
                                       timeout=max(args.timeout * 6, 6.0)).check())

    reporter = Reporter(
        target=args.target, ip=ip, open_ports=open_ports,
        services=services, findings=findings,
        duration=time.time() - started,
        use_color=not args.no_color)
    reporter.to_console()

    if args.output or args.format:
        fmt = args.format or os.path.splitext(args.output)[1].lstrip(".").lower() or "json"
        if fmt not in ("json", "html", "csv"):
            fmt = "json"
        path = args.output or f"reports/scan-{time.strftime('%Y%m%d-%H%M%S')}.{fmt}"
        {"json": reporter.to_json,
         "html": reporter.to_html,
         "csv":  reporter.to_csv}[fmt](path)

    return 1 if reporter.has_critical_or_high() else 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    print_banner()

    if not args.yes and not confirm(args.target):
        print("  Aborted: authorisation not confirmed.\n")
        return 2

    try:
        return run(args)
    except KeyboardInterrupt:
        print("\n  Interrupted by user.\n")
        return 2
    except Exception as exc:
        print(f"  Unexpected error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
