"""
modules/sqli_engine.py
======================
AI Red Team Harness v3 — Multi-Stage SQL Injection Detection Engine

Implements an 8-phase detection pipeline designed to eliminate false positives
that arise from frontend validation errors, React/Next.js hydration errors,
WAF blocks, CDN responses, and generic HTTP error pages.

A finding is only confirmed CRITICAL/HIGH when direct database evidence exists
(fingerprinted DB error, consistent boolean differential, or timing confirmation).

Pipeline overview:
  Phase 1 — Initial anomaly signal (change in status / length / content)
  Phase 2 — Database error fingerprinting (MySQL, PgSQL, MSSQL, Oracle, SQLite)
  Phase 3 — Differential testing (quote, escaped, boolean-true/false, numeric)
  Phase 4 — Frontend framework detection (Next.js, React, Vue, Angular …)
  Phase 5 — Confidence scoring (0 – 1.0)
  Phase 6 — Severity assignment (evidence-gated CRITICAL/HIGH rules)
  Phase 7 — False-positive suppression (FP reason taxonomy)
  Phase 8 — Conservative reporting labels (no premature "confirmed" claims)

Python: 3.11+
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Phase 2 — Database fingerprint patterns
# ---------------------------------------------------------------------------

_DB_FINGERPRINTS: dict[str, re.Pattern[str]] = {
    "MySQL": re.compile(
        r"you have an error in your sql syntax"
        r"|mysql_fetch_(?:array|row|assoc)\(\)"
        r"|mysql_num_rows\(\)"
        r"|MySQLSyntaxErrorException"
        r"|com\.mysql\.jdbc"
        r"|Warning.*?mysql_"
        r"|valid MySQL result"
        r"|check the manual that corresponds to your (MySQL|MariaDB)",
        re.I | re.S,
    ),
    "PostgreSQL": re.compile(
        r"PostgreSQL.*?ERROR"
        r"|Warning.*?pg_"
        r"|Npgsql\."
        r"|PG::SyntaxError"
        r"|PSQLException"
        r"|ERROR:\s+syntax error at or near"
        r"|unterminated quoted string at or near",
        re.I | re.S,
    ),
    "MSSQL": re.compile(
        r"Microsoft OLE DB Provider for SQL Server"
        r"|ODBC SQL Server Driver"
        r"|SqlException"
        r"|Incorrect syntax near"
        r"|Unclosed quotation mark after the character string"
        r"|SQLServer JDBC Driver"
        r"|\[SQL Server\]"
        r"|Conversion failed when converting",
        re.I | re.S,
    ),
    "Oracle": re.compile(
        r"ORA-[0-9]{4,5}"
        r"|Oracle error"
        r"|Oracle.*?Driver"
        r"|Warning.*?oci_"
        r"|quoted string not properly terminated",
        re.I | re.S,
    ),
    "SQLite": re.compile(
        r"SQLite.*?Exception"
        r"|System\.Data\.SQLite"
        r"|Warning.*?sqlite_"
        r"|sqlite3\.OperationalError"
        r"|\[SQLITE_ERROR\]",
        re.I | re.S,
    ),
    "Generic-SQL": re.compile(
        r"\bDB Error\b"
        r"|SQLSTATE\["
        r"|PDOException"
        r"|Syntax error or access violation",
        re.I,
    ),
}

# ---------------------------------------------------------------------------
# Phase 4 — Frontend framework signatures
# ---------------------------------------------------------------------------

_FRONTEND_TECH_KEYWORDS = frozenset({
    "next.js", "nextjs", "react", "vue", "vue.js", "angular",
    "svelte", "sveltekit", "nuxt", "nuxt.js", "astro", "gatsby",
    "vite", "solid.js", "solidjs", "remix", "qwik", "preact",
})

# Response body patterns that confirm frontend rendering
_FRONTEND_BODY_RE = re.compile(
    r"__NEXT_DATA__"
    r"|_next/static"
    r"|__nuxt__"
    r"|ng-version="
    r"|__vue_app__"
    r"|__svelte"
    r"|window\.__INITIAL_STATE__",
    re.I,
)

# ---------------------------------------------------------------------------
# Phase 7 — False-positive suppression patterns
# ---------------------------------------------------------------------------

# Ordered: most specific first so we assign the most informative FP tag
_FP_RULES: list[tuple[str, re.Pattern[str]]] = [
    # Properly escaped output — the quote was sanitised
    ("escaped_output", re.compile(
        r"&#39;|&apos;|&#x27;|\\u0027|\\'", re.I,
    )),
    # WAF/security product blocks
    ("waf_block", re.compile(
        r"attention required.*?cloudflare"
        r"|request blocked"
        r"|blocked by.*?(?:firewall|waf|security)"
        r"|incapsula incident id"
        r"|sucuri website firewall"
        r"|access denied.*?(?:firewall|policy)",
        re.I | re.S,
    )),
    # CDN / cache infrastructure errors
    ("cdn_error", re.compile(
        r"CF-RAY:"
        r"|x-amz-cf-id:"
        r"|Varnish cache"
        r"|x-cache:\s*MISS"
        r"|via:.*?varnish"
        r"|cdn-cache-status:",
        re.I,
    )),
    # Next.js / React SSR errors
    ("nextjs_error", re.compile(
        r"application error: a client-side exception has occurred"
        r"|(?:nextjs?|next).*?(?:error|exception)"
        r"|_next/static",
        re.I,
    )),
    ("react_hydration", re.compile(
        r"hydration.*?error"
        r"|minified react error"
        r"|reactdom.*?hydrate"
        r"|__reactFiber",
        re.I,
    )),
    # Generic frontend form validation text
    ("frontend_validation", re.compile(
        r"(?:field|input|value)\s+(?:is\s+)?required"
        r"|please\s+enter\s+(?:a\s+)?valid"
        r"|must\s+be\s+(?:at\s+least|between|a)"
        r"|minimum\s+\d+\s+character"
        r"|invalid\s+(?:input|format|value|email|phone)"
        r"|enter\s+a\s+valid",
        re.I,
    )),
    # Bare HTTP error pages with no SQL content
    ("generic_http_error", re.compile(
        r"<title>\s*(?:400 Bad Request|403 Forbidden|404 Not Found|"
        r"405 Method Not Allowed|429 Too Many Requests)\s*</title>",
        re.I,
    )),
    # SPA framework markers
    ("spa_framework", re.compile(
        r"ng-version=|__vue_app__|__nuxt__|_sapper_|__svelte",
        re.I,
    )),
]

# FP tags that fully suppress a finding even without backend evidence
_HARD_SUPPRESS_TAGS = frozenset({
    "escaped_output", "waf_block", "cdn_error",
})

# FP tags that suppress only when there is no DB fingerprint
_SOFT_SUPPRESS_TAGS = frozenset({
    "frontend_validation", "nextjs_error", "react_hydration",
    "generic_http_error", "spa_framework",
})

# ---------------------------------------------------------------------------
# Differential probe payloads
# ---------------------------------------------------------------------------

_BOOL_TRUE_PAYLOAD  = "' AND '1'='1"
_BOOL_FALSE_PAYLOAD = "' AND '1'='2"
_TIMING_PAYLOAD_MYSQL  = "' AND SLEEP(5)-- -"
_TIMING_PAYLOAD_MSSQL  = "'; WAITFOR DELAY '0:0:5'-- -"
_TIMING_PAYLOAD_PGSQL  = "'; SELECT pg_sleep(5)-- -"

# ---------------------------------------------------------------------------
# Internal data structures
# ---------------------------------------------------------------------------

@dataclass
class _ProbeResult:
    status:   int   = 0
    length:   int   = 0
    body:     str   = ""
    elapsed:  float = 0.0
    db_fp:    str | None = None
    fp_tags:  list[str]  = field(default_factory=list)

    @classmethod
    def null(cls) -> "_ProbeResult":
        return cls()


@dataclass
class _DiffResult:
    """
    Holds all differential probe responses for one (url, parameter) pair.
    Properties express the key anomaly signals used in Phase 5/6 verdict.
    """
    baseline:   _ProbeResult
    quote:      _ProbeResult   # payload: '
    dquote:     _ProbeResult   # payload: "
    escaped:    _ProbeResult   # payload: \'
    bool_true:  _ProbeResult   # payload: ' AND '1'='1
    bool_false: _ProbeResult   # payload: ' AND '1'='2

    # ── Convenience properties ───────────────────────────────────────────

    @property
    def has_db_fingerprint(self) -> bool:
        return any(p.db_fp for p in (self.quote, self.dquote, self.bool_true, self.bool_false))

    @property
    def db_fingerprint(self) -> str | None:
        for p in (self.quote, self.dquote, self.bool_true, self.bool_false):
            if p.db_fp:
                return p.db_fp
        return None

    @property
    def bool_diff_ratio(self) -> float:
        """Fractional length difference between boolean true/false responses."""
        bt, bf = self.bool_true.length, self.bool_false.length
        denom = max(bt, bf, 1)
        return abs(bt - bf) / denom

    @property
    def quote_change_ratio(self) -> float:
        """Fractional body length change when injecting a single-quote."""
        base = self.baseline.length
        if base == 0:
            return 0.0
        return abs(self.quote.length - base) / base

    @property
    def bool_true_matches_baseline(self) -> bool:
        """True condition response should resemble the clean baseline if injectable."""
        base = self.baseline.length
        if base == 0:
            return False
        return abs(self.bool_true.length - base) / base < 0.08

    @property
    def quote_status_anomaly(self) -> bool:
        return self.quote.status != self.baseline.status and self.baseline.status == 200

    @property
    def all_fp_tags(self) -> set[str]:
        tags: set[str] = set()
        for p in (self.quote, self.dquote, self.bool_true, self.bool_false):
            tags.update(p.fp_tags)
        return tags


@dataclass
class _Verdict:
    label:          str    # "confirmed_error" | "confirmed_boolean" | "confirmed_timing"
                           # | "suspicious" | "fp" | "clean"
    confidence:     float  # 0.0 – 1.0
    severity:       str    # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    title:          str    # full finding title
    description:    str
    evidence:       str
    cvss_score:     float


# ---------------------------------------------------------------------------
# SQLiDetectionEngine
# ---------------------------------------------------------------------------

class SQLiDetectionEngine:
    """
    Multi-stage SQLi detector.  Call scan_param() per URL parameter and
    scan_form_field() per form input.  All HTTP I/O is delegated via
    get_fn / post_fn callables so the engine stays transport-agnostic.

    Args:
        technologies:      Technology stack from attack surface discovery.
        timing_threshold:  Seconds of delay before a timing probe is flagged.
        finding_factory:   Callable matching WebVAPTEngine._finding() signature.
                           If None, returns raw _Verdict objects (for testing).
    """

    def __init__(
        self,
        technologies:     list[str],
        timing_threshold: float = 4.5,
        finding_factory:  Callable[..., Any] | None = None,
    ) -> None:
        self._techs           = [t.lower() for t in technologies]
        self._timing_thresh   = timing_threshold
        self._factory         = finding_factory
        self._is_frontend     = self._check_frontend()

    # ── Phase 4 ─────────────────────────────────────────────────────────────

    def _check_frontend(self) -> bool:
        joined = " ".join(self._techs)
        return any(kw in joined for kw in _FRONTEND_TECH_KEYWORDS)

    def _is_frontend_body(self, body: str) -> bool:
        return bool(_FRONTEND_BODY_RE.search(body))

    # ── Probe helpers ────────────────────────────────────────────────────────

    def _analyze(self, resp: Any, elapsed: float = 0.0) -> _ProbeResult:
        if resp is None:
            return _ProbeResult.null()

        body = getattr(resp, "text", "") or ""
        status = getattr(resp, "status_code", 0)

        db_fp: str | None = None
        for db_name, pattern in _DB_FINGERPRINTS.items():
            if pattern.search(body):
                db_fp = db_name
                break

        fp_tags: list[str] = []
        for tag, pattern in _FP_RULES:
            if pattern.search(body):
                fp_tags.append(tag)

        # Also scan headers for WAF/CDN signals
        headers = getattr(resp, "headers", {})
        header_blob = " ".join(f"{k}:{v}" for k, v in headers.items())
        for tag, pattern in _FP_RULES:
            if tag in ("waf_block", "cdn_error") and pattern.search(header_blob):
                if tag not in fp_tags:
                    fp_tags.append(tag)

        # Augment frontend detection from body if not yet flagged from tech stack
        if not self._is_frontend and self._is_frontend_body(body):
            if "spa_framework" not in fp_tags:
                fp_tags.append("spa_framework")

        return _ProbeResult(
            status=status,
            length=len(body),
            body=body[:3000],
            elapsed=elapsed,
            db_fp=db_fp,
            fp_tags=fp_tags,
        )

    async def _probe(
        self,
        get_fn: Callable,
        url: str,
        param: str,
        value: str,
    ) -> _ProbeResult:
        t0 = time.monotonic()
        resp = await get_fn(url, params={param: value})
        return self._analyze(resp, time.monotonic() - t0)

    # ── Phase 3 — Differential test suite ───────────────────────────────────

    async def _differential(
        self,
        get_fn:   Callable,
        url:      str,
        param:    str,
        baseline: _ProbeResult,
    ) -> _DiffResult:
        """Run all differential probes.  Baseline must be pre-fetched by caller."""
        quote   = await self._probe(get_fn, url, param, "'")
        dquote  = await self._probe(get_fn, url, param, '"')
        escaped = await self._probe(get_fn, url, param, "\\'")
        btrue   = await self._probe(get_fn, url, param, _BOOL_TRUE_PAYLOAD)
        bfalse  = await self._probe(get_fn, url, param, _BOOL_FALSE_PAYLOAD)
        return _DiffResult(
            baseline=baseline,
            quote=quote,
            dquote=dquote,
            escaped=escaped,
            bool_true=btrue,
            bool_false=bfalse,
        )

    # ── Phase 7 — FP suppression ─────────────────────────────────────────────

    def _fp_reason(self, diff: _DiffResult) -> str | None:
        tags = diff.all_fp_tags

        # Hard suppression — block regardless of other signals
        for tag in _HARD_SUPPRESS_TAGS:
            if tag in tags:
                return tag

        if not diff.has_db_fingerprint:
            for tag in _SOFT_SUPPRESS_TAGS:
                if tag in tags:
                    return tag

            # Generic 400 with tiny body and no DB evidence — likely WAF/input rejection
            if (diff.quote.status == 400
                    and diff.quote.length < 800
                    and not diff.has_db_fingerprint):
                return "generic_400_no_evidence"

        return None

    # ── Phase 5 + 6 — Confidence scoring and severity assignment ────────────

    def _verdict(
        self,
        diff: _DiffResult,
        timing: float,
        fp_reason: str | None,
        param: str,
        url: str,
    ) -> _Verdict:
        # ── Confirmed: error-based (Phase 2 hit) ────────────────────────────
        if diff.has_db_fingerprint and fp_reason is None:
            db = diff.db_fingerprint
            return _Verdict(
                label="confirmed_error",
                confidence=0.95,
                severity="CRITICAL",
                title=f"Potential SQL Injection (Error-Based) — {param}",
                description=(
                    f"The application returns a {db} database error message when a single-quote "
                    f"character is injected into parameter '{param}'. This indicates unsanitised "
                    "SQL query construction. An attacker may be able to extract data, bypass "
                    "authentication, or escalate depending on database privileges and configuration."
                ),
                evidence=(
                    f"{db} error fingerprint detected in response to quote probe on "
                    f"parameter '{param}' at {url}"
                ),
                cvss_score=9.8,
            )

        # ── Confirmed: boolean-based blind ──────────────────────────────────
        bool_diff = diff.bool_diff_ratio
        if (fp_reason is None
                and diff.baseline.status == 200
                and diff.baseline.length > 100       # non-trivial page body
                and bool_diff >= 0.08                # ≥8 % body length divergence
                and diff.bool_true_matches_baseline  # true condition ≈ clean baseline
                and diff.bool_true.status == diff.baseline.status):

            confidence = round(min(0.90, 0.60 + bool_diff), 2)
            # Downgrade if frontend detected and no DB fingerprint
            sev   = "MEDIUM" if self._is_frontend else "HIGH"
            cvss  = 5.0      if self._is_frontend else 8.6
            return _Verdict(
                label="confirmed_boolean",
                confidence=confidence,
                severity=sev,
                title=f"Potential SQL Injection (Boolean-Based Blind) — {param}",
                description=(
                    f"Response body length differs by {bool_diff:.1%} between boolean true "
                    f"('{_BOOL_TRUE_PAYLOAD}') and false ('{_BOOL_FALSE_PAYLOAD}') conditions "
                    f"on parameter '{param}'. The true condition closely mirrors the baseline "
                    "response, which is consistent with conditional SQL injection behaviour. "
                    + ("A frontend framework was detected; manual confirmation is advised."
                       if self._is_frontend else
                       "No database fingerprint was obtained, but the differential pattern is strong.")
                ),
                evidence=(
                    f"bool_true_len={diff.bool_true.length}, "
                    f"bool_false_len={diff.bool_false.length} "
                    f"({bool_diff:.1%} diff). "
                    f"baseline_len={diff.baseline.length}. "
                    f"Parameter: '{param}'"
                ),
                cvss_score=cvss,
            )

        # ── Confirmed: time-based blind ──────────────────────────────────────
        if timing >= self._timing_thresh and fp_reason is None:
            return _Verdict(
                label="confirmed_timing",
                confidence=0.75,
                severity="HIGH",
                title=f"Potential SQL Injection (Time-Based Blind) — {param}",
                description=(
                    f"The server delayed its response by {timing:.1f}s when a time-delay "
                    f"SQL payload was injected into parameter '{param}' "
                    f"(threshold: {self._timing_thresh}s). This is consistent with time-based "
                    "blind SQL injection where the database executes the injected SLEEP/WAITFOR "
                    "statement."
                ),
                evidence=(
                    f"SLEEP(5) payload caused {timing:.1f}s delay on parameter '{param}'. "
                    f"Normal baseline elapsed: {diff.baseline.elapsed:.2f}s"
                ),
                cvss_score=7.5,
            )

        # ── Suspicious: length/status change, no DB evidence ─────────────────
        len_change = diff.quote_change_ratio
        status_changed = diff.quote_status_anomaly

        if fp_reason is None and (len_change >= 0.10 or status_changed):
            if self._is_frontend or "spa_framework" in diff.all_fp_tags:
                return _Verdict(
                    label="suspicious",
                    confidence=0.25,
                    severity="LOW",
                    title=f"Frontend Validation Anomaly (Possible Injection Signal) — {param}",
                    description=(
                        f"Parameter '{param}' produced a {len_change:.1%} response length change "
                        "when a single-quote was injected. However, a client-side framework "
                        "(Next.js/React/Vue) was detected on this application, and no database "
                        "error fingerprint was found. This is most likely a frontend validation "
                        "response, not SQL injection. Manual backend testing is recommended."
                    ),
                    evidence=(
                        f"baseline_len={diff.baseline.length}, "
                        f"quote_len={diff.quote.length} ({len_change:.1%} change). "
                        f"FP tags: {sorted(diff.all_fp_tags) or 'none'}"
                    ),
                    cvss_score=2.5,
                )
            else:
                return _Verdict(
                    label="suspicious",
                    confidence=0.35,
                    severity="LOW",
                    title=f"Unconfirmed Injection-Like Behavior — {param}",
                    description=(
                        f"Parameter '{param}' produced a measurably different response "
                        f"({len_change:.1%} body length change) when a single-quote character "
                        "was injected, but no database error fingerprint was identified and "
                        "boolean-based differential testing did not confirm injection. This "
                        "may reflect application-level input filtering, backend error handling, "
                        "or a non-SQL data store. Manual confirmation is required."
                    ),
                    evidence=(
                        f"baseline_len={diff.baseline.length}, "
                        f"quote_len={diff.quote.length} ({len_change:.1%} change). "
                        f"status: {diff.baseline.status}→{diff.quote.status}. "
                        f"bool_diff={diff.bool_diff_ratio:.1%}. No DB fingerprint."
                    ),
                    cvss_score=3.1,
                )

        # ── No meaningful signal ─────────────────────────────────────────────
        return _Verdict(
            label="clean",
            confidence=0.0,
            severity="INFO",
            title="",
            description="",
            evidence="",
            cvss_score=0.0,
        )

    # ── Finding builder ──────────────────────────────────────────────────────

    _REMEDIATION = (
        "Use parameterised queries or prepared statements. Never concatenate user input "
        "into SQL strings. Apply server-side allowlist input validation. Suppress verbose "
        "database error messages in production. Consider a WAF as a defence-in-depth layer."
    )
    _REFERENCES = [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/"
        "SQL_Injection_Prevention_Cheat_Sheet.html",
        "https://portswigger.net/web-security/sql-injection",
    ]

    def _make_finding(self, verdict: _Verdict, url: str, param: str) -> Any | None:
        if verdict.label in ("clean",) or verdict.confidence < 0.20:
            return None
        if self._factory is None:
            return verdict

        from modules.web_vapt_engine import WebRiskLevel  # deferred to avoid circular import
        sev_map = {
            "CRITICAL": WebRiskLevel.CRITICAL,
            "HIGH":     WebRiskLevel.HIGH,
            "MEDIUM":   WebRiskLevel.MEDIUM,
            "LOW":      WebRiskLevel.LOW,
            "INFO":     WebRiskLevel.INFO,
        }
        return self._factory(
            "sqli",
            verdict.title,
            sev_map[verdict.severity],
            verdict.confidence,
            url, param,
            verdict.description,
            verdict.evidence,
            self._REMEDIATION,
            self._REFERENCES,
            cvss_score=verdict.cvss_score,
        )

    # ── Public API ───────────────────────────────────────────────────────────

    async def scan_param(
        self,
        get_fn:   Callable,
        url:      str,
        param:    str,
        kill_fn:  Callable[[], bool],
    ) -> list[Any]:
        """
        Run the full 8-phase pipeline against one URL query parameter.
        Returns a list of findings (empty if no signal above threshold).
        """
        if kill_fn():
            return []

        # Phase 1 — baseline (clean request)
        baseline = await self._probe(get_fn, url, param, "safe_baseline_value")
        if baseline.status == 0:
            return []  # target unreachable

        if kill_fn():
            return []

        # Phase 3 — full differential (baseline pre-fetched, no duplicate call)
        diff = await self._differential(get_fn, url, param, baseline)

        # Phase 7 — FP suppression
        fp_reason = self._fp_reason(diff)
        logger.debug(
            "sqli probe | url=%s param=%s fp=%s bool_diff=%.2f db_fp=%s",
            url, param, fp_reason, diff.bool_diff_ratio, diff.db_fingerprint,
        )

        # Timing probe — only when no DB fingerprint yet and not a known FP
        timing = 0.0
        if not diff.has_db_fingerprint and fp_reason is None:
            if kill_fn():
                return []
            t0 = time.monotonic()
            await get_fn(url, params={param: _TIMING_PAYLOAD_MYSQL})
            timing = time.monotonic() - t0

        # Phase 5 + 6 — verdict
        verdict = self._verdict(diff, timing, fp_reason, param, url)
        finding = self._make_finding(verdict, url, param)
        return [finding] if finding is not None else []

    async def scan_form_field(
        self,
        get_fn:     Callable,
        post_fn:    Callable,
        action:     str,
        method:     str,
        field_name: str,
        base_data:  dict[str, str],
        kill_fn:    Callable[[], bool],
    ) -> list[Any]:
        """
        Run error-based detection on a single HTML form field.
        Only confirms if a DB fingerprint is present and no FP tag hard-suppresses.
        """
        if kill_fn():
            return []

        async def _submit(val: str) -> _ProbeResult:
            data = {**base_data, field_name: val}
            t0 = time.monotonic()
            if method == "POST":
                resp = await post_fn(action, data=data)
            else:
                resp = await get_fn(action, params=data)
            return self._analyze(resp, time.monotonic() - t0)

        baseline = await _submit("safe_baseline_value")
        if baseline.status == 0:
            return []

        quote = await _submit("'")

        # Only proceed if DB fingerprint detected
        if not quote.db_fp:
            return []

        # Hard-suppress check
        if _HARD_SUPPRESS_TAGS & set(quote.fp_tags):
            return []

        verdict = _Verdict(
            label="confirmed_error",
            confidence=0.92,
            severity="CRITICAL",
            title=f"Potential SQL Injection (Error-Based, Form) — {field_name}",
            description=(
                f"Form field '{field_name}' triggers a {quote.db_fp} database error when a "
                "single-quote character is submitted. This indicates unsanitised SQL query "
                "construction in the form handler. No data was extracted or modified."
            ),
            evidence=(
                f"{quote.db_fp} error pattern in response to '{field_name}' = \"'\" "
                f"(status {quote.status}, body length {quote.length}) at action: {action}"
            ),
            cvss_score=9.8,
        )
        finding = self._make_finding(verdict, action, field_name)
        return [finding] if finding is not None else []
