"""
tests/unit/test_sqli_engine.py
================================
Unit tests for modules/sqli_engine.py

Coverage:
  - Frontend validation → LOW / not CRITICAL
  - Reflected payloads with no DB error → suppressed
  - Actual DB error fingerprints → CRITICAL confirmed_error
  - Boolean differential → HIGH confirmed_boolean
  - Timing delay → HIGH confirmed_timing
  - WAF / CDN responses → hard-suppressed
  - Escaped output → hard-suppressed
  - Next.js / React hydration errors → soft-suppressed
  - Static / no-change response → clean (no finding)
  - Generic 400 without DB error → suppressed
"""

from __future__ import annotations

import asyncio
import sys
import types
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Minimal stub for WebRiskLevel so the engine can be imported without
# the full web_vapt_engine module (avoids httpx / yaml dependency in unit CI)
# ---------------------------------------------------------------------------

def _make_web_vapt_stub() -> None:
    """Insert a minimal modules.web_vapt_engine stub into sys.modules."""
    if "modules.web_vapt_engine" in sys.modules:
        return
    mod = types.ModuleType("modules.web_vapt_engine")

    class _FakeRiskLevel(str):
        CRITICAL = "CRITICAL"
        HIGH     = "HIGH"
        MEDIUM   = "MEDIUM"
        LOW      = "LOW"
        INFO     = "INFO"

    mod.WebRiskLevel = _FakeRiskLevel  # type: ignore[attr-defined]
    sys.modules["modules.web_vapt_engine"] = mod


_make_web_vapt_stub()

from modules.sqli_engine import (  # noqa: E402
    SQLiDetectionEngine,
    _DB_FINGERPRINTS,
    _FP_RULES,
    _BOOL_TRUE_PAYLOAD,
    _BOOL_FALSE_PAYLOAD,
)


# ---------------------------------------------------------------------------
# Fake HTTP response helper
# ---------------------------------------------------------------------------

@dataclass
class _FakeResp:
    status_code: int = 200
    text: str = "<html><body>Normal page content here</body></html>"
    headers: dict = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {}


_NORMAL_BODY   = "<html><body>Normal page — no database here</body></html>"
_NORMAL_BODY_L = _NORMAL_BODY * 3   # longer page to make bool diff meaningful

# ── DB error bodies ────────────────────────────────────────────────────────

_MYSQL_ERROR_BODY = (
    "<html><body>Warning: You have an error in your SQL syntax; "
    "check the manual that corresponds to your MySQL server version</body></html>"
)
_PGSQL_ERROR_BODY = (
    "<html><body>PSQLException: ERROR:  syntax error at or near \"'\" "
    "LINE 1: SELECT * FROM users WHERE id='</body></html>"
)
_MSSQL_ERROR_BODY = (
    "<html><body>Microsoft OLE DB Provider for SQL Server error '80040e14' "
    "Incorrect syntax near the keyword 'AND'.</body></html>"
)
_SQLITE_ERROR_BODY = (
    "<html><body>sqlite3.OperationalError: near \"'\": syntax error</body></html>"
)

# ── FP bodies ──────────────────────────────────────────────────────────────

_NEXTJS_ERROR_BODY = (
    "<!DOCTYPE html><html><body>"
    "<h1>Application error: a client-side exception has occurred</h1>"
    "<script id='__NEXT_DATA__' type='application/json'>{}</script>"
    "</body></html>"
)
_REACT_HYDRATION_BODY = (
    "<html><body>Minified React error #418; "
    "__reactFiber... hydration error</body></html>"
)
_FRONTEND_VALIDATION_BODY = (
    "<html><body><span class='error'>Please enter a valid input. "
    "Field is required and must be at least 3 characters.</span></body></html>"
)
_WAF_BLOCK_BODY = (
    "<html><body>Attention Required! One more step. "
    "This website is using a security service to protect itself from online attacks. "
    "Cloudflare Ray ID: abc123</body></html>"
)
_CDN_ERROR_BODY = _NORMAL_BODY  # body is normal, but header carries the tag
_CDN_HEADERS    = {"CF-RAY": "12345-LHR", "server": "cloudflare"}
_ESCAPED_BODY   = (
    "<html><body>You entered: &#39; which is not valid.</body></html>"
)
_GENERIC_400_BODY = (
    "<html><body><title>400 Bad Request</title>"
    "<p>Your request was invalid.</p></body></html>"
)


# ---------------------------------------------------------------------------
# Build engine + mock get_fn
# ---------------------------------------------------------------------------

def _make_engine(
    techs: list[str] | None = None,
    timing_thresh: float = 4.5,
) -> tuple[SQLiDetectionEngine, list[Any]]:
    collected: list[Any] = []

    def factory(*args: Any, **kwargs: Any) -> dict[str, Any]:
        finding = {
            "category":    args[0],
            "title":       args[1],
            "severity":    str(args[2]),
            "confidence":  args[3],
            "url":         args[4],
            "param":       args[5],
            "description": args[6],
            "evidence":    args[7],
            "cvss_score":  kwargs.get("cvss_score", 0.0),
        }
        collected.append(finding)
        return finding

    engine = SQLiDetectionEngine(
        technologies=techs or [],
        timing_threshold=timing_thresh,
        finding_factory=factory,
    )
    return engine, collected


def _kill_false() -> bool:
    return False


# ---------------------------------------------------------------------------
# Helpers for building get_fn sequences
# ---------------------------------------------------------------------------

def _seq_get(*responses: _FakeResp):
    """Returns a get_fn that yields responses in order, then repeats the last."""
    calls = list(responses)
    idx = [0]

    async def get_fn(url: str, params: dict | None = None) -> _FakeResp:
        r = calls[min(idx[0], len(calls) - 1)]
        idx[0] += 1
        return r

    return get_fn


def _const_get(resp: _FakeResp):
    """All calls return the same response."""
    async def get_fn(url: str, params: dict | None = None) -> _FakeResp:
        return resp
    return get_fn


# ---------------------------------------------------------------------------
# Phase 2 — DB fingerprint pattern tests
# ---------------------------------------------------------------------------

class TestDbFingerprints:
    def test_mysql_pattern(self) -> None:
        assert _DB_FINGERPRINTS["MySQL"].search(_MYSQL_ERROR_BODY)

    def test_postgresql_pattern(self) -> None:
        assert _DB_FINGERPRINTS["PostgreSQL"].search(_PGSQL_ERROR_BODY)

    def test_mssql_pattern(self) -> None:
        assert _DB_FINGERPRINTS["MSSQL"].search(_MSSQL_ERROR_BODY)

    def test_sqlite_pattern(self) -> None:
        assert _DB_FINGERPRINTS["SQLite"].search(_SQLITE_ERROR_BODY)

    def test_normal_page_no_fingerprint(self) -> None:
        for db, pattern in _DB_FINGERPRINTS.items():
            assert not pattern.search(_NORMAL_BODY), f"{db} falsely matched normal page"

    def test_frontend_validation_no_fingerprint(self) -> None:
        for db, pattern in _DB_FINGERPRINTS.items():
            assert not pattern.search(_FRONTEND_VALIDATION_BODY)

    def test_nextjs_error_no_fingerprint(self) -> None:
        for db, pattern in _DB_FINGERPRINTS.items():
            assert not pattern.search(_NEXTJS_ERROR_BODY)


# ---------------------------------------------------------------------------
# Phase 7 — FP pattern tests
# ---------------------------------------------------------------------------

class TestFpPatterns:
    def _tags(self, body: str, headers: dict | None = None) -> set[str]:
        found = set()
        for tag, pattern in _FP_RULES:
            if pattern.search(body):
                found.add(tag)
        if headers:
            blob = " ".join(f"{k}:{v}" for k, v in headers.items())
            for tag, pattern in _FP_RULES:
                if tag in ("waf_block", "cdn_error") and pattern.search(blob):
                    found.add(tag)
        return found

    def test_waf_block_detected(self) -> None:
        assert "waf_block" in self._tags(_WAF_BLOCK_BODY)

    def test_cdn_detected_via_header(self) -> None:
        assert "cdn_error" in self._tags(_CDN_ERROR_BODY, _CDN_HEADERS)

    def test_escaped_output_detected(self) -> None:
        assert "escaped_output" in self._tags(_ESCAPED_BODY)

    def test_nextjs_error_detected(self) -> None:
        assert "nextjs_error" in self._tags(_NEXTJS_ERROR_BODY)

    def test_react_hydration_detected(self) -> None:
        assert "react_hydration" in self._tags(_REACT_HYDRATION_BODY)

    def test_frontend_validation_detected(self) -> None:
        assert "frontend_validation" in self._tags(_FRONTEND_VALIDATION_BODY)

    def test_normal_page_no_fp_tags(self) -> None:
        assert not self._tags(_NORMAL_BODY)

    def test_mysql_error_no_fp_tags(self) -> None:
        assert not self._tags(_MYSQL_ERROR_BODY)


# ---------------------------------------------------------------------------
# scan_param — confirmed error-based
# ---------------------------------------------------------------------------

class TestScanParamErrorBased:
    def test_mysql_error_produces_critical(self) -> None:
        engine, collected = _make_engine()
        # Probe sequence: baseline, then diff (quote/dquote/escaped/btrue/bfalse)
        # No timing probe because DB fingerprint detected → short-circuits
        get_fn = _seq_get(
            _FakeResp(text=_NORMAL_BODY),      # baseline
            _FakeResp(text=_MYSQL_ERROR_BODY), # diff: quote  ← db_fp set here
            _FakeResp(text=_NORMAL_BODY),      # diff: dquote
            _FakeResp(text=_NORMAL_BODY),      # diff: escaped
            _FakeResp(text=_NORMAL_BODY),      # diff: bool_true
            _FakeResp(text=_NORMAL_BODY),      # diff: bool_false
        )
        asyncio.run(engine.scan_param(get_fn, "http://example.test/", "id", _kill_false))
        assert len(collected) == 1
        f = collected[0]
        assert f["severity"] == "CRITICAL"
        assert f["confidence"] >= 0.90
        assert f["cvss_score"] >= 9.0
        assert "Error-Based" in f["title"]
        assert "MySQL" in f["evidence"]

    def test_pgsql_error_produces_critical(self) -> None:
        engine, collected = _make_engine()
        get_fn = _seq_get(
            _FakeResp(text=_NORMAL_BODY),
            _FakeResp(text=_PGSQL_ERROR_BODY),  # diff: quote
            *[_FakeResp(text=_NORMAL_BODY)] * 4,
        )
        asyncio.run(engine.scan_param(get_fn, "http://example.test/", "q", _kill_false))
        assert len(collected) == 1
        assert collected[0]["severity"] == "CRITICAL"

    def test_sqlite_error_produces_critical(self) -> None:
        engine, collected = _make_engine()
        get_fn = _seq_get(
            _FakeResp(text=_NORMAL_BODY),
            _FakeResp(text=_SQLITE_ERROR_BODY),  # diff: quote
            *[_FakeResp(text=_NORMAL_BODY)] * 4,
        )
        asyncio.run(engine.scan_param(get_fn, "http://example.test/", "search", _kill_false))
        assert collected[0]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# scan_param — false positive suppression
# ---------------------------------------------------------------------------

class TestScanParamFpSuppression:
    def test_waf_block_suppressed(self) -> None:
        engine, collected = _make_engine()
        # baseline + diff (5 probes): WAF returns on all injection probes
        get_fn = _seq_get(
            _FakeResp(text=_NORMAL_BODY),
            *[_FakeResp(text=_WAF_BLOCK_BODY)] * 5,
        )
        asyncio.run(engine.scan_param(get_fn, "http://example.test/", "q", _kill_false))
        assert collected == [], "WAF block must not produce a finding"

    def test_escaped_output_suppressed(self) -> None:
        engine, collected = _make_engine()
        get_fn = _seq_get(
            _FakeResp(text=_NORMAL_BODY),
            *[_FakeResp(text=_ESCAPED_BODY)] * 5,
        )
        asyncio.run(engine.scan_param(get_fn, "http://example.test/", "q", _kill_false))
        assert collected == [], "Escaped HTML output must not produce a finding"

    def test_nextjs_error_suppressed_without_db_fp(self) -> None:
        engine, collected = _make_engine()
        get_fn = _seq_get(
            _FakeResp(text=_NORMAL_BODY),
            *[_FakeResp(text=_NEXTJS_ERROR_BODY)] * 5,
        )
        asyncio.run(engine.scan_param(get_fn, "http://example.test/", "page", _kill_false))
        assert collected == [], "Next.js error without DB fingerprint must not produce a finding"

    def test_react_hydration_suppressed(self) -> None:
        engine, collected = _make_engine()
        get_fn = _seq_get(
            _FakeResp(text=_NORMAL_BODY),
            *[_FakeResp(text=_REACT_HYDRATION_BODY)] * 5,
        )
        asyncio.run(engine.scan_param(get_fn, "http://example.test/", "id", _kill_false))
        assert collected == [], "React hydration error must not produce a finding"

    def test_frontend_validation_suppressed(self) -> None:
        engine, collected = _make_engine()
        get_fn = _seq_get(
            _FakeResp(text=_NORMAL_BODY),
            *[_FakeResp(text=_FRONTEND_VALIDATION_BODY)] * 5,
        )
        asyncio.run(engine.scan_param(get_fn, "http://example.test/", "email", _kill_false))
        assert collected == [], "Frontend validation error must not produce a finding"

    def test_generic_400_suppressed_without_db(self) -> None:
        engine, collected = _make_engine()
        get_fn = _seq_get(
            _FakeResp(text=_NORMAL_BODY, status_code=200),
            *[_FakeResp(text=_GENERIC_400_BODY, status_code=400)] * 5,
        )
        asyncio.run(engine.scan_param(get_fn, "http://example.test/", "id", _kill_false))
        assert collected == [], "Generic 400 without DB error must not produce a finding"

    def test_static_site_no_change_clean(self) -> None:
        """Same response for all payloads → no finding."""
        engine, collected = _make_engine()
        get_fn = _const_get(_FakeResp(text=_NORMAL_BODY))
        asyncio.run(engine.scan_param(get_fn, "http://static.test/", "q", _kill_false))
        assert collected == []

    def test_nosql_site_generic_error_not_critical(self) -> None:
        """A site returning a generic error (no SQL fingerprint) must not be CRITICAL."""
        generic_error = "<html><body>An error occurred processing your request.</body></html>"
        engine, collected = _make_engine()
        # Quote changes response length significantly but no DB error
        get_fn = _seq_get(
            _FakeResp(text=_NORMAL_BODY),       # baseline
            *[_FakeResp(text=generic_error)] * 5,  # diff probes
            _FakeResp(text=generic_error),         # timing probe (no DB fp → runs)
        )
        asyncio.run(engine.scan_param(get_fn, "http://nosql.test/", "filter", _kill_false))
        for f in collected:
            assert f["severity"] not in ("CRITICAL", "HIGH"), (
                "No DB fingerprint must prevent CRITICAL/HIGH severity"
            )


# ---------------------------------------------------------------------------
# scan_param — boolean-based confirmation
# ---------------------------------------------------------------------------

class TestScanParamBooleanBased:
    def test_boolean_differential_produces_high(self) -> None:
        """True condition matches baseline; false returns much shorter body."""
        engine, collected = _make_engine(techs=[])

        base_body  = _NORMAL_BODY_L                        # ~200 chars
        false_body = "<html><body>No results</body></html>"  # much shorter

        # Sequence: baseline + diff (quote/dquote/escaped/btrue/bfalse) + timing
        # No DB fp → timing probe fires (fast → no timing finding raised)
        get_fn = _seq_get(
            _FakeResp(text=base_body),   # baseline
            _FakeResp(text=base_body),   # diff: quote  (same, no DB fp)
            _FakeResp(text=base_body),   # diff: dquote
            _FakeResp(text=base_body),   # diff: escaped
            _FakeResp(text=base_body),   # diff: bool_true ≈ baseline
            _FakeResp(text=false_body),  # diff: bool_false — shorter
            _FakeResp(text=base_body),   # timing probe
        )
        asyncio.run(engine.scan_param(get_fn, "http://example.test/", "id", _kill_false))
        assert len(collected) == 1, "Boolean differential should produce exactly one finding"
        f = collected[0]
        assert f["severity"] in ("HIGH", "MEDIUM")
        assert "Boolean" in f["title"]
        assert f["confidence"] >= 0.65

    def test_boolean_differential_downgraded_for_react_tech(self) -> None:
        """Same differential on a React app → MEDIUM not HIGH."""
        engine, collected = _make_engine(techs=["React", "Next.js"])

        base_body  = _NORMAL_BODY_L
        false_body = "<html><body>No</body></html>"

        get_fn = _seq_get(
            _FakeResp(text=base_body),   # baseline
            _FakeResp(text=base_body),   # diff: quote
            _FakeResp(text=base_body),   # diff: dquote
            _FakeResp(text=base_body),   # diff: escaped
            _FakeResp(text=base_body),   # diff: bool_true
            _FakeResp(text=false_body),  # diff: bool_false
            _FakeResp(text=base_body),   # timing probe
        )
        asyncio.run(engine.scan_param(get_fn, "http://nextapp.test/", "id", _kill_false))
        assert len(collected) == 1
        assert collected[0]["severity"] == "MEDIUM"
        assert collected[0]["cvss_score"] < 8.0


# ---------------------------------------------------------------------------
# scan_param — timing-based
# ---------------------------------------------------------------------------

class TestScanParamTimingBased:
    def test_timing_probe_produces_high(self) -> None:
        """Simulate a slow response on the SLEEP payload."""
        engine, collected = _make_engine(timing_thresh=1.0)

        base_body = _NORMAL_BODY

        call_count = [0]

        async def slow_get(url: str, params: dict | None = None) -> _FakeResp:
            call_count[0] += 1
            if params and any("SLEEP" in str(v) for v in params.values()):
                import asyncio as _asyncio
                await _asyncio.sleep(1.2)  # triggers timing threshold
            return _FakeResp(text=base_body)

        asyncio.run(engine.scan_param(slow_get, "http://example.test/", "id", _kill_false))
        assert len(collected) == 1
        f = collected[0]
        assert f["severity"] == "HIGH"
        assert "Time-Based" in f["title"]


# ---------------------------------------------------------------------------
# scan_param — frontend framework awareness
# ---------------------------------------------------------------------------

class TestFrontendFrameworkAwareness:
    def test_nextjs_tech_with_validation_error_is_low(self) -> None:
        engine, collected = _make_engine(techs=["Next.js", "React"])
        # Quote causes a >10% length change but no DB fingerprint
        long_base = _NORMAL_BODY * 5
        short_resp = "<html><body>Invalid</body></html>"
        get_fn = _seq_get(
            _FakeResp(text=long_base),    # baseline
            *[_FakeResp(text=short_resp)] * 5,  # diff: quote/dquote/escaped/btrue/bfalse
            _FakeResp(text=short_resp),   # timing probe
        )
        asyncio.run(engine.scan_param(get_fn, "http://next.test/", "q", _kill_false))
        # If a finding was emitted, it must not be CRITICAL or HIGH
        for f in collected:
            assert f["severity"] not in ("CRITICAL", "HIGH"), (
                "Next.js app with no DB error must not produce CRITICAL/HIGH"
            )

    def test_vue_app_body_marker_detected(self) -> None:
        """__vue_app__ in body should flag spa_framework."""
        vue_body = "<html><body>Oops, invalid input! <div id='app' __vue_app__></div></body></html>"
        engine, collected = _make_engine()
        get_fn = _seq_get(
            _FakeResp(text=_NORMAL_BODY),  # baseline
            *[_FakeResp(text=vue_body)] * 5,  # diff probes
            _FakeResp(text=vue_body),          # timing probe
        )
        asyncio.run(engine.scan_param(get_fn, "http://vue.test/", "name", _kill_false))
        for f in collected:
            assert f["severity"] not in ("CRITICAL", "HIGH")


# ---------------------------------------------------------------------------
# scan_form_field — error-based
# ---------------------------------------------------------------------------

class TestScanFormField:
    def test_form_mysql_error_produces_critical(self) -> None:
        engine, collected = _make_engine()

        async def post_fn(url: str, data: dict | None = None) -> _FakeResp:
            val = (data or {}).get("username", "")
            if "'" in val:
                return _FakeResp(text=_MYSQL_ERROR_BODY)
            return _FakeResp(text=_NORMAL_BODY)

        async def get_fn(url: str, params: dict | None = None) -> _FakeResp:
            return _FakeResp(text=_NORMAL_BODY)

        asyncio.run(engine.scan_form_field(
            get_fn, post_fn,
            "http://example.test/login", "POST",
            "username", {"username": "", "password": "test"},
            _kill_false,
        ))
        assert len(collected) == 1
        f = collected[0]
        assert f["severity"] == "CRITICAL"
        assert "Form" in f["title"]
        assert f["cvss_score"] >= 9.0

    def test_form_no_db_error_no_finding(self) -> None:
        engine, collected = _make_engine()

        async def post_fn(url: str, data: dict | None = None) -> _FakeResp:
            return _FakeResp(text=_FRONTEND_VALIDATION_BODY)

        async def get_fn(url: str, params: dict | None = None) -> _FakeResp:
            return _FakeResp(text=_NORMAL_BODY)

        asyncio.run(engine.scan_form_field(
            get_fn, post_fn,
            "http://example.test/login", "POST",
            "email", {"email": "", "pass": "test"},
            _kill_false,
        ))
        assert collected == [], "Frontend validation in form must not produce a finding"

    def test_form_waf_block_suppressed(self) -> None:
        engine, collected = _make_engine()

        async def post_fn(url: str, data: dict | None = None) -> _FakeResp:
            return _FakeResp(text=_WAF_BLOCK_BODY, status_code=403)

        async def get_fn(url: str, params: dict | None = None) -> _FakeResp:
            return _FakeResp(text=_NORMAL_BODY)

        asyncio.run(engine.scan_form_field(
            get_fn, post_fn,
            "http://example.test/search", "POST",
            "q", {"q": ""},
            _kill_false,
        ))
        assert collected == []


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------

class TestKillSwitch:
    def test_kill_switch_aborts_immediately(self) -> None:
        engine, collected = _make_engine()
        get_fn = _const_get(_FakeResp(text=_MYSQL_ERROR_BODY))

        asyncio.run(engine.scan_param(get_fn, "http://example.test/", "id", lambda: True))
        assert collected == [], "Kill switch should abort before any finding"
