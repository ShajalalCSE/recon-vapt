"""
tests/unit/test_validation_agent.py
=====================================
Unit tests for modules/web_validation_agent.py

Coverage:
  XSSValidator        — script / attribute / URL / HTML-body contexts
  CSRFValidator       — tokenless POST outcomes (200/403/302-login/302-ok)
  HeaderFindingValidator — HSTS / X-Frame / X-Content-Type / Referrer / Permissions
  SensitiveFileValidator — robots.txt / credentials / git / bare 200
  FindingValidator    — HTTP 500, WAF block, confidence gate
  CachePoisoningValidator — no-cache / no-reflect / reflect-only / full-confirm
  DVWAEnumerator      — detection, login, enumeration
  WebValidationAgent  — routing, _merge_outcome, POTENTIAL label, DVWA pass-through
  _merge_outcome      — exploit_status, comparison_result, severity downgrade
"""

from __future__ import annotations

import asyncio
import sys
import types
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Stubs — keep imports independent of httpx / yaml
# ---------------------------------------------------------------------------

def _ensure_stubs() -> None:
    for name in ("httpx", "yaml"):
        if name not in sys.modules:
            sys.modules[name] = types.ModuleType(name)

    if "modules.web_vapt_engine" not in sys.modules:
        mod = types.ModuleType("modules.web_vapt_engine")

        class _RL:
            CRITICAL = "CRITICAL"
            HIGH     = "HIGH"
            MEDIUM   = "MEDIUM"
            LOW      = "LOW"
            INFO     = "INFO"

            def __init__(self, v="MEDIUM"):
                self.value = v

            def __eq__(self, other):
                return (
                    (isinstance(other, _RL) and self.value == other.value)
                    or self.value == other
                )

            # Must return the raw value string so str(severity) == "HIGH" etc.,
            # which matches what test_sqli_engine.py expects from its own stub.
            def __str__(self):
                return self.value

            def __repr__(self):
                return self.value

        _RL.CRITICAL = _RL("CRITICAL")
        _RL.HIGH     = _RL("HIGH")
        _RL.MEDIUM   = _RL("MEDIUM")
        _RL.LOW      = _RL("LOW")
        _RL.INFO     = _RL("INFO")

        mod.WebRiskLevel = _RL  # type: ignore[attr-defined]

        @dataclass
        class _WF:
            id: str = "WEB-TEST"
            title: str = "test"
            severity: Any = field(default_factory=lambda: _RL.MEDIUM)
            confidence: float = 0.70
            endpoint: str = "http://lab/"
            parameter: str = "q"
            description: str = ""
            evidence: str = ""
            remediation: str = ""
            cwe: str = "CWE-0"
            owasp: str = ""
            references: list = field(default_factory=list)
            cvss_score: float = 5.0
            timestamp: float = 0.0
            module: str = "general"
            proof_of_concept: str = ""
            confidence_pct: int = 0
            validation_status: str = "potential"
            raw_request: str = ""
            raw_response_excerpt: str = ""
            reproduction_steps: list = field(default_factory=list)
            validation_logic: str = ""
            fp_checks_performed: list = field(default_factory=list)
            exploitability: str = ""
            exploit_status: str = "UNVERIFIED"
            comparison_result: str = ""

        mod.WebFinding = _WF  # type: ignore[attr-defined]
        sys.modules["modules.web_vapt_engine"] = mod


_ensure_stubs()

from modules.web_validation_agent import (  # noqa: E402
    CONFIDENCE_INSUFFICIENT,
    CONFIDENCE_MODERATE,
    CONFIDENCE_STRONG,
    CONFIDENCE_VERIFIED,
    CONFIDENCE_WEAK,
    CachePoisoningValidator,
    CSRFValidator,
    DVWAEnumerator,
    FindingValidator,
    HeaderFindingValidator,
    SensitiveFileValidator,
    ValidationOutcome,
    WebValidationAgent,
    XSSValidator,
    _downgrade_severity,
    _merge_outcome,
)

WebFinding  = sys.modules["modules.web_vapt_engine"].WebFinding
WebRiskLevel = sys.modules["modules.web_vapt_engine"].WebRiskLevel

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(**kwargs) -> Any:
    """Create a WebFinding-like object with sensible defaults."""
    defaults = dict(
        id="WEB-TEST", title="test finding",
        severity=WebRiskLevel.MEDIUM, confidence=0.70,
        endpoint="http://lab/test", parameter="q",
        description="", evidence="", remediation="",
        cwe="CWE-0", owasp="", references=[],
        cvss_score=5.0, timestamp=0.0, module="general",
        proof_of_concept="", confidence_pct=0,
        validation_status="potential", raw_request="",
        raw_response_excerpt="", reproduction_steps=[],
        validation_logic="", fp_checks_performed=[],
        exploitability="", exploit_status="UNVERIFIED",
        comparison_result="",
    )
    defaults.update(kwargs)
    return WebFinding(**defaults)


class _Resp:
    """Fake httpx.Response."""
    def __init__(self, status_code: int = 200, text: str = "", headers: dict | None = None):
        self.status_code = status_code
        self.text        = text
        self.headers     = headers or {}


def _const_get(resp: _Resp):
    async def _get(url, headers=None, params=None):
        return resp
    return _get


def _seq_get(*responses):
    calls = list(responses)
    async def _get(url, headers=None, params=None):
        return calls.pop(0) if calls else None
    return _get


def _const_post(resp: _Resp):
    async def _post(url, data=None, json_=None, headers=None):
        return resp
    return _post


# ===========================================================================
# XSSValidator
# ===========================================================================

class TestXSSValidator:

    def _val(self, evidence, **kw) -> ValidationOutcome:
        f = _finding(module="xss", title="Reflected XSS", evidence=evidence, **kw)
        return XSSValidator().validate(f)

    def test_script_context_is_confirmed(self):
        o = self._val("Marker found unencoded in JavaScript context")
        assert o.exploit_status    == "CONFIRMED"
        assert o.validation_status == "confirmed"
        assert o.confidence_pct    >= CONFIDENCE_STRONG

    def test_script_context_no_downgrade(self):
        o = self._val("Marker found unencoded in JavaScript context")
        assert o.downgraded_severity is None

    def test_html_attribute_context_is_unverified(self):
        o = self._val("Marker found unencoded in HTML attribute context")
        assert o.exploit_status    == "UNVERIFIED"
        assert o.validation_status == "potential"
        assert o.confidence_pct    == CONFIDENCE_MODERATE

    def test_html_attribute_context_not_downgraded(self):
        o = self._val("Marker found unencoded in HTML attribute context")
        assert o.downgraded_severity is None

    def test_url_attribute_context_is_unverified(self):
        o = self._val("Marker found unencoded in URL attribute context")
        assert o.exploit_status    == "UNVERIFIED"
        assert o.validation_status == "potential"

    def test_html_body_context_downgraded_to_low(self):
        o = self._val("Marker found unencoded in HTML body context")
        assert o.exploit_status       == "UNVERIFIED"
        assert o.downgraded_severity  == "LOW"
        assert o.confidence_pct       == CONFIDENCE_WEAK

    def test_html_body_context_stays_potential(self):
        o = self._val("Marker found unencoded in HTML body context")
        assert o.validation_status == "potential"

    def test_unknown_context_defaults_to_body_rules(self):
        o = self._val("Marker '<xss123>' reflected in page")
        assert o.exploit_status    == "UNVERIFIED"
        assert o.downgraded_severity == "LOW"

    def test_comparison_result_preserved_from_finding(self):
        o = self._val(
            "Marker found in JavaScript context",
            comparison_result="Baseline: clean. Attack: reflected."
        )
        assert "Baseline" in o.comparison_result

    def test_comparison_result_built_from_evidence_when_empty(self):
        o = self._val("Marker found unencoded in HTML body context")
        assert len(o.comparison_result) > 0

    def test_raw_request_populated(self):
        o = self._val("Marker in HTML body context")
        assert "http://lab/test" in o.raw_request

    def test_reproduction_steps_provided(self):
        o = self._val("Marker in JavaScript context")
        assert len(o.reproduction_steps) >= 2

    def test_form_xss_body_context_also_downgraded(self):
        f = _finding(
            module="xss",
            title="Reflected XSS via Form — username",
            evidence="Marker '<xssABCD>' returned unencoded in HTML body context via form",
        )
        o = XSSValidator().validate(f)
        assert o.downgraded_severity == "LOW"
        assert o.exploit_status      == "UNVERIFIED"


# ===========================================================================
# CSRFValidator
# ===========================================================================

class TestCSRFValidator:

    def _f(self, **kw):
        defaults = dict(
            module="csrf",
            title="Missing CSRF Token — http://lab/change-pass",
            endpoint="http://lab/change-pass",
            evidence=(
                "POST form at 'http://lab/change-pass' has no CSRF token field. "
                "Fields: ['new_password', 'confirm_password']"
            ),
            comparison_result="no token found",
        )
        defaults.update(kw)
        return _finding(**defaults)

    @pytest.mark.asyncio
    async def test_no_post_fn_returns_potential(self):
        v = CSRFValidator(get_fn=None, post_fn=None, kill_fn=lambda: False)
        o = await v.validate(self._f())
        assert o.validation_status == "potential"
        assert o.exploit_status    == "UNVERIFIED"
        assert "no_http_client" in o.fp_checks_performed

    @pytest.mark.asyncio
    async def test_200_no_rejection_keyword_confirmed(self):
        post = _const_post(_Resp(200, "<html>Password changed successfully</html>"))
        v    = CSRFValidator(get_fn=None, post_fn=post, kill_fn=lambda: False)
        o    = await v.validate(self._f())
        assert o.exploit_status    == "CONFIRMED"
        assert o.validation_status == "confirmed"
        assert o.confidence_pct    >= CONFIDENCE_STRONG

    @pytest.mark.asyncio
    async def test_200_with_csrf_rejection_in_body_is_info(self):
        post = _const_post(_Resp(200, "Invalid CSRF token. Access forbidden."))
        v    = CSRFValidator(get_fn=None, post_fn=post, kill_fn=lambda: False)
        o    = await v.validate(self._f())
        assert o.exploit_status       == "UNVERIFIED"
        assert o.validation_status    in ("informational", "potential")
        assert "body_contains_csrf_rejection" in o.fp_checks_performed

    @pytest.mark.asyncio
    async def test_403_response_rejected_as_info(self):
        post = _const_post(_Resp(403, "Forbidden"))
        v    = CSRFValidator(get_fn=None, post_fn=post, kill_fn=lambda: False)
        o    = await v.validate(self._f())
        assert o.exploit_status      == "UNVERIFIED"
        assert o.validation_status   in ("informational", "potential")
        assert o.downgraded_severity == "LOW"

    @pytest.mark.asyncio
    async def test_302_to_login_is_info(self):
        post = _const_post(_Resp(302, "", {"location": "/login.php"}))
        v    = CSRFValidator(get_fn=None, post_fn=post, kill_fn=lambda: False)
        o    = await v.validate(self._f())
        assert o.exploit_status    == "UNVERIFIED"
        assert o.validation_status in ("informational", "potential")

    @pytest.mark.asyncio
    async def test_302_to_non_login_is_potential(self):
        post = _const_post(_Resp(302, "", {"location": "/dashboard"}))
        v    = CSRFValidator(get_fn=None, post_fn=post, kill_fn=lambda: False)
        o    = await v.validate(self._f())
        assert o.exploit_status    == "UNVERIFIED"
        assert o.validation_status == "potential"
        assert o.confidence_pct    == CONFIDENCE_MODERATE

    @pytest.mark.asyncio
    async def test_none_response_returns_potential(self):
        async def _fail(url, data=None, json_=None, headers=None):
            return None
        v = CSRFValidator(get_fn=None, post_fn=_fail, kill_fn=lambda: False)
        o = await v.validate(self._f())
        assert o.validation_status == "potential"
        assert o.exploit_status    == "UNVERIFIED"

    @pytest.mark.asyncio
    async def test_field_names_extracted_from_evidence(self):
        # Verify the POST data uses field names parsed from evidence
        posted_data = {}
        async def _capture_post(url, data=None, json_=None, headers=None):
            posted_data.update(data or {})
            return _Resp(200, "OK")
        v = CSRFValidator(get_fn=None, post_fn=_capture_post, kill_fn=lambda: False)
        await v.validate(self._f())
        assert "new_password" in posted_data
        assert "confirm_password" in posted_data

    @pytest.mark.asyncio
    async def test_comparison_result_set_on_confirm(self):
        post = _const_post(_Resp(200, "Password changed!"))
        v    = CSRFValidator(get_fn=None, post_fn=post, kill_fn=lambda: False)
        o    = await v.validate(self._f())
        assert "tokenless" in o.comparison_result.lower() or "HTTP 200" in o.comparison_result


# ===========================================================================
# HeaderFindingValidator
# ===========================================================================

class TestHeaderFindingValidator:

    def _val(self, param, severity="HIGH", **kw) -> ValidationOutcome:
        f = _finding(
            module="header",
            title=f"Missing {param} Header",
            severity=WebRiskLevel.HIGH if severity == "HIGH" else WebRiskLevel.MEDIUM,
            parameter=param,
            **kw,
        )
        return HeaderFindingValidator().validate(f)

    def test_hsts_high_downgraded_to_medium(self):
        o = self._val("strict-transport-security", severity="HIGH")
        assert o.downgraded_severity == "MEDIUM"
        assert o.exploit_status      == "UNVERIFIED"

    def test_x_content_type_options_downgraded_to_low(self):
        o = self._val("x-content-type-options", severity="MEDIUM")
        assert o.downgraded_severity == "LOW"

    def test_referrer_policy_downgraded_to_low(self):
        o = self._val("referrer-policy", severity="MEDIUM")
        assert o.downgraded_severity == "LOW"

    def test_permissions_policy_downgraded_to_low(self):
        o = self._val("permissions-policy", severity="MEDIUM")
        assert o.downgraded_severity == "LOW"

    def test_x_xss_protection_downgraded_to_low(self):
        o = self._val("x-xss-protection", severity="MEDIUM")
        assert o.downgraded_severity == "LOW"

    def test_x_frame_options_not_downgraded(self):
        # Clickjacking is a real risk — X-Frame-Options should not be suppressed
        o = self._val("x-frame-options", severity="MEDIUM")
        assert o.downgraded_severity is None

    def test_all_header_findings_are_unverified(self):
        for param in ("strict-transport-security", "x-content-type-options",
                      "referrer-policy", "permissions-policy", "x-frame-options"):
            o = self._val(param)
            assert o.exploit_status == "UNVERIFIED", f"Expected UNVERIFIED for {param}"

    def test_comparison_result_describes_absence(self):
        o = self._val("strict-transport-security")
        assert "absent" in o.comparison_result.lower() or "header" in o.comparison_result.lower()

    def test_validation_logic_cites_rule7(self):
        o = self._val("referrer-policy")
        assert "Rule 7" in o.validation_logic or "rule 7" in o.validation_logic.lower()


# ===========================================================================
# SensitiveFileValidator
# ===========================================================================

class TestSensitiveFileValidator:

    def _val(self, endpoint, evidence="HTTP 200", **kw) -> ValidationOutcome:
        f = _finding(
            module="sensitive_file",
            title=f"Sensitive File Exposed — {endpoint}",
            endpoint=endpoint,
            evidence=evidence,
            **kw,
        )
        return SensitiveFileValidator().validate(f)

    def test_robots_txt_downgraded_to_info(self):
        o = self._val("http://lab/robots.txt")
        assert o.downgraded_severity == "INFO"
        assert o.validation_status   == "informational"

    def test_robots_txt_is_unverified(self):
        o = self._val("http://lab/robots.txt")
        assert o.exploit_status == "UNVERIFIED"

    def test_credentials_in_evidence_confirmed_critical(self):
        o = self._val(
            "http://lab/.env",
            evidence="HTTP 200 ... DB_PASSWORD=supersecret AWS_SECRET=key123",
        )
        assert o.exploit_status    == "CONFIRMED"
        assert o.validation_status == "confirmed"
        assert o.confidence_pct    == CONFIDENCE_VERIFIED

    def test_api_key_in_evidence_confirmed(self):
        o = self._val(
            "http://lab/config.php",
            evidence="HTTP 200 ... API_KEY=abc123xyz",
        )
        assert o.exploit_status == "CONFIRMED"

    def test_git_metadata_confirmed_high(self):
        o = self._val("http://lab/.git/config")
        assert o.exploit_status    == "CONFIRMED"
        assert o.validation_status == "confirmed"
        assert o.confidence_pct    >= CONFIDENCE_STRONG

    def test_bare_200_no_content_is_potential_low(self):
        o = self._val("http://lab/backup.sql", evidence="HTTP 200 for http://lab/backup.sql")
        assert o.exploit_status      == "UNVERIFIED"
        assert o.validation_status   == "potential"
        # Should NOT be CONFIRMED or CRITICAL without evidence
        assert o.exploit_status != "CONFIRMED"

    def test_comparison_result_describes_endpoint(self):
        o = self._val("http://lab/.env")
        assert "lab" in o.comparison_result.lower() or ".env" in o.comparison_result

    def test_fp_check_recorded(self):
        o = self._val("http://lab/robots.txt")
        assert "robots_txt_informational" in o.fp_checks_performed


# ===========================================================================
# FindingValidator (general)
# ===========================================================================

class TestFindingValidator:

    def test_http500_sqli_downgraded_to_medium(self):
        f = _finding(
            module="sqli",
            title="SQL Injection — id",
            severity=WebRiskLevel.HIGH,
            confidence=0.80,
            evidence="<title> 500 Internal Server Error </title>",
        )
        o = FindingValidator().validate(f)
        assert o.downgraded_severity == "MEDIUM"
        assert o.exploit_status      == "UNVERIFIED"
        assert "http500_not_sqli_evidence" in o.fp_checks_performed

    def test_waf_block_downgraded_to_info(self):
        f = _finding(
            module="sqli",
            title="SQL Injection — id",
            severity=WebRiskLevel.HIGH,
            confidence=0.90,
            evidence="Attention Required! | Cloudflare request blocked",
        )
        o = FindingValidator().validate(f)
        assert o.downgraded_severity == "INFO"
        assert o.validation_status   == "informational"
        assert "waf_block_detected"  in o.fp_checks_performed

    def test_high_confidence_finding_confirmed(self):
        f = _finding(
            module="sqli",
            title="SQL Injection — id",
            severity=WebRiskLevel.CRITICAL,
            confidence=0.95,
            evidence="you have an error in your SQL syntax",
        )
        o = FindingValidator().validate(f)
        assert o.validation_status == "confirmed"
        assert o.exploit_status    == "CONFIRMED"

    def test_low_confidence_finding_stays_potential(self):
        f = _finding(
            module="sqli",
            title="SQL Injection — id",
            severity=WebRiskLevel.CRITICAL,
            confidence=0.30,   # below 80% threshold for CRITICAL
        )
        o = FindingValidator().validate(f)
        assert o.validation_status == "potential"

    def test_comparison_result_falls_back_to_evidence(self):
        f = _finding(evidence="some evidence text")
        o = FindingValidator().validate(f)
        assert len(o.comparison_result) > 0


# ===========================================================================
# _downgrade_severity helper
# ===========================================================================

class TestDowngradeSeverity:
    def test_critical_to_high(self):
        assert _downgrade_severity("CRITICAL") == "HIGH"

    def test_high_to_medium(self):
        assert _downgrade_severity("HIGH") == "MEDIUM"

    def test_medium_to_low(self):
        assert _downgrade_severity("MEDIUM") == "LOW"

    def test_low_to_info(self):
        assert _downgrade_severity("LOW") == "INFO"

    def test_info_stays_info(self):
        assert _downgrade_severity("INFO") == "INFO"

    def test_unknown_returns_low(self):
        assert _downgrade_severity("UNKNOWN") == "LOW"


# ===========================================================================
# _merge_outcome
# ===========================================================================

class TestMergeOutcome:

    def test_exploit_status_written(self):
        f = _finding()
        o = ValidationOutcome(exploit_status="CONFIRMED")
        _merge_outcome(f, o)
        assert f.exploit_status == "CONFIRMED"

    def test_comparison_result_written(self):
        f = _finding()
        o = ValidationOutcome(comparison_result="Baseline vs attack diff here")
        _merge_outcome(f, o)
        assert f.comparison_result == "Baseline vs attack diff here"

    def test_comparison_result_not_overwritten_by_empty(self):
        f = _finding(comparison_result="original diff")
        o = ValidationOutcome(comparison_result="")
        _merge_outcome(f, o)
        assert f.comparison_result == "original diff"

    def test_severity_downgrade_applied(self):
        f = _finding(severity=WebRiskLevel.HIGH)
        o = ValidationOutcome(downgraded_severity="LOW", downgrade_reason="test")
        _merge_outcome(f, o)
        assert f.severity == WebRiskLevel.LOW

    def test_potential_label_added_when_potential(self):
        f = _finding(title="Reflected XSS")
        o = ValidationOutcome(validation_status="potential", exploit_status="UNVERIFIED")
        _merge_outcome(f, o)
        assert "POTENTIAL ISSUE" in f.title.upper()

    def test_no_potential_label_when_confirmed(self):
        f = _finding(title="SQL Injection")
        o = ValidationOutcome(validation_status="confirmed", exploit_status="CONFIRMED")
        _merge_outcome(f, o)
        assert "POTENTIAL ISSUE" not in f.title.upper()

    def test_potential_label_not_duplicated(self):
        f = _finding(title="[POTENTIAL ISSUE — MANUAL VALIDATION REQUIRED] XSS")
        o = ValidationOutcome(validation_status="potential")
        _merge_outcome(f, o)
        assert f.title.count("POTENTIAL ISSUE") == 1

    def test_confidence_pct_written(self):
        f = _finding()
        o = ValidationOutcome(confidence_pct=87)
        _merge_outcome(f, o)
        assert f.confidence_pct == 87

    def test_fp_checks_written(self):
        f = _finding()
        o = ValidationOutcome(fp_checks_performed=["check_a", "check_b"])
        _merge_outcome(f, o)
        assert "check_a" in f.fp_checks_performed


# ===========================================================================
# CachePoisoningValidator (async)
# ===========================================================================

class TestCachePoisoningValidator:

    @pytest.mark.asyncio
    async def test_not_cacheable_returns_informational(self):
        resp = _Resp(200, "hello", {"cache-control": "private, no-store"})
        v    = CachePoisoningValidator(get_fn=_const_get(resp), kill_fn=lambda: False)
        o    = await v.validate("http://lab/", "X-Forwarded-Host", "evil.com")
        assert o.validation_status == "informational"
        assert o.exploit_status    == "UNVERIFIED"
        assert "no_cache_infra_detected" in o.fp_checks_performed

    @pytest.mark.asyncio
    async def test_no_reflection_returns_informational(self):
        baseline  = _Resp(200, "normal page", {"cache-control": "public, max-age=300"})
        poisoned  = _Resp(200, "normal page no reflection here")
        v = CachePoisoningValidator(
            get_fn=_seq_get(baseline, poisoned),
            kill_fn=lambda: False,
        )
        o = await v.validate("http://lab/", "X-Forwarded-Host", "evil.com")
        assert o.validation_status == "informational"
        assert "not_reflected" in " ".join(o.fp_checks_performed)

    @pytest.mark.asyncio
    async def test_reflection_no_persistence_is_informational(self):
        baseline  = _Resp(200, "page",  {"cache-control": "public, max-age=300"})
        poisoned  = _Resp(200, "page evil.com was here")
        clean     = _Resp(200, "page clean no evil")
        v = CachePoisoningValidator(
            get_fn=_seq_get(baseline, poisoned, clean),
            kill_fn=lambda: False,
        )
        o = await v.validate("http://lab/", "X-Forwarded-Host", "evil.com")
        assert o.validation_status == "informational"
        assert o.exploit_status    == "UNVERIFIED"
        assert "poison_not_confirmed_in_clean_request" in o.fp_checks_performed

    @pytest.mark.asyncio
    async def test_full_confirm_returns_confirmed(self):
        baseline = _Resp(200, "page", {"cache-control": "public, max-age=300"})
        poisoned = _Resp(200, "page evil.com injected")
        clean    = _Resp(200, "page evil.com from cache", {"cf-cache-status": "HIT"})
        v = CachePoisoningValidator(
            get_fn=_seq_get(baseline, poisoned, clean),
            kill_fn=lambda: False,
        )
        o = await v.validate("http://lab/", "X-Forwarded-Host", "evil.com")
        assert o.validation_status == "confirmed"
        assert o.exploit_status    == "CONFIRMED"
        assert o.confidence_pct    == CONFIDENCE_VERIFIED

    @pytest.mark.asyncio
    async def test_reflection_no_cache_hit_is_potential_low(self):
        baseline = _Resp(200, "page", {"cache-control": "public, max-age=300"})
        poisoned = _Resp(200, "page evil.com injected")
        clean    = _Resp(200, "page evil.com still here")  # no HIT header
        v = CachePoisoningValidator(
            get_fn=_seq_get(baseline, poisoned, clean),
            kill_fn=lambda: False,
        )
        o = await v.validate("http://lab/", "X-Forwarded-Host", "evil.com")
        assert o.validation_status   in ("potential", "informational")
        assert o.exploit_status      == "UNVERIFIED"

    @pytest.mark.asyncio
    async def test_baseline_failure_returns_gracefully(self):
        async def _fail(url, headers=None, params=None):
            return None
        v = CachePoisoningValidator(get_fn=_fail, kill_fn=lambda: False)
        o = await v.validate("http://lab/", "X-Forwarded-Host", "evil.com")
        assert "baseline_unreachable" in o.fp_checks_performed


# ===========================================================================
# DVWAEnumerator
# ===========================================================================

class TestDVWAEnumerator:

    _DVWA_PAGE = (
        "<html><body>"
        "<h1>Damn Vulnerable Web Application</h1>"
        "<div class='dvwaPage'>DVWA Security</div>"
        "</body></html>"
    )

    @pytest.mark.asyncio
    async def test_is_dvwa_detects_marker(self):
        resp = _Resp(200, self._DVWA_PAGE)
        e    = DVWAEnumerator(get_fn=_const_get(resp), post_fn=None, kill_fn=lambda: False)
        assert await e.is_dvwa("http://192.168.0.101/dvwa") is True

    @pytest.mark.asyncio
    async def test_is_dvwa_false_for_non_dvwa_page(self):
        resp = _Resp(200, "<html><body>Normal corporate website</body></html>")
        e    = DVWAEnumerator(get_fn=_const_get(resp), post_fn=None, kill_fn=lambda: False)
        assert await e.is_dvwa("http://example.com") is False

    @pytest.mark.asyncio
    async def test_is_dvwa_false_when_no_get_fn(self):
        e = DVWAEnumerator(get_fn=None, post_fn=None, kill_fn=lambda: False)
        assert await e.is_dvwa("http://192.168.0.101/dvwa") is False

    @pytest.mark.asyncio
    async def test_enumerate_returns_empty_for_non_dvwa(self):
        resp = _Resp(200, "<html><body>Corporate intranet portal</body></html>")
        e    = DVWAEnumerator(get_fn=_const_get(resp), post_fn=None, kill_fn=lambda: False)
        result = await e.enumerate("http://example.com")
        assert result == []

    @pytest.mark.asyncio
    async def test_enumerate_returns_findings_for_dvwa(self):
        # First call: is_dvwa check (login.php page) → DVWA detected
        # Subsequent calls: module paths → all return DVWA page with 200
        call_count = [0]
        async def _get(url, headers=None, params=None):
            call_count[0] += 1
            return _Resp(200, self._DVWA_PAGE)

        async def _post(url, data=None, json_=None, headers=None):
            return _Resp(302, "", {"location": "/dvwa/index.php"})

        e      = DVWAEnumerator(get_fn=_get, post_fn=_post, kill_fn=lambda: False)
        result = await e.enumerate("http://192.168.0.101/dvwa")
        assert len(result) >= 1
        assert all(getattr(f, "exploit_status", "") == "CONFIRMED" for f in result)

    @pytest.mark.asyncio
    async def test_enumerate_finding_titles_contain_module_name(self):
        async def _get(url, headers=None, params=None):
            return _Resp(200, self._DVWA_PAGE)
        async def _post(url, data=None, json_=None, headers=None):
            return _Resp(302, "", {"location": "/dvwa/index.php"})

        e      = DVWAEnumerator(get_fn=_get, post_fn=_post, kill_fn=lambda: False)
        result = await e.enumerate("http://192.168.0.101/dvwa")
        titles = [getattr(f, "title", "") for f in result]
        assert any("sqli" in t.lower() or "DVWA" in t for t in titles)

    @pytest.mark.asyncio
    async def test_enumerate_respects_kill_switch(self):
        calls = [0]
        async def _get(url, headers=None, params=None):
            calls[0] += 1
            return _Resp(200, self._DVWA_PAGE)

        killed = [False]
        def _kill():
            # Kill after login phase
            if calls[0] > 5:
                killed[0] = True
            return killed[0]

        e      = DVWAEnumerator(get_fn=_get, post_fn=None, kill_fn=_kill)
        result = await e.enumerate("http://192.168.0.101/dvwa")
        # Should stop early — fewer than 6 findings
        assert len(result) < 6

    @pytest.mark.asyncio
    async def test_enumerate_sets_validation_status_confirmed(self):
        async def _get(url, headers=None, params=None):
            return _Resp(200, self._DVWA_PAGE)
        async def _post(url, data=None, json_=None, headers=None):
            return _Resp(302, "", {"location": "/dvwa/index.php"})

        e      = DVWAEnumerator(get_fn=_get, post_fn=_post, kill_fn=lambda: False)
        result = await e.enumerate("http://192.168.0.101/dvwa")
        for f in result:
            assert getattr(f, "validation_status", "") == "confirmed"


# ===========================================================================
# WebValidationAgent routing
# ===========================================================================

class TestWebValidationAgentRouting:

    @pytest.mark.asyncio
    async def test_xss_finding_routed_to_xss_validator(self):
        f = _finding(
            module="xss",
            title="Reflected XSS — q",
            evidence="Marker found in JavaScript context",
        )
        agent  = WebValidationAgent(kill_fn=lambda: False)
        result = await agent.validate_all([f], surface=None)
        assert result[0].exploit_status    == "CONFIRMED"
        assert result[0].validation_status == "confirmed"

    @pytest.mark.asyncio
    async def test_xss_body_finding_downgraded_to_low(self):
        f = _finding(
            module="xss",
            title="Reflected XSS — q",
            evidence="Marker found in HTML body context",
        )
        agent  = WebValidationAgent(kill_fn=lambda: False)
        result = await agent.validate_all([f], surface=None)
        assert result[0].exploit_status == "UNVERIFIED"
        assert result[0].severity == WebRiskLevel.LOW

    @pytest.mark.asyncio
    async def test_csrf_finding_routed_to_csrf_validator(self):
        f = _finding(
            module="csrf",
            title="Missing CSRF Token — http://lab/change",
            endpoint="http://lab/change",
            evidence="POST form at 'http://lab/change' has no CSRF token field. Fields: ['pwd']",
        )
        post   = _const_post(_Resp(403, "Forbidden"))
        agent  = WebValidationAgent(post_fn=post, kill_fn=lambda: False)
        result = await agent.validate_all([f], surface=None)
        assert result[0].exploit_status == "UNVERIFIED"

    @pytest.mark.asyncio
    async def test_header_finding_routed_to_header_validator(self):
        f = _finding(
            module="header",
            title="Missing strict-transport-security Header",
            parameter="strict-transport-security",
            severity=WebRiskLevel.HIGH,
        )
        agent  = WebValidationAgent(kill_fn=lambda: False)
        result = await agent.validate_all([f], surface=None)
        # Should be downgraded from HIGH to MEDIUM
        assert result[0].severity == WebRiskLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_sensitive_file_routed_to_sensitive_file_validator(self):
        f = _finding(
            module="sensitive_file",
            title="Sensitive File Exposed — /robots.txt",
            endpoint="http://lab/robots.txt",
            evidence="HTTP 200 for http://lab/robots.txt",
        )
        agent  = WebValidationAgent(kill_fn=lambda: False)
        result = await agent.validate_all([f], surface=None)
        assert result[0].severity == WebRiskLevel.INFO

    @pytest.mark.asyncio
    async def test_dvwa_findings_pass_through_unchanged(self):
        """DVWAEnumerator pre-validates findings — agent must not re-validate them."""
        f = _finding(
            module="dvwa_sqli",
            title="DVWA Module Accessible — sqli",
            exploit_status="CONFIRMED",
            validation_status="confirmed",
        )
        agent  = WebValidationAgent(kill_fn=lambda: False)
        result = await agent.validate_all([f], surface=None)
        assert result[0].exploit_status    == "CONFIRMED"
        assert result[0].validation_status == "confirmed"
        assert "POTENTIAL ISSUE" not in result[0].title.upper()

    @pytest.mark.asyncio
    async def test_kill_switch_stops_validation(self):
        findings = [_finding(title=f"finding {i}") for i in range(10)]
        killed   = [False]

        def _kill():
            killed[0] = True
            return True

        agent  = WebValidationAgent(kill_fn=_kill)
        result = await agent.validate_all(findings, surface=None)
        # First finding processed before kill triggered, rest aborted
        assert len(result) <= 1

    @pytest.mark.asyncio
    async def test_reproduction_steps_always_populated(self):
        f = _finding(module="general", title="Some Finding", evidence="some signal")
        agent  = WebValidationAgent(kill_fn=lambda: False)
        result = await agent.validate_all([f], surface=None)
        assert len(result[0].reproduction_steps) > 0

    @pytest.mark.asyncio
    async def test_multiple_findings_all_processed(self):
        findings = [
            _finding(module="xss",   title="Reflected XSS", evidence="HTML body context"),
            _finding(module="header", title="Missing Header", parameter="referrer-policy",
                     severity=WebRiskLevel.MEDIUM),
            _finding(module="sensitive_file", title="Exposed File",
                     endpoint="http://lab/robots.txt", evidence="HTTP 200"),
        ]
        agent  = WebValidationAgent(kill_fn=lambda: False)
        result = await agent.validate_all(findings, surface=None)
        assert len(result) == 3
        assert all(getattr(f, "exploit_status", None) is not None for f in result)

    @pytest.mark.asyncio
    async def test_csp_header_finding_not_routed_to_xss_validator(self):
        """'Missing Content-Security-Policy Header' has module=xss but should
        go through HeaderFindingValidator, not XSSValidator (title check)."""
        f = _finding(
            module="xss",
            title="Missing Content-Security-Policy Header",
            parameter="content-security-policy",
            severity=WebRiskLevel.MEDIUM,
        )
        agent  = WebValidationAgent(kill_fn=lambda: False)
        result = await agent.validate_all([f], surface=None)
        # CSP absence is a header issue — should not be CONFIRMED as an executed exploit
        assert result[0].exploit_status == "UNVERIFIED"
