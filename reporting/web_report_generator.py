"""
reporting/web_report_generator.py
==================================
AI Red Team Harness v3 — Web VAPT Report Generator

Produces multi-format security assessment reports from WebAssessmentResult:
  - JSON (machine-readable, full detail)
  - Markdown (human-readable with executive summary, findings, roadmap)
  - Risk summary dict (for programmatic consumption)
  - Remediation roadmap (prioritised action list)

All output is written to config.reporting.output_dir (default: reports/web/).

Python: 3.11+
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from utils.logger import get_logger

if TYPE_CHECKING:
    from modules.web_vapt_engine import WebAssessmentResult, WebFinding, WebRiskLevel

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Risk level ordering for sorting
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}

_SEVERITY_ICON: dict[str, str] = {
    "CRITICAL": "[CRIT]",
    "HIGH":     "[HIGH]",
    "MEDIUM":   "[MED] ",
    "LOW":      "[LOW] ",
    "INFO":     "[INFO]",
}

# Remediation priority mapped to OWASP category keywords
_OWASP_REMEDIATION_HINTS: dict[str, str] = {
    "Injection": (
        "Use parameterised queries / prepared statements. "
        "Apply strict input validation and output encoding."
    ),
    "Broken Access Control": (
        "Enforce server-side access controls on every endpoint. "
        "Implement least-privilege and deny-by-default policies."
    ),
    "Cryptographic Failures": (
        "Enforce TLS 1.2+ with HSTS. Rotate secrets regularly. "
        "Use strong, well-reviewed cryptographic algorithms."
    ),
    "Security Misconfiguration": (
        "Harden server configuration, remove debug/default pages, "
        "set security headers (CSP, X-Frame-Options, HSTS, etc.)."
    ),
    "Identification and Authentication Failures": (
        "Implement MFA, enforce strong password policies, "
        "use secure session management and token rotation."
    ),
    "Insecure Design": (
        "Adopt threat modelling during design. Restrict file upload "
        "types, sizes, and storage locations."
    ),
    "Software and Data Integrity Failures": (
        "Validate all deserialized inputs. Pin dependencies and "
        "verify integrity via checksums."
    ),
    "SSRF": (
        "Restrict outbound HTTP from the application. Whitelist "
        "allowed destinations and block cloud metadata endpoints."
    ),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _severity_bar(score: float, width: int = 12) -> str:
    filled = round((score / 10.0) * width)
    return "[" + "#" * filled + "-" * (width - filled) + f"] {score:.1f}"


def _truncate(text: str, max_len: int = 400) -> str:
    return text if len(text) <= max_len else text[:max_len] + "..."


def _sorted_findings(findings: list["WebFinding"]) -> list["WebFinding"]:
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER.get(f.severity.value, 9), -f.cvss_score))


# ---------------------------------------------------------------------------
# Risk Summary builder
# ---------------------------------------------------------------------------

def _build_risk_summary(result: "WebAssessmentResult") -> dict[str, Any]:
    s = result.summary
    findings = result.findings

    owasp_counts: dict[str, int] = {}
    cwe_counts:   dict[str, int] = {}
    for f in findings:
        owasp_counts[f.owasp] = owasp_counts.get(f.owasp, 0) + 1
        cwe_counts[f.cwe]     = cwe_counts.get(f.cwe, 0) + 1

    top_owasp = sorted(owasp_counts.items(), key=lambda x: -x[1])[:5]
    top_cwe   = sorted(cwe_counts.items(), key=lambda x: -x[1])[:5]

    return {
        "total_findings":     s.total_findings,
        "critical":           s.critical,
        "high":               s.high,
        "medium":             s.medium,
        "low":                s.low,
        "info":               s.info,
        "risk_score":         s.risk_score,
        "risk_label":         _risk_label(s.risk_score),
        "top_owasp":          [{"category": k, "count": v} for k, v in top_owasp],
        "top_cwe":            [{"cwe": k, "count": v} for k, v in top_cwe],
        "by_category":        s.by_category,
        "scan_duration_s":    s.scan_duration_seconds,
        "urls_scanned":       s.urls_scanned,
        "forms_tested":       s.forms_tested,
        "parameters_tested":  s.parameters_tested,
    }


def _risk_label(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFORMATIONAL"


# ---------------------------------------------------------------------------
# Executive Summary builder
# ---------------------------------------------------------------------------

def _build_executive_summary(result: "WebAssessmentResult") -> str:
    s     = result.summary
    label = _risk_label(s.risk_score)
    dur   = s.scan_duration_seconds

    lines: list[str] = [
        f"A Web Application Vulnerability Assessment was conducted against "
        f"`{result.target_url}` using AI Red Team Harness v3. "
        f"The scan completed in {dur:.0f} seconds and examined "
        f"{s.urls_scanned} URL(s), {s.forms_tested} form(s), and "
        f"{s.parameters_tested} parameter(s).",
        "",
        f"**Overall Risk Rating: {label}** (score {s.risk_score:.1f}/100)",
        "",
        f"The assessment identified **{s.total_findings} finding(s)**: "
        f"{s.critical} CRITICAL, {s.high} HIGH, {s.medium} MEDIUM, "
        f"{s.low} LOW, {s.info} INFO.",
    ]

    if s.critical > 0:
        crits = [f.title for f in result.findings if f.severity.value == "CRITICAL"][:3]
        lines += [
            "",
            "**Critical issues requiring immediate attention:**",
            *[f"- {t}" for t in crits],
        ]

    if result.errors:
        lines += [
            "",
            f"**Note:** {len(result.errors)} scan component(s) encountered errors. "
            "Review the full report for details.",
        ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Remediation Roadmap builder
# ---------------------------------------------------------------------------

def _build_remediation_roadmap(result: "WebAssessmentResult") -> list[dict[str, Any]]:
    """
    Returns a prioritised list of remediation actions grouped by OWASP category,
    ordered CRITICAL → HIGH → MEDIUM → LOW → INFO.
    """
    grouped: dict[str, dict[str, Any]] = {}

    for f in _sorted_findings(result.findings):
        key = f.owasp
        if key not in grouped:
            grouped[key] = {
                "owasp_category": f.owasp,
                "severity":       f.severity.value,
                "findings":       [],
                "generic_advice": _generic_advice(f.owasp),
            }
        grouped[key]["findings"].append({
            "id":          f.id,
            "title":       f.title,
            "cvss_score":  f.cvss_score,
            "cwe":         f.cwe,
            "endpoint":    f.endpoint,
            "remediation": f.remediation,
        })

    # Sort groups by highest severity within each group
    severity_key = lambda g: _SEVERITY_ORDER.get(g["severity"], 9)
    return sorted(grouped.values(), key=severity_key)


def _generic_advice(owasp_category: str) -> str:
    for keyword, advice in _OWASP_REMEDIATION_HINTS.items():
        if keyword.lower() in owasp_category.lower():
            return advice
    return "Apply defence-in-depth: validate inputs, enforce least privilege, monitor anomalies."


# ---------------------------------------------------------------------------
# JSON Renderer
# ---------------------------------------------------------------------------

class _JSONRenderer:
    def render(self, result: "WebAssessmentResult", report_id: str) -> dict[str, Any]:
        risk_summary = _build_risk_summary(result)
        exec_summary = _build_executive_summary(result)
        roadmap      = _build_remediation_roadmap(result)

        d = {
            "report_id":           report_id,
            "schema_version":      "1.0",
            "generated_at":        _now_iso(),
            "framework":           "AI Red Team Harness v3",
            "report_type":         "Web Application Vulnerability Assessment",
            "session_id":          result.session_id,
            "target_url":          result.target_url,
            "scan_started_at":     datetime.fromtimestamp(result.started_at, tz=timezone.utc).isoformat(),
            "scan_ended_at":       datetime.fromtimestamp(result.ended_at,   tz=timezone.utc).isoformat(),
            "executive_summary":   exec_summary,
            "risk_summary":        risk_summary,
            "findings":            [f.to_dict() for f in _sorted_findings(result.findings)],
            "remediation_roadmap": roadmap,
            "attack_surface":      result.attack_surface,
            "tool_outputs":        result.tool_outputs,
            "scan_errors":         result.errors,
        }
        lr = getattr(result, "llm_result", None)
        if lr is not None and not getattr(lr, "error", ""):
            d["llm_analysis"] = {
                "model":           getattr(lr, "model_used", ""),
                "iterations_used": getattr(lr, "iterations_used", 0),
                "executive_brief": getattr(lr, "executive_brief", ""),
                "risk_rating":     getattr(lr, "risk_rating", ""),
                "attack_chains":   getattr(lr, "attack_chains", []),
                "agent_log": [
                    {
                        "iteration":   t.iteration,
                        "tool":        t.tool,
                        "params":      t.params,
                        "reasoning":   t.reasoning,
                        "tool_output": t.tool_output[:400],
                    }
                    for t in getattr(lr, "agent_log", [])
                ],
            }
        return d


# ---------------------------------------------------------------------------
# Markdown Renderer
# ---------------------------------------------------------------------------

class _MarkdownRenderer:
    def render(self, result: "WebAssessmentResult", report_id: str) -> str:
        exec_summary = _build_executive_summary(result)
        risk_summary = _build_risk_summary(result)
        roadmap      = _build_remediation_roadmap(result)

        sections = [
            self._header(result, report_id),
            self._exec_summary_section(exec_summary),
            self._llm_analysis_section(getattr(result, "llm_result", None)),
            self._risk_dashboard(risk_summary),
            self._attack_surface_section(result),
            self._findings_section(result.findings),
            self._remediation_roadmap_section(roadmap),
            self._tool_outputs_section(result.tool_outputs),
            self._methodology_section(),
            self._footer(report_id),
        ]
        return "\n\n".join(s for s in sections if s.strip())

    # ── Section renderers ────────────────────────────────────────────────

    def _header(self, result: "WebAssessmentResult", report_id: str) -> str:
        started = datetime.fromtimestamp(result.started_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return (
            "# Web Application Security Assessment Report\n\n"
            f"**Report ID:** `{report_id}`  \n"
            f"**Target:** `{result.target_url}`  \n"
            f"**Scan Date:** {started}  \n"
            f"**Generated:** {_now_iso()}  \n"
            "**Classification:** CONFIDENTIAL — RESTRICTED DISTRIBUTION  \n"
            "**Framework:** AI Red Team Harness v3"
        )

    def _exec_summary_section(self, summary_text: str) -> str:
        return f"## Executive Summary\n\n{summary_text}"

    def _llm_analysis_section(self, lr: Any | None) -> str:
        if lr is None:
            return ""
        error = getattr(lr, "error", "")
        if error:
            return (
                "## LLM Agent Analysis\n\n"
                f"> **Agent skipped:** {error}\n\n"
                "Run with `--web-vapt-llm` and ensure Ollama is running: "
                "`ollama pull llama3 && ollama serve`"
            )

        model       = getattr(lr, "model_used",      "?")
        iterations  = getattr(lr, "iterations_used", 0)
        risk_rating = getattr(lr, "risk_rating",     "N/A")
        brief       = getattr(lr, "executive_brief", "")
        chains      = getattr(lr, "attack_chains",   [])
        agent_log   = getattr(lr, "agent_log",       [])

        lines = [
            "## LLM Agent Analysis\n",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Model** | `{model}` |",
            f"| **Iterations** | {iterations} |",
            f"| **LLM Risk Rating** | `{risk_rating}` |",
            "",
        ]

        if brief:
            lines += ["### Executive Brief (LLM-generated)\n", brief, ""]

        if chains:
            lines.append("### Attack Chains Identified\n")
            for i, chain in enumerate(chains, 1):
                lines.append(f"{i}. {chain}")
            lines.append("")

        if agent_log:
            lines.append("### Agent Reasoning Log\n")
            lines.append("| # | Tool | Reasoning | Result (excerpt) |")
            lines.append("|---|------|-----------|-----------------|")
            for t in agent_log:
                reason  = _truncate(t.reasoning,   60).replace("|", "/")
                output  = _truncate(t.tool_output, 80).replace("|", "/").replace("\n", " ")
                params_s = ", ".join(f"{k}={v}" for k, v in t.params.items() if k != "reason")
                lines.append(
                    f"| {t.iteration + 1} | `{t.tool}({params_s[:40]})` "
                    f"| {reason} | {output} |"
                )
            lines.append("")

        return "\n".join(lines)

    def _risk_dashboard(self, rs: dict[str, Any]) -> str:
        label = rs["risk_label"]
        score = rs["risk_score"]
        bar   = _severity_bar(min(score / 10.0, 10.0) * 10.0 / 10.0 * 10.0)

        lines = [
            "## Risk Dashboard\n",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Overall Risk | **{label}** |",
            f"| Risk Score | {score:.1f} / 100 |",
            f"| Total Findings | {rs['total_findings']} |",
            f"| CRITICAL | {rs['critical']} |",
            f"| HIGH | {rs['high']} |",
            f"| MEDIUM | {rs['medium']} |",
            f"| LOW | {rs['low']} |",
            f"| INFO | {rs['info']} |",
            f"| URLs Scanned | {rs['urls_scanned']} |",
            f"| Forms Tested | {rs['forms_tested']} |",
            f"| Params Tested | {rs['parameters_tested']} |",
            f"| Scan Duration | {rs['scan_duration_s']:.0f}s |",
        ]

        if rs.get("top_owasp"):
            lines += ["", "**Top OWASP Categories:**", ""]
            for entry in rs["top_owasp"]:
                lines.append(f"- {entry['category']}: **{entry['count']}** finding(s)")

        if rs.get("by_category"):
            lines += ["", "**Findings by Category:**", ""]
            for cat, cnt in sorted(rs["by_category"].items()):
                if cnt > 0:
                    lines.append(f"- `{cat}`: {cnt}")

        return "\n".join(lines)

    def _attack_surface_section(self, result: "WebAssessmentResult") -> str:
        surface = result.attack_surface
        if not surface:
            return ""
        lines = ["## Attack Surface\n"]
        if surface.get("urls"):
            lines.append(f"**Discovered URLs ({len(surface['urls'])}):**\n")
            for url in surface["urls"][:20]:
                lines.append(f"- `{url}`")
            if len(surface["urls"]) > 20:
                lines.append(f"- _...and {len(surface['urls'])-20} more_")
        if surface.get("technologies"):
            lines.append(f"\n**Technologies Detected:** {', '.join(surface['technologies'])}")
        if surface.get("api_endpoints"):
            lines.append(f"\n**API Endpoints ({len(surface['api_endpoints'])}):**\n")
            for ep in surface["api_endpoints"][:10]:
                lines.append(f"- `{ep}`")
        return "\n".join(lines)

    def _findings_section(self, findings: list["WebFinding"]) -> str:
        if not findings:
            return "## Findings\n\n_No security vulnerabilities identified._"
        sorted_f = _sorted_findings(findings)
        sections = ["## Findings\n"]
        for f in sorted_f:
            sections.append(self._render_finding(f))
        return "\n".join(sections)

    def _render_finding(self, f: "WebFinding") -> str:
        icon       = _SEVERITY_ICON.get(f.severity.value, "")
        refs       = "\n".join(f"  - {r}" for r in f.references) if f.references else "  - N/A"
        conf_pct   = getattr(f, "confidence_pct", int(round(f.confidence * 100)))
        val_status = getattr(f, "validation_status", "potential")
        status_tag = {
            "confirmed":    "CONFIRMED",
            "potential":    "POTENTIAL — MANUAL VALIDATION REQUIRED",
            "informational": "INFORMATIONAL",
        }.get(val_status, val_status.upper())

        exploit_status  = getattr(f, "exploit_status",   "UNVERIFIED")
        exploit_badge   = "**CONFIRMED**" if exploit_status == "CONFIRMED" else "*UNVERIFIED*"
        comparison_result = getattr(f, "comparison_result", "")

        sections: list[str] = [
            f"### {icon} {f.id}: {f.title}\n",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Severity** | `{f.severity.value}` |",
            f"| **CVSS Score** | {_severity_bar(f.cvss_score)} |",
            f"| **Confidence** | {conf_pct}% |",
            f"| **Validation Status** | **{status_tag}** |",
            f"| **Exploit Status** | {exploit_badge} |",
            f"| **OWASP** | {f.owasp} |",
            f"| **CWE** | {f.cwe} |",
            f"| **Endpoint** | `{f.endpoint}` |",
            f"| **Parameter** | `{f.parameter}` |",
            "",
            f"**Description**\n\n{f.description}",
        ]

        # ── Comparison Result ─────────────────────────────────────────────
        if comparison_result:
            sections.append(
                f"\n**Comparison Result** *(baseline vs attack)*\n\n"
                f"> {_truncate(comparison_result, 350)}"
            )

        # ── Evidence ──────────────────────────────────────────────────────
        sections.append(f"\n**Evidence**\n\n```\n{_truncate(f.evidence, 350)}\n```")

        # ── Raw Request ───────────────────────────────────────────────────
        raw_req = getattr(f, "raw_request", "")
        if raw_req:
            sections.append(f"\n**Exact Reproduction — Raw Request**\n\n```http\n{_truncate(raw_req, 400)}\n```")

        # ── Raw Response Excerpt ──────────────────────────────────────────
        raw_resp = getattr(f, "raw_response_excerpt", "")
        if raw_resp:
            sections.append(f"\n**Raw Response Evidence**\n\n```\n{_truncate(raw_resp, 400)}\n```")

        # ── Reproduction Steps ────────────────────────────────────────────
        steps = getattr(f, "reproduction_steps", [])
        if steps:
            step_lines = "\n".join(steps)
            sections.append(f"\n**Exact Reproduction Steps**\n\n{step_lines}")

        # ── Validation Logic ──────────────────────────────────────────────
        val_logic = getattr(f, "validation_logic", "")
        if val_logic:
            sections.append(f"\n**Validation Logic**\n\n{_truncate(val_logic, 300)}")

        # ── False Positive Checks ─────────────────────────────────────────
        fp_checks = getattr(f, "fp_checks_performed", [])
        if fp_checks:
            fp_list = "\n".join(f"- `{c}`" for c in fp_checks)
            sections.append(f"\n**False Positive Checks Performed**\n\n{fp_list}")

        # ── Exploitability Assessment ─────────────────────────────────────
        exploit = getattr(f, "exploitability", "")
        if exploit:
            sections.append(f"\n**Exploitability Assessment**\n\n{_truncate(exploit, 250)}")

        # ── Remediation ───────────────────────────────────────────────────
        sections.append(f"\n**Remediation**\n\n{f.remediation}")
        sections.append(f"\n**References**\n\n{refs}")
        sections.append("\n---")

        return "\n".join(sections)

    def _remediation_roadmap_section(self, roadmap: list[dict[str, Any]]) -> str:
        if not roadmap:
            return ""
        lines = [
            "## Remediation Roadmap\n",
            "Findings are listed in priority order (CRITICAL first). "
            "Address items in this sequence to achieve maximum risk reduction.\n",
        ]
        for i, group in enumerate(roadmap, 1):
            sev   = group["severity"]
            owasp = group["owasp_category"]
            icon  = _SEVERITY_ICON.get(sev, "")
            lines += [
                f"### {i}. {icon} {owasp}\n",
                f"**Generic Advice:** {group['generic_advice']}\n",
                "**Affected findings:**\n",
            ]
            for finding in group["findings"]:
                lines += [
                    f"- **{finding['id']}** – {finding['title']}  ",
                    f"  `{finding['cwe']}` | CVSS {finding['cvss_score']:.1f} | "
                    f"Endpoint: `{finding['endpoint']}`  ",
                    f"  _{finding['remediation']}_\n",
                ]
        return "\n".join(lines)

    def _tool_outputs_section(self, tool_outputs: dict[str, Any]) -> str:
        if not tool_outputs:
            return ""
        lines = ["## External Tool Outputs\n"]
        for tool, output in tool_outputs.items():
            lines.append(f"### {tool}\n")
            if isinstance(output, dict):
                status = output.get("status", "unknown")
                lines.append(f"**Status:** {status}\n")
                if output.get("findings"):
                    lines.append("**Findings:**\n")
                    for finding in output["findings"][:10]:
                        lines.append(f"- {finding}")
                if output.get("error"):
                    lines.append(f"**Error:** {output['error']}\n")
            else:
                lines.append(f"```\n{_truncate(str(output), 500)}\n```\n")
        return "\n".join(lines)

    def _methodology_section(self) -> str:
        return (
            "## Methodology\n\n"
            "This assessment was conducted using **AI Red Team Harness v3 — Web VAPT Engine**, "
            "a controlled, non-destructive web application security testing framework. "
            "All tests targeted pre-approved, allowlisted infrastructure only. "
            "No production-impacting payloads were used.\n\n"
            "**Checks performed:**\n\n"
            "- SQL Injection (error-based, boolean-based, time-based)\n"
            "- Cross-Site Scripting (reflected, DOM indicators)\n"
            "- Local / Remote File Inclusion\n"
            "- Command Injection\n"
            "- CSRF token validation\n"
            "- Authentication bypass\n"
            "- CORS misconfiguration\n"
            "- Security headers audit\n"
            "- TLS configuration review\n"
            "- Sensitive file and debug endpoint exposure\n"
            "- SSRF and Open Redirect indicators\n"
            "- JWT security analysis\n"
            "- GraphQL introspection\n"
            "- Prototype pollution indicators\n"
            "- IDOR detection\n\n"
            "**Scoring:** CVSS v3.1-inspired with OWASP Top 10 2021 and CWE cross-references."
        )

    def _footer(self, report_id: str) -> str:
        return (
            "---\n\n"
            f"*Report generated by AI Red Team Harness v3 Web VAPT Engine · "
            f"`{report_id}` · For authorised security personnel only.*"
        )


# ---------------------------------------------------------------------------
# Public API: WebReportGenerator
# ---------------------------------------------------------------------------

class WebReportGenerator:
    """
    Generates multi-format reports from a WebAssessmentResult.

    Usage:
        gen    = WebReportGenerator(config=cfg.get("reporting", {}))
        report = gen.generate(result)
        # report["markdown_path"], report["json_path"], report["risk_summary"], etc.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = config or {}
        output_dir = cfg.get("output_dir", "reports/web")
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._md_renderer   = _MarkdownRenderer()
        self._json_renderer = _JSONRenderer()
        logger.info("WebReportGenerator ready | output=%s", self._output_dir)

    def generate(self, result: "WebAssessmentResult") -> dict[str, Any]:
        """
        Generate all report formats and write them to output_dir.

        Returns a dict containing:
          - report_id        : str
          - markdown_path    : str  (absolute path to .md file)
          - json_path        : str  (absolute path to .json file)
          - risk_summary     : dict
          - executive_summary: str
          - remediation_roadmap: list[dict]
          - output_dir       : str
        """
        report_id = f"WEB-{uuid.uuid4().hex[:12].upper()}"
        ts        = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        risk_summary     = _build_risk_summary(result)
        exec_summary     = _build_executive_summary(result)
        remediation_road = _build_remediation_roadmap(result)

        # --- JSON ---
        json_data = self._json_renderer.render(result, report_id)
        json_path = self._output_dir / f"web_vapt_{ts}.json"
        try:
            json_path.write_text(
                json.dumps(json_data, indent=2, default=str, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.info("JSON report written | path=%s", json_path)
        except OSError as exc:
            logger.error("Failed to write JSON report: %s", exc)
            json_path = self._output_dir / "web_vapt_FAILED.json"

        # --- Markdown ---
        md_text  = self._md_renderer.render(result, report_id)
        md_path  = self._output_dir / f"web_vapt_{ts}.md"
        try:
            md_path.write_text(md_text, encoding="utf-8")
            logger.info("Markdown report written | path=%s", md_path)
        except OSError as exc:
            logger.error("Failed to write Markdown report: %s", exc)
            md_path = self._output_dir / "web_vapt_FAILED.md"

        return {
            "report_id":            report_id,
            "markdown_path":        str(md_path.resolve()),
            "json_path":            str(json_path.resolve()),
            "risk_summary":         risk_summary,
            "executive_summary":    exec_summary,
            "remediation_roadmap":  remediation_road,
            "output_dir":           str(self._output_dir.resolve()),
            "generated_at":         _now_iso(),
        }
