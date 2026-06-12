#!/usr/bin/env python3
"""
run_agent.py
============
Agentic Penetration Testing Mode
AI Red Team Harness v3

Autonomous, multi-phase pentest agent that reasons about a target,
selects tools dynamically, discovers exploits, and builds MITRE ATT&CK
attack chains — producing a full narrative threat report.

Phases (automatic, iterative):
  1  Reconnaissance  — ports, DNS, fingerprint, WAF, whois
  2  Subdomain deep  — when subdomains discovered
  3  Web discovery   — ffuf, gobuster, nikto
  4  Exploit lookup  — searchsploit + NVD CVE API
  5  Chain analysis  — MITRE ATT&CK mapping + attack path scoring
  6  OSINT           — harvester, gau, waybackurls
  7  Vuln scan       — nuclei targeted
  8  SMB             — when port 445/139 open

Usage:
  python run_agent.py --target http://192.168.0.101
  python run_agent.py --target http://192.168.0.101 --max-iter 8
  python run_agent.py --target http://192.168.0.101 --verbose
  python run_agent.py --target http://192.168.0.101 --output reports/agent
  python run_agent.py --create-lab-marker

Authorised lab environments only.
Python: 3.11+
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).parent.resolve()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from utils.logger import get_logger, set_level

logger = get_logger(__name__)

BANNER = """\
+──────────────────────────────────────────────────────────+
|          AI Red Team Harness  v3.0                        |
|          AGENTIC PENTEST MODE  —  Autonomous ReAct Loop   |
|                                                           |
|  Phases: Recon → Exploit Lookup → ATT&CK Chain Analysis   |
|  *** AUTHORISED LAB ENVIRONMENTS ONLY ***                 |
+──────────────────────────────────────────────────────────+"""


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_agent.py",
        description="Agentic Pentest Mode — AI Red Team Harness v3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--target", metavar="URL",
                   help="Target URL or IP (must be in config/safety.yaml allowlist)")
    p.add_argument("--max-iter", metavar="N", type=int, default=10,
                   help="Maximum agent iterations (default: 10)")
    p.add_argument("--output", metavar="DIR", default="reports/agent",
                   help="Output directory (default: reports/agent)")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Show agent reasoning and reflection at each step")
    p.add_argument("--no-nvd", action="store_true",
                   help="Disable NVD CVE API lookups (offline mode)")
    p.add_argument("--create-lab-marker", action="store_true",
                   help="Create .lab_mode_enabled safety marker and exit")
    return p


# ── Safety ────────────────────────────────────────────────────────────────────

def _check_safety(target: str) -> str | None:
    lab_marker = PROJECT_ROOT / ".lab_mode_enabled"
    if not lab_marker.exists():
        return (
            "Lab marker missing.\n"
            "  Run: python run_agent.py --create-lab-marker"
        )
    safety_path = PROJECT_ROOT / "config" / "safety.yaml"
    try:
        import yaml
        with open(safety_path, encoding="utf-8") as f:
            safety = yaml.safe_load(f) or {}
    except Exception as exc:
        return f"Cannot read config/safety.yaml: {exc}"

    allowed: list[str] = safety.get("web_vapt", {}).get("allowed_urls", [])
    t_host = urlparse(target).netloc or target
    for entry in allowed:
        e_host = urlparse(entry).netloc or entry
        if t_host == e_host or target.startswith(entry):
            return None
    return (
        f"Target '{target}' not in allowlist.\n"
        f"  Add to config/safety.yaml under web_vapt.allowed_urls"
    )


# ── Report writer ─────────────────────────────────────────────────────────────

def _write_report(result: "AgentResult", output_dir: str, interrupted: bool) -> dict:
    from modules.agent_loop import AgentResult
    from modules.exploit_engine import ExploitReport
    from modules.attack_chain import ChainReport

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    tag  = "PARTIAL_" if interrupted else ""
    stem = f"agent_{tag}{ts}"
    ctx  = result.context

    # ── JSON ──────────────────────────────────────────────────────────────────
    er: ExploitReport | None = ctx.exploit_report
    cr: ChainReport   | None = ctx.chain_report

    data: dict = {
        "report_id":      stem,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "target":         result.target,
        "interrupted":    interrupted,
        "duration_s":     round(result.duration, 1),
        "iterations":     result.iterations_used,
        "stop_reason":    result.stop_reason,
        "open_ports":     ctx.open_ports,
        "subdomains":     ctx.subdomains,
        "technologies":   ctx.technologies,
        "waf_detected":   ctx.waf_detected,
        "dns_records":    ctx.dns_records,
        "web_dirs":       ctx.web_dirs,
        "emails":         ctx.emails,
        "historical_urls_count": len(ctx.historical_urls),
        "findings": [
            {
                "tool":     getattr(f, "tool", ""),
                "category": getattr(f, "category", ""),
                "title":    getattr(f, "title", ""),
                "severity": getattr(f, "severity", "info"),
                "detail":   getattr(f, "detail", "")[:400],
            }
            for f in ctx.findings
        ],
        "exploits": [e.to_dict() for e in er.exploits[:20]] if er else [],
        "msf_commands":   er.msf_commands if er else [],
        "cves_found":     er.cves_found if er else [],
        "attack_chains": [
            {
                "chain_id":       c.chain_id,
                "name":           c.name,
                "score":          c.score,
                "impact":         c.impact,
                "mitre_tactics":  c.mitre_tactics,
                "mitre_techniques": c.mitre_techniques,
                "ascii_path":     c.ascii_path(),
                "narrative":      c.narrative,
            }
            for c in (cr.chains if cr else [])
        ],
        "attack_surface_score": cr.attack_surface_score if cr else 0,
        "mitre_coverage":       cr.mitre_coverage if cr else [],
        "agent_thoughts": [
            {
                "iteration":   t.iteration,
                "action":      t.action,
                "reasoning":   t.reasoning,
                "observation": t.observation,
                "reflection":  t.reflection,
            }
            for t in ctx.thoughts
        ],
    }

    json_path = out / f"{stem}.json"
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    # ── Markdown ──────────────────────────────────────────────────────────────
    md = _render_markdown(data, result, ctx, interrupted)
    md_path = out / f"{stem}.md"
    md_path.write_text(md, encoding="utf-8")

    return {"json_path": str(json_path), "markdown_path": str(md_path), "report_id": stem}


def _render_markdown(data: dict, result: "AgentResult", ctx: "AgentContext",
                     interrupted: bool) -> str:
    lines: list[str] = []
    status = "**PARTIAL — interrupted**" if interrupted else "Complete"

    lines += [
        f"# Agent Pentest Report — {result.target}",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Generated | {data['generated_at']} |",
        f"| Target | `{result.target}` |",
        f"| Duration | {data['duration_s']}s |",
        f"| Iterations | {data['iterations']} |",
        f"| Stop reason | {data['stop_reason']} |",
        f"| Status | {status} |",
        "",
    ]

    # Executive summary
    er = ctx.exploit_report
    cr = ctx.chain_report
    top_chain = cr.top_chain if cr else None

    lines += ["## Executive Summary", ""]
    lines.append(
        f"Autonomous pentest agent ran **{data['iterations']} iteration(s)** against "
        f"`{result.target}`. "
        f"Discovered **{len(ctx.open_ports)} open port(s)**, "
        f"**{len(ctx.technologies)} technology stack component(s)**, "
        f"and **{len(ctx.findings)} security finding(s)**. "
    )
    if er:
        lines.append(
            f"Exploit intelligence surfaced **{len(er.exploits)} potential exploit(s)** "
            f"({er.critical_count} critical, {er.high_count} high). "
        )
    if cr and cr.chains:
        lines.append(
            f"**{len(cr.chains)} attack chain(s)** mapped to MITRE ATT&CK. "
            f"Attack surface score: **{cr.attack_surface_score}/10**. "
            f"Tactics covered: {', '.join(cr.mitre_coverage)}."
        )
    if top_chain:
        lines.append(f"\nHighest-risk chain: **{top_chain.name}** (score {top_chain.score})")
    lines.append("")

    # Open Ports
    if ctx.open_ports:
        lines += ["## Open Ports", "",
                  "| Port | Protocol | Service | State |",
                  "|------|----------|---------|-------|"]
        for p in ctx.open_ports:
            lines.append(
                f"| {p.get('port','')} | {p.get('protocol','tcp')} "
                f"| {p.get('service','')} | {p.get('state','open')} |"
            )
        lines.append("")

    # Technologies
    if ctx.technologies:
        lines += ["## Technologies Detected", ""]
        lines.append(", ".join(f"`{t}`" for t in ctx.technologies))
        lines.append("")

    if ctx.waf_detected:
        lines += ["## WAF Detected", "", f"`{ctx.waf_detected}`", ""]

    # DNS
    if ctx.dns_records:
        lines += ["## DNS Records", ""]
        for rtype, vals in ctx.dns_records.items():
            lines.append(f"**{rtype}**: {', '.join(vals)}")
        lines.append("")

    # Subdomains
    if ctx.subdomains:
        lines += [f"## Subdomains ({len(ctx.subdomains)} found)", ""]
        for s in ctx.subdomains[:30]:
            lines.append(f"- `{s}`")
        if len(ctx.subdomains) > 30:
            lines.append(f"- *(+{len(ctx.subdomains)-30} more — see JSON)*")
        lines.append("")

    # Web paths
    if ctx.web_dirs:
        lines += [f"## Web Paths ({len(ctx.web_dirs)} discovered)", ""]
        for d in ctx.web_dirs[:50]:
            lines.append(f"- `{d}`")
        if len(ctx.web_dirs) > 50:
            lines.append(f"- *(+{len(ctx.web_dirs)-50} more — see JSON)*")
        lines.append("")

    # Findings
    if ctx.findings:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_f = sorted(
            ctx.findings,
            key=lambda f: sev_order.get(getattr(f, "severity", "info").lower(), 9),
        )
        lines += [f"## Security Findings ({len(ctx.findings)})", ""]
        for f in sorted_f:
            sev = getattr(f, "severity", "info").upper()
            title = getattr(f, "title", "")
            tool  = getattr(f, "tool", "")
            detail = getattr(f, "detail", "")
            lines += [
                f"### [{sev}] {title}",
                f"**Tool**: `{tool}`",
                "",
                detail,
                "",
            ]

    # Exploit Intelligence
    if er and er.exploits:
        lines += [f"## Exploit Intelligence ({len(er.exploits)} found)", ""]
        if er.cves_found:
            lines.append(f"**CVEs identified**: {', '.join(er.cves_found)}")
            lines.append("")
        lines += ["| Title | Type | Platform | CVSS | Severity |",
                  "|-------|------|----------|------|----------|"]
        for e in er.exploits[:20]:
            lines.append(
                f"| {e.title[:55]} | {e.exploit_type} | {e.platform} "
                f"| {e.cvss_score:.1f} | {e.severity} |"
            )
        lines.append("")

        if er.msf_commands:
            lines += ["### Metasploit Modules", "", "```"]
            for cmd in er.msf_commands[:5]:
                lines.append(cmd)
                lines.append("---")
            lines += ["```", ""]

        if er.searchsploit_cmds:
            lines += ["### searchsploit Copy Commands", "", "```bash"]
            lines += er.searchsploit_cmds[:8]
            lines += ["```", ""]

    # Attack Chains
    if cr and cr.chains:
        lines += [f"## MITRE ATT&CK Attack Chains ({len(cr.chains)} identified)", ""]
        lines.append(f"**Attack Surface Score**: {cr.attack_surface_score}/10")
        lines.append(f"**Tactics Covered**: {', '.join(cr.mitre_coverage)}")
        lines.append("")
        for i, chain in enumerate(cr.chains, 1):
            lines += [
                f"### Chain {i}: {chain.name}  (score {chain.score})",
                "",
                f"**Impact**: {chain.impact}",
                "",
                "**Attack Path**:",
                "```",
                chain.ascii_path(),
                "```",
                "",
                "**Narrative**:",
                "",
                chain.narrative,
                "",
            ]

    # Agent Thoughts
    if ctx.thoughts:
        lines += ["## Agent Reasoning Log", ""]
        for t in ctx.thoughts:
            lines += [
                f"### Iteration {t.iteration} — `{t.action}`",
                f"- **Reasoning**: {t.reasoning}",
                f"- **Observation**: {t.observation}",
                f"- **Reflection**: {t.reflection}",
                "",
            ]

    return "\n".join(lines)


# ── Main agent runner ─────────────────────────────────────────────────────────

async def run_agent(args: argparse.Namespace) -> int:
    if not getattr(args, "_banner_shown", False):
        print(BANNER)
        print()

    if args.verbose:
        set_level("DEBUG")

    target = (args.target or "").strip()
    if not target:
        print("  [ERROR] --target URL is required.\n")
        print("  Example: python run_agent.py --target http://192.168.0.101\n")
        return 1

    err = _check_safety(target)
    if err:
        print(f"\n  [BLOCKED] {err}\n")
        return 2

    print(f"  Target     : {target}")
    print(f"  Max iters  : {args.max_iter}")
    print(f"  Output     : {args.output}")
    print(f"  NVD API    : {'disabled' if args.no_nvd else 'enabled'}")
    print()

    try:
        from modules.agent_loop import PentestAgent
    except ImportError as exc:
        print(f"\n  [ERROR] Cannot import PentestAgent: {exc}\n")
        return 1

    kill_switch = asyncio.Event()

    def _sigint() -> None:
        print("\n\n  [Agent] Kill switch triggered — saving partial results...\n")
        kill_switch.set()

    import signal as _signal
    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(_signal.SIGINT, _sigint)
    except (NotImplementedError, AttributeError):
        def _win_sigint(sig, frame):
            loop.call_soon_threadsafe(_sigint)
        _signal.signal(_signal.SIGINT, _win_sigint)

    import yaml
    cfg: dict = {}
    try:
        with open(PROJECT_ROOT / "config" / "web_vapt.yaml", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except Exception:
        pass

    cfg["exploit_engine"] = {"nvd_enabled": not args.no_nvd}

    agent = PentestAgent(
        config=cfg,
        kill_switch=kill_switch,
        max_iterations=args.max_iter,
        verbose=args.verbose,
    )

    print(f"  Starting autonomous agent loop...\n")
    print(f"  {'─'*54}")
    start = time.time()

    try:
        result = await agent.run(target)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n  Agent aborted before collecting results.\n")
        return 130
    except Exception as exc:
        logger.exception("Agent failed: %s", exc)
        print(f"\n  [ERROR] Agent failed: {exc}\n")
        return 1

    result.duration = time.time() - start
    interrupted = kill_switch.is_set()

    try:
        report = _write_report(result, args.output, interrupted)
    except Exception as exc:
        logger.exception("Report failed: %s", exc)
        print(f"\n  [ERROR] Report generation failed: {exc}\n")
        return 1

    # ── Final summary ─────────────────────────────────────────────────────────
    ctx = result.context
    er  = ctx.exploit_report
    cr  = ctx.chain_report

    print(f"\n  {'='*58}")
    print(f"  AGENT {'INTERRUPTED — PARTIAL RESULTS' if interrupted else 'COMPLETE'}")
    print(f"  {'='*58}")
    print(f"  Report ID     : {report['report_id']}")
    print(f"  Target        : {result.target}")
    print(f"  Duration      : {result.duration:.0f}s  ({result.iterations_used} iterations)")
    print(f"  Stop reason   : {result.stop_reason}")
    print()

    print(f"  Open ports    : {len(ctx.open_ports)}")
    if ctx.open_ports:
        port_strs = [
            f"{p['port']}/{p.get('protocol','tcp')} ({p.get('service','')})"
            for p in ctx.open_ports[:8]
        ]
        print(f"    {', '.join(port_strs)}")

    if ctx.technologies:
        print(f"  Technologies  : {', '.join(ctx.technologies[:8])}")
    if ctx.waf_detected:
        print(f"  WAF           : {ctx.waf_detected}")
    if ctx.subdomains:
        preview = ", ".join(ctx.subdomains[:5])
        extra   = f" (+{len(ctx.subdomains)-5} more)" if len(ctx.subdomains) > 5 else ""
        print(f"  Subdomains    : {len(ctx.subdomains)}  ({preview}{extra})")
    if ctx.web_dirs:
        print(f"  Web paths     : {len(ctx.web_dirs)} discovered")

    # Findings
    if ctx.findings:
        sev_counts: dict[str, int] = {}
        for f in ctx.findings:
            s = getattr(f, "severity", "info").lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        print(f"\n  Findings      : {len(ctx.findings)}")
        for sev in ("critical", "high", "medium", "low", "info"):
            n = sev_counts.get(sev, 0)
            if n:
                print(f"    {sev.upper():<10}: {n}")

    # Exploits
    if er:
        print(f"\n  Exploits      : {len(er.exploits)} matches "
              f"({er.critical_count} critical, {er.high_count} high)")
        if er.cves_found:
            print(f"  CVEs          : {', '.join(er.cves_found[:6])}")
        if er.msf_commands:
            print(f"  MSF modules   : {len(er.msf_commands)} available")

    # Attack chains
    if cr and cr.chains:
        print(f"\n  Attack chains : {len(cr.chains)}")
        print(f"  Surface score : {cr.attack_surface_score}/10")
        print(f"  ATT&CK tactic : {', '.join(cr.mitre_coverage)}")
        top = cr.top_chain
        if top:
            print(f"\n  Top chain     : {top.name}  (score {top.score})")
            print(f"  Impact        : {top.impact}")
            print(f"\n  Attack Path:")
            print(top.ascii_path())

    print(f"\n  JSON Report   : {report['json_path']}")
    print(f"  MD Report     : {report['markdown_path']}")
    if interrupted:
        print(f"\n  NOTE: Agent stopped by Ctrl+C. Report contains partial results.")
    print(f"  {'='*58}\n")

    return 0


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if args.verbose:
        set_level("DEBUG")

    if args.create_lab_marker:
        marker = PROJECT_ROOT / ".lab_mode_enabled"
        ts = datetime.now(timezone.utc).isoformat()
        marker.write_text(f"lab_mode_enabled=true\ncreated_at={ts}\n", encoding="utf-8")
        print(f"\n  Lab marker created: {marker}\n")
        sys.exit(0)

    print(BANNER)
    print()
    args._banner_shown = True

    try:
        code = asyncio.run(run_agent(args))
        sys.exit(code)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n\n  Interrupted.\n")
        sys.exit(130)
    except Exception as exc:
        logger.exception("Fatal: %s", exc)
        print(f"\n  Fatal error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
