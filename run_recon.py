#!/usr/bin/env python3
"""
run_recon.py
============
Kali Linux Recon Tools — Standalone Scanner
AI Red Team Harness v3

Runs 29 Kali recon tools against a target and generates a JSON + Markdown report.

Usage:
  python run_recon.py --target http://192.168.0.101
  python run_recon.py --target http://192.168.0.101 --tools nmap,subfinder,ffuf
  python run_recon.py --target http://192.168.0.101 --tools nmap --output reports/recon
  python run_recon.py --list-tools
  python run_recon.py --create-lab-marker

Available tools:
  Network  : nmap, masscan
  DNS      : nslookup, dig, dnsrecon, dnsx, fierce, dnsenum
  Subdomain: subfinder, amass, assetfinder
  Fuzzing  : ffuf, gobuster, feroxbuster, dirb, dirsearch, wfuzz
  Fingerprint: whatweb, wafw00f, nikto, httpx
  OSINT    : theharvester, whois
  Historical: gau, waybackurls
  Vuln Scan: nuclei
  SMB      : enum4linux, smbmap
  Crawl    : katana

Default tools (when --tools is omitted):
  nmap, nslookup, dig, subfinder, ffuf, gobuster,
  whatweb, wafw00f, nikto, nuclei, whois

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

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.resolve()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from utils.logger import get_logger, set_level

logger = get_logger(__name__)

BANNER = """\
+----------------------------------------------------------+
|          AI Red Team Harness  v3.0                       |
|          Kali Linux Recon Tools Scanner                  |
|                                                          |
|  *** AUTHORISED LAB ENVIRONMENTS ONLY ***                |
+----------------------------------------------------------+"""


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_recon.py",
        description="Kali Recon Tools — AI Red Team Harness v3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--target", metavar="URL",
        help="Target URL or IP (must be in config/safety.yaml allowlist)",
    )
    p.add_argument(
        "--tools", metavar="TOOL1,TOOL2,...",
        help=(
            "Comma-separated list of tools to run. "
            "Omit to run the default set: "
            "nmap, nslookup, dig, subfinder, ffuf, gobuster, "
            "whatweb, wafw00f, nikto, nuclei, whois."
        ),
    )
    p.add_argument(
        "--list-tools", action="store_true",
        help="List all supported recon tools with categories and exit.",
    )
    p.add_argument(
        "--output", metavar="DIR", default="reports/recon",
        help="Output directory for reports (default: reports/recon)",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable DEBUG-level logging",
    )
    p.add_argument(
        "--create-lab-marker", action="store_true",
        help="Create .lab_mode_enabled safety marker and exit",
    )
    return p


# ---------------------------------------------------------------------------
# Utility commands
# ---------------------------------------------------------------------------

def cmd_create_lab_marker() -> None:
    marker = PROJECT_ROOT / ".lab_mode_enabled"
    ts = datetime.now(timezone.utc).isoformat()
    marker.write_text(f"lab_mode_enabled=true\ncreated_at={ts}\n", encoding="utf-8")
    print(f"\n  Lab marker created: {marker}\n")


def cmd_list_tools() -> None:
    try:
        from modules.recon_tools import ALL_TOOLS, DEFAULT_ENABLED
    except ImportError:
        print("\n  [ERROR] modules/recon_tools.py not found.\n")
        return

    categories: dict[str, list[tuple[str, bool]]] = {}
    for tool, cat in sorted(ALL_TOOLS.items()):
        categories.setdefault(cat, []).append((tool, tool in DEFAULT_ENABLED))

    cat_labels = {
        "network_scan": "Network Scanning",
        "dns":          "DNS Reconnaissance",
        "subdomain":    "Subdomain Enumeration",
        "web_fuzz":     "Web Fuzzing / Dir Brute Force",
        "fingerprint":  "Web Fingerprinting",
        "osint":        "OSINT",
        "historical":   "Historical URLs",
        "vulnerability":"Vulnerability Scanning",
        "smb":          "SMB / Windows Recon",
        "crawl":        "Web Crawling",
    }

    print("\n  Supported Recon Tools")
    print("  " + "─" * 54)
    for cat, label in cat_labels.items():
        tools = categories.get(cat, [])
        if not tools:
            continue
        print(f"\n  [{label}]")
        for tool, default in sorted(tools):
            marker = " (default)" if default else ""
            print(f"    {tool:<18}{marker}")
    print()
    print("  Use --tools TOOL1,TOOL2,... to select specific tools.")
    print()


# ---------------------------------------------------------------------------
# Safety check
# ---------------------------------------------------------------------------

def _check_safety(target_url: str) -> str | None:
    """Return an error string if target is not allowed, else None."""
    safety_path = PROJECT_ROOT / "config" / "safety.yaml"
    lab_marker  = PROJECT_ROOT / ".lab_mode_enabled"

    if not lab_marker.exists():
        return (
            "Lab marker missing. Run:  python run_recon.py --create-lab-marker\n"
            "  This confirms you are scanning an authorised lab environment."
        )

    try:
        import yaml
        with open(safety_path, encoding="utf-8") as f:
            safety = yaml.safe_load(f) or {}
    except Exception as exc:
        return f"Cannot read config/safety.yaml: {exc}"

    allowed: list[str] = safety.get("web_vapt", {}).get("allowed_urls", [])
    from urllib.parse import urlparse
    target_host = urlparse(target_url).netloc or target_url
    for entry in allowed:
        entry_host = urlparse(entry).netloc or entry
        if target_host == entry_host or target_url.startswith(entry):
            return None

    return (
        f"Target '{target_url}' is not in the allowlist.\n"
        f"  Add it to config/safety.yaml under web_vapt.allowed_urls"
    )


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def _write_report(result: "ReconResult", output_dir: str, interrupted: bool) -> dict:
    from modules.recon_tools import ReconResult  # type: ignore
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    ts  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    tag = "PARTIAL_" if interrupted else ""
    stem = f"recon_{tag}{ts}"

    # ── JSON ────────────────────────────────────────────────────────────────
    data = {
        "report_id":         stem,
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "target_url":        result.target_url,
        "domain":            result.domain,
        "host":              result.host,
        "port":              result.port,
        "interrupted":       interrupted,
        "duration_s":        round(result.duration, 1),
        "tools_run":         result.tools_run,
        "tools_available":   result.tools_available,
        "tools_unavailable": result.tools_unavailable,
        "open_ports":        result.open_ports,
        "subdomains":        result.subdomains,
        "dns_records":       result.dns_records,
        "web_dirs":          result.web_dirs,
        "technologies":      result.technologies,
        "emails":            result.emails,
        "historical_urls":   result.historical_urls,
        "waf_detected":      result.waf_detected,
        "findings":          [
            {
                "tool":       f.tool,
                "category":   f.category,
                "title":      f.title,
                "severity":   f.severity,
                "detail":     f.detail,
                "data":       f.data,
            }
            for f in result.findings
        ],
    }
    json_path = out / f"{stem}.json"
    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # ── Markdown ────────────────────────────────────────────────────────────
    lines: list[str] = []
    lines += [
        f"# Recon Report — {result.target_url}",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Generated | {data['generated_at']} |",
        f"| Target | `{result.target_url}` |",
        f"| Host | `{result.host}` |",
        f"| Duration | {data['duration_s']}s |",
        f"| Status | {'**PARTIAL — interrupted**' if interrupted else 'Complete'} |",
        f"",
    ]

    # Tools
    lines += [
        "## Tools",
        f"- **Run**: {', '.join(result.tools_run) or 'none'}",
        f"- **Available**: {', '.join(result.tools_available) or 'none'}",
        f"- **Unavailable / skipped**: {', '.join(result.tools_unavailable) or 'none'}",
        "",
    ]

    # Open ports
    if result.open_ports:
        lines += ["## Open Ports", ""]
        lines += ["| Port | Protocol | Service | State |",
                  "|------|----------|---------|-------|"]
        for p in result.open_ports:
            lines.append(
                f"| {p.get('port','')} | {p.get('protocol','tcp')} "
                f"| {p.get('service','')} | {p.get('state','open')} |"
            )
        lines.append("")

    # DNS
    if result.dns_records:
        lines += ["## DNS Records", ""]
        for rtype, vals in result.dns_records.items():
            lines.append(f"**{rtype}**: {', '.join(vals)}")
        lines.append("")

    # Subdomains
    if result.subdomains:
        lines += ["## Subdomains", ""]
        for s in result.subdomains:
            lines.append(f"- `{s}`")
        lines.append("")

    # Web dirs
    if result.web_dirs:
        lines += [f"## Web Paths ({len(result.web_dirs)} found)", ""]
        for d in result.web_dirs[:100]:
            lines.append(f"- `{d}`")
        if len(result.web_dirs) > 100:
            lines.append(f"- *(+{len(result.web_dirs)-100} more — see JSON)*")
        lines.append("")

    # Technologies
    if result.technologies:
        lines += ["## Technologies Detected", ""]
        lines.append(", ".join(f"`{t}`" for t in result.technologies))
        lines.append("")

    # WAF
    if result.waf_detected:
        lines += ["## WAF Detected", "", f"`{result.waf_detected}`", ""]

    # Emails
    if result.emails:
        lines += ["## Emails Found", ""]
        for e in result.emails:
            lines.append(f"- {e}")
        lines.append("")

    # Findings
    if result.findings:
        lines += [f"## Findings ({len(result.findings)})", ""]
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            result.findings,
            key=lambda f: sev_order.get(f.severity.lower(), 9),
        )
        for f in sorted_findings:
            lines += [
                f"### [{f.severity.upper()}] {f.title}",
                f"**Tool**: `{f.tool}` | **Category**: {f.category}",
                "",
                f.detail,
                "",
            ]
            if f.data:
                evidence = str(f.data)[:500]
                lines += ["**Evidence**:", "```", evidence, "```", ""]

    md_path = out / f"{stem}.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")

    return {"json_path": str(json_path), "markdown_path": str(md_path), "report_id": stem}


# ---------------------------------------------------------------------------
# Main recon runner
# ---------------------------------------------------------------------------

async def run_recon(args: argparse.Namespace) -> int:
    print(BANNER)
    print()

    if args.verbose:
        set_level("DEBUG")

    target_url = (args.target or "").strip()
    if not target_url:
        print("  [ERROR] --target URL is required.\n")
        print("  Example: python run_recon.py --target http://192.168.0.101\n")
        return 1

    tool_filter = [t.strip() for t in args.tools.split(",")] if args.tools else None

    # Safety check
    err = _check_safety(target_url)
    if err:
        print(f"\n  [BLOCKED] {err}\n")
        return 2

    print(f"  Target : {target_url}")
    print(f"  Tools  : {', '.join(tool_filter) if tool_filter else 'default set'}")
    print(f"  Output : {args.output}")
    print()

    try:
        from modules.recon_tools import ReconEngine
    except ImportError as exc:
        print(f"\n  [ERROR] Cannot import ReconEngine: {exc}")
        print("  Install dependencies:  pip install -r requirements.txt\n")
        return 1

    kill_switch = asyncio.Event()

    def _sigint() -> None:
        print("\n\n  Kill switch triggered. Stopping recon...\n")
        kill_switch.set()

    import signal as _signal
    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(_signal.SIGINT, _sigint)
    except (NotImplementedError, AttributeError):
        def _win_sigint(sig, frame):
            loop.call_soon_threadsafe(_sigint)
        _signal.signal(_signal.SIGINT, _win_sigint)

    # Load config for tool timeouts / wordlists
    import yaml
    cfg_path = PROJECT_ROOT / "config" / "web_vapt.yaml"
    cfg: dict = {}
    try:
        with open(cfg_path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except Exception:
        pass

    engine = ReconEngine(config=cfg, kill_switch=kill_switch)

    print("  Starting recon scan...\n")
    start = time.time()

    try:
        result = await engine.run(target_url, tool_filter=tool_filter)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n  Recon aborted before any results were collected.\n")
        return 130
    except Exception as exc:
        logger.exception("Recon failed: %s", exc)
        print(f"\n  [ERROR] Recon failed: {exc}\n")
        return 1

    result.duration = time.time() - start
    interrupted = kill_switch.is_set()

    # Write report
    try:
        report = _write_report(result, args.output, interrupted)
    except Exception as exc:
        logger.exception("Report generation failed: %s", exc)
        print(f"\n  [ERROR] Report generation failed: {exc}\n")
        return 1

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'='*58}")
    print(f"  RECON {'INTERRUPTED — PARTIAL RESULTS' if interrupted else 'COMPLETE'}")
    print(f"{'='*58}")
    print(f"  Report ID   : {report['report_id']}")
    print(f"  Target      : {result.target_url}")
    print(f"  Duration    : {result.duration:.0f}s")
    print(f"  Tools run   : {len(result.tools_run)}")
    if result.tools_run:
        print(f"    {', '.join(sorted(result.tools_run))}")
    if result.tools_unavailable:
        print(f"  Skipped     : {', '.join(sorted(result.tools_unavailable))}")

    if result.open_ports:
        port_strs = [
            f"{p['port']}/{p.get('protocol','tcp')} ({p.get('service','')})"
            for p in result.open_ports[:10]
        ]
        print(f"\n  Open Ports  : {', '.join(port_strs)}"
              + (f"  (+{len(result.open_ports)-10} more)" if len(result.open_ports) > 10 else ""))

    if result.subdomains:
        print(f"  Subdomains  : {len(result.subdomains)}  "
              f"({', '.join(result.subdomains[:5])}"
              + (", ..." if len(result.subdomains) > 5 else "") + ")")

    if result.web_dirs:
        print(f"  Web Paths   : {len(result.web_dirs)} discovered")

    if result.technologies:
        print(f"  Tech Stack  : {', '.join(result.technologies[:8])}")

    if result.waf_detected:
        print(f"  WAF         : {result.waf_detected}")

    if result.dns_records:
        print(f"  DNS         : {', '.join(f'{k}({len(v)})' for k, v in result.dns_records.items())}")

    if result.findings:
        sev_counts: dict[str, int] = {}
        for f in result.findings:
            sev_counts[f.severity.lower()] = sev_counts.get(f.severity.lower(), 0) + 1
        print(f"\n  Findings    : {len(result.findings)}")
        for sev in ("critical", "high", "medium", "low", "info"):
            n = sev_counts.get(sev, 0)
            if n:
                print(f"    {sev.upper():<10}: {n}")

    print(f"\n  JSON Report : {report['json_path']}")
    print(f"  MD Report   : {report['markdown_path']}")
    if interrupted:
        print(f"\n  NOTE: Scan was stopped by Ctrl+C. Report contains partial results.")
    print(f"{'='*58}\n")

    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        set_level("DEBUG")

    if args.create_lab_marker:
        cmd_create_lab_marker()
        sys.exit(0)

    if args.list_tools:
        cmd_list_tools()
        sys.exit(0)

    try:
        code = asyncio.run(run_recon(args))
        sys.exit(code)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n\n  Interrupted.\n")
        sys.exit(130)
    except Exception as exc:
        logger.exception("Fatal error: %s", exc)
        print(f"\n  Fatal error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
