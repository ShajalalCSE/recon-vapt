#!/usr/bin/env python3
"""
run_vapt.py
===========
Web VAPT Standalone Entry Point
AI Red Team Harness v3 - Web Application Penetration Testing

Usage:
  python run_vapt.py --target http://192.168.0.101/dvwa
  python run_vapt.py --target http://192.168.0.101/dvwa --llm
  python run_vapt.py --target http://192.168.0.101/dvwa --llm --model llama3 --iter 5
  python run_vapt.py --target http://192.168.0.101/dvwa --cookie "PHPSESSID=abc123"
  python run_vapt.py --target http://192.168.0.101/dvwa --username admin --password secret
  python run_vapt.py --target http://192.168.0.101/dvwa --modules sqli,xss,lfi
  python run_vapt.py --create-lab-marker
  python run_vapt.py --dry-run --target http://192.168.0.101/dvwa

Authorised lab environments only.
Python: 3.11+
"""

from __future__ import annotations

import argparse
import asyncio
import io
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Bootstrap: ensure this folder is on sys.path
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.resolve()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Fix Windows console encoding for box-drawing characters
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from utils.logger import get_logger, set_level
from utils.burp_parser import parse_burp_request, ParsedBurpRequest

logger = get_logger(__name__)

BANNER = """\
+----------------------------------------------------------+
|          AI Red Team Harness  v3.0                       |
|          Web Application Penetration Testing             |
|                                                          |
|  *** AUTHORISED LAB ENVIRONMENTS ONLY ***                |
+----------------------------------------------------------+"""


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_vapt.py",
        description="Web VAPT - AI Red Team Harness v3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--target", metavar="URL",
        help="Target URL to scan (must be in config/safety.yaml allowlist)",
    )
    p.add_argument(
        "--output", metavar="DIR", default="reports/web",
        help="Output directory for reports (default: reports/web)",
    )
    p.add_argument(
        "--llm", action="store_true", default=False,
        help="Enable LLM agent (Phase 6) for AI-powered analysis",
    )
    p.add_argument(
        "--model", metavar="MODEL", default="llama3",
        help="Ollama model name for LLM agent (default: llama3)",
    )
    p.add_argument(
        "--llm-url", metavar="URL", default="http://localhost:11434",
        help="Ollama base URL (default: http://localhost:11434)",
    )
    p.add_argument(
        "--iter", metavar="N", type=int, default=12,
        help="Max LLM agent iterations (default: 12)",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable DEBUG-level logging",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Print resolved config then exit without scanning",
    )
    p.add_argument(
        "--create-lab-marker", action="store_true",
        help="Create .lab_mode_enabled safety marker and exit",
    )

    # ── Burp Suite request file ─────────────────────────────────────────────
    p.add_argument(
        "--request", "-r", metavar="FILE",
        help=(
            "Path to a raw HTTP request file exported from Burp Suite "
            "(same as sqlmap -r).  Extracts target URL, headers, cookies, "
            "session data, and parameters automatically.  "
            "--target is optional when -r is used."
        ),
    )

    # ── Authentication ──────────────────────────────────────────────────────
    auth = p.add_argument_group("authentication (optional)")
    auth.add_argument(
        "--cookie", metavar="COOKIE_STRING",
        help='Raw Cookie header value, e.g. "PHPSESSID=abc123; token=xyz"',
    )
    auth.add_argument(
        "--username", metavar="USER",
        help="Username for HTTP Basic Auth",
    )
    auth.add_argument(
        "--password", metavar="PASS",
        help="Password for HTTP Basic Auth (use with --username)",
    )

    # ── Module selection ────────────────────────────────────────────────────
    p.add_argument(
        "--modules", metavar="MOD1,MOD2,...",
        help=(
            "Comma-separated list of scan modules to run. "
            "Available: sqli, xss, idor, lfi, rfi, command_injection, csrf, auth, "
            "file_upload, security_headers, tls, cors, sensitive_files, "
            "debug_endpoints, ssrf, open_redirect, graphql, jwt, "
            "prototype_pollution, jwt_algorithm_confusion, wasm_memory_corruption, "
            "css_container_injection, http3_stream_side_channel, env_var_leakage, "
            "async_hooks_poisoning, http_smuggling_webtransport, mongodb_injection, "
            "dom_clobbering, server_timing_side_channel, web_crypto_timing, "
            "import_map_override, cache_stamping, webauthn_rp_confusion, "
            "deno_deserialization, http3_0rtt_replay, hpack_poisoning, "
            "graphql_n_plus_one, phar_deserialization. "
            "Omit to run all enabled modules."
        ),
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


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

async def run_scan(args: argparse.Namespace) -> int:
    print(BANNER)
    print()

    if args.verbose:
        set_level("DEBUG")

    # ── Parse Burp request file (optional) ────────────────────────────────
    burp: ParsedBurpRequest | None = None
    if args.request:
        req_path = Path(args.request)
        if not req_path.exists():
            print(f"  [ERROR] Burp request file not found: {req_path}\n")
            return 1
        try:
            burp = parse_burp_request(req_path)
        except Exception as exc:
            print(f"  [ERROR] Failed to parse Burp request file: {exc}\n")
            return 1

    # Target: explicit --target wins; fall back to URL from Burp file
    target_url = (args.target or "").strip()
    if not target_url and burp is not None:
        target_url = burp.url
    if not target_url:
        print("  [ERROR] --target URL is required (or provide a Burp file with -r).\n")
        print("  Example: python run_vapt.py --target http://192.168.0.101/dvwa\n")
        print("           python run_vapt.py -r burp_request.txt\n")
        return 1

    print(f"  Target   : {target_url}")
    print(f"  Output   : {args.output}")
    if args.llm:
        print(f"  LLM      : {args.model} @ {args.llm_url}  (max {args.iter} iterations)")
    if burp:
        print(f"  Burp file: {args.request}")
        print(f"  Method   : {burp.method}")
        param_count = len(burp.query_params) + len(burp.body_params)
        if param_count:
            all_names = ", ".join(burp.all_param_names())
            print(f"  Params   : {param_count} ({all_names})")
        if burp.cookie_header:
            preview = burp.cookie_header[:50] + ("..." if len(burp.cookie_header) > 50 else "")
            print(f"  Cookies  : {preview}")
        if burp.safe_headers:
            print(f"  Headers  : {len(burp.safe_headers)} forwarded from Burp file")
    if args.cookie:
        preview = args.cookie[:40] + ("..." if len(args.cookie) > 40 else "")
        print(f"  Cookie   : {preview}  (--cookie override)")
    if args.username:
        print(f"  Auth     : {args.username} / {'*' * min(len(args.password or ''), 8)}")
    if args.modules:
        print(f"  Modules  : {args.modules}")
    print()

    if args.dry_run:
        print("  [DRY RUN] Config resolved. No requests sent.\n")
        return 0

    try:
        from modules.web_vapt_engine import WebVAPTEngine
    except ImportError as exc:
        print(f"\n  [ERROR] Cannot import WebVAPTEngine: {exc}")
        print("  Install dependencies:  pip install -r requirements.txt\n")
        return 1

    kill_switch = asyncio.Event()

    def _sigint() -> None:
        print("\n\n  Kill switch triggered. Stopping scan...\n")
        kill_switch.set()

    loop = asyncio.get_running_loop()
    try:
        import signal
        loop.add_signal_handler(signal.SIGINT, _sigint)
    except (NotImplementedError, AttributeError):
        pass  # Windows SIGINT limitation

    module_filter = [m.strip() for m in args.modules.split(",")] if args.modules else None
    basic_auth = (args.username, args.password) if args.username and args.password else None

    # Cookie priority: explicit --cookie flag > Burp Cookie header
    effective_cookie = args.cookie or (burp.cookie_header if burp else None) or None
    extra_headers    = burp.safe_headers if burp else {}

    engine = WebVAPTEngine(
        config_path=PROJECT_ROOT / "config" / "web_vapt.yaml",
        safety_path=PROJECT_ROOT / "config" / "safety.yaml",
        kill_switch=kill_switch,
        cookies=effective_cookie,
        auth=basic_auth,
        module_filter=module_filter,
        extra_headers=extra_headers,
        burp_seed=burp,
    )

    if args.llm:
        engine._cfg["llm"] = {
            "enabled":        True,
            "model":          args.model,
            "base_url":       args.llm_url,
            "max_iterations": args.iter,
        }

    try:
        result = await engine.assess(target_url)
    except ValueError as exc:
        print(f"\n  [BLOCKED] {exc}\n")
        print("  Add the target URL to config/safety.yaml under web_vapt.allowed_urls\n")
        return 2
    except Exception as exc:
        logger.exception("Scan failed: %s", exc)
        print(f"\n  [ERROR] Scan failed: {exc}\n")
        return 1

    engine._cfg.setdefault("reporting", {})["output_dir"] = args.output
    report = await engine.generate_report(result)

    # Print summary
    rs = report.get("risk_summary", {})
    print(f"\n{'='*58}")
    print(f"  WEB VAPT COMPLETE")
    print(f"{'='*58}")
    print(f"  Report ID   : {report.get('report_id', '?')}")
    print(f"  Target      : {result.target_url}")
    print(f"  Duration    : {rs.get('scan_duration_s', 0):.0f}s")
    print(f"  Risk Score  : {rs.get('risk_score', 0):.1f}/100  [{rs.get('risk_label', '?')}]")
    print(f"  Findings    : {rs.get('total_findings', 0)}")
    print(f"    CRITICAL  : {rs.get('critical', 0)}")
    print(f"    HIGH      : {rs.get('high', 0)}")
    print(f"    MEDIUM    : {rs.get('medium', 0)}")
    print(f"    LOW       : {rs.get('low', 0)}")
    print(f"    INFO      : {rs.get('info', 0)}")
    print(f"  JSON Report : {report.get('json_path', '?')}")
    print(f"  MD Report   : {report.get('markdown_path', '?')}")
    print(f"{'='*58}\n")

    if rs.get("critical", 0) > 0 or rs.get("high", 0) > 0:
        print("  NOTE: CRITICAL / HIGH findings detected.")
        print("  Review the Markdown report for remediation steps.\n")

    # LLM agent summary
    lr = getattr(result, "llm_result", None)
    if lr is not None:
        print(f"{'--'*29}")
        if getattr(lr, "error", ""):
            print(f"  LLM Agent  : SKIPPED -- {lr.error}")
        else:
            print(f"  LLM Agent  : {getattr(lr,'model_used','?')} "
                  f"({getattr(lr,'iterations_used',0)} iterations)")
            print(f"  Risk Rating: {getattr(lr,'risk_rating','N/A')}")
            brief = getattr(lr, "executive_brief", "")
            if brief:
                print(f"\n  Executive Brief:\n")
                for line in brief.split(". "):
                    if line.strip():
                        print(f"    {line.strip()}.")
            chains = getattr(lr, "attack_chains", [])
            if chains:
                print(f"\n  Attack Chains Identified:")
                for c in chains:
                    print(f"    - {c}")
        print(f"{'--'*29}\n")

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

    try:
        code = asyncio.run(run_scan(args))
        sys.exit(code)
    except KeyboardInterrupt:
        print("\n\n  Interrupted.\n")
        sys.exit(130)
    except Exception as exc:
        logger.exception("Fatal error: %s", exc)
        print(f"\n  Fatal error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
