"""
modules/agent_loop.py
=====================
Agentic Pentesting Loop — ReAct Pattern

Implements an autonomous, iterative penetration testing agent using the
Reason → Act → Observe → Reflect (ReAct) pattern.

Each iteration the agent:
  1. THINK  — rule-based + optional LLM reasoning over current context
  2. PLAN   — select next action from available skill set
  3. ACT    — execute tool (recon / exploit lookup / chain analysis)
  4. OBSERVE — parse output, merge findings into knowledge graph
  5. REFLECT — update hypotheses, decide if goal met or loop continues

No external API calls are required (runs fully offline with rule-based
planner). Pluggable LLM backend can be enabled via config.

Authorised lab environments only.
Python: 3.11+
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)


# ── Knowledge context accumulated across iterations ───────────────────────────

@dataclass
class AgentContext:
    target: str
    max_iterations: int = 10

    # Accumulated knowledge
    findings: list          = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    open_ports: list[dict]  = field(default_factory=list)
    subdomains: list[str]   = field(default_factory=list)
    web_dirs: list[str]     = field(default_factory=list)
    dns_records: dict       = field(default_factory=dict)
    emails: list[str]       = field(default_factory=list)
    historical_urls: list[str] = field(default_factory=list)
    waf_detected: str       = ""

    # Phase results
    exploit_report: Any     = None
    chain_report: Any       = None

    # Agent state
    completed_actions: list[str] = field(default_factory=list)
    hypotheses: list[str]   = field(default_factory=list)
    thoughts: list["AgentThought"] = field(default_factory=list)
    iteration: int          = 0
    start_time: float       = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    def merge_recon(self, result: Any) -> None:
        for f in getattr(result, "findings", []):
            if f not in self.findings:
                self.findings.append(f)
        for p in getattr(result, "open_ports", []):
            if p not in self.open_ports:
                self.open_ports.append(p)
        for s in getattr(result, "subdomains", []):
            if s not in self.subdomains:
                self.subdomains.append(s)
        for t in getattr(result, "technologies", []):
            if t not in self.technologies:
                self.technologies.append(t)
        for d in getattr(result, "web_dirs", []):
            if d not in self.web_dirs:
                self.web_dirs.append(d)
        for e in getattr(result, "emails", []):
            if e not in self.emails:
                self.emails.append(e)
        for u in getattr(result, "historical_urls", []):
            if u not in self.historical_urls:
                self.historical_urls.append(u)
        self.dns_records.update(getattr(result, "dns_records", {}))
        if getattr(result, "waf_detected", ""):
            self.waf_detected = result.waf_detected

    def smb_ports_open(self) -> bool:
        ports = {str(p.get("port", "")) for p in self.open_ports}
        return bool(ports & {"445", "139", "137"})

    def has_web(self) -> bool:
        return bool(self.technologies or self.web_dirs)


@dataclass
class AgentThought:
    iteration: int
    reasoning: str
    action: str
    action_args: dict
    observation: str = ""
    reflection: str = ""


@dataclass
class AgentResult:
    target: str
    iterations_used: int
    context: AgentContext
    success: bool
    stop_reason: str
    duration: float

    def summary(self) -> str:
        ctx = self.context
        return (
            f"Target: {self.target}\n"
            f"Duration: {self.duration:.0f}s  |  Iterations: {self.iterations_used}\n"
            f"Findings: {len(ctx.findings)}  |  "
            f"Ports: {len(ctx.open_ports)}  |  "
            f"Subdomains: {len(ctx.subdomains)}  |  "
            f"Technologies: {len(ctx.technologies)}\n"
            f"Exploits: {len(ctx.exploit_report.exploits) if ctx.exploit_report else 0}  |  "
            f"Attack chains: {len(ctx.chain_report.chains) if ctx.chain_report else 0}\n"
            f"Stop reason: {self.stop_reason}"
        )


# ── Rule-based planner ────────────────────────────────────────────────────────

class _Planner:
    """
    Priority-ordered rule set that selects the next agent action.
    Each rule: (condition_fn, action_name, action_args_fn)
    """

    def __init__(self, recon_phases: list[dict] | None = None):
        self._phases = recon_phases or [
            {"name": "initial_recon",   "tools": ["nmap", "nslookup", "whatweb", "wafw00f", "whois"]},
            {"name": "subdomain_deep",  "tools": ["subfinder", "dig", "dnsrecon"]},
            {"name": "web_discovery",   "tools": ["ffuf", "gobuster", "nikto"]},
            {"name": "osint",           "tools": ["theharvester", "gau", "waybackurls"]},
            {"name": "vuln_scan",       "tools": ["nuclei"]},
            {"name": "smb_scan",        "tools": ["enum4linux", "smbmap"]},
        ]

    def plan(self, ctx: AgentContext) -> tuple[str, dict]:
        done = set(ctx.completed_actions)

        if "initial_recon" not in done:
            return "recon", self._phases[0]

        if ctx.subdomains and "subdomain_deep" not in done:
            return "recon", self._phases[1]

        if ctx.has_web() and "web_discovery" not in done:
            return "recon", self._phases[2]

        if ctx.findings and "exploit_lookup" not in done:
            return "exploit_lookup", {}

        if ctx.exploit_report and "chain_analysis" not in done:
            return "chain_analysis", {}

        if ctx.subdomains and "osint" not in done:
            return "recon", self._phases[3]

        if ctx.technologies and "vuln_scan" not in done:
            return "recon", self._phases[4]

        if ctx.smb_ports_open() and "smb_scan" not in done:
            return "recon", self._phases[5]

        return "done", {}

    @staticmethod
    def reason(action: str, args: dict, ctx: AgentContext) -> str:
        phase = args.get("name", action)
        phase_reasons = {
            "initial_recon":  f"No data yet — probing attack surface of {ctx.target}",
            "subdomain_deep": f"{len(ctx.subdomains)} subdomain(s) found — enumerating DNS",
            "web_discovery":  f"Tech stack {ctx.technologies[:3]} — crawling for hidden paths",
            "osint":          "External target — harvesting OSINT and historical URLs",
            "vuln_scan":      "Tech identified — running targeted nuclei vuln scan",
            "smb_scan":       "SMB port open — enumerating shares and users",
            "exploit_lookup": f"{len(ctx.findings)} finding(s) — searching exploit-db + NVD",
            "chain_analysis": "Exploit data ready — mapping MITRE ATT&CK chains",
        }
        return phase_reasons.get(phase, f"Executing {phase}")

    @staticmethod
    def reflect(action: str, ctx: AgentContext) -> str:
        if action == "initial_recon":
            sev_counts: dict[str, int] = {}
            for f in ctx.findings:
                s = getattr(f, "severity", "info").lower()
                sev_counts[s] = sev_counts.get(s, 0) + 1
            crit = sev_counts.get("critical", 0)
            high = sev_counts.get("high", 0)
            return (
                f"Initial surface: {len(ctx.open_ports)} port(s), "
                f"{len(ctx.technologies)} tech(s), "
                f"{len(ctx.findings)} finding(s) "
                f"({crit} critical, {high} high)."
                + (f" WAF detected: {ctx.waf_detected}." if ctx.waf_detected else "")
            )
        if action == "exploit_lookup":
            er = ctx.exploit_report
            return (
                f"Found {len(er.exploits)} exploit(s) "
                f"({er.critical_count} critical, {er.high_count} high). "
                f"CVEs: {', '.join(er.cves_found[:4]) or 'none'}."
            ) if er else "Exploit lookup produced no results."
        if action == "chain_analysis":
            cr = ctx.chain_report
            return (
                f"Built {len(cr.chains)} chain(s). "
                f"Surface score: {cr.attack_surface_score}/10. "
                f"ATT&CK coverage: {', '.join(cr.mitre_coverage[:4])}."
            ) if cr else "No attack chains identified."
        return "Phase complete."


# ── Agent ─────────────────────────────────────────────────────────────────────

class PentestAgent:
    """
    Autonomous agentic pentest loop.

    Each call to run() iterates through the planner's action queue,
    accumulating findings, exploits, and attack chains.
    """

    def __init__(
        self,
        config: dict,
        kill_switch: asyncio.Event | None = None,
        max_iterations: int = 10,
        verbose: bool = False,
    ):
        self._cfg    = config
        self._kill   = kill_switch or asyncio.Event()
        self._max    = max_iterations
        self._verbose = verbose
        self._planner = _Planner()

    async def run(self, target: str) -> AgentResult:
        ctx = AgentContext(target=target, max_iterations=self._max)
        stop = "max_iterations"

        for i in range(self._max):
            if self._kill.is_set():
                stop = "kill_switch"
                break

            ctx.iteration = i + 1
            action, args = self._planner.plan(ctx)

            if action == "done":
                stop = "all_actions_complete"
                break

            reasoning  = self._planner.reason(action, args, ctx)
            thought = AgentThought(
                iteration=i + 1,
                reasoning=reasoning,
                action=action,
                action_args=args,
            )
            ctx.thoughts.append(thought)

            label = args.get("name", action)
            print(f"\n  [Agent  {i+1}/{self._max}]  {label}")
            if self._verbose:
                print(f"    Reason : {reasoning}")

            obs = await self._dispatch(action, args, ctx)
            thought.observation = obs[:400]
            thought.reflection  = self._planner.reflect(label, ctx)
            ctx.completed_actions.append(label)

            print(f"    Observe: {obs[:150]}{'...' if len(obs) > 150 else ''}")
            if self._verbose:
                print(f"    Reflect: {thought.reflection}")

        return AgentResult(
            target=target,
            iterations_used=ctx.iteration,
            context=ctx,
            success=bool(ctx.findings or ctx.open_ports),
            stop_reason=stop,
            duration=ctx.elapsed,
        )

    # ── Dispatch ──────────────────────────────────────────────────────────────

    async def _dispatch(self, action: str, args: dict, ctx: AgentContext) -> str:
        if action == "recon":
            return await self._do_recon(args.get("tools", []), ctx)
        if action == "exploit_lookup":
            return await self._do_exploit_lookup(ctx)
        if action == "chain_analysis":
            return await self._do_chain_analysis(ctx)
        return f"Unknown action: {action}"

    async def _do_recon(self, tools: list[str], ctx: AgentContext) -> str:
        try:
            from modules.recon_tools import ReconEngine
        except ImportError:
            return "ReconEngine not available"
        engine = ReconEngine(config=self._cfg, kill_switch=self._kill)
        try:
            result = await engine.run(ctx.target, tool_filter=tools or None)
        except Exception as exc:
            return f"Recon error: {exc}"
        ctx.merge_recon(result)
        return (
            f"{len(result.open_ports)} port(s), "
            f"{len(result.subdomains)} subdomain(s), "
            f"{len(result.findings)} finding(s), "
            f"{len(result.technologies)} tech(s). "
            f"Tools: {', '.join(result.tools_run)}."
        )

    async def _do_exploit_lookup(self, ctx: AgentContext) -> str:
        try:
            from modules.exploit_engine import ExploitEngine
        except ImportError:
            return "ExploitEngine not available"
        engine = ExploitEngine()
        try:
            report = await engine.analyze(ctx.findings, ctx.technologies, ctx.open_ports)
            report.target = ctx.target
        except Exception as exc:
            return f"Exploit lookup error: {exc}"
        ctx.exploit_report = report
        return report.summary

    async def _do_chain_analysis(self, ctx: AgentContext) -> str:
        try:
            from modules.attack_chain import AttackChainBuilder
        except ImportError:
            return "AttackChainBuilder not available"
        builder = AttackChainBuilder()
        try:
            report = builder.build(ctx.findings, ctx.target)
        except Exception as exc:
            return f"Chain analysis error: {exc}"
        ctx.chain_report = report
        return report.narrative_summary
