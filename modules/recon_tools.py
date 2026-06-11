"""
modules/recon_tools.py
======================
Kali Linux Recon Tools Integration
AI Red Team Harness v3 - Reconnaissance Engine

Integrates all major Kali Linux reconnaissance tools:

  Network Scanning   : nmap (full NSE), masscan
  DNS Recon          : nslookup, dig (AXFR), dnsrecon, dnsx, fierce, dnsenum
  Subdomain Enum     : subfinder, amass, assetfinder, gobuster (dns)
  Web Fuzzing        : ffuf, gobuster (dir/vhost), feroxbuster, dirb, dirsearch, wfuzz
  Web Fingerprinting : whatweb, wafw00f, nikto, httpx
  OSINT              : theHarvester, whois
  Historical URLs    : gau, waybackurls
  Vulnerability Scan : nuclei
  SMB / Windows      : enum4linux, smbmap
  Crawling           : katana

All tools run via asyncio.create_subprocess_exec — never shell=True.
Unavailable tools are skipped gracefully (FileNotFoundError caught).

Authorised lab / owned-infrastructure use only.
Python: 3.11+
"""

from __future__ import annotations

import asyncio
import json
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ReconFinding:
    tool: str
    category: str   # network | dns | subdomain | web_fuzz | fingerprint | osint | vulnerability
    title: str
    detail: str
    severity: str = "info"   # info | low | medium | high | critical
    target: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReconResult:
    target_url: str
    domain: str
    host: str
    port: int
    findings: list[ReconFinding]        = field(default_factory=list)
    tool_outputs: dict[str, Any]        = field(default_factory=dict)
    tools_run: list[str]                = field(default_factory=list)
    tools_available: list[str]          = field(default_factory=list)
    tools_unavailable: list[str]        = field(default_factory=list)
    subdomains: list[str]               = field(default_factory=list)
    open_ports: list[dict]              = field(default_factory=list)
    dns_records: dict[str, list[str]]   = field(default_factory=dict)
    web_dirs: list[str]                 = field(default_factory=list)
    technologies: list[str]             = field(default_factory=list)
    emails: list[str]                   = field(default_factory=list)
    historical_urls: list[str]          = field(default_factory=list)
    waf_detected: str                   = ""
    duration: float                     = 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Recon Engine
# ─────────────────────────────────────────────────────────────────────────────

# All known tools and their categories
ALL_TOOLS: dict[str, str] = {
    # Network
    "nmap":          "network_scan",
    "masscan":       "network_scan",
    # DNS
    "nslookup":      "dns",
    "dig":           "dns",
    "dnsrecon":      "dns",
    "dnsx":          "dns",
    "fierce":        "dns",
    "dnsenum":       "dns",
    # Subdomain Enumeration
    "subfinder":     "subdomain",
    "amass":         "subdomain",
    "assetfinder":   "subdomain",
    # Web Fuzzing
    "ffuf":          "web_fuzz",
    "gobuster":      "web_fuzz",
    "feroxbuster":   "web_fuzz",
    "dirb":          "web_fuzz",
    "dirsearch":     "web_fuzz",
    "wfuzz":         "web_fuzz",
    # Fingerprinting
    "whatweb":       "fingerprint",
    "wafw00f":       "fingerprint",
    "nikto":         "fingerprint",
    "httpx":         "fingerprint",
    # OSINT
    "theharvester":  "osint",
    "whois":         "osint",
    # Historical URLs
    "gau":           "historical",
    "waybackurls":   "historical",
    # Vulnerability
    "nuclei":        "vulnerability",
    # SMB / Windows
    "enum4linux":    "smb",
    "smbmap":        "smb",
    # Crawl
    "katana":        "crawl",
}

# Tools enabled by default when no tool_filter is given
DEFAULT_ENABLED: set[str] = {
    "nmap", "nslookup", "dig", "subfinder",
    "ffuf", "gobuster", "whatweb", "wafw00f",
    "nikto", "nuclei", "whois",
}


def _kill_proc(proc: asyncio.subprocess.Process) -> None:
    """Best-effort subprocess termination. Silently ignores all errors."""
    try:
        proc.kill()
    except Exception:
        pass


class ReconEngine:
    """
    Orchestrates all Kali Linux recon tools against a target URL.
    Tools that are not installed in PATH are skipped gracefully.
    """

    DEFAULT_TIMEOUT = 120.0

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        kill_switch: asyncio.Event | None = None,
    ) -> None:
        self._cfg  = config or {}
        self._kill = kill_switch
        self._tool_timeout = float(
            self._cfg.get("timeouts", {}).get("tool_execution_seconds", self.DEFAULT_TIMEOUT)
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    async def run(
        self,
        target_url: str,
        tool_filter: list[str] | None = None,
    ) -> ReconResult:
        """
        Run recon tools against target_url.
        tool_filter: names of specific tools to run (None = all default-enabled).
        """
        t0     = time.time()
        parsed = urlparse(target_url)
        host   = parsed.hostname or ""
        port   = parsed.port or (443 if parsed.scheme == "https" else 80)
        domain = host

        result = ReconResult(
            target_url=target_url,
            domain=domain,
            host=host,
            port=port,
        )

        tools_cfg = self._cfg.get("tools", {})

        def _enabled(name: str, default_on: bool = False) -> bool:
            if tool_filter:
                return name in tool_filter
            cfg_val = tools_cfg.get(name, {}).get("enabled", None)
            if cfg_val is not None:
                return bool(cfg_val)
            return default_on or (name in DEFAULT_ENABLED)

        # ── Build task map ────────────────────────────────────────────────────
        tasks: dict[str, Any] = {}

        # Network Scanning
        if _enabled("nmap") and host:
            tasks["nmap"] = self._run_nmap(host, tools_cfg.get("nmap", {}))
        if _enabled("masscan") and host:
            tasks["masscan"] = self._run_masscan(host, tools_cfg.get("masscan", {}))

        target_is_ip = _is_ip(domain)

        # DNS Recon — nslookup/dig work on both IPs (reverse) and domains
        if _enabled("nslookup") and domain:
            tasks["nslookup"] = self._run_nslookup(domain)
        if _enabled("dig") and domain:
            tasks["dig"] = self._run_dig(domain)
        # dnsrecon / dnsx / fierce / dnsenum require a real domain name
        if _enabled("dnsrecon") and domain and not target_is_ip:
            tasks["dnsrecon"] = self._run_dnsrecon(domain, tools_cfg.get("dnsrecon", {}))
        if _enabled("dnsx") and domain and not target_is_ip:
            tasks["dnsx"] = self._run_dnsx(domain)
        if _enabled("fierce") and domain and not target_is_ip:
            tasks["fierce"] = self._run_fierce(domain)
        if _enabled("dnsenum") and domain and not target_is_ip:
            tasks["dnsenum"] = self._run_dnsenum(domain)

        # Subdomain Enumeration — requires a real domain name, not an IP
        if _enabled("subfinder") and domain and not target_is_ip:
            tasks["subfinder"] = self._run_subfinder(domain, tools_cfg.get("subfinder", {}))
        if _enabled("amass") and domain and not target_is_ip:
            tasks["amass"] = self._run_amass(domain, tools_cfg.get("amass", {}))
        if _enabled("assetfinder") and domain and not target_is_ip:
            tasks["assetfinder"] = self._run_assetfinder(domain)

        # Gobuster runs dir mode on URL, dns mode on domain (if non-IP)
        if _enabled("gobuster"):
            tasks["gobuster_dir"] = self._run_gobuster_dir(target_url, tools_cfg.get("gobuster", {}))
            is_real_domain = (
                domain
                and domain != "localhost"
                and not _is_ip(domain)
            )
            if is_real_domain:
                tasks["gobuster_dns"] = self._run_gobuster_dns(domain, tools_cfg.get("gobuster", {}))
                tasks["gobuster_vhost"] = self._run_gobuster_vhost(
                    target_url, domain, tools_cfg.get("gobuster", {})
                )

        # Web Fuzzing
        if _enabled("ffuf"):
            tasks["ffuf"] = self._run_ffuf(target_url, tools_cfg.get("ffuf", {}))
        if _enabled("feroxbuster"):
            tasks["feroxbuster"] = self._run_feroxbuster(target_url, tools_cfg.get("feroxbuster", {}))
        if _enabled("dirb"):
            tasks["dirb"] = self._run_dirb(target_url, tools_cfg.get("dirb", {}))
        if _enabled("dirsearch"):
            tasks["dirsearch"] = self._run_dirsearch(target_url)
        if _enabled("wfuzz"):
            tasks["wfuzz"] = self._run_wfuzz(target_url, tools_cfg.get("wfuzz", {}))

        # Web Fingerprinting
        if _enabled("whatweb"):
            tasks["whatweb"] = self._run_whatweb(target_url)
        if _enabled("wafw00f"):
            tasks["wafw00f"] = self._run_wafw00f(target_url)
        if _enabled("nikto"):
            tasks["nikto"] = self._run_nikto(target_url)
        if _enabled("httpx") and host:
            tasks["httpx"] = self._run_httpx(target_url, tools_cfg.get("httpx", {}))

        # OSINT — theharvester/gau/waybackurls require a real domain
        if _enabled("theharvester") and domain and not target_is_ip:
            tasks["theharvester"] = self._run_theharvester(domain, tools_cfg.get("theharvester", {}))
        if _enabled("whois") and domain:
            tasks["whois"] = self._run_whois(domain)

        # Historical URLs — require a real domain name
        if _enabled("gau") and domain and not target_is_ip:
            tasks["gau"] = self._run_gau(domain)
        if _enabled("waybackurls") and domain and not target_is_ip:
            tasks["waybackurls"] = self._run_waybackurls(domain)

        # Vulnerability Scanning
        if _enabled("nuclei"):
            tasks["nuclei"] = self._run_nuclei(target_url, tools_cfg.get("nuclei", {}))

        # SMB / Windows Recon
        if _enabled("enum4linux") and host:
            tasks["enum4linux"] = self._run_enum4linux(host)
        if _enabled("smbmap") and host:
            tasks["smbmap"] = self._run_smbmap(host)

        # Crawl
        if _enabled("katana"):
            tasks["katana"] = self._run_katana(target_url)

        if not tasks:
            result.duration = time.time() - t0
            return result

        logger.info("ReconEngine: running %d tools: %s", len(tasks), ", ".join(tasks.keys()))

        # ── Execute all concurrently ──────────────────────────────────────────
        coro_list  = list(tasks.values())
        name_list  = list(tasks.keys())
        raw_results = await asyncio.gather(*coro_list, return_exceptions=True)

        # ── Collect results ───────────────────────────────────────────────────
        for name, res in zip(name_list, raw_results):
            if isinstance(res, Exception):
                logger.warning("Recon tool %s failed: %s", name, res)
                result.tool_outputs[name] = {"available": False, "error": str(res)}
                result.tools_unavailable.append(name)
            else:
                result.tool_outputs[name] = res
                result.tools_run.append(name)
                if res.get("available"):
                    result.tools_available.append(name)
                    self._process_output(result, name, res)
                else:
                    result.tools_unavailable.append(name)

        result.duration = time.time() - t0
        logger.info(
            "ReconEngine: complete in %.1fs | available=%d unavailable=%d "
            "ports=%d subdomains=%d dirs=%d",
            result.duration,
            len(result.tools_available),
            len(result.tools_unavailable),
            len(result.open_ports),
            len(result.subdomains),
            len(result.web_dirs),
        )
        return result

    def _process_output(self, result: ReconResult, tool: str, output: dict[str, Any]) -> None:
        """Normalise tool output into ReconResult aggregated fields."""

        if tool == "nmap":
            ports = output.get("open_ports", [])
            result.open_ports.extend(p for p in ports if p not in result.open_ports)
            for p in ports:
                if p.get("state") == "open":
                    result.findings.append(ReconFinding(
                        tool=tool, category="network",
                        title=f"Open Port {p.get('port')}/{p.get('protocol','tcp')}",
                        detail=f"Service: {p.get('service','')} {p.get('version','')}".strip(),
                        severity="info", target=result.host, data=p,
                    ))

        elif tool == "masscan":
            ports = output.get("open_ports", [])
            result.open_ports.extend(p for p in ports if p not in result.open_ports)

        elif tool in ("subfinder", "amass", "assetfinder", "gobuster_dns"):
            subs = output.get("subdomains", [])
            new  = [s for s in subs if s and s not in result.subdomains]
            result.subdomains.extend(new)
            if new:
                result.findings.append(ReconFinding(
                    tool=tool, category="subdomain",
                    title=f"{len(new)} Subdomains Discovered via {tool}",
                    detail=", ".join(new[:15]) + ("…" if len(new) > 15 else ""),
                    severity="info", target=result.domain,
                    data={"subdomains": new},
                ))

        elif tool in ("nslookup", "dig", "dnsrecon", "dnsx", "dnsenum", "fierce"):
            records = output.get("records", {})
            for rtype, values in records.items():
                existing = result.dns_records.get(rtype, [])
                result.dns_records[rtype] = list(dict.fromkeys(existing + values))
            if records:
                result.findings.append(ReconFinding(
                    tool=tool, category="dns",
                    title=f"DNS Records Found ({', '.join(records.keys())})",
                    detail=f"{sum(len(v) for v in records.values())} total records",
                    severity="info", target=result.domain, data=records,
                ))

        elif tool in ("ffuf", "gobuster_dir", "feroxbuster", "dirb", "dirsearch", "wfuzz"):
            paths = output.get("paths", [])
            new   = [p for p in paths if p and p not in result.web_dirs]
            result.web_dirs.extend(new)
            if new:
                result.findings.append(ReconFinding(
                    tool=tool, category="web_fuzz",
                    title=f"{len(new)} Web Paths Discovered via {tool}",
                    detail="\n".join(new[:20]),
                    severity="low", target=result.target_url,
                    data={"paths": new},
                ))

        elif tool == "gobuster_vhost":
            vhosts = output.get("vhosts", [])
            if vhosts:
                result.findings.append(ReconFinding(
                    tool=tool, category="web_fuzz",
                    title=f"{len(vhosts)} Virtual Hosts Discovered",
                    detail="\n".join(vhosts[:15]),
                    severity="low", target=result.target_url,
                    data={"vhosts": vhosts},
                ))

        elif tool == "whatweb":
            techs = output.get("technologies", [])
            new   = [t for t in techs if t and t not in result.technologies]
            result.technologies.extend(new)

        elif tool == "wafw00f":
            waf = output.get("waf", "")
            if waf and waf.lower() not in ("none", "no waf detected", ""):
                result.waf_detected = waf
                result.findings.append(ReconFinding(
                    tool=tool, category="fingerprint",
                    title=f"WAF Detected: {waf}",
                    detail=f"Web Application Firewall identified: {waf}",
                    severity="info", target=result.target_url, data={"waf": waf},
                ))

        elif tool == "theharvester":
            emails = output.get("emails", [])
            result.emails.extend(e for e in emails if e not in result.emails)
            subs   = output.get("subdomains", [])
            result.subdomains.extend(s for s in subs if s not in result.subdomains)
            if emails:
                result.findings.append(ReconFinding(
                    tool=tool, category="osint",
                    title=f"{len(emails)} Email Addresses Found",
                    detail=", ".join(emails[:10]),
                    severity="info", target=result.domain,
                    data={"emails": emails},
                ))

        elif tool in ("gau", "waybackurls"):
            urls = output.get("urls", [])
            new  = [u for u in urls if u and u not in result.historical_urls]
            result.historical_urls.extend(new)

        elif tool == "nuclei":
            for v in output.get("findings", []):
                sev = v.get("info", {}).get("severity", "info").lower()
                result.findings.append(ReconFinding(
                    tool=tool, category="vulnerability",
                    title=v.get("info", {}).get("name", "Nuclei Finding"),
                    detail=v.get("info", {}).get("description", ""),
                    severity=sev, target=v.get("matched-at", result.target_url),
                    data=v,
                ))

    # ─────────────────────────────────────────────────────────────────────────
    # Base subprocess runner
    # ─────────────────────────────────────────────────────────────────────────

    async def _run_tool(
        self,
        cmd: list[str],
        timeout: float | None = None,
        tool_name: str = "",
    ) -> tuple[str, str, int]:
        """Run cmd via asyncio subprocess. Never uses shell=True. Returns (stdout, stderr, rc)."""
        _timeout = timeout or self._tool_timeout
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            comm_task = asyncio.ensure_future(proc.communicate())

            # Race the subprocess against the kill switch (if any) and the timeout
            if self._kill is not None:
                kill_task = asyncio.ensure_future(self._kill.wait())
                try:
                    done, _ = await asyncio.wait(
                        {comm_task, kill_task},
                        timeout=_timeout,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                except asyncio.CancelledError:
                    kill_task.cancel()
                    comm_task.cancel()
                    _kill_proc(proc)
                    raise
                finally:
                    kill_task.cancel()

                if comm_task in done and not comm_task.cancelled():
                    stdout_b, stderr_b = comm_task.result()
                else:
                    # Kill switch fired or timeout — terminate the process
                    comm_task.cancel()
                    _kill_proc(proc)
                    try:
                        await asyncio.wait_for(proc.communicate(), timeout=2.0)
                    except Exception:
                        pass
                    if self._kill.is_set():
                        logger.debug("Tool %s stopped by kill switch", tool_name)
                        return "", "stopped by kill switch", -1
                    logger.warning("Tool %s timed out after %.0fs", tool_name, _timeout)
                    return "", f"timeout after {_timeout}s", -1
            else:
                try:
                    stdout_b, stderr_b = await asyncio.wait_for(comm_task, timeout=_timeout)
                except asyncio.TimeoutError:
                    comm_task.cancel()
                    _kill_proc(proc)
                    try:
                        await proc.communicate()
                    except Exception:
                        pass
                    logger.warning("Tool %s timed out after %.0fs", tool_name, _timeout)
                    return "", f"timeout after {_timeout}s", -1
                except asyncio.CancelledError:
                    comm_task.cancel()
                    _kill_proc(proc)
                    raise

            return (
                stdout_b.decode("utf-8", errors="replace"),
                stderr_b.decode("utf-8", errors="replace"),
                proc.returncode or 0,
            )
        except FileNotFoundError:
            logger.debug("Tool not available (not in PATH): %s", tool_name)
            return "", f"{tool_name} not found in PATH", 127
        except asyncio.CancelledError:
            if proc is not None:
                _kill_proc(proc)
            raise
        except Exception as exc:
            logger.warning("Tool %s unexpected error: %s", tool_name, exc)
            return "", str(exc), -1

    # =========================================================================
    # Network Scanning
    # =========================================================================

    async def _run_nmap(self, host: str, cfg: dict) -> dict[str, Any]:
        """
        Comprehensive nmap scan:
          -sV  service/version detection
          -sC  default NSE scripts
          -O   OS detection
          NSE: http-enum, http-headers, http-methods, http-auth, http-shellshock,
               http-title, http-server-header, http-robots.txt, http-git,
               ssl-enum-ciphers, ssl-heartbleed, ssl-poodle,
               ftp-anon, ssh-auth-methods, smb-vuln-ms17-010
          XML output (-oX -) parsed into structured port list.
        """
        port_range = cfg.get("port_range", "1-10000")
        timing     = cfg.get("timing_template", "T4")
        scripts    = cfg.get("script_scan", [
            "http-enum", "http-headers", "http-methods", "http-auth",
            "http-title", "http-server-header", "http-robots.txt",
            "http-git", "http-shellshock", "http-userdir-enum",
            "ssl-enum-ciphers", "ssl-heartbleed", "ssl-poodle",
            "ftp-anon", "ftp-bounce", "ssh-auth-methods",
            "smb-vuln-ms17-010", "smb-security-mode",
        ])
        script_str = ",".join(scripts)

        cmd = [
            "nmap", f"-{timing}", "-sV", "-sC",
            "--script", script_str,
            "-p", str(port_range),
            "--open",
            "-oX", "-",
            host,
        ]
        if cfg.get("os_detection", True):
            cmd.insert(1, "-O")

        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout * 3, "nmap")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        open_ports = _parse_nmap_xml(stdout)
        return {
            "available": True,
            "host": host,
            "open_ports": open_ports,
            "count": len(open_ports),
            "raw": stdout[:8000],
        }

    async def _run_masscan(self, host: str, cfg: dict) -> dict[str, Any]:
        """Fast port discovery with masscan."""
        port_range = cfg.get("port_range", "1-65535")
        rate       = cfg.get("rate", 1000)
        cmd = ["masscan", host, "-p", str(port_range), "--rate", str(rate), "-oJ", "-"]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "masscan")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        ports: list[dict] = []
        try:
            data = json.loads(stdout)
            for entry in data:
                for p in entry.get("ports", []):
                    ports.append({
                        "port": p.get("port"),
                        "protocol": p.get("proto", "tcp"),
                        "state": p.get("status", "open"),
                        "service": "",
                    })
        except (json.JSONDecodeError, ValueError):
            pass
        return {"available": True, "open_ports": ports, "count": len(ports)}

    # =========================================================================
    # DNS Reconnaissance
    # =========================================================================

    async def _run_nslookup(self, domain: str) -> dict[str, Any]:
        """
        nslookup: query A, AAAA, MX, NS, TXT, CNAME, SOA for domains,
        or PTR reverse lookup for IP addresses.
        """
        records: dict[str, list[str]] = {}

        if _is_ip(domain):
            # Reverse DNS lookup
            cmd = ["nslookup", domain]
            stdout, stderr, rc = await self._run_tool(cmd, 10.0, "nslookup-PTR")
            if rc == 127:
                return {"available": False, "error": "nslookup not found in PATH"}
            ptr: list[str] = []
            for line in stdout.splitlines():
                line = line.strip()
                if "name =" in line.lower():
                    val = line.split("=")[-1].strip().rstrip(".")
                    if val:
                        ptr.append(val)
            if ptr:
                records["PTR"] = ptr
            return {
                "available": True,
                "domain": domain,
                "records": records,
                "note": "IP target — performed reverse DNS lookup",
            }

        # Domain: query all standard record types
        not_found = False
        for qtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            cmd = ["nslookup", f"-type={qtype}", domain]
            stdout, _, rc = await self._run_tool(cmd, 10.0, f"nslookup-{qtype}")
            if rc == 127:
                not_found = True
                break
            if stdout:
                parsed = _parse_nslookup_output(stdout, qtype)
                if parsed:
                    records[qtype] = parsed

        if not_found:
            return {"available": False, "error": "nslookup not found in PATH"}
        return {"available": True, "domain": domain, "records": records}

    async def _run_dig(self, domain: str) -> dict[str, Any]:
        """
        dig: detailed DNS records + zone transfer (AXFR) attempt.
        For IP addresses performs a reverse PTR lookup (dig -x).
        """
        records: dict[str, list[str]] = {}

        if _is_ip(domain):
            # Reverse PTR lookup
            cmd = ["dig", "-x", domain, "+noall", "+answer"]
            stdout, stderr, rc = await self._run_tool(cmd, 10.0, "dig-PTR")
            if rc == 127:
                return {"available": False, "error": "dig not found in PATH"}
            parsed = _parse_dig_answer(stdout)
            if parsed:
                records["PTR"] = parsed
            return {
                "available": True,
                "domain": domain,
                "records": records,
                "note": "IP target — performed reverse DNS lookup",
            }

        # Domain: query all standard record types
        not_found = False
        for qtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "ANY"):
            cmd = ["dig", "+noall", "+answer", qtype, domain]
            stdout, _, rc = await self._run_tool(cmd, 10.0, f"dig-{qtype}")
            if rc == 127:
                not_found = True
                break
            if stdout:
                parsed = _parse_dig_answer(stdout)
                if parsed:
                    records[qtype] = parsed

        if not_found:
            return {"available": False, "error": "dig not found in PATH"}

        # Zone transfer attempt (educational — typically REFUSED)
        axfr_out = ""
        cmd_axfr = ["dig", "AXFR", domain]
        stdout_axfr, _, _ = await self._run_tool(cmd_axfr, 15.0, "dig-axfr")
        if (stdout_axfr
                and "Transfer failed" not in stdout_axfr
                and "REFUSED" not in stdout_axfr
                and "no servers could be reached" not in stdout_axfr.lower()):
            axfr_out = stdout_axfr[:2000]

        return {
            "available": True,
            "domain": domain,
            "records": records,
            "axfr_result": axfr_out or "REFUSED / FAILED (expected)",
        }

    async def _run_dnsrecon(self, domain: str, cfg: dict) -> dict[str, Any]:
        """dnsrecon: comprehensive DNS enumeration (std, SRV, bruteforce, AXFR)."""
        scan_type = cfg.get("scan_type", "std,brt,srv,axfr")
        cmd = [
            "dnsrecon", "-d", domain,
            "-t", scan_type,
            "--json", "/dev/stdout",
        ]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "dnsrecon")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        records: dict[str, list[str]] = {}
        subdomains: list[str] = []
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                for entry in data:
                    rtype = entry.get("type", "MISC")
                    name  = entry.get("name", entry.get("target", ""))
                    addr  = entry.get("address", entry.get("strings", ""))
                    val   = f"{name} -> {addr}" if name and addr else (name or str(addr))
                    if val:
                        records.setdefault(rtype, []).append(val)
                    if name and domain in name and name != domain:
                        subdomains.append(name)
        except (json.JSONDecodeError, ValueError):
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("[*]") or line.startswith("[+]"):
                    records.setdefault("misc", []).append(line[3:].strip())

        return {
            "available": True,
            "domain": domain,
            "records": records,
            "subdomains": subdomains,
        }

    async def _run_dnsx(self, domain: str) -> dict[str, Any]:
        """dnsx: fast multi-type DNS resolver."""
        cmd = [
            "dnsx", "-d", domain,
            "-a", "-aaaa", "-mx", "-ns", "-txt",
            "-json", "-silent",
        ]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "dnsx")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        records: dict[str, list[str]] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                for rtype in ("a", "aaaa", "mx", "ns", "txt"):
                    vals = d.get(rtype, [])
                    if vals:
                        records.setdefault(rtype.upper(), []).extend(vals)
            except (json.JSONDecodeError, ValueError):
                pass
        if not records:
            return {"available": False, "error": "dnsx: no records returned"}
        return {"available": True, "domain": domain, "records": records}

    async def _run_fierce(self, domain: str) -> dict[str, Any]:
        """fierce: DNS brute force + zone walk."""
        wordlist = "/usr/share/fierce/hosts.txt"
        cmd = ["fierce", "--domain", domain]
        if Path(wordlist).exists():
            cmd += ["--subdomains-file", wordlist]

        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "fierce")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        subdomains: list[str] = []
        records: dict[str, list[str]] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if domain in line and "." in line:
                parts = line.split()
                if parts:
                    sub = parts[0].rstrip(".")
                    if sub.endswith(domain) and sub != domain:
                        subdomains.append(sub)
            if "IP:" in line or "Found:" in line:
                records.setdefault("A", []).append(line)

        return {
            "available": True,
            "domain": domain,
            "subdomains": subdomains,
            "records": records,
            "raw": stdout[:3000],
        }

    async def _run_dnsenum(self, domain: str) -> dict[str, Any]:
        """dnsenum: DNS enumeration including subdomain brute force."""
        cmd = ["dnsenum", "--nocolor", "--noreverse", domain]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "dnsenum")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        subdomains: list[str] = []
        records: dict[str, list[str]] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if domain in line and line.endswith("."):
                sub = line.split()[0].rstrip(".")
                if sub and sub.endswith(domain) and sub != domain:
                    subdomains.append(sub)
            if "Name Servers:" in line or "Mail Servers:" in line:
                records.setdefault("NS", []).append(line)

        return {
            "available": True,
            "domain": domain,
            "subdomains": subdomains,
            "records": records,
            "raw": stdout[:3000],
        }

    # =========================================================================
    # Subdomain Enumeration
    # =========================================================================

    async def _run_subfinder(self, domain: str, cfg: dict) -> dict[str, Any]:
        """subfinder: passive subdomain enumeration from many sources."""
        cmd = ["subfinder", "-d", domain, "-silent"]
        sources = cfg.get("sources", [])
        if sources:
            cmd += ["-sources", ",".join(sources)]
        if cfg.get("recursive", False):
            cmd.append("-recursive")

        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "subfinder")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        subs = [s.strip() for s in stdout.splitlines() if s.strip()]
        return {"available": True, "domain": domain, "subdomains": subs, "count": len(subs)}

    async def _run_amass(self, domain: str, cfg: dict) -> dict[str, Any]:
        """amass: comprehensive subdomain enumeration (passive or active)."""
        mode = cfg.get("mode", "passive")
        cmd  = ["amass", "enum", f"-{mode}", "-d", domain]
        if cfg.get("config"):
            cmd += ["-config", cfg["config"]]

        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout * 3, "amass")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        subs: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                name = d.get("name", "")
                if name:
                    subs.append(name)
            except (json.JSONDecodeError, ValueError):
                if domain in line:
                    subs.append(line.split()[0])

        return {"available": True, "domain": domain, "subdomains": subs, "count": len(subs)}

    async def _run_assetfinder(self, domain: str) -> dict[str, Any]:
        """assetfinder: quick subdomain discovery."""
        cmd = ["assetfinder", "--subs-only", domain]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "assetfinder")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        subs = [s.strip() for s in stdout.splitlines() if s.strip() and domain in s]
        return {"available": True, "domain": domain, "subdomains": subs, "count": len(subs)}

    # =========================================================================
    # Web Fuzzing / Directory Brute Force
    # =========================================================================

    async def _run_ffuf(self, url: str, cfg: dict) -> dict[str, Any]:
        """
        ffuf: fast web fuzzer for directory/file/parameter discovery.
        Appends /FUZZ to the base URL if no FUZZ marker present.
        """
        wordlist = cfg.get(
            "wordlist",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        )
        threads  = str(cfg.get("threads", 50))
        statuses = cfg.get("matcher_status", "200,204,301,302,307,401,403,405")

        fuzz_url = url.rstrip("/") + "/FUZZ" if "FUZZ" not in url else url

        cmd = [
            "ffuf",
            "-u", fuzz_url,
            "-w", wordlist,
            "-t", threads,
            "-mc", statuses,
            "-o", "/dev/stdout",
            "-of", "json",
            "-s",
        ]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout * 2, "ffuf")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        paths: list[str] = []
        try:
            data = json.loads(stdout)
            for res in data.get("results", []):
                path   = res.get("url", res.get("input", {}).get("FUZZ", ""))
                status = res.get("status", 0)
                size   = res.get("length", 0)
                if path:
                    paths.append(f"{path} [Status:{status}] [Size:{size}]")
        except (json.JSONDecodeError, ValueError):
            for line in stdout.splitlines():
                if "[Status:" in line or "200" in line:
                    paths.append(line.strip())

        return {"available": True, "target": url, "paths": paths, "count": len(paths)}

    async def _run_gobuster_dir(self, url: str, cfg: dict) -> dict[str, Any]:
        """gobuster dir: directory/file brute forcing."""
        wordlist   = cfg.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
        threads    = str(cfg.get("threads", 30))
        statuses   = cfg.get("status_codes", "200,204,301,302,307,401,403")
        extensions = cfg.get("extensions", "php,html,txt,js,json,xml,bak,zip")

        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-t", threads,
            "-s", statuses,
            "-x", extensions,
            "--no-error",
            "-q",
        ]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout * 2, "gobuster-dir")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        paths = [
            line.strip()
            for line in stdout.splitlines()
            if line.strip() and ("Status:" in line or line.strip().startswith("/"))
        ]
        return {"available": True, "target": url, "paths": paths, "count": len(paths)}

    async def _run_gobuster_dns(self, domain: str, cfg: dict) -> dict[str, Any]:
        """gobuster dns: subdomain brute forcing."""
        wordlist = cfg.get(
            "dns_wordlist",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        )
        threads = str(cfg.get("threads", 30))

        cmd = [
            "gobuster", "dns",
            "-d", domain,
            "-w", wordlist,
            "-t", threads,
            "--no-error",
            "-q",
        ]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout * 2, "gobuster-dns")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        subs: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if domain in line:
                parts = line.split()
                if parts:
                    subs.append(parts[-1].rstrip("."))

        return {"available": True, "domain": domain, "subdomains": subs, "count": len(subs)}

    async def _run_gobuster_vhost(self, url: str, domain: str, cfg: dict) -> dict[str, Any]:
        """gobuster vhost: virtual host discovery."""
        wordlist = cfg.get(
            "wordlist",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        )
        threads = str(cfg.get("threads", 30))

        cmd = [
            "gobuster", "vhost",
            "-u", url,
            "-w", wordlist,
            "-t", threads,
            "--no-error",
            "-q",
        ]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout * 2, "gobuster-vhost")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        vhosts = [
            line.strip()
            for line in stdout.splitlines()
            if line.strip() and "Found:" in line
        ]
        return {"available": True, "target": url, "vhosts": vhosts}

    async def _run_feroxbuster(self, url: str, cfg: dict) -> dict[str, Any]:
        """feroxbuster: recursive directory fuzzing."""
        wordlist = cfg.get(
            "wordlist",
            "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
        )
        threads  = str(cfg.get("threads", 50))
        statuses = cfg.get("status_codes", "200,204,301,302,307,401,403,405,500")

        cmd = [
            "feroxbuster",
            "--url", url,
            "--wordlist", wordlist,
            "--threads", threads,
            "--status-codes", statuses,
            "--quiet",
            "--json",
            "--output", "/dev/stdout",
        ]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout * 2, "feroxbuster")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        paths: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                if d.get("type") == "response":
                    path   = d.get("url", "")
                    status = d.get("status", 0)
                    if path:
                        paths.append(f"{path} [Status:{status}]")
            except (json.JSONDecodeError, ValueError):
                if url in line:
                    paths.append(line)

        return {"available": True, "target": url, "paths": paths, "count": len(paths)}

    async def _run_dirb(self, url: str, cfg: dict) -> dict[str, Any]:
        """dirb: classic directory brute force."""
        wordlist = cfg.get("wordlist", "/usr/share/dirb/wordlists/common.txt")
        cmd = ["dirb", url, wordlist, "-S", "-r", "-o", "/dev/stdout"]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout * 2, "dirb")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        paths = [
            line.strip()[2:]
            for line in stdout.splitlines()
            if line.strip().startswith("+ ") and url in line
        ]
        return {"available": True, "target": url, "paths": paths, "count": len(paths)}

    async def _run_dirsearch(self, url: str) -> dict[str, Any]:
        """dirsearch: directory/file discovery with auto extension detection."""
        cmd = [
            "dirsearch", "-u", url,
            "--format", "json",
            "-o", "/dev/stdout",
            "--quiet",
        ]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout * 2, "dirsearch")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        paths: list[str] = []
        try:
            data = json.loads(stdout)
            for entry in data.get("results", []):
                path   = entry.get("url", entry.get("path", ""))
                status = entry.get("status", 0)
                if path:
                    paths.append(f"{path} [Status:{status}]")
        except (json.JSONDecodeError, ValueError):
            for line in stdout.splitlines():
                if "[" in line and "]" in line:
                    paths.append(line.strip())

        return {"available": True, "target": url, "paths": paths, "count": len(paths)}

    async def _run_wfuzz(self, url: str, cfg: dict) -> dict[str, Any]:
        """wfuzz: highly configurable web application fuzzer."""
        wordlist = cfg.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
        fuzz_url = url.rstrip("/") + "/FUZZ" if "FUZZ" not in url else url

        cmd = [
            "wfuzz", "-w", wordlist,
            "--hc", "404",
            "-f", "/dev/stdout,json",
            fuzz_url,
        ]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout * 2, "wfuzz")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        paths: list[str] = []
        try:
            data = json.loads(stdout)
            items = data if isinstance(data, list) else data.get("results", [])
            for item in items:
                found_url  = item.get("url", "")
                resp_code  = item.get("code", 0)
                if found_url:
                    paths.append(f"{found_url} [Status:{resp_code}]")
        except (json.JSONDecodeError, ValueError):
            for line in stdout.splitlines():
                if any(code in line for code in ("200", "301", "302", "403")):
                    paths.append(line.strip())

        return {"available": True, "target": url, "paths": paths, "count": len(paths)}

    # =========================================================================
    # Web Fingerprinting
    # =========================================================================

    async def _run_whatweb(self, url: str) -> dict[str, Any]:
        """whatweb: identify technologies, CMS, frameworks."""
        cmd = ["whatweb", "--log-json=-", "--quiet", "--color=never", url]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "whatweb")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        technologies: list[str] = []
        try:
            data = json.loads(stdout)
            if isinstance(data, list) and data:
                plugins = data[0].get("plugins", {})
                technologies = list(plugins.keys())
        except (json.JSONDecodeError, ValueError):
            for line in stdout.splitlines():
                if "[" in line:
                    for part in line.split("[")[1:]:
                        tech = part.split("]")[0].strip()
                        if tech:
                            technologies.append(tech)

        return {"available": True, "url": url, "technologies": technologies, "raw": stdout[:2000]}

    async def _run_wafw00f(self, url: str) -> dict[str, Any]:
        """wafw00f: detect and identify WAF presence."""
        cmd = ["wafw00f", url, "-a", "-o", "/dev/stdout", "-f", "json"]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "wafw00f")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        waf = ""
        try:
            data = json.loads(stdout)
            entries = data if isinstance(data, list) else [data]
            for entry in entries:
                fw = entry.get("firewall", "") or entry.get("manufacturer", "")
                if fw:
                    waf = fw
                    break
        except (json.JSONDecodeError, ValueError):
            for line in stdout.splitlines():
                line_l = line.lower()
                if "is behind" in line_l or "waf" in line_l:
                    waf = line.strip()
                    break
                if "no waf" in line_l or "not behind" in line_l:
                    waf = "None"
                    break

        return {"available": True, "url": url, "waf": waf or "None"}

    async def _run_nikto(self, url: str) -> dict[str, Any]:
        """nikto: web server vulnerability scanner."""
        cmd = ["nikto", "-h", url, "-Format", "json", "-nointeractive", "-Tuning", "x"]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "nikto")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}
        try:
            return {"available": True, "output": json.loads(stdout)}
        except (json.JSONDecodeError, ValueError):
            return {"available": True, "raw": stdout[:3000]}

    async def _run_httpx(self, url: str, cfg: dict) -> dict[str, Any]:
        """httpx: fast HTTP probing, title, tech detection."""
        flags = cfg.get("flags", [
            "-silent", "-follow-redirects", "-title",
            "-tech-detect", "-status-code", "-content-length",
            "-web-server", "-json",
        ])
        cmd = ["httpx", "-u", url] + list(flags)
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "httpx")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        result: dict[str, Any] = {"available": True, "url": url}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                result.update({k: v for k, v in {
                    "status_code":    d.get("status_code"),
                    "title":          d.get("title"),
                    "technologies":   d.get("tech", []),
                    "web_server":     d.get("webserver"),
                    "content_length": d.get("content_length"),
                }.items() if v is not None})
            except (json.JSONDecodeError, ValueError):
                pass
        return result

    # =========================================================================
    # OSINT
    # =========================================================================

    async def _run_theharvester(self, domain: str, cfg: dict) -> dict[str, Any]:
        """theHarvester: gather emails, subdomains, IPs from public sources."""
        sources = cfg.get("sources", "google,bing,duckduckgo,linkedin,hackertarget")
        limit   = str(cfg.get("limit", 500))
        cmd = [
            "theHarvester", "-d", domain,
            "-b", sources,
            "-l", limit,
            "-f", "/dev/stdout",
        ]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout * 2, "theHarvester")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        emails:     list[str] = []
        subdomains: list[str] = []
        ips:        list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if "@" in line and "." in line and not line.startswith("["):
                emails.append(line)
            elif domain in line and "." in line and "@" not in line and not line.startswith("["):
                parts = line.split()
                if parts and parts[0].endswith(domain):
                    subdomains.append(parts[0])
            elif _is_ip(line):
                ips.append(line)

        return {
            "available": True,
            "domain": domain,
            "emails": emails,
            "subdomains": subdomains,
            "ips": ips,
            "raw": stdout[:5000],
        }

    async def _run_whois(self, domain: str) -> dict[str, Any]:
        """whois: domain registration information."""
        cmd = ["whois", domain]
        stdout, stderr, rc = await self._run_tool(cmd, 30.0, "whois")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        _keep = {
            "registrar", "registrant_name", "registrant_organization",
            "creation_date", "expiry_date", "expiration_date", "updated_date",
            "name_server", "status", "registrant_email", "dnssec",
        }
        info: dict[str, str] = {}
        for line in stdout.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                k = key.strip().lower().replace(" ", "_")
                v = val.strip()
                if v and k in _keep and k not in info:
                    info[k] = v

        return {"available": True, "domain": domain, "info": info, "raw": stdout[:3000]}

    # =========================================================================
    # Historical URLs
    # =========================================================================

    async def _run_gau(self, domain: str) -> dict[str, Any]:
        """gau: fetch all known URLs for a domain from public archives."""
        cmd = [
            "gau", "--json",
            "--blacklist", "png,jpg,gif,jpeg,css,woff,woff2,ttf,eot,svg,ico",
            domain,
        ]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "gau")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        urls: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                u = d.get("url", "")
                if u:
                    urls.append(u)
            except (json.JSONDecodeError, ValueError):
                if line.startswith("http"):
                    urls.append(line)

        return {"available": True, "domain": domain, "urls": urls[:500], "count": len(urls)}

    async def _run_waybackurls(self, domain: str) -> dict[str, Any]:
        """waybackurls: fetch Wayback Machine URLs for a domain."""
        cmd = ["waybackurls", domain]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "waybackurls")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        urls = [u.strip() for u in stdout.splitlines() if u.strip().startswith("http")]
        return {"available": True, "domain": domain, "urls": urls[:500], "count": len(urls)}

    # =========================================================================
    # Vulnerability Scanning
    # =========================================================================

    async def _run_nuclei(self, url: str, cfg: dict) -> dict[str, Any]:
        """nuclei: template-based vulnerability scanner."""
        severity    = cfg.get("severity_filter", "low,medium,high,critical")
        templates   = cfg.get("templates", ["cves/", "misconfiguration/", "vulnerabilities/"])
        rate_limit  = str(cfg.get("rate_limit", 150))
        concurrency = str(cfg.get("concurrency", 50))

        cmd = [
            "nuclei", "-u", url,
            "-json", "-silent",
            "-severity", severity,
            "-rl", rate_limit,
            "-c", concurrency,
        ]
        for tmpl in templates:
            cmd += ["-t", tmpl]

        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout * 3, "nuclei")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        findings: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                pass
        return {"available": True, "findings": findings, "count": len(findings)}

    # =========================================================================
    # SMB / Windows Recon
    # =========================================================================

    async def _run_enum4linux(self, host: str) -> dict[str, Any]:
        """enum4linux: SMB/CIFS/Windows enumeration."""
        cmd = ["enum4linux", "-a", "-o", host]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "enum4linux")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        info: dict[str, Any] = {"host": host}
        for line in stdout.splitlines():
            if "Domain Name:" in line:
                info["domain"] = line.split(":")[-1].strip()
            elif "OS:" in line:
                info["os"] = line.split(":")[-1].strip()
            elif "Workgroup" in line:
                info["workgroup"] = line.split(":")[-1].strip()

        return {"available": True, "raw": stdout[:5000], **info}

    async def _run_smbmap(self, host: str) -> dict[str, Any]:
        """smbmap: SMB share enumeration with permissions."""
        cmd = ["smbmap", "-H", host, "--no-banner"]
        stdout, stderr, rc = await self._run_tool(cmd, self._tool_timeout, "smbmap")
        if not stdout or rc == 127:
            return {"available": False, "error": stderr[:500]}

        shares = [
            line.strip()
            for line in stdout.splitlines()
            if any(kw in line for kw in ("READ", "WRITE", "NO ACCESS"))
        ]
        return {"available": True, "host": host, "shares": shares, "raw": stdout[:2000]}

    # =========================================================================
    # Web Crawling
    # =========================================================================

    async def _run_katana(self, url: str) -> dict[str, Any]:
        """katana: JS-aware web crawler."""
        cmd = ["katana", "-u", url, "-silent", "-jc", "-depth", "3", "-jsonl"]
        stdout, _, rc = await self._run_tool(cmd, self._tool_timeout, "katana")
        if rc == 127:
            return {"available": False, "error": "katana not found"}

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

        if not urls:
            return {"available": False, "error": "katana: no URLs crawled"}
        return {"available": True, "target": url, "urls": urls[:200], "count": len(urls)}


# ─────────────────────────────────────────────────────────────────────────────
# Output Parsers (module-level helpers)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_nmap_xml(xml_str: str) -> list[dict[str, Any]]:
    """Parse nmap XML (-oX -) into a list of open-port dicts."""
    ports: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_str)
        for host_el in root.findall("host"):
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                svc_el   = port_el.find("service")
                state = state_el.get("state", "") if state_el is not None else ""
                if state != "open":
                    continue
                portid  = port_el.get("portid", "")
                proto   = port_el.get("protocol", "tcp")
                svc     = svc_el.get("name", "")    if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""
                # Collect NSE script output
                scripts: list[str] = []
                for sc_el in port_el.findall("script"):
                    sc_id  = sc_el.get("id", "")
                    sc_out = sc_el.get("output", "")[:300]
                    if sc_id and sc_out:
                        scripts.append(f"{sc_id}: {sc_out}")
                ports.append({
                    "port":     int(portid) if portid.isdigit() else portid,
                    "protocol": proto,
                    "state":    state,
                    "service":  svc,
                    "product":  product,
                    "version":  f"{product} {version}".strip(),
                    "scripts":  scripts,
                })
    except ET.ParseError:
        pass
    return ports


def _parse_nslookup_output(output: str, qtype: str) -> list[str]:
    """Parse nslookup text output for a given record type."""
    results: list[str] = []
    in_answer = False
    for line in output.splitlines():
        line = line.strip()
        if "Non-authoritative answer" in line or "Authoritative answers" in line:
            in_answer = True
            continue
        if in_answer and line and not line.startswith("Server") and not line.startswith("Address"):
            if "=" in line or "address" in line.lower():
                val = line.split("=")[-1].strip()
                if not val:
                    val = line.split("address")[-1].strip().split()[-1] if "address" in line.lower() else ""
                if val:
                    results.append(val)
    return results


def _parse_dig_answer(output: str) -> list[str]:
    """Parse dig +noall +answer output — each line is: name ttl class type rdata."""
    results: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) >= 5:
            results.append(parts[-1].rstrip("."))
    return results


def _is_ip(s: str) -> bool:
    """Return True if string looks like an IPv4 address."""
    parts = s.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
