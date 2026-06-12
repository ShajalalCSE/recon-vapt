"""
modules/attack_chain.py
=======================
Attack Chain Builder — MITRE ATT&CK Mapping & Vulnerability Chaining

Maps recon/vapt findings to MITRE ATT&CK techniques, builds a directed
attack graph, identifies the highest-impact exploit chains, and generates
human-readable attack narratives.

Authorised lab environments only.
Python: 3.11+
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ── MITRE ATT&CK tactic order (kill-chain progression) ───────────────────────
TACTIC_ORDER: list[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact",
]

# ── Keyword → (tactic, T-ID, technique) lookup table ─────────────────────────
# Each entry: ([keywords], tactic, technique_id, technique_name)
_MAPPING: list[tuple[list[str], str, str, str]] = [
    # Reconnaissance
    (["nmap", "port scan", "open port", "service detection"],
     "Reconnaissance", "T1046", "Network Service Scanning"),
    (["dns", "nslookup", "dig", "zone transfer", "subdomain"],
     "Reconnaissance", "T1018", "Remote System Discovery"),
    (["whois", "asn", "ip range"],
     "Reconnaissance", "T1590", "Gather Victim Network Information"),
    (["theharvester", "email", "linkedin"],
     "Reconnaissance", "T1589", "Gather Victim Identity Information"),
    (["waybackurls", "gau", "historical url", "archived"],
     "Reconnaissance", "T1593", "Search Open Websites/Domains"),
    (["whatweb", "technology", "fingerprint", "cms", "framework", "version"],
     "Reconnaissance", "T1592", "Gather Victim Host Information"),

    # Initial Access
    (["sqli", "sql injection", "sql error", "blind sql"],
     "Initial Access", "T1190", "Exploit Public-Facing Application"),
    (["xss", "cross-site scripting", "reflected xss", "stored xss"],
     "Initial Access", "T1190", "Exploit Public-Facing Application"),
    (["lfi", "local file inclusion", "path traversal", "directory traversal", "../"],
     "Initial Access", "T1190", "Exploit Public-Facing Application"),
    (["rfi", "remote file inclusion"],
     "Initial Access", "T1190", "Exploit Public-Facing Application"),
    (["ssrf", "server-side request forgery"],
     "Initial Access", "T1190", "Exploit Public-Facing Application"),
    (["xxe", "xml external entity"],
     "Initial Access", "T1190", "Exploit Public-Facing Application"),
    (["open redirect"],
     "Initial Access", "T1566", "Phishing — Link Redirect"),
    (["default password", "default credentials", "weak password", "auth bypass"],
     "Initial Access", "T1078", "Valid Accounts — Default"),
    (["cve-2021-41773", "cve-2021-42013"],
     "Initial Access", "T1190", "Apache Path Traversal RCE"),
    (["cve-2021-44228", "log4shell", "log4j"],
     "Initial Access", "T1190", "Log4Shell RCE"),
    (["cve-2022-26134", "confluence"],
     "Initial Access", "T1190", "Confluence OGNL Injection"),

    # Execution
    (["rce", "remote code execution", "command injection", "os command", "shell"],
     "Execution", "T1059", "Command and Scripting Interpreter"),
    (["deserialization", "phar", "java deserialization", "pickle"],
     "Execution", "T1059", "Deserialization RCE"),
    (["template injection", "ssti", "server-side template"],
     "Execution", "T1059", "Template Injection RCE"),
    (["prototype pollution"],
     "Execution", "T1059.007", "JavaScript Prototype Pollution"),
    (["cve-2017-5638", "struts"],
     "Execution", "T1059", "Apache Struts OGNL RCE"),

    # Persistence
    (["webshell", "web shell", "backdoor", "uploader"],
     "Persistence", "T1505.003", "Web Shell"),
    (["cron", "scheduled task", "startup"],
     "Persistence", "T1053", "Scheduled Task/Job"),
    (["ssh key", "authorized_keys"],
     "Persistence", "T1098", "Account Manipulation — SSH Keys"),

    # Privilege Escalation
    (["privilege escalation", "privesc", "sudo", "suid", "setuid"],
     "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
    (["cve-2022-0847", "dirtypipe"],
     "Privilege Escalation", "T1068", "Dirty Pipe Linux PrivEsc"),
    (["cve-2021-3560", "polkit"],
     "Privilege Escalation", "T1068", "Polkit Auth Bypass"),
    (["cve-2020-1472", "zerologon"],
     "Privilege Escalation", "T1068", "ZeroLogon Domain Admin"),

    # Defense Evasion
    (["waf bypass", "firewall bypass", "403 bypass", "ip filter bypass"],
     "Defense Evasion", "T1027", "Obfuscated Files or Information"),
    (["http smuggling", "request smuggling"],
     "Defense Evasion", "T1036", "Request Smuggling Masquerading"),
    (["clickjacking", "x-frame-options missing", "frame"],
     "Defense Evasion", "T1036", "UI Redressing"),
    (["weak cipher", "tls", "ssl", "certificate", "outdated ssl"],
     "Defense Evasion", "T1573", "Encrypted Channel — Weak Crypto"),

    # Credential Access
    (["jwt", "json web token", "jwt secret", "jwt alg none"],
     "Credential Access", "T1552", "Unsecured Credentials — JWT"),
    (["credential", "password", "password exposed", "cleartext password"],
     "Credential Access", "T1552", "Unsecured Credentials"),
    (["csrf", "cross-site request forgery"],
     "Credential Access", "T1185", "Browser Session Hijacking"),
    (["cookie", "session fixation", "httponly missing", "secure flag"],
     "Credential Access", "T1539", "Steal Web Session Cookie"),
    (["ntlm", "net-ntlmv2", "hash capture"],
     "Credential Access", "T1557", "NTLM Hash Capture"),

    # Discovery
    (["idor", "insecure direct object", "broken access control"],
     "Discovery", "T1083", "File and Directory Discovery"),
    (["backup file", ".bak", ".old", "exposed config", ".env", ".git"],
     "Discovery", "T1083", "Sensitive File Discovery"),
    (["directory listing", "directory traversal", "directory index"],
     "Discovery", "T1083", "File and Directory Discovery"),
    (["graphql introspection", "graphql"],
     "Discovery", "T1046", "GraphQL Schema Discovery"),

    # Lateral Movement
    (["smb", "samba", "enum4linux", "net share", "445"],
     "Lateral Movement", "T1021.002", "SMB/Windows Admin Shares"),
    (["rdp", "remote desktop", "3389"],
     "Lateral Movement", "T1021.001", "Remote Desktop Protocol"),
    (["cve-2017-0144", "eternalblue", "ms17-010"],
     "Lateral Movement", "T1210", "EternalBlue SMB Exploit"),
    (["ssh", "22"],
     "Lateral Movement", "T1021.004", "SSH Lateral Movement"),
    (["pivot", "lateral movement"],
     "Lateral Movement", "T1021", "Remote Services"),

    # Collection
    (["cors", "cross-origin", "access-control-allow"],
     "Collection", "T1185", "Cross-Origin Data Exfiltration"),
    (["sensitive data", "pii", "personal data", "credit card", "ssn"],
     "Collection", "T1005", "Data from Local System"),
    (["api key", "secret key", "token exposed"],
     "Collection", "T1552", "Credential / Token Harvesting"),

    # Exfiltration
    (["data exfil", "exfiltration", "data leak"],
     "Exfiltration", "T1041", "Exfiltration Over C2"),

    # Impact
    (["dos", "denial of service", "ddos"],
     "Impact", "T1499", "Endpoint Denial of Service"),
    (["cve-2023-44487", "rapid reset", "http/2"],
     "Impact", "T1499", "HTTP/2 Rapid Reset DoS"),
    (["ransomware", "encrypt files", "wiper"],
     "Impact", "T1486", "Data Encrypted for Impact"),
    (["defacement", "web defacement"],
     "Impact", "T1491", "Website Defacement"),
]


# ── Severity → exploitability score ──────────────────────────────────────────
_SEV_SCORE: dict[str, float] = {
    "critical": 1.0,
    "high":     0.8,
    "medium":   0.5,
    "low":      0.3,
    "info":     0.1,
}


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class AttackNode:
    node_id: str
    tactic: str
    technique_id: str
    technique: str
    finding_title: str
    finding_severity: str
    tool: str
    detail: str = ""
    exploitability: float = 0.5

    @property
    def tactic_index(self) -> int:
        try:
            return TACTIC_ORDER.index(self.tactic)
        except ValueError:
            return 99


@dataclass
class AttackChain:
    chain_id: str
    name: str
    nodes: list[AttackNode]
    score: float
    impact: str
    narrative: str
    mitre_tactics: list[str]
    mitre_techniques: list[str]

    def ascii_path(self) -> str:
        parts = [f"[{n.technique_id}] {n.tactic}" for n in self.nodes]
        sep = "\n    ↓\n  "
        return "  " + sep.join(parts)


@dataclass
class ChainReport:
    nodes: list[AttackNode]
    chains: list[AttackChain]
    attack_surface_score: float
    mitre_coverage: list[str]
    top_chain: AttackChain | None
    narrative_summary: str


# ── Node mapping ──────────────────────────────────────────────────────────────

def _map_finding(finding: Any, idx: int) -> list[AttackNode]:
    title  = (getattr(finding, "title",  "") or "").lower()
    detail = (getattr(finding, "detail", "") or "").lower()
    sev    = getattr(finding, "severity", "info")
    tool   = getattr(finding, "tool", "unknown")
    text   = title + " " + detail
    exploit = _SEV_SCORE.get(sev.lower(), 0.1)

    nodes: list[AttackNode] = []
    seen: set[str] = set()

    for keywords, tactic, tid, technique in _MAPPING:
        if any(kw in text for kw in keywords):
            if tid not in seen:
                seen.add(tid)
                nodes.append(AttackNode(
                    node_id=f"N{idx:03d}-{tid}",
                    tactic=tactic,
                    technique_id=tid,
                    technique=technique,
                    finding_title=getattr(finding, "title", ""),
                    finding_severity=sev,
                    tool=tool,
                    detail=getattr(finding, "detail", "")[:200],
                    exploitability=exploit,
                ))

    if not nodes:
        nodes.append(AttackNode(
            node_id=f"N{idx:03d}-T1592",
            tactic="Reconnaissance",
            technique_id="T1592",
            technique="Gather Victim Host Information",
            finding_title=getattr(finding, "title", "Unknown"),
            finding_severity=sev,
            tool=tool,
            exploitability=exploit,
        ))

    return nodes


def _score(nodes: list[AttackNode]) -> float:
    if not nodes:
        return 0.0
    tactic_div = len({n.tactic for n in nodes})
    avg_exploit = sum(n.exploitability for n in nodes) / len(nodes)
    span_bonus  = min(len(nodes) / 5.0, 1.5)
    return round(tactic_div * avg_exploit * (1 + span_bonus), 2)


def _infer_impact(tactics: set[str]) -> str:
    if "Impact" in tactics:
        return "System disruption, ransomware, or data destruction."
    if "Exfiltration" in tactics:
        return "Sensitive data exfiltration — credentials, PII, or IP."
    if "Lateral Movement" in tactics:
        return "Network-wide compromise via lateral movement."
    if "Privilege Escalation" in tactics:
        return "Full system takeover via privilege escalation."
    if "Persistence" in tactics:
        return "Persistent backdoor — ongoing unauthorized access."
    if "Credential Access" in tactics:
        return "Account takeover via credential theft."
    if "Execution" in tactics:
        return "Remote code execution on target host."
    if "Initial Access" in tactics:
        return "Initial foothold established on target system."
    return "Information disclosure and expanded attack surface."


def _narrative(chain: "AttackChain", target: str) -> str:
    lines: list[str] = [
        f"Attack Path: {chain.name}",
        f"Target: {target}",
        f"Score: {chain.score}  |  Tactics: {len(chain.mitre_tactics)}  |  "
        f"Techniques: {', '.join(chain.mitre_techniques)}",
        "",
    ]
    for i, node in enumerate(chain.nodes, 1):
        actor = "An attacker" if i == 1 else "next"
        lines.append(
            f"  Step {i}  [{node.technique_id} — {node.tactic}]"
        )
        lines.append(
            f"           {actor} leverages {node.technique!r} "
            f"via '{node.finding_title}' "
            f"(severity: {node.finding_severity}, tool: {node.tool})."
        )
    lines += ["", f"Impact: {chain.impact}"]
    return "\n".join(lines)


# ── Builder ───────────────────────────────────────────────────────────────────

class AttackChainBuilder:
    def build(self, findings: list, target: str = "") -> ChainReport:
        # Step 1: map all findings to nodes
        raw: list[AttackNode] = []
        for idx, f in enumerate(findings):
            raw.extend(_map_finding(f, idx))

        # Deduplicate by technique_id — keep highest exploitability
        by_tid: dict[str, AttackNode] = {}
        for node in raw:
            tid = node.technique_id
            if tid not in by_tid or node.exploitability > by_tid[tid].exploitability:
                by_tid[tid] = node
        nodes = sorted(by_tid.values(), key=lambda n: n.tactic_index)

        # Step 2: build chains
        chains: list[AttackChain] = []
        chains += self._progressive_chains(nodes, target)
        chains += self._named_chains(nodes, target)

        # Deduplicate chains
        seen_sigs: set[frozenset] = set()
        unique_chains: list[AttackChain] = []
        for c in chains:
            sig = frozenset(n.technique_id for n in c.nodes)
            if sig not in seen_sigs and len(sig) >= 2:
                seen_sigs.add(sig)
                unique_chains.append(c)

        unique_chains.sort(key=lambda c: c.score, reverse=True)

        # Surface score
        tactic_set = {n.tactic for n in nodes}
        avg_exploit = (
            sum(n.exploitability for n in nodes) / len(nodes) if nodes else 0
        )
        surface_score = round(
            len(tactic_set) / len(TACTIC_ORDER) * 10 * avg_exploit, 1
        )

        coverage = sorted(
            tactic_set,
            key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99,
        )

        top = unique_chains[0] if unique_chains else None

        if unique_chains:
            summary = (
                f"{len(unique_chains)} attack chain(s) built. "
                f"Top chain: '{unique_chains[0].name}' (score {unique_chains[0].score}). "
                f"ATT&CK tactics covered: {', '.join(coverage)}. "
                f"Surface score: {surface_score}/10."
            )
        else:
            summary = (
                "No multi-step attack chains identified. "
                f"Single-tactic findings cover: {', '.join(coverage) or 'none'}."
            )

        return ChainReport(
            nodes=nodes,
            chains=unique_chains[:12],
            attack_surface_score=surface_score,
            mitre_coverage=coverage,
            top_chain=top,
            narrative_summary=summary,
        )

    # ── Chain construction helpers ────────────────────────────────────────────

    def _progressive_chains(self, nodes: list[AttackNode], target: str) -> list[AttackChain]:
        tactic_groups: dict[str, list[AttackNode]] = {}
        for n in nodes:
            tactic_groups.setdefault(n.tactic, []).append(n)

        tactic_seq = [t for t in TACTIC_ORDER if t in tactic_groups]
        if len(tactic_seq) < 2:
            return []

        chains: list[AttackChain] = []
        for window in range(2, min(7, len(tactic_seq) + 1)):
            for start in range(len(tactic_seq) - window + 1):
                tactics = tactic_seq[start:start + window]
                chain_nodes = [
                    max(tactic_groups[t], key=lambda n: n.exploitability)
                    for t in tactics
                ]
                impact = _infer_impact(set(tactics))
                score  = _score(chain_nodes)
                name   = f"{tactics[0]} → {tactics[-1]}"
                c = AttackChain(
                    chain_id=f"PC-{''.join(t[0] for t in tactics)}",
                    name=name,
                    nodes=chain_nodes,
                    score=score,
                    impact=impact,
                    narrative="",
                    mitre_tactics=tactics,
                    mitre_techniques=[n.technique_id for n in chain_nodes],
                )
                c.narrative = _narrative(c, target)
                chains.append(c)
        return chains

    def _named_chains(self, nodes: list[AttackNode], target: str) -> list[AttackChain]:
        chains: list[AttackChain] = []
        by_tactic: dict[str, list[AttackNode]] = {}
        for n in nodes:
            by_tactic.setdefault(n.tactic, []).append(n)

        def _best(tactic: str) -> AttackNode | None:
            group = by_tactic.get(tactic, [])
            return max(group, key=lambda n: n.exploitability) if group else None

        # Named scenario 1: Full Kill Chain (Recon → Impact)
        scenario_tactics = [
            "Reconnaissance", "Initial Access", "Execution",
            "Privilege Escalation", "Lateral Movement", "Impact",
        ]
        selected = [_best(t) for t in scenario_tactics if _best(t)]
        if len(selected) >= 3:
            c = AttackChain(
                chain_id="NC-FULLKILL",
                name="Full Kill Chain",
                nodes=selected,
                score=_score(selected) * 1.5,
                impact="Complete system compromise — RCE, PrivEsc, and lateral movement to full domain control.",
                narrative="",
                mitre_tactics=[n.tactic for n in selected],
                mitre_techniques=[n.technique_id for n in selected],
            )
            c.narrative = _narrative(c, target)
            chains.append(c)

        # Named scenario 2: Data Breach (IA → CA → Collection → Exfil)
        ia   = _best("Initial Access")
        ca   = _best("Credential Access")
        col  = _best("Collection")
        exfil = _best("Exfiltration")
        breach = [x for x in [ia, ca, col, exfil] if x]
        if len(breach) >= 2:
            c = AttackChain(
                chain_id="NC-BREACH",
                name="Data Breach Path",
                nodes=breach,
                score=_score(breach) * 1.3,
                impact="Sensitive data exfiltration — PII, credentials, or intellectual property at risk.",
                narrative="",
                mitre_tactics=[n.tactic for n in breach],
                mitre_techniques=[n.technique_id for n in breach],
            )
            c.narrative = _narrative(c, target)
            chains.append(c)

        # Named scenario 3: Ransomware Deployment
        exec_  = _best("Execution")
        pe     = _best("Privilege Escalation")
        impact = _best("Impact")
        ransom = [x for x in [ia, exec_, pe, impact] if x]
        if len(ransom) >= 3:
            c = AttackChain(
                chain_id="NC-RANSOM",
                name="Ransomware Deployment Path",
                nodes=ransom,
                score=_score(ransom) * 1.4,
                impact="Ransomware deployment — encrypted files, service disruption, extortion.",
                narrative="",
                mitre_tactics=[n.tactic for n in ransom],
                mitre_techniques=[n.technique_id for n in ransom],
            )
            c.narrative = _narrative(c, target)
            chains.append(c)

        return chains
