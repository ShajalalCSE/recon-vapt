# AI Red Team Harness v3 — User Manual

**Web Application Penetration Testing Framework**
*Authorised lab / owned-infrastructure use only*

---

## Table of Contents

1. [Overview](#1-overview)
2. [Requirements](#2-requirements)
3. [Installation](#3-installation)
4. [Safety System](#4-safety-system)
5. [Quick Start](#5-quick-start)
6. [run_vapt.py — Web Vulnerability Scanner](#6-run_vaptpy--web-vulnerability-scanner)
7. [run_recon.py — Recon Tools Scanner](#7-run_reconpy--recon-tools-scanner)
8. [run_agent.py — Agentic Mode](#8-run_agentpy--agentic-mode)
9. [Burp Suite Integration](#9-burp-suite-integration)
10. [Authentication Options](#10-authentication-options)
11. [Module Selection](#11-module-selection)
12. [Configuration Files](#12-configuration-files)
13. [Scan Phases](#13-scan-phases)
14. [Understanding Reports](#14-understanding-reports)
15. [Scan Modules Reference](#15-scan-modules-reference)
16. [Troubleshooting](#16-troubleshooting)
17. [Workflow Examples](#17-workflow-examples)
18. [Recon Tools Reference](#18-recon-tools-reference)

---

## 1. Overview

AI Red Team Harness v3 is a Python-based, non-destructive web application security assessment framework split into two independent entry points:

| Script | Purpose | Reports |
|---|---|---|
| `run_vapt.py` | Web vulnerability scanning (SQLi, XSS, IDOR, LFI, CORS, etc.) | `reports/web/` |
| `run_recon.py` | Kali Linux recon tools (nmap, subfinder, ffuf, gobuster, etc.) | `reports/recon/` |
| `run_agent.py` | **Agentic mode** — autonomous ReAct loop with exploit lookup + MITRE ATT&CK chains | `reports/agent/` |

Run them together for a full assessment, or independently as needed.

**Key design principles:**
- Every target must be explicitly allowlisted before any request is sent
- Rate-limited by a token bucket — never floods the target
- All checks are read-only; no payloads are written or executed on the target
- Findings are validated and false-positive filtered before reporting
- All subprocess calls use `asyncio.create_subprocess_exec` — never `shell=True`

### Web VAPT flow (`run_vapt.py`)

```
Phase 1  →  Attack surface discovery (crawl + katana + Burp seed)
Phase 1b →  Merge Burp request data into surface (if -r used)
Phase 2  →  38 scan modules run concurrently (max 8 at once)
Phase 4  →  Deduplicate and confidence-threshold filter
Phase 5  →  Evidence-gated validation agent
Phase 6  →  LLM agent reasoning (optional, requires Ollama)
         →  Report written to reports/web/
```

### Recon flow (`run_recon.py`)

```
         →  29 Kali tools run concurrently (nmap, subfinder, ffuf, etc.)
         →  Tools not found in PATH are silently skipped
         →  Kill switch: Ctrl+C saves partial results immediately
         →  Report written to reports/recon/
```

### Agentic flow (`run_agent.py`)

```
Iteration 1  →  initial_recon   (nmap, nslookup, whatweb, wafw00f, whois)
Iteration 2  →  subdomain_deep  (subfinder, dig, dnsrecon)    ← if subdomains found
Iteration 3  →  web_discovery   (ffuf, gobuster, nikto)       ← if tech identified
Iteration 4  →  exploit_lookup  (searchsploit + NVD CVE API)  ← maps findings to CVEs
Iteration 5  →  chain_analysis  (MITRE ATT&CK graph + scoring)
Iteration 6  →  osint           (theharvester, gau, waybackurls)
Iteration 7  →  vuln_scan       (nuclei targeted)
Iteration 8  →  smb_scan        (enum4linux, smbmap)          ← if port 445/139 open
             →  Report written to reports/agent/
```

Each iteration uses findings from previous ones — the agent reasons about what to explore next.

---

## 2. Requirements

| Requirement | Minimum |
|---|---|
| Python | 3.11+ |
| httpx | 0.27+ |
| PyYAML | 6.0+ |
| OS | Windows / Linux / macOS (Kali recommended for recon tools) |

**Optional external tools** (used by `run_recon.py` — not found in PATH are silently skipped):

| Category | Tool | Purpose | Default |
|---|---|---|---|
| Network | `nmap` | Port scan, service detection, NSE scripts | yes |
| Network | `masscan` | Fast full-range port sweep | no |
| DNS | `nslookup` | A, AAAA, MX, NS, TXT, CNAME, SOA queries | yes |
| DNS | `dig` | Detailed DNS records + zone transfer attempt | yes |
| DNS | `dnsrecon` | Comprehensive DNS enum (std, SRV, brute, AXFR) | yes |
| DNS | `dnsx` | Fast multi-type DNS resolver | no |
| DNS | `fierce` | DNS brute force + zone walk | no |
| DNS | `dnsenum` | DNS enumeration with subdomain brute force | no |
| Subdomain | `subfinder` | Passive subdomain enumeration from 10+ sources | yes |
| Subdomain | `amass` | Comprehensive subdomain enumeration | no |
| Subdomain | `assetfinder` | Quick subdomain discovery | no |
| Web Fuzz | `ffuf` | Fast directory/file/parameter fuzzing | yes |
| Web Fuzz | `gobuster` | Dir, DNS, and vhost brute forcing | yes |
| Web Fuzz | `feroxbuster` | Recursive directory fuzzing | no |
| Web Fuzz | `dirb` | Classic directory brute force | no |
| Web Fuzz | `dirsearch` | Directory/file discovery | no |
| Web Fuzz | `wfuzz` | Configurable web application fuzzer | no |
| Fingerprint | `whatweb` | Technology, CMS, and framework detection | yes |
| Fingerprint | `wafw00f` | WAF detection and identification | yes |
| Fingerprint | `nikto` | Web server misconfiguration scan | yes |
| Fingerprint | `httpx` | HTTP probing and tech detection | no |
| OSINT | `whois` | Domain registration information | yes |
| OSINT | `theHarvester` | Email, subdomain, IP from public sources | no |
| Historical | `gau` | Historical URLs from Wayback/Common Crawl | no |
| Historical | `waybackurls` | Wayback Machine URL discovery | no |
| Vuln Scan | `nuclei` | Template-based CVE and misconfiguration scan | yes |
| SMB | `enum4linux` | SMB/CIFS/Windows enumeration | no |
| SMB | `smbmap` | SMB share enumeration with permissions | no |
| Crawl | `katana` | JavaScript-rendered web crawling (SPA support) | no |

Install Python dependencies:

```bash
pip install -r requirements.txt
```

---

## 3. Installation

```bash
# Clone or copy the project
cd /path/to/vapt

# Install Python dependencies
pip install -r requirements.txt

# Create the safety marker (required before any scan)
python run_vapt.py --create-lab-marker
# or
python run_recon.py --create-lab-marker
# or
python run_agent.py --create-lab-marker
```

The lab marker file (`.lab_mode_enabled`) is a safety gate. Without it, all scans are blocked.

---

## 4. Safety System

Both scripts enforce the same two-layer allowlist before sending any traffic.

### 4.1 Lab Marker

The file `.lab_mode_enabled` must exist in the project root. Create it once:

```bash
python run_vapt.py --create-lab-marker
```

### 4.2 URL Allowlist

Every target must appear in `config/safety.yaml` under `web_vapt.allowed_urls`. Adding `http://192.168.0.102` covers all paths under that host.

```yaml
# config/safety.yaml
web_vapt:
  allowed_urls:
    - "http://localhost"
    - "https://localhost"
    - "http://127.0.0.1"
    - "http://192.168.0.107"
    - "http://192.168.0.107/dvwa"
    - "https://your-owned-domain.com"
```

If you scan a target not in the allowlist, both scripts exit immediately:

```
[BLOCKED] Target 'https://example.com' is not in the web VAPT allowlist
```

---

## 5. Quick Start

### Web vulnerability scan

```bash
python run_vapt.py --target http://192.168.0.102/dvwa/
```

### Kali recon tools scan

```bash
python run_recon.py --target http://192.168.0.102
```

### Autonomous agentic pentest (all-in-one)

```bash
python run_agent.py --target http://192.168.0.102
```

### Specific recon tools only

```bash
python run_recon.py --target http://192.168.0.102 --tools nmap,subfinder,ffuf
```

### Scan using a Burp Suite captured request

```bash
python run_vapt.py -r burp_request.txt
```

### List all available recon tools

```bash
python run_recon.py --list-tools
```

### Dry run — confirm config without scanning

```bash
python run_vapt.py --target http://192.168.0.102/dvwa/ --dry-run
```

---

## 6. run_vapt.py — Web Vulnerability Scanner

Runs 38 web vulnerability scan modules (SQLi, XSS, IDOR, LFI, CORS, JWT, SSRF, etc.) against a target. Does **not** run external recon tools — use `run_recon.py` for that.

```
python run_vapt.py [OPTIONS]
```

**Core options:**

| Option | Short | Default | Description |
|---|---|---|---|
| `--target URL` | | — | Target URL to scan |
| `--request FILE` | `-r` | — | Burp Suite raw request file |
| `--output DIR` | | `reports/web` | Output directory for reports |
| `--modules LIST` | | all enabled | Comma-separated vuln module names |
| `--cookie STRING` | | — | Raw `Cookie:` header value |
| `--username USER` | | — | Username for HTTP Basic Auth |
| `--password PASS` | | — | Password for HTTP Basic Auth |
| `--llm` | | off | Enable LLM agent (Phase 6) |
| `--model NAME` | | `llama3` | Ollama model for LLM agent |
| `--llm-url URL` | | `http://localhost:11434` | Ollama base URL |
| `--iter N` | | `12` | Max LLM iterations |
| `--verbose` | `-v` | off | Enable DEBUG logging |
| `--dry-run` | | off | Print resolved config, no scan |
| `--create-lab-marker` | | — | Create safety marker file and exit |

**Priority rules:**

- `--target` takes precedence over the URL inferred from `-r`
- `--cookie` takes precedence over the `Cookie:` header in the Burp file
- `--modules` is case-insensitive; spaces around commas are ignored

**Ctrl+C behaviour:** Sets the kill switch — current module finishes, partial results are saved to `reports/web/` immediately.

---

## 7. run_recon.py — Recon Tools Scanner

Runs up to 29 Kali Linux recon tools concurrently against a target. Generates a standalone JSON + Markdown report in `reports/recon/`. Completely independent of the web vuln scanner.

```
python run_recon.py [OPTIONS]
```

**Options:**

| Option | Short | Default | Description |
|---|---|---|---|
| `--target URL` | | — | Target URL or IP |
| `--tools LIST` | | default set | Comma-separated recon tool names |
| `--list-tools` | | — | Print all 29 tools with categories and exit |
| `--output DIR` | | `reports/recon` | Output directory for reports |
| `--verbose` | `-v` | off | Enable DEBUG logging |
| `--create-lab-marker` | | — | Create safety marker file and exit |

**Default tools** (run when `--tools` is omitted, if installed):

```
nmap, nslookup, dig, subfinder, ffuf, gobuster,
whatweb, wafw00f, nikto, nuclei, whois
```

**Examples:**

```bash
# Run all default tools
python run_recon.py --target http://192.168.0.102

# Run only specific tools
python run_recon.py --target http://192.168.0.102 --tools nmap,subfinder,ffuf,gobuster

# DNS and subdomain recon only
python run_recon.py --target http://192.168.0.102 --tools nslookup,dig,dnsrecon,subfinder

# Port scan + WAF + fingerprint
python run_recon.py --target http://192.168.0.102 --tools nmap,wafw00f,whatweb

# Save to a custom directory
python run_recon.py --target http://192.168.0.102 --output reports/recon/pass1

# List all supported tools
python run_recon.py --list-tools
```

**Ctrl+C behaviour:** Kills any running subprocess immediately (nmap, ffuf, etc.) and writes a partial report marked `PARTIAL_` before exiting.

**Report location:** `reports/recon/recon_YYYYMMDD_HHMMSS.md` and `.json`

---

## 8. run_agent.py — Agentic Mode

`run_agent.py` is the most advanced entry point. It runs an autonomous **ReAct (Reason → Act → Observe → Reflect)** loop that intelligently sequences recon tools, discovers exploits, and maps findings to MITRE ATT&CK attack chains — all without manual tool selection.

```
python run_agent.py [OPTIONS]
```

**Options:**

| Option | Short | Default | Description |
|---|---|---|---|
| `--target URL` | | — | Target URL or IP (must be in allowlist) |
| `--max-iter N` | | `10` | Maximum agent iterations |
| `--output DIR` | | `reports/agent` | Output directory for reports |
| `--verbose` | `-v` | off | Show agent reasoning + reflection each step |
| `--no-nvd` | | off | Disable NVD CVE API calls (offline mode) |
| `--create-lab-marker` | | — | Create safety marker and exit |

**Examples:**

```bash
# Full autonomous pentest
python run_agent.py --target http://192.168.0.102

# Cap at 6 iterations (faster, less thorough)
python run_agent.py --target http://192.168.0.102 --max-iter 6

# See the agent's reasoning at each step
python run_agent.py --target http://192.168.0.102 --verbose

# Offline mode — skip NVD CVE API lookups
python run_agent.py --target http://192.168.0.102 --no-nvd

# Custom output folder
python run_agent.py --target http://192.168.0.102 --output reports/agent/pass1
```

### 8.1 How the Agent Works

The agent maintains an **AgentContext** — a knowledge graph that accumulates findings across iterations. A rule-based **Planner** decides the next action based on what has been discovered so far:

| Priority | Action | Triggers when |
|---|---|---|
| 1 | `initial_recon` | No data yet |
| 2 | `subdomain_deep` | Subdomains discovered |
| 3 | `web_discovery` | Technologies fingerprinted |
| 4 | `exploit_lookup` | Findings available |
| 5 | `chain_analysis` | Exploit report ready |
| 6 | `osint` | Subdomains exist (external target) |
| 7 | `vuln_scan` | Tech stack identified |
| 8 | `smb_scan` | Port 445/139 found open |

Each action feeds its results back into the context so later actions have richer data to work with.

### 8.2 Exploit Intelligence Engine

`modules/exploit_engine.py` is invoked during the `exploit_lookup` phase:

- **searchsploit** — searches the local Exploit-DB copy on Kali for matching exploits (by technology name, service, or CVE)
- **NVD CVE API v2** — enriches each match with CVSS score, vector, and description (no API key required; disable with `--no-nvd`)
- **Metasploit hints** — curated mapping from CVE → MSF module for 15 major vulnerabilities

Output includes:
- Exploit table (title, type, platform, CVSS, severity)
- `searchsploit -m <path>` copy commands
- Ready-to-paste `msfconsole` module stubs

### 8.3 MITRE ATT&CK Chain Analysis

`modules/attack_chain.py` is invoked during the `chain_analysis` phase:

- Maps every finding to MITRE ATT&CK tactic + technique via a 50+ keyword table
- Builds a **directed attack graph** progressing through the kill chain
- Scores each chain: `tactic_diversity × avg_exploitability × span_bonus`
- Generates **named attack scenarios**:

| Scenario | Tactics chained |
|---|---|
| Full Kill Chain | Recon → Initial Access → Execution → PrivEsc → Lateral Movement → Impact |
| Data Breach Path | Initial Access → Credential Access → Collection → Exfiltration |
| Ransomware Path | Initial Access → Execution → PrivEsc → Impact |

Each chain includes:
- ASCII attack path visualization
- Step-by-step narrative (who, what, via which finding, with what severity)
- Impact statement

### 8.4 Agent Report

Reports are written to `reports/agent/` as JSON + Markdown:

```
reports/agent/
  agent_YYYYMMDD_HHMMSS.md       ← Full narrative report
  agent_YYYYMMDD_HHMMSS.json     ← Machine-readable (all data)
  agent_PARTIAL_YYYYMMDD_HHMMSS.md   ← Written on Ctrl+C
```

The Markdown report sections:
1. Executive Summary
2. Open Ports table
3. Technologies detected
4. WAF detected (if any)
5. DNS records
6. Subdomains
7. Web paths discovered
8. Security Findings (sorted by severity)
9. **Exploit Intelligence** — table + MSF commands + searchsploit commands
10. **MITRE ATT&CK Attack Chains** — ASCII paths + narratives for each chain
11. Agent Reasoning Log — reasoning/observation/reflection per iteration

### 8.5 Agent Terminal Output Example

```
  [Agent  1/10]  initial_recon
    Observe: 3 port(s), 0 subdomain(s), 4 finding(s), 3 tech(s). Tools: nmap, nslookup, whatweb...

  [Agent  2/10]  web_discovery
    Observe: 0 port(s), 0 subdomain(s), 12 finding(s), 3 tech(s). Tools: ffuf, gobuster, nikto...

  [Agent  3/10]  exploit_lookup
    Observe: Exploit search complete: 18 matches (2 critical, 4 high). CVEs: CVE-2021-41773...

  [Agent  4/10]  chain_analysis
    Observe: 3 attack chain(s) built. Top chain: 'Initial Access → Execution' (score 4.8)...

  ══════════════════════════════════════════════════════
  AGENT COMPLETE
  ══════════════════════════════════════════════════════
  Report ID     : agent_20260613_142301
  Duration      : 187s  (4 iterations)
  Open ports    : 3
  Technologies  : Apache/2.4.49, PHP/7.4, MySQL
  Findings      : 16
    CRITICAL    : 2
    HIGH        : 5
  Exploits      : 18 matches (2 critical, 4 high)
  CVEs          : CVE-2021-41773, CVE-2021-42013
  MSF modules   : 1 available

  Attack chains : 3
  Surface score : 6.2/10
  ATT&CK tactic : Reconnaissance, Initial Access, Execution

  Top chain     : Initial Access → Execution  (score 4.8)
  Attack Path:
    [T1190 — Initial Access]
        ↓
    [T1059 — Execution]
  ══════════════════════════════════════════════════════
```

---

## 9. Burp Suite Integration

The `-r` flag (available on `run_vapt.py`) accepts any raw HTTP request file — the same format Burp Suite exports and `sqlmap -r` accepts.

### How to export from Burp Suite

1. In **Proxy → HTTP history** or **Repeater**, right-click the request
2. Select **Save item** (Proxy history) or copy from Repeater's raw view
3. Save as a `.txt` file

A valid Burp request file:

```
POST /dvwa/login.php HTTP/1.1
Host: 192.168.0.102
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml
Cookie: security=low; PHPSESSID=890d395c1b362ffa9f857201e36573c7
Content-Type: application/x-www-form-urlencoded
Content-Length: 48

username=admin&password=password&Login=Login
```

### What gets extracted automatically

| Extracted data | Used for |
|---|---|
| `Host` header | Reconstruct full target URL |
| `Cookie` header | Authenticate all scan requests |
| `User-Agent`, `Accept`, `Referer` | Forward on every engine request |
| URL query parameters (`?foo=bar`) | Inject into attack surface parameters |
| POST body parameters | Create a synthetic form for injection testing |
| HTTP method (GET/POST/PUT) | Set form method for all scan modules |

### Scheme auto-detection

| Host value | Inferred scheme |
|---|---|
| `192.168.x.x`, `10.x.x.x`, `172.16-31.x.x` | `http` |
| `localhost`, `127.x.x.x` | `http` |
| `*.local`, `*.lan`, `*.internal` | `http` |
| Host with port `:80` | `http` |
| Host with port `:443` | `https` |
| Public domain, no port | `https` |

To force a specific scheme, use `--target` explicitly:

```bash
python run_vapt.py -r burp_request.txt --target https://192.168.0.102/dvwa/
```

### Combining `-r` with other flags

```bash
# Override the cookie after re-logging in
python run_vapt.py -r burp_request.txt --cookie "PHPSESSID=newtoken123"

# Run only injection modules on the captured request
python run_vapt.py -r burp_request.txt --modules sqli,xss,lfi,command_injection

# Full authenticated scan with verbose output
python run_vapt.py -r burp_request.txt --verbose
```

---

## 10. Authentication Options

### Option A — Burp Suite file (recommended)

Captures everything automatically including session cookies, CSRF tokens, and custom headers.

```bash
python run_vapt.py -r burp_request.txt
```

### Option B — Manual cookie

Paste the `Cookie:` header value directly.

```bash
python run_vapt.py --target http://192.168.0.102/dvwa/ \
  --cookie "security=low; PHPSESSID=890d395c1b362ffa9f857201e36573c7"
```

### Option C — HTTP Basic Auth

```bash
python run_vapt.py --target http://192.168.0.102/ \
  --username admin --password secret
```

### Combining auth methods

`--cookie` overrides the cookie from the Burp file:

```bash
python run_vapt.py -r burp_request.txt \
  --cookie "PHPSESSID=refreshedtoken" \
  --username admin --password secret
```

---

## 11. Module Selection

By default, all 38 modules run. Use `--modules` to run specific ones:

```bash
# Run only injection modules
python run_vapt.py --target http://192.168.0.102/dvwa/ \
  --modules sqli,xss,lfi,rfi,command_injection

# Run only authentication and session checks
python run_vapt.py --target http://target.com \
  --modules auth,csrf,jwt,jwt_algorithm_confusion

# Run only passive header/config checks (no injection)
python run_vapt.py --target http://target.com \
  --modules security_headers,tls,cors,sensitive_files,debug_endpoints
```

### All available module names

**Classic OWASP modules:**

| Module name | Tests for |
|---|---|
| `sqli` | SQL Injection (error, boolean, time-based, union) |
| `xss` | Cross-Site Scripting (reflected, DOM, stored indicators) |
| `idor` | Insecure Direct Object Reference |
| `lfi` | Local File Inclusion (path traversal, PHP wrappers) |
| `rfi` | Remote File Inclusion |
| `command_injection` | OS Command Injection |
| `csrf` | CSRF token missing / bypass |
| `auth` | Session fixation, cookie flags, brute-force indicators |
| `file_upload` | Unrestricted file upload |
| `security_headers` | Missing/misconfigured security headers |
| `tls` | TLS version, weak ciphers, certificate issues |
| `cors` | CORS misconfiguration |
| `sensitive_files` | `.env`, `.git`, backup files, config exposure |
| `debug_endpoints` | `/admin`, `/actuator`, phpMyAdmin, Swagger |
| `ssrf` | Server-Side Request Forgery |
| `open_redirect` | Open redirect parameters |
| `graphql` | GraphQL introspection, injection, depth attacks |
| `jwt` | JWT none-algorithm, weak secret, header injection |
| `prototype_pollution` | Prototype pollution (server-side and client-side) |

**Advanced 2026 modules:**

| Module name | Tests for |
|---|---|
| `jwt_algorithm_confusion` | JWT algorithm downgrade (RS256→HS256, PQ downgrade) |
| `wasm_memory_corruption` | WASM edge runtime heap/JIT vulnerabilities |
| `css_container_injection` | CSS container query timing exfiltration |
| `http3_stream_side_channel` | HTTP/3 QUIC stream isolation bypass |
| `env_var_leakage` | ESM import.meta.resolve environment leakage |
| `async_hooks_poisoning` | AsyncLocalStorage cross-contamination |
| `http_smuggling_webtransport` | HTTP smuggling via WebTransport/QUIC |
| `mongodb_injection` | MongoDB aggregation pipeline injection |
| `dom_clobbering` | DOM clobbering sandbox and CSP bypass |
| `server_timing_side_channel` | Sub-millisecond blind SQLi via Server-Timing |
| `web_crypto_timing` | Web Crypto API key-recovery timing attack |
| `import_map_override` | Import map SharedWorker injection |
| `cache_stamping` | CDN cache poisoning via stale-while-revalidate |
| `webauthn_rp_confusion` | WebAuthn passkey RP ID subdomain confusion |
| `deno_deserialization` | Deno Node.js compat V8 sandbox escape |
| `http3_0rtt_replay` | HTTP/3 0-RTT early data replay |
| `hpack_poisoning` | HTTP/2 HPACK dynamic table header poisoning |
| `graphql_n_plus_one` | GraphQL N+1 amplification / resolver exhaustion |
| `phar_deserialization` | PHP phar:// deserialization with GC exploitation |

---

## 12. Configuration Files

### `config/safety.yaml` — Safety and allowlist

```yaml
web_vapt:
  allowed_urls:
    - "http://192.168.0.102"
    - "https://your-domain.com"
  require_lab_marker: true

kill_switch:
  max_attack_budget: 500
  max_session_duration_seconds: 7200
```

### `config/web_vapt.yaml` — Engine behaviour

Controls crawling depth, rate limits, timeouts, payloads, and module settings. Also controls recon tool settings used by `run_recon.py`.

```yaml
concurrency:
  max_parallel_scans: 8
  max_parallel_requests: 5

rate_limiting:
  requests_per_second: 10.0
  burst_size: 20

timeouts:
  http_request_seconds: 15.0
  connect_timeout_seconds: 5.0
  tool_execution_seconds: 120

crawl:
  max_depth: 5
  max_urls: 250

modules:
  sqli:
    enabled: true
    max_payloads: 30
  xss:
    enabled: true
    max_payloads: 25

tools:
  nmap:
    enabled: true
    port_range: "1-10000"
    timing_template: "T4"
  ffuf:
    enabled: true
    wordlist: "/usr/share/seclists/Discovery/Web-Content/common.txt"
    threads: 50
  amass:
    enabled: false   # disabled by default
```

**Disabling a module permanently:**

```yaml
modules:
  wasm_memory_corruption:
    enabled: false
```

---

## 13. Scan Phases

### Phase 1 — Attack Surface Discovery (run_vapt.py only)

Crawls the target URL and extracts:
- All `<a href>` links within the same domain
- HTML `<form>` elements with inputs, method, and action
- URL query parameters
- JavaScript files (`<script src>`)
- WebAssembly (`.wasm`) references
- Import maps, service workers
- WebSocket endpoints detected in JavaScript source
- GraphQL endpoints by path pattern

If `katana` is installed, a second deeper crawl runs with JavaScript execution enabled for React/Vue/Angular SPAs.

**When attack surface is minimal (1 URL, 0 forms):**

1. **JavaScript SPA** — Install `katana` for JS-rendered crawling
2. **Login wall** — Use `-r` with a Burp file or `--cookie` to authenticate

### Phase 1b — Burp Seed Merge (run_vapt.py only)

If `-r` was used, parsed request data is merged into the attack surface:
- Target URL added to `surface.urls`
- Query and body parameters merged into `surface.parameters`
- A synthetic `<form>` is created from all parameters so injection modules test them
- Browser headers forwarded on all requests
- Cookie injected into the HTTP client

### Phase 2 — Scan Modules (run_vapt.py only)

All enabled modules run concurrently (max 8 at a time). Each module receives the full attack surface and iterates over URLs, forms, and parameters independently.

Modules that need parameters (SQLi, XSS, LFI, etc.) complete instantly if no forms/params were found — they have nothing to test. This is why `-r` or a crawlable target with forms is important for injection testing.

Modules that probe fixed paths (sensitive_files, debug_endpoints, security_headers, cors, tls) always produce results regardless of crawl depth.

### Phase 3 — Recon Tools (run_recon.py only)

`run_recon.py` runs all selected Kali tools concurrently via `ReconEngine`. Each tool executes as a subprocess — never with `shell=True`. Tools not found in PATH are silently skipped.

> **Note:** `run_vapt.py` does **not** run external recon tools. Use `run_recon.py` separately.

### Phase 4 — Deduplication (run_vapt.py only)

Findings below the minimum confidence threshold (default: 20%) are dropped. Duplicates for the same endpoint + parameter + category are merged.

### Phase 5 — Validation Agent (run_vapt.py only)

Each finding is re-validated by replaying the payload and comparing the response against a baseline. Validated findings are marked **CONFIRMED**; others are **POTENTIAL — MANUAL VALIDATION REQUIRED**.

### Phase 6 — LLM Agent (run_vapt.py, optional)

When `--llm` is used, a local Ollama model analyses findings and generates:
- Executive brief
- Risk rating
- Attack chain narratives
- Prioritised remediation advice

```bash
python run_vapt.py --target http://192.168.0.102/dvwa/ --llm --model llama3
```

---

## 14. Understanding Reports

### Web VAPT reports (`run_vapt.py`)

Written to `reports/web/` in both formats:

```
reports/web/
  web_vapt_YYYYMMDD_HHMMSS.md    ← Human-readable
  web_vapt_YYYYMMDD_HHMMSS.json  ← Machine-readable
```

### Recon reports (`run_recon.py`)

Written to `reports/recon/` in both formats:

```
reports/recon/
  recon_YYYYMMDD_HHMMSS.md       ← Human-readable
  recon_YYYYMMDD_HHMMSS.json     ← Machine-readable
  recon_PARTIAL_YYYYMMDD_HHMMSS.md   ← Written if Ctrl+C was pressed
```

### Severity levels

| Level | CVSS range | Meaning |
|---|---|---|
| CRITICAL | 9.0 – 10.0 | Directly exploitable, high impact |
| HIGH | 7.0 – 8.9 | Likely exploitable with moderate effort |
| MEDIUM | 4.0 – 6.9 | Exploitable under certain conditions |
| LOW | 1.0 – 3.9 | Limited impact or hard to exploit |
| INFO | 0.0 | Informational, no direct impact |

### Validation status (web VAPT only)

| Status | Meaning |
|---|---|
| **CONFIRMED** | Evidence re-validated; anomaly reproduced |
| **POTENTIAL — MANUAL VALIDATION REQUIRED** | Signal detected but not definitively confirmed |

### Risk score (web VAPT only)

The overall risk score (0–100) is a weighted sum of findings by severity.

| Score range | Label |
|---|---|
| 80 – 100 | CRITICAL |
| 60 – 79 | HIGH |
| 40 – 59 | MEDIUM |
| 20 – 39 | LOW |
| 0 – 19 | INFORMATIONAL |

### Web VAPT terminal summary

```
==========================================================
  WEB VAPT COMPLETE
==========================================================
  Report ID   : web_vapt_20260612_140312
  Target      : http://192.168.0.102/dvwa/
  Duration    : 45s
  Risk Score  : 72.5/100  [HIGH]
  Findings    : 18
    CRITICAL  : 2
    HIGH      : 4
    MEDIUM    : 7
    LOW       : 3
    INFO      : 2

  JSON Report : reports/web/web_vapt_20260612_140312.json
  MD Report   : reports/web/web_vapt_20260612_140312.md
==========================================================
```

### Recon terminal summary

```
==========================================================
  RECON COMPLETE
==========================================================
  Report ID   : recon_20260612_140312
  Target      : http://192.168.0.102
  Duration    : 62s
  Tools run   : 8
    dig, ffuf, gobuster, nikto, nmap, nslookup, whatweb, whois

  Open Ports  : 80/tcp (http), 443/tcp (https), 3306/tcp (mysql)
  Subdomains  : 3  (dev.target.lab, api.target.lab, ...)
  Web Paths   : 47 discovered
  Tech Stack  : Apache, PHP, MySQL, WordPress
  WAF         : ModSecurity
  DNS         : A(2), MX(1), NS(3), TXT(4)

  JSON Report : reports/recon/recon_20260612_140312.json
  MD Report   : reports/recon/recon_20260612_140312.md
==========================================================
```

---

## 15. Scan Modules Reference

See [Section 11 — Module Selection](#11-module-selection) for the full module name list.

### How scan modules use the attack surface

| Module type | Requires | Notes |
|---|---|---|
| Injection (SQLi, XSS, LFI, etc.) | Forms or URL parameters | Skip silently with 0 forms/params |
| File exposure (sensitive_files, debug_endpoints) | Only target URL | Always run |
| Header analysis (security_headers, cors, tls) | Only target URL | Always run |
| Auth checks (auth, csrf, jwt) | Cookies or forms | Partial results without auth |
| GraphQL | GraphQL endpoint | Skips if no `/graphql` path found |

**Tip:** For applications with login walls or SPAs, always use `-r` with a Burp file to ensure injection modules have parameters to test.

---

## 16. Troubleshooting

### `[BLOCKED] Target is not in the web VAPT allowlist`

Add the target to `config/safety.yaml`:

```yaml
web_vapt:
  allowed_urls:
    - "http://your-target.com"
```

### `Lab marker not found`

Run once:

```bash
python run_vapt.py --create-lab-marker
# or
python run_recon.py --create-lab-marker
```

### `Attack surface: 1 URLs, 0 forms, 0 params`

The crawler found nothing to inject. Causes:

1. **JavaScript SPA** — Install `katana` for JS-rendered crawling
2. **Login wall** — Use `-r` with a Burp file or `--cookie` to authenticate
3. **Request blocked by WAF** — Add `--verbose` to see GET errors
4. **Target unreachable** — Add `--verbose` and check for `GET ... failed:`

### Target auto-selects wrong scheme

```bash
python run_vapt.py -r burp.txt --target http://192.168.0.102/dvwa/
```

### Recon tool shows as `Skipped` in the summary

The binary was not found in PATH. Install it:

```bash
# Kali Linux (apt)
sudo apt install nmap subfinder ffuf gobuster dnsrecon wafw00f nikto whatweb whois

# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

### Ctrl+C — report not generated

Both scripts use a kill switch pattern. When Ctrl+C is pressed:
1. Running subprocesses (nmap, ffuf, etc.) are killed within 1–2 seconds
2. Partial results collected so far are written to a report immediately
3. The report filename is prefixed with `PARTIAL_` for recon reports

If no report is written, ensure you have write permission to the output directory.

### `Cannot import WebVAPTEngine` on startup

```bash
pip install -r requirements.txt
```

### nmap returns no results

nmap requires root privileges for OS detection and SYN scans. Run with `sudo` on Linux, or disable OS detection in config:

```yaml
tools:
  nmap:
    os_detection: false
    port_range: "80,443,8080,8443"
```

### ffuf / gobuster find nothing

The default wordlists may not be installed:

```bash
ls /usr/share/seclists/Discovery/Web-Content/common.txt
# If missing:
sudo apt install seclists
```

---

## 17. Workflow Examples

### Example 1 — Quick passive check (no injection)

```bash
python run_vapt.py --target https://example.com \
  --modules security_headers,tls,cors,sensitive_files,debug_endpoints
```

Runs in under 30 seconds. Good for a first-pass check of headers and exposed files.

---

### Example 2 — Authenticated DVWA scan via Burp

1. Open DVWA in your browser with Burp Suite proxying traffic
2. Navigate to any DVWA page while authenticated
3. In Burp Proxy history, right-click the request → **Save item** → `burp_dvwa.txt`
4. Run:

```bash
python run_vapt.py -r burp_dvwa.txt
```

---

### Example 3 — Targeted injection test

```bash
python run_vapt.py -r burp_login.txt \
  --modules sqli,xss,command_injection,lfi
```

---

### Example 4 — Full scan with LLM analysis

```bash
ollama serve   # in another terminal

python run_vapt.py --target http://192.168.0.102/dvwa/ \
  --cookie "security=low; PHPSESSID=abc123" \
  --llm --model llama3 --iter 15
```

---

### Example 5 — Recon first, then vuln scan

```bash
# Step 1 — run all default recon tools, save separately
python run_recon.py --target http://192.168.0.102 --output reports/recon/pass1

# Step 2 — review the recon report, then run vuln scan
python run_vapt.py -r burp_dvwa.txt --output reports/web/pass1
```

---

### Example 6 — Targeted recon (DNS and subdomains only)

```bash
python run_recon.py --target http://target.lab \
  --tools nslookup,dig,dnsrecon,subfinder
```

---

### Example 7 — Port scan + WAF + fingerprint

```bash
python run_recon.py --target http://192.168.0.102 \
  --tools nmap,wafw00f,whatweb
```

---

### Example 8 — Directory discovery with multiple fuzzers

```bash
python run_recon.py --target http://192.168.0.102/dvwa/ \
  --tools ffuf,gobuster,nikto
```

---

### Example 9 — OSINT and historical URLs

```bash
# Enable OSINT tools in config/web_vapt.yaml first:
#   theharvester.enabled: true
#   gau.enabled: true
#   waybackurls.enabled: true

python run_recon.py --target http://target.com \
  --tools theharvester,whois,gau,waybackurls,subfinder
```

---

### Example 10 — Iterative scanning workflow

```bash
# 1. Recon pass
python run_recon.py --target http://192.168.0.102 --output reports/recon/pass1

# 2. Full vuln scan using Burp session
python run_vapt.py -r burp.txt --output reports/web/pass1

# 3. Focused follow-up on confirmed injectable params
python run_vapt.py -r burp.txt --modules sqli,lfi \
  --output reports/web/pass2 --verbose

# 4. Final report with LLM analysis
python run_vapt.py -r burp.txt --llm --output reports/web/final
```

---

### Example 11 — HTTP Basic Auth target

```bash
python run_vapt.py --target http://192.168.0.102/protected/ \
  --username admin --password password123 \
  --modules auth,security_headers,sensitive_files,debug_endpoints
```

---

### Example 12 — Full autonomous agentic assessment

```bash
# One command — agent decides everything
python run_agent.py --target http://192.168.0.102
```

The agent runs recon, fingerprinting, exploit lookup, and chain analysis automatically. Report is written to `reports/agent/`.

---

### Example 13 — Agent with verbose reasoning

```bash
# See the agent's reasoning, observation, and reflection at every step
python run_agent.py --target http://192.168.0.102 --verbose --max-iter 6
```

Use this when you want to understand *why* the agent is making each decision.

---

### Example 14 — Agent offline (no NVD API)

```bash
# searchsploit only — no outbound HTTP calls to NVD
python run_agent.py --target http://192.168.0.102 --no-nvd
```

Use in air-gapped lab environments where internet access is restricted.

---

### Example 15 — Three-tool full workflow (recommended)

```bash
# Step 1 — recon intelligence (fastest, standalone)
python run_recon.py --target http://192.168.0.102 --output reports/recon/pass1

# Step 2 — web vuln scan with Burp session
python run_vapt.py -r burp.txt --output reports/web/pass1

# Step 3 — agentic mode to tie it all together + exploit chains
python run_agent.py --target http://192.168.0.102 --output reports/agent/pass1
```

Review all three reports together for a complete picture: recon data + specific injection findings + attack chain narrative.

---

### Example 16 — Agent + exploit database post-analysis

After `run_agent.py` completes, use the MSF commands from the report directly:

```bash
# Copy an exploit to your working directory (path from report)
searchsploit -m "exploits/linux/remote/50383.py"

# Or paste the msfconsole stub from the report
msfconsole -q -x "use exploit/multi/http/apache_normalize_path_rce; set RHOSTS 192.168.0.102; exploit"
```

---

## 18. Recon Tools Reference

### 18.1 Overview

The `ReconEngine` (`modules/recon_tools.py`) integrates 29 Kali Linux reconnaissance tools. Run it via `run_recon.py`.

```bash
# List all tools with categories and default-enabled status
python run_recon.py --list-tools
```

Output:

```
  Supported Recon Tools
  ──────────────────────────────────────────────────────

  [Network Scanning]
    masscan
    nmap               (default)

  [DNS Reconnaissance]
    dig                (default)
    dnsenum
    dnsrecon           (default)
    dnsx
    fierce
    nslookup           (default)

  [Subdomain Enumeration]
    amass
    assetfinder
    subfinder          (default)

  [Web Fuzzing / Dir Brute Force]
    dirb
    dirsearch
    feroxbuster
    ffuf               (default)
    gobuster           (default)
    wfuzz

  [Web Fingerprinting]
    httpx
    nikto              (default)
    wafw00f            (default)
    whatweb            (default)

  [OSINT]
    theharvester
    whois              (default)

  [Historical URLs]
    gau
    waybackurls

  [Vulnerability Scanning]
    nuclei             (default)

  [SMB / Windows Recon]
    enum4linux
    smbmap

  [Web Crawling]
    katana
```

---

### 18.2 Tool Details

#### nmap — Network Scanning

Comprehensive port scan with service/version detection, OS detection, and NSE scripts.

**NSE scripts run by default:**
`http-enum`, `http-headers`, `http-methods`, `http-auth`, `http-title`, `http-server-header`, `http-robots.txt`, `http-git`, `http-shellshock`, `ssl-enum-ciphers`, `ssl-heartbleed`, `ssl-poodle`, `ftp-anon`, `ssh-auth-methods`, `smb-vuln-ms17-010`, `smb-security-mode`

**Config (`config/web_vapt.yaml`):**

```yaml
tools:
  nmap:
    enabled: true
    port_range: "1-10000"        # use "1-65535" for full sweep
    timing_template: "T4"        # T1 (slow) to T5 (insane)
    os_detection: true
```

---

#### nslookup — DNS Lookup

Queries A, AAAA, MX, NS, TXT, CNAME, SOA. Works on Linux and Windows without extra installation.

---

#### dig — DNS Records + Zone Transfer

Queries all record types with full answer sections. Attempts AXFR zone transfer (a successful transfer is a HIGH finding).

---

#### dnsrecon — DNS Reconnaissance

Standard enumeration, SRV discovery, brute-force subdomain enum, and AXFR attempt.

```yaml
tools:
  dnsrecon:
    enabled: true
    scan_type: "std,brt,srv,axfr"
```

---

#### subfinder — Subdomain Enumeration

Passive subdomain discovery from crtsh, hackertarget, AlienVault, VirusTotal, dnsdumpster, and more.

```yaml
tools:
  subfinder:
    enabled: true
    recursive: true
```

---

#### ffuf — Fast Web Fuzzer

Appends `/FUZZ` to the target and fuzzes with the configured wordlist.

```yaml
tools:
  ffuf:
    enabled: true
    wordlist: "/usr/share/seclists/Discovery/Web-Content/common.txt"
    threads: 50
    matcher_status: "200,204,301,302,307,401,403,405"
```

---

#### gobuster — Directory, DNS, and VHost Brute Force

Runs dir mode (path brute force), dns mode (subdomain brute force), and vhost mode automatically.

```yaml
tools:
  gobuster:
    enabled: true
    wordlist: "/usr/share/seclists/Discovery/Web-Content/common.txt"
    status_codes: "200,204,301,302,307,401,403"
    extensions: "php,html,txt,js,json,xml,bak,zip"
    threads: 30
```

---

#### wafw00f — WAF Detection

Identifies WAF product (Cloudflare, ModSecurity, Akamai, etc.) or reports None.

---

#### whatweb — Technology Fingerprinting

Detects CMS platforms (WordPress, Drupal, Joomla), frameworks, server software, and JavaScript libraries.

---

#### nikto — Web Server Scanner

Scans for 6,700+ potentially dangerous files, outdated software, and misconfigurations.

---

#### nuclei — Template-Based Vulnerability Scanner

Runs community templates for CVEs, misconfigurations, exposed panels, and secrets.

```yaml
tools:
  nuclei:
    enabled: true
    templates:
      - "cves/"
      - "misconfiguration/"
      - "vulnerabilities/"
      - "exposures/"
    severity_filter: "low,medium,high,critical"
    rate_limit: 150
    concurrency: 50
```

---

#### whois — Domain Registration Info

Queries registrar, registrant, creation/expiry dates, nameservers, and contact emails.

---

#### theHarvester — OSINT Gathering

Harvests emails, subdomains, and IPs from Google, Bing, DuckDuckGo, LinkedIn, and HackerTarget.

```yaml
tools:
  theharvester:
    enabled: true
    sources: "google,bing,duckduckgo,linkedin,hackertarget"
    limit: 500
```

---

#### amass — Comprehensive Subdomain Enumeration

Deeper subdomain enumeration than subfinder. Heavier — recommended for thorough engagements.

```yaml
tools:
  amass:
    enabled: true
    mode: "passive"    # passive | active
```

---

#### feroxbuster — Recursive Directory Fuzzing

Recursively follows every found directory. Generates more traffic than ffuf/gobuster.

```yaml
tools:
  feroxbuster:
    enabled: true
    wordlist: "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
    threads: 50
```

---

#### gau / waybackurls — Historical URL Discovery

**gau** queries Wayback Machine, Common Crawl, and OTX. **waybackurls** queries Wayback Machine directly. Finds forgotten endpoints, old admin panels, and leaked files.

```yaml
tools:
  gau:
    enabled: true
  waybackurls:
    enabled: true
```

---

#### enum4linux / smbmap — SMB Recon

`enum4linux` enumerates SMB shares, users, groups, and domain info. `smbmap` lists share permissions. Only useful when port 445 is open.

```yaml
tools:
  enum4linux:
    enabled: true
  smbmap:
    enabled: true
```

---

### 18.3 Wordlists

Most fuzzing tools require wordlists from the **SecLists** collection:

```bash
sudo apt install seclists
```

Default wordlist paths:

| Tool | Default wordlist |
|---|---|
| ffuf | `/usr/share/seclists/Discovery/Web-Content/common.txt` |
| gobuster dir | `/usr/share/seclists/Discovery/Web-Content/common.txt` |
| gobuster dns | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` |
| feroxbuster | `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt` |
| dirb | `/usr/share/dirb/wordlists/common.txt` |
| wfuzz | `/usr/share/seclists/Discovery/Web-Content/common.txt` |

Override in `config/web_vapt.yaml` under the relevant tool key.

---

### 18.4 Recon Tool Configuration Quick Reference

```yaml
# Enable a non-default tool
tools:
  amass:
    enabled: true

# Disable a default tool
tools:
  nikto:
    enabled: false

# Faster nmap (common ports only)
tools:
  nmap:
    port_range: "21,22,80,443,445,3306,8080,8443"
    timing_template: "T3"
    os_detection: false

# Bigger ffuf wordlist
tools:
  ffuf:
    wordlist: "/usr/share/seclists/Discovery/Web-Content/big.txt"
    threads: 100
    matcher_status: "200,301,302,403"

# Add OSINT sources
tools:
  theharvester:
    enabled: true
    sources: "google,bing,duckduckgo,linkedin,hackertarget,crtsh"
    limit: 1000
```

---

*AI Red Team Harness v3 — For authorised security assessments only.*
*Python 3.11+ · httpx 0.27+ · PyYAML 6.0+*

---

### Module map

| Module | File | Purpose |
|---|---|---|
| `WebVAPTEngine` | `modules/web_vapt_engine.py` | Web vulnerability scan engine |
| `ReconEngine` | `modules/recon_tools.py` | 29 Kali tool orchestrator |
| `ExploitEngine` | `modules/exploit_engine.py` | searchsploit + NVD + MSF mapping |
| `AttackChainBuilder` | `modules/attack_chain.py` | MITRE ATT&CK chain analysis |
| `PentestAgent` | `modules/agent_loop.py` | Autonomous ReAct agentic loop |
