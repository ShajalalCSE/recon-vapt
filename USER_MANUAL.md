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
6. [Command Reference](#6-command-reference)
7. [Burp Suite Integration](#7-burp-suite-integration)
8. [Authentication Options](#8-authentication-options)
9. [Module Selection](#9-module-selection)
10. [Configuration Files](#10-configuration-files)
11. [Scan Phases](#11-scan-phases)
12. [Understanding Reports](#12-understanding-reports)
13. [Scan Modules Reference](#13-scan-modules-reference)
14. [Troubleshooting](#14-troubleshooting)
15. [Workflow Examples](#15-workflow-examples)

---

## 1. Overview

AI Red Team Harness v3 is a Python-based, non-destructive web application vulnerability assessment framework. It crawls a target, discovers attack surface elements, fires over 38 scan modules, validates findings, and generates detailed Markdown and JSON reports.

**Key design principles:**
- Every target must be explicitly allowlisted before any request is sent
- Rate-limited by a token bucket — never floods the target
- All checks are read-only; no payloads are written or executed on the target
- Findings are validated and false-positive filtered before reporting

**Assessment flow:**

```
Phase 1  →  Attack surface discovery (crawl + Burp seed)
Phase 1b →  Merge Burp request data into surface (if -r used)
Phase 2  →  38 scan modules run concurrently (max 8 at once)
Phase 3  →  External tools (nuclei, nmap, nikto, etc.) if installed
Phase 4  →  Deduplicate and confidence-threshold filter
Phase 5  →  Evidence-gated validation agent
Phase 6  →  LLM agent reasoning (optional, requires Ollama)
         →  Report generation (Markdown + JSON)
```

---

## 2. Requirements

| Requirement | Minimum |
|---|---|
| Python | 3.11+ |
| httpx | 0.27+ |
| PyYAML | 6.0+ |
| OS | Windows / Linux / macOS |

**Optional external tools** (improves coverage if installed in PATH):

| Tool | Purpose |
|---|---|
| `katana` | JavaScript-rendered crawling (SPA support) |
| `nuclei` | Template-based CVE and misconfiguration scanning |
| `nmap` | Port scan and service detection |
| `nikto` | Web server misconfiguration scan |
| `whatweb` | Technology fingerprinting |
| `subfinder` | Subdomain enumeration |
| `gau` | Historical URL discovery |
| `feroxbuster` | Directory bruteforce |
| `ffuf` | Parameter and path fuzzing |
| `testssl.sh` | Deep TLS analysis |

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
```

The lab marker file (`.lab_mode_enabled`) is a safety gate. Without it, all scans are blocked. Re-create it any time:

```bash
python run_vapt.py --create-lab-marker
```

---

## 4. Safety System

The framework enforces a two-layer allowlist before sending any traffic.

### 4.1 Lab Marker

The file `.lab_mode_enabled` must exist in the project root. Create it once:

```bash
python run_vapt.py --create-lab-marker
```

### 4.2 URL Allowlist

Every target must appear in `config/safety.yaml` under `web_vapt.allowed_urls`. The engine performs a prefix match — adding `http://192.168.0.102` also covers all paths under that host.

```yaml
# config/safety.yaml
web_vapt:
  allowed_urls:
    - "http://localhost"
    - "https://localhost"
    - "http://127.0.0.1"
    - "http://192.168.0.102"        # local DVWA
    - "http://192.168.0.102/dvwa"
    - "https://your-owned-domain.com"
```

**Adding a new target:**

1. Open `config/safety.yaml`
2. Add the URL under `web_vapt.allowed_urls`
3. Save the file — no restart needed

If you try to scan a target not in the allowlist, the engine exits immediately with:

```
[BLOCKED] Target 'https://example.com' is not in the web VAPT allowlist
```

---

## 5. Quick Start

### Simplest scan — URL only

```bash
python run_vapt.py --target http://192.168.0.102/dvwa/
```

### Scan with a Burp Suite captured request

```bash
python run_vapt.py -r burp_request.txt
```

The target URL, cookies, session ID, headers, and parameters are all read from the file automatically.

### Dry run — confirm config without scanning

```bash
python run_vapt.py --target http://192.168.0.102/dvwa/ --dry-run
```

---

## 6. Command Reference

```
python run_vapt.py [OPTIONS]
```

| Option | Short | Default | Description |
|---|---|---|---|
| `--target URL` | | — | Target URL to scan |
| `--request FILE` | `-r` | — | Burp Suite raw request file |
| `--output DIR` | | `reports/web` | Output directory for reports |
| `--modules LIST` | | all enabled | Comma-separated module names to run |
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

### Priority rules

- `--target` takes precedence over the URL inferred from `-r`
- `--cookie` takes precedence over the `Cookie:` header in the Burp file
- `--modules` is case-insensitive; spaces around commas are ignored

---

## 7. Burp Suite Integration

The `-r` flag accepts any raw HTTP request file — the same format Burp Suite exports and `sqlmap -r` accepts.

### How to export from Burp Suite

1. In **Proxy → HTTP history** or **Repeater**, right-click the request
2. Select **Save item** (Proxy history) or copy from Repeater's raw view
3. Save as a `.txt` file

A valid Burp request file looks like:

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

The parser infers `http` or `https` from the Host header — no configuration needed:

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
# Use Burp file for headers/params but override the cookie (e.g. after re-login)
python run_vapt.py -r burp_request.txt --cookie "PHPSESSID=newtoken123"

# Run only injection modules on the captured request
python run_vapt.py -r burp_request.txt --modules sqli,xss,lfi,command_injection

# Full authenticated scan with verbose output
python run_vapt.py -r burp_request.txt --verbose
```

---

## 8. Authentication Options

### Option A — Burp Suite file (recommended)

Captures everything automatically including session cookies, CSRF tokens, and custom headers.

```bash
python run_vapt.py -r burp_request.txt
```

### Option B — Manual cookie

Paste the `Cookie:` header value directly. Useful when you have a session token but no Burp file.

```bash
python run_vapt.py --target http://192.168.0.102/dvwa/ \
  --cookie "security=low; PHPSESSID=890d395c1b362ffa9f857201e36573c7"
```

### Option C — HTTP Basic Auth

For applications protected by HTTP Basic Authentication (e.g., `.htpasswd`-protected pages).

```bash
python run_vapt.py --target http://192.168.0.102/ \
  --username admin --password secret
```

### Combining auth methods

Cookie and Basic Auth can be used together. If `-r` is also used, `--cookie` overrides the cookie from the Burp file:

```bash
python run_vapt.py -r burp_request.txt \
  --cookie "PHPSESSID=refreshedtoken" \
  --username admin --password secret
```

---

## 9. Module Selection

By default, all 38 modules run. Use `--modules` to run only specific ones — useful for targeted follow-up scans or when you already know the technology stack.

```bash
# Run only injection modules
python run_vapt.py --target http://192.168.0.102/dvwa/ \
  --modules sqli,xss,lfi,rfi,command_injection

# Run only authentication and session checks
python run_vapt.py --target http://target.com \
  --modules auth,csrf,jwt,jwt_algorithm_confusion

# Run only reconnaissance (no active injection)
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

## 10. Configuration Files

### `config/safety.yaml` — Safety and allowlist

Controls who can be scanned and what is blocked.

**Key settings:**

```yaml
web_vapt:
  allowed_urls:           # Targets permitted for scanning
    - "http://192.168.0.102"
    - "https://your-domain.com"

  require_lab_marker: true  # Must have .lab_mode_enabled file

sandbox:
  require_lab_marker: true  # Same gate for all scan types

kill_switch:
  max_attack_budget: 500         # Max findings before auto-stop
  max_session_duration_seconds: 7200  # 2 hour hard cutoff
```

### `config/web_vapt.yaml` — Engine behaviour

Controls crawling depth, rate limits, timeouts, payloads, and which modules are enabled.

**Key settings:**

```yaml
concurrency:
  max_parallel_scans: 8      # Modules running at once
  max_parallel_requests: 5   # Concurrent HTTP requests per module

rate_limiting:
  requests_per_second: 10.0  # Token bucket rate
  burst_size: 20             # Max burst

timeouts:
  http_request_seconds: 15.0
  connect_timeout_seconds: 5.0
  tool_execution_seconds: 120

crawl:
  max_depth: 5               # How deep the crawler follows links
  max_urls: 250              # Max URLs to crawl

modules:
  sqli:
    enabled: true            # Set to false to permanently disable
    max_payloads: 30
  xss:
    enabled: true
    max_payloads: 25
  # ... all 38 modules have enabled: true/false
```

**Disabling a module permanently** (vs using `--modules` for one scan):

```yaml
modules:
  wasm_memory_corruption:
    enabled: false   # Never runs even without --modules filter
```

---

## 11. Scan Phases

### Phase 1 — Attack Surface Discovery

The engine crawls the target URL using a built-in HTML parser that extracts:
- All `<a href>` links within the same domain
- HTML `<form>` elements with their inputs, method, and action
- URL query parameters
- `<script src>` JavaScript files
- WebAssembly (`.wasm`) references
- Import maps, service workers
- WebSocket endpoints detected in JavaScript source
- GraphQL endpoints by path pattern

If `katana` is installed, a second deeper crawl runs with JavaScript execution enabled (`-jc` flag), which discovers content in React/Vue/Angular SPAs.

**When attack surface is minimal (1 URL, 0 forms):**

The most common cause is a JavaScript-rendered SPA where the raw HTML contains only a `<div id="root">` and a JS bundle. In this case:
- Install `katana` for JS-rendered crawling
- Use `-r` with a Burp file to manually inject the endpoint and parameters

### Phase 1b — Burp Seed Merge

If `-r` was used, the parsed request data is merged into the attack surface:
- Target URL added to `surface.urls`
- Query and body parameters merged into `surface.parameters`
- A synthetic `<form>` is created from all parameters so injection modules test them
- Browser headers (User-Agent, Accept, Referer) are forwarded on all requests
- Cookie is injected into the HTTP client for all subsequent requests

### Phase 2 — Scan Modules

All enabled modules run concurrently. The semaphore limits to 8 at a time. Each module receives the full attack surface and iterates over URLs, forms, and parameters independently.

Modules that need parameters (SQLi, XSS, LFI, IDOR, etc.) will complete instantly if no forms/parameters were discovered — they have nothing to test. This is normal behaviour and is why `-r` or a crawlable target with forms is important for injection testing.

Modules that probe fixed paths (sensitive_files, debug_endpoints, security_headers, cors, tls) always produce results regardless of crawl depth.

### Phase 3 — External Tools

If tools are installed in PATH, the engine runs them automatically:
- `nuclei` — template-based vulnerability scanning
- `nmap` — port and service scan
- `nikto` — web server misconfiguration
- `whatweb` — technology detection
- `subfinder` — subdomain enumeration
- `gau` — historical URL discovery

If a tool is not found, it is silently skipped and noted in the report under **External Tool Outputs**.

### Phase 4 — Deduplication and Filtering

Findings below the minimum confidence threshold (default: 0.2 = 20%) are dropped. Duplicate findings for the same endpoint + parameter + category are merged.

### Phase 5 — Validation Agent

Each remaining finding is re-validated by the `WebValidationAgent`. It re-sends the payload and compares the response against a baseline to confirm the anomaly is real. Validated findings are marked **CONFIRMED**; unconfirmed ones are marked **POTENTIAL — MANUAL VALIDATION REQUIRED**.

### Phase 6 — LLM Agent (optional)

When `--llm` is used, a local Ollama model analyses all findings and generates:
- Executive brief
- Risk rating
- Attack chain narratives
- Prioritised remediation advice

Requires Ollama running locally. Default model: `llama3`.

```bash
python run_vapt.py --target http://192.168.0.102/dvwa/ --llm --model llama3
```

---

## 12. Understanding Reports

Reports are written to `reports/web/` (or the directory set with `--output`) in both Markdown (`.md`) and JSON (`.json`) format.

### Report structure

```
reports/web/
  web_vapt_YYYYMMDD_HHMMSS.md    ← Human-readable report
  web_vapt_YYYYMMDD_HHMMSS.json  ← Machine-readable findings
```

### Severity levels

| Level | CVSS range | Meaning |
|---|---|---|
| CRITICAL | 9.0 – 10.0 | Directly exploitable, high impact |
| HIGH | 7.0 – 8.9 | Likely exploitable with moderate effort |
| MEDIUM | 4.0 – 6.9 | Exploitable under certain conditions |
| LOW | 1.0 – 3.9 | Limited impact or hard to exploit |
| INFO | 0.0 | Informational, no direct impact |

### Validation status

| Status | Meaning |
|---|---|
| **CONFIRMED** | Evidence re-validated; anomaly reproduced |
| **POTENTIAL — MANUAL VALIDATION REQUIRED** | Engine detected a signal but could not definitively confirm |

### Risk score

The overall risk score (0–100) is calculated from the weighted sum of findings by severity. Use it as a quick health indicator across scans.

### Reading a finding

Each finding contains:
- **Finding ID** — unique identifier (e.g., `WEB-13043EA5`)
- **Severity** and **CVSS score**
- **Confidence** — engine's certainty (0–100%)
- **Validation status** — CONFIRMED or POTENTIAL
- **Endpoint** — the URL that triggered the finding
- **Parameter** — the specific parameter or header
- **Description** — what was found
- **Comparison Result** — baseline vs attack response
- **Evidence** — raw response excerpt
- **Exact Reproduction Steps** — how to manually verify
- **Remediation** — how to fix it
- **References** — OWASP / CWE / RFC links

---

## 13. Scan Modules Reference

See [Section 9 — Module Selection](#9-module-selection) for the full module name list.

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

## 14. Troubleshooting

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
```

### `Attack surface: 1 URLs, 0 forms, 0 params`

The crawler found nothing to inject. Causes:

1. **JavaScript SPA** — Install `katana` for JS-rendered crawling
2. **Login wall** — Use `-r` with a Burp file or `--cookie` to authenticate
3. **Request blocked by WAF/Cloudflare** — Add `--verbose` to see the GET error; try with a real browser User-Agent via `-r`
4. **Target unreachable** — Add `--verbose` and check for `GET ... failed:` in output

### Target auto-selects wrong scheme (http vs https)

Use `--target` to force the scheme:

```bash
python run_vapt.py -r burp.txt --target http://192.168.0.102/dvwa/
```

Or use the Burp file — scheme is auto-inferred from the host (private IPs → http).

### Scan appears to hang after attack surface discovery

The scan is running Phase 2 (30+ modules) silently. With 0 forms/params, most modules complete instantly but `sensitive_files` and `debug_endpoints` still send ~200 probes. At 10 req/s this takes ~20 seconds. Enable `--verbose` to see per-request activity.

### External tools show `not found in PATH`

Install the tools and ensure they are in your system PATH. They are optional — the scan runs fully without them.

### `Cannot import WebVAPTEngine` on startup

```bash
pip install -r requirements.txt
```

---

## 15. Workflow Examples

### Example 1 — Quick recon (no authentication)

```bash
python run_vapt.py --target https://example.com \
  --modules security_headers,tls,cors,sensitive_files,debug_endpoints
```

Runs in under 30 seconds. Good for a first-pass check of any public site.

---

### Example 2 — Authenticated DVWA scan via Burp

1. Open DVWA in your browser with Burp Suite proxying traffic
2. Navigate to any DVWA page while authenticated
3. In Burp Proxy history, right-click the request → **Save item** → `burp_dvwa.txt`
4. Run the scan:

```bash
python run_vapt.py -r burp_dvwa.txt
```

The scan now uses your session cookie and tests all DVWA parameters for injection.

---

### Example 3 — Targeted injection test on a known endpoint

You know the login form is vulnerable; scan only injection modules:

```bash
python run_vapt.py -r burp_login.txt \
  --modules sqli,xss,command_injection,lfi,ssti
```

---

### Example 4 — Full scan with LLM analysis

```bash
# Start Ollama in another terminal
ollama serve

# Run full scan with AI analysis
python run_vapt.py --target http://192.168.0.102/dvwa/ \
  --cookie "security=low; PHPSESSID=abc123" \
  --llm --model llama3 --iter 15
```

The LLM agent produces an executive brief and attack chain analysis in the report.

---

### Example 5 — Iterative scanning workflow

```bash
# 1. First pass — full discovery
python run_vapt.py -r burp.txt --output reports/pass1

# 2. Review report, then re-run only confirmed vulnerable areas
python run_vapt.py -r burp.txt --modules sqli,lfi \
  --output reports/pass2 --verbose

# 3. Final report with LLM analysis
python run_vapt.py -r burp.txt --llm --output reports/final
```

---

### Example 6 — HTTP Basic Auth target

```bash
python run_vapt.py --target http://192.168.0.102/protected/ \
  --username admin --password password123 \
  --modules auth,security_headers,sensitive_files,debug_endpoints
```

---

## Appendix — Output Summary Fields

When a scan completes, the terminal prints:

```
==========================================================
  WEB VAPT COMPLETE
==========================================================
  Report ID   : WEB-xxxxxxxx
  Target      : http://192.168.0.102/dvwa/
  Duration    : 45s
  Risk Score  : 72.5/100  [HIGH]
  Findings    : 18
    CRITICAL  : 2
    HIGH      : 4
    MEDIUM    : 7
    LOW       : 3
    INFO      : 2
  JSON Report : reports/web/web_vapt_20260520_010203.json
  MD Report   : reports/web/web_vapt_20260520_010203.md
==========================================================
```

**Risk labels:**

| Score range | Label |
|---|---|
| 80 – 100 | CRITICAL |
| 60 – 79 | HIGH |
| 40 – 59 | MEDIUM |
| 20 – 39 | LOW |
| 0 – 19 | INFORMATIONAL |

---

*AI Red Team Harness v3 — For authorised security assessments only.*
*Python 3.11+ · httpx 0.27+ · PyYAML 6.0+*
