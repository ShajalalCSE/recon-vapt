================================================================================
  WEB VAPT -- STANDALONE PROJECT
  AI Red Team Harness v3
================================================================================
  Authorized Lab Use Only | Defensive Security Testing
================================================================================


SETUP (one time)
----------------
  1. Install dependencies:
       pip install -r requirements.txt

  2. Create the lab safety marker:
       python run_vapt.py --create-lab-marker

  3. Add your target to config/safety.yaml under web_vapt.allowed_urls


QUICK START
-----------
  Basic scan:
    python run_vapt.py --target http://192.168.0.102/dvwa

  From a Burp Suite captured request (recommended):
    python run_vapt.py -r burp_request.txt

  With session cookie:
    python run_vapt.py --target http://192.168.0.102/dvwa --cookie "PHPSESSID=abc123; security=low"

  With HTTP Basic Auth:
    python run_vapt.py --target http://192.168.0.102/ --username admin --password secret

  Run specific attack modules only:
    python run_vapt.py --target http://192.168.0.102/dvwa --modules sqli,xss,lfi

  Burp file + targeted modules (most common workflow):
    python run_vapt.py -r burp_request.txt --modules sqli,xss,csrf,lfi

  With LLM analysis (requires Ollama + llama3):
    python run_vapt.py -r burp_request.txt --llm

  Dry run (no requests sent):
    python run_vapt.py -r burp_request.txt --dry-run

  Verbose logging:
    python run_vapt.py -r burp_request.txt --verbose


ALL FLAGS
---------
  --target URL           Target URL to scan (optional if -r is used)
  -r / --request FILE    Burp Suite raw request file (extracts URL, cookies,
                         headers, and parameters automatically)
  --output DIR           Report output directory (default: reports/web)
  --modules MOD1,MOD2    Comma-separated list of modules to run (default: all)
  --cookie STRING        Raw Cookie header, e.g. "PHPSESSID=abc; token=xyz"
  --username USER        Username for HTTP Basic Auth
  --password PASS        Password for HTTP Basic Auth
  --llm                  Enable LLM agent (Phase 6) for AI analysis
  --model MODEL          Ollama model name (default: llama3)
  --llm-url URL          Ollama base URL (default: http://localhost:11434)
  --iter N               Max LLM iterations (default: 12)
  --verbose / -v         Enable DEBUG logging
  --dry-run              Print resolved config, no scan
  --create-lab-marker    Create .lab_mode_enabled safety marker and exit


AVAILABLE MODULES (--modules)
------------------------------
  Classic OWASP:
    sqli, xss, idor, lfi, rfi, command_injection, csrf, auth,
    file_upload, security_headers, tls, cors, sensitive_files,
    debug_endpoints, ssrf, open_redirect, graphql, jwt, prototype_pollution

  Advanced 2026:
    jwt_algorithm_confusion, wasm_memory_corruption, css_container_injection,
    http3_stream_side_channel, env_var_leakage, async_hooks_poisoning,
    http_smuggling_webtransport, mongodb_injection, dom_clobbering,
    server_timing_side_channel, web_crypto_timing, import_map_override,
    cache_stamping, webauthn_rp_confusion, deno_deserialization,
    http3_0rtt_replay, hpack_poisoning, graphql_n_plus_one, phar_deserialization


BURP SUITE INTEGRATION
----------------------
  1. In Burp Suite, right-click any request in Proxy history
  2. Select "Save item" and save as burp_request.txt
  3. Run: python run_vapt.py -r burp_request.txt

  The parser extracts automatically:
    - Target URL (Host header + path)
    - HTTP method (GET / POST / PUT)
    - Session cookies (Cookie header)
    - Browser headers (User-Agent, Accept, Referer)
    - URL query parameters
    - POST body parameters (form-encoded, JSON, multipart)

  Scheme is auto-detected from the Host header:
    - Private IPs (192.168.x, 10.x, 172.16-31.x) -> http
    - localhost / 127.x.x.x                        -> http
    - Public domain, no port                        -> https
    - Port :443 in Host                             -> https
    - Port :80 in Host                              -> http

  To force a scheme: python run_vapt.py -r burp.txt --target http://192.168.0.102/dvwa/


PROJECT STRUCTURE
-----------------
  run_vapt.py                   Entry point (run this)
  requirements.txt              Python dependencies (httpx, pyyaml)
  USER_MANUAL.md                Full user manual
  config/
    safety.yaml                 Allowlist -- add your targets here
    web_vapt.yaml               Engine settings (modules, rate limits, timeouts)
  modules/
    web_vapt_engine.py          Core scan engine (38 vuln modules)
    web_validation_agent.py     Evidence-gated finding validator
    web_llm_agent.py            LLM reasoning agent (Ollama)
    sqli_engine.py              Multi-stage SQLi detection engine
  reporting/
    web_report_generator.py     JSON + Markdown report generator
  utils/
    burp_parser.py              Burp Suite / proxy request file parser
    logger.py                   Structured logging
    config_loader.py            YAML config loader
  payloads/web/                 Attack payload wordlists
  tests/unit/                   Unit tests
  reports/web/                  Scan output (auto-created)
  logs/                         Log files (auto-created)


ADDING A TARGET
---------------
  Edit config/safety.yaml, add under web_vapt.allowed_urls:

    web_vapt:
      allowed_urls:
        - "http://192.168.0.102"
        - "http://192.168.0.102/dvwa"
        - "https://your-owned-domain.com"

  Then run normally -- no restart needed.


RUNNING TESTS
-------------
  pytest tests/unit/test_sqli_engine.py -v
  pytest tests/unit/test_validation_agent.py -v
  pytest tests/ -v


================================================================================
  SECURITY NOTICE: Only scan systems you own or have explicit written permission
  to test. The .lab_mode_enabled marker must be present. Never run against
  production systems without written authorisation.
  See USER_MANUAL.md for full documentation.
================================================================================
