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
    python run_vapt.py --target http://192.168.0.101/dvwa

  With LLM analysis (requires Ollama + llama3):
    python run_vapt.py --target http://192.168.0.101/dvwa --llm

  With verbose logging:
    python run_vapt.py --target http://192.168.0.101/dvwa --llm --verbose

  Limit LLM iterations (faster):
    python run_vapt.py --target http://192.168.0.101/dvwa --llm --iter 3

  Dry run (no requests sent):
    python run_vapt.py --target http://192.168.0.101/dvwa --dry-run


ALL FLAGS
---------
  --target URL       Target URL to scan (required)
  --output DIR       Report output directory (default: reports/web)
  --llm              Enable LLM agent for AI-powered analysis
  --model MODEL      Ollama model name (default: llama3)
  --llm-url URL      Ollama URL (default: http://localhost:11434)
  --iter N           Max LLM iterations (default: 12)
  --verbose / -v     Debug logging
  --dry-run          Validate config, no scan
  --create-lab-marker  Create safety marker file


PROJECT STRUCTURE
-----------------
  run_vapt.py                 Entry point (run this)
  requirements.txt            Python dependencies
  config/
    safety.yaml               Allowlist -- add your targets here
    web_vapt.yaml             Scan module settings
  modules/
    web_vapt_engine.py        Core scan engine (20+ vuln modules)
    web_validation_agent.py   Evidence-gated finding validator
    web_llm_agent.py          LLM reasoning agent (Ollama/llama3)
    sqli_engine.py            Multi-stage SQLi detection engine
  reporting/
    web_report_generator.py   JSON + Markdown report generator
  utils/
    logger.py                 Structured logging
    config_loader.py          YAML config loader
  payloads/web/               Attack payload files
  tests/unit/                 Unit tests
  reports/web/                Scan output (auto-created)
  logs/                       Log files (auto-created)


ADDING A TARGET
---------------
  Edit config/safety.yaml and add under web_vapt.allowed_urls:

    web_vapt:
      allowed_urls:
        - "http://192.168.0.101"
        - "http://10.10.10.50"    <- your new target


RUNNING TESTS
-------------
  pytest tests/unit/test_sqli_engine.py -v
  pytest tests/unit/test_validation_agent.py -v
  pytest tests/ -v


================================================================================
  SECURITY NOTICE: Only scan systems you own or have explicit written permission
  to test. The .lab_mode_enabled marker must be present. Never run against
  production systems.
================================================================================
