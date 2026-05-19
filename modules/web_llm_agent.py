# -*- coding: utf-8 -*-
"""
modules/web_llm_agent.py
========================
AI Red Team Harness v3 - LLM-Powered Web Security Agent

Integrates a local Ollama LLM (default: llama3) into the web VAPT pipeline.
The agent runs a tool-calling loop to reason about scan findings, probe
additional attack surfaces, and produce an executive brief.

Security constraints:
- All HTTP calls are gated through the engine's existing safety guard
- No destructive exploitation, no persistence, no DoS
- Authorized lab environments only
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

try:
    from utils.logger import get_logger
except ImportError:
    import logging
    def get_logger(name: str):
        return logging.getLogger(name)

logger = get_logger("modules.web_llm_agent")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_MODEL        = "llama3"
_DEFAULT_OLLAMA_URL   = "http://localhost:11434"
_LLM_CONNECT_TIMEOUT  = 10.0
_LLM_READ_TIMEOUT     = 300.0  # model load + first-token can take 3-5 min on CPU
_LLM_WARMUP_TIMEOUT   = 300.0  # same budget for warmup ping
_MAX_ITERATIONS       = 12
_TOOL_OUTPUT_MAX_LEN  = 2_000
_CONTEXT_WINDOW_CHARS = 8_000

_SYSTEM_PROMPT = """\
You are a web security analyst. Review the scan findings and call tools to verify them.

Tools (one JSON per turn):
{"tool":"scan_sqli","url":"<url>","param":"<name>"}
{"tool":"scan_xss","url":"<url>","param":"<name>"}
{"tool":"scan_headers","url":"<url>"}
{"tool":"examine","finding_id":"<id>"}
{"tool":"add_note","text":"<note>"}
{"tool":"done"}

Rules: no DoS, only test listed URLs, end with done then write a brief risk summary.
"""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AgentTurn:
    iteration:   int
    tool:        str
    params:      dict
    reasoning:   str
    tool_output: str
    llm_tokens:  int = 0


@dataclass
class WebLLMResult:
    executive_brief:     str              = ""
    risk_rating:         str              = "UNKNOWN"
    attack_chains:       list[str]        = field(default_factory=list)
    additional_findings: list[Any]        = field(default_factory=list)
    agent_log:           list[AgentTurn]  = field(default_factory=list)
    model_used:          str              = _DEFAULT_MODEL
    iterations_used:     int              = 0
    error:               str              = ""


# ---------------------------------------------------------------------------
# Ollama HTTP client
# ---------------------------------------------------------------------------

class OllamaClient:
    def __init__(self, base_url: str = _DEFAULT_OLLAMA_URL, model: str = _DEFAULT_MODEL):
        self._base_url = base_url.rstrip("/")
        self._model    = model

    async def chat(self, messages: list[dict], temperature: float = 0.2) -> tuple[str, int]:
        """Stream the response so per-chunk timeout applies, not total response time."""
        url = f"{self._base_url}/api/chat"
        payload = {
            "model":   self._model,
            "messages": messages,
            "stream":  True,
            "options": {"temperature": temperature},
        }
        timeout = httpx.Timeout(
            connect=_LLM_CONNECT_TIMEOUT,
            read=_LLM_READ_TIMEOUT,
            write=10.0,
            pool=5.0,
        )
        parts: list[str] = []
        tokens = 0
        async with httpx.AsyncClient(timeout=timeout) as client:
            async with client.stream("POST", url, json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        chunk = data.get("message", {}).get("content", "")
                        if chunk:
                            parts.append(chunk)
                        if data.get("done"):
                            tokens = data.get("eval_count", 0)
                            break
                    except json.JSONDecodeError:
                        continue
        return "".join(parts), tokens

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self._base_url}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False

    async def warmup(self) -> bool:
        """Send a trivial prompt to load the model into memory before the main loop."""
        logger.info("LLM agent: warming up model '%s' (may take 1-3 min on CPU)...", self._model)
        try:
            url = f"{self._base_url}/api/generate"
            payload = {"model": self._model, "prompt": "hi", "stream": False}
            timeout = httpx.Timeout(connect=_LLM_CONNECT_TIMEOUT, read=_LLM_WARMUP_TIMEOUT,
                                    write=10.0, pool=5.0)
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, json=payload)
                ok = resp.status_code == 200
                if ok:
                    logger.info("LLM agent: model warm and ready.")
                return ok
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
            logger.warning("LLM agent: warmup failed: %s", err)
            return False

    async def check_model(self) -> bool:
        """Return True if self._model is present in Ollama's local library."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self._base_url}/api/tags")
                if resp.status_code != 200:
                    return False
                models = [m.get("name", "") for m in resp.json().get("models", [])]
                return any(self._model in m for m in models)
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Tool executor
# ---------------------------------------------------------------------------

class _ToolExecutor:
    def __init__(
        self,
        get_fn:   Callable,
        post_fn:  Callable,
        findings: list[Any],
        surface:  Any,
    ):
        self._get      = get_fn
        self._post     = post_fn
        self._findings = {str(i): f for i, f in enumerate(findings)}
        self._surface  = surface

    async def execute(self, tool: str, params: dict) -> str:
        try:
            if tool == "scan_sqli":
                return await self._scan_sqli(params)
            elif tool == "scan_xss":
                return await self._scan_xss(params)
            elif tool == "scan_lfi":
                return await self._scan_lfi(params)
            elif tool == "scan_headers":
                return await self._scan_headers(params)
            elif tool == "scan_file":
                return await self._scan_file(params)
            elif tool == "examine":
                return self._examine(params)
            elif tool == "add_note":
                return f"Note recorded: {params.get('text', '')}"
            elif tool == "done":
                return "DONE"
            else:
                return f"Unknown tool: {tool}"
        except Exception as exc:
            return f"Tool error: {exc}"

    async def _scan_sqli(self, params: dict) -> str:
        url   = params.get("url", "")
        param = params.get("param", "id")
        probes = ["'", "' OR '1'='1", "1 AND 1=1", "1; SELECT 1--"]
        results = []
        for probe in probes[:2]:
            try:
                resp = await self._get(url, params={param: probe})
                body = (resp.text if hasattr(resp, "text") else str(resp))[:500]
                results.append(f"Probe {repr(probe)}: status={getattr(resp,'status_code',0)}, body_snippet={body[:200]}")
            except Exception as exc:
                results.append(f"Probe {repr(probe)}: error={exc}")
        return "\n".join(results)[:_TOOL_OUTPUT_MAX_LEN]

    async def _scan_xss(self, params: dict) -> str:
        url   = params.get("url", "")
        param = params.get("param", "q")
        marker = "XSS_PROBE_49281"
        probe  = f"<script>alert('{marker}')</script>"
        try:
            resp = await self._get(url, params={param: probe})
            body = (resp.text if hasattr(resp, "text") else str(resp))
            reflected = marker in body
            return f"Reflected={reflected}, status={getattr(resp,'status_code',0)}, body_len={len(body)}"
        except Exception as exc:
            return f"Error: {exc}"

    async def _scan_lfi(self, params: dict) -> str:
        url   = params.get("url", "")
        param = params.get("param", "file")
        payloads = ["../../../etc/passwd", "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd"]
        results = []
        for payload in payloads[:2]:
            try:
                resp = await self._get(url, params={param: payload})
                body = (resp.text if hasattr(resp, "text") else str(resp))
                lfi  = "root:" in body or "bin/bash" in body
                results.append(f"Payload={repr(payload)}: lfi_indicator={lfi}, status={getattr(resp,'status_code',0)}")
            except Exception as exc:
                results.append(f"Payload={repr(payload)}: error={exc}")
        return "\n".join(results)[:_TOOL_OUTPUT_MAX_LEN]

    async def _scan_headers(self, params: dict) -> str:
        url = params.get("url", "")
        try:
            resp = await self._get(url)
            hdrs = dict(getattr(resp, "headers", {}))
            security_hdrs = [
                "strict-transport-security", "content-security-policy",
                "x-frame-options", "x-content-type-options",
                "referrer-policy", "permissions-policy",
            ]
            present  = [h for h in security_hdrs if h in hdrs]
            missing  = [h for h in security_hdrs if h not in hdrs]
            server   = hdrs.get("server", "not disclosed")
            powered  = hdrs.get("x-powered-by", "not disclosed")
            return (
                f"Present: {present}\n"
                f"Missing: {missing}\n"
                f"Server: {server}\n"
                f"X-Powered-By: {powered}"
            )
        except Exception as exc:
            return f"Error: {exc}"

    async def _scan_file(self, params: dict) -> str:
        url = params.get("url", "")
        try:
            resp = await self._get(url)
            body = (resp.text if hasattr(resp, "text") else str(resp))[:400]
            return f"status={getattr(resp,'status_code',0)}, body_snippet={body}"
        except Exception as exc:
            return f"Error: {exc}"

    def _examine(self, params: dict) -> str:
        fid = str(params.get("finding_id", ""))
        if fid in self._findings:
            f = self._findings[fid]
            return json.dumps({
                "id":          fid,
                "title":       getattr(f, "title", ""),
                "severity":    str(getattr(f, "severity", "")),
                "url":         getattr(f, "url", ""),
                "evidence":    getattr(f, "evidence", "")[:400],
                "exploit_status": getattr(f, "exploit_status", "UNVERIFIED"),
            }, indent=2)
        return f"Finding {fid!r} not found. Available IDs: {list(self._findings.keys())[:10]}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _summarise_surface(surface: Any, findings: list[Any]) -> str:
    urls   = getattr(surface, "urls", [])
    forms  = getattr(surface, "forms", [])
    params = getattr(surface, "parameters", {})
    lines  = [
        f"Target: {getattr(surface, 'base_url', 'unknown')}",
        f"URLs crawled: {len(urls)}",
        f"Forms found: {len(forms)}",
        f"Parameters: {sum(len(v) for v in params.values())}",
        f"Initial findings: {len(findings)}",
        "",
        "Finding summary:",
    ]
    for i, f in enumerate(findings[:15]):
        sev = str(getattr(f, "severity", "?"))
        title = getattr(f, "title", "?")
        url   = getattr(f, "url", "")
        lines.append(f"  [{i}] {sev} - {title} - {url}")
    if len(findings) > 15:
        lines.append(f"  ... and {len(findings)-15} more")
    return "\n".join(lines)


def _parse_tool_call(text: str) -> tuple[str, dict] | tuple[None, None]:
    matches = re.findall(r'\{[^{}]+\}', text)
    for m in matches:
        try:
            data = json.loads(m)
            if "tool" in data:
                tool   = data.pop("tool")
                params = data
                return tool, params
        except json.JSONDecodeError:
            continue
    return None, None


def _fmt_findings(findings: list[Any]) -> str:
    lines = []
    for i, f in enumerate(findings[:10]):  # cap at 10 to keep prompt small
        lines.append(
            f"[{i}] {getattr(f,'severity','?')} | {getattr(f,'title','?')} | "
            f"exploit={getattr(f,'exploit_status','?')}"
        )
    if len(findings) > 10:
        lines.append(f"... +{len(findings)-10} more findings")
    return "\n".join(lines) if lines else "No findings."


def _trim_messages(messages: list[dict], max_chars: int = _CONTEXT_WINDOW_CHARS) -> list[dict]:
    total = sum(len(m.get("content", "")) for m in messages)
    if total <= max_chars:
        return messages
    trimmed = [messages[0]]
    for msg in messages[1:]:
        content = msg.get("content", "")
        if len(content) > 600:
            msg = {**msg, "content": content[:600] + " ...[trimmed]"}
        trimmed.append(msg)
    return trimmed


# ---------------------------------------------------------------------------
# Main agent class
# ---------------------------------------------------------------------------

class WebLLMAgent:
    """
    LLM-powered reasoning agent for web VAPT.

    Uses a local Ollama instance to run a tool-calling loop that analyses
    scan findings and probes additional attack vectors.
    """

    def __init__(self, config: dict | None = None):
        cfg             = config or {}
        self._model     = cfg.get("model", _DEFAULT_MODEL)
        self._base_url  = cfg.get("base_url", _DEFAULT_OLLAMA_URL)
        self._max_iter  = int(cfg.get("max_iterations", _MAX_ITERATIONS))
        self._client    = OllamaClient(base_url=self._base_url, model=self._model)

    async def run(
        self,
        engine:    Any,  # noqa: ARG002 - reserved for future engine callbacks
        surface:   Any,
        findings:  list[Any],
        get_fn:    Callable,
        post_fn:   Callable,
        kill_fn:   Callable,
    ) -> WebLLMResult:
        result = WebLLMResult(model_used=self._model)

        if not await self._client.is_available():
            result.error = f"Ollama not reachable at {self._base_url}"
            logger.warning("LLM agent: %s", result.error)
            return result

        if not await self._client.check_model():
            result.error = (
                f"Model '{self._model}' not found in Ollama. "
                f"Run: ollama pull {self._model}"
            )
            logger.warning("LLM agent: %s", result.error)
            return result

        if not await self._client.warmup():
            result.error = f"Model '{self._model}' failed to warm up — check Ollama logs"
            logger.warning("LLM agent: %s", result.error)
            return result

        logger.info("LLM agent: starting tool-calling loop | model=%s max_iter=%d", self._model, self._max_iter)

        executor = _ToolExecutor(
            get_fn=get_fn,
            post_fn=post_fn,
            findings=findings,
            surface=surface,
        )

        surface_summary = _summarise_surface(surface, findings)
        findings_text   = _fmt_findings(findings)

        messages: list[dict] = [
            {"role": "system",  "content": _SYSTEM_PROMPT},
            {"role": "user",    "content": (
                f"Security scan complete. Here is the target context:\n\n"
                f"{surface_summary}\n\n"
                f"Initial findings:\n{findings_text}\n\n"
                f"Begin your analysis. Call tools as needed, then call done."
            )},
        ]

        iteration = 0
        while iteration < self._max_iter:
            if kill_fn and kill_fn():
                logger.info("LLM agent: kill signal received, stopping")
                break

            try:
                messages = _trim_messages(messages)
                llm_text, tokens = await self._client.chat(messages)
            except Exception as exc:
                err_msg = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
                logger.warning("LLM chat error at iteration %d: %s", iteration, err_msg)
                result.error = err_msg
                break

            messages.append({"role": "assistant", "content": llm_text})

            tool, params = _parse_tool_call(llm_text)

            if tool is None:
                turn = AgentTurn(
                    iteration=iteration,
                    tool="(no tool)",
                    params={},
                    reasoning=llm_text[:300],
                    tool_output="",
                    llm_tokens=tokens,
                )
                result.agent_log.append(turn)
                iteration += 1
                continue

            tool_output = await executor.execute(tool, params or {})

            reasoning = llm_text
            for tc in re.findall(r'\{[^{}]+\}', llm_text):
                reasoning = reasoning.replace(tc, "").strip()

            turn = AgentTurn(
                iteration=iteration,
                tool=tool,
                params=params or {},
                reasoning=reasoning[:400],
                tool_output=tool_output[:_TOOL_OUTPUT_MAX_LEN],
                llm_tokens=tokens,
            )
            result.agent_log.append(turn)

            if tool == "done":
                iteration += 1
                break

            messages.append({
                "role":    "user",
                "content": f"Tool result:\n{tool_output[:_TOOL_OUTPUT_MAX_LEN]}",
            })
            iteration += 1

        result.iterations_used = iteration

        try:
            brief = await self._request_brief(messages)
            result.executive_brief = brief
            result.risk_rating     = self._extract_risk_rating(brief)
            result.attack_chains   = self._extract_attack_chains(brief)
        except Exception as exc:
            err_msg = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
            logger.warning("LLM brief generation failed: %s", err_msg)
            result.executive_brief = f"Brief generation failed: {err_msg}"

        return result

    async def _request_brief(self, messages: list[dict]) -> str:
        brief_messages = list(messages) + [{
            "role": "user",
            "content": (
                "Now write your final executive brief. Include:\n"
                "1. RISK RATING: (CRITICAL/HIGH/MEDIUM/LOW/INFO)\n"
                "2. Key confirmed vulnerabilities\n"
                "3. Attack chains (numbered list)\n"
                "4. Recommended mitigations\n"
                "Keep it under 400 words."
            ),
        }]
        text, _ = await self._client.chat(brief_messages, temperature=0.1)
        return text

    def _extract_risk_rating(self, brief: str) -> str:
        m = re.search(
            r"RISK\s+RATING\s*[:\-]\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)",
            brief, re.IGNORECASE,
        )
        if m:
            return m.group(1).upper()
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if level in brief.upper():
                return level
        return "UNKNOWN"

    def _extract_attack_chains(self, brief: str) -> list[str]:
        chains: list[str] = []
        for m in re.finditer(r'^\s*\d+[.)]\s+(.+)', brief, re.MULTILINE):
            line = m.group(1).strip()
            if len(line) > 10:
                chains.append(line)
        return chains[:10]
