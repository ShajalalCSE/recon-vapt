"""
utils/burp_parser.py
====================
Parser for raw HTTP request files exported from Burp Suite (or any proxy).

The file format is a plain-text raw HTTP/1.x request:

    POST /login.php HTTP/1.1
    Host: example.com
    User-Agent: Mozilla/5.0 ...
    Cookie: PHPSESSID=abc123; token=xyz
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 35

    username=admin&password=secret&submit=Login

Works identically to sqlmap's -r flag.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# Headers httpx manages automatically — never forward these
_SKIP_HEADERS = frozenset({
    "host", "content-length", "transfer-encoding",
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "upgrade",
})


@dataclass
class ParsedBurpRequest:
    method:        str                       # GET / POST / PUT / …
    url:           str                       # full reconstructed URL
    path:          str                       # path component only
    scheme:        str                       # http / https
    host:          str                       # host[:port]
    headers:       dict[str, str]            # all headers, lowercase keys
    cookie_header: str                       # raw Cookie: value (may be empty)
    body:          str                       # raw request body
    query_params:  dict[str, list[str]]      # parsed from URL ?query
    body_params:   dict[str, list[str]]      # parsed from body (form / JSON / multipart)
    content_type:  str
    # Headers safe to forward on every request (skip connection-management ones)
    safe_headers:  dict[str, str] = field(default_factory=dict)

    def all_param_names(self) -> list[str]:
        """Return unique parameter names from both URL and body."""
        seen: set[str] = set()
        out: list[str] = []
        for name in list(self.query_params) + list(self.body_params):
            if name not in seen:
                seen.add(name)
                out.append(name)
        return out

    def as_form_dict(self) -> dict:
        """
        Represent the Burp request as an AttackSurface-compatible form entry
        so scan modules (SQLi, XSS, CSRF, …) treat it as a discovered form.
        """
        all_params = {**self.query_params, **self.body_params}
        inputs = [
            {
                "name":  name,
                "type":  "password" if "pass" in name.lower() else "text",
                "value": vals[0] if vals else "",
            }
            for name, vals in all_params.items()
        ]
        return {
            "action":          self.path,
            "method":          self.method,
            "enctype":         "application/x-www-form-urlencoded",
            "inputs":          inputs,
            "resolved_action": self.url,
            "_source":         "burp_request",
        }


_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _infer_scheme(host: str) -> str:
    """
    Infer http or https from the Host header value.

    Rules (in priority order):
      1. Explicit port in Host header: :443 → https, :80 → http
      2. "localhost" or "127.*" → http
      3. Private-range IP (10.x, 172.16-31.x, 192.168.x) → http
      4. Everything else (public domain, no port) → https
    """
    # Strip brackets from IPv6, e.g. [::1]:8080
    hostname = host.strip("[]")
    port: int | None = None

    # Split off port
    if hostname.startswith("["):
        # IPv6 with port: [::1]:443
        bracket_end = hostname.find("]")
        if bracket_end != -1 and len(hostname) > bracket_end + 1 and hostname[bracket_end + 1] == ":":
            try:
                port = int(hostname[bracket_end + 2:])
            except ValueError:
                pass
        hostname = hostname[1:bracket_end] if bracket_end != -1 else hostname
    elif ":" in hostname:
        parts = hostname.rsplit(":", 1)
        hostname = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass

    if port == 443:
        return "https"
    if port == 80:
        return "http"

    lower = hostname.lower()
    if lower in ("localhost", "localhost.localdomain"):
        return "http"

    try:
        addr = ipaddress.ip_address(hostname)
        if any(addr in net for net in _PRIVATE_NETS):
            return "http"
        # Public IP with no port → assume https
        return "https"
    except ValueError:
        pass

    # Hostname (not an IP): check for common local suffixes
    if lower.endswith((".local", ".lan", ".internal", ".test", ".localhost")):
        return "http"

    # Public domain, no port clue → https
    return "https"


def parse_burp_request(
    path: str | Path,
    default_scheme: str | None = None,
) -> ParsedBurpRequest:
    """
    Parse a raw HTTP request file and return a :class:`ParsedBurpRequest`.

    Parameters
    ----------
    path:
        Path to the Burp-exported request file.
    default_scheme:
        Force a specific scheme (``"http"`` or ``"https"``).  When ``None``
        (the default) the scheme is inferred automatically: private/local IPs
        → ``http``; port 443 → ``https``; port 80 → ``http``; public domains
        with no port clue → ``https``.

    Raises
    ------
    ValueError
        If the file is empty or the request line cannot be parsed.
    """
    # Read as bytes so text-mode CR/LF conversion on Windows doesn't corrupt
    # the \r\n sequences before we can normalise them ourselves.
    raw = Path(path).read_bytes().decode("utf-8", errors="replace")

    # Normalise line endings (handles \r\n, bare \r, bare \n)
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")

    # Split header block and body at the first blank line
    if "\n\n" in raw:
        header_section, body = raw.split("\n\n", 1)
    else:
        header_section, body = raw, ""

    lines = header_section.strip().splitlines()
    if not lines:
        raise ValueError("Burp request file is empty")

    # ── Request line ──────────────────────────────────────────────────────
    req_line = lines[0].strip()
    parts = req_line.split(None, 2)
    if len(parts) < 2:
        raise ValueError(f"Cannot parse HTTP request line: {req_line!r}")

    method    = parts[0].upper()
    raw_path  = parts[1]

    # ── Headers ───────────────────────────────────────────────────────────
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        headers[key.strip().lower()] = val.strip()

    host = headers.get("host", "localhost")

    # ── Full URL reconstruction ───────────────────────────────────────────
    if raw_path.startswith(("http://", "https://")):
        url          = raw_path
        parsed_url   = urlparse(url)
        scheme       = parsed_url.scheme
        path_only    = parsed_url.path
        query_string = parsed_url.query
    else:
        # Infer scheme from Host header unless caller forced one
        scheme       = default_scheme if default_scheme else _infer_scheme(host)
        path_only    = raw_path.split("?")[0]
        query_string = raw_path.split("?")[1] if "?" in raw_path else ""
        url          = f"{scheme}://{host}{raw_path}"

    # ── Parameters ────────────────────────────────────────────────────────
    query_params = parse_qs(query_string, keep_blank_values=True)

    content_type = headers.get("content-type", "")
    body_params: dict[str, list[str]] = {}
    body = body.strip()

    if body:
        if "application/x-www-form-urlencoded" in content_type:
            body_params = parse_qs(body, keep_blank_values=True)

        elif "application/json" in content_type:
            try:
                parsed_json = json.loads(body)
                if isinstance(parsed_json, dict):
                    body_params = {k: [str(v)] for k, v in parsed_json.items()}
            except Exception:
                pass

        elif "multipart/form-data" in content_type:
            for match in re.finditer(r'name=["\']([^"\']+)["\']', body):
                body_params.setdefault(match.group(1), [""])

        else:
            # Last resort: try form-encoding even if content-type is missing
            try:
                candidate = parse_qs(body, keep_blank_values=True)
                if candidate:
                    body_params = candidate
            except Exception:
                pass

    cookie_header = headers.get("cookie", "")

    # Headers safe to forward on every engine request
    safe_headers = {
        k: v for k, v in headers.items()
        if k not in _SKIP_HEADERS and k != "cookie"
    }

    return ParsedBurpRequest(
        method        = method,
        url           = url,
        path          = path_only,
        scheme        = scheme,
        host          = host,
        headers       = headers,
        cookie_header = cookie_header,
        body          = body,
        query_params  = query_params,
        body_params   = body_params,
        content_type  = content_type,
        safe_headers  = safe_headers,
    )
