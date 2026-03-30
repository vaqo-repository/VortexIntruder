"""
VortexIntruder MCP Server
Exposes VortexIntruder's HTTP fuzzing capabilities to VS Code Copilot agent
via the Model Context Protocol (MCP) over stdio transport.

Usage (VS Code connects automatically via .vscode/mcp.json):
    python mcp_server.py
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import sys
import urllib.parse
from pathlib import Path
from typing import Any

import httpx

# Project root on sys.path so engine.* imports work
sys.path.insert(0, str(Path(__file__).parent))

import random as _random

from engine.parser import (
    detect_positions,
    parse_raw_request,
    substitute_payload,
    update_content_length,
)

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("VortexIntruder")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _random_ip() -> str:
    return ".".join(str(_random.randint(1, 254)) for _ in range(4))


async def _do_send(
    raw_request: str,
    target_override: str = "",
    proxy: str = "",
    verify_ssl: bool = False,
    follow_redirects: bool = False,
    timeout: float = 15.0,
    spoof_ip: str = "",
) -> dict[str, Any]:
    """Core async HTTP sender — returns a response dict."""
    parsed = parse_raw_request(raw_request, target_override)

    # Fix Content-Length after payload substitution may have changed body size
    parsed.headers = update_content_length(parsed.headers, parsed.body)

    # IP spoofing headers
    if spoof_ip:
        ip = _random_ip() if spoof_ip.lower() == "random" else spoof_ip
        parsed.headers["X-Forwarded-For"] = ip
        parsed.headers["X-Real-IP"] = ip
        parsed.headers["X-Originating-IP"] = ip
        parsed.headers["X-Remote-IP"] = ip
        parsed.headers["X-Client-IP"] = ip
        parsed.headers["Forwarded"] = f"for={ip}"

    client_kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(timeout, connect=timeout),
        "follow_redirects": follow_redirects,
        "verify": verify_ssl,
        "http2": False,
    }
    if proxy.strip():
        client_kwargs["proxies"] = proxy.strip()

    async with httpx.AsyncClient(**client_kwargs) as client:
        t0 = asyncio.get_event_loop().time()
        resp = await client.request(
            method=parsed.method,
            url=parsed.url,
            headers=dict(parsed.headers),
            content=parsed.body.encode() if parsed.body else None,
        )
        elapsed_ms = (asyncio.get_event_loop().time() - t0) * 1000

    body_text = resp.text
    return {
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "body": body_text,
        "length": len(resp.content),
        "elapsed_ms": round(elapsed_ms, 2),
        "url": str(resp.url),
    }


def _format_response(r: dict[str, Any]) -> str:
    """Pretty-format a response dict for agent consumption."""
    header_lines = "\n".join(f"  {k}: {v}" for k, v in r["headers"].items())
    return (
        f"HTTP {r['status_code']}  |  {r['length']} bytes  |  {r['elapsed_ms']} ms\n"
        f"URL: {r['url']}\n"
        f"─── Response Headers ───\n{header_lines}\n"
        f"─── Response Body ───\n{r['body']}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tool 1 — Send a raw HTTP request
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
async def send_request(
    raw_request: str,
    target_override: str = "",
    proxy: str = "",
    verify_ssl: bool = False,
    follow_redirects: bool = False,
    timeout: float = 15.0,
    spoof_ip: str = "",
) -> str:
    """
    Send a single raw HTTP request and return the full response.

    Args:
        raw_request: Complete raw HTTP request text.
                     Example:
                       GET /filter?category=Gifts HTTP/1.1
                       Host: example.web-security-academy.net
                       Cookie: session=abc123

        target_override: Optional base URL to override the Host header
                         (e.g. "https://0ad9.web-security-academy.net").
        proxy: Optional proxy URL, e.g. "http://127.0.0.1:8080".
        verify_ssl: Verify TLS certificates (default False).
        follow_redirects: Follow HTTP redirects (default False).
        timeout: Request timeout seconds (default 15).

    Returns:
        Formatted string with status code, headers, body, and timing.
    """
    try:
        result = await _do_send(
            raw_request=raw_request,
            target_override=target_override,
            proxy=proxy,
            verify_ssl=verify_ssl,
            follow_redirects=follow_redirects,
            timeout=timeout,
            spoof_ip=spoof_ip,
        )
        return _format_response(result)
    except Exception as exc:
        return f"ERROR: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# Tool 2 — Send a request with a payload substituted at § markers
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
async def send_request_with_payload(
    raw_request: str,
    payload: str,
    target_override: str = "",
    proxy: str = "",
    verify_ssl: bool = False,
    follow_redirects: bool = False,
    timeout: float = 15.0,
    spoof_ip: str = "",
) -> str:
    """
    Substitute a single payload into all § markers of the raw request, then send it.

    Use this for iterative SQL injection / fuzzing — mark the injection point with
    §...§ in the raw request and pass each payload one at a time.

    Args:
        raw_request: Raw HTTP request with § injection markers, e.g.:
                       GET /filter?category=§Gifts§ HTTP/1.1
                       Host: example.web-security-academy.net
        payload: The string to substitute at every § marker position.
        target_override: Optional base URL override.
        proxy: Optional proxy URL.
        verify_ssl: Verify TLS certificates.
        follow_redirects: Follow redirects.
        timeout: Timeout seconds.

    Returns:
        Formatted response string.
    """
    try:
        substituted = substitute_payload(raw_request, [payload], mode="battering_ram")
        result = await _do_send(
            raw_request=substituted,
            target_override=target_override,
            proxy=proxy,
            verify_ssl=verify_ssl,
            follow_redirects=follow_redirects,
            timeout=timeout,
            spoof_ip=spoof_ip,
        )
        return _format_response(result)
    except Exception as exc:
        return f"ERROR: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# Tool 3 — Batch fuzz: send multiple payloads concurrently
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
async def batch_fuzz(
    raw_request: str,
    payloads: list[str],
    target_override: str = "",
    proxy: str = "",
    verify_ssl: bool = False,
    follow_redirects: bool = False,
    timeout: float = 15.0,
    concurrency: int = 5,
    spoof_ip: str = "",
) -> str:
    """
    Send multiple payloads against §-marked positions and return a summary table.

    Ideal for testing multiple SQL injection strings, wordlists, or UNION probes
    in one call. Results are returned sorted by payload order.

    Args:
        raw_request: Raw HTTP request containing § markers.
        payloads: List of payload strings to test.
        target_override: Optional base URL override.
        proxy: Optional proxy URL.
        verify_ssl: Verify TLS.
        follow_redirects: Follow redirects.
        timeout: Per-request timeout seconds.
        concurrency: Maximum simultaneous requests (default 5).

    Returns:
        A table of: payload | status | length | time_ms | short body excerpt.
    """
    sem = asyncio.Semaphore(concurrency)

    async def _one(idx: int, pld: str) -> dict[str, Any]:
        async with sem:
            try:
                subst = substitute_payload(raw_request, [pld], mode="battering_ram")
                # Use fresh random IP per request when spoof_ip="random"
                per_req_ip = _random_ip() if spoof_ip.lower() == "random" else spoof_ip
                r = await _do_send(
                    raw_request=subst,
                    target_override=target_override,
                    proxy=proxy,
                    verify_ssl=verify_ssl,
                    follow_redirects=follow_redirects,
                    timeout=timeout,
                    spoof_ip=per_req_ip,
                )
                return {"idx": idx, "payload": pld, **r, "error": ""}
            except Exception as exc:
                return {
                    "idx": idx, "payload": pld,
                    "status_code": 0, "length": 0,
                    "elapsed_ms": 0, "body": "", "error": str(exc),
                }

    tasks = [_one(i, p) for i, p in enumerate(payloads)]
    results = await asyncio.gather(*tasks)
    results.sort(key=lambda x: x["idx"])

    lines = ["#   | Status | Length  | ms       | Payload"]
    lines.append("─" * 70)
    for r in results:
        excerpt = r["body"][:60].replace("\n", " ") if not r["error"] else r["error"]
        lines.append(
            f"{r['idx']:3d} | {r['status_code']:6d} | {r['length']:7d} | "
            f"{r['elapsed_ms']:8.1f} | {r['payload']!r:30s} | {excerpt}"
        )
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Tool 4 — Parse a raw HTTP request
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def parse_request(raw_request: str) -> str:
    """
    Parse a raw HTTP request string and return its components as JSON.

    Useful for inspecting method, URL, headers, body of a captured request
    before crafting injection payloads.

    Args:
        raw_request: Raw HTTP request text.

    Returns:
        JSON string with keys: method, url, host, port, scheme, path, headers, body.
    """
    try:
        parsed = parse_raw_request(raw_request)
        return json.dumps({
            "method": parsed.method,
            "url": parsed.url,
            "host": parsed.host,
            "port": parsed.port,
            "scheme": parsed.scheme,
            "path": parsed.path,
            "headers": parsed.headers,
            "body": parsed.body,
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ─────────────────────────────────────────────────────────────────────────────
# Tool 5 — Detect § injection positions in a request
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def detect_injection_points(raw_request: str) -> str:
    """
    Find all § marker positions in a raw HTTP request.

    Returns the list of text segments currently enclosed by § markers,
    showing where payloads will be injected.

    Args:
        raw_request: Raw HTTP request text (may contain §...§ markers).

    Returns:
        JSON list of current placeholder values at each injection point.
    """
    positions = detect_positions(raw_request)
    return json.dumps(positions, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Tool 6 — Encode / decode text
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def encode_decode(text: str, operation: str) -> str:
    """
    Encode or decode a string using common web security encodings.

    Args:
        text: The input string to transform.
        operation: One of:
            url_encode        — URL-encode all characters
            url_encode_safe   — URL-encode only special characters (% & = + space ...)
            url_decode        — URL-decode
            base64_encode     — Base64 encode
            base64_decode     — Base64 decode
            html_encode       — HTML entity encode (& < > " ')
            html_decode       — HTML entity decode
            hex_encode        — Hex encode (UTF-8 bytes → hex string)
            hex_decode        — Hex string → UTF-8 text
            md5               — MD5 hash (hex)
            sha1              — SHA-1 hash (hex)
            sha256            — SHA-256 hash (hex)

    Returns:
        The transformed string, or an error message.
    """
    import html as _html
    op = operation.lower().strip()
    try:
        if op == "url_encode":
            return urllib.parse.quote(text, safe="")
        elif op == "url_encode_safe":
            return urllib.parse.quote(text, safe="/:@!$'()*,;")
        elif op == "url_decode":
            return urllib.parse.unquote(text)
        elif op == "base64_encode":
            return base64.b64encode(text.encode()).decode()
        elif op == "base64_decode":
            return base64.b64decode(text.encode()).decode(errors="replace")
        elif op == "html_encode":
            return _html.escape(text, quote=True)
        elif op == "html_decode":
            return _html.unescape(text)
        elif op == "hex_encode":
            return text.encode("utf-8").hex()
        elif op == "hex_decode":
            return bytes.fromhex(text).decode("utf-8", errors="replace")
        elif op == "md5":
            return hashlib.md5(text.encode()).hexdigest()
        elif op == "sha1":
            return hashlib.sha1(text.encode()).hexdigest()
        elif op == "sha256":
            return hashlib.sha256(text.encode()).hexdigest()
        else:
            return f"Unknown operation '{operation}'. See tool description for valid operations."
    except Exception as exc:
        return f"ERROR: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# Tool 7 — Build a UNION SQL injection probe (Oracle helper)
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def build_sqli_union_probe(
    columns: int,
    text_column_index: int = 0,
    payload: str = "'abc'",
    table: str = "dual",
    comment: str = "--",
) -> str:
    """
    Generate a UNION SELECT probe string for SQL injection testing.

    Automatically builds the correct column count with NULL fillers and places
    a test string in the specified column. Includes Oracle dual table support.

    Args:
        columns: Total number of columns in the original query.
        text_column_index: Zero-based index of the string-type column (default 0).
        payload: SQL value to inject into text_column_index (default "'abc'").
        table: FROM table for Oracle (default "dual"; omit for MySQL/MSSQL using "").
        comment: SQL comment sequence (default "--"; use "#" for MySQL).

    Returns:
        Ready-to-use UNION SELECT string, e.g.:
          ' UNION SELECT NULL,'abc',NULL FROM dual--
    """
    cols = []
    for i in range(columns):
        cols.append(payload if i == text_column_index else "NULL")
    col_str = ",".join(cols)
    from_clause = f" FROM {table}" if table.strip() else ""
    return f"' UNION SELECT {col_str}{from_clause}{comment}"


# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")
