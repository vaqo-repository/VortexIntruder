"""
VortexIntruder v1.0 – Raw HTTP Request Parser
Parses raw HTTP text into method, URL, headers, and body.
Handles §marker§ placeholder detection and substitution.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


MARKER = "§"
MARKER_PATTERN = re.compile(r"§(.*?)§")


@dataclass
class ParsedRequest:
    method: str = "GET"
    path: str = "/"
    http_version: str = "HTTP/1.1"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    host: str = ""
    port: int = 443
    scheme: str = "https"

    @property
    def url(self) -> str:
        port_str = ""
        default = 443 if self.scheme == "https" else 80
        if self.port != default:
            port_str = f":{self.port}"
        return f"{self.scheme}://{self.host}{port_str}{self.path}"


def detect_positions(raw: str) -> list[str]:
    """Return list of marker-enclosed strings from the raw request."""
    return MARKER_PATTERN.findall(raw)


def add_markers(text: str, start: int, end: int) -> str:
    """Wrap text[start:end] with § markers."""
    return text[:start] + MARKER + text[start:end] + MARKER + text[end:]


def clear_markers(text: str) -> str:
    """Remove all § markers from text."""
    return text.replace(MARKER, "")


def substitute_payload(raw: str, payloads: list[str], mode: str = "sniper",
                        position_index: int = 0) -> str:
    """
    Replace §...§ markers with payloads according to attack mode.
    - sniper: replace one position at a time (position_index), others restored.
    - battering_ram: all positions get the same payload (payloads[0]).
    - pitchfork / cluster_bomb: each position gets its own payload from the list.
    """
    positions = list(MARKER_PATTERN.finditer(raw))
    if not positions:
        return raw

    result = raw
    # Process in reverse order to preserve offsets
    for i, match in reversed(list(enumerate(positions))):
        if mode == "sniper":
            replacement = payloads[0] if i == position_index else match.group(1)
        elif mode == "battering_ram":
            replacement = payloads[0]
        else:  # pitchfork / cluster_bomb
            replacement = payloads[i] if i < len(payloads) else match.group(1)
        result = result[:match.start()] + replacement + result[match.end():]

    return result


def parse_raw_request(raw: str, target_override: str = "") -> ParsedRequest:
    """
    Parse a raw HTTP request string into a ParsedRequest object.
    All § markers should already be substituted before calling this.
    """
    req = ParsedRequest()

    # Split headers and body
    if "\r\n\r\n" in raw:
        header_block, req.body = raw.split("\r\n\r\n", 1)
    elif "\n\n" in raw:
        header_block, req.body = raw.split("\n\n", 1)
    else:
        header_block = raw
        req.body = ""

    lines = header_block.replace("\r\n", "\n").split("\n")
    if not lines:
        return req

    # Parse request line
    request_line = lines[0].strip()
    parts = request_line.split(" ", 2)
    if len(parts) >= 2:
        req.method = parts[0].upper()
        req.path = parts[1]
    if len(parts) >= 3:
        req.http_version = parts[2]

    # Parse headers
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            req.headers[key.strip()] = value.strip()

    # Determine host/port/scheme
    if target_override:
        _apply_target(req, target_override)
    elif "Host" in req.headers:
        _apply_target(req, req.headers["Host"])

    return req


def _apply_target(req: ParsedRequest, host_str: str) -> None:
    """Parse host string and apply to request."""
    host_str = host_str.strip()
    if "://" in host_str:
        parsed = urlparse(host_str)
        req.scheme = parsed.scheme or "https"
        req.host = parsed.hostname or ""
        req.port = parsed.port or (443 if req.scheme == "https" else 80)
        if parsed.path and parsed.path != "/":
            req.path = parsed.path
    else:
        if ":" in host_str:
            h, p = host_str.rsplit(":", 1)
            req.host = h
            try:
                req.port = int(p)
            except ValueError:
                req.port = 443
        else:
            req.host = host_str
            req.port = 443
        req.scheme = "https" if req.port == 443 else "http"


def update_content_length(headers: dict[str, str], body: str) -> dict[str, str]:
    """Recalculate Content-Length based on actual body size."""
    updated = dict(headers)
    if body:
        updated["Content-Length"] = str(len(body.encode("utf-8", errors="replace")))
    elif "Content-Length" in updated:
        updated["Content-Length"] = "0"
    return updated


def guess_target_from_raw(raw: str) -> str:
    """Try to extract host from a raw request's Host header."""
    for line in raw.replace("\r\n", "\n").split("\n"):
        if line.lower().startswith("host:"):
            return line.split(":", 1)[1].strip()
    return ""
