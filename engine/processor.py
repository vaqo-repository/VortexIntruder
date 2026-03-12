"""
VortexIntruder v1.0 – Payload Processor Pipeline
Middleware between payload generators and the async engine.
Applies a stack of transformation rules to each payload in order.
"""
from __future__ import annotations

import base64
import hashlib
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RuleType(Enum):
    PREFIX = "Add Prefix"
    SUFFIX = "Add Suffix"
    MATCH_REPLACE = "Match & Replace"
    UPPERCASE = "Upper Case"
    LOWERCASE = "Lower Case"
    PROPERCASE = "Proper Case"
    TOGGLECASE = "Toggle Case"
    URL_ENCODE_KEY = "URL Encode (Key Chars)"
    URL_ENCODE_ALL = "URL Encode (All)"
    BASE64_ENCODE = "Base64 Encode"
    BASE64_ENCODE_NOPAD = "Base64 Encode (No Padding)"
    HEX_ENCODE = "Hex Encode"
    UNICODE_ESCAPE = "Unicode Escape"
    MD5 = "MD5 Hash"
    SHA1 = "SHA-1 Hash"
    SHA256 = "SHA-256 Hash"
    SHA512 = "SHA-512 Hash"
    NUMBER_PAD = "Number Padding"
    NUMBER_HEX = "Number to Hex"


ALL_RULE_TYPES = [r for r in RuleType]

# Characters typically URL-encoded in payloads
URL_KEY_CHARS = set("&=+#%/ ;?@")


@dataclass
class ProcessingRule:
    rule_type: RuleType
    param1: str = ""   # e.g., prefix string, regex pattern, pad width
    param2: str = ""   # e.g., suffix string, replacement string

    def __str__(self) -> str:
        if self.rule_type in (RuleType.PREFIX, RuleType.SUFFIX):
            return f"{self.rule_type.value}: \"{self.param1}\""
        if self.rule_type == RuleType.MATCH_REPLACE:
            return f"{self.rule_type.value}: /{self.param1}/ → \"{self.param2}\""
        if self.rule_type == RuleType.NUMBER_PAD:
            return f"{self.rule_type.value}: width={self.param1}"
        return self.rule_type.value


@dataclass
class PayloadProcessor:
    """
    Applies an ordered stack of processing rules to each payload string.
    Acts as middleware between the WordlistGenerator and the AsyncEngine.
    """
    rules: list[ProcessingRule] = field(default_factory=list)

    def add_rule(self, rule: ProcessingRule) -> None:
        self.rules.append(rule)

    def remove_rule(self, index: int) -> None:
        if 0 <= index < len(self.rules):
            self.rules.pop(index)

    def move_rule(self, from_idx: int, to_idx: int) -> None:
        if 0 <= from_idx < len(self.rules) and 0 <= to_idx < len(self.rules):
            rule = self.rules.pop(from_idx)
            self.rules.insert(to_idx, rule)

    def clear_rules(self) -> None:
        self.rules.clear()

    def process(self, payload: str) -> str:
        """Apply all rules sequentially to a single payload."""
        result = payload
        for rule in self.rules:
            result = _apply_rule(result, rule)
        return result


def _apply_rule(payload: str, rule: ProcessingRule) -> str:
    """Apply a single processing rule to a payload string."""
    rt = rule.rule_type

    if rt == RuleType.PREFIX:
        return rule.param1 + payload

    if rt == RuleType.SUFFIX:
        return payload + rule.param1

    if rt == RuleType.MATCH_REPLACE:
        try:
            return re.sub(rule.param1, rule.param2, payload)
        except re.error:
            return payload

    if rt == RuleType.UPPERCASE:
        return payload.upper()

    if rt == RuleType.LOWERCASE:
        return payload.lower()

    if rt == RuleType.PROPERCASE:
        return payload.title()

    if rt == RuleType.TOGGLECASE:
        return payload.swapcase()

    if rt == RuleType.URL_ENCODE_KEY:
        return "".join(
            urllib.parse.quote(ch, safe="") if ch in URL_KEY_CHARS else ch
            for ch in payload
        )

    if rt == RuleType.URL_ENCODE_ALL:
        return urllib.parse.quote(payload, safe="")

    if rt == RuleType.BASE64_ENCODE:
        return base64.b64encode(payload.encode("utf-8")).decode("ascii")

    if rt == RuleType.BASE64_ENCODE_NOPAD:
        encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        return encoded.rstrip("=")

    if rt == RuleType.HEX_ENCODE:
        return payload.encode("utf-8").hex()

    if rt == RuleType.UNICODE_ESCAPE:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    if rt == RuleType.MD5:
        return hashlib.md5(payload.encode("utf-8")).hexdigest()

    if rt == RuleType.SHA1:
        return hashlib.sha1(payload.encode("utf-8")).hexdigest()

    if rt == RuleType.SHA256:
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    if rt == RuleType.SHA512:
        return hashlib.sha512(payload.encode("utf-8")).hexdigest()

    if rt == RuleType.NUMBER_PAD:
        try:
            width = int(rule.param1)
            return payload.zfill(width)
        except ValueError:
            return payload

    if rt == RuleType.NUMBER_HEX:
        try:
            return hex(int(payload))[2:]
        except ValueError:
            return payload

    return payload


# ---------------------------------------------------------------------------
# Transport encoding – applied AFTER processor pipeline, at injection time
# ---------------------------------------------------------------------------

@dataclass
class TransportEncoder:
    """
    Final URL-encoding of specific characters in the payload
    right before it's placed into the request template.
    """
    chars_to_encode: set[str] = field(default_factory=lambda: set())

    def encode(self, payload: str) -> str:
        if not self.chars_to_encode:
            return payload
        return "".join(
            urllib.parse.quote(ch, safe="") if ch in self.chars_to_encode else ch
            for ch in payload
        )
