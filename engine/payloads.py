"""
VortexIntruder v1.0 – Payload Generators
Memory-efficient generators for all payload types.
Supports wordlist streaming, numeric ranges, brute-force character sets, and null payloads.
"""
from __future__ import annotations

import itertools
import random
import string
from pathlib import Path
from typing import Generator, Iterator


def wordlist_generator(filepath: str, start_index: int = 0) -> Generator[str, None, None]:
    """
    Stream a wordlist file line-by-line using yield.
    Handles files >5GB without loading into RAM.
    Supports resume via start_index.
    """
    path = Path(filepath)
    if not path.is_file():
        return
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f):
            if idx < start_index:
                continue
            stripped = line.rstrip("\n\r")
            if stripped:
                yield stripped


def manual_list_generator(items: list[str]) -> Generator[str, None, None]:
    """Yield items from a manually entered list."""
    for item in items:
        stripped = item.strip()
        if stripped:
            yield stripped


def number_range_generator(
    start: float, end: float, step: float = 1,
    min_int_digits: int = 0, max_int_digits: int = 0,
    min_frac_digits: int = 0, max_frac_digits: int = 0,
    base: int = 10, use_random: bool = False,
) -> Generator[str, None, None]:
    """
    Generate numeric payloads with full Burp-style formatting.

    Args:
        start/end/step: Numeric range.
        min_int_digits: Minimum integer digits (zero-padded, e.g. 1 → 001).
        max_int_digits: Maximum integer digits (truncated from left if exceeded).
        min_frac_digits: Minimum fraction digits (e.g. 1.5 → 1.50).
        max_frac_digits: Maximum fraction digits (rounded if exceeded).
        base: 10 for decimal, 16 for hex.
        use_random: If True, yield random numbers within range instead of sequential.
    """
    if step == 0:
        step = 1
    is_float = (step != int(step)) or min_frac_digits > 0 or max_frac_digits > 0

    if use_random:
        count = int(abs(end - start) / abs(step)) + 1 if step else 1
        for _ in range(count):
            if is_float:
                val = random.uniform(min(start, end), max(start, end))
            else:
                val = random.randint(int(min(start, end)), int(max(start, end)))
            yield _format_number(val, base, min_int_digits, max_int_digits,
                                 min_frac_digits, max_frac_digits, is_float)
        return

    current = start
    while (step > 0 and current <= end) or (step < 0 and current >= end):
        yield _format_number(current, base, min_int_digits, max_int_digits,
                             min_frac_digits, max_frac_digits, is_float)
        current += step
        current = round(current, 10)  # avoid float drift


def _format_number(
    value: float, base: int,
    min_int_digits: int, max_int_digits: int,
    min_frac_digits: int, max_frac_digits: int,
    is_float: bool,
) -> str:
    """Format a number with Burp-style digit controls."""
    if base == 16:
        int_val = int(value)
        hex_str = hex(int_val)[2:]
        if min_int_digits > 0:
            hex_str = hex_str.zfill(min_int_digits)
        if max_int_digits > 0 and len(hex_str) > max_int_digits:
            hex_str = hex_str[-max_int_digits:]
        return hex_str

    if is_float:
        # Round to max_frac_digits
        frac_d = max_frac_digits if max_frac_digits > 0 else 2
        rounded = round(value, frac_d)
        int_part, frac_part = f"{rounded:.{frac_d}f}".split(".")

        # Min fraction digits — pad right
        if min_frac_digits > 0 and len(frac_part) < min_frac_digits:
            frac_part = frac_part.ljust(min_frac_digits, "0")

        # Trim trailing zeros down to min_frac_digits
        if min_frac_digits == 0 and max_frac_digits > 0:
            frac_part = frac_part.rstrip("0") or "0"
        elif len(frac_part) > min_frac_digits:
            trimmed = frac_part.rstrip("0")
            if len(trimmed) < min_frac_digits:
                frac_part = frac_part[:min_frac_digits]
            else:
                frac_part = trimmed
    else:
        int_part = str(int(value))
        frac_part = ""

    # Handle negative sign for int padding
    negative = int_part.startswith("-")
    if negative:
        int_part = int_part[1:]

    # Min integer digits — zero-pad
    if min_int_digits > 0 and len(int_part) < min_int_digits:
        int_part = int_part.zfill(min_int_digits)

    # Max integer digits — truncate from left
    if max_int_digits > 0 and len(int_part) > max_int_digits:
        int_part = int_part[-max_int_digits:]

    result = ("-" if negative else "") + int_part
    if frac_part:
        result += "." + frac_part
    return result


def bruteforce_generator(charset: str, min_length: int, max_length: int) -> Generator[str, None, None]:
    """
    Generate all combinations of charset from min_length to max_length.
    Uses itertools.product for efficiency.
    """
    if not charset:
        charset = string.ascii_lowercase
    for length in range(min_length, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


def null_payload_generator(count: int) -> Generator[str, None, None]:
    """Generate empty string payloads for null-payload attacks."""
    for _ in range(count):
        yield ""


# ---------------------------------------------------------------------------
# Payload modifiers (applied before attack starts to the full generator)
# ---------------------------------------------------------------------------

def shuffle_payloads(gen: Iterator[str]) -> list[str]:
    """Materialize and shuffle payloads. Use only for manageable sizes."""
    items = list(gen)
    random.shuffle(items)
    return items


def deduplicate_payloads(gen: Iterator[str]) -> Generator[str, None, None]:
    """Remove duplicates while preserving order."""
    seen: set[str] = set()
    for item in gen:
        if item not in seen:
            seen.add(item)
            yield item


def filter_by_length(gen: Iterator[str], min_len: int = 0,
                     max_len: int = 999999) -> Generator[str, None, None]:
    """Filter payloads by string length."""
    for item in gen:
        if min_len <= len(item) <= max_len:
            yield item


# ---------------------------------------------------------------------------
# Attack-type iterators
# ---------------------------------------------------------------------------

def sniper_iterator(payloads: Iterator[str], num_positions: int) -> Generator[tuple[int, list[str]], None, None]:
    """
    Sniper: one payload set, one position at a time.
    Yields (position_index, [payload]) for each position and each payload.
    """
    payload_list = list(payloads)
    for pos_idx in range(num_positions):
        for payload in payload_list:
            yield pos_idx, [payload]


def battering_ram_iterator(payloads: Iterator[str]) -> Generator[tuple[int, list[str]], None, None]:
    """
    Battering Ram: same payload in all positions.
    Yields (-1, [payload]) — the -1 signals all positions.
    """
    for payload in payloads:
        yield -1, [payload]


def pitchfork_iterator(*payload_sets: Iterator[str]) -> Generator[tuple[int, list[str]], None, None]:
    """
    Pitchfork: multiple sets iterate in lockstep.
    Yields (-1, [p1, p2, ...]) for each row.
    """
    for combo in zip(*payload_sets):
        yield -1, list(combo)


def cluster_bomb_iterator(*payload_sets: Iterator[str]) -> Generator[tuple[int, list[str]], None, None]:
    """
    Cluster Bomb: Cartesian product of all payload sets.
    Yields (-1, [p1, p2, ...]) for each combination.
    """
    materialized = [list(ps) for ps in payload_sets]
    for combo in itertools.product(*materialized):
        yield -1, list(combo)
