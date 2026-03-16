"""
VortexIntruder v1.0 â€“ Async Fuzzer Engine
Core engine using httpx.AsyncClient + asyncio.Semaphore.
Runs in a background QThread to avoid freezing the GUI.
"""
from __future__ import annotations

import asyncio
import csv
import json
import random
import re
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import httpx
from PyQt6.QtCore import QThread, pyqtSignal, QMutex, QWaitCondition

from engine.parser import (
    ParsedRequest,
    parse_raw_request,
    substitute_payload,
    update_content_length,
    detect_positions,
)
from engine.processor import PayloadProcessor, TransportEncoder


# ---------------------------------------------------------------------------
# Data classes for results
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Macro data classes
# ---------------------------------------------------------------------------

@dataclass
class MacroExtraction:
    """One extraction rule: pull a named value from a macro step's response."""
    source: str = "cookie"    # "cookie" | "header" | "body_regex"
    key: str = ""              # cookie name, header name, or regex pattern
    variable: str = ""         # name used as {{variable}} in later requests
    group: int = 1             # capture group index (body_regex only)


@dataclass
class MacroStep:
    """One HTTP request step in a macro sequence."""
    raw_request: str = ""
    extractions: list[MacroExtraction] = field(default_factory=list)


@dataclass
class MacroConfig:
    """A named macro: ordered steps + trigger rules."""
    name: str = "Macro"
    steps: list[MacroStep] = field(default_factory=list)
    run_before: bool = True          # execute once before attack starts
    rerun_on_response: str = ""      # re-run when fuzz response body contains this text
    rerun_every: int = 0             # re-run every N fuzz requests (0 = disabled)
    run_per_request: bool = False    # run before EACH fuzz request (independent session per request)


# ---------------------------------------------------------------------------
# Fuzz result / Attack config
# ---------------------------------------------------------------------------

@dataclass
class FuzzResult:
    request_id: int = 0
    payload: str = ""
    status_code: int = 0
    error: str = ""
    timed_out: bool = False
    length: int = 0
    elapsed_ms: float = 0.0
    grep_extract: str = ""
    grep_match: bool = False
    response_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    request_text: str = ""


@dataclass
class AttackConfig:
    raw_request: str = ""
    target_override: str = ""
    attack_type: str = "sniper"        # sniper, battering_ram, pitchfork, cluster_bomb
    concurrency: int = 10
    timeout: float = 10.0
    follow_redirects: bool = False
    update_content_length: bool = True
    proxy: str = ""
    connection_header: str = ""        # "", "close", "keep-alive"
    grep_match_strings: list[str] = field(default_factory=list)
    grep_exclude_strings: list[str] = field(default_factory=list)
    grep_extract_regex: str = ""
    verify_ssl: bool = False
    cookie_handling: str = "preserve"  # "preserve" or "update"
    start_index: int = 0
    # Throttling & interleave
    delay_ms: float = 0.0            # delay between each fuzz request (ms)
    jitter_ms: float = 0.0           # random Â±jitter added to delay (ms)
    interleave_enabled: bool = False  # send a safe request every N fuzz requests
    interleave_every: int = 3        # N â€” every how many fuzz requests
    interleave_request: str = ""     # raw HTTP text of the safe request
    interleave_follow_redirects: bool = True  # follow redirects for safe request
    auto_pause_errors: bool = False  # pause when N consecutive errors occur
    auto_pause_threshold: int = 5    # N consecutive errors before auto-pause
    macros: list[MacroConfig] = field(default_factory=list)
    # IP rotation
    auto_ip_rotate: bool = False
    ip_rotate_headers: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Fuzzer Engine Thread
# ---------------------------------------------------------------------------

class FuzzerEngine(QThread):
    """
    Runs the async fuzzing loop in a background thread.
    Communicates results back to the GUI via Qt signals.
    """
    result_ready = pyqtSignal(object)      # FuzzResult
    progress = pyqtSignal(int, int)        # current, total
    stats_update = pyqtSignal(float, float)  # rps, error_rate
    log_message = pyqtSignal(str)          # log text
    attack_finished = pyqtSignal()
    session_index = pyqtSignal(int)        # last processed index for resume

    def __init__(self) -> None:
        super().__init__()
        self.config = AttackConfig()
        self.processor = PayloadProcessor()
        self.transport_encoder = TransportEncoder()
        self.payload_iterator: Iterator[tuple[int, list[str]]] | None = None
        self.total_payloads: int = 0

        self._stop_flag = False
        self._pause_mutex = QMutex()
        self._pause_condition = QWaitCondition()
        self._paused = False
        self._macro_vars: dict[str, str] = {}

    # -- control methods (called from GUI thread) --

    def stop(self) -> None:
        self._stop_flag = True
        if self._paused:
            self.resume()

    def pause(self) -> None:
        self._paused = True

    def resume(self) -> None:
        self._paused = False
        self._pause_condition.wakeAll()

    @property
    def is_paused(self) -> bool:
        return self._paused

    # -- main thread entry --

    def run(self) -> None:
        self._stop_flag = False
        self._paused = False
        try:
            asyncio.run(self._run_attack())
        except Exception as e:
            self.log_message.emit(f"[FATAL] {e}")
        finally:
            self.attack_finished.emit()

    # -- async core --

    async def _run_attack(self) -> None:
        sem = asyncio.Semaphore(max(1, self.config.concurrency))

        proxy_url = self.config.proxy.strip() if self.config.proxy else None
        transport_kwargs: dict[str, Any] = {}
        if not self.config.verify_ssl:
            transport_kwargs["verify"] = False

        client_kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(self.config.timeout, connect=self.config.timeout),
            "follow_redirects": self.config.follow_redirects,
            "verify": self.config.verify_ssl,
            "http2": True,
        }
        if proxy_url:
            client_kwargs["proxy"] = proxy_url

        # Store for per-request macro isolation
        self._client_kwargs = client_kwargs

        request_counter = 0
        error_counter = 0
        consecutive_errors = 0
        start_time = time.monotonic()
        tasks: list[asyncio.Task] = []

        cookie_jar: dict[str, str] = {}

        async with httpx.AsyncClient(**client_kwargs) as client:
            if self.payload_iterator is None:
                self.log_message.emit("[ERROR] No payload iterator configured.")
                return

            # -- Run pre-attack macros --
            self._macro_vars = {}
            for macro in self.config.macros:
                if macro.run_before and macro.steps:
                    await self._run_macro(macro, client)

            idx = 0
            _macro_rerun_needed = False  # set when a response triggers macro rerun
            for pos_index, payload_list in self.payload_iterator:
                if self._stop_flag:
                    break

                # Pause handling
                if self._paused:
                    self._pause_mutex.lock()
                    self._pause_condition.wait(self._pause_mutex)
                    self._pause_mutex.unlock()
                    if self._stop_flag:
                        break

                # -- Handle macro rerun triggered by previous response --
                if _macro_rerun_needed:
                    if tasks:
                        remaining, _ = await asyncio.wait(tasks)
                        for t in remaining:
                            self.session_index.emit(idx)
                        tasks.clear()
                    for macro in self.config.macros:
                        if macro.rerun_on_response:
                            await self._run_macro(macro, client)
                    _macro_rerun_needed = False

                idx += 1
                if idx <= self.config.start_index:
                    continue

                request_counter += 1
                rid = request_counter

                # -- Macro rerun every N requests --
                for macro in self.config.macros:
                    if macro.rerun_every > 0 and request_counter % macro.rerun_every == 0:
                        if tasks:
                            remaining, _ = await asyncio.wait(tasks)
                            for t in remaining:
                                self.session_index.emit(idx)
                            tasks.clear()
                        await self._run_macro(macro, client)

                # -- Delay + Jitter --
                if self.config.delay_ms > 0 or self.config.jitter_ms > 0:
                    delay = self.config.delay_ms
                    if self.config.jitter_ms > 0:
                        delay += random.uniform(-self.config.jitter_ms, self.config.jitter_ms)
                    if delay > 0:
                        await asyncio.sleep(max(0, delay) / 1000.0)

                # -- Interleave safe request --
                if (self.config.interleave_enabled
                        and self.config.interleave_request
                        and request_counter % self.config.interleave_every == 0):
                    await self._send_safe_request(client, cookie_jar)

                # Process payloads through the pipeline
                processed = []
                for p in payload_list:
                    transformed = self.processor.process(p)
                    transformed = self.transport_encoder.encode(transformed)
                    processed.append(transformed)

                task = asyncio.create_task(
                    self._send_request(
                        client, sem, rid, pos_index, processed,
                        cookie_jar,
                    )
                )
                tasks.append(task)

                # Emit stats periodically
                if rid % 50 == 0:
                    elapsed = time.monotonic() - start_time
                    rps = rid / elapsed if elapsed > 0 else 0
                    err_rate = (error_counter / rid * 100) if rid > 0 else 0
                    self.stats_update.emit(rps, err_rate)
                    self.progress.emit(rid, self.total_payloads)

                # Throttle task creation to avoid memory buildup
                if len(tasks) >= self.config.concurrency * 2:
                    done, pending = await asyncio.wait(
                        tasks, return_when=asyncio.FIRST_COMPLETED
                    )
                    for t in done:
                        result = t.result()
                        has_error = bool(result and (result.error or result.timed_out
                                                     or (result.status_code >= 400)))
                        if has_error:
                            error_counter += 1
                            consecutive_errors += 1
                        else:
                            consecutive_errors = 0
                        # Auto-pause on consecutive errors
                        if (self.config.auto_pause_errors
                                and consecutive_errors >= self.config.auto_pause_threshold):
                            self._paused = True
                            consecutive_errors = 0
                            self.log_message.emit(
                                f"[WARN] Auto-paused after {self.config.auto_pause_threshold} "
                                f"consecutive errors. Resume when ready."
                            )
                        # Check macro rerun on response body match
                        if result and result.response_body:
                            for macro in self.config.macros:
                                if (macro.rerun_on_response
                                        and macro.rerun_on_response.lower()
                                        in result.response_body.lower()):
                                    _macro_rerun_needed = True
                        self.session_index.emit(idx)
                    tasks = list(pending)

            # Wait for remaining tasks
            if tasks:
                done, _ = await asyncio.wait(tasks)
                for t in done:
                    result = t.result()
                    if result and result.error:
                        error_counter += 1

            # Final stats
            elapsed = time.monotonic() - start_time
            rps = request_counter / elapsed if elapsed > 0 else 0
            err_rate = (error_counter / request_counter * 100) if request_counter > 0 else 0
            self.stats_update.emit(rps, err_rate)
            self.progress.emit(request_counter, self.total_payloads)
            self.session_index.emit(idx)
            self.log_message.emit(
                f"[DONE] {request_counter} requests in {elapsed:.2f}s "
                f"({rps:.1f} req/s, {err_rate:.1f}% errors)"
            )

    # -----------------------------------------------------------------------
    # Macro helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _apply_vars(text: str, variables: dict[str, str]) -> str:
        """Replace {{var_name}} placeholders with values from the given dict."""
        for var, val in variables.items():
            text = text.replace(f"{{{{{var}}}}}", val)
        return text

    def _apply_macro_vars(self, text: str) -> str:
        """Replace {{var_name}} placeholders with extracted macro values."""
        return self._apply_vars(text, self._macro_vars)

    async def _run_macro(
        self,
        macro: MacroConfig,
        client: httpx.AsyncClient,
        target_vars: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Execute all steps of a macro and extract variables.

        If *target_vars* is given, variables are written there (per-request mode).
        Otherwise they are written to the shared `self._macro_vars`.
        Returns the variables dict that was written to.
        """
        variables = target_vars if target_vars is not None else self._macro_vars
        self.log_message.emit(f"[MACRO] Running '{macro.name}'...")
        for i, step in enumerate(macro.steps):
            if not step.raw_request.strip():
                continue
            try:
                raw = self._apply_vars(step.raw_request, variables)
                parsed = parse_raw_request(raw, self.config.target_override)
                if self.config.update_content_length:
                    parsed.headers = update_content_length(parsed.headers, parsed.body)
                response = await client.request(
                    method=parsed.method,
                    url=parsed.url,
                    headers=parsed.headers,
                    content=parsed.body.encode("utf-8") if parsed.body else None,
                    follow_redirects=True,
                )
                self.log_message.emit(
                    f"[MACRO] '{macro.name}' step {i + 1} â†’ {response.status_code}"
                )
                for ext in step.extractions:
                    if not ext.key or not ext.variable:
                        continue
                    value = ""
                    if ext.source == "cookie":
                        # Collect Set-Cookie from redirect history + final response
                        all_set_cookies: list[str] = []
                        if response.history:
                            for hist_resp in response.history:
                                all_set_cookies.extend(
                                    hist_resp.headers.get_list("set-cookie")
                                )
                        all_set_cookies.extend(
                            response.headers.get_list("set-cookie")
                        )
                        for sc in all_set_cookies:
                            part = sc.split(";")[0].strip()
                            if "=" in part:
                                k, v = part.split("=", 1)
                                if k.strip() == ext.key:
                                    value = v.strip()
                    elif ext.source == "header":
                        value = response.headers.get(ext.key, "")
                    elif ext.source == "body_regex":
                        try:
                            m = re.search(ext.key, response.text)
                            if m:
                                grp = ext.group if m.lastindex and ext.group <= m.lastindex else 0
                                value = m.group(grp)
                        except re.error:
                            pass
                    if value:
                        variables[ext.variable] = value
                        self.log_message.emit(
                            f"[MACRO] Extracted {{{{{ext.variable}}}}} = {value[:60]}"
                        )
            except Exception as exc:
                self.log_message.emit(f"[MACRO] '{macro.name}' step {i + 1} failed: {exc}")
        return variables

    async def _send_safe_request(
        self,
        client: httpx.AsyncClient,
        cookie_jar: dict[str, str],
    ) -> None:
        """Send the interleave safe request and emit it as a result row."""
        result = FuzzResult(request_id=0, payload="[SAFE REQUEST]")
        try:
            parsed = parse_raw_request(
                self.config.interleave_request, self.config.target_override
            )
            if self.config.update_content_length:
                parsed.headers = update_content_length(parsed.headers, parsed.body)
            result.request_text = self.config.interleave_request
            t0 = time.monotonic()
            response = await client.request(
                method=parsed.method,
                url=parsed.url,
                headers=parsed.headers,
                content=parsed.body.encode("utf-8") if parsed.body else None,
                follow_redirects=self.config.interleave_follow_redirects,
            )
            result.elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
            result.status_code = response.status_code
            result.length = len(response.content)
            result.response_body = response.text
            result.response_headers = dict(response.headers)
            self.log_message.emit(
                f"[INTERLEAVE] Safe request sent â†’ {response.status_code}"
            )
        except Exception as exc:
            result.error = str(exc)
            self.log_message.emit(f"[INTERLEAVE] Safe request failed: {exc}")
        self.result_ready.emit(result)

    async def _do_fuzz_request(
        self,
        client: httpx.AsyncClient,
        rid: int,
        pos_index: int,
        payloads: list[str],
        cookie_jar: dict[str, str],
        per_req_vars: dict[str, str],
        result: FuzzResult,
    ) -> FuzzResult:
        """Build, send, and process a single fuzz request."""
        # Substitute payloads into the raw request
        if self.config.attack_type == "sniper":
            raw_filled = substitute_payload(
                self.config.raw_request, payloads,
                mode="sniper", position_index=pos_index,
            )
        elif self.config.attack_type == "battering_ram":
            raw_filled = substitute_payload(
                self.config.raw_request, payloads, mode="battering_ram",
            )
        else:
            raw_filled = substitute_payload(
                self.config.raw_request, payloads, mode="pitchfork",
            )

        # Apply macro variables (per-request first, then shared)
        if per_req_vars:
            raw_filled = self._apply_vars(raw_filled, per_req_vars)
        if self._macro_vars:
            raw_filled = self._apply_macro_vars(raw_filled)

        # Parse the filled request
        parsed = parse_raw_request(raw_filled, self.config.target_override)

        # Connection header override
        if self.config.connection_header:
            parsed.headers["Connection"] = self.config.connection_header

        # IP rotation headers
        if self.config.auto_ip_rotate and self.config.ip_rotate_headers:
            fake_ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            for hdr_name in self.config.ip_rotate_headers:
                parsed.headers[hdr_name] = fake_ip

        # Cookie handling
        if self.config.cookie_handling == "update" and cookie_jar:
            existing = parsed.headers.get("Cookie", "")
            for k, v in cookie_jar.items():
                if k not in existing:
                    existing += f"; {k}={v}" if existing else f"{k}={v}"
            parsed.headers["Cookie"] = existing

        # Update Content-Length
        if self.config.update_content_length:
            parsed.headers = update_content_length(parsed.headers, parsed.body)

        # Build final request text for display (includes injected headers)
        header_lines = f"{parsed.method} {parsed.path} HTTP/1.1"
        for hk, hv in parsed.headers.items():
            header_lines += f"\r\n{hk}: {hv}"
        if parsed.body:
            header_lines += f"\r\n\r\n{parsed.body}"
        result.request_text = header_lines

        # Send
        t0 = time.monotonic()
        response = await client.request(
            method=parsed.method,
            url=parsed.url,
            headers=parsed.headers,
            content=parsed.body.encode("utf-8") if parsed.body else None,
        )
        elapsed_ms = (time.monotonic() - t0) * 1000

        result.status_code = response.status_code
        result.length = len(response.content)
        result.elapsed_ms = round(elapsed_ms, 1)
        result.response_body = response.text
        result.response_headers = dict(response.headers)

        if response.status_code >= 400:
            result.error = f"HTTP {response.status_code}"

        # Update cookie jar
        if self.config.cookie_handling == "update":
            for cookie_header in response.headers.get_list("set-cookie"):
                if "=" in cookie_header:
                    part = cookie_header.split(";")[0]
                    k, v = part.split("=", 1)
                    cookie_jar[k.strip()] = v.strip()

        # Grep - Match
        if self.config.grep_match_strings:
            body_lower = response.text.lower()
            for gm in self.config.grep_match_strings:
                if gm.lower() in body_lower:
                    result.grep_match = True
                    break

        # Grep - Exclude
        if self.config.grep_exclude_strings:
            body_lower = response.text.lower()
            for ge in self.config.grep_exclude_strings:
                if ge.lower() in body_lower:
                    return result

        # Grep - Extract
        if self.config.grep_extract_regex:
            try:
                m = re.search(self.config.grep_extract_regex, response.text)
                if m:
                    result.grep_extract = m.group(1) if m.lastindex else m.group(0)
            except re.error:
                pass

        return result

    async def _send_request(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        rid: int,
        pos_index: int,
        payloads: list[str],
        cookie_jar: dict[str, str],
    ) -> FuzzResult:
        result = FuzzResult(request_id=rid, payload=", ".join(payloads))

        async with sem:
            if self._stop_flag:
                return result

            try:
                # -- Per-request macros: isolated client per task --
                per_req_vars: dict[str, str] = {}
                has_per_req = any(
                    m.run_per_request and m.steps for m in self.config.macros
                )
                if has_per_req:
                    async with httpx.AsyncClient(**self._client_kwargs) as iso_client:
                        for macro in self.config.macros:
                            if macro.run_per_request and macro.steps:
                                await self._run_macro(
                                    macro, iso_client, target_vars=per_req_vars
                                )
                        # Send the fuzz request through the isolated client too
                        result = await self._do_fuzz_request(
                            iso_client, rid, pos_index, payloads,
                            cookie_jar, per_req_vars, result,
                        )
                else:
                    result = await self._do_fuzz_request(
                        client, rid, pos_index, payloads,
                        cookie_jar, per_req_vars, result,
                    )

            except httpx.TimeoutException:
                result.timed_out = True
                result.error = "Timeout"
                self.log_message.emit(f"[TIMEOUT] Request #{rid}")

            except httpx.ConnectError as e:
                result.error = f"Connect: {e}"
                self.log_message.emit(f"[CONNECT ERROR] #{rid}: {e}")

            except ssl.SSLError as e:
                result.error = f"SSL: {e}"
                self.log_message.emit(f"[SSL ERROR] #{rid}: {e}")

            except httpx.HTTPError as e:
                result.error = str(e)
                self.log_message.emit(f"[HTTP ERROR] #{rid}: {e}")

            except Exception as e:
                result.error = str(e)
                self.log_message.emit(f"[ERROR] #{rid}: {e}")

            self.result_ready.emit(result)
            return result


# ---------------------------------------------------------------------------
# Export utilities
# ---------------------------------------------------------------------------

def export_results_csv(results: list[FuzzResult], filepath: str) -> None:
    """Export results to CSV file."""
    path = Path(filepath)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ID", "Payload", "Status", "Error", "Timeout",
            "Length", "Time (ms)", "Grep Extract", "Grep Match",
        ])
        for r in results:
            writer.writerow([
                r.request_id, r.payload, r.status_code, r.error,
                r.timed_out, r.length, r.elapsed_ms,
                r.grep_extract, r.grep_match,
            ])


def export_results_json(results: list[FuzzResult], filepath: str) -> None:
    """Export results to JSON file including request/response data."""
    path = Path(filepath)
    data = []
    for r in results:
        data.append({
            "id": r.request_id,
            "payload": r.payload,
            "status_code": r.status_code,
            "error": r.error,
            "timed_out": r.timed_out,
            "length": r.length,
            "elapsed_ms": r.elapsed_ms,
            "grep_extract": r.grep_extract,
            "grep_match": r.grep_match,
            "request": r.request_text,
            "response_body": r.response_body,
            "response_headers": r.response_headers,
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
