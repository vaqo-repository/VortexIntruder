"""
VortexIntruder v1.0 – Async Fuzzer Engine
Core engine using httpx.AsyncClient + asyncio.Semaphore.
Runs in a background QThread to avoid freezing the GUI.
"""
from __future__ import annotations

import asyncio
import csv
import json
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

        request_counter = 0
        error_counter = 0
        start_time = time.monotonic()
        tasks: list[asyncio.Task] = []

        cookie_jar: dict[str, str] = {}

        async with httpx.AsyncClient(**client_kwargs) as client:
            if self.payload_iterator is None:
                self.log_message.emit("[ERROR] No payload iterator configured.")
                return

            idx = 0
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

                idx += 1
                if idx <= self.config.start_index:
                    continue

                request_counter += 1
                rid = request_counter

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
                        if result and result.error:
                            error_counter += 1
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

                # Parse the filled request
                parsed = parse_raw_request(raw_filled, self.config.target_override)
                result.request_text = raw_filled

                # Connection header override
                if self.config.connection_header:
                    parsed.headers["Connection"] = self.config.connection_header

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

                # Build httpx request
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

                # Flag non-2xx status as error info
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
                            return result  # exclude from results

                # Grep - Extract
                if self.config.grep_extract_regex:
                    try:
                        m = re.search(self.config.grep_extract_regex, response.text)
                        if m:
                            result.grep_extract = m.group(1) if m.lastindex else m.group(0)
                    except re.error:
                        pass

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
