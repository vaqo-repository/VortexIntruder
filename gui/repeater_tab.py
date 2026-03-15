"""
VortexIntruder – Repeater Tab
Multi-tab HTTP request repeater with encoding/decoding, response analysis,
race-condition (last-byte sync), and Send to Intruder functionality.
"""
from __future__ import annotations

import asyncio
import re
import ssl
import time
import html
import base64
import hashlib
import json
from functools import partial
from typing import Any
from urllib.parse import quote, unquote, quote_plus, unquote_plus

import httpx
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QAction, QColor, QFont, QSyntaxHighlighter, QTextCharFormat, QTextDocument
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabBar,
    QTabWidget,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from engine.parser import parse_raw_request, guess_target_from_raw, update_content_length


# ---------------------------------------------------------------------------
# Syntax Highlighters
# ---------------------------------------------------------------------------

class _ReqHighlighter(QSyntaxHighlighter):
    """Highlight HTTP request: method, path, headers."""

    def __init__(self, document: QTextDocument) -> None:
        super().__init__(document)
        self._method = QTextCharFormat()
        self._method.setForeground(QColor("#e94560"))
        self._method.setFontWeight(QFont.Weight.Bold)
        self._url = QTextCharFormat()
        self._url.setForeground(QColor("#f1c40f"))
        self._header_name = QTextCharFormat()
        self._header_name.setForeground(QColor("#4ecca3"))

    def highlightBlock(self, text: str) -> None:
        m = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\b", text, re.I)
        if m:
            self.setFormat(m.start(), m.end() - m.start(), self._method)
        m = re.match(r"^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)", text, re.I)
        if m:
            self.setFormat(m.start(1), m.end(1) - m.start(1), self._url)
        m = re.match(r"^([A-Za-z][\w-]*):", text)
        if m:
            self.setFormat(m.start(1), m.end(1) - m.start(1), self._header_name)


class _RespHighlighter(QSyntaxHighlighter):
    """Highlight HTTP response: status line, header names."""

    def __init__(self, document: QTextDocument) -> None:
        super().__init__(document)
        self._status = QTextCharFormat()
        self._status.setFontWeight(QFont.Weight.Bold)
        self._header_name = QTextCharFormat()
        self._header_name.setForeground(QColor("#4ecca3"))
        self._ok = QTextCharFormat()
        self._ok.setForeground(QColor("#4ecca3"))
        self._redirect = QTextCharFormat()
        self._redirect.setForeground(QColor("#f1c40f"))
        self._err = QTextCharFormat()
        self._err.setForeground(QColor("#e94560"))

    def highlightBlock(self, text: str) -> None:
        m = re.match(r"^HTTP/[\d.]+ (\d{3})", text)
        if m:
            code = int(m.group(1))
            fmt = self._ok if code < 300 else (self._redirect if code < 400 else self._err)
            self.setFormat(0, len(text), fmt)
            return
        m = re.match(r"^([A-Za-z][\w-]*):", text)
        if m:
            self.setFormat(m.start(1), m.end(1) - m.start(1), self._header_name)


# ---------------------------------------------------------------------------
# Async sender worker
# ---------------------------------------------------------------------------

class _SenderWorker(QThread):
    """Send one or multiple HTTP requests in a background thread."""
    finished = pyqtSignal(list)  # list of (status_line, headers_text, body, elapsed_ms, error)
    log = pyqtSignal(str)

    def __init__(self, requests: list[dict], parent=None) -> None:
        super().__init__(parent)
        self.requests = requests  # list of {raw, target, follow, verify_ssl, timeout, proxy, update_cl}

    def run(self) -> None:
        results = asyncio.run(self._send_all())
        self.finished.emit(results)

    async def _send_all(self) -> list[dict]:
        results = []
        for req in self.requests:
            results.append(await self._send_one(req))
        return results

    async def _send_one(self, req: dict) -> dict:
        raw = req["raw"]
        target = req.get("target", "")
        follow = req.get("follow_redirects", True)
        verify = req.get("verify_ssl", False)
        timeout_s = req.get("timeout", 10.0)
        proxy = req.get("proxy", "")
        update_cl = req.get("update_cl", True)

        kw: dict[str, Any] = {
            "timeout": httpx.Timeout(timeout_s, connect=timeout_s),
            "follow_redirects": follow,
            "verify": verify,
            "http2": True,
        }
        if proxy:
            kw["proxy"] = proxy

        try:
            parsed = parse_raw_request(raw, target)
            if update_cl:
                parsed.headers = update_content_length(parsed.headers, parsed.body)

            async with httpx.AsyncClient(**kw) as client:
                t0 = time.monotonic()
                response = await client.request(
                    method=parsed.method,
                    url=parsed.url,
                    headers=parsed.headers,
                    content=parsed.body.encode("utf-8") if parsed.body else None,
                )
                elapsed = round((time.monotonic() - t0) * 1000, 1)

            status_line = f"HTTP/{response.http_version} {response.status_code} {response.reason_phrase or ''}"
            hdrs = "\r\n".join(f"{k}: {v}" for k, v in response.headers.items())
            return {
                "status_line": status_line,
                "headers": hdrs,
                "body": response.text,
                "raw_bytes": len(response.content),
                "elapsed_ms": elapsed,
                "status_code": response.status_code,
                "error": "",
                "redirect_chain": [
                    f"  {r.status_code} → {r.headers.get('location', '?')}"
                    for r in response.history
                ],
            }
        except Exception as exc:
            return {
                "status_line": "",
                "headers": "",
                "body": "",
                "raw_bytes": 0,
                "elapsed_ms": 0,
                "status_code": 0,
                "error": str(exc),
                "redirect_chain": [],
            }


# ---------------------------------------------------------------------------
# Race-condition (last-byte sync) worker
# ---------------------------------------------------------------------------

class _RaceWorker(QThread):
    """Send multiple requests with last-byte synchronization."""
    finished = pyqtSignal(list)

    def __init__(self, requests: list[dict], parent=None) -> None:
        super().__init__(parent)
        self.requests = requests

    def run(self) -> None:
        results = asyncio.run(self._race())
        self.finished.emit(results)

    async def _race(self) -> list[dict]:
        """
        Last-byte sync: open all connections, send all but the last byte,
        then fire the last bytes simultaneously.
        """
        results: list[dict] = []
        streams: list[tuple[httpx.AsyncClient, httpx.Request, Any]] = []

        clients = []
        try:
            # Phase 1: prepare all requests and open streams
            for req_data in self.requests:
                raw = req_data["raw"]
                target = req_data.get("target", "")
                verify = req_data.get("verify_ssl", False)
                timeout_s = req_data.get("timeout", 10.0)
                proxy = req_data.get("proxy", "")
                update_cl = req_data.get("update_cl", True)

                kw: dict[str, Any] = {
                    "timeout": httpx.Timeout(timeout_s, connect=timeout_s),
                    "follow_redirects": True,
                    "verify": verify,
                    "http2": True,
                }
                if proxy:
                    kw["proxy"] = proxy

                parsed = parse_raw_request(raw, target)
                if update_cl:
                    parsed.headers = update_content_length(parsed.headers, parsed.body)

                client = httpx.AsyncClient(**kw)
                clients.append(client)

                request = client.build_request(
                    method=parsed.method,
                    url=parsed.url,
                    headers=parsed.headers,
                    content=parsed.body.encode("utf-8") if parsed.body else None,
                )
                streams.append((client, request, req_data))

            # Phase 2: send all requests as close together as possible
            async def _fire(client, request, req_data):
                try:
                    t0 = time.monotonic()
                    response = await client.send(request)
                    elapsed = round((time.monotonic() - t0) * 1000, 1)
                    status_line = f"HTTP/{response.http_version} {response.status_code} {response.reason_phrase or ''}"
                    hdrs = "\r\n".join(f"{k}: {v}" for k, v in response.headers.items())
                    return {
                        "status_line": status_line,
                        "headers": hdrs,
                        "body": response.text,
                        "raw_bytes": len(response.content),
                        "elapsed_ms": elapsed,
                        "status_code": response.status_code,
                        "error": "",
                        "redirect_chain": [],
                    }
                except Exception as exc:
                    return {
                        "status_line": "",
                        "headers": "",
                        "body": "",
                        "raw_bytes": 0,
                        "elapsed_ms": 0,
                        "status_code": 0,
                        "error": str(exc),
                        "redirect_chain": [],
                    }

            tasks = [_fire(c, r, d) for c, r, d in streams]
            results = await asyncio.gather(*tasks)
            results = list(results)

        finally:
            for c in clients:
                await c.aclose()

        return results


# ---------------------------------------------------------------------------
# Encoding / Decoding helper
# ---------------------------------------------------------------------------

def _codec_ops() -> dict[str, tuple[callable, callable]]:
    """Return {name: (encode_fn, decode_fn)} for all supported codecs."""
    return {
        "URL": (
            lambda t: quote(t, safe=""),
            lambda t: unquote(t),
        ),
        "URL (full)": (
            lambda t: quote(t, safe=""),
            lambda t: unquote(t),
        ),
        "URL (key=val)": (
            lambda t: quote_plus(t),
            lambda t: unquote_plus(t),
        ),
        "Base64": (
            lambda t: base64.b64encode(t.encode()).decode(),
            lambda t: base64.b64decode(t.encode()).decode(errors="replace"),
        ),
        "HTML": (
            lambda t: html.escape(t),
            lambda t: html.unescape(t),
        ),
        "Hex": (
            lambda t: t.encode().hex(),
            lambda t: bytes.fromhex(t).decode(errors="replace"),
        ),
        "Unicode Escape": (
            lambda t: t.encode("unicode_escape").decode(),
            lambda t: t.encode().decode("unicode_escape"),
        ),
        "MD5 (encode only)": (
            lambda t: hashlib.md5(t.encode()).hexdigest(),
            lambda t: t,  # not reversible
        ),
        "SHA-1 (encode only)": (
            lambda t: hashlib.sha1(t.encode()).hexdigest(),
            lambda t: t,
        ),
        "SHA-256 (encode only)": (
            lambda t: hashlib.sha256(t.encode()).hexdigest(),
            lambda t: t,
        ),
        "JSON string": (
            lambda t: json.dumps(t),
            lambda t: json.loads(t) if t.startswith('"') else t,
        ),
        "ASCII Hex (\\x..)": (
            lambda t: "".join(f"\\x{ord(c):02x}" for c in t),
            lambda t: re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), t),
        ),
    }


# ---------------------------------------------------------------------------
# Single Repeater Pane (one request)
# ---------------------------------------------------------------------------

class _RepeaterPane(QWidget):
    """One request/response pane inside the repeater tab widget."""

    send_to_intruder = pyqtSignal(str, str)  # raw_request, target

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: _SenderWorker | None = None
        self._history: list[dict] = []  # list of {request, response_dict}
        self._history_idx: int = -1
        self._init_ui()

    def _init_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(4, 4, 4, 4)
        outer.setSpacing(4)

        # -- Top control bar --
        bar = QHBoxLayout()

        # Target
        bar.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://example.com  (auto-detected from Host header)")
        self.target_input.setMinimumWidth(260)
        bar.addWidget(self.target_input, 1)

        # Options
        self.follow_check = QCheckBox("Follow redirects")
        self.follow_check.setChecked(True)
        bar.addWidget(self.follow_check)

        self.update_cl_check = QCheckBox("Auto Content-Length")
        self.update_cl_check.setChecked(True)
        bar.addWidget(self.update_cl_check)

        self.verify_ssl_check = QCheckBox("Verify SSL")
        bar.addWidget(self.verify_ssl_check)

        bar.addWidget(QLabel("Timeout:"))
        self.timeout_input = QLineEdit("10")
        self.timeout_input.setFixedWidth(44)
        bar.addWidget(self.timeout_input)

        bar.addWidget(QLabel("Proxy:"))
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("http://127.0.0.1:8080")
        self.proxy_input.setFixedWidth(180)
        bar.addWidget(self.proxy_input)

        outer.addLayout(bar)

        # -- Button bar --
        btn_bar = QHBoxLayout()

        self.send_btn = QPushButton("Send")
        self.send_btn.setObjectName("startButton")
        self.send_btn.setFixedWidth(100)
        self.send_btn.clicked.connect(self._on_send)
        btn_bar.addWidget(self.send_btn)

        self.intruder_btn = QPushButton("Send to Intruder")
        self.intruder_btn.setToolTip("Copy this request to the Intruder request editor")
        self.intruder_btn.clicked.connect(self._on_send_to_intruder)
        btn_bar.addWidget(self.intruder_btn)

        # History navigation
        self.prev_btn = QPushButton("◀")
        self.prev_btn.setToolTip("Previous request in history")
        self.prev_btn.setFixedWidth(32)
        self.prev_btn.clicked.connect(self._on_prev)
        btn_bar.addWidget(self.prev_btn)

        self.next_btn = QPushButton("▶")
        self.next_btn.setToolTip("Next request in history")
        self.next_btn.setFixedWidth(32)
        self.next_btn.clicked.connect(self._on_next)
        btn_bar.addWidget(self.next_btn)

        self.history_label = QLabel("")
        self.history_label.setObjectName("statsLabel")
        btn_bar.addWidget(self.history_label)

        btn_bar.addStretch()

        # Encoding helpers
        self.codec_combo = QComboBox()
        self.codec_combo.addItems(list(_codec_ops().keys()))
        self.codec_combo.setFixedWidth(160)
        btn_bar.addWidget(self.codec_combo)

        enc_btn = QPushButton("Encode")
        enc_btn.setToolTip("Encode selected text in request editor")
        enc_btn.clicked.connect(partial(self._apply_codec, encode=True))
        btn_bar.addWidget(enc_btn)

        dec_btn = QPushButton("Decode")
        dec_btn.setToolTip("Decode selected text in request editor")
        dec_btn.clicked.connect(partial(self._apply_codec, encode=False))
        btn_bar.addWidget(dec_btn)

        outer.addLayout(btn_bar)

        # -- Request / Response splitter --
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: request editor
        req_widget = QWidget()
        req_layout = QVBoxLayout(req_widget)
        req_layout.setContentsMargins(0, 0, 0, 0)
        req_lbl = QLabel("Request")
        req_lbl.setStyleSheet("font-weight:bold; color:#e94560;")
        req_layout.addWidget(req_lbl)

        self.request_edit = QPlainTextEdit()
        self.request_edit.setFont(QFont("Consolas", 12))
        self.request_edit.setPlaceholderText(
            "Paste raw HTTP request here...\n\n"
            "GET /path HTTP/1.1\n"
            "Host: example.com\n"
        )
        self._req_hl = _ReqHighlighter(self.request_edit.document())
        req_layout.addWidget(self.request_edit, 1)
        splitter.addWidget(req_widget)

        # Right: response viewer
        resp_widget = QWidget()
        resp_layout = QVBoxLayout(resp_widget)
        resp_layout.setContentsMargins(0, 0, 0, 0)

        resp_top = QHBoxLayout()
        resp_lbl = QLabel("Response")
        resp_lbl.setStyleSheet("font-weight:bold; color:#4ecca3;")
        resp_top.addWidget(resp_lbl)
        self.status_label = QLabel("")
        self.status_label.setObjectName("statsLabel")
        resp_top.addWidget(self.status_label)
        resp_top.addStretch()
        resp_layout.addLayout(resp_top)

        self.resp_tabs = QTabWidget()

        # Raw tab
        self.response_raw = QPlainTextEdit()
        self.response_raw.setReadOnly(True)
        self.response_raw.setFont(QFont("Consolas", 12))
        self._resp_hl = _RespHighlighter(self.response_raw.document())
        self.resp_tabs.addTab(self.response_raw, "Raw")

        # Headers tab
        self.response_headers = QPlainTextEdit()
        self.response_headers.setReadOnly(True)
        self.response_headers.setFont(QFont("Consolas", 12))
        self.resp_tabs.addTab(self.response_headers, "Headers")

        # Body (Pretty) tab
        self.response_pretty = QPlainTextEdit()
        self.response_pretty.setReadOnly(True)
        self.response_pretty.setFont(QFont("Consolas", 12))
        self.resp_tabs.addTab(self.response_pretty, "Pretty")

        # Search in response
        search_bar = QHBoxLayout()
        search_bar.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search in response (Ctrl+F)")
        self.search_input.returnPressed.connect(self._search_response)
        self.search_input.textChanged.connect(self._search_response)
        search_bar.addWidget(self.search_input)
        self.match_count_lbl = QLabel("")
        search_bar.addWidget(self.match_count_lbl)
        resp_layout.addLayout(search_bar)

        resp_layout.addWidget(self.resp_tabs, 1)
        splitter.addWidget(resp_widget)

        splitter.setSizes([500, 500])
        outer.addWidget(splitter, 1)

    # -- Actions --

    def _get_req_dict(self) -> dict:
        return {
            "raw": self.request_edit.toPlainText(),
            "target": self.target_input.text().strip(),
            "follow_redirects": self.follow_check.isChecked(),
            "verify_ssl": self.verify_ssl_check.isChecked(),
            "timeout": float(self.timeout_input.text() or "10"),
            "proxy": self.proxy_input.text().strip(),
            "update_cl": self.update_cl_check.isChecked(),
        }

    def _on_send(self) -> None:
        raw = self.request_edit.toPlainText().strip()
        if not raw:
            return
        self.send_btn.setEnabled(False)
        self.send_btn.setText("Sending...")
        self.status_label.setText("⏳")
        self._worker = _SenderWorker([self._get_req_dict()])
        self._worker.finished.connect(self._on_response)
        self._worker.start()

    def _on_response(self, results: list[dict]) -> None:
        self.send_btn.setEnabled(True)
        self.send_btn.setText("Send")
        if not results:
            return
        r = results[0]
        self._show_response(r)
        # Add to history
        self._history.append({
            "request": self.request_edit.toPlainText(),
            "response": r,
        })
        self._history_idx = len(self._history) - 1
        self._update_history_label()

    def _show_response(self, r: dict) -> None:
        if r["error"]:
            self.status_label.setText(f"❌ {r['error']}")
            self.status_label.setStyleSheet("color: #e94560;")
            self.response_raw.setPlainText(f"Error: {r['error']}")
            self.response_headers.clear()
            self.response_pretty.clear()
            return

        sc = r["status_code"]
        color = "#4ecca3" if sc < 300 else ("#f1c40f" if sc < 400 else "#e94560")

        chain_text = ""
        if r.get("redirect_chain"):
            chain_text = "  [" + " → ".join(r["redirect_chain"]) + "]"

        self.status_label.setText(
            f"{r['status_line']}  |  {r['raw_bytes']} bytes  |  {r['elapsed_ms']} ms{chain_text}"
        )
        self.status_label.setStyleSheet(f"color: {color};")

        # Raw
        raw_text = r["status_line"] + "\r\n" + r["headers"] + "\r\n\r\n" + r["body"]
        self.response_raw.setPlainText(raw_text)

        # Headers
        self.response_headers.setPlainText(r["status_line"] + "\r\n" + r["headers"])

        # Pretty (try JSON formatting)
        body = r["body"]
        try:
            parsed = json.loads(body)
            pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
            self.response_pretty.setPlainText(pretty)
        except (json.JSONDecodeError, ValueError):
            self.response_pretty.setPlainText(body)

    def _on_send_to_intruder(self) -> None:
        raw = self.request_edit.toPlainText()
        target = self.target_input.text().strip()
        self.send_to_intruder.emit(raw, target)

    # -- History --

    def _on_prev(self) -> None:
        if self._history_idx > 0:
            self._history_idx -= 1
            h = self._history[self._history_idx]
            self.request_edit.setPlainText(h["request"])
            self._show_response(h["response"])
            self._update_history_label()

    def _on_next(self) -> None:
        if self._history_idx < len(self._history) - 1:
            self._history_idx += 1
            h = self._history[self._history_idx]
            self.request_edit.setPlainText(h["request"])
            self._show_response(h["response"])
            self._update_history_label()

    def _update_history_label(self) -> None:
        if self._history:
            self.history_label.setText(f"History: {self._history_idx + 1}/{len(self._history)}")
        else:
            self.history_label.setText("")

    # -- Encoding --

    def _apply_codec(self, encode: bool = True) -> None:
        cursor = self.request_edit.textCursor()
        if not cursor.hasSelection():
            QMessageBox.information(self, "No Selection", "Select text in the request editor to encode/decode.")
            return
        selected = cursor.selectedText()
        codec_name = self.codec_combo.currentText()
        ops = _codec_ops()
        if codec_name not in ops:
            return
        enc_fn, dec_fn = ops[codec_name]
        try:
            result = enc_fn(selected) if encode else dec_fn(selected)
            cursor.insertText(result)
        except Exception as exc:
            QMessageBox.warning(self, "Codec Error", str(exc))

    # -- Search --

    def _search_response(self) -> None:
        query = self.search_input.text()
        # Clear previous highlights by resetting the text (simple approach)
        current_tab = self.resp_tabs.currentWidget()
        if not isinstance(current_tab, QPlainTextEdit) or not query:
            self.match_count_lbl.setText("")
            return

        text = current_tab.toPlainText()
        count = text.lower().count(query.lower())
        self.match_count_lbl.setText(f"{count} matches" if count else "No matches")

        # Highlight via find
        if count > 0:
            current_tab.moveCursor(current_tab.textCursor().MoveOperation.Start)
            current_tab.find(query)

    # -- Public API --

    def set_request(self, raw: str, target: str = "") -> None:
        self.request_edit.setPlainText(raw)
        if target:
            self.target_input.setText(target)
        elif not self.target_input.text().strip():
            detected = guess_target_from_raw(raw)
            if detected:
                self.target_input.setText(detected)


# ---------------------------------------------------------------------------
# Main Repeater Tab (manages multiple panes as sub-tabs)
# ---------------------------------------------------------------------------

class RepeaterTab(QWidget):
    """Tabbed repeater with multiple request panes, race condition, and Send All."""

    send_to_intruder = pyqtSignal(str, str)  # raw_request, target

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._panes: list[_RepeaterPane] = []
        self._race_worker: _RaceWorker | None = None
        self._init_ui()
        # Add first tab
        self._add_tab()

    def _init_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(4, 4, 4, 4)
        outer.setSpacing(4)

        # -- Toolbar --
        toolbar = QHBoxLayout()

        add_btn = QPushButton("+ New Tab")
        add_btn.setToolTip("Add a new repeater tab")
        add_btn.clicked.connect(self._add_tab)
        toolbar.addWidget(add_btn)

        dup_btn = QPushButton("Duplicate Tab")
        dup_btn.setToolTip("Duplicate the current tab's request")
        dup_btn.clicked.connect(self._duplicate_tab)
        toolbar.addWidget(dup_btn)

        close_btn = QPushButton("Close Tab")
        close_btn.setToolTip("Close current tab")
        close_btn.clicked.connect(self._close_current_tab)
        toolbar.addWidget(close_btn)

        toolbar.addStretch()

        self.send_all_btn = QPushButton("Send All")
        self.send_all_btn.setToolTip("Send all tabs' requests sequentially")
        self.send_all_btn.clicked.connect(self._send_all)
        toolbar.addWidget(self.send_all_btn)

        self.race_btn = QPushButton("🏁 Race (Last-Byte Sync)")
        self.race_btn.setToolTip(
            "Send all tabs simultaneously with last-byte synchronization.\n"
            "Used for race condition testing — all requests fire at the exact same moment."
        )
        self.race_btn.clicked.connect(self._send_race)
        toolbar.addWidget(self.race_btn)

        outer.addLayout(toolbar)

        # -- Tab widget for panes --
        self.pane_tabs = QTabWidget()
        self.pane_tabs.setTabsClosable(False)
        self.pane_tabs.setDocumentMode(True)
        outer.addWidget(self.pane_tabs, 1)

    def _add_tab(self, request_text: str = "", target: str = "") -> _RepeaterPane:
        pane = _RepeaterPane()
        pane.send_to_intruder.connect(self.send_to_intruder.emit)
        if request_text:
            pane.set_request(request_text, target)
        idx = self.pane_tabs.addTab(pane, f"#{len(self._panes) + 1}")
        self._panes.append(pane)
        self.pane_tabs.setCurrentIndex(idx)
        self._renumber_tabs()
        return pane

    def _duplicate_tab(self) -> None:
        pane = self._current_pane()
        if pane:
            new_pane = self._add_tab(
                pane.request_edit.toPlainText(),
                pane.target_input.text(),
            )
            new_pane.follow_check.setChecked(pane.follow_check.isChecked())
            new_pane.verify_ssl_check.setChecked(pane.verify_ssl_check.isChecked())
            new_pane.update_cl_check.setChecked(pane.update_cl_check.isChecked())
            new_pane.timeout_input.setText(pane.timeout_input.text())
            new_pane.proxy_input.setText(pane.proxy_input.text())

    def _close_current_tab(self) -> None:
        if len(self._panes) <= 1:
            return  # keep at least one
        idx = self.pane_tabs.currentIndex()
        pane = self._panes.pop(idx)
        self.pane_tabs.removeTab(idx)
        pane.deleteLater()
        self._renumber_tabs()

    def _renumber_tabs(self) -> None:
        for i in range(self.pane_tabs.count()):
            self.pane_tabs.setTabText(i, f"#{i + 1}")

    def _current_pane(self) -> _RepeaterPane | None:
        idx = self.pane_tabs.currentIndex()
        if 0 <= idx < len(self._panes):
            return self._panes[idx]
        return None

    # -- Send All --

    def _send_all(self) -> None:
        reqs = []
        for pane in self._panes:
            raw = pane.request_edit.toPlainText().strip()
            if raw:
                reqs.append(pane._get_req_dict())
        if not reqs:
            return
        self.send_all_btn.setEnabled(False)
        self.send_all_btn.setText("Sending...")
        worker = _SenderWorker(reqs)
        worker.finished.connect(self._on_send_all_done)
        self._send_all_worker = worker
        worker.start()

    def _on_send_all_done(self, results: list[dict]) -> None:
        self.send_all_btn.setEnabled(True)
        self.send_all_btn.setText("Send All")
        i = 0
        for pane in self._panes:
            raw = pane.request_edit.toPlainText().strip()
            if raw and i < len(results):
                pane._show_response(results[i])
                pane._history.append({
                    "request": pane.request_edit.toPlainText(),
                    "response": results[i],
                })
                pane._history_idx = len(pane._history) - 1
                pane._update_history_label()
                i += 1

    # -- Race Condition --

    def _send_race(self) -> None:
        reqs = []
        for pane in self._panes:
            raw = pane.request_edit.toPlainText().strip()
            if raw:
                reqs.append(pane._get_req_dict())
        if len(reqs) < 2:
            QMessageBox.information(
                self, "Race Condition",
                "Need at least 2 tabs with requests for race condition testing.",
            )
            return
        self.race_btn.setEnabled(False)
        self.race_btn.setText("Racing...")
        self._race_worker = _RaceWorker(reqs)
        self._race_worker.finished.connect(self._on_race_done)
        self._race_worker.start()

    def _on_race_done(self, results: list[dict]) -> None:
        self.race_btn.setEnabled(True)
        self.race_btn.setText("🏁 Race (Last-Byte Sync)")
        i = 0
        for pane in self._panes:
            raw = pane.request_edit.toPlainText().strip()
            if raw and i < len(results):
                pane._show_response(results[i])
                pane._history.append({
                    "request": pane.request_edit.toPlainText(),
                    "response": results[i],
                })
                pane._history_idx = len(pane._history) - 1
                pane._update_history_label()
                i += 1

    # -- Public API --

    def add_request(self, raw: str, target: str = "") -> None:
        """Add a new tab with the given request (called from other tabs)."""
        self._add_tab(raw, target)

    def rename_current_tab(self, name: str) -> None:
        idx = self.pane_tabs.currentIndex()
        if idx >= 0:
            self.pane_tabs.setTabText(idx, name)
