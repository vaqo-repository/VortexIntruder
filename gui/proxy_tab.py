"""
VortexIntruder v1.0 – Proxy Tab
Detects Burp Suite installation, opens its embedded browser,
and captures / displays proxied HTTP traffic in real time.
"""
from __future__ import annotations

import os
import glob
import json
import socket
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Any
from urllib.parse import urlparse

import httpx
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QAction, QColor, QFont
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


# ---------------------------------------------------------------------------
# Burp Suite Detection
# ---------------------------------------------------------------------------

_BURP_COMMON_PATHS: list[str] = [
    # Default installer locations on Windows
    r"C:\Program Files\BurpSuiteCommunity\BurpSuiteCommunity.exe",
    r"C:\Program Files\BurpSuitePro\BurpSuitePro.exe",
    r"C:\Program Files (x86)\BurpSuiteCommunity\BurpSuiteCommunity.exe",
    r"C:\Program Files (x86)\BurpSuitePro\BurpSuitePro.exe",
    # User-local installs
    os.path.expandvars(r"%LOCALAPPDATA%\BurpSuiteCommunity\BurpSuiteCommunity.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\BurpSuitePro\BurpSuitePro.exe"),
    os.path.expandvars(r"%USERPROFILE%\BurpSuiteCommunity\BurpSuiteCommunity.exe"),
    os.path.expandvars(r"%USERPROFILE%\BurpSuitePro\BurpSuitePro.exe"),
]


def find_burp_suite() -> str | None:
    """Return the path to a Burp Suite executable, or None."""
    for p in _BURP_COMMON_PATHS:
        if os.path.isfile(p):
            return p

    # Try glob for versioned directories
    for pattern in [
        r"C:\Program Files\BurpSuite*\BurpSuite*.exe",
        r"C:\Program Files (x86)\BurpSuite*\BurpSuite*.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\BurpSuite*\BurpSuite*.exe"),
    ]:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]

    # Check PATH
    for d in os.environ.get("PATH", "").split(os.pathsep):
        for name in ("BurpSuiteCommunity.exe", "BurpSuitePro.exe"):
            candidate = os.path.join(d, name)
            if os.path.isfile(candidate):
                return candidate

    return None


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

@dataclass
class ProxiedRequest:
    index: int = 0
    timestamp: str = ""
    method: str = ""
    url: str = ""
    host: str = ""
    status_code: int = 0
    content_length: int = 0
    content_type: str = ""
    elapsed_ms: int = 0
    request_headers: str = ""
    request_body: str = ""
    response_headers: str = ""
    response_body: str = ""


# ---------------------------------------------------------------------------
# Proxy Server (threading HTTP proxy)
# ---------------------------------------------------------------------------

class _ProxyHandler(BaseHTTPRequestHandler):
    """Handles HTTP CONNECT tunneling and plain HTTP proxy requests."""

    server: "_ThreadedProxyServer"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Suppress default stderr logging
        pass

    def do_CONNECT(self) -> None:
        """Handle HTTPS CONNECT tunneling – direct or via upstream proxy."""
        target = self.path  # e.g. "example.com:443"
        host, _, port_str = target.partition(":")
        port = int(port_str) if port_str else 443

        # Record the CONNECT as a captured entry
        entry = ProxiedRequest(
            index=self.server.next_index(),
            timestamp=time.strftime("%H:%M:%S"),
            method="CONNECT",
            url=target,
            host=host,
            status_code=200,
            request_headers=f"CONNECT {target} HTTP/1.1\r\nHost: {target}",
        )
        self.server.on_request(entry)

        try:
            if self.server.upstream_host:
                # Connect to upstream proxy and send CONNECT
                remote = socket.create_connection(
                    (self.server.upstream_host, self.server.upstream_port), timeout=10
                )
                connect_req = (
                    f"CONNECT {target} HTTP/1.1\r\n"
                    f"Host: {target}\r\n\r\n"
                ).encode()
                remote.sendall(connect_req)
                # Read upstream proxy response
                resp_data = b""
                while b"\r\n\r\n" not in resp_data:
                    chunk = remote.recv(4096)
                    if not chunk:
                        raise ConnectionError("Upstream proxy closed connection")
                    resp_data += chunk
            else:
                # Direct connection
                remote = socket.create_connection((host, port), timeout=10)
        except Exception:
            self.send_error(502, "Bad Gateway")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()

        self.connection.setblocking(False)
        remote.setblocking(False)

        conns = [self.connection, remote]
        timeout_secs = 60
        last_activity = time.time()

        while time.time() - last_activity < timeout_secs:
            import select
            readable, _, exceptional = select.select(conns, [], conns, 1.0)
            if exceptional:
                break
            for s in readable:
                other = remote if s is self.connection else self.connection
                try:
                    data = s.recv(65536)
                except (BlockingIOError, ssl.SSLWantReadError):
                    continue
                except Exception:
                    data = b""
                if not data:
                    remote.close()
                    return
                other.sendall(data)
                last_activity = time.time()

        remote.close()

    def _proxy_request(self, method: str) -> None:
        """Forward a plain HTTP request and record it."""
        url = self.path
        parsed = urlparse(url)

        # Read request body
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len else b""

        # Build headers for forwarding (skip hop-by-hop)
        hop_by_hop = {
            "proxy-connection", "keep-alive", "transfer-encoding",
            "te", "connection", "proxy-authorization",
            "proxy-authenticate", "upgrade",
        }
        fwd_headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in hop_by_hop
        }

        # Format request headers for display
        req_header_lines = f"{method} {parsed.path or '/'} HTTP/1.1\r\n"
        req_header_lines += "\r\n".join(f"{k}: {v}" for k, v in self.headers.items())

        # Build upstream proxy URL if configured
        upstream_proxy = None
        if self.server.upstream_host:
            upstream_proxy = f"http://{self.server.upstream_host}:{self.server.upstream_port}"

        start = time.time()
        try:
            with httpx.Client(
                verify=False, timeout=30, follow_redirects=False,
                proxy=upstream_proxy,
            ) as client:
                resp = client.request(
                    method,
                    url,
                    headers=fwd_headers,
                    content=body,
                )
            elapsed = int((time.time() - start) * 1000)

            # Send response back to client
            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                if k.lower() not in ("transfer-encoding", "content-encoding", "content-length"):
                    self.send_header(k, v)
            resp_body = resp.content
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)

            # Record the request
            entry = ProxiedRequest(
                index=self.server.next_index(),
                timestamp=time.strftime("%H:%M:%S"),
                method=method,
                url=url,
                host=parsed.hostname or "",
                status_code=resp.status_code,
                content_length=len(resp_body),
                content_type=resp.headers.get("content-type", ""),
                elapsed_ms=elapsed,
                request_headers=req_header_lines,
                request_body=body.decode("utf-8", errors="replace"),
                response_headers="\r\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
                response_body=resp_body.decode("utf-8", errors="replace"),
            )
            self.server.on_request(entry)

        except Exception as exc:
            elapsed = int((time.time() - start) * 1000)
            self.send_error(502, str(exc))
            entry = ProxiedRequest(
                index=self.server.next_index(),
                timestamp=time.strftime("%H:%M:%S"),
                method=method,
                url=url,
                host=parsed.hostname or "",
                status_code=502,
                elapsed_ms=elapsed,
                request_headers=req_header_lines,
                request_body=body.decode("utf-8", errors="replace"),
                response_body=str(exc),
            )
            self.server.on_request(entry)

    # Forward every HTTP method through _proxy_request
    do_GET = lambda self: self._proxy_request("GET")
    do_POST = lambda self: self._proxy_request("POST")
    do_PUT = lambda self: self._proxy_request("PUT")
    do_DELETE = lambda self: self._proxy_request("DELETE")
    do_PATCH = lambda self: self._proxy_request("PATCH")
    do_HEAD = lambda self: self._proxy_request("HEAD")
    do_OPTIONS = lambda self: self._proxy_request("OPTIONS")


class _ThreadedProxyServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    upstream_host: str = ""
    upstream_port: int = 0

    def __init__(self, addr: tuple[str, int], callback,
                 upstream_host: str = "", upstream_port: int = 0):
        super().__init__(addr, _ProxyHandler)
        self._callback = callback
        self._counter = 0
        self._lock = threading.Lock()
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port

    def next_index(self) -> int:
        with self._lock:
            self._counter += 1
            return self._counter

    def on_request(self, entry: ProxiedRequest) -> None:
        if self._callback:
            self._callback(entry)


# ---------------------------------------------------------------------------
# Proxy Worker Thread  (QThread for Qt signal integration)
# ---------------------------------------------------------------------------

class _ProxyWorker(QThread):
    request_captured = pyqtSignal(object)  # ProxiedRequest

    def __init__(self, host: str, port: int,
                 upstream_host: str = "", upstream_port: int = 0,
                 parent=None):
        super().__init__(parent)
        self._host = host
        self._port = port
        self._upstream_host = upstream_host
        self._upstream_port = upstream_port
        self._server: _ThreadedProxyServer | None = None

    def run(self) -> None:
        self._server = _ThreadedProxyServer(
            (self._host, self._port),
            callback=lambda entry: self.request_captured.emit(entry),
            upstream_host=self._upstream_host,
            upstream_port=self._upstream_port,
        )
        self._server.serve_forever()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
        self.quit()
        self.wait(3000)


# ---------------------------------------------------------------------------
# Proxy Tab Widget
# ---------------------------------------------------------------------------

class ProxyTab(QWidget):
    """Proxy capture tab: starts an HTTP proxy, detects/opens Burp browser, shows traffic."""

    send_to_repeater = pyqtSignal(str)   # raw request text

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._worker: _ProxyWorker | None = None
        self._entries: list[ProxiedRequest] = []
        self._burp_path: str | None = None
        self._init_ui()
        # Auto-detect Burp Suite on init
        QTimer.singleShot(200, self._detect_burp)

    # -------------------------------------------------------------- UI

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # --- Control Row ---
        ctrl_group = QGroupBox("HTTP Proxy")
        ctrl_layout = QVBoxLayout(ctrl_group)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Listen:"))
        self._host_edit = QLineEdit("127.0.0.1")
        self._host_edit.setFixedWidth(120)
        row1.addWidget(self._host_edit)
        row1.addWidget(QLabel(":"))
        self._port_edit = QLineEdit("8888")
        self._port_edit.setFixedWidth(60)
        row1.addWidget(self._port_edit)

        self._start_btn = QPushButton("▶  Start Proxy")
        self._start_btn.setObjectName("startButton")
        self._start_btn.setFixedWidth(140)
        self._start_btn.clicked.connect(self._toggle_proxy)
        row1.addWidget(self._start_btn)

        self._status_label = QLabel("⏹  Stopped")
        self._status_label.setObjectName("statsLabel")
        row1.addWidget(self._status_label)

        row1.addStretch()
        ctrl_layout.addLayout(row1)

        # Upstream proxy row (chain through existing proxy like Burp)
        row_upstream = QHBoxLayout()
        self._upstream_check = QPushButton("🔗  Upstream Proxy (chain)")
        self._upstream_check.setCheckable(True)
        self._upstream_check.setFixedWidth(200)
        self._upstream_check.setToolTip(
            "Enable to forward all traffic through an existing proxy (e.g. Burp Suite on 8080).\n"
            "Browser → VortexIntruder → Upstream Proxy → Internet\n"
            "Both VortexIntruder and the upstream proxy will see all traffic."
        )
        self._upstream_check.toggled.connect(self._on_upstream_toggled)
        row_upstream.addWidget(self._upstream_check)

        row_upstream.addWidget(QLabel("Upstream:"))
        self._upstream_host_edit = QLineEdit("127.0.0.1")
        self._upstream_host_edit.setFixedWidth(120)
        self._upstream_host_edit.setEnabled(False)
        row_upstream.addWidget(self._upstream_host_edit)
        row_upstream.addWidget(QLabel(":"))
        self._upstream_port_edit = QLineEdit("8080")
        self._upstream_port_edit.setFixedWidth(60)
        self._upstream_port_edit.setEnabled(False)
        self._upstream_port_edit.setToolTip("Burp Suite default: 8080")
        row_upstream.addWidget(self._upstream_port_edit)

        self._upstream_status = QLabel("")
        self._upstream_status.setObjectName("statsLabel")
        row_upstream.addWidget(self._upstream_status)

        row_upstream.addStretch()
        ctrl_layout.addLayout(row_upstream)

        # Burp Suite row
        row2 = QHBoxLayout()
        self._burp_label = QLabel("Burp Suite: Detecting...")
        self._burp_label.setObjectName("statsLabel")
        row2.addWidget(self._burp_label)

        self._open_burp_btn = QPushButton("🚀  Open Burp Browser")
        self._open_burp_btn.setToolTip(
            "Launches Burp Suite's embedded Chromium browser pre-configured to use Burp's proxy.\n"
            "Proxied traffic will appear in the table below."
        )
        self._open_burp_btn.setEnabled(False)
        self._open_burp_btn.clicked.connect(self._open_burp_browser)
        row2.addWidget(self._open_burp_btn)

        self._open_sys_browser_btn = QPushButton("🌐  Open System Browser")
        self._open_sys_browser_btn.setToolTip(
            "Opens the default system browser.\n"
            "Configure its proxy to point to VortexIntruder's proxy address."
        )
        self._open_sys_browser_btn.clicked.connect(self._open_system_browser)
        row2.addWidget(self._open_sys_browser_btn)

        self._burp_path_btn = QPushButton("📁  Set Burp Path")
        self._burp_path_btn.setToolTip("Manually set the path to Burp Suite executable")
        self._burp_path_btn.clicked.connect(self._set_burp_path)
        row2.addWidget(self._burp_path_btn)

        row2.addStretch()
        ctrl_layout.addLayout(row2)

        layout.addWidget(ctrl_group)

        # --- Main Splitter: Table (top) + Detail (bottom) ---
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Top: Traffic table
        table_container = QWidget()
        table_layout = QVBoxLayout(table_container)
        table_layout.setContentsMargins(0, 0, 0, 0)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter:"))
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("Filter by URL, host, method... (real-time)")
        self._filter_edit.textChanged.connect(self._apply_filter)
        filter_row.addWidget(self._filter_edit)

        self._clear_btn = QPushButton("🗑  Clear")
        self._clear_btn.setFixedWidth(90)
        self._clear_btn.clicked.connect(self._clear_table)
        filter_row.addWidget(self._clear_btn)

        self._count_label = QLabel("0 requests")
        filter_row.addWidget(self._count_label)
        table_layout.addLayout(filter_row)

        self._table = QTableWidget()
        self._table.setColumnCount(8)
        self._table.setHorizontalHeaderLabels([
            "#", "Time", "Method", "Host", "URL", "Status", "Length", "Time (ms)"
        ])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setColumnWidth(0, 50)
        self._table.setColumnWidth(1, 70)
        self._table.setColumnWidth(2, 65)
        self._table.setColumnWidth(3, 160)
        self._table.setColumnWidth(5, 60)
        self._table.setColumnWidth(6, 80)
        self._table.setColumnWidth(7, 70)
        self._table.currentCellChanged.connect(self._on_row_selected)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        table_layout.addWidget(self._table)
        splitter.addWidget(table_container)

        # Bottom: Request / Response detail viewer
        detail_widget = QWidget()
        detail_layout = QHBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)

        # Left: Request detail
        req_group = QGroupBox("Request")
        req_layout = QVBoxLayout(req_group)
        self._req_viewer = QPlainTextEdit()
        self._req_viewer.setReadOnly(True)
        self._req_viewer.setFont(QFont("Consolas", 11))
        req_layout.addWidget(self._req_viewer)
        detail_layout.addWidget(req_group)

        # Right: Response detail
        resp_group = QGroupBox("Response")
        resp_layout = QVBoxLayout(resp_group)
        self._resp_viewer = QPlainTextEdit()
        self._resp_viewer.setReadOnly(True)
        self._resp_viewer.setFont(QFont("Consolas", 11))
        resp_layout.addWidget(self._resp_viewer)
        detail_layout.addWidget(resp_group)

        splitter.addWidget(detail_widget)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter, 1)

    # -------------------------------------------------------------- BURP DETECTION

    def _detect_burp(self) -> None:
        self._burp_path = find_burp_suite()
        if self._burp_path:
            name = os.path.basename(self._burp_path)
            self._burp_label.setText(f"✅  Burp Suite found: {name}")
            self._burp_label.setStyleSheet("color: #4ecca3;")
            self._open_burp_btn.setEnabled(True)
        else:
            self._burp_label.setText("⚠  Burp Suite not found (set path manually)")
            self._burp_label.setStyleSheet("color: #e67e22;")

    def _set_burp_path(self) -> None:
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Burp Suite Executable", "",
            "Executables (*.exe);;All Files (*)"
        )
        if path and os.path.isfile(path):
            self._burp_path = path
            name = os.path.basename(path)
            self._burp_label.setText(f"✅  Burp Suite: {name}")
            self._burp_label.setStyleSheet("color: #4ecca3;")
            self._open_burp_btn.setEnabled(True)

    # -------------------------------------------------------------- PROXY CONTROL

    def _on_upstream_toggled(self, checked: bool) -> None:
        self._upstream_host_edit.setEnabled(checked)
        self._upstream_port_edit.setEnabled(checked)
        if checked:
            self._upstream_status.setText("⛓  Chain mode ON")
            self._upstream_status.setStyleSheet("color: #f1c40f;")
        else:
            self._upstream_status.setText("")
            self._upstream_status.setStyleSheet("")

    def _toggle_proxy(self) -> None:
        if self._worker and self._worker.isRunning():
            self._stop_proxy()
        else:
            self._start_proxy()

    def _start_proxy(self) -> None:
        host = self._host_edit.text().strip() or "127.0.0.1"
        try:
            port = int(self._port_edit.text().strip())
        except ValueError:
            QMessageBox.warning(self, "Invalid Port", "Please enter a valid port number.")
            return

        # Upstream proxy settings
        upstream_host = ""
        upstream_port = 0
        if self._upstream_check.isChecked():
            upstream_host = self._upstream_host_edit.text().strip() or "127.0.0.1"
            try:
                upstream_port = int(self._upstream_port_edit.text().strip())
            except ValueError:
                QMessageBox.warning(self, "Invalid Upstream Port",
                                    "Please enter a valid upstream proxy port.")
                return
            # Verify upstream proxy is reachable
            try:
                test_sock = socket.create_connection(
                    (upstream_host, upstream_port), timeout=3
                )
                test_sock.close()
            except OSError:
                QMessageBox.warning(
                    self, "Upstream Proxy Unreachable",
                    f"Cannot connect to upstream proxy at {upstream_host}:{upstream_port}.\n"
                    "Make sure Burp Suite (or your proxy) is running first."
                )
                return

        # Check if listen port is available
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.bind((host, port))
            test_sock.close()
        except OSError:
            QMessageBox.warning(
                self, "Port In Use",
                f"Port {port} is already in use.\n"
                "Another proxy or Burp Suite may be running on this port."
            )
            return

        self._worker = _ProxyWorker(
            host, port,
            upstream_host=upstream_host,
            upstream_port=upstream_port,
            parent=self,
        )
        self._worker.request_captured.connect(self._on_request_captured)
        self._worker.start()

        self._start_btn.setText("⏹  Stop Proxy")
        if upstream_host:
            self._status_label.setText(
                f"🟢  {host}:{port}  →  {upstream_host}:{upstream_port}"
            )
            self._upstream_status.setText(f"⛓  Chained to {upstream_host}:{upstream_port}")
            self._upstream_status.setStyleSheet("color: #4ecca3; font-weight: bold;")
        else:
            self._status_label.setText(f"🟢  Listening on {host}:{port}")
        self._status_label.setStyleSheet("color: #4ecca3; font-weight: bold;")
        self._host_edit.setEnabled(False)
        self._port_edit.setEnabled(False)
        self._upstream_check.setEnabled(False)
        self._upstream_host_edit.setEnabled(False)
        self._upstream_port_edit.setEnabled(False)

    def _stop_proxy(self) -> None:
        if self._worker:
            self._worker.stop()
            self._worker = None
        self._start_btn.setText("▶  Start Proxy")
        self._status_label.setText("⏹  Stopped")
        self._status_label.setStyleSheet("")
        self._host_edit.setEnabled(True)
        self._port_edit.setEnabled(True)
        self._upstream_check.setEnabled(True)
        is_chain = self._upstream_check.isChecked()
        self._upstream_host_edit.setEnabled(is_chain)
        self._upstream_port_edit.setEnabled(is_chain)
        if is_chain:
            self._upstream_status.setText("⛓  Chain mode ON")
            self._upstream_status.setStyleSheet("color: #f1c40f;")
        else:
            self._upstream_status.setText("")

    # -------------------------------------------------------------- BROWSER LAUNCH

    def _open_burp_browser(self) -> None:
        """Launch Burp Suite which has its own embedded Chromium browser."""
        if not self._burp_path or not os.path.isfile(self._burp_path):
            QMessageBox.warning(
                self, "Burp Suite Not Found",
                "Burp Suite executable not found. Use 'Set Burp Path' to locate it."
            )
            return

        host = self._host_edit.text().strip() or "127.0.0.1"
        port = self._port_edit.text().strip() or "8888"

        try:
            subprocess.Popen(
                [self._burp_path],
                creationflags=subprocess.DETACHED_PROCESS
                    | subprocess.CREATE_NEW_PROCESS_GROUP
                    | subprocess.CREATE_NO_WINDOW,
            )
            QMessageBox.information(
                self, "Burp Suite Launched",
                f"Burp Suite is starting.\n\n"
                f"1. In Burp Suite, go to Proxy → Options\n"
                f"2. Set the proxy listener to {host}:{port}\n"
                f"   (or keep Burp's default 127.0.0.1:8080)\n"
                f"3. Open Burp's built-in browser from Proxy → Intercept → Open Browser\n"
                f"4. All HTTP traffic will appear in VortexIntruder's proxy tab\n\n"
                f"Tip: You can set VortexIntruder's proxy port to 8080 to match Burp's default,\n"
                f"or configure Burp's upstream proxy to forward to {host}:{port}."
            )
        except Exception as exc:
            QMessageBox.critical(self, "Launch Error", f"Failed to start Burp Suite:\n{exc}")

    def _open_system_browser(self) -> None:
        """Open system default browser with a hint about proxy configuration."""
        host = self._host_edit.text().strip() or "127.0.0.1"
        port = self._port_edit.text().strip() or "8888"

        if not (self._worker and self._worker.isRunning()):
            reply = QMessageBox.question(
                self, "Proxy Not Running",
                "The proxy is not running. Start it first?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._start_proxy()
            else:
                return

        # Try to open Chrome with proxy flags – most common browser, best proxy flag support
        chrome_paths = [
            os.path.expandvars(r"%PROGRAMFILES%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%PROGRAMFILES(X86)%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        ]

        chrome = None
        for p in chrome_paths:
            if os.path.isfile(p):
                chrome = p
                break

        if chrome:
            try:
                subprocess.Popen(
                    [
                        chrome,
                        f"--proxy-server=http://{host}:{port}",
                        "--ignore-certificate-errors",
                        "--new-window",
                        "http://example.com",
                    ],
                    creationflags=subprocess.DETACHED_PROCESS
                        | subprocess.CREATE_NEW_PROCESS_GROUP
                        | subprocess.CREATE_NO_WINDOW,
                )
                return
            except Exception:
                pass

        # Fallback: open default browser and show instructions
        import webbrowser
        webbrowser.open("http://example.com")
        QMessageBox.information(
            self, "Configure Browser Proxy",
            f"Configure your browser's proxy settings:\n\n"
            f"  HTTP Proxy:  {host}\n"
            f"  Port:        {port}\n\n"
            f"All HTTP traffic through this proxy will be captured below."
        )

    # -------------------------------------------------------------- TRAFFIC CAPTURE

    def _on_request_captured(self, entry: ProxiedRequest) -> None:
        self._entries.append(entry)
        self._add_table_row(entry)
        self._count_label.setText(f"{len(self._entries)} requests")

    def _add_table_row(self, entry: ProxiedRequest) -> None:
        # Check filter
        filt = self._filter_edit.text().strip().lower()
        if filt:
            searchable = f"{entry.method} {entry.host} {entry.url}".lower()
            if filt not in searchable:
                return

        row = self._table.rowCount()
        self._table.insertRow(row)

        items = [
            str(entry.index),
            entry.timestamp,
            entry.method,
            entry.host,
            entry.url,
            str(entry.status_code),
            str(entry.content_length),
            str(entry.elapsed_ms),
        ]

        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)

            # Color-code status
            if col == 5:
                code = entry.status_code
                if 200 <= code < 300:
                    item.setForeground(QColor("#4ecca3"))
                elif 300 <= code < 400:
                    item.setForeground(QColor("#f1c40f"))
                elif 400 <= code < 500:
                    item.setForeground(QColor("#e67e22"))
                elif code >= 500:
                    item.setForeground(QColor("#e74c3c"))

            # Color-code methods
            if col == 2:
                if entry.method in ("POST", "PUT", "PATCH", "DELETE"):
                    item.setForeground(QColor("#e94560"))
                else:
                    item.setForeground(QColor("#4ecca3"))

            self._table.setItem(row, col, item)

        # Auto-scroll to latest
        self._table.scrollToBottom()

    # -------------------------------------------------------------- DETAIL VIEW

    def _on_row_selected(self, row: int, col: int, prev_row: int, prev_col: int) -> None:
        if row < 0:
            return

        # Find the entry by index stored in col 0
        idx_item = self._table.item(row, 0)
        if not idx_item:
            return
        try:
            idx = int(idx_item.text())
        except ValueError:
            return

        entry = None
        for e in self._entries:
            if e.index == idx:
                entry = e
                break
        if not entry:
            return

        # Show request
        req_text = entry.request_headers
        if entry.request_body:
            req_text += "\r\n\r\n" + entry.request_body
        self._req_viewer.setPlainText(req_text)

        # Show response
        resp_text = f"HTTP/1.1 {entry.status_code}\r\n"
        resp_text += entry.response_headers
        if entry.response_body:
            # Try pretty-print JSON
            resp_body = entry.response_body
            if "json" in entry.content_type.lower():
                try:
                    parsed = json.loads(resp_body)
                    resp_body = json.dumps(parsed, indent=2, ensure_ascii=False)
                except Exception:
                    pass
            resp_text += "\r\n\r\n" + resp_body
        self._resp_viewer.setPlainText(resp_text)

    # -------------------------------------------------------------- CONTEXT MENU

    def _context_menu(self, pos) -> None:
        row = self._table.currentRow()
        if row < 0:
            return

        menu = QMenu(self)

        act_repeater = QAction("Send to Repeater", self)
        act_repeater.triggered.connect(lambda: self._send_selected_to_repeater())
        menu.addAction(act_repeater)

        act_copy_url = QAction("Copy URL", self)
        act_copy_url.triggered.connect(lambda: self._copy_cell(row, 4))
        menu.addAction(act_copy_url)

        act_copy_req = QAction("Copy Request", self)
        act_copy_req.triggered.connect(lambda: self._copy_request(row))
        menu.addAction(act_copy_req)

        menu.exec(self._table.viewport().mapToGlobal(pos))

    def _copy_cell(self, row: int, col: int) -> None:
        item = self._table.item(row, col)
        if item:
            QApplication.clipboard().setText(item.text())

    def _copy_request(self, row: int) -> None:
        idx_item = self._table.item(row, 0)
        if not idx_item:
            return
        try:
            idx = int(idx_item.text())
        except ValueError:
            return
        for e in self._entries:
            if e.index == idx:
                text = e.request_headers
                if e.request_body:
                    text += "\r\n\r\n" + e.request_body
                QApplication.clipboard().setText(text)
                break

    def _send_selected_to_repeater(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        idx_item = self._table.item(row, 0)
        if not idx_item:
            return
        try:
            idx = int(idx_item.text())
        except ValueError:
            return
        for e in self._entries:
            if e.index == idx:
                text = e.request_headers
                if e.request_body:
                    text += "\r\n\r\n" + e.request_body
                self.send_to_repeater.emit(text)
                break

    # -------------------------------------------------------------- FILTER / CLEAR

    def _apply_filter(self, text: str) -> None:
        """Rebuild the table based on the current filter."""
        self._table.setRowCount(0)
        for entry in self._entries:
            self._add_table_row(entry)

    def _clear_table(self) -> None:
        self._entries.clear()
        self._table.setRowCount(0)
        self._req_viewer.clear()
        self._resp_viewer.clear()
        self._count_label.setText("0 requests")

    # -------------------------------------------------------------- CLEANUP

    def cleanup(self) -> None:
        """Stop proxy server on shutdown."""
        if self._worker and self._worker.isRunning():
            self._worker.stop()
