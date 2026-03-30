"""
VortexIntruder – Advanced Tools Tab
Embedded terminal + sandboxed security tool execution.
Tools run inside Docker containers or process-jailed environments.
"""
from __future__ import annotations

import os
import re
import tempfile

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QKeyEvent, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from engine.sandbox import (
    DockerBuildThread,
    SandboxedRunThread,
    ToolDownloadThread,
    TOOL_REGISTRY,
    is_docker_available,
    is_tool_downloaded,
    docker_image_exists,
)

# ---------------------------------------------------------------------------
# ANSI color codes → QTextCharFormat mapping
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")

_ANSI_COLORS = {
    30: "#888888", 31: "#e84545", 32: "#4ecca3", 33: "#e8b86d",
    34: "#5599ff", 35: "#c678dd", 36: "#56b6c2", 37: "#cccccc",
    90: "#666666", 91: "#ff6b6b", 92: "#69f0ae", 93: "#ffd54f",
    94: "#82b1ff", 95: "#ea80fc", 96: "#84ffff", 97: "#ffffff",
}


class TerminalOutput(QTextEdit):
    """Rich-text terminal output widget with ANSI color support."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 10))
        self.setStyleSheet(
            "QTextEdit { background: #1a1a2e; color: #cccccc; "
            "border: 1px solid #333; padding: 4px; }"
        )
        self._default_fmt = QTextCharFormat()
        self._default_fmt.setForeground(QColor("#cccccc"))
        self._current_fmt = QTextCharFormat(self._default_fmt)

    def append_ansi(self, text: str):
        """Append text with ANSI escape code parsing."""
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        parts = _ANSI_RE.split(text)
        # parts alternates: text, ansi_code, text, ansi_code, ...
        for i, part in enumerate(parts):
            if i % 2 == 0:
                # Regular text
                if part:
                    cursor.insertText(part, self._current_fmt)
            else:
                # ANSI code
                self._apply_ansi(part)

        cursor.insertText("\n", self._current_fmt)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def _apply_ansi(self, code_str: str):
        if not code_str or code_str == "0":
            self._current_fmt = QTextCharFormat(self._default_fmt)
            return
        for code in code_str.split(";"):
            try:
                c = int(code)
            except ValueError:
                continue
            if c == 0:
                self._current_fmt = QTextCharFormat(self._default_fmt)
            elif c == 1:
                self._current_fmt.setFontWeight(QFont.Weight.Bold)
            elif c in _ANSI_COLORS:
                self._current_fmt.setForeground(QColor(_ANSI_COLORS[c]))


# ---------------------------------------------------------------------------
# SQLMap presets
# ---------------------------------------------------------------------------

SQLMAP_PRESETS: dict[str, list[str]] = {
    "(Custom)": [],
    "Basic Detection": ["--batch", "--smart"],
    "Full Auto": ["--batch", "--level=5", "--risk=3", "--random-agent"],
    "Database Enumeration": ["--batch", "--dbs"],
    "Table Dump": ["--batch", "--tables"],
    "WAF Bypass": ["--batch", "--tamper=between,randomcase,space2comment", "--random-agent"],
    "POST Form": ["--batch", "--level=3"],
    "Cookie Injection": ["--batch", "--level=3"],
    "Time-Based Blind": ["--batch", "--technique=T", "--time-sec=5"],
    "OS Shell": ["--batch", "--os-shell"],
}


# ---------------------------------------------------------------------------
# SQLMap Widget
# ---------------------------------------------------------------------------

class SQLMapWidget(QWidget):
    """SQLMap configuration panel with embedded terminal output."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._download_thread: ToolDownloadThread | None = None
        self._docker_build_thread: DockerBuildThread | None = None
        self._run_thread: SandboxedRunThread | None = None
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        root.setSpacing(0)

        # ── Status bar ──────────────────────────────────────────────
        status_frame = QFrame()
        status_frame.setStyleSheet(
            "QFrame { background: #16213e; border: 1px solid #333; "
            "border-radius: 4px; padding: 4px 8px; }"
        )
        status_row = QHBoxLayout(status_frame)
        status_row.setContentsMargins(4, 2, 4, 2)
        status_row.setSpacing(8)

        self.status_label = QLabel("Checking environment...")
        self.status_label.setStyleSheet("font-weight: bold;")
        status_row.addWidget(self.status_label, 1)

        self.download_btn = QPushButton("Download SQLMap")
        self.download_btn.setFixedHeight(26)
        self.download_btn.clicked.connect(self._download_tool)
        status_row.addWidget(self.download_btn)

        self.docker_btn = QPushButton("Build Docker Image")
        self.docker_btn.setFixedHeight(26)
        self.docker_btn.setToolTip("Build isolated Docker container (optional, best security)")
        self.docker_btn.clicked.connect(self._build_docker)
        status_row.addWidget(self.docker_btn)
        root.addWidget(status_frame)
        root.addSpacing(4)

        # ── Collapsible config area ─────────────────────────────────
        self._config_widget = QWidget()
        config_layout = QVBoxLayout(self._config_widget)
        config_layout.setContentsMargins(0, 0, 0, 0)
        config_layout.setSpacing(4)

        # ---- Target group ----
        self.target_tabs = QTabWidget()
        self.target_tabs.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #333; }"
        )

        # URL Mode
        url_page = QWidget()
        ul = QVBoxLayout(url_page)
        ul.setContentsMargins(8, 8, 8, 4)
        ul.setSpacing(4)

        for label_text, attr, placeholder in (
            ("URL:", "url_input", "http://target.com/page?id=1"),
            ("POST Data:", "post_data_input", "username=admin&password=test  (optional)"),
            ("Cookie:", "cookie_input", "PHPSESSID=abc123  (optional)"),
        ):
            row = QHBoxLayout()
            lbl = QLabel(label_text)
            lbl.setFixedWidth(70)
            row.addWidget(lbl)
            inp = QLineEdit()
            inp.setPlaceholderText(placeholder)
            inp.setFixedHeight(26)
            setattr(self, attr, inp)
            row.addWidget(inp, 1)
            ul.addLayout(row)

        self.target_tabs.addTab(url_page, "  URL Mode  ")

        # Raw Request Mode
        raw_page = QWidget()
        rl = QVBoxLayout(raw_page)
        rl.setContentsMargins(8, 4, 8, 4)
        rl.setSpacing(2)

        raw_hint = QLabel("Paste full HTTP request (Burp Suite / dev tools):")
        raw_hint.setStyleSheet("color: #888; font-size: 11px;")
        rl.addWidget(raw_hint)

        self.raw_request_input = QPlainTextEdit()
        self.raw_request_input.setPlaceholderText(
            "GET /page?id=1 HTTP/1.1\n"
            "Host: target.com\n"
            "Cookie: PHPSESSID=abc123\n"
            "User-Agent: Mozilla/5.0 ...\n"
            "\n"
            "username=admin&password=test"
        )
        self.raw_request_input.setFont(QFont("Consolas", 10))
        self.raw_request_input.setStyleSheet(
            "QPlainTextEdit { background: #1a1a2e; color: #e8b86d; "
            "border: 1px solid #333; padding: 4px; }"
        )
        self.raw_request_input.setMinimumHeight(80)
        rl.addWidget(self.raw_request_input, 1)
        self.target_tabs.addTab(raw_page, "  Raw Request  ")

        config_layout.addWidget(self.target_tabs)
        self._raw_request_file: str | None = None

        # ---- Options (compact grid) ----
        opts = QGroupBox("Options")
        opts.setStyleSheet(
            "QGroupBox { font-weight: bold; padding-top: 14px; margin-top: 4px; }"
        )
        ol = QVBoxLayout(opts)
        ol.setContentsMargins(8, 4, 8, 4)
        ol.setSpacing(3)

        # Preset row
        p_row = QHBoxLayout()
        p_row.addWidget(QLabel("Preset:"))
        self.preset_combo = QComboBox()
        self.preset_combo.setFixedHeight(26)
        for name in SQLMAP_PRESETS:
            self.preset_combo.addItem(name)
        self.preset_combo.currentTextChanged.connect(self._on_preset_changed)
        p_row.addWidget(self.preset_combo, 1)
        ol.addLayout(p_row)

        # Checkbox row 1
        c1 = QHBoxLayout()
        self.chk_batch = QCheckBox("--batch")
        self.chk_batch.setChecked(True)
        self.chk_random_agent = QCheckBox("--random-agent")
        self.chk_random_agent.setChecked(True)
        self.chk_dbs = QCheckBox("--dbs")
        self.chk_verbose = QCheckBox("-v 3")
        self.chk_forms = QCheckBox("--forms")
        self.chk_crawl = QCheckBox("--crawl=2")
        self.chk_threads = QCheckBox("--threads=5")
        self.chk_force_ssl = QCheckBox("--force-ssl")
        self.chk_force_ssl.setChecked(True)
        for cb in (self.chk_batch, self.chk_random_agent, self.chk_dbs,
                   self.chk_verbose, self.chk_forms, self.chk_crawl,
                   self.chk_threads, self.chk_force_ssl):
            c1.addWidget(cb)
        c1.addStretch()
        ol.addLayout(c1)

        # Level / Risk / Tamper row
        lr = QHBoxLayout()
        lr.addWidget(QLabel("Level:"))
        self.level_combo = QComboBox()
        self.level_combo.addItems(["1", "2", "3", "4", "5"])
        self.level_combo.setFixedWidth(55)
        self.level_combo.setFixedHeight(26)
        lr.addWidget(self.level_combo)
        lr.addSpacing(10)
        lr.addWidget(QLabel("Risk:"))
        self.risk_combo = QComboBox()
        self.risk_combo.addItems(["1", "2", "3"])
        self.risk_combo.setFixedWidth(55)
        self.risk_combo.setFixedHeight(26)
        lr.addWidget(self.risk_combo)
        lr.addSpacing(10)
        lr.addWidget(QLabel("Tamper:"))
        self.tamper_input = QLineEdit()
        self.tamper_input.setPlaceholderText("between,randomcase,space2comment")
        self.tamper_input.setFixedHeight(26)
        lr.addWidget(self.tamper_input, 1)
        ol.addLayout(lr)

        # Extra flags
        ef = QHBoxLayout()
        ef.addWidget(QLabel("Extra:"))
        self.extra_flags_input = QLineEdit()
        self.extra_flags_input.setPlaceholderText("--technique=BEU --prefix=')'")
        self.extra_flags_input.setFixedHeight(26)
        ef.addWidget(self.extra_flags_input, 1)
        ol.addLayout(ef)

        config_layout.addWidget(opts)

        # ---- Command preview ----
        cmd_row = QHBoxLayout()
        cmd_row.setSpacing(6)
        cmd_lbl = QLabel("Cmd:")
        cmd_lbl.setStyleSheet("font-weight: bold; color: #888;")
        cmd_row.addWidget(cmd_lbl)
        self.cmd_preview = QLineEdit()
        self.cmd_preview.setReadOnly(True)
        self.cmd_preview.setFixedHeight(26)
        self.cmd_preview.setStyleSheet(
            "color: #4ecca3; font-family: Consolas; background: #0f0f23; "
            "border: 1px solid #333; padding: 2px 6px;"
        )
        cmd_row.addWidget(self.cmd_preview, 1)
        config_layout.addLayout(cmd_row)

        # ---- Action buttons ----
        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        self.run_btn = QPushButton("▶ Run SQLMap")
        self.run_btn.setObjectName("startButton")
        self.run_btn.setFixedHeight(30)
        self.run_btn.setEnabled(False)
        self.run_btn.clicked.connect(self._run_sqlmap)
        self.stop_btn = QPushButton("■ Stop")
        self.stop_btn.setObjectName("stopButton")
        self.stop_btn.setFixedHeight(30)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_sqlmap)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setFixedHeight(30)
        self.clear_btn.clicked.connect(lambda: self.terminal.clear())
        btn_row.addWidget(self.run_btn)
        btn_row.addWidget(self.stop_btn)
        btn_row.addWidget(self.clear_btn)
        btn_row.addStretch()
        config_layout.addLayout(btn_row)

        root.addWidget(self._config_widget)
        root.addSpacing(2)

        # ── Terminal header + toggle ────────────────────────────────
        header_bar = QFrame()
        header_bar.setStyleSheet(
            "QFrame { background: #16213e; border: 1px solid #333; "
            "border-bottom: none; border-radius: 0; }"
        )
        hbl = QHBoxLayout(header_bar)
        hbl.setContentsMargins(8, 2, 4, 2)
        hbl.setSpacing(0)

        term_label = QLabel("Sandboxed Terminal")
        term_label.setStyleSheet(
            "color: #4ecca3; font-family: Consolas; "
            "font-size: 12px; font-weight: bold;"
        )
        hbl.addWidget(term_label, 1)

        self.toggle_config_btn = QPushButton("▲ Hide Config")
        self.toggle_config_btn.setFixedSize(120, 22)
        self.toggle_config_btn.setStyleSheet(
            "QPushButton { background: #0f3460; color: #e8b86d; "
            "font-family: Consolas; font-size: 11px; font-weight: bold; "
            "border: 1px solid #444; border-radius: 3px; padding: 1px 8px; }"
            "QPushButton:hover { background: #1a4a7a; }"
        )
        self.toggle_config_btn.clicked.connect(self._toggle_config)
        hbl.addWidget(self.toggle_config_btn)

        root.addWidget(header_bar)

        # ── Terminal output ─────────────────────────────────────────
        self.terminal = TerminalOutput()
        root.addWidget(self.terminal, 1)

        # ── Wire signals ────────────────────────────────────────────
        for w in (self.url_input, self.post_data_input, self.cookie_input,
                  self.tamper_input, self.extra_flags_input):
            w.textChanged.connect(self._update_cmd)
        self.raw_request_input.textChanged.connect(self._update_cmd)
        self.target_tabs.currentChanged.connect(self._update_cmd)
        for w in (self.chk_batch, self.chk_random_agent, self.chk_dbs,
                  self.chk_verbose, self.chk_forms, self.chk_crawl,
                  self.chk_threads, self.chk_force_ssl):
            w.toggled.connect(self._update_cmd)
        self.level_combo.currentTextChanged.connect(self._update_cmd)
        self.risk_combo.currentTextChanged.connect(self._update_cmd)

        QTimer.singleShot(300, self._refresh_status)

    # ------------------------------------------------------------------ Toggle

    def _toggle_config(self):
        visible = self._config_widget.isVisible()
        self._config_widget.setVisible(not visible)
        if visible:
            self.toggle_config_btn.setText("▼ Show Config")
        else:
            self.toggle_config_btn.setText("▲ Hide Config")

    # ------------------------------------------------------------------ Status

    def _refresh_status(self):
        parts = []
        downloaded = is_tool_downloaded("sqlmap")
        docker_ok, _ = is_docker_available()
        has_docker_img = docker_ok and docker_image_exists(
            TOOL_REGISTRY["sqlmap"]["docker_image"]
        )

        if has_docker_img:
            parts.append("Docker sandbox: Ready")
            self.status_label.setStyleSheet("color: #4ecca3; font-weight: bold;")
            self.run_btn.setEnabled(True)
            self.download_btn.setEnabled(True)
            self.docker_btn.setText("Rebuild Docker Image")
        elif downloaded:
            if docker_ok:
                parts.append("SQLMap: Downloaded | Docker: available (image not built)")
                self.docker_btn.setEnabled(True)
            else:
                parts.append("SQLMap: Downloaded | Mode: Process Jail")
                self.docker_btn.setEnabled(False)
            self.status_label.setStyleSheet("color: #e8b86d; font-weight: bold;")
            self.run_btn.setEnabled(True)
            self.download_btn.setText("Re-download")
        else:
            parts.append("SQLMap: Not downloaded")
            self.status_label.setStyleSheet("color: #e84545; font-weight: bold;")
            self.run_btn.setEnabled(False)
            self.download_btn.setText("Download SQLMap")
            self.docker_btn.setEnabled(docker_ok)

        self.status_label.setText(" | ".join(parts))

    # ------------------------------------------------------------------ Download

    def _download_tool(self):
        self.download_btn.setEnabled(False)
        self.terminal.clear()
        self._download_thread = ToolDownloadThread("sqlmap")
        self._download_thread.log_line.connect(self.terminal.append_ansi)
        self._download_thread.finished_signal.connect(self._on_download_done)
        self._download_thread.start()

    def _on_download_done(self, ok: bool, msg: str):
        self.download_btn.setEnabled(True)
        if not ok:
            self.terminal.append_ansi(f"\x1b[31m[ERROR] {msg}\x1b[0m")
        self._refresh_status()
        self._download_thread = None

    # ------------------------------------------------------------------ Docker

    def _build_docker(self):
        self.docker_btn.setEnabled(False)
        self.terminal.clear()
        self._docker_build_thread = DockerBuildThread("sqlmap")
        self._docker_build_thread.log_line.connect(self.terminal.append_ansi)
        self._docker_build_thread.finished_signal.connect(self._on_docker_done)
        self._docker_build_thread.start()

    def _on_docker_done(self, ok: bool, msg: str):
        self.docker_btn.setEnabled(True)
        if not ok:
            self.terminal.append_ansi(f"\x1b[31m[ERROR] {msg}\x1b[0m")
        self._refresh_status()
        self._docker_build_thread = None

    # ------------------------------------------------------------------ Run

    def _is_raw_mode(self) -> bool:
        return self.target_tabs.currentIndex() == 1

    def _save_raw_request(self) -> str | None:
        """Save raw request to a temp file and return path."""
        raw = self.raw_request_input.toPlainText().strip()
        if not raw:
            return None
        # SQLMap only supports HTTP/1.x — downgrade HTTP/2 if present
        raw = raw.replace(" HTTP/2\r\n", " HTTP/1.1\r\n")
        raw = raw.replace(" HTTP/2\n", " HTTP/1.1\n")
        # HTTP requests MUST end with a blank line after headers
        if not raw.endswith("\n\n"):
            raw += "\r\n\r\n"
        # Clean up old file
        self._cleanup_raw_file()
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="vortex_req_")
        with os.fdopen(fd, "wb") as f:
            # Write with CRLF line endings (HTTP standard)
            f.write(raw.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8"))
        self._raw_request_file = path
        return path

    def _cleanup_raw_file(self):
        if self._raw_request_file and os.path.exists(self._raw_request_file):
            try:
                os.remove(self._raw_request_file)
            except OSError:
                pass
            self._raw_request_file = None

    def _build_args(self) -> list[str]:
        args: list[str] = []

        if self._is_raw_mode():
            # Raw request mode — use -r flag (file saved at run time)
            args.append("-r")
            args.append("<request_file>")
        else:
            url = self.url_input.text().strip()
            if url:
                # Auto-add https:// if no scheme
                if url and not url.startswith(("http://", "https://")):
                    url = "https://" + url
                args.extend(["-u", url])
            post = self.post_data_input.text().strip()
            if post:
                args.extend(["--data", post])
            cookie = self.cookie_input.text().strip()
            if cookie:
                args.extend(["--cookie", cookie])
        if self.chk_batch.isChecked():
            args.append("--batch")
        if self.chk_random_agent.isChecked():
            args.append("--random-agent")
        if self.chk_dbs.isChecked():
            args.append("--dbs")
        if self.chk_verbose.isChecked():
            args.extend(["-v", "3"])
        if self.chk_force_ssl.isChecked():
            args.append("--force-ssl")
        if self.chk_forms.isChecked():
            args.append("--forms")
        if self.chk_crawl.isChecked():
            args.append("--crawl=2")
        if self.chk_threads.isChecked():
            args.append("--threads=5")
        level = self.level_combo.currentText()
        if level != "1":
            args.append(f"--level={level}")
        risk = self.risk_combo.currentText()
        if risk != "1":
            args.append(f"--risk={risk}")
        tamper = self.tamper_input.text().strip()
        if tamper:
            args.extend(["--tamper", tamper])
        extra = self.extra_flags_input.text().strip()
        if extra:
            args.extend(extra.split())
        return args

    def _update_cmd(self):
        self.cmd_preview.setText(f"sqlmap {' '.join(self._build_args())}")

    def _on_preset_changed(self, name: str):
        if name == "(Custom)":
            return
        self.chk_batch.setChecked(False)
        self.chk_random_agent.setChecked(False)
        self.chk_dbs.setChecked(False)
        self.chk_verbose.setChecked(False)
        self.chk_forms.setChecked(False)
        self.chk_crawl.setChecked(False)
        self.chk_threads.setChecked(False)
        # Keep --force-ssl as-is (user intention)
        self.level_combo.setCurrentText("1")
        self.risk_combo.setCurrentText("1")
        self.tamper_input.clear()
        self.extra_flags_input.clear()

        extra: list[str] = []
        for f in SQLMAP_PRESETS[name]:
            if f == "--batch":
                self.chk_batch.setChecked(True)
            elif f == "--random-agent":
                self.chk_random_agent.setChecked(True)
            elif f == "--dbs":
                self.chk_dbs.setChecked(True)
            elif f == "--forms":
                self.chk_forms.setChecked(True)
            elif f.startswith("--level="):
                self.level_combo.setCurrentText(f.split("=")[1])
            elif f.startswith("--risk="):
                self.risk_combo.setCurrentText(f.split("=")[1])
            elif f.startswith("--tamper="):
                self.tamper_input.setText(f.split("=", 1)[1])
            else:
                extra.append(f)
        if extra:
            self.extra_flags_input.setText(" ".join(extra))
        self._update_cmd()

    def _run_sqlmap(self):
        if self._is_raw_mode():
            raw = self.raw_request_input.toPlainText().strip()
            if not raw:
                QMessageBox.warning(self, "No Request", "Please paste a raw HTTP request.")
                return
            req_file = self._save_raw_request()
            if not req_file:
                return
            args = self._build_args()
            # Replace placeholder with actual temp file path
            args = [req_file if a == "<request_file>" else a for a in args]
            # Debug: show file details in terminal
            try:
                with open(req_file, "rb") as _dbg:
                    _bytes = _dbg.read()
                _first = _bytes.split(b"\r\n")[0].decode("utf-8", errors="replace")
                self.terminal.append_ansi(
                    f"\x1b[36m[RAW REQUEST] Saved to: {req_file}  "
                    f"({len(_bytes)} bytes)\x1b[0m"
                )
                self.terminal.append_ansi(
                    f"\x1b[36m[RAW REQUEST] Line 1: {_first}\x1b[0m"
                )
                _crlf_end = _bytes.endswith(b"\r\n\r\n")
                self.terminal.append_ansi(
                    f"\x1b[36m[RAW REQUEST] Ends with CRLF+CRLF: "
                    f"{_crlf_end}\x1b[0m"
                )
            except Exception as _e:
                self.terminal.append_ansi(
                    f"\x1b[31m[RAW REQUEST] Debug error: {_e}\x1b[0m"
                )
        else:
            url = self.url_input.text().strip()
            if not url:
                QMessageBox.warning(self, "No Target", "Please enter a target URL.")
                return
            args = self._build_args()
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.terminal.clear()

        self._run_thread = SandboxedRunThread("sqlmap", args)
        self._run_thread.output_line.connect(self.terminal.append_ansi)
        self._run_thread.finished_signal.connect(self._on_run_done)
        self._run_thread.start()

    def _stop_sqlmap(self):
        if self._run_thread:
            self._run_thread.stop()

    def _on_run_done(self, code: int, msg: str):
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._run_thread = None
        self._cleanup_raw_file()

    def set_target_url(self, url: str):
        self.url_input.setText(url)


# ---------------------------------------------------------------------------
# Advanced Tools Tab
# ---------------------------------------------------------------------------

class AdvancedToolsTab(QWidget):
    """Container tab for sandboxed security tools."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        info = QLabel(
            "All tools run in a sandbox (Docker container or process jail) — "
            "isolated from host filesystem, restricted memory, stripped environment. "
            "Safe for untrusted tools."
        )
        info.setStyleSheet("color: #888; font-style: italic; padding: 4px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        self.sub_tabs = QTabWidget()
        self.sqlmap_widget = SQLMapWidget()
        self.sub_tabs.addTab(self.sqlmap_widget, "SQLMap")
        layout.addWidget(self.sub_tabs, 1)
