"""
VortexIntruder v1.0 – Request Editor Tab
Raw HTTP request editor with § marker support and syntax highlighting.
"""
from __future__ import annotations

import re

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import (
    QColor,
    QFont,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextDocument,
)
from PyQt6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from engine.parser import MARKER, guess_target_from_raw

_PARAM_VALUE_RE = re.compile(r"([^&=]+)=([^&]*)")
_JSON_VALUE_RE = re.compile(r'("(?:[^"\\]|\\.)*")\s*:\s*("(?:[^"\\]|\\.)*"|\d+(?:\.\d+)?|true|false|null)')
_COOKIE_RE = re.compile(r"([^;=\s]+)=([^;]*)")


# ---------------------------------------------------------------------------
# Syntax Highlighter for HTTP requests
# ---------------------------------------------------------------------------

class HttpHighlighter(QSyntaxHighlighter):
    """Highlight HTTP method, headers, and § markers."""

    def __init__(self, document: QTextDocument) -> None:
        super().__init__(document)

        # HTTP methods
        self._method_fmt = QTextCharFormat()
        self._method_fmt.setForeground(QColor("#e94560"))
        self._method_fmt.setFontWeight(QFont.Weight.Bold)

        # Header names
        self._header_fmt = QTextCharFormat()
        self._header_fmt.setForeground(QColor("#4ecca3"))

        # Header values
        self._value_fmt = QTextCharFormat()
        self._value_fmt.setForeground(QColor("#c9d1d9"))

        # § markers
        self._marker_fmt = QTextCharFormat()
        self._marker_fmt.setForeground(QColor("#ff6b81"))
        self._marker_fmt.setBackground(QColor("#3d1a2e"))
        self._marker_fmt.setFontWeight(QFont.Weight.Bold)

        # URL path
        self._url_fmt = QTextCharFormat()
        self._url_fmt.setForeground(QColor("#f1c40f"))

        self._rules = [
            (re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\b"),
             self._method_fmt),
            (re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)"),
             None),  # Special – URL part
            (re.compile(r"^([A-Za-z][\w-]*):\s*"), self._header_fmt),
            (re.compile(r"§[^§]*§"), self._marker_fmt),
        ]

    def highlightBlock(self, text: str) -> None:
        # Method
        m = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\b", text)
        if m:
            self.setFormat(m.start(), m.end() - m.start(), self._method_fmt)

        # URL in request line
        m = re.match(
            r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)", text
        )
        if m:
            self.setFormat(m.start(2), m.end(2) - m.start(2), self._url_fmt)

        # Header name
        m = re.match(r"^([A-Za-z][\w-]*):", text)
        if m:
            self.setFormat(m.start(1), m.end(1) - m.start(1), self._header_fmt)

        # § markers (can appear anywhere)
        for match in re.finditer(r"§[^§]*§", text):
            self.setFormat(match.start(), match.end() - match.start(), self._marker_fmt)


# ---------------------------------------------------------------------------
# Request Tab Widget
# ---------------------------------------------------------------------------

class RequestTab(QWidget):
    """Target & Request editor tab with § marker management."""

    target_changed = pyqtSignal(str)  # emits host string

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # -- Target override row --
        target_group = QGroupBox("Target")
        target_layout = QHBoxLayout(target_group)
        target_layout.addWidget(QLabel("Host:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText(
            "Auto-detected from Host header  (or override: https://example.com:443)"
        )
        self.target_input.textChanged.connect(self.target_changed.emit)
        target_layout.addWidget(self.target_input)
        layout.addWidget(target_group)

        # -- Request editor --
        editor_group = QGroupBox("Raw HTTP Request")
        editor_layout = QVBoxLayout(editor_group)

        # Button bar
        btn_bar = QHBoxLayout()

        # Method selector
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"])
        self.method_combo.setToolTip("Change HTTP method")
        self.method_combo.setFixedWidth(100)
        self.method_combo.currentTextChanged.connect(self._on_method_changed)

        self.add_marker_btn = QPushButton("Add §")
        self.add_marker_btn.setObjectName("markerButton")
        self.add_marker_btn.setToolTip("Wrap selected text with § markers (payload position)")
        self.add_marker_btn.clicked.connect(self._add_marker)

        self.clear_marker_btn = QPushButton("Clear §")
        self.clear_marker_btn.setToolTip("Remove all § markers")
        self.clear_marker_btn.clicked.connect(self._clear_markers)

        self.auto_detect_btn = QPushButton("Auto-Detect Target")
        self.auto_detect_btn.clicked.connect(self._auto_detect_target)

        self.auto_positions_btn = QPushButton("Auto §")
        self.auto_positions_btn.setObjectName("markerButton")
        self.auto_positions_btn.setToolTip(
            "Auto-detect parameters (URL query, body, cookies, JSON) and wrap values with § markers"
        )
        self.auto_positions_btn.clicked.connect(self._auto_detect_positions)

        self.position_count_label = QLabel("Positions: 0")
        self.position_count_label.setObjectName("statsLabel")

        btn_bar.addWidget(self.method_combo)
        btn_bar.addWidget(self.add_marker_btn)
        btn_bar.addWidget(self.clear_marker_btn)
        btn_bar.addWidget(self.auto_detect_btn)
        btn_bar.addWidget(self.auto_positions_btn)
        btn_bar.addStretch()
        btn_bar.addWidget(self.position_count_label)
        editor_layout.addLayout(btn_bar)

        # Text editor
        self.editor = QPlainTextEdit()
        self.editor.setFont(QFont("Consolas", 12))
        self.editor.setPlaceholderText(
            "Paste your raw HTTP request here...\n\n"
            "Example:\n"
            "POST /login HTTP/1.1\n"
            "Host: example.com\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "\n"
            "username=admin&password=§password§"
        )
        self.editor.setTabStopDistance(32)
        self._highlighter = HttpHighlighter(self.editor.document())
        self.editor.textChanged.connect(self._update_position_count)
        self.editor.textChanged.connect(self._sync_method_combo)
        editor_layout.addWidget(self.editor)

        layout.addWidget(editor_group, 1)

    _METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT")
    _METHOD_RE = re.compile(
        r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)(\s+)",
        re.IGNORECASE,
    )

    def _sync_method_combo(self) -> None:
        """Update method combo to reflect first line of raw request (without triggering replace)."""
        text = self.editor.toPlainText()
        m = self._METHOD_RE.match(text)
        if m:
            method = m.group(1).upper()
            if self.method_combo.currentText() != method:
                self.method_combo.blockSignals(True)
                idx = self.method_combo.findText(method)
                if idx >= 0:
                    self.method_combo.setCurrentIndex(idx)
                self.method_combo.blockSignals(False)

    def _on_method_changed(self, new_method: str) -> None:
        """Replace the HTTP method in the first line of the raw request."""
        text = self.editor.toPlainText()
        new_text = self._METHOD_RE.sub(lambda m: new_method + m.group(2), text, count=1)
        if new_text != text:
            cursor_pos = self.editor.textCursor().position()
            self.editor.blockSignals(True)
            self.editor.setPlainText(new_text)
            self.editor.blockSignals(False)
            # Restore cursor roughly
            cursor = self.editor.textCursor()
            cursor.setPosition(min(cursor_pos, len(new_text)))
            self.editor.setTextCursor(cursor)
            self._update_position_count()

    def _add_marker(self) -> None:
        cursor = self.editor.textCursor()
        if cursor.hasSelection():
            selected = cursor.selectedText()
            cursor.insertText(f"{MARKER}{selected}{MARKER}")
        else:
            cursor.insertText(f"{MARKER}{MARKER}")
        self.editor.setTextCursor(cursor)
        self._update_position_count()

    def _clear_markers(self) -> None:
        text = self.editor.toPlainText()
        self.editor.setPlainText(text.replace(MARKER, ""))
        self._update_position_count()

    def _auto_detect_target(self) -> None:
        raw = self.editor.toPlainText()
        host = guess_target_from_raw(raw)
        if host:
            self.target_input.setText(host)

    def _auto_detect_positions(self) -> None:
        """Auto-detect parameter values in URL query, body, cookies, and JSON and wrap with § markers."""
        raw = self.editor.toPlainText()
        # Remove existing markers first
        raw = raw.replace(MARKER, "")

        # Split request into head (request line + headers) and body
        if "\n\n" in raw:
            head, body = raw.split("\n\n", 1)
        elif "\r\n\r\n" in raw:
            head, body = raw.split("\r\n\r\n", 1)
        else:
            head = raw
            body = ""

        lines = head.split("\n")
        result_lines = []

        for i, line in enumerate(lines):
            if i == 0:
                # Request line: GET /path?key=val&key2=val2 HTTP/1.1
                m = re.match(r'^(\S+\s+)([^\s]+)(\s+HTTP/\S+)?$', line.rstrip('\r'), re.IGNORECASE)
                if m:
                    method_part, path, proto = m.group(1), m.group(2), m.group(3) or ""
                    if "?" in path:
                        base_path, query = path.split("?", 1)
                        new_query = _PARAM_VALUE_RE.sub(
                            lambda pm: f"{pm.group(1)}={MARKER}{pm.group(2)}{MARKER}", query
                        )
                        result_lines.append(f"{method_part}{base_path}?{new_query}{proto}")
                    else:
                        result_lines.append(line)
                else:
                    result_lines.append(line)
            else:
                # Headers — handle Cookie header
                stripped = line.rstrip('\r')
                if stripped.lower().startswith("cookie:"):
                    prefix = stripped[:stripped.index(":") + 1]
                    cookie_val = stripped[len(prefix):].strip()
                    new_cookie = _COOKIE_RE.sub(
                        lambda cm: f"{cm.group(1)}={MARKER}{cm.group(2)}{MARKER}", cookie_val
                    )
                    result_lines.append(f"{prefix} {new_cookie}")
                else:
                    result_lines.append(line)

        new_head = "\n".join(result_lines)

        # Process body
        new_body = body
        if body.strip():
            stripped_body = body.strip()
            if stripped_body.startswith("{") or stripped_body.startswith("["):
                # JSON body — wrap values
                new_body = _JSON_VALUE_RE.sub(
                    lambda jm: f"{jm.group(1)}: {MARKER}{jm.group(2)}{MARKER}", body
                )
            else:
                # Form-encoded body — wrap values
                new_body = _PARAM_VALUE_RE.sub(
                    lambda pm: f"{pm.group(1)}={MARKER}{pm.group(2)}{MARKER}", body
                )

        # Reassemble
        sep = "\r\n\r\n" if "\r\n\r\n" in raw or "\r\n" in head else "\n\n"
        if body or raw.endswith("\n\n") or raw.endswith("\r\n\r\n"):
            result = new_head + sep + new_body
        else:
            result = new_head

        self.editor.setPlainText(result)
        self._update_position_count()

    def _update_position_count(self) -> None:
        text = self.editor.toPlainText()
        count = len(re.findall(r"§[^§]*§", text))
        self.position_count_label.setText(f"Positions: {count}")

    def get_raw_request(self) -> str:
        return self.editor.toPlainText()

    def get_target(self) -> str:
        return self.target_input.text().strip()

    def get_position_count(self) -> int:
        text = self.editor.toPlainText()
        return len(re.findall(r"§[^§]*§", text))

    def set_raw_request(self, text: str) -> None:
        self.editor.setPlainText(text)

    def set_target(self, target: str) -> None:
        self.target_input.setText(target)

    def get_data(self) -> dict:
        return {
            "raw_request": self.get_raw_request(),
            "target": self.get_target(),
        }

    def set_data(self, data: dict) -> None:
        self.set_raw_request(data.get("raw_request", ""))
        self.set_target(data.get("target", ""))
