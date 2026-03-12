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
        self.add_marker_btn = QPushButton("Add §")
        self.add_marker_btn.setObjectName("markerButton")
        self.add_marker_btn.setToolTip("Wrap selected text with § markers (payload position)")
        self.add_marker_btn.clicked.connect(self._add_marker)

        self.clear_marker_btn = QPushButton("Clear §")
        self.clear_marker_btn.setToolTip("Remove all § markers")
        self.clear_marker_btn.clicked.connect(self._clear_markers)

        self.auto_detect_btn = QPushButton("Auto-Detect Target")
        self.auto_detect_btn.clicked.connect(self._auto_detect_target)

        self.position_count_label = QLabel("Positions: 0")
        self.position_count_label.setObjectName("statsLabel")

        btn_bar.addWidget(self.add_marker_btn)
        btn_bar.addWidget(self.clear_marker_btn)
        btn_bar.addWidget(self.auto_detect_btn)
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
        editor_layout.addWidget(self.editor)

        layout.addWidget(editor_group, 1)

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
