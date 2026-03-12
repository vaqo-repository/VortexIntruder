"""
VortexIntruder v1.0 – Logger Tab
Dedicated log viewer for engine events, errors, and filtered status codes.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QTextCharFormat
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class LoggerTab(QWidget):
    """Log viewer tab with severity filtering."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._all_logs: list[str] = []
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # Filter bar
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            "All", "Errors Only", "Timeouts Only",
            "403 Forbidden", "500 Server Error", "INFO",
        ])
        self.filter_combo.currentIndexChanged.connect(self._apply_filter)
        filter_row.addWidget(self.filter_combo)

        self.clear_btn = QPushButton("Clear Log")
        self.clear_btn.clicked.connect(self.clear_log)
        filter_row.addWidget(self.clear_btn)
        filter_row.addStretch()

        self.count_label = QLabel("0 entries")
        self.count_label.setObjectName("statsLabel")
        filter_row.addWidget(self.count_label)

        layout.addLayout(filter_row)

        # Log text area
        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumBlockCount(50000)
        layout.addWidget(self.log_text, 1)

    def append_log(self, message: str) -> None:
        """Add a log entry."""
        self._all_logs.append(message)
        self.count_label.setText(f"{len(self._all_logs)} entries")

        # Check filter
        if self._matches_filter(message):
            self.log_text.appendPlainText(message)

    def clear_log(self) -> None:
        self._all_logs.clear()
        self.log_text.clear()
        self.count_label.setText("0 entries")

    def _apply_filter(self) -> None:
        self.log_text.clear()
        for msg in self._all_logs:
            if self._matches_filter(msg):
                self.log_text.appendPlainText(msg)

    def _matches_filter(self, msg: str) -> bool:
        idx = self.filter_combo.currentIndex()
        if idx == 0:
            return True
        if idx == 1:
            return "ERROR" in msg or "FATAL" in msg
        if idx == 2:
            return "TIMEOUT" in msg
        if idx == 3:
            return "403" in msg
        if idx == 4:
            return "500" in msg
        if idx == 5:
            return "INFO" in msg or "DONE" in msg
        return True
