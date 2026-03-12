"""
VortexIntruder v1.0 – Diff Dialog
Side-by-side response comparison dialog using Python's difflib.
"""
from __future__ import annotations

import difflib

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QTextCharFormat
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
)


class DiffDialog(QDialog):
    """Side-by-side response diff dialog."""

    def __init__(
        self,
        body1: str,
        body2: str,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("VortexIntruder – Response Diff")
        self.setMinimumSize(1000, 600)
        self._build_ui(body1, body2)

    def _build_ui(self, body1: str, body2: str) -> None:
        layout = QVBoxLayout(self)

        # Header
        header = QHBoxLayout()
        header.addWidget(QLabel("Response A"))
        header.addWidget(QLabel("Response B"))
        layout.addLayout(header)

        # Side-by-side editors
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.left_edit = QTextEdit()
        self.left_edit.setReadOnly(True)
        self.left_edit.setFont(QFont("Consolas", 11))

        self.right_edit = QTextEdit()
        self.right_edit.setReadOnly(True)
        self.right_edit.setFont(QFont("Consolas", 11))

        splitter.addWidget(self.left_edit)
        splitter.addWidget(self.right_edit)
        layout.addWidget(splitter, 1)

        # Unified diff
        layout.addWidget(QLabel("Unified Diff:"))
        self.diff_edit = QPlainTextEdit()
        self.diff_edit.setReadOnly(True)
        self.diff_edit.setFont(QFont("Consolas", 11))
        self.diff_edit.setMaximumHeight(250)
        layout.addWidget(self.diff_edit)

        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)

        # Perform diff
        self._compute_diff(body1, body2)

    def _compute_diff(self, body1: str, body2: str) -> None:
        lines1 = body1.splitlines(keepends=True)
        lines2 = body2.splitlines(keepends=True)

        # Color-code left/right
        self.left_edit.setPlainText(body1)
        self.right_edit.setPlainText(body2)

        # Unified diff
        diff = difflib.unified_diff(
            lines1, lines2,
            fromfile="Response A", tofile="Response B",
            lineterm="",
        )
        diff_text = "\n".join(diff)
        self.diff_edit.setPlainText(diff_text if diff_text else "(No differences)")

        # Highlight changed lines in left/right
        sm = difflib.SequenceMatcher(None, lines1, lines2)
        self._highlight_changes(self.left_edit, lines1, sm.get_opcodes(), side="left")
        self._highlight_changes(self.right_edit, lines2, sm.get_opcodes(), side="right")

    def _highlight_changes(self, editor: QTextEdit, lines: list[str],
                           opcodes: list, side: str) -> None:
        add_fmt = QTextCharFormat()
        add_fmt.setBackground(QColor("#1a3d1a"))
        del_fmt = QTextCharFormat()
        del_fmt.setBackground(QColor("#3d1a1a"))
        chg_fmt = QTextCharFormat()
        chg_fmt.setBackground(QColor("#3d3d1a"))

        cursor = editor.textCursor()
        cursor.movePosition(cursor.MoveOperation.Start)

        for tag, i1, i2, j1, j2 in opcodes:
            if side == "left":
                start, end = i1, i2
            else:
                start, end = j1, j2

            if tag == "equal":
                continue

            fmt = chg_fmt
            if tag == "insert" and side == "right":
                fmt = add_fmt
            elif tag == "delete" and side == "left":
                fmt = del_fmt
            elif tag == "replace":
                fmt = chg_fmt

            # Move cursor to the relevant lines and highlight
            cursor.movePosition(cursor.MoveOperation.Start)
            for _ in range(start):
                cursor.movePosition(cursor.MoveOperation.Down)

            for _ in range(end - start):
                cursor.movePosition(cursor.MoveOperation.StartOfLine)
                cursor.movePosition(
                    cursor.MoveOperation.EndOfLine,
                    cursor.MoveMode.KeepAnchor,
                )
                cursor.mergeCharFormat(fmt)
                cursor.movePosition(cursor.MoveOperation.Down)
