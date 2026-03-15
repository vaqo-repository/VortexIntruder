"""
VortexIntruder v1.0 – Results Tab
Real-time results table with filtering, context menu, and response viewer.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QAction, QBrush, QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from engine.fuzzer import FuzzResult, export_results_csv, export_results_json
from gui.styles import GREP_MATCH_COLOR, GREP_MATCH_FG


COLUMNS = [
    "#", "Payload", "Status", "Length", "Time (ms)",
    "Grep Extract", "Comment",
]


class ResultsTab(QWidget):
    """Results display tab with filtering and export."""

    send_to_request = pyqtSignal(str)  # raw request text for re-fuzzing
    send_to_repeater = pyqtSignal(str)  # raw request text for repeater
    compare_responses = pyqtSignal(str, str)  # two response bodies for diff

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._results: list[FuzzResult] = []
        self._baseline_length: int | None = None
        self._baseline_status: int | None = None
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # -- Dashboard stats row --
        dash = QHBoxLayout()
        self.rps_label = QLabel("RPS: 0")
        self.rps_label.setObjectName("statsLabel")
        self.error_label = QLabel("Errors: 0%")
        self.error_label.setObjectName("statsLabel")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)

        dash.addWidget(self.rps_label)
        dash.addWidget(self.error_label)
        dash.addWidget(self.progress_bar, 1)
        layout.addLayout(dash)

        # -- Filter bar --
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText(
            "Filter by status code, payload text, or grep extract..."
        )
        self.filter_input.textChanged.connect(self._apply_filter)
        filter_row.addWidget(self.filter_input)

        self.clear_results_btn = QPushButton("Clear All")
        self.clear_results_btn.clicked.connect(self.clear_results)
        filter_row.addWidget(self.clear_results_btn)

        self.export_csv_btn = QPushButton("Export CSV")
        self.export_csv_btn.clicked.connect(self._export_csv)
        filter_row.addWidget(self.export_csv_btn)

        self.export_json_btn = QPushButton("Export JSON")
        self.export_json_btn.clicked.connect(self._export_json)
        filter_row.addWidget(self.export_json_btn)

        layout.addLayout(filter_row)

        # -- Splitter: table + response viewer --
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.currentCellChanged.connect(self._on_row_selected)

        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)

        # Set reasonable default column widths
        self.table.setColumnWidth(0, 50)   # #
        self.table.setColumnWidth(1, 200)  # Payload
        self.table.setColumnWidth(2, 60)   # Status
        self.table.setColumnWidth(3, 70)   # Length
        self.table.setColumnWidth(4, 75)   # Time
        self.table.setColumnWidth(5, 130)  # Grep Extract
        # col 6 (Comment) stretches

        splitter.addWidget(self.table)

        # Request / Response viewer tabs
        viewer_tabs = QTabWidget()

        self.request_viewer = QPlainTextEdit()
        self.request_viewer.setReadOnly(True)
        self.request_viewer.setPlaceholderText("Select a row to view the request...")
        viewer_tabs.addTab(self.request_viewer, "Request")

        self.response_viewer = QPlainTextEdit()
        self.response_viewer.setReadOnly(True)
        self.response_viewer.setPlaceholderText("Select a row to view the response...")
        viewer_tabs.addTab(self.response_viewer, "Response")

        splitter.addWidget(viewer_tabs)
        splitter.setSizes([500, 200])

        layout.addWidget(splitter, 1)

    # -- public API --

    def add_result(self, result: FuzzResult) -> None:
        """Add a single result row to the table."""
        self._results.append(result)

        # Track baseline from first successful response
        if self._baseline_length is None and result.status_code > 0:
            self._baseline_length = result.length
            self._baseline_status = result.status_code

        # Generate auto-comment
        comment = self._auto_comment(result)

        self.table.setSortingEnabled(False)
        row = self.table.rowCount()
        self.table.insertRow(row)

        items = [
            self._num_item(result.request_id),
            QTableWidgetItem(result.payload),
            self._num_item(result.status_code),
            self._num_item(result.length),
            self._num_item(result.elapsed_ms),
            QTableWidgetItem(result.grep_extract),
            QTableWidgetItem(comment),
        ]

        # Determine row color based on status code
        status_color = self._get_status_color(result.status_code)
        is_interesting = bool(comment)

        for col, item in enumerate(items):
            if result.grep_match:
                item.setBackground(QBrush(QColor(GREP_MATCH_COLOR)))
                item.setForeground(QBrush(QColor(GREP_MATCH_FG)))
            elif result.error or result.timed_out:
                item.setForeground(QBrush(QColor("#e74c3c")))  # red for errors
            elif is_interesting and status_color != "#4ecca3":
                item.setForeground(QBrush(QColor("#f39c12")))  # gold for interesting
            elif status_color:
                item.setForeground(QBrush(QColor(status_color)))
            self.table.setItem(row, col, item)

        self.table.setSortingEnabled(True)

        # Auto-scroll
        self.table.scrollToBottom()

    def update_stats(self, rps: float, error_rate: float) -> None:
        self.rps_label.setText(f"RPS: {rps:.1f}")
        color = "#4ecca3" if error_rate < 10 else "#e94560"
        self.error_label.setText(f"Errors: {error_rate:.1f}%")
        self.error_label.setStyleSheet(f"color: {color};")

    def update_progress(self, current: int, total: int) -> None:
        if total > 0:
            pct = min(100, int(current / total * 100))
            self.progress_bar.setValue(pct)
            self.progress_bar.setFormat(f"{current}/{total} ({pct}%)")
        else:
            self.progress_bar.setValue(0)

    def clear_results(self) -> None:
        self._results.clear()
        self._baseline_length = None
        self._baseline_status = None
        self.table.setRowCount(0)
        self.request_viewer.clear()
        self.response_viewer.clear()
        self.progress_bar.setValue(0)
        self.rps_label.setText("RPS: 0")
        self.error_label.setText("Errors: 0%")

    def get_results(self) -> list[FuzzResult]:
        return list(self._results)

    # -- filtering --

    def _apply_filter(self, text: str) -> None:
        text_lower = text.lower()
        for row in range(self.table.rowCount()):
            visible = False
            if not text_lower:
                visible = True
            else:
                for col in range(self.table.columnCount()):
                    item = self.table.item(row, col)
                    if item and text_lower in item.text().lower():
                        visible = True
                        break
            self.table.setRowHidden(row, not visible)

    # -- context menu --

    def _show_context_menu(self, pos) -> None:
        menu = QMenu(self)

        send_action = QAction("Send to Request Editor", self)
        send_action.triggered.connect(self._send_selected_to_request)
        menu.addAction(send_action)

        repeater_action = QAction("Send to Repeater", self)
        repeater_action.triggered.connect(self._send_selected_to_repeater)
        menu.addAction(repeater_action)

        diff_action = QAction("Compare Selected Responses (Diff)", self)
        diff_action.triggered.connect(self._diff_selected)
        menu.addAction(diff_action)

        copy_action = QAction("Copy Payload", self)
        copy_action.triggered.connect(self._copy_payload)
        menu.addAction(copy_action)

        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _send_selected_to_request(self) -> None:
        row = self.table.currentRow()
        if 0 <= row < len(self._results):
            self.send_to_request.emit(self._results[row].request_text)

    def _send_selected_to_repeater(self) -> None:
        row = self.table.currentRow()
        if 0 <= row < len(self._results):
            self.send_to_repeater.emit(self._results[row].request_text)

    def _diff_selected(self) -> None:
        rows = sorted(set(idx.row() for idx in self.table.selectedIndexes()))
        if len(rows) >= 2:
            r1 = self._results[rows[0]] if rows[0] < len(self._results) else None
            r2 = self._results[rows[1]] if rows[1] < len(self._results) else None
            if r1 and r2:
                self.compare_responses.emit(r1.response_body, r2.response_body)

    def _copy_payload(self) -> None:
        row = self.table.currentRow()
        if 0 <= row < len(self._results):
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            if clipboard:
                clipboard.setText(self._results[row].payload)

    def _on_row_selected(self, row: int, *_) -> None:
        if 0 <= row < len(self._results):
            r = self._results[row]
            # Request tab
            self.request_viewer.setPlainText(r.request_text)
            # Response tab
            resp = ""
            for k, v in r.response_headers.items():
                resp += f"{k}: {v}\n"
            resp += "\n" + r.response_body
            self.response_viewer.setPlainText(resp)

    # -- export --

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", "results.csv", "CSV Files (*.csv)"
        )
        if path:
            export_results_csv(self._results, path)

    def _export_json(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON", "results.json", "JSON Files (*.json)"
        )
        if path:
            export_results_json(self._results, path)

    # -- helpers --

    @staticmethod
    def _num_item(value) -> QTableWidgetItem:
        """Create a table item that sorts numerically."""
        item = QTableWidgetItem()
        item.setData(Qt.ItemDataRole.DisplayRole, value)
        return item

    def _auto_comment(self, result: FuzzResult) -> str:
        """Generate automatic comment based on response analysis."""
        parts: list[str] = []

        # Network / timeout errors
        if result.timed_out:
            parts.append("\u23f1 TIMEOUT")
        if result.error and not result.error.startswith("HTTP"):
            parts.append(f"\u26a0 {result.error}")

        # Status code analysis
        sc = result.status_code
        if sc == 0:
            return " | ".join(parts) if parts else ""
        if sc in (301, 302, 303, 307, 308):
            loc = result.response_headers.get("location", "")
            parts.append(f"\u2192 Redirect: {loc[:40]}" if loc else "\u2192 Redirect")
        elif sc == 403:
            parts.append("\U0001f6ab Forbidden")
        elif sc == 429:
            parts.append("\u23f3 Rate Limited")
        elif sc >= 500:
            parts.append("\U0001f4a5 Server Error")

        # Length difference from baseline
        if self._baseline_length is not None and result.length != self._baseline_length:
            diff = result.length - self._baseline_length
            sign = "+" if diff > 0 else ""
            parts.append(f"\u0394len {sign}{diff}")

        # Cookie set
        if "set-cookie" in result.response_headers:
            parts.append("\U0001f36a Cookie set")

        # Slow response (>2s)
        if result.elapsed_ms > 2000:
            parts.append(f"\U0001f422 Slow ({result.elapsed_ms:.0f}ms)")

        return " | ".join(parts)

    @staticmethod
    def _get_status_color(status_code: int) -> str | None:
        """Return a color string based on HTTP status code."""
        if status_code == 0:
            return None
        if 200 <= status_code < 300:
            return "#4ecca3"  # green for 2xx
        if 300 <= status_code < 400:
            return "#f1c40f"  # yellow for 3xx
        if 400 <= status_code < 500:
            return "#e67e22"  # orange for 4xx
        if status_code >= 500:
            return "#e74c3c"  # red for 5xx
        return None
