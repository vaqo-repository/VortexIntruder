"""
VortexIntruder – Macros Tab
Burp-style macro recorder: define sequences of HTTP requests that run
before the attack or on specific triggers, with variable extraction.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from engine.fuzzer import MacroConfig, MacroExtraction, MacroStep


# ---------------------------------------------------------------------------
# Single step widget
# ---------------------------------------------------------------------------

class _StepWidget(QWidget):
    """Editor for one macro step: raw request + extractions table."""

    _SRC_LABELS = ["Response Cookie", "Response Header", "Body Regex"]
    _SRC_MAP = {
        "Response Cookie": "cookie",
        "Response Header": "header",
        "Body Regex": "body_regex",
    }
    _SRC_REVERSE = {v: k for k, v in _SRC_MAP.items()}

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(6)

        # -- Request editor --
        req_group = QGroupBox("HTTP Request")
        req_layout = QVBoxLayout(req_group)
        req_layout.setContentsMargins(6, 6, 6, 6)
        self.request_edit = QPlainTextEdit()
        self.request_edit.setFont(QFont("Consolas", 11))
        self.request_edit.setPlaceholderText(
            "POST /login HTTP/1.1\n"
            "Host: example.com\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            "username=admin&password=secret\n\n"
            "Tip: use {{variable_name}} to inject values extracted in earlier steps."
        )
        req_layout.addWidget(self.request_edit)
        layout.addWidget(req_group, 2)

        # -- Extractions --
        ext_group = QGroupBox("Extract Variables from Response")
        ext_layout = QVBoxLayout(ext_group)
        ext_layout.setContentsMargins(6, 6, 6, 6)
        ext_layout.setSpacing(4)

        ext_header = QHBoxLayout()
        ext_header.addWidget(QLabel(
            "Extracted values are available as {{name}} in later steps and in the fuzz request."
        ))
        ext_header.addStretch()
        self.add_ext_btn = QPushButton("+ Add")
        self.add_ext_btn.setFixedWidth(60)
        self.add_ext_btn.clicked.connect(self._add_row)
        self.del_ext_btn = QPushButton("− Del")
        self.del_ext_btn.setFixedWidth(60)
        self.del_ext_btn.clicked.connect(self._del_row)
        ext_header.addWidget(self.add_ext_btn)
        ext_header.addWidget(self.del_ext_btn)
        ext_layout.addLayout(ext_header)

        self.ext_table = QTableWidget(0, 4)
        self.ext_table.setHorizontalHeaderLabels(
            ["Source", "Key / Regex Pattern", "Variable Name", "Group #"]
        )
        hh = self.ext_table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.ext_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ext_table.setMaximumHeight(160)
        ext_layout.addWidget(self.ext_table)
        layout.addWidget(ext_group, 1)

    # -- extraction table helpers --

    def _add_row(self) -> None:
        row = self.ext_table.rowCount()
        self.ext_table.insertRow(row)
        combo = QComboBox()
        combo.addItems(self._SRC_LABELS)
        self.ext_table.setCellWidget(row, 0, combo)
        self.ext_table.setItem(row, 1, QTableWidgetItem(""))
        self.ext_table.setItem(row, 2, QTableWidgetItem(""))
        spin = QSpinBox()
        spin.setRange(0, 20)
        spin.setValue(1)
        self.ext_table.setCellWidget(row, 3, spin)

    def _del_row(self) -> None:
        row = self.ext_table.currentRow()
        if row >= 0:
            self.ext_table.removeRow(row)

    # -- data accessors --

    def get_raw_request(self) -> str:
        return self.request_edit.toPlainText()

    def set_raw_request(self, text: str) -> None:
        self.request_edit.setPlainText(text)

    def get_extractions(self) -> list[dict]:
        result = []
        for r in range(self.ext_table.rowCount()):
            src_w = self.ext_table.cellWidget(r, 0)
            key_i = self.ext_table.item(r, 1)
            var_i = self.ext_table.item(r, 2)
            grp_w = self.ext_table.cellWidget(r, 3)
            if src_w and key_i and var_i:
                result.append({
                    "source": self._SRC_MAP.get(src_w.currentText(), "cookie"),
                    "key": key_i.text().strip(),
                    "variable": var_i.text().strip(),
                    "group": grp_w.value() if grp_w else 1,
                })
        return result

    def set_extractions(self, extractions: list[dict]) -> None:
        self.ext_table.setRowCount(0)
        for ext in extractions:
            row = self.ext_table.rowCount()
            self.ext_table.insertRow(row)
            combo = QComboBox()
            combo.addItems(self._SRC_LABELS)
            combo.setCurrentText(self._SRC_REVERSE.get(ext.get("source", "cookie"), "Response Cookie"))
            self.ext_table.setCellWidget(row, 0, combo)
            self.ext_table.setItem(row, 1, QTableWidgetItem(ext.get("key", "")))
            self.ext_table.setItem(row, 2, QTableWidgetItem(ext.get("variable", "")))
            spin = QSpinBox()
            spin.setRange(0, 20)
            spin.setValue(ext.get("group", 1))
            self.ext_table.setCellWidget(row, 3, spin)


# ---------------------------------------------------------------------------
# Macro editor panel (right side)
# ---------------------------------------------------------------------------

class _MacroEditor(QWidget):
    """Right-side panel for editing one macro."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # -- Name --
        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Macro Name:"))
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g. Login")
        name_row.addWidget(self.name_edit)
        layout.addLayout(name_row)

        # -- Steps --
        steps_group = QGroupBox("Steps")
        steps_layout = QVBoxLayout(steps_group)
        steps_layout.setContentsMargins(6, 6, 6, 6)
        steps_layout.setSpacing(4)

        steps_btn_row = QHBoxLayout()
        steps_btn_row.addWidget(QLabel("Each step is an HTTP request executed in order:"))
        steps_btn_row.addStretch()
        self.add_step_btn = QPushButton("+ Step")
        self.add_step_btn.setFixedWidth(70)
        self.add_step_btn.clicked.connect(self._add_step)
        self.del_step_btn = QPushButton("− Step")
        self.del_step_btn.setFixedWidth(70)
        self.del_step_btn.clicked.connect(self._del_step)
        steps_btn_row.addWidget(self.add_step_btn)
        steps_btn_row.addWidget(self.del_step_btn)
        steps_layout.addLayout(steps_btn_row)

        self.steps_tabs = QTabWidget()
        self.steps_tabs.setTabsClosable(False)
        steps_layout.addWidget(self.steps_tabs)
        layout.addWidget(steps_group, 3)

        # -- Triggers --
        trigger_group = QGroupBox("Triggers")
        trigger_layout = QVBoxLayout(trigger_group)
        trigger_layout.setContentsMargins(8, 8, 8, 8)
        trigger_layout.setSpacing(6)

        self.run_before_check = QCheckBox("Run this macro once before the attack starts")
        self.run_before_check.setChecked(True)
        trigger_layout.addWidget(self.run_before_check)

        rerun_row = QHBoxLayout()
        self.rerun_on_check = QCheckBox("Re-run when fuzz response contains:")
        self.rerun_on_edit = QLineEdit()
        self.rerun_on_edit.setPlaceholderText("e.g.  logged_out  or  session expired")
        self.rerun_on_edit.setEnabled(False)
        self.rerun_on_check.toggled.connect(self.rerun_on_edit.setEnabled)
        rerun_row.addWidget(self.rerun_on_check)
        rerun_row.addWidget(self.rerun_on_edit, 1)
        trigger_layout.addLayout(rerun_row)

        every_row = QHBoxLayout()
        self.rerun_every_check = QCheckBox("Re-run every")
        self.rerun_every_spin = QSpinBox()
        self.rerun_every_spin.setRange(1, 100000)
        self.rerun_every_spin.setValue(50)
        self.rerun_every_spin.setEnabled(False)
        self.rerun_every_check.toggled.connect(self.rerun_every_spin.setEnabled)
        every_row.addWidget(self.rerun_every_check)
        every_row.addWidget(self.rerun_every_spin)
        every_row.addWidget(QLabel("fuzz requests"))
        every_row.addStretch()
        trigger_layout.addLayout(every_row)
        layout.addWidget(trigger_group)

        # Start with one empty step
        self._add_step()

    # -- Step management --

    def _add_step(self) -> None:
        idx = self.steps_tabs.count() + 1
        w = _StepWidget()
        self.steps_tabs.addTab(w, f"Step {idx}")
        self.steps_tabs.setCurrentIndex(self.steps_tabs.count() - 1)

    def _del_step(self) -> None:
        if self.steps_tabs.count() > 1:
            self.steps_tabs.removeTab(self.steps_tabs.currentIndex())
            # Rename remaining tabs
            for i in range(self.steps_tabs.count()):
                self.steps_tabs.setTabText(i, f"Step {i + 1}")

    # -- Serialise / deserialise --

    def get_data(self) -> dict:
        steps = []
        for i in range(self.steps_tabs.count()):
            w: _StepWidget = self.steps_tabs.widget(i)  # type: ignore
            steps.append({
                "raw_request": w.get_raw_request(),
                "extractions": w.get_extractions(),
            })
        return {
            "name": self.name_edit.text().strip() or "Macro",
            "steps": steps,
            "run_before": self.run_before_check.isChecked(),
            "rerun_on_response": self.rerun_on_edit.text().strip() if self.rerun_on_check.isChecked() else "",
            "rerun_every": self.rerun_every_spin.value() if self.rerun_every_check.isChecked() else 0,
        }

    def set_data(self, data: dict) -> None:
        self.name_edit.setText(data.get("name", "Macro"))

        # Restore steps
        while self.steps_tabs.count():
            self.steps_tabs.removeTab(0)
        for step_data in data.get("steps", [{"raw_request": "", "extractions": []}]):
            w = _StepWidget()
            w.set_raw_request(step_data.get("raw_request", ""))
            w.set_extractions(step_data.get("extractions", []))
            self.steps_tabs.addTab(w, f"Step {self.steps_tabs.count() + 1}")

        self.run_before_check.setChecked(data.get("run_before", True))

        rerun_on = data.get("rerun_on_response", "")
        self.rerun_on_check.setChecked(bool(rerun_on))
        self.rerun_on_edit.setText(rerun_on)
        self.rerun_on_edit.setEnabled(bool(rerun_on))

        rerun_every = data.get("rerun_every", 0)
        self.rerun_every_check.setChecked(rerun_every > 0)
        self.rerun_every_spin.setValue(rerun_every if rerun_every > 0 else 50)
        self.rerun_every_spin.setEnabled(rerun_every > 0)


# ---------------------------------------------------------------------------
# Main MacrosTab
# ---------------------------------------------------------------------------

class MacrosTab(QWidget):
    """
    Burp-style Macros tab.

    Left panel: macro list + add/remove
    Right panel: macro editor (name, steps, triggers)
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._macros: list[dict] = []   # list of serialised macro dicts
        self._current_idx: int = -1
        self._init_ui()

    def _init_ui(self) -> None:
        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(splitter)

        # -- Left: macro list --
        left = QWidget()
        left.setMinimumWidth(160)
        left.setMaximumWidth(220)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(8, 8, 4, 8)
        left_layout.setSpacing(6)

        left_layout.addWidget(QLabel("Macros:"))
        self.macro_list = QListWidget()
        self.macro_list.currentRowChanged.connect(self._on_macro_selected)
        left_layout.addWidget(self.macro_list, 1)

        btn_row = QHBoxLayout()
        self.add_btn = QPushButton("+ Add")
        self.add_btn.clicked.connect(self._add_macro)
        self.del_btn = QPushButton("− Del")
        self.del_btn.clicked.connect(self._del_macro)
        btn_row.addWidget(self.add_btn)
        btn_row.addWidget(self.del_btn)
        left_layout.addLayout(btn_row)

        hint = QLabel(
            "<small><i>Macros run HTTP sequences before/during the attack "
            "and inject extracted values ({{var}}) into fuzz requests.</i></small>"
        )
        hint.setWordWrap(True)
        hint.setAlignment(Qt.AlignmentFlag.AlignTop)
        left_layout.addWidget(hint)

        splitter.addWidget(left)

        # -- Right: stacked (empty placeholder / editor) --
        self._stack = QStackedWidget()

        # Page 0: empty hint
        empty = QLabel(
            "No macros yet.\n\nClick \"+ Add\" to create a macro.\n\n"
            "Example use case:\n"
            "  Step 1: GET /login → extract CSRF token\n"
            "  Step 2: POST /login → extract session cookie\n\n"
            "Then use {{session}} in your fuzz request headers."
        )
        empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty.setWordWrap(True)
        self._stack.addWidget(empty)

        # Page 1: editor (single instance, loaded per macro)
        self._editor = _MacroEditor()
        self._stack.addWidget(self._editor)

        splitter.addWidget(self._stack)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

    # -- Macro list management --

    def _add_macro(self) -> None:
        self._save_current()
        data = {
            "name": f"Macro {len(self._macros) + 1}",
            "steps": [{"raw_request": "", "extractions": []}],
            "run_before": True,
            "rerun_on_response": "",
            "rerun_every": 0,
        }
        self._macros.append(data)
        item = QListWidgetItem(data["name"])
        self.macro_list.addItem(item)
        self.macro_list.setCurrentRow(len(self._macros) - 1)

    def _del_macro(self) -> None:
        row = self.macro_list.currentRow()
        if row < 0:
            return
        self._macros.pop(row)
        self.macro_list.takeItem(row)
        self._current_idx = -1
        if self._macros:
            self.macro_list.setCurrentRow(min(row, len(self._macros) - 1))
        else:
            self._stack.setCurrentIndex(0)

    def _save_current(self) -> None:
        if self._current_idx < 0 or self._current_idx >= len(self._macros):
            return
        data = self._editor.get_data()
        self._macros[self._current_idx] = data
        self.macro_list.item(self._current_idx).setText(data["name"])

    def _on_macro_selected(self, row: int) -> None:
        self._save_current()
        self._current_idx = row
        if row < 0 or row >= len(self._macros):
            self._stack.setCurrentIndex(0)
            return
        self._editor.set_data(self._macros[row])
        self._stack.setCurrentIndex(1)

    # -- Public API --

    def get_macro_configs(self) -> list[MacroConfig]:
        """Return MacroConfig list ready to pass to AttackConfig.macros."""
        self._save_current()
        configs = []
        for data in self._macros:
            steps = []
            for step_data in data.get("steps", []):
                extractions = [
                    MacroExtraction(
                        source=e["source"],
                        key=e["key"],
                        variable=e["variable"],
                        group=e.get("group", 1),
                    )
                    for e in step_data.get("extractions", [])
                    if e.get("key") and e.get("variable")
                ]
                if step_data.get("raw_request", "").strip():
                    steps.append(MacroStep(
                        raw_request=step_data["raw_request"],
                        extractions=extractions,
                    ))
            if steps:
                configs.append(MacroConfig(
                    name=data.get("name", "Macro"),
                    steps=steps,
                    run_before=data.get("run_before", True),
                    rerun_on_response=data.get("rerun_on_response", ""),
                    rerun_every=data.get("rerun_every", 0),
                ))
        return configs
