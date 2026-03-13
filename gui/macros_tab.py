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
    QScrollArea,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
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
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        # Scroll area so nothing gets squished
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(6)

        # -- Request editor --
        req_group = QGroupBox("HTTP Request")
        req_layout = QVBoxLayout(req_group)
        req_layout.setContentsMargins(6, 6, 6, 6)
        self.request_edit = QPlainTextEdit()
        self.request_edit.setFont(QFont("Consolas", 11))
        self.request_edit.setMinimumHeight(180)
        self.request_edit.setPlaceholderText(
            "POST /login HTTP/1.1\n"
            "Host: example.com\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            "username=admin&password=secret\n\n"
            "Tip: use {{variable_name}} to inject values extracted in earlier steps."
        )
        req_layout.addWidget(self.request_edit)
        layout.addWidget(req_group)

        # -- Extractions --
        ext_group = QGroupBox("Extract Variables from Response")
        ext_layout = QVBoxLayout(ext_group)
        ext_layout.setContentsMargins(6, 6, 6, 6)
        ext_layout.setSpacing(4)

        ext_header = QHBoxLayout()
        ext_header.addWidget(QLabel("Extracted values -> available as {{name}} in later steps and in the fuzz request."))
        ext_header.addStretch()
        self.add_ext_btn = QPushButton("+ Add")
        self.add_ext_btn.setFixedWidth(60)
        self.add_ext_btn.clicked.connect(self._add_row)
        self.del_ext_btn = QPushButton("- Del")
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
        self.ext_table.setMinimumHeight(120)
        ext_layout.addWidget(self.ext_table)
        layout.addWidget(ext_group)

        layout.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll)

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

        # -- Main splitter: Steps (top) / Triggers (bottom) --
        editor_splitter = QSplitter(Qt.Orientation.Vertical)

        # Steps group
        steps_group = QGroupBox("Steps")
        steps_outer = QHBoxLayout(steps_group)
        steps_outer.setContentsMargins(6, 6, 6, 6)
        steps_outer.setSpacing(6)

        # Left: step list + add/del buttons
        step_left_w = QWidget()
        step_left_w.setFixedWidth(95)
        step_left = QVBoxLayout(step_left_w)
        step_left.setContentsMargins(0, 0, 0, 0)
        step_left.setSpacing(4)
        self.step_list = QListWidget()
        self.step_list.currentRowChanged.connect(self._on_step_selected)
        step_left.addWidget(self.step_list)
        step_btn_row = QHBoxLayout()
        self.add_step_btn = QPushButton("+")
        self.add_step_btn.setToolTip("Add step")
        self.add_step_btn.clicked.connect(self._add_step)
        self.del_step_btn = QPushButton("-")
        self.del_step_btn.setToolTip("Delete step")
        self.del_step_btn.clicked.connect(self._del_step)
        step_btn_row.addWidget(self.add_step_btn)
        step_btn_row.addWidget(self.del_step_btn)
        step_left.addLayout(step_btn_row)
        steps_outer.addWidget(step_left_w)

        # Right: stacked step editors
        self.step_stack = QStackedWidget()
        steps_outer.addWidget(self.step_stack, 1)
        editor_splitter.addWidget(steps_group)

        # Triggers group
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
        trigger_layout.addStretch()
        editor_splitter.addWidget(trigger_group)

        editor_splitter.setStretchFactor(0, 4)
        editor_splitter.setStretchFactor(1, 1)
        editor_splitter.setSizes([480, 140])
        layout.addWidget(editor_splitter, 1)

        # Start with one empty step
        self._add_step()

    # -- Step management --

    def _add_step(self) -> None:
        idx = self.step_list.count() + 1
        w = _StepWidget()
        self.step_stack.addWidget(w)
        self.step_list.addItem(f"Step {idx}")
        self.step_list.setCurrentRow(self.step_list.count() - 1)

    def _del_step(self) -> None:
        if self.step_list.count() <= 1:
            return
        row = self.step_list.currentRow()
        if row < 0:
            return
        w = self.step_stack.widget(row)
        self.step_stack.removeWidget(w)
        w.deleteLater()
        self.step_list.takeItem(row)
        # Rename remaining items
        for i in range(self.step_list.count()):
            self.step_list.item(i).setText(f"Step {i + 1}")

    def _on_step_selected(self, row: int) -> None:
        if row >= 0:
            self.step_stack.setCurrentIndex(row)

    # -- Serialise / deserialise --

    def get_data(self) -> dict:
        steps = []
        for i in range(self.step_stack.count()):
            w: _StepWidget = self.step_stack.widget(i)  # type: ignore
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
        while self.step_stack.count():
            w = self.step_stack.widget(0)
            self.step_stack.removeWidget(w)
            w.deleteLater()
        self.step_list.clear()
        for i, step_data in enumerate(data.get("steps", [{"raw_request": "", "extractions": []}])):
            w = _StepWidget()
            w.set_raw_request(step_data.get("raw_request", ""))
            w.set_extractions(step_data.get("extractions", []))
            self.step_stack.addWidget(w)
            self.step_list.addItem(f"Step {i + 1}")
        if self.step_list.count():
            self.step_list.setCurrentRow(0)

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
        self.del_btn = QPushButton("- Del")
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
            "  Step 1: GET /login -> extract CSRF token\n"
            "  Step 2: POST /login -> extract session cookie\n\n"
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
