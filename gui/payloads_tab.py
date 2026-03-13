"""
VortexIntruder v1.0 – Payloads Tab
Full payload configuration: source, processing rules pipeline, transport encoding.
Supports drag-and-drop rule reordering and real-time test transformation.
"""
from __future__ import annotations

import string
from typing import Iterator

from PyQt6.QtCore import Qt, QStringListModel, QMimeData
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from engine.payloads import (
    bruteforce_generator,
    manual_list_generator,
    null_payload_generator,
    number_range_generator,
    wordlist_generator,
)
from engine.processor import (
    ALL_RULE_TYPES,
    PayloadProcessor,
    ProcessingRule,
    RuleType,
    TransportEncoder,
)


PAYLOAD_TYPES = [
    "Simple List",
    "Numbers (Range)",
    "Brute-forcer",
    "Null Payloads",
    "File Wordlist",
]


def _repeat_generator(gen: Iterator[str], count: int) -> Iterator[str]:
    """Yield each item from gen repeated `count` times."""
    for item in gen:
        for _ in range(count):
            yield item


class DraggableListView(QListView):
    """QListView with drag-and-drop reordering support."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.setDragDropMode(QListView.DragDropMode.InternalMove)


class PayloadsTab(QWidget):
    """Full payload configuration tab."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.processor = PayloadProcessor()
        self.transport_encoder = TransportEncoder()
        self._rules_model = QStringListModel()
        self._file_path = ""
        self._current_set_idx = 0
        self._num_sets = 4
        self._set_states: list[dict] = [self._default_state() for _ in range(self._num_sets)]
        self._init_ui()
        # Connect set switcher AFTER ui is built
        self.set_combo.currentIndexChanged.connect(self._on_set_changed)

    @staticmethod
    def _default_state() -> dict:
        return {
            "type_idx": 0,
            "manual_text": "",
            "file_path": "",
            "num_start": 0.0, "num_end": 100.0, "num_step": 1.0,
            "num_min_int": 0, "num_max_int": 0,
            "num_min_frac": 0, "num_max_frac": 0,
            "num_sequential": True, "num_decimal": True,
            "brute_charset": "abcdefghijklmnopqrstuvwxyz",
            "brute_min": 1, "brute_max": 4,
            "null_count": 100,
            "filter_check": False, "filter_min": 0, "filter_max": 99999,
            "repeat_count": 1, "order_sequential": True,
            "rules": [],
            "encoding_chars": set(),
        }

    def _save_set_state(self, idx: int) -> None:
        """Save current UI values to the state dict for set idx."""
        s = self._set_states[idx]
        s["type_idx"] = self.type_combo.currentIndex()
        s["manual_text"] = self.manual_text.toPlainText()
        s["file_path"] = self._file_path
        s["num_start"] = self.num_start.value()
        s["num_end"] = self.num_end.value()
        s["num_step"] = self.num_step.value()
        s["num_min_int"] = self.num_min_int.value()
        s["num_max_int"] = self.num_max_int.value()
        s["num_min_frac"] = self.num_min_frac.value()
        s["num_max_frac"] = self.num_max_frac.value()
        s["num_sequential"] = self.num_sequential_radio.isChecked()
        s["num_decimal"] = self.num_decimal_radio.isChecked()
        s["brute_charset"] = self.brute_charset.text()
        s["brute_min"] = self.brute_min.value()
        s["brute_max"] = self.brute_max.value()
        s["null_count"] = self.null_count.value()
        s["filter_check"] = self.filter_check.isChecked()
        s["filter_min"] = self.filter_min.value()
        s["filter_max"] = self.filter_max.value()
        s["repeat_count"] = self.repeat_count.value()
        s["order_sequential"] = self.order_sequential_radio.isChecked()
        s["rules"] = list(self.processor.rules)
        s["encoding_chars"] = {ch for ch, cb in self._encoding_checks.items() if cb.isChecked()}

    def _load_set_state(self, idx: int) -> None:
        """Restore UI fields from the state dict for set idx."""
        s = self._set_states[idx]
        self.type_combo.setCurrentIndex(s["type_idx"])
        self.manual_text.setPlainText(s["manual_text"])
        self._file_path = s["file_path"]
        self.file_path_edit.setText(s["file_path"])
        self.num_start.setValue(s["num_start"])
        self.num_end.setValue(s["num_end"])
        self.num_step.setValue(s["num_step"])
        self.num_min_int.setValue(s["num_min_int"])
        self.num_max_int.setValue(s["num_max_int"])
        self.num_min_frac.setValue(s["num_min_frac"])
        self.num_max_frac.setValue(s["num_max_frac"])
        self.num_sequential_radio.setChecked(s["num_sequential"])
        self.num_random_radio.setChecked(not s["num_sequential"])
        self.num_decimal_radio.setChecked(s["num_decimal"])
        self.num_hex_radio.setChecked(not s["num_decimal"])
        self.brute_charset.setText(s["brute_charset"])
        self.brute_min.setValue(s["brute_min"])
        self.brute_max.setValue(s["brute_max"])
        self.null_count.setValue(s["null_count"])
        self.filter_check.setChecked(s["filter_check"])
        self.filter_min.setValue(s["filter_min"])
        self.filter_max.setValue(s["filter_max"])
        self.repeat_count.setValue(s["repeat_count"])
        self.order_sequential_radio.setChecked(s["order_sequential"])
        self.order_random_radio.setChecked(not s["order_sequential"])
        # Restore rules
        self.processor.clear_rules()
        for rule in s["rules"]:
            self.processor.add_rule(rule)
        self._refresh_rules_model()
        # Restore encoding
        for ch, cb in self._encoding_checks.items():
            cb.setChecked(ch in s["encoding_chars"])

    def _on_set_changed(self, new_idx: int) -> None:
        """Save old set state, load new set state."""
        self._save_set_state(self._current_set_idx)
        self._current_set_idx = new_idx
        self._load_set_state(new_idx)

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        top_row = QHBoxLayout()

        # -- Payload set selector --
        top_row.addWidget(QLabel("Payload Set:"))
        self.set_combo = QComboBox()
        self.set_combo.addItems(["Set 1", "Set 2", "Set 3", "Set 4"])
        top_row.addWidget(self.set_combo)
        top_row.addStretch()
        layout.addLayout(top_row)

        # Sub-tabs for payload source vs rules
        sub_tabs = QTabWidget()

        # === Source tab ===
        source_widget = QWidget()
        source_layout = QVBoxLayout(source_widget)

        # Payload type
        type_row = QHBoxLayout()
        type_row.addWidget(QLabel("Payload Type:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(PAYLOAD_TYPES)
        self.type_combo.currentIndexChanged.connect(self._on_type_changed)
        type_row.addWidget(self.type_combo)
        type_row.addStretch()
        source_layout.addLayout(type_row)

        # -- Simple list / manual --
        self.manual_group = QGroupBox("Manual Payload List")
        manual_layout = QVBoxLayout(self.manual_group)
        self.manual_text = QPlainTextEdit()
        self.manual_text.setPlaceholderText("Enter payloads, one per line...")
        manual_layout.addWidget(self.manual_text)

        mod_row = QHBoxLayout()
        self.shuffle_btn = QPushButton("Shuffle")
        self.dedup_btn = QPushButton("Remove Duplicates")
        mod_row.addWidget(self.shuffle_btn)
        mod_row.addWidget(self.dedup_btn)
        self.shuffle_btn.clicked.connect(self._shuffle_manual)
        self.dedup_btn.clicked.connect(self._dedup_manual)
        mod_row.addStretch()
        manual_layout.addLayout(mod_row)
        source_layout.addWidget(self.manual_group)

        # -- File wordlist --
        self.file_group = QGroupBox("File Wordlist")
        file_layout = QHBoxLayout(self.file_group)
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Path to wordlist file...")
        self.file_path_edit.setReadOnly(True)
        self.file_browse_btn = QPushButton("Browse...")
        self.file_browse_btn.clicked.connect(self._browse_file)
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(self.file_browse_btn)
        self.file_group.setVisible(False)
        source_layout.addWidget(self.file_group)

        # -- Numbers range (Burp-style professional layout) --
        self.numbers_group = QGroupBox("Number Range")
        num_main = QVBoxLayout(self.numbers_group)

        # Row 1: Type (Sequential / Random)
        type_row = QHBoxLayout()
        type_row.addWidget(QLabel("Type:"))
        self.num_sequential_radio = QRadioButton("Sequential")
        self.num_random_radio = QRadioButton("Random")
        self.num_sequential_radio.setChecked(True)
        type_row.addWidget(self.num_sequential_radio)
        type_row.addWidget(self.num_random_radio)
        type_row.addStretch()
        num_main.addLayout(type_row)

        # Row 2: From / To / Step
        range_row = QHBoxLayout()
        range_row.addWidget(QLabel("From:"))
        self.num_start = QDoubleSpinBox()
        self.num_start.setRange(-999999999, 999999999)
        self.num_start.setDecimals(6)
        self.num_start.setValue(0)
        self.num_start.setMinimumWidth(120)
        range_row.addWidget(self.num_start)

        range_row.addWidget(QLabel("To:"))
        self.num_end = QDoubleSpinBox()
        self.num_end.setRange(-999999999, 999999999)
        self.num_end.setDecimals(6)
        self.num_end.setValue(100)
        self.num_end.setMinimumWidth(120)
        range_row.addWidget(self.num_end)

        range_row.addWidget(QLabel("Step:"))
        self.num_step = QDoubleSpinBox()
        self.num_step.setRange(0.000001, 999999)
        self.num_step.setDecimals(6)
        self.num_step.setValue(1)
        self.num_step.setMinimumWidth(100)
        range_row.addWidget(self.num_step)
        range_row.addStretch()
        num_main.addLayout(range_row)

        # Row 3: Base (Decimal / Hex)
        base_row = QHBoxLayout()
        base_row.addWidget(QLabel("Base:"))
        self.num_decimal_radio = QRadioButton("Decimal")
        self.num_hex_radio = QRadioButton("Hex")
        self.num_decimal_radio.setChecked(True)
        base_row.addWidget(self.num_decimal_radio)
        base_row.addWidget(self.num_hex_radio)
        base_row.addStretch()
        num_main.addLayout(base_row)

        # Row 4: Number format – digit controls
        format_group = QGroupBox("Number Format")
        fmt_layout = QVBoxLayout(format_group)

        int_row = QHBoxLayout()
        int_row.addWidget(QLabel("Min integer digits:"))
        self.num_min_int = QSpinBox()
        self.num_min_int.setRange(0, 20)
        self.num_min_int.setValue(0)
        self.num_min_int.setToolTip("Zero-pad to this width (e.g. 3 → 001)")
        int_row.addWidget(self.num_min_int)

        int_row.addWidget(QLabel("Max integer digits:"))
        self.num_max_int = QSpinBox()
        self.num_max_int.setRange(0, 20)
        self.num_max_int.setValue(0)
        self.num_max_int.setToolTip("Truncate from left if exceeded (0 = no limit)")
        int_row.addWidget(self.num_max_int)
        int_row.addStretch()
        fmt_layout.addLayout(int_row)

        frac_row = QHBoxLayout()
        frac_row.addWidget(QLabel("Min fraction digits:"))
        self.num_min_frac = QSpinBox()
        self.num_min_frac.setRange(0, 10)
        self.num_min_frac.setValue(0)
        self.num_min_frac.setToolTip("Pad with trailing zeros (e.g. 1.5 → 1.50)")
        frac_row.addWidget(self.num_min_frac)

        frac_row.addWidget(QLabel("Max fraction digits:"))
        self.num_max_frac = QSpinBox()
        self.num_max_frac.setRange(0, 10)
        self.num_max_frac.setValue(0)
        self.num_max_frac.setToolTip("Round to this many decimal places")
        frac_row.addWidget(self.num_max_frac)
        frac_row.addStretch()
        fmt_layout.addLayout(frac_row)

        num_main.addWidget(format_group)

        # Row 5: Live preview examples
        preview_row = QHBoxLayout()
        preview_row.addWidget(QLabel("Examples:"))
        self.num_preview_label = QLabel("0, 1, 2, 3, ... 100")
        self.num_preview_label.setStyleSheet(
            "color: #4ecca3; font-family: Consolas; font-size: 12px;"
        )
        self.num_preview_label.setWordWrap(True)
        preview_row.addWidget(self.num_preview_label, 1)
        num_main.addLayout(preview_row)

        # Connect all number fields to live preview update
        for widget in (
            self.num_start, self.num_end, self.num_step,
        ):
            widget.valueChanged.connect(self._update_num_preview)
        for widget in (
            self.num_min_int, self.num_max_int,
            self.num_min_frac, self.num_max_frac,
        ):
            widget.valueChanged.connect(self._update_num_preview)
        self.num_sequential_radio.toggled.connect(self._update_num_preview)
        self.num_hex_radio.toggled.connect(self._update_num_preview)

        self.numbers_group.setVisible(False)
        source_layout.addWidget(self.numbers_group)
        self._update_num_preview()

        # -- Brute-forcer --
        self.brute_group = QGroupBox("Brute-forcer Settings")
        brute_layout = QHBoxLayout(self.brute_group)
        brute_layout.addWidget(QLabel("Charset:"))
        self.brute_charset = QLineEdit(string.ascii_lowercase)
        brute_layout.addWidget(self.brute_charset)
        brute_layout.addWidget(QLabel("Min Len:"))
        self.brute_min = QSpinBox()
        self.brute_min.setRange(1, 12)
        self.brute_min.setValue(1)
        brute_layout.addWidget(self.brute_min)
        brute_layout.addWidget(QLabel("Max Len:"))
        self.brute_max = QSpinBox()
        self.brute_max.setRange(1, 12)
        self.brute_max.setValue(4)
        brute_layout.addWidget(self.brute_max)
        self.brute_group.setVisible(False)
        source_layout.addWidget(self.brute_group)

        # -- Null payloads --
        self.null_group = QGroupBox("Null Payloads")
        null_layout = QHBoxLayout(self.null_group)
        null_layout.addWidget(QLabel("Count:"))
        self.null_count = QSpinBox()
        self.null_count.setRange(1, 999999999)
        self.null_count.setValue(100)
        null_layout.addWidget(self.null_count)
        self.null_group.setVisible(False)
        source_layout.addWidget(self.null_group)

        # Length filter
        filter_row = QHBoxLayout()
        self.filter_check = QCheckBox("Filter by Length")
        self.filter_min = QSpinBox()
        self.filter_min.setRange(0, 99999)
        self.filter_max = QSpinBox()
        self.filter_max.setRange(0, 99999)
        self.filter_max.setValue(99999)
        filter_row.addWidget(self.filter_check)
        filter_row.addWidget(QLabel("Min:"))
        filter_row.addWidget(self.filter_min)
        filter_row.addWidget(QLabel("Max:"))
        filter_row.addWidget(self.filter_max)
        filter_row.addStretch()
        source_layout.addLayout(filter_row)

        # -- Payload Options: repeat & order --
        opts_group = QGroupBox("Payload Options")
        opts_layout = QHBoxLayout(opts_group)

        opts_layout.addWidget(QLabel("Repeat each payload:"))
        self.repeat_count = QSpinBox()
        self.repeat_count.setRange(1, 999999)
        self.repeat_count.setValue(1)
        self.repeat_count.setToolTip("How many times to send each payload")
        opts_layout.addWidget(self.repeat_count)

        opts_layout.addWidget(QLabel("  Order:"))
        self.order_sequential_radio = QRadioButton("Sequential")
        self.order_random_radio = QRadioButton("Random")
        self.order_sequential_radio.setChecked(True)
        opts_layout.addWidget(self.order_sequential_radio)
        opts_layout.addWidget(self.order_random_radio)
        opts_layout.addStretch()
        source_layout.addWidget(opts_group)

        source_layout.addStretch()
        sub_tabs.addTab(source_widget, "Payload Source")

        # === Processing Rules tab ===
        rules_widget = QWidget()
        rules_layout = QVBoxLayout(rules_widget)

        rules_layout.addWidget(QLabel("Processing Rules Pipeline (applied in order):"))

        rules_row = QHBoxLayout()

        # Rule list (draggable)
        self.rules_list = DraggableListView()
        self.rules_list.setModel(self._rules_model)
        rules_row.addWidget(self.rules_list, 2)

        # Rule controls
        ctrl_layout = QVBoxLayout()
        self.rule_type_combo = QComboBox()
        self.rule_type_combo.addItems([r.value for r in ALL_RULE_TYPES])
        self.rule_type_combo.currentIndexChanged.connect(self._on_rule_type_changed)
        ctrl_layout.addWidget(QLabel("Rule Type:"))
        ctrl_layout.addWidget(self.rule_type_combo)

        ctrl_layout.addWidget(QLabel("Param 1:"))
        self.rule_param1 = QLineEdit()
        self.rule_param1.setPlaceholderText("prefix / regex / pad width")
        ctrl_layout.addWidget(self.rule_param1)

        ctrl_layout.addWidget(QLabel("Param 2:"))
        self.rule_param2 = QLineEdit()
        self.rule_param2.setPlaceholderText("suffix / replacement")
        ctrl_layout.addWidget(self.rule_param2)

        self.add_rule_btn = QPushButton("Add Rule")
        self.add_rule_btn.clicked.connect(self._add_rule)
        ctrl_layout.addWidget(self.add_rule_btn)

        self.remove_rule_btn = QPushButton("Remove Selected")
        self.remove_rule_btn.clicked.connect(self._remove_rule)
        ctrl_layout.addWidget(self.remove_rule_btn)

        self.clear_rules_btn = QPushButton("Clear All")
        self.clear_rules_btn.clicked.connect(self._clear_rules)
        ctrl_layout.addWidget(self.clear_rules_btn)

        ctrl_layout.addStretch()

        # Test rule
        ctrl_layout.addWidget(QLabel("── Test Pipeline ──"))
        self.test_input = QLineEdit()
        self.test_input.setPlaceholderText("Type a sample payload...")
        ctrl_layout.addWidget(self.test_input)

        self.test_btn = QPushButton("Test Rule")
        self.test_btn.clicked.connect(self._test_rule)
        ctrl_layout.addWidget(self.test_btn)

        self.test_output = QLineEdit()
        self.test_output.setReadOnly(True)
        self.test_output.setPlaceholderText("Transformed result")
        ctrl_layout.addWidget(self.test_output)

        rules_row.addLayout(ctrl_layout, 1)
        rules_layout.addLayout(rules_row)

        sub_tabs.addTab(rules_widget, "Processing Rules")

        # === Transport Encoding tab ===
        encoding_widget = QWidget()
        enc_layout = QVBoxLayout(encoding_widget)
        enc_layout.addWidget(QLabel(
            "Select characters to URL-encode in the final payload injection:"
        ))

        self._encoding_checks: dict[str, QCheckBox] = {}
        chars = [
            ("Space", " "), ("&", "&"), ("=", "="), ("#", "#"),
            ("+", "+"), ("%", "%"), ("/", "/"), (";", ";"),
            ("?", "?"), ("@", "@"), ("!", "!"), ("'", "'"),
            ('"', '"'), ("<", "<"), (">", ">"),
        ]
        enc_grid = QHBoxLayout()
        col_layouts = [QVBoxLayout() for _ in range(3)]
        for i, (label, ch) in enumerate(chars):
            cb = QCheckBox(f"{label}  →  %{ord(ch):02X}")
            self._encoding_checks[ch] = cb
            col_layouts[i % 3].addWidget(cb)
        for cl in col_layouts:
            cl.addStretch()
            enc_grid.addLayout(cl)
        enc_layout.addLayout(enc_grid)
        enc_layout.addStretch()

        sub_tabs.addTab(encoding_widget, "Payload Encoding")

        layout.addWidget(sub_tabs, 1)

    # -- type switching --

    def _update_num_preview(self, *_) -> None:
        """Show live examples of what the number generator will produce."""
        try:
            base = 16 if self.num_hex_radio.isChecked() else 10
            gen = number_range_generator(
                self.num_start.value(), self.num_end.value(),
                self.num_step.value(),
                self.num_min_int.value(), self.num_max_int.value(),
                self.num_min_frac.value(), self.num_max_frac.value(),
                base, False,
            )
            samples = []
            for i, val in enumerate(gen):
                if i < 4:
                    samples.append(val)
                elif i == 4:
                    samples.append("...")
                    last = val
                else:
                    last = val
            if len(samples) > 4 and 'last' in dir():
                samples.append(last)
            self.num_preview_label.setText(", ".join(samples))
        except Exception:
            self.num_preview_label.setText("—")

    def _on_type_changed(self, idx: int) -> None:
        self.manual_group.setVisible(idx == 0)
        self.numbers_group.setVisible(idx == 1)
        self.brute_group.setVisible(idx == 2)
        self.null_group.setVisible(idx == 3)
        self.file_group.setVisible(idx == 4)

    def _on_rule_type_changed(self, idx: int) -> None:
        rt = ALL_RULE_TYPES[idx]
        needs_p1 = rt in (
            RuleType.PREFIX, RuleType.SUFFIX, RuleType.MATCH_REPLACE,
            RuleType.NUMBER_PAD,
        )
        needs_p2 = rt == RuleType.MATCH_REPLACE
        self.rule_param1.setEnabled(needs_p1)
        self.rule_param2.setEnabled(needs_p2)

    # -- file browse --

    def _browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist", "", "Text Files (*.txt *.lst *.csv);;All Files (*)"
        )
        if path:
            self._file_path = path
            self.file_path_edit.setText(path)

    # -- manual list modifiers --

    def _shuffle_manual(self) -> None:
        import random
        lines = self.manual_text.toPlainText().strip().split("\n")
        random.shuffle(lines)
        self.manual_text.setPlainText("\n".join(lines))

    def _dedup_manual(self) -> None:
        lines = self.manual_text.toPlainText().strip().split("\n")
        seen: set[str] = set()
        unique: list[str] = []
        for line in lines:
            if line not in seen:
                seen.add(line)
                unique.append(line)
        self.manual_text.setPlainText("\n".join(unique))

    # -- rule management --

    def _add_rule(self) -> None:
        idx = self.rule_type_combo.currentIndex()
        rt = ALL_RULE_TYPES[idx]
        rule = ProcessingRule(
            rule_type=rt,
            param1=self.rule_param1.text(),
            param2=self.rule_param2.text(),
        )
        self.processor.add_rule(rule)
        self._refresh_rules_model()

    def _remove_rule(self) -> None:
        indexes = self.rules_list.selectedIndexes()
        if indexes:
            self.processor.remove_rule(indexes[0].row())
            self._refresh_rules_model()

    def _clear_rules(self) -> None:
        self.processor.clear_rules()
        self._refresh_rules_model()

    def _refresh_rules_model(self) -> None:
        self._rules_model.setStringList([str(r) for r in self.processor.rules])

    def _test_rule(self) -> None:
        sample = self.test_input.text()
        result = self.processor.process(sample)
        result = self._build_transport_encoder().encode(result)
        self.test_output.setText(result)

    # -- public API --

    def _build_transport_encoder(self) -> TransportEncoder:
        chars = set()
        for ch, cb in self._encoding_checks.items():
            if cb.isChecked():
                chars.add(ch)
        return TransportEncoder(chars_to_encode=chars)

    def get_transport_encoder(self) -> TransportEncoder:
        return self._build_transport_encoder()

    def get_processor(self) -> PayloadProcessor:
        return self.processor

    def get_payload_generator_for_set(self, set_idx: int, start_index: int = 0) -> Iterator[str]:
        """Build generator from a specific set's saved state (for pitchfork/cluster_bomb)."""
        # Save current UI, briefly switch to target set, build generator, switch back
        self._save_set_state(self._current_set_idx)
        saved_idx = self._current_set_idx
        self._load_set_state(set_idx)
        gen = self.get_payload_generator(start_index)
        self._load_set_state(saved_idx)
        self._current_set_idx = saved_idx
        return gen

    def get_payload_generator(self, start_index: int = 0) -> Iterator[str]:
        """Build and return a payload generator based on current settings."""
        idx = self.type_combo.currentIndex()

        if idx == 0:
            # Simple list
            items = self.manual_text.toPlainText().strip().split("\n")
            gen = manual_list_generator(items)
        elif idx == 1:
            # Numbers
            base = 16 if self.num_hex_radio.isChecked() else 10
            gen = number_range_generator(
                self.num_start.value(),
                self.num_end.value(),
                self.num_step.value(),
                self.num_min_int.value(),
                self.num_max_int.value(),
                self.num_min_frac.value(),
                self.num_max_frac.value(),
                base,
                self.num_random_radio.isChecked(),
            )
        elif idx == 2:
            # Brute-forcer
            gen = bruteforce_generator(
                self.brute_charset.text(),
                self.brute_min.value(),
                self.brute_max.value(),
            )
        elif idx == 3:
            # Null payloads
            gen = null_payload_generator(self.null_count.value())
        elif idx == 4:
            # File wordlist
            gen = wordlist_generator(self._file_path, start_index)
        else:
            gen = manual_list_generator([])

        # Apply length filter if enabled
        if self.filter_check.isChecked():
            from engine.payloads import filter_by_length
            gen = filter_by_length(gen, self.filter_min.value(), self.filter_max.value())

        # Apply repeat
        repeat = self.repeat_count.value()
        if repeat > 1:
            gen = _repeat_generator(gen, repeat)

        # Apply shuffle if random order selected
        if self.order_random_radio.isChecked():
            import random
            items = list(gen)
            random.shuffle(items)
            gen = iter(items)

        return gen

    def estimate_payload_count(self) -> int:
        """Estimate total payload count for progress bar."""
        idx = self.type_combo.currentIndex()
        if idx == 0:
            base = len(self.manual_text.toPlainText().strip().split("\n"))
        elif idx == 1:
            start = self.num_start.value()
            end = self.num_end.value()
            step = max(0.000001, self.num_step.value())
            base = max(0, int((end - start) / step) + 1)
        elif idx == 2:
            charset_len = len(self.brute_charset.text()) or 26
            mn, mx = self.brute_min.value(), self.brute_max.value()
            base = sum(charset_len ** i for i in range(mn, mx + 1))
        elif idx == 3:
            base = self.null_count.value()
        elif idx == 4:
            if self._file_path:
                try:
                    with open(self._file_path, "rb") as f:
                        base = sum(1 for _ in f)
                except OSError:
                    base = 0
            else:
                base = 0
        else:
            base = 0
        return base * self.repeat_count.value()

    def get_data(self) -> dict:
        """Serialize all payload set states for save/load."""
        self._save_set_state(self._current_set_idx)
        sets = []
        for s in self._set_states:
            sets.append({
                "type_idx": s["type_idx"],
                "manual_text": s["manual_text"],
                "file_path": s["file_path"],
                "num_start": s["num_start"],
                "num_end": s["num_end"],
                "num_step": s["num_step"],
                "num_min_int": s["num_min_int"],
                "num_max_int": s["num_max_int"],
                "num_min_frac": s["num_min_frac"],
                "num_max_frac": s["num_max_frac"],
                "num_sequential": s["num_sequential"],
                "num_decimal": s["num_decimal"],
                "brute_charset": s["brute_charset"],
                "brute_min": s["brute_min"],
                "brute_max": s["brute_max"],
                "null_count": s["null_count"],
                "filter_check": s["filter_check"],
                "filter_min": s["filter_min"],
                "filter_max": s["filter_max"],
                "repeat_count": s["repeat_count"],
                "order_sequential": s["order_sequential"],
                "rules": [
                    {"type": r.rule_type.value, "param1": r.param1, "param2": r.param2}
                    for r in s["rules"]
                ],
                "encoding_chars": sorted(s["encoding_chars"]),
            })
        return {"current_set": self._current_set_idx, "sets": sets}

    def set_data(self, data: dict) -> None:
        """Restore all payload set states from saved data."""
        sets = data.get("sets", [])
        for i, sd in enumerate(sets[:self._num_sets]):
            rules = []
            for rd in sd.get("rules", []):
                for rt in RuleType:
                    if rt.value == rd.get("type"):
                        rules.append(ProcessingRule(rt, rd.get("param1", ""), rd.get("param2", "")))
                        break
            self._set_states[i] = {
                "type_idx": sd.get("type_idx", 0),
                "manual_text": sd.get("manual_text", ""),
                "file_path": sd.get("file_path", ""),
                "num_start": sd.get("num_start", 0.0),
                "num_end": sd.get("num_end", 100.0),
                "num_step": sd.get("num_step", 1.0),
                "num_min_int": sd.get("num_min_int", 0),
                "num_max_int": sd.get("num_max_int", 0),
                "num_min_frac": sd.get("num_min_frac", 0),
                "num_max_frac": sd.get("num_max_frac", 0),
                "num_sequential": sd.get("num_sequential", True),
                "num_decimal": sd.get("num_decimal", True),
                "brute_charset": sd.get("brute_charset", "abcdefghijklmnopqrstuvwxyz"),
                "brute_min": sd.get("brute_min", 1),
                "brute_max": sd.get("brute_max", 4),
                "null_count": sd.get("null_count", 100),
                "filter_check": sd.get("filter_check", False),
                "filter_min": sd.get("filter_min", 0),
                "filter_max": sd.get("filter_max", 99999),
                "repeat_count": sd.get("repeat_count", 1),
                "order_sequential": sd.get("order_sequential", True),
                "rules": rules,
                "encoding_chars": set(sd.get("encoding_chars", [])),
            }
        cur = data.get("current_set", 0)
        self.set_combo.setCurrentIndex(cur)
        self._current_set_idx = cur
        self._load_set_state(cur)
