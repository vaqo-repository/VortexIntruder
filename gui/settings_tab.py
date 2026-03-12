"""
VortexIntruder v1.0 – Settings Tab
Attack type, concurrency, proxy, grep, and advanced request options.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QScrollArea,
    QSlider,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)


ATTACK_TYPES = [
    ("Sniper", "sniper"),
    ("Battering Ram", "battering_ram"),
    ("Pitchfork", "pitchfork"),
    ("Cluster Bomb", "cluster_bomb"),
]


class SettingsTab(QWidget):
    """Engine configuration tab."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self) -> None:
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(14)

        # -- Attack type --
        attack_group = QGroupBox("Attack Type")
        att_layout = QHBoxLayout(attack_group)
        att_layout.setContentsMargins(10, 8, 10, 8)
        att_layout.addWidget(QLabel("Type:"))
        self.attack_combo = QComboBox()
        for label, _ in ATTACK_TYPES:
            self.attack_combo.addItem(label)
        att_layout.addWidget(self.attack_combo)
        att_layout.addStretch()
        layout.addWidget(attack_group)

        # -- Concurrency --
        conc_group = QGroupBox("Concurrency")
        conc_layout = QVBoxLayout(conc_group)
        conc_layout.setContentsMargins(10, 8, 10, 8)
        conc_layout.setSpacing(6)
        slider_row = QHBoxLayout()
        slider_row.addWidget(QLabel("Threads:"))
        self.concurrency_slider = QSlider(Qt.Orientation.Horizontal)
        self.concurrency_slider.setRange(1, 200)
        self.concurrency_slider.setValue(20)
        self.concurrency_slider.setTickInterval(10)
        self.concurrency_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.concurrency_slider.valueChanged.connect(self._update_conc_label)
        slider_row.addWidget(self.concurrency_slider)
        self.conc_label = QLabel("20")
        self.conc_label.setObjectName("statsLabel")
        self.conc_label.setMinimumWidth(40)
        slider_row.addWidget(self.conc_label)
        conc_layout.addLayout(slider_row)
        layout.addWidget(conc_group)

        # -- Timeouts --
        timeout_group = QGroupBox("Timeout")
        to_layout = QHBoxLayout(timeout_group)
        to_layout.setContentsMargins(10, 8, 10, 8)
        to_layout.addWidget(QLabel("Request Timeout (s):"))
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(1.0, 300.0)
        self.timeout_spin.setValue(10.0)
        self.timeout_spin.setSingleStep(1.0)
        to_layout.addWidget(self.timeout_spin)
        to_layout.addStretch()
        layout.addWidget(timeout_group)

        # -- Request options --
        req_group = QGroupBox("Request Options")
        req_layout = QVBoxLayout(req_group)
        req_layout.setContentsMargins(10, 8, 10, 8)
        req_layout.setSpacing(6)
        self.follow_redirects = QCheckBox("Follow Redirects")
        self.update_content_length = QCheckBox("Update Content-Length Header")
        self.update_content_length.setChecked(True)
        self.verify_ssl = QCheckBox("Verify SSL Certificates")

        conn_row = QHBoxLayout()
        conn_row.addWidget(QLabel("Connection Header:"))
        self.connection_combo = QComboBox()
        self.connection_combo.addItems(["(Default)", "Connection: close", "Connection: keep-alive"])
        conn_row.addWidget(self.connection_combo)
        conn_row.addStretch()

        cookie_row = QHBoxLayout()
        cookie_row.addWidget(QLabel("Cookie Handling:"))
        self.cookie_combo = QComboBox()
        self.cookie_combo.addItems(["Preserve from Request", "Update from Responses"])
        cookie_row.addWidget(self.cookie_combo)
        cookie_row.addStretch()

        req_layout.addWidget(self.follow_redirects)
        req_layout.addWidget(self.update_content_length)
        req_layout.addWidget(self.verify_ssl)
        req_layout.addLayout(conn_row)
        req_layout.addLayout(cookie_row)
        layout.addWidget(req_group)

        # -- Proxy --
        proxy_group = QGroupBox("Upstream Proxy")
        proxy_layout = QHBoxLayout(proxy_group)
        proxy_layout.setContentsMargins(10, 8, 10, 8)
        proxy_layout.addWidget(QLabel("Proxy URL:"))
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("http://127.0.0.1:8080")
        proxy_layout.addWidget(self.proxy_input)
        layout.addWidget(proxy_group)

        # -- Grep Match --
        grep_group = QGroupBox("Grep – Match / Exclude")
        grep_layout = QVBoxLayout(grep_group)
        grep_layout.setContentsMargins(10, 8, 10, 8)
        grep_layout.setSpacing(6)
        grep_layout.addWidget(QLabel("Match Strings (one per line) — rows highlighted RED:"))
        self.grep_match_text = QPlainTextEdit()
        self.grep_match_text.setMaximumHeight(80)
        self.grep_match_text.setPlaceholderText("Invalid password\nLogin failed")
        grep_layout.addWidget(self.grep_match_text)

        grep_layout.addWidget(QLabel("Exclude Strings (one per line) — rows hidden:"))
        self.grep_exclude_text = QPlainTextEdit()
        self.grep_exclude_text.setMaximumHeight(80)
        self.grep_exclude_text.setPlaceholderText("Try again\nRate limited")
        grep_layout.addWidget(self.grep_exclude_text)
        layout.addWidget(grep_group)

        # -- Grep Extract --
        extract_group = QGroupBox("Grep – Extract (Regex)")
        extract_layout = QHBoxLayout(extract_group)
        extract_layout.setContentsMargins(10, 8, 10, 8)
        extract_layout.addWidget(QLabel("Regex:"))
        self.grep_extract_input = QLineEdit()
        self.grep_extract_input.setPlaceholderText(
            r'<input name="csrf" value="(.*?)"'
        )
        extract_layout.addWidget(self.grep_extract_input)
        layout.addWidget(extract_group)

        # -- Resume --
        resume_group = QGroupBox("Session Resume")
        resume_layout = QHBoxLayout(resume_group)
        resume_layout.setContentsMargins(10, 8, 10, 8)
        resume_layout.addWidget(QLabel("Start from index:"))
        self.resume_index = QSpinBox()
        self.resume_index.setRange(0, 999999999)
        resume_layout.addWidget(self.resume_index)
        resume_layout.addStretch()
        layout.addWidget(resume_group)

        layout.addStretch()

        scroll.setWidget(container)
        outer_layout.addWidget(scroll)

    def _update_conc_label(self, val: int) -> None:
        self.conc_label.setText(str(val))

    # -- public getters --

    def get_attack_type(self) -> str:
        return ATTACK_TYPES[self.attack_combo.currentIndex()][1]

    def get_concurrency(self) -> int:
        return self.concurrency_slider.value()

    def get_timeout(self) -> float:
        return self.timeout_spin.value()

    def get_follow_redirects(self) -> bool:
        return self.follow_redirects.isChecked()

    def get_update_content_length(self) -> bool:
        return self.update_content_length.isChecked()

    def get_verify_ssl(self) -> bool:
        return self.verify_ssl.isChecked()

    def get_proxy(self) -> str:
        return self.proxy_input.text().strip()

    def get_connection_header(self) -> str:
        idx = self.connection_combo.currentIndex()
        if idx == 1:
            return "close"
        if idx == 2:
            return "keep-alive"
        return ""

    def get_cookie_handling(self) -> str:
        return "update" if self.cookie_combo.currentIndex() == 1 else "preserve"

    def get_grep_match_strings(self) -> list[str]:
        text = self.grep_match_text.toPlainText().strip()
        return [s.strip() for s in text.split("\n") if s.strip()] if text else []

    def get_grep_exclude_strings(self) -> list[str]:
        text = self.grep_exclude_text.toPlainText().strip()
        return [s.strip() for s in text.split("\n") if s.strip()] if text else []

    def get_grep_extract_regex(self) -> str:
        return self.grep_extract_input.text().strip()

    def get_start_index(self) -> int:
        return self.resume_index.value()

    def set_resume_index(self, idx: int) -> None:
        self.resume_index.setValue(idx)
