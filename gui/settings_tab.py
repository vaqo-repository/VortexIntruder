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

        # -- Throttling & Interleave --
        throttle_group = QGroupBox("Throttling & Safe Request Interleave")
        thr_layout = QVBoxLayout(throttle_group)
        thr_layout.setContentsMargins(10, 8, 10, 8)
        thr_layout.setSpacing(8)

        # Delay row
        delay_row = QHBoxLayout()
        self.delay_check = QCheckBox("Delay between requests:")
        delay_row.addWidget(self.delay_check)
        self.delay_spin = QDoubleSpinBox()
        self.delay_spin.setRange(0, 60000)
        self.delay_spin.setValue(0)
        self.delay_spin.setSuffix(" ms")
        self.delay_spin.setDecimals(0)
        self.delay_spin.setMinimumWidth(100)
        delay_row.addWidget(self.delay_spin)
        delay_row.addWidget(QLabel("  Jitter ±"))
        self.jitter_spin = QDoubleSpinBox()
        self.jitter_spin.setRange(0, 30000)
        self.jitter_spin.setValue(0)
        self.jitter_spin.setSuffix(" ms")
        self.jitter_spin.setDecimals(0)
        self.jitter_spin.setMinimumWidth(100)
        delay_row.addWidget(self.jitter_spin)
        delay_row.addStretch()
        thr_layout.addLayout(delay_row)

        # Auto-pause row
        autopause_row = QHBoxLayout()
        self.autopause_check = QCheckBox("Auto-pause after")
        autopause_row.addWidget(self.autopause_check)
        self.autopause_spin = QSpinBox()
        self.autopause_spin.setRange(1, 9999)
        self.autopause_spin.setValue(5)
        autopause_row.addWidget(self.autopause_spin)
        autopause_row.addWidget(QLabel("consecutive errors/non-2xx"))
        autopause_row.addStretch()
        thr_layout.addLayout(autopause_row)

        # Interleave row
        interleave_row = QHBoxLayout()
        self.interleave_check = QCheckBox("Send safe request every")
        interleave_row.addWidget(self.interleave_check)
        self.interleave_every_spin = QSpinBox()
        self.interleave_every_spin.setRange(1, 99999)
        self.interleave_every_spin.setValue(3)
        interleave_row.addWidget(self.interleave_every_spin)
        interleave_row.addWidget(QLabel("fuzz requests"))
        interleave_row.addStretch()
        thr_layout.addLayout(interleave_row)

        self.interleave_check.toggled.connect(self._on_interleave_toggled)
        thr_layout.addWidget(QLabel("Safe Request (raw HTTP — sent as-is, no payload substitution):"))
        self.interleave_request_edit = QPlainTextEdit()
        self.interleave_request_edit.setMaximumHeight(130)
        self.interleave_request_edit.setPlaceholderText(
            "GET /home HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\n\r\n"
        )
        self.interleave_request_edit.setEnabled(False)
        thr_layout.addWidget(self.interleave_request_edit)

        self.interleave_follow_redirects = QCheckBox("Follow redirects for safe request")
        self.interleave_follow_redirects.setChecked(True)
        self.interleave_follow_redirects.setEnabled(False)
        thr_layout.addWidget(self.interleave_follow_redirects)

        layout.addWidget(throttle_group)

        # -- IP Rotation / Anti-Ban --
        ip_group = QGroupBox("IP Rotation / Anti-Ban Headers")
        ip_layout = QVBoxLayout(ip_group)
        ip_layout.setContentsMargins(10, 8, 10, 8)
        ip_layout.setSpacing(6)

        self.ip_rotate_check = QCheckBox("Enable auto IP rotation (random IP per request)")
        self.ip_rotate_check.setToolTip(
            "Automatically inject spoofed IP headers with a random IP address on each request.\n"
            "This can help bypass IP-based rate limiting on misconfigured WAFs/proxies."
        )
        ip_layout.addWidget(self.ip_rotate_check)

        ip_layout.addWidget(QLabel("Headers to inject (check the ones you want):"))

        self._ip_header_checks: dict[str, QCheckBox] = {}
        _ip_headers = [
            ("X-Forwarded-For", True),
            ("X-Real-IP", True),
            ("X-Originating-IP", False),
            ("X-Remote-IP", False),
            ("X-Remote-Addr", False),
            ("X-Client-IP", False),
            ("CF-Connecting-IP", False),
            ("True-Client-IP", False),
            ("Forwarded", False),
            ("X-Forwarded-Host", False),
        ]
        row1 = QHBoxLayout()
        row2 = QHBoxLayout()
        for i, (name, default_on) in enumerate(_ip_headers):
            cb = QCheckBox(name)
            cb.setChecked(default_on)
            self._ip_header_checks[name] = cb
            if i < 5:
                row1.addWidget(cb)
            else:
                row2.addWidget(cb)
        row1.addStretch()
        row2.addStretch()
        ip_layout.addLayout(row1)
        ip_layout.addLayout(row2)

        layout.addWidget(ip_group)

        layout.addStretch()

        scroll.setWidget(container)
        outer_layout.addWidget(scroll)

    def _update_conc_label(self, val: int) -> None:
        self.conc_label.setText(str(val))

    def _on_interleave_toggled(self, checked: bool) -> None:
        self.interleave_request_edit.setEnabled(checked)
        self.interleave_follow_redirects.setEnabled(checked)

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

    def get_delay_ms(self) -> float:
        return self.delay_spin.value() if self.delay_check.isChecked() else 0.0

    def get_jitter_ms(self) -> float:
        return self.jitter_spin.value() if self.delay_check.isChecked() else 0.0

    def get_auto_pause_enabled(self) -> bool:
        return self.autopause_check.isChecked()

    def get_auto_pause_threshold(self) -> int:
        return self.autopause_spin.value()

    def get_interleave_enabled(self) -> bool:
        return self.interleave_check.isChecked()

    def get_interleave_every(self) -> int:
        return self.interleave_every_spin.value()

    def get_interleave_request(self) -> str:
        return self.interleave_request_edit.toPlainText().strip()

    def get_interleave_follow_redirects(self) -> bool:
        return self.interleave_follow_redirects.isChecked()

    def get_auto_ip_rotate(self) -> bool:
        return self.ip_rotate_check.isChecked()

    def get_ip_rotate_headers(self) -> list[str]:
        return [name for name, cb in self._ip_header_checks.items() if cb.isChecked()]

    def get_data(self) -> dict:
        return {
            "attack_type": self.get_attack_type(),
            "concurrency": self.get_concurrency(),
            "timeout": self.get_timeout(),
            "follow_redirects": self.get_follow_redirects(),
            "update_content_length": self.get_update_content_length(),
            "verify_ssl": self.get_verify_ssl(),
            "connection_header": self.connection_combo.currentIndex(),
            "cookie_handling": self.cookie_combo.currentIndex(),
            "proxy": self.get_proxy(),
            "grep_match": self.grep_match_text.toPlainText(),
            "grep_exclude": self.grep_exclude_text.toPlainText(),
            "grep_extract": self.get_grep_extract_regex(),
            "start_index": self.get_start_index(),
            "delay_check": self.delay_check.isChecked(),
            "delay_ms": self.delay_spin.value(),
            "jitter_ms": self.jitter_spin.value(),
            "autopause_check": self.autopause_check.isChecked(),
            "autopause_threshold": self.autopause_spin.value(),
            "interleave_check": self.interleave_check.isChecked(),
            "interleave_every": self.interleave_every_spin.value(),
            "interleave_request": self.interleave_request_edit.toPlainText(),
            "interleave_follow_redirects": self.interleave_follow_redirects.isChecked(),
            "auto_ip_rotate": self.ip_rotate_check.isChecked(),
            "ip_rotate_headers": {name: cb.isChecked() for name, cb in self._ip_header_checks.items()},
        }

    def set_data(self, data: dict) -> None:
        # Attack type
        at = data.get("attack_type", "sniper")
        for i, (_, key) in enumerate(ATTACK_TYPES):
            if key == at:
                self.attack_combo.setCurrentIndex(i)
                break
        self.concurrency_slider.setValue(data.get("concurrency", 20))
        self.timeout_spin.setValue(data.get("timeout", 10.0))
        self.follow_redirects.setChecked(data.get("follow_redirects", False))
        self.update_content_length.setChecked(data.get("update_content_length", True))
        self.verify_ssl.setChecked(data.get("verify_ssl", False))
        self.connection_combo.setCurrentIndex(data.get("connection_header", 0))
        self.cookie_combo.setCurrentIndex(data.get("cookie_handling", 0))
        self.proxy_input.setText(data.get("proxy", ""))
        self.grep_match_text.setPlainText(data.get("grep_match", ""))
        self.grep_exclude_text.setPlainText(data.get("grep_exclude", ""))
        self.grep_extract_input.setText(data.get("grep_extract", ""))
        self.resume_index.setValue(data.get("start_index", 0))
        self.delay_check.setChecked(data.get("delay_check", False))
        self.delay_spin.setValue(data.get("delay_ms", 0))
        self.jitter_spin.setValue(data.get("jitter_ms", 0))
        self.autopause_check.setChecked(data.get("autopause_check", False))
        self.autopause_spin.setValue(data.get("autopause_threshold", 5))
        self.interleave_check.setChecked(data.get("interleave_check", False))
        self.interleave_every_spin.setValue(data.get("interleave_every", 3))
        self.interleave_request_edit.setPlainText(data.get("interleave_request", ""))
        self.interleave_follow_redirects.setChecked(data.get("interleave_follow_redirects", True))
        self.ip_rotate_check.setChecked(data.get("auto_ip_rotate", False))
        ip_hdrs = data.get("ip_rotate_headers", {})
        if isinstance(ip_hdrs, dict):
            for name, cb in self._ip_header_checks.items():
                if name in ip_hdrs:
                    cb.setChecked(ip_hdrs[name])
