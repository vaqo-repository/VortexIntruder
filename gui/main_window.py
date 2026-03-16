"""
VortexIntruder v1.0 – Main Window
Central application window connecting all tabs and the fuzzer engine.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QCloseEvent, QFont
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QPushButton,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from engine.fuzzer import AttackConfig, FuzzResult, FuzzerEngine
from engine.payloads import (
    battering_ram_iterator,
    cluster_bomb_iterator,
    pitchfork_iterator,
    sniper_iterator,
)
from gui.diff_dialog import DiffDialog
from gui.logger_tab import LoggerTab
from gui.macros_tab import MacrosTab
from gui.payloads_tab import PayloadsTab
from gui.proxy_tab import ProxyTab
from gui.repeater_tab import RepeaterTab
from gui.request_tab import RequestTab
from gui.results_tab import ResultsTab
from gui.settings_tab import SettingsTab
from gui.styles import DARK_STYLESHEET, LIGHT_STYLESHEET


class MainWindow(QMainWindow):
    """VortexIntruder main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("VortexIntruder v1.0 - HTTP Fuzzer  |  by Vaqo")
        self.setMinimumSize(1100, 750)
        self.resize(1300, 850)

        self._engine: FuzzerEngine | None = None
        self._last_session_index = 0
        self._current_theme = "dark"

        self._init_ui()
        self._connect_signals()
        self.setStyleSheet(DARK_STYLESHEET)
        self.statusBar().showMessage("Ready  |  VortexIntruder v1.0  |  by Vaqo")

    # ------------------------------------------------------------------ UI

    def _init_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(6, 6, 6, 6)
        main_layout.setSpacing(4)

        # Title bar
        title_row = QHBoxLayout()
        title_lbl = QLabel("VortexIntruder v1.0")
        title_lbl.setObjectName("titleLabel")
        title_row.addWidget(title_lbl)
        title_row.addStretch()

        # Theme switcher
        theme_label = QLabel("Theme:")
        theme_label.setStyleSheet("font-weight: bold; margin-right: 4px;")
        title_row.addWidget(theme_label)

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark", "Light"])
        self.theme_combo.setFixedWidth(120)
        self.theme_combo.setCurrentIndex(0)
        self.theme_combo.currentIndexChanged.connect(self._on_theme_changed)
        title_row.addWidget(self.theme_combo)

        author_lbl = QLabel("by Vaqo")
        author_lbl.setStyleSheet(
            "color: #4ecca3; font-size: 13px; font-weight: bold; "
            "font-style: italic; margin-right: 16px;"
        )
        title_row.addWidget(author_lbl)

        # Save / Load scenario buttons
        self.save_scenario_btn = QPushButton("Save Scenario")
        self.save_scenario_btn.clicked.connect(self._save_scenario)
        self.load_scenario_btn = QPushButton("Load Scenario")
        self.load_scenario_btn.clicked.connect(self._load_scenario)
        title_row.addWidget(self.save_scenario_btn)
        title_row.addWidget(self.load_scenario_btn)

        # Control buttons
        self.start_btn = QPushButton("Start Attack")
        self.start_btn.setObjectName("startButton")
        self.start_btn.clicked.connect(self._start_attack)

        self.pause_btn = QPushButton("Pause")
        self.pause_btn.setEnabled(False)
        self.pause_btn.clicked.connect(self._toggle_pause)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("stopButton")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_attack)

        title_row.addWidget(self.start_btn)
        title_row.addWidget(self.pause_btn)
        title_row.addWidget(self.stop_btn)
        main_layout.addLayout(title_row)

        # Tab widget
        self.tabs = QTabWidget()

        self.request_tab = RequestTab()
        self.payloads_tab = PayloadsTab()
        self.settings_tab = SettingsTab()
        self.macros_tab = MacrosTab()
        self.repeater_tab = RepeaterTab()
        self.results_tab = ResultsTab()
        self.logger_tab = LoggerTab()
        self.proxy_tab = ProxyTab()

        self.tabs.addTab(self.request_tab, "Target & Request")
        self.tabs.addTab(self.payloads_tab, "Payloads")
        self.tabs.addTab(self.settings_tab, "Settings")
        self.tabs.addTab(self.macros_tab, "Macros")
        self.tabs.addTab(self.repeater_tab, "Repeater")
        self.tabs.addTab(self.results_tab, "Results")
        self.tabs.addTab(self.logger_tab, "Logger")
        self.tabs.addTab(self.proxy_tab, "HTTP Proxy")

        main_layout.addWidget(self.tabs, 1)

        # Status bar
        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)

    def _connect_signals(self) -> None:
        # Results tab inter-tab signals
        self.results_tab.send_to_request.connect(self._on_send_to_request)
        self.results_tab.compare_responses.connect(self._on_compare_responses)
        self.results_tab.send_to_repeater.connect(self._on_send_to_repeater)
        # Repeater → Intruder
        self.repeater_tab.send_to_intruder.connect(self._on_send_to_request_with_target)
        # Proxy → Repeater
        self.proxy_tab.send_to_repeater.connect(self._on_send_to_repeater)

    # -------------------------------------------------------------- THEME

    def _on_theme_changed(self, index: int) -> None:
        if index == 0:
            self._current_theme = "dark"
            self.setStyleSheet(DARK_STYLESHEET)
        else:
            self._current_theme = "light"
            self.setStyleSheet(LIGHT_STYLESHEET)

    # -------------------------------------------------------------- ATTACK

    def _start_attack(self) -> None:
        raw = self.request_tab.get_raw_request()
        if not raw.strip():
            QMessageBox.warning(self, "No Request", "Please paste a raw HTTP request first.")
            return

        position_count = self.request_tab.get_position_count()
        if position_count == 0:
            QMessageBox.warning(
                self, "No Positions",
                "No § markers found. Highlight text and click 'Add §'.",
            )
            return

        # Read and immediately reset resume index
        start_idx = self.settings_tab.get_start_index()
        self.settings_tab.set_resume_index(0)

        # Build attack config
        config = AttackConfig(
            raw_request=raw,
            target_override=self.request_tab.get_target(),
            attack_type=self.settings_tab.get_attack_type(),
            concurrency=self.settings_tab.get_concurrency(),
            timeout=self.settings_tab.get_timeout(),
            follow_redirects=self.settings_tab.get_follow_redirects(),
            update_content_length=self.settings_tab.get_update_content_length(),
            proxy=self.settings_tab.get_proxy(),
            connection_header=self.settings_tab.get_connection_header(),
            grep_match_strings=self.settings_tab.get_grep_match_strings(),
            grep_exclude_strings=self.settings_tab.get_grep_exclude_strings(),
            grep_extract_regex=self.settings_tab.get_grep_extract_regex(),
            verify_ssl=self.settings_tab.get_verify_ssl(),
            cookie_handling=self.settings_tab.get_cookie_handling(),
            start_index=start_idx,
            delay_ms=self.settings_tab.get_delay_ms(),
            jitter_ms=self.settings_tab.get_jitter_ms(),
            auto_pause_errors=self.settings_tab.get_auto_pause_enabled(),
            auto_pause_threshold=self.settings_tab.get_auto_pause_threshold(),
            interleave_enabled=self.settings_tab.get_interleave_enabled(),
            interleave_every=self.settings_tab.get_interleave_every(),
            interleave_request=self.settings_tab.get_interleave_request(),
            interleave_follow_redirects=self.settings_tab.get_interleave_follow_redirects(),
            macros=self.macros_tab.get_macro_configs(),
            auto_ip_rotate=self.settings_tab.get_auto_ip_rotate(),
            ip_rotate_headers=self.settings_tab.get_ip_rotate_headers(),
        )

        # Build payload iterator based on attack type
        attack_type = config.attack_type

        try:
            gen1 = self.payloads_tab.get_payload_generator(start_idx)
            est = self.payloads_tab.estimate_payload_count()

            if attack_type == "sniper":
                iterator = sniper_iterator(gen1, position_count)
                total = est * position_count
            elif attack_type == "battering_ram":
                iterator = battering_ram_iterator(gen1)
                total = est
            elif attack_type == "pitchfork":
                gens = [self.payloads_tab.get_payload_generator_for_set(i, start_idx)
                        for i in range(position_count)]
                iterator = pitchfork_iterator(*gens)
                total = est
            elif attack_type == "cluster_bomb":
                gens = [self.payloads_tab.get_payload_generator_for_set(i, start_idx)
                        for i in range(position_count)]
                iterator = cluster_bomb_iterator(*gens)
                total = est ** position_count if position_count > 0 else est
            else:
                iterator = battering_ram_iterator(gen1)
                total = est

        except Exception as e:
            QMessageBox.critical(self, "Payload Error", str(e))
            return

        # Create and configure engine
        self._engine = FuzzerEngine()
        self._engine.config = config
        self._engine.processor = self.payloads_tab.get_processor()
        self._engine.transport_encoder = self.payloads_tab.get_transport_encoder()
        self._engine.payload_iterator = iterator
        self._engine.total_payloads = total

        # Connect engine signals
        self._engine.result_ready.connect(self.results_tab.add_result)
        self._engine.stats_update.connect(self.results_tab.update_stats)
        self._engine.progress.connect(self.results_tab.update_progress)
        self._engine.log_message.connect(self.logger_tab.append_log)
        self._engine.attack_finished.connect(self._on_attack_finished)
        self._engine.session_index.connect(self._on_session_index)

        # Update UI state
        self.start_btn.setEnabled(False)
        self.pause_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)
        self.results_tab.clear_results()
        self.logger_tab.append_log(
            f"[INFO] Attack started: {attack_type} | "
            f"Concurrency: {config.concurrency} | "
            f"Estimated payloads: {total}"
        )

        # Switch to results
        self.tabs.setCurrentWidget(self.results_tab)

        # Start engine thread
        self._engine.start()
        self._status_bar.showMessage("Attack running...")

    def _toggle_pause(self) -> None:
        if self._engine is None:
            return
        if self._engine.is_paused:
            self._engine.resume()
            self.pause_btn.setText("Pause")
            self._status_bar.showMessage("Attack running...")
        else:
            self._engine.pause()
            self.pause_btn.setText("Resume")
            self._status_bar.showMessage("Attack paused")

    def _stop_attack(self) -> None:
        if self._engine:
            self._engine.stop()
            self._status_bar.showMessage("Stopping...")

    def _on_attack_finished(self) -> None:
        self.start_btn.setEnabled(True)
        self.pause_btn.setEnabled(False)
        self.pause_btn.setText("Pause")
        self.stop_btn.setEnabled(False)
        self._status_bar.showMessage(
            f"Attack complete  |  Last index: {self._last_session_index}"
        )
        self.logger_tab.append_log(
            f"[INFO] Attack finished. Last index: {self._last_session_index} "
            f"(set 'Start from index' manually to resume)"
        )

    def _on_session_index(self, idx: int) -> None:
        self._last_session_index = idx

    # -------------------------------------------------------- INTER-TAB

    def _on_send_to_request(self, raw_text: str) -> None:
        self.request_tab.set_raw_request(raw_text)
        self.tabs.setCurrentWidget(self.request_tab)

    def _on_send_to_request_with_target(self, raw_text: str, target: str) -> None:
        self.request_tab.set_raw_request(raw_text)
        if target:
            self.request_tab.set_target(target)
        self.tabs.setCurrentWidget(self.request_tab)

    def _on_send_to_repeater(self, raw_text: str) -> None:
        self.repeater_tab.add_request(raw_text)
        self.tabs.setCurrentWidget(self.repeater_tab)

    def _on_compare_responses(self, body1: str, body2: str) -> None:
        dlg = DiffDialog(body1, body2, self)
        dlg.exec()

    # -------------------------------------------------------- SAVE / LOAD SCENARIO

    def _collect_scenario(self) -> dict:
        return {
            "version": "1.1",
            "request": self.request_tab.get_data(),
            "payloads": self.payloads_tab.get_data(),
            "settings": self.settings_tab.get_data(),
            "macros": self.macros_tab.get_data(),
        }

    def _apply_scenario(self, scenario: dict) -> None:
        if "request" in scenario:
            self.request_tab.set_data(scenario["request"])
        if "payloads" in scenario:
            self.payloads_tab.set_data(scenario["payloads"])
        if "settings" in scenario:
            self.settings_tab.set_data(scenario["settings"])
        if "macros" in scenario:
            self.macros_tab.set_data(scenario["macros"])

    def _save_scenario(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Scenario", "", "VortexIntruder Scenario (*.vortex);;JSON (*.json);;All Files (*)"
        )
        if not path:
            return
        try:
            scenario = self._collect_scenario()
            with open(path, "w", encoding="utf-8") as f:
                json.dump(scenario, f, indent=2, ensure_ascii=False)
            self._status_bar.showMessage(f"Scenario saved: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", str(e))

    def _load_scenario(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Scenario", "", "VortexIntruder Scenario (*.vortex);;JSON (*.json);;All Files (*)"
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                scenario = json.load(f)
            self._apply_scenario(scenario)
            self._status_bar.showMessage(f"Scenario loaded: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Load Error", str(e))

    # -------------------------------------------------------- CLEAN EXIT

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._engine and self._engine.isRunning():
            reply = QMessageBox.question(
                self,
                "Attack Running",
                "An attack is still running. Stop and exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return
            self._engine.stop()
            self._engine.wait(3000)
        self.proxy_tab.cleanup()
        event.accept()
