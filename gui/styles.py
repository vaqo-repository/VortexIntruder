"""
VortexIntruder v1.0 – Theme Styles
Dark and Light QSS stylesheets for a professional security-tool aesthetic.
"""

LIGHT_STYLESHEET = """
/* ====================== GLOBAL ====================== */
QWidget {
    background-color: #f5f6fa;
    color: #2d3436;
    font-family: "Segoe UI", "Consolas", monospace;
    font-size: 13px;
}

QMainWindow {
    background-color: #ebedf0;
}

/* ====================== TAB WIDGET ====================== */
QTabWidget::pane {
    border: 1px solid #c8ccd0;
    background-color: #f5f6fa;
    border-radius: 4px;
}

QTabBar::tab {
    background-color: #e4e6e9;
    color: #636e72;
    padding: 8px 20px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    border: 1px solid #c8ccd0;
    border-bottom: none;
    min-width: 100px;
}

QTabBar::tab:selected {
    background-color: #ffffff;
    color: #d63031;
    font-weight: bold;
    border-bottom: 2px solid #d63031;
}

QTabBar::tab:hover {
    background-color: #dfe4ea;
    color: #2d3436;
}

/* ====================== BUTTONS ====================== */
QPushButton {
    background-color: #dfe6e9;
    color: #2d3436;
    border: 1px solid #b2bec3;
    border-radius: 4px;
    padding: 6px 16px;
    min-height: 24px;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #b2bec3;
    border-color: #d63031;
}

QPushButton:pressed {
    background-color: #d63031;
    color: #ffffff;
}

QPushButton:disabled {
    background-color: #ecf0f1;
    color: #b2bec3;
    border-color: #dcdde1;
}

QPushButton#startButton {
    background-color: #00b894;
    border-color: #00cec9;
    color: #ffffff;
    font-size: 14px;
    padding: 8px 24px;
}

QPushButton#startButton:hover {
    background-color: #00cec9;
}

QPushButton#stopButton {
    background-color: #d63031;
    border-color: #e17055;
    color: #ffffff;
}

QPushButton#stopButton:hover {
    background-color: #e17055;
}

QPushButton#markerButton {
    background-color: #d63031;
    color: #ffffff;
    border-color: #e17055;
    font-weight: bold;
}

QPushButton#markerButton:hover {
    background-color: #e17055;
}

/* ====================== TEXT EDITORS ====================== */
QPlainTextEdit, QTextEdit {
    background-color: #ffffff;
    color: #2d3436;
    border: 1px solid #c8ccd0;
    border-radius: 4px;
    padding: 4px;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 13px;
    selection-background-color: #74b9ff;
    selection-color: #2d3436;
}

/* ====================== LINE EDITS ====================== */
QLineEdit {
    background-color: #ffffff;
    color: #2d3436;
    border: 1px solid #c8ccd0;
    border-radius: 4px;
    padding: 4px 8px;
    min-height: 26px;
}

QLineEdit:focus {
    border-color: #d63031;
}

/* ====================== COMBO BOX ====================== */
QComboBox {
    background-color: #ffffff;
    color: #2d3436;
    border: 1px solid #c8ccd0;
    border-radius: 4px;
    padding: 4px 8px;
    min-height: 26px;
}

QComboBox::drop-down {
    border: none;
    width: 24px;
}

QComboBox QAbstractItemView {
    background-color: #ffffff;
    color: #2d3436;
    selection-background-color: #74b9ff;
    border: 1px solid #c8ccd0;
}

/* ====================== SPIN BOX ====================== */
QSpinBox, QDoubleSpinBox {
    background-color: #ffffff;
    color: #2d3436;
    border: 1px solid #c8ccd0;
    border-radius: 4px;
    padding: 4px;
    min-height: 26px;
}

/* ====================== SLIDER ====================== */
QSlider::groove:horizontal {
    height: 6px;
    background: #c8ccd0;
    border-radius: 3px;
}

QSlider::handle:horizontal {
    background: #d63031;
    width: 16px;
    height: 16px;
    margin: -5px 0;
    border-radius: 8px;
}

QSlider::sub-page:horizontal {
    background: #d63031;
    border-radius: 3px;
}

/* ====================== TABLE ====================== */
QTableWidget, QTableView {
    background-color: #ffffff;
    color: #2d3436;
    gridline-color: #dcdde1;
    border: 1px solid #c8ccd0;
    border-radius: 4px;
    selection-background-color: #dfe6e9;
    alternate-background-color: #f8f9fa;
}

QHeaderView::section {
    background-color: #ebedf0;
    color: #d63031;
    padding: 6px;
    border: none;
    border-right: 1px solid #c8ccd0;
    border-bottom: 1px solid #c8ccd0;
    font-weight: bold;
}

/* ====================== PROGRESS BAR ====================== */
QProgressBar {
    background-color: #dfe6e9;
    border: 1px solid #c8ccd0;
    border-radius: 6px;
    text-align: center;
    color: #2d3436;
    min-height: 20px;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #d63031, stop:1 #e17055);
    border-radius: 5px;
}

/* ====================== CHECK BOX ====================== */
QCheckBox {
    spacing: 8px;
    color: #2d3436;
    min-height: 24px;
    padding: 2px 0;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #b2bec3;
    border-radius: 3px;
    background-color: #ffffff;
}

QCheckBox::indicator:checked {
    background-color: #d63031;
    border-color: #d63031;
}

/* ====================== RADIO BUTTON ====================== */
QRadioButton {
    spacing: 8px;
    color: #2d3436;
    min-height: 24px;
}

QRadioButton::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #b2bec3;
    border-radius: 8px;
    background-color: #ffffff;
}

QRadioButton::indicator:checked {
    background-color: #d63031;
    border-color: #d63031;
}

/* ====================== LIST VIEW ====================== */
QListView {
    background-color: #ffffff;
    color: #2d3436;
    border: 1px solid #c8ccd0;
    border-radius: 4px;
    outline: none;
}

QListView::item {
    padding: 4px;
    border-bottom: 1px solid #dcdde1;
}

QListView::item:selected {
    background-color: #dfe6e9;
    color: #d63031;
}

/* ====================== GROUP BOX ====================== */
QGroupBox {
    border: 1px solid #c8ccd0;
    border-radius: 6px;
    margin-top: 20px;
    padding: 28px 10px 10px 10px;
    font-weight: bold;
    color: #d63031;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    top: 4px;
    padding: 2px 8px;
    background-color: #f5f6fa;
}

/* ====================== SCROLLBAR ====================== */
QScrollBar:vertical {
    background: #ebedf0;
    width: 10px;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background: #b2bec3;
    min-height: 30px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background: #d63031;
}

QScrollBar:horizontal {
    background: #ebedf0;
    height: 10px;
    border-radius: 5px;
}

QScrollBar::handle:horizontal {
    background: #b2bec3;
    min-width: 30px;
    border-radius: 5px;
}

QScrollBar::add-line, QScrollBar::sub-line {
    height: 0px;
    width: 0px;
}

/* ====================== LABELS ====================== */
QLabel {
    color: #2d3436;
    min-height: 18px;
}

QLabel#titleLabel {
    color: #d63031;
    font-size: 18px;
    font-weight: bold;
}

QLabel#statsLabel {
    color: #00b894;
    font-size: 15px;
    font-weight: bold;
    font-family: "Consolas", monospace;
}

/* ====================== MENU ====================== */
QMenu {
    background-color: #ffffff;
    color: #2d3436;
    border: 1px solid #c8ccd0;
}

QMenu::item:selected {
    background-color: #d63031;
    color: #ffffff;
}

/* ====================== SPLITTER ====================== */
QSplitter::handle {
    background-color: #c8ccd0;
}

/* ====================== STATUS BAR ====================== */
QStatusBar {
    background-color: #ebedf0;
    color: #636e72;
    border-top: 1px solid #c8ccd0;
}

/* ====================== TOOL TIP ====================== */
QToolTip {
    background-color: #ffffff;
    color: #2d3436;
    border: 1px solid #d63031;
    padding: 4px;
}

/* ====================== SCROLL AREA ====================== */
QScrollArea {
    background-color: #f5f6fa;
    border: none;
}
"""

DARK_STYLESHEET = """
/* ====================== GLOBAL ====================== */
QWidget {
    background-color: #1e1e1e;
    color: #e0e0e0;
    font-family: "Segoe UI", "Consolas", monospace;
    font-size: 13px;
}

QMainWindow {
    background-color: #252526;
}

/* ====================== TAB WIDGET ====================== */
QTabWidget::pane {
    border: 1px solid #3c3c3c;
    background-color: #1e1e1e;
    border-radius: 4px;
}

QTabBar::tab {
    background-color: #2d2d2d;
    color: #a0a0a0;
    padding: 8px 20px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    border: 1px solid #3c3c3c;
    border-bottom: none;
    min-width: 100px;
}

QTabBar::tab:selected {
    background-color: #3c3c3c;
    color: #e94560;
    font-weight: bold;
}

QTabBar::tab:hover {
    background-color: #383838;
    color: #ffffff;
}

/* ====================== BUTTONS ====================== */
QPushButton {
    background-color: #333333;
    color: #e0e0e0;
    border: 1px solid #4a4a4a;
    border-radius: 4px;
    padding: 6px 16px;
    min-height: 24px;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #4a4a4a;
    border-color: #e94560;
}

QPushButton:pressed {
    background-color: #e94560;
    color: #ffffff;
}

QPushButton:disabled {
    background-color: #2d2d2d;
    color: #606060;
    border-color: #3c3c3c;
}

QPushButton#startButton {
    background-color: #1b8a2a;
    border-color: #22a834;
    color: #ffffff;
    font-size: 14px;
    padding: 8px 24px;
}

QPushButton#startButton:hover {
    background-color: #22a834;
}

QPushButton#stopButton {
    background-color: #c0392b;
    border-color: #e74c3c;
    color: #ffffff;
}

QPushButton#stopButton:hover {
    background-color: #e74c3c;
}

QPushButton#markerButton {
    background-color: #e94560;
    color: #ffffff;
    border-color: #ff6b81;
    font-weight: bold;
}

QPushButton#markerButton:hover {
    background-color: #ff6b81;
}

/* ====================== TEXT EDITORS ====================== */
QPlainTextEdit, QTextEdit {
    background-color: #1a1a1a;
    color: #d4d4d4;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    padding: 4px;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 13px;
    selection-background-color: #e94560;
    selection-color: #ffffff;
}

/* ====================== LINE EDITS ====================== */
QLineEdit {
    background-color: #1a1a1a;
    color: #d4d4d4;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    padding: 4px 8px;
    min-height: 26px;
}

QLineEdit:focus {
    border-color: #e94560;
}

/* ====================== COMBO BOX ====================== */
QComboBox {
    background-color: #1a1a1a;
    color: #d4d4d4;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    padding: 4px 8px;
    min-height: 26px;
}

QComboBox::drop-down {
    border: none;
    width: 24px;
}

QComboBox QAbstractItemView {
    background-color: #252526;
    color: #e0e0e0;
    selection-background-color: #e94560;
    border: 1px solid #3c3c3c;
}

/* ====================== SPIN BOX ====================== */
QSpinBox, QDoubleSpinBox {
    background-color: #1a1a1a;
    color: #d4d4d4;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    padding: 4px;
    min-height: 26px;
}

/* ====================== SLIDER ====================== */
QSlider::groove:horizontal {
    height: 6px;
    background: #3c3c3c;
    border-radius: 3px;
}

QSlider::handle:horizontal {
    background: #e94560;
    width: 16px;
    height: 16px;
    margin: -5px 0;
    border-radius: 8px;
}

QSlider::sub-page:horizontal {
    background: #e94560;
    border-radius: 3px;
}

/* ====================== TABLE ====================== */
QTableWidget, QTableView {
    background-color: #1a1a1a;
    color: #d4d4d4;
    gridline-color: #2d2d2d;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    selection-background-color: #3c3c3c;
    alternate-background-color: #222222;
}

QHeaderView::section {
    background-color: #2d2d2d;
    color: #e94560;
    padding: 6px;
    border: none;
    border-right: 1px solid #3c3c3c;
    border-bottom: 1px solid #3c3c3c;
    font-weight: bold;
}

/* ====================== PROGRESS BAR ====================== */
QProgressBar {
    background-color: #1a1a1a;
    border: 1px solid #3c3c3c;
    border-radius: 6px;
    text-align: center;
    color: #e0e0e0;
    min-height: 20px;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #e94560, stop:1 #ff6b81);
    border-radius: 5px;
}

/* ====================== CHECK BOX ====================== */
QCheckBox {
    spacing: 8px;
    color: #e0e0e0;
    min-height: 24px;
    padding: 2px 0;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #3c3c3c;
    border-radius: 3px;
    background-color: #1a1a1a;
}

QCheckBox::indicator:checked {
    background-color: #e94560;
    border-color: #e94560;
}

/* ====================== LIST VIEW ====================== */
QListView {
    background-color: #1a1a1a;
    color: #d4d4d4;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    outline: none;
}

QListView::item {
    padding: 4px;
    border-bottom: 1px solid #2d2d2d;
}

QListView::item:selected {
    background-color: #3c3c3c;
    color: #e94560;
}

/* ====================== GROUP BOX ====================== */
QGroupBox {
    border: 1px solid #3c3c3c;
    border-radius: 6px;
    margin-top: 20px;
    padding: 28px 10px 10px 10px;
    font-weight: bold;
    color: #e94560;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    top: 4px;
    padding: 2px 8px;
    background-color: #1e1e1e;
}

/* ====================== SCROLLBAR ====================== */
QScrollBar:vertical {
    background: #1a1a1a;
    width: 10px;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background: #4a4a4a;
    min-height: 30px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background: #e94560;
}

QScrollBar:horizontal {
    background: #1a1a1a;
    height: 10px;
    border-radius: 5px;
}

QScrollBar::handle:horizontal {
    background: #4a4a4a;
    min-width: 30px;
    border-radius: 5px;
}

QScrollBar::add-line, QScrollBar::sub-line {
    height: 0px;
    width: 0px;
}

/* ====================== LABELS ====================== */
QLabel {
    color: #c0c0c0;
    min-height: 18px;
}

QLabel#titleLabel {
    color: #e94560;
    font-size: 18px;
    font-weight: bold;
}

QLabel#statsLabel {
    color: #4ecca3;
    font-size: 15px;
    font-weight: bold;
    font-family: "Consolas", monospace;
}

/* ====================== MENU ====================== */
QMenu {
    background-color: #252526;
    color: #e0e0e0;
    border: 1px solid #3c3c3c;
}

QMenu::item:selected {
    background-color: #e94560;
    color: #ffffff;
}

/* ====================== SPLITTER ====================== */
QSplitter::handle {
    background-color: #3c3c3c;
}

/* ====================== STATUS BAR ====================== */
QStatusBar {
    background-color: #252526;
    color: #a0a0a0;
    border-top: 1px solid #3c3c3c;
}

/* ====================== TOOL TIP ====================== */
QToolTip {
    background-color: #2d2d2d;
    color: #e0e0e0;
    border: 1px solid #e94560;
    padding: 4px;
}
"""

# Row highlight color for grep matches
GREP_MATCH_COLOR = "#3d1a1a"
GREP_MATCH_FG = "#ff6b6b"

GREP_MATCH_COLOR_LIGHT = "#ffcccc"
GREP_MATCH_FG_LIGHT = "#c0392b"
