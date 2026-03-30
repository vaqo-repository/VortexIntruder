#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           VortexIntruder v1.0 – HTTP Fuzzer                 ║
║   Professional Asynchronous HTTP Fuzzer with PyQt6 GUI      ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  HOW TO USE:                                                 ║
║  1. Install dependencies:                                    ║
║       pip install -r requirements.txt                        ║
║                                                              ║
║  2. Run the application:                                     ║
║       python vortex_intruder.py                              ║
║                                                              ║
║  3. Workflow:                                                ║
║     a) Paste a raw HTTP request in the "Target & Request"    ║
║        tab.                                                  ║
║     b) Highlight text to fuzz and click "Add §" to mark      ║
║        injection points.                                     ║
║     c) Configure payloads in the "Payloads" tab (wordlist,   ║
║        numbers, brute-force, or manual list).                ║
║     d) Set attack type, concurrency, and grep rules in       ║
║        "Settings".                                           ║
║     e) Click "Start Attack" and monitor results in real      ║
║        time.                                                 ║
║     f) Export results to CSV/JSON from the "Results" tab.    ║
║                                                              ║
║  4. Build standalone .exe:                                   ║
║       pyinstaller --noconfirm --onefile --windowed           ║
║         --name VortexIntruder                                ║
║         --add-data "gui;gui" --add-data "engine;engine"      ║
║         vortex_intruder.py                                   ║
║                                                              ║
║  Requirements: Python 3.10+                                  ║
║  Dependencies: httpx, PyQt6, pyqtdarktheme, beautifulsoup4  ║
╚══════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import os
import sys
import warnings

warnings.filterwarnings("ignore", message="pkg_resources is deprecated")


def check_dependencies() -> list[str]:
    """Check for required packages and return list of missing ones."""
    missing = []
    for pkg, module in [
        ("PyQt6", "PyQt6.QtWidgets"),
        ("httpx", "httpx"),
    ]:
        try:
            __import__(module)
        except ImportError:
            missing.append(pkg)
    return missing


def main() -> None:
    # Dependency check
    missing = check_dependencies()
    if missing:
        print(f"[ERROR] Missing dependencies: {', '.join(missing)}")
        print("Install with:  pip install -r requirements.txt")
        sys.exit(1)

    # Enable High-DPI scaling for 4K monitors
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
    os.environ.setdefault("QT_SCALE_FACTOR_ROUNDING_POLICY", "PassThrough")

    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import Qt

    app = QApplication(sys.argv)
    app.setApplicationName("VortexIntruder")
    app.setApplicationVersion("1.0")

    from gui.main_window import MainWindow

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    main()
