# ⚡ VortexIntruder v1.1

**Professional HTTP Fuzzer with PyQt6 GUI — inspired by Burp Suite Intruder**

> by **Vaqo**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![PyQt6](https://img.shields.io/badge/GUI-PyQt6-green?logo=qt)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

---

## 📸 Overview

VortexIntruder is a desktop HTTP fuzzing tool designed for penetration testers and security researchers. It allows you to craft raw HTTP requests, define injection points with `§` markers, and launch automated attacks with customizable payloads — all through a professional dark/light themed GUI.

---

## ✨ Features

### 🎯 Attack Types
| Type | Description |
|------|-------------|
| **Sniper** | Single payload cycled through each position one at a time |
| **Battering Ram** | Same payload inserted into all positions simultaneously |
| **Pitchfork** | Different payloads per position, iterated in parallel |
| **Cluster Bomb** | All combinations of payloads across all positions |

### 📦 Payload Types
- **Simple List** — manual input or load from wordlist file
- **Numbers** — sequential/random with configurable:
  - Integer & fraction digit control (min/max)
  - Decimal or Hexadecimal base
  - Step value with float precision
  - Live preview of generated payloads
- **Brute Force** — character set + min/max length permutations
- **Null Payloads** — empty payloads for baseline testing

### 🔁 Payload Options
- **Repeat each payload N times** — send every entry multiple times (useful for rate-limit testing)
- **Sequential or Random order** — randomize payload delivery order

### ⚙️ Payload Processing Rules
| Rule | Description |
|------|-------------|
| Add Prefix / Suffix | Prepend or append strings |
| Match & Replace | Regex-based find and replace |
| Case Transforms | Upper, Lower, Proper, Toggle |
| URL Encode | Key chars only or full encoding |
| Base64 Encode | With or without padding |
| Hex Encode | Hexadecimal representation |
| Unicode Escape | Unicode escape sequences |
| Hash | MD5, SHA-1, SHA-256, SHA-512 |
| Number Pad | Zero-pad to specified width |
| Number to Hex | Convert to hexadecimal |

### 🛡️ Throttling & Safe Request Interleave
One of VortexIntruder's most powerful evasion features:

#### Delay + Jitter
- Add a configurable delay (ms) between each fuzz request
- Add random ±jitter to make timing less predictable
- Useful for bypassing rate limiting and WAF detection

#### Safe Request Interleave
- Automatically sends a "safe" or "reset" HTTP request every N fuzz requests
- **Use case:** If a server locks an account after 3 failed logins, configure interleave to send a valid/successful request every 2 fuzz attempts — keeping the session alive and resetting lockout counters.
- The safe request is fully customizable — paste any raw HTTP request (including valid cookies, tokens, etc.)
- Logged in the Logger tab with `[INTERLEAVE]` prefix

**Example setup:**
```
☑ Send safe request every: 2  fuzz requests

Safe Request:
GET /home HTTP/1.1
Host: target.com
Cookie: session=valid_session_token
```
With this config, VortexIntruder sends: `fuzz → fuzz → GET /home → fuzz → fuzz → GET /home → ...`

#### Auto-Pause on Errors
- Automatically pauses the attack after N consecutive error/non-2xx responses
- Prevents wasting requests when the server is blocking or rate-limiting
- Resume manually when ready

### 📊 Results & Analysis
- **Auto-Comment** — intelligent response analysis:
  - `Δlen +23` — response length differs from baseline
  - `→ Redirect: /dashboard` — 3xx with Location header
  - `🍪 Cookie set` — Set-Cookie detected
  - `🚫 Forbidden` / `⏳ Rate Limited` / `💥 Server Error`
  - `🐢 Slow (3200ms)` — slow response detection
  - `⏱ TIMEOUT` — request timeout
- **Request / Response viewer** — click any row to view the sent request and full response in separate tabs
- **Status code coloring** — green (2xx), yellow (3xx), orange (4xx), red (5xx)
- **Grep Match** — highlight rows matching specific strings
- **Grep Extract** — regex extraction from responses (e.g., CSRF tokens)
- **Response Diff** — side-by-side comparison of two responses
- **CSV / JSON export**
- **Filter bar** — live search across all columns

### 🔧 Engine
- Async HTTP engine powered by `httpx` with HTTP/2 support
- Adjustable concurrency (1–200 threads) via semaphore
- Pause / Resume / Stop controls
- Cookie handling (preserve or update from responses)
- Upstream proxy support (Burp, ZAP, mitmproxy)
- SSL verification toggle
- Session resume from index
- Auto Content-Length update

### 🎨 Themes
- **Dark** — professional dark gray theme
- **Light** — clean light theme
- Switch instantly from the top toolbar

---

## 🚀 Installation

### Requirements
- Python 3.10+
- Windows / Linux / macOS

### Setup

```bash
git clone https://github.com/vaqo-repository/VortexIntruder.git
cd VortexIntruder
pip install -r requirements.txt
python vortex_intruder.py
```

### Build Executable (Windows)

```bash
pyinstaller --noconfirm --onefile --windowed --name VortexIntruder ^
    --add-data "gui;gui" --add-data "engine;engine" ^
    vortex_intruder.py
```

The executable will be in the `dist/` folder.

---

## 📖 Usage

### 1. Set Target & Request
Paste a raw HTTP request into the **Target & Request** tab:

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=§test§
```

Select the text you want to fuzz and click **Add §** to mark injection points.

### 2. Configure Payloads
Go to **Payloads** tab:
- Choose payload type (Simple List, Numbers, Brute Force, Null)
- Load a wordlist file or enter values manually
- Set **Repeat** count and order (sequential/random)
- Add processing rules (prefix, suffix, encoding, hashing, etc.)

### 3. Configure Settings
Go to **Settings** tab:
- Select attack type (Sniper, Battering Ram, Pitchfork, Cluster Bomb)
- Adjust concurrency and timeout
- Set grep match/exclude strings
- Configure proxy, SSL, and cookie handling
- **Throttling & Safe Request Interleave** — configure delay, jitter, interleave, and auto-pause

### 4. Launch Attack
Click **▶ Start Attack** — results appear in real-time in the **Results** tab.

### 5. Analyze Results
- Sort by Status, Length, or Time to find anomalies
- Check the **Comment** column for auto-detected insights
- Click any row to view the sent **Request** and full **Response** in separate tabs
- Right-click for context menu (Send to Request, Diff, Copy)
- Use the filter bar to narrow results
- Export to CSV or JSON

---

## 🧪 Test Server

A built-in test server is included for local testing:

```bash
python test_server.py
```

Runs on `http://127.0.0.1:9999` with these response scenarios:

| Condition | Status | Response |
|-----------|--------|----------|
| Valid login (`admin`/`secret123`) | 302 | Redirect + session cookie |
| Wrong credentials | 401 | "Login failed" |
| `blocked` in password | 403 | "Account Locked" |
| `ratelimit` in password | 429 | "Rate Limited" |
| `error`/`crash` in password | 500 | "Server Error" |
| SQL injection patterns | 200 | "Welcome" (SQLi bypass simulation) |
| Password < 4 chars | 200 | "Password too short" |

---

## 📁 Project Structure

```
VortexIntruder/
├── vortex_intruder.py      # Entry point
├── requirements.txt        # Dependencies
├── test_server.py          # Local test server
├── test_passwords.txt      # Sample wordlist (517 passwords)
├── engine/
│   ├── parser.py           # Raw HTTP request parser & § marker handling
│   ├── payloads.py         # Payload generators & attack iterators
│   ├── processor.py        # Payload processing pipeline (18 rule types)
│   └── fuzzer.py           # Async fuzzer engine (QThread + httpx)
└── gui/
    ├── styles.py           # Dark & Light QSS themes
    ├── request_tab.py      # Request editor with syntax highlighting
    ├── payloads_tab.py     # Payload configuration UI
    ├── settings_tab.py     # Attack settings, throttling & grep configuration
    ├── results_tab.py      # Results table with auto-comment analysis
    ├── logger_tab.py       # Filtered log viewer
    ├── diff_dialog.py      # Response diff dialog
    └── main_window.py      # Main window & attack orchestration
```

---

## 📋 Changelog

### v1.1
- Added **payload repeat count** — send each payload N times
- Added **random payload order** option
- Added **Throttling & Safe Request Interleave** section:
  - Delay + Jitter between requests
  - Safe request interleave (every N fuzz requests)
  - Auto-pause on consecutive errors
- Added **Request / Response viewer tabs** in Results panel
- Fixed re-attack resume index bug

### v1.0
- Initial release

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper authorization before testing any system. The author is not responsible for any misuse or damage caused by this tool.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

**Made with ❤️ by Vaqo**

**Professional HTTP Fuzzer with PyQt6 GUI — inspired by Burp Suite Intruder**

> by **Vaqo**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![PyQt6](https://img.shields.io/badge/GUI-PyQt6-green?logo=qt)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

---

## 📸 Overview

VortexIntruder is a desktop HTTP fuzzing tool designed for penetration testers and security researchers. It allows you to craft raw HTTP requests, define injection points with `§` markers, and launch automated attacks with customizable payloads — all through a professional dark/light themed GUI.

---

## ✨ Features

### 🎯 Attack Types
| Type | Description |
|------|-------------|
| **Sniper** | Single payload cycled through each position one at a time |
| **Battering Ram** | Same payload inserted into all positions simultaneously |
| **Pitchfork** | Different payloads per position, iterated in parallel |
| **Cluster Bomb** | All combinations of payloads across all positions |

### 📦 Payload Types
- **Simple List** — manual input or load from wordlist file
- **Numbers** — sequential/random with configurable:
  - Integer & fraction digit control (min/max)
  - Decimal or Hexadecimal base
  - Step value with float precision
  - Live preview of generated payloads
- **Brute Force** — character set + min/max length permutations
- **Null Payloads** — empty payloads for baseline testing

### ⚙️ Payload Processing Rules
| Rule | Description |
|------|-------------|
| Add Prefix / Suffix | Prepend or append strings |
| Match & Replace | Regex-based find and replace |
| Case Transforms | Upper, Lower, Proper, Toggle |
| URL Encode | Key chars only or full encoding |
| Base64 Encode | With or without padding |
| Hex Encode | Hexadecimal representation |
| Unicode Escape | Unicode escape sequences |
| Hash | MD5, SHA-1, SHA-256, SHA-512 |
| Number Pad | Zero-pad to specified width |
| Number to Hex | Convert to hexadecimal |

### 📊 Results & Analysis
- **Auto-Comment** — intelligent response analysis:
  - `Δlen +23` — response length differs from baseline
  - `→ Redirect: /dashboard` — 3xx with Location header
  - `🍪 Cookie set` — Set-Cookie detected
  - `🚫 Forbidden` / `⏳ Rate Limited` / `💥 Server Error`
  - `🐢 Slow (3200ms)` — slow response detection
  - `⏱ TIMEOUT` — request timeout
- **Status code coloring** — green (2xx), yellow (3xx), orange (4xx), red (5xx)
- **Grep Match** — highlight rows matching specific strings
- **Grep Extract** — regex extraction from responses (e.g., CSRF tokens)
- **Response Diff** — side-by-side comparison of two responses
- **CSV / JSON export**
- **Filter bar** — live search across all columns

### 🔧 Engine
- Async HTTP engine powered by `httpx` with HTTP/2 support
- Adjustable concurrency (1–200 threads) via semaphore
- Pause / Resume / Stop controls
- Cookie handling (preserve or update from responses)
- Upstream proxy support (Burp, ZAP, mitmproxy)
- SSL verification toggle
- Session resume from index
- Auto Content-Length update

### 🎨 Themes
- **Dark** — professional dark gray theme
- **Light** — clean light theme
- Switch instantly from the top toolbar

---

## 🚀 Installation

### Requirements
- Python 3.10+
- Windows / Linux / macOS

### Setup

```bash
git clone https://github.com/vaqo-repository/VortexIntruder.git
cd VortexIntruder
pip install -r requirements.txt
python vortex_intruder.py
```

### Build Executable (Windows)

```bash
pyinstaller --noconfirm --onefile --windowed --name VortexIntruder ^
    --add-data "gui;gui" --add-data "engine;engine" ^
    --exclude-module qdarktheme --exclude-module pyqtdarktheme ^
    vortex_intruder.py
```

The executable will be in the `dist/` folder.

---

## 📖 Usage

### 1. Set Target & Request
Paste a raw HTTP request into the **Target & Request** tab:

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=§test§
```

Select the text you want to fuzz and click **Add §** to mark injection points.

### 2. Configure Payloads
Go to **Payloads** tab:
- Choose payload type (Simple List, Numbers, Brute Force, Null)
- Load a wordlist file or enter values manually
- Add processing rules (prefix, suffix, encoding, hashing, etc.)

### 3. Configure Settings
Go to **Settings** tab:
- Select attack type (Sniper, Battering Ram, Pitchfork, Cluster Bomb)
- Adjust concurrency and timeout
- Set grep match/exclude strings
- Configure proxy, SSL, and cookie handling

### 4. Launch Attack
Click **▶ Start Attack** — results appear in real-time in the **Results** tab.

### 5. Analyze Results
- Sort by Status, Length, or Time to find anomalies
- Check the **Comment** column for auto-detected insights
- Click any row to view the full response body
- Right-click for context menu (Send to Request, Diff, Copy)
- Use the filter bar to narrow results
- Export to CSV or JSON

---

## 🧪 Test Server

A built-in test server is included for local testing:

```bash
python test_server.py
```

Runs on `http://127.0.0.1:9999` with these response scenarios:

| Condition | Status | Response |
|-----------|--------|----------|
| Valid login (`admin`/`secret123`) | 302 | Redirect + session cookie |
| Wrong credentials | 401 | "Login failed" |
| `blocked` in password | 403 | "Account Locked" |
| `ratelimit` in password | 429 | "Rate Limited" |
| `error`/`crash` in password | 500 | "Server Error" |
| SQL injection patterns | 200 | "Welcome" (SQLi bypass simulation) |
| Password < 4 chars | 200 | "Password too short" |

---

## 📁 Project Structure

```
VortexIntruder/
├── vortex_intruder.py      # Entry point
├── requirements.txt        # Dependencies
├── test_server.py          # Local test server
├── test_passwords.txt      # Sample wordlist (517 passwords)
├── engine/
│   ├── parser.py           # Raw HTTP request parser & § marker handling
│   ├── payloads.py         # Payload generators & attack iterators
│   ├── processor.py        # Payload processing pipeline (18 rule types)
│   └── fuzzer.py           # Async fuzzer engine (QThread + httpx)
└── gui/
    ├── styles.py           # Dark & Light QSS themes
    ├── request_tab.py      # Request editor with syntax highlighting
    ├── payloads_tab.py     # Payload configuration UI
    ├── settings_tab.py     # Attack settings & grep configuration
    ├── results_tab.py      # Results table with auto-comment analysis
    ├── logger_tab.py       # Filtered log viewer
    ├── diff_dialog.py      # Response diff dialog
    └── main_window.py      # Main window & attack orchestration
```

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper authorization before testing any system. The author is not responsible for any misuse or damage caused by this tool.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

**Made with ❤️ by Vaqo**
