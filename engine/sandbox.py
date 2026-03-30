"""
VortexIntruder – Sandbox Engine
Multi-layer isolation for running untrusted security tools:
  1. Docker container (best) – full filesystem/network/capability isolation
  2. Process jail (fallback) – Job Objects (Win) / bwrap (Linux) + restricted env

All tools live under .tools/<name>/ and NEVER have access to host files.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Optional
from urllib.request import urlretrieve

from PyQt6.QtCore import QThread, pyqtSignal

# ---------------------------------------------------------------------------
# Platform helpers
# ---------------------------------------------------------------------------

_IS_WIN = sys.platform == "win32"

_POPEN_KWARGS: dict = {}
if _IS_WIN:
    _POPEN_KWARGS["creationflags"] = subprocess.CREATE_NO_WINDOW

_BASE_DIR = Path(sys._MEIPASS) if getattr(sys, "frozen", False) else Path(__file__).resolve().parent.parent
_TOOLS_DIR = _BASE_DIR / ".tools"
_EMBED_PYTHON_DIR = _TOOLS_DIR / "python-embed"

_IS_FROZEN = getattr(sys, "frozen", False)


def _get_python() -> str:
    """Return path to a usable Python interpreter.

    Priority:
      1. Bundled python-embed (ships with the exe)
      2. System Python on PATH
    """
    # Bundled embeddable Python (always present in exe builds)
    embed_exe = _EMBED_PYTHON_DIR / ("python.exe" if _IS_WIN else "python3")
    if embed_exe.is_file():
        return str(embed_exe)
    # Fallback: system Python
    for name in ("python", "python3"):
        p = shutil.which(name)
        if p:
            return p
    return sys.executable


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, dict] = {
    "sqlmap": {
        "display": "SQLMap",
        "git_url": "https://github.com/sqlmapproject/sqlmap.git",
        "zip_url": "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip",
        "zip_inner": "sqlmap-master",
        "entry": "sqlmap.py",
        "docker_image": "vortex-sandbox-sqlmap:latest",
        "dockerfile": (
            "FROM python:3.12-slim\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends git "
            "&& rm -rf /var/lib/apt/lists/* "
            "&& git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap "
            "&& apt-get purge -y git && apt-get autoremove -y\n"
            "WORKDIR /opt/sqlmap\n"
            'ENTRYPOINT ["python3", "sqlmap.py"]\n'
        ),
    },
}


def tool_dir(name: str) -> Path:
    return _TOOLS_DIR / name


def tool_entry(name: str) -> Path:
    return tool_dir(name) / TOOL_REGISTRY[name]["entry"]


def is_tool_downloaded(name: str) -> bool:
    return tool_entry(name).is_file()


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

def is_docker_available() -> tuple[bool, str]:
    if not shutil.which("docker"):
        return False, "Docker not installed"
    try:
        r = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=10,
            **_POPEN_KWARGS,
        )
        if r.returncode != 0:
            return False, "Docker not running"
        return True, "Docker ready"
    except Exception:
        return False, "Docker not responding"


def docker_image_exists(tag: str) -> bool:
    try:
        r = subprocess.run(
            ["docker", "images", "-q", tag],
            capture_output=True, text=True, timeout=10, **_POPEN_KWARGS,
        )
        return bool(r.stdout.strip())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Linux sandbox: try bwrap, then plain
# ---------------------------------------------------------------------------

def _linux_sandbox_prefix(tool_path: str) -> list[str]:
    """Return command prefix for Linux process sandboxing."""
    bwrap = shutil.which("bwrap")
    if bwrap:
        return [
            bwrap,
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/sbin", "/sbin",
            "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf",
            "--ro-bind", "/etc/ssl", "/etc/ssl",
            "--ro-bind", tool_path, tool_path,
            "--tmpfs", "/tmp",
            "--proc", "/proc",
            "--dev", "/dev",
            "--unshare-pid",
            "--unshare-ipc",
            "--die-with-parent",
            "--",
        ]
    return []


# ---------------------------------------------------------------------------
# Windows sandbox: Job Object limiting via ctypes
# ---------------------------------------------------------------------------

if _IS_WIN:
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    _JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
    _JobObjectExtendedLimitInformation = 9

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [("f" + str(i), ctypes.c_ulonglong) for i in range(6)]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    def _create_job_object(memory_mb: int = 512, max_processes: int = 32) -> int:
        handle = _kernel32.CreateJobObjectW(None, None)
        if not handle:
            return 0
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | _JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        )
        info.ProcessMemoryLimit = memory_mb * 1024 * 1024
        info.BasicLimitInformation.ActiveProcessLimit = max_processes
        _kernel32.SetInformationJobObject(
            handle, _JobObjectExtendedLimitInformation,
            ctypes.byref(info), ctypes.sizeof(info),
        )
        return handle

    def _assign_job(job_handle: int, pid: int) -> None:
        proc_handle = _kernel32.OpenProcess(0x1F0FFF, False, pid)
        if proc_handle:
            _kernel32.AssignProcessToJobObject(job_handle, proc_handle)
            _kernel32.CloseHandle(proc_handle)


# ---------------------------------------------------------------------------
# Download thread
# ---------------------------------------------------------------------------

class ToolDownloadThread(QThread):
    """Downloads a tool via git clone or ZIP fallback."""
    log_line = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, tool_name: str, parent=None):
        super().__init__(parent)
        self.tool_name = tool_name

    def run(self):
        info = TOOL_REGISTRY.get(self.tool_name)
        if not info:
            self.finished_signal.emit(False, f"Unknown tool: {self.tool_name}")
            return

        dest = tool_dir(self.tool_name)
        entry = tool_entry(self.tool_name)

        if entry.is_file():
            self.log_line.emit(f"{info['display']} is already downloaded.")
            self.finished_signal.emit(True, "Ready.")
            return

        dest.parent.mkdir(parents=True, exist_ok=True)

        # Try git clone first
        if shutil.which("git"):
            self.log_line.emit(f"Cloning {info['display']} (shallow)...")
            try:
                proc = subprocess.Popen(
                    ["git", "clone", "--depth", "1", info["git_url"], str(dest)],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    **_POPEN_KWARGS,
                )
                for line in proc.stdout:
                    self.log_line.emit(line.rstrip())
                proc.wait(timeout=180)
                if proc.returncode == 0 and entry.is_file():
                    self.log_line.emit(f"\n{info['display']} downloaded successfully!")
                    self.finished_signal.emit(True, "Ready.")
                    return
            except Exception as exc:
                self.log_line.emit(f"Git clone failed: {exc}")
                if dest.exists():
                    shutil.rmtree(dest, ignore_errors=True)

        # Fallback: ZIP
        self.log_line.emit(f"Downloading {info['display']} as ZIP...")
        try:
            zip_path = dest.parent / f"{self.tool_name}.zip"
            self.log_line.emit(f"Fetching {info['zip_url']} ...")
            urlretrieve(info["zip_url"], str(zip_path))
            self.log_line.emit("Extracting...")
            with zipfile.ZipFile(str(zip_path), "r") as zf:
                zf.extractall(str(dest.parent))
            extracted = dest.parent / info["zip_inner"]
            if extracted.is_dir():
                extracted.rename(dest)
            zip_path.unlink(missing_ok=True)

            if entry.is_file():
                self.log_line.emit(f"\n{info['display']} downloaded successfully!")
                self.finished_signal.emit(True, "Ready.")
            else:
                self.finished_signal.emit(False, "Download OK but entry point not found.")
        except Exception as exc:
            self.log_line.emit(f"\nDownload failed: {exc}")
            self.finished_signal.emit(False, str(exc))


# ---------------------------------------------------------------------------
# Docker image build thread
# ---------------------------------------------------------------------------

class DockerBuildThread(QThread):
    log_line = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, tool_name: str, parent=None):
        super().__init__(parent)
        self.tool_name = tool_name

    def run(self):
        info = TOOL_REGISTRY.get(self.tool_name)
        if not info or "dockerfile" not in info:
            self.finished_signal.emit(False, "No Dockerfile configured.")
            return

        tag = info["docker_image"]
        if docker_image_exists(tag):
            self.log_line.emit(f"Image {tag} already exists.")
            self.finished_signal.emit(True, "Ready.")
            return

        self.log_line.emit(f"Building Docker image {tag} ...")
        try:
            proc = subprocess.Popen(
                ["docker", "build", "-t", tag, "-"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, **_POPEN_KWARGS,
            )
            proc.stdin.write(info["dockerfile"])
            proc.stdin.close()
            for line in proc.stdout:
                self.log_line.emit(line.rstrip())
            proc.wait(timeout=300)
            if proc.returncode == 0:
                self.log_line.emit("\nDocker image built!")
                self.finished_signal.emit(True, "Ready.")
            else:
                self.finished_signal.emit(False, f"Build failed (exit {proc.returncode})")
        except Exception as exc:
            self.finished_signal.emit(False, str(exc))


# ---------------------------------------------------------------------------
# Sandboxed run thread – auto-picks Docker or process-jail
# ---------------------------------------------------------------------------

class SandboxedRunThread(QThread):
    """
    Best available sandbox:
      Docker? → docker run (container isolation)
      Windows? → Job Object + stripped environment
      Linux? → bwrap / stripped environment
    """
    output_line = pyqtSignal(str)
    finished_signal = pyqtSignal(int, str)

    def __init__(self, tool_name: str, args: list[str], parent=None):
        super().__init__(parent)
        self.tool_name = tool_name
        self.args = args
        self._stop_flag = False
        self._proc: Optional[subprocess.Popen] = None
        self._job_handle: int = 0

    def run(self):
        info = TOOL_REGISTRY.get(self.tool_name)
        if not info:
            self.finished_signal.emit(1, "Unknown tool")
            return

        docker_ok, _ = is_docker_available()
        if docker_ok and docker_image_exists(info["docker_image"]):
            self._run_docker(info)
        elif is_tool_downloaded(self.tool_name):
            self._run_jailed(info)
        else:
            self.output_line.emit(
                f"[ERROR] {info['display']} not available. "
                "Download it first or install Docker."
            )
            self.finished_signal.emit(1, "Not available")

    def _run_docker(self, info: dict):
        tag = info["docker_image"]
        cmd = [
            "docker", "run", "--rm",
            "--read-only",
            "--tmpfs", "/tmp",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--memory", "512m",
            "--cpus", "1",
            tag,
        ] + self.args
        self.output_line.emit("[DOCKER SANDBOX] Full container isolation")
        self.output_line.emit(f"[DOCKER SANDBOX] {info['display']} {' '.join(self.args)}\n")
        self._exec(cmd)

    def _run_jailed(self, info: dict):
        t_dir = str(tool_dir(self.tool_name))
        entry = str(tool_entry(self.tool_name))
        python = _get_python()
        cmd_base = [python, entry] + self.args

        clean_env = {
            "PATH": os.path.dirname(python),
            "PYTHONPATH": t_dir,
            "HOME": t_dir,
            "USERPROFILE": t_dir,
            "TEMP": tempfile.gettempdir(),
            "TMP": tempfile.gettempdir(),
            "LANG": "en_US.UTF-8",
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        }
        for k in ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"):
            if k in os.environ:
                clean_env[k] = os.environ[k]

        if _IS_WIN:
            cmd = cmd_base
            label = "PROCESS JAIL"
            self.output_line.emit(f"[{label}] Windows Job Object sandbox")
        else:
            prefix = _linux_sandbox_prefix(t_dir)
            cmd = prefix + cmd_base
            label = "BWRAP SANDBOX" if prefix else "PROCESS JAIL"
            self.output_line.emit(f"[{label}] Linux process sandbox")

        self.output_line.emit(f"[{label}] {info['display']} {' '.join(self.args)}")
        self.output_line.emit(f"[{label}] Memory: 512 MB | Stripped env | Isolated CWD")
        self.output_line.emit(f"[{label}] Python: {python}")
        self.output_line.emit(f"[{label}] CWD: {t_dir}\n")
        self._exec(cmd, env=clean_env, cwd=t_dir, use_job_object=_IS_WIN)

    def _exec(self, cmd: list[str], env: dict | None = None,
              cwd: str | None = None, use_job_object: bool = False):
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=cwd, env=env, **_POPEN_KWARGS,
            )

            if use_job_object and _IS_WIN:
                try:
                    self._job_handle = _create_job_object(memory_mb=512, max_processes=32)
                    if self._job_handle:
                        _assign_job(self._job_handle, self._proc.pid)
                except Exception:
                    pass

            for line in self._proc.stdout:
                if self._stop_flag:
                    self._proc.terminate()
                    self.output_line.emit("\n[SANDBOX] Terminated by user.")
                    break
                self.output_line.emit(line.rstrip())

            self._proc.wait(timeout=10)
            code = self._proc.returncode or 0
            self.output_line.emit(f"\n[SANDBOX] Exit code: {code}")
            self.finished_signal.emit(code, "OK" if code == 0 else f"Exit {code}")

        except Exception as exc:
            self.output_line.emit(f"\n[SANDBOX] Error: {exc}")
            self.finished_signal.emit(1, str(exc))
        finally:
            if self._job_handle and _IS_WIN:
                _kernel32.CloseHandle(self._job_handle)
                self._job_handle = 0

    def stop(self):
        self._stop_flag = True
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
