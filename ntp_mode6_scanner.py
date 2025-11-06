#!/usr/bin/env python3
"""
ntp_mode6_scanner.py  (ntpq-only, single-file output, console verdicts)

Parallel scanner to run NTP Mode-6 (control) queries across many targets:
  - ntpq -c "mrulist {ip}"
  - ntpq -c "readlist {ip}"
  - ntpq -c "monstats {ip}"
  - ntpq -c "rv {ip}"
  - ntpq -p {ip}"

Outputs:
  <out-dir>/scan_<timestamp>.log     (all text results in one file; default)
  <out-dir>/summary_<timestamp>.json (or --json-summary path)

Console: shows per-command verdicts (VULNERABLE / RESPONDED / NO RESPONSE / TIMEOUT / ERROR)
Note: heuristics are conservative indicators only — manual review required.
Use only on hosts you own or are authorized to test.
"""

from __future__ import annotations
import argparse
import concurrent.futures
import json
import re
import shlex
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# -------- Defaults --------
DEFAULT_OUT_DIR = Path("results")
DEFAULT_CONCURRENCY = 10
DEFAULT_TIMEOUT = 10  # seconds per command
COMMANDS = [
    'ntpq -c "mrulist {ip}"',
    'ntpq -c "readlist {ip}"',
    'ntpq -c "monstats {ip}"',
    'ntpq -c "rv {ip}"',
    'ntpq -p {ip}',
]

# ANSI colors for console (will degrade gracefully if not supported)
CSI = "\033["
RESET = CSI + "0m"
GREEN = CSI + "32m"
YELLOW = CSI + "33m"
RED = CSI + "31m"
CYAN = CSI + "36m"

# -------- Helpers --------
def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def run_subprocess(cmd: str, timeout: int) -> Dict:
    out = {"cmd": cmd, "returncode": None, "timed_out": False, "stdout": "", "stderr": ""}
    try:
        proc = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=timeout)
        out["returncode"] = proc.returncode
        out["stdout"] = proc.stdout or ""
        out["stderr"] = proc.stderr or ""
    except subprocess.TimeoutExpired as e:
        out["timed_out"] = True
        out["stdout"] = (e.stdout or "")
        out["stderr"] = (e.stderr or f"Timed out after {timeout}s")
    except FileNotFoundError as e:
        out["stderr"] = f"Command not found: {e}"
    except Exception as e:
        out["stderr"] = f"Unexpected error: {e}"
    return out

class ConcurrentWriter:
    def __init__(self, path: Path):
        self.path = path
        self._fh = path.open("a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()

    def write_block(self, text: str) -> None:
        with self._lock:
            self._fh.write(text)
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.close()
            except Exception:
                pass

# Thread-safe console print
_console_lock = threading.Lock()
def console_print(text: str, color: Optional[str] = None) -> None:
    with _console_lock:
        if color:
            sys.stdout.write(color + text + RESET + "\n")
        else:
            sys.stdout.write(text + "\n")
        sys.stdout.flush()

# Heuristic helpers
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

def evaluate_run(ip: str, tmpl_cmd: str, res: Dict) -> Tuple[str, str]:
    """
    Return (status, reason).
    status in {"VULNERABLE","RESPONDED","NO RESPONSE","TIMEOUT","ERROR"}
    """
    cmdname = tmpl_cmd.split()[1] if len(tmpl_cmd.split()) > 1 else tmpl_cmd
    stdout = (res.get("stdout") or "").strip()
    stderr = (res.get("stderr") or "").strip()
    timed_out = bool(res.get("timed_out"))
    rc = res.get("returncode")

    # Timeout
    if timed_out:
        return ("TIMEOUT", f"Command timed out after configured timeout")

    # Command not found or other error
    if stderr and ("not found" in stderr.lower() or "command not found" in stderr.lower()):
        return ("ERROR", f"{stderr.splitlines()[0]}")

    # Heuristic for mrulist/readlist: lots of IP-like tokens => possible amplification / disclosure
    if "mrulist" in tmpl_cmd or "readlist" in tmpl_cmd:
        ips = IP_RE.findall(stdout)
        if ips and len(ips) > 5:
            return ("VULNERABLE", f"Returned {len(ips)} IP-like entries (possible MRU/READ exposure)")
        # sometimes responses are dot-separated lists; fallback on dots count
        if stdout.count(".") > 30:
            return ("VULNERABLE", "Large dot-separated reply (many tokens) — possible exposure")
        if stdout:
            return ("RESPONDED", "Non-empty reply but not many IP-like tokens")
        # fall through to NO RESPONSE

    # monstats/rv/p: if returncode 0 and stdout non-empty => responded (possible info leak)
    if any(x in tmpl_cmd for x in ("monstats", "rv", "-p")):
        if rc == 0 and stdout:
            # monstats sometimes includes words like "stat", "packets", etc.
            return ("RESPONDED", f"Returned data ({len(stdout)} chars)")
        if rc is None:
            return ("ERROR", stderr or "No return code")
        if stdout == "":
            return ("NO RESPONSE", "No output")

    # Generic fallback
    if res.get("returncode") == 0 and stdout:
        return ("RESPONDED", f"Return code 0 and non-empty output")
    if res.get("returncode") is not None and res.get("returncode") != 0:
        return ("NO RESPONSE", f"Return code {res.get('returncode')}, stderr present")
    return ("NO RESPONSE", stderr or "No output")

def probe_target(ip: str, writer: ConcurrentWriter, timeout: int) -> Dict:
    stamp = datetime.utcnow().isoformat() + "Z"
    summary = {"ip": ip, "timestamp": stamp, "runs": []}

    for tmpl in COMMANDS:
        cmd = tmpl.format(ip=ip)
        res = run_subprocess(cmd, timeout)

        # Compose a single block for the consolidated file
        block = []
        block.append("\n" + "=" * 80 + "\n")
        block.append(f"IP: {ip}\n")
        block.append(f"Command: {cmd}\n")
        block.append(f"Timestamp: {stamp}\n")
        block.append(f"Timed out: {res['timed_out']}\n")
        block.append(f"Return code: {res['returncode']}\n")
        block.append("-" * 80 + "\n")
        if res["stdout"]:
            block.append("=== STDOUT ===\n")
            block.append(res["stdout"])
            if not res["stdout"].endswith("\n"):
                block.append("\n")
        if res["stderr"]:
            block.append("=== STDERR ===\n")
            block.append(res["stderr"])
            if not res["stderr"].endswith("\n"):
                block.append("\n"
