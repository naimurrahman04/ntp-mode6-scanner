#!/usr/bin/env python3
"""
ntp_mode6_scanner.py  (ntpq-only, single-file output, console verdicts)

Parallel scanner to run NTP Mode-6 (control) queries across many targets:
  - ntpq -c "mrulist {ip}"
  - ntpq -c "readlist {ip}"
  - ntpq -c "monstats {ip}"
  - ntpq -c "rv {ip}"
  - ntpq -p {ip}

Outputs:
  <out-dir>/scan_<timestamp>.log     (all text results in one file; default)
  <out-dir>/summary_<timestamp>.json (or --json-summary path)

Console: shows per-command verdicts (VULNERABLE / RESPONDED / NO RESPONSE / TIMEOUT / ERROR)
Notes:
  - Heuristics are conservative indicators — review logs for confirmation.
  - Use only on hosts you own or are authorized to test.
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
DEFAULT_VULN_THRESHOLD = 6  # IP-like tokens in mrulist/readlist to flag as "VULNERABLE"
COMMANDS = [
    'ntpq -c "mrulist {ip}"',
    'ntpq -c "readlist {ip}"',
    'ntpq -c "monstats {ip}"',
    'ntpq -c "rv {ip}"',
    'ntpq -p {ip}',
]

# ANSI colors (optionally disabled)
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
_use_color = True
def console_print(text: str, color: Optional[str] = None) -> None:
    with _console_lock:
        if _use_color and color:
            sys.stdout.write(color + text + RESET + "\n")
        else:
            sys.stdout.write(text + "\n")
        sys.stdout.flush()

# Heuristic helpers
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

def evaluate_run(ip: str, tmpl_cmd: str, res: Dict, vuln_threshold: int) -> Tuple[str, str]:
    """
    Return (status, reason).
    status in {"VULNERABLE","RESPONDED","NO RESPONSE","TIMEOUT","ERROR"}
    """
    stdout = (res.get("stdout") or "").strip()
    stderr = (res.get("stderr") or "").strip()
    timed_out = bool(res.get("timed_out"))
    rc = res.get("returncode")

    # Timeout
    if timed_out:
        return ("TIMEOUT", "Command timed out after configured timeout")

    # Command not found or other fatal error
    if stderr and ("not found" in stderr.lower() or "command not found" in stderr.lower()):
        return ("ERROR", (stderr.splitlines() or ["Command not found"])[0])

    # mrulist/readlist: IP-like token count (or dot-count fallback)
    if "mrulist" in tmpl_cmd or "readlist" in tmpl_cmd:
        ips = IP_RE.findall(stdout)
        if ips and len(ips) >= vuln_threshold:
            return ("VULNERABLE", f"Returned {len(ips)} IP-like entries (>= {vuln_threshold})")
        if not ips and stdout.count(".") > 30:
            return ("VULNERABLE", "Large dot-separated reply (many tokens) — possible exposure")
        if stdout:
            return ("RESPONDED", "Non-empty reply but below vuln threshold")
        return ("NO RESPONSE", "No output")

    # monstats/rv/-p: respond => informational exposure likelihood
    if any(x in tmpl_cmd for x in ("monstats", "rv", "-p")):
        if rc == 0 and stdout:
            return ("RESPONDED", f"Returned data ({len(stdout)} chars)")
        if rc is None:
            return ("ERROR", stderr or "No return code")
        if stdout == "":
            return ("NO RESPONSE", "No output")

    # Generic fallback
    if rc == 0 and stdout:
        return ("RESPONDED", "Return code 0 and non-empty output")
    if rc is not None and rc != 0:
        return ("NO RESPONSE", f"Return code {rc}, stderr present")
    return ("NO RESPONSE", stderr or "No output")

def probe_target(ip: str, writer: ConcurrentWriter, timeout: int, vuln_threshold: int) -> Dict:
    stamp = datetime.utcnow().isoformat() + "Z"
    summary = {"ip": ip, "timestamp": stamp, "runs": []}

    for tmpl in COMMANDS:
        cmd = tmpl.format(ip=ip)
        res = run_subprocess(cmd, timeout)

        # ---- Consolidated log block (fixed version; balanced quotes/parentheses) ----
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
                block.append("\n")

        block.append("=" * 80 + "\n")
        writer.write_block("".join(block))
        # ---------------------------------------------------------------------------

        status, reason = evaluate_run(ip, cmd, res, vuln_threshold)

        # Console output format: [IP] <command_short> : STATUS - reason
        cmd_short = cmd.replace(f" {ip}", "").replace(ip, "").strip()
        console_msg = f"[{ip}] {cmd_short:18} : {status:11} - {reason}"
        if status == "VULNERABLE":
            console_print(console_msg, RED)
        elif status == "RESPONDED":
            console_print(console_msg, YELLOW)
        elif status == "TIMEOUT":
            console_print(console_msg, CYAN)
        elif status == "ERROR":
            console_print(console_msg, RED)
        else:  # NO RESPONSE
            console_print(console_msg, GREEN)

        summary["runs"].append({
            "cmd": cmd,
            "returncode": res["returncode"],
            "timed_out": res["timed_out"],
            "stdout_snippet": (res["stdout"][:2000] + "...") if len(res["stdout"]) > 2000 else res["stdout"],
            "stderr_snippet": res["stderr"][:1000] if res["stderr"] else "",
            "status": status,
            "reason": reason,
        })

    return summary

def load_ips(path: Path) -> List[str]:
    seen, ips = set(), []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s not in seen:
                seen.add(s)
                ips.append(s)
    return ips

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ntp_mode6_scanner",
        description="Parallel NTP Mode-6 scanner (ntpq-only, single-file output + console verdicts)"
    )
    p.add_argument("--ips-file", "-i", type=Path, required=True, help="File with one IP/hostname per line")
    p.add_argument("--out-dir", "-o", type=Path, default=DEFAULT_OUT_DIR, help="Output directory (default: results/)")
    p.add_argument("--concurrency", "-c", type=int, default=DEFAULT_CONCURRENCY, help=f"Parallel workers (default: {DEFAULT_CONCURRENCY})")
    p.add_argument("--timeout", "-t", type=int, default=DEFAULT_TIMEOUT, help=f"Per-command timeout seconds (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--json-summary", type=Path, default=None, help="Write JSON summary to this path (default under out-dir)")
    p.add_argument("--single-file", type=Path, default=None, help="Path for the consolidated text file (default under out-dir)")
    p.add_argument("--vuln-threshold", type=int, default=DEFAULT_VULN_THRESHOLD, help=f"IP-like token count to mark mrulist/readlist as VULNERABLE (default: {DEFAULT_VULN_THRESHOLD})")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors in console output")
    return p

def main(argv: Optional[List[str]] = None) -> int:
    global _use_color
    args = build_argparser().parse_args(argv)

    _use_color = not args.no_color

    if not args.ips_file.exists():
        print(f"ips-file not found: {args.ips_file}", file=sys.stderr)
        return 2

    ips = load_ips(args.ips_file)
    if not ips:
        print("No IPs found in ips-file", file=sys.stderr)
        return 3

    ensure_dir(args.out_dir)

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    single_file = args.single_file or (args.out_dir / f"scan_{ts}.log")
    writer = ConcurrentWriter(single_file)

    console_print(f"[+] Loaded {len(ips)} targets. Consolidated log -> {single_file.resolve()}")
    console_print(f"[+] Concurrency={args.concurrency}, timeout={args.timeout}s, vuln-threshold={args.vuln_threshold}")

    # Write a header once
    writer.write_block(
        f"# NTP Mode-6 scan\n# Generated: {datetime.utcnow().isoformat()}Z\n"
        f"# Targets: {len(ips)}\n# File: {single_file}\n\n"
    )

    summaries = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
            futs = {ex.submit(probe_target, ip, writer, max(1, args.timeout), max(1, args.vuln_threshold)): ip for ip in ips}
            for fut in concurrent.futures.as_completed(futs):
                ip = futs[fut]
                try:
                    s = fut.result()
                    summaries.append(s)
                    console_print(f"[{ip}] finished all commands")
                except Exception as e:
                    console_print(f"[{ip}] Unexpected error: {e}", RED)
    finally:
        writer.close()

    summary_path = args.json_summary or (args.out_dir / f"summary_{ts}.json")
    try:
        with summary_path.open("w", encoding="utf-8") as fh:
            json.dump({"generated": datetime.utcnow().isoformat() + "Z", "results": summaries}, fh, indent=2)
        console_print(f"[+] Summary written to {summary_path}")
    except Exception as e:
        console_print(f"Failed to write summary: {e}", RED)
        return 4

    # Aggregate suspects (mrulist/readlist VULNERABLE)
    suspects = []
    for s in summaries:
        for r in s.get("runs", []):
            if r.get("status") == "VULNERABLE":
                suspects.append((s["ip"], r["cmd"], r.get("reason", "")))

    if suspects:
        console_print("\nPotentially interesting (heuristic-detected):", YELLOW)
        for ip, cmd, reason in suspects:
            console_print(f" - {ip}: {cmd} -> {reason}", YELLOW)
        console_print(f"\nReview the consolidated log: {single_file}")
    else:
        console_print("\nNo obvious large mrulist/readlist replies detected by heuristic. Review outputs manually if needed.")
        console_print(f"Log file: {single_file}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
