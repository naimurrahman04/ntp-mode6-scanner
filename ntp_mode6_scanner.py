#!/usr/bin/env python3
"""
ntp_mode6_scanner.py

Parallel scanner to run NTP Mode-6 (control) queries (mrulist, readlist, monstats, rv, peers)
across multiple targets. Optionally run Nmap NSE checks (ntp-info, ntp-monlist) if nmap is installed.

Usage:
    python3 ntp_mode6_scanner.py --ips-file ips.txt
    python3 ntp_mode6_scanner.py --ips-file ips.txt --nmap

Outputs:
    ./results/<ip>/<command>.txt
    ./results/summary_<timestamp>.json

WARNING:
    Only run this script against systems you own or are explicitly authorized to test.
"""

from __future__ import annotations
import argparse
import concurrent.futures
import json
import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# -------- Configuration defaults --------
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
NMAP_SCRIPT = "--script=ntp-info,ntp-monlist -sU -p 123"

# -------- Helpers --------
def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def safe_filename(s: str) -> str:
    # keep filename safe: remove quotes and replace spaces/slashes/colons
    return s.replace('"', '').replace(' ', '_').replace('/', '_').replace(':', '_')

def run_subprocess(cmd: str, timeout: int) -> Dict:
    """
    Run a command, capture stdout/stderr, record return code and timeout.
    """
    result = {
        "cmd": cmd,
        "returncode": None,
        "timed_out": False,
        "stdout": "",
        "stderr": "",
    }
    try:
        proc = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=timeout)
        result["returncode"] = proc.returncode
        result["stdout"] = proc.stdout or ""
        result["stderr"] = proc.stderr or ""
    except subprocess.TimeoutExpired as e:
        result["timed_out"] = True
        result["stdout"] = getattr(e, "stdout", "") or ""
        result["stderr"] = getattr(e, "stderr", "") or f"Timed out after {timeout}s"
    except FileNotFoundError as e:
        result["stderr"] = f"Command not found: {e}"
    except Exception as e:
        result["stderr"] = f"Unexpected error: {e}"
    return result

# -------- Core scanning logic --------
def probe_target(ip: str, out_dir: Path, timeout: int, run_nmap: bool) -> Dict:
    """
    Run all configured commands against ip and save outputs. Returns a summary dict.
    """
    ip_dir = out_dir / ip
    ensure_dir(ip_dir)

    summary = {
        "ip": ip,
        "runs": [],
        "nmap": None,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    for tmpl in COMMANDS:
        cmd = tmpl.format(ip=ip)
        res = run_subprocess(cmd, timeout=timeout)

        filename = safe_filename(cmd) + ".txt"
        out_path = ip_dir / filename
        header = (
            f"Command: {cmd}\n"
            f"IP: {ip}\n"
            f"Timestamp: {summary['timestamp']}\n"
            f"Timed out: {res['timed_out']}\n"
            f"Return code: {res['returncode']}\n"
            + ("-"*60) + "\n"
        )
        try:
            with out_path.open("w", encoding="utf-8") as fh:
                fh.write(header)
                if res["stdout"]:
                    fh.write("=== STDOUT ===\n")
                    fh.write(res["stdout"])
                if res["stderr"]:
                    fh.write("\n=== STDERR ===\n")
                    fh.write(res["stderr"])
        except Exception as e:
            # store write error
            res["stderr"] += f"\nFailed to write output file: {e}"

        res_record = {
            "cmd": cmd,
            "out_path": str(out_path),
            "returncode": res["returncode"],
            "timed_out": res["timed_out"],
            "stdout_snippet": (res["stdout"][:2000] + "...") if res["stdout"] and len(res["stdout"]) > 2000 else res["stdout"],
            "stderr_snippet": res["stderr"][:1000] if res["stderr"] else "",
        }
        summary["runs"].append(res_record)

    # Optionally run nmap NSE scripts if requested and nmap present
    if run_nmap:
        if shutil.which("nmap"):
            nmap_out = out_dir / ip / "nmap_ntp_info.txt"
            nmap_cmd = f"nmap {NMAP_SCRIPT} {ip}"
            nres = run_subprocess(nmap_cmd, timeout=timeout * 3)
            try:
                with nmap_out.open("w", encoding="utf-8") as fh:
                    fh.write(f"# {nmap_cmd}\nTimestamp: {summary['timestamp']}\n\n")
                    if nres["stdout"]:
                        fh.write("=== STDOUT ===\n")
                        fh.write(nres["stdout"])
                    if nres["stderr"]:
                        fh.write("\n=== STDERR ===\n")
                        fh.write(nres["stderr"])
            except Exception as e:
                nres["stderr"] += f"\nFailed to write nmap file: {e}"
            summary["nmap"] = {
                "cmd": nmap_cmd,
                "out_path": str(nmap_out),
                "returncode": nres["returncode"],
                "timed_out": nres["timed_out"],
                "stdout_snippet": (nres["stdout"][:2000] + "...") if nres["stdout"] and len(nres["stdout"]) > 2000 else nres["stdout"],
                "stderr_snippet": nres["stderr"][:1000] if nres["stderr"] else "",
            }
        else:
            summary["nmap"] = {"error": "nmap not installed or not on PATH"}

    return summary

def load_ips(path: Path) -> List[str]:
    with path.open("r", encoding="utf-8") as fh:
        lines = [line.strip() for line in fh if line.strip() and not line.strip().startswith("#")]
    # deduplicate, preserve order
    seen = set()
    ips = []
    for l in lines:
        if l not in seen:
            ips.append(l)
            seen.add(l)
    return ips

# -------- CLI and main --------
def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ntp_mode6_scanner", description="Parallel NTP Mode-6 scanner")
    p.add_argument("--ips-file", "-i", type=Path, required=True, help="File with one IP/hostname per line")
    p.add_argument("--out-dir", "-o", type=Path, default=DEFAULT_OUT_DIR, help="Output directory (default: results/)")
    p.add_argument("--concurrency", "-c", type=int, default=DEFAULT_CONCURRENCY, help=f"Max parallel workers (default: {DEFAULT_CONCURRENCY})")
    p.add_argument("--timeout", "-t", type=int, default=DEFAULT_TIMEOUT, help=f"Per-command timeout seconds (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--nmap", action="store_true", help="Run nmap NSE checks (requires nmap on PATH)")
    p.add_argument("--json-summary", type=Path, default=None, help="Write JSON summary to path (default under out-dir)")
    return p

def main(argv: Optional[List[str]] = None) -> int:
    args = build_argparser().parse_args(argv)
    ips_file = args.ips_file
    out_dir = args.out_dir
    concurrency = max(1, args.concurrency)
    timeout = max(1, args.timeout)
    run_nmap = bool(args.nmap)

    if not ips_file.exists():
        print(f"ips-file not found: {ips_file}", file=sys.stderr)
        return 2

    ips = load_ips(ips_file)
    if not ips:
        print("No IPs found in ips-file", file=sys.stderr)
        return 3

    ensure_dir(out_dir)
    print(f"[+] Loaded {len(ips)} targets. Results -> {out_dir.resolve()}")
    print(f"[+] Concurrency={concurrency}, timeout={timeout}s, nmap={run_nmap}")

    summaries = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(probe_target, ip, out_dir, timeout, run_nmap): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            try:
                s = fut.result()
                summaries.append(s)

                # safe nmap handling (avoid NoneType.get issue)
                runs_count = len(s.get("runs", []))
                nmap_obj = s.get("nmap")
                if isinstance(nmap_obj, dict):
                    # nmap returned structured info (either results or error)
                    nmap_present = True
                    nmap_err = nmap_obj.get("error")
                    nmap_rc = nmap_obj.get("returncode")
                else:
                    nmap_present = False
                    nmap_err = None
                    nmap_rc = None

                print(f"[{ip}] done. commands={runs_count} nmap={nmap_present} nmap_err={nmap_err} nmap_rc={nmap_rc}")
            except Exception as e:
                print(f"[{ip}] Unexpected error: {e}", file=sys.stderr)

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    summary_path = args.json_summary or out_dir / f"summary_{timestamp}.json"
    try:
        with summary_path.open("w", encoding="utf-8") as fh:
            json.dump({"generated": datetime.utcnow().isoformat() + "Z", "results": summaries}, fh, indent=2)
        print(f"[+] Summary written to {summary_path}")
    except Exception as e:
        print(f"Failed to write summary: {e}", file=sys.stderr)
        return 4

    # Basic post-scan heuristic: list targets where monlist-like outputs appear large
    potential_vuln = []
    for s in summaries:
        for r in s.get("runs", []):
            cmdlow = r.get("cmd", "").lower()
            if any(x in cmdlow for x in ("mrulist", "monlist", "readlist")):
                try:
                    with open(r["out_path"], "r", encoding="utf-8") as fh:
                        content = fh.read()
                        dots = content.count(".")
                        if dots > 30:  # tunable threshold
                            potential_vuln.append({"ip": s["ip"], "cmd": r["cmd"], "out": r["out_path"]})
                except Exception:
                    continue

    if potential_vuln:
        print("\nPotentially vulnerable hosts (heuristic):")
        for pv in potential_vuln:
            print(f" - {pv['ip']} : {pv['cmd']} -> {pv['out']}")
    else:
        print("\nNo obvious large monlist-like replies detected by heuristic. Inspect outputs for details.")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
