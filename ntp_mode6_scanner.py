#!/usr/bin/env python3
"""
ntp_mode6_scanner.py  (ntpq-only)

Parallel scanner to run NTP Mode-6 (control) queries across many targets:
  - ntpq -c "mrulist {ip}"
  - ntpq -c "readlist {ip}"
  - ntpq -c "monstats {ip}"
  - ntpq -c "rv {ip}"
  - ntpq -p {ip}

Outputs:
  results/<ip>/<command>.txt
  results/summary_<timestamp>.json   (or path provided via --json-summary)

Usage:
  python3 ntp_mode6_scanner.py --ips-file ips.txt

Note: Use only on hosts you own or are authorized to test.
"""

from __future__ import annotations
import argparse
import concurrent.futures
import json
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

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

# -------- Helpers --------
def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def safe_filename(s: str) -> str:
    return s.replace('"', "").replace(" ", "_").replace("/", "_").replace(":", "_")

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

def probe_target(ip: str, out_dir: Path, timeout: int) -> Dict:
    ip_dir = out_dir / ip
    ensure_dir(ip_dir)

    stamp = datetime.utcnow().isoformat() + "Z"
    summary = {"ip": ip, "timestamp": stamp, "runs": []}

    for tmpl in COMMANDS:
        cmd = tmpl.format(ip=ip)
        res = run_subprocess(cmd, timeout)
        fname = safe_filename(cmd) + ".txt"
        out_path = ip_dir / fname
        header = (
            f"Command: {cmd}\nIP: {ip}\nTimestamp: {stamp}\n"
            f"Timed out: {res['timed_out']}\nReturn code: {res['returncode']}\n"
            + ("-" * 60) + "\n"
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
            res["stderr"] += f"\nFailed to write output file: {e}"

        summary["runs"].append({
            "cmd": cmd,
            "out_path": str(out_path),
            "returncode": res["returncode"],
            "timed_out": res["timed_out"],
            "stdout_snippet": (res["stdout"][:2000] + "...") if len(res["stdout"]) > 2000 else res["stdout"],
            "stderr_snippet": res["stderr"][:1000] if res["stderr"] else "",
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
    p = argparse.ArgumentParser(prog="ntp_mode6_scanner", description="Parallel NTP Mode-6 scanner (ntpq-only)")
    p.add_argument("--ips-file", "-i", type=Path, required=True, help="File with one IP/hostname per line")
    p.add_argument("--out-dir", "-o", type=Path, default=DEFAULT_OUT_DIR, help="Output directory (default: results/)")
    p.add_argument("--concurrency", "-c", type=int, default=DEFAULT_CONCURRENCY, help=f"Parallel workers (default: {DEFAULT_CONCURRENCY})")
    p.add_argument("--timeout", "-t", type=int, default=DEFAULT_TIMEOUT, help=f"Per-command timeout seconds (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--json-summary", type=Path, default=None, help="Write JSON summary to this path (default under out-dir)")
    return p

def main(argv: Optional[List[str]] = None) -> int:
    args = build_argparser().parse_args(argv)
    if not args.ips_file.exists():
        print(f"ips-file not found: {args.ips_file}", file=sys.stderr)
        return 2

    ips = load_ips(args.ips_file)
    if not ips:
        print("No IPs found in ips-file", file=sys.stderr)
        return 3

    ensure_dir(args.out_dir)
    print(f"[+] Loaded {len(ips)} targets. Results -> {args.out_dir.resolve()}")
    print(f"[+] Concurrency={args.concurrency}, timeout={args.timeout}s")

    summaries = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        futs = {ex.submit(probe_target, ip, args.out_dir, max(1, args.timeout)): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futs):
            ip = futs[fut]
            try:
                s = fut.result()
                summaries.append(s)
                print(f"[{ip}] done. commands={len(s.get('runs', []))}")
            except Exception as e:
                print(f"[{ip}] Unexpected error: {e}", file=sys.stderr)

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    summary_path = args.json_summary or (args.out_dir / f"summary_{ts}.json")
    try:
        with summary_path.open("w", encoding="utf-8") as fh:
            json.dump({"generated": datetime.utcnow().isoformat() + "Z", "results": summaries}, fh, indent=2)
        print(f"[+] Summary written to {summary_path}")
    except Exception as e:
        print(f"Failed to write summary: {e}", file=sys.stderr)
        return 4

    # Simple heuristic to flag big mrulist/readlist outputs
    suspects = []
    for s in summaries:
        for r in s.get("runs", []):
            cmdlow = r.get("cmd", "").lower()
            if any(x in cmdlow for x in ("mrulist", "readlist")):
                try:
                    with open(r["out_path"], "r", encoding="utf-8") as fh:
                        content = fh.read()
                        if content.count(".") > 30:  # crude proxy for lots of IPs
                            suspects.append((s["ip"], r["cmd"], r["out_path"]))
                except Exception:
                    pass

    if suspects:
        print("\nPotentially interesting (many IP-like tokens):")
        for ip, cmd, path in suspects:
            print(f" - {ip}: {cmd} -> {path}")
    else:
        print("\nNo obvious large mrulist/readlist replies detected by heuristic. Review outputs manually if needed.")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
