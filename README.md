# NTP Mode-6 Scanner

A professional, safe, and parallel scanner for detecting NTP **Mode-6 control query** information disclosure (e.g., `monlist`, `mrulist`, `readlist`, `monstats`, `rv`). The project runs `ntpq` commands against multiple targets, saves per-target outputs and a structured JSON summary, and optionally uses `nmap` to run NSE checks.

> **Important**: Only use this tool on hosts you own or have explicit written authorization to test. Unauthorized scanning is illegal.

---

## Features
- Runs multiple `ntpq` mode-6 checks per host in parallel.
- Optional Nmap NSE checks (`ntp-info`, `ntp-monlist`) if `nmap` is installed.
- Saves outputs to `results/<ip>/` and a JSON summary file.
- Basic heuristic to highlight potentially large `monlist`/`mrulist` responses.
- Configurable concurrency, timeouts, and output location.

---

## Requirements
- Python 3.8+
- `ntpq` available on PATH (part of `ntp` or similar package)
- Optional: `nmap` for NSE checks (if you pass `--nmap`)

On Debian/Ubuntu:
```bash
sudo apt update
sudo apt install -y ntp nmap   # nmap optional
python3 ntp_mode6_scanner.py --ips-file ips.txt
python3 ntp_mode6_scanner.py -i ips.txt -o ./results -c 20 -t 8 --nmap

---

If you want, I can:
- provide a `requirements.txt` (not much needed beyond Python stdlib),  
- add a version that uses `asyncio` + `aiofiles` for very large target lists, or  
- provide a GitHub Actions workflow to run basic static checks and create releases.

Which would you like next?
