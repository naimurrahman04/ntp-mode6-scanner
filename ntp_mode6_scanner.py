#!/usr/bin/env python3
import socket
import struct
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

MODE6_REQUEST = b"\x16\x02\x00\x00\x00\x00\x00\x00"  # READVAR / MODE6

def send_mode6(ip, timeout=3):
    data = MODE6_REQUEST
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(data, (ip, 123))
        resp, _ = sock.recvfrom(4096)
        return resp
    except socket.timeout:
        return None
    except Exception:
        return None
    finally:
        sock.close()

def analyze_response(resp):
    if not resp:
        return "No response / filtered / not vulnerable"

    size = len(resp)

    # Heuristic logic:
    if size > 400:
        return f"LIKELY VULNERABLE (Mode 6 data leak, response size = {size} bytes)"
    elif size > 48:
        return f"Responds to Mode 6 (check manually) response size = {size} bytes"
    else:
        return f"Safe / minimal response ({size} bytes)"

def main():
    parser = argparse.ArgumentParser(description="Pure Python NTP Mode 6 Scanner")
    parser.add_argument("--ips-file", required=True, help="File with one IP per line")
    parser.add_argument("--threads", type=int, default=20)
    args = parser.parse_args()

    with open(args.ips_file) as f:
        targets = [line.strip() for line in f if line.strip()]

    print(f"[+] Loaded {len(targets)} targets")
    print("[+] Scanning...\n")

    results = {}
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = { pool.submit(send_mode6, ip): ip for ip in targets }
        for fut in as_completed(futures):
            ip = futures[fut]
            resp = fut.result()
            results[ip] = analyze_response(resp)
            print(f"{ip:<16} -> {results[ip]}")

    print("\n=== Summary ===")
    for ip, status in results.items():
        print(f"{ip:<16} {status}")

if __name__ == "__main__":
    main()
