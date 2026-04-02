#!/usr/bin/env python3
"""
Poll Sony VPL-PHZ60 projectors for firmware version from a CSV file.

CSV format (projectors.csv):
    host,port,password
    rockefeller-208-projector.openav.dartmouth.edu,80,admin
    ...

Usage:
    python3 sony_class_1_fw.py
    python3 sony_class_1_fw.py --csv /path/to/projectors.csv
"""

import csv
import json
import sys
import urllib.request
import urllib.error

DEFAULT_CSV = "projectors.csv"
RSC_CGI_PATH = "/rsc-cgi-bin/rsc.cgi.elf"
QUERY_PARAMS = "t:26,c:12,p:132072"
TIMEOUT = 10


def get_firmware(host: str) -> str:
    """Query a single projector and return its firmware version string."""
    url = f"http://{host}:80{RSC_CGI_PATH}?{QUERY_PARAMS}"

    req = urllib.request.Request(url, method="POST")
    req.add_header("Content-Length", "0")
    req.add_header("User-Agent", "FirmwarePoller/1.0")

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="replace").strip()
    except (urllib.error.URLError, OSError) as e:
        return f"ERROR: {e}"

    raw = raw.replace("},]", "}]")

    try:
        data = json.loads(raw)
        return data[0].get("pver", "N/A")
    except (json.JSONDecodeError, IndexError, KeyError) as e:
        return f"PARSE ERROR: {e}"


def main():
    csv_path = DEFAULT_CSV
    if "--csv" in sys.argv:
        idx = sys.argv.index("--csv")
        if idx + 1 < len(sys.argv):
            csv_path = sys.argv[idx + 1]

    try:
        with open(csv_path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    except FileNotFoundError:
        print(f"Error: {csv_path} not found", file=sys.stderr)
        sys.exit(1)

    if not rows:
        print("Error: CSV is empty", file=sys.stderr)
        sys.exit(1)

    # Determine column widths for table formatting
    results = []
    for row in rows:
        host = row["host"].strip()
        # CSV port is typically PJLink — the web interface is always on 80
        fw = get_firmware(host)
        results.append((host, fw))

    host_width = max(len("Host"), max(len(r[0]) for r in results))
    fw_width = max(len("Firmware"), max(len(r[1]) for r in results))

    # Print table
    header = f"{'Host':<{host_width}}  {'Firmware':<{fw_width}}"
    sep = f"{'-' * host_width}  {'-' * fw_width}"
    print(header)
    print(sep)
    for host, fw in results:
        print(f"{host:<{host_width}}  {fw:<{fw_width}}")


if __name__ == "__main__":
    main()
