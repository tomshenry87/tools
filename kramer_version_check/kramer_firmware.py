#!/usr/bin/env python3
"""
query_kramer_fixed.py

Same functionality as the original script, but:

* Uses a **strict error filter** – only lines that start with 'ERROR=' are cleared.
* Handles the case where the device returns the serial number as 'SERIAL='.
* Provides a '--debug' flag to show exact protocol replies.
"""

import argparse
import csv
import json
import socket
import sys
from pathlib import Path
from typing import Dict, List, Tuple

from tabulate import tabulate

# --------------------------------------------------------------
# OPTIONAL tqdm import – graceful fallback if tqdm is missing
# --------------------------------------------------------------
try:
    from tqdm import tqdm  # type: ignore
except ModuleNotFoundError:          # pragma: no cover
    def tqdm(iterable, *args, **kwargs):
        return iterable
# --------------------------------------------------------------

DEFAULT_PORT = 5000
TIMEOUT_SEC = 5
BUFFER_SIZE = 4096

# --------------------------------------------------------------
# Commands + column titles (exact same five keywords)
# --------------------------------------------------------------
COMMANDS = [
    ("BUILD-DATE",   "Build‑date"),
    ("MODEL",        "Model"),
    ("PROT-VERSION", "Prot‑ver"),
    ("SN",           "SN"),
    ("VERSION",      "Version"),
]

# --------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------
def read_switcher_csv(csv_path: Path) -> List[Tuple[str, int]]:
    """Read host[,port] lines from switchers.csv."""
    hosts = []
    with csv_path.open(newline="") as f:
        for row in csv.reader(f):
            if not row or not row[0].strip():
                continue
            host = row[0].strip()
            port = int(row[1]) if len(row) > 1 and row[1].strip() else DEFAULT_PORT
            hosts.append((host, port))
    return hosts


def send_cmd(sock: socket.socket, cmd: str) -> str:
    """Send a command (already contains the trailing '?') and return the raw line."""
    full_cmd = cmd + "\r\n"
    sock.sendall(full_cmd.encode("utf-8"))

    data = b""
    while not data.endswith(b"\r\n"):
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            break
        data += chunk
        if len(data) > 4096:               # safety guard
            break
    return data.decode("utf-8", errors="replace").rstrip("\r\n")


def _clean_error(val: str) -> str:
    """
    Keep the value unless the device explicitly reported an error.
    The protocol uses the literal prefix 'ERROR=' for failures.
    """
    if not val:
        return ""
    if val.upper().startswith("ERROR="):
        return ""          # treat as a true error → blank cell
    return val


def query_one_switch(host: str, port: int = DEFAULT_PORT, debug: bool = False) -> Dict[str, str]:
    """
    Connect to a switcher and query every keyword in COMMANDS.
    Returns a dict like: {"host": "...", "BUILD-DATE": "...", "SN": "...", ...}
    """
    result = {"host": host}
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SEC) as sock:
            for key, _ in COMMANDS:
                try:
                    reply = send_cmd(sock, f"GET {key}?")
                    if debug:
                        print(f"[DEBUG] {host}:{port} → GET {key}? → raw reply: {repr(reply)}")
                except (socket.timeout, socket.error) as exc:
                    result[key] = _clean_error(f"COMM-ERR ({exc})")
                    continue

                # Expected reply: KEY=VALUE
                if "=" in reply:
                    r_key, r_val = reply.split("=", 1)
                    r_key = r_key.strip().upper()
                    # Normal case – the key matches what we asked for
                    if r_key == key.upper():
                        result[key] = _clean_error(r_val.strip())
                    # Fallback: the device used the keyword "SERIAL" instead of "SN"
                    elif key == "SN" and r_key == "SERIAL":
                        result[key] = _clean_error(r_val.strip())
                    else:
                        result[key] = _clean_error(f"UNEXPECTED ({reply})")
                else:
                    result[key] = _clean_error(f"ERR ({reply})")
    except (socket.timeout, socket.error) as exc:
        for key, _ in COMMANDS:
            result[key] = _clean_error(f"UNREACHABLE ({exc})")
    return result


def build_table(data: List[Dict[str, str]]) -> str:
    """Build a tabulate table (plain column titles)."""
    headers = ["host"] + [col_title for _, col_title in COMMANDS]
    rows = []
    for entry in data:
        row = [entry.get("host", "")]
        for key, _ in COMMANDS:
            row.append(_clean_error(entry.get(key, "")))
        rows.append(row)
    return tabulate(rows, headers=headers, tablefmt="grid")


# ----------------------------------------------------------------------
# Main entry point
# ----------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Query Kramer 3000 series (including 440H2) for firmware info."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print raw protocol replies – helpful for troubleshooting.",
    )
    args = parser.parse_args()

    csv_path = Path("switchers.csv")
    if not csv_path.is_file():
        sys.stderr.write(f"❌  File not found: {csv_path}\n")
        sys.exit(1)

    switchers = read_switcher_csv(csv_path)
    if not switchers:
        sys.stderr.write("❌  No hosts found in switchers.csv\n")
        sys.exit(1)

    results: List[Dict[str, str]] = []

    print(f"🔎  Querying {len(switchers)} Kramer switcher(s)...")
    for host, port in tqdm(switchers, desc="Switchers", unit="switch"):
        results.append(query_one_switch(host, port, debug=args.debug))

    # ----- DISPLAY -----
    print("\n📊  Query Results")
    print(build_table(results))

    # ----- SAVE -----
    json_path = Path("results.json")
    with json_path.open("w", encoding="utf-8") as jf:
        json.dump(results, jf, indent=2, ensure_ascii=False)
    print(f"\n💾  Results written to {json_path}")


if __name__ == "__main__":
    main()
