#!/usr/bin/env python3
"""
query_vp440h2_fixed.py

Query a Kramer VP‑440H2 (or any 3000‑series unit that follows the same
TCP/IP control protocol) for the five pieces of information listed in the
VP‑440H2 manual:

    • Build‑date   → GET BUILDDATE?
    • Model        → GET MODEL?
    • Protocol version → GET PROT‑VER?
    • Serial number (SN or SERIAL)
    • Firmware version → GET VERSION?

The script reads a CSV file called `switchers.csv` (host[,port]),
prints a table with `tabulate`, and writes `results.json`.

Optional flag:
    --debug    – print the raw protocol reply for each command (useful
                 when troubleshooting spelling/format issues).

Author : ChatGPT
Date   : 2026‑03‑18
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
# OPTIONAL tqdm – nice progress bar, but not required
# --------------------------------------------------------------
try:
    from tqdm import tqdm  # type: ignore
except ModuleNotFoundError:          # pragma: no cover
    def tqdm(iterable, *args, **kwargs):
        return iterable
# --------------------------------------------------------------

DEFAULT_PORT = 5000          # default TCP port for the VP‑440H2 control interface
TIMEOUT_SEC = 5
BUFFER_SIZE = 4096

# ----------------------------------------------------------------------
# Helper to make key comparison tolerant of hyphens and case.
# The protocol replies may contain hyphens (e.g. PROT‑VER) while we store
# the "canonical" keyword without hyphens (PROTVERSION) in the code.
# ----------------------------------------------------------------------
def _norm(k: str) -> str:
    """Return a normalized version of a protocol keyword:
       uppercase and without any hyphens."""
    return k.replace("-", "").upper()


# ----------------------------------------------------------------------
# Commands as they appear in the VP‑440H2 manual.
# The first element is the **exact** keyword we must send (including hyphens
# where the manual requires them).  The second element is the column title
# we display in the table.
# ----------------------------------------------------------------------
COMMANDS = [
    ("BUILDDATE",   "Build‑date"),
    ("MODEL",       "Model"),
    ("PROT-VER",    "Prot‑ver"),   # <-- hyphen is part of the official command
    ("SN",          "SN"),         # device may also answer with SERIAL=
    ("VERSION",     "Version"),
]

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
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
    """
    Send a fully‑formed command (the trailing '?' is already in *cmd*)
    and return the **raw reply line**, stripped only of the final CRLF.
    """
    full_cmd = cmd + "\r\n"
    sock.sendall(full_cmd.encode("utf-8"))

    data = b""
    while not data.endswith(b"\r\n"):
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:            # connection closed unexpectedly
            break
        data += chunk
        if len(data) > 4096:     # safety guard – replies are tiny
            break
    # Decode using replacement for any unexpected bytes (should never happen)
    return data.decode("utf-8", errors="replace").rstrip("\r\n")


def _clean_error(val: str) -> str:
    """
    Keep the value unless the device explicitly returned an error.
    According to the manual, errors start with the literal text
    'ERROR='.
    """
    if not val:
        return ""
    if val.upper().startswith("ERROR="):
        return ""            # true protocol error → blank field
    return val


def query_one_switch(host: str,
                     port: int = DEFAULT_PORT,
                     debug: bool = False) -> Dict[str, str]:
    """
    Open a TCP socket to the VP‑440H2, issue each command from COMMANDS,
    and return a dict containing the host and the five values.
    """
    result = {"host": host}
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SEC) as sock:
            for key, _ in COMMANDS:
                try:
                    # Build the exact command the manual requires.
                    reply = send_cmd(sock, f"GET {key}?")
                    if debug:
                        print(f"[DEBUG] {host}:{port} → GET {key}? → raw reply: {repr(reply)}")
                except (socket.timeout, socket.error) as exc:
                    result[key] = _clean_error(f"COMM‑ERR ({exc})")
                    continue

                # Expected successful reply:  KEY=VALUE
                if "=" in reply:
                    r_key, r_val = reply.split("=", 1)
                    r_key_norm = _norm(r_key.strip())

                    # Normal case – the key we asked for matches the reply key
                    if r_key_norm == _norm(key):
                        result[key] = _clean_error(r_val.strip())
                    # Serial‑number fallback: device may answer with SERIAL=
                    elif key == "SN" and r_key_norm == _norm("SERIAL"):
                        result[key] = _clean_error(r_val.strip())
                    else:
                        # Unexpected key – treat as an error (blank it)
                        result[key] = _clean_error(f"UNEXPECTED ({reply})")
                else:
                    # No '=' means we got something that is not a proper key‑value line
                    result[key] = _clean_error(f"ERR ({reply})")
    except (socket.timeout, socket.error) as exc:
        # Whole device unreachable – blank every field
        for key, _ in COMMANDS:
            result[key] = _clean_error(f"UNREACHABLE ({exc})")
    return result


def build_table(data: List[Dict[str, str]]) -> str:
    """Render a pretty table using the column titles defined in COMMANDS."""
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
        description="Query Kramer VP‑440H2 (or any 3000‑series) for firmware info."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print raw protocol replies – useful for troubleshooting.",
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

    print(f"🔎  Querying {len(switchers)} VP‑440H2 switcher(s)...")
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
