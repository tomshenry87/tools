#!/usr/bin/env python3
"""
kramer_raw_dump.py

For each host in switchers.csv:
    - open a TCP connection to the Kramer 3000 control port (default 5000)
    - send the five official GET commands (the protocol requires a trailing "?")
    - print the **raw reply line** exactly as the device sent it
    - write a JSON file (raw_results.json) that contains those raw lines

Usage:
    python3 kramer_raw_dump.py          # normal mode – prints raw replies
    python3 kramer_raw_dump.py --json   # also write raw_results.json
"""

import argparse
import csv
import json
import socket
import sys
from pathlib import Path
from typing import List, Tuple

# --------------------------------------------------------------
# Optional tqdm – nice progress bar, but not required
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

# The five commands **exactly** as defined in the PDF (note the trailing "?")
COMMANDS = [
    "GET BUILD-DATE?",
    "GET MODEL?",
    "GET PROT-VERSION?",
    "GET SN?",
    "GET VERSION?",
]

def read_switcher_csv(csv_path: Path) -> List[Tuple[str, int]]:
    """Read host[,port] lines – returns list of (host, port)."""
    hosts = []
    with csv_path.open(newline="") as f:
        for row in csv.reader(f):
            if not row or not row[0].strip():
                continue
            host = row[0].strip()
            port = int(row[1]) if len(row) > 1 and row[1].strip() else DEFAULT_PORT
            hosts.append((host, port))
    return hosts


def recv_line(sock: socket.socket) -> str:
    """
    Read ONE line terminated by CRLF (\r\n) and return it **exactly** as received
    (no stripping of spaces or characters – only the trailing CRLF is removed).
    """
    data = b""
    while not data.endswith(b"\r\n"):
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:              # connection closed unexpectedly
            break
        data += chunk
        if len(data) > 4096:       # safety guard – replies are tiny
            break
    # Return a *decoded* string – keep everything else untouched.
    return data.decode("utf-8", errors="replace").rstrip("\r\n")


def query_host(host: str, port: int) -> List[Tuple[str, str]]:
    """
    Connect to a single switcher, issue each command in COMMANDS,
    and return a list of (command, raw_reply) tuples.
    """
    results = []
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SEC) as sock:
            for cmd in COMMANDS:
                # Send command (already contains the "?")
                sock.sendall((cmd + "\r\n").encode("utf-8"))
                raw_reply = recv_line(sock)          # raw line from the device
                results.append((cmd, raw_reply))
    except (socket.timeout, socket.error) as exc:
        # If we cannot talk to the device, make a placeholder entry for each cmd
        for cmd in COMMANDS:
            results.append((cmd, f"CONN‑ERR ({exc})"))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dump raw Kramer 3000 protocol replies (no parsing)."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also write a JSON file (raw_results.json) with the raw replies."
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

    # This dict will hold the final JSON structure if the user asked for it:
    #   { "host:port": { "GET BUILD-DATE?": "BUILD-DATE=2023‑03‑15", … } }
    json_blob = {}

    print(f"🔎  Querying {len(switchers)} switcher(s) – raw output follows:\n")
    for host, port in tqdm(switchers, desc="Switchers", unit="switch"):
        raw_pairs = query_host(host, port)

        # Pretty‑print to the console
        print(f"\n=== {host}:{port} ===")
        for cmd, reply in raw_pairs:
            print(f"{cmd:<18} → {reply}")

        # Add to the JSON structure (if needed)
        if args.json:
            json_blob[f"{host}:{port}"] = {cmd: reply for cmd, reply in raw_pairs}

    if args.json:
        json_path = Path("raw_results.json")
        with json_path.open("w", encoding="utf-8") as jf:
            json.dump(json_blob, jf, indent=2, ensure_ascii=False)
        print(f"\n💾  Raw results also written to {json_path}")


if __name__ == "__main__":
    main()
