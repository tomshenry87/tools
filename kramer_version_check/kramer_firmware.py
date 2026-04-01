#!/usr/bin/env python3
"""
Kramer VP-440H2 - Protocol 3000 Device Query Tool
===================================================
Reads a list of hosts from switchers.csv (one column: "host", optionally a
second column "port").  For each host it opens a TCP socket, sends the
standard Protocol 3000 queries, then prints a formatted table to the CLI
and saves results.json.

Protocol 3000 reference (VP-440H2 User Manual):
  Command syntax : #<COMMAND>\r
  Response syntax: ~nn@<COMMAND> <value>\r\n
  Default TCP port: 5000

Usage:
  Normal run   : python3 query_kramer.py
  Full debug   : python3 query_kramer.py --debug
  Single host  : python3 query_kramer.py --debug --host 192.168.1.100
  Single cmd   : python3 query_kramer.py --debug --host 192.168.1.100 --cmd firmware

Dependencies: pip install tabulate tqdm
"""

import argparse
import csv
import json
import re
import shutil
import socket
import sys
import time
from pathlib import Path

try:
    from tabulate import tabulate
except ImportError:
    print("[ERROR] tabulate not installed.  Run: pip install tabulate tqdm")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("[ERROR] tqdm not installed.  Run: pip install tabulate tqdm")
    sys.exit(1)

try:
    from dateutil import parser as dateutil_parser
    _DATEUTIL = True
except ImportError:
    _DATEUTIL = False

# constants
DEFAULT_TCP_PORT = 5000
CONNECT_TIMEOUT  = 8.0
RECV_TIMEOUT     = 8.0
BUFFER_SIZE      = 4096
CSV_FILE         = "switchers.csv"
JSON_FILE        = "results.json"

# Scalar queries: key -> (command, response regex)
SCALAR_QUERIES = {
    "model":      ("#MODEL?\r",      re.compile(r"~\d+@MODEL\s+(.+)",      re.IGNORECASE)),
    "build_date": ("#BUILD-DATE?\r", re.compile(r"~\d+@BUILD-DATE\s+(.+)", re.IGNORECASE)),
    "prot_ver":   ("#PROT-VER?\r",   re.compile(r"~\d+@PROT-VER\s+(.+)",   re.IGNORECASE)),
    "serial":     ("#SN?\r",         re.compile(r"~\d+@SN\s+(.+)",         re.IGNORECASE)),
    "firmware":   ("#VERSION?\r",    re.compile(r"~\d+@VERSION\s+(.+)",    re.IGNORECASE)),
    "mac":        ("#NET-MAC?\r",    re.compile(r"~\d+@NET-MAC\s+(.+)",    re.IGNORECASE)),
}

ALL_CMD_KEYS = list(SCALAR_QUERIES.keys())

# Style guide: single accent colour (bright cyan) used only for the progress
# bar fill. All other output is default terminal white. Debug hex dump retains
# its own colours as it is a diagnostic tool, not normal output.
CYAN  = "\033[96m"   # bright cyan - progress bar fill only
RST   = "\033[0m"

# Debug-only ANSI colours (not used in normal output)
_YLW = "\033[33m"
_GRN = "\033[32m"
_DIM = "\033[2m"
_RED = "\033[31m"
_MGT = "\033[35m"

DEBUG = False


def debug_print(host, label, data):
    if not DEBUG:
        return
    dir_col   = _MGT if "SEND" in label.upper() else _GRN
    hex_width = 16
    header    = f"DEBUG [{host}] {label} ({len(data)} bytes)"
    box_w     = max(len(header) + 4, 62)
    print(f"\n{_YLW}  +-- {dir_col}{header}{_YLW} {'-' * max(0, box_w - len(header) - 4)}+{RST}")
    if not data:
        print(f"{_YLW}  |{RST}  (empty)")
    else:
        for offset in range(0, len(data), hex_width):
            chunk     = data[offset: offset + hex_width]
            hex_cols  = " ".join(f"{b:02X}" for b in chunk)
            hex_cols += "   " * (hex_width - len(chunk))
            ascii_col = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"{_YLW}  |{RST} {_DIM}{offset:04X}{RST}  {CYAN}{hex_cols}{RST}  {_GRN}|{ascii_col.ljust(hex_width)}|{RST}")
        decoded = data.decode("ascii", errors="replace")
        visible = (decoded
                   .replace("\r", f"{_RED}{{CR}}{RST}")
                   .replace("\n", f"{_RED}{{LF}}{RST}")
                   .replace("\x00", f"{_RED}{{NUL}}{RST}"))
        print(f"{_YLW}  |{RST}  decoded : {visible}")
    print(f"{_YLW}  +{'-' * box_w}+{RST}\n")


def send_query(sock, command, host=""):
    payload = command.encode("ascii")
    debug_print(host, f"SEND  {command.strip()!r}", payload)
    sock.sendall(payload)
    time.sleep(0.1)
    response = b""
    deadline = time.time() + RECV_TIMEOUT
    while time.time() < deadline:
        try:
            chunk = sock.recv(BUFFER_SIZE)
            if chunk:
                response += chunk
                if b"\n" in response:
                    break
        except socket.timeout:
            break
    debug_print(host, f"RECV  {command.strip()!r}", response)
    return response.decode("ascii", errors="replace").strip()


def normalise_date(raw):
    """
    Normalise any date string returned by the device to yyyy/mm/dd.
    Handles formats such as:
      2024-07-12, 12/07/2024, Jul 12 2024, 20240712, 12-Jul-24, etc.
    Uses python-dateutil if available, otherwise falls back to regex patterns.
    Returns the original string unchanged if parsing fails.
    """
    if not raw or raw == "N/A":
        return raw

    # Strip any trailing time component (e.g. "2024-07-12 14:32:00")
    date_part = raw.split()[0] if raw.split() else raw

    if _DATEUTIL:
        try:
            dt = dateutil_parser.parse(raw, dayfirst=False)
            return dt.strftime("%Y/%m/%d")
        except (ValueError, OverflowError):
            pass

    # Fallback regex patterns (no dateutil)
    import re as _re
    patterns = [
        # yyyy-mm-dd or yyyy/mm/dd
        (_re.compile(r"^(\d{4})[-/](\d{1,2})[-/](\d{1,2})$"), "%Y/%m/%d", lambda m: f"{m[1]}/{int(m[2]):02d}/{int(m[3]):02d}"),
        # dd-mm-yyyy or dd/mm/yyyy
        (_re.compile(r"^(\d{1,2})[-/](\d{1,2})[-/](\d{4})$"), "%Y/%m/%d", lambda m: f"{m[3]}/{int(m[2]):02d}/{int(m[1]):02d}"),
        # yyyymmdd
        (_re.compile(r"^(\d{4})(\d{2})(\d{2})$"), "%Y/%m/%d", lambda m: f"{m[1]}/{m[2]}/{m[3]}"),
    ]
    for pat, _, formatter in patterns:
        match = pat.match(date_part)
        if match:
            try:
                return formatter(match.groups())
            except (ValueError, IndexError):
                pass

    return raw  # return original if all parsing fails


def query_device(host, port):
    result = {
        "host":       host,
        "build_date": "N/A",
        "model":      "N/A",
        "prot_ver":   "N/A",
        "serial":     "N/A",
        "firmware":   "N/A",
        "mac":        "N/A",
        "status":     "OK",
    }
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(RECV_TIMEOUT)
            hs = b"#\r"
            debug_print(host, "SEND  handshake", hs)
            sock.sendall(hs)
            time.sleep(0.15)
            try:
                hs_resp = sock.recv(BUFFER_SIZE)
                debug_print(host, "RECV  handshake", hs_resp)
            except socket.timeout:
                debug_print(host, "RECV  handshake", b"(timeout - no banner)")

            for key, (command, pattern) in SCALAR_QUERIES.items():
                raw = send_query(sock, command, host=host)
                for line in raw.splitlines():
                    m = pattern.search(line)
                    if m:
                        result[key] = m.group(1).strip()
                        break

            result["build_date"] = normalise_date(result["build_date"])

    except ConnectionRefusedError:
        result["status"] = "ERROR: Connection refused"
    except socket.timeout:
        result["status"] = "ERROR: Timeout"
    except OSError as exc:
        result["status"] = f"ERROR: {exc}"
    return result


def debug_probe(host, port, cmd_key):
    print(f"\n  == Debug probe: {host}:{port} ==\n")
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(RECV_TIMEOUT)
            hs = b"#\r"
            debug_print(host, "SEND  handshake", hs)
            sock.sendall(hs)
            time.sleep(0.15)
            try:
                hs_resp = sock.recv(BUFFER_SIZE)
                debug_print(host, "RECV  handshake", hs_resp)
            except socket.timeout:
                debug_print(host, "RECV  handshake", b"(timeout)")

            targets = (
                {cmd_key: SCALAR_QUERIES[cmd_key]}
                if cmd_key
                else SCALAR_QUERIES
            )
            for key, (command, pattern) in targets.items():
                raw    = send_query(sock, command, host=host)
                parsed = "N/A"
                for line in raw.splitlines():
                    m = pattern.search(line)
                    if m:
                        parsed = m.group(1).strip()
                        break
                print(f"  parsed [{key}] => {parsed!r}\n")

    except (ConnectionRefusedError, socket.timeout, OSError) as exc:
        print(f"\n  Connection failed: {exc}\n")
    sys.exit(0)


def load_hosts(csv_path):
    hosts = []
    path  = Path(csv_path)
    if not path.exists():
        print(f"[ERROR] CSV file not found: {csv_path}")
        sys.exit(1)
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        for i, row in enumerate(reader):
            if not row or not row[0].strip():
                continue
            raw_host = row[0].strip()
            if i == 0 and not _looks_like_host(raw_host):
                continue
            port = DEFAULT_TCP_PORT
            if len(row) >= 2 and row[1].strip().isdigit():
                port = int(row[1].strip())
            hosts.append((raw_host, port))
    if not hosts:
        print("[ERROR] No hosts found in switchers.csv.")
        sys.exit(1)
    return hosts


def _looks_like_host(value):
    ip = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    hn = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-\.]*[A-Za-z0-9])?$")
    return bool(ip.match(value) or hn.match(value))


def main():
    global DEBUG

    parser = argparse.ArgumentParser(
        description="Query Kramer VP-440H2 devices via Protocol 3000 TCP."
    )
    parser.add_argument("--debug", action="store_true",
                        help="Print hex+ASCII dump of every socket exchange.")
    parser.add_argument("--host", metavar="IP",
                        help="(Debug) Target a single host instead of switchers.csv.")
    parser.add_argument("--port", metavar="PORT", type=int, default=DEFAULT_TCP_PORT,
                        help=f"TCP port (default: {DEFAULT_TCP_PORT}).")
    parser.add_argument("--cmd", metavar="CMD", choices=ALL_CMD_KEYS,
                        help="(Debug) Probe only one command. Choices: " + ", ".join(ALL_CMD_KEYS))
    args = parser.parse_args()

    DEBUG = args.debug

    if args.debug and args.host:
        debug_probe(args.host, args.port, args.cmd)
        return
    if args.cmd:
        parser.error("--cmd requires --debug and --host")

    hosts   = load_hosts(CSV_FILE)
    results = []

    debug_label = "  [DEBUG ON]" if DEBUG else ""
    print(f"\nQuerying {len(hosts)} device(s) via Kramer Protocol 3000 (TCP){debug_label}...\n")

    term_width = shutil.get_terminal_size().columns
    bar_width  = term_width - 2

    with tqdm(
        hosts,
        total=len(hosts),
        unit="device",
        bar_format="{percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] {postfix}",
        colour="cyan",
        ncols=bar_width,
    ) as progress:
        for host, port in progress:
            progress.set_postfix_str(host)
            result = query_device(host, port)
            results.append(result)


    table_rows = [
        [r["host"], r["build_date"], r["model"], r["prot_ver"],
         r["serial"], r["firmware"], r["mac"], r["status"]]
        for r in results
    ]
    headers = ["Host", "Build Date", "Model", "Protocol Ver", "Serial", "Firmware Ver", "Mac", "Status"]

    print()
    print(tabulate(table_rows, headers=headers, tablefmt="outline"))
    print()

    with open(JSON_FILE, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print(f"Results saved to: {JSON_FILE}\n")


if __name__ == "__main__":
    main()
