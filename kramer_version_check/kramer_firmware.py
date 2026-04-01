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
  Normal run   : python3 kramer_firmware.py
  Full debug   : python3 kramer_firmware.py --debug
  Single host  : python3 kramer_firmware.py --debug --host 192.168.1.100
  Single cmd   : python3 kramer_firmware.py --debug --host 192.168.1.100 --cmd firmware

Dependencies: pip install tabulate tqdm python-dateutil
"""

import argparse
import csv
import json
import re
import shutil
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
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

# ---------------------------------------------------------------------------
# ANSI colour palette  (style guide §1)
# ---------------------------------------------------------------------------
CYAN   = "\033[96m"   # Progress bar fill
GREEN  = "\033[92m"   # Success states
RED    = "\033[91m"   # Failure / error states
YELLOW = "\033[93m"   # Warning / auth error states
WHITE  = "\033[97m"   # All body text, table content, labels
BOLD   = "\033[1m"    # Section headers, label emphasis
RESET  = "\033[0m"    # Always close every colour block

# Debug-only private colours (never used in normal output)
_DBG_YLW = "\033[33m"
_DBG_GRN = "\033[32m"
_DBG_DIM = "\033[2m"
_DBG_RED = "\033[31m"
_DBG_MGT = "\033[35m"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_TCP_PORT = 5000
CONNECT_TIMEOUT  = 8.0
RECV_TIMEOUT     = 8.0
BUFFER_SIZE      = 4096
CSV_FILE         = "switchers.csv"
JSON_FILE        = "results.json"
WORKERS          = 5
SEND_PAUSE       = 0.02       # 20 ms post-send pause
DRAIN_WINDOW     = 0.05       # 50 ms non-blocking drain window

# ---------------------------------------------------------------------------
# Protocol queries
# ---------------------------------------------------------------------------
SCALAR_QUERIES = {
    "model":      ("#MODEL?\r",      re.compile(r"~\d+@MODEL\s+(.+)",      re.IGNORECASE)),
    "build_date": ("#BUILD-DATE?\r", re.compile(r"~\d+@BUILD-DATE\s+(.+)", re.IGNORECASE)),
    "prot_ver":   ("#PROT-VER?\r",   re.compile(r"~\d+@PROT-VER\s+(.+)",   re.IGNORECASE)),
    "serial":     ("#SN?\r",         re.compile(r"~\d+@SN\s+(.+)",         re.IGNORECASE)),
    "firmware":   ("#VERSION?\r",    re.compile(r"~\d+@VERSION\s+(.+)",    re.IGNORECASE)),
    "mac":        ("#NET-MAC?\r",    re.compile(r"~\d+@NET-MAC\s+(.+)",    re.IGNORECASE)),
}

ALL_CMD_KEYS = list(SCALAR_QUERIES.keys())

DEBUG = False


# ---------------------------------------------------------------------------
# Debug helpers
# ---------------------------------------------------------------------------
def debug_print(host, label, data):
    if not DEBUG:
        return
    dir_col   = _DBG_MGT if "SEND" in label.upper() else _DBG_GRN
    hex_width = 16
    header    = f"DEBUG [{host}] {label} ({len(data)} bytes)"
    box_w     = max(len(header) + 4, 62)
    print(f"\n{_DBG_YLW}  +-- {dir_col}{header}{_DBG_YLW} {'-' * max(0, box_w - len(header) - 4)}+{RESET}")
    if not data:
        print(f"{_DBG_YLW}  |{RESET}  (empty)")
    else:
        for offset in range(0, len(data), hex_width):
            chunk     = data[offset: offset + hex_width]
            hex_cols  = " ".join(f"{b:02X}" for b in chunk)
            hex_cols += "   " * (hex_width - len(chunk))
            ascii_col = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"{_DBG_YLW}  |{RESET} {_DBG_DIM}{offset:04X}{RESET}  {CYAN}{hex_cols}{RESET}  {_DBG_GRN}|{ascii_col.ljust(hex_width)}|{RESET}")
        decoded = data.decode("ascii", errors="replace")
        visible = (decoded
                   .replace("\r", f"{_DBG_RED}{{CR}}{RESET}")
                   .replace("\n", f"{_DBG_RED}{{LF}}{RESET}")
                   .replace("\x00", f"{_DBG_RED}{{NUL}}{RESET}"))
        print(f"{_DBG_YLW}  |{RESET}  decoded : {visible}")
    print(f"{_DBG_YLW}  +{'-' * box_w}+{RESET}\n")


# ---------------------------------------------------------------------------
# Socket I/O
# ---------------------------------------------------------------------------
def send_query(sock, command, host=""):
    """Send one Protocol 3000 command and return the stripped response string.

    Two-phase receive:
      1. Short pause then blocking read until a newline arrives or timeout.
      2. Brief non-blocking drain to catch any additional buffered lines.
    """
    payload = command.encode("ascii")
    debug_print(host, f"SEND  {command.strip()!r}", payload)
    sock.sendall(payload)
    time.sleep(SEND_PAUSE)

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

    sock.setblocking(False)
    drain_deadline = time.time() + DRAIN_WINDOW
    while time.time() < drain_deadline:
        try:
            chunk = sock.recv(BUFFER_SIZE)
            if chunk:
                response += chunk
        except (BlockingIOError, socket.error):
            break
    sock.setblocking(True)
    sock.settimeout(RECV_TIMEOUT)

    debug_print(host, f"RECV  {command.strip()!r}", response)
    return response.decode("ascii", errors="replace").strip()


# ---------------------------------------------------------------------------
# Date normalisation
# ---------------------------------------------------------------------------
_DATE_PATTERNS = [
    (
        re.compile(r"^(\d{4})[-/](\d{1,2})[-/](\d{1,2})"),
        lambda m: datetime(int(m[1]), int(m[2]), int(m[3])).strftime("%Y/%m/%d"),
    ),
    (
        re.compile(r"^(\d{1,2})[-/](\d{1,2})[-/](\d{4})"),
        lambda m: datetime(int(m[3]), int(m[2]), int(m[1])).strftime("%Y/%m/%d"),
    ),
    (
        re.compile(r"^(\d{4})(\d{2})(\d{2})$"),
        lambda m: datetime(int(m[1]), int(m[2]), int(m[3])).strftime("%Y/%m/%d"),
    ),
]


def normalise_date(raw):
    """Return *raw* normalised to ``yyyy/mm/dd``, or unchanged if unparseable."""
    if not raw or raw == "N/A":
        return raw
    if _DATEUTIL:
        try:
            return dateutil_parser.parse(raw, dayfirst=False).strftime("%Y/%m/%d")
        except (ValueError, OverflowError):
            return raw
    for pattern, converter in _DATE_PATTERNS:
        m = pattern.match(raw.split()[0])
        if m:
            try:
                return converter(m)
            except ValueError:
                pass
    return raw


# ---------------------------------------------------------------------------
# Table helpers  (style guide §3)
# ---------------------------------------------------------------------------
def status_icon(r):
    s = r.get("status", "error")
    if s == "success":
        return f"{GREEN}\u2713 OK{RESET}{WHITE}"
    elif s == "auth_error":
        return f"{YELLOW}\u2717 AUTH ERR{RESET}{WHITE}"
    return f"{RED}\u2717 ERROR{RESET}{WHITE}"


def clean(val):
    s = str(val) if val is not None else "N/A"
    if s in ("None", "-1", ""):
        return "N/A"
    if s.startswith("ERROR") or s in ("Not available", "AUTH ERROR", "See diagnostic"):
        return "N/A"
    return s


def truncate_error(err, max_len=30):
    if not err:
        return ""
    s = str(err)
    for pat, label in [
        # Protocol 3000 – specific
        (r"Protocol 3000",               "Proto3000 error"),
        # Generic network
        (r"[Cc]onnection timed out",     "Timed out"),
        (r"[Cc]onnection refused",       "Conn refused"),
        (r"[Nn]o response .* timeout",   "No response"),
        (r"[Nn]o route to host",         "No route"),
        (r"[Nn]etwork is unreachable",   "Net unreachable"),
        (r"[Nn]ame or service not known","DNS failed"),
        (r"[Nn]etwork error",            "Network error"),
        (r"[Aa]uthentication required",  "Auth required"),
        (r"[Nn]ot a .* device",          "Not supported"),
        (r"[Mm]alformed",                "Bad response"),
    ]:
        if re.search(pat, s):
            return label
    s = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', '', s)
    s = re.sub(r'\[Errno\s*-?\d+\]\s*', '', s)
    s = re.sub(r'\s+', ' ', s).strip(': ')
    return (s[:max_len - 3] + "...") if len(s) > max_len else (s or "Error")


# ---------------------------------------------------------------------------
# Device querying
# ---------------------------------------------------------------------------
def query_device(host, port):
    ts    = datetime.now(timezone.utc).isoformat()
    result = {
        "host":            host,
        "port":            port,
        "query_timestamp": ts,
        "status":          "error",
        "error":           None,
        "build_date":      "N/A",
        "model":           "N/A",
        "prot_ver":        "N/A",
        "serial":          "N/A",
        "firmware":        "N/A",
        "mac":             "N/A",
    }
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(RECV_TIMEOUT)

            hs = b"#\r"
            debug_print(host, "SEND  handshake", hs)
            sock.sendall(hs)
            time.sleep(SEND_PAUSE)
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
            result["status"]     = "success"

    except ConnectionRefusedError as exc:
        result["error"] = str(exc)
    except socket.timeout as exc:
        result["error"] = str(exc)
    except OSError as exc:
        result["error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Debug probe
# ---------------------------------------------------------------------------
class DebugProbeError(Exception):
    """Raised when debug_probe encounters a fatal connection problem."""


def debug_probe(host, port, cmd_key):
    print(f"\n  == Debug probe: {host}:{port} ==\n")
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(RECV_TIMEOUT)

            hs = b"#\r"
            debug_print(host, "SEND  handshake", hs)
            sock.sendall(hs)
            time.sleep(SEND_PAUSE)
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
        raise DebugProbeError(f"Connection failed: {exc}") from exc


# ---------------------------------------------------------------------------
# CSV loader  (style guide §6)
# ---------------------------------------------------------------------------
def load_csv(csv_path):
    devices = []
    p = Path(csv_path)
    if not p.exists():
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} CSV not found: {csv_path}{RESET}")
        sys.exit(1)
    with open(p, "r", encoding="utf-8-sig") as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(f, dialect=dialect)
        if not reader.fieldnames:
            print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} CSV is empty{RESET}")
            sys.exit(1)
        col_map = {n.strip().lower(): n for n in reader.fieldnames}
        if "host" not in col_map:
            print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} CSV needs a 'host' column.{RESET}")
            sys.exit(1)
        for row in reader:
            host = row.get(col_map["host"], "").strip()
            if not host or host.startswith("#"):
                continue
            port = DEFAULT_TCP_PORT
            if "port" in col_map:
                raw_port = row.get(col_map["port"], "").strip()
                if raw_port.isdigit():
                    port = int(raw_port)
            devices.append({"host": host, "port": port})
    if not devices:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No hosts found in {csv_path}{RESET}")
        sys.exit(1)
    return devices


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
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
        try:
            debug_probe(args.host, args.port, args.cmd)
        except DebugProbeError as exc:
            print(f"\n  {exc}\n")
            sys.exit(1)
        sys.exit(0)

    if args.cmd:
        parser.error("--cmd requires --debug and --host")

    devices    = load_csv(CSV_FILE)
    total      = len(devices)
    start_time = time.time()

    # -- Header block (style guide §2) --------------------------------------
    print(f"{WHITE}")
    print(f"  {BOLD}Kramer VP-440H2 Query Tool{RESET}{WHITE}")
    print(f"  Protocol 3000 TCP device interrogation")
    print(f"  Input:   {CSV_FILE}")
    print(f"  Output:  {JSON_FILE}")
    print(f"  Workers: {WORKERS}")
    print(f"  Timeout: {CONNECT_TIMEOUT:.0f}s")
    print(f"{RESET}")

    # -- Progress bar (style guide §3) -------------------------------------
    term_width = shutil.get_terminal_size((120, 24)).columns
    bar_fmt = (
        f"  {WHITE}Scanning{RESET} "
        f"{CYAN}{{bar}}{RESET}"
        f" {WHITE}{{n_fmt}}/{{total_fmt}}{RESET}"
        f" {WHITE}[{{elapsed}}<{{remaining}}]{RESET}"
        f"  {WHITE}{{postfix}}{RESET}"
    )

    results     = []
    active_lock = threading.Lock()
    latest_host = {"value": ""}

    def worker_task(device):
        with active_lock:
            latest_host["value"] = device["host"]
        return query_device(device["host"], device["port"])

    with tqdm(
        total=total,
        bar_format=bar_fmt,
        ncols=term_width,
        dynamic_ncols=True,
        file=sys.stderr,
        leave=True,
    ) as pbar:
        with ThreadPoolExecutor(max_workers=WORKERS) as executor:
            futures = {executor.submit(worker_task, d): d for d in devices}
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                with active_lock:
                    host_display = latest_host["value"]
                pbar.set_postfix_str(host_display, refresh=False)
                pbar.update(1)

        elapsed = time.time() - start_time
        pbar.set_postfix_str(
            f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s",
            refresh=True,
        )

    # -- Tally results ------------------------------------------------------
    ok   = sum(1 for r in results if r["status"] == "success")
    auth = sum(1 for r in results if r["status"] == "auth_error")
    err  = sum(1 for r in results if r["status"] == "error")

    # -- Build table (style guide §3) --------------------------------------
    # Column order: Status | Host | Model | Firmware | Build Date | Protocol Ver | Serial | MAC | Error
    table_rows = []
    for r in results:
        error_raw = r.get("error") or ""
        table_rows.append([
            status_icon(r),
            clean(r["host"]),
            clean(r["model"]),
            clean(r["firmware"]),
            clean(r["build_date"]),
            clean(r["prot_ver"]),
            clean(r["serial"]),
            clean(r["mac"]),
            truncate_error(error_raw),
        ])

    headers = ["Status", "Host", "Model", "Firmware", "Build Date",
               "Protocol Ver", "Serial", "MAC", "Error"]

    table = tabulate(
        table_rows,
        headers=headers,
        tablefmt="pretty",
        stralign="left",
        numalign="right",
    )

    # -- Title banner -------------------------------------------------------
    first_line = table.split("\n")[0]
    raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw         = max(raw_width, 60)
    title      = "Kramer VP-440H2 Query Results — Protocol 3000"
    pad        = (bw - len(title)) // 2

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")
    for line in table.split("\n"):
        print(f"  {line}")

    # -- Summary footer -----------------------------------------------------
    print()
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}\u2717{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )
    print(f"  {BOLD}MAC Addresses{RESET}{WHITE} \u2014 Reported: {sum(1 for r in results if r.get('mac') not in ('N/A', None))}/{total}")
    print(f"{RESET}")

    # -- Closing footer lines -----------------------------------------------
    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {JSON_FILE}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({WORKERS} workers){RESET}")
    print()

    # -- JSON output (style guide §5) --------------------------------------
    ts_now = datetime.now(timezone.utc).isoformat()
    output = {
        "query_info": {
            "csv_file":        str(Path(CSV_FILE).resolve()),
            "timestamp":       ts_now,
            "protocol":        "Kramer Protocol 3000",
            "mode":            "sequential",
            "workers":         WORKERS,
            "total":           total,
            "success":         ok,
            "errors":          err,
            "elapsed_seconds": round(elapsed, 2),
        },
        "switches": results,
    }

    with open(JSON_FILE, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2)


if __name__ == "__main__":
    main()
