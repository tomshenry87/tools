#!/usr/bin/env python3
"""
Kramer VP-440H2 - Protocol 3000 Device Query Tool
===================================================
Reads a list of hosts from secrets/kramer_firmware.csv (one column: "host",
optionally a second column "port").  For each host it opens a TCP socket, sends
the standard Protocol 3000 queries, then prints a formatted table to the CLI and
saves a timestamped JSON report to kramer_version_check/files/.

Protocol 3000 reference (VP-440H2 User Manual):
  Command syntax : #<COMMAND>\r
  Response syntax: ~nn@<COMMAND> <value>\r\n
  Default TCP port: 5000

Usage (standard flags: see --help):
  Normal run   : python3 kramer_script.py
  Version audit: python3 kramer_script.py --firmware 1.02.0008 1.02.0010
  Single host  : python3 kramer_script.py --host 192.168.1.100
  Trace        : python3 kramer_script.py --host 192.168.1.100 --debug
  Raw replies  : python3 kramer_script.py --host 192.168.1.100 --raw
  Single cmd   : python3 kramer_script.py --host 192.168.1.100 --cmd firmware_version

Dependencies: pip install tabulate tqdm python-dateutil
"""

import csv
import json
import os
import re
import shutil
import socket
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import standard_cli as cli  # noqa: E402  (standard flags, --debug/--raw helpers)

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
# ANSI palette  (spec 3.1)
# ---------------------------------------------------------------------------
CYAN   = "\033[96m"   # Progress bar fill — reserved, nothing else
GREEN  = "\033[92m"   # Success states
RED    = "\033[91m"   # Failure / error states
YELLOW = "\033[93m"   # Auth-error states
WHITE  = "\033[97m"   # All body text, table content, labels
BOLD   = "\033[1m"    # Section headers, label emphasis
RESET  = "\033[0m"    # Always close every colour block

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_PORT     = 5000
CONNECT_TIMEOUT  = 8.0        # -t/--timeout sets this and RECV_TIMEOUT
RECV_TIMEOUT     = 8.0
BUFFER_SIZE      = 4096
WORKERS          = 5          # default for -w/--workers
SEND_PAUSE       = 0.02       # 20 ms post-send pause
DRAIN_WINDOW     = 0.05       # 50 ms non-blocking drain window

MANUFACTURER     = "Kramer"

CSV_FILE         = "secrets/kramer_firmware.csv"     # relative to this script's folder
OUTPUT_DIR       = "kramer_version_check/files"      # results_<YYYYMMDD>_<HHMMSS>.json

# ---------------------------------------------------------------------------
# Protocol queries  (spec section 4 — command framing unchanged)
# ---------------------------------------------------------------------------
SCALAR_QUERIES = {
    "model":            ("#MODEL?\r",      re.compile(r"~\d+@MODEL\s+(.+)",      re.IGNORECASE)),
    "build_date":       ("#BUILD-DATE?\r", re.compile(r"~\d+@BUILD-DATE\s+(.+)", re.IGNORECASE)),
    "prot_ver":         ("#PROT-VER?\r",   re.compile(r"~\d+@PROT-VER\s+(.+)",   re.IGNORECASE)),
    "serial":           ("#SN?\r",         re.compile(r"~\d+@SN\s+(.+)",         re.IGNORECASE)),
    "firmware_version": ("#VERSION?\r",    re.compile(r"~\d+@VERSION\s+(.+)",    re.IGNORECASE)),
    "mac":              ("#NET-MAC?\r",    re.compile(r"~\d+@NET-MAC\s+(.+)",    re.IGNORECASE)),
}

ALL_CMD_KEYS = list(SCALAR_QUERIES.keys())


# ---------------------------------------------------------------------------
# Debug helpers
# ---------------------------------------------------------------------------
def debug_print(host, label, data):
    """--debug: hex + ASCII dump of one socket exchange (stderr, host-prefixed)."""
    cli.debug.hexdump(host, label, data)


# ---------------------------------------------------------------------------
# Socket I/O  (spec section 4 — do not change)
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
            cli.debug.log(host, f"no complete reply to {command.strip()!r} within "
                                f"{RECV_TIMEOUT:g}s; using what arrived")
            break

    sock.setblocking(False)
    drain_deadline = time.time() + DRAIN_WINDOW
    while time.time() < drain_deadline:
        try:
            chunk = sock.recv(BUFFER_SIZE)
            if chunk:
                response += chunk
        except (BlockingIOError, socket.error) as exc:
            if not isinstance(exc, BlockingIOError):   # BlockingIOError = drained, normal
                cli.debug.log(host, f"drain after {command.strip()!r} stopped: {exc}")
            break
    sock.setblocking(True)
    sock.settimeout(RECV_TIMEOUT)

    debug_print(host, f"RECV  {command.strip()!r}", response)
    return response.decode("ascii", errors="replace").strip()


# ---------------------------------------------------------------------------
# Date normalisation  (spec section 4 — do not change)
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
# Shared helpers — byte-identical across all scripts  (spec 3.5)
# ---------------------------------------------------------------------------
def get_terminal_width() -> int:
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 120


def clean(val) -> str:
    """Sanitise a value for table display — converts None/-1/empty to N/A."""
    s = str(val) if val is not None else "N/A"
    if s in ("None", "-1", ""):
        return "N/A"
    if s.startswith("ERROR") or s in ("Not available", "AUTH ERROR", "See diagnostic"):
        return "N/A"
    return s


def status_icon(r: dict) -> str:
    """Return a coloured status icon string for a result dict."""
    s = r.get("status", "error")
    if s == "success":
        return f"{GREEN}✓ OK{RESET}{WHITE}"
    elif s == "auth_error":
        return f"{YELLOW}✗ AUTH ERR{RESET}{WHITE}"
    return f"{RED}✗ ERROR{RESET}{WHITE}"


# ---------------------------------------------------------------------------
# Error label truncation  (spec 3.6)
# ---------------------------------------------------------------------------
BASE_ERROR_PATTERNS = [
    (r"[Cc]onnection timed out",      "Timed out"),
    (r"[Tt]imed? out",                "Timed out"),
    (r"[Cc]onnection refused",        "Conn refused"),
    (r"[Nn]o response",               "No response"),
    (r"[Nn]o data received",          "No response"),
    (r"[Nn]o route to host",          "No route"),
    (r"[Nn]etwork is unreachable",    "Net unreachable"),
    (r"[Nn]ame or service not known", "DNS failed"),
    (r"[Nn]etwork error",             "Network error"),
    (r"[Uu]nexpected response",       "Bad response"),
    (r"[Ii]nvalid response",          "Bad response"),
    (r"[Mm]alformed",                 "Bad response"),
    (r"[Nn]ot a .* device",           "Not supported"),
]

# Protocol-specific patterns for this script, matched BEFORE the base list.
# Protocol 3000 ~NN@ERR responses and the bare ERR forms the device returns
# for unsupported or malformed commands.
PROTOCOL_ERROR_PATTERNS = [
    (r"~\d+@ERR\s*0*1\b",   "Cmd unsupported"),
    (r"~\d+@ERR\s*0*2\b",   "Param out of range"),
    (r"~\d+@ERR\s*0*3\b",   "Cmd unavailable"),
    (r"~\d+@ERR",           "Device error"),
    (r"\bERR\s*\d+\b",      "Device error"),
    (r"\bERR\b",            "Device error"),
]


def truncate_error(err, max_len: int = 30) -> str:
    """Map verbose exception messages to short readable labels."""
    if not err:
        return ""
    s = str(err)
    for pat, label in PROTOCOL_ERROR_PATTERNS + BASE_ERROR_PATTERNS:
        if re.search(pat, s):
            return label
    s = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', '', s)
    s = re.sub(r'\[Errno\s*-?\d+\]\s*', '', s)
    s = re.sub(r'\s+', ' ', s).strip(': ')
    return (s[:max_len - 3] + "...") if len(s) > max_len else (s or "Error")


# ---------------------------------------------------------------------------
# Device querying
# ---------------------------------------------------------------------------
def connect(host, port):
    cli.debug.log(host, f"connecting to {host}:{port} (timeout {CONNECT_TIMEOUT:g}s)")
    sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    cli.debug.log(host, "connected")
    return sock


def handshake(sock, host):
    """Send the bare '#' handshake. Return the reply bytes, or None if none came."""
    hs = b"#\r"
    debug_print(host, "SEND  handshake", hs)
    sock.sendall(hs)
    time.sleep(SEND_PAUSE)
    try:
        hs_resp = sock.recv(BUFFER_SIZE)
        debug_print(host, "RECV  handshake", hs_resp)
        return hs_resp
    except socket.timeout:
        cli.debug.log(host, f"RECV  handshake: no reply within {RECV_TIMEOUT:g}s (no banner); continuing")
        return None


def parse_reply(raw, pattern):
    """Value captured by pattern from the first matching reply line, else None."""
    for line in raw.splitlines():
        m = pattern.search(line)
        if m:
            return m.group(1).strip()
    return None


def query_device(host, port):
    result = {
        "host":             host,
        "port":             port,
        "query_timestamp":  datetime.now(timezone.utc).isoformat(),
        "status":           "error",
        "error":            None,
        "manufacturer":     MANUFACTURER,
        "model":            None,
        "firmware_version": None,
        "serial":           None,
        "mac":              None,
        "build_date":       None,
        "prot_ver":         None,
    }
    try:
        with connect(host, port) as sock:
            sock.settimeout(RECV_TIMEOUT)
            handshake(sock, host)

            for key, (command, pattern) in SCALAR_QUERIES.items():
                raw = send_query(sock, command, host=host)
                value = parse_reply(raw, pattern)
                if value is not None:
                    result[key] = value
                    cli.debug.log(host, f"{key} = {value!r}")
                else:
                    cli.debug.log(host, f"{key}: no '{command.strip()}' answer in reply {raw!r}; left empty")

            if result["build_date"]:
                normalised = normalise_date(result["build_date"])
                cli.debug.log(host, f"build_date {result['build_date']!r} -> {normalised!r}")
                result["build_date"] = normalised
            result["status"] = "success"

    except (ConnectionRefusedError, socket.timeout, OSError) as exc:
        cli.debug.log(host, f"connection failed: {type(exc).__name__}: {exc}")
        result["error"] = str(exc)

    cli.debug.log(host, f"result: {result['status']}"
                        + (f" ({result['error']})" if result["error"] else ""))
    return result


# ---------------------------------------------------------------------------
# --raw / --cmd probe
# ---------------------------------------------------------------------------
def dump_raw(dev, cmd_key=None):
    """
    --raw: connect, send the handshake and every query (only cmd_key's with
    --cmd), and print each raw reply plus the value parsed from it.
    """
    host, port = dev["host"], dev["port"]
    with connect(host, port) as sock:
        sock.settimeout(RECV_TIMEOUT)
        hs_resp = handshake(sock, host)
        if hs_resp is None:
            cli.raw_error("handshake #", f"no reply within {RECV_TIMEOUT:g}s")
        else:
            cli.raw_item("handshake #", hs_resp.decode("ascii", errors="replace").strip())

        targets = {cmd_key: SCALAR_QUERIES[cmd_key]} if cmd_key else SCALAR_QUERIES
        for key, (command, pattern) in targets.items():
            label = f"{command.strip()}  [{key}]"
            raw = send_query(sock, command, host=host)
            if not raw:
                cli.raw_error(label, f"no reply within {RECV_TIMEOUT:g}s")
                continue
            parsed = parse_reply(raw, pattern)
            cli.raw_item(label, raw)
            print(f"parsed {key} => {'N/A' if parsed is None else repr(parsed)}")


# ---------------------------------------------------------------------------
# CSV loader  (spec 3.7)
# ---------------------------------------------------------------------------
def load_csv(csv_path: str) -> list:
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
            try:
                port = int(row.get(col_map.get("port", ""), DEFAULT_PORT) or DEFAULT_PORT)
            except (ValueError, TypeError):
                port = DEFAULT_PORT
            # Parse this script's additional columns here — port.
            devices.append({"host": host, "port": port})
    if not devices:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No valid entries found in CSV.{RESET}")
        sys.exit(1)
    return devices


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    global CONNECT_TIMEOUT, RECV_TIMEOUT

    parser = cli.build_parser(
        script_file=__file__,
        description="Query Kramer VP-440H2 devices via Protocol 3000 TCP.",
        default_csv=CSV_FILE,
        output_dir=OUTPUT_DIR,
        default_port=DEFAULT_PORT,
        default_timeout=CONNECT_TIMEOUT,
        default_workers=WORKERS,
        timeout_type=float,
        timeout_help=(f"Connect timeout, and the wait for each reply, in seconds "
                      f"(default: {CONNECT_TIMEOUT:g})"),
        host_help=("Query HOST instead of the whole CSV. Repeat for several hosts. "
                   "If HOST is in the CSV, that row's port is reused."),
        raw_help=("Print each device's raw reply to the handshake and every query "
                  f"({', '.join(q[0].strip() for q in SCALAR_QUERIES.values())}) and "
                  "the value parsed from it, then exit without the table or JSON. "
                  "Works with --host or the whole CSV."),
        debug_help=("Trace every connection and a hex + ASCII dump of every command and "
                    "reply to stderr, prefixed with the host. The normal table and JSON "
                    "still run."),
        epilog=f"""
Examples:
  python3 kramer_script.py                                   # whole CSV
  python3 kramer_script.py --host 192.168.1.100              # one switcher
  python3 kramer_script.py --host 192.168.1.100 --debug      # + hex trace
  python3 kramer_script.py --host 192.168.1.100 --raw        # raw replies only
  python3 kramer_script.py --host 192.168.1.100 --cmd firmware_version
  python3 kramer_script.py --firmware 1.02.0008 1.02.0010    # who is NOT on these
  python3 kramer_script.py -i devices.csv -t 4 -w 10 -o out.json

Protocol:
  Protocol 3000 over TCP (default port {DEFAULT_PORT}), no authentication.
  "#CMD?\\r" -> "~nn@CMD value\\r\\n". A bare "#\\r" handshake is sent first.
  -t sets both the connect timeout and the wait for each reply.
        """,
    )
    group = parser.add_argument_group("Kramer options")
    group.add_argument("--cmd", metavar="CMD", choices=ALL_CMD_KEYS,
        help="Probe only this one query: print its raw reply and parsed value "
             "(implies --raw: no table/JSON). Works with --host or the whole CSV; "
             "add --debug for the hex trace. Choices: " + ", ".join(ALL_CMD_KEYS))
    args = cli.parse_args(parser)

    CONNECT_TIMEOUT = RECV_TIMEOUT = args.timeout
    if args.cmd:
        args.raw = True     # --cmd is a one-query raw probe

    devices    = cli.select_devices(args, load_csv,
                                    lambda host: {"host": host, "port": DEFAULT_PORT})
    total      = len(devices)
    start_time = time.time()

    # -- Header block (spec 3.2) -------------------------------------------
    print(f"{WHITE}")
    print(f"  {BOLD}Kramer VP-440H2 - Protocol 3000 Device Query Tool{RESET}{WHITE}")
    print(f"  Queries Kramer matrix switchers for firmware and build date")
    print(f"  Input:   {cli.input_label(args)}")
    print(f"  Output:  {'(none: --raw)' if args.raw else args.output}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout:g}s")
    if args.cmd:
        print(f"  Command: {args.cmd} only ({SCALAR_QUERIES[args.cmd][0].strip()})")
    if args.firmware:
        print(f"  Filter:  Showing devices not on firmware {cli.firmware_label(args.firmware)}")
    if args.debug:
        print(f"  Debug:   on (trace on stderr)")
    print(f"{RESET}")

    # -- --raw / --cmd: raw replies only, no table / JSON ------------------
    if args.raw:
        cli.run_raw(devices, lambda d: dump_raw(d, args.cmd))
        return

    # -- Progress bar (spec 3.3) -------------------------------------------
    term_width = get_terminal_width()
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
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(worker_task, d): d for d in devices}
            for future in as_completed(futures):
                results.append(future.result())
                with active_lock:
                    host_display = latest_host["value"]
                pbar.set_postfix_str(host_display, refresh=False)
                pbar.update(1)

        elapsed = time.time() - start_time
        pbar.set_postfix_str(
            f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s",
            refresh=True,
        )

    # -- Tally -------------------------------------------------------------
    ok   = sum(1 for r in results if r["status"] == "success")
    auth = sum(1 for r in results if r["status"] == "auth_error")
    err  = sum(1 for r in results if r["status"] == "error")

    # -- Table (spec 3.4) --------------------------------------------------
    # --firmware filters the table view only; JSON always receives all results.
    firmware_filter = args.firmware
    display_results = cli.firmware_mismatches(results, firmware_filter)
    filtered_count = len(results) - len(display_results)

    # Status | Host | Manufacturer | Model | Firmware | Build Date | Protocol Ver | Serial | MAC | Error
    table_rows = [
        [
            status_icon(r),
            clean(r["host"]),
            clean(r["manufacturer"]),
            clean(r["model"]),
            clean(r["firmware_version"]),
            clean(r["build_date"]),
            clean(r["prot_ver"]),
            clean(r["serial"]),
            clean(r["mac"]),
            truncate_error(r.get("error") or ""),
        ]
        for r in display_results
    ]

    headers = ["Status", "Host", "Manufacturer", "Model", "Firmware",
               "Build Date", "Protocol Ver", "Serial", "MAC", "Error"]

    table = tabulate(
        table_rows,
        headers=headers,
        tablefmt="pretty",
        stralign="left",
        numalign="right",
    )

    # -- Title banner ------------------------------------------------------
    first_line = table.split("\n")[0]
    raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw         = max(raw_width, 60)
    title      = "Kramer VP-440H2 Query Results — Protocol 3000"
    if firmware_filter:
        title += f" — Excluding {cli.firmware_label(firmware_filter)}"
    pad        = max(0, (bw - len(title)) // 2)

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")
    for line in table.split("\n"):
        print(f"  {line}")

    # -- Summary footer (spec 3.8) -----------------------------------------
    print()
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}✓{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}✗{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}✗{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )

    # Device-specific metrics line: firmware version breakdown across the fleet
    version_counts = Counter(
        r["firmware_version"] for r in results
        if r["status"] == "success" and r.get("firmware_version")
    )
    if version_counts:
        breakdown = "  |  ".join(
            f"{ver}: {count}" for ver, count in version_counts.most_common()
        )
        print(f"  {BOLD}Firmware Versions{RESET}{WHITE} — {breakdown}")
    else:
        print(f"  {BOLD}Firmware Versions{RESET}{WHITE} — No data available")

    if firmware_filter:
        print(
            f"  {BOLD}Firmware Filter:{RESET}{WHITE} hiding {filtered_count} device(s) "
            f"on {cli.firmware_label(firmware_filter)} — {len(display_results)} device(s) shown"
        )
    print(f"{RESET}")

    # -- JSON output (spec 2.1 / 2.7) --------------------------------------
    output = {
        "query_info": {
            "csv_file":        cli.input_label(args),
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "protocol":        "Kramer Protocol 3000",
            "mode":            "threaded",
            "workers":         args.workers,
            "total":           total,
            "success":         ok,
            "errors":          err,
            "elapsed_seconds": round(elapsed, 2),
        },
        "switches": results,
    }

    cli.ensure_parent(args.output)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2)

    # -- Closing lines (spec 3.8) ------------------------------------------
    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {args.output}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({args.workers} workers){RESET}")
    print()


if __name__ == "__main__":
    main()
