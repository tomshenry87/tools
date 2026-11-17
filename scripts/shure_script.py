#!/usr/bin/env python3
"""
Shure MXA Microphone Query Tool

Queries Shure MXA ceiling and table array microphones via the Shure
Command Strings protocol over TCP, port 2202.

Supported models:
  - MXA910   (ceiling array)
  - MXA920   (ceiling array)
  - MXA710   (linear array)
  - MXA310   (table array)

Protocol reference:
  - https://www.shure.com/en-US/docs/commandstrings/MXA920
  - TCP socket on port 2202
  - Command format:  < GET PARAMETER >
  - Response format: < REP PARAMETER {value} >

Queries (per official Shure documentation):
  - DEVICE_ID                    Friendly name / device identifier
  - MODEL                        Hardware model (e.g. MXA920-S)
  - SERIAL_NUM                   Serial number
  - CONTROL_MAC_ADDR             Control MAC address
  - FW_VER                       Firmware version string
  - IP_ADDR_NET_AUDIO_PRIMARY    Primary audio network IP address
  - NA_DEVICE_NAME               Dante device name
  - ENCRYPTION                   Encryption status (ON/OFF)

Conforms to: Conformance Spec — shure_script.py
"""

import csv
import json
import re
import sys
import os
import socket
import shutil
import argparse
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import standard_cli as cli  # noqa: E402  (standard flags, --debug/--raw helpers)

try:
    from tabulate import tabulate
except ImportError:
    print("ERROR: 'tabulate' library is required. Install with: pip install tabulate")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("ERROR: 'tqdm' library is required. Install with: pip install tqdm")
    sys.exit(1)

# ---------------------------------------------------------------------------
# ANSI palette (spec 3.1) — no other colours
# ---------------------------------------------------------------------------
CYAN   = "\033[96m"   # Progress bar fill — reserved, nothing else
GREEN  = "\033[92m"   # Success states
RED    = "\033[91m"   # Failure / error states
YELLOW = "\033[93m"   # Auth-error states
WHITE  = "\033[97m"   # All body text, table content, labels
BOLD   = "\033[1m"    # Section headers, label emphasis
RESET  = "\033[0m"    # Always close every colour block

# ---------------------------------------------------------------------------
# Defaults & constants
# ---------------------------------------------------------------------------
DEFAULT_CSV     = "secrets/shuremxa_firmware.csv"   # relative to this script's folder
OUTPUT_DIR      = "shure_mxa/files"                 # results_<YYYYMMDD>_<HHMMSS>.json
DEFAULT_TIMEOUT = 10
DEFAULT_PORT    = 2202
DEFAULT_WORKERS = 5

MANUFACTURER    = "Shure"
PROTOCOL_LABEL  = "Shure Command Strings (TCP port 2202)"

# Parameters to query — device-level (no channel index)
# Per official Shure MXA920 Command Strings documentation
DEVICE_PARAMS = [
    "DEVICE_ID",
    "MODEL",
    "SERIAL_NUM",
    "CONTROL_MAC_ADDR",
    "FW_VER",
    "IP_ADDR_NET_AUDIO_PRIMARY",
    "NA_DEVICE_NAME",
    "ENCRYPTION",
]

RECV_BUFFER = 4096


# ---------------------------------------------------------------------------
# Shared helpers (spec 3.5) — byte-identical across all scripts
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
# Error labels (spec 3.6) — protocol patterns matched BEFORE the base list
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

# Protocol-specific patterns for this script: Shure Command Strings failures —
# REP responses that do not match the requested parameter, and ERR forms.
PROTOCOL_ERROR_PATTERNS = [
    (r"<\s*REP\s+ERR\s*>",            "Command error"),
    (r"REP\s+ERR",                    "Command error"),
    (r"[Pp]arameter mismatch",        "Param mismatch"),
    (r"[Uu]nrecognised parameter",    "Unknown param"),
    (r"[Uu]nrecognized parameter",    "Unknown param"),
    (r"[Nn]o REP for",                "Param mismatch"),
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
# CSV loader (spec 3.7)
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
            except (ValueError, TypeError) as e:
                cli.debug.log(host, f"bad port in CSV ({e}); using {DEFAULT_PORT}")
                port = DEFAULT_PORT
            # Parse this script's additional columns here — port.
            devices.append({"host": host, "port": port})
    if not devices:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No valid entries found in CSV.{RESET}")
        sys.exit(1)
    return devices


# ---------------------------------------------------------------------------
# Shure Command Strings protocol helpers
# PROTECTED (spec 4) — do not alter framing, sequencing, or timeouts
# ---------------------------------------------------------------------------
def send_command(sock: socket.socket, command: str, timeout: float = 5.0,
                 host: str = "?") -> str:
    """
    Send a single command string and return the response.
    Command format: < GET PARAMETER >
    Response format: < REP PARAMETER {value} >
    host is only used to label the --debug trace.
    """
    cmd = f"< {command} >\r\n"
    sock.settimeout(timeout)
    cli.debug.sent(host, cmd)
    sock.sendall(cmd.encode("utf-8"))
    time.sleep(0.5)
    sock.settimeout(timeout)
    data = sock.recv(RECV_BUFFER)
    cli.debug.received(host, data)
    if not data:
        raise Exception("No data received from device")
    return data.decode("utf-8", errors="replace").strip()


def parse_response(raw: str, parameter: str) -> str:
    """
    Parse a Shure command string response.
    Handles both formats:
      < REP PARAMETER {value                        } >  (curly braces, padded)
      < REP PARAMETER value >                            (plain value)
    """
    # Match value inside curly braces: < REP [x] PARAMETER {value} >
    pattern = rf'<\s*REP\s+(?:\d+\s+)?{re.escape(parameter)}\s+\{{(.*?)\}}\s*>'
    match = re.search(pattern, raw, re.IGNORECASE)
    if match:
        value = match.group(1).strip()
        if value and value.upper() not in ("UNKNOWN", "UNKN"):
            return value
        return "N/A"

    # Fallback — value without curly braces
    pattern2 = rf'<\s*REP\s+(?:\d+\s+)?{re.escape(parameter)}\s+(.*?)\s*>'
    match2 = re.search(pattern2, raw, re.IGNORECASE)
    if match2:
        value = match2.group(1).strip().strip("{}")
        if value and value.upper() not in ("UNKNOWN", "UNKN"):
            return value
        return "N/A"

    # Check for error responses
    if "ERR" in raw.upper():
        return "N/A"

    return "N/A"


def query_device_parameter(sock: socket.socket, parameter: str,
                           timeout: float = 5.0, host: str = "?") -> str:
    """Query a single parameter from a Shure device."""
    try:
        raw = send_command(sock, f"GET {parameter}", timeout=timeout, host=host)
        value = parse_response(raw, parameter)
        if value == "N/A":
            cli.debug.log(host, f"{parameter}: no usable value in reply")
        return value
    except Exception as e:
        cli.debug.log(host, f"GET {parameter} failed: {e}")
        return "N/A"


# ---------------------------------------------------------------------------
# Main query
# PROTECTED (spec 4) — command sequence and timeouts unchanged;
# only the result dict key names conform to the spec's data contract.
# ---------------------------------------------------------------------------
def query_microphone(host: str, port: int,
                     timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Query a single Shure MXA microphone for device information."""
    result = {
        "host":             host,
        "port":             port,
        "status":           "error",
        "manufacturer":     MANUFACTURER,
        "model":            None,
        "firmware_version": None,
        "serial":           None,
        "mac":              None,
        "device_id":        None,
        "ip_address":       None,
        "dante_name":       None,
        "encryption":       None,
        "error":            None,
        "query_timestamp":  datetime.now(timezone.utc).isoformat(),
    }

    try:
        cli.debug.log(host, f"connecting to {host}:{port} (timeout {timeout}s)")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        cli.debug.log(host, "connected")

        try:
            # Small delay after connect to let the device settle
            time.sleep(0.5)

            result["device_id"]        = query_device_parameter(sock, "DEVICE_ID", timeout, host)
            result["model"]            = query_device_parameter(sock, "MODEL", timeout, host)
            result["serial"]           = query_device_parameter(sock, "SERIAL_NUM", timeout, host)
            result["mac"]              = query_device_parameter(sock, "CONTROL_MAC_ADDR", timeout, host)
            result["firmware_version"] = query_device_parameter(sock, "FW_VER", timeout, host)
            result["ip_address"]       = query_device_parameter(sock, "IP_ADDR_NET_AUDIO_PRIMARY", timeout, host)
            result["dante_name"]       = query_device_parameter(sock, "NA_DEVICE_NAME", timeout, host)
            result["encryption"]       = query_device_parameter(sock, "ENCRYPTION", timeout, host)

            result["status"] = "success"

        finally:
            sock.close()

    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except OSError as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    # "N/A" is a display sentinel, not data — the contract wants null for
    # "not reported" so the dashboard's ?? handling behaves correctly.
    for key in ("model", "firmware_version", "serial", "mac",
                "device_id", "ip_address", "dante_name", "encryption"):
        if result[key] == "N/A":
            result[key] = None

    cli.debug.log(host, f"result: {result['status']}" + (f" ({result['error']})" if result["error"] else ""))
    return result


def dump_raw(dev: dict, timeout: int = DEFAULT_TIMEOUT):
    """--raw: print the raw reply (and parsed value) for every GET parameter."""
    host, port = dev["host"], dev["port"]
    cli.debug.log(host, f"connecting to {host}:{port} (timeout {timeout}s)")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))   # failure -> run_raw prints a connection error
        time.sleep(0.5)

        for param in DEVICE_PARAMS:
            label = f"GET {param}"
            try:
                raw = send_command(sock, label, timeout=timeout, host=host)
                cli.raw_item(label, f"{raw}\n(parsed: {parse_response(raw, param)})")
            except Exception as e:
                cli.raw_error(label, e)
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Output — JSON (spec 2.1, 2.7)
# ---------------------------------------------------------------------------
def save_results_json(results: list, filepath: str, args, elapsed: float):
    cli.ensure_parent(filepath)
    ok   = sum(1 for r in results if r["status"] == "success")
    auth = sum(1 for r in results if r["status"] == "auth_error")
    err  = sum(1 for r in results if r["status"] == "error")
    output = {
        "query_info": {
            "csv_file":        cli.input_label(args),
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "protocol":        PROTOCOL_LABEL,
            "mode":            "single-host" if args.host else "csv",
            "workers":         args.workers,
            "total":           len(results),
            "success":         ok,
            "auth_errors":     auth,
            "errors":          err,
            "elapsed_seconds": round(elapsed, 2),
        },
        "microphones": results,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Output — terminal (spec 3.4, 3.8)
# ---------------------------------------------------------------------------
def print_results_table(results: list, output_file: str, elapsed: float,
                        workers: int, firmware_filter: list = None):
    """Render the results table following the conformance spec."""

    # --firmware: show only devices NOT on one of the versions (errors included).
    # The full results list is always saved to JSON regardless.
    display_results = cli.firmware_mismatches(results, firmware_filter)

    table_data = []
    for r in display_results:
        row = [
            status_icon(r),
            clean(r["host"]),
            clean(r.get("manufacturer")),
            clean(r.get("model")),
            clean(r.get("firmware_version")),
            clean(r.get("serial")),
            clean(r.get("mac")),
            clean(r.get("device_id")),
            clean(r.get("encryption")),
            truncate_error(r.get("error")),
        ]
        table_data.append(row)

    headers = ["Status", "Host", "Manufacturer", "Model", "Firmware",
               "Serial", "MAC", "Device ID", "Encryption", "Error"]

    table = tabulate(table_data, headers=headers,
                     tablefmt="pretty", stralign="left", numalign="right")

    first_line = table.split("\n")[0]
    raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw         = max(raw_width, 60)

    title = "Shure MXA Microphone — Device Query Results"
    pad   = (bw - len(title)) // 2

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")
    for line in table.split("\n"):
        print(f"  {line}")

    total = len(results)
    ok    = sum(1 for r in results if r["status"] == "success")
    auth  = sum(1 for r in results if r["status"] == "auth_error")
    err   = sum(1 for r in results if r["status"] == "error")

    print()
    if firmware_filter:
        print(
            f"  {BOLD}Firmware filter:{RESET}{WHITE} {cli.firmware_label(firmware_filter)}  |  "
            f"{BOLD}Showing:{RESET}{WHITE} {len(display_results)} of {total} devices"
        )
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}✓{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}✗{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}✗{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )

    # Device-specific metrics line — firmware version breakdown across the fleet
    fw_counts = {}
    for r in results:
        fw = r.get("firmware_version")
        if fw:
            fw_counts[fw] = fw_counts.get(fw, 0) + 1

    reported = sum(fw_counts.values())
    if reported:
        parts = "  |  ".join(
            f"{BOLD}{v}:{RESET}{WHITE} {c}"
            for v, c in sorted(fw_counts.items())
        )
        print(
            f"  {BOLD}Firmware —{RESET}{WHITE} {parts}  |  "
            f"{BOLD}Versions:{RESET}{WHITE} {len(fw_counts)}  |  "
            f"{BOLD}Reported:{RESET}{WHITE} {reported}/{total}"
        )
    else:
        print(f"  {BOLD}Firmware —{RESET}{WHITE} No data available")

    print()
    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {output_file}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers){RESET}")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = cli.build_parser(
        script_file=__file__,
        description="Query Shure MXA microphones for device info via Command Strings protocol.",
        default_csv=DEFAULT_CSV,
        output_dir=OUTPUT_DIR,
        default_port=DEFAULT_PORT,
        default_timeout=DEFAULT_TIMEOUT,
        default_workers=DEFAULT_WORKERS,
        epilog="""
Examples:
  python3 shure_script.py                              # whole CSV
  python3 shure_script.py --host 192.168.1.10          # one device
  python3 shure_script.py --host 192.168.1.10 -p 2202
  python3 shure_script.py --host 192.168.1.10 --raw
  python3 shure_script.py --host 192.168.1.10 --debug
  python3 shure_script.py --firmware 4.7.13 5.0.104    # who is NOT on these
  python3 shure_script.py -i mics.csv -t 15 -w 10 -o out.json

Protocol:
  Shure Command Strings over TCP port 2202. No authentication required.
  Commands use the format: < GET PARAMETER >
  Reference: https://www.shure.com/en-US/docs/commandstrings/MXA920

Queried Parameters:
  DEVICE_ID                    Friendly name / device identifier
  MODEL                        Hardware model (e.g. MXA920-S, MXA910, MXA710)
  SERIAL_NUM                   Device serial number
  CONTROL_MAC_ADDR             Control MAC address
  FW_VER                       Firmware version string (--firmware compares this)
  IP_ADDR_NET_AUDIO_PRIMARY    Primary audio network IP address
  NA_DEVICE_NAME               Dante device name
  ENCRYPTION                   Encryption status (ON/OFF)
        """,
    )
    args = cli.parse_args(parser)
    term_width = get_terminal_width()
    start_time = time.monotonic()

    # -------------------------------------------------------------------
    # Header block (spec 3.2)
    # -------------------------------------------------------------------
    print(f"{WHITE}")
    print(f"  {BOLD}Shure MXA Microphone Query Tool{RESET}{WHITE}")
    print(f"  Queries MXA arrays via Shure Command Strings")
    print(f"  Input:   {cli.input_label(args)}")
    print(f"  Output:  {'(none: --raw)' if args.raw else args.output}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    if args.firmware:
        print(f"  Filter:  Showing devices not on firmware {cli.firmware_label(args.firmware)}")
    if args.debug:
        print(f"  Debug:   on (trace on stderr)")
    print(f"{RESET}")

    # -------------------------------------------------------------------
    # Build device list (--host or CSV)
    # -------------------------------------------------------------------
    microphones = cli.select_devices(
        args, load_csv, lambda host: {"host": host, "port": DEFAULT_PORT})

    # -------------------------------------------------------------------
    # --raw: dump what each device sends back, no table / JSON
    # -------------------------------------------------------------------
    if args.raw:
        cli.run_raw(microphones, lambda d: dump_raw(d, timeout=args.timeout))
        return

    # -------------------------------------------------------------------
    # Progress bar + concurrent query loop (spec 3.3)
    # -------------------------------------------------------------------
    bar_fmt = (
        f"  {WHITE}Scanning{RESET} "
        f"{CYAN}{{bar}}{RESET}"
        f" {WHITE}{{n_fmt}}/{{total_fmt}}{RESET}"
        f" {WHITE}[{{elapsed}}<{{remaining}}]{RESET}"
        f"  {WHITE}{{postfix}}{RESET}"
    )

    results      = []
    results_lock = threading.Lock()
    active_lock  = threading.Lock()
    latest_host  = {"value": ""}

    def do_query(d):
        with active_lock:
            latest_host["value"] = d["host"]
        return query_microphone(d["host"], d["port"], timeout=args.timeout)

    with tqdm(total=len(microphones), bar_format=bar_fmt, ncols=term_width,
              dynamic_ncols=True, file=sys.stderr, leave=True) as pbar:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(do_query, d): d for d in microphones}
            for fut in as_completed(futures):
                with results_lock:
                    results.append(fut.result())
                with active_lock:
                    pbar.set_postfix_str(latest_host["value"], refresh=False)
                pbar.update(1)

        elapsed = time.monotonic() - start_time
        pbar.set_postfix_str(
            f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s",
            refresh=True,
        )

    # Re-sort results to match original input order
    host_order = {d["host"]: i for i, d in enumerate(microphones)}
    results.sort(key=lambda r: host_order.get(r["host"], 0))

    print_results_table(results, args.output, elapsed, args.workers, args.firmware)
    save_results_json(results, args.output, args, elapsed)


if __name__ == "__main__":
    main()
