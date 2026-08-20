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
DEFAULT_CSV     = "secrets/shuremxa_firmware.csv"
OUTPUT_DIR      = "shure_mxa/files"
DEFAULT_OUTPUT  = os.path.join(
    OUTPUT_DIR,
    f"results_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
)
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
            except (ValueError, TypeError):
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
def send_command(sock: socket.socket, command: str, timeout: float = 5.0) -> str:
    """
    Send a single command string and return the response.
    Command format: < GET PARAMETER >
    Response format: < REP PARAMETER {value} >
    """
    cmd = f"< {command} >\r\n"
    sock.settimeout(timeout)
    sock.sendall(cmd.encode("utf-8"))
    time.sleep(0.5)
    sock.settimeout(timeout)
    data = sock.recv(RECV_BUFFER)
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
                           timeout: float = 5.0) -> str:
    """Query a single parameter from a Shure device."""
    try:
        raw = send_command(sock, f"GET {parameter}", timeout=timeout)
        return parse_response(raw, parameter)
    except Exception:
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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        try:
            # Small delay after connect to let the device settle
            time.sleep(0.5)

            result["device_id"]        = query_device_parameter(sock, "DEVICE_ID", timeout)
            result["model"]            = query_device_parameter(sock, "MODEL", timeout)
            result["serial"]           = query_device_parameter(sock, "SERIAL_NUM", timeout)
            result["mac"]              = query_device_parameter(sock, "CONTROL_MAC_ADDR", timeout)
            result["firmware_version"] = query_device_parameter(sock, "FW_VER", timeout)
            result["ip_address"]       = query_device_parameter(sock, "IP_ADDR_NET_AUDIO_PRIMARY", timeout)
            result["dante_name"]       = query_device_parameter(sock, "NA_DEVICE_NAME", timeout)
            result["encryption"]       = query_device_parameter(sock, "ENCRYPTION", timeout)

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

    return result


def query_microphone_raw(host: str, port: int,
                         timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Query all parameters and return raw responses for debugging."""
    raw_results = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        try:
            time.sleep(0.5)

            for param in DEVICE_PARAMS:
                try:
                    raw = send_command(sock, f"GET {param}", timeout=timeout)
                    parsed = parse_response(raw, param)
                    raw_results[param] = {"raw": raw, "parsed": parsed}
                except Exception as e:
                    raw_results[param] = {"raw": str(e), "parsed": "ERROR"}
        finally:
            sock.close()

    except Exception as e:
        raw_results["_connection_error"] = str(e)

    return raw_results


# ---------------------------------------------------------------------------
# Output — JSON (spec 2.1, 2.7)
# ---------------------------------------------------------------------------
def save_results_json(results: list, filepath: str, args, elapsed: float):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    ok   = sum(1 for r in results if r["status"] == "success")
    auth = sum(1 for r in results if r["status"] == "auth_error")
    err  = sum(1 for r in results if r["status"] == "error")
    output = {
        "query_info": {
            "csv_file":        "(single host)" if args.host else str(Path(args.input).resolve()),
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
                        workers: int):
    """Render the results table following the conformance spec."""

    table_data = []
    for r in results:
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
    parser = argparse.ArgumentParser(
        description="Query Shure MXA microphones for device info via Command Strings protocol.",
        epilog="""
Examples:
  python shure_script.py
  python shure_script.py -i my_mics.csv
  python shure_script.py --host 192.168.1.10
  python shure_script.py --host 192.168.1.10 --port 2202
  python shure_script.py --host 192.168.1.10 --raw
  python shure_script.py -i mics.csv -t 15 -o output.json -w 10

Protocol:
  Shure Command Strings over TCP port 2202. No authentication required.
  Commands use the format: < GET PARAMETER >
  Reference: https://www.shure.com/en-US/docs/commandstrings/MXA920

Queried Parameters:
  DEVICE_ID                    Friendly name / device identifier
  MODEL                        Hardware model (e.g. MXA920-S, MXA910, MXA710)
  SERIAL_NUM                   Device serial number
  CONTROL_MAC_ADDR             Control MAC address
  FW_VER                       Firmware version string
  IP_ADDR_NET_AUDIO_PRIMARY    Primary audio network IP address
  NA_DEVICE_NAME               Dante device name
  ENCRYPTION                   Encryption status (ON/OFF)
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-i", "--input",   default=DEFAULT_CSV,
        help=f"CSV file with 'host'/'port' columns (default: {DEFAULT_CSV})")
    parser.add_argument("--host",          default=None,
        help="Query a single host instead of reading a CSV")
    parser.add_argument("-o", "--output",  default=DEFAULT_OUTPUT,
        help=f"Output JSON file (default: {DEFAULT_OUTPUT})")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-p", "--port",    type=int, default=DEFAULT_PORT,
        help=f"Port for --host mode (default: {DEFAULT_PORT})")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
        help=f"Number of concurrent workers (default: {DEFAULT_WORKERS})")
    parser.add_argument("--raw",           action="store_true", default=False,
        help="With --host: dump raw command string responses for all parameters.")

    args = parser.parse_args()
    term_width = get_terminal_width()
    start_time = time.monotonic()

    # -------------------------------------------------------------------
    # Header block (spec 3.2)
    # -------------------------------------------------------------------
    input_display = args.host if args.host else args.input
    print(f"{WHITE}")
    print(f"  {BOLD}Shure MXA Microphone Query Tool{RESET}{WHITE}")
    print(f"  Queries MXA arrays via Shure Command Strings")
    print(f"  Input:   {input_display}")
    print(f"  Output:  {args.output}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    print(f"{RESET}")

    # -------------------------------------------------------------------
    # Single-host --raw dump
    # -------------------------------------------------------------------
    if args.host and args.raw:
        print(f"{WHITE}  Raw Command String responses from {args.host}:{args.port}:{RESET}\n")
        raw = query_microphone_raw(args.host, args.port, timeout=args.timeout)

        conn_err = raw.pop("_connection_error", None)

        if conn_err:
            print(f"  {RED}Connection error:{RESET}{WHITE} {conn_err}{RESET}")
            return

        for param, data in raw.items():
            if isinstance(data, dict):
                print(f"  {WHITE}{BOLD}GET {param}{RESET}")
                print(f"  {WHITE}  Raw:    {data['raw']}{RESET}")
                print(f"  {WHITE}  Parsed: {data['parsed']}{RESET}")
                print()
        return

    # -------------------------------------------------------------------
    # Build device list
    # -------------------------------------------------------------------
    microphones = [{"host": args.host, "port": args.port}] if args.host else load_csv(args.input)

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

    print_results_table(results, args.output, elapsed, args.workers)
    save_results_json(results, args.output, args, elapsed)


if __name__ == "__main__":
    main()
