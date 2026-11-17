#!/usr/bin/env python3
"""
Global Caché Relay Query Tool

Uses the Global Caché Unified TCP API v1.1 documented in:
  - Global Caché Unified TCP API v1.1 (PN: 200113-01)
  - TCP Port: 4998 (raw socket connection)
  - Commands: getversion, getdevices, getstate

Queries each device for:
  - Firmware version          (getversion)
  - Device capabilities       (getdevices — module/port enumeration)
  - Relay port states         (getstate for each RELAY/RELAYSENSOR port)

Supports querying GC-100, iTach, Flex, and Global Connect product families.

The Unified TCP API has no authentication on these units.
"""

import csv
import json
import re
import sys
import os
import shutil
import socket
import argparse
import threading
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
# ANSI color palette
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
DEFAULT_CSV     = "secrets/relay_firmware.csv"      # relative to this script's folder
OUTPUT_DIR      = "relay_firmware/files"            # results_<YYYYMMDD>_<HHMMSS>.json
DEFAULT_TIMEOUT = 10
DEFAULT_PORT    = 4998
DEFAULT_WORKERS = 5

MANUFACTURER    = "Global Caché"

RELAY_PORT_TYPES = {"RELAY", "RELAYSENSOR"}

RELAY_STATE_LABELS = {
    "0": "Open",
    "1": "Closed",
    "2": "On2",
}


# ---------------------------------------------------------------------------
# Utility helpers
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
        return f"{GREEN}\u2713 OK{RESET}{WHITE}"
    elif s == "auth_error":
        return f"{YELLOW}\u2717 AUTH ERR{RESET}{WHITE}"
    return f"{RED}\u2717 ERROR{RESET}{WHITE}"


# Protocol-specific patterns for this script, matched BEFORE the base list.
# NOTE: the Global Caché relay code (RO001-RO004) pattern is placed ahead of the
# generic ERR.*00x patterns. "ERR RO001" is matched by `ERR.*001`, so with the
# generic patterns first a relay error would be mislabelled "Unknown command".
PROTOCOL_ERROR_PATTERNS = [
    (r"ERR\s+RO00[1-4]",              "Relay error"),
    (r"ERR.*001",                     "Unknown command"),
    (r"ERR.*002",                     "Invalid syntax"),
    (r"ERR.*003",                     "Invalid address"),
    (r"ERR.*005",                     "Not supported"),
    (r"[Nn]o relay ports",            "No relay ports"),
]

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


def format_relay_states(states: list) -> str:
    """Format a list of relay state dicts into a compact string."""
    if not states:
        return "N/A"
    parts = []
    for s in states:
        addr  = s.get("address", "?")
        state = s.get("state", "?")
        label = RELAY_STATE_LABELS.get(str(state), str(state))
        parts.append(f"{addr}:{label}")
    return "  ".join(parts) if parts else "N/A"


# ---------------------------------------------------------------------------
# CSV loader
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
# Global Caché TCP API helpers  —  PROTOCOL LOGIC, DO NOT MODIFY
# ---------------------------------------------------------------------------
def tcp_command(host: str, port: int, command: str,
                timeout: int = DEFAULT_TIMEOUT,
                multi_line: bool = False,
                end_marker: str = None) -> str:
    """
    Send a single command over a raw TCP socket and return the response.

    For multi-line responses (e.g. getdevices) set multi_line=True and
    provide end_marker (e.g. 'endlistdevices').
    """
    cli.debug.log(host, f"connecting to {host}:{port} (timeout {timeout}s)")
    with socket.create_connection((host, port), timeout=timeout) as sock:
        cli.debug.sent(host, command + "\r")
        sock.sendall((command + "\r").encode("ascii"))
        data = b""
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    cli.debug.log(host, "connection closed by device")
                    break
                data += chunk
                decoded = data.decode("ascii", errors="replace")
                if multi_line and end_marker and end_marker in decoded:
                    break
                if not multi_line and "\r" in decoded:
                    break
            except socket.timeout:
                cli.debug.log(host, f"recv timed out after {timeout}s ({len(data)} bytes so far)")
                break
        cli.debug.received(host, data)
    return data.decode("ascii", errors="replace").strip()


def get_version(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Send getversion and return the raw version string."""
    response = tcp_command(host, port, "getversion", timeout=timeout)
    if not response:
        raise Exception("No response to getversion")
    # GC-100 responds: version,<module>,<ver>
    # iTach/Flex/GC respond with the version string directly
    if response.startswith("version,"):
        parts = response.split(",")
        return parts[2].strip() if len(parts) >= 3 else response
    if response.startswith("ERR") or response.startswith("unknowncommand"):
        raise Exception(f"getversion error: {response}")
    return response.strip()


def get_devices(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> list:
    """
    Send getdevices and parse the multi-line response.

    Returns a list of dicts: [{module, ports, type, subtype}, ...]
    """
    response = tcp_command(
        host, port, "getdevices", timeout=timeout,
        multi_line=True, end_marker="endlistdevices"
    )
    return parse_devices(response)


def parse_devices(response: str) -> list:
    """Parse a getdevices reply (also used by --raw on the text it printed)."""
    if not response:
        return []
    modules = []
    for line in response.splitlines():
        line = line.strip()
        if not line or line == "endlistdevices":
            continue
        if line.startswith("device,"):
            # device,<module>,<ports> <type>[_subtype]
            parts = line.split(",", 2)
            if len(parts) < 3:
                continue
            module = parts[1].strip()
            type_field = parts[2].strip()
            type_parts = type_field.split(None, 1)
            ports_str  = type_parts[0] if type_parts else "0"
            type_str   = type_parts[1] if len(type_parts) > 1 else ""
            # type_str may be "RELAY_SPST_3A" — split on first underscore
            type_sub   = type_str.split("_", 1)
            port_type  = type_sub[0].strip()
            subtype    = type_sub[1].strip() if len(type_sub) > 1 else None
            try:
                port_count = int(ports_str)
            except ValueError:
                port_count = 0
            modules.append({
                "module":    module,
                "ports":     port_count,
                "type":      port_type,
                "subtype":   subtype,
            })
    return modules


def get_relay_ports(modules: list) -> list:
    """
    From a parsed getdevices module list, return only relay-capable entries
    as (module_addr, port_count) tuples.
    """
    relay_ports = []
    for m in modules:
        if m["type"].upper() in RELAY_PORT_TYPES:
            relay_ports.append((m["module"], m["ports"]))
    return relay_ports


def query_relay_states(host: str, port: int, relay_modules: list,
                       timeout: int = DEFAULT_TIMEOUT) -> list:
    """
    For each relay module/port, call getstate and return state dicts.

    relay_modules: list of (module_addr, port_count)
    Returns: [{"module": m, "port": p, "address": "m:p", "state": s}, ...]
    """
    states = []
    for module_addr, port_count in relay_modules:
        for p in range(1, port_count + 1):
            addr = f"{module_addr}:{p}"
            try:
                response = tcp_command(
                    host, port, f"getstate,{addr}", timeout=timeout
                )
                # Expected: state,<module>:<port>,<state>
                if response.startswith("state,"):
                    parts = response.split(",")
                    state_val = parts[2].strip() if len(parts) >= 3 else "?"
                    states.append({
                        "module":  module_addr,
                        "port":    str(p),
                        "address": addr,
                        "state":   state_val,
                    })
                else:
                    # ERR or unexpected — record as unknown
                    states.append({
                        "module":  module_addr,
                        "port":    str(p),
                        "address": addr,
                        "state":   "ERR",
                        "error":   response,
                    })
            except Exception as e:
                cli.debug.log(host, f"getstate,{addr} failed: {e}")
                states.append({
                    "module":  module_addr,
                    "port":    str(p),
                    "address": addr,
                    "state":   "ERR",
                    "error":   str(e),
                })
    return states


def detect_product_family(version: str) -> str:
    """
    Infer the product family from a raw version string.

    GC-100: 3.2-06 / 3.2-12 / 3.2-18
    iTach:  710-10xx-XX
    Flex:   710-20xx-XX / 710-30xx-XX / 710-40xx-XX
    GC:     other 710- patterns
    """
    if not version or version == "N/A":
        return "N/A"
    if re.match(r'^3\.\d+-\d+$', version):
        return "GC-100"
    if re.match(r'^710-10\d{2}-', version):
        return "iTach"
    if re.match(r'^710-[234]\d{3}-', version):
        return "Flex"
    if re.match(r'^710-', version):
        return "Global Connect"
    return "Unknown"


# ---------------------------------------------------------------------------
# Main query
# ---------------------------------------------------------------------------
def query_device(host: str, port: int,
                 timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Query a single Global Caché device for version and relay states."""
    result = {
        "host":               host,
        "port":               port,
        "query_timestamp":    datetime.now(timezone.utc).isoformat(),
        "status":             "error",
        "error":              None,
        "manufacturer":       MANUFACTURER,
        "model":              None,
        "firmware_version":   None,
        "serial":             None,
        "mac":                None,
        "relay_module_count": None,
        "relay_port_count":   None,
        "relay_states":       [],
        "modules":            [],
    }

    try:
        # 1. Firmware version
        version = get_version(host, port, timeout)
        result["firmware_version"] = version
        result["model"]            = detect_product_family(version)

        # 2. Device capabilities
        modules = get_devices(host, port, timeout)
        result["modules"] = modules

        relay_modules = get_relay_ports(modules)
        result["relay_module_count"] = len(relay_modules)
        result["relay_port_count"]   = sum(pc for _, pc in relay_modules)

        # 3. Relay states
        if relay_modules:
            states = query_relay_states(host, port, relay_modules, timeout)
            result["relay_states"] = states
            failed = [s for s in states if s.get("state") == "ERR"]
            if states and len(failed) == len(states):
                # Every port failed — the device is not usefully reporting.
                result["status"] = "error"
                result["error"]  = "Relay state query failed on all ports"
            else:
                # Reachable and reporting. Individual port failures are
                # recorded inside relay_states rather than downgrading the
                # whole device, which would count it offline on the dashboard.
                result["status"] = "success"
                result["error"]  = None
        else:
            result["status"] = "error"
            result["error"]  = "No relay ports found"

    except OSError as e:
        cli.debug.log(host, f"{type(e).__name__}: {e}")
        err_str = str(e)
        if "timed out" in err_str.lower() or "timeout" in err_str.lower():
            result["error"] = "Connection timed out"
        elif "refused" in err_str.lower():
            result["error"] = f"Cannot connect to {host}:{port}"
        elif "no route" in err_str.lower():
            result["error"] = "No route to host"
        elif "network is unreachable" in err_str.lower():
            result["error"] = "Network unreachable"
        elif "name or service not known" in err_str.lower():
            result["error"] = "DNS failed"
        else:
            result["error"] = err_str
    except Exception as e:
        result["error"] = str(e)

    cli.debug.log(host, f"result: {result['status']}" + (f" ({result['error']})" if result["error"] else ""))
    return result


# Relay addresses probed by --raw when getdevices reports no relay ports
RAW_PROBE_ADDRESSES = ["1:1", "1:2", "1:3", "3:1", "3:2", "3:3"]


def _visible_eol(text: str) -> str:
    """--raw: show CR/LF as \\r / \\n and break the line there, so a
    CR-separated reply (getdevices) doesn't overwrite itself on the terminal."""
    if not text:
        return "(no reply)"
    return re.sub(r"\r\n|\r|\n",
                  lambda m: m.group(0).replace("\r", "\\r").replace("\n", "\\n") + "\n", text)


def dump_raw(dev: dict, timeout: int = DEFAULT_TIMEOUT):
    """
    --raw: print the raw reply to getversion, getdevices and getstate for
    every relay port getdevices reports (or a few common addresses if none).
    Each command is its own TCP connection, as in a normal run.
    """
    host, port = dev["host"], dev["port"]
    # getversion failing means the device is unreachable -> run_raw reports it
    cli.raw_item("getversion", _visible_eol(tcp_command(host, port, "getversion", timeout=timeout)))

    addresses = list(RAW_PROBE_ADDRESSES)
    try:
        devs = tcp_command(host, port, "getdevices", timeout=timeout,
                           multi_line=True, end_marker="endlistdevices")
        cli.raw_item("getdevices", _visible_eol(devs))
        found = [f"{m}:{p}" for m, n in get_relay_ports(parse_devices(devs))
                 for p in range(1, n + 1)]
        if found:
            addresses = found
        else:
            cli.raw_item("note", "no relay ports in getdevices; probing common addresses")
    except Exception as e:
        cli.raw_error("getdevices", e)

    for addr in addresses:
        label = f"getstate,{addr}"
        try:
            cli.raw_item(label, _visible_eol(tcp_command(host, port, label, timeout=timeout)))
        except Exception as e:
            cli.raw_error(label, e)


# ---------------------------------------------------------------------------
# Output
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
            "protocol":        "Global Caché Unified TCP API v1.1 (raw TCP port 4998)",
            "mode":            "single-host" if args.host else "csv-batch",
            "workers":         args.workers,
            "total":           len(results),
            "success":         ok,
            "auth_errors":     auth,
            "errors":          err,
            "elapsed_seconds": round(elapsed, 2),
        },
        "relays": results,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)


def print_results_table(results: list, output_file: str, elapsed: float,
                        workers: int, firmware_filter: list = None):
    """Render the results table following the project visual style guide."""

    # --firmware: show only devices NOT on one of the versions (errors included).
    # The full results list is always saved to JSON regardless.
    display_results = cli.firmware_mismatches(results, firmware_filter)

    table_data = []
    for r in display_results:
        relay_summary = format_relay_states(r.get("relay_states", []))
        row = [
            status_icon(r),
            clean(r["host"]),
            clean(r["manufacturer"]),
            clean(r["model"]),
            clean(r["firmware_version"]),
            clean(r["relay_module_count"]),
            clean(r["relay_port_count"]),
            relay_summary,
            truncate_error(r.get("error") or ""),
        ]
        table_data.append(row)

    headers = ["Status", "Host", "Manufacturer", "Model", "Firmware",
               "Relay Mods", "Ports", "Port States (mod:port:state)", "Error"]

    table = tabulate(table_data, headers=headers,
                     tablefmt="pretty", stralign="left", numalign="right")

    first_line = table.split("\n")[0]
    raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw         = max(raw_width, 60)

    title = "Global Caché — Relay Query Results"
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
        f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}\u2717{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )

    # Device-specific metrics line — total relay ports discovered fleet-wide
    total_relay_ports = sum(
        r["relay_port_count"] for r in results
        if isinstance(r.get("relay_port_count"), int)
    )
    devices_with_relays = sum(
        1 for r in results
        if isinstance(r.get("relay_port_count"), int) and r["relay_port_count"] > 0
    )

    state_counts = {}
    for r in results:
        for s in r.get("relay_states", []):
            label = RELAY_STATE_LABELS.get(str(s.get("state")), str(s.get("state")))
            state_counts[label] = state_counts.get(label, 0) + 1
    reported = sum(v for k, v in state_counts.items() if k not in ("ERR", "None", "?"))

    if total_relay_ports:
        parts = "  |  ".join(
            f"{BOLD}{k}:{RESET}{WHITE} {v}" for k, v in sorted(state_counts.items())
        )
        print(
            f"  {BOLD}Relay Ports \u2014{RESET}{WHITE} "
            f"Discovered: {total_relay_ports}  |  "
            f"Devices: {devices_with_relays}/{total}  |  "
            f"{parts}  |  Reported: {reported}/{total_relay_ports}"
        )
    else:
        print(f"  {BOLD}Relay Ports \u2014{RESET}{WHITE} No data available")

    print()
    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {output_file}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers){RESET}")
    print(f"{RESET}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = cli.build_parser(
        script_file=__file__,
        description="Query Global Caché devices for firmware version and relay states via Unified TCP API.",
        default_csv=DEFAULT_CSV,
        output_dir=OUTPUT_DIR,
        default_port=DEFAULT_PORT,
        default_timeout=DEFAULT_TIMEOUT,
        default_workers=DEFAULT_WORKERS,
        firmware_help=("Show only devices NOT on any of these firmware versions in the "
                       "table (the getversion string, e.g. 710-1005-05). "
                       "The JSON always has every device."),
        epilog="""
Examples:
  python3 relay_script.py                               # whole CSV
  python3 relay_script.py --host 192.168.1.50           # one device
  python3 relay_script.py --host 192.168.1.50 --raw
  python3 relay_script.py --host 192.168.1.50 --debug
  python3 relay_script.py --firmware 710-1005-05 3.2-12 # who is NOT on these
  python3 relay_script.py -i devices.csv -t 15 -w 10 -o out.json

Authentication:
  The Global Caché TCP API (port 4998) requires no authentication.

Firmware Version:
  GC-100:         3.2-06 / 3.2-12 / 3.2-18
  iTach:          710-10xx-XX
  Flex:           710-20xx-XX / 710-30xx-XX / 710-40xx-XX
  Global Connect: other 710-XXXX-XX formats

Relay States:
  0 = Open (off)
  1 = Closed / SPDT on1
  2 = SPDT/DPDT on2
        """,
    )
    args = cli.parse_args(parser)

    term_width = get_terminal_width()

    import time
    start_time = time.monotonic()

    # -----------------------------------------------------------------------
    # Header block
    # -----------------------------------------------------------------------
    print(f"{WHITE}")
    print(f"  {BOLD}Global Caché Relay Query Tool{RESET}{WHITE}")
    print(f"  Queries Global Caché modules for firmware and relay port states")
    print(f"  Input:   {cli.input_label(args)}")
    print(f"  Output:  {'(none: --raw)' if args.raw else args.output}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    print(f"  API:     TCP port {args.port if (args.host and args.port) else DEFAULT_PORT} (no authentication)")
    if args.firmware:
        print(f"  Filter:  Showing devices not on firmware {cli.firmware_label(args.firmware)}")
    if args.debug:
        print(f"  Debug:   on (trace on stderr)")
    print(f"{RESET}")

    # -----------------------------------------------------------------------
    # Build device list (--host or CSV)
    # -----------------------------------------------------------------------
    devices = cli.select_devices(
        args, load_csv, lambda host: {"host": host, "port": DEFAULT_PORT})

    # -----------------------------------------------------------------------
    # --raw: dump what each device sends back, no table / JSON
    # -----------------------------------------------------------------------
    if args.raw:
        cli.run_raw(devices, lambda d: dump_raw(d, timeout=args.timeout))
        return

    # -----------------------------------------------------------------------
    # Progress bar + concurrent query loop
    # -----------------------------------------------------------------------
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
        return query_device(d["host"], d["port"], timeout=args.timeout)

    with tqdm(total=len(devices), bar_format=bar_fmt, ncols=term_width,
              dynamic_ncols=True, file=sys.stderr, leave=True) as pbar:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(do_query, d): d for d in devices}
            for fut in as_completed(futures):
                with results_lock:
                    results.append(fut.result())
                with active_lock:
                    pbar.set_postfix_str(latest_host["value"], refresh=False)
                pbar.update(1)

    elapsed = time.monotonic() - start_time
    pbar.set_postfix_str(f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s", refresh=True)

    # Re-sort results to match original input order
    host_order = {d["host"]: i for i, d in enumerate(devices)}
    results.sort(key=lambda r: host_order.get(r["host"], 0))

    print_results_table(results, args.output, elapsed, args.workers, args.firmware)
    save_results_json(results, args.output, args, elapsed)


if __name__ == "__main__":
    main()
