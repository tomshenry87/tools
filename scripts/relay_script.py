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
CYAN   = "\033[96m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
WHITE  = "\033[97m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ---------------------------------------------------------------------------
# Defaults & constants
# ---------------------------------------------------------------------------
DEFAULT_CSV     = "secrets/relay_firmware.csv"
OUTPUT_DIR      = "relay_firmware/files"
DEFAULT_OUTPUT  = os.path.join(
    OUTPUT_DIR,
    f"results_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
)
DEFAULT_TIMEOUT = 10
DEFAULT_PORT    = 4998
DEFAULT_WORKERS = 5

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


def truncate_error(err, max_len: int = 30) -> str:
    """Map verbose exception messages to short readable labels."""
    if not err:
        return ""
    s = str(err)
    for pat, label in [
        (r"[Tt]imed? out",                    "Timed out"),
        (r"[Cc]onnection refused",             "Conn refused"),
        (r"[Nn]o response",                    "No response"),
        (r"[Nn]o route to host",               "No route"),
        (r"[Nn]etwork is unreachable",         "Net unreachable"),
        (r"[Nn]ame or service not known",      "DNS failed"),
        (r"[Nn]etwork error",                  "Network error"),
        (r"ERR.*001",                          "Unknown command"),
        (r"ERR.*002",                          "Invalid syntax"),
        (r"ERR.*003",                          "Invalid address"),
        (r"ERR.*005",                          "Not supported"),
        (r"ERR\s+RO00[1-4]",                   "Relay error"),
        (r"[Nn]o relay ports",                 "No relay ports"),
        (r"[Nn]ot a .* device",               "Not supported"),
        (r"[Mm]alformed",                      "Bad response"),
        (r"[Ii]nvalid response",               "Bad response"),
    ]:
        if re.search(pat, s):
            return label
    s = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', '', s)
    s = re.sub(r'\[Errno\s*-?\d+\]\s*', '', s)
    s = re.sub(r'\s+', ' ', s).strip(': ')
    return (s[:max_len - 3] + "...") if len(s) > max_len else (s or "Error")


def status_icon(r: dict) -> str:
    """Return a coloured status icon string for a result dict."""
    s = r.get("status", "error")
    if s == "success":
        return f"{GREEN}\u2713 OK{RESET}{WHITE}"
    elif s == "partial":
        return f"{YELLOW}\u2713 PARTIAL{RESET}{WHITE}"
    return f"{RED}\u2717 ERROR{RESET}{WHITE}"


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
            except (ValueError, TypeError):
                port = DEFAULT_PORT
            devices.append({"host": host, "port": port})
    if not devices:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No valid entries found in CSV.{RESET}")
        sys.exit(1)
    return devices


# ---------------------------------------------------------------------------
# Global Caché TCP API helpers
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
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall((command + "\r").encode("ascii"))
        data = b""
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                decoded = data.decode("ascii", errors="replace")
                if multi_line and end_marker and end_marker in decoded:
                    break
                if not multi_line and "\r" in decoded:
                    break
            except socket.timeout:
                break
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
        "host":              host,
        "port":              port,
        "status":            "error",
        "firmware_version":  "N/A",
        "product_family":    "N/A",
        "relay_module_count": 0,
        "relay_port_count":  0,
        "relay_states":      [],
        "modules":           [],
        "error":             None,
        "query_timestamp":   datetime.now(timezone.utc).isoformat(),
    }

    try:
        # 1. Firmware version
        version = get_version(host, port, timeout)
        result["firmware_version"] = version
        result["product_family"]   = detect_product_family(version)

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
            # Partial success if some state queries errored
            any_err = any(s.get("state") == "ERR" for s in states)
            result["status"] = "partial" if any_err else "success"
        else:
            result["status"] = "success"
            result["error"]  = "No relay ports found"

    except OSError as e:
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

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def save_results_json(results: list, filepath: str, args, elapsed: float):
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    ok      = sum(1 for r in results if r["status"] == "success")
    partial = sum(1 for r in results if r["status"] == "partial")
    err     = sum(1 for r in results if r["status"] == "error")
    output  = {
        "query_info": {
            "csv_file":        str(Path(args.input).resolve()) if not args.host else args.host,
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "protocol":        "Global Caché Unified TCP API v1.1 (raw TCP port 4998)",
            "mode":            "single-host" if args.host else "csv-batch",
            "workers":         args.workers,
            "total":           len(results),
            "success":         ok,
            "partial":         partial,
            "errors":          err,
            "elapsed_seconds": round(elapsed, 2),
        },
        "relays": results,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)


def print_results_table(results: list, output_file: str, elapsed: float,
                        workers: int):
    """Render the results table following the project visual style guide."""

    table_data = []
    for r in results:
        relay_summary = format_relay_states(r.get("relay_states", []))
        row = [
            status_icon(r),
            clean(r["host"]),
            clean(r["product_family"]),
            clean(r["firmware_version"]),
            clean(str(r["relay_module_count"]) if r["relay_module_count"] else "N/A"),
            clean(str(r["relay_port_count"]) if r["relay_port_count"] else "N/A"),
            relay_summary if relay_summary != "N/A" else "N/A",
            truncate_error(r.get("error") or ""),
        ]
        table_data.append(row)

    headers = ["Status", "Host", "Family", "Firmware",
               "Relay Mods", "Ports", "Port States (mod:state)", "Error"]

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

    total   = len(results)
    ok      = sum(1 for r in results if r["status"] == "success")
    partial = sum(1 for r in results if r["status"] == "partial")
    err     = sum(1 for r in results if r["status"] == "error")

    print()
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}\u2713{RESET}{WHITE} {BOLD}Partial:{RESET}{WHITE} {partial}  |  "
        f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )

    # Relay state summary
    state_counts = {}
    for r in results:
        for s in r.get("relay_states", []):
            sv = s.get("state", "?")
            label = RELAY_STATE_LABELS.get(str(sv), str(sv))
            state_counts[label] = state_counts.get(label, 0) + 1

    total_relay_ports = sum(r.get("relay_port_count", 0) for r in results)
    reported = sum(v for k, v in state_counts.items() if k not in ("ERR", "?"))

    if state_counts:
        parts = "  |  ".join(
            f"{BOLD}{k}:{RESET}{WHITE} {v}"
            for k, v in sorted(state_counts.items())
        )
        print(
            f"  {BOLD}Relay States \u2014{RESET}{WHITE} {parts}  |  "
            f"{BOLD}Reported:{RESET}{WHITE} {reported}/{total_relay_ports}"
        )
    else:
        print(f"  {BOLD}Relay States \u2014{RESET}{WHITE} No data available")

    print()
    print(f"  {BOLD}Results saved:{RESET}{WHITE} {output_file}")
    print(f"  {BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers)")
    print(f"{RESET}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Query Global Caché devices for firmware version and relay states via Unified TCP API.",
        epilog="""
Examples:
  python relay_script.py
  python relay_script.py -i my_devices.csv
  python relay_script.py --host 192.168.1.50
  python relay_script.py -i devices.csv -t 15 -o output.json -w 10
  python relay_script.py --host 192.168.1.50 --raw

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
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-i", "--input",   default=DEFAULT_CSV,
        help=f"CSV file with 'host'/'port' columns (default: {DEFAULT_CSV})")
    parser.add_argument("--host",          default=None,
        help="Query a single host instead of reading a CSV")
    parser.add_argument("-o", "--output",  default=DEFAULT_OUTPUT,
        help=f"Output JSON file (default: timestamped file in {OUTPUT_DIR})")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-p", "--port",    type=int, default=DEFAULT_PORT,
        help=f"TCP port for --host mode (default: {DEFAULT_PORT})")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
        help=f"Number of concurrent workers (default: {DEFAULT_WORKERS})")
    parser.add_argument("--raw",           action="store_true", default=False,
        help="With --host: dump raw getversion and getdevices responses.")

    args = parser.parse_args()

    term_width = get_terminal_width()

    import time
    start_time = time.monotonic()

    # -----------------------------------------------------------------------
    # Header block
    # -----------------------------------------------------------------------
    input_display = args.host if args.host else args.input
    print(f"{WHITE}")
    print(f"  {BOLD}Global Caché — Relay Query Tool{RESET}{WHITE}")
    print(f"  Queries firmware version and relay port states via Unified TCP API.")
    print(f"  Input:    {input_display}")
    print(f"  Output:   {args.output}")
    print(f"  Workers:  {args.workers}")
    print(f"  Timeout:  {args.timeout}s")
    print(f"  API Port: {args.port if args.host else DEFAULT_PORT} (TCP)")
    print(f"{RESET}")

    # -----------------------------------------------------------------------
    # --raw dump mode (single host)
    # -----------------------------------------------------------------------
    if args.host and args.raw:
        print(f"{WHITE}Raw API responses for {args.host}:{args.port}{RESET}\n")
        try:
            ver = tcp_command(args.host, args.port, "getversion", timeout=args.timeout)
            print(f"{WHITE}--- getversion ---{RESET}")
            print(ver)
        except Exception as e:
            print(f"{WHITE}--- getversion --- {RED}ERROR:{RESET} {e}")
        print()
        try:
            devs = tcp_command(
                args.host, args.port, "getdevices", timeout=args.timeout,
                multi_line=True, end_marker="endlistdevices"
            )
            print(f"{WHITE}--- getdevices ---{RESET}")
            print(devs)
        except Exception as e:
            print(f"{WHITE}--- getdevices --- {RED}ERROR:{RESET} {e}")
        print()
        # Attempt getstate for a few common relay addresses
        for addr in ["1:1", "1:2", "1:3", "3:1", "3:2", "3:3"]:
            try:
                resp = tcp_command(args.host, args.port, f"getstate,{addr}",
                                   timeout=args.timeout)
                print(f"{WHITE}--- getstate,{addr} ---{RESET}")
                print(resp)
            except Exception as e:
                print(f"{WHITE}--- getstate,{addr} --- {RED}ERROR:{RESET} {e}")
        return

    # -----------------------------------------------------------------------
    # Build device list
    # -----------------------------------------------------------------------
    displays = [{"host": args.host, "port": args.port}] if args.host else load_csv(args.input)

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

    with tqdm(total=len(displays), bar_format=bar_fmt, ncols=term_width,
              dynamic_ncols=True, file=sys.stderr, leave=True) as pbar:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(do_query, d): d for d in displays}
            for fut in as_completed(futures):
                with results_lock:
                    results.append(fut.result())
                with active_lock:
                    pbar.set_postfix_str(latest_host["value"], refresh=False)
                pbar.update(1)

    elapsed = time.monotonic() - start_time
    pbar.set_postfix_str(f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s", refresh=True)

    # Re-sort results to match original input order
    host_order = {d["host"]: i for i, d in enumerate(displays)}
    results.sort(key=lambda r: host_order.get(r["host"], 0))

    print_results_table(results, args.output, elapsed, args.workers)
    save_results_json(results, args.output, args, elapsed)


if __name__ == "__main__":
    main()
