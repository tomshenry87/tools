#!/usr/bin/env python3
"""
ELO Touch Panel (Android) ADB Query Tool

Queries ELO touch panels over network ADB (TCP/IP, default port 5555) for:
  - Model        (ro.product.model)
  - Manufacturer (ro.product.manufacturer)
  - Serial       (ro.serialno)
  - Android ver  (ro.build.version.release)
  - SDK level    (ro.build.version.sdk)
  - Build/FW     (ro.build.display.id / ro.build.id)
  - Build date   (ro.build.date)

Workflow per host:
  1. adb connect <host>:<port>
  2. adb -s <host>:<port> shell getprop <key>   (batched)
  3. adb disconnect <host>:<port>

The ADB server must be running locally. The script will start it via
`adb start-server` on launch if it isn't already.
"""

import csv
import json
import re
import sys
import os
import shutil
import argparse
import subprocess
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
DEFAULT_CSV      = "secrets/tp_firmware.csv"
OUTPUT_DIR       = "tp_firmware/files"
DEFAULT_OUTPUT   = os.path.join(
    OUTPUT_DIR,
    f"results_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
)
DEFAULT_TIMEOUT  = 10
DEFAULT_PORT     = 5555
DEFAULT_WORKERS  = 5
DEFAULT_ADB      = "adb"

# getprop keys we want to query. Kept as a list so we can issue them in a
# single shell call per device and parse the output line-by-line.
GETPROP_KEYS = [
    "ro.product.model",
    "ro.product.manufacturer",
    "ro.product.brand",
    "ro.product.device",
    "ro.serialno",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.display.id",
    "ro.build.id",
    "ro.build.date",
    "ro.build.fingerprint",
]


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
        (r"[Cc]onnection timed out",            "Timed out"),
        (r"[Cc]onnection refused",              "Conn refused"),
        (r"[Nn]o response .* timeout",          "No response"),
        (r"[Nn]o route to host",                "No route"),
        (r"[Nn]etwork is unreachable",          "Net unreachable"),
        (r"[Nn]ame or service not known",       "DNS failed"),
        (r"[Nn]etwork error",                   "Network error"),
        (r"unable to connect",                  "Connect failed"),
        (r"failed to connect",                  "Connect failed"),
        (r"device unauthori[sz]ed",             "Unauthorized"),
        (r"device offline",                     "Device offline"),
        (r"device .* not found",                "Not connected"),
        (r"more than one device",               "Ambiguous target"),
        (r"adb .* not found",                   "adb missing"),
        (r"[Aa]uthentication required",         "Auth required"),
        (r"[Cc]ommand timed out",               "Cmd timeout"),
        (r"[Mm]alformed",                       "Bad response"),
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
    elif s == "auth_error":
        return f"{YELLOW}\u2717 AUTH ERR{RESET}{WHITE}"
    return f"{RED}\u2717 ERROR{RESET}{WHITE}"


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
# ADB helpers
# ---------------------------------------------------------------------------
def run_adb(adb_bin: str, args: list, timeout: int) -> tuple:
    """
    Run an adb command. Returns (returncode, stdout, stderr).
    Never raises on non-zero; only raises on timeout / binary missing.
    """
    try:
        proc = subprocess.run(
            [adb_bin] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        raise Exception("adb binary not found — install Android platform-tools or pass --adb")
    except subprocess.TimeoutExpired:
        raise Exception("Command timed out")


def adb_start_server(adb_bin: str, timeout: int = 10) -> None:
    try:
        run_adb(adb_bin, ["start-server"], timeout=timeout)
    except Exception:
        pass


def adb_connect(adb_bin: str, target: str, timeout: int) -> tuple:
    """Returns (success: bool, message: str)."""
    rc, out, err = run_adb(adb_bin, ["connect", target], timeout=timeout)
    combined = (out + err).strip().lower()

    if "connected to" in combined or "already connected" in combined:
        return True, "connected"
    if "unable to connect" in combined:
        return False, "unable to connect"
    if "failed to connect" in combined:
        return False, "failed to connect"
    if "cannot connect" in combined:
        return False, "cannot connect"
    if rc != 0:
        return False, combined or f"adb connect rc={rc}"
    # Some adb builds print nothing but succeed — treat empty + rc=0 as OK
    return True, "connected"


def adb_disconnect(adb_bin: str, target: str, timeout: int = 5) -> None:
    try:
        run_adb(adb_bin, ["disconnect", target], timeout=timeout)
    except Exception:
        pass


def adb_get_state(adb_bin: str, target: str, timeout: int) -> str:
    """Returns the adb connection state string (device / offline / unauthorized / unknown)."""
    rc, out, err = run_adb(adb_bin, ["-s", target, "get-state"], timeout=timeout)
    if rc != 0:
        blob = (out + err).strip().lower()
        if "unauthorized" in blob:
            return "unauthorized"
        if "offline" in blob:
            return "offline"
        if "not found" in blob:
            return "not found"
        return blob or "unknown"
    return out.strip() or "unknown"


def adb_getprops(adb_bin: str, target: str, keys: list, timeout: int) -> dict:
    """
    Issue one shell call that runs `getprop <key>` for every key, separated
    by a sentinel so we can split the output back into (key -> value) pairs.

    Using a sentinel beats shelling out once per property (11x fewer round
    trips) and beats plain `getprop` (which dumps hundreds of unrelated props).
    """
    sentinel = "<<<ELO_ADB_SEP>>>"
    # Build: getprop ro.product.model; echo SEP; getprop ro.serialno; echo SEP; ...
    cmd_parts = []
    for k in keys:
        cmd_parts.append(f"getprop {k}")
        cmd_parts.append(f"echo {sentinel}")
    shell_cmd = "; ".join(cmd_parts)

    rc, out, err = run_adb(
        adb_bin,
        ["-s", target, "shell", shell_cmd],
        timeout=timeout,
    )
    if rc != 0:
        blob = (out + err).strip()
        raise Exception(blob or f"adb shell rc={rc}")

    # Split by sentinel, strip trailing sentinel if present
    chunks = out.split(sentinel)
    # The last chunk is the tail after the final echo — discard if empty-ish
    values = [c.strip() for c in chunks[:len(keys)]]
    while len(values) < len(keys):
        values.append("")
    return dict(zip(keys, values))


# ---------------------------------------------------------------------------
# Main query
# ---------------------------------------------------------------------------
def query_panel(host: str, port: int, adb_bin: str,
                timeout: int = DEFAULT_TIMEOUT,
                skip_connect: bool = False) -> dict:
    """Query a single ELO panel over ADB for identity + build info."""
    target = f"{host}:{port}"
    result = {
        "host":                 host,
        "port":                 port,
        "status":               "error",
        "model":                "N/A",
        "manufacturer":         "N/A",
        "brand":                "N/A",
        "device":               "N/A",
        "serial":               "N/A",
        "android_version":      "N/A",
        "sdk":                  "N/A",
        "build_id":             "N/A",
        "build_display_id":     "N/A",
        "build_date":           "N/A",
        "build_fingerprint":    "N/A",
        "firmware_version":     "N/A",
        "adb_state":            "N/A",
        "error":                None,
        "query_timestamp":      datetime.now(timezone.utc).isoformat(),
    }

    try:
        if not skip_connect:
            ok, msg = adb_connect(adb_bin, target, timeout=timeout)
            if not ok:
                result["error"] = msg
                return result

        state = adb_get_state(adb_bin, target, timeout=timeout)
        result["adb_state"] = state

        if state == "unauthorized":
            result["status"] = "auth_error"
            result["error"]  = "device unauthorized — approve RSA fingerprint on panel"
            return result
        if state != "device":
            result["error"] = f"device {state}"
            return result

        props = adb_getprops(adb_bin, target, GETPROP_KEYS, timeout=timeout)

        result["model"]             = props.get("ro.product.model")           or "N/A"
        result["manufacturer"]      = props.get("ro.product.manufacturer")    or "N/A"
        result["brand"]             = props.get("ro.product.brand")           or "N/A"
        result["device"]            = props.get("ro.product.device")          or "N/A"
        result["serial"]            = props.get("ro.serialno")                or "N/A"
        result["android_version"]   = props.get("ro.build.version.release")   or "N/A"
        result["sdk"]               = props.get("ro.build.version.sdk")       or "N/A"
        result["build_id"]          = props.get("ro.build.id")                or "N/A"
        result["build_display_id"]  = props.get("ro.build.display.id")        or "N/A"
        result["build_date"]        = props.get("ro.build.date")              or "N/A"
        result["build_fingerprint"] = props.get("ro.build.fingerprint")       or "N/A"

        # Primary firmware identifier: display.id (human-readable build label)
        # Fall back to build.id if display.id is missing.
        fw = result["build_display_id"]
        if not fw or fw == "N/A":
            fw = result["build_id"]
        result["firmware_version"] = fw or "N/A"

        result["status"] = "success"

    except Exception as e:
        result["error"] = str(e)

    finally:
        if not skip_connect:
            adb_disconnect(adb_bin, target)

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def save_results_json(results: list, filepath: str, args, elapsed: float):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    ok   = sum(1 for r in results if r["status"] == "success")
    auth = sum(1 for r in results if r["status"] == "auth_error")
    err  = sum(1 for r in results if r["status"] == "error")
    output = {
        "query_info": {
            "csv_file":        str(Path(args.input).resolve()),
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "protocol":        "Android Debug Bridge (ADB) over TCP/IP",
            "mode":            "connect + getprop + disconnect" if not args.no_connect else "getprop only (pre-connected)",
            "workers":         args.workers,
            "total":           len(results),
            "success":         ok,
            "auth_errors":     auth,
            "errors":          err,
            "elapsed_seconds": round(elapsed, 2),
        },
        "panels": results,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)


def print_results_table(results: list, output_file: str, elapsed: float,
                        workers: int, firmware_filter: str = None):
    """Render the results table following the project visual style guide."""

    # Apply firmware filter — mismatched or errored rows only.
    # The full results list is always saved to JSON regardless.
    if firmware_filter:
        display_results = [
            r for r in results
            if r.get("firmware_version", "N/A") != firmware_filter
        ]
    else:
        display_results = results

    table_data = []
    for r in display_results:
        row = [
            status_icon(r),
            clean(r["host"]),
            clean(r["manufacturer"]),
            clean(r["model"]),
            clean(r["firmware_version"]),
            clean(r["serial"]),
            clean(r["android_version"]),
            clean(r["adb_state"]),
            truncate_error(r.get("error")),
        ]
        table_data.append(row)

    headers = ["Status", "Host", "Manufacturer", "Model", "Firmware",
               "Serial", "Android", "ADB State", "Error"]

    table = tabulate(table_data, headers=headers,
                     tablefmt="pretty", stralign="left", numalign="right")

    first_line = table.split("\n")[0]
    raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw         = max(raw_width, 60)

    title = "ELO Touch Panel \u2014 ADB Query Results"
    if firmware_filter:
        title += f"  \u2014  Mismatched: {len(display_results)}/{len(results)}"
    pad   = (bw - len(title)) // 2

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")
    for line in table.split("\n"):
        print(f"  {line}")

    total = len(display_results)
    ok    = sum(1 for r in display_results if r["status"] == "success")
    auth  = sum(1 for r in display_results if r["status"] == "auth_error")
    err   = sum(1 for r in display_results if r["status"] == "error")

    print()
    if firmware_filter:
        print(
            f"  {BOLD}Firmware filter:{RESET}{WHITE} {firmware_filter}  |  "
            f"{BOLD}Showing:{RESET}{WHITE} {len(display_results)} of {len(results)} panels"
        )
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}\u2717{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )

    # Android version distribution
    av_counts = {}
    for r in display_results:
        av = r.get("android_version", "N/A")
        av_counts[av] = av_counts.get(av, 0) + 1

    reported = sum(v for k, v in av_counts.items() if k != "N/A")
    if reported:
        parts = "  |  ".join(
            f"{BOLD}Android {v}:{RESET}{WHITE} {c}"
            for v, c in sorted(av_counts.items()) if v != "N/A"
        )
        print(f"  {BOLD}Android versions \u2014{RESET}{WHITE} {parts}  |  {BOLD}Reported:{RESET}{WHITE} {reported}/{total}")
    else:
        print(f"  {BOLD}Android versions \u2014{RESET}{WHITE} No data available")

    print()
    print(f"  {BOLD}Results saved:{RESET}{WHITE} {output_file}")
    print(f"  {BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers)")
    print(f"{RESET}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Query ELO Android touch panels for firmware / build info via ADB over TCP/IP.",
        epilog="""
Examples:
  python elo_adb_query.py
  python elo_adb_query.py -i my_panels.csv
  python elo_adb_query.py --host 192.168.1.50
  python elo_adb_query.py --host 192.168.1.50 -p 5555 --raw
  python elo_adb_query.py -i tp_firmware.csv -t 15 -o output.json -w 10
  python elo_adb_query.py --firmware FDF4.160707.001

Prerequisites:
  - Android platform-tools installed and `adb` on PATH (or pass --adb).
  - Each panel has ADB over TCP/IP enabled (default port 5555).
  - The first connection to a new panel may require approval of the host's
    RSA fingerprint on the panel itself (shown as AUTH ERR).

Firmware Version:
  Uses ro.build.display.id (human-readable build label), falling back to
  ro.build.id if display.id is not set.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-i", "--input",        default=DEFAULT_CSV,
        help=f"CSV file with 'host'/'port' columns (default: {DEFAULT_CSV})")
    parser.add_argument("--host",               default=None,
        help="Query a single host instead of reading a CSV")
    parser.add_argument("-p", "--port",         type=int, default=DEFAULT_PORT,
        help=f"Port for --host mode (default: {DEFAULT_PORT})")
    parser.add_argument("-o", "--output",       default=DEFAULT_OUTPUT,
        help=f"Output JSON file (default: {DEFAULT_OUTPUT})")
    parser.add_argument("-t", "--timeout",      type=int, default=DEFAULT_TIMEOUT,
        help=f"Per-command timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-w", "--workers",      type=int, default=DEFAULT_WORKERS,
        help=f"Number of concurrent workers (default: {DEFAULT_WORKERS})")
    parser.add_argument("--adb",                default=DEFAULT_ADB,
        help=f"Path to adb binary (default: {DEFAULT_ADB} — uses PATH)")
    parser.add_argument("--no-connect",         action="store_true", default=False,
        help="Skip adb connect/disconnect (assume panels are already connected)")
    parser.add_argument("--raw",                action="store_true", default=False,
        help="With --host: dump the full getprop output for the device.")
    parser.add_argument("--firmware",           default=None, metavar="VERSION",
        help="Only show panels whose firmware does NOT match VERSION in the terminal table. JSON output always contains all results.")

    args = parser.parse_args()

    term_width = get_terminal_width()

    import time
    start_time = time.monotonic()

    # Ensure adb server is running before we fan out worker threads — avoids
    # a thundering-herd where every worker tries to spawn the daemon at once.
    adb_start_server(args.adb, timeout=args.timeout)

    # -----------------------------------------------------------------------
    # Header block
    # -----------------------------------------------------------------------
    input_display = args.host if args.host else args.input
    print(f"{WHITE}")
    print(f"  {BOLD}ELO Touch Panel — ADB Query Tool{RESET}{WHITE}")
    print(f"  Queries Android build info via `adb connect` + `getprop`.")
    print(f"  Input:   {input_display}")
    print(f"  Output:  {args.output}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    print(f"  ADB:     {args.adb}")
    print(f"  Mode:    {'pre-connected (no auto-connect)' if args.no_connect else 'auto connect + disconnect'}")
    if args.firmware:
        print(f"  Filter:  Showing panels not on firmware {args.firmware}")
    print(f"{RESET}")

    # -----------------------------------------------------------------------
    # Single-host --raw dump
    # -----------------------------------------------------------------------
    if args.host and args.raw:
        target = f"{args.host}:{args.port}"
        print(f"{WHITE}Raw getprop dump for {target}:{RESET}\n")
        try:
            if not args.no_connect:
                ok, msg = adb_connect(args.adb, target, timeout=args.timeout)
                print(f"{WHITE}--- adb connect --- {GREEN if ok else RED}{msg}{RESET}")
                if not ok:
                    return
            state = adb_get_state(args.adb, target, timeout=args.timeout)
            print(f"{WHITE}--- adb get-state --- {state}{RESET}\n")
            rc, out, err = run_adb(args.adb, ["-s", target, "shell", "getprop"], timeout=args.timeout)
            if rc == 0:
                print(out)
            else:
                print(f"{RED}ERROR:{RESET} {err or out}")
        except Exception as e:
            print(f"{RED}ERROR:{RESET} {e}")
        finally:
            if not args.no_connect:
                adb_disconnect(args.adb, target)
        return

    # -----------------------------------------------------------------------
    # Build panel list
    # -----------------------------------------------------------------------
    panels = [{"host": args.host, "port": args.port}] if args.host else load_csv(args.input)

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
        return query_panel(
            d["host"], d["port"],
            adb_bin=args.adb,
            timeout=args.timeout,
            skip_connect=args.no_connect,
        )

    with tqdm(total=len(panels), bar_format=bar_fmt, ncols=term_width,
              dynamic_ncols=True, file=sys.stderr, leave=True) as pbar:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(do_query, d): d for d in panels}
            for fut in as_completed(futures):
                with results_lock:
                    results.append(fut.result())
                with active_lock:
                    pbar.set_postfix_str(latest_host["value"], refresh=False)
                pbar.update(1)

    elapsed = time.monotonic() - start_time
    pbar.set_postfix_str(f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s", refresh=True)

    # Re-sort results to match original CSV input order
    host_order = {d["host"]: i for i, d in enumerate(panels)}
    results.sort(key=lambda r: host_order.get(r["host"], 0))

    print_results_table(results, args.output, elapsed, args.workers, args.firmware)
    save_results_json(results, args.output, args, elapsed)


if __name__ == "__main__":
    main()
