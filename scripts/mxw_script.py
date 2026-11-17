#!/usr/bin/env python3
"""
mxw_query.py - Shure Microflex Wireless (MXW) APT inventory & health query.

Connects to each APT via the legacy MXW command-string protocol (TCP/2202),
queries identity + per-channel mic status, and emits a styled terminal
report plus a JSON file for downstream tooling.

Usage:
    python3 mxw_script.py                         # reads secrets/mxw_firmware.csv
    python3 mxw_script.py -i other_hosts.csv [-o out.json] [-w 5] [-t 3]
    python3 mxw_script.py --host 10.1.2.3 [--raw | --debug]
    (python3 mxw_script.py other_hosts.csv still works: legacy positional CSV)

Defaults:
    Input:  secrets/mxw_firmware.csv
    Output: mxw_firmware/files/results_<YYYYMMDD>_<HHMMSS>.json
            Envelope: {"query_info": {...}, "transceivers": [...]}

CSV columns:
    host           required - IP or hostname of the MXW APT
    port           optional - TCP port (default 2202)
"""

import argparse
import csv
import json
import os
import re
import shutil
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import standard_cli as cli  # noqa: E402  (standard flags, --debug/--raw helpers)

from tabulate import tabulate
from tqdm import tqdm

# ---------------------------------------------------------------------------
# ANSI Color Palette (per style guide)
# ---------------------------------------------------------------------------
CYAN   = "\033[96m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
WHITE  = "\033[97m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------
DEFAULT_PORT    = 2202
DEFAULT_TIMEOUT = 3
DEFAULT_WORKERS = 5
PROTOCOL_NAME   = "Shure MXW Command Strings v1"

DEFAULT_CSV     = "secrets/mxw_firmware.csv"        # relative to this script's folder
OUTPUT_DIR      = "mxw_firmware/files"              # results_<YYYYMMDD>_<HHMMSS>.json

# MXW magic battery values
BATT_ON_CHARGER = 65533
BATT_CALCULATING = 65534
BATT_OFF         = 65535
BATT_MIC_OFF     = 255

# Regex to parse "< REP [n] PARAM value... >" responses
REP_RE = re.compile(r"<\s*REP(?:\s+(\d+))?\s+(\S+)\s+(.*?)\s*>")

# Per-channel sweep after GET DEVICE_ID (channel 0 = all channels)
CHANNEL_COMMANDS = ("GET 0 TX_AVAILABLE",
                    "GET 0 TX_TYPE",
                    "GET 0 TX_STATUS",
                    "GET 0 BATT_CHARGE",
                    "GET 0 BATT_HEALTH")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def clean(val):
    """Style guide: normalize Nones, sentinels, and error strings to 'N/A'."""
    s = str(val) if val is not None else "N/A"
    if s in ("None", "-1", ""):
        return "N/A"
    if s.startswith("ERROR") or s in ("Not available", "AUTH ERROR", "See diagnostic"):
        return "N/A"
    return s


def truncate_error(err, max_len=30):
    """Style guide: short, readable error labels for the table."""
    if not err:
        return ""
    s = str(err)
    for pat, label in [
        # MXW-specific
        (r"REP\s*ERR",                    "Unknown cmd"),
        (r"No\s*REP\s*received",          "No response"),
        (r"Malformed\s*response",         "Bad response"),
        # Generic network
        (r"[Cc]onnection timed out",      "Timed out"),
        (r"[Cc]onnection refused",        "Conn refused"),
        (r"[Nn]o response .* timeout",    "No response"),
        (r"[Nn]o route to host",          "No route"),
        (r"[Nn]etwork is unreachable",    "Net unreachable"),
        (r"[Nn]ame or service not known", "DNS failed"),
        (r"timed out",                    "Timed out"),
    ]:
        if re.search(pat, s):
            return label
    s = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', '', s)
    s = re.sub(r'\[Errno\s*-?\d+\]\s*', '', s)
    s = re.sub(r'\s+', ' ', s).strip(': ')
    return (s[:max_len - 3] + "...") if len(s) > max_len else (s or "Error")


def status_icon(r):
    s = r.get("status", "error")
    if s == "success":
        return f"{GREEN}\u2713 OK{RESET}{WHITE}"
    elif s == "auth_error":
        return f"{YELLOW}\u2717 AUTH ERR{RESET}{WHITE}"
    return f"{RED}\u2717 ERROR{RESET}{WHITE}"


def channels_from_device_id(device_id):
    """MXWAPT2/4/8 → 2/4/8 channels. Returns None if not determinable."""
    if not device_id:
        return None
    m = re.search(r"MXWAPT(\d+)", device_id)
    if m:
        return int(m.group(1))
    return None


def summary_state(statuses):
    """Worst-case across channels for the State column."""
    if not statuses:
        return "N/A"
    priority = ["ACTIVE", "MUTE", "STANDBY", "ON_CHARGER", "UNKNOWN"]
    present = [s for s in priority if s in statuses]
    return present[0] if present else statuses[0]


# ---------------------------------------------------------------------------
# Network query
# ---------------------------------------------------------------------------
def _send(sock, command, drain_wait=0.3, host="?"):
    """Send one MXW command, drain reply until socket goes quiet.

    host is only used to label the --debug trace.
    """
    cli.debug.sent(host, f"< {command} >")
    sock.sendall(f"< {command} >".encode("ascii"))
    sock.settimeout(drain_wait)
    chunks = []
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                cli.debug.log(host, "connection closed by device")
                break
            chunks.append(data)
    except socket.timeout:
        cli.debug.log(host, f"quiet for {drain_wait}s: end of reply")
    cli.debug.received(host, b"".join(chunks))
    return b"".join(chunks).decode("ascii", errors="replace")


def _parse_reps(text):
    """Parse all '< REP [n] PARAM value >' frames into a dict.

    Returns {param: value} for device-scope and {(channel, param): value}
    for per-channel. Strips surrounding {braces} from string values.
    """
    parsed = {}
    for ch, param, val in REP_RE.findall(text):
        val = val.strip()
        if val.startswith("{") and val.endswith("}"):
            val = val[1:-1].strip()
        if ch:
            parsed[(int(ch), param)] = val
        else:
            parsed[param] = val
    return parsed


def query_apt(host, port, timeout):
    """Connect, query, and return a result dict for one APT."""
    result = {
        "host": host,
        "port": port,
        "query_timestamp": datetime.now(timezone.utc).isoformat(),
        "manufacturer": "Shure",
        "model": None,
        "firmware": None,           # not exposed via MXW command strings
        "device_id": None,
        "channel_count": None,
        "channels_linked": None,
        "channels": [],
        "min_batt_charge": None,
        "min_batt_health": None,
        "state": None,
        "status": "error",
        "error": None,
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            cli.debug.log(host, f"connecting to {host}:{port} (timeout {timeout}s)")
            s.settimeout(timeout)
            s.connect((host, port))
            cli.debug.log(host, "connected")

            # 1) Device identity
            reps = _parse_reps(_send(s, "GET DEVICE_ID", host=host))
            device_id = reps.get("DEVICE_ID")
            if not device_id:
                raise RuntimeError("No REP received for DEVICE_ID")
            if device_id.startswith("REP ERR") or device_id == "ERR":
                raise RuntimeError("REP ERR on DEVICE_ID")

            result["device_id"] = device_id
            ch_count = channels_from_device_id(device_id)
            result["channel_count"] = ch_count
            if ch_count:
                result["model"] = f"MXWAPT{ch_count}"
            else:
                result["model"] = "MXWAPT"

            # 2) Per-channel sweep (channel 0 = all)
            combined = ""
            for cmd in CHANNEL_COMMANDS:
                combined += _send(s, cmd, host=host)
            ch_reps = _parse_reps(combined)

            channels = []
            statuses = []
            charges = []
            healths = []
            linked = 0

            for ch in range(1, (ch_count or 0) + 1):
                avail   = ch_reps.get((ch, "TX_AVAILABLE"))
                tx_type = ch_reps.get((ch, "TX_TYPE"))
                tx_stat = ch_reps.get((ch, "TX_STATUS"))
                charge  = ch_reps.get((ch, "BATT_CHARGE"))
                health  = ch_reps.get((ch, "BATT_HEALTH"))

                if avail == "YES":
                    linked += 1

                # Battery charge interpretation
                charge_val = None
                try:
                    raw = int(charge) if charge is not None else None
                    if raw is not None and raw not in (BATT_MIC_OFF,):
                        charge_val = raw
                        charges.append(raw)
                except (TypeError, ValueError):
                    cli.debug.log(host, f"ch {ch}: BATT_CHARGE {charge!r} is not a number")

                # Battery health interpretation
                health_val = None
                try:
                    raw = int(health) if health is not None else None
                    if raw is not None and 0 <= raw <= 100:
                        health_val = raw
                        healths.append(raw)
                except (TypeError, ValueError):
                    cli.debug.log(host, f"ch {ch}: BATT_HEALTH {health!r} is not a number")

                if tx_stat:
                    statuses.append(tx_stat)

                channels.append({
                    "channel": ch,
                    "tx_available": avail,
                    "tx_type": tx_type,
                    "tx_status": tx_stat,
                    "batt_charge": charge_val,
                    "batt_health": health_val,
                })

            result["channels"]        = channels
            result["channels_linked"] = linked
            result["min_batt_charge"] = min(charges) if charges else None
            result["min_batt_health"] = min(healths) if healths else None
            result["state"]           = summary_state(statuses)
            result["status"]          = "success"

    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except OSError as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    cli.debug.log(host, f"result: {result['status']}" + (f" ({result['error']})" if result["error"] else ""))
    return result


def dump_raw(dev, timeout):
    """--raw: print the raw reply to GET DEVICE_ID and each per-channel GET."""
    host, port = dev["host"], dev["port"]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        cli.debug.log(host, f"connecting to {host}:{port} (timeout {timeout}s)")
        s.settimeout(timeout)
        s.connect((host, port))   # failure -> run_raw prints a connection error
        for cmd in ("GET DEVICE_ID",) + CHANNEL_COMMANDS:
            try:
                cli.raw_item(cmd, _send(s, cmd, host=host) or "(no reply)")
            except Exception as e:
                cli.raw_error(cmd, e)


# ---------------------------------------------------------------------------
# CSV loader (per style guide)
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
            print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} CSV needs 'host' column.{RESET}")
            sys.exit(1)
        for row in reader:
            host = row.get(col_map["host"], "").strip()
            if not host or host.startswith("#"):
                continue
            port = DEFAULT_PORT
            if "port" in col_map:
                pv = row.get(col_map["port"], "").strip()
                if pv:
                    try:
                        port = int(pv)
                    except ValueError:
                        cli.debug.log(host, f"bad port {pv!r} in CSV; using {DEFAULT_PORT}")
            devices.append({"host": host, "port": port})
    return devices


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = cli.build_parser(
        script_file=__file__,
        description="Query Shure MXW APTs over TCP/2202.",
        default_csv=DEFAULT_CSV,
        output_dir=OUTPUT_DIR,
        default_port=DEFAULT_PORT,
        default_timeout=DEFAULT_TIMEOUT,
        default_workers=DEFAULT_WORKERS,
        timeout_type=float,
        firmware_help=("Show only devices NOT on any of these firmware versions in the "
                       "table. MXW command strings expose no firmware version, so every "
                       "APT counts as a mismatch and the table lists them all. "
                       "The JSON always has every device."),
        epilog="""
Examples:
  python3 mxw_script.py                          # whole CSV
  python3 mxw_script.py --host 10.1.2.3          # one APT
  python3 mxw_script.py --host 10.1.2.3 --raw
  python3 mxw_script.py --host 10.1.2.3 --debug
  python3 mxw_script.py -i hosts.csv -t 5 -w 10 -o out.json

Protocol:
  Shure MXW command strings over TCP port 2202. No authentication.
  Commands: GET DEVICE_ID, then GET 0 TX_AVAILABLE / TX_TYPE / TX_STATUS /
  BATT_CHARGE / BATT_HEALTH (channel 0 = all channels).
  No firmware version is exposed, so the Firmware column is always N/A.

CSV columns:
  host   required - IP or hostname of the MXW APT
  port   optional - TCP port (default 2202)
        """,
    )
    # Legacy: the CSV used to be a positional argument. Still accepted, hidden.
    ap.add_argument("csv_file", nargs="?", default=None, help=argparse.SUPPRESS)
    args = cli.parse_args(ap)
    if args.csv_file:
        args.input = args.csv_file

    devices = cli.select_devices(
        args, load_csv, lambda host: {"host": host, "port": DEFAULT_PORT})
    total = len(devices)
    if total == 0:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No devices in CSV.{RESET}")
        sys.exit(1)

    # ---------- Header block ----------
    print(f"{WHITE}")
    print(f"  {BOLD}Shure MXW Inventory Query{RESET}{WHITE}")
    print(f"  Queries MXW APTs for identity, channel status, and battery telemetry")
    print(f"  Input:    {cli.input_label(args)}")
    print(f"  Output:   {'(none: --raw)' if args.raw else args.output}")
    print(f"  Workers:  {args.workers}")
    print(f"  Timeout:  {args.timeout}s")
    print(f"  Protocol: {PROTOCOL_NAME}")
    if args.firmware:
        print(f"  Filter:   Showing devices not on firmware {cli.firmware_label(args.firmware)}")
    if args.debug:
        print(f"  Debug:    on (trace on stderr)")
    print(f"{RESET}")

    # ---------- --raw: dump what each APT sends back, no table / JSON ----------
    if args.raw:
        cli.run_raw(devices, lambda d: dump_raw(d, args.timeout))
        return

    # ---------- Progress bar setup ----------
    active_lock = threading.Lock()
    latest_host = {"value": ""}

    def worker(dev):
        with active_lock:
            latest_host["value"] = dev["host"]
        return query_apt(dev["host"], dev["port"], args.timeout)

    term_width = shutil.get_terminal_size((120, 24)).columns
    bar_fmt = (
        f"  {WHITE}Scanning{RESET} "
        f"{CYAN}{{bar}}{RESET}"
        f" {WHITE}{{n_fmt}}/{{total_fmt}}{RESET}"
        f" {WHITE}[{{elapsed}}<{{remaining}}]{RESET}"
        f"  {WHITE}{{postfix}}{RESET}"
    )

    results = []
    start = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as ex, tqdm(
        total=total,
        bar_format=bar_fmt,
        ncols=term_width,
        dynamic_ncols=True,
        file=sys.stderr,
        leave=True,
    ) as pbar:
        futures = {ex.submit(worker, d): d for d in devices}
        for fut in as_completed(futures):
            results.append(fut.result())
            with active_lock:
                host_display = latest_host["value"]
            pbar.set_postfix_str(host_display, refresh=False)
            pbar.update(1)

        elapsed = time.time() - start
        pbar.set_postfix_str(
            f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s",
            refresh=True,
        )

    # Sort results to match input order
    order = {d["host"]: i for i, d in enumerate(devices)}
    results.sort(key=lambda r: order.get(r["host"], 1e9))

    # ---------- Counts ----------
    ok   = sum(1 for r in results if r["status"] == "success")
    auth = sum(1 for r in results if r["status"] == "auth_error")
    err  = sum(1 for r in results if r["status"] == "error")

    # ---------- Build table ----------
    # --firmware: only devices NOT on one of the versions. MXW reports no
    # firmware, so with a filter every APT is listed. JSON keeps every device.
    display_results = cli.firmware_mismatches(results, args.firmware, key="firmware")
    headers = [
        "Status", "Host", "Manufacturer", "Model", "Firmware",
        "Channels", "Min Batt %", "Min Health %", "State", "Error",
    ]
    rows = []
    for r in display_results:
        ch_count  = r.get("channel_count")
        ch_linked = r.get("channels_linked")
        ch_cell   = f"{ch_linked}/{ch_count}" if (ch_count and ch_linked is not None) else "N/A"

        rows.append([
            status_icon(r),
            clean(r.get("host")),
            clean(r.get("manufacturer")),
            clean(r.get("model")),
            clean(r.get("firmware")),
            clean(ch_cell),
            clean(r.get("min_batt_charge")),
            clean(r.get("min_batt_health")),
            clean(r.get("state")),
            truncate_error(r.get("error")),
        ])

    table = tabulate(rows, headers=headers, tablefmt="pretty",
                     stralign="left", numalign="right")

    # ---------- Banner + table print ----------
    first_line = table.split("\n")[0]
    raw_width = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw = max(raw_width, 60)

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    title = "Shure MXW Query Results \u2014 Channel & Battery Status"
    pad = (bw - len(title)) // 2
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")

    for line in table.split("\n"):
        print(f"  {line}")

    # ---------- Summary footer ----------
    print()
    if args.firmware:
        print(
            f"  {BOLD}Firmware filter:{RESET}{WHITE} {cli.firmware_label(args.firmware)}  |  "
            f"{BOLD}Showing:{RESET}{WHITE} {len(display_results)} of {total} devices"
        )
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}\u2717{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )

    # Per-channel battery charges (all linked mics from successful APTs)
    charge_vals = []
    for r in results:
        if r["status"] != "success":
            continue
        for ch in r.get("channels", []):
            if ch.get("batt_charge") is not None:
                charge_vals.append(ch["batt_charge"])

    if charge_vals:
        avg = sum(charge_vals) / len(charge_vals)
        print(
            f"  {BOLD}Battery Charge %{RESET}{WHITE} \u2014 "
            f"Avg: {avg:.0f}  |  Min: {min(charge_vals)}  |  "
            f"Max: {max(charge_vals)}  |  Reported: {len(charge_vals)}/{total}"
        )
    else:
        print(f"  {BOLD}Battery Charge %{RESET}{WHITE} \u2014 No data available")

    print(f"{RESET}")

    # ---------- JSON output ----------
    out = {
        "query_info": {
            "csv_file": cli.input_label(args),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": PROTOCOL_NAME,
            "mode": "tcp-command-strings",
            "workers": args.workers,
            "total": total,
            "success": ok,
            "errors": err,
            "elapsed_seconds": round(elapsed, 2),
        },
        "transceivers": results,
    }
    cli.ensure_parent(args.output)
    Path(args.output).write_text(json.dumps(out, indent=2))

    # ---------- Closing footer ----------
    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {args.output}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({args.workers} workers){RESET}")
    print()


if __name__ == "__main__":
    main()
