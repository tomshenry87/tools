#!/usr/bin/env python3
"""
AXIS Camera VAPIX Query Tool
Queries AXIS cameras for firmware version and temperature via the official
VAPIX API (basicdeviceinfo.cgi, param.cgi, temperaturecontrol.cgi).

CSV format: host,username,password
"""

import csv
import json
import os
import re
import sys
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from time import time

import argparse

import requests
import urllib3
from requests.auth import HTTPDigestAuth
from tabulate import tabulate
from tqdm import tqdm

# ── Suppress SSL warnings for cameras using self-signed certs ─────────────────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── ANSI colour palette ───────────────────────────────────────────────────────
CYAN   = "\033[96m"   # Progress bar fill
GREEN  = "\033[92m"   # Success states
RED    = "\033[91m"   # Failure / error states
YELLOW = "\033[93m"   # Warning / auth error states
WHITE  = "\033[97m"   # All body text, table content, labels
BOLD   = "\033[1m"    # Section headers, label emphasis
RESET  = "\033[0m"    # Always close every colour block

# ── Config ────────────────────────────────────────────────────────────────────
FILES_DIR   = Path("files")
CSV_FILE    = str(FILES_DIR / "cameras.csv")
OUTPUT_FILE = str(FILES_DIR / "results.json")
MAX_WORKERS = 5
TIMEOUT     = 10      # seconds per request
VERIFY_SSL  = False   # set True if your cameras have valid certs

# Sensors to prefer (priority order) when picking a single "best" reading
# for the table. "Main" is the overall board temp on M4328-P / M3068-P.
PREFERRED_SENSORS = ["main", "soc", "cpu", "board", "case"]

# Noise words stripped from ProdFullName before display
_MODEL_STRIP = re.compile(
    r"\b(AXIS|Network Camera|Panoramic Camera|Fixed Dome|Mini Dome|"
    r"Fisheye|Box Camera|Bullet|Camera)\b",
    re.IGNORECASE,
)

# Thread-safe tracking of the most recently started host for the progress bar
_active_lock = threading.Lock()
_latest_host = {"value": ""}


# ─────────────────────────────────────────────────────────────────────────────
# CSV loader
# ─────────────────────────────────────────────────────────────────────────────

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
            username = row.get(col_map.get("username", ""), "root").strip() or "root"
            password = row.get(col_map.get("password", ""), "").strip()
            devices.append({"host": host, "username": username, "password": password})
    return devices


# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────

def clean(val) -> str:
    """Normalise any value for safe table display."""
    s = str(val) if val is not None else "N/A"
    if s in ("None", "-1", ""):
        return "N/A"
    if s.startswith("ERROR") or s in ("Not available", "AUTH ERROR", "See diagnostic"):
        return "N/A"
    return s


def truncate_error(err, max_len: int = 30) -> str:
    """Map verbose exception messages to short, readable labels."""
    if not err:
        return ""
    s = str(err)
    for pat, label in [
        # VAPIX / HTTP specific
        (r"HTTP 401",                         "Auth failed"),
        (r"HTTP 403",                         "Forbidden"),
        (r"HTTP 404",                         "API not found"),
        (r"HTTP [45]\d\d",                    "HTTP error"),
        # Network
        (r"[Cc]onnection timed out",          "Timed out"),
        (r"[Cc]onnection refused",            "Conn refused"),
        (r"[Nn]o response .* timeout",        "No response"),
        (r"[Nn]o route to host",              "No route"),
        (r"[Nn]etwork is unreachable",        "Net unreachable"),
        (r"[Nn]ame or service not known",     "DNS failed"),
        (r"[Nn]etwork error",                 "Network error"),
        # Auth
        (r"[Aa]uthentication required",       "Auth required"),
        # Generic
        (r"[Nn]ot a .* device",               "Not supported"),
        (r"[Mm]alformed",                     "Bad response"),
    ]:
        if re.search(pat, s):
            return label
    s = re.sub(r'\d{1,3}(?:\.\d{1,3}){3}:\d+', '', s)
    s = re.sub(r'\[Errno\s*-?\d+\]\s*', '', s)
    s = re.sub(r'\s+', ' ', s).strip(': ')
    return (s[:max_len - 3] + "...") if len(s) > max_len else (s or "Error")


def status_icon(r: dict) -> str:
    s = r.get("status", "error")
    if s == "success":
        return f"{GREEN}\u2713 OK{RESET}{WHITE}"
    elif s == "auth_error":
        return f"{YELLOW}\u2717 AUTH ERR{RESET}{WHITE}"
    return f"{RED}\u2717 ERROR{RESET}{WHITE}"


def format_temp(result: dict) -> str:
    """Return a single clean temperature string for table display (Fahrenheit)."""
    temp_f = result.get("temperature_f", "N/A")
    name   = result.get("sensor_name", "")
    if temp_f and temp_f != "N/A":
        label = f" ({name})" if name and name not in ("N/A", "") else ""
        return f"{temp_f}°F{label}"
    return "N/A"


# ─────────────────────────────────────────────────────────────────────────────
# VAPIX helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_firmware_and_model(host: str, auth: HTTPDigestAuth) -> dict:
    """
    Query /axis-cgi/basicdeviceinfo.cgi for firmware version and model info.
    VAPIX Basic Device Information API — method: getAllProperties
    Ref: https://developer.axis.com/vapix/network-video/basic-device-information/
    """
    url     = f"https://{host}/axis-cgi/basicdeviceinfo.cgi"
    payload = {"apiVersion": "1.0", "context": "axis-query", "method": "getAllProperties"}
    resp    = requests.post(url, json=payload, auth=auth, timeout=TIMEOUT, verify=VERIFY_SSL)
    resp.raise_for_status()
    props     = resp.json().get("data", {}).get("propertyList", {})
    raw_model = props.get("ProdFullName", props.get("ProdNbr", "N/A"))
    model     = _MODEL_STRIP.sub("", raw_model).strip()
    model     = re.sub(r"\s{2,}", " ", model)
    return {
        "firmware_version": props.get("Version", "N/A"),
        "model":            model or raw_model,
        "serial_number":    props.get("SerialNumber", "N/A"),
        "build_date":       props.get("BuildDate", "N/A"),
    }


def get_mac_address(host: str, auth: HTTPDigestAuth) -> str:
    """
    Query /axis-cgi/param.cgi for the MAC address of the primary interface.
    VAPIX Network Settings — Network.eth0.MACAddress parameter.
    Ref: https://developer.axis.com/vapix/network-video/network-settings/
    """
    url    = f"https://{host}/axis-cgi/param.cgi"
    params = {"action": "list", "group": "Network.eth0.MACAddress"}
    resp   = requests.get(url, params=params, auth=auth, timeout=TIMEOUT, verify=VERIFY_SSL)
    resp.raise_for_status()
    for line in resp.text.strip().splitlines():
        if "=" in line:
            _, _, value = line.partition("=")
            mac = value.strip()
            if mac:
                return mac
    return "N/A"


def get_temperature(host: str, auth: HTTPDigestAuth) -> dict:
    """
    Query /axis-cgi/temperaturecontrol.cgi?action=statusall
    VAPIX Temperature Control API — statusall action.
    Ref: https://developer.axis.com/vapix/network-video/temperature-control/

    Response format (plain text, newline-separated key=value):
        Sensor.S0.Name=Main
        Sensor.S0.Celsius=43.50
        Sensor.S0.Fahrenheit=110.30
        Sensor.S1.Name=CPU
        ...
    """
    url    = f"https://{host}/axis-cgi/temperaturecontrol.cgi"
    params = {"action": "statusall"}
    resp   = requests.get(url, params=params, auth=auth, timeout=TIMEOUT, verify=VERIFY_SSL)
    resp.raise_for_status()

    sensors: dict[str, dict] = {}
    for line in resp.text.strip().splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        m = re.match(r"^Sensor\.(S\d+)\.(\w+)$", key.strip(), re.IGNORECASE)
        if m:
            sid   = m.group(1).upper()
            field = m.group(2).lower()
            sensors.setdefault(sid, {})[field] = value.strip()

    if not sensors:
        return {"temperature_c": "N/A", "temperature_f": "N/A", "sensor_name": "N/A", "all_sensors": []}

    all_sensors = [
        {
            "sensor_id":     sid,
            "sensor_name":   s.get("name", sid),
            "temperature_c": s.get("celsius",    "N/A"),
            "temperature_f": s.get("fahrenheit", "N/A"),
        }
        for sid in sorted(sensors.keys())
        for s in [sensors[sid]]
    ]

    best = None
    for preferred in PREFERRED_SENSORS:
        for s in all_sensors:
            if preferred in s["sensor_name"].lower():
                best = s
                break
        if best:
            break
    if best is None:
        best = all_sensors[0]

    return {
        "temperature_c": best["temperature_c"],
        "temperature_f": best["temperature_f"],
        "sensor_name":   best["sensor_name"],
        "all_sensors":   all_sensors,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Per-camera worker
# ─────────────────────────────────────────────────────────────────────────────

def query_camera(row: dict) -> dict:
    """Connect to one camera, query firmware + temperature, return result dict."""
    host     = row["host"].strip()
    username = row.get("username", "root").strip()
    password = row.get("password", "").strip()

    with _active_lock:
        _latest_host["value"] = host

    result = {
        "host":             host,
        "query_timestamp":  datetime.now(timezone.utc).isoformat(),
        "status":           "error",
        "firmware_version": "N/A",
        "model":            "N/A",
        "serial_number":    "N/A",
        "mac_address":      "N/A",
        "build_date":       "N/A",
        "temperature_c":    "N/A",
        "temperature_f":    "N/A",
        "sensor_name":      "N/A",
        "all_sensors":      [],
        "error":            None,
    }

    auth = HTTPDigestAuth(username, password)

    try:
        fw = get_firmware_and_model(host, auth)
        result.update(fw)

        try:
            result["mac_address"] = get_mac_address(host, auth)
        except Exception as me:
            result["mac_error"] = truncate_error(str(me))

        try:
            temp = get_temperature(host, auth)
            result.update(temp)
        except Exception as te:
            result["temp_error"] = truncate_error(str(te))

        result["status"] = "success"

    except requests.exceptions.HTTPError as he:
        code = he.response.status_code
        result["status"] = "auth_error" if code in (401, 403) else "error"
        result["error"]  = truncate_error(f"HTTP {code}")
    except requests.exceptions.ConnectTimeout:
        result["error"] = "Timed out"
    except requests.exceptions.ConnectionError:
        result["error"] = "Unreachable"
    except Exception as ex:
        result["error"] = truncate_error(str(ex))

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────────────────────────────────────

def print_header(total: int, firmware_filter: str | None) -> None:
    print(f"{WHITE}")
    print(f"  {BOLD}AXIS VAPIX Camera Query{RESET}{WHITE}")
    print(f"  Queries firmware version and temperature via VAPIX API")
    print(f"  Input:   {CSV_FILE}")
    print(f"  Output:  {OUTPUT_FILE}")
    print(f"  Workers: {MAX_WORKERS}")
    print(f"  Timeout: {TIMEOUT}s")
    print(f"  Devices: {total}")
    if firmware_filter:
        print(f"  Filter:  Hiding firmware version {firmware_filter} from table")
    print(f"{RESET}")


def print_table(results: list, firmware_filter: str | None = None) -> None:
    visible = [
        r for r in results
        if firmware_filter is None or r.get("firmware_version") != firmware_filter
    ]
    filtered_count = len(results) - len(visible)
    headers = ["Status", "Host", "Model", "Firmware", "MAC", "Serial", "Temperature", "Error"]
    rows = []
    for r in visible:
        rows.append([
            status_icon(r),
            clean(r.get("host")),
            clean(r.get("model")),
            clean(r.get("firmware_version")),
            clean(r.get("mac_address")),
            clean(r.get("serial_number")),
            clean(format_temp(r)),
            truncate_error(r.get("error") or r.get("temp_error", "")),
        ])

    if not rows:
        rows = [["No results to display"] + [""] * (len(headers) - 1)]
    table = tabulate(rows, headers=headers, tablefmt="pretty",
                     stralign="left", numalign="right")

    # Scale banner to actual table width (strip ANSI before measuring)
    first_line = table.split("\n")[0]
    raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw         = max(raw_width, 60)
    title      = "AXIS Camera Query Results — Firmware & Temperature"
    pad        = (bw - len(title)) // 2

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")
    for line in table.split("\n"):
        print(f"  {line}")
    if filtered_count:
        print(f"  {YELLOW}  {filtered_count} device(s) with firmware {firmware_filter} hidden by --firmware filter{RESET}{WHITE}")
    print(f"{RESET}")


def print_summary(results: list, elapsed: float, temp_vals_f: list, filtered_count: int = 0) -> None:
    total = len(results)
    ok    = sum(1 for r in results if r["status"] == "success")
    auth  = sum(1 for r in results if r["status"] == "auth_error")
    err   = total - ok - auth

    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}\u2717{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
        + (f"  |  {YELLOW}{BOLD}Filtered:{RESET}{WHITE} {filtered_count}{RESET}" if filtered_count else "")
    )

    if temp_vals_f:
        avg = sum(temp_vals_f) / len(temp_vals_f)
        print(
            f"  {BOLD}Temperature (°F){RESET}{WHITE} \u2014 "
            f"Avg: {avg:.1f}  |  Min: {min(temp_vals_f):.1f}  |  "
            f"Max: {max(temp_vals_f):.1f}  |  Reported: {len(temp_vals_f)}/{total}"
        )
    else:
        print(f"  {BOLD}Temperature (°F){RESET}{WHITE} \u2014 No data available")

    print()
    print(f"  {BOLD}Results saved:{RESET}{WHITE} {OUTPUT_FILE}{RESET}")
    print(f"  {BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({MAX_WORKERS} workers){RESET}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# JSON output
# ─────────────────────────────────────────────────────────────────────────────

def save_json(results: list, elapsed: float) -> None:
    total = len(results)
    ok    = sum(1 for r in results if r["status"] == "success")
    auth  = sum(1 for r in results if r["status"] == "auth_error")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump({
            "query_info": {
                "csv_file":        str(Path(CSV_FILE).resolve()),
                "timestamp":       datetime.now(timezone.utc).isoformat(),
                "protocol":        "VAPIX 3 (HTTPS/Digest)",
                "mode":            "firmware+temperature",
                "workers":         MAX_WORKERS,
                "total":           total,
                "success":         ok,
                "auth_errors":     auth,
                "errors":          total - ok - auth,
                "elapsed_seconds": round(elapsed, 2),
            },
            "cameras": results,
        }, fh, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="AXIS VAPIX Camera Query Tool")
    parser.add_argument(
        "--firmware",
        metavar="VERSION",
        help="Hide cameras matching this firmware version from the table (e.g. 11.11.68). Full results are still saved to JSON.",
    )
    args = parser.parse_args()
    firmware_filter = args.firmware.strip() if args.firmware else None

    FILES_DIR.mkdir(exist_ok=True)
    cameras = load_csv(CSV_FILE)
    total   = len(cameras)

    print_header(total, firmware_filter)

    term_width = shutil.get_terminal_size((120, 24)).columns
    bar_fmt = (
        f"  {WHITE}Scanning{RESET} "
        f"{CYAN}{{bar}}{RESET}"
        f" {WHITE}{{n_fmt}}/{{total_fmt}}{RESET}"
        f" {WHITE}[{{elapsed}}<{{remaining}}]{RESET}"
        f"  {WHITE}{{postfix}}{RESET}"
    )

    results   = []
    host_order = {cam["host"].strip(): i for i, cam in enumerate(cameras)}
    t_start   = time()

    with tqdm(
        total=total,
        bar_format=bar_fmt,
        ncols=term_width,
        dynamic_ncols=True,
        file=sys.stderr,
        leave=True,
    ) as pbar:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {pool.submit(query_camera, cam): cam for cam in cameras}
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                with _active_lock:
                    host_display = _latest_host["value"]
                pbar.set_postfix_str(host_display, refresh=False)
                pbar.update(1)

        elapsed = time() - t_start
        pbar.set_postfix_str(
            f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s",
            refresh=True,
        )

    # Restore original CSV order
    results.sort(key=lambda r: host_order.get(r["host"], 9999))

    # Collect numeric temperature values for summary stats
    temp_vals_f = []
    for r in results:
        try:
            temp_vals_f.append(float(r["temperature_f"]))
        except (ValueError, TypeError):
            pass

    print_table(results, firmware_filter)
    filtered_count = sum(1 for r in results if firmware_filter and r.get("firmware_version") == firmware_filter)
    print_summary(results, elapsed, temp_vals_f, filtered_count)
    save_json(results, elapsed)


if __name__ == "__main__":
    main()
