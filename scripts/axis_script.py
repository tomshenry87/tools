#!/usr/bin/env python3
"""
AXIS Camera VAPIX Query Tool
Queries AXIS cameras for firmware version and temperature via the official
VAPIX API (basicdeviceinfo.cgi, param.cgi, temperaturecontrol.cgi).

Protocol: VAPIX API over HTTPS, HTTP Digest auth, self-signed certs tolerated.
CSV format: host,port,username,password  (port optional, defaults to 443)
"""

import argparse
import csv
import json
import re
import sys
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from time import time

import requests
import urllib3
from requests.auth import HTTPDigestAuth
from tabulate import tabulate
from tqdm import tqdm

# ── Suppress SSL warnings for cameras using self-signed certs ─────────────────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── ANSI palette (spec 3.1) ───────────────────────────────────────────────────
CYAN   = "\033[96m"   # Progress bar fill — reserved, nothing else
GREEN  = "\033[92m"   # Success states
RED    = "\033[91m"   # Failure / error states
YELLOW = "\033[93m"   # Auth-error states
WHITE  = "\033[97m"   # All body text, table content, labels
BOLD   = "\033[1m"    # Section headers, label emphasis
RESET  = "\033[0m"    # Always close every colour block

# ── Paths (spec 2.7, 3.7) ─────────────────────────────────────────────────────
# Anchored to the script's own location so the paths hold regardless of CWD.
SCRIPT_DIR  = Path(__file__).resolve().parent
SECRETS_DIR = SCRIPT_DIR / "secrets"
FILES_DIR   = SCRIPT_DIR / "axis_firmware" / "files"

CSV_FILE    = str(SECRETS_DIR / "axis_firmware.csv")
_RUN_TS     = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
OUTPUT_FILE = str(FILES_DIR / f"results_{_RUN_TS}.json")

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_PORT = 443
MANUFACTURER = "AXIS"
MAX_WORKERS  = 5        # Concurrent camera queries
TIMEOUT      = 10       # Seconds per request
VERIFY_SSL   = False    # Set True if your cameras have valid certs
PROTOCOL     = "VAPIX 3 (HTTPS/Digest)"
MODE         = "firmware+temperature"

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
# Shared helpers — byte-identical across all scripts (spec 3.5)
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Error label mapping (spec 3.6)
# ─────────────────────────────────────────────────────────────────────────────

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
PROTOCOL_ERROR_PATTERNS = [
    # VAPIX HTTP Digest authentication rejection
    (r"HTTP 401",                            "Auth failed"),
    (r"401 Client Error",                    "Auth failed"),
    (r"HTTP 403",                            "Forbidden"),
    (r"403 Client Error",                    "Forbidden"),
    # VAPIX endpoint absent on older firmware
    (r"HTTP 404",                            "API not found"),
    (r"404 Client Error",                    "API not found"),
    # TLS handshake against self-signed certificates
    (r"CERTIFICATE_VERIFY_FAILED",           "Cert untrusted"),
    (r"[Ss]elf.signed certificate",          "Cert untrusted"),
    (r"[Hh]andshake",                        "TLS handshake"),
    (r"SSLError|[Ss]sl[Ee]rror",             "TLS error"),
    # VAPIX Error envelopes for parameters older firmware does not expose
    (r"[Uu]nsupported (?:API )?version",     "Unsup. API ver"),
    (r"[Pp]roperty not (?:found|available)", "Prop unavailable"),
    (r"VAPIX .*[Ee]rror",                    "VAPIX error"),
    # Generic HTTP fallbacks — after the specific codes above
    (r"HTTP 5\d\d|5\d\d Server Error",       "HTTP server err"),
    (r"HTTP 4\d\d|4\d\d Client Error",       "HTTP client err"),
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


# ─────────────────────────────────────────────────────────────────────────────
# CSV loader (spec 3.7)
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
            try:
                port = int(row.get(col_map.get("port", ""), DEFAULT_PORT) or DEFAULT_PORT)
            except (ValueError, TypeError):
                port = DEFAULT_PORT
            # This script's additional columns.
            username = (row.get(col_map.get("username", ""), "") or "").strip() or "root"
            password = (row.get(col_map.get("password", ""), "") or "").strip()
            devices.append({
                "host":     host,
                "port":     port,
                "username": username,
                "password": password,
            })
    if not devices:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No valid entries found in CSV.{RESET}")
        sys.exit(1)
    return devices


# ─────────────────────────────────────────────────────────────────────────────
# VAPIX helpers — PROTOCOL LOGIC, DO NOT CHANGE (spec 4)
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
    raw_model = props.get("ProdFullName", props.get("ProdNbr"))
    model     = None
    if raw_model:
        model = _MODEL_STRIP.sub("", raw_model).strip()
        model = re.sub(r"\s{2,}", " ", model) or raw_model
    return {
        "firmware_version": props.get("Version"),
        "model":            model,
        "serial":           props.get("SerialNumber"),
        "build_date":       props.get("BuildDate"),
    }


def get_mac_address(host: str, auth: HTTPDigestAuth):
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
    return None


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
        return {
            "temperature_c": None,
            "temperature_f": None,
            "sensor_name":   None,
            "all_sensors":   [],
        }

    all_sensors = [
        {
            "sensor_id":     sid,
            "sensor_name":   sensors[sid].get("name", sid),
            "temperature_c": sensors[sid].get("celsius"),
            "temperature_f": sensors[sid].get("fahrenheit"),
        }
        for sid in sorted(sensors.keys())
    ]

    best = None
    for preferred in PREFERRED_SENSORS:
        for s in all_sensors:
            if preferred in (s["sensor_name"] or "").lower():
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
# Per-camera worker — orchestration and error classification unchanged (spec 4)
# ─────────────────────────────────────────────────────────────────────────────

def query_camera(row: dict) -> dict:
    """Connect to one camera, query firmware + temperature, return result dict."""
    # Host passed through verbatim — no trim, no lowercase (spec 2.6).
    host     = row["host"]
    username = row.get("username", "root")
    password = row.get("password", "")

    with _active_lock:
        _latest_host["value"] = host

    result = {
        "host":             host,
        "port":             row.get("port", DEFAULT_PORT),
        "query_timestamp":  datetime.now(timezone.utc).isoformat(),
        "status":           "error",
        "error":            None,
        "manufacturer":     MANUFACTURER,
        "model":            None,
        "firmware_version": None,
        "serial":           None,
        "mac":              None,
        "build_date":       None,
        "temperature_c":    None,
        "temperature_f":    None,
        "sensor_name":      None,
        "all_sensors":      [],
    }

    auth = HTTPDigestAuth(username, password)

    try:
        fw = get_firmware_and_model(host, auth)
        result.update(fw)

        try:
            result["mac"] = get_mac_address(host, auth)
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
# Terminal presentation (spec 3)
# ─────────────────────────────────────────────────────────────────────────────

def format_temp(result: dict):
    """Single clean temperature string for table display — Fahrenheit (spec 2.4)."""
    temp_f = result.get("temperature_f")
    name   = result.get("sensor_name")
    if temp_f in (None, "", "N/A"):
        return None
    label = f" ({name})" if name and name != "N/A" else ""
    return f"{temp_f}°F{label}"


def print_header(total: int, firmware_filter) -> None:
    print(f"{WHITE}")
    print(f"  {BOLD}AXIS Camera VAPIX Query Tool{RESET}{WHITE}")
    print(f"  Queries AXIS cameras for firmware version and temperature")
    print(f"  Input:   {CSV_FILE}")
    print(f"  Output:  {OUTPUT_FILE}")
    print(f"  Workers: {MAX_WORKERS}")
    print(f"  Timeout: {TIMEOUT}s")
    print(f"  Devices: {total}")
    if firmware_filter:
        print(f"  Filter:  Hiding firmware version {firmware_filter} from table")
    print(f"{RESET}")


def print_table(results: list, firmware_filter=None) -> None:
    visible = [
        r for r in results
        if firmware_filter is None or r.get("firmware_version") != firmware_filter
    ]
    filtered_count = len(results) - len(visible)

    # Column order per spec 3.4 — no Port column.
    headers = ["Status", "Host", "Manufacturer", "Model", "Firmware",
               "MAC", "Serial", "Temperature", "Error"]
    rows = []
    for r in visible:
        rows.append([
            status_icon(r),
            clean(r.get("host")),
            clean(r.get("manufacturer")),
            clean(r.get("model")),
            clean(r.get("firmware_version")),
            clean(r.get("mac")),
            clean(r.get("serial")),
            clean(format_temp(r)),
            truncate_error(r.get("error") or r.get("temp_error") or ""),
        ])
    if not rows:
        rows = [["No results to display"] + [""] * (len(headers) - 1)]

    table = tabulate(rows, headers=headers, tablefmt="pretty",
                     stralign="left", numalign="right")

    # Banner scaled to real table width, measured after stripping ANSI.
    first_line = table.split("\n")[0]
    raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw         = max(raw_width, 60)
    title      = "AXIS Camera Query Results — Firmware & Temperature"
    pad        = max(0, (bw - len(title)) // 2)

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")
    for line in table.split("\n"):
        print(f"  {line}")
    if filtered_count:
        print(f"  {YELLOW}{filtered_count} device(s) with firmware "
              f"{firmware_filter} hidden by --firmware filter{RESET}{WHITE}")
    print(f"{RESET}")


def print_summary(results: list, elapsed: float, temp_vals_f: list,
                  filtered_count: int = 0) -> None:
    total = len(results)
    ok    = sum(1 for r in results if r["status"] == "success")
    auth  = sum(1 for r in results if r["status"] == "auth_error")
    err   = total - ok - auth

    print(f"{WHITE}")
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}✓{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}✗{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}✗{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
        + (f"  |  {YELLOW}{BOLD}Filtered:{RESET}{WHITE} {filtered_count}" if filtered_count else "")
    )

    if temp_vals_f:
        avg = sum(temp_vals_f) / len(temp_vals_f)
        print(
            f"  {BOLD}Board Temperature (°F){RESET}{WHITE} — "
            f"Avg: {avg:.1f}  |  Min: {min(temp_vals_f):.1f}  |  "
            f"Max: {max(temp_vals_f):.1f}  |  Reported: {len(temp_vals_f)}/{total}"
        )
    else:
        print(f"  {BOLD}Board Temperature (°F){RESET}{WHITE} — No data available")

    print()
    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {OUTPUT_FILE}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({MAX_WORKERS} workers){RESET}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# JSON output (spec 2.1)
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
                "protocol":        PROTOCOL,
                "mode":            MODE,
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
    parser = argparse.ArgumentParser(description="AXIS Camera VAPIX Query Tool")
    parser.add_argument(
        "--firmware",
        metavar="VERSION",
        help="Hide cameras matching this firmware version from the table "
             "(e.g. 11.11.68). Full results are still saved to JSON.",
    )
    args = parser.parse_args()
    firmware_filter = args.firmware.strip() if args.firmware else None

    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    FILES_DIR.mkdir(parents=True, exist_ok=True)

    cameras = load_csv(CSV_FILE)
    total   = len(cameras)

    print_header(total, firmware_filter)

    bar_fmt = (
        f"  {WHITE}Scanning{RESET} "
        f"{CYAN}{{bar}}{RESET}"
        f" {WHITE}{{n_fmt}}/{{total_fmt}}{RESET}"
        f" {WHITE}[{{elapsed}}<{{remaining}}]{RESET}"
        f"  {WHITE}{{postfix}}{RESET}"
    )

    results    = []
    host_order = {cam["host"]: i for i, cam in enumerate(cameras)}
    t_start    = time()

    with tqdm(
        total=total,
        bar_format=bar_fmt,
        ncols=get_terminal_width(),
        dynamic_ncols=True,
        file=sys.stderr,
        leave=True,
    ) as pbar:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {pool.submit(query_camera, cam): cam for cam in cameras}
            for future in as_completed(futures):
                results.append(future.result())
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

    # Fahrenheit values for the metrics line
    temp_vals_f = []
    for r in results:
        try:
            temp_vals_f.append(float(r["temperature_f"]))
        except (ValueError, TypeError):
            pass

    filtered_count = sum(
        1 for r in results
        if firmware_filter and r.get("firmware_version") == firmware_filter
    )

    print_table(results, firmware_filter)
    print_summary(results, elapsed, temp_vals_f, filtered_count)
    save_json(results, elapsed)


if __name__ == "__main__":
    main()
