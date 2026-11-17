#!/usr/bin/env python3
"""
AXIS Camera VAPIX Query Tool
Queries AXIS cameras for firmware version and temperature via the official
VAPIX API (basicdeviceinfo.cgi, param.cgi, temperaturecontrol.cgi).

Protocol: VAPIX API over HTTPS, HTTP Digest auth, self-signed certs tolerated.
CSV format: host,port,username,password  (port optional, defaults to 443)
Run with --help for the flags (--host, --raw, --debug, --firmware, ...).
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
from urllib.parse import urlencode

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import standard_cli as cli  # noqa: E402  (standard flags, --debug/--raw helpers)

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
# Relative to the script's own folder so the paths hold regardless of CWD
# (-i / -o override them).
SCRIPT_DIR  = Path(__file__).resolve().parent
SECRETS_DIR = SCRIPT_DIR / "secrets"
DEFAULT_CSV = "secrets/axis_firmware.csv"
OUTPUT_DIR  = "axis_firmware/files"           # results_<YYYYMMDD>_<HHMMSS>.json

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_PORT     = 443
DEFAULT_USERNAME = "root"   # used when the CSV has no username / for --host not in the CSV
DEFAULT_PASSWORD = ""
MANUFACTURER     = "AXIS"
DEFAULT_WORKERS  = 5        # Concurrent camera queries (-w)
DEFAULT_TIMEOUT  = 10       # Seconds per request (-t)
VERIFY_SSL       = False    # Set True if your cameras have valid certs
PROTOCOL         = "VAPIX 3 (HTTPS/Digest)"
MODE             = "firmware+temperature"

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
            username = (row.get(col_map.get("username", ""), "") or "").strip() or DEFAULT_USERNAME
            password = (row.get(col_map.get("password", ""), "") or "").strip() or DEFAULT_PASSWORD
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

def vapix_url(host: str, port, path: str) -> str:
    """https://HOST/path on the default port 443, else https://HOST:PORT/path."""
    port = int(port or DEFAULT_PORT)
    return f"https://{host}{path}" if port == DEFAULT_PORT else f"https://{host}:{port}{path}"


def _trace_request(host: str, method: str, url: str, timeout, params=None, payload=None) -> None:
    """--debug: one request about to be sent (credentials are never traced)."""
    shown = f"{url}?{urlencode(params)}" if params else url
    cli.debug.log(host, f"{method} {shown} (Digest auth, timeout {timeout}s, verify={VERIFY_SSL})")
    if payload is not None:
        cli.debug.sent(host, payload)


def _trace_response(host: str, resp) -> None:
    """--debug: the reply's status line and body."""
    if cli.debug.enabled:
        cli.debug.log(host, f"HTTP {resp.status_code} {getattr(resp, 'reason', '') or ''}")
        cli.debug.received(host, resp.text)


def get_firmware_and_model(host: str, auth: HTTPDigestAuth, port=DEFAULT_PORT,
                           timeout=DEFAULT_TIMEOUT) -> dict:
    """
    Query /axis-cgi/basicdeviceinfo.cgi for firmware version and model info.
    VAPIX Basic Device Information API — method: getAllProperties
    Ref: https://developer.axis.com/vapix/network-video/basic-device-information/
    """
    url     = vapix_url(host, port, "/axis-cgi/basicdeviceinfo.cgi")
    payload = {"apiVersion": "1.0", "context": "axis-query", "method": "getAllProperties"}
    _trace_request(host, "POST", url, timeout, payload=payload)
    resp    = requests.post(url, json=payload, auth=auth, timeout=timeout, verify=VERIFY_SSL)
    _trace_response(host, resp)
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


def get_mac_address(host: str, auth: HTTPDigestAuth, port=DEFAULT_PORT,
                    timeout=DEFAULT_TIMEOUT):
    """
    Query /axis-cgi/param.cgi for the MAC address of the primary interface.
    VAPIX Network Settings — Network.eth0.MACAddress parameter.
    Ref: https://developer.axis.com/vapix/network-video/network-settings/
    """
    url    = vapix_url(host, port, "/axis-cgi/param.cgi")
    params = {"action": "list", "group": "Network.eth0.MACAddress"}
    _trace_request(host, "GET", url, timeout, params=params)
    resp   = requests.get(url, params=params, auth=auth, timeout=timeout, verify=VERIFY_SSL)
    _trace_response(host, resp)
    resp.raise_for_status()
    for line in resp.text.strip().splitlines():
        if "=" in line:
            _, _, value = line.partition("=")
            mac = value.strip()
            if mac:
                return mac
    return None


def get_temperature(host: str, auth: HTTPDigestAuth, port=DEFAULT_PORT,
                    timeout=DEFAULT_TIMEOUT) -> dict:
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
    url    = vapix_url(host, port, "/axis-cgi/temperaturecontrol.cgi")
    params = {"action": "statusall"}
    _trace_request(host, "GET", url, timeout, params=params)
    resp   = requests.get(url, params=params, auth=auth, timeout=timeout, verify=VERIFY_SSL)
    _trace_response(host, resp)
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

def query_camera(row: dict, timeout=DEFAULT_TIMEOUT) -> dict:
    """Connect to one camera, query firmware + temperature, return result dict."""
    # Host passed through verbatim — no trim, no lowercase (spec 2.6).
    host     = row["host"]
    port     = row.get("port", DEFAULT_PORT)
    username = row.get("username", DEFAULT_USERNAME)
    password = row.get("password", DEFAULT_PASSWORD)

    with _active_lock:
        _latest_host["value"] = host

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
        "temperature_c":    None,
        "temperature_f":    None,
        "sensor_name":      None,
        "all_sensors":      [],
    }

    auth = HTTPDigestAuth(username, password)

    try:
        fw = get_firmware_and_model(host, auth, port, timeout)
        result.update(fw)

        try:
            result["mac"] = get_mac_address(host, auth, port, timeout)
        except Exception as me:
            cli.debug.log(host, f"MAC query failed: {type(me).__name__}: {me}")
            result["mac_error"] = truncate_error(str(me))

        try:
            temp = get_temperature(host, auth, port, timeout)
            result.update(temp)
        except Exception as te:
            cli.debug.log(host, f"temperature query failed: {type(te).__name__}: {te}")
            result["temp_error"] = truncate_error(str(te))

        result["status"] = "success"

    except requests.exceptions.HTTPError as he:
        cli.debug.log(host, f"basicdeviceinfo failed: {he}")
        code = he.response.status_code
        result["status"] = "auth_error" if code in (401, 403) else "error"
        result["error"]  = truncate_error(f"HTTP {code}")
    except requests.exceptions.ConnectTimeout as ex:
        cli.debug.log(host, f"connect timeout: {ex}")
        result["error"] = "Timed out"
    except requests.exceptions.ConnectionError as ex:
        cli.debug.log(host, f"connection error: {ex}")
        result["error"] = "Unreachable"
    except Exception as ex:
        cli.debug.log(host, f"query failed: {type(ex).__name__}: {ex}")
        result["error"] = truncate_error(str(ex))

    cli.debug.log(host, f"result: {result['status']}" + (f" ({result['error']})" if result["error"] else ""))
    return result


def dump_raw(dev: dict, timeout) -> None:
    """--raw: send the three VAPIX requests the query sends and print each reply as received."""
    host, port = dev["host"], dev.get("port", DEFAULT_PORT)
    auth = HTTPDigestAuth(dev.get("username", DEFAULT_USERNAME), dev.get("password", DEFAULT_PASSWORD))
    calls = [
        ("POST", "/axis-cgi/basicdeviceinfo.cgi",
         {"json": {"apiVersion": "1.0", "context": "axis-query", "method": "getAllProperties"}}),
        ("GET", "/axis-cgi/param.cgi",
         {"params": {"action": "list", "group": "Network.eth0.MACAddress"}}),
        ("GET", "/axis-cgi/temperaturecontrol.cgi",
         {"params": {"action": "statusall"}}),
    ]
    for method, path, kw in calls:
        url = vapix_url(host, port, path)
        what = kw.get("json", {}).get("method") or "&".join(f"{k}={v}" for k, v in kw["params"].items())
        label = f"{method} {path} ({what})"
        send = requests.post if method == "POST" else requests.get
        _trace_request(host, method, url, timeout, params=kw.get("params"), payload=kw.get("json"))
        try:
            resp = send(url, auth=auth, timeout=timeout, verify=VERIFY_SSL, **kw)
        except Exception as e:
            cli.raw_error(label, f"{type(e).__name__}: {e}")
            if isinstance(e, requests.exceptions.ConnectionError):
                # No connection at all (the query stops here too): skip the rest
                cli.raw_error("remaining requests", "skipped (could not connect)")
                return
            continue
        _trace_response(host, resp)
        cli.raw_item(f"{label}  HTTP {resp.status_code}", resp.text)


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


def print_header(total: int, args) -> None:
    print(f"{WHITE}")
    print(f"  {BOLD}AXIS Camera VAPIX Query Tool{RESET}{WHITE}")
    print(f"  Queries AXIS cameras for firmware version and temperature")
    print(f"  Input:   {cli.input_label(args)}")
    print(f"  Output:  {'(none: --raw)' if args.raw else args.output}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    print(f"  Devices: {total}")
    if args.firmware:
        print(f"  Filter:  Hiding firmware version {cli.firmware_label(args.firmware)} from table")
    if args.debug:
        print(f"  Debug:   on (trace on stderr)")
    print(f"{RESET}")


def print_table(results: list, firmware_filter=None) -> None:
    visible = cli.firmware_mismatches(results, firmware_filter)
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
              f"{cli.firmware_label(firmware_filter)} hidden by --firmware filter{RESET}{WHITE}")
    print(f"{RESET}")


def print_summary(results: list, elapsed: float, temp_vals_f: list,
                  filtered_count: int = 0, output_file: str = "",
                  workers: int = DEFAULT_WORKERS) -> None:
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
    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {output_file}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers){RESET}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# JSON output (spec 2.1)
# ─────────────────────────────────────────────────────────────────────────────

def save_json(results: list, elapsed: float, args) -> None:
    total = len(results)
    ok    = sum(1 for r in results if r["status"] == "success")
    auth  = sum(1 for r in results if r["status"] == "auth_error")
    cli.ensure_parent(args.output)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump({
            "query_info": {
                "csv_file":        cli.input_label(args),
                "timestamp":       datetime.now(timezone.utc).isoformat(),
                "protocol":        PROTOCOL,
                "mode":            MODE,
                "workers":         args.workers,
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
    parser = cli.build_parser(
        script_file=__file__,
        description="AXIS Camera VAPIX Query Tool\n"
                    "Queries AXIS cameras for firmware, model, serial, MAC and temperature\n"
                    "over HTTPS (VAPIX, HTTP Digest auth, self-signed certs tolerated).",
        default_csv=DEFAULT_CSV,
        output_dir=OUTPUT_DIR,
        default_port=DEFAULT_PORT,
        default_timeout=DEFAULT_TIMEOUT,
        default_workers=DEFAULT_WORKERS,
        auth=cli.AUTH_USER_PASSWORD,
        port_help=(f"HTTPS port for --host targets (default: the CSV row's, else "
                   f"{DEFAULT_PORT})"),
        firmware_help=("Hide cameras on any of these firmware versions from the table "
                       "(e.g. 11.11.68 12.0.1). Full results are still saved to JSON."),
        raw_help=("Print each camera's raw replies to the three VAPIX requests "
                  "(basicdeviceinfo, param.cgi MAC, temperaturecontrol), then exit "
                  "without the table or JSON. Works with --host or the whole CSV."),
        epilog=f"""
Examples:
  python3 axis_script.py                                   # whole CSV
  python3 axis_script.py --host cam-101.example.edu        # one camera (CSV row's login if listed)
  python3 axis_script.py --host 10.0.0.5 -u root --password s3cret
  python3 axis_script.py --host cam-101.example.edu --raw
  python3 axis_script.py --host cam-101.example.edu --debug
  python3 axis_script.py --firmware 11.11.68 12.0.1        # cameras NOT on either version
  python3 axis_script.py -i cams.csv -t 15 -w 10 -o out.json

CSV columns: host,port,username,password  (port optional, default {DEFAULT_PORT};
  username default {DEFAULT_USERNAME}). A --host that is not in the CSV uses
  {DEFAULT_USERNAME} with an empty password unless -u / --password are given.
        """,
    )
    args = cli.parse_args(parser)

    SECRETS_DIR.mkdir(parents=True, exist_ok=True)

    cameras = cli.select_devices(
        args, load_csv,
        lambda host: {"host": host, "port": DEFAULT_PORT,
                      "username": DEFAULT_USERNAME, "password": DEFAULT_PASSWORD})
    total   = len(cameras)

    print_header(total, args)

    # --raw: dump what each camera sends back, no table / JSON
    if args.raw:
        cli.run_raw(cameras, lambda d: dump_raw(d, args.timeout))
        return

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
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(query_camera, cam, args.timeout): cam for cam in cameras}
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

    filtered_count = len(results) - len(cli.firmware_mismatches(results, args.firmware))

    print_table(results, args.firmware)
    print_summary(results, elapsed, temp_vals_f, filtered_count, args.output, args.workers)
    save_json(results, elapsed, args)


if __name__ == "__main__":
    main()
