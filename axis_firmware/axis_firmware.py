#!/usr/bin/env python3
"""
AXIS Camera VAPIX Query Tool
Queries AXIS M4328-P and M3068-P cameras for firmware version and temperature
via the official VAPIX API (basicdeviceinfo.cgi and temperaturecontrol.cgi).

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
from datetime import datetime

import requests
import urllib3
from requests.auth import HTTPDigestAuth
from tabulate import tabulate
from tqdm import tqdm

# ── Suppress SSL warnings for cameras using self-signed certs ─────────────────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── ANSI colour helpers ───────────────────────────────────────────────────────
W  = "\033[97m"   # bright white  — all text
C  = "\033[96m"   # cyan          — progress bar only
R  = "\033[0m"    # reset

# Noise words stripped from ProdFullName before display
_MODEL_STRIP = re.compile(
    r"\b(AXIS|Network Camera|Panoramic Camera|Fixed Dome|Mini Dome|"
    r"Fisheye|Box Camera|Bullet|Camera)\b",
    re.IGNORECASE,
)

# ── Config ────────────────────────────────────────────────────────────────────
CSV_FILE     = "cameras.csv"
OUTPUT_FILE  = "results.json"
MAX_WORKERS  = 5
TIMEOUT      = 10       # seconds per request
VERIFY_SSL   = False    # set True if your cameras have valid certs

# Sensors to prefer (in priority order) when picking a single "best" reading
# for the table. The M4328-P / M3068-P typically expose sensors named
# "Main", "CPU", "Image Sensor", "Optics" — "Main" is the overall board temp.
PREFERRED_SENSORS = ["main", "soc", "cpu", "board", "case"]


# ─────────────────────────────────────────────────────────────────────────────
# VAPIX helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_firmware_and_model(host: str, auth: HTTPDigestAuth) -> dict:
    """
    Query /axis-cgi/basicdeviceinfo.cgi for firmware version and model info.
    VAPIX Basic Device Information API — method: getAllProperties
    Ref: https://developer.axis.com/vapix/network-video/basic-device-information/
    """
    url = f"https://{host}/axis-cgi/basicdeviceinfo.cgi"
    payload = {
        "apiVersion": "1.0",
        "context":    "axis-query",
        "method":     "getAllProperties",
    }
    resp = requests.post(url, json=payload, auth=auth,
                         timeout=TIMEOUT, verify=VERIFY_SSL)
    resp.raise_for_status()
    props = resp.json().get("data", {}).get("propertyList", {})
    raw_model = props.get("ProdFullName", props.get("ProdNbr", "N/A"))
    model     = _MODEL_STRIP.sub("", raw_model).strip()
    model     = re.sub(r"\s{2,}", " ", model)   # collapse double spaces
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

    resp = requests.get(url, params=params, auth=auth,
                        timeout=TIMEOUT, verify=VERIFY_SSL)
    resp.raise_for_status()

    # Response is plain text: "root.Network.eth0.MACAddress=AC:CC:8E:XX:XX:XX"
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
    VAPIX Temperature Control API — statusall action (no device= param).
    Ref: https://developer.axis.com/vapix/network-video/temperature-control/

    Official response format (plain text, newline-separated key=value):
        Sensor.S0.Name=Main
        Sensor.S0.Celsius=43.50
        Sensor.S0.Fahrenheit=110.30
        Sensor.S1.Name=CPU
        Sensor.S1.Celsius=50.44
        Sensor.S1.Fahrenheit=122.79
        ...
    """
    url    = f"https://{host}/axis-cgi/temperaturecontrol.cgi"
    params = {"action": "statusall"}   # correct per official docs — no device= param

    resp = requests.get(url, params=params, auth=auth,
                        timeout=TIMEOUT, verify=VERIFY_SSL)
    resp.raise_for_status()

    # ── Parse "Sensor.S0.Celsius=43.50" style response ────────────────────
    sensors: dict[str, dict] = {}
    for line in resp.text.strip().splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        m = re.match(r"^Sensor\.(S\d+)\.(\w+)$", key.strip(), re.IGNORECASE)
        if m:
            sid   = m.group(1).upper()   # e.g. "S0"
            field = m.group(2).lower()   # "celsius" | "fahrenheit" | "name"
            sensors.setdefault(sid, {})[field] = value.strip()

    if not sensors:
        return {
            "temperature_c": "N/A",
            "temperature_f": "N/A",
            "sensor_name":   "N/A",
            "all_sensors":   [],
        }

    # ── Collect all sensors for JSON output ───────────────────────────────
    all_sensors = []
    for sid in sorted(sensors.keys()):
        s = sensors[sid]
        all_sensors.append({
            "sensor_id":     sid,
            "sensor_name":   s.get("name", sid),
            "temperature_c": s.get("celsius",    "N/A"),
            "temperature_f": s.get("fahrenheit", "N/A"),
        })

    # ── Pick the single best sensor for the table display ─────────────────
    best = None
    for preferred in PREFERRED_SENSORS:
        for s in all_sensors:
            if preferred in s["sensor_name"].lower():
                best = s
                break
        if best:
            break
    if best is None:
        best = all_sensors[0]   # fall back to S0

    return {
        "temperature_c": best["temperature_c"],
        "temperature_f": best["temperature_f"],
        "sensor_name":   best["sensor_name"],
        "all_sensors":   all_sensors,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Per-camera worker
# ─────────────────────────────────────────────────────────────────────────────

def query_camera(row: dict, progress: tqdm) -> dict:
    """Connect to one camera, query firmware + temperature, return result dict."""
    host     = row["host"].strip()
    username = row.get("username", "root").strip()
    password = row.get("password", "").strip()

    progress.set_description(f"  Querying {host:<30}")

    result = {
        "host":             host,
        "timestamp":        datetime.utcnow().isoformat() + "Z",
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
        except Exception:
            pass  # MAC failure is non-fatal; leave as N/A

        try:
            temp = get_temperature(host, auth)
            result.update(temp)
        except Exception as te:
            result["temp_error"] = str(te)

        result["status"] = "ok"

    except requests.exceptions.ConnectTimeout:
        result["error"] = "Timed out"
    except requests.exceptions.ConnectionError:
        result["error"] = "Unreachable"
    except requests.exceptions.HTTPError as he:
        result["error"] = f"HTTP {he.response.status_code}"
    except Exception as ex:
        result["error"] = str(ex)[:60]
    finally:
        progress.update(1)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────

def format_temp(result: dict) -> str:
    """Return a single clean temperature string for table display (Fahrenheit)."""
    temp_f = result.get("temperature_f", "N/A")
    name   = result.get("sensor_name", "")
    if temp_f and temp_f != "N/A":
        label = f" ({name})" if name and name not in ("N/A", "") else ""
        return f"{temp_f}°F{label}"
    return "N/A"


def print_table(results: list) -> None:
    """Print a centred titled table using tabulate — all text white."""
    term_width = shutil.get_terminal_size((120, 40)).columns

    # ── Centred title — white ─────────────────────────────────────────────
    title  = "Axis Camera Firmware"
    border = "─" * len(title)
    def centre(s: str) -> str:
        return " " * max(0, (term_width - len(s)) // 2) + s

    print(f"{W}{centre(border)}")
    print(centre(title))
    print(f"{centre(border)}{R}")

    # ── Table rows ────────────────────────────────────────────────────────
    headers = ["Host", "Status", "Model", "Firmware", "Mac", "Serial", "Temperature", "Error"]
    rows = []
    for r in results:
        rows.append([
            r["host"],
            r["status"].upper(),
            r.get("model", "N/A"),
            r.get("firmware_version", "N/A"),
            r.get("mac_address", "N/A"),
            r.get("serial_number", "N/A"),
            format_temp(r),
            r.get("error") or r.get("temp_error", "") or "",
        ])

    table = tabulate(rows, headers=headers, tablefmt="rounded_outline",
                     maxcolwidths=[None, 7, 22, 14, 17, 18, 18, 28])

    # Wrap entire table in white
    table_width = len(table.splitlines()[0]) if table else 0
    pad = " " * max(0, (term_width - table_width) // 2)
    wrapped = "\n".join(pad + line for line in table.splitlines()) \
              if table_width < term_width else table
    print(f"{W}{wrapped}{R}")


def save_json(results: list) -> None:
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump({
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "cameras": results,
        }, fh, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def load_csv(path: str) -> list[dict]:
    if not os.path.isfile(path):
        sys.exit(f"[ERROR] CSV file not found: {path}")
    with open(path, newline="", encoding="utf-8") as fh:
        rows = [{k.lower().strip(): v for k, v in row.items()}
                for row in csv.DictReader(fh)]
    if not rows:
        sys.exit("[ERROR] cameras.csv is empty.")
    if "host" not in rows[0]:
        sys.exit("[ERROR] cameras.csv must contain a 'host' column.")
    return rows


def main() -> None:
    cameras = load_csv(CSV_FILE)
    total   = len(cameras)

    print(f"{W}\n  AXIS VAPIX Camera Query  —  {total} device(s) found in {CSV_FILE}\n{R}")

    bar_format = (
        f"{W}  {{desc}}  {R}"
        f"{C}{{bar}}{R}"
        f"{W}  {{n_fmt}}/{{total_fmt}}  [{{elapsed}}<{{remaining}}]{R}"
    )

    results = []
    with tqdm(
        total=total,
        bar_format=bar_format,
        ncols=shutil.get_terminal_size((120, 40)).columns - 2,
        dynamic_ncols=True,
        leave=True,
    ) as progress:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {
                pool.submit(query_camera, cam, progress): cam
                for cam in cameras
            }
            for future in as_completed(futures):
                results.append(future.result())

    # Restore original CSV order
    host_order = {cam["host"].strip(): i for i, cam in enumerate(cameras)}
    results.sort(key=lambda r: host_order.get(r["host"], 9999))

    print()
    print_table(results)
    print()

    save_json(results)

    ok  = sum(1 for r in results if r["status"] == "ok")
    err = total - ok
    print(f"{W}  Done.  {ok} succeeded / {err} failed  →  {OUTPUT_FILE}\n{R}")


if __name__ == "__main__":
    main()
