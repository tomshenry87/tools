#!/usr/bin/env python3
"""
MikroTik Router Firmware Checker
==================================
Reads router credentials from secrets/mikrotik_firmware.csv (default),
connects via SSH, queries /system/package/print for RouterOS version,
/system/routerboard/print for board model and firmware, and
/system/health/print for PoE consumption and board temperature.

Writes results to mikrotik_version_check/files/results_<YYYYMMDD>_<HHMMSS>.json
and prints a summary table.

Usage (standard flags: see lib/standard_cli.py or --help):
    python3 mikrotik_script.py
    python3 mikrotik_script.py --host 10.0.0.1 --debug
    python3 mikrotik_script.py --host 10.0.0.1 --raw
    python3 mikrotik_script.py -i secrets/other.csv -o files/other.json
    python3 mikrotik_script.py -w 10 -t 20
    python3 mikrotik_script.py --include-raw --debug
    python3 mikrotik_script.py --firmware 7.14.2 7.15.1
"""

from __future__ import annotations

import csv
import json
import logging
import os
import re
import shutil
import socket
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import standard_cli as cli  # noqa: E402  (standard flags, --debug/--raw helpers)

try:
    import paramiko
except ImportError:
    sys.exit("ERROR: pip install paramiko")

try:
    from tabulate import tabulate
except ImportError:
    sys.exit("ERROR: pip install tabulate")

try:
    from tqdm import tqdm
except ImportError:
    sys.exit("ERROR: pip install tqdm")

# ──────────────────────────────────────────────
#  ANSI palette — spec 3.1. No other colours.
# ──────────────────────────────────────────────
CYAN   = "\033[96m"   # Progress bar fill — reserved, nothing else
GREEN  = "\033[92m"   # Success states
RED    = "\033[91m"   # Failure / error states
YELLOW = "\033[93m"   # Auth-error states
WHITE  = "\033[97m"   # All body text, table content, labels
BOLD   = "\033[1m"    # Section headers, label emphasis
RESET  = "\033[0m"    # Always close every colour block

# ──────────────────────────────────────────────
#  Constants
# ──────────────────────────────────────────────
DEFAULT_CSV      = "secrets/mikrotik_firmware.csv"   # relative to this script's folder
OUTPUT_DIR       = "mikrotik_version_check/files"    # results_<YYYYMMDD>_<HHMMSS>.json
DEFAULT_PORT     = 22
DEFAULT_USERNAME = "admin"
DEFAULT_TIMEOUT  = 15
DEFAULT_WORKERS  = 5
MANUFACTURER     = "MikroTik"

# RouterOS commands, in the order they are run
CMD_PACKAGES    = "/system/package/print"
CMD_ROUTERBOARD = "/system/routerboard/print"
CMD_HEALTH      = "/system/health/print"

# ──────────────────────────────────────────────
#  Logging — plain, no colours. Set up in main():
#  WARNING normally; with --debug (alias --verbose)
#  cli.debug.enable() configures DEBUG logging
#  (paramiko's own messages included) instead.
# ──────────────────────────────────────────────
LOG_FORMAT  = "%(asctime)s  %(levelname)-8s  %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Per-model health field overrides
#  Keys are matched as case-insensitive prefixes
#  against the model string from routerboard/print.
#  Add new models here — no other changes needed.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MODEL_HEALTH_MAP: dict[str, dict] = {
    "CRS112-8G-4S": {"temp_field": "temperature", "poe_field": "poe-out-consumption"},
    "CRS112-8P-4S": {"temp_field": "temperature", "poe_field": "poe-out-consumption"},
    "RB960PGS":     {"temp_field": "temperature", "poe_field": "poe-out-consumption"},
}

# Defaults used when a model is not found in MODEL_HEALTH_MAP
DEFAULT_HEALTH_FIELDS: dict = {"temp_field": "board-temperature1", "poe_field": "poe-out-consumption"}


def get_health_fields(model: str | None) -> dict:
    """
    Returns the health field config for a given model string.
    Matches case-insensitively against MODEL_HEALTH_MAP keys.
    Falls back to DEFAULT_HEALTH_FIELDS if no match is found.
    """
    if model:
        model_upper = model.upper()
        for key, fields in MODEL_HEALTH_MAP.items():
            if model_upper.startswith(key.upper()):
                return fields
    return DEFAULT_HEALTH_FIELDS


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Shared helpers — spec 3.5, byte-identical
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Error label truncation — spec 3.6
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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

# Protocol-specific patterns for this script — RouterOS SSH failures:
# authentication rejection, bad command name, paramiko transport errors.
PROTOCOL_ERROR_PATTERNS = [
    (r"[Aa]uthentication failed",         "Auth failed"),
    (r"[Aa]uthentication required",       "Auth required"),
    (r"[Bb]ad command name",              "Bad command"),
    (r"expected end of command",          "Bad command"),
    (r"[Nn]o matching .* found",          "SSH negotiation"),
    (r"[Ee]rror reading SSH protocol",    "SSH handshake"),
    (r"[Ss]ocket is closed",              "SSH closed"),
    (r"SSH session not active",           "SSH closed"),
    (r"[Ee]mpty output",                  "Empty output"),
    (r"[Cc]ould not parse",               "Parse error"),
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CSV loader — spec 3.7
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
            username = (row.get(col_map.get("username", ""), "") or "").strip() or "admin"
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Strip ANSI escape codes
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def strip_ansi(text: str) -> str:
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    text = re.sub(r"\x1b\].*?\x07", "", text)
    text = re.sub(r"\x1b[()][AB012]", "", text)
    text = re.sub(r"\x1b.", "", text)
    text = re.sub(r"[\x00-\x08\x0e-\x1f\x7f]", "", text)
    return text


def celsius_to_fahrenheit(c: float) -> float:
    return round(c * 9 / 5 + 32, 1)


def visible(text: str) -> str:
    """
    Device text for --raw / --debug: CRLF -> LF, and every other control or
    escape character (ANSI colour codes from the shell, stray CRs) shown as
    \\xNN so it can't garble the terminal.
    """
    text = text.replace("\r\n", "\n")
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", lambda m: f"\\x{ord(m.group()):02x}", text)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SSH: connect (shared by the query and --raw)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def connect_ssh(client: paramiko.SSHClient, host: str, port: int,
                username: str, password: str, timeout: int) -> None:
    cli.debug.log(host, f"connecting to {host}:{port} as {username!r} (timeout {timeout}s)")
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
        disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]},
    )
    cli.debug.log(host, "connected and authenticated")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SSH: get command output (tries TWO methods)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def get_command_output(client: paramiko.SSHClient, command: str, host: str = "") -> str:
    try:
        cli.debug.sent(host, f"{command}   (exec_command)")
        _, stdout, _ = client.exec_command(command, timeout=15)
        output = stdout.read().decode("utf-8", errors="replace")
        cli.debug.received(host, visible(output) or "(no output)")
        if output.strip():
            return output
        cli.debug.log(host, "exec_command gave no output; retrying in an interactive shell")
    except Exception as exc:
        cli.debug.log(host, f"exec_command failed ({type(exc).__name__}: {exc}); "
                            "retrying in an interactive shell")

    try:
        channel = client.invoke_shell(width=200, height=50)
        time.sleep(2)
        if channel.recv_ready():
            banner = channel.recv(65535)
            cli.debug.log(host, "shell banner (discarded): "
                                + cli.show(visible(banner.decode("utf-8", errors="replace"))))

        cli.debug.sent(host, f"{command}   (interactive shell)")
        channel.send(command + "\n")
        time.sleep(3)

        raw = b""
        deadline = time.time() + 15
        while time.time() < deadline:
            if channel.recv_ready():
                raw += channel.recv(65535)
                time.sleep(0.5)
            else:
                time.sleep(0.5)
                if not channel.recv_ready():
                    break

        channel.close()
        output = raw.decode("utf-8", errors="replace")
        cli.debug.received(host, visible(output) or "(no output)")
        return output
    except Exception as exc:
        cli.debug.log(host, f"interactive shell failed ({type(exc).__name__}: {exc})")

    return ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Parse packages — extract NAME + VERSION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_packages(raw: str) -> list[dict]:
    clean_text = strip_ansi(raw)
    packages: list[dict] = []
    seen: set[str] = set()

    kv_matches = re.findall(
        r'name\s*=\s*"([^"]+)".*?version\s*=\s*"([^"]+)"',
        clean_text,
        re.IGNORECASE,
    )
    if kv_matches:
        for name, version in kv_matches:
            key = f"{name.strip()}|{version.strip()}"
            if key not in seen:
                seen.add(key)
                packages.append({"name": name.strip(), "version": version.strip()})
        return packages

    for line in clean_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("#", "Columns", "Flags")):
            continue
        if "/system" in stripped.lower():
            continue
        if stripped.endswith((">", "#")):
            continue

        m = re.match(
            r"^\s*\d+\s+([X\s]{0,3})\s*(\S+)\s+(\d+\.\d+\S*)",
            stripped,
        )
        if m:
            flags, name, version = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
            key = f"{name}|{version}"
            if key not in seen:
                seen.add(key)
                pkg: dict = {"name": name, "version": version}
                if "X" in flags:
                    pkg["disabled"] = True
                packages.append(pkg)
            continue

        m = re.match(r"^\s*(\S+)\s+(\d+\.\d+\S*)\s*$", stripped)
        if m:
            name, version = m.group(1).strip(), m.group(2).strip()
            if name.lower() in ("name", "version", "#", "columns:", "flags:"):
                continue
            key = f"{name}|{version}"
            if key not in seen:
                seen.add(key)
                packages.append({"name": name, "version": version})

    return packages


def get_routeros_version(packages: list[dict]) -> str | None:
    for pkg in packages:
        if "routeros" in pkg["name"].lower():
            return pkg["version"]
    for pkg in packages:
        if pkg["name"].lower() == "system":
            return pkg["version"]
    return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Parse routerboard — extract MODEL + FIRMWARE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_routerboard(raw: str) -> dict:
    clean_text = strip_ansi(raw)
    result = {"model": None, "current_firmware": None}

    for line in clean_text.splitlines():
        stripped = line.strip()

        if result["model"] is None:
            m = re.search(r"(?i)model\s*[:=]\s*(.+)", stripped)
            if m:
                result["model"] = m.group(1).strip()

        if result["current_firmware"] is None:
            m = re.search(r"(?i)current-firmware\s*[:=]\s*(\S+)", stripped)
            if m:
                result["current_firmware"] = m.group(1).strip()

        if result["model"] and result["current_firmware"]:
            break

    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Parse health — extract POE + TEMPERATURE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_health(raw: str, temp_field: str = "board-temperature1", poe_field: str = "poe-out-consumption") -> dict:
    """
    Parses the output of /system/health/print.
    Extracts:
      - poe_out_consumption_w  : float (watts) or None
      - board_temperature1_c   : float (Celsius) or None
      - board_temperature1_f   : float (Fahrenheit) or None

    RouterOS health output varies by device and version. Two formats
    are supported:

      Columnar (RouterOS 7.x):
        # NAME                    VALUE  TYPE
        0 board-temperature1       42     C
        1 poe-out-consumption      8.5    W

      Key-value (RouterOS 6.x):
        board-temperature1: 42
        poe-out-consumption: 8.5
    """
    clean_text = strip_ansi(raw)
    result: dict = {
        "poe_out_consumption_w": None,
        "board_temperature1_c":  None,
        "board_temperature1_f":  None,
    }

    for line in clean_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Columnar: index  name  value  [unit]
        m = re.match(r"^\s*\d+\s+([\w\-]+)\s+([\d.]+)\s*(\S*)", stripped)
        if m:
            name, value = m.group(1).lower(), m.group(2)
        else:
            # Key-value: name: value
            m = re.match(r"(?i)([\w\-]+)\s*[:=]\s*([\d.]+)", stripped)
            if not m:
                continue
            name, value = m.group(1).lower(), m.group(2)

        try:
            fval = float(value)
        except ValueError:
            continue

        if name == poe_field.lower() and result["poe_out_consumption_w"] is None:
            result["poe_out_consumption_w"] = fval

        if name == temp_field.lower() and result["board_temperature1_c"] is None:
            result["board_temperature1_c"] = fval
            result["board_temperature1_f"] = celsius_to_fahrenheit(fval)

    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Check ONE router
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_router(
    host: str,
    username: str = "admin",
    password: str = "",
    port: int = DEFAULT_PORT,
    timeout: int = 15,
    include_raw: bool = False,
) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    result: dict = {
        "host":                  host,
        "port":                  port,
        "query_timestamp":       ts,
        "status":                "error",
        "manufacturer":          MANUFACTURER,
        "model":                 None,
        "serial":                None,
        "mac":                   None,
        "firmware_version":      None,
        "routeros_version":      None,
        "poe_out_consumption_w": None,
        "board_temperature1_c":  None,
        "board_temperature1_f":  None,
        "packages":              [],
        "error":                 None,
    }
    if include_raw:
        result["raw_packages"]    = ""
        result["raw_routerboard"] = ""
        result["raw_health"]      = ""

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        connect_ssh(client, host, port, username, password, timeout)

        # Query 1: packages
        raw_pkg = get_command_output(client, CMD_PACKAGES, host=host)
        if include_raw:
            result["raw_packages"] = raw_pkg

        if not raw_pkg.strip():
            result["error"] = "Router returned empty output"
            cli.debug.log(host, f"result: {result['status']} ({result['error']})")
            return result

        packages = parse_packages(raw_pkg)
        result["packages"] = packages
        cli.debug.log(host, f"parsed packages: {packages}")

        if packages:
            result["routeros_version"] = get_routeros_version(packages)
            result["status"] = "success"
        else:
            result["error"] = "Could not parse any packages from output"

        # Query 2: routerboard (best-effort)
        raw_rb = get_command_output(client, CMD_ROUTERBOARD, host=host)
        if include_raw:
            result["raw_routerboard"] = raw_rb
        if raw_rb.strip():
            rb = parse_routerboard(raw_rb)
            result["model"]            = rb["model"]
            result["firmware_version"] = rb["current_firmware"]

        # Canonical firmware field falls back to the RouterOS version
        if not result["firmware_version"]:
            result["firmware_version"] = result["routeros_version"]

        # Query 3: health (best-effort)
        raw_health = get_command_output(client, CMD_HEALTH, host=host)
        if include_raw:
            result["raw_health"] = raw_health
        if raw_health.strip():
            hf = get_health_fields(result.get("model"))
            cli.debug.log(host, f"health fields for model {result.get('model')!r}: {hf}")
            health = parse_health(raw_health, temp_field=hf["temp_field"], poe_field=hf["poe_field"])
            result["poe_out_consumption_w"] = health["poe_out_consumption_w"]
            result["board_temperature1_c"]  = health["board_temperature1_c"]
            result["board_temperature1_f"]  = health["board_temperature1_f"]

    except paramiko.AuthenticationException as exc:
        cli.debug.log(host, f"authentication rejected: {exc}")
        result["status"] = "auth_error"
        result["error"]  = "Authentication failed"
    except (paramiko.SSHException, socket.error) as exc:
        result["error"] = f"SSH/network error: {exc}"
    except Exception as exc:
        result["error"] = f"Unexpected error: {exc}"
    finally:
        client.close()

    cli.debug.log(host, f"result: {result['status']}"
                        + (f" ({result['error']})" if result["error"] else "")
                        + f"; firmware={result['firmware_version']} routeros={result['routeros_version']}"
                          f" model={result['model']}")
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Print results table — spec 3.4 / 3.8
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def print_results_table(
    results: list[dict],
    elapsed: float,
    workers: int,
    output_path: str,
    firmware_filter: list | None = None,
) -> None:
    headers = [
        "Status", "Host", "Manufacturer", "Model", "Firmware",
        "RouterOS Version", "Temp (°F)", "Total PoE (W)", "Error",
    ]

    # When --firmware is set, only show devices whose firmware_version is
    # not one of the targets, including errors and
    # unreachable devices (same rule as every script). All results are
    # still written to JSON.
    if firmware_filter:
        display_results = cli.firmware_mismatches(results, firmware_filter)
    else:
        display_results = results

    rows: list[list] = []
    for r in display_results:
        poe  = r.get("poe_out_consumption_w")
        temp = r.get("board_temperature1_f")
        rows.append([
            status_icon(r),
            f"{WHITE}{clean(r['host'])}{RESET}",
            f"{WHITE}{clean(r.get('manufacturer'))}{RESET}",
            f"{WHITE}{clean(r.get('model'))}{RESET}",
            f"{WHITE}{clean(r.get('firmware_version'))}{RESET}",
            f"{WHITE}{clean(r.get('routeros_version'))}{RESET}",
            f"{WHITE}{clean(f'{temp}°F' if temp is not None else None)}{RESET}",
            f"{WHITE}{clean(f'{poe} W' if poe is not None else None)}{RESET}",
            f"{WHITE}{truncate_error(r.get('error'))}{RESET}",
        ])

    table = tabulate(rows, headers=headers, tablefmt="pretty", stralign="left", numalign="right")

    first_line = table.split("\n")[0]
    raw_width = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw = max(raw_width, 60)

    if firmware_filter:
        title = f"MikroTik RouterOS — Firmware Mismatch: target {cli.firmware_label(firmware_filter)}"
    else:
        title = "MikroTik RouterOS Query Results"
    pad = (bw - len(title)) // 2

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")
    for line in table.split("\n"):
        print(f"  {line}")

    # Counts always reflect full results, not just displayed rows
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

    if firmware_filter:
        # The mismatches (errors included) are exactly the table rows
        mismatched = len(display_results)
        matched    = len(results) - mismatched
        print(
            f"  {BOLD}Firmware Filter:{RESET}{WHITE} {cli.firmware_label(firmware_filter)}  |  "
            f"{GREEN}✓{RESET}{WHITE} {BOLD}Matched:{RESET}{WHITE} {matched}  |  "
            f"{YELLOW}✗{RESET}{WHITE} {BOLD}Mismatch:{RESET}{WHITE} {mismatched}"
        )

    # Device-specific metrics — RouterOS version breakdown
    version_counts = Counter(
        r["routeros_version"]
        for r in results
        if r["status"] == "success" and r.get("routeros_version")
    )
    if version_counts:
        breakdown = "  |  ".join(
            f"{ver}: {cnt}" for ver, cnt in sorted(version_counts.items())
        )
        print(
            f"  {BOLD}RouterOS Versions{RESET}{WHITE} — "
            f"{breakdown}  |  Reported: {sum(version_counts.values())}/{total}"
        )
    else:
        print(f"  {BOLD}RouterOS Versions{RESET}{WHITE} — No data available")

    # Device-specific metrics — board temperature (Fahrenheit is the display unit)
    temp_vals = [
        r["board_temperature1_f"]
        for r in results
        if r.get("board_temperature1_f") is not None
    ]
    if temp_vals:
        print(
            f"  {BOLD}Board Temp (°F){RESET}{WHITE} — "
            f"Avg: {sum(temp_vals)/len(temp_vals):.1f}  |  "
            f"Min: {min(temp_vals)}  |  "
            f"Max: {max(temp_vals)}  |  "
            f"Reported: {len(temp_vals)}/{total}"
        )
    else:
        print(f"  {BOLD}Board Temp (°F){RESET}{WHITE} — No data available")

    # Device-specific metrics — PoE consumption
    poe_vals = [
        r["poe_out_consumption_w"]
        for r in results
        if r.get("poe_out_consumption_w") is not None
    ]
    if poe_vals:
        print(
            f"  {BOLD}Total PoE (W){RESET}{WHITE} — "
            f"Avg: {sum(poe_vals)/len(poe_vals):.1f}  |  "
            f"Min: {min(poe_vals)}  |  "
            f"Max: {max(poe_vals)}  |  "
            f"Reported: {len(poe_vals)}/{total}"
        )
    else:
        print(f"  {BOLD}Total PoE (W){RESET}{WHITE} — No data available")

    print()
    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {output_path}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers){RESET}")
    print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Check ALL routers (concurrent)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_all_routers(
    routers: list[dict],
    output_path: str,
    input_label: str,
    workers: int = DEFAULT_WORKERS,
    timeout: int = DEFAULT_TIMEOUT,
    include_raw: bool = False,
    firmware_filter: list | None = None,
) -> None:
    all_results: list[dict] = [None] * len(routers)
    start_ts = datetime.now(timezone.utc)
    t0 = time.monotonic()

    active_lock = threading.Lock()
    latest_host: dict = {"value": ""}

    term_width = shutil.get_terminal_size((120, 24)).columns
    bar_fmt = (
        f"  {WHITE}Scanning{RESET} "
        f"{CYAN}{{bar}}{RESET}"
        f" {WHITE}{{n_fmt}}/{{total_fmt}}{RESET}"
        f" {WHITE}[{{elapsed}}<{{remaining}}]{RESET}"
        f"  {WHITE}{{postfix}}{RESET}"
    )

    with tqdm(
        total=len(routers),
        bar_format=bar_fmt,
        ncols=term_width,
        dynamic_ncols=True,
        file=sys.stderr,
        leave=True,
    ) as pbar:
        def task(idx: int, router: dict) -> tuple[int, dict]:
            with active_lock:
                latest_host["value"] = router["host"]
            result = check_router(
                host=router["host"],
                username=router["username"],
                password=router["password"],
                port=router["port"],
                timeout=timeout,
                include_raw=include_raw,
            )
            return idx, result

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(task, i, r): i for i, r in enumerate(routers)}
            for future in as_completed(futures):
                idx, result = future.result()
                all_results[idx] = result
                with active_lock:
                    host_display = latest_host["value"]
                pbar.set_postfix_str(host_display, refresh=False)
                pbar.update(1)

        elapsed = time.monotonic() - t0
        pbar.set_postfix_str(
            f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s",
            refresh=True,
        )

    elapsed = time.monotonic() - t0

    ok   = sum(1 for r in all_results if r["status"] == "success")
    auth = sum(1 for r in all_results if r["status"] == "auth_error")
    err  = sum(1 for r in all_results if r["status"] == "error")

    cli.ensure_parent(output_path)
    output = {
        "query_info": {
            "csv_file":        input_label,
            "timestamp":       start_ts.isoformat(),
            "protocol":        "SSH / RouterOS CLI",
            "mode":            (f"firmware filter: {cli.firmware_label(firmware_filter)}"
                                if firmware_filter else "package version query"),
            "workers":         workers,
            "total":           len(all_results),
            "success":         ok,
            "auth_errors":     auth,
            "errors":          err,
            "elapsed_seconds": round(elapsed, 2),
        },
        "routers": all_results,
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, ensure_ascii=False)

    print_results_table(all_results, elapsed, workers, output_path, firmware_filter=firmware_filter)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def dump_raw(dev: dict, timeout: int) -> None:
    """--raw: print what each RouterOS command returns (the text the parsers see)."""
    host = dev["host"]
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_ssh(client, host, dev["port"], dev["username"], dev["password"], timeout)
        for cmd in (CMD_PACKAGES, CMD_ROUTERBOARD, CMD_HEALTH):
            output = get_command_output(client, cmd, host=host)
            if output.strip():
                cli.raw_item(cmd, visible(output).rstrip())
            else:
                cli.raw_error(cmd, "no output (exec_command and interactive shell both empty)")
    finally:
        client.close()


def make_device(host: str) -> dict:
    """--host target not in the CSV: same shape and defaults as load_csv()."""
    return {"host": host, "port": DEFAULT_PORT, "username": DEFAULT_USERNAME, "password": ""}


def main() -> None:
    parser = cli.build_parser(
        script_file=__file__,
        description="Check MikroTik router firmware and package versions via SSH.",
        default_csv=DEFAULT_CSV,
        output_dir=OUTPUT_DIR,
        default_port=DEFAULT_PORT,
        default_timeout=DEFAULT_TIMEOUT,
        default_workers=DEFAULT_WORKERS,
        auth=cli.AUTH_USER_PASSWORD,
        timeout_help=(f"SSH connect timeout in seconds (default: {DEFAULT_TIMEOUT}). "
                      "Each command has its own fixed 15s timeout."),
        firmware_help=("Show only successfully queried routers NOT on any of these versions "
                       "(routerboard current-firmware, else the RouterOS version). Errors are "
                       "left out of the table. The JSON always has every router."),
        epilog="""
Examples:
  python3 mikrotik_script.py                               # whole CSV
  python3 mikrotik_script.py --host 10.0.0.1               # one router (CSV row reused if listed)
  python3 mikrotik_script.py --host 10.0.0.1 -u admin --password 'secret'
  python3 mikrotik_script.py --host 10.0.0.1 --raw         # raw SSH output per command
  python3 mikrotik_script.py --host 10.0.0.1 --debug       # trace the SSH exchange to stderr
  python3 mikrotik_script.py --firmware 7.14.2 7.15.1      # who is NOT on these
  python3 mikrotik_script.py --include-raw -o out.json     # keep raw output in the JSON

Protocol:
  SSH on port 22 with the CSV's username/password (username defaults to admin).
  Commands: /system/package/print, /system/routerboard/print, /system/health/print.
  Each runs via exec_command, falling back to an interactive shell if that
  returns nothing.
        """,
    )
    group = parser.add_argument_group("MikroTik options")
    group.add_argument("--include-raw", action="store_true", default=False,
        help="Store each router's raw SSH output in the results JSON (raw_packages, "
             "raw_routerboard, raw_health). Unlike --raw, the normal run still happens.")
    args = cli.parse_args(parser)

    if not args.debug:
        # Under --debug, cli.debug.enable() has already set up DEBUG logging.
        logging.basicConfig(level=logging.WARNING, format=LOG_FORMAT, datefmt=LOG_DATEFMT)

    # Header block — spec 3.2
    print(f"{WHITE}")
    print(f"  {BOLD}MikroTik Router Firmware Checker{RESET}{WHITE}")
    print(f"  Queries RouterOS version, packages, and board health over SSH")
    print(f"  Input:   {cli.input_label(args)}")
    print(f"  Output:  {'(none: --raw)' if args.raw else args.output}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    if args.firmware:
        print(f"  Firmware Filter: {cli.firmware_label(args.firmware)} — showing mismatched devices only")
    if args.debug:
        print(f"  Debug:   on (trace on stderr)")
    print(f"{RESET}")

    routers = cli.select_devices(args, load_csv, make_device)

    # --raw: dump what each router sends back, no table / JSON
    if args.raw:
        cli.run_raw(routers, lambda d: dump_raw(d, args.timeout))
        return

    print(f"  {WHITE}Loaded {BOLD}{len(routers)}{RESET}{WHITE} router(s){RESET}\n")

    check_all_routers(
        routers,
        args.output,
        input_label=cli.input_label(args),
        workers=args.workers,
        timeout=args.timeout,
        include_raw=args.include_raw,
        firmware_filter=args.firmware,
    )


if __name__ == "__main__":
    main()
