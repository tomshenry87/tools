#!/usr/bin/env python3
"""
Netgear M4250 Router Version & CPU Temp Checker
=================================================
Reads router credentials from secrets/netgear_firmware.csv (default), connects via SSH,
runs `show hardware`, `show environment | include Temp`, and `show poe`,
extracts firmware version, model, serial, CPU temperature, and PoE consumption,
writes results to netgear_firmware/files/results_YYYYMMDD_HHMMSS.json (default),
and prints a summary table.

Temperature note: the M4250 CLI reports Celsius. The terminal table and metrics
line display Fahrenheit (engineers here read °F). The JSON emits BOTH
`board_temperature1_f` and `board_temperature1_c`, each suffixed truthfully.

Usage (standard flags: see lib/standard_cli.py or --help):
    python3 netgear_script.py
    python3 netgear_script.py --host 10.0.0.2 --debug
    python3 netgear_script.py --host 10.0.0.2 --raw
    python3 netgear_script.py -i secrets/netgear_firmware.csv
    python3 netgear_script.py --include-raw --debug
    python3 netgear_script.py --firmware 12.0.20.7 13.0.4.26

CSV columns: host, username, password, port (port defaults to 22)
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
#  ANSI colour palette
# ──────────────────────────────────────────────
CYAN   = "\033[96m"   # Progress bar fill — reserved, nothing else
GREEN  = "\033[92m"   # Success states
RED    = "\033[91m"   # Failure / error states
YELLOW = "\033[93m"   # Auth-error states
WHITE  = "\033[97m"   # All body text, table content, labels
BOLD   = "\033[1m"    # Section headers, label emphasis
RESET  = "\033[0m"    # Always close every colour block

DEFAULT_CSV      = "secrets/netgear_firmware.csv"   # relative to this script's folder
OUTPUT_DIR       = "netgear_firmware/files"         # results_<YYYYMMDD>_<HHMMSS>.json
DEFAULT_PORT     = 22
DEFAULT_USERNAME = "admin"
DEFAULT_TIMEOUT  = 20
DEFAULT_WORKERS  = 5

# CLI commands sent over the interactive shell, in order, with their
# read-until-prompt timeouts (seconds)
SETUP_COMMANDS = [("en", 10), ("terminal length 0", 5)]
CMD_HARDWARE    = "show hardware"
CMD_ENVIRONMENT = "show environment | include Temp"
CMD_POE         = "show poe"
QUERY_TIMEOUT   = 20

# ──────────────────────────────────────────────
#  Logging — plain text, no colours. Set up in main():
#  WARNING normally; with --debug (alias --verbose)
#  cli.debug.enable() configures DEBUG logging
#  (paramiko's own messages included) instead.
# ──────────────────────────────────────────────
LOG_FORMAT  = "%(asctime)s  %(levelname)-8s  %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Unit conversion
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def fahrenheit_to_celsius(f: float) -> float:
    """Inverse of mikrotik_script.py's celsius_to_fahrenheit()."""
    return (f - 32) * 5 / 9


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Shared helpers — byte-identical across all scripts
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
        return f"{GREEN}\u2713 OK{RESET}{WHITE}"
    elif s == "auth_error":
        return f"{YELLOW}\u2717 AUTH ERR{RESET}{WHITE}"
    return f"{RED}\u2717 ERROR{RESET}{WHITE}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Error truncation — shared base + protocol extension
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

# Protocol-specific patterns for this script, matched BEFORE the base list.
# Netgear CLI failures — auth rejection, `% Invalid input`, paramiko transport.
PROTOCOL_ERROR_PATTERNS = [
    (r"[Aa]uthentication failed",   "Auth failed"),
    (r"[Aa]uthentication required", "Auth required"),
    (r"%\s*[Ii]nvalid input",       "Invalid input"),
    (r"[Ii]ncomplete command",      "Invalid input"),
    (r"[Nn]o existing session",     "No session"),
    (r"SSH.*[Ee]rror",              "SSH error"),
    (r"[Ee]rror reading SSH",       "SSH error"),
    (r"[Cc]ould not parse firmware", "Parse error"),
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
#  CSV loader
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


def visible(text: str) -> str:
    """
    Device text for --raw / --debug: CRLF -> LF, and every other control or
    escape character (ANSI codes from the vt100 shell, stray CRs) shown as
    \\xNN so it can't garble the terminal.
    """
    text = text.replace("\r\n", "\n")
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", lambda m: f"\\x{ord(m.group()):02x}", text)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SSH shell helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def connect_ssh(client: paramiko.SSHClient, host: str, port: int,
                username: str, password: str, timeout: int) -> None:
    """Connect + authenticate (shared by the query and --raw)."""
    cli.debug.log(host, f"connecting to {host}:{port} as {username!r} (timeout {timeout}s)")
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    cli.debug.log(host, "connected and authenticated")


def _read_until_prompt(channel: paramiko.Channel, timeout: float = 15.0, host: str = "") -> str:
    """
    Read from an interactive SSH channel until a CLI prompt is detected
    or the timeout expires.  Netgear M4250 prompts end with '>' or '#'.
    """
    raw = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(65535)
            raw += chunk
            decoded = raw.decode("utf-8", errors="replace")
            if re.search(r"[>#]\s*$", decoded.rstrip()):
                break
        else:
            time.sleep(0.3)
    else:
        cli.debug.log(host, f"no prompt within {timeout:g}s ({len(raw)} bytes received)")
    return raw.decode("utf-8", errors="replace")


def open_shell(client: paramiko.SSHClient, host: str = "") -> tuple[paramiko.Channel, str]:
    """Open an interactive shell and wait for the first prompt. Returns (channel, banner)."""
    channel = client.invoke_shell(term="vt100", width=220, height=50)
    time.sleep(2)
    banner = _read_until_prompt(channel, timeout=10, host=host)  # banner / MOTD (not parsed)
    cli.debug.log(host, f"shell banner: {cli.show(visible(banner))}")
    return channel, banner


def run_command(channel: paramiko.Channel, command: str, timeout: float = 20.0,
                host: str = "") -> str:
    """Send a command and return the output up to the next prompt."""
    cli.debug.sent(host, command)
    channel.send(command + "\n")
    time.sleep(0.5)
    output = _read_until_prompt(channel, timeout=timeout, host=host)
    cli.debug.received(host, visible(output) or "(no output)")
    return output


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Parse serial number from `show hardware`
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_serial_number(raw: str) -> str | None:
    """
    Parses the output of `show hardware` for a line like:
        Serial Number.................. ABC1234567890
    Returns the serial number string or None if not found.
    """
    clean_text = strip_ansi(raw)
    m = re.search(
        r"Serial\s+Number[.\s]+(\S+)",
        clean_text,
        re.IGNORECASE,
    )
    if m:
        return m.group(1).strip().rstrip(".,;")
    return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Parse machine model from `show hardware`
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_machine_model(raw: str) -> str | None:
    """
    Parses the output of `show hardware` for a line like:
        Machine Model.................. M4250-10G2F-PoE+
    Returns the model string or None if not found.
    """
    clean_text = strip_ansi(raw)
    m = re.search(
        r"Machine\s+Model[.\s]+(\S+)",
        clean_text,
        re.IGNORECASE,
    )
    if m:
        return m.group(1).strip().rstrip(".,;")
    return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Parse firmware version from `show hardware`
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_firmware_version(raw: str) -> str | None:
    """
    `show hardware` on an M4250 typically includes lines like:
        Software Version...................  12.0.20.7
        Firmware Version:               12.0.20.7
    Also handles "Build" and "Image" variants seen on some firmware trains.
    """
    clean_text = strip_ansi(raw)
    patterns = [
        r"software\s+version[\s.:]+(\S+)",
        r"firmware\s+version[\s.:]+(\S+)",
        r"build\s+number[\s.:]+(\S+)",
        r"\bversion[\s.:]+(\d+\.\d+[\d.]*)",
    ]
    for pat in patterns:
        m = re.search(pat, clean_text, re.IGNORECASE)
        if m:
            v = m.group(1).strip().rstrip(".,;")
            if v.lower() not in ("is", "the", "a", "not"):
                return v
    return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Parse total PoE power from `show poe`
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_poe_power(raw: str) -> tuple[str | None, float | None]:
    """
    Parses the output of `show poe` for a line like:
        Total Power Consumed...........  82.4 Watts
    Returns (display_string, numeric_value) or (None, None) if not found.
    """
    clean_text = strip_ansi(raw)
    m = re.search(
        r"Total\s+Power\s+Consumed[.\s]+(\d+(?:\.\d+)?)",
        clean_text,
        re.IGNORECASE,
    )
    if m:
        val = float(m.group(1))
        return f"{val:.1f} W", val
    return None, None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Parse CPU temperature from `show environment`
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_cpu_temp(raw: str) -> tuple[str | None, float | None]:
    """
    Returns (display_string, numeric_value) or (None, None) if not found.
    Matches lines like:  Temp (C)........ 40

    NOTE: the returned numeric value is FAHRENHEIT. The CLI reports Celsius and
    this function converts. Callers must treat the returned number as °F.
    """
    clean_text = strip_ansi(raw)
    m = re.search(
        r"^Temp\s*\(C\)[.\s]+(\d+(?:\.\d+)?)\s*$",
        clean_text,
        re.IGNORECASE | re.MULTILINE,
    )
    if m:
        val_c = float(m.group(1).strip())
        val_f = val_c * 9 / 5 + 32
        return f"{val_f:.0f} \u00b0F", val_f
    return None, None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Check ONE router
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_router(
    host: str,
    username: str = "admin",
    password: str = "",
    port: int = DEFAULT_PORT,
    timeout: int = 20,
    include_raw: bool = False,
) -> dict:
    queried_at = datetime.now(timezone.utc).isoformat()
    result: dict = {
        "host":                  host,
        "port":                  port,
        "query_timestamp":       queried_at,
        "status":                "error",
        "manufacturer":          "Netgear",
        "model":                 None,
        "serial":                None,
        "mac":                   None,
        "firmware_version":      None,
        "board_temperature1_f":  None,
        "board_temperature1_c":  None,
        "poe_out_consumption_w": None,
        "error":                 None,
        # CLI-only display strings — not read by the dashboard's router branch
        "cpu_temp":              None,
        "poe_consumed":          None,
    }

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        connect_ssh(client, host, port, username, password, timeout)

        channel, _banner = open_shell(client, host=host)

        for cmd, cmd_timeout in SETUP_COMMANDS:          # en, terminal length 0
            run_command(channel, cmd, timeout=cmd_timeout, host=host)

        raw_ver = run_command(channel, CMD_HARDWARE,    timeout=QUERY_TIMEOUT, host=host)
        raw_env = run_command(channel, CMD_ENVIRONMENT, timeout=QUERY_TIMEOUT, host=host)
        raw_poe = run_command(channel, CMD_POE,         timeout=QUERY_TIMEOUT, host=host)

        if include_raw:
            result["raw_version"]     = raw_ver
            result["raw_environment"] = raw_env
            result["raw_poe"]         = raw_poe

        firmware         = parse_firmware_version(raw_ver)
        model            = parse_machine_model(raw_ver)
        serial           = parse_serial_number(raw_ver)
        temp_str, temp_f = parse_cpu_temp(raw_env)   # temp_f is FAHRENHEIT
        poe_str, poe_w   = parse_poe_power(raw_poe)

        result["model"]            = model
        result["serial"]           = serial
        result["firmware_version"] = firmware

        # Temperature — emit both units, each suffixed truthfully.
        # parse_cpu_temp() returns Fahrenheit; Celsius is derived from it.
        result["board_temperature1_f"] = temp_f
        result["board_temperature1_c"] = (
            round(fahrenheit_to_celsius(temp_f), 2) if temp_f is not None else None
        )

        result["poe_out_consumption_w"] = poe_w

        # CLI display strings
        result["cpu_temp"]     = temp_str
        result["poe_consumed"] = poe_str

        if firmware is not None:
            result["status"] = "success"
            result["error"]  = None
        else:
            result["status"] = "error"
            result["error"]  = "Could not parse firmware version from output"

        run_command(channel, "exit", timeout=5, host=host)
        run_command(channel, "exit", timeout=5, host=host)
        channel.close()

    except paramiko.AuthenticationException as exc:
        cli.debug.log(host, f"authentication rejected: {exc}")
        result["status"] = "auth_error"
        result["error"]  = "Authentication failed"
    except (paramiko.SSHException, socket.error) as exc:
        result["status"] = "error"
        result["error"]  = f"SSH/network error: {exc}"
    except Exception as exc:
        result["status"] = "error"
        result["error"]  = f"Unexpected error: {exc}"
    finally:
        client.close()

    cli.debug.log(host, f"result: {result['status']}"
                        + (f" ({result['error']})" if result["error"] else "")
                        + f"; firmware={result['firmware_version']} model={result['model']}"
                          f" temp={result['cpu_temp']} poe={result['poe_consumed']}")
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Print results table
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def print_results_table(
    results: list[dict],
    elapsed: float,
    firmware_filter: list | None = None,
) -> None:
    headers = [
        "Status", "Host", "Manufacturer", "Model", "Firmware",
        "Serial", "CPU Temp", "PoE (W)", "Error",
    ]
    rows: list[list[str]] = []

    temp_vals: list[float] = []   # Fahrenheit — the CLI display unit
    poe_vals:  list[float] = []

    # Apply firmware filter if provided: devices not on one of the target
    # versions, including ones that could not be read (same rule as every
    # script). The JSON always has every device.
    if firmware_filter:
        display_results = cli.firmware_mismatches(results, firmware_filter)
    else:
        display_results = results

    for r in display_results:
        rows.append([
            status_icon(r),
            clean(r.get("host")),
            clean(r.get("manufacturer")),
            clean(r.get("model")),
            clean(r.get("firmware_version")),
            clean(r.get("serial")),
            clean(r.get("cpu_temp")),
            clean(r.get("poe_consumed")),
            truncate_error(r.get("error")),
        ])

    # Metrics are computed across ALL results, not just the filtered view
    for r in results:
        tv = r.get("board_temperature1_f")
        if tv is not None:
            temp_vals.append(tv)
        pv = r.get("poe_out_consumption_w")
        if pv is not None:
            poe_vals.append(pv)

    total = len(results)
    ok    = sum(1 for r in results if r["status"] == "success")
    auth  = sum(1 for r in results if r["status"] == "auth_error")
    err   = sum(1 for r in results if r["status"] == "error")

    # All-matched shortcut
    if firmware_filter and not display_results:
        print(f"{WHITE}")
        print(f"  {GREEN}\u2713 All devices are running firmware "
              f"{cli.firmware_label(firmware_filter)}{RESET}{WHITE}")
    else:
        table = tabulate(
            rows,
            headers=headers,
            tablefmt="pretty",
            stralign="left",
            numalign="right",
        )

        first_line = table.split("\n")[0]
        raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
        bw         = max(raw_width, 60)

        if firmware_filter:
            title = f"Netgear M4250 \u2014 Firmware Mismatch: expected {cli.firmware_label(firmware_filter)}"
        else:
            title = "Netgear M4250 Query Results \u2014 Firmware & CPU Temp"
        pad = max(0, (bw - len(title)) // 2)

        print(f"{WHITE}")
        print(f"  {'=' * bw}")
        print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
        print(f"  {'=' * bw}")
        for line in table.split("\n"):
            print(f"  {line}")

    print()
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}\u2717{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )

    if firmware_filter:
        mismatches = len(display_results)
        matched    = len(results) - mismatches
        print(
            f"  {BOLD}Firmware Filter:{RESET}{WHITE} {cli.firmware_label(firmware_filter)}  |  "
            f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Matched:{RESET}{WHITE} {matched}  |  "
            f"{RED}\u2717{RESET}{WHITE} {BOLD}Mismatched:{RESET}{WHITE} {mismatches}"
        )

    if temp_vals:
        avg = sum(temp_vals) / len(temp_vals)
        print(
            f"  {BOLD}CPU Temp (\u00b0F){RESET}{WHITE} \u2014 "
            f"Avg: {avg:.0f}  |  "
            f"Min: {min(temp_vals):.0f}  |  "
            f"Max: {max(temp_vals):.0f}  |  "
            f"Reported: {len(temp_vals)}/{total}"
        )
    else:
        print(f"  {BOLD}CPU Temp (\u00b0F){RESET}{WHITE} \u2014 No data available")

    if poe_vals:
        avg_p = sum(poe_vals) / len(poe_vals)
        print(
            f"  {BOLD}PoE Consumed (W){RESET}{WHITE} \u2014 "
            f"Avg: {avg_p:.1f}  |  "
            f"Min: {min(poe_vals):.1f}  |  "
            f"Max: {max(poe_vals):.1f}  |  "
            f"Reported: {len(poe_vals)}/{total}"
        )
    else:
        print(f"  {BOLD}PoE Consumed (W){RESET}{WHITE} \u2014 No data available")

    print(f"{RESET}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Check ALL routers with progress bar
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_all_routers(
    routers: list[dict],
    output_path: str,
    input_label: str,
    include_raw: bool = False,
    max_workers: int = DEFAULT_WORKERS,
    timeout: int = DEFAULT_TIMEOUT,
    firmware_filter: list | None = None,
) -> None:
    all_results: list[dict] = [None] * len(routers)  # preserve order

    active_lock = threading.Lock()
    latest_host = {"value": ""}
    t_start     = time.time()

    term_width = get_terminal_width()

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
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_index: dict = {}
            for i, router in enumerate(routers):
                fut = executor.submit(
                    check_router,
                    host=router["host"],
                    username=router["username"],
                    password=router["password"],
                    port=router["port"],
                    timeout=timeout,
                    include_raw=include_raw,
                )
                future_to_index[fut] = i

            for future in as_completed(future_to_index):
                idx    = future_to_index[future]
                result = future.result()
                all_results[idx] = result

                with active_lock:
                    latest_host["value"] = result["host"]
                    host_display = latest_host["value"]
                pbar.set_postfix_str(host_display, refresh=False)
                pbar.update(1)

        elapsed = time.time() - t_start
        pbar.set_postfix_str(
            f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s",
            refresh=True,
        )

    elapsed = time.time() - t_start

    # ── Write JSON ────────────────────────────────────────────────────────
    total  = len(all_results)
    ok     = sum(1 for r in all_results if r["status"] == "success")
    errors = total - ok

    cli.ensure_parent(output_path)
    payload = {
        "query_info": {
            "csv_file":        input_label,
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "protocol":        "SSH / Netgear CLI",
            "mode":            "firmware+temp+poe",
            "workers":         max_workers,
            "total":           total,
            "success":         ok,
            "errors":          errors,
            "elapsed_seconds": round(elapsed, 2),
        },
        "routers": all_results,
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    # ── Print table ───────────────────────────────────────────────────────
    print_results_table(all_results, elapsed, firmware_filter=firmware_filter)

    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {output_path}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({max_workers} workers){RESET}")
    print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def dump_raw(dev: dict, timeout: int) -> None:
    """
    --raw: print what the switch sends back for every line typed in the
    shell (login banner, en, terminal length 0, the three show commands),
    each including the echoed command and the next prompt.
    """
    host = dev["host"]
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_ssh(client, host, dev["port"], dev["username"], dev["password"], timeout)
        channel, banner = open_shell(client, host=host)
        cli.raw_item("login banner / first prompt", visible(banner).strip())
        commands = SETUP_COMMANDS + [(c, QUERY_TIMEOUT) for c in (CMD_HARDWARE, CMD_ENVIRONMENT, CMD_POE)]
        for cmd, cmd_timeout in commands:
            output = run_command(channel, cmd, timeout=cmd_timeout, host=host)
            if output:
                cli.raw_item(cmd, visible(output).strip())
            else:
                cli.raw_error(cmd, f"no reply within {cmd_timeout}s")
        channel.close()
    finally:
        client.close()


def make_device(host: str) -> dict:
    """--host target not in the CSV: same shape and defaults as load_csv()."""
    return {"host": host, "port": DEFAULT_PORT, "username": DEFAULT_USERNAME, "password": ""}


def main() -> None:
    parser = cli.build_parser(
        script_file=__file__,
        description=(
            "Check Netgear M4250 firmware versions, CPU temps, and PoE draw via SSH.\n"
            "Defaults: reads secrets/netgear_firmware.csv, writes to netgear_firmware/files/\n\n"
            "CSV columns: host, username, password, port"
        ),
        default_csv=DEFAULT_CSV,
        output_dir=OUTPUT_DIR,
        default_port=DEFAULT_PORT,
        default_timeout=DEFAULT_TIMEOUT,
        default_workers=DEFAULT_WORKERS,
        auth=cli.AUTH_USER_PASSWORD,
        timeout_help=(f"SSH connect timeout in seconds (default: {DEFAULT_TIMEOUT}). "
                      "Each CLI command has its own fixed read timeout."),
        firmware_help=("Show only devices whose reported firmware is NOT one of these "
                       "versions (devices with no firmware reading are left out of the "
                       "table). The JSON always has every device."),
        epilog="""
Examples:
  python3 netgear_script.py                                # whole CSV
  python3 netgear_script.py --host 10.0.0.2                # one switch (CSV row reused if listed)
  python3 netgear_script.py --host 10.0.0.2 -u admin --password 'secret'
  python3 netgear_script.py --host 10.0.0.2 --raw          # raw CLI output per command
  python3 netgear_script.py --host 10.0.0.2 --debug        # trace the SSH exchange to stderr
  python3 netgear_script.py --firmware 12.0.20.7 13.0.4.26 # who is NOT on these
  python3 netgear_script.py --include-raw -o out.json      # keep raw output in the JSON

Protocol:
  SSH on port 22 with the CSV's username/password (username defaults to admin),
  then an interactive vt100 shell: en, terminal length 0, show hardware,
  show environment | include Temp, show poe, exit, exit.
        """,
    )
    group = parser.add_argument_group("Netgear options")
    group.add_argument("--include-raw", action="store_true", default=False,
        help="Store each switch's raw CLI output in the results JSON (raw_version, "
             "raw_environment, raw_poe). Unlike --raw, the normal run still happens.")
    args = cli.parse_args(parser)

    if not args.debug:
        # Under --debug, cli.debug.enable() has already set up DEBUG logging.
        logging.basicConfig(level=logging.WARNING, format=LOG_FORMAT, datefmt=LOG_DATEFMT)

    print(f"{WHITE}")
    print(f"  {BOLD}Netgear M4250 Version & CPU Temp Checker{RESET}{WHITE}")
    print(f"  Queries M4250 devices for firmware version and CPU temperature over SSH")
    print(f"  Input:   {cli.input_label(args)}")
    print(f"  Output:  {'(none: --raw)' if args.raw else args.output}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    if args.firmware:
        print(f"  Filter:  showing devices not on firmware {cli.firmware_label(args.firmware)}")
    if args.debug:
        print(f"  Debug:   on (trace on stderr)")
    print(f"{RESET}")

    routers = cli.select_devices(args, load_csv, make_device)

    # --raw: dump what each switch sends back, no table / JSON
    if args.raw:
        cli.run_raw(routers, lambda d: dump_raw(d, args.timeout))
        return

    print(f"  {WHITE}Loaded {BOLD}{len(routers)}{RESET}{WHITE} device(s){RESET}\n")

    check_all_routers(
        routers,
        args.output,
        input_label=cli.input_label(args),
        include_raw=args.include_raw,
        max_workers=args.workers,
        timeout=args.timeout,
        firmware_filter=args.firmware,
    )


if __name__ == "__main__":
    main()
