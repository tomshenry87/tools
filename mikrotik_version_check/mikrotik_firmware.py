#!/usr/bin/env python3
"""
MikroTik Router Firmware Checker
==================================
Reads router credentials from routers.csv (default), connects via SSH,
queries /system/package/print for RouterOS version,
/system/routerboard/print for board model and current firmware, and
/system/health/print for PoE consumption and board temperature,
writes results to results.json (default), and prints a summary table.

Usage:
    python3 mikrotik_firmware.py
    python3 mikrotik_firmware.py --verbose
    python3 mikrotik_firmware.py --csv other_routers.csv --output other_results.json
    python3 mikrotik_firmware.py --workers 10 --timeout 20
    python3 mikrotik_firmware.py --include-raw --verbose
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
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
#  ANSI color palette
# ──────────────────────────────────────────────
CYAN   = "\033[96m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
WHITE  = "\033[97m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ──────────────────────────────────────────────
#  Logging — plain, no colors
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("mikrotik_firmware")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Per-model health field overrides
#  Keys are matched as case-insensitive prefixes
#  against the model string from routerboard/print.
#  Add new models here — no other changes needed.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MODEL_HEALTH_MAP: dict[str, dict] = {
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
#  CSV loader
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def load_csv(csv_path: str) -> list[dict]:
    devices: list[dict] = []
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
        host_key = (
            col_map.get("host") or col_map.get("hostname")
            or col_map.get("ip") or col_map.get("address")
        )
        if not host_key:
            print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} CSV needs a 'host' column.{RESET}")
            sys.exit(1)
        for row in reader:
            host = row.get(host_key, "").strip()
            if not host or host.startswith("#"):
                continue
            try:
                port = int(row.get(col_map.get("port", ""), "") or 22)
            except ValueError:
                port = 22
            devices.append({
                "host":     host,
                "username": row.get(col_map.get("username", ""), "").strip() or "admin",
                "password": row.get(col_map.get("password", ""), "").strip(),
                "port":     port,
            })
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Table value helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def clean(val) -> str:
    s = str(val) if val is not None else "N/A"
    if s in ("None", "-1", ""):
        return "N/A"
    if s.startswith("ERROR") or s in ("Not available", "AUTH ERROR", "See diagnostic"):
        return "N/A"
    return s


def truncate_error(err, max_len: int = 30) -> str:
    if not err:
        return ""
    s = str(err)
    for pat, label in [
        # MikroTik / SSH-specific patterns first
        (r"[Aa]uthentication failed",     "Auth failed"),
        (r"[Aa]uthentication required",   "Auth required"),
        (r"[Nn]o matching .* found",      "SSH negotiation"),
        (r"[Ee]mpty output",              "Empty output"),
        (r"[Cc]ould not parse",           "Parse error"),
        # Generic network patterns
        (r"[Cc]onnection timed out",      "Timed out"),
        (r"[Cc]onnection refused",        "Conn refused"),
        (r"[Nn]o response .* timeout",    "No response"),
        (r"[Nn]o route to host",          "No route"),
        (r"[Nn]etwork is unreachable",    "Net unreachable"),
        (r"[Nn]ame or service not known", "DNS failed"),
        (r"[Nn]etwork error",             "Network error"),
        (r"[Mm]alformed",                 "Bad response"),
    ]:
        if re.search(pat, s):
            return label
    s = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', '', s)
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


def celsius_to_fahrenheit(c: float) -> float:
    return round(c * 9 / 5 + 32, 1)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SSH: get command output (tries TWO methods)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def get_command_output(client: paramiko.SSHClient, command: str) -> str:
    try:
        _, stdout, _ = client.exec_command(command, timeout=15)
        output = stdout.read().decode("utf-8", errors="replace")
        if output.strip():
            return output
    except Exception:
        pass

    try:
        channel = client.invoke_shell(width=200, height=50)
        time.sleep(2)
        if channel.recv_ready():
            channel.recv(65535)

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
        return raw.decode("utf-8", errors="replace")
    except Exception:
        pass

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
        m = re.match(
            r"^\s*\d+\s+([\w\-]+)\s+([\d.]+)\s*(\S*)",
            stripped,
        )
        if m:
            name, value, _ = m.group(1).lower(), m.group(2), m.group(3)
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
    port: int = 22,
    timeout: int = 15,
    include_raw: bool = False,
) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    result: dict = {
        "host":                  host,
        "port":                  port,
        "query_timestamp":       ts,
        "status":                "error",
        "model":                 None,
        "routeros_version":      None,
        "current_firmware":      None,
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

        # Query 1: packages
        raw_pkg = get_command_output(client, "/system/package/print")
        if include_raw:
            result["raw_packages"] = raw_pkg

        if not raw_pkg.strip():
            result["error"] = "Router returned empty output"
            return result

        packages = parse_packages(raw_pkg)
        result["packages"] = packages

        if packages:
            result["routeros_version"] = get_routeros_version(packages)
            result["status"] = "success"
        else:
            result["error"] = "Could not parse any packages from output"

        # Query 2: routerboard (best-effort)
        raw_rb = get_command_output(client, "/system/routerboard/print")
        if include_raw:
            result["raw_routerboard"] = raw_rb
        if raw_rb.strip():
            rb = parse_routerboard(raw_rb)
            result["model"]            = rb["model"]
            result["current_firmware"] = rb["current_firmware"]

        # Query 3: health (best-effort)
        raw_health = get_command_output(client, "/system/health/print")
        if include_raw:
            result["raw_health"] = raw_health
        if raw_health.strip():
            hf = get_health_fields(result.get("model"))
            health = parse_health(raw_health, temp_field=hf["temp_field"], poe_field=hf["poe_field"])
            result["poe_out_consumption_w"] = health["poe_out_consumption_w"]
            result["board_temperature1_c"]  = health["board_temperature1_c"]
            result["board_temperature1_f"]  = health["board_temperature1_f"]

    except paramiko.AuthenticationException:
        result["status"] = "auth_error"
        result["error"]  = "Authentication failed"
    except (paramiko.SSHException, socket.error) as exc:
        result["error"] = f"SSH/network error: {exc}"
    except Exception as exc:
        result["error"] = f"Unexpected error: {exc}"
    finally:
        client.close()

    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Print results table
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def print_results_table(results: list[dict], elapsed: float, workers: int, output_path: Path) -> None:
    headers = [
        "Status", "Host", "Model", "RouterOS Version",
        "Firmware", "Total PoE (W)", "Temp (°F)", "Error",
    ]

    rows: list[list] = []
    for r in results:
        poe   = r.get("poe_out_consumption_w")
        temp  = r.get("board_temperature1_f")

        rows.append([
            status_icon(r),
            f"{WHITE}{clean(r['host'])}{RESET}",
            f"{WHITE}{clean(r.get('model'))}{RESET}",
            f"{WHITE}{clean(r.get('routeros_version'))}{RESET}",
            f"{WHITE}{clean(r.get('current_firmware'))}{RESET}",
            f"{WHITE}{clean(f'{poe} W' if poe is not None else None)}{RESET}",
            f"{WHITE}{clean(f'{temp}°F' if temp is not None else None)}{RESET}",
            f"{WHITE}{truncate_error(r.get('error'))}{RESET}",
        ])

    table = tabulate(rows, headers=headers, tablefmt="pretty", stralign="left", numalign="right")

    first_line = table.split("\n")[0]
    raw_width = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw = max(raw_width, 60)

    title = "MikroTik RouterOS Query Results"
    pad = (bw - len(title)) // 2

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")
    for line in table.split("\n"):
        print(f"  {line}")

    total     = len(results)
    ok        = sum(1 for r in results if r["status"] == "success")
    auth_errs = sum(1 for r in results if r["status"] == "auth_error")
    failed    = sum(1 for r in results if r["status"] == "error")

    print()
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}\u2717{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth_errs}  |  "
        f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {failed}"
    )

    # RouterOS version breakdown
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
            f"  {BOLD}RouterOS Versions{RESET}{WHITE} \u2014 "
            f"{breakdown}  |  Reported: {sum(version_counts.values())}/{total}"
        )
    else:
        print(f"  {BOLD}RouterOS Versions{RESET}{WHITE} \u2014 No data available")

    # PoE summary
    poe_vals = [
        r["poe_out_consumption_w"]
        for r in results
        if r.get("poe_out_consumption_w") is not None
    ]
    if poe_vals:
        print(
            f"  {BOLD}Total PoE (W){RESET}{WHITE} \u2014 "
            f"Avg: {sum(poe_vals)/len(poe_vals):.1f}  |  "
            f"Min: {min(poe_vals)}  |  "
            f"Max: {max(poe_vals)}  |  "
            f"Reported: {len(poe_vals)}/{total}"
        )
    else:
        print(f"  {BOLD}Total PoE (W){RESET}{WHITE} \u2014 No data available")

    # Temperature summary
    temp_vals = [
        r["board_temperature1_f"]
        for r in results
        if r.get("board_temperature1_f") is not None
    ]
    if temp_vals:
        print(
            f"  {BOLD}Board Temp (°F){RESET}{WHITE} \u2014 "
            f"Avg: {sum(temp_vals)/len(temp_vals):.1f}  |  "
            f"Min: {min(temp_vals)}  |  "
            f"Max: {max(temp_vals)}  |  "
            f"Reported: {len(temp_vals)}/{total}"
        )
    else:
        print(f"  {BOLD}Board Temp (°F){RESET}{WHITE} \u2014 No data available")

    print()
    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {output_path}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers){RESET}")
    print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Check ALL routers (concurrent)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_all_routers(
    routers: list[dict],
    output_path: Path,
    workers: int = 5,
    timeout: int = 15,
    include_raw: bool = False,
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

    ok        = sum(1 for r in all_results if r["status"] == "success")
    auth_errs = sum(1 for r in all_results if r["status"] == "auth_error")
    errors    = sum(1 for r in all_results if r["status"] == "error")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output = {
        "query_info": {
            "csv_file":        str(output_path.parent / "routers.csv"),
            "timestamp":       start_ts.isoformat(),
            "protocol":        "SSH / RouterOS CLI",
            "mode":            "package version query",
            "workers":         workers,
            "total":           len(all_results),
            "success":         ok,
            "auth_errors":     auth_errs,
            "errors":          errors,
            "elapsed_seconds": round(elapsed, 2),
        },
        "routers": all_results,
    }
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, ensure_ascii=False)

    print_results_table(all_results, elapsed, workers, output_path)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main() -> None:
    p = argparse.ArgumentParser(
        description="Check MikroTik router firmware and package versions via SSH.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--csv",         type=Path, default=Path("routers.csv"),   help="Input CSV (default: routers.csv)")
    p.add_argument("--output",      type=Path, default=Path("results.json"),  help="Output JSON (default: results.json)")
    p.add_argument("--workers",     type=int,  default=5,                     help="Concurrent SSH workers (default: 5)")
    p.add_argument("--timeout",     type=int,  default=15,                    help="Per-router timeout in seconds (default: 15)")
    p.add_argument("--verbose",     action="store_true",                      help="Enable DEBUG logging")
    p.add_argument("--include-raw", action="store_true",                      help="Include raw SSH output in results.json")
    args = p.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print(f"{WHITE}")
    print(f"  {BOLD}MikroTik RouterOS Firmware Checker{RESET}{WHITE}")
    print(f"  Connects via SSH and queries package versions, board firmware, and health")
    print(f"  Input:   {args.csv}")
    print(f"  Output:  {args.output}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    print(f"{RESET}")

    routers = load_csv(str(args.csv))
    if not routers:
        print(f"  {WHITE}{BOLD}Error:{RESET}{WHITE} No routers found in {args.csv}{RESET}")
        sys.exit(1)

    print(f"  {WHITE}Loaded {BOLD}{len(routers)}{RESET}{WHITE} router(s){RESET}\n")

    check_all_routers(
        routers,
        args.output,
        workers=args.workers,
        timeout=args.timeout,
        include_raw=args.include_raw,
    )


if __name__ == "__main__":
    main()
