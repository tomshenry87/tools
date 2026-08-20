#!/usr/bin/env python3
"""
CyberPower OR700LCDRM1U UPS SNMP Query Tool

Queries CyberPower UPS units equipped with the RMCARD205 network management
card over SNMPv2c.

MIBs used:
  - CPS-MIB (CyberPower private MIB, enterprise OID 1.3.6.1.4.1.3808)
  - MIB-II (RFC 1213) for MAC address via ifPhysAddress

Data collected per device:
  - Model name         (CPS-MIB upsBaseIdentModel)
  - Serial number      (CPS-MIB upsAdvanceIdentSerialNumber)
  - MAC address        (MIB-II ifPhysAddress.1)
  - UPS firmware       (CPS-MIB upsAdvanceIdentFirmwareRevision)
  - RMCARD firmware    (CPS-MIB upsAdvanceIdentAgentFirmwareRevision)
  - Battery status     (CPS-MIB upsBaseBatteryStatus)
  - Battery capacity % (CPS-MIB upsAdvanceBatteryCapacity)
  - Runtime remaining  (CPS-MIB upsAdvanceBatteryRunTimeRemaining)
  - Replace indicator  (CPS-MIB upsAdvanceBatteryReplaceIndicator)
  - Calibration state  (CPS-MIB runtime calibration result / date)

CSV input columns:
  host        - IP address or hostname (required)
  community   - SNMP v2c community string (optional, default: public)
  port        - UDP port (optional, default: 161)

Output:
  ups_firmware/files/results_<YYYYMMDD>_<HHMMSS>.json
  Envelope: {"query_info": {...}, "ups": [...]}

Calibration note:
  The OR700LCDRM1U uses a runtime calibration (NOT a battery self-test) to
  accurately calculate remaining runtime. CyberPower recommends running this
  once per year or after battery replacement. Reported as:
    - calibration_status: "running" | "passed" | "failed" | "never_run"
    - calibration_needed: true/false  (true if last result was >= 365 days ago
                                       or if calibration has never been run)
  This is informational only and never affects `status`.

Note on internal temperature:
  The OR700LCDRM1U does not expose upsTemperature (1.3.6.1.4.1.3808.1.1.1.10.2.0).
  That OID returns "no such name" on this hardware — it is only present on the
  OL and PR series. No temperature_c / temperature_f fields are emitted.

Dependencies:
  sudo apt install libsnmp-dev snmp-mibs-downloader python3-dev
  pip3 install easysnmp tabulate tqdm
  -- or --
  sudo apt install python3-easysnmp python3-tabulate python3-tqdm
"""

import csv
import json
import re
import sys
import os
import shutil
import argparse
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

try:
    from easysnmp import Session, EasySNMPTimeoutError, EasySNMPError
except ImportError:
    print("ERROR: 'easysnmp' is required.")
    print("       sudo apt install libsnmp-dev snmp-mibs-downloader python3-dev")
    print("       pip3 install easysnmp")
    sys.exit(1)

try:
    from tabulate import tabulate
except ImportError:
    print("ERROR: 'tabulate' is required.  pip3 install tabulate")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("ERROR: 'tqdm' is required.  pip3 install tqdm")
    sys.exit(1)

# ---------------------------------------------------------------------------
# ANSI color palette
# ---------------------------------------------------------------------------
CYAN   = "\033[96m"   # Progress bar fill — reserved, nothing else
GREEN  = "\033[92m"   # Success states
RED    = "\033[91m"   # Failure / error states
YELLOW = "\033[93m"   # Auth-error states
WHITE  = "\033[97m"   # All body text, table content, labels
BOLD   = "\033[1m"    # Section headers, label emphasis
RESET  = "\033[0m"    # Always close every colour block

# ---------------------------------------------------------------------------
# Defaults & constants
# ---------------------------------------------------------------------------
DEFAULT_CSV       = "secrets/ups_firmware.csv"
OUTPUT_DIR        = "ups_firmware/files"
DEFAULT_OUTPUT    = os.path.join(
    OUTPUT_DIR,
    f"results_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
)
DEFAULT_COMMUNITY = "public"
DEFAULT_TIMEOUT   = 10
DEFAULT_PORT      = 161
DEFAULT_WORKERS   = 5

MANUFACTURER      = "CyberPower"
PROTOCOL_LABEL    = "SNMPv2c — CPS-MIB (CyberPower) + MIB-II (RFC 1213)"

# ---------------------------------------------------------------------------
# CPS-MIB OID map  (CyberPower enterprise: 1.3.6.1.4.1.3808)
# ---------------------------------------------------------------------------
OID = {
    # Identity
    "model":              "1.3.6.1.4.1.3808.1.1.1.1.1.1.0",
    "serial":             "1.3.6.1.4.1.3808.1.1.1.1.2.3.0",
    "ups_firmware":       "1.3.6.1.4.1.3808.1.1.1.1.2.1.0",
    "agent_firmware":     "1.3.6.1.4.1.3808.1.1.1.1.2.4.0",   # upsAdvanceIdentAgentFirmwareRevision

    # Battery
    "battery_status":     "1.3.6.1.4.1.3808.1.1.1.2.1.1.0",   # 1=unknown 2=normal 3=low
    "battery_capacity":   "1.3.6.1.4.1.3808.1.1.1.2.2.1.0",   # percent
    "runtime_remaining":  "1.3.6.1.4.1.3808.1.1.1.2.2.4.0",   # centiseconds
    "replace_indicator":  "1.3.6.1.4.1.3808.1.1.1.2.2.5.0",   # 1=ok 2=replace

    # Runtime calibration
    "calibration_cmd":    "1.3.6.1.4.1.3808.1.1.1.7.2.6.0",   # 1=none 2=running 3=cancelled
    "calibration_result": "1.3.6.1.4.1.3808.1.1.1.7.2.3.0",   # 1=never 2=passed 3=failed
    "calibration_date":   "1.3.6.1.4.1.3808.1.1.1.7.2.4.0",   # mm/dd/yyyy

    # MIB-II
    "mac":                "1.3.6.1.2.1.2.2.1.6.1",             # ifPhysAddress.1
}

BATTERY_STATUS_MAP = {1: "unknown", 2: "normal", 3: "low"}
CALIBRATION_RESULT_MAP = {1: "never_run", 2: "passed", 3: "failed"}
REPLACE_MAP = {1: "ok", 2: "replace_battery"}

CALIBRATION_INTERVAL_DAYS = 365

# Error strings that indicate an SNMP authentication/community failure rather
# than a transport failure. Used only for status classification.
AUTH_ERROR_PATTERNS = [
    r"[Ww]rong community",
    r"[Bb]ad community",
    r"authorizationError",
    r"[Aa]uthentication failure",
    r"[Aa]uthorization",
    r"USM",
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


def status_icon(r: dict) -> str:
    """Return a coloured status icon string for a result dict."""
    s = r.get("status", "error")
    if s == "success":
        return f"{GREEN}\u2713 OK{RESET}{WHITE}"
    elif s == "auth_error":
        return f"{YELLOW}\u2717 AUTH ERR{RESET}{WHITE}"
    return f"{RED}\u2717 ERROR{RESET}{WHITE}"


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
    (r"[Ww]rong community",                    "Bad community"),
    (r"[Bb]ad community",                      "Bad community"),
    (r"authorizationError|[Aa]uthorization",   "Auth failed"),
    (r"[Aa]uthentication failure",             "Auth failed"),
    (r"[Nn]o such name",                       "OID not found"),
    (r"[Nn]oSuchObject|NOSUCHOBJECT",          "OID not found"),
    (r"[Nn]oSuchInstance|NOSUCHINSTANCE",      "OID not found"),
    (r"[Nn]o such (object|variable)",          "OID not found"),
    (r"[Ee]ndOfMibView|ENDOFMIBVIEW",          "OID not found"),
    (r"[Uu]DP.*timeout|SNMP.*timeout",         "SNMP timeout"),
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


def classify_status(err: str) -> str:
    """
    Map an error string to one of the two failure statuses from spec 2.5.

    NOTE: SNMPv2c has no authentication handshake — a wrong community string and
    an unreachable host both surface as a silent timeout at the transport layer.
    An agent that replies with authorizationError, or an easysnmp build that
    reports the community explicitly, is classified auth_error; everything else
    falls through to error. See the README for the full caveat.
    """
    if not err:
        return "error"
    for pat in AUTH_ERROR_PATTERNS:
        if re.search(pat, str(err)):
            return "auth_error"
    return "error"


def format_mac(raw: str) -> str:
    """
    easysnmp returns MAC as a raw byte string like '\\x00\\x0cXY...'
    or sometimes as a hex string. Normalise to XX:XX:XX:XX:XX:XX.
    """
    try:
        b = raw.encode("latin-1")
        if len(b) == 6:
            return ":".join(f"{x:02X}" for x in b)
    except Exception:
        pass
    # Try treating it as already hex-ish
    hex_only = re.sub(r'[^0-9a-fA-F]', '', raw)
    if len(hex_only) == 12:
        return ":".join(hex_only[i:i+2].upper() for i in range(0, 12, 2))
    return "N/A"


def format_runtime(centiseconds: str) -> str:
    """Convert centiseconds string to HH:MM."""
    try:
        secs = int(centiseconds) // 100
        hrs  = secs // 3600
        mins = (secs % 3600) // 60
        return f"{hrs}h {mins:02d}m"
    except Exception:
        return "N/A"


def parse_calibration_date(date_str: str):
    if not date_str or date_str in ("N/A", "01/01/0001", "00/00/0000", ""):
        return None, "N/A"
    for fmt in ("%m/%d/%Y", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            return dt, dt.strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None, date_str


def calibration_needed(result_code: int, date_str: str) -> bool:
    if result_code == 1:       # never run
        return True
    dt, _ = parse_calibration_date(date_str)
    if dt is None:
        return True
    return (datetime.now() - dt).days >= CALIBRATION_INTERVAL_DAYS


# ---------------------------------------------------------------------------
# SNMP helpers  (easysnmp)  --  PROTOCOL LOGIC, DO NOT MODIFY
# ---------------------------------------------------------------------------
def make_session(host: str, port: int, community: str,
                 timeout: int) -> Session:
    return Session(
        hostname=host,
        remote_port=port,
        community=community,
        version=2,
        timeout=timeout,
        retries=1,
        use_numeric=True,       # return raw OID strings, not MIB names
    )


def snmp_get_value(session: Session, oid: str) -> tuple:
    """
    Returns (value_string, error_string).
    value_string is None on failure.
    """
    try:
        result = session.get(oid)
        val = result.value
        if val in (None, "NOSUCHOBJECT", "NOSUCHINSTANCE", "ENDOFMIBVIEW"):
            return None, f"No such object: {oid}"
        return str(val).strip(), None
    except EasySNMPTimeoutError:
        return None, "Timed out"
    except EasySNMPError as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)


def snmp_get_int(session: Session, oid: str) -> int:
    val, err = snmp_get_value(session, oid)
    if err or val is None:
        return -1
    try:
        return int(val)
    except ValueError:
        return -1


def snmp_get_str(session: Session, oid: str) -> str:
    val, err = snmp_get_value(session, oid)
    if err or val is None:
        return "N/A"
    return val if val not in ("", "None") else "N/A"


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
            community = (
                row.get(col_map.get("community", ""), DEFAULT_COMMUNITY)
                or DEFAULT_COMMUNITY
            ).strip()
            devices.append({"host": host, "port": port, "community": community})
    if not devices:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No valid entries found in CSV.{RESET}")
        sys.exit(1)
    return devices


# ---------------------------------------------------------------------------
# Main per-device query
# ---------------------------------------------------------------------------
def query_ups(host: str, port: int, community: str,
              timeout: int = DEFAULT_TIMEOUT) -> dict:
    result = {
        "host":                  host,      # written through unmodified
        "port":                  port,
        "status":                "error",
        "manufacturer":          MANUFACTURER,
        "model":                 "N/A",
        "serial":                "N/A",
        "mac":                   "N/A",
        "firmware_version":      "N/A",
        "agent_firmware":        "N/A",
        "battery_status":        "N/A",
        "battery_capacity_pct":  None,
        "runtime_remaining_raw": None,
        "runtime_remaining":     "N/A",
        "replace_indicator":     "N/A",
        "calibration_status":    "N/A",
        "calibration_date":      "N/A",
        "calibration_needed":    None,
        "error":                 None,
        "query_timestamp":       datetime.now(timezone.utc).isoformat(),
    }

    try:
        session = make_session(host, port, community, timeout)

        # ---- Model (connectivity probe) ----
        model_val, model_err = snmp_get_value(session, OID["model"])
        if model_err:
            result["error"]  = model_err
            result["status"] = classify_status(model_err)
            return result
        result["model"] = model_val or "N/A"

        # ---- Identity ----
        result["serial"]           = snmp_get_str(session, OID["serial"])
        result["firmware_version"] = snmp_get_str(session, OID["ups_firmware"])
        result["agent_firmware"]   = snmp_get_str(session, OID["agent_firmware"])

        # ---- MAC address ----
        mac_raw, _ = snmp_get_value(session, OID["mac"])
        if mac_raw:
            result["mac"] = format_mac(mac_raw)

        # ---- Battery ----
        batt_status_int = snmp_get_int(session, OID["battery_status"])
        batt_cap_int    = snmp_get_int(session, OID["battery_capacity"])
        runtime_raw     = snmp_get_int(session, OID["runtime_remaining"])
        replace_int     = snmp_get_int(session, OID["replace_indicator"])

        result["battery_status"]        = BATTERY_STATUS_MAP.get(batt_status_int, "unknown")
        result["battery_capacity_pct"]  = batt_cap_int if batt_cap_int >= 0 else None
        result["runtime_remaining_raw"] = runtime_raw  if runtime_raw  >= 0 else None
        result["runtime_remaining"]     = (
            format_runtime(str(runtime_raw)) if runtime_raw >= 0 else "N/A"
        )
        result["replace_indicator"] = REPLACE_MAP.get(replace_int, "N/A")

        # ---- Calibration (informational only — never affects status) ----
        cal_result_int = snmp_get_int(session, OID["calibration_result"])
        cal_date_str   = snmp_get_str(session, OID["calibration_date"])
        cal_cmd_int    = snmp_get_int(session, OID["calibration_cmd"])

        result["calibration_status"] = CALIBRATION_RESULT_MAP.get(cal_result_int, "unknown")
        if cal_cmd_int == 2:
            result["calibration_status"] = "running"

        _, cal_date_display = parse_calibration_date(cal_date_str)
        result["calibration_date"]   = cal_date_display
        result["calibration_needed"] = calibration_needed(cal_result_int, cal_date_str)

        # ---- Final status ----
        # Spec 2.5: only success | auth_error | error. The device answered, so
        # this is success even where a battery needs attention — a low battery
        # or replace indicator is a fleet condition surfaced in the table and
        # metrics line, not a query failure.
        result["status"] = "success"

    except Exception as e:
        result["error"]  = str(e)
        result["status"] = classify_status(str(e))

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
            "protocol":        PROTOCOL_LABEL,
            "mode":            "SNMPv2c read (community)",
            "workers":         args.workers,
            "total":           len(results),
            "success":         ok,
            "auth_errors":     auth,
            "errors":          err,
            "elapsed_seconds": round(elapsed, 2),
        },
        "ups": results,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)


def print_results_table(results: list, output_file: str,
                        elapsed: float, workers: int):

    table_data = []
    for r in results:
        cap = r.get("battery_capacity_pct")
        cap_str = f"{cap}%" if cap is not None else "N/A"

        cal_needed = r.get("calibration_needed")
        if cal_needed is True:
            cal_flag = "YES"
        elif cal_needed is False:
            cal_flag = "No"
        else:
            cal_flag = "N/A"

        replace = r.get("replace_indicator", "N/A")
        if replace == "replace_battery":
            replace_str = "REPLACE"
        elif replace == "ok":
            replace_str = "OK"
        else:
            replace_str = "N/A"

        row = [
            status_icon(r),
            clean(r["host"]),
            clean(r["manufacturer"]),
            clean(r["model"]),
            clean(r["firmware_version"]),
            clean(r["agent_firmware"]),
            clean(r["serial"]),
            clean(r["mac"]),
            cap_str,
            clean(r["runtime_remaining"]),
            replace_str,
            cal_flag,
            clean(r["battery_status"]),
            truncate_error(r.get("error")),
        ]
        table_data.append(row)

    headers = [
        "Status", "Host", "Manufacturer", "Model", "Firmware",
        "Card FW", "Serial", "MAC",
        "Capacity", "Runtime", "Replace?", "Cal Due?",
        "Batt Status",
        "Error",
    ]

    table = tabulate(table_data, headers=headers,
                     tablefmt="pretty", stralign="left", numalign="right")

    first_line = table.split("\n")[0]
    raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw         = max(raw_width, 60)

    title = "CyberPower OR700LCDRM1U \u2014 UPS Status Query Results"
    pad   = max((bw - len(title)) // 2, 0)

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")
    for line in table.split("\n"):
        print(f"  {line}")

    total = len(results)
    ok    = sum(1 for r in results if r["status"] == "success")
    auth  = sum(1 for r in results if r["status"] == "auth_error")
    err   = sum(1 for r in results if r["status"] == "error")

    print()
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}\u2717{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )

    # Device-specific metrics line — battery capacity and replacement count
    cap_vals = [r["battery_capacity_pct"] for r in results
                if r.get("battery_capacity_pct") is not None]
    replace_count = sum(1 for r in results
                        if r.get("replace_indicator") == "replace_battery")
    if cap_vals:
        print(
            f"  {BOLD}Battery Capacity \u2014{RESET}{WHITE} "
            f"Avg: {sum(cap_vals)/len(cap_vals):.0f}%  |  "
            f"Min: {min(cap_vals)}%  |  "
            f"Max: {max(cap_vals)}%  |  "
            f"Needs replacement: {replace_count}  |  "
            f"Reported: {len(cap_vals)}/{total}"
        )
    else:
        print(f"  {BOLD}Battery Capacity \u2014{RESET}{WHITE} No data available")

    cal_due = sum(1 for r in results if r.get("calibration_needed") is True)
    cal_ok  = sum(1 for r in results if r.get("calibration_needed") is False)
    if cal_due or cal_ok:
        print(
            f"  {BOLD}Calibration \u2014{RESET}{WHITE} "
            f"Due: {cal_due}  |  Up to date: {cal_ok}  |  "
            f"Reported: {cal_due + cal_ok}/{total}"
        )
    else:
        print(f"  {BOLD}Calibration \u2014{RESET}{WHITE} No data available")

    print()
    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {output_file}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers){RESET}")
    print(f"{RESET}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description=(
            "Query CyberPower OR700LCDRM1U UPS units via SNMP (RMCARD205).\n"
            "Reports model, serial, MAC, firmware, battery %, runtime,\n"
            "and whether annual runtime calibration is due."
        ),
        epilog="""
Examples:
  python3 ups_script.py
  python3 ups_script.py -i secrets/ups_firmware.csv
  python3 ups_script.py -i ups_firmware.csv -c mySecret -w 10
  python3 ups_script.py --host 192.168.1.50
  python3 ups_script.py --host 192.168.1.50 --raw

CSV format (secrets/ups_firmware.csv):
  host,community,port
  192.168.1.50,public,161
  192.168.1.51,mySecret,161
  # Comment lines are skipped

Calibration:
  CyberPower recommends a runtime calibration once per year or after battery
  replacement. calibration_needed=true if the last recorded calibration date
  is >= 365 days ago, or if it has never been run. Informational only — it
  never changes the device status.
  To trigger from the RMCARD205 web UI:
    UPS -> Diagnostics -> Runtime Calibration -> Start
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-i", "--input",     default=DEFAULT_CSV,
        help=f"CSV file with host/community/port columns (default: {DEFAULT_CSV})")
    parser.add_argument("--host",            default=None,
        help="Query a single host instead of reading a CSV")
    parser.add_argument("-o", "--output",    default=DEFAULT_OUTPUT,
        help=f"Output JSON file (default: timestamped in {OUTPUT_DIR})")
    parser.add_argument("-c", "--community", default=DEFAULT_COMMUNITY,
        help=f"SNMP community string override (default: {DEFAULT_COMMUNITY})")
    parser.add_argument("-t", "--timeout",   type=int, default=DEFAULT_TIMEOUT,
        help=f"SNMP timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-p", "--port",      type=int, default=DEFAULT_PORT,
        help=f"UDP port for --host mode (default: {DEFAULT_PORT})")
    parser.add_argument("-w", "--workers",   type=int, default=DEFAULT_WORKERS,
        help=f"Concurrent workers (default: {DEFAULT_WORKERS})")
    parser.add_argument("--raw",             action="store_true", default=False,
        help="With --host: dump all raw SNMP OID values and exit")

    args = parser.parse_args()

    term_width = get_terminal_width()

    # -----------------------------------------------------------------------
    # Header block
    # -----------------------------------------------------------------------
    input_display = args.host if args.host else args.input
    print(f"{WHITE}")
    print(f"  {BOLD}CyberPower OR700LCDRM1U UPS SNMP Query Tool{RESET}{WHITE}")
    print(f"  Queries CyberPower UPS units with RMCARD205 cards over SNMP")
    print(f"  Input:   {input_display}")
    print(f"  Output:  {args.output}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    print(f"  Mode:    SNMPv2c read (community)")
    print(f"{RESET}")

    # -----------------------------------------------------------------------
    # --host --raw dump
    # -----------------------------------------------------------------------
    if args.host and args.raw:
        print(f"{WHITE}Raw SNMP OID dump for {args.host}:{args.port}{RESET}\n")
        session = make_session(args.host, args.port, args.community, args.timeout)
        for name, oid in OID.items():
            val, err = snmp_get_value(session, oid)
            if err:
                print(f"  {RED}{name:<25}{RESET}{WHITE} {oid}  =>  ERROR: {err}{RESET}")
            else:
                print(f"  {GREEN}{name:<25}{RESET}{WHITE} {oid}  =>  {val!r}{RESET}")
        return

    # -----------------------------------------------------------------------
    # Build device list
    # -----------------------------------------------------------------------
    if args.host:
        devices = [{"host": args.host, "port": args.port, "community": args.community}]
    else:
        devices = load_csv(args.input)
        if args.community != DEFAULT_COMMUNITY:
            for d in devices:
                d["community"] = args.community

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
        return query_ups(d["host"], d["port"], d["community"], timeout=args.timeout)

    start_time = time.monotonic()

    with tqdm(total=len(devices), bar_format=bar_fmt, ncols=term_width,
              dynamic_ncols=True, file=sys.stderr, leave=True) as pbar:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(do_query, d): d for d in devices}
            for fut in as_completed(futures):
                with results_lock:
                    results.append(fut.result())
                with active_lock:
                    pbar.set_postfix_str(latest_host["value"], refresh=False)
                pbar.update(1)

    elapsed = time.monotonic() - start_time
    pbar.set_postfix_str(
        f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s", refresh=True
    )

    # Re-sort to match original input order
    host_order = {d["host"]: i for i, d in enumerate(devices)}
    results.sort(key=lambda r: host_order.get(r["host"], 0))

    print_results_table(results, args.output, elapsed, args.workers)
    save_results_json(results, args.output, args, elapsed)


if __name__ == "__main__":
    main()
