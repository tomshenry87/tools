#!/usr/bin/env python3
"""
CyberPower OR700LCDRM1U UPS SNMP Query Tool

Uses SNMP to query CyberPower UPS units equipped with the RMCARD205
network management card.

MIBs used:
  - CPS-MIB (CyberPower private MIB, enterprise OID 1.3.6.1.4.1.3808)
  - MIB-II (RFC 1213) for MAC address via ifPhysAddress

Data collected per device:
  - Model name         (CPS-MIB upsBaseIdentModel)
  - Serial number      (CPS-MIB upsAdvanceIdentSerialNumber)
  - MAC address        (MIB-II ifPhysAddress.1)
  - UPS firmware       (CPS-MIB upsBaseIdentFirmwareVersion)
  - RMCARD firmware    (CPS-MIB upsAdvanceIdentAgentFirmwareVersion)
  - Battery capacity % (CPS-MIB upsAdvanceBatteryCapacity)
  - Runtime remaining  (CPS-MIB upsAdvanceBatteryRunTimeRemaining)
  - Battery status     (CPS-MIB upsBaseBatteryStatus)
  - Calibration status (CPS-MIB upsAdvanceBatteryRunTimeCalibration)
  - Last calibration   (derived from calibration result OID)

CSV input columns:
  host        - IP address or hostname (required)
  community   - SNMP v1/v2c community string (optional, default: public)
  port        - UDP port (optional, default: 161)

Output:
  JSON file with query_info metadata and a "ups" array of per-device results.

Calibration note:
  The OR700LCDRM1U uses a runtime calibration (NOT a battery self-test) to
  accurately calculate remaining runtime. CyberPower recommends running this
  once per year or after battery replacement. The script reports:
    - calibration_status: "running" | "done" | "failed" | "unknown"
    - calibration_needed: true/false  (true if last result was >365 days ago
                                       or if calibration has never been run)
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
    from pysnmp.hlapi import (
        getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity
    )
    from pysnmp.proto.errind import RequestTimedOut, NetworkError
except ImportError:
    print("ERROR: 'pysnmp' library is required. Install with: pip install pysnmp")
    sys.exit(1)

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

# ---------------------------------------------------------------------------
# CPS-MIB OID map  (CyberPower enterprise: 1.3.6.1.4.1.3808)
# ---------------------------------------------------------------------------
OID = {
    # Identity
    "model":              "1.3.6.1.4.1.3808.1.1.1.1.1.1.0",   # upsBaseIdentModel
    "serial":             "1.3.6.1.4.1.3808.1.1.1.1.2.3.0",   # upsAdvanceIdentSerialNumber
    "ups_firmware":       "1.3.6.1.4.1.3808.1.1.1.1.2.1.0",   # upsBaseIdentFirmwareVersion
    "agent_firmware":     "1.3.6.1.4.1.3808.1.1.1.1.1.4.0",   # upsAdvanceIdentAgentFirmwareVersion

    # Battery
    "battery_status":     "1.3.6.1.4.1.3808.1.1.1.2.1.1.0",   # upsBaseBatteryStatus (1=unknown,2=normal,3=low)
    "battery_capacity":   "1.3.6.1.4.1.3808.1.1.1.2.2.1.0",   # upsAdvanceBatteryCapacity (%)
    "runtime_remaining":  "1.3.6.1.4.1.3808.1.1.1.2.2.4.0",   # upsAdvanceBatteryRunTimeRemaining (timeticks)
    "replace_indicator":  "1.3.6.1.4.1.3808.1.1.1.2.2.5.0",   # upsAdvanceBatteryReplaceIndicator (1=ok,2=replace)

    # Runtime calibration
    # 1=noCalibration  2=performCalibration  3=calibrationCancelled
    "calibration_cmd":    "1.3.6.1.4.1.3808.1.1.1.7.2.6.0",   # upsAdvanceBatteryRunTimeCalibration
    # 1=noTestsInitiated 2=calibrationSucceeded 3=calibrationFailed
    "calibration_result": "1.3.6.1.4.1.3808.1.1.1.7.2.3.0",   # upsAdvanceBatteryRunTimeCalibrationResult
    # Date of last calibration  mm/dd/yyyy
    "calibration_date":   "1.3.6.1.4.1.3808.1.1.1.7.2.4.0",   # upsAdvanceBatteryRunTimeCalibrationDate

    # MIB-II — MAC address
    "mac_address":        "1.3.6.1.2.1.2.2.1.6.1",             # ifPhysAddress.1
}

BATTERY_STATUS_MAP = {
    1: "unknown",
    2: "normal",
    3: "low",
}

CALIBRATION_RESULT_MAP = {
    1: "never_run",
    2: "passed",
    3: "failed",
}

REPLACE_MAP = {
    1: "ok",
    2: "replace_battery",
}

# Days threshold — flag calibration_needed if last run was more than this long ago
CALIBRATION_INTERVAL_DAYS = 365


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def get_terminal_width() -> int:
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 120


def clean(val) -> str:
    s = str(val) if val is not None else "N/A"
    if s in ("None", "-1", "", "0"):
        return "N/A"
    if s.startswith("ERROR") or s in ("Not available", "AUTH ERROR", "See diagnostic"):
        return "N/A"
    return s


def truncate_error(err, max_len: int = 30) -> str:
    if not err:
        return ""
    s = str(err)
    for pat, label in [
        (r"[Cc]onnection timed out",          "Timed out"),
        (r"[Tt]imed.?[Oo]ut|timed out",       "Timed out"),
        (r"[Cc]onnection refused",             "Conn refused"),
        (r"[Nn]o response",                    "No response"),
        (r"[Nn]o route to host",               "No route"),
        (r"[Nn]etwork is unreachable",         "Net unreachable"),
        (r"[Nn]ame or service not known",      "DNS failed"),
        (r"[Nn]etwork error",                  "Network error"),
        (r"[Uu]DP.*timeout|SNMP.*timeout",     "SNMP timeout"),
        (r"[Nn]o SNMP response",               "No SNMP response"),
        (r"[Ww]rong community",                "Bad community"),
        (r"[Nn]o such (object|variable)",      "OID not found"),
        (r"[Nn]ot a.*device",                  "Not supported"),
        (r"[Mm]alformed",                      "Bad response"),
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
    elif s == "warn":
        return f"{YELLOW}\u26a0 WARN{RESET}{WHITE}"
    return f"{RED}\u2717 ERROR{RESET}{WHITE}"


def format_mac(raw_bytes) -> str:
    """Convert pysnmp OctetString bytes to XX:XX:XX:XX:XX:XX notation."""
    try:
        if hasattr(raw_bytes, 'asOctets'):
            octets = raw_bytes.asOctets()
        else:
            octets = bytes(raw_bytes)
        if len(octets) == 6:
            return ":".join(f"{b:02X}" for b in octets)
    except Exception:
        pass
    return "N/A"


def format_runtime(timeticks) -> str:
    """Convert centiseconds (SNMP TimeTicks) to human-readable HH:MM."""
    try:
        secs = int(timeticks) // 100
        mins = secs // 60
        hrs  = mins // 60
        mins = mins % 60
        return f"{hrs}h {mins:02d}m"
    except Exception:
        return "N/A"


def parse_calibration_date(date_str: str):
    """
    Parse mm/dd/yyyy calibration date.
    Returns (datetime, str_display) or (None, "N/A").
    """
    if not date_str or date_str in ("N/A", "01/01/0001", "00/00/0000"):
        return None, "N/A"
    for fmt in ("%m/%d/%Y", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            return dt, dt.strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None, date_str


def calibration_needed(result_code: int, date_str: str) -> bool:
    """
    Returns True if annual calibration is overdue or has never been run.
    """
    if result_code == 1:   # never run
        return True
    dt, _ = parse_calibration_date(date_str)
    if dt is None:
        return True        # no date recorded — treat as needed
    age_days = (datetime.now() - dt).days
    return age_days >= CALIBRATION_INTERVAL_DAYS


# ---------------------------------------------------------------------------
# SNMP helpers
# ---------------------------------------------------------------------------
def snmp_get(host: str, port: int, community: str,
             oid: str, timeout: int) -> tuple:
    """
    Single SNMP GET.  Returns (value, error_string).
    value is the pysnmp object on success, None on failure.
    """
    try:
        error_indication, error_status, error_index, var_binds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),   # mpModel=1 => SNMPv2c
                UdpTransportTarget((host, port), timeout=timeout, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
        )
        if error_indication:
            return None, str(error_indication)
        if error_status:
            return None, f"{error_status.prettyPrint()} at {error_index}"
        for _, val in var_binds:
            return val, None
        return None, "No value returned"
    except Exception as e:
        return None, str(e)


def snmp_get_str(host, port, community, oid, timeout) -> str:
    val, err = snmp_get(host, port, community, oid, timeout)
    if err or val is None:
        return "N/A"
    s = str(val).strip()
    return s if s not in ("", "None") else "N/A"


def snmp_get_int(host, port, community, oid, timeout) -> int:
    val, err = snmp_get(host, port, community, oid, timeout)
    if err or val is None:
        return -1
    try:
        return int(val)
    except Exception:
        return -1


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
# Main query function
# ---------------------------------------------------------------------------
def query_ups(host: str, port: int, community: str,
              timeout: int = DEFAULT_TIMEOUT) -> dict:
    result = {
        "host":                  host,
        "port":                  port,
        "community":             community,
        "status":                "error",
        "model":                 "N/A",
        "serial":                "N/A",
        "mac_address":           "N/A",
        "ups_firmware":          "N/A",
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

    # ---- Model (also acts as a connectivity probe) ----
    model_val, model_err = snmp_get(host, port, community,
                                    OID["model"], timeout)
    if model_err:
        result["error"] = model_err
        return result

    result["model"] = str(model_val).strip() or "N/A"

    # ---- Identity ----
    result["serial"]        = snmp_get_str(host, port, community, OID["serial"],       timeout)
    result["ups_firmware"]  = snmp_get_str(host, port, community, OID["ups_firmware"], timeout)
    result["agent_firmware"]= snmp_get_str(host, port, community, OID["agent_firmware"],timeout)

    # ---- MAC address (MIB-II ifPhysAddress.1) ----
    mac_val, _ = snmp_get(host, port, community, OID["mac_address"], timeout)
    if mac_val is not None:
        result["mac_address"] = format_mac(mac_val)

    # ---- Battery ----
    batt_status_int = snmp_get_int(host, port, community, OID["battery_status"],  timeout)
    batt_cap_int    = snmp_get_int(host, port, community, OID["battery_capacity"], timeout)
    runtime_raw     = snmp_get_int(host, port, community, OID["runtime_remaining"],timeout)
    replace_int     = snmp_get_int(host, port, community, OID["replace_indicator"],timeout)

    result["battery_status"]       = BATTERY_STATUS_MAP.get(batt_status_int, "unknown")
    result["battery_capacity_pct"] = batt_cap_int if batt_cap_int >= 0 else None
    result["runtime_remaining_raw"]= runtime_raw  if runtime_raw  >= 0 else None
    result["runtime_remaining"]    = format_runtime(runtime_raw) if runtime_raw >= 0 else "N/A"
    result["replace_indicator"]    = REPLACE_MAP.get(replace_int, "N/A")

    # ---- Calibration ----
    cal_result_int = snmp_get_int(host, port, community, OID["calibration_result"], timeout)
    cal_date_str   = snmp_get_str(host, port, community, OID["calibration_date"],   timeout)
    cal_cmd_int    = snmp_get_int(host, port, community, OID["calibration_cmd"],     timeout)

    result["calibration_status"] = CALIBRATION_RESULT_MAP.get(cal_result_int, "unknown")

    # If a calibration is currently running, override
    if cal_cmd_int == 2:
        result["calibration_status"] = "running"

    _, cal_date_display = parse_calibration_date(cal_date_str)
    result["calibration_date"]   = cal_date_display
    result["calibration_needed"] = calibration_needed(cal_result_int, cal_date_str)

    # ---- Final status ----
    # Warn if battery needs replacing or calibration is overdue
    if (result["replace_indicator"] == "replace_battery"
            or result["calibration_needed"]
            or result["battery_status"] == "low"):
        result["status"] = "warn"
    else:
        result["status"] = "success"

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def save_results_json(results: list, filepath: str, args, elapsed: float):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    ok   = sum(1 for r in results if r["status"] == "success")
    warn = sum(1 for r in results if r["status"] == "warn")
    err  = sum(1 for r in results if r["status"] == "error")
    output = {
        "query_info": {
            "csv_file":        str(Path(args.input).resolve()),
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "protocol":        "SNMP v2c — CPS-MIB (CyberPower) + MIB-II (RFC 1213)",
            "community":       args.community,
            "workers":         args.workers,
            "total":           len(results),
            "success":         ok,
            "warnings":        warn,
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
            cal_flag = f"{YELLOW}YES{RESET}{WHITE}"
        elif cal_needed is False:
            cal_flag = f"{GREEN}No{RESET}{WHITE}"
        else:
            cal_flag = "N/A"

        replace = r.get("replace_indicator", "N/A")
        if replace == "replace_battery":
            replace_str = f"{RED}REPLACE{RESET}{WHITE}"
        elif replace == "ok":
            replace_str = f"{GREEN}OK{RESET}{WHITE}"
        else:
            replace_str = "N/A"

        row = [
            status_icon(r),
            clean(r["host"]),
            clean(r["model"]),
            clean(r["serial"]),
            clean(r["mac_address"]),
            clean(r["ups_firmware"]),
            clean(r["agent_firmware"]),
            clean(r["battery_status"]),
            cap_str,
            clean(r["runtime_remaining"]),
            replace_str,
            clean(r["calibration_status"]),
            clean(r["calibration_date"]),
            cal_flag,
            truncate_error(r.get("error")),
        ]
        table_data.append(row)

    headers = [
        "Status", "Host", "Model", "Serial", "MAC Address",
        "UPS FW", "Card FW",
        "Batt Status", "Capacity", "Runtime",
        "Replace?", "Cal Status", "Last Cal", "Cal Due?",
        "Error",
    ]

    table = tabulate(table_data, headers=headers,
                     tablefmt="pretty", stralign="left", numalign="right")

    first_line = table.split("\n")[0]
    raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw         = max(raw_width, 80)

    title = "CyberPower OR700LCDRM1U — UPS Status Query Results"
    pad   = max((bw - len(title)) // 2, 0)

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")
    for line in table.split("\n"):
        print(f"  {line}")

    total = len(results)
    ok    = sum(1 for r in results if r["status"] == "success")
    warn  = sum(1 for r in results if r["status"] == "warn")
    err   = sum(1 for r in results if r["status"] == "error")

    print()
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}\u26a0{RESET}{WHITE} {BOLD}Warnings:{RESET}{WHITE} {warn}  |  "
        f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )

    # Battery capacity metrics
    cap_vals = [r["battery_capacity_pct"] for r in results
                if r.get("battery_capacity_pct") is not None]
    if cap_vals:
        print(
            f"  {BOLD}Battery Capacity \u2014{RESET}{WHITE} "
            f"Avg: {sum(cap_vals)/len(cap_vals):.0f}%  |  "
            f"Min: {min(cap_vals)}%  |  "
            f"Max: {max(cap_vals)}%  |  "
            f"Reported: {len(cap_vals)}/{total}"
        )
    else:
        print(f"  {BOLD}Battery Capacity \u2014{RESET}{WHITE} No data available")

    # Calibration summary
    cal_due   = sum(1 for r in results if r.get("calibration_needed") is True)
    cal_ok    = sum(1 for r in results if r.get("calibration_needed") is False)
    if cal_due:
        print(
            f"  {BOLD}Calibration \u2014{RESET}{WHITE} "
            f"{YELLOW}{cal_due} device(s) due for annual runtime calibration{RESET}{WHITE}  |  "
            f"{GREEN}{cal_ok} up to date{RESET}{WHITE}"
        )
    else:
        print(f"  {BOLD}Calibration \u2014{RESET}{WHITE} All devices up to date")

    print()
    print(f"  {BOLD}Results saved:{RESET}{WHITE} {output_file}")
    print(f"  {BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers)")
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
  python cyberpower_ups_query.py
  python cyberpower_ups_query.py -i secrets/ups_firmware.csv
  python cyberpower_ups_query.py -i ups_firmware.csv -c mySecret -w 10
  python cyberpower_ups_query.py --host 192.168.1.50
  python cyberpower_ups_query.py --host 192.168.1.50 --raw

CSV format (ups_firmware.csv):
  host,community,port
  192.168.1.50,public,161
  192.168.1.51,mySecret,161
  # Comment lines are skipped

Calibration:
  CyberPower recommends a runtime calibration once per year or after battery
  replacement. The script flags 'calibration_needed: true' if the last
  recorded calibration date is >= 365 days ago, or if it has never been run.
  To trigger a calibration from the RMCARD205 web UI:
    UPS -> Diagnostics -> Runtime Calibration -> Start
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-i", "--input",     default=DEFAULT_CSV,
        help=f"CSV file with host/community/port columns (default: {DEFAULT_CSV})")
    parser.add_argument("--host",            default=None,
        help="Query a single host instead of reading a CSV")
    parser.add_argument("-o", "--output",    default=DEFAULT_OUTPUT,
        help=f"Output JSON file (default: timestamped file in {OUTPUT_DIR})")
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
    print(f"  {BOLD}CyberPower OR700LCDRM1U — UPS SNMP Query Tool{RESET}{WHITE}")
    print(f"  Queries UPS status via SNMP using CPS-MIB and MIB-II.")
    print(f"  Input:     {input_display}")
    print(f"  Output:    {args.output}")
    print(f"  Workers:   {args.workers}")
    print(f"  Timeout:   {args.timeout}s")
    print(f"  Community: {args.community}")
    print(f"  Protocol:  SNMPv2c — CPS-MIB + MIB-II (RFC 1213)")
    print(f"{RESET}")

    # -----------------------------------------------------------------------
    # --host --raw dump
    # -----------------------------------------------------------------------
    if args.host and args.raw:
        print(f"{WHITE}Raw SNMP OID values for {args.host}:{args.port}{RESET}\n")
        community = args.community
        for name, oid in OID.items():
            val, err = snmp_get(args.host, args.port, community, oid, args.timeout)
            if err:
                print(f"  {RED}{name:<25}{RESET} {oid}  =>  ERROR: {err}")
            else:
                print(f"  {GREEN}{name:<25}{RESET} {oid}  =>  {val!r}")
        return

    # -----------------------------------------------------------------------
    # Build device list
    # -----------------------------------------------------------------------
    if args.host:
        devices = [{"host": args.host, "port": args.port, "community": args.community}]
    else:
        devices = load_csv(args.input)
        # CLI --community overrides CSV community when explicitly passed
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
