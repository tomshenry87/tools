#!/usr/bin/env python3
"""
Sony Bravia BZ40H/BZ40L Firmware Version Query Tool

Uses the Sony BRAVIA REST API (JSON-RPC) documented in:
  - Sony BRAVIA Professional Display IP Control API
  - Endpoint: /sony/system
  - Method: getSystemInformation (v1.7 with fallback to v1.4, v1.0)
  - Method: getInterfaceInformation (v1.0)
  - Method: getPowerSavingMode (v1.0)

Supports two authentication modes:
  - None: No authentication (X-Auth-PSK header omitted)
  - PSK:  Pre-Shared Key via X-Auth-PSK header
  - Fallback: Retries with PSK "1234" on HTTP 403 when no PSK is configured
"""

import csv
import json
import re
import sys
import os
import shutil
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library is required. Install with: pip install requests")
    sys.exit(1)

from requests.exceptions import Timeout, ConnectionError as RequestsConnectionError

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

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
DEFAULT_CSV      = "displays.csv"
DEFAULT_OUTPUT   = "results.json"
DEFAULT_PSK      = None
DEFAULT_TIMEOUT  = 10
DEFAULT_PORT     = 80
DEFAULT_WORKERS  = 5
API_ENDPOINT     = "/sony/system"
FALLBACK_PSK     = "1234"

SYSTEM_INFO_VERSIONS = ["1.7", "1.4", "1.0"]

POWER_SAVING_LABELS = {
    "off":        "Off (disabled)",
    "low":        "Low",
    "high":       "High",
    "pictureOff": "Picture Off (panel off)",
}


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


def truncate_error(err, max_len: int = 30) -> str:
    """Map verbose exception messages to short readable labels."""
    if not err:
        return ""
    s = str(err)
    for pat, label in [
        (r"[Cc]onnection timed out",          "Timed out"),
        (r"[Cc]onnection refused",             "Conn refused"),
        (r"[Nn]o response .* timeout",         "No response"),
        (r"[Nn]o route to host",               "No route"),
        (r"[Nn]etwork is unreachable",         "Net unreachable"),
        (r"[Nn]ame or service not known",      "DNS failed"),
        (r"[Nn]etwork error",                  "Network error"),
        (r"[Aa]uthentication required",        "Auth required"),
        (r"HTTP 403",                          "Auth failed"),
        (r"HTTP 404",                          "IP ctrl disabled"),
        (r"[Aa]ll API versions failed",        "API unsupported"),
        (r"[Nn]ot a .* device",               "Not supported"),
        (r"[Mm]alformed",                      "Bad response"),
    ]:
        if re.search(pat, s):
            return label
    s = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', '', s)
    s = re.sub(r'\[Errno\s*-?\d+\]\s*', '', s)
    s = re.sub(r'\s+', ' ', s).strip(': ')
    return (s[:max_len - 3] + "...") if len(s) > max_len else (s or "Error")


def status_icon(r: dict) -> str:
    """Return a coloured status icon string for a result dict."""
    s = r.get("status", "error")
    if s == "success":
        return f"{GREEN}\u2713 OK{RESET}{WHITE}"
    elif s == "auth_error":
        return f"{YELLOW}\u2717 AUTH ERR{RESET}{WHITE}"
    return f"{RED}\u2717 ERROR{RESET}{WHITE}"


def format_power_saving_mode(mode: str) -> str:
    if not mode or mode == "N/A":
        return "N/A"
    return POWER_SAVING_LABELS.get(mode, mode)


def parse_fw_version(raw: str) -> str:
    """
    Parse a raw Sony fwVersion string to a short readable version.
    e.g. "PKG1.6.0.81.60.1.00.0960BBA" -> "6.0.81.60"
    Falls back to the raw string if the format is unexpected.
    """
    if not raw or raw == "N/A":
        return raw
    try:
        stripped = raw.lstrip("PKGpkg")
        parts = stripped.split(".")
        if len(parts) >= 5:
            return ".".join(parts[1:5])
    except Exception:
        pass
    return raw


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
            devices.append({"host": host, "port": port})
    if not devices:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No valid entries found in CSV.{RESET}")
        sys.exit(1)
    return devices


# ---------------------------------------------------------------------------
# Sony REST API helpers
# ---------------------------------------------------------------------------
def build_headers(psk: str = None) -> dict:
    h = {"Content-Type": "application/json"}
    if psk:
        h["X-Auth-PSK"] = psk
    return h


def call_sony_api(host: str, port: int, method: str, params: list,
                  version: str, request_id: int = 1, psk: str = None,
                  timeout: int = DEFAULT_TIMEOUT) -> dict:
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}{API_ENDPOINT}"
    payload = {"method": method, "id": request_id, "params": params, "version": version}
    response = requests.post(url, json=payload, headers=build_headers(psk),
                             timeout=timeout, verify=False)
    response.raise_for_status()
    return response.json()


def get_system_information(host: str, port: int, psk: str = None,
                           timeout: int = DEFAULT_TIMEOUT) -> tuple:
    """Tries v1.7 -> v1.4 -> v1.0. Returns (result_dict, api_version_used)."""
    last_error = None
    for api_version in SYSTEM_INFO_VERSIONS:
        try:
            result = call_sony_api(host=host, port=port, method="getSystemInformation",
                                   params=[], version=api_version, request_id=1,
                                   psk=psk, timeout=timeout)
            if "error" in result:
                code = result["error"][0] if isinstance(result["error"], list) else result["error"]
                msg  = result["error"][1] if isinstance(result["error"], list) and len(result["error"]) > 1 else "Unknown"
                if isinstance(code, int) and code in [12, 15]:
                    last_error = f"v{api_version} not supported (error {code})"
                    continue
                raise Exception(f"API Error {code}: {msg}")
            return result.get("result", [{}])[0], api_version
        except requests.exceptions.HTTPError:
            raise
        except Timeout:
            raise
        except RequestsConnectionError:
            raise
        except Exception as e:
            if "API Error" in str(e):
                last_error = str(e)
                continue
            raise
    raise Exception(f"All API versions failed. Last: {last_error}")


def get_interface_information(host: str, port: int, psk: str = None,
                              timeout: int = DEFAULT_TIMEOUT) -> dict:
    result = call_sony_api(host=host, port=port, method="getInterfaceInformation",
                           params=[], version="1.0", request_id=2, psk=psk, timeout=timeout)
    if "error" in result:
        return {}
    return result.get("result", [{}])[0]


def get_network_settings(host: str, port: int, psk: str = None,
                         timeout: int = DEFAULT_TIMEOUT) -> list:
    try:
        result = call_sony_api(host=host, port=port, method="getNetworkSettings",
                               params=[{"netif": ""}], version="1.0", request_id=3,
                               psk=psk, timeout=timeout)
        if "error" in result:
            return []
        return result.get("result", [[]])[0]
    except Exception:
        return []


def get_power_saving_mode(host: str, port: int, psk: str = None,
                          timeout: int = DEFAULT_TIMEOUT) -> str:
    """
    Calls getPowerSavingMode v1.0. Auth level None — works with or without PSK.
    Documented values: "off", "low", "high", "pictureOff".
    """
    try:
        result = call_sony_api(host=host, port=port, method="getPowerSavingMode",
                               params=[], version="1.0", request_id=4,
                               psk=psk, timeout=timeout)
        if "error" in result:
            return "N/A"
        data = result.get("result", [{}])[0]
        return data.get("mode", "N/A") or "N/A"
    except Exception:
        return "N/A"


def set_auth_none(host: str, port: int, psk: str,
                  timeout: int = DEFAULT_TIMEOUT) -> tuple:
    """Set IP control authentication to None using the provided PSK."""
    try:
        result = call_sony_api(host=host, port=port, method="setRemoteDeviceSettings",
                               params=[{"target": "accessPermission", "value": "off"}],
                               version="1.0", request_id=20, psk=psk, timeout=timeout)
        if "error" in result:
            code = result["error"][0] if isinstance(result["error"], list) else result["error"]
            msg  = result["error"][1] if isinstance(result["error"], list) and len(result["error"]) > 1 else "Unknown"
            return False, f"API error {code}: {msg}"
        return True, "Authentication set to None"
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code if e.response else "?"
        if code == 403:
            return False, "HTTP 403 — PSK incorrect or auth already None"
        return False, f"HTTP {code}"
    except Timeout:
        return False, "Timed out"
    except RequestsConnectionError:
        return False, "Conn refused"
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Main query
# ---------------------------------------------------------------------------
def query_display(host: str, port: int, psk: str = None,
                  timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Query a single Sony Bravia display for firmware and power saving mode."""
    result = {
        "host":                 host,
        "port":                 port,
        "status":               "error",
        "model":                "N/A",
        "serial":               "N/A",
        "firmware_version":     "N/A",
        "firmware_version_raw": "N/A",
        "mac_address":          "N/A",
        "device_name":          "N/A",
        "interface_version":    "N/A",
        "product_name":         "N/A",
        "generation":           "N/A",
        "api_version_used":     "N/A",
        "power_saving_mode":    "N/A",
        "auth_note":            None,
        "error":                None,
        "query_timestamp":      datetime.now(timezone.utc).isoformat(),
    }

    effective_psk = psk

    try:
        try:
            sys_info, api_version = get_system_information(host, port, effective_psk, timeout)
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 403 and not psk:
                sys_info, api_version = get_system_information(host, port, FALLBACK_PSK, timeout)
                effective_psk = FALLBACK_PSK
                result["auth_note"] = f"fallback PSK '{FALLBACK_PSK}' used"
            else:
                raise

        result["api_version_used"] = api_version
        result["model"]            = sys_info.get("model",      "N/A")
        result["serial"]           = sys_info.get("serial",     "N/A")
        result["mac_address"]      = sys_info.get("macAddr",    "N/A")
        result["device_name"]      = sys_info.get("name",       "N/A")
        result["generation"]       = sys_info.get("generation", "N/A")
        result["product_name"]     = sys_info.get("product",    "N/A")

        if api_version == "1.7":
            raw_fw = sys_info.get("fwVersion", "N/A") or "N/A"
            result["firmware_version"]     = parse_fw_version(raw_fw)
            result["firmware_version_raw"] = raw_fw
        else:
            result["firmware_version"]     = sys_info.get("generation", "N/A") or "N/A"
            result["firmware_version_raw"] = "N/A"

        result["status"] = "success"

        try:
            iface = get_interface_information(host, port, effective_psk, timeout)
            if iface:
                result["interface_version"] = iface.get("interfaceVersion", "N/A")
                if result["product_name"] == "N/A":
                    result["product_name"] = iface.get("productName", "N/A")
        except Exception:
            pass

        if not result["mac_address"] or result["mac_address"] == "N/A":
            try:
                for iface in get_network_settings(host, port, effective_psk, timeout):
                    hw = iface.get("hwAddr", "")
                    if hw:
                        result["mac_address"] = hw
                        break
            except Exception:
                pass

        result["power_saving_mode"] = get_power_saving_mode(host, port, effective_psk, timeout)

    except Timeout:
        result["error"] = "Connection timed out"
    except RequestsConnectionError:
        result["error"] = f"Cannot connect to {host}:{port}"
    except requests.exceptions.HTTPError as e:
        sc = e.response.status_code if e.response else "Unknown"
        if sc == 403:
            result["status"] = "auth_error"
            result["error"]  = "HTTP 403 — check PSK or set auth to None"
        elif sc == 404:
            result["error"] = "HTTP 404 — IP control not enabled"
        else:
            result["error"] = f"HTTP {sc}"
    except Exception as e:
        result["error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def save_results_json(results: list, filepath: str, args, elapsed: float):
    ok   = sum(1 for r in results if r["status"] == "success")
    auth = sum(1 for r in results if r["status"] == "auth_error")
    err  = sum(1 for r in results if r["status"] == "error")
    output = {
        "query_info": {
            "csv_file":        str(Path(args.input).resolve()),
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "protocol":        f"Sony BRAVIA REST API (JSON-RPC, versions {', '.join(SYSTEM_INFO_VERSIONS)})",
            "mode":            "PSK" if args.psk else f"None (fallback: {FALLBACK_PSK})",
            "workers":         args.workers,
            "total":           len(results),
            "success":         ok,
            "auth_errors":     auth,
            "errors":          err,
            "elapsed_seconds": round(elapsed, 2),
        },
        "displays": results,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)


def print_results_table(results: list, output_file: str, elapsed: float, workers: int):
    """Render the results table following the project visual style guide."""

    table_data = []
    for r in results:
        row = [
            status_icon(r),
            clean(r["host"]),
            clean(r["model"]),
            clean(r["firmware_version"]),
            clean(r["serial"]),
            clean(r["mac_address"]),
            clean(r["api_version_used"]),
            format_power_saving_mode(clean(r.get("power_saving_mode", "N/A"))),
            truncate_error(r.get("error") or (
                f"[{r['auth_note']}]" if r.get("auth_note") else ""
            )),
        ]
        table_data.append(row)

    headers = ["Status", "Host", "Model", "Firmware", "Serial",
               "MAC Address", "API Ver", "Pwr Save", "Error"]

    table = tabulate(table_data, headers=headers,
                     tablefmt="pretty", stralign="left", numalign="right")

    first_line = table.split("\n")[0]
    raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw         = max(raw_width, 60)

    title = "Sony Bravia BZ40H/BZ40L \u2014 Firmware Query Results"
    pad   = (bw - len(title)) // 2

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

    psm_counts = {}
    for r in results:
        mode = r.get("power_saving_mode", "N/A")
        psm_counts[mode] = psm_counts.get(mode, 0) + 1

    reported = sum(v for k, v in psm_counts.items() if k != "N/A")
    if reported:
        parts = "  |  ".join(
            f"{BOLD}{POWER_SAVING_LABELS.get(m, m)}:{RESET}{WHITE} {c}"
            for m, c in sorted(psm_counts.items()) if m != "N/A"
        )
        print(f"  {BOLD}Power Saving \u2014{RESET}{WHITE} {parts}  |  {BOLD}Reported:{RESET}{WHITE} {reported}/{total}")
    else:
        print(f"  {BOLD}Power Saving \u2014{RESET}{WHITE} No data available")

    print()
    print(f"  {BOLD}Results saved:{RESET}{WHITE} {output_file}")
    print(f"  {BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers)")
    print(f"{RESET}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Query Sony Bravia BZ40H/BZ40L displays for firmware version via Sony REST API.",
        epilog="""
Examples:
  python sony_fw_query.py
  python sony_fw_query.py -i my_displays.csv
  python sony_fw_query.py -k MyPreSharedKey
  python sony_fw_query.py -i displays.csv -k 0000 -t 15 -o output.json -w 10
  python sony_fw_query.py --set-auth-none -k 0000
  python sony_fw_query.py --set-auth-none -k 0000 --host 192.168.1.100
  python sony_fw_query.py --host 192.168.1.100 --raw

Authentication:
  By default no PSK is sent. On HTTP 403 the script automatically retries
  with the fallback PSK "1234" and notes this in the output.

Firmware Version:
  v1.7 devices: fwVersion field, parsed to short form (e.g. 6.0.81.60).
  v1.0/v1.4 devices: generation field used as best available identifier.

Power Saving Mode:
  getPowerSavingMode (v1.0) — auth level None, works with or without PSK.
  Values: off | low | high | pictureOff
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-i", "--input",        default=DEFAULT_CSV,
        help=f"CSV file with 'host'/'port' columns (default: {DEFAULT_CSV})")
    parser.add_argument("--host",               default=None,
        help="Query a single host instead of reading a CSV")
    parser.add_argument("-o", "--output",       default=DEFAULT_OUTPUT,
        help=f"Output JSON file (default: {DEFAULT_OUTPUT})")
    parser.add_argument("-k", "--psk",          default=DEFAULT_PSK,
        help="Pre-Shared Key (default: no authentication)")
    parser.add_argument("-t", "--timeout",      type=int, default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-p", "--port",         type=int, default=DEFAULT_PORT,
        help=f"Port for --host mode (default: {DEFAULT_PORT})")
    parser.add_argument("-w", "--workers",      type=int, default=DEFAULT_WORKERS,
        help=f"Number of concurrent workers (default: {DEFAULT_WORKERS})")
    parser.add_argument("--set-auth-none",      action="store_true", default=False,
        help="Use the PSK (-k) to set each display's IP control auth to None.")
    parser.add_argument("--raw",                action="store_true", default=False,
        help="With --host: dump raw getSystemInformation responses for all API versions.")

    args = parser.parse_args()

    if args.set_auth_none and not args.psk:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} --set-auth-none requires -k <psk>{RESET}")
        sys.exit(1)

    term_width = get_terminal_width()

    import time
    start_time = time.monotonic()

    # -----------------------------------------------------------------------
    # --set-auth-none mode
    # -----------------------------------------------------------------------
    if args.set_auth_none:
        displays = [{"host": args.host, "port": args.port}] if args.host else load_csv(args.input)

        print(f"{WHITE}")
        print(f"  {BOLD}Sony Bravia — Set Authentication to None{RESET}{WHITE}")
        print(f"  Sets IP Control auth to None using the provided PSK.")
        print(f"  Input:   {args.input}")
        print(f"  Output:  {args.output}")
        print(f"  Workers: {args.workers}")
        print(f"  Timeout: {args.timeout}s")
        print(f"  PSK:     {args.psk}")
        print(f"{RESET}")

        bar_fmt = (
            f"  {WHITE}Connecting{RESET} "
            f"{CYAN}{{bar}}{RESET}"
            f" {WHITE}{{n_fmt}}/{{total_fmt}}{RESET}"
            f" {WHITE}[{{elapsed}}<{{remaining}}]{RESET}"
            f"  {WHITE}{{postfix}}{RESET}"
        )

        auth_results = []
        results_lock = threading.Lock()
        active_lock  = threading.Lock()
        latest_host  = {"value": ""}

        def do_set_auth(d):
            with active_lock:
                latest_host["value"] = d["host"]
            success, message = set_auth_none(d["host"], d["port"], psk=args.psk, timeout=args.timeout)
            return {"host": d["host"], "success": success, "message": message}

        with tqdm(total=len(displays), bar_format=bar_fmt, ncols=term_width,
                  dynamic_ncols=True, file=sys.stderr, leave=True) as pbar:
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                futures = {ex.submit(do_set_auth, d): d for d in displays}
                for fut in as_completed(futures):
                    with results_lock:
                        auth_results.append(fut.result())
                    with active_lock:
                        pbar.set_postfix_str(latest_host["value"], refresh=False)
                    pbar.update(1)

        elapsed = time.monotonic() - start_time
        pbar.set_postfix_str(f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s", refresh=True)

        # Sort output to match input order
        host_order = {d["host"]: i for i, d in enumerate(displays)}
        auth_results.sort(key=lambda r: host_order.get(r["host"], 0))

        table = tabulate(
            [["✓ OK" if r["success"] else "✗ FAIL", r["host"], r["message"]]
             for r in auth_results],
            headers=["Status", "Host", "Message"],
            tablefmt="pretty", stralign="left"
        )

        first_line = table.split("\n")[0]
        bw = max(len(re.sub(r'\033\[[0-9;]*m', '', first_line)), 60)
        title = "Set Authentication to None \u2014 Results"

        print(f"{WHITE}")
        print(f"  {'=' * bw}")
        print(f"  {' ' * ((bw - len(title)) // 2)}{BOLD}{title}{RESET}{WHITE}")
        print(f"  {'=' * bw}")
        for line in table.split("\n"):
            print(f"  {line}")

        ok  = sum(1 for r in auth_results if r["success"])
        err = len(auth_results) - ok
        print()
        print(
            f"  {BOLD}Total:{RESET}{WHITE} {len(auth_results)}  |  "
            f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
            f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
        )
        print(f"  {BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({args.workers} workers)")
        print(f"{RESET}")
        return

    # -----------------------------------------------------------------------
    # Header block
    # -----------------------------------------------------------------------
    input_display = args.host if args.host else args.input
    print(f"{WHITE}")
    print(f"  {BOLD}Sony Bravia BZ40H/BZ40L — Firmware Query Tool{RESET}{WHITE}")
    print(f"  Queries firmware version and power saving mode via Sony REST API.")
    print(f"  Input:   {input_display}")
    print(f"  Output:  {args.output}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    print(f"  Auth:    {'PSK' if args.psk else f'None (fallback: {FALLBACK_PSK})'}")
    print(f"  API:     {' -> '.join(SYSTEM_INFO_VERSIONS)} (automatic fallback)")
    print(f"{RESET}")

    # -----------------------------------------------------------------------
    # Single-host --raw dump
    # -----------------------------------------------------------------------
    if args.host and args.raw:
        print(f"{WHITE}Raw getSystemInformation responses:{RESET}\n")
        for v in SYSTEM_INFO_VERSIONS:
            try:
                r = call_sony_api(args.host, args.port, "getSystemInformation", [], v,
                                  psk=args.psk, timeout=args.timeout)
                print(f"{WHITE}--- v{v} ---{RESET}")
                print(json.dumps(r, indent=2))
            except Exception as e:
                print(f"{WHITE}--- v{v} --- {RED}ERROR:{RESET} {e}")
            print()
        try:
            r = call_sony_api(args.host, args.port, "getInterfaceInformation", [], "1.0",
                              request_id=2, psk=args.psk, timeout=args.timeout)
            print(f"{WHITE}--- getInterfaceInformation v1.0 ---{RESET}")
            print(json.dumps(r, indent=2))
        except Exception as e:
            print(f"{WHITE}--- getInterfaceInformation v1.0 --- {RED}ERROR:{RESET} {e}")
        return

    # -----------------------------------------------------------------------
    # Build display list
    # -----------------------------------------------------------------------
    displays = [{"host": args.host, "port": args.port}] if args.host else load_csv(args.input)

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
        return query_display(d["host"], d["port"], psk=args.psk, timeout=args.timeout)

    with tqdm(total=len(displays), bar_format=bar_fmt, ncols=term_width,
              dynamic_ncols=True, file=sys.stderr, leave=True) as pbar:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(do_query, d): d for d in displays}
            for fut in as_completed(futures):
                with results_lock:
                    results.append(fut.result())
                with active_lock:
                    pbar.set_postfix_str(latest_host["value"], refresh=False)
                pbar.update(1)

    elapsed = time.monotonic() - start_time
    pbar.set_postfix_str(f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s", refresh=True)

    # Re-sort results to match original CSV input order
    host_order = {d["host"]: i for i, d in enumerate(displays)}
    results.sort(key=lambda r: host_order.get(r["host"], 0))

    print_results_table(results, args.output, elapsed, args.workers)
    save_results_json(results, args.output, args, elapsed)


if __name__ == "__main__":
    main()
