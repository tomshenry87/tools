#!/usr/bin/env python3
"""
Sony Bravia BZ40H/BZ40L Firmware Version Query Tool

Uses the Sony BRAVIA REST API (JSON-RPC):
  - Endpoint: /sony/system
  - Method: getSystemInformation (v1.7 with fallback to v1.4, v1.0)
  - Method: getInterfaceInformation (v1.0)
  - Method: getNetworkSettings (v1.0)
  - Method: getPowerSavingMode (v1.0)

Authentication modes:
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
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import standard_cli as cli  # noqa: E402  (standard flags, --debug/--raw helpers)

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library is required. Install with: pip3 install requests")
    sys.exit(1)

from requests.exceptions import Timeout, ConnectionError as RequestsConnectionError

try:
    from tabulate import tabulate
except ImportError:
    print("ERROR: 'tabulate' library is required. Install with: pip3 install tabulate")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("ERROR: 'tqdm' library is required. Install with: pip3 install tqdm")
    sys.exit(1)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# ANSI palette (spec 3.1) — no other colours
# ---------------------------------------------------------------------------
CYAN   = "\033[96m"   # Progress bar fill — reserved, nothing else
GREEN  = "\033[92m"   # Success states
RED    = "\033[91m"   # Failure / error states
YELLOW = "\033[93m"   # Auth-error states
WHITE  = "\033[97m"   # All body text, table content, labels
BOLD   = "\033[1m"    # Section headers, label emphasis
RESET  = "\033[0m"    # Always close every colour block

# ---------------------------------------------------------------------------
# Paths & defaults
# ---------------------------------------------------------------------------
DEFAULT_CSV      = "secrets/bravia_firmware.csv"    # relative to this script's folder
OUTPUT_DIR       = "bravia_firmware/files"          # results_<YYYYMMDD>_<HHMMSS>.json

DEFAULT_PSK      = None
FALLBACK_PSK     = "1234"
DEFAULT_TIMEOUT  = 10
DEFAULT_PORT     = 80
DEFAULT_WORKERS  = 5
API_ENDPOINT     = "/sony/system"
MANUFACTURER     = "Sony"

SYSTEM_INFO_VERSIONS = ["1.7", "1.4", "1.0"]

POWER_SAVING_LABELS = {
    "off":        "Off (disabled)",
    "low":        "Low",
    "high":       "High",
    "pictureOff": "Picture Off (panel off)",
}


# Every JSON-RPC request the query makes, in order: (method, params, version, id).
# --raw sends each of these and prints the reply.
RAW_REQUESTS = (
    [("getSystemInformation", [], v, 1) for v in SYSTEM_INFO_VERSIONS] + [
        ("getInterfaceInformation", [],             "1.0", 2),
        ("getNetworkSettings",      [{"netif": ""}], "1.0", 3),
        ("getPowerSavingMode",      [],             "1.0", 4),
    ]
)


# ---------------------------------------------------------------------------
# Shared helpers (spec 3.5) — byte-identical across all scripts
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
        return f"{GREEN}✓ OK{RESET}{WHITE}"
    elif s == "auth_error":
        return f"{YELLOW}✗ AUTH ERR{RESET}{WHITE}"
    return f"{RED}✗ ERROR{RESET}{WHITE}"


# ---------------------------------------------------------------------------
# Error labels (spec 3.6) — protocol patterns first, then base
# ---------------------------------------------------------------------------
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

# Sony JSON-RPC error envelopes and PSK rejection responses.
PROTOCOL_ERROR_PATTERNS = [
    (r"HTTP 403",                     "Auth failed"),
    (r"HTTP 404",                     "IP ctrl disabled"),
    (r"API Error 3\b",                "Illegal argument"),
    (r"API Error 5\b",                "Illegal state"),
    (r"API Error 7\b",                "Display off"),
    (r"API Error 12\b",               "Not implemented"),
    (r"API Error 14\b",               "Unsupported ver"),
    (r"API Error 15\b",               "Unsupported op"),
    (r"API Error 40005\b",            "Display busy"),
    (r"[Aa]ll API versions failed",   "API unsupported"),
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


# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------
def format_power_saving_mode(mode: str) -> str:
    """Human-readable label for a getPowerSavingMode value (display only)."""
    if not mode or mode == "N/A":
        return "N/A"
    return POWER_SAVING_LABELS.get(mode, mode)


# ---------------------------------------------------------------------------
# CSV loader (spec 3.7)
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
            psk = (row.get(col_map.get("psk", ""), "") or "").strip() or None
            devices.append({"host": host, "port": port, "psk": psk})
    if not devices:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No valid entries found in CSV.{RESET}")
        sys.exit(1)
    return devices


# ---------------------------------------------------------------------------
# Sony REST API — PROTOCOL LOGIC, DO NOT MODIFY (spec 4)
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
    headers = build_headers(psk)
    # Trace only: headers go through cli.redact so the X-Auth-PSK value is never shown.
    cli.debug.log(host, f"POST {url} (timeout {timeout}s) headers: {cli.redact(headers)}")
    cli.debug.sent(host, json.dumps(payload))
    try:
        response = requests.post(url, json=payload, headers=headers,
                                 timeout=timeout, verify=False)
    except Exception as e:
        cli.debug.log(host, f"{method} v{version}: request failed: {type(e).__name__}: {e}")
        raise
    cli.debug.log(host, f"{method} v{version}: HTTP {response.status_code}")
    if cli.debug.enabled:   # .text may run charset detection; only touch it when tracing
        cli.debug.received(host, response.text)
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
                    cli.debug.log(host, f"getSystemInformation {last_error}; trying next version")
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
                cli.debug.log(host, f"getSystemInformation v{api_version}: {e}; trying next version")
                continue
            raise
    raise Exception(f"All API versions failed. Last: {last_error}")


def get_interface_information(host: str, port: int, psk: str = None,
                              timeout: int = DEFAULT_TIMEOUT) -> dict:
    result = call_sony_api(host=host, port=port, method="getInterfaceInformation",
                           params=[], version="1.0", request_id=2, psk=psk, timeout=timeout)
    if "error" in result:
        cli.debug.log(host, f"getInterfaceInformation error {result['error']}; ignored")
        return {}
    return result.get("result", [{}])[0]


def get_network_settings(host: str, port: int, psk: str = None,
                         timeout: int = DEFAULT_TIMEOUT) -> list:
    try:
        result = call_sony_api(host=host, port=port, method="getNetworkSettings",
                               params=[{"netif": ""}], version="1.0", request_id=3,
                               psk=psk, timeout=timeout)
        if "error" in result:
            cli.debug.log(host, f"getNetworkSettings error {result['error']}; ignored")
            return []
        return result.get("result", [[]])[0]
    except Exception as e:
        cli.debug.log(host, f"getNetworkSettings failed: {e}")
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
            cli.debug.log(host, f"getPowerSavingMode error {result['error']}; ignored")
            return "N/A"
        data = result.get("result", [{}])[0]
        return data.get("mode", "N/A") or "N/A"
    except Exception as e:
        cli.debug.log(host, f"getPowerSavingMode failed: {e}")
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
        # A Response for a 4xx/5xx is falsy, so test it against None.
        code = e.response.status_code if e.response is not None else "?"
        if code == 403:
            return False, "HTTP 403 — PSK incorrect or auth already None"
        return False, f"HTTP {code}"
    except Timeout:
        return False, "Timed out"
    except RequestsConnectionError:
        return False, "Conn refused"
    except Exception as e:
        return False, str(e)


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
    except Exception as e:
        cli.debug.log("parse_fw_version", f"could not parse {raw!r}: {e}; using it as-is")
    return raw


# ---------------------------------------------------------------------------
# Per-device query
# ---------------------------------------------------------------------------
def query_display(host: str, port: int, psk: str = None,
                  timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Query a single Sony Bravia display. Returns a spec-conformant record."""
    result = {
        # Common fields (spec 2.3)
        "host":                 host,
        "port":                 port,
        "query_timestamp":      datetime.now(timezone.utc).isoformat(),
        "status":               "error",
        "error":                None,
        "firmware_version":     "N/A",
        "model":                "N/A",
        "serial":               "N/A",
        "mac":                  "N/A",
        "manufacturer":         MANUFACTURER,
        # Device-specific fields (spec 2.4)
        "device_name":          "N/A",
        "power_saving_mode":    "N/A",
        # Supplementary diagnostics
        "firmware_version_raw": "N/A",
        "generation":           "N/A",
        "product":              "N/A",
        "interface_version":    "N/A",
        "api_version_used":     "N/A",
        "auth_note":            None,
    }

    effective_psk = psk

    try:
        try:
            sys_info, api_version = get_system_information(host, port, effective_psk, timeout)
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 403 and not psk:
                cli.debug.log(host, "HTTP 403 with no PSK; retrying with the fallback PSK")
                sys_info, api_version = get_system_information(host, port, FALLBACK_PSK, timeout)
                effective_psk = FALLBACK_PSK
                result["auth_note"] = f"fallback PSK '{FALLBACK_PSK}' used"
            else:
                raise

        result["api_version_used"] = api_version
        result["model"]            = sys_info.get("model",      "N/A")
        result["serial"]           = sys_info.get("serial",     "N/A")
        result["mac"]              = sys_info.get("macAddr",    "N/A")
        result["device_name"]      = sys_info.get("name",       "N/A")
        result["generation"]       = sys_info.get("generation", "N/A")
        result["product"]          = sys_info.get("product",    "N/A")

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
                if result["product"] == "N/A":
                    result["product"] = iface.get("productName", "N/A")
        except Exception as e:
            cli.debug.log(host, f"getInterfaceInformation failed: {e}")

        if not result["mac"] or result["mac"] == "N/A":
            cli.debug.log(host, "no macAddr in getSystemInformation; asking getNetworkSettings")
            try:
                for iface in get_network_settings(host, port, effective_psk, timeout):
                    hw = iface.get("hwAddr", "")
                    if hw:
                        result["mac"] = hw
                        break
            except Exception as e:
                cli.debug.log(host, f"getNetworkSettings parse failed: {e}")

        result["power_saving_mode"] = get_power_saving_mode(host, port, effective_psk, timeout)

    except Timeout:
        result["error"] = "Connection timed out"
    except RequestsConnectionError:
        result["error"] = f"Cannot connect to {host}:{port}"
    except requests.exceptions.HTTPError as e:
        # A Response for a 4xx/5xx is falsy, so test it against None. A 403 here
        # is final: the given PSK, or the fallback PSK after a 403 with none.
        sc = e.response.status_code if e.response is not None else "Unknown"
        if sc == 403:
            result["status"] = "auth_error"
            result["error"]  = "HTTP 403 — check PSK or set auth to None"
        elif sc == 404:
            result["error"] = "HTTP 404 — IP control not enabled"
        else:
            result["error"] = f"HTTP {sc}"
    except Exception as e:
        result["error"] = str(e)

    cli.debug.log(host, f"result: {result['status']}"
                        + (f" ({result['error']})" if result["error"] else "")
                        + (" [fallback PSK used]" if result["auth_note"] else ""))
    return result


# ---------------------------------------------------------------------------
# JSON output (spec 2.1, 2.7)
# ---------------------------------------------------------------------------
def save_results_json(results: list, filepath: str, args, elapsed: float):
    ok   = sum(1 for r in results if r["status"] == "success")
    auth = sum(1 for r in results if r["status"] == "auth_error")
    err  = sum(1 for r in results if r["status"] == "error")

    out = Path(filepath)
    cli.ensure_parent(out)

    output = {
        "query_info": {
            "csv_file":        cli.input_label(args),
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "protocol":        f"Sony BRAVIA REST API (JSON-RPC, versions {', '.join(SYSTEM_INFO_VERSIONS)})",
            "mode":            "PSK" if args.password else f"None (fallback: {FALLBACK_PSK})",
            "workers":         args.workers,
            "total":           len(results),
            "success":         ok,
            "auth_errors":     auth,
            "errors":          err,
            "elapsed_seconds": round(elapsed, 2),
        },
        "displays": results,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Terminal output (spec 3.4, 3.8)
# ---------------------------------------------------------------------------
def print_results_table(results: list, output_file: str, elapsed: float,
                        workers: int, firmware_filter: list = None):
    """Render the results table. JSON always retains the full result set."""

    shown = cli.firmware_mismatches(results, firmware_filter)

    table_data = []
    for r in shown:
        note = r.get("auth_note")
        err_cell = truncate_error(r.get("error")) or (f"[{note}]" if note else "")
        table_data.append([
            status_icon(r),
            clean(r["host"]),
            clean(r["manufacturer"]),
            clean(r["model"]),
            clean(r["firmware_version"]),
            clean(r["serial"]),
            clean(r["mac"]),
            clean(r["api_version_used"]),
            format_power_saving_mode(clean(r.get("power_saving_mode", "N/A"))),
            err_cell,
        ])

    headers = ["Status", "Host", "Manufacturer", "Model", "Firmware",
               "Serial", "MAC", "API Ver", "Pwr Save", "Error"]

    table = tabulate(table_data, headers=headers,
                     tablefmt="pretty", stralign="left", numalign="right")

    first_line = table.split("\n")[0]
    raw_width = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw = max(raw_width, 60)

    title = "Sony Bravia BZ40H/BZ40L Firmware Query Results"
    if firmware_filter:
        title += f"  —  Mismatched: {len(shown)}/{len(results)}"
    pad = max((bw - len(title)) // 2, 0)

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")
    for line in table.split("\n"):
        print(f"  {line}")

    total = len(shown)
    ok    = sum(1 for r in shown if r["status"] == "success")
    auth  = sum(1 for r in shown if r["status"] == "auth_error")
    err   = sum(1 for r in shown if r["status"] == "error")

    print()
    if firmware_filter:
        print(
            f"  {BOLD}Firmware filter:{RESET}{WHITE} {cli.firmware_label(firmware_filter)}  |  "
            f"{BOLD}Showing:{RESET}{WHITE} {len(shown)} of {len(results)} displays"
        )
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}✓{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}✗{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}✗{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )

    # Device-specific metrics line — displays by power saving mode
    counts = {}
    for r in shown:
        mode = r.get("power_saving_mode", "N/A")
        if mode and mode != "N/A":
            counts[mode] = counts.get(mode, 0) + 1
    reported = sum(counts.values())
    if reported:
        parts = "  |  ".join(
            f"{POWER_SAVING_LABELS.get(m, m)}: {c}" for m, c in sorted(counts.items())
        )
        print(f"  {BOLD}Power Saving{RESET}{WHITE} — {parts}  |  Reported: {reported}/{total}")
    else:
        print(f"  {BOLD}Power Saving{RESET}{WHITE} — No data available")

    print()
    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {output_file}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers){RESET}")
    print(f"{RESET}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def dump_raw(dev: dict, psk: str, timeout: int):
    """
    --raw: send every JSON-RPC request the query makes and print each reply.
    Like the normal query, an HTTP 403 with no PSK is retried with the
    fallback PSK, and that PSK is used for the remaining requests.
    """
    host, port = dev["host"], dev["port"]
    for method, params, version, request_id in RAW_REQUESTS:
        label = f"{method} v{version}"
        try:
            try:
                reply = call_sony_api(host, port, method, params, version,
                                      request_id=request_id, psk=psk, timeout=timeout)
            except requests.exceptions.HTTPError as e:
                if e.response is None or e.response.status_code != 403 or psk:
                    raise
                cli.raw_error(label, f"{e} (no PSK); retrying with the fallback PSK")
                psk = FALLBACK_PSK
                label += " (fallback PSK)"
                reply = call_sony_api(host, port, method, params, version,
                                      request_id=request_id, psk=psk, timeout=timeout)
            cli.raw_item(label, reply)
        except (Timeout, RequestsConnectionError) as e:
            # Same as the normal query: an unreachable display stops here
            # instead of waiting out every remaining request.
            cli.raw_error(label, e)
            cli.raw_error("remaining requests", "skipped (display not reachable)")
            return
        except Exception as e:
            cli.raw_error(label, e)


def main():
    parser = cli.build_parser(
        script_file=__file__,
        description="Query Sony Bravia BZ40H/BZ40L displays for firmware version via the Sony REST API.",
        default_csv=DEFAULT_CSV,
        output_dir=OUTPUT_DIR,
        default_port=DEFAULT_PORT,
        default_timeout=DEFAULT_TIMEOUT,
        default_workers=DEFAULT_WORKERS,
        auth=cli.AUTH_PASSWORD,
        port_help=f"Port for --host targets (default: {DEFAULT_PORT}; 443 uses HTTPS)",
        raw_help=("Print every JSON-RPC reply the query asks for (getSystemInformation "
                  f"v{', v'.join(SYSTEM_INFO_VERSIONS)}, getInterfaceInformation, "
                  "getNetworkSettings, getPowerSavingMode) for each display, then exit "
                  "without the table or JSON. Works with --host or the whole CSV."),
        epilog="""
Examples:
  python3 bravia_script.py                                  # whole CSV
  python3 bravia_script.py --host 192.168.1.100             # one display
  python3 bravia_script.py --host 192.168.1.100 --password 0000
  python3 bravia_script.py --host 192.168.1.100 --raw
  python3 bravia_script.py --host 192.168.1.100 --debug
  python3 bravia_script.py --firmware 6.0.81.60 6.0.82.10   # who is NOT on these
  python3 bravia_script.py -i other.csv -t 15 -w 8 -o out.json
  python3 bravia_script.py --set-auth-none --password 0000

Authentication:
  The display's password is its IP control Pre-Shared Key (PSK), sent in the
  X-Auth-PSK header. The CSV may give one per display ("psk" column);
  --password (or the old -k/--psk) is used for every display queried.
  With no PSK, an HTTP 403 is retried once with the fallback PSK "1234";
  auth_error is only reported after every attempt fails.

Firmware Version:
  v1.7 devices: fwVersion parsed to short form (e.g. 6.0.81.60).
  v1.0/v1.4 devices: generation field used as best available identifier.

Power Saving Mode:
  getPowerSavingMode (v1.0) — values: off | low | high | pictureOff
        """,
        # The display's "password" is its PSK: say so in --help.
        password_help=("Pre-Shared Key (PSK) sent as X-Auth-PSK. Used for every display "
                       "queried (CSV or --host), overriding the CSV's psk column. "
                       "Same as the old -k/--psk."),
    )
    cli.add_alias(parser, "-k", "--psk", dest="password")

    group = parser.add_argument_group("Bravia options")
    group.add_argument("--set-auth-none", action="store_true", default=False,
        help="Use the PSK (--password or -k) to set each display's IP control auth "
             "to None. Prints a terminal table only; no JSON.")

    args = cli.parse_args(parser)

    if args.set_auth_none and not args.password:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} --set-auth-none requires --password <psk> (or -k <psk>){RESET}")
        sys.exit(1)

    term_width = shutil.get_terminal_size((120, 24)).columns
    start_time = time.monotonic()

    # A --host target that is not in the CSV: same shape as a load_csv() row.
    def make_device(host):
        return {"host": host, "port": DEFAULT_PORT, "psk": DEFAULT_PSK}

    # -----------------------------------------------------------------------
    # --set-auth-none mode
    # -----------------------------------------------------------------------
    if args.set_auth_none:
        devices = cli.select_devices(args, load_csv, make_device, password_key="psk")

        print(f"{WHITE}")
        print(f"  {BOLD}Sony Bravia BZ40H/BZ40L Firmware Version Query Tool{RESET}{WHITE}")
        print(f"  Sets IP Control authentication to None via the Sony REST API")
        print(f"  Input:   {cli.input_label(args)}")
        print(f"  Output:  (terminal only)")
        print(f"  Workers: {args.workers}")
        print(f"  Timeout: {args.timeout}s")
        print(f"  PSK:     set (hidden)")
        if args.debug:
            print(f"  Debug:   on (trace on stderr)")
        print(f"{RESET}")

        bar_fmt = (
            f"  {WHITE}Scanning{RESET} "
            f"{CYAN}{{bar}}{RESET}"
            f" {WHITE}{{n_fmt}}/{{total_fmt}}{RESET}"
            f" {WHITE}[{{elapsed}}<{{remaining}}]{RESET}"
            f"  {WHITE}{{postfix}}{RESET}"
        )

        auth_results  = []
        results_lock  = threading.Lock()
        active_lock   = threading.Lock()
        latest_host   = {"value": ""}

        def do_set_auth(d):
            with active_lock:
                latest_host["value"] = d["host"]
            success, message = set_auth_none(d["host"], d["port"],
                                             psk=args.password, timeout=args.timeout)
            cli.debug.log(d["host"], f"set-auth-none: {'ok' if success else 'failed'}: {message}")
            return {"host": d["host"], "success": success, "message": message}

        with tqdm(total=len(devices), bar_format=bar_fmt, ncols=term_width,
                  dynamic_ncols=True, file=sys.stderr, leave=True) as pbar:
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                futures = [ex.submit(do_set_auth, d) for d in devices]
                for fut in as_completed(futures):
                    with results_lock:
                        auth_results.append(fut.result())
                    with active_lock:
                        pbar.set_postfix_str(latest_host["value"], refresh=False)
                    pbar.update(1)
            elapsed = time.monotonic() - start_time
            pbar.set_postfix_str(f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s",
                                 refresh=True)

        order = {d["host"]: i for i, d in enumerate(devices)}
        auth_results.sort(key=lambda r: order.get(r["host"], 0))

        table = tabulate(
            [[f"{GREEN}✓ OK{RESET}{WHITE}" if r["success"] else f"{RED}✗ ERROR{RESET}{WHITE}",
              r["host"], truncate_error(r["message"]) if not r["success"] else r["message"]]
             for r in auth_results],
            headers=["Status", "Host", "Message"],
            tablefmt="pretty", stralign="left", numalign="right"
        )

        first_line = table.split("\n")[0]
        bw = max(len(re.sub(r'\033\[[0-9;]*m', '', first_line)), 60)
        title = "Set Authentication to None — Results"
        pad = max((bw - len(title)) // 2, 0)

        print(f"{WHITE}")
        print(f"  {'=' * bw}")
        print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
        print(f"  {'=' * bw}")
        for line in table.split("\n"):
            print(f"  {line}")

        ok  = sum(1 for r in auth_results if r["success"])
        err = len(auth_results) - ok
        print()
        print(
            f"  {BOLD}Total:{RESET}{WHITE} {len(auth_results)}  |  "
            f"{GREEN}✓{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
            f"{YELLOW}✗{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} 0  |  "
            f"{RED}✗{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
        )
        print()
        print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} (terminal only){RESET}")
        print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({args.workers} workers){RESET}")
        print(f"{RESET}")
        return

    # -----------------------------------------------------------------------
    # Header block (spec 3.2)
    # -----------------------------------------------------------------------
    print(f"{WHITE}")
    print(f"  {BOLD}Sony Bravia BZ40H/BZ40L Firmware Version Query Tool{RESET}{WHITE}")
    print(f"  Queries Bravia professional displays via the Sony REST API")
    print(f"  Input:   {cli.input_label(args)}")
    print(f"  Output:  {'(none: --raw)' if args.raw else args.output}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    print(f"  Auth:    {'PSK' if args.password else f'None (fallback: {FALLBACK_PSK})'}")
    print(f"  API:     {' -> '.join(SYSTEM_INFO_VERSIONS)} (automatic fallback)")
    if args.firmware:
        print(f"  Filter:  Showing displays not on firmware {cli.firmware_label(args.firmware)}")
    if args.debug:
        print(f"  Debug:   on (trace on stderr)")
    print(f"{RESET}")

    devices = cli.select_devices(args, load_csv, make_device, password_key="psk")

    # -----------------------------------------------------------------------
    # --raw: print every JSON-RPC reply, no table / JSON
    # -----------------------------------------------------------------------
    if args.raw:
        cli.run_raw(devices, lambda d: dump_raw(d, args.password or d.get("psk"), args.timeout))
        return

    # -----------------------------------------------------------------------
    # Progress bar + concurrent query loop (spec 3.3)
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
        return query_display(d["host"], d["port"],
                             psk=(args.password or d.get("psk")), timeout=args.timeout)

    with tqdm(total=len(devices), bar_format=bar_fmt, ncols=term_width,
              dynamic_ncols=True, file=sys.stderr, leave=True) as pbar:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = [ex.submit(do_query, d) for d in devices]
            for fut in as_completed(futures):
                with results_lock:
                    results.append(fut.result())
                with active_lock:
                    pbar.set_postfix_str(latest_host["value"], refresh=False)
                pbar.update(1)
        elapsed = time.monotonic() - start_time
        pbar.set_postfix_str(f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s",
                             refresh=True)

    order = {d["host"]: i for i, d in enumerate(devices)}
    results.sort(key=lambda r: order.get(r["host"], 0))

    save_results_json(results, args.output, args, elapsed)
    print_results_table(results, args.output, elapsed, args.workers, args.firmware)


if __name__ == "__main__":
    main()
