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
"""

import csv
import json
import sys
import os
import shutil
import argparse
from datetime import datetime

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

# Suppress InsecureRequestWarning for HTTPS without cert verification
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Defaults
DEFAULT_CSV     = "displays.csv"
DEFAULT_OUTPUT  = "results.json"
DEFAULT_PSK     = None
DEFAULT_TIMEOUT = 10
DEFAULT_PORT     = 80
API_ENDPOINT     = "/sony/system"
FALLBACK_PSK     = "1234"  # Retried automatically on HTTP 403 when no PSK is set

# ANSI color codes
CYAN  = "\033[96m"
RESET = "\033[0m"

# Ordered list of API versions to try for getSystemInformation
SYSTEM_INFO_VERSIONS = ["1.7", "1.4", "1.0"]

# Human-readable labels for all documented getPowerSavingMode values.
POWER_SAVING_LABELS = {
    "off":        "Off (disabled)",
    "low":        "Low",
    "high":       "High",
    "pictureOff": "Picture Off (panel off)",
}


def parse_fw_version(raw: str) -> str:
    """
    Parse a raw Sony fwVersion string into a human-readable version number.

    Example: "PKG1.6.0.81.60.1.00.0960BBA" -> "6.0.81.60"

    The format is: PKG<major>.<v1>.<v2>.<v3>.<v4>.<rest...>
    We extract segments 1-4 (zero-indexed) after splitting on ".".
    Falls back to the raw string if it doesn't match the expected format.
    """
    if not raw or raw == "N/A":
        return raw
    try:
        # Strip leading "PKG" prefix if present, then split on "."
        stripped = raw.lstrip("PKGpkg")
        parts = stripped.split(".")
        if len(parts) >= 5:
            return ".".join(parts[1:5])
    except Exception:
        pass
    return raw


def format_power_saving_mode(mode: str) -> str:
    """
    Return a human-readable label for a getPowerSavingMode value.
    Falls back to the raw value if undocumented, or 'N/A' if missing.
    """
    if not mode or mode == "N/A":
        return "N/A"
    return POWER_SAVING_LABELS.get(mode, mode)


def get_terminal_width() -> int:
    """Get current terminal width, with a safe fallback."""
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 120


def get_error_truncate_length() -> int:
    """Scale error truncation length based on terminal width."""
    width = get_terminal_width()
    if width >= 200:
        return 50
    elif width >= 150:
        return 35
    elif width >= 120:
        return 25
    elif width >= 80:
        return 15
    else:
        return 10


def build_headers(psk: str = None) -> dict:
    """Build request headers based on authentication mode."""
    headers = {"Content-Type": "application/json"}
    if psk:
        headers["X-Auth-PSK"] = psk
    return headers


def call_sony_api(host: str, port: int, method: str, params: list,
                  version: str, request_id: int = 1, psk: str = None,
                  timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Generic Sony BRAVIA JSON-RPC API caller."""
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}{API_ENDPOINT}"

    payload = {
        "method":  method,
        "id":      request_id,
        "params":  params,
        "version": version
    }

    response = requests.post(
        url,
        json=payload,
        headers=build_headers(psk),
        timeout=timeout,
        verify=False
    )
    response.raise_for_status()
    return response.json()


def get_system_information(host: str, port: int, psk: str = None,
                           timeout: int = DEFAULT_TIMEOUT) -> tuple:
    """
    Calls getSystemInformation. Tries v1.7 -> v1.4 -> v1.0.

    Returns:
        tuple of (result_dict, api_version_used)
    """
    last_error = None

    for api_version in SYSTEM_INFO_VERSIONS:
        try:
            result = call_sony_api(
                host=host, port=port,
                method="getSystemInformation",
                params=[], version=api_version,
                request_id=1, psk=psk, timeout=timeout
            )

            if "error" in result:
                error_code = result["error"][0] if isinstance(result["error"], list) else result["error"]
                error_msg  = result["error"][1] if isinstance(result["error"], list) and len(result["error"]) > 1 else "Unknown"
                if isinstance(error_code, int) and error_code in [12, 15]:
                    last_error = f"v{api_version} not supported (error {error_code})"
                    continue
                else:
                    raise Exception(f"API Error {error_code}: {error_msg}")

            data = result.get("result", [{}])[0]
            return data, api_version

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
            else:
                raise

    raise Exception(f"All API versions failed. Last: {last_error}")


def get_interface_information(host: str, port: int, psk: str = None,
                              timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Calls getInterfaceInformation v1.0."""
    result = call_sony_api(
        host=host, port=port,
        method="getInterfaceInformation",
        params=[], version="1.0",
        request_id=2, psk=psk, timeout=timeout
    )
    if "error" in result:
        return {}
    return result.get("result", [{}])[0]


def get_network_settings(host: str, port: int, psk: str = None,
                         timeout: int = DEFAULT_TIMEOUT) -> list:
    """Calls getNetworkSettings v1.0."""
    try:
        result = call_sony_api(
            host=host, port=port,
            method="getNetworkSettings",
            params=[{"netif": ""}], version="1.0",
            request_id=3, psk=psk, timeout=timeout
        )
        if "error" in result:
            return []
        return result.get("result", [[]])[0]
    except Exception:
        return []


def get_power_saving_mode(host: str, port: int, psk: str = None,
                          timeout: int = DEFAULT_TIMEOUT) -> str:
    """
    Calls getPowerSavingMode v1.0 on /sony/system.

    Auth level is None — no PSK required, but PSK is passed through if
    provided so the call works regardless of the display's auth setting.

    Documented return values: "off", "low", "high", "pictureOff".
    Returns "N/A" if the call fails or the field is absent.
    """
    try:
        result = call_sony_api(
            host=host, port=port,
            method="getPowerSavingMode",
            params=[], version="1.0",
            request_id=4, psk=psk, timeout=timeout
        )
        if "error" in result:
            return "N/A"
        data = result.get("result", [{}])[0]
        return data.get("mode", "N/A") or "N/A"
    except Exception:
        return "N/A"


def set_auth_none(host: str, port: int, psk: str,
                  timeout: int = DEFAULT_TIMEOUT) -> tuple:
    """
    Use the PSK to set the display's IP control authentication to None.

    Returns:
        tuple of (success: bool, message: str)
    """
    try:
        result = call_sony_api(
            host=host, port=port,
            method="setRemoteDeviceSettings",
            params=[{"target": "accessPermission", "value": "off"}],
            version="1.0", request_id=20, psk=psk, timeout=timeout
        )
        if "error" in result:
            error_code = result["error"][0] if isinstance(result["error"], list) else result["error"]
            error_msg  = result["error"][1] if isinstance(result["error"], list) and len(result["error"]) > 1 else "Unknown"
            return False, f"API error {error_code}: {error_msg}"
        return True, "Authentication set to None"

    except requests.exceptions.HTTPError as e:
        code = e.response.status_code if e.response else "?"
        if code == 403:
            return False, "HTTP 403 — PSK incorrect or auth already set to None"
        return False, f"HTTP {code}"
    except Timeout:
        return False, "Connection timed out"
    except RequestsConnectionError:
        return False, f"Cannot connect to {host}:{port}"
    except Exception as e:
        return False, str(e)


def query_display(host: str, port: int, psk: str = None,
                  timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Query a single Sony Bravia display for firmware/system information
    and power saving mode.
    """
    result = {
        "host":               host,
        "port":               port,
        "status":             "ERROR",
        "model":              "N/A",
        "serial":             "N/A",
        "firmware_version":   "N/A",
        "firmware_version_raw": "N/A",
        "mac_address":        "N/A",
        "device_name":        "N/A",
        "interface_version":  "N/A",
        "product_name":       "N/A",
        "generation":         "N/A",
        "api_version_used":   "N/A",
        "power_saving_mode":  "N/A",
        "auth_note":          None,
        "error":              None,
        "timestamp":          datetime.utcnow().isoformat() + "Z"
    }

    # If no PSK was provided and we get a 403, retry once with the fallback PSK.
    def _try_query(effective_psk):
        return get_system_information(host, port, effective_psk, timeout)

    try:
        try:
            sys_info, api_version = _try_query(psk)
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 403 and not psk:
                sys_info, api_version = _try_query(FALLBACK_PSK)
                psk = FALLBACK_PSK
                result["auth_note"] = f"fallback PSK '{FALLBACK_PSK}' used"
            else:
                raise

        result["api_version_used"] = api_version
        result["model"]       = sys_info.get("model",      "N/A")
        result["serial"]      = sys_info.get("serial",     "N/A")
        result["mac_address"] = sys_info.get("macAddr",    "N/A")
        result["device_name"] = sys_info.get("name",       "N/A")
        result["generation"]  = sys_info.get("generation", "N/A")
        result["product_name"]= sys_info.get("product",    "N/A")

        # v1.7 exposes "fwVersion" — the actual firmware build string.
        # v1.0/v1.4 do not; fall back to "generation" as the best available identifier.
        if api_version == "1.7":
            raw_fw = sys_info.get("fwVersion", "N/A") or "N/A"
            result["firmware_version"] = parse_fw_version(raw_fw)
            result["firmware_version_raw"] = raw_fw
        else:
            result["firmware_version"] = sys_info.get("generation", "N/A") or "N/A"
            result["firmware_version_raw"] = "N/A"

        result["status"] = "OK"

        try:
            iface_info = get_interface_information(host, port, psk, timeout)
            if iface_info:
                result["interface_version"] = iface_info.get("interfaceVersion", "N/A")
                if result["product_name"] == "N/A":
                    result["product_name"] = iface_info.get("productName", "N/A")
        except Exception:
            pass

        if result["mac_address"] == "N/A" or not result["mac_address"]:
            try:
                net_settings = get_network_settings(host, port, psk, timeout)
                for iface in net_settings:
                    hw_addr = iface.get("hwAddr", "")
                    if hw_addr:
                        result["mac_address"] = hw_addr
                        break
            except Exception:
                pass

        # Power saving mode (best-effort; does not affect status).
        result["power_saving_mode"] = get_power_saving_mode(host, port, psk, timeout)

    except Timeout:
        result["error"] = "Connection timed out"
    except RequestsConnectionError:
        result["error"] = f"Cannot connect to {host}:{port}"
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response else "Unknown"
        if status_code == 403:
            result["error"] = "HTTP 403 — check PSK or set auth to None"
        elif status_code == 404:
            result["error"] = "HTTP 404 — IP control not enabled"
        else:
            result["error"] = f"HTTP {status_code}"
    except Exception as e:
        result["error"] = str(e)

    return result


def read_csv_input(filepath: str) -> list:
    """Read the CSV input file containing host and port columns."""
    displays = []

    if not os.path.exists(filepath):
        print(f"ERROR: CSV file '{filepath}' not found.")
        print(f"Please create '{filepath}' with the following format:\n")
        print("  host,port")
        print("  192.168.1.100,80")
        print("  192.168.1.101,80")
        sys.exit(1)

    with open(filepath, "r", newline="", encoding="utf-8-sig") as csvfile:
        reader = csv.DictReader(csvfile)

        if not reader.fieldnames:
            print("ERROR: CSV file is empty or has no headers.")
            sys.exit(1)

        normalized_fields = [f.strip().lower() for f in reader.fieldnames]
        if "host" not in normalized_fields:
            print(f"ERROR: CSV must contain a 'host' column. Found columns: {reader.fieldnames}")
            sys.exit(1)

        for row_num, row in enumerate(reader, start=2):
            normalized_row = {k.strip().lower(): v.strip() for k, v in row.items() if v}
            host = normalized_row.get("host", "").strip()
            if not host:
                print(f"WARNING: Skipping row {row_num} — empty host.")
                continue
            try:
                port = int(normalized_row.get("port", str(DEFAULT_PORT)).strip())
            except ValueError:
                print(f"WARNING: Invalid port on row {row_num}, defaulting to {DEFAULT_PORT}.")
                port = DEFAULT_PORT
            displays.append({"host": host, "port": port})

    if not displays:
        print("ERROR: No valid display entries found in CSV.")
        sys.exit(1)

    return displays


def save_results_json(results: list, filepath: str = DEFAULT_OUTPUT):
    """Save query results to a JSON file."""
    output = {
        "query_timestamp":    datetime.utcnow().isoformat() + "Z",
        "total_displays":     len(results),
        "successful_queries": sum(1 for r in results if r["status"] == "OK"),
        "failed_queries":     sum(1 for r in results if r["status"] == "ERROR"),
        "results":            results
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to: {filepath}")


def truncate(text: str, length: int = None) -> str:
    """Truncate a string to specified length with ellipsis."""
    if length is None:
        length = get_error_truncate_length()
    if not text:
        return ""
    if len(text) <= length:
        return text
    return text[:length - 3] + "..."


def print_results_table(results: list):
    """Print results as a formatted table scaled to terminal width."""
    term_width = get_terminal_width()
    error_max  = get_error_truncate_length()

    # Column ladder (narrowest to widest):
    #   always:  Status, Host, Model, Firmware Version
    #   narrow+: Serial
    #   medium+: MAC Address, API Ver, Pwr Save
    #   wide+:   Error
    wide   = term_width >= 160
    medium = term_width >= 120
    narrow = term_width >= 80

    table_data = []
    for r in results:
        status_icon = "✓" if r["status"] == "OK" else "✗"
        row = [
            f"{status_icon} {r['status']}",
            r["host"],
            r["model"],
            r["firmware_version"],
        ]
        if narrow:
            row.append(r["serial"])
        if medium:
            row.append(r["mac_address"])
            row.append(r["api_version_used"])
            row.append(format_power_saving_mode(r.get("power_saving_mode", "N/A")))
        if wide:
            error_str = r.get("error", "") or ""
            auth_note = r.get("auth_note", "") or ""
            cell = truncate(error_str, error_max)
            if auth_note:
                cell = f"{cell} [{auth_note}]".strip()
            row.append(cell)
        table_data.append(row)

    headers = ["Status", "Host", "Model", "Firmware Version"]
    if narrow:
        headers.append("Serial")
    if medium:
        headers.extend(["MAC Address", "API Ver", "Pwr Save"])
    if wide:
        headers.append("Error / Note")

    separator = "=" * term_width
    title = "Sony Bravia BZ40H/BZ40L — Firmware Version Query Results"

    print(f"\n{separator}")
    print(title.center(term_width))
    print(separator)

    try:
        print(tabulate(table_data, headers=headers, tablefmt="pipe",
                       maxcolwidths=[None] * len(headers)))
    except TypeError:
        print(tabulate(table_data, headers=headers, tablefmt="pipe"))

    summary = (f"Total: {len(results)} | "
               f"Success: {sum(1 for r in results if r['status'] == 'OK')} | "
               f"Failed: {sum(1 for r in results if r['status'] == 'ERROR')}")

    print(f"\n{summary}")

    if medium:
        psm_counts = {}
        for r in results:
            mode = r.get("power_saving_mode", "N/A")
            psm_counts[mode] = psm_counts.get(mode, 0) + 1
        psm_parts = ", ".join(
            f"{POWER_SAVING_LABELS.get(m, m)}: {c}"
            for m, c in sorted(psm_counts.items())
        )
        print(f"Power Saving — {psm_parts}")

    hidden = []
    if not narrow:
        hidden.append("Serial")
    if not medium:
        hidden.extend(["MAC Address", "API Ver", "Pwr Save"])
    if not wide:
        hidden.append("Error")
    if hidden:
        print(f"(Columns hidden due to terminal width: {', '.join(hidden)} — "
              f"widen terminal or see {DEFAULT_OUTPUT} for full data)")

    print(f"Terminal width: {term_width} cols")


def main():
    parser = argparse.ArgumentParser(
        description="Query Sony Bravia BZ40H/BZ40L displays for firmware version via Sony REST API.",
        epilog="""
Examples:
  python sony_fw_query.py
  python sony_fw_query.py -i my_displays.csv
  python sony_fw_query.py -k MyPreSharedKey
  python sony_fw_query.py -i displays.csv -k 0000 -t 15 -o output.json

  # Set auth to None on all displays in CSV using PSK:
  python sony_fw_query.py --set-auth-none -k 0000

  # Set auth to None on a single display:
  python sony_fw_query.py --set-auth-none -k 0000 --host 192.168.1.100

Authentication:
  By default NO authentication is used (X-Auth-PSK header is omitted).
  This requires displays to be set to Authentication = None.

  To use PSK authentication, pass -k <key>:
    python sony_fw_query.py -k 0000

  Display setting for no auth:
    Settings > Network > Home Network > IP Control > Authentication > None

  Display setting for PSK auth:
    Settings > Network > Home Network > IP Control > Authentication > Normal and Pre-Shared Key
    Settings > Network > Home Network > IP Control > Pre-Shared Key > <your key>

Firmware Version:
  On v1.7 devices the "fwVersion" field is used (e.g. PKG0.6.0.81.00.1.00.0951BBA).
  On v1.0/v1.4 devices "fwVersion" is not available; "generation" is shown instead.

Power Saving Mode:
  getPowerSavingMode (v1.0) is queried for every display.
  Auth level for this API is None, so it works with or without a PSK.
  Documented values: off, low, high, pictureOff.
  The column appears in the table at medium terminal width (>=120 cols).
  The footer prints a breakdown of mode counts across all queried displays.

API Version:
  The script tries getSystemInformation v1.7 first, then falls back to
  v1.4 and v1.0 for older firmware. The API version used is shown in results.

CSV Format (default: displays.csv):
  host,port
  192.168.1.100,80
  192.168.1.101,80
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-i", "--input",   default=DEFAULT_CSV,
        help=f"Path to CSV file with 'host' and 'port' columns (default: {DEFAULT_CSV})")
    parser.add_argument("--host",          default=None,
        help="Query a single display by hostname/IP (e.g. --host 192.168.1.100)")
    parser.add_argument("-o", "--output",  default=DEFAULT_OUTPUT,
        help=f"Output JSON file path (default: {DEFAULT_OUTPUT})")
    parser.add_argument("-k", "--psk",     default=DEFAULT_PSK,
        help="Pre-Shared Key for authentication (default: no authentication)")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-p", "--port",    type=int, default=DEFAULT_PORT,
        help=f"Port for --host mode (default: {DEFAULT_PORT})")
    parser.add_argument("--set-auth-none", action="store_true", default=False,
        help="Use the PSK (-k) to set each display's IP control authentication to None.")
    parser.add_argument("--raw",           action="store_true", default=False,
        help="When used with --host, dump raw getSystemInformation responses for all API versions.")

    args = parser.parse_args()

    if args.set_auth_none and not args.psk:
        print("ERROR: --set-auth-none requires a PSK via -k (default Sony PSK is 0000)")
        print("  Example: python sony_fw_query.py --set-auth-none -k 0000")
        sys.exit(1)

    term_width = get_terminal_width()

    # -------------------------------------------------------------------------
    # --set-auth-none mode
    # -------------------------------------------------------------------------
    if args.set_auth_none:
        displays = [{"host": args.host, "port": args.port}] if args.host else read_csv_input(args.input)

        print(f"Mode:     Set authentication to None")
        print(f"PSK:      {args.psk}")
        print(f"Displays: {len(displays)}\n")

        auth_results = []
        with tqdm(total=len(displays), desc="Setting auth to None",
                  bar_format=f"{{l_bar}}{CYAN}{{bar}}{RESET}{{r_bar}}",
                  ncols=max(40, term_width - 2), unit="display") as pbar:
            for d in displays:
                pbar.set_postfix_str(d["host"], refresh=True)
                success, message = set_auth_none(d["host"], d["port"], psk=args.psk, timeout=args.timeout)
                auth_results.append({"host": d["host"], "port": d["port"],
                                     "success": success, "message": message})
                pbar.update(1)

        separator = "=" * term_width
        print(f"\n{separator}")
        print("Set Authentication to None — Results".center(term_width))
        print(separator)
        print(tabulate(
            [["✓ OK" if r["success"] else "✗ FAIL", r["host"], r["message"]] for r in auth_results],
            headers=["Status", "Host", "Message"], tablefmt="pipe"
        ))
        ok = sum(1 for r in auth_results if r["success"])
        print(f"\nTotal: {len(auth_results)} | Success: {ok} | Failed: {len(auth_results) - ok}")
        return

    # Print configuration
    print(f"Authentication: {'PSK (Pre-Shared Key)' if args.psk else 'None (no X-Auth-PSK header)'}")

    # -------------------------------------------------------------------------
    # Single-host mode: --host
    # -------------------------------------------------------------------------
    if args.host:
        print(f"Mode:         Single host ({args.host}:{args.port})")
        print(f"API versions: Will try {' -> '.join(SYSTEM_INFO_VERSIONS)} (automatic fallback)\n")

        if args.raw:
            print("Raw getSystemInformation responses:\n")
            for v in SYSTEM_INFO_VERSIONS:
                try:
                    r = call_sony_api(args.host, args.port, "getSystemInformation", [], v,
                                      psk=args.psk, timeout=args.timeout)
                    print(f"--- v{v} ---")
                    print(json.dumps(r, indent=2))
                except Exception as e:
                    print(f"--- v{v} --- ERROR: {e}")
                print()
            try:
                r = call_sony_api(args.host, args.port, "getInterfaceInformation", [], "1.0",
                                  request_id=2, psk=args.psk, timeout=args.timeout)
                print("--- getInterfaceInformation v1.0 ---")
                print(json.dumps(r, indent=2))
            except Exception as e:
                print(f"--- getInterfaceInformation v1.0 --- ERROR: {e}")
            return

        result = query_display(args.host, args.port, psk=args.psk, timeout=args.timeout)
        print_results_table([result])
        save_results_json([result], args.output)
        return

    # -------------------------------------------------------------------------
    # Normal CSV batch mode
    # -------------------------------------------------------------------------
    print(f"API versions: Will try {' -> '.join(SYSTEM_INFO_VERSIONS)} (automatic fallback)")
    print(f"Reading:      {args.input}")

    displays = read_csv_input(args.input)
    print(f"Displays:     {len(displays)} found")
    print(f"Terminal:     {term_width} cols\n")

    results = []
    with tqdm(total=len(displays), desc="Querying displays",
              bar_format=f"{{l_bar}}{CYAN}{{bar}}{RESET}{{r_bar}}",
              ncols=max(40, term_width - 2), unit="display") as pbar:
        for d in displays:
            pbar.set_postfix_str(d["host"], refresh=True)
            results.append(query_display(d["host"], d["port"], psk=args.psk, timeout=args.timeout))
            pbar.update(1)

    print_results_table(results)
    save_results_json(results, args.output)


if __name__ == "__main__":
    main()
