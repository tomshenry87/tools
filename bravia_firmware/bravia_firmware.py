#!/usr/bin/env python3
"""
Sony Bravia BZ40H/BZ40L Firmware Version Query Tool

Uses the Sony BRAVIA REST API (JSON-RPC) documented in:
  - Sony BRAVIA Professional Display IP Control API
  - Endpoint: /sony/system
  - Method: getSystemInformation (v1.7 with fallback to v1.0)
  - Method: getInterfaceInformation (v1.0)
  - Method: getDeviceStatus (v1.0) — used for temperature query

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

from requests.exceptions import RequestException, Timeout, ConnectionError as RequestsConnectionError

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
DEFAULT_CSV = "displays.csv"
DEFAULT_OUTPUT = "results.json"
DEFAULT_PSK = None
DEFAULT_TIMEOUT = 10
DEFAULT_PORT = 80
API_ENDPOINT = "/sony/system"

# ANSI color codes
CYAN = "\033[96m"
RESET = "\033[0m"

# Ordered list of API versions to try for getSystemInformation
SYSTEM_INFO_VERSIONS = ["1.7", "1.4", "1.0"]

# Temperature target names to try, in order of preference.
# The BZ40H/BZ40L typically reports cabinet temperature via getDeviceStatus.
# Some firmware versions also expose boardTemp/cabinetTemp in getSystemInformation.
TEMPERATURE_TARGETS = ["cabinetTemp", "boardTemp", "temperature"]

# Firmware major versions known NOT to support temperature via the REST API.
# Generation 5.x (e.g. 5.5.0) does not implement getDeviceStatus at all —
# confirmed by getMethodTypes returning no such method and error code 12.
TEMP_UNSUPPORTED_GENERATIONS = {5}


def firmware_supports_temperature(generation: str) -> tuple:
    """
    Check whether this firmware generation is known to support temperature queries.

    Returns:
        tuple of (supported: bool, reason: str)
    """
    if not generation or generation == "N/A":
        return True, ""  # Unknown — let it try; fail gracefully

    try:
        major = int(generation.split(".")[0])
    except (ValueError, IndexError):
        return True, ""  # Unparseable — let it try

    if major in TEMP_UNSUPPORTED_GENERATIONS:
        return False, f"not supported on generation {generation} firmware (getDeviceStatus unavailable)"

    return True, ""


def celsius_to_fahrenheit(celsius: float) -> float:
    """Convert Celsius to Fahrenheit."""
    return round((celsius * 9 / 5) + 32, 1)


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
    """
    Build request headers based on authentication mode.
    """
    headers = {
        "Content-Type": "application/json"
    }

    if psk:
        headers["X-Auth-PSK"] = psk

    return headers


def call_sony_api(host: str, port: int, method: str, params: list,
                  version: str, request_id: int = 1, psk: str = None,
                  timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Generic Sony BRAVIA JSON-RPC API caller.
    """
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}{API_ENDPOINT}"

    payload = {
        "method": method,
        "id": request_id,
        "params": params,
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
                host=host,
                port=port,
                method="getSystemInformation",
                params=[],
                version=api_version,
                request_id=1,
                psk=psk,
                timeout=timeout
            )

            if "error" in result:
                error_code = result["error"][0] if isinstance(result["error"], list) else result["error"]
                error_msg = result["error"][1] if isinstance(result["error"], list) and len(result["error"]) > 1 else "Unknown"

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
            error_str = str(e)
            if "API Error" in error_str:
                last_error = error_str
                continue
            else:
                raise

    raise Exception(f"All API versions failed. Last: {last_error}")


def get_interface_information(host: str, port: int, psk: str = None,
                              timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Calls getInterfaceInformation v1.0.
    """
    result = call_sony_api(
        host=host,
        port=port,
        method="getInterfaceInformation",
        params=[],
        version="1.0",
        request_id=2,
        psk=psk,
        timeout=timeout
    )

    if "error" in result:
        return {}

    return result.get("result", [{}])[0]


def get_network_settings(host: str, port: int, psk: str = None,
                         timeout: int = DEFAULT_TIMEOUT) -> list:
    """
    Calls getNetworkSettings v1.0.
    """
    try:
        result = call_sony_api(
            host=host,
            port=port,
            method="getNetworkSettings",
            params=[{"netif": ""}],
            version="1.0",
            request_id=3,
            psk=psk,
            timeout=timeout
        )

        if "error" in result:
            return []

        return result.get("result", [[]])[0]
    except Exception:
        return []


def set_auth_none(host: str, port: int, psk: str,
                  timeout: int = DEFAULT_TIMEOUT) -> tuple:
    """
    Use the PSK to set the display's IP control authentication to None.

    This calls setRemoteDeviceSettings with target=accessPermission, value=off,
    which is equivalent to setting:
      Settings > Network & Internet > Local network setup > IP Control >
      Authentication > None

    Requires a valid PSK to authenticate the request. Once set, subsequent
    requests can omit the X-Auth-PSK header entirely.

    Returns:
        tuple of (success: bool, message: str)
    """
    try:
        result = call_sony_api(
            host=host,
            port=port,
            method="setRemoteDeviceSettings",
            params=[{"target": "accessPermission", "value": "off"}],
            version="1.0",
            request_id=20,
            psk=psk,
            timeout=timeout
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


def get_temperature(host: str, port: int, psk: str = None,
                    timeout: int = DEFAULT_TIMEOUT) -> tuple:
    """
    Query the display's internal temperature via getDeviceStatus.

    The BZ40H/BZ40L exposes temperature through getDeviceStatus with a
    target parameter. The API returns temperature in Celsius as an integer
    or float string. We try multiple target names in order of preference.

    Falls back to reading boardTemp/cabinetTemp directly from
    getSystemInformation if getDeviceStatus is unsupported.

    Returns:
        tuple of (temp_celsius: float | None, temp_fahrenheit: float | None, source: str)
        source describes where the value came from (for transparency in JSON output).
    """
    # Strategy 1: getDeviceStatus with explicit temperature targets
    for target in TEMPERATURE_TARGETS:
        try:
            result = call_sony_api(
                host=host,
                port=port,
                method="getDeviceStatus",
                params=[{"target": target}],
                version="1.0",
                request_id=10,
                psk=psk,
                timeout=timeout
            )

            if "error" in result:
                continue

            items = result.get("result", [[]])[0]
            if not isinstance(items, list):
                items = [items]

            for item in items:
                value = item.get("value") if isinstance(item, dict) else None
                if value is not None:
                    try:
                        temp_c = float(value)
                        return temp_c, celsius_to_fahrenheit(temp_c), f"getDeviceStatus/{target}"
                    except (ValueError, TypeError):
                        continue

        except Exception:
            continue

    # Strategy 2: getDeviceStatus with no target (returns all status items)
    try:
        result = call_sony_api(
            host=host,
            port=port,
            method="getDeviceStatus",
            params=[{"target": ""}],
            version="1.0",
            request_id=11,
            psk=psk,
            timeout=timeout
        )

        if "error" not in result:
            items = result.get("result", [[]])[0]
            if isinstance(items, list):
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    item_target = item.get("target", "").lower()
                    if any(t in item_target for t in ["temp", "temperature"]):
                        value = item.get("value")
                        if value is not None:
                            try:
                                temp_c = float(value)
                                return temp_c, celsius_to_fahrenheit(temp_c), f"getDeviceStatus/{item.get('target', 'unknown')}"
                            except (ValueError, TypeError):
                                pass
    except Exception:
        pass

    # Strategy 3: boardTemp / cabinetTemp fields from getSystemInformation result
    # (some firmware versions embed these directly in the sysinfo response)
    try:
        sys_info, _ = get_system_information(host, port, psk, timeout)
        for field in ["cabinetTemp", "boardTemp"]:
            raw = sys_info.get(field)
            if raw is not None:
                try:
                    temp_c = float(raw)
                    return temp_c, celsius_to_fahrenheit(temp_c), f"getSystemInformation/{field}"
                except (ValueError, TypeError):
                    continue
    except Exception:
        pass

    return None, None, "N/A"


def query_display(host: str, port: int, psk: str = None,
                  timeout: int = DEFAULT_TIMEOUT,
                  query_temp: bool = True) -> dict:
    """
    Query a single Sony Bravia display for firmware/system information
    and optionally its internal temperature.
    """
    result = {
        "host": host,
        "port": port,
        "status": "ERROR",
        "model": "N/A",
        "serial": "N/A",
        "firmware_version": "N/A",
        "mac_address": "N/A",
        "device_name": "N/A",
        "interface_version": "N/A",
        "product_name": "N/A",
        "generation": "N/A",
        "api_version_used": "N/A",
        "temperature_c": None,
        "temperature_f": None,
        "temperature_source": "N/A",
        "error": None,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    try:
        sys_info, api_version = get_system_information(host, port, psk, timeout)

        result["api_version_used"] = api_version
        result["model"] = sys_info.get("model", "N/A")
        result["serial"] = sys_info.get("serial", "N/A")
        result["mac_address"] = sys_info.get("macAddr", "N/A")
        result["device_name"] = sys_info.get("name", "N/A")
        result["generation"] = sys_info.get("generation", "N/A")
        result["product_name"] = sys_info.get("product", "N/A")

        firmware = sys_info.get("version", "")
        if not firmware:
            firmware = sys_info.get("generation", "N/A")
        result["firmware_version"] = firmware

        result["status"] = "OK"

        try:
            iface_info = get_interface_information(host, port, psk, timeout)
            if iface_info:
                result["interface_version"] = iface_info.get("interfaceVersion", "N/A")
                if result["product_name"] == "N/A":
                    result["product_name"] = iface_info.get("productName", "N/A")

                if result["firmware_version"] == "N/A" or not result["firmware_version"]:
                    server_name = iface_info.get("serverName", "")
                    if server_name:
                        result["firmware_version"] = server_name
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

        # Temperature query (best-effort; does not affect status).
        # Skip early if this firmware generation is known not to support it.
        if query_temp:
            supported, skip_reason = firmware_supports_temperature(result["generation"])
            if supported:
                temp_c, temp_f, temp_source = get_temperature(host, port, psk, timeout)
                result["temperature_c"] = temp_c
                result["temperature_f"] = temp_f
                result["temperature_source"] = temp_source
            else:
                result["temperature_c"] = None
                result["temperature_f"] = None
                result["temperature_source"] = f"skipped — {skip_reason}"

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
        "query_timestamp": datetime.utcnow().isoformat() + "Z",
        "total_displays": len(results),
        "successful_queries": sum(1 for r in results if r["status"] == "OK"),
        "failed_queries": sum(1 for r in results if r["status"] == "ERROR"),
        "results": results
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


def format_temperature(temp_f) -> str:
    """Format a temperature value for display. Returns 'N/A' if unavailable."""
    if temp_f is None:
        return "N/A"
    return f"{temp_f}°F"


def print_results_table(results: list, show_temp: bool = True):
    """Print results as a formatted table scaled to terminal width."""
    term_width = get_terminal_width()
    error_max = get_error_truncate_length()

    # Determine which columns to show based on terminal width.
    # Temperature is included whenever show_temp is True and terminal allows it.
    # Column ladder (narrowest to widest):
    #   always:  Status, Host, Model, Firmware Version
    #   narrow+: Serial
    #   medium+: MAC Address, API Ver
    #   wide+:   Temp (°F), Error
    wide = term_width >= 160
    medium = term_width >= 120
    narrow = term_width >= 80

    table_data = []
    for r in results:
        status_icon = "✓" if r["status"] == "OK" else "✗"
        error_info = truncate(r.get("error", "") or "", error_max)

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
        if wide and show_temp:
            row.append(format_temperature(r.get("temperature_f")))
        if wide:
            row.append(error_info)

        table_data.append(row)

    headers = [
        "Status", "Host", "Model", "Firmware Version",
    ]

    if narrow:
        headers.append("Serial")
    if medium:
        headers.extend(["MAC Address", "API Ver"])
    if wide and show_temp:
        headers.append("Temp (°F)")
    if wide:
        headers.append("Error")

    separator = "=" * term_width
    title = "Sony Bravia BZ40H/BZ40L — Firmware Version Query Results"

    print(f"\n{separator}")
    print(title.center(term_width))
    print(separator)

    try:
        print(tabulate(
            table_data,
            headers=headers,
            tablefmt="pipe",
            maxcolwidths=[None] * len(headers)
        ))
    except TypeError:
        # Older tabulate versions don't support maxcolwidths
        print(tabulate(table_data, headers=headers, tablefmt="pipe"))

    summary = (f"Total: {len(results)} | "
               f"Success: {sum(1 for r in results if r['status'] == 'OK')} | "
               f"Failed: {sum(1 for r in results if r['status'] == 'ERROR')}")

    # Temperature summary line (only when temp was queried)
    if show_temp:
        temps_available = [r for r in results if r.get("temperature_f") is not None]
        if temps_available:
            avg_f = sum(r["temperature_f"] for r in temps_available) / len(temps_available)
            max_f = max(r["temperature_f"] for r in temps_available)
            min_f = min(r["temperature_f"] for r in temps_available)
            temp_summary = (f"Temperature — Avg: {avg_f:.1f}°F  "
                            f"Min: {min_f}°F  Max: {max_f}°F  "
                            f"({len(temps_available)}/{len(results)} reported)")
        else:
            temp_summary = "Temperature — not available on any queried display"

    # Show hidden columns hint if terminal is too narrow
    hidden = []
    if not narrow:
        hidden.extend(["Serial"])
    if not medium:
        hidden.extend(["MAC Address", "API Ver"])
    if not wide:
        if show_temp:
            hidden.extend(["Temp (°F)"])
        hidden.extend(["Error"])

    print(f"\n{summary}")

    if show_temp:
        print(temp_summary)

    if hidden:
        print(f"(Columns hidden due to terminal width: {', '.join(hidden)} — "
              f"widen terminal or see {DEFAULT_OUTPUT} for full data)")

    print(f"Terminal width: {term_width} cols")


def main():
    parser = argparse.ArgumentParser(
        description="Query Sony Bravia BZ40H/BZ40L displays for firmware version and temperature via Sony REST API.",
        epilog="""
Examples:
  python sony_fw_query.py
  python sony_fw_query.py -i my_displays.csv
  python sony_fw_query.py -k MyPreSharedKey
  python sony_fw_query.py -i displays.csv -k 0000 -t 15 -o output.json
  python sony_fw_query.py --no-temp

  # Set auth to None on all displays in CSV using default PSK:
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

Temperature:
  Temperature is queried by default via getDeviceStatus (v1.0) on /sony/system.
  The script tries the following target names in order:
    cabinetTemp, boardTemp, temperature
  It also falls back to reading boardTemp/cabinetTemp fields from
  getSystemInformation if getDeviceStatus does not respond.

  Results are reported in Fahrenheit (°F) in the table and in both
  Celsius and Fahrenheit in the JSON output file.

  Firmware skip logic:
    Generation 5.x (e.g. FW-55BZ40L on 5.5.0) does not implement
    getDeviceStatus at all. The script detects this from the generation
    field and skips the temperature query immediately rather than making
    several failing API calls. The JSON output will show:
      "temperature_source": "skipped — not supported on generation 5.5.0 firmware"
    To add or remove generations from the skip list, edit
    TEMP_UNSUPPORTED_GENERATIONS in the script.

  Temperature is a best-effort query — if unsupported by a display's
  firmware, "N/A" is shown and the overall query status is not affected.

  Use --no-temp to skip temperature queries entirely (faster).

API Version:
  The script automatically tries getSystemInformation v1.7 first (which
  includes a direct 'version' firmware field), then falls back to v1.4
  and finally v1.0 for older firmware. The API version used is shown in
  the results.

CSV Format (default: displays.csv):
  host,port
  192.168.1.100,80
  192.168.1.101,80
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-i", "--input",
        default=DEFAULT_CSV,
        help=f"Path to CSV file with 'host' and 'port' columns (default: {DEFAULT_CSV})"
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Query a single display by hostname/IP instead of reading a CSV (e.g. --host 192.168.1.100)"
    )
    parser.add_argument(
        "-o", "--output",
        default=DEFAULT_OUTPUT,
        help=f"Output JSON file path (default: {DEFAULT_OUTPUT})"
    )
    parser.add_argument(
        "-k", "--psk",
        default=DEFAULT_PSK,
        help="Pre-Shared Key for authentication (default: no authentication)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port to use when querying a single host via --host (default: {DEFAULT_PORT})"
    )
    parser.add_argument(
        "--no-temp",
        action="store_true",
        default=False,
        help="Skip temperature queries (faster; use if your firmware does not support it)"
    )
    parser.add_argument(
        "--set-auth-none",
        action="store_true",
        default=False,
        help=(
            "Use the PSK (-k) to set each display's IP control authentication to None. "
            "Requires -k to be set (default PSK is 0000). "
            "Does not query firmware or temperature — auth change only."
        )
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        default=False,
        help="When used with --host, dump the raw getSystemInformation response for all API versions"
    )

    args = parser.parse_args()
    query_temp = not args.no_temp

    # --set-auth-none requires a PSK to authenticate the change
    if args.set_auth_none and not args.psk:
        print("ERROR: --set-auth-none requires a PSK via -k (default Sony PSK is 0000)")
        print("  Example: python sony_fw_query.py --set-auth-none -k 0000")
        sys.exit(1)

    term_width = get_terminal_width()

    # -------------------------------------------------------------------------
    # --set-auth-none mode: iterate displays and remove PSK requirement
    # -------------------------------------------------------------------------
    if args.set_auth_none:
        if args.host:
            displays = [{"host": args.host, "port": args.port}]
        else:
            displays = read_csv_input(args.input)

        print(f"Mode:           Set authentication to None")
        print(f"PSK:            {args.psk}")
        print(f"Displays:       {len(displays)}\n")

        bar_width = max(40, get_terminal_width() - 2)
        auth_results = []

        with tqdm(
            total=len(displays),
            desc="Setting auth to None",
            bar_format=f"{{l_bar}}{CYAN}{{bar}}{RESET}{{r_bar}}",
            ncols=bar_width,
            unit="display"
        ) as pbar:
            for display in displays:
                host = display["host"]
                port = display["port"]
                pbar.set_postfix_str(host, refresh=True)
                success, message = set_auth_none(host, port, psk=args.psk, timeout=args.timeout)
                auth_results.append({
                    "host": host,
                    "port": port,
                    "success": success,
                    "message": message
                })
                pbar.update(1)

        # Print results table
        term_width = get_terminal_width()
        separator = "=" * term_width
        print(f"\n{separator}")
        print("Set Authentication to None — Results".center(term_width))
        print(separator)

        table_data = [
            [
                "✓ OK" if r["success"] else "✗ FAIL",
                r["host"],
                r["message"]
            ]
            for r in auth_results
        ]
        print(tabulate(table_data, headers=["Status", "Host", "Message"], tablefmt="pipe"))

        ok    = sum(1 for r in auth_results if r["success"])
        failed = sum(1 for r in auth_results if not r["success"])
        print(f"\nTotal: {len(auth_results)} | Success: {ok} | Failed: {failed}")
        return

    # Print configuration
    if args.psk:
        print(f"Authentication: PSK (Pre-Shared Key)")
    else:
        print(f"Authentication: None (no X-Auth-PSK header)")

    # -------------------------------------------------------------------------
    # Single-host mode: --host
    # -------------------------------------------------------------------------
    if args.host:
        host = args.host
        port = args.port
        print(f"Mode:           Single host ({host}:{port})")
        print(f"API versions:   Will try {' -> '.join(SYSTEM_INFO_VERSIONS)} (automatic fallback)\n")

        if args.raw:
            # Dump raw getSystemInformation for every version so we can
            # inspect exactly which fields the device returns
            print("Raw getSystemInformation responses:\n")
            for v in SYSTEM_INFO_VERSIONS:
                try:
                    result = call_sony_api(host, port, "getSystemInformation", [], v,
                                           psk=args.psk, timeout=args.timeout)
                    print(f"--- v{v} ---")
                    print(json.dumps(result, indent=2))
                except Exception as e:
                    print(f"--- v{v} --- ERROR: {e}")
                print()

            # Also dump getInterfaceInformation raw
            try:
                result = call_sony_api(host, port, "getInterfaceInformation", [], "1.0",
                                       request_id=2, psk=args.psk, timeout=args.timeout)
                print("--- getInterfaceInformation v1.0 ---")
                print(json.dumps(result, indent=2))
            except Exception as e:
                print(f"--- getInterfaceInformation v1.0 --- ERROR: {e}")
            return

        result = query_display(host, port, psk=args.psk, timeout=args.timeout,
                               query_temp=query_temp)

        print_results_table([result], show_temp=query_temp)
        save_results_json([result], args.output)
        return

    # -------------------------------------------------------------------------
    # Normal CSV batch mode
    # -------------------------------------------------------------------------
    print(f"API versions:   Will try {' -> '.join(SYSTEM_INFO_VERSIONS)} (automatic fallback)")
    print(f"Temperature:    {'Enabled (°F, best-effort)' if query_temp else 'Disabled (--no-temp)'}")
    print(f"Reading:        {args.input}")

    displays = read_csv_input(args.input)
    print(f"Displays:       {len(displays)} found")
    print(f"Terminal:       {term_width} cols\n")

    bar_width = max(40, term_width - 2)

    results = []
    with tqdm(
        total=len(displays),
        desc="Querying displays",
        bar_format=f"{{l_bar}}{CYAN}{{bar}}{RESET}{{r_bar}}",
        ncols=bar_width,
        unit="display"
    ) as pbar:
        for display in displays:
            host = display["host"]
            port = display["port"]

            pbar.set_postfix_str(host, refresh=True)

            result = query_display(host, port, psk=args.psk, timeout=args.timeout,
                                   query_temp=query_temp)
            results.append(result)

            pbar.update(1)

    print_results_table(results, show_temp=query_temp)
    save_results_json(results, args.output)


if __name__ == "__main__":
    main()
