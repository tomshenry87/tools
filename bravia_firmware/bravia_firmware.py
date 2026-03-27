#!/usr/bin/env python3
"""
Sony Bravia Professional Display Firmware Query & Update Tool

Uses the Sony BRAVIA REST API (JSON-RPC) documented in:
  - Sony BRAVIA Professional Display IP Control API
  - Endpoint: /sony/system
  - Method: getSystemInformation (v1.7 with fallback to v1.0)
  - Method: getInterfaceInformation (v1.0)
  - Method: getCurrentSoftwareUpdateInformation (v1.0)
  - Method: getSoftwareUpdateInfo (v1.0) [fallback]
  - Method: setSoftwareUpdate (v1.0)

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

# Methods to try for update information (in order)
UPDATE_CHECK_METHODS = [
    {"method": "getCurrentSoftwareUpdateInformation", "version": "1.0", "params": []},
    {"method": "getSoftwareUpdateInfo", "version": "1.0", "params": []},
]


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
    headers = {
        "Content-Type": "application/json"
    }
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


def get_supported_methods(host: str, port: int, psk: str = None,
                          timeout: int = DEFAULT_TIMEOUT,
                          debug: bool = False) -> list:
    """
    Calls getMethodTypes to discover which API methods the display supports.

    Service: system
    Method: getMethodTypes
    Version: 1.0
    Parameters: [""] (empty string returns all methods)

    Returns:
        list of supported method names
    """
    try:
        result = call_sony_api(
            host=host,
            port=port,
            method="getMethodTypes",
            params=[""],
            version="1.0",
            request_id=99,
            psk=psk,
            timeout=timeout
        )

        if "error" in result:
            return []

        methods = []
        results_list = result.get("results", [])
        for entry in results_list:
            if isinstance(entry, list) and len(entry) > 0:
                methods.append(entry[0])
            elif isinstance(entry, str):
                methods.append(entry)

        if debug:
            print(f"  [DEBUG] {host} supported system methods: {methods}")

        return methods

    except Exception as e:
        if debug:
            print(f"  [DEBUG] {host} getMethodTypes error: {str(e)}")
        return []


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
    """Calls getInterfaceInformation v1.0."""
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
    """Calls getNetworkSettings v1.0."""
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


def parse_update_response(raw_result: dict) -> dict:
    """
    Parse the raw JSON-RPC response from update check methods.

    Handles multiple response formats from different Sony models:

    Format A: {"result": [{"isUpdatable": true, "swInfo": [...]}]}
    Format B: {"result": [{"isUpdatable": "true", "swInfo": [...]}]}
    Format C: {"result": [[{"isUpdatable": true, "swInfo": [...]}]]}
    Format D: {"result": [{"isUpdatable": true, "targetVersion": "..."}]}

    Returns:
        dict with normalized keys: is_updatable, target_version, current_version, raw
    """
    parsed = {
        "is_updatable": False,
        "target_version": "",
        "current_version": "",
        "raw": raw_result
    }

    if "error" in raw_result:
        return parsed

    result_data = raw_result.get("result", [])

    # Unwrap nested lists: {"result": [[{...}]]}
    if result_data and isinstance(result_data, list):
        if len(result_data) > 0 and isinstance(result_data[0], list):
            result_data = result_data[0]

    # Get the first result object
    if result_data and isinstance(result_data, list) and len(result_data) > 0:
        info = result_data[0] if isinstance(result_data[0], dict) else {}
    elif isinstance(result_data, dict):
        info = result_data
    else:
        return parsed

    # Parse isUpdatable — handle bool, string, and int
    is_updatable = info.get("isUpdatable", info.get("updatable", False))
    if isinstance(is_updatable, str):
        is_updatable = is_updatable.lower() in ("true", "1", "yes")
    elif isinstance(is_updatable, int):
        is_updatable = bool(is_updatable)
    parsed["is_updatable"] = bool(is_updatable)

    # Try to get target version from swInfo array
    sw_info = info.get("swInfo", [])

    if isinstance(sw_info, list) and len(sw_info) > 0:
        sw_entry = sw_info[0] if isinstance(sw_info[0], dict) else {}
        parsed["target_version"] = (
            sw_entry.get("targetVersion", "") or
            sw_entry.get("target_version", "") or
            sw_entry.get("version", "") or
            ""
        )
        parsed["current_version"] = (
            sw_entry.get("currentVersion", "") or
            sw_entry.get("current_version", "") or
            ""
        )
    elif isinstance(sw_info, dict):
        parsed["target_version"] = (
            sw_info.get("targetVersion", "") or
            sw_info.get("target_version", "") or
            sw_info.get("version", "") or
            ""
        )
        parsed["current_version"] = (
            sw_info.get("currentVersion", "") or
            sw_info.get("current_version", "") or
            ""
        )

    # Fallback: some models put targetVersion directly in the info dict
    if not parsed["target_version"]:
        parsed["target_version"] = (
            info.get("targetVersion", "") or
            info.get("target_version", "") or
            info.get("updateVersion", "") or
            ""
        )

    if not parsed["current_version"]:
        parsed["current_version"] = (
            info.get("currentVersion", "") or
            info.get("current_version", "") or
            ""
        )

    return parsed


def get_update_information(host: str, port: int, psk: str = None,
                           timeout: int = DEFAULT_TIMEOUT,
                           debug: bool = False) -> dict:
    """
    Check for available firmware updates by trying multiple API methods.

    Tries in order:
        1. getCurrentSoftwareUpdateInformation v1.0
        2. getSoftwareUpdateInfo v1.0

    If all methods return error 12 (method not found), returns
    'Not Supported' status so the user knows the display doesn't
    support remote update checking.

    Returns:
        dict with normalized update information
    """
    last_error = None
    method_used = None

    for method_info in UPDATE_CHECK_METHODS:
        method_name = method_info["method"]
        method_version = method_info["version"]
        method_params = method_info["params"]

        try:
            raw_result = call_sony_api(
                host=host,
                port=port,
                method=method_name,
                params=method_params,
                version=method_version,
                request_id=4,
                psk=psk,
                timeout=timeout
            )

            if debug:
                print(f"\n  [DEBUG] {host} {method_name} v{method_version} response: "
                      f"{json.dumps(raw_result, indent=2)}")

            # Check for error 12 (method not found) — try next method
            if "error" in raw_result:
                error_code = raw_result["error"][0] if isinstance(raw_result["error"], list) else raw_result["error"]
                if isinstance(error_code, int) and error_code == 12:
                    last_error = f"{method_name} not supported (error 12)"
                    if debug:
                        print(f"  [DEBUG] {host} {method_name}: not supported, trying next method...")
                    continue
                else:
                    # Other API error — still a valid response, method exists but returned error
                    error_msg = raw_result["error"][1] if isinstance(raw_result["error"], list) and len(raw_result["error"]) > 1 else "Unknown"
                    last_error = f"{method_name}: error {error_code} — {error_msg}"
                    if debug:
                        print(f"  [DEBUG] {host} {method_name}: API error {error_code} — {error_msg}")
                    continue

            # Success — parse the response
            parsed = parse_update_response(raw_result)
            parsed["method_used"] = method_name

            if debug:
                print(f"  [DEBUG] {host} parsed update info ({method_name}): "
                      f"{json.dumps({k: v for k, v in parsed.items() if k != 'raw'}, indent=2)}")

            return parsed

        except requests.exceptions.HTTPError:
            raise
        except Timeout:
            raise
        except RequestsConnectionError:
            raise
        except Exception as e:
            last_error = f"{method_name}: {str(e)}"
            if debug:
                print(f"  [DEBUG] {host} {method_name} exception: {str(e)}")
            continue

    # All methods failed
    if debug:
        print(f"  [DEBUG] {host} all update check methods failed. Last error: {last_error}")

    return {
        "is_updatable": False,
        "target_version": "",
        "current_version": "",
        "not_supported": True,
        "error": last_error,
        "method_used": None
    }


def trigger_software_update(host: str, port: int, psk: str = None,
                            timeout: int = DEFAULT_TIMEOUT,
                            debug: bool = False) -> dict:
    """
    Calls setSoftwareUpdate v1.0 to trigger a network firmware update.

    The display will:
        1. Download the firmware from Sony servers
        2. Verify the firmware integrity
        3. Install the firmware
        4. Automatically reboot

    WARNING: The display will reboot during the update process.
    """
    try:
        result = call_sony_api(
            host=host,
            port=port,
            method="setSoftwareUpdate",
            params=[{"network": True}],
            version="1.0",
            request_id=5,
            psk=psk,
            timeout=timeout
        )

        if debug:
            print(f"\n  [DEBUG] {host} setSoftwareUpdate response: {json.dumps(result, indent=2)}")

        if "error" in result:
            error_code = result["error"][0] if isinstance(result["error"], list) else result["error"]
            error_msg = result["error"][1] if isinstance(result["error"], list) and len(result["error"]) > 1 else "Unknown"

            # Error 12 = method not found
            if isinstance(error_code, int) and error_code == 12:
                return {"success": False, "error": "setSoftwareUpdate not supported on this model"}
            # Error 7 = already updating / in progress
            elif isinstance(error_code, int) and error_code == 7:
                return {"success": True, "error": "Update already in progress"}
            # Error 40 = no update available
            elif isinstance(error_code, int) and error_code == 40:
                return {"success": False, "error": "No update available from Sony servers"}
            else:
                return {"success": False, "error": f"API Error {error_code}: {error_msg}"}

        return {"success": True, "error": None}

    except Exception as e:
        return {"success": False, "error": str(e)}


def query_display(host: str, port: int, psk: str = None,
                  timeout: int = DEFAULT_TIMEOUT,
                  debug: bool = False) -> dict:
    """Query a single Sony Bravia display for firmware and update information."""
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
        "update_available": "N/A",
        "target_version": "",
        "update_check_method": "N/A",
        "error": None,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    try:
        sys_info, api_version = get_system_information(host, port, psk, timeout)

        if debug:
            print(f"\n  [DEBUG] {host} getSystemInformation v{api_version}: "
                  f"{json.dumps(sys_info, indent=2)}")

        result["api_version_used"] = api_version
        result["model"] = sys_info.get("model", "N/A")
        result["serial"] = sys_info.get("serial", "N/A")
        result["mac_address"] = sys_info.get("macAddr", "N/A")
        result["device_name"] = sys_info.get("name", "N/A")
        result["generation"] = sys_info.get("generation", "N/A")
        result["product_name"] = sys_info.get("product", "N/A")

        firmware = sys_info.get("version", "")
        if not firmware:
            firmware = sys_info.get("generation", "")
        if not firmware:
            firmware = "N/A"
        result["firmware_version"] = firmware

        result["status"] = "OK"

        # Get interface information
        try:
            iface_info = get_interface_information(host, port, psk, timeout)
            if debug and iface_info:
                print(f"  [DEBUG] {host} getInterfaceInformation: "
                      f"{json.dumps(iface_info, indent=2)}")
            if iface_info:
                result["interface_version"] = iface_info.get("interfaceVersion", "N/A")
                if result["product_name"] == "N/A":
                    result["product_name"] = iface_info.get("productName", "N/A")
                if result["firmware_version"] == "N/A":
                    server_name = iface_info.get("serverName", "")
                    if server_name:
                        result["firmware_version"] = server_name
        except Exception:
            pass

        # Get MAC from network settings if needed
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

        # Check for firmware updates (tries multiple methods)
        try:
            update_info = get_update_information(host, port, psk, timeout, debug)

            if update_info.get("not_supported"):
                result["update_available"] = "Not Supported"
                result["update_check_method"] = "None"
            else:
                result["update_available"] = "Yes" if update_info["is_updatable"] else "No"
                result["target_version"] = update_info.get("target_version", "")
                result["update_check_method"] = update_info.get("method_used", "N/A")

            if debug:
                result["_raw_update_response"] = update_info.get("raw", {})

        except Exception as e:
            result["update_available"] = "Error"
            if debug:
                print(f"  [DEBUG] {host} update check exception: {str(e)}")

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


def find_display_by_host(displays: list, host: str) -> dict:
    """Find a display entry by host/IP from the loaded display list."""
    for display in displays:
        if display["host"] == host:
            return display
    return None


def save_results_json(results: list, filepath: str = DEFAULT_OUTPUT):
    """Save query results to a JSON file."""
    output = {
        "query_timestamp": datetime.utcnow().isoformat() + "Z",
        "total_displays": len(results),
        "successful_queries": sum(1 for r in results if r["status"] == "OK"),
        "failed_queries": sum(1 for r in results if r["status"] == "ERROR"),
        "updates_available": sum(1 for r in results if r.get("update_available") == "Yes"),
        "update_check_not_supported": sum(1 for r in results if r.get("update_available") == "Not Supported"),
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


def print_results_table(results: list):
    """Print results as a formatted table scaled to terminal width."""
    term_width = get_terminal_width()
    error_max = get_error_truncate_length()

    wide = term_width >= 200
    medium_wide = term_width >= 160
    medium = term_width >= 120
    narrow = term_width >= 80

    table_data = []
    for r in results:
        status_icon = "✓" if r["status"] == "OK" else "✗"
        error_info = truncate(r.get("error", "") or "", error_max)
        update = r.get("update_available", "N/A")
        target = r.get("target_version", "") or ""

        row = [
            f"{status_icon} {r['status']}",
            r["host"],
            r["model"],
            r["firmware_version"],
        ]

        if narrow:
            row.append(update)
        if medium:
            if update == "Yes" and target:
                row.append(target)
            else:
                row.append("")
            row.append(r["serial"])
        if medium_wide:
            row.append(r["mac_address"])
            row.append(r["api_version_used"])
        if wide:
            row.append(error_info)

        table_data.append(row)

    headers = ["Status", "Host", "Model", "Firmware Version"]

    if narrow:
        headers.append("Update")
    if medium:
        headers.extend(["Target Version", "Serial"])
    if medium_wide:
        headers.extend(["MAC Address", "API Ver"])
    if wide:
        headers.append("Error")

    separator = "=" * term_width
    title = "Sony Bravia Professional Display — Firmware & Update Status"

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
        print(tabulate(table_data, headers=headers, tablefmt="pipe"))

    total = len(results)
    success = sum(1 for r in results if r["status"] == "OK")
    failed = sum(1 for r in results if r["status"] == "ERROR")
    updatable = sum(1 for r in results if r.get("update_available") == "Yes")
    no_update = sum(1 for r in results if r.get("update_available") == "No")
    not_supported = sum(1 for r in results if r.get("update_available") == "Not Supported")

    summary = (f"Total: {total} | Success: {success} | Failed: {failed} | "
               f"Updates: {updatable} | Current: {no_update} | "
               f"Update Check N/A: {not_supported}")
    print(f"\n{summary}")

    if not_supported > 0:
        print(f"\nNote: {not_supported} display(s) do not support remote update checking.")
        print("Use --update <host> to attempt a direct update trigger on these displays,")
        print("or update via USB / Sony Pro Device Manager.")

    hidden = []
    if not narrow:
        hidden.append("Update")
    if not medium:
        hidden.extend(["Target Version", "Serial"])
    if not medium_wide:
        hidden.extend(["MAC Address", "API Ver"])
    if not wide:
        hidden.append("Error")

    if hidden:
        print(f"(Columns hidden due to terminal width: {', '.join(hidden)} — "
              f"widen terminal or see {DEFAULT_OUTPUT} for full data)")

    print(f"Terminal width: {term_width} cols")


def print_update_results(update_results: list):
    """Print firmware update trigger results."""
    term_width = get_terminal_width()
    error_max = get_error_truncate_length()

    table_data = []
    for r in update_results:
        status_icon = "✓" if r["success"] else "✗"
        status_text = "Triggered" if r["success"] else "Failed"
        error_info = truncate(r.get("error", "") or "", error_max)

        table_data.append([
            f"{status_icon} {status_text}",
            r["host"],
            r.get("model", "N/A"),
            r.get("current_version", "N/A"),
            r.get("target_version", "") or "N/A",
            error_info
        ])

    headers = ["Status", "Host", "Model", "Current FW", "Target FW", "Error"]

    separator = "=" * term_width
    title = "Firmware Update Trigger Results"

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
        print(tabulate(table_data, headers=headers, tablefmt="pipe"))

    triggered = sum(1 for r in update_results if r["success"])
    failed = sum(1 for r in update_results if not r["success"])
    print(f"\nTriggered: {triggered} | Failed: {failed}")

    if triggered > 0:
        print("\nWARNING: Displays that accepted the update will download firmware")
        print("from Sony servers and reboot automatically during installation.")


def confirm_update(hosts_description: str) -> bool:
    """Prompt user for confirmation before triggering updates."""
    print(f"\n{'!' * 70}")
    print("WARNING: Firmware update will be triggered on: " + hosts_description)
    print("The display(s) will:")
    print("  1. Download firmware from Sony update servers")
    print("  2. Verify firmware integrity")
    print("  3. Install firmware")
    print("  4. Reboot automatically")
    print(f"{'!' * 70}")

    while True:
        response = input("\nProceed with firmware update? (yes/no): ").strip().lower()
        if response in ("yes", "y"):
            return True
        elif response in ("no", "n"):
            return False
        else:
            print("Please enter 'yes' or 'no'.")


def run_update(targets: list, results: list, psk: str = None,
               timeout: int = DEFAULT_TIMEOUT, debug: bool = False):
    """Trigger firmware updates on specified displays."""
    term_width = get_terminal_width()
    bar_width = max(40, term_width - 2)

    result_lookup = {}
    for r in results:
        result_lookup[r["host"]] = r

    update_results = []

    with tqdm(
        total=len(targets),
        desc="Triggering updates",
        bar_format=f"{{l_bar}}{CYAN}{{bar}}{RESET}{{r_bar}}",
        ncols=bar_width,
        unit="display"
    ) as pbar:
        for display in targets:
            host = display["host"]
            port = display["port"]

            pbar.set_postfix_str(host, refresh=True)

            query_result = result_lookup.get(host, {})

            update_result = {
                "host": host,
                "port": port,
                "model": query_result.get("model", "N/A"),
                "current_version": query_result.get("firmware_version", "N/A"),
                "target_version": query_result.get("target_version", ""),
                "success": False,
                "error": None,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

            trigger_response = trigger_software_update(host, port, psk, timeout, debug)
            update_result["success"] = trigger_response["success"]
            update_result["error"] = trigger_response.get("error")

            update_results.append(update_result)
            pbar.update(1)

    print_update_results(update_results)


def main():
    parser = argparse.ArgumentParser(
        description="Query Sony Bravia professional displays for firmware version and manage updates.",
        epilog="""
Examples:
  Query all displays (default):
    python sony_fw_query.py

  Query with debug output (shows raw API responses):
    python sony_fw_query.py --debug

  Query with PSK authentication:
    python sony_fw_query.py -k MyPreSharedKey

  Trigger firmware update on a single display:
    python sony_fw_query.py --update 192.168.1.100

  Trigger firmware update on multiple displays:
    python sony_fw_query.py --update 192.168.1.100 192.168.1.101

  Trigger firmware update on ALL displays that have updates available:
    python sony_fw_query.py --update-all

  Force update attempt on a display even if update check is not supported:
    python sony_fw_query.py --update wentworth-205-display.openav.dartmouth.edu

  Combine options:
    python sony_fw_query.py -i displays.csv -k 0000 --update-all -o output.json

Authentication:
  By default NO authentication is used (X-Auth-PSK header is omitted).
  This requires displays to be set to Authentication = None.

Firmware Updates:
  Updates are downloaded from Sony's servers by the display itself.
  The display must have internet access. After downloading, the display
  will reboot automatically to install the update.

  Note: Some models (e.g., BZ53L) do not support the update check API
  method. You can still attempt --update <host> which calls
  setSoftwareUpdate directly — the display will check Sony servers
  on its own.

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
        "--update",
        nargs="+",
        metavar="HOST",
        help="Trigger firmware update on specific host(s)"
    )
    parser.add_argument(
        "--update-all",
        action="store_true",
        help="Trigger firmware update on ALL displays that have updates available"
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip confirmation prompt for updates"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show raw API responses for troubleshooting"
    )

    args = parser.parse_args()

    term_width = get_terminal_width()

    # Print configuration
    if args.psk:
        print(f"Authentication: PSK (Pre-Shared Key)")
    else:
        print(f"Authentication: None (no X-Auth-PSK header)")

    print(f"API versions:   Will try {' -> '.join(SYSTEM_INFO_VERSIONS)} (automatic fallback)")
    print(f"Update check:   Will try {' -> '.join(m['method'] for m in UPDATE_CHECK_METHODS)}")
    print(f"Reading:        {args.input}")

    displays = read_csv_input(args.input)
    print(f"Displays:       {len(displays)} found")

    mode = "Query + Update" if (args.update or args.update_all) else "Query Only"
    print(f"Mode:           {mode}")
    if args.debug:
        print(f"Debug:          Enabled")
    print(f"Terminal:       {term_width} cols\n")

    # Phase 1: Query all displays
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

            result = query_display(host, port, psk=args.psk,
                                   timeout=args.timeout, debug=args.debug)
            results.append(result)

            pbar.update(1)

    print_results_table(results)
    save_results_json(results, args.output)

    # Phase 2: Trigger updates if requested
    if args.update or args.update_all:

        if args.update_all:
            updatable = [
                r for r in results
                if r.get("update_available") == "Yes" and r["status"] == "OK"
            ]

            if not updatable:
                print("\nNo displays reported available firmware updates.")
                not_supported = [r for r in results if r.get("update_available") == "Not Supported"]
                if not_supported:
                    hosts = ", ".join(r["host"] for r in not_supported)
                    print(f"\n{len(not_supported)} display(s) don't support update checking: {hosts}")
                    print("Use --update <host> to attempt update directly on these displays.")
                return

            targets = [{"host": r["host"], "port": r["port"]} for r in updatable]
            hosts_desc = f"ALL {len(targets)} display(s) with available updates"

        else:
            targets = []
            not_found = []

            for host in args.update:
                display = find_display_by_host(displays, host)
                if display:
                    targets.append(display)
                else:
                    not_found.append(host)

            if not_found:
                print(f"\nWARNING: Host(s) not found in {args.input}: {', '.join(not_found)}")

            if not targets:
                print("\nERROR: No valid hosts to update.")
                return

            # Inform user about update status for each target
            for target in targets:
                query_result = next((r for r in results if r["host"] == target["host"]), None)
                if query_result:
                    update_status = query_result.get("update_available", "N/A")
                    if update_status == "Yes":
                        target_ver = query_result.get("target_version", "unknown")
                        print(f"  {target['host']}: Update available -> {target_ver}")
                    elif update_status == "Not Supported":
                        print(f"  {target['host']}: Update check not supported — will attempt direct trigger")
                    elif update_status == "No":
                        print(f"  {target['host']}: No update reported — will attempt direct trigger anyway")
                    else:
                        print(f"  {target['host']}: Update status unknown — will attempt direct trigger")

            hosts_desc = ", ".join(t["host"] for t in targets)

        if args.yes or confirm_update(hosts_desc):
            run_update(targets, results, psk=args.psk,
                       timeout=args.timeout, debug=args.debug)
        else:
            print("\nUpdate cancelled.")


if __name__ == "__main__":
    main()
