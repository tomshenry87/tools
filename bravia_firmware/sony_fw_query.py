#!/usr/bin/env python3
"""
Sony Bravia BZ40H/BZ40L Firmware Version Query Tool

Uses the Sony BRAVIA REST API (JSON-RPC) documented in:
  - Sony BRAVIA Professional Display IP Control API
  - Endpoint: /sony/system
  - Method: getSystemInformation (v1.7)
  - Method: getInterfaceInformation (v1.0)

Supports three authentication modes:
  - None: No authentication (X-Auth-PSK header omitted)
  - PSK:  Pre-Shared Key via X-Auth-PSK header
"""

import csv
import json
import sys
import os
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

# Suppress InsecureRequestWarning for HTTPS without cert verification
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Defaults
DEFAULT_CSV = "displays.csv"
DEFAULT_OUTPUT = "results.json"
DEFAULT_PSK = None  # None = no authentication
DEFAULT_TIMEOUT = 10
DEFAULT_PORT = 80
API_ENDPOINT = "/sony/system"


def build_headers(psk: str = None) -> dict:
    """
    Build request headers based on authentication mode.

    When PSK is None or empty, the X-Auth-PSK header is omitted entirely,
    which corresponds to Authentication mode 'None' on the display.

    When PSK is provided, the X-Auth-PSK header is included,
    which corresponds to Authentication mode 'Normal and Pre-Shared Key'.
    """
    headers = {
        "Content-Type": "application/json"
    }

    if psk:
        headers["X-Auth-PSK"] = psk

    return headers


def get_system_information(host: str, port: int, psk: str = None,
                           timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Calls the Sony BRAVIA REST API method 'getSystemInformation' via JSON-RPC.

    Sony BRAVIA Professional Display API Reference:
        Service: system
        Method: getSystemInformation
        Version: 1.7
        Parameters: [] (empty array)

    Version 1.7 response contains:
        - product: Product category (e.g., "Professional Display")
        - region: Region code
        - language: Current language
        - model: Model name (e.g., "FW-50BZ40H")
        - serial: Serial number
        - macAddr: MAC address
        - name: Device name
        - generation: Generation string
        - area: Area code
        - cid: Client ID
        - icon: Icon URL
        - bdAddr: Bluetooth device address
        - version: Software/firmware version string
        - chipId: Chip identifier
        - uuid: Universally unique identifier
        - helpUrl: Help URL
        - storageSize: Storage size
        - essid: Connected Wi-Fi SSID
    """
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}{API_ENDPOINT}"

    payload = {
        "method": "getSystemInformation",
        "id": 1,
        "params": [],
        "version": "1.7"
    }

    response = requests.post(
        url,
        json=payload,
        headers=build_headers(psk),
        timeout=timeout,
        verify=False
    )
    response.raise_for_status()

    result = response.json()

    if "error" in result:
        error_code = result["error"][0] if isinstance(result["error"], list) else result["error"]
        error_msg = result["error"][1] if isinstance(result["error"], list) and len(result["error"]) > 1 else "Unknown"
        raise Exception(f"API Error {error_code}: {error_msg}")

    return result.get("result", [{}])[0]


def get_interface_information(host: str, port: int, psk: str = None,
                              timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Calls the Sony BRAVIA REST API method 'getInterfaceInformation'.

    Service: system
    Method: getInterfaceInformation
    Version: 1.0

    Response contains:
        - productName
        - modelName
        - productCategory
        - interfaceVersion: API interface version
        - serverName
    """
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}{API_ENDPOINT}"

    payload = {
        "method": "getInterfaceInformation",
        "id": 2,
        "params": [],
        "version": "1.0"
    }

    response = requests.post(
        url,
        json=payload,
        headers=build_headers(psk),
        timeout=timeout,
        verify=False
    )
    response.raise_for_status()

    result = response.json()

    if "error" in result:
        return {}

    return result.get("result", [{}])[0]


def get_network_settings(host: str, port: int, psk: str = None,
                         timeout: int = DEFAULT_TIMEOUT) -> list:
    """
    Calls the Sony BRAVIA REST API method 'getNetworkSettings'.

    Service: system
    Method: getNetworkSettings
    Version: 1.0
    Parameters: [{"netif": ""}] — empty string returns all interfaces
    """
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}{API_ENDPOINT}"

    payload = {
        "method": "getNetworkSettings",
        "id": 3,
        "params": [{"netif": ""}],
        "version": "1.0"
    }

    try:
        response = requests.post(
            url,
            json=payload,
            headers=build_headers(psk),
            timeout=timeout,
            verify=False
        )
        response.raise_for_status()
        result = response.json()

        if "error" in result:
            return []

        return result.get("result", [[]])[0]
    except Exception:
        return []


def query_display(host: str, port: int, psk: str = None,
                  timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Query a single Sony Bravia display for firmware/system information.
    Uses getSystemInformation v1.7 which includes the 'version' field
    containing the firmware/software version string directly.
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
        "error": None,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    try:
        # Primary call: getSystemInformation v1.7
        sys_info = get_system_information(host, port, psk, timeout)

        result["model"] = sys_info.get("model", "N/A")
        result["serial"] = sys_info.get("serial", "N/A")
        result["mac_address"] = sys_info.get("macAddr", "N/A")
        result["device_name"] = sys_info.get("name", "N/A")
        result["generation"] = sys_info.get("generation", "N/A")
        result["product_name"] = sys_info.get("product", "N/A")

        # v1.7 provides the 'version' field directly with firmware version
        firmware = sys_info.get("version", "")
        if not firmware:
            # Fallback to generation if version field is not populated
            firmware = sys_info.get("generation", "N/A")
        result["firmware_version"] = firmware

        result["status"] = "OK"

        # Supplementary call: getInterfaceInformation
        try:
            iface_info = get_interface_information(host, port, psk, timeout)
            if iface_info:
                result["interface_version"] = iface_info.get("interfaceVersion", "N/A")
                if result["product_name"] == "N/A":
                    result["product_name"] = iface_info.get("productName", "N/A")
        except Exception:
            pass

        # Supplementary: get MAC from network settings if not in sys info
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

    except Timeout:
        result["error"] = "Connection timed out"
    except RequestsConnectionError:
        result["error"] = f"Could not connect to {host}:{port}"
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response else "Unknown"
        if status_code == 403:
            result["error"] = ("HTTP 403 Forbidden — display requires authentication. "
                               "Use -k to provide a PSK or set display authentication to 'None'")
        elif status_code == 404:
            result["error"] = "HTTP 404 — API endpoint not found. Verify IP control is enabled."
        else:
            result["error"] = f"HTTP Error {status_code}: {str(e)}"
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


def print_results_table(results: list):
    """Print results as a formatted table."""
    table_data = []
    for r in results:
        status_icon = "✓" if r["status"] == "OK" else "✗"
        error_info = r.get("error", "") or ""

        table_data.append([
            f"{status_icon} {r['status']}",
            r["host"],
            r["port"],
            r["model"],
            r["firmware_version"],
            r["serial"],
            r["mac_address"],
            r["device_name"],
            error_info[:50] + "..." if len(error_info) > 50 else error_info
        ])

    headers = [
        "Status", "Host", "Port", "Model",
        "Firmware Version", "Serial", "MAC Address",
        "Device Name", "Error"
    ]

    print("\n" + "=" * 120)
    print("Sony Bravia BZ40H/BZ40L — Firmware Version Query Results")
    print("=" * 120)
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    print(f"\nTotal: {len(results)} | "
          f"Success: {sum(1 for r in results if r['status'] == 'OK')} | "
          f"Failed: {sum(1 for r in results if r['status'] == 'ERROR')}")


def main():
    parser = argparse.ArgumentParser(
        description="Query Sony Bravia BZ40H/BZ40L displays for firmware version via Sony REST API.",
        epilog="""
Examples:
  python sony_fw_query.py
  python sony_fw_query.py -i my_displays.csv
  python sony_fw_query.py -k MyPreSharedKey
  python sony_fw_query.py -i displays.csv -k 0000 -t 15 -o output.json

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

    args = parser.parse_args()

    # Print auth mode
    if args.psk:
        print(f"Authentication: PSK (Pre-Shared Key)")
    else:
        print(f"Authentication: None (no X-Auth-PSK header)")

    print(f"Reading display list from: {args.input}")
    displays = read_csv_input(args.input)
    print(f"Found {len(displays)} display(s) to query.\n")

    results = []
    for i, display in enumerate(displays, start=1):
        host = display["host"]
        port = display["port"]
        print(f"[{i}/{len(displays)}] Querying {host}:{port}...", end=" ", flush=True)

        result = query_display(host, port, psk=args.psk, timeout=args.timeout)
        results.append(result)

        if result["status"] == "OK":
            print(f"OK — Model: {result['model']}, FW: {result['firmware_version']}")
        else:
            print(f"FAILED — {result['error']}")

    print_results_table(results)
    save_results_json(results, args.output)


if __name__ == "__main__":
    main()
