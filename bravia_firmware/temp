#!/usr/bin/env python3
"""
Sony Bravia Temperature Debug Tool

Probes a single display to discover what methods and data are available,
specifically hunting for any temperature-related fields.

Usage:
  python sony_temp_debug.py 192.168.1.100
  python sony_temp_debug.py 192.168.1.100 -k MyPSK
  python sony_temp_debug.py 192.168.1.100 -p 443
"""

import json
import sys
import argparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("ERROR: pip install requests")
    sys.exit(1)

DEFAULT_PORT = 80
DEFAULT_TIMEOUT = 10

# Every target string worth trying for getDeviceStatus
DEVICE_STATUS_TARGETS = [
    "",                  # empty = return all
    "temperature",
    "cabinetTemp",
    "boardTemp",
    "panelTemp",
    "ambientTemp",
    "temp",
    "thermalStatus",
    "boardTemperature",
    "cabinetTemperature",
]

# Service endpoints to probe (some Sony models expose system info on multiple paths)
ENDPOINTS = ["/sony/system", "/sony/avContent", "/sony/video"]


def call(host, port, endpoint, method, params, version, psk=None, timeout=DEFAULT_TIMEOUT):
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}{endpoint}"
    headers = {"Content-Type": "application/json"}
    if psk:
        headers["X-Auth-PSK"] = psk
    payload = {"method": method, "id": 1, "params": params, "version": version}
    r = requests.post(url, json=payload, headers=headers, timeout=timeout, verify=False)
    r.raise_for_status()
    return r.json()


def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def dump(label, data):
    print(f"\n--- {label} ---")
    print(json.dumps(data, indent=2))


def probe_get_method_types(host, port, endpoint, psk):
    """Ask the display what methods it supports on this endpoint."""
    section(f"getMethodTypes — {endpoint}")
    for version in ["1.0"]:
        try:
            result = call(host, port, endpoint, "getMethodTypes", [""], version, psk)
            dump(f"getMethodTypes v{version}", result)
            return result
        except Exception as e:
            print(f"  getMethodTypes v{version}: {e}")
    return None


def probe_get_versions(host, port, endpoint, psk):
    """Ask what API versions each method supports."""
    section(f"getVersions — {endpoint}")
    try:
        result = call(host, port, endpoint, "getVersions", [], "1.0", psk)
        dump("getVersions", result)
    except Exception as e:
        print(f"  getVersions: {e}")


def probe_system_info(host, port, psk):
    """Dump full getSystemInformation response for all versions."""
    section("getSystemInformation (all versions)")
    for v in ["1.7", "1.4", "1.0"]:
        try:
            result = call(host, port, "/sony/system", "getSystemInformation", [], v, psk)
            if "error" in result:
                print(f"  v{v}: API error {result['error']}")
            else:
                dump(f"v{v} result", result.get("result", [{}])[0])
                # Highlight any temperature-looking fields
                data = result.get("result", [{}])[0]
                temp_fields = {k: v for k, v in data.items()
                               if "temp" in k.lower() or "thermal" in k.lower()}
                if temp_fields:
                    print(f"\n  *** TEMPERATURE FIELDS FOUND in getSystemInformation v{v}: ***")
                    print(f"  {temp_fields}")
        except Exception as e:
            print(f"  v{v}: {e}")


def probe_device_status(host, port, psk):
    """Try getDeviceStatus with every known temperature target."""
    section("getDeviceStatus — temperature target sweep")
    for target in DEVICE_STATUS_TARGETS:
        label = f'target="{target}"' if target else 'target="" (all)'
        try:
            result = call(host, port, "/sony/system", "getDeviceStatus",
                          [{"target": target}], "1.0", psk)
            if "error" in result:
                err = result["error"]
                print(f"  {label:30s} → API error {err}")
            else:
                items = result.get("result", [[]])[0]
                print(f"  {label:30s} → {json.dumps(items)}")
                # Flag anything temperature-related
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict):
                            k = item.get("target", "")
                            if "temp" in k.lower() or "thermal" in k.lower():
                                print(f"    *** TEMPERATURE ITEM: {item} ***")
        except requests.exceptions.HTTPError as e:
            print(f"  {label:30s} → HTTP {e.response.status_code if e.response else '?'}")
        except Exception as e:
            print(f"  {label:30s} → {type(e).__name__}: {e}")


def probe_get_all_device_status(host, port, psk):
    """Try getting all device status items at once (no target filter)."""
    section("getDeviceStatus — no params (raw call)")
    try:
        result = call(host, port, "/sony/system", "getDeviceStatus", [], "1.0", psk)
        dump("result", result)
    except Exception as e:
        print(f"  {e}")


def probe_thermal_info(host, port, psk):
    """Try some less common method names that might expose temperature."""
    section("Probing alternate temperature method names")
    candidates = [
        ("getThermalStatus",    [],               "1.0"),
        ("getTemperatureInfo",  [],               "1.0"),
        ("getTemperatureStatus",[],               "1.0"),
        ("getEnvironmentSensorInfo", [],          "1.0"),
        ("getHardwareInfo",     [],               "1.0"),
        ("getStatusInfo",       [],               "1.0"),
        ("getStatusInfo",       [{"target": ""}], "1.0"),
    ]
    for method, params, version in candidates:
        try:
            result = call(host, port, "/sony/system", method, params, version, psk)
            if "error" in result:
                print(f"  {method:35s} → API error {result['error']}")
            else:
                print(f"  {method:35s} → {json.dumps(result.get('result', []))}")
        except requests.exceptions.HTTPError as e:
            code = e.response.status_code if e.response else "?"
            print(f"  {method:35s} → HTTP {code}")
        except Exception as e:
            print(f"  {method:35s} → {type(e).__name__}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Debug Sony Bravia temperature API availability on a single display."
    )
    parser.add_argument("host", help="Display IP address or hostname")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("-k", "--psk", default=None, help="Pre-Shared Key (if required)")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()

    print(f"\nTarget:  {args.host}:{args.port}")
    print(f"Auth:    {'PSK provided' if args.psk else 'None'}")

    # 1. Discover supported methods
    for ep in ENDPOINTS:
        try:
            probe_get_method_types(args.host, args.port, ep, args.psk)
        except Exception:
            pass

    # 2. Full sysinfo dump (check for embedded temp fields)
    probe_system_info(args.host, args.port, args.psk)

    # 3. Sweep all known temperature targets via getDeviceStatus
    probe_device_status(args.host, args.port, args.psk)

    # 4. Raw getDeviceStatus with no params
    probe_get_all_device_status(args.host, args.port, args.psk)

    # 5. Try alternate method names
    probe_thermal_info(args.host, args.port, args.psk)

    section("DONE — search output above for '***' to find temperature data")
    print("  If nothing was found, temperature may not be exposed via REST API")
    print("  on this firmware version. Check 'getMethodTypes' output for clues.\n")


if __name__ == "__main__":
    main()
