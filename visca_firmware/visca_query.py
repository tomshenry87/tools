#!/usr/bin/env python3
"""
Sony VISCA over IP - Camera System Information Query Tool

Connects to Sony cameras via VISCA over IP protocol and queries:
- CAM_VersionInq (software version, model, ROM version, socket number)
  
Reads camera hosts from a CSV file and outputs results to CLI and results.json.

VISCA over IP Reference:
  https://pro.sony/s3/2022/09/14131603/VISCA-Command-List-Version-2.00.pdf

VISCA over IP default port: 52381
Payload structure:
  - Payload Type:   2 bytes (0x01 0x10 for VISCA command, 0x01 0x11 for VISCA inquiry)
  - Payload Length:  2 bytes
  - Sequence Number: 4 bytes (incremented per message)
  - Payload:         N bytes (the VISCA command/inquiry bytes)
"""

import csv
import json
import socket
import struct
import sys
import os
import argparse
import time
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Constants / Configuration
# ---------------------------------------------------------------------------

VISCA_DEFAULT_PORT = 52381
DEFAULT_TIMEOUT = 5  # seconds — used as default; can be overridden via CLI

# VISCA over IP payload types
PAYLOAD_TYPE_VISCA_COMMAND = 0x0100
PAYLOAD_TYPE_VISCA_INQUIRY = 0x0110
PAYLOAD_TYPE_VISCA_REPLY = 0x0111
PAYLOAD_TYPE_VISCA_DEVICE_SETTING = 0x0120
PAYLOAD_TYPE_CONTROL_COMMAND = 0x0200
PAYLOAD_TYPE_CONTROL_REPLY = 0x0201

# ---- VISCA Inquiry Commands (System Section) ----

# CAM_VersionInq: 81 09 00 02 FF
VISCA_INQ_CAM_VERSION = bytes([0x81, 0x09, 0x00, 0x02, 0xFF])

# IF_InfInq: 81 09 00 00 FF
VISCA_INQ_INTERFACE = bytes([0x81, 0x09, 0x00, 0x00, 0xFF])

# CAM_SoftVersionInq (available on some newer models): 81 09 04 00 FF
VISCA_INQ_SOFT_VERSION = bytes([0x81, 0x09, 0x04, 0x00, 0xFF])

# MultAddrInq (System): 81 09 00 01 FF
VISCA_INQ_MULT_ADDR = bytes([0x81, 0x09, 0x00, 0x01, 0xFF])

# CAM_ICRModeInq: 81 09 04 01 FF
VISCA_INQ_MODE_STATUS = bytes([0x81, 0x09, 0x04, 0x01, 0xFF])


# ---------------------------------------------------------------------------
# Known Sony Model Codes
# ---------------------------------------------------------------------------
SONY_MODEL_CODES = {
    0x0519: "SRG-X400",
    0x0520: "SRG-X120",
    0x0560: "SRG-201SE",
    0x0610: "BRC-X400",
    0x0611: "BRC-X401",
    0x0620: "BRC-X1000",
    0x0630: "SRG-X400",
    0x0640: "SRG-201M2",
    0x0650: "SRG-HD1M2",
    0x0402: "EVI-D70",
    0x0504: "SRG-300H",
    0x0505: "SRG-300SE",
    0x0506: "SRG-301SE",
    0x0507: "SRG-120DH",
    0x0508: "SRG-120DS",
    0x0509: "SRG-120DU",
    0x050A: "SRG-121DH",
    0x050B: "SRG-HD1",
    0x050C: "SRG-300SE/301SE",
    0x0414: "EVI-H100S",
    0x0415: "EVI-H100V",
    0x0516: "BRC-H900",
    0x0517: "BRC-Z330",
    0x0112: "EVI-D100",
    0x0252: "BRC-300",
    0x0253: "BRC-Z700",
    0x0413: "BRC-H700",
    0x0418: "EVI-HD1",
    0x0419: "EVI-HD7V",
    0x041A: "BRC-Z330",
    0x0602: "BRC-X1000",
    0x0612: "BRC-X400",
    0x0710: "SRG-A40",
    0x0711: "SRG-A12",
    0x0720: "BRC-AM7",
    0x0730: "ILME-FR7",
    0x0740: "SRG-HD1M2",
}

# ---------------------------------------------------------------------------
# Known Vendor IDs
# ---------------------------------------------------------------------------
VENDOR_CODES = {
    0x00: "Sony",
    0x01: "Unknown Vendor 0x01",
}


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def build_visca_ip_packet(payload: bytes, sequence_number: int,
                          payload_type: int = PAYLOAD_TYPE_VISCA_INQUIRY) -> bytes:
    """
    Build a VISCA over IP packet.

    Structure (big-endian):
        Payload Type:     2 bytes
        Payload Length:   2 bytes
        Sequence Number:  4 bytes
        Payload:          N bytes
    """
    header = struct.pack('>HHI', payload_type, len(payload), sequence_number)
    return header + payload


def parse_visca_ip_response(data: bytes) -> dict:
    """
    Parse the VISCA over IP envelope.

    Returns a dict with:
        payload_type, payload_length, sequence_number, payload (bytes)
    """
    if len(data) < 8:
        return {"error": "Response too short", "raw": data.hex()}

    payload_type, payload_length, sequence_number = struct.unpack('>HHI', data[:8])
    payload = data[8:8 + payload_length]

    return {
        "payload_type": payload_type,
        "payload_length": payload_length,
        "sequence_number": sequence_number,
        "payload": payload,
    }


def send_visca_inquiry(sock: socket.socket, inquiry: bytes,
                       sequence_number: int) -> Optional[bytes]:
    """
    Send a VISCA inquiry over the connected socket and return the response payload.
    Handles ACK (0x4y) and then waits for Completion (0x5y) or Error.
    Returns the final response payload bytes, or None on failure.
    """
    packet = build_visca_ip_packet(inquiry, sequence_number, PAYLOAD_TYPE_VISCA_INQUIRY)

    try:
        sock.sendall(packet)
    except socket.error as e:
        print(f"      [ERROR] Failed to send inquiry: {e}")
        return None

    # Read response(s) — we may get ACK first then completion, or just completion
    attempts = 0
    max_attempts = 5
    while attempts < max_attempts:
        attempts += 1
        try:
            data = sock.recv(1024)
        except socket.timeout:
            print("      [ERROR] Socket timeout waiting for response")
            return None
        except socket.error as e:
            print(f"      [ERROR] Socket error: {e}")
            return None

        if not data:
            print("      [ERROR] Empty response / connection closed")
            return None

        parsed = parse_visca_ip_response(data)
        if "error" in parsed:
            print(f"      [ERROR] {parsed['error']}  raw={parsed.get('raw', '')}")
            return None

        payload = parsed["payload"]

        if len(payload) < 2:
            continue

        reply_type = payload[1] & 0xF0

        # 0x40-0x4F = ACK — keep waiting for completion
        if reply_type == 0x40:
            continue

        # 0x50-0x5F = Completion (inquiry response)
        if reply_type == 0x50:
            return payload

        # 0x60 = Error
        if reply_type == 0x60:
            error_code = payload[2] if len(payload) > 2 else 0xFF
            error_meanings = {
                0x01: "Message length error",
                0x02: "Syntax error",
                0x03: "Command buffer full",
                0x04: "Command cancelled",
                0x05: "No socket (to be cancelled)",
                0x41: "Command not executable",
            }
            meaning = error_meanings.get(error_code, f"Unknown error 0x{error_code:02X}")
            print(f"      [ERROR] Camera returned error: {meaning}")
            return None

        # Anything else — keep trying
        continue

    print("      [ERROR] Max response read attempts exceeded")
    return None


def parse_version_response(payload: bytes) -> dict:
    """
    Parse CAM_VersionInq response payload.

    Expected: 90 50 00 vv ww ww xx xx yy yy zz FF
    """
    result = {}

    if payload and payload[-1] == 0xFF:
        payload = payload[:-1]

    if len(payload) < 8:
        result["parse_error"] = f"Version response too short ({len(payload)} bytes)"
        result["raw_hex"] = payload.hex()
        return result

    vendor_id = payload[3]
    model_code = (payload[4] << 8) | payload[5]
    rom_revision = (payload[6] << 8) | payload[7]

    max_socket = None
    if len(payload) >= 10:
        max_socket = (payload[8] << 8) | payload[9]

    result["vendor_id"] = f"0x{vendor_id:02X}"
    result["vendor_name"] = VENDOR_CODES.get(vendor_id, f"Unknown (0x{vendor_id:02X})")
    result["model_code"] = f"0x{model_code:04X}"
    result["model_name"] = SONY_MODEL_CODES.get(model_code, f"Unknown Model (0x{model_code:04X})")
    result["rom_revision"] = f"0x{rom_revision:04X}"
    result["rom_revision_decimal"] = rom_revision
    result["firmware_version"] = f"{(rom_revision >> 8) & 0xFF}.{rom_revision & 0xFF:02d}"

    if max_socket is not None:
        result["max_sockets"] = max_socket

    result["raw_hex"] = payload.hex()
    return result


def parse_software_version_response(payload: bytes) -> dict:
    """
    Parse CAM_SoftVersionInq response if available.
    """
    result = {}

    if payload and payload[-1] == 0xFF:
        payload = payload[:-1]

    if len(payload) < 3:
        result["parse_error"] = "Software version response too short"
        result["raw_hex"] = payload.hex() if payload else ""
        return result

    version_bytes = payload[2:]

    try:
        ascii_str = version_bytes.decode('ascii', errors='ignore')
        printable = ''.join(c if c.isprintable() else '.' for c in ascii_str)
        result["software_version_ascii"] = printable
    except Exception:
        pass

    result["software_version_hex"] = version_bytes.hex()
    result["raw_hex"] = payload.hex()

    return result


def parse_interface_response(payload: bytes) -> dict:
    """Parse IF_InfInq response."""
    result = {}
    if payload and payload[-1] == 0xFF:
        payload = payload[:-1]
    result["raw_hex"] = payload.hex() if payload else ""
    return result


def determine_camera_generation(version_info: dict) -> str:
    """
    Attempt to determine camera generation based on model code.
    """
    model_code_str = version_info.get("model_code", "")

    try:
        model_code = int(model_code_str, 16)
    except (ValueError, TypeError):
        return "Unknown"

    if model_code >= 0x0700:
        return "Gen 4 / AI-based (SRG-A series, FR7, BRC-AM7)"
    elif model_code >= 0x0600:
        return "Gen 3 (BRC-X400/X1000 series, 4K capable)"
    elif model_code >= 0x0500:
        return "Gen 2 (SRG/BRC HD series)"
    elif model_code >= 0x0400:
        return "Gen 1.5 (EVI-H/HD series, BRC-H series)"
    elif model_code >= 0x0200:
        return "Gen 1 (BRC-300/Z700 series, SD era)"
    elif model_code >= 0x0100:
        return "Legacy (EVI-D series)"
    else:
        return "Unknown Generation"


# ---------------------------------------------------------------------------
# Main Camera Query Function
# ---------------------------------------------------------------------------

def query_camera(host: str, port: int, camera_name: str,
                 timeout: int) -> dict:
    """
    Connect to a single camera and perform all system inquiry commands.
    Returns a dict with all gathered information.
    """
    result = {
        "host": host,
        "port": port,
        "camera_name": camera_name,
        "timestamp": datetime.now().isoformat(),
        "status": "unknown",
        "version_info": {},
        "software_version_info": {},
        "interface_info": {},
        "camera_generation": "",
        "errors": [],
    }

    display_name = camera_name if camera_name else host
    print(f"\n{'=' * 60}")
    print(f"  Querying: {display_name} ({host}:{port})")
    print(f"{'=' * 60}")

    # ----- Connect -----
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        print(f"  Connecting to {host}:{port} ...")
        sock.connect((host, port))
        print(f"  Connected successfully.")
    except socket.timeout:
        msg = f"Connection timed out ({timeout}s)"
        print(f"  [FAIL] {msg}")
        result["status"] = "connection_timeout"
        result["errors"].append(msg)
        sock.close()
        return result
    except socket.error as e:
        msg = f"Connection failed: {e}"
        print(f"  [FAIL] {msg}")
        result["status"] = "connection_error"
        result["errors"].append(msg)
        sock.close()
        return result

    seq = 1

    # ===== 1. CAM_VersionInq =====
    print(f"\n  [1/4] Sending CAM_VersionInq (81 09 00 02 FF) ...")
    resp = send_visca_inquiry(sock, VISCA_INQ_CAM_VERSION, seq)
    seq += 1

    if resp:
        version_info = parse_version_response(resp)
        result["version_info"] = version_info
        print(f"      Vendor:           {version_info.get('vendor_name', 'N/A')}")
        print(f"      Model Code:       {version_info.get('model_code', 'N/A')}")
        print(f"      Model Name:       {version_info.get('model_name', 'N/A')}")
        print(f"      ROM Revision:     {version_info.get('rom_revision', 'N/A')}")
        print(f"      Firmware Version: {version_info.get('firmware_version', 'N/A')}")
        if version_info.get('max_sockets') is not None:
            print(f"      Max Sockets:      {version_info.get('max_sockets')}")
        if "parse_error" in version_info:
            print(f"      [WARN] {version_info['parse_error']}")
            result["errors"].append(version_info["parse_error"])
    else:
        print("      No response / error.")
        result["errors"].append("CAM_VersionInq failed")

    time.sleep(0.1)

    # ===== 2. CAM_SoftVersionInq =====
    print(f"\n  [2/4] Sending CAM_SoftVersionInq (81 09 04 00 FF) ...")
    resp = send_visca_inquiry(sock, VISCA_INQ_SOFT_VERSION, seq)
    seq += 1

    if resp:
        sw_info = parse_software_version_response(resp)
        result["software_version_info"] = sw_info
        if sw_info.get("software_version_ascii"):
            print(f"      Software Version (ASCII): {sw_info['software_version_ascii']}")
        print(f"      Software Version (Hex):   {sw_info.get('software_version_hex', 'N/A')}")
        if "parse_error" in sw_info:
            print(f"      [WARN] {sw_info['parse_error']}")
    else:
        print("      Not supported or no response (normal for some models).")
        result["software_version_info"] = {"note": "Not supported on this model"}

    time.sleep(0.1)

    # ===== 3. IF_InfInq =====
    print(f"\n  [3/4] Sending IF_InfInq (81 09 00 00 FF) ...")
    resp = send_visca_inquiry(sock, VISCA_INQ_INTERFACE, seq)
    seq += 1

    if resp:
        iface_info = parse_interface_response(resp)
        result["interface_info"] = iface_info
        print(f"      Interface Info (Hex): {iface_info.get('raw_hex', 'N/A')}")
    else:
        print("      Not supported or no response.")
        result["interface_info"] = {"note": "Not supported or no response"}

    time.sleep(0.1)

    # ===== 4. Camera Generation =====
    print(f"\n  [4/4] Determining camera generation ...")
    generation = determine_camera_generation(result["version_info"])
    result["camera_generation"] = generation
    print(f"      Camera Generation: {generation}")

    # ===== Cleanup =====
    try:
        sock.close()
    except Exception:
        pass

    if result["version_info"] and "parse_error" not in result["version_info"]:
        result["status"] = "success"
    elif result["version_info"]:
        result["status"] = "partial"
    else:
        result["status"] = "failed"

    return result


# ---------------------------------------------------------------------------
# CSV Reading
# ---------------------------------------------------------------------------

def read_csv(filepath: str) -> list:
    """
    Read camera hosts from CSV file.

    Expected CSV columns (header row required):
        host  - IP address or hostname (REQUIRED)
        port  - VISCA port (optional, defaults to 52381)
        name  - Friendly name (optional)
    """
    cameras = []

    if not os.path.isfile(filepath):
        print(f"[ERROR] CSV file not found: {filepath}")
        sys.exit(1)

    with open(filepath, 'r', newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            print(f"[ERROR] CSV file is empty or has no header row.")
            sys.exit(1)

        # Normalize field names for lookup
        fieldnames_lower = [fn.lower().strip() for fn in reader.fieldnames]

        has_host = ('host' in fieldnames_lower or
                    'ip' in fieldnames_lower or
                    'address' in fieldnames_lower)

        if not has_host:
            print(f"[ERROR] CSV must have a 'host' column. Found: {reader.fieldnames}")
            sys.exit(1)

        for row_num, row in enumerate(reader, start=2):
            row_lower = {k.lower().strip(): (v.strip() if v else '')
                         for k, v in row.items()}

            host = (row_lower.get('host') or
                    row_lower.get('ip') or
                    row_lower.get('address', ''))

            if not host:
                print(f"  [WARN] Row {row_num}: Missing host, skipping.")
                continue

            port_str = row_lower.get('port', '') or str(VISCA_DEFAULT_PORT)
            try:
                port = int(port_str)
            except ValueError:
                print(f"  [WARN] Row {row_num}: Invalid port '{port_str}', "
                      f"using default {VISCA_DEFAULT_PORT}.")
                port = VISCA_DEFAULT_PORT

            name = (row_lower.get('name', '') or
                    row_lower.get('camera_name', ''))

            cameras.append({
                "host": host,
                "port": port,
                "name": name,
            })

    return cameras


# ---------------------------------------------------------------------------
# CLI Output Summary
# ---------------------------------------------------------------------------

def print_summary(results: list):
    """Print a formatted summary table of all results."""

    print(f"\n\n{'#' * 70}")
    print(f"  SUMMARY OF ALL CAMERAS")
    print(f"{'#' * 70}\n")

    header = (f"{'#':<4} {'Name':<25} {'Host':<18} {'Status':<12} "
              f"{'Model':<20} {'FW Version':<12} {'Generation'}")
    print(header)
    print("-" * len(header))

    for i, r in enumerate(results, 1):
        name = (r.get("camera_name") or "")[:24]
        host = (r.get("host") or "")[:17]
        status = (r.get("status") or "unknown")[:11]
        model = r.get("version_info", {}).get("model_name", "N/A")[:19]
        fw = r.get("version_info", {}).get("firmware_version", "N/A")[:11]
        gen = r.get("camera_generation") or "N/A"

        # ANSI color for status
        if status == "success":
            status_display = f"\033[92m{status:<12}\033[0m"
        elif status == "partial":
            status_display = f"\033[93m{status:<12}\033[0m"
        else:
            status_display = f"\033[91m{status:<12}\033[0m"

        print(f"{i:<4} {name:<25} {host:<18} {status_display} "
              f"{model:<20} {fw:<12} {gen}")

    print()

    total = len(results)
    success = sum(1 for r in results if r["status"] == "success")
    partial = sum(1 for r in results if r["status"] == "partial")
    failed = total - success - partial

    print(f"  Total: {total}  |  Success: {success}  "
          f"|  Partial: {partial}  |  Failed: {failed}")
    print()


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Sony VISCA over IP - Camera System Information Query Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
CSV File Format:
  The CSV file should have a header row with at least a 'host' column.
  Optional columns: 'port' (default 52381), 'name' (friendly name).

  Example cameras.csv:
    host,port,name
    192.168.1.100,52381,Camera A - Main Hall
    192.168.1.101,52381,Camera B - Stage Left
    192.168.1.102,,Camera C - Balcony

Output:
  Results are displayed in the terminal and saved to results.json.
        """
    )

    parser.add_argument(
        "csv_file",
        help="Path to CSV file containing camera hosts"
    )
    parser.add_argument(
        "-o", "--output",
        default="results.json",
        help="Output JSON file path (default: results.json)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Socket timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        help="Override port for all cameras (default: use CSV values or 52381)"
    )

    args = parser.parse_args()

    # Store the timeout value from args — NO global mutation needed
    timeout = args.timeout

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║       Sony VISCA over IP - Camera Firmware Query Tool       ║
║                                                              ║
║  Protocol: VISCA over IP (TCP port {VISCA_DEFAULT_PORT})                  ║
║  Queries:  CAM_VersionInq, SoftVersionInq, IF_InfInq        ║
║  Timeout:  {timeout} seconds                                        ║
╚══════════════════════════════════════════════════════════════╝
    """)

    # Read CSV
    print(f"Reading camera list from: {args.csv_file}")
    cameras = read_csv(args.csv_file)

    if not cameras:
        print("[ERROR] No cameras found in CSV file.")
        sys.exit(1)

    print(f"Found {len(cameras)} camera(s) to query.\n")

    # Query each camera sequentially
    all_results = []
    for idx, cam in enumerate(cameras, 1):
        host = cam["host"]
        port = args.port if args.port else cam["port"]
        name = cam["name"]

        print(f"\n[Camera {idx}/{len(cameras)}]")
        result = query_camera(host, port, name, timeout)
        all_results.append(result)

        # Small delay between cameras
        if idx < len(cameras):
            time.sleep(0.2)

    # Print summary
    print_summary(all_results)

    # Save to JSON
    output_data = {
        "query_timestamp": datetime.now().isoformat(),
        "csv_source": args.csv_file,
        "total_cameras": len(all_results),
        "timeout_seconds": timeout,
        "results": all_results,
    }

    output_path = args.output
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, default=str)
        print(f"Results saved to: {os.path.abspath(output_path)}")
    except IOError as e:
        print(f"[ERROR] Failed to write results file: {e}")
        sys.exit(1)

    print("\nDone.")


if __name__ == "__main__":
    main()
