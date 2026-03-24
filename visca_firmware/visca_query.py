#!/usr/bin/env python3
"""
Camera Firmware Query Tool

Target cameras:
  - Sony SRG-A40    (VISCA over IP, TCP 52381)
  - Sony SRG-X400   (VISCA over IP, TCP 52381)
  - Prisual TEM-20N (VISCA over IP, TCP 1259 — may also support HTTP CGI)

This script queries each camera for firmware/version information using
the appropriate protocol for each camera type.

Sony cameras:    VISCA over IP with 8-byte header envelope
Prisual cameras: Attempts VISCA over IP first, falls back to raw VISCA,
                 then falls back to HTTP CGI query
"""

import csv
import json
import socket
import struct
import sys
import os
import argparse
import time
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Camera Profiles
# ---------------------------------------------------------------------------

CAMERA_PROFILES = {
    "srg-a40": {
        "display_name": "Sony SRG-A40",
        "manufacturer": "Sony",
        "default_port": 52381,
        "transport": "tcp",
        "visca_mode": "sony_ip",     # 8-byte header + VISCA payload
        "supports_version_inq": True,
        "supports_soft_version_inq": True,
        "supports_interface_inq": False,
        "generation": "Gen 4 / AI-based PTZ",
        "expected_model_codes": [0x0710],
    },
    "srg-x400": {
        "display_name": "Sony SRG-X400",
        "manufacturer": "Sony",
        "default_port": 52381,
        "transport": "tcp",
        "visca_mode": "sony_ip",
        "supports_version_inq": True,
        "supports_soft_version_inq": False,
        "supports_interface_inq": False,
        "generation": "Gen 3 / 4K PTZ",
        "expected_model_codes": [0x0519, 0x0630],
    },
    "tem-20n": {
        "display_name": "Prisual TEM-20N",
        "manufacturer": "Prisual",
        "default_port": 1259,
        "transport": "tcp",
        "visca_mode": "auto",        # try sony_ip first, then raw
        "supports_version_inq": True,
        "supports_soft_version_inq": False,
        "supports_interface_inq": False,
        "generation": "Prisual 20x NDI/IP PTZ",
        "expected_model_codes": [],   # unknown — will discover
        "http_cgi_fallback": True,
        "http_port": 80,
        "cgi_endpoints": [
            "/cgi-bin/param.cgi?get_device_conf",
            "/cgi-bin/ptzctrl.cgi?action=getinfo",
            "/api/param?action=get&group=device",
            "/onvif/device_service",
        ],
    },
}

# Alias lookups (user might type these in CSV)
PROFILE_ALIASES = {
    "srg-a40": "srg-a40",
    "srga40": "srg-a40",
    "sony srg-a40": "srg-a40",
    "a40": "srg-a40",
    "srg-x400": "srg-x400",
    "srgx400": "srg-x400",
    "sony srg-x400": "srg-x400",
    "x400": "srg-x400",
    "tem-20n": "tem-20n",
    "tem20n": "tem-20n",
    "prisual tem-20n": "tem-20n",
    "prisual": "tem-20n",
    "tenveo": "tem-20n",
}


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 5

# VISCA over IP payload types
PAYLOAD_TYPE_VISCA_INQUIRY = 0x0110
PAYLOAD_TYPE_VISCA_REPLY = 0x0111

# VISCA Inquiry Commands
VISCA_INQ_CAM_VERSION = bytes([0x81, 0x09, 0x00, 0x02, 0xFF])
VISCA_INQ_SOFT_VERSION = bytes([0x81, 0x09, 0x04, 0x00, 0xFF])
VISCA_INQ_INTERFACE = bytes([0x81, 0x09, 0x00, 0x00, 0xFF])

# Known model codes
SONY_MODEL_CODES = {
    0x0519: "SRG-X400",
    0x0630: "SRG-X400",
    0x0710: "SRG-A40",
    0x0711: "SRG-A12",
}

VENDOR_CODES = {
    0x00: "Sony",
}


# ---------------------------------------------------------------------------
# VISCA Packet Handling
# ---------------------------------------------------------------------------

def build_visca_ip_packet(payload: bytes, sequence_number: int) -> bytes:
    """Build VISCA over IP packet with 8-byte Sony header."""
    header = struct.pack('>HHI',
                         PAYLOAD_TYPE_VISCA_INQUIRY,
                         len(payload),
                         sequence_number)
    return header + payload


def parse_visca_ip_response(data: bytes) -> dict:
    """Parse Sony VISCA over IP 8-byte header + payload."""
    if len(data) < 8:
        return {"error": "Response too short", "raw": data.hex()}

    payload_type, payload_length, seq = struct.unpack('>HHI', data[:8])
    payload = data[8:8 + payload_length]

    return {
        "payload_type": payload_type,
        "payload_length": payload_length,
        "sequence_number": seq,
        "payload": payload,
    }


def is_visca_reply(data: bytes) -> bool:
    """
    Check if raw bytes look like a VISCA reply.
    VISCA replies start with 0x90 (address 1 reply) and end with 0xFF.
    """
    if len(data) < 3:
        return False
    return data[0] == 0x90 and data[-1] == 0xFF


def classify_reply(payload: bytes) -> str:
    """Classify VISCA reply type from the payload."""
    if len(payload) < 2:
        return "unknown"

    reply_byte = payload[1] & 0xF0
    if reply_byte == 0x50:
        return "completion"
    elif reply_byte == 0x40:
        return "ack"
    elif reply_byte == 0x60:
        return "error"
    return "unknown"


def get_visca_error_meaning(payload: bytes) -> str:
    """Extract human-readable error from VISCA error reply."""
    error_code = payload[2] if len(payload) > 2 else 0xFF
    meanings = {
        0x01: "Message length error",
        0x02: "Syntax error (command not supported)",
        0x03: "Command buffer full",
        0x04: "Command cancelled",
        0x05: "No socket",
        0x41: "Command not executable",
    }
    return meanings.get(error_code, f"Unknown error 0x{error_code:02X}")


# ---------------------------------------------------------------------------
# Sony VISCA over IP (8-byte header mode)
# ---------------------------------------------------------------------------

def send_inquiry_sony_ip(sock: socket.socket, inquiry: bytes,
                         seq: int) -> Optional[bytes]:
    """
    Send inquiry using Sony VISCA over IP envelope (8-byte header).
    Used by: SRG-A40, SRG-X400
    """
    packet = build_visca_ip_packet(inquiry, seq)

    try:
        sock.sendall(packet)
    except socket.error as e:
        print(f"      [ERROR] Send failed: {e}")
        return None

    # Read response — handle possible ACK before completion
    for attempt in range(2):
        try:
            data = sock.recv(1024)
        except socket.timeout:
            print("      [ERROR] Timeout waiting for response")
            return None
        except socket.error as e:
            print(f"      [ERROR] Recv error: {e}")
            return None

        if not data:
            print("      [ERROR] Connection closed")
            return None

        parsed = parse_visca_ip_response(data)
        if "error" in parsed:
            print(f"      [ERROR] {parsed['error']}")
            return None

        payload = parsed["payload"]
        rtype = classify_reply(payload)

        if rtype == "completion":
            return payload
        elif rtype == "ack":
            print(f"      (ACK received, waiting for completion ...)")
            continue
        elif rtype == "error":
            print(f"      [ERROR] {get_visca_error_meaning(payload)}")
            return None
        else:
            print(f"      [ERROR] Unexpected reply: {payload.hex()}")
            return None

    print("      [ERROR] No completion after ACK")
    return None


# ---------------------------------------------------------------------------
# Raw VISCA (no header — for third-party cameras like Prisual)
# ---------------------------------------------------------------------------

def send_inquiry_raw(sock: socket.socket,
                     inquiry: bytes) -> Optional[bytes]:
    """
    Send raw VISCA inquiry with NO IP envelope header.
    Some third-party cameras (Prisual, PTZOptics, etc.) expect
    bare VISCA bytes on their TCP port.

    Send: 81 09 00 02 FF
    Recv: 90 50 00 vv ww ww xx xx yy yy FF
    """
    try:
        sock.sendall(inquiry)
    except socket.error as e:
        print(f"      [ERROR] Raw send failed: {e}")
        return None

    try:
        data = sock.recv(1024)
    except socket.timeout:
        print("      [ERROR] Raw VISCA timeout")
        return None
    except socket.error as e:
        print(f"      [ERROR] Raw recv error: {e}")
        return None

    if not data:
        print("      [ERROR] Empty raw response")
        return None

    # Check if response has Sony IP header (camera might wrap replies)
    if len(data) > 8:
        # Try parsing as Sony IP first
        parsed = parse_visca_ip_response(data)
        if "error" not in parsed and len(parsed["payload"]) >= 3:
            payload = parsed["payload"]
            if is_visca_reply(payload):
                rtype = classify_reply(payload)
                if rtype == "completion":
                    return payload
                elif rtype == "error":
                    print(f"      [ERROR] {get_visca_error_meaning(payload)}")
                    return None

    # Try as raw VISCA reply (no header)
    if is_visca_reply(data):
        rtype = classify_reply(data)
        if rtype == "completion":
            return data
        elif rtype == "error":
            print(f"      [ERROR] {get_visca_error_meaning(data)}")
            return None

    # Couldn't parse either way
    print(f"      [ERROR] Unrecognized response: {data.hex()}")
    return None


# ---------------------------------------------------------------------------
# Prisual HTTP CGI Fallback
# ---------------------------------------------------------------------------

def query_prisual_http(host: str, http_port: int,
                       timeout: int) -> dict:
    """
    Fall back to HTTP CGI to get Prisual TEM-20N device info.

    Many Prisual/Tenveo cameras expose device information via
    HTTP endpoints even when VISCA queries don't return version info.
    """
    result = {
        "method": "http_cgi",
        "endpoints_tried": [],
        "device_info_raw": {},
    }

    endpoints = CAMERA_PROFILES["tem-20n"]["cgi_endpoints"]

    for endpoint in endpoints:
        url = f"http://{host}:{http_port}{endpoint}"
        result["endpoints_tried"].append(url)
        print(f"      Trying: {url}")

        try:
            req = urllib.request.Request(url, method='GET')
            req.add_header('User-Agent', 'VISCA-Query/1.0')

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                body = resp.read().decode('utf-8', errors='replace')

                if status == 200 and body:
                    print(f"      HTTP {status} — Got response "
                          f"({len(body)} bytes)")
                    result["device_info_raw"][endpoint] = body

                    # Try to extract version-like info
                    parsed = parse_http_device_info(body)
                    if parsed:
                        result.update(parsed)
                        return result
                else:
                    print(f"      HTTP {status} — No useful data")

        except urllib.error.HTTPError as e:
            print(f"      HTTP {e.code}: {e.reason}")
            # Try with basic auth
            if e.code == 401:
                print(f"      (Requires authentication — "
                      f"trying admin/admin)")
                try:
                    auth_result = query_prisual_http_auth(
                        host, http_port, endpoint, timeout
                    )
                    if auth_result:
                        result.update(auth_result)
                        return result
                except Exception:
                    pass

        except urllib.error.URLError as e:
            print(f"      URL error: {e.reason}")
        except Exception as e:
            print(f"      Error: {e}")

    return result


def query_prisual_http_auth(host: str, http_port: int,
                            endpoint: str, timeout: int) -> Optional[dict]:
    """Try HTTP endpoint with common default credentials."""
    import base64

    # Common default credentials for PTZ cameras
    credentials = [
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "888888"),
        ("admin", "123456"),
    ]

    url = f"http://{host}:{http_port}{endpoint}"

    for user, passwd in credentials:
        try:
            auth_str = base64.b64encode(
                f"{user}:{passwd}".encode()
            ).decode()

            req = urllib.request.Request(url, method='GET')
            req.add_header('Authorization', f'Basic {auth_str}')
            req.add_header('User-Agent', 'VISCA-Query/1.0')

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    body = resp.read().decode('utf-8', errors='replace')
                    if body:
                        print(f"      Auth success ({user}:***)")
                        parsed = parse_http_device_info(body)
                        if parsed:
                            parsed["auth_used"] = f"{user}:***"
                            return parsed

        except urllib.error.HTTPError:
            continue
        except Exception:
            continue

    return None


def parse_http_device_info(body: str) -> Optional[dict]:
    """
    Parse device info from HTTP response body.
    Handles JSON, key=value, and XML-ish formats.
    """
    result = {}

    # Try JSON
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            # Look for version-like keys
            for key in data:
                key_lower = key.lower()
                if any(term in key_lower for term in
                       ['version', 'firmware', 'fw', 'software', 'sw']):
                    result["firmware_version"] = str(data[key])
                if any(term in key_lower for term in
                       ['model', 'device', 'name', 'product']):
                    result["model_name"] = str(data[key])
                if any(term in key_lower for term in
                       ['serial', 'sn', 'mac']):
                    result["serial_number"] = str(data[key])
            if result:
                result["parse_method"] = "json"
                return result
    except (json.JSONDecodeError, ValueError):
        pass

    # Try key=value format (common in CGI responses)
    lines = body.strip().split('\n')
    for line in lines:
        if '=' in line:
            key, _, value = line.partition('=')
            key = key.strip().lower()
            value = value.strip().strip('"').strip("'")

            if any(term in key for term in
                   ['version', 'firmware', 'fw_ver', 'software']):
                result["firmware_version"] = value
            if any(term in key for term in
                   ['model', 'device_name', 'product']):
                result["model_name"] = value
            if any(term in key for term in
                   ['serial', 'sn', 'mac_addr']):
                result["serial_number"] = value

    if result:
        result["parse_method"] = "key_value"
        return result

    # Try finding version patterns in raw text
    import re
    version_pattern = re.compile(
        r'(?:version|firmware|fw)[:\s=]+([0-9]+\.[0-9]+[.\-0-9]*)',
        re.IGNORECASE
    )
    match = version_pattern.search(body)
    if match:
        result["firmware_version"] = match.group(1)
        result["parse_method"] = "regex"
        return result

    return None


# ---------------------------------------------------------------------------
# Response Parsers
# ---------------------------------------------------------------------------

def parse_version_response(payload: bytes, profile: dict) -> dict:
    """
    Parse CAM_VersionInq reply.

    Sony format:    90 50 00 vv ww ww xx xx yy yy [zz] FF
    Third-party:    90 50 00 vv ww ww xx xx FF  (may be shorter)
    """
    result = {}

    if payload and payload[-1] == 0xFF:
        payload = payload[:-1]

    if len(payload) < 6:
        result["parse_error"] = (
            f"Response too short ({len(payload)} bytes)"
        )
        result["raw_hex"] = payload.hex()
        return result

    manufacturer = profile.get("manufacturer", "Unknown")

    if manufacturer == "Sony" and len(payload) >= 8:
        # Standard Sony parsing
        vendor_id = payload[3]
        model_code = (payload[4] << 8) | payload[5]
        rom_revision = (payload[6] << 8) | payload[7]

        max_socket = None
        if len(payload) >= 10:
            max_socket = (payload[8] << 8) | payload[9]

        result["vendor_id"] = f"0x{vendor_id:02X}"
        result["vendor_name"] = VENDOR_CODES.get(
            vendor_id, f"Unknown (0x{vendor_id:02X})"
        )
        result["model_code"] = f"0x{model_code:04X}"
        result["model_name"] = SONY_MODEL_CODES.get(
            model_code, f"Unknown Sony (0x{model_code:04X})"
        )
        result["rom_revision"] = f"0x{rom_revision:04X}"
        result["rom_revision_decimal"] = rom_revision
        result["firmware_version"] = (
            f"{(rom_revision >> 8) & 0xFF}."
            f"{rom_revision & 0xFF:02d}"
        )
        if max_socket is not None:
            result["max_sockets"] = max_socket

    else:
        # Third-party camera (Prisual) — be flexible
        result["vendor_name"] = manufacturer

        # Try to extract whatever we can
        if len(payload) >= 6:
            vendor_id = payload[3] if len(payload) > 3 else 0xFF
            result["vendor_id"] = f"0x{vendor_id:02X}"

        if len(payload) >= 6:
            model_code = (payload[4] << 8) | payload[5]
            result["model_code"] = f"0x{model_code:04X}"

        if len(payload) >= 8:
            rom_revision = (payload[6] << 8) | payload[7]
            result["rom_revision"] = f"0x{rom_revision:04X}"
            result["rom_revision_decimal"] = rom_revision
            result["firmware_version"] = (
                f"{(rom_revision >> 8) & 0xFF}."
                f"{rom_revision & 0xFF:02d}"
            )

        # For Prisual, also try interpreting bytes as ASCII
        data_bytes = payload[2:]
        try:
            ascii_str = data_bytes.decode('ascii', errors='ignore')
            printable = ''.join(
                c if c.isprintable() else '' for c in ascii_str
            )
            if printable and len(printable) > 2:
                result["version_ascii"] = printable
        except Exception:
            pass

    result["raw_hex"] = payload.hex()
    return result


def parse_software_version_response(payload: bytes) -> dict:
    """Parse CAM_SoftVersionInq reply."""
    result = {}

    if payload and payload[-1] == 0xFF:
        payload = payload[:-1]

    if len(payload) < 3:
        result["parse_error"] = "Response too short"
        result["raw_hex"] = payload.hex() if payload else ""
        return result

    version_bytes = payload[2:]

    try:
        ascii_str = version_bytes.decode('ascii', errors='ignore')
        printable = ''.join(
            c if c.isprintable() else '.' for c in ascii_str
        )
        result["software_version_ascii"] = printable
    except Exception:
        pass

    result["software_version_hex"] = version_bytes.hex()
    result["raw_hex"] = payload.hex()
    return result


# ---------------------------------------------------------------------------
# Camera Query Logic
# ---------------------------------------------------------------------------

def resolve_profile(camera_type: str) -> Optional[dict]:
    """Look up camera profile from type string."""
    key = PROFILE_ALIASES.get(camera_type.lower().strip())
    if key and key in CAMERA_PROFILES:
        return CAMERA_PROFILES[key].copy()
    return None


def send_inquiry(sock: socket.socket, inquiry: bytes,
                 seq: int, visca_mode: str,
                 host: str = "", port: int = 0) -> Optional[bytes]:
    """
    Dispatch inquiry to correct transport handler.

    visca_mode:
      'sony_ip' — 8-byte header envelope (Sony cameras)
      'raw'     — bare VISCA bytes (some third-party cameras)
      'auto'    — try sony_ip first, fall back to raw
    """
    if visca_mode == "sony_ip":
        return send_inquiry_sony_ip(sock, inquiry, seq)

    elif visca_mode == "raw":
        return send_inquiry_raw(sock, inquiry)

    elif visca_mode == "auto":
        # Try Sony IP envelope first
        resp = send_inquiry_sony_ip(sock, inquiry, seq)
        if resp:
            return resp

        # If that failed, the socket may be in a bad state
        # We can't easily retry on the same TCP socket
        # Return None — caller should retry with raw mode
        return None

    else:
        print(f"      [ERROR] Unknown VISCA mode: {visca_mode}")
        return None


def query_camera(host: str, port: int, camera_name: str,
                 camera_type: str, timeout: int) -> dict:
    """
    Query a single camera based on its profile.
    """
    profile = resolve_profile(camera_type)

    if not profile:
        print(f"\n  [ERROR] Unknown camera type: '{camera_type}'")
        print(f"  Supported types: {list(CAMERA_PROFILES.keys())}")
        return {
            "host": host,
            "port": port,
            "camera_name": camera_name,
            "camera_type": camera_type,
            "status": "error",
            "errors": [f"Unknown camera type: {camera_type}"],
        }

    actual_port = port if port else profile["default_port"]
    visca_mode = profile["visca_mode"]
    manufacturer = profile["manufacturer"]

    result = {
        "host": host,
        "port": actual_port,
        "camera_name": camera_name,
        "camera_type": camera_type,
        "camera_profile": profile["display_name"],
        "manufacturer": manufacturer,
        "timestamp": datetime.now().isoformat(),
        "transport": f"TCP {actual_port}",
        "visca_mode": visca_mode,
        "status": "unknown",
        "version_info": {},
        "software_version_info": {},
        "http_info": {},
        "camera_generation": profile["generation"],
        "errors": [],
    }

    display_name = camera_name if camera_name else host
    print(f"\n{'=' * 60}")
    print(f"  Camera:   {display_name}")
    print(f"  Host:     {host}:{actual_port}")
    print(f"  Type:     {profile['display_name']}")
    print(f"  VISCA:    {visca_mode} mode")
    print(f"{'=' * 60}")

    # ---- TCP Connect ----
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        print(f"\n  Connecting TCP to {host}:{actual_port} ...")
        sock.connect((host, actual_port))
        print(f"  Connected.")
    except ConnectionRefusedError:
        msg = (f"TCP {actual_port} refused — check that VISCA over IP "
               f"is enabled and port is correct")
        print(f"  [FAIL] {msg}")
        result["status"] = "connection_refused"
        result["errors"].append(msg)

        # For Prisual, try HTTP fallback
        if profile.get("http_cgi_fallback"):
            print(f"\n  Attempting HTTP CGI fallback ...")
            http_info = query_prisual_http(
                host, profile.get("http_port", 80), timeout
            )
            result["http_info"] = http_info
            if http_info.get("firmware_version"):
                result["version_info"]["firmware_version"] = (
                    http_info["firmware_version"]
                )
                result["version_info"]["source"] = "http_cgi"
                result["status"] = "partial"
                if http_info.get("model_name"):
                    result["version_info"]["model_name"] = (
                        http_info["model_name"]
                    )

        sock.close()
        return result

    except socket.timeout:
        msg = f"Connection timed out ({timeout}s)"
        print(f"  [FAIL] {msg}")
        result["status"] = "connection_timeout"
        result["errors"].append(msg)
        sock.close()
        return result

    except OSError as e:
        msg = f"Connection failed: {e}"
        print(f"  [FAIL] {msg}")
        result["status"] = "connection_error"
        result["errors"].append(msg)
        sock.close()
        return result

    seq = 1
    active_mode = visca_mode

    # ===== Handle auto mode for Prisual =====
    if visca_mode == "auto":
        print(f"\n  Auto-detecting VISCA mode ...")
        print(f"  Trying Sony IP envelope first ...")

        test_resp = send_inquiry_sony_ip(
            sock, VISCA_INQ_CAM_VERSION, seq
        )
        seq += 1

        if test_resp:
            active_mode = "sony_ip"
            print(f"  Detected: Sony VISCA over IP envelope")
            # We already have the version response
            print(f"\n  [1/2] CAM_VersionInq — already received")
            print(f"        Raw reply:  {test_resp.hex()}")
            version_info = parse_version_response(test_resp, profile)
            result["version_info"] = version_info
            result["visca_mode"] = "sony_ip (auto-detected)"
        else:
            # Reconnect for raw mode (socket may be dirty)
            print(f"  Sony IP failed — reconnecting for raw mode ...")
            try:
                sock.close()
            except Exception:
                pass

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect((host, actual_port))
            except Exception as e:
                msg = f"Reconnect failed: {e}"
                print(f"  [FAIL] {msg}")
                result["errors"].append(msg)
                result["status"] = "connection_error"
                sock.close()
                return result

            active_mode = "raw"
            print(f"  Trying raw VISCA (no header) ...")

            test_resp = send_inquiry_raw(
                sock, VISCA_INQ_CAM_VERSION
            )

            if test_resp:
                print(f"  Detected: Raw VISCA mode")
                print(f"\n  [1/2] CAM_VersionInq — already received")
                print(f"        Raw reply:  {test_resp.hex()}")
                version_info = parse_version_response(
                    test_resp, profile
                )
                result["version_info"] = version_info
                result["visca_mode"] = "raw (auto-detected)"
            else:
                print(f"  Raw VISCA also failed")
                result["errors"].append(
                    "Neither Sony IP nor raw VISCA worked"
                )
                result["visca_mode"] = "none detected"

    # ===== Non-auto mode: Run CAM_VersionInq =====
    if visca_mode != "auto":
        print(f"\n  [1/2] CAM_VersionInq (81 09 00 02 FF)")

        resp = send_inquiry(sock, VISCA_INQ_CAM_VERSION,
                            seq, active_mode)
        seq += 1

        if resp:
            print(f"        Raw reply:  {resp.hex()}")
            version_info = parse_version_response(resp, profile)
            result["version_info"] = version_info
        else:
            print("        No valid response.")
            result["errors"].append("CAM_VersionInq: no response")

    # Print version info if we have it
    if result["version_info"]:
        vi = result["version_info"]
        print(f"        Vendor:           "
              f"{vi.get('vendor_name', 'N/A')}")
        if vi.get('model_code'):
            print(f"        Model Code:       "
                  f"{vi.get('model_code', 'N/A')}")
        if vi.get('model_name'):
            print(f"        Model Name:       "
                  f"{vi.get('model_name', 'N/A')}")
        if vi.get('rom_revision'):
            print(f"        ROM Revision:     "
                  f"{vi.get('rom_revision', 'N/A')}")
        if vi.get('firmware_version'):
            print(f"        Firmware Version: "
                  f"{vi.get('firmware_version', 'N/A')}")
        if vi.get('version_ascii'):
            print(f"        Version (ASCII):  "
                  f"{vi.get('version_ascii')}")
        if vi.get('max_sockets') is not None:
            print(f"        Max Sockets:      "
                  f"{vi.get('max_sockets')}")
        if "parse_error" in vi:
            print(f"        [WARN] {vi['parse_error']}")
            result["errors"].append(vi["parse_error"])

    time.sleep(0.1)

    # ===== 2. CAM_SoftVersionInq (Sony SRG-A40 only) =====
    if profile["supports_soft_version_inq"]:
        print(f"\n  [2/2] CAM_SoftVersionInq (81 09 04 00 FF)")

        resp = send_inquiry(sock, VISCA_INQ_SOFT_VERSION,
                            seq, active_mode)
        seq += 1

        if resp:
            print(f"        Raw reply:  {resp.hex()}")
            sw_info = parse_software_version_response(resp)
            result["software_version_info"] = sw_info
            if sw_info.get("software_version_ascii"):
                print(f"        Version (ASCII): "
                      f"{sw_info['software_version_ascii']}")
            print(f"        Version (Hex):   "
                  f"{sw_info.get('software_version_hex', 'N/A')}")
        else:
            print("        Not supported or no response.")
            result["software_version_info"] = {
                "note": "Not supported"
            }
    else:
        print(f"\n  [2/2] CAM_SoftVersionInq — skipped "
              f"(not supported on {profile['display_name']})")
        result["software_version_info"] = {"note": "Skipped per profile"}

    # ---- Cleanup TCP ----
    try:
        sock.close()
    except Exception:
        pass

    # ===== HTTP fallback for Prisual if VISCA didn't get firmware =====
    if (profile.get("http_cgi_fallback") and
            not result["version_info"].get("firmware_version")):
        print(f"\n  VISCA didn't return firmware version.")
        print(f"  Attempting HTTP CGI fallback ...")
        http_info = query_prisual_http(
            host, profile.get("http_port", 80), timeout
        )
        result["http_info"] = http_info
        if http_info.get("firmware_version"):
            result["version_info"]["firmware_version"] = (
                http_info["firmware_version"]
            )
            result["version_info"]["firmware_source"] = "http_cgi"
        if http_info.get("model_name"):
            result["version_info"]["model_name"] = (
                http_info["model_name"]
            )

    # ===== Final status =====
    if result["version_info"].get("firmware_version"):
        result["status"] = "success"
    elif result["version_info"]:
        result["status"] = "partial"
    else:
        result["status"] = "failed"

    print(f"\n  Generation: {result['camera_generation']}")
    print(f"  Status:     {result['status']}")

    return result


# ---------------------------------------------------------------------------
# CSV Reader
# ---------------------------------------------------------------------------

def read_csv(filepath: str) -> list:
    """
    Read camera list from CSV.

    Required columns: host, type
    Optional columns: port, name

    'type' must be one of: srg-a40, srg-x400, tem-20n
    (or any alias from PROFILE_ALIASES)
    """
    cameras = []

    if not os.path.isfile(filepath):
        print(f"[ERROR] CSV file not found: {filepath}")
        sys.exit(1)

    with open(filepath, 'r', newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            print("[ERROR] CSV is empty or has no header.")
            sys.exit(1)

        fieldnames_lower = [fn.lower().strip() for fn in reader.fieldnames]

        has_host = any(
            col in fieldnames_lower for col in ['host', 'ip', 'address']
        )
        has_type = any(
            col in fieldnames_lower for col in ['type', 'model', 'camera_type']
        )

        if not has_host:
            print(f"[ERROR] CSV needs 'host' column. "
                  f"Found: {reader.fieldnames}")
            sys.exit(1)

        if not has_type:
            print(f"[ERROR] CSV needs 'type' column to identify "
                  f"camera model.")
            print(f"  Valid types: srg-a40, srg-x400, tem-20n")
            print(f"  Found columns: {reader.fieldnames}")
            sys.exit(1)

        for row_num, row in enumerate(reader, start=2):
            row_lower = {
                k.lower().strip(): (v.strip() if v else '')
                for k, v in row.items()
            }

            host = (row_lower.get('host') or row_lower.get('ip') or
                    row_lower.get('address', ''))
            if not host:
                print(f"  [WARN] Row {row_num}: No host, skipping.")
                continue

            camera_type = (row_lower.get('type') or
                           row_lower.get('model') or
                           row_lower.get('camera_type', ''))
            if not camera_type:
                print(f"  [WARN] Row {row_num}: No type, skipping.")
                continue

            # Validate type
            profile_key = PROFILE_ALIASES.get(camera_type.lower())
            if not profile_key:
                print(f"  [WARN] Row {row_num}: Unknown type "
                      f"'{camera_type}'. "
                      f"Valid: srg-a40, srg-x400, tem-20n")
                continue

            port_str = row_lower.get('port', '')
            if port_str:
                try:
                    port = int(port_str)
                except ValueError:
                    print(f"  [WARN] Row {row_num}: Bad port, "
                          f"using profile default.")
                    port = 0
            else:
                port = 0  # will use profile default

            name = (row_lower.get('name', '') or
                    row_lower.get('camera_name', ''))

            cameras.append({
                "host": host,
                "port": port,
                "name": name,
                "type": camera_type,
            })

    return cameras


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(results: list):
    """Print formatted summary table."""

    print(f"\n\n{'#' * 75}")
    print(f"  RESULTS SUMMARY")
    print(f"{'#' * 75}\n")

    header = (f"{'#':<4} {'Name':<22} {'Host':<16} {'Type':<14} "
              f"{'Status':<10} {'FW Version':<12} {'Source'}")
    print(header)
    print("-" * 100)

    for i, r in enumerate(results, 1):
        name = (r.get("camera_name") or "")[:21]
        host = (r.get("host") or "")[:15]
        ctype = (r.get("camera_profile") or r.get("camera_type", ""))[:13]
        status = (r.get("status") or "unknown")
        fw = r.get("version_info", {}).get("firmware_version", "N/A")[:11]
        source = r.get("version_info", {}).get(
            "firmware_source", r.get("visca_mode", "visca"))[:15]

        if status == "success":
            sc = f"\033[92m{status:<10}\033[0m"
        elif status == "partial":
            sc = f"\033[93m{status:<10}\033[0m"
        else:
            sc = f"\033[91m{status:<10}\033[0m"

        print(f"{i:<4} {name:<22} {host:<16} {ctype:<14} "
              f"{sc} {fw:<12} {source}")

    print()
    total = len(results)
    success = sum(1 for r in results if r["status"] == "success")
    partial = sum(1 for r in results if r["status"] == "partial")
    failed = total - success - partial
    print(f"  Total: {total}  |  Success: {success}  "
          f"|  Partial: {partial}  |  Failed: {failed}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Camera Firmware Query Tool "
                    "(Sony SRG-A40, SRG-X400, Prisual TEM-20N)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported Cameras:
  ┌──────────────┬──────────┬───────────────────────────────────┐
  │ Camera       │ Port     │ Protocol                          │
  ├──────────────┼──────────┼───────────────────────────────────┤
  │ Sony SRG-A40 │ TCP 52381│ VISCA over IP (Sony envelope)     │
  │ Sony SRG-X400│ TCP 52381│ VISCA over IP (Sony envelope)     │
  │ Prisual      │ TCP 1259 │ VISCA (auto-detect envelope/raw)  │
  │ TEM-20N      │          │ + HTTP CGI fallback               │
  └──────────────┴──────────┴───────────────────────────────────┘

CSV Format:
  host,type,port,name
  192.168.1.100,srg-a40,,Camera A
  192.168.1.101,srg-x400,,Camera B
  192.168.1.102,tem-20n,,Camera C
  192.168.1.103,tem-20n,5678,Camera D Custom Port

Valid type values:
  srg-a40, a40, srg-x400, x400, tem-20n, prisual
        """
    )

    parser.add_argument("csv_file",
                        help="CSV file with camera hosts")
    parser.add_argument("-o", "--output", default="results.json",
                        help="Output JSON (default: results.json)")
    parser.add_argument("-t", "--timeout", type=int,
                        default=DEFAULT_TIMEOUT,
                        help=f"Timeout (default: {DEFAULT_TIMEOUT}s)")

    args = parser.parse_args()
    timeout = args.timeout

    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║           Camera Firmware Query Tool                          ║
║                                                               ║
║  Targets:                                                     ║
║    Sony SRG-A40    │ TCP 52381 │ VISCA over IP                ║
║    Sony SRG-X400   │ TCP 52381 │ VISCA over IP                ║
║    Prisual TEM-20N │ TCP 1259  │ VISCA + HTTP fallback        ║
║                                                               ║
║  Timeout: {timeout}s                                              ║
╚═══════════════════════════════════════════════════════════════╝
    """)

    print(f"Reading: {args.csv_file}")
    cameras = read_csv(args.csv_file)

    if not cameras:
        print("[ERROR] No valid cameras found in CSV.")
        sys.exit(1)

    print(f"Found {len(cameras)} camera(s):\n")
    for i, cam in enumerate(cameras, 1):
        profile = resolve_profile(cam["type"])
        pname = profile["display_name"] if profile else cam["type"]
        port = cam["port"] or (profile["default_port"] if profile else "?")
        print(f"  {i}. {cam.get('name') or cam['host']:<30} "
              f"{cam['host']:<16} {pname:<18} port {port}")

    all_results = []
    for idx, cam in enumerate(cameras, 1):
        print(f"\n\n[Camera {idx}/{len(cameras)}]")
        result = query_camera(
            host=cam["host"],
            port=cam["port"],
            camera_name=cam["name"],
            camera_type=cam["type"],
            timeout=timeout,
        )
        all_results.append(result)

        if idx < len(cameras):
            time.sleep(0.3)

    print_summary(all_results)

    output_data = {
        "query_timestamp": datetime.now().isoformat(),
        "csv_source": args.csv_file,
        "total_cameras": len(all_results),
        "timeout_seconds": timeout,
        "supported_models": {
            k: v["display_name"]
            for k, v in CAMERA_PROFILES.items()
        },
        "results": all_results,
    }

    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, default=str)
        print(f"Results saved to: {os.path.abspath(args.output)}")
    except IOError as e:
        print(f"[ERROR] Failed to write output: {e}")
        sys.exit(1)

    print("\nDone.")


if __name__ == "__main__":
    main()
