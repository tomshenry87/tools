#!/usr/bin/env python3
"""
Camera Firmware Query Tool

Target cameras:
  - Sony SRG-X400  (VISCA over IP)
  - Sony SRG-A40   (VISCA over IP)
  - Prisual TEM-20N

Transport strategy (per camera):
  1. UDP  — Send to port 52381, receive on port 52380 (Sony asymmetric layout)
  2. TCP  — Fallback: connect to port 52381, send/recv on same socket

Sony VISCA over IP packet format:
  [2B payload_type][2B payload_length][4B sequence_number][N bytes VISCA]
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
        "transport": "udp_first",
        "udp_send_port": 52381,
        "udp_recv_port": 52380,
        "visca_mode": "sony_ip",
        "supports_version_inq": True,
        "supports_soft_version_inq": True,
        "generation": "Gen 4 / AI-based PTZ",
        "expected_model_codes": [0x0710],
    },
    "srg-x400": {
        "display_name": "Sony SRG-X400",
        "manufacturer": "Sony",
        "default_port": 52381,
        "transport": "udp_first",
        "udp_send_port": 52381,
        "udp_recv_port": 52380,
        "visca_mode": "sony_ip",
        "supports_version_inq": True,
        "supports_soft_version_inq": False,
        "generation": "Gen 3 / 4K PTZ",
        "expected_model_codes": [0x0519, 0x0630],
    },
    "tem-20n": {
        "display_name": "Prisual TEM-20N",
        "manufacturer": "Prisual",
        "default_port": 1259,
        "transport": "tcp",           # Prisual uses plain TCP, no asymmetric ports
        "visca_mode": "auto",
        "supports_version_inq": True,
        "supports_soft_version_inq": False,
        "generation": "Prisual 20x NDI/IP PTZ",
        "expected_model_codes": [],
        "http_cgi_fallback": True,
        "http_port": 80,
        "cgi_endpoints": [
            "/cgi-bin/param.cgi?get_device_conf",
            "/cgi-bin/ptzctrl.cgi?action=getinfo",
            "/api/param?action=get&group=device",
        ],
    },
}

PROFILE_ALIASES = {
    "srg-a40": "srg-a40", "srga40": "srg-a40",
    "sony srg-a40": "srg-a40", "a40": "srg-a40",
    "srg-x400": "srg-x400", "srgx400": "srg-x400",
    "sony srg-x400": "srg-x400", "x400": "srg-x400",
    "tem-20n": "tem-20n", "tem20n": "tem-20n",
    "prisual tem-20n": "tem-20n", "prisual": "tem-20n",
}


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 5

PAYLOAD_TYPE_VISCA_INQUIRY = 0x0110
PAYLOAD_TYPE_VISCA_REPLY   = 0x0111

VISCA_INQ_CAM_VERSION  = bytes([0x81, 0x09, 0x00, 0x02, 0xFF])
VISCA_INQ_SOFT_VERSION = bytes([0x81, 0x09, 0x04, 0x00, 0xFF])

SONY_MODEL_CODES = {
    0x0519: "SRG-X400",
    0x0630: "SRG-X400",
    0x0710: "SRG-A40",
    0x0711: "SRG-A12",
}

VENDOR_CODES = {0x00: "Sony"}


# ---------------------------------------------------------------------------
# VISCA Packet Helpers
# ---------------------------------------------------------------------------

def build_visca_ip_packet(payload: bytes, sequence_number: int) -> bytes:
    """Build Sony VISCA over IP packet with 8-byte header."""
    header = struct.pack('>HHI',
                         PAYLOAD_TYPE_VISCA_INQUIRY,
                         len(payload),
                         sequence_number)
    return header + payload


def parse_visca_ip_response(data: bytes) -> dict:
    """Parse 8-byte Sony VISCA over IP header + payload."""
    if len(data) < 8:
        return {"error": "Response too short", "raw": data.hex()}
    payload_type, payload_length, seq = struct.unpack('>HHI', data[:8])
    payload = data[8: 8 + payload_length]
    return {
        "payload_type": payload_type,
        "payload_length": payload_length,
        "sequence_number": seq,
        "payload": payload,
    }


def is_visca_reply(data: bytes) -> bool:
    return len(data) >= 3 and data[0] == 0x90 and data[-1] == 0xFF


def classify_reply(payload: bytes) -> str:
    if len(payload) < 2:
        return "unknown"
    b = payload[1] & 0xF0
    return {0x50: "completion", 0x40: "ack", 0x60: "error"}.get(b, "unknown")


def get_visca_error_meaning(payload: bytes) -> str:
    code = payload[2] if len(payload) > 2 else 0xFF
    return {
        0x01: "Message length error",
        0x02: "Syntax error (command not supported)",
        0x03: "Command buffer full",
        0x04: "Command cancelled",
        0x05: "No socket",
        0x41: "Command not executable",
    }.get(code, f"Unknown error 0x{code:02X}")


# ---------------------------------------------------------------------------
# UDP Transport  (Sony asymmetric: send→52381, recv←52380)
# ---------------------------------------------------------------------------

def send_inquiry_udp(host: str, send_port: int, recv_port: int,
                     inquiry: bytes, seq: int,
                     timeout: int) -> Optional[bytes]:
    """
    Send VISCA inquiry via UDP.

    Sony cameras send replies back TO port 52380 on the querying host,
    so we bind locally on recv_port before sending.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        # Bind on the port the camera will reply to
        try:
            sock.bind(('', recv_port))
            print(f"      UDP bound on local port {recv_port} "
                  f"(replies expected here)")
        except OSError as e:
            print(f"      [WARN] Could not bind port {recv_port}: {e}")
            print(f"      Trying without bind — reply may still arrive ...")

        packet = build_visca_ip_packet(inquiry, seq)
        print(f"      UDP → {host}:{send_port}  "
              f"payload: {packet.hex()}")
        sock.sendto(packet, (host, send_port))

        # Read response — handle possible ACK before completion
        for attempt in range(3):
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                print(f"      [ERROR] UDP timeout waiting for reply "
                      f"(attempt {attempt + 1})")
                if attempt < 2:
                    # Retry the send
                    print(f"      Retrying send ...")
                    sock.sendto(packet, (host, send_port))
                    continue
                return None

            print(f"      UDP ← {addr}  raw: {data.hex()}")

            parsed = parse_visca_ip_response(data)
            if "error" in parsed:
                # Maybe it's a raw VISCA reply without envelope
                if is_visca_reply(data):
                    rtype = classify_reply(data)
                    if rtype == "completion":
                        return data
                    elif rtype == "error":
                        print(f"      [ERROR] {get_visca_error_meaning(data)}")
                        return None
                print(f"      [ERROR] {parsed['error']}: {data.hex()}")
                return None

            payload = parsed["payload"]
            rtype = classify_reply(payload)

            if rtype == "completion":
                return payload
            elif rtype == "ack":
                print(f"      (ACK — waiting for completion ...)")
                continue
            elif rtype == "error":
                print(f"      [ERROR] {get_visca_error_meaning(payload)}")
                return None
            else:
                print(f"      [WARN] Unexpected reply: {payload.hex()}")
                return None

    except Exception as e:
        print(f"      [ERROR] UDP exception: {e}")
        return None
    finally:
        sock.close()

    return None


# ---------------------------------------------------------------------------
# TCP Transport  (fallback)
# ---------------------------------------------------------------------------

def send_inquiry_tcp(sock: socket.socket, inquiry: bytes,
                     seq: int) -> Optional[bytes]:
    """Send VISCA inquiry over an already-connected TCP socket."""
    packet = build_visca_ip_packet(inquiry, seq)
    try:
        sock.sendall(packet)
    except socket.error as e:
        print(f"      [ERROR] TCP send failed: {e}")
        return None

    for attempt in range(2):
        try:
            data = sock.recv(1024)
        except socket.timeout:
            print("      [ERROR] TCP timeout")
            return None
        except socket.error as e:
            print(f"      [ERROR] TCP recv error: {e}")
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
            print(f"      (ACK — waiting for completion ...)")
            continue
        elif rtype == "error":
            print(f"      [ERROR] {get_visca_error_meaning(payload)}")
            return None

    print("      [ERROR] No completion after ACK")
    return None


def connect_tcp(host: str, port: int, timeout: int) -> Optional[socket.socket]:
    """Open a TCP connection, return socket or None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        print(f"      TCP connecting to {host}:{port} ...")
        sock.connect((host, port))
        print(f"      TCP connected.")
        return sock
    except ConnectionRefusedError:
        print(f"      [FAIL] TCP {port} refused")
    except socket.timeout:
        print(f"      [FAIL] TCP connection timed out ({timeout}s)")
    except OSError as e:
        print(f"      [FAIL] TCP error: {e}")
    sock.close()
    return None


# ---------------------------------------------------------------------------
# Response Parsers
# ---------------------------------------------------------------------------

def parse_version_response(payload: bytes, profile: dict) -> dict:
    """
    Parse CAM_VersionInq reply.
    Sony:  90 50 00 vv ww ww xx xx yy yy [zz] FF
    """
    result = {}
    if payload and payload[-1] == 0xFF:
        payload = payload[:-1]

    if len(payload) < 6:
        result["parse_error"] = f"Response too short ({len(payload)} bytes)"
        result["raw_hex"] = payload.hex()
        return result

    if profile.get("manufacturer") == "Sony" and len(payload) >= 8:
        vendor_id  = payload[3]
        model_code = (payload[4] << 8) | payload[5]
        rom_rev    = (payload[6] << 8) | payload[7]
        max_socket = ((payload[8] << 8) | payload[9]) if len(payload) >= 10 else None

        result["vendor_id"]              = f"0x{vendor_id:02X}"
        result["vendor_name"]            = VENDOR_CODES.get(vendor_id, f"Unknown (0x{vendor_id:02X})")
        result["model_code"]             = f"0x{model_code:04X}"
        result["model_name"]             = SONY_MODEL_CODES.get(model_code, f"Unknown Sony (0x{model_code:04X})")
        result["rom_revision"]           = f"0x{rom_rev:04X}"
        result["rom_revision_decimal"]   = rom_rev
        result["firmware_version"]       = f"{(rom_rev >> 8) & 0xFF}.{rom_rev & 0xFF:02d}"
        if max_socket is not None:
            result["max_sockets"] = max_socket
    else:
        result["vendor_name"] = profile.get("manufacturer", "Unknown")
        if len(payload) >= 6:
            model_code = (payload[4] << 8) | payload[5]
            result["model_code"] = f"0x{model_code:04X}"
        if len(payload) >= 8:
            rom_rev = (payload[6] << 8) | payload[7]
            result["rom_revision"]      = f"0x{rom_rev:04X}"
            result["firmware_version"]  = f"{(rom_rev >> 8) & 0xFF}.{rom_rev & 0xFF:02d}"

    result["raw_hex"] = payload.hex()
    return result


def parse_software_version_response(payload: bytes) -> dict:
    """Parse CAM_SoftVersionInq reply."""
    result = {}
    if payload and payload[-1] == 0xFF:
        payload = payload[:-1]
    if len(payload) < 3:
        result["parse_error"] = "Response too short"
        return result
    version_bytes = payload[2:]
    try:
        ascii_str = version_bytes.decode('ascii', errors='ignore')
        result["software_version_ascii"] = ''.join(
            c if c.isprintable() else '.' for c in ascii_str
        )
    except Exception:
        pass
    result["software_version_hex"] = version_bytes.hex()
    result["raw_hex"] = payload.hex()
    return result


# ---------------------------------------------------------------------------
# HTTP CGI Fallback (Prisual only)
# ---------------------------------------------------------------------------

def query_prisual_http(host: str, http_port: int, timeout: int) -> dict:
    result = {"method": "http_cgi", "endpoints_tried": [], "device_info_raw": {}}
    endpoints = CAMERA_PROFILES["tem-20n"]["cgi_endpoints"]

    for endpoint in endpoints:
        url = f"http://{host}:{http_port}{endpoint}"
        result["endpoints_tried"].append(url)
        print(f"      Trying: {url}")
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'VISCA-Query/1.0')
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    body = resp.read().decode('utf-8', errors='replace')
                    if body:
                        parsed = _parse_http_body(body)
                        if parsed:
                            result.update(parsed)
                            return result
        except Exception as e:
            print(f"      {e}")
    return result


def _parse_http_body(body: str) -> Optional[dict]:
    import re, json as _json
    try:
        data = _json.loads(body)
        if isinstance(data, dict):
            out = {}
            for k, v in data.items():
                kl = k.lower()
                if any(t in kl for t in ['version', 'firmware', 'fw']):
                    out["firmware_version"] = str(v)
                if any(t in kl for t in ['model', 'device', 'product']):
                    out["model_name"] = str(v)
            if out:
                return out
    except Exception:
        pass

    out = {}
    for line in body.strip().split('\n'):
        if '=' in line:
            k, _, v = line.partition('=')
            k = k.strip().lower(); v = v.strip().strip('"\'')
            if any(t in k for t in ['version', 'firmware']):
                out["firmware_version"] = v
            if any(t in k for t in ['model', 'device_name']):
                out["model_name"] = v
    if out:
        return out

    m = re.search(r'(?:version|firmware|fw)[:\s=]+([0-9]+\.[0-9][.\-0-9]*)',
                  body, re.IGNORECASE)
    if m:
        return {"firmware_version": m.group(1)}
    return None


# ---------------------------------------------------------------------------
# Profile Resolver
# ---------------------------------------------------------------------------

def resolve_profile(camera_type: str) -> Optional[dict]:
    key = PROFILE_ALIASES.get(camera_type.lower().strip())
    if key and key in CAMERA_PROFILES:
        return CAMERA_PROFILES[key].copy()
    return None


# ---------------------------------------------------------------------------
# Main Camera Query
# ---------------------------------------------------------------------------

def query_camera(host: str, port: int, camera_name: str,
                 camera_type: str, timeout: int) -> dict:

    profile = resolve_profile(camera_type)
    if not profile:
        return {
            "host": host, "camera_name": camera_name,
            "camera_type": camera_type, "status": "error",
            "errors": [f"Unknown camera type: {camera_type}"],
        }

    actual_port = port if port else profile["default_port"]
    transport   = profile.get("transport", "udp_first")

    result = {
        "host": host,
        "port": actual_port,
        "camera_name": camera_name,
        "camera_type": camera_type,
        "camera_profile": profile["display_name"],
        "manufacturer": profile["manufacturer"],
        "timestamp": datetime.now().isoformat(),
        "camera_generation": profile["generation"],
        "status": "unknown",
        "transport_used": None,
        "version_info": {},
        "software_version_info": {},
        "http_info": {},
        "errors": [],
    }

    display = camera_name if camera_name else host
    print(f"\n{'=' * 60}")
    print(f"  Camera:    {display}")
    print(f"  Host:      {host}:{actual_port}")
    print(f"  Type:      {profile['display_name']}")
    print(f"  Transport: {transport}")
    print(f"{'=' * 60}")

    seq = 1
    version_payload = None

    # ----------------------------------------------------------------
    # UDP-first path (Sony SRG-A40 / SRG-X400)
    # ----------------------------------------------------------------
    if transport == "udp_first":
        udp_send = profile.get("udp_send_port", 52381)
        udp_recv = profile.get("udp_recv_port", 52380)

        print(f"\n  [Step 1] Trying UDP  "
              f"(send→{udp_send}, recv←{udp_recv}) ...")

        version_payload = send_inquiry_udp(
            host, udp_send, udp_recv,
            VISCA_INQ_CAM_VERSION, seq, timeout
        )

        if version_payload:
            result["transport_used"] = f"UDP (send:{udp_send} recv:{udp_recv})"
            seq += 1
        else:
            print(f"\n  UDP failed — falling back to TCP port {actual_port} ...")
            print(f"\n  [Step 2] Trying TCP port {actual_port} ...")

            tcp_sock = connect_tcp(host, actual_port, timeout)
            if tcp_sock is None:
                msg = f"Both UDP and TCP failed for {host}"
                print(f"  [FAIL] {msg}")
                result["status"] = "connection_failed"
                result["errors"].append(msg)
                return result

            result["transport_used"] = f"TCP:{actual_port}"
            version_payload = send_inquiry_tcp(tcp_sock, VISCA_INQ_CAM_VERSION, seq)
            seq += 1

            # --- CAM_SoftVersionInq over TCP (SRG-A40 only) ---
            if version_payload and profile["supports_soft_version_inq"]:
                print(f"\n  CAM_SoftVersionInq ...")
                sw_resp = send_inquiry_tcp(tcp_sock, VISCA_INQ_SOFT_VERSION, seq)
                if sw_resp:
                    result["software_version_info"] = \
                        parse_software_version_response(sw_resp)
            tcp_sock.close()

    # ----------------------------------------------------------------
    # TCP-only path (Prisual TEM-20N)
    # ----------------------------------------------------------------
    elif transport == "tcp":
        print(f"\n  Connecting TCP to {host}:{actual_port} ...")
        tcp_sock = connect_tcp(host, actual_port, timeout)

        if tcp_sock is None:
            result["status"] = "connection_refused"
            result["errors"].append(f"TCP {actual_port} refused/timeout")
            # HTTP fallback for Prisual
            if profile.get("http_cgi_fallback"):
                http_info = query_prisual_http(host, profile.get("http_port", 80), timeout)
                result["http_info"] = http_info
                if http_info.get("firmware_version"):
                    result["version_info"]["firmware_version"] = http_info["firmware_version"]
                    result["version_info"]["source"] = "http_cgi"
                    result["status"] = "partial"
            return result

        result["transport_used"] = f"TCP:{actual_port}"

        # Prisual auto-detect: try Sony IP envelope, then raw
        visca_mode = profile.get("visca_mode", "auto")
        if visca_mode == "auto":
            version_payload = send_inquiry_tcp(tcp_sock, VISCA_INQ_CAM_VERSION, seq)
            if not version_payload:
                # Try raw VISCA (no header)
                try:
                    tcp_sock.sendall(VISCA_INQ_CAM_VERSION)
                    raw = tcp_sock.recv(1024)
                    if raw and is_visca_reply(raw) and classify_reply(raw) == "completion":
                        version_payload = raw
                except Exception:
                    pass
        else:
            version_payload = send_inquiry_tcp(tcp_sock, VISCA_INQ_CAM_VERSION, seq)

        seq += 1
        tcp_sock.close()

    # ----------------------------------------------------------------
    # Parse version response
    # ----------------------------------------------------------------
    if version_payload:
        print(f"\n  CAM_VersionInq raw reply: {version_payload.hex()}")
        vi = parse_version_response(version_payload, profile)
        result["version_info"] = vi

        print(f"  Vendor:           {vi.get('vendor_name', 'N/A')}")
        if vi.get('model_code'):
            print(f"  Model Code:       {vi['model_code']}")
        if vi.get('model_name'):
            print(f"  Model Name:       {vi['model_name']}")
        if vi.get('rom_revision'):
            print(f"  ROM Revision:     {vi['rom_revision']}")
        if vi.get('firmware_version'):
            print(f"  Firmware Version: {vi['firmware_version']}")
        if vi.get('max_sockets') is not None:
            print(f"  Max Sockets:      {vi['max_sockets']}")
        if "parse_error" in vi:
            print(f"  [WARN] {vi['parse_error']}")
            result["errors"].append(vi["parse_error"])
    else:
        print(f"\n  No VISCA version response received.")
        result["errors"].append("CAM_VersionInq: no response")

    # ----------------------------------------------------------------
    # CAM_SoftVersionInq over UDP (SRG-A40 only, if UDP was used)
    # ----------------------------------------------------------------
    if (profile["supports_soft_version_inq"]
            and result["transport_used"]
            and result["transport_used"].startswith("UDP")
            and not result["software_version_info"]):

        print(f"\n  CAM_SoftVersionInq ...")
        udp_send = profile.get("udp_send_port", 52381)
        udp_recv = profile.get("udp_recv_port", 52380)
        sw_resp = send_inquiry_udp(host, udp_send, udp_recv,
                                   VISCA_INQ_SOFT_VERSION, seq, timeout)
        if sw_resp:
            result["software_version_info"] = \
                parse_software_version_response(sw_resp)
        else:
            result["software_version_info"] = {"note": "No response"}

    # ----------------------------------------------------------------
    # HTTP fallback for Prisual if VISCA gave no firmware
    # ----------------------------------------------------------------
    if (profile.get("http_cgi_fallback")
            and not result["version_info"].get("firmware_version")):
        print(f"\n  Attempting HTTP CGI fallback ...")
        http_info = query_prisual_http(host, profile.get("http_port", 80), timeout)
        result["http_info"] = http_info
        if http_info.get("firmware_version"):
            result["version_info"]["firmware_version"] = http_info["firmware_version"]
            result["version_info"]["firmware_source"] = "http_cgi"
        if http_info.get("model_name"):
            result["version_info"]["model_name"] = http_info["model_name"]

    # ----------------------------------------------------------------
    # Final status
    # ----------------------------------------------------------------
    if result["version_info"].get("firmware_version"):
        result["status"] = "success"
    elif result["version_info"]:
        result["status"] = "partial"
    else:
        result["status"] = "failed"

    print(f"\n  Generation:     {result['camera_generation']}")
    print(f"  Transport used: {result['transport_used']}")
    print(f"  Status:         {result['status']}")
    return result


# ---------------------------------------------------------------------------
# CSV Reader
# ---------------------------------------------------------------------------

def read_csv(filepath: str) -> list:
    cameras = []
    if not os.path.isfile(filepath):
        print(f"[ERROR] CSV not found: {filepath}")
        sys.exit(1)

    with open(filepath, 'r', newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        fieldnames_lower = [fn.lower().strip() for fn in (reader.fieldnames or [])]

        if not any(c in fieldnames_lower for c in ['host', 'ip', 'address']):
            print(f"[ERROR] CSV needs a 'host' column. Found: {reader.fieldnames}")
            sys.exit(1)
        if not any(c in fieldnames_lower for c in ['type', 'model', 'camera_type']):
            print(f"[ERROR] CSV needs a 'type' column. Found: {reader.fieldnames}")
            sys.exit(1)

        for row_num, row in enumerate(reader, start=2):
            rl = {k.lower().strip(): (v.strip() if v else '') for k, v in row.items()}
            host = rl.get('host') or rl.get('ip') or rl.get('address', '')
            if not host:
                print(f"  [WARN] Row {row_num}: no host, skipping.")
                continue
            camera_type = rl.get('type') or rl.get('model') or rl.get('camera_type', '')
            if not camera_type:
                print(f"  [WARN] Row {row_num}: no type, skipping.")
                continue
            if not PROFILE_ALIASES.get(camera_type.lower()):
                print(f"  [WARN] Row {row_num}: unknown type '{camera_type}', skipping.")
                continue
            try:
                port = int(rl.get('port', '') or 0)
            except ValueError:
                port = 0
            cameras.append({
                "host": host,
                "port": port,
                "name": rl.get('name') or rl.get('camera_name', ''),
                "type": camera_type,
            })
    return cameras


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(results: list):
    print(f"\n\n{'#' * 75}")
    print(f"  RESULTS SUMMARY")
    print(f"{'#' * 75}\n")
    print(f"{'#':<4} {'Name':<22} {'Host':<16} {'Type':<14} "
          f"{'Status':<10} {'FW Version':<12} {'Transport'}")
    print("-" * 100)

    for i, r in enumerate(results, 1):
        name   = (r.get("camera_name") or "")[:21]
        host   = (r.get("host") or "")[:15]
        ctype  = (r.get("camera_profile") or r.get("camera_type", ""))[:13]
        status = r.get("status", "unknown")
        fw     = r.get("version_info", {}).get("firmware_version", "N/A")[:11]
        tport  = (r.get("transport_used") or "—")[:20]

        if status == "success":
            sc = f"\033[92m{status:<10}\033[0m"
        elif status == "partial":
            sc = f"\033[93m{status:<10}\033[0m"
        else:
            sc = f"\033[91m{status:<10}\033[0m"

        print(f"{i:<4} {name:<22} {host:<16} {ctype:<14} {sc} {fw:<12} {tport}")

    print()
    total   = len(results)
    success = sum(1 for r in results if r["status"] == "success")
    partial = sum(1 for r in results if r["status"] == "partial")
    failed  = total - success - partial
    print(f"  Total: {total}  |  Success: {success}  "
          f"|  Partial: {partial}  |  Failed: {failed}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Camera Firmware Query Tool — UDP-first with TCP fallback",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Transport strategy for Sony cameras:
  1. UDP  send→52381  recv←52380  (Sony asymmetric VISCA over IP)
  2. TCP  connect→52381           (fallback if UDP gets no reply)

CSV format:
  host,type,port,name
  192.168.1.100,srg-x400,,Main Stage
  192.168.1.101,srg-a40,,Backup
  192.168.1.102,tem-20n,,Prisual Cam

Valid type values: srg-a40, a40, srg-x400, x400, tem-20n, prisual
        """
    )
    parser.add_argument("csv_file", help="CSV file with camera list")
    parser.add_argument("-o", "--output", default="results.json",
                        help="Output JSON file (default: results.json)")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Timeout in seconds (default: {DEFAULT_TIMEOUT})")

    args = parser.parse_args()

    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║         Camera Firmware Query Tool                            ║
║                                                               ║
║  Sony SRG-X400 / SRG-A40:                                    ║
║    Step 1 — UDP  send:52381  recv:52380                       ║
║    Step 2 — TCP  52381  (fallback)                            ║
║                                                               ║
║  Timeout: {args.timeout}s                                              ║
╚═══════════════════════════════════════════════════════════════╝
""")

    cameras = read_csv(args.csv_file)
    if not cameras:
        print("[ERROR] No valid cameras in CSV.")
        sys.exit(1)

    print(f"Found {len(cameras)} camera(s):\n")
    for i, cam in enumerate(cameras, 1):
        p    = resolve_profile(cam["type"])
        port = cam["port"] or (p["default_port"] if p else "?")
        print(f"  {i}. {(cam.get('name') or cam['host']):<30} "
              f"{cam['host']:<16} {(p['display_name'] if p else cam['type']):<18} port {port}")

    all_results = []
    for idx, cam in enumerate(cameras, 1):
        print(f"\n\n[Camera {idx}/{len(cameras)}]")
        result = query_camera(
            host=cam["host"], port=cam["port"],
            camera_name=cam["name"], camera_type=cam["type"],
            timeout=args.timeout,
        )
        all_results.append(result)
        if idx < len(cameras):
            time.sleep(0.3)

    print_summary(all_results)

    output_data = {
        "query_timestamp": datetime.now().isoformat(),
        "csv_source": args.csv_file,
        "total_cameras": len(all_results),
        "timeout_seconds": args.timeout,
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
