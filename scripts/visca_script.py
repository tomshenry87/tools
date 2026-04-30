#!/usr/bin/env python3
"""
Sony VISCA-over-IP Firmware Query Tool

Targets:
  - Sony SRG-X400 (model code 0x0617, others)
  - Sony SRG-A40  (model code 0x0710)
  - Sony SRG-A12  (model code 0x0711)

Protocol: VISCA over IP (UDP 52381) — Sony 8-byte header envelope

Validated handshake (against an SRG-X400 returning fw 3.00):
  1. Bind a local UDP socket on port 52381 (camera replies to this port)
  2. Send a RESET packet (payload type 0x0200, payload 0x01) to sync seq #
  3. Wait for the 0x0201 control reply
  4. Send CAM_VersionInq (payload type 0x0110) with seq=1
  5. Camera replies with payload type 0x0111 + VISCA completion bytes
  6. (Optional) Send CAM_SoftVersionInq for SRG-A40

Packet format (8-byte header + VISCA payload):
  [2B payload_type][2B payload_length][4B sequence_number][N bytes payload]

Note: only one process at a time can bind UDP 52381 on this machine, so
queries are issued sequentially even though a workers argument is exposed
for compatibility with the standard CLI.
"""

import csv
import json
import re
import socket
import struct
import sys
import os
import shutil
import argparse
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

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
DEFAULT_CSV     = "secrets/visca_firmware.csv"
OUTPUT_DIR      = "visca_firmware/files"
DEFAULT_OUTPUT  = os.path.join(
    OUTPUT_DIR,
    f"results_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
)
DEFAULT_PORT    = 52381
DEFAULT_TIMEOUT = 3
DEFAULT_WORKERS = 1   # only one process can bind UDP 52381 — kept for CLI parity

LOCAL_VISCA_PORT = 52381

# VISCA-over-IP payload types
PT_VISCA_INQUIRY   = 0x0110
PT_VISCA_REPLY     = 0x0111
PT_CONTROL_COMMAND = 0x0200
PT_CONTROL_REPLY   = 0x0201

# Control command payloads
CTRL_RESET_SEQ = bytes([0x01])

# VISCA inquiries
VISCA_INQ_CAM_VERSION  = bytes([0x81, 0x09, 0x00, 0x02, 0xFF])
VISCA_INQ_SOFT_VERSION = bytes([0x81, 0x09, 0x04, 0x00, 0xFF])

# Known model codes (extend as discovered)
SONY_MODEL_CODES = {
    0x0617: "SRG-X400",
    0x0519: "SRG-X400",
    0x0630: "SRG-X400",
    0x0710: "SRG-A40",
    0x0711: "SRG-A12",
}

# Camera profiles — keyed by canonical camera type string
CAMERA_PROFILES = {
    "srg-a40": {
        "display_name": "Sony SRG-A40",
        "manufacturer": "Sony",
        "supports_soft_version_inq": True,
    },
    "srg-x400": {
        "display_name": "Sony SRG-X400",
        "manufacturer": "Sony",
        "supports_soft_version_inq": False,
    },
    "prisual": {
        # Prisual / Tenveo / many third-party PTZ cameras use VISCA on a
        # different port and may skip Sony's 8-byte header. The script's
        # inquiry handler tolerates both wrapped and bare VISCA replies.
        "display_name": "Prisual / Generic VISCA",
        "manufacturer": "Prisual",
        "supports_soft_version_inq": False,
    },
    "generic-visca": {
        "display_name": "Generic VISCA-over-IP",
        "manufacturer": "Unknown",
        "supports_soft_version_inq": False,
    },
    "auto": {
        # Used when CSV doesn't declare a type — the camera tells us what
        # it is via the VISCA CAM_VersionInq reply, then we look up the
        # real profile by model code.
        "display_name": "Auto-detect",
        "manufacturer": "Unknown",
        "supports_soft_version_inq": False,
    },
}

PROFILE_ALIASES = {
    "srg-a40": "srg-a40",  "srga40": "srg-a40",
    "sony srg-a40": "srg-a40", "a40": "srg-a40",
    "srg-x400": "srg-x400", "srgx400": "srg-x400",
    "sony srg-x400": "srg-x400", "x400": "srg-x400",
    "prisual": "prisual", "tenveo": "prisual",
    "ptzoptics": "prisual", "tem-20n": "prisual", "tem20n": "prisual",
    "generic": "generic-visca", "generic-visca": "generic-visca",
    "visca": "generic-visca", "other": "generic-visca",
    "auto": "auto", "": "auto",
}

# Map raw model code (from CAM_VersionInq) → canonical profile key.
# Used during auto-detection to decide which profile to load.
MODEL_CODE_TO_PROFILE = {
    0x0617: "srg-x400",
    0x0519: "srg-x400",
    0x0630: "srg-x400",
    0x0710: "srg-a40",
    0x0711: "srg-a40",  # SRG-A12 shares the SRG-A40 firmware family
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
        (r"RESET handshake failed",            "No VISCA reply"),
        (r"[Ss]equence number",                "Seq sync error"),
        (r"[Bb]ind .* port",                   "Port 52381 in use"),
        (r"CAM_VersionInq: no response",       "No version reply"),
        (r"[Uu]nknown camera type",            "Unknown model"),
        (r"[Nn]ot a .* device",                "Not supported"),
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


def resolve_profile(camera_type: str):
    """Look up the camera profile from a CSV `type` value.

    An empty/missing/unknown type returns the 'auto' profile, which causes
    the query to detect the model from the VISCA CAM_VersionInq reply.
    """
    norm = (camera_type or "").lower().strip()
    key  = PROFILE_ALIASES.get(norm, "auto" if norm == "" else None)
    if key and key in CAMERA_PROFILES:
        return CAMERA_PROFILES[key].copy()
    return None


def profile_from_model_code(model_code: int):
    """Return the canonical profile dict matching a numeric model code, or None."""
    profile_key = MODEL_CODE_TO_PROFILE.get(model_code)
    if profile_key and profile_key in CAMERA_PROFILES:
        return CAMERA_PROFILES[profile_key].copy()
    return None


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
        # type/model column is OPTIONAL — if absent, the script auto-detects
        # the camera model from the VISCA CAM_VersionInq reply
        type_col = col_map.get("type") or col_map.get("model")
        for row in reader:
            host = row.get(col_map["host"], "").strip()
            if not host or host.startswith("#"):
                continue
            try:
                port = int(row.get(col_map.get("port", ""), DEFAULT_PORT) or DEFAULT_PORT)
            except (ValueError, TypeError):
                port = DEFAULT_PORT
            ctype = row.get(type_col, "").strip() if type_col else ""
            name  = row.get(col_map.get("name", ""), "").strip() if "name" in col_map else ""
            devices.append({
                "host": host, "port": port,
                "type": ctype, "name": name,
            })
    if not devices:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No valid entries found in CSV.{RESET}")
        sys.exit(1)
    return devices


# ---------------------------------------------------------------------------
# VISCA Packet Helpers
# ---------------------------------------------------------------------------
def build_packet(payload_type: int, payload: bytes, seq: int) -> bytes:
    return struct.pack('>HHI', payload_type, len(payload), seq) + payload


def parse_packet(data: bytes) -> dict:
    if len(data) < 8:
        return {"error": f"Packet too short ({len(data)} bytes)"}
    payload_type, payload_length, seq = struct.unpack('>HHI', data[:8])
    return {
        "payload_type":     payload_type,
        "payload_length":   payload_length,
        "sequence_number":  seq,
        "payload":          data[8:8 + payload_length],
    }


def classify_visca_reply(payload: bytes) -> str:
    if len(payload) < 2:
        return "unknown"
    b = payload[1] & 0xF0
    return {0x40: "ack", 0x50: "completion", 0x60: "error"}.get(b, "unknown")


def visca_error_meaning(payload: bytes) -> str:
    code = payload[2] if len(payload) > 2 else 0xFF
    return {
        0x01: "Message length error",
        0x02: "Syntax error / command not supported",
        0x03: "Command buffer full",
        0x04: "Command cancelled",
        0x05: "No socket",
        0x41: "Command not executable",
    }.get(code, f"Unknown error 0x{code:02X}")


# ---------------------------------------------------------------------------
# UDP Transport
# ---------------------------------------------------------------------------
def open_visca_socket(timeout: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    try:
        sock.bind(('', LOCAL_VISCA_PORT))
        return sock, None
    except OSError as e:
        sock.close()
        return None, f"Cannot bind local UDP port {LOCAL_VISCA_PORT}: {e}"


def send_and_receive(sock, packet, dest):
    try:
        sock.sendto(packet, dest)
    except OSError as e:
        return None, f"sendto failed: {e}"
    try:
        data, _ = sock.recvfrom(1024)
        return data, None
    except socket.timeout:
        return None, "No response (timeout)"
    except OSError as e:
        return None, f"recvfrom failed: {e}"


def visca_reset_sequence(sock, dest):
    """Send RESET (0x0200 + 0x01) and wait for the 0x0201 control reply."""
    packet = build_packet(PT_CONTROL_COMMAND, CTRL_RESET_SEQ, 0)
    reply, err = send_and_receive(sock, packet, dest)
    if reply is None:
        return False, err or "RESET handshake failed"

    parsed = parse_packet(reply)
    if "error" in parsed:
        return False, parsed["error"]

    if parsed["payload_type"] == PT_CONTROL_REPLY:
        return True, None

    return False, f"Unexpected RESET reply type 0x{parsed['payload_type']:04X}"


def _is_raw_visca_payload(data: bytes) -> bool:
    """Detect a bare VISCA reply (90 ... FF) with no Sony 8-byte envelope."""
    return len(data) >= 3 and data[0] == 0x90 and data[-1] == 0xFF


def send_visca_inquiry(sock, dest, inquiry, seq):
    """Send a VISCA inquiry, return (visca_payload, error).

    Tolerates both Sony's 8-byte envelope and bare VISCA replies that some
    third-party cameras (PTZOptics, Prisual, Tenveo, etc.) send.
    """
    packet = build_packet(PT_VISCA_INQUIRY, inquiry, seq)
    reply, err = send_and_receive(sock, packet, dest)
    if reply is None:
        return None, err or "No response"

    # Some cameras skip the 8-byte envelope and just send raw VISCA bytes.
    if _is_raw_visca_payload(reply) and len(reply) < 8:
        rtype = classify_visca_reply(reply)
        if rtype == "completion":
            return reply, None
        if rtype == "error":
            return None, visca_error_meaning(reply)

    parsed = parse_packet(reply)
    if "error" in parsed:
        # Maybe the whole reply is raw VISCA — try that
        if _is_raw_visca_payload(reply):
            return reply, None
        return None, parsed["error"]

    if (parsed["payload_type"] == PT_CONTROL_REPLY
            and parsed["payload"] == bytes([0x0F, 0x01])):
        return None, "Sequence number out of sync"

    if parsed["payload_type"] != PT_VISCA_REPLY:
        # Some cameras might wrap things differently — fall back to raw check
        if _is_raw_visca_payload(reply):
            return reply, None
        return None, f"Unexpected reply type 0x{parsed['payload_type']:04X}"

    visca_payload = parsed["payload"]
    rtype = classify_visca_reply(visca_payload)

    if rtype == "completion":
        return visca_payload, None
    if rtype == "error":
        return None, visca_error_meaning(visca_payload)
    if rtype == "ack":
        try:
            data, _ = sock.recvfrom(1024)
            p2 = parse_packet(data)
            if p2.get("payload_type") == PT_VISCA_REPLY:
                return p2["payload"], None
            if _is_raw_visca_payload(data):
                return data, None
            return None, "No completion after ACK"
        except socket.timeout:
            return None, "No completion after ACK (timeout)"

    return None, f"Unrecognized VISCA reply: {visca_payload.hex()}"


# ---------------------------------------------------------------------------
# Response Parsers
# ---------------------------------------------------------------------------
def parse_version_response(payload: bytes, manufacturer: str) -> dict:
    """
    Parse CAM_VersionInq reply.
      90 50 vv vv ww ww xx xx yy yy FF
      | |  vendor model rom   max
    """
    result = {}
    if payload and payload[-1] == 0xFF:
        payload = payload[:-1]

    if len(payload) < 4:
        result["parse_error"] = f"Response too short ({len(payload)} bytes)"
        result["raw_hex"]     = payload.hex()
        return result

    # Bytes 0..1 are 90 50 (address + completion). Useful data starts at 2.
    # Non-Sony VISCA cameras may return fewer fields than Sony's 10-byte format.
    vendor_id  = (payload[2] << 8) | payload[3] if len(payload) >= 4 else None
    model_code = (payload[4] << 8) | payload[5] if len(payload) >= 6 else None
    rom_rev    = (payload[6] << 8) | payload[7] if len(payload) >= 8 else None
    max_sock   = (payload[8] << 8) | payload[9] if len(payload) >= 10 else None

    if vendor_id is not None:
        result["vendor_id"]   = f"0x{vendor_id:04X}"
        result["vendor_name"] = "Sony" if vendor_id == 0x0001 else manufacturer
    if model_code is not None:
        result["model_code"]  = f"0x{model_code:04X}"
        result["model_name"]  = SONY_MODEL_CODES.get(
            model_code, f"Unknown (0x{model_code:04X})"
        )
    if rom_rev is not None:
        result["rom_revision"]         = f"0x{rom_rev:04X}"
        result["rom_revision_decimal"] = rom_rev
        result["firmware_version"]     = f"{(rom_rev >> 8) & 0xFF}.{rom_rev & 0xFF:02d}"
    if max_sock is not None:
        result["max_sockets"]          = max_sock

    # If we got nothing structured (rom_rev missing), surface raw bytes
    # as the firmware string so the user at least sees something.
    if rom_rev is None and len(payload) > 2:
        result["firmware_version"] = payload[2:].hex()

    result["raw_hex"] = payload.hex()
    return result


def parse_software_version_response(payload: bytes) -> dict:
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
    return result


# ---------------------------------------------------------------------------
# Main camera query
# ---------------------------------------------------------------------------
def query_camera(host: str, port: int, camera_name: str, camera_type: str,
                 timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Query a single camera. Returns a result dict shaped like the Bravia tool."""
    result = {
        "host":                 host,
        "port":                 port,
        "camera_name":          camera_name,
        "camera_type":          camera_type,
        "status":               "error",
        "manufacturer":         "N/A",
        "model":                "N/A",
        "model_code":           "N/A",
        "firmware_version":     "N/A",
        "rom_revision":         "N/A",
        "vendor_id":            "N/A",
        "max_sockets":          "N/A",
        "software_version":     "N/A",
        "software_version_hex": "N/A",
        "error":                None,
        "query_timestamp":      datetime.now(timezone.utc).isoformat(),
    }

    profile = resolve_profile(camera_type)
    if not profile:
        result["error"] = f"Unknown camera type: {camera_type}"
        return result

    result["manufacturer"] = profile["manufacturer"]
    dest = (host, port)

    sock, bind_err = open_visca_socket(timeout)
    if sock is None:
        result["error"] = bind_err
        return result

    try:
        # 1. RESET handshake (Sony's VISCA-over-IP requires this; third-party
        #    cameras may not implement it but often still answer inquiries.)
        reset_ok, reset_err = visca_reset_sequence(sock, dest)
        if not reset_ok:
            # Don't bail out yet — try the inquiry anyway. If that also
            # fails we'll surface the original RESET error.
            result["reset_status"] = "skipped"
            result["reset_error"]  = reset_err
        else:
            result["reset_status"] = "ok"

        time.sleep(0.05)

        # 2. CAM_VersionInq
        version_payload, err = send_visca_inquiry(
            sock, dest, VISCA_INQ_CAM_VERSION, seq=1
        )
        if version_payload is None:
            # Inquiry failed — surface RESET error first if we had one,
            # since that's usually the more informative failure.
            if not reset_ok:
                result["error"] = reset_err or "RESET handshake failed"
            else:
                result["error"] = err or "CAM_VersionInq: no response"
            return result

        vi = parse_version_response(version_payload, profile["manufacturer"])
        if "parse_error" in vi:
            result["error"] = vi["parse_error"]
            return result

        result["model"]            = vi.get("model_name", "N/A")
        result["model_code"]       = vi.get("model_code", "N/A")
        result["firmware_version"] = vi.get("firmware_version", "N/A")
        result["rom_revision"]     = vi.get("rom_revision", "N/A")
        result["vendor_id"]        = vi.get("vendor_id", "N/A")
        result["manufacturer"]     = vi.get("vendor_name", profile["manufacturer"])
        if vi.get("max_sockets") is not None:
            result["max_sockets"]  = vi["max_sockets"]

        # If we started in auto-detect mode, upgrade to the real profile
        # using the model code the camera just reported. This decides
        # whether the SRG-A40-only soft version inquiry is run.
        if camera_type.lower().strip() in ("", "auto"):
            try:
                model_code_int = int(vi.get("model_code", "0x0000"), 16)
            except (TypeError, ValueError):
                model_code_int = 0
            detected = profile_from_model_code(model_code_int)
            if detected:
                profile = detected
                result["camera_type"] = profile["display_name"]

        result["status"] = "success"

        # 3. CAM_SoftVersionInq (SRG-A40 only)
        if profile["supports_soft_version_inq"]:
            time.sleep(0.05)
            sw_payload, _ = send_visca_inquiry(
                sock, dest, VISCA_INQ_SOFT_VERSION, seq=2
            )
            if sw_payload:
                sw = parse_software_version_response(sw_payload)
                if sw.get("software_version_ascii"):
                    result["software_version"] = sw["software_version_ascii"]
                if sw.get("software_version_hex"):
                    result["software_version_hex"] = sw["software_version_hex"]

    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def save_results_json(results: list, filepath: str, args, elapsed: float):
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    ok   = sum(1 for r in results if r["status"] == "success")
    auth = sum(1 for r in results if r["status"] == "auth_error")
    err  = sum(1 for r in results if r["status"] == "error")
    output = {
        "query_info": {
            "csv_file":        str(Path(args.input).resolve()) if not args.host else None,
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "protocol":        "VISCA over IP (UDP) — Sony 8-byte header envelope",
            "mode":            f"local UDP port {LOCAL_VISCA_PORT}, RESET-then-inquire",
            "workers":         args.workers,
            "total":           len(results),
            "success":         ok,
            "auth_errors":     auth,
            "errors":          err,
            "elapsed_seconds": round(elapsed, 2),
        },
        "cameras": results,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)


def print_results_table(results: list, output_file: str, elapsed: float,
                        workers: int, firmware_filter: str = None):

    if firmware_filter:
        display_results = [
            r for r in results
            if r.get("firmware_version", "N/A") != firmware_filter
        ]
    else:
        display_results = results

    table_data = []
    for r in display_results:
        row = [
            status_icon(r),
            clean(r["host"]),
            clean(r.get("manufacturer")),
            clean(r.get("model")),
            clean(r.get("firmware_version")),
            clean(r.get("model_code")),
            clean(r.get("rom_revision")),
            truncate_error(r.get("error")),
        ]
        table_data.append(row)

    headers = ["Status", "Host", "Manufacturer", "Model",
               "Firmware", "Model Code", "ROM Rev", "Error"]

    table = tabulate(table_data, headers=headers,
                     tablefmt="pretty", stralign="left", numalign="right")

    first_line = table.split("\n")[0]
    raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw         = max(raw_width, 60)

    title = "Sony VISCA-over-IP \u2014 Firmware Query Results"
    if firmware_filter:
        title += f"  \u2014  Mismatched: {len(display_results)}/{len(results)}"
    pad   = (bw - len(title)) // 2

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")
    for line in table.split("\n"):
        print(f"  {line}")

    total = len(display_results)
    ok    = sum(1 for r in display_results if r["status"] == "success")
    auth  = sum(1 for r in display_results if r["status"] == "auth_error")
    err   = sum(1 for r in display_results if r["status"] == "error")

    print()
    if firmware_filter:
        print(
            f"  {BOLD}Firmware filter:{RESET}{WHITE} {firmware_filter}  |  "
            f"{BOLD}Showing:{RESET}{WHITE} {len(display_results)} of {len(results)} cameras"
        )
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}\u2717{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )

    # Firmware distribution metric
    fw_counts = {}
    for r in display_results:
        if r["status"] == "success":
            fw = r.get("firmware_version", "N/A")
            fw_counts[fw] = fw_counts.get(fw, 0) + 1

    reported = sum(fw_counts.values())
    if reported:
        parts = "  |  ".join(
            f"{BOLD}{fw}:{RESET}{WHITE} {c}"
            for fw, c in sorted(fw_counts.items())
        )
        print(f"  {BOLD}Firmware Versions \u2014{RESET}{WHITE} {parts}  |  "
              f"{BOLD}Reported:{RESET}{WHITE} {reported}/{total}")
    else:
        print(f"  {BOLD}Firmware Versions \u2014{RESET}{WHITE} No data available")

    print()
    print(f"  {BOLD}Results saved:{RESET}{WHITE} {output_file}")
    print(f"  {BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers)")
    print(f"{RESET}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Query Sony VISCA-over-IP cameras (SRG-X400, SRG-A40) for firmware version.",
        epilog="""
Examples:
  python visca_script.py
  python visca_script.py -i my_cameras.csv
  python visca_script.py -i cameras.csv -t 5 -o output.json
  python visca_script.py --host 10.8.129.79
  python visca_script.py --host 10.8.129.79 --type srg-x400
  python visca_script.py --firmware 3.00

CSV Format:
  host                                   <- 'host' is the only required column
  10.8.129.79
  192.168.1.50
  # comments are skipped

  host,type,port,name                    <- type/port/name are all optional
  10.8.129.79,,,Dewey-010 Camera 2
  192.168.1.50,srg-a40,,Studio A         <- type is a hint, not required

Valid type hints (case-insensitive):
  srg-a40, a40            (Sony SRG-A40 family)
  srg-x400, x400          (Sony SRG-X400 family)
  prisual, tenveo,        (Third-party VISCA cameras — tolerates both
  ptzoptics, tem-20n       wrapped and bare-VISCA replies)
  generic-visca, visca    (Any other VISCA-over-IP camera)
  auto                    (Default — model identified from the reply)

Auto-detection:
  When the type column is missing or empty, the script reads the model
  code from the camera's VISCA reply (e.g. 0x0617 -> SRG-X400) and
  decides automatically whether to run the SRG-A40-only soft version
  inquiry.

Protocol Notes:
  - Uses UDP 52381 with Sony's 8-byte header envelope.
  - Binds the local socket to UDP 52381 — only one process at a time can do this.
  - Sends a RESET (0x0200 + 0x01) before every camera to sync sequence numbers.
  - Cameras are queried sequentially because of the local-port constraint;
    --workers is accepted for CLI parity but always behaves as 1.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-i", "--input",   default=DEFAULT_CSV,
        help=f"CSV file with 'host' column (type/port/name optional) "
             f"(default: {DEFAULT_CSV})")
    parser.add_argument("--host",          default=None,
        help="Query a single host instead of reading a CSV")
    parser.add_argument("--type",          default=None,
        help="Optional camera type hint (e.g. srg-x400, srg-a40). "
             "If omitted, the model is auto-detected from the VISCA reply.")
    parser.add_argument("-o", "--output",  default=DEFAULT_OUTPUT,
        help=f"Output JSON file (default: {DEFAULT_OUTPUT})")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
        help=f"UDP timeout per packet in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-p", "--port",    type=int, default=DEFAULT_PORT,
        help=f"Port for --host mode (default: {DEFAULT_PORT})")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
        help=f"Workers (default: {DEFAULT_WORKERS}; always sequential due to UDP 52381 bind)")
    parser.add_argument("--firmware",      default=None, metavar="VERSION",
        help="Only show cameras whose firmware does NOT match VERSION in the terminal table "
             "(e.g. --firmware 3.00). JSON output always contains all results.")

    args = parser.parse_args()

    term_width = get_terminal_width()
    start_time = time.monotonic()

    # -----------------------------------------------------------------------
    # Header block
    # -----------------------------------------------------------------------
    input_display = args.host if args.host else args.input
    print(f"{WHITE}")
    print(f"  {BOLD}Sony VISCA-over-IP Firmware Query Tool{RESET}{WHITE}")
    print(f"  Queries firmware version via VISCA over IP (UDP 52381).")
    print(f"  Input:   {input_display}")
    print(f"  Output:  {args.output}")
    print(f"  Workers: {args.workers} (sequential — UDP {LOCAL_VISCA_PORT} bind)")
    print(f"  Timeout: {args.timeout}s")
    print(f"  Mode:    Bind UDP {LOCAL_VISCA_PORT} \u2192 RESET \u2192 inquire")
    if args.firmware:
        print(f"  Filter:  Showing cameras not on firmware {args.firmware}")
    print(f"{RESET}")

    # -----------------------------------------------------------------------
    # Build camera list
    # -----------------------------------------------------------------------
    if args.host:
        cameras = [{
            "host": args.host,
            "port": args.port,
            "type": args.type or "auto",
            "name": "",
        }]
    else:
        cameras = load_csv(args.input)

    # -----------------------------------------------------------------------
    # Progress bar + sequential query loop
    # (UDP 52381 can only be bound by one process — no concurrency)
    # -----------------------------------------------------------------------
    bar_fmt = (
        f"  {WHITE}Scanning{RESET} "
        f"{CYAN}{{bar}}{RESET}"
        f" {WHITE}{{n_fmt}}/{{total_fmt}}{RESET}"
        f" {WHITE}[{{elapsed}}<{{remaining}}]{RESET}"
        f"  {WHITE}{{postfix}}{RESET}"
    )

    results     = []
    active_lock = threading.Lock()
    latest_host = {"value": ""}

    with tqdm(total=len(cameras), bar_format=bar_fmt, ncols=term_width,
              dynamic_ncols=True, file=sys.stderr, leave=True) as pbar:
        for cam in cameras:
            with active_lock:
                latest_host["value"] = cam["host"]
            pbar.set_postfix_str(latest_host["value"], refresh=False)

            r = query_camera(
                host=cam["host"],
                port=cam["port"],
                camera_name=cam.get("name", ""),
                camera_type=cam.get("type", ""),
                timeout=args.timeout,
            )
            results.append(r)
            pbar.update(1)

            # Brief pause to let the local UDP port fully release
            time.sleep(0.2)

        elapsed = time.monotonic() - start_time
        pbar.set_postfix_str(
            f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s",
            refresh=True,
        )

    # Preserve CSV order
    host_order = {c["host"]: i for i, c in enumerate(cameras)}
    results.sort(key=lambda r: host_order.get(r["host"], 0))

    print_results_table(results, args.output, elapsed, args.workers, args.firmware)
    save_results_json(results, args.output, args, elapsed)


if __name__ == "__main__":
    main()
