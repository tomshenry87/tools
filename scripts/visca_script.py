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
import urllib.request
import urllib.error
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

# Known vendor IDs encountered in the wild. Sony is the only officially
# documented one; others were discovered empirically from real cameras.
VENDOR_NAMES = {
    0x0001: "Sony",
    0x0052: "Unknown (vendor 0x0052)",   # stub VISCA — only echoes vendor ID
    0x0056: "Prisual",                   # confirmed via Prisual TEM-20N PRO
}

# Model codes keyed by (vendor_id, model_code) so labels stay unambiguous
# across vendors that happen to reuse model code numbers.
MODEL_CODES = {
    # Sony (vendor 0x0001)
    (0x0001, 0x0617): "Sony SRG-X400",      # confirmed
    (0x0001, 0x0519): "Sony SRG-X400",      # alternate revision seen on older units
    (0x0001, 0x0630): "Sony SRG-X400",      # alternate revision seen on older units
    (0x0001, 0x0621): "Sony SRG-A40",       # confirmed
    (0x0001, 0x0710): "Sony SRG-A40",       # legacy mapping kept for safety
    (0x0001, 0x0711): "Sony SRG-A12",

    # Prisual (vendor 0x0056)
    (0x0056, 0x46D5): "Prisual TEM-20N PRO",  # confirmed
}

# Cameras that don't actually report a model/firmware in CAM_VersionInq
# (we get a 4-byte stub reply with only the vendor ID). Used to suppress
# the misleading "firmware = vendor_id_hex" fallback in the table.
STUB_VISCA_VENDORS = {0x0052}

# Vendor-specific decoding for the ROM-revision bytes (payload[6..7]).
#
# Sony documents the two bytes as  major.<minor-as-decimal>  so 0x0313
# means "3.19".  Other vendors put the bytes there but *display* them
# verbatim — Prisual's GUI shows "X8.03.13" for the same 0x0313 bytes,
# which means they treat 0x13 as the literal string "13" rather than
# converting it to decimal.
#
# Each entry maps vendor_id -> a callable taking the 16-bit ROM value
# and returning a human-readable firmware version string.

def _decode_firmware_sony(rom_rev: int) -> str:
    """Sony format: major.<minor-as-decimal>  e.g. 0x0300 -> '3.00'"""
    return f"{(rom_rev >> 8) & 0xFF}.{rom_rev & 0xFF:02d}"


def _decode_firmware_prisual(rom_rev: int) -> str:
    """Prisual format: major.<minor-as-hex>  e.g. 0x0313 -> '3.13'"""
    return f"{(rom_rev >> 8) & 0xFF}.{rom_rev & 0xFF:02X}"


VENDOR_FW_DECODERS = {
    0x0001: _decode_firmware_sony,      # Sony — decimal minor
    0x0056: _decode_firmware_prisual,   # Prisual — hex-as-displayed minor
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


def _nullify(val):
    """
    Normalise a display sentinel to a real JSON null.

    The protocol parsers in section 4 are left untouched and may hand back
    the string "N/A" (or an empty string) to mean "not reported". The JSON
    contract requires null for that case, while clean() turns null back into
    "N/A" for the terminal table. This is the boundary between the two.
    """
    if val is None:
        return None
    if isinstance(val, str) and val.strip() in ("", "N/A", "None"):
        return None
    return val


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

# Protocol-specific patterns for this script, matched BEFORE the base list.
# These cover the VISCA error payload classes decoded by visca_error_meaning()
# plus the VISCA-over-IP transport failures specific to this tool.
PROTOCOL_ERROR_PATTERNS = [
    (r"[Ss]yntax error",              "Syntax error"),
    (r"[Cc]ommand buffer full",       "Buffer full"),
    (r"[Cc]ommand cancelled",         "Cmd cancelled"),
    (r"[Nn]o socket",                 "No socket"),
    (r"[Cc]ommand not executable",    "Not executable"),
    (r"[Mm]essage length error",      "Bad length"),
    (r"RESET handshake failed",       "No VISCA reply"),
    (r"[Ss]equence number",           "Seq sync error"),
    (r"[Bb]ind .* port",              "Port 52381 in use"),
    (r"CAM_VersionInq",               "No version reply"),
    (r"[Uu]nknown camera type",       "Unknown model"),
    (r"[Uu]nexpected reply type",     "Bad envelope"),
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


def status_icon(r: dict) -> str:
    """Return a coloured status icon string for a result dict."""
    s = r.get("status", "error")
    if s == "success":
        return f"{GREEN}✓ OK{RESET}{WHITE}"
    elif s == "auth_error":
        return f"{YELLOW}✗ AUTH ERR{RESET}{WHITE}"
    return f"{RED}✗ ERROR{RESET}{WHITE}"


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
# Debug logging
# ---------------------------------------------------------------------------
# Module-level debug state. Set by main() based on the --debug flag.
DEBUG = False


def dbg(msg: str, color: str = ""):
    """Print a debug message to stderr when --debug is enabled."""
    if not DEBUG:
        return
    prefix = f"  {YELLOW}[debug]{RESET} "
    print(f"{prefix}{color}{msg}{RESET}", file=sys.stderr)


def dbg_hex(label: str, data: bytes, max_bytes: int = 64):
    """Pretty-print a hex dump of bytes for debug output."""
    if not DEBUG:
        return
    if not data:
        dbg(f"{label}: <empty>")
        return
    truncated = data[:max_bytes]
    hex_str   = " ".join(f"{b:02x}" for b in truncated)
    suffix    = f" ... (+{len(data) - max_bytes} more)" if len(data) > max_bytes else ""
    dbg(f"{label} ({len(data)}b): {hex_str}{suffix}")


def dbg_parsed_packet(label: str, parsed: dict):
    """Show parsed Sony envelope fields if applicable."""
    if not DEBUG:
        return
    if "error" in parsed:
        dbg(f"{label}: parse error — {parsed['error']}")
        return
    pt = parsed.get("payload_type")
    pl = parsed.get("payload_length")
    sq = parsed.get("sequence_number")
    pp = parsed.get("payload", b"")
    pt_name = {
        PT_VISCA_INQUIRY:   "VISCA_INQUIRY",
        PT_VISCA_REPLY:     "VISCA_REPLY",
        PT_CONTROL_COMMAND: "CONTROL_CMD",
        PT_CONTROL_REPLY:   "CONTROL_REPLY",
    }.get(pt, f"unknown(0x{pt:04X})")
    dbg(f"{label}: type={pt_name}  len={pl}  seq={sq}  payload={pp.hex()}")


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
    dbg(f"\u2192 {dest[0]}:{dest[1]}")
    dbg_hex("  sent", packet)
    try:
        sock.sendto(packet, dest)
    except OSError as e:
        dbg(f"  sendto failed: {e}", color=RED)
        return None, f"sendto failed: {e}"
    try:
        data, addr = sock.recvfrom(1024)
        dbg(f"\u2190 {addr[0]}:{addr[1]}")
        dbg_hex("  recv", data)
        return data, None
    except socket.timeout:
        dbg("  no reply (timeout)", color=RED)
        return None, "No response (timeout)"
    except OSError as e:
        dbg(f"  recvfrom failed: {e}", color=RED)
        return None, f"recvfrom failed: {e}"


def visca_reset_sequence(sock, dest):
    """Send RESET (0x0200 + 0x01) and wait for the 0x0201 control reply."""
    dbg("RESET handshake \u2014 syncing sequence number")
    packet = build_packet(PT_CONTROL_COMMAND, CTRL_RESET_SEQ, 0)
    reply, err = send_and_receive(sock, packet, dest)
    if reply is None:
        dbg(f"  RESET failed: {err}", color=RED)
        return False, err or "RESET handshake failed"

    parsed = parse_packet(reply)
    dbg_parsed_packet("  RESET reply", parsed)

    if "error" in parsed:
        return False, parsed["error"]

    if parsed["payload_type"] == PT_CONTROL_REPLY:
        dbg("  RESET ok", color=GREEN)
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
    dbg(f"VISCA inquiry seq={seq}: {inquiry.hex()}")
    packet = build_packet(PT_VISCA_INQUIRY, inquiry, seq)
    reply, err = send_and_receive(sock, packet, dest)
    if reply is None:
        return None, err or "No response"

    # Some cameras skip the 8-byte envelope and just send raw VISCA bytes.
    if _is_raw_visca_payload(reply) and len(reply) < 8:
        dbg("  reply looks like RAW VISCA (no Sony envelope)")
        rtype = classify_visca_reply(reply)
        dbg(f"  raw VISCA classified as: {rtype}")
        if rtype == "completion":
            return reply, None
        if rtype == "error":
            return None, visca_error_meaning(reply)

    parsed = parse_packet(reply)
    dbg_parsed_packet("  parsed envelope", parsed)
    if "error" in parsed:
        if _is_raw_visca_payload(reply):
            dbg("  envelope parse failed but raw VISCA detected \u2014 using raw")
            return reply, None
        return None, parsed["error"]

    if (parsed["payload_type"] == PT_CONTROL_REPLY
            and parsed["payload"] == bytes([0x0F, 0x01])):
        dbg("  camera reports sequence-number error", color=RED)
        return None, "Sequence number out of sync"

    if parsed["payload_type"] != PT_VISCA_REPLY:
        if _is_raw_visca_payload(reply):
            dbg("  unexpected envelope type but raw VISCA pattern detected")
            return reply, None
        return None, f"Unexpected reply type 0x{parsed['payload_type']:04X}"

    visca_payload = parsed["payload"]
    rtype = classify_visca_reply(visca_payload)
    dbg(f"  VISCA payload classified as: {rtype}")

    if rtype == "completion":
        return visca_payload, None
    if rtype == "error":
        return None, visca_error_meaning(visca_payload)
    if rtype == "ack":
        dbg("  ACK received, waiting for completion")
        try:
            data, _ = sock.recvfrom(1024)
            dbg_hex("  recv (post-ACK)", data)
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

    Some non-Sony cameras return shorter replies; we cope with anything
    from a 2-byte stub up to the full Sony 10-byte format.
    """
    result = {}
    if payload and payload[-1] == 0xFF:
        payload = payload[:-1]

    if len(payload) < 4:
        result["parse_error"] = f"Response too short ({len(payload)} bytes)"
        result["raw_hex"]     = payload.hex()
        return result

    # Bytes 0..1 are 90 50 (address + completion). Useful data starts at 2.
    vendor_id  = (payload[2] << 8) | payload[3] if len(payload) >= 4 else None
    model_code = (payload[4] << 8) | payload[5] if len(payload) >= 6 else None
    rom_rev    = (payload[6] << 8) | payload[7] if len(payload) >= 8 else None
    max_sock   = (payload[8] << 8) | payload[9] if len(payload) >= 10 else None

    if vendor_id is not None:
        result["vendor_id"]   = f"0x{vendor_id:04X}"
        result["vendor_name"] = VENDOR_NAMES.get(
            vendor_id, manufacturer if manufacturer != "Unknown" else f"Unknown (vendor 0x{vendor_id:04X})"
        )

    if model_code is not None:
        result["model_code"] = f"0x{model_code:04X}"
        # Look up by (vendor, model) so vendors that reuse model numbers
        # don't get mislabeled as each other's models.
        if vendor_id is not None and (vendor_id, model_code) in MODEL_CODES:
            result["model_name"] = MODEL_CODES[(vendor_id, model_code)]
        else:
            result["model_name"] = f"Unknown (0x{model_code:04X})"

    if rom_rev is not None:
        result["rom_revision"]         = f"0x{rom_rev:04X}"
        result["rom_revision_decimal"] = rom_rev
        # Decode firmware string using vendor-specific rules.
        # Falls back to Sony-style (decimal minor) for unknown vendors.
        decoder = VENDOR_FW_DECODERS.get(vendor_id, _decode_firmware_sony)
        result["firmware_version"]     = decoder(rom_rev)
        result["firmware_decoder"]     = decoder.__name__
    if max_sock is not None:
        result["max_sockets"]          = max_sock

    # Stub VISCA cameras (e.g. vendor 0x0052) only return their vendor ID
    # with no model or ROM revision. Don't fabricate a misleading firmware
    # string from the vendor bytes — surface the truth as N/A.
    if rom_rev is None and vendor_id in STUB_VISCA_VENDORS:
        result["firmware_version"] = "N/A"
        result["firmware_note"]    = "Camera does not report firmware via VISCA"

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
# HTTP Fingerprinting — used to identify cameras whose VISCA reply is a stub
# ---------------------------------------------------------------------------
# Brand signatures we look for in HTTP headers, HTML, and CGI responses.
# Order matters — more specific patterns first.
HTTP_FINGERPRINT_PATTERNS = [
    # (regex, vendor label) — case-insensitive search
    (r"prisual",                                 "Prisual"),
    (r"tem-?20n[\s_-]*pro",                      "Prisual TEM-20N PRO"),
    (r"tem-?20n",                                "Prisual TEM-20N"),
    (r"tenveo",                                  "Tenveo"),
    (r"ptzoptics",                               "PTZOptics"),
    (r"sony[\s_-]*srg",                          "Sony SRG"),
    (r"\bbrc-x\d+",                              "Sony BRC-X"),
    (r"avonic",                                  "Avonic"),
    (r"\baver\b|avermedia",                      "AVer"),
    (r"bolin",                                   "Bolin"),
    (r"birddog",                                 "BirdDog"),
    (r"marshall[\s_-]*electronics",              "Marshall"),
    (r"lumens",                                  "Lumens"),
    (r"vaddio",                                  "Vaddio"),
    (r"panasonic",                               "Panasonic"),
    (r"canon",                                   "Canon"),
    (r"angekis",                                 "Angekis"),
]

# Common HTTP probes — tried in order, first hit wins
HTTP_PROBE_PATHS = [
    "/",
    "/index.html",
    "/login.html",
    "/cgi-bin/param.cgi?get_device_conf",
    "/cgi-bin/param.cgi?get_dev_info",
    "/cgi-bin/ptzctrl.cgi?action=getinfo",
    "/api/system/info",
    "/system/system.html",
    "/onvif/device_service",
]


def _parse_param_cgi(body: str) -> dict:
    """
    Parse a key=value-style response body like:
        devname = "HD Camera"
        devtype = "V60"
        versioninfo = "SOC v6.3.37 - ARM v6.4.79T"
        device_model = " F2.V10 "
        firmware_version = "1.2.3"

    Returns a dict of normalized lowercase keys -> stripped values.
    Returns empty dict if no key=value pairs found.
    """
    fields = {}
    for line in body.splitlines():
        # Tolerant pattern: key = "value"  or  key = value  or  key=value
        m = re.match(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"?([^"\r\n]*?)"?\s*$', line)
        if m:
            key   = m.group(1).strip().lower()
            value = m.group(2).strip()
            if key and value:
                fields[key] = value
    return fields


def _summarize_cgi_fields(fields: dict) -> dict:
    """
    Pick the most useful identification fields out of a parsed param.cgi
    response. Returns a dict with normalized keys we care about.
    """
    out = {}
    if not fields:
        return out

    # Friendly model name: prefer device_model, fall back to devtype + devname
    devtype  = fields.get("devtype")    or fields.get("dev_type")
    devname  = fields.get("devname")    or fields.get("dev_name")
    devmodel = fields.get("device_model") or fields.get("model")
    if devmodel:
        model_label = devmodel
        if devtype and devtype not in devmodel:
            model_label = f"{devtype} ({devmodel})"
    elif devtype and devname:
        model_label = f"{devtype} ({devname})"
    elif devtype:
        model_label = devtype
    elif devname:
        model_label = devname
    else:
        model_label = None

    if model_label:
        out["model_label"] = model_label
    if devtype:
        out["devtype"]      = devtype
    if devname:
        out["devname"]      = devname
    if devmodel:
        out["device_model"] = devmodel

    # Firmware: prefer explicit firmware fields, else fall back to versioninfo
    fw = (fields.get("firmware_version") or fields.get("firmware")
          or fields.get("fw_version")    or fields.get("sw_version")
          or fields.get("software_version"))
    if fw:
        out["firmware_version"] = fw
    elif fields.get("versioninfo"):
        out["firmware_version"] = fields["versioninfo"]

    return out


def _vendor_from_cgi_signature(fields: dict) -> str:
    """
    Identify the brand from CGI field signatures when no brand string was
    found in any HTTP response. The Prisual family of cameras (and their
    OEM clones — Tenveo, some PTZOptics) share a distinctive `param.cgi`
    response shape with `devname`/`devtype`/`versioninfo`/`device_model`
    fields. We use that as a Prisual-family signature.

    Returns a vendor label, or empty string when no signature matches.
    """
    if not fields:
        return ""
    keys = set(fields.keys())

    # Prisual / OEM family — distinctive set of field names
    prisual_signals = {"devname", "devtype", "versioninfo", "device_model"}
    if len(keys & prisual_signals) >= 3:
        # Optionally tighten the label using devtype if it looks like a model
        devtype = fields.get("devtype", "").strip()
        if devtype:
            return f"Prisual (devtype {devtype})"
        return "Prisual (CGI signature)"

    return ""


def http_fingerprint(host: str, timeout: int = 3,
                     verbose: bool = False) -> dict:
    """
    Try to identify the camera by HTTP fingerprinting.

    Returns dict with keys:
      vendor       : best-guess vendor name, or None
      matched_pat  : the regex pattern that matched
      source_url   : URL where the match was found
      server       : value of the HTTP Server header (raw)
      title        : <title> from HTML body, if present
      cgi_fields   : raw key=value dict parsed from param.cgi-style endpoints
      cgi_summary  : normalized {model_label, firmware_version, devtype, ...}
      probes_tried : list of URLs probed
      probe_results: list of {url, status, server, title, snippet, cgi_fields}

    Never raises — all errors get captured as probe_results entries.
    """
    result = {
        "vendor":        None,
        "matched_pat":   None,
        "source_url":    None,
        "server":        None,
        "title":         None,
        "cgi_fields":    {},
        "cgi_summary":   {},
        "probes_tried":  [],
        "probe_results": [],
    }

    title_re = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

    for path in HTTP_PROBE_PATHS:
        url = f"http://{host}{path}"
        result["probes_tried"].append(url)

        if verbose:
            dbg(f"HTTP probe \u2192 {url}")

        probe = {"url": url, "status": None, "server": None,
                 "title": None, "snippet": None, "cgi_fields": None,
                 "error": None}

        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "visca_script-fingerprint/1.0")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                probe["status"] = resp.status
                probe["server"] = resp.headers.get("Server")
                body_bytes = resp.read(32 * 1024)
                body = body_bytes.decode("utf-8", errors="replace")

                # Capture <title> if present
                m = title_re.search(body)
                if m:
                    probe["title"] = m.group(1).strip()[:120]

                # Snippet: first ~300 visible chars after stripping tags
                visible = re.sub(r"<[^>]+>", " ", body)
                visible = re.sub(r"\s+", " ", visible).strip()
                probe["snippet"] = visible[:300]

                # If this looks like a key=value param.cgi response, parse it.
                # We accumulate fields across multiple CGI endpoints because
                # different endpoints expose different keys.
                cgi_fields = _parse_param_cgi(body)
                if cgi_fields:
                    probe["cgi_fields"] = cgi_fields
                    # Merge into the top-level result, but don't clobber values
                    # captured from an earlier probe
                    for k, v in cgi_fields.items():
                        result["cgi_fields"].setdefault(k, v)
                    summary = _summarize_cgi_fields(result["cgi_fields"])
                    if summary:
                        result["cgi_summary"] = summary
                        if verbose:
                            for k, v in summary.items():
                                dbg(f"  CGI summary: {k} = {v!r}", color=GREEN)

                # Match against fingerprint patterns — search headers, title,
                # CGI fields, and visible body
                cgi_text = " ".join(f"{k}={v}" for k, v in cgi_fields.items()) \
                    if cgi_fields else ""
                haystack = " ".join(filter(None, [
                    probe["server"] or "",
                    probe["title"]  or "",
                    cgi_text,
                    visible[:2000],
                ]))

                for pat, label in HTTP_FINGERPRINT_PATTERNS:
                    if re.search(pat, haystack, re.I):
                        result["vendor"]      = label
                        result["matched_pat"] = pat
                        result["source_url"]  = url
                        result["server"]      = probe["server"]
                        result["title"]       = probe["title"]
                        result["probe_results"].append(probe)
                        if verbose:
                            dbg(f"  match: {label}  (pattern: {pat})", color=GREEN)
                        return result

        except urllib.error.HTTPError as e:
            probe["status"] = e.code
            probe["error"]  = f"HTTP {e.code}"
            # 401/403 still expose the Server header, which might fingerprint
            try:
                probe["server"] = e.headers.get("Server") if e.headers else None
            except Exception:
                pass
            if probe["server"]:
                for pat, label in HTTP_FINGERPRINT_PATTERNS:
                    if re.search(pat, probe["server"], re.I):
                        result["vendor"]      = label
                        result["matched_pat"] = pat
                        result["source_url"]  = url
                        result["server"]      = probe["server"]
                        result["probe_results"].append(probe)
                        if verbose:
                            dbg(f"  match (auth-protected): {label}", color=GREEN)
                        return result
        except urllib.error.URLError as e:
            probe["error"] = f"URL error: {e.reason}"
        except socket.timeout:
            probe["error"] = "Timed out"
        except Exception as e:
            probe["error"] = f"{type(e).__name__}: {e}"

        result["probe_results"].append(probe)

        if verbose:
            if probe["error"]:
                dbg(f"  {probe['error']}")
            else:
                dbg(f"  HTTP {probe['status']}  server={probe['server']!r}  "
                    f"title={probe['title']!r}")

    # Last-resort: if no brand string matched anywhere, see if the CGI
    # field shape itself fingerprints a known OEM family.
    if not result["vendor"] and result.get("cgi_fields"):
        sig_vendor = _vendor_from_cgi_signature(result["cgi_fields"])
        if sig_vendor:
            result["vendor"]      = sig_vendor
            result["matched_pat"] = "<cgi-field-signature>"
            # Best-effort source URL: the probe whose fields filled the summary
            for p in result["probe_results"]:
                if p.get("cgi_fields"):
                    result["source_url"] = p["url"]
                    break
            if verbose:
                dbg(f"  CGI field signature \u2192 {sig_vendor}", color=GREEN)

    return result



def query_camera(host: str, port: int, camera_name: str, camera_type: str,
                 timeout: int = DEFAULT_TIMEOUT,
                 fingerprint_stubs: bool = True) -> dict:
    """Query a single camera. Returns a result dict shaped like the Bravia tool.

    If `fingerprint_stubs` is True and the camera returns a stub VISCA reply
    (no model/firmware) the script will probe HTTP to try to identify the
    camera by web UI signatures.
    """
    result = {
        # --- Common fields (spec 2.3) -----------------------------------
        # `host` is written through exactly as supplied by the CSV loader.
        "host":                 host,
        "port":                 port,
        "query_timestamp":      datetime.now(timezone.utc).isoformat(),
        "status":               "error",
        "error":                None,
        "firmware_version":     None,
        "model":                None,
        "serial":               None,   # VISCA reports no serial — always null
        "mac":                  None,   # VISCA reports no MAC — always null
        "manufacturer":         None,

        # --- Device-specific fields (spec 2.4) --------------------------
        # VISCA has no temperature or build-date inquiry, so both stay null.
        # Both temperature scales are emitted so the suffix always matches
        # the value it holds and the dashboard's Celsius gauge keeps working.
        "temperature_c":        None,
        "temperature_f":        None,
        "build_date":           None,

        # --- Additional VISCA diagnostics (not read by the dashboard) ----
        "camera_name":          camera_name,
        "camera_type":          camera_type,
        "model_code":           None,
        "rom_revision":         None,
        "vendor_id":            None,
        "max_sockets":          None,
        "software_version":     None,
        "software_version_hex": None,
        "fingerprint":          None,    # populated if HTTP probe runs
    }

    profile = resolve_profile(camera_type)
    if not profile:
        result["error"] = f"Unknown camera type: {camera_type}"
        return result

    if DEBUG:
        dbg("=" * 60)
        dbg(f"Camera: {camera_name or host}  ({host}:{port})")
        dbg(f"Type hint: {camera_type or '(none)'}  \u2192  profile: {profile['display_name']}")
        dbg("=" * 60)

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
            dbg(f"Version parse error: {vi['parse_error']}", color=RED)
            dbg_hex("  raw payload", version_payload)
            result["error"] = vi["parse_error"]
            return result

        if DEBUG:
            dbg("Parsed version response:")
            for k in ("vendor_id", "vendor_name", "model_code", "model_name",
                     "rom_revision", "firmware_version", "max_sockets", "raw_hex"):
                if k in vi:
                    dbg(f"  {k} = {vi[k]}")

        # The protocol parsers are left untouched (spec section 4) and may
        # return the string "N/A" as a sentinel. Normalise it to null here so
        # the JSON contract holds — clean() still renders "N/A" in the table.
        result["model"]            = _nullify(vi.get("model_name"))
        result["model_code"]       = _nullify(vi.get("model_code"))
        result["firmware_version"] = _nullify(vi.get("firmware_version"))
        result["rom_revision"]     = _nullify(vi.get("rom_revision"))
        result["vendor_id"]        = _nullify(vi.get("vendor_id"))
        result["manufacturer"]     = _nullify(vi.get("vendor_name")) \
            or _nullify(profile["manufacturer"])
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
                dbg(f"Auto-detect: model 0x{model_code_int:04X} \u2192 "
                    f"{detected['display_name']}", color=GREEN)
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

    # ----- 4. HTTP fingerprint fallback for stub VISCA cameras -----
    # If the VISCA reply gave us a vendor we can't identify (or no useful
    # data at all), poke the camera's web UI for brand signatures.
    def _unidentified(val) -> bool:
        """True when a field is null/blank or an 'Unknown (0x....)' placeholder."""
        return val is None or (isinstance(val, str)
                               and (val.strip() == ""
                                    or val.startswith("Unknown")))

    needs_fingerprint = (
        fingerprint_stubs
        and result["status"] == "success"
        and _unidentified(result["model"])
    )
    if needs_fingerprint:
        dbg(f"Stub or unknown VISCA reply \u2014 trying HTTP fingerprint",
            color=YELLOW)
        fp = http_fingerprint(host, timeout=timeout, verbose=DEBUG)
        result["fingerprint"] = fp

        # 4a. Brand match found — use vendor name as manufacturer/model
        if fp.get("vendor"):
            if _unidentified(result["manufacturer"]):
                result["manufacturer"] = fp["vendor"].split()[0]
            if _unidentified(result["model"]):
                result["model"] = fp["vendor"]
            dbg(f"Fingerprint identified: {fp['vendor']}  "
                f"(via {fp['source_url']})", color=GREEN)

        # 4b. No brand match, but the param.cgi-style endpoint gave us
        #     model + firmware fields — surface those even though we don't
        #     know the manufacturer
        cgi_summary = fp.get("cgi_summary") or {}
        if cgi_summary:
            if _unidentified(result["model"]) and cgi_summary.get("model_label"):
                result["model"] = cgi_summary["model_label"]
            if (result["firmware_version"] is None
                    and cgi_summary.get("firmware_version")):
                result["firmware_version"] = cgi_summary["firmware_version"]
                # Clear the misleading "doesn't report firmware" note now
                # that we have a real version
                result.pop("firmware_note", None)
            dbg(f"CGI fields supplied: model={cgi_summary.get('model_label')!r}  "
                f"fw={cgi_summary.get('firmware_version')!r}", color=GREEN)

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
        # firmware_version is null when the camera does not report one, so
        # compare against the cleaned display form rather than the raw value.
        display_results = [
            r for r in results
            if clean(r.get("firmware_version")) != firmware_filter
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
            truncate_error(r.get("error")),
        ]
        table_data.append(row)

    headers = ["Status", "Host", "Manufacturer", "Model",
               "Firmware", "Error"]

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
        f"{GREEN}✓{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}✗{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}✗{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )

    # Device-specific metrics line — firmware version breakdown across the
    # fleet. Cameras that report no firmware (null) are excluded from the
    # breakdown but still counted in the Reported denominator.
    fw_counts = {}
    for r in display_results:
        if r["status"] == "success" and r.get("firmware_version"):
            fw = str(r["firmware_version"])
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
    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {output_file}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers){RESET}")
    print()


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
    parser.add_argument("--debug",         action="store_true", default=False,
        help="Print raw packet exchange (sent/received bytes, parsed envelope, "
             "and protocol decisions) to stderr. Useful for unfamiliar cameras.")
    parser.add_argument("--no-fingerprint", action="store_true", default=False,
        help="Disable the HTTP fingerprint fallback that runs on stub/unknown "
             "VISCA replies. Faster, but unidentified cameras stay 'Unknown'.")
    parser.add_argument("--fingerprint-only", default=None, metavar="HOST",
        help="Only run the HTTP fingerprint probe against HOST and exit. "
             "Useful to investigate a single camera's identity without VISCA.")

    args = parser.parse_args()

    # Activate debug logging based on the flag
    global DEBUG
    DEBUG = args.debug

    term_width = get_terminal_width()
    start_time = time.monotonic()

    # -----------------------------------------------------------------------
    # --fingerprint-only mode: probe HTTP only, no VISCA, then exit
    # -----------------------------------------------------------------------
    if args.fingerprint_only:
        host = args.fingerprint_only
        print(f"{WHITE}")
        print(f"  {BOLD}HTTP Fingerprint Probe{RESET}{WHITE}")
        print(f"  Host:    {host}")
        print(f"  Timeout: {args.timeout}s")
        print(f"{RESET}")

        # Force debug on for this mode so the user sees probe details
        DEBUG = True
        fp = http_fingerprint(host, timeout=args.timeout, verbose=True)

        print(f"\n{WHITE}")
        if fp.get("vendor"):
            print(f"  {BOLD}{GREEN}\u2713 Identified:{RESET}{WHITE} {fp['vendor']}")
            print(f"  {BOLD}Source:{RESET}{WHITE}     {fp['source_url']}")
            print(f"  {BOLD}Server:{RESET}{WHITE}     {fp.get('server') or '(no header)'}")
            print(f"  {BOLD}Title:{RESET}{WHITE}      {fp.get('title')  or '(none)'}")
            print(f"  {BOLD}Pattern:{RESET}{WHITE}    {fp.get('matched_pat')}")
        else:
            print(f"  {RED}{BOLD}\u2717 Could not identify brand by HTTP signatures.{RESET}{WHITE}")
            print(f"  Probes tried: {len(fp['probes_tried'])}")

        # Always show CGI fields if any were captured — they often contain
        # the only useful identification info even when no brand matched
        cgi_summary = fp.get("cgi_summary") or {}
        if cgi_summary:
            print()
            print(f"  {BOLD}{GREEN}\u2713 Camera info from param.cgi:{RESET}{WHITE}")
            for k, v in cgi_summary.items():
                print(f"    {BOLD}{k:18s}{RESET}{WHITE} {v}")

        cgi_fields = fp.get("cgi_fields") or {}
        if cgi_fields and not cgi_summary:
            print()
            print(f"  {BOLD}Raw CGI key=value fields:{RESET}{WHITE}")
            for k, v in cgi_fields.items():
                print(f"    {k:18s} {v!r}")

        if not fp.get("vendor"):
            print()
            print(f"  {BOLD}Probe results:{RESET}{WHITE}")
            for p in fp.get("probe_results", []):
                status = p.get("status") or "ERR"
                err    = f"  err={p['error']}" if p.get("error") else ""
                srv    = f"  server={p['server']!r}" if p.get("server") else ""
                ttl    = f"  title={p['title']!r}"   if p.get("title")  else ""
                print(f"    [{status}]  {p['url']}{srv}{ttl}{err}")
                if p.get("cgi_fields"):
                    for k, v in p["cgi_fields"].items():
                        print(f"          \u2517 {k} = {v!r}")
                elif p.get("snippet"):
                    snippet = p["snippet"][:200]
                    print(f"          \u2517 {snippet}")
        print(f"{RESET}")
        return

    # -----------------------------------------------------------------------
    # Header block
    # -----------------------------------------------------------------------
    input_display = args.host if args.host else args.input
    print(f"{WHITE}")
    print(f"  {BOLD}Sony VISCA-over-IP Firmware Query Tool{RESET}{WHITE}")
    print(f"  Queries VISCA-over-IP cameras for firmware and model information")
    print(f"  Input:   {input_display}")
    print(f"  Output:  {args.output}")
    print(f"  Workers: {args.workers} (sequential — UDP {LOCAL_VISCA_PORT} bind)")
    print(f"  Timeout: {args.timeout}s")
    print(f"  Mode:    Bind UDP {LOCAL_VISCA_PORT} \u2192 RESET \u2192 inquire")
    if args.firmware:
        print(f"  Filter:  Showing cameras not on firmware {args.firmware}")
    if args.no_fingerprint:
        print(f"  HTTP fp: {RED}OFF{RESET}{WHITE} (skipping HTTP probe on unknown cameras)")
    else:
        print(f"  HTTP fp: ON \u2014 unknown VISCA replies trigger an HTTP probe")
    if args.debug:
        print(f"  {YELLOW}{BOLD}Debug:   ON{RESET}{WHITE} \u2014 raw packet trace on stderr")
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

    # Disable the tqdm progress bar in debug mode — its constant redraw
    # interleaves messily with the [debug] trace lines on stderr.
    with tqdm(total=len(cameras), bar_format=bar_fmt, ncols=term_width,
              dynamic_ncols=True, file=sys.stderr, leave=True,
              disable=args.debug) as pbar:
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
                fingerprint_stubs=not args.no_fingerprint,
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
