#!/usr/bin/env python3
"""
PJLink Projector Firmware & Lamp Hours Query (Class 1 + Class 2)

Dependencies:
    pip3 install tabulate tqdm paramiko

Queries projectors via PJLink protocol for:
    - Firmware version (INFO for Class 1, SVER for Class 2)
    - Lamp hours (LAMP for all classes)
    - Manufacturer, model, and other device info

Defaults:
    Input:  secrets/pjlink_firmware.csv
    Output: projector_version_check/files/results_<YYYYMMDD>_<HHMMSS>.json
"""

import socket
import hashlib
import json
import csv
import os
import sys
import re
import time
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import standard_cli as cli  # noqa: E402  (standard flags, --debug/--raw helpers)

from tabulate import tabulate
from tqdm import tqdm

try:
    import paramiko  # noqa: F401
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_PORT = 4352
DEFAULT_CSV = "secrets/pjlink_firmware.csv"              # relative to this script's folder
DEFAULT_OUTPUT_DIR = "projector_version_check/files"     # results_<YYYYMMDD>_<HHMMSS>.json
DEFAULT_TIMEOUT = 10
DEFAULT_WORKERS = 5
ARRAY_KEY = "projectors"

# --raw: every command the old --diagnostic sent, plus the extra --all queries
RAW_COMMANDS = [
    ("%1", "CLSS"), ("%1", "POWR"), ("%1", "INF1"), ("%1", "INF2"),
    ("%1", "INFO"), ("%1", "NAME"), ("%1", "LAMP"), ("%1", "ERST"),
    ("%2", "SVER"), ("%2", "SNUM"),
]
RAW_COMMANDS_ALL = [
    ("%1", "INPT"), ("%1", "INST"), ("%1", "AVMT"),
    ("%2", "FILT"), ("%2", "IRES"), ("%2", "RRES"),
]


# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------

CYAN = "\033[96m"    # Progress bar fill — reserved, nothing else
GREEN = "\033[92m"   # Success states
RED = "\033[91m"     # Failure / error states
YELLOW = "\033[93m"  # Auth-error states
WHITE = "\033[97m"   # All body text, table content, labels
BOLD = "\033[1m"     # Section headers, label emphasis
RESET = "\033[0m"    # Always close every colour block


# ---------------------------------------------------------------------------
# Debug trace (--debug)
# The old pjlink logger is gone: --debug now goes through cli.debug, which
# prefixes every line with the host and writes to stderr.
# ---------------------------------------------------------------------------

_DIGEST_RE = re.compile(rb"^[0-9a-f]{32}(?=%)")


def _mask_digest(data: bytes) -> bytes:
    """Packet as it may be traced: the MD5 auth digest prefix is replaced, never logged."""
    return _DIGEST_RE.sub(b"<md5 digest>", bytes(data))


# ---------------------------------------------------------------------------
# Shared helpers — byte-identical across all scripts (spec 3.5)
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


def status_icon(r: dict) -> str:
    """Return a coloured status icon string for a result dict."""
    s = r.get("status", "error")
    if s == "success":
        return f"{GREEN}✓ OK{RESET}{WHITE}"
    elif s == "auth_error":
        return f"{YELLOW}✗ AUTH ERR{RESET}{WHITE}"
    return f"{RED}✗ ERROR{RESET}{WHITE}"


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
# PJLink protocol errors. PJLINK ERRA is authentication failure; ERR1-ERR4 are
# undefined command, out of parameter, unavailable time, and projector failure.
# The specific codes precede the generic ERRA entry so it cannot swallow them.
PROTOCOL_ERROR_PATTERNS = [
    (r"PJLINK ERRA", "Auth failed"),
    (r"ERR1",        "Undefined cmd"),
    (r"ERR2",        "Out of parameter"),
    (r"ERR3",        "Unavailable time"),
    (r"ERR4",        "Device failure"),
    (r"ERRA",        "Auth error"),
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


# ---------------------------------------------------------------------------
# PJLink Client  —  PROTECTED IN FULL (spec 4). DO NOT MODIFY.
# Class 1 / Class 2 negotiation, auth challenge/response, command framing.
# Field naming for the JSON contract is handled downstream in query_projector().
# The only additions are --debug trace calls (cli.debug.*), which change nothing
# when --debug is off; the auth digest and password are never traced.
# ---------------------------------------------------------------------------

class PJLinkError(Exception):
    pass


class PJLinkAuthError(PJLinkError):
    pass


class PJLinkClient:
    DEFAULT_PORT = DEFAULT_PORT
    BUFFER_SIZE = 4096
    DEFAULT_TIMEOUT = 10
    MAX_PASSWORD_LENGTH = 32
    COMMAND_DELAY = 0.15

    POWER_STATES = {
        "0": "Standby",
        "1": "Lamp On / Power On",
        "2": "Cooling",
        "3": "Warm-up",
    }

    ERROR_CODES = {
        "ERR1": "Undefined command",
        "ERR2": "Out of parameter",
        "ERR3": "Unavailable time",
        "ERR4": "Projector/Display failure",
    }

    ERST_POSITIONS = ["fan", "lamp", "temperature", "cover_open", "filter", "other"]
    ERST_VALUES = {"0": "OK", "1": "Warning", "2": "Error"}

    def __init__(self, host, port=DEFAULT_PORT, password=None, timeout=DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.socket = None
        self.security_enabled = False
        self.random_number = None
        self.detected_class = None
        self.auth_sent = False

        if self.password and len(self.password.encode("utf-8")) > self.MAX_PASSWORD_LENGTH:
            raise PJLinkError(f"Password exceeds {self.MAX_PASSWORD_LENGTH} bytes")

    def connect(self):
        try:
            cli.debug.log(self.host, f"connecting to {self.host}:{self.port} (timeout {self.timeout}s)")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.host, self.port))
            cli.debug.log(self.host, "connected; waiting for PJLINK greeting")
            raw = self._receive_raw_line()
            greeting = raw.decode("utf-8", errors="replace")
            self._parse_greeting(greeting)
            cli.debug.log(self.host, "greeting ok: authentication "
                          + ("ON (MD5 digest will be sent)" if self.security_enabled else "off"))
        except socket.timeout:
            raise PJLinkError(f"Connection timed out: {self.host}:{self.port}")
        except ConnectionRefusedError:
            raise PJLinkError(f"Connection refused: {self.host}:{self.port}")
        except OSError as e:
            raise PJLinkError(f"Network error: {self.host}:{self.port}: {e}")

    def _parse_greeting(self, greeting):
        line = greeting.strip()
        if not line.startswith("PJLINK"):
            raise PJLinkError(f"Not a PJLink device: {repr(line)}")
        parts = line.split(None, 2)
        if len(parts) < 2:
            raise PJLinkError(f"Malformed greeting: {repr(line)}")
        if parts[1] == "0":
            self.security_enabled = False
        elif parts[1] == "1":
            self.security_enabled = True
            if len(parts) < 3:
                raise PJLinkError(f"Auth greeting missing random: {repr(line)}")
            self.random_number = parts[2]
            if not self.password:
                raise PJLinkError("Authentication required but no password provided.")
        elif parts[1] == "ERRA":
            raise PJLinkAuthError("ERRA in greeting")
        else:
            raise PJLinkError(f"Unknown greeting: {repr(line)}")

    def disconnect(self):
        if self.socket:
            try:
                self.socket.close()
            except OSError as e:
                cli.debug.log(self.host, f"close failed (ignored): {e}")
            finally:
                self.socket = None

    def _receive_raw_line(self) -> bytes:
        if not self.socket:
            raise PJLinkError("Not connected.")
        data = b""
        try:
            while True:
                byte = self.socket.recv(1)
                if not byte:
                    break
                data += byte
                if byte == b"\r":
                    break
                if byte == b"\n" and len(data) >= 2 and data[-2:] == b"\r\n":
                    break
                if len(data) > self.BUFFER_SIZE:
                    break
        except socket.timeout:
            if not data:
                cli.debug.log(self.host, f"recv: nothing within {self.timeout}s")
                raise PJLinkError(f"No response from {self.host} (timeout)")
            cli.debug.log(self.host, f"recv: timed out after {len(data)} bytes; using the partial line")
        if data:
            cli.debug.received(self.host, data)
        else:
            cli.debug.log(self.host, "recv: nothing (connection closed by the device)")
        return data

    def _drain_socket(self):
        if not self.socket:
            return
        orig = self.socket.gettimeout()
        try:
            self.socket.settimeout(0.3)
            while True:
                chunk = self.socket.recv(self.BUFFER_SIZE)
                if not chunk:
                    break
                cli.debug.log(self.host, f"drained stale data: {cli.show(chunk)}")
        except (socket.timeout, OSError) as e:
            if not isinstance(e, socket.timeout):  # a timeout just means nothing left to drain
                cli.debug.log(self.host, f"drain failed (ignored): {e}")
        finally:
            self.socket.settimeout(orig)

    def _compute_digest(self) -> str:
        # Never trace the nonce + password input or the digest itself (see _mask_digest).
        if not self.security_enabled or not self.random_number:
            return ""
        digest = hashlib.md5(
            f"{self.random_number}{self.password}".encode("utf-8")
        ).hexdigest()
        return digest

    def _send_raw(self, data: bytes):
        if not self.socket:
            raise PJLinkError("Not connected.")
        cli.debug.sent(self.host, _mask_digest(data))
        self.socket.sendall(data)

    def _should_prepend_digest(self) -> bool:
        if not self.security_enabled:
            return False
        if self.detected_class is None or self.detected_class == "1":
            return True
        return not self.auth_sent

    def _build_packet(self, header, cmd, param, force_digest=None) -> bytes:
        cmd_str = f"{header}{cmd} {param}\r"
        if force_digest is True:
            d = self._compute_digest()
            s = f"{d}{cmd_str}" if d else cmd_str
        elif force_digest is False:
            s = cmd_str
        else:
            if self._should_prepend_digest():
                d = self._compute_digest()
                s = f"{d}{cmd_str}" if d else cmd_str
            else:
                s = cmd_str
        return s.encode("utf-8")

    def _send_and_receive(self, header, cmd, param="?", force_digest=None) -> str:
        pkt = self._build_packet(header, cmd, param, force_digest)
        self._send_raw(pkt)
        if self.security_enabled and (
            force_digest is True
            or (force_digest is None and self._should_prepend_digest())
        ):
            self.auth_sent = True
        time.sleep(self.COMMAND_DELAY)
        raw = self._receive_raw_line()
        return raw.decode("utf-8", errors="replace").strip("\r\n \t")

    def _send_command(self, cmd, param="?", class_prefix=None) -> str:
        if not self.socket:
            raise PJLinkError("Not connected.")
        header = class_prefix or "%1"
        try:
            resp = self._send_and_receive(header, cmd, param)
            if resp:
                if "PJLINK" in resp.upper() and "ERRA" in resp.upper():
                    raise PJLinkAuthError("PJLINK ERRA")
                return self._parse_response(resp, cmd)
            cli.debug.log(self.host, f"{header}{cmd}: empty reply; trying retry variants")
        except (socket.timeout, OSError) as e:
            cli.debug.log(self.host, f"{header}{cmd}: {e}; trying retry variants")
        return self._retry_command(cmd, param, header)

    def _retry_command(self, cmd, param, orig_hdr) -> str:
        alt = "%2" if orig_hdr == "%1" else "%1"
        for name, hdr, dig in [
            ("drain", orig_hdr, None), ("force", orig_hdr, True),
            ("nodig", orig_hdr, False), ("alt", alt, None),
            ("alt+dig", alt, True), ("alt-dig", alt, False),
        ]:
            try:
                self._drain_socket()
                time.sleep(0.1)
                resp = self._send_and_receive(hdr, cmd, param, dig)
                if resp and not ("PJLINK" in resp.upper() and "ERRA" in resp.upper()):
                    return self._parse_response(resp, cmd)
                cli.debug.log(self.host, f"retry '{name}' {hdr}{cmd}: "
                              + ("PJLINK ERRA" if resp else "empty reply"))
            except (PJLinkError, socket.timeout, OSError) as e:
                cli.debug.log(self.host, f"retry '{name}' {hdr}{cmd} failed: {e}")
                continue
        raise PJLinkError(f"No response for {cmd} after retries.")

    def _parse_response(self, raw, expected_cmd) -> str:
        line = raw.strip("\r\n \t")
        if not line:
            raise PJLinkError(f"Empty response for {expected_cmd}")
        if "PJLINK" in line.upper() and "ERRA" in line.upper():
            raise PJLinkAuthError("PJLINK ERRA")
        for c in ("1", "2"):
            pfx = f"%{c}{expected_cmd}="
            if pfx in line:
                return self._check_error(line[line.index(pfx) + len(pfx):].strip(), expected_cmd)
        lu = line.upper()
        for c in ("1", "2"):
            pu = f"%{c}{expected_cmd.upper()}="
            if pu in lu:
                idx = lu.index(pu)
                return self._check_error(line[idx + len(pu):].strip(), expected_cmd)
        m = re.search(r"%([12])([A-Za-z0-9]{4})=(.*)", line)
        if m:
            return self._check_error(m.group(3).strip(), expected_cmd)
        if "=" in line:
            _, _, v = line.partition("=")
            if v.strip():
                return self._check_error(v.strip(), expected_cmd)
        raise PJLinkError(f"Cannot parse {expected_cmd}: {repr(raw)}")

    def _check_error(self, value, cmd) -> str:
        u = value.strip().upper()
        if u in self.ERROR_CODES:
            return f"ERROR: {self.ERROR_CODES[u]} ({u})"
        return value

    def _safe_query(self, label, func):
        try:
            return func(), None
        except PJLinkError as e:
            cli.debug.log(self.host, f"{label} failed: {e}")
            return None, str(e)

    def detect_class(self) -> str:
        self.detected_class = "1"
        self.auth_sent = False
        try:
            v = self._send_command("CLSS", "?", "%1")
            if v and not v.startswith("ERROR"):
                self.detected_class = v.strip()
        except PJLinkError as e:
            cli.debug.log(self.host, f"CLSS failed ({e}); assuming Class 1")
            self.detected_class = "1"
        if self.detected_class == "1":
            self.auth_sent = False
        cli.debug.log(self.host, f"PJLink class: {self.detected_class}")
        return self.detected_class

    # -- Class 1 --

    def get_power_status(self) -> str:
        v = self._send_command("POWR", "?", "%1")
        return v if v.startswith("ERROR") else self.POWER_STATES.get(v.strip(), f"Unknown ({v})")

    def get_lamp_info_raw(self) -> str:
        return self._send_command("LAMP", "?", "%1")

    def _normalize_lamp(self, raw):
        c = re.sub(r'[Ll][Aa][Mm][Pp]\s*\d+\s*:\s*', '', raw.strip())
        return re.sub(r'\s+', ' ', c).strip()

    def get_lamp_info_parsed(self) -> list:
        raw = self.get_lamp_info_raw()
        if raw.startswith("ERROR"):
            return [{"error": raw}]
        norm = self._normalize_lamp(raw)
        if not norm:
            return [{"raw": raw, "error": "Parse failed"}]
        lamps, tokens, i, n = [], norm.split(), 0, 1
        while i < len(tokens):
            try:
                h = int(tokens[i])
            except ValueError:
                i += 1
                continue
            on, st = None, "Unknown"
            if i + 1 < len(tokens) and tokens[i + 1] in ("0", "1"):
                on = tokens[i + 1] == "1"
                st = "On" if on else "Off"
                i += 2
            else:
                i += 1
            lamps.append({"lamp": n, "hours": f"{h}h", "hours_int": h, "on": on, "status": st})
            n += 1
        return lamps if lamps else [{"raw": raw, "error": "Parse failed"}]

    def get_lamp_hours_total(self) -> tuple:
        lamps = self.get_lamp_info_parsed()
        t = sum(l.get("hours_int", 0) for l in lamps if "hours_int" in l)
        c = sum(1 for l in lamps if "hours_int" in l)
        return (t, f"{t}h") if c > 0 else (-1, "N/A")

    def get_lamp_hours_summary(self) -> str:
        lamps = self.get_lamp_info_parsed()
        parts = []
        for l in lamps:
            if "hours" in l:
                parts.append(f"Lamp {l['lamp']}: {l['hours']} ({l.get('status', '?')})")
            elif "error" in l:
                return l["error"]
        return "; ".join(parts) if parts else "N/A"

    def get_name(self) -> str:
        return self._send_command("NAME", "?", "%1")

    def get_manufacturer(self) -> str:
        return self._send_command("INF1", "?", "%1")

    def get_product_name(self) -> str:
        return self._send_command("INF2", "?", "%1")

    def get_other_info(self) -> str:
        return self._send_command("INFO", "?", "%1")

    def get_error_status(self) -> str:
        return self._send_command("ERST", "?", "%1")

    def get_input(self) -> str:
        return self._send_command("INPT", "?", "%1")

    def get_input_list(self) -> str:
        return self._send_command("INST", "?", "%1")

    def get_mute_status(self) -> str:
        return self._send_command("AVMT", "?", "%1")

    # -- Class 2 --

    def get_software_version(self) -> str:
        return self._send_command("SVER", "?", "%2")

    def get_serial_number(self) -> str:
        return self._send_command("SNUM", "?", "%2")

    def get_filter_usage(self) -> str:
        return self._send_command("FILT", "?", "%2")

    def get_input_resolution(self) -> str:
        return self._send_command("IRES", "?", "%2")

    def get_recommended_resolution(self) -> str:
        return self._send_command("RRES", "?", "%2")

    # -- High-level --

    def get_firmware_info(self) -> dict:
        info = {}
        info["pjlink_class"] = self.detect_class()
        for k, f in [("manufacturer", self.get_manufacturer),
                      ("product_name", self.get_product_name),
                      ("projector_name", self.get_name)]:
            v, e = self._safe_query(k, f)
            info[k] = v if v is not None else f"ERROR: {e}"
        v, e = self._safe_query("other_info", self.get_other_info)
        info["other_info"] = v if v is not None else f"ERROR: {e}"
        if self.detected_class == "2":
            v, e = self._safe_query("software_version", self.get_software_version)
            info["software_version"] = v if v is not None else f"ERROR: {e}"
            v, e = self._safe_query("serial_number", self.get_serial_number)
            info["serial_number"] = v if v is not None else f"ERROR: {e}"
        info["firmware_version"] = self._derive_fw(info)
        self._query_lamp(info)
        v, e = self._safe_query("power_status", self.get_power_status)
        info["power_status"] = v if v is not None else f"ERROR: {e}"
        return info

    def get_all_info(self) -> dict:
        info = {}
        info["pjlink_class"] = self.detect_class()
        for k, f in [
            ("power_status", self.get_power_status),
            ("manufacturer", self.get_manufacturer),
            ("product_name", self.get_product_name),
            ("projector_name", self.get_name),
            ("other_info", self.get_other_info),
            ("input_current", self.get_input),
            ("input_list", self.get_input_list),
            ("mute_status", self.get_mute_status),
            ("error_status", self.get_error_status),
        ]:
            v, e = self._safe_query(k, f)
            info[k] = v if v is not None else f"ERROR: {e}"
        self._query_lamp(info)
        if self.detected_class == "2":
            for k, f in [
                ("software_version", self.get_software_version),
                ("serial_number", self.get_serial_number),
                ("filter_usage", self.get_filter_usage),
                ("input_resolution", self.get_input_resolution),
                ("recommended_resolution", self.get_recommended_resolution),
            ]:
                v, e = self._safe_query(k, f)
                info[k] = v if v is not None else f"ERROR: {e}"
        info["firmware_version"] = self._derive_fw(info)
        return info

    def _query_lamp(self, info):
        v, e = self._safe_query("lamp_info_raw", self.get_lamp_info_raw)
        info["lamp_info_raw"] = v if v is not None else f"ERROR: {e}"
        try:
            info["lamp_info"] = self.get_lamp_info_parsed()
        except PJLinkError as e:
            cli.debug.log(self.host, f"lamp_info failed: {e}")
            info["lamp_info"] = []
        try:
            ti, ts = self.get_lamp_hours_total()
            info["lamp_hours_total"] = ti
            info["lamp_hours_total_display"] = ts
        except PJLinkError as e:
            cli.debug.log(self.host, f"lamp_hours_total failed: {e}")
            info["lamp_hours_total"] = -1
            info["lamp_hours_total_display"] = "N/A"
        try:
            info["lamp_hours_summary"] = self.get_lamp_hours_summary()
        except PJLinkError as e:
            cli.debug.log(self.host, f"lamp_hours_summary failed: {e}")
            info["lamp_hours_summary"] = "N/A"

    def _derive_fw(self, info) -> str:
        # Class 2: prefer SVER (dedicated software version command)
        if info.get("pjlink_class") == "2":
            sv = info.get("software_version", "")
            if sv and isinstance(sv, str) and not sv.startswith("ERROR"):
                return sv

        # Class 1 & fallback: use INFO (free-form field, manufacturer-dependent)
        oi = info.get("other_info", "")
        if oi and isinstance(oi, str) and not oi.startswith("ERROR"):
            return oi

        # Class 1 has no standardised firmware command — report honestly
        if info.get("pjlink_class") == "1":
            return "N/A (Class 1)"

        return "Not available"

    def run_diagnostic(self) -> dict:
        diag = {"host": self.host, "port": self.port,
                "security": self.security_enabled, "commands": []}
        for hdr, cmd in [
            ("%1", "CLSS"), ("%1", "POWR"), ("%1", "INF1"), ("%1", "INF2"),
            ("%1", "INFO"), ("%1", "NAME"), ("%1", "LAMP"), ("%1", "ERST"),
            ("%2", "SVER"), ("%2", "SNUM"),
        ]:
            entry = {"command": f"{hdr}{cmd} ?", "attempts": []}
            for dig in ([True, False] if self.security_enabled else [False]):
                att = {"digest": dig, "sent": None, "recv": None, "parsed": None, "error": None}
                pkt = self._build_packet(hdr, cmd, "?", force_digest=dig)
                att["sent"] = repr(pkt)
                try:
                    self._drain_socket()
                    self._send_raw(pkt)
                    time.sleep(0.2)
                    raw = self._receive_raw_line()
                    att["recv"] = repr(raw)
                    dec = raw.decode("utf-8", errors="replace").strip()
                    if dec:
                        try:
                            att["parsed"] = self._parse_response(dec, cmd)
                        except PJLinkError as e:
                            att["parsed"] = f"PARSE_ERROR: {e}"
                        break
                    else:
                        att["error"] = "Empty"
                except Exception as e:
                    att["error"] = str(e)
                entry["attempts"].append(att)
            diag["commands"].append(entry)
        return diag


# ---------------------------------------------------------------------------
# CSV (spec 3.7)
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
        for row in reader:
            host = row.get(col_map["host"], "").strip()
            if not host or host.startswith("#"):
                continue
            try:
                port = int(row.get(col_map.get("port", ""), DEFAULT_PORT) or DEFAULT_PORT)
            except (ValueError, TypeError):
                port = DEFAULT_PORT
            password = None
            if "password" in col_map:
                password = row.get(col_map["password"], "").strip() or None
            devices.append({"host": host, "port": port, "password": password})
    if not devices:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No valid entries found in CSV.{RESET}")
        sys.exit(1)
    return devices


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------

def _map_to_contract(info: dict) -> dict:
    """Map PJLinkClient's internal field names onto the JSON data contract.

    Kept outside PJLinkClient so the protected class stays untouched (spec 4)
    while the emitted JSON conforms to spec 2.3 / 2.4.
    """
    out = dict(info)
    if "product_name" in out:
        out["model"] = out.pop("product_name")
    if "serial_number" in out:
        out["serial"] = out.pop("serial_number")
    # lamp_hours_total is read with `??` — null means not reported, 0 is a real
    # zero reading. The client uses -1 as its not-reported sentinel.
    if out.get("lamp_hours_total") == -1:
        out["lamp_hours_total"] = None
    return out


def make_device(host: str) -> dict:
    """--host target that is not in the CSV: same shape as a load_csv() row."""
    return {"host": host, "port": DEFAULT_PORT, "password": None}


class _QueryClient(PJLinkClient):
    """PJLinkClient for query_projector(): a rejected password ends the query.

    The protected client swallows PJLINK ERRA in detect_class() (it assumes
    Class 1) and in _safe_query() (the field becomes "ERROR: PJLINK ERRA"), so
    a wrong password used to come out as status "success" with N/A fields.
    This subclass notes the ERRA and raises it at the first of those points, so
    query_projector() reports auth_error. PJLinkClient itself, --info and
    --send are unchanged.
    """

    auth_rejected = False

    def _send_command(self, cmd, param="?", class_prefix=None):
        try:
            return super()._send_command(cmd, param, class_prefix)
        except PJLinkAuthError:
            self.auth_rejected = True
            raise

    def _stop_if_rejected(self):
        if self.auth_rejected:
            cli.debug.log(self.host, "password rejected (PJLINK ERRA); stopping")
            raise PJLinkAuthError("PJLINK ERRA — password rejected")

    def detect_class(self) -> str:
        detected = super().detect_class()
        self._stop_if_rejected()
        return detected

    def _safe_query(self, label, func):
        found = super()._safe_query(label, func)
        self._stop_if_rejected()
        return found


def query_projector(host, port, password, timeout, query_all):
    result = {
        "host": host,
        "port": port,
        "query_timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "success",
        "error": None,
        "manufacturer": None,
        "model": None,
        "serial": None,
        "mac": None,
        "firmware_version": None,
        "lamp_hours_total": None,
        "power_status": None,
    }
    client = _QueryClient(host=host, port=port, password=password, timeout=timeout)
    try:
        client.connect()
        if query_all:
            result.update(_map_to_contract(client.get_all_info()))
        else:
            result.update(_map_to_contract(client.get_firmware_info()))
    except PJLinkAuthError as e:
        result.update(status="auth_error", error=str(e),
                      lamp_hours_total_display="N/A", lamp_hours_summary="N/A")
    except PJLinkError as e:
        result.update(status="error", error=str(e),
                      lamp_hours_total_display="N/A", lamp_hours_summary="N/A")
    except Exception as e:
        result.update(status="error", error=f"{type(e).__name__}: {e}",
                      lamp_hours_total_display="N/A", lamp_hours_summary="N/A")
    finally:
        client.disconnect()
    cli.debug.log(host, f"result: {result['status']}"
                        + (f" ({result['error']})" if result["error"] else
                           f" (firmware {result.get('firmware_version')})"))
    return result


def dump_raw(dev: dict, timeout: int, query_all: bool = False):
    """
    --raw (was --diagnostic): print the greeting, then the raw reply to every
    diagnostic query. With authentication on, each command is tried with the
    MD5 digest first and again without it if that gets no reply. The digest
    itself is never printed.
    """
    host, port = dev["host"], dev["port"]
    client = PJLinkClient(host=host, port=port, password=dev.get("password"), timeout=timeout)
    try:
        # PJLinkClient.connect() parses the greeting without keeping it, so the
        # same steps are done here to show it before it is parsed.
        cli.debug.log(host, f"connecting to {host}:{port} (timeout {timeout}s)")
        client.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.socket.settimeout(timeout)
        client.socket.connect((host, port))
        greeting = client._receive_raw_line()
        cli.raw_item("greeting", greeting.rstrip(b"\r\n"))
        client._parse_greeting(greeting.decode("utf-8", errors="replace"))

        for hdr, cmd in RAW_COMMANDS + (RAW_COMMANDS_ALL if query_all else []):
            for dig in ([True, False] if client.security_enabled else [False]):
                label = f"{hdr}{cmd} ?"
                if client.security_enabled:
                    label += " (with digest)" if dig else " (without digest)"
                try:
                    client._drain_socket()
                    client._send_raw(client._build_packet(hdr, cmd, "?", force_digest=dig))
                    time.sleep(0.2)
                    raw = client._receive_raw_line()
                except Exception as e:
                    cli.raw_error(label, e)
                    continue
                if raw.strip():
                    cli.raw_item(label, raw.rstrip(b"\r\n"))
                    break
                cli.raw_error(label, "empty reply")
    finally:
        client.disconnect()


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def save_to_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def print_results_table(results, firmware_filter=None):
    rows = []
    for r in results:
        rows.append([
            status_icon(r),
            r.get("host", "N/A"),
            clean(r.get("manufacturer")),
            clean(r.get("model")),
            clean(r.get("firmware_version")),
            clean(r.get("lamp_hours_total_display")),
            clean(r.get("pjlink_class")),
            clean(r.get("projector_name")),
            clean(r.get("power_status")),
            truncate_error(r.get("error", "")),
        ])

    headers = [
        "Status", "Host", "Manufacturer", "Model", "Firmware",
        "Lamp Hours", "Class", "Name", "Power", "Error",
    ]

    table = tabulate(
        rows, headers=headers,
        tablefmt="pretty",
        stralign="left",
        numalign="right",
    )

    first_line = table.split("\n")[0]
    raw_width = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw = max(raw_width, 60)

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    if firmware_filter:
        title = f"PJLink Firmware Mismatch \u2014 Expected: {firmware_filter}"
    else:
        title = "PJLink Projector Query Results \u2014 Firmware & Lamp Hours"
    pad = max((bw - len(title)) // 2, 0)
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")

    for line in table.split("\n"):
        print(f"  {line}")

    total = len(results)
    ok = sum(1 for r in results if r.get("status") == "success")
    auth = sum(1 for r in results if r.get("status") == "auth_error")
    err = total - ok - auth

    # null means not reported; 0 is a genuine reading and is counted (spec 2.4)
    lamp_vals = [
        r.get("lamp_hours_total") for r in results
        if isinstance(r.get("lamp_hours_total"), int) and r.get("lamp_hours_total") >= 0
    ]

    print()
    if firmware_filter:
        print(
            f"  {BOLD}Firmware mismatches:{RESET}{WHITE} {total}  |  "
            f"{BOLD}Expected:{RESET}{WHITE} {firmware_filter}"
        )
    else:
        print(
            f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
            f"{GREEN}✓{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
            f"{YELLOW}✗{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
            f"{RED}✗{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
        )

    if lamp_vals:
        avg = sum(lamp_vals) / len(lamp_vals)
        print(
            f"  {BOLD}Lamp Hours{RESET}{WHITE} \u2014 "
            f"Avg: {avg:.0f}h  |  Min: {min(lamp_vals)}h  |  "
            f"Max: {max(lamp_vals)}h  |  Reported: {len(lamp_vals)}/{total}"
        )
    else:
        print(f"  {BOLD}Lamp Hours{RESET}{WHITE} \u2014 No data available")

    print(f"{RESET}")


# ---------------------------------------------------------------------------
# Send mode
# ---------------------------------------------------------------------------

KNOWN_COMMANDS = {
    "POWR": {"0": "Standby (Off)", "1": "Power On"},
    "AVMT": {"10": "Video mute on", "11": "Video mute off",
             "20": "Audio mute on", "21": "Audio mute off",
             "30": "AV mute on",    "31": "AV mute off"},
    "INPT": {},
}


def run_send_mode(host, port, password, cmd, param, timeout):
    print(f"{WHITE}")
    print(f"  {BOLD}Send Command{RESET}{WHITE}")
    print(f"  Host:    {host}:{port}")
    print(f"  Command: {cmd} {param}")
    print(f"  {'─' * 60}{RESET}")

    label = KNOWN_COMMANDS.get(cmd, {}).get(param, "")
    if label:
        print(f"{WHITE}  Action:  {BOLD}{label}{RESET}")

    client = PJLinkClient(host=host, port=port, password=password, timeout=timeout)
    try:
        client.connect()
        client.detect_class()

        raw_resp = client._send_command(cmd, param)

        print(f"{WHITE}  {BOLD}Response:{RESET}{WHITE} {raw_resp}{RESET}")

        resp_u = raw_resp.strip().upper()
        if param == "?":
            meaning = KNOWN_COMMANDS.get(cmd, {}).get(raw_resp.strip(), "")
            if cmd == "POWR":
                meaning = client.POWER_STATES.get(raw_resp.strip(), "")
            if meaning:
                print(f"  {GREEN}✓ {meaning}{RESET}")
            else:
                print(f"  {GREEN}✓ Query response{RESET}")
        elif resp_u == "OK":
            print(f"  {GREEN}✓ Command accepted{RESET}")
        elif resp_u.startswith("ERROR:"):
            print(f"  {RED}✗ Device returned an error{RESET}")
        else:
            print(f"  {YELLOW}? Unexpected response{RESET}")

    except PJLinkAuthError as e:
        print(f"  {YELLOW}✗ AUTH ERROR — {e}{RESET}")
    except PJLinkError as e:
        print(f"  {RED}✗ {truncate_error(str(e))}{RESET}")
    except Exception as e:
        print(f"  {RED}✗ {type(e).__name__}: {e}{RESET}")
    finally:
        client.disconnect()

    print(f"{WHITE}  {'─' * 60}{RESET}")
    print()


# ---------------------------------------------------------------------------
# INFO mode  —  PROTECTED (spec 4). DO NOT MODIFY.
# ---------------------------------------------------------------------------

def run_info_mode(projectors, timeout):
    total = len(projectors)
    print(f"{WHITE}")
    print(f"  {BOLD}INFO Query Mode{RESET}{WHITE} — Class 1 'Other Information' (INFO)")
    print(f"  Querying {total} device(s) sequentially")
    print(f"  {'─' * 60}{RESET}")

    for idx, proj in enumerate(projectors, 1):
        host = proj["host"]
        port = proj["port"]
        password = proj["password"]

        print(f"{WHITE}  [{idx}/{total}] {BOLD}{host}{RESET}{WHITE}", end="  ", flush=True)

        client = PJLinkClient(host=host, port=port, password=password, timeout=timeout)
        try:
            client.connect()
            pjlink_class = client.detect_class()

            raw = None
            parsed = None
            error = None

            try:
                raw = client.get_other_info()
            except PJLinkError as e:
                error = str(e)

            if raw and not raw.startswith("ERROR"):
                info = {"pjlink_class": pjlink_class, "other_info": raw}
                parsed = client._derive_fw(info)
            elif raw and raw.startswith("ERROR"):
                parsed = raw
            else:
                parsed = "N/A"

            class_label = f"Class {pjlink_class}"

            if error:
                print(f"{RED}✗ {error}{RESET}")
            else:
                print(f"{GREEN}✓{RESET}{WHITE}  {BOLD}Class:{RESET}{WHITE} {class_label}")
                raw_display    = raw    if raw    else "—"
                parsed_display = parsed if parsed else "—"
                print(f"         {BOLD}Raw:{RESET}{WHITE}    {raw_display}")
                print(f"         {BOLD}Parsed:{RESET}{WHITE} {parsed_display}")

        except PJLinkAuthError as e:
            print(f"{YELLOW}✗ AUTH ERROR — {e}{RESET}")
        except PJLinkError as e:
            print(f"{RED}✗ {truncate_error(str(e))}{RESET}")
        except Exception as e:
            print(f"{RED}✗ {type(e).__name__}: {e}{RESET}")
        finally:
            client.disconnect()

        print(f"{WHITE}  {'─' * 60}{RESET}")

    print(f"{WHITE}  {BOLD}Done.{RESET}{WHITE} Queried {total} device(s).{RESET}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = cli.build_parser(
        script_file=__file__,
        description="PJLink projector firmware & lamp hours query (Class 1 + 2)",
        default_csv=DEFAULT_CSV,
        output_dir=DEFAULT_OUTPUT_DIR,
        default_port=DEFAULT_PORT,
        default_timeout=DEFAULT_TIMEOUT,
        default_workers=DEFAULT_WORKERS,
        auth=cli.AUTH_PASSWORD,
        host_help=("Query HOST instead of the whole CSV (also the target of --send). "
                   "Repeat for several hosts. If HOST is in the CSV, that row's port "
                   "and password are reused."),
        raw_help=("Print each projector's PJLINK greeting and its raw reply to every "
                  "query (CLSS POWR INF1 INF2 INFO NAME LAMP ERST SVER SNUM; --all adds "
                  "INPT INST AVMT FILT IRES RRES), then exit without the table or JSON. "
                  "Works with --host or the whole CSV. Replaces --diagnostic."),
        debug_help=("Trace every connection, command sent and reply received (plus "
                    "retries) to stderr, prefixed with the host. The password and MD5 "
                    "auth digest are never shown. The normal table and JSON still run."),
        epilog=f"""
CSV Format:
    host,port,password
    192.168.1.100,4352,mypassword
    192.168.1.101,,

Examples:
    %(prog)s                                     # whole CSV
    %(prog)s --host 192.168.1.10                 # one projector
    %(prog)s --host 192.168.1.10 --password 'secret'
    %(prog)s --host 192.168.1.10 --raw           # greeting + raw reply to every query
    %(prog)s --host 192.168.1.10 --debug         # trace the exchange on stderr
    %(prog)s --firmware 1.07 1.08                # who is NOT on 1.07 or 1.08
    %(prog)s -i my_projectors.csv -o my_results.json -w 10 --all
    %(prog)s --info 192.168.1.10 --password 'secret'
    %(prog)s --send POWR 1 --host 192.168.1.10

Protocol:
    PJLink over TCP {DEFAULT_PORT}. Class 1 and Class 2; MD5 password
    authentication when the projector asks for it (PJLINK 1 <random>).
        """,
    )
    group = parser.add_argument_group("PJLink options")
    group.add_argument("--all", action="store_true",
                       help="Query every PJLink command (inputs, mute, error status, "
                            "filter, resolution, ...), not just firmware + lamp")
    group.add_argument("--info", nargs="?", const=True, metavar="HOST",
                       help="Query INFO one device at a time (CSV, --host, or the HOST "
                            "given here) and print raw + parsed values; no JSON")
    group.add_argument("--send", nargs=2, metavar=("CMD", "PARAM"),
                       help="Send one PJLink command to each --host, e.g. "
                            "--send POWR 1 --host 192.168.1.10; no JSON")
    cli.add_alias(parser, "--diagnostic", dest="raw", action="store_true")

    args = cli.parse_args(parser)

    # --info HOST is the same as --info --host HOST
    if isinstance(args.info, str):
        args.host = (args.host or []) + [args.info]

    output_file = args.output
    workers = max(1, args.workers)

    if args.send:
        output_display = "(none: --send)"
    elif args.info:
        output_display = "(none: --info)"
    elif args.raw:
        output_display = "(none: --raw)"
    else:
        output_display = output_file

    # -- Header (spec 3.2) --
    print(f"{WHITE}")
    print(f"  {BOLD}PJLink Projector Firmware & Lamp Hours Query{RESET}{WHITE}")
    print(f"  Queries projectors via PJLink Class 1 and Class 2")
    print(f"  Input:   {cli.input_label(args)}")
    print(f"  Output:  {output_display}")
    print(f"  Workers: {workers}")
    print(f"  Timeout: {args.timeout}s")
    if args.firmware:
        print(f"  {BOLD}Firmware Filter:{RESET}{WHITE} showing mismatches against "
              f"{cli.firmware_label(args.firmware)}")
    if args.debug:
        print(f"  Debug:   on (trace on stderr)")
    print(f"{RESET}")

    if args.send and not args.host:
        print(f"  {WHITE}{BOLD}Error:{RESET}{WHITE} --send requires --host{RESET}")
        sys.exit(1)

    # -- Device list: --host (reusing the CSV row when listed) or the whole CSV --
    projectors = cli.select_devices(args, load_csv, make_device)

    # -- Send mode: one command to each --host --
    if args.send:
        for proj in projectors:
            run_send_mode(
                host=proj["host"], port=proj["port"], password=proj["password"],
                cmd=args.send[0].upper(), param=args.send[1], timeout=args.timeout,
            )
        sys.exit(0)

    # -- INFO mode: sequential, one device at a time --
    if args.info:
        run_info_mode(projectors, args.timeout)
        sys.exit(0)

    # -- --raw: greeting + raw reply to every query, no table / JSON --
    if args.raw:
        cli.run_raw(projectors, lambda d: dump_raw(d, args.timeout, args.all))
        return

    total = len(projectors)

    # -- Track only the most recently started host --
    active_lock = threading.Lock()
    latest_host = {"value": ""}

    def worker_task(proj):
        host = proj["host"]
        with active_lock:
            latest_host["value"] = host
        return proj, query_projector(
            host=host, port=proj["port"], password=proj["password"],
            timeout=args.timeout, query_all=args.all,
        )

    # -- Run with thread pool + tqdm (spec 3.3) --
    results_map = {}
    start = time.time()

    term_width = get_terminal_width()

    bar_fmt = (
        f"  {WHITE}Scanning{RESET} "
        f"{CYAN}{{bar}}{RESET}"
        f" {WHITE}{{n_fmt}}/{{total_fmt}}{RESET}"
        f" {WHITE}[{{elapsed}}<{{remaining}}]{RESET}"
        f"  {WHITE}{{postfix}}{RESET}"
    )

    with tqdm(
        total=total,
        bar_format=bar_fmt,
        ncols=term_width,
        dynamic_ncols=True,
        file=sys.stderr,
        leave=True,
    ) as pbar:

        pbar.set_postfix_str("", refresh=False)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(worker_task, p): idx
                for idx, p in enumerate(projectors)
            }

            for future in as_completed(futures):
                idx = futures[future]
                try:
                    proj, result = future.result()
                    results_map[idx] = result
                except Exception as e:
                    p = projectors[idx]
                    results_map[idx] = {
                        "host": p["host"],
                        "port": p["port"],
                        "query_timestamp": datetime.now(timezone.utc).isoformat(),
                        "status": "error",
                        "error": f"Worker error: {e}",
                        "manufacturer": None,
                        "model": None,
                        "serial": None,
                        "mac": None,
                        "firmware_version": None,
                        "lamp_hours_total": None,
                        "power_status": None,
                        "lamp_hours_total_display": "N/A",
                        "lamp_hours_summary": "N/A",
                    }

                with active_lock:
                    host_display = latest_host["value"]
                pbar.set_postfix_str(host_display, refresh=False)
                pbar.update(1)

        elapsed = time.time() - start
        pbar.set_postfix_str(
            f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s",
            refresh=True,
        )

    # -- Reassemble in CSV order --
    results = [results_map[i] for i in range(total)]

    # -- Save JSON (spec 2.1) --
    output_data = {
        "query_info": {
            "csv_file": cli.input_label(args),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": "PJLink Class 1 + Class 2",
            "mode": "all" if args.all else "firmware+lamp",
            "workers": workers,
            "total": total,
            "success": sum(1 for r in results if r["status"] == "success"),
            "errors": sum(1 for r in results if r["status"] != "success"),
            "elapsed_seconds": round(elapsed, 1),
        },
        ARRAY_KEY: results,
    }

    cli.ensure_parent(output_file)
    save_to_json(output_data, output_file)

    # -- Print table: with --firmware, only devices NOT on one of those versions --
    if args.firmware:
        mismatches = cli.firmware_mismatches(results, args.firmware)
        print_results_table(mismatches, firmware_filter=cli.firmware_label(args.firmware))
    else:
        print_results_table(results)

    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {output_file}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers){RESET}")
    print()


if __name__ == "__main__":
    main()
