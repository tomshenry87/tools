#!/usr/bin/env python3
"""
PJLink Projector Firmware & Lamp Hours Query (Class 1 + Class 2)

Dependencies:
    pip install tabulate tqdm paramiko

Queries projectors via PJLink protocol for:
    - Firmware version (INFO for Class 1, SVER for Class 2)
    - Lamp hours (LAMP for all classes)
    - Manufacturer, model, and other device info

Defaults:
    Input:  projectors.csv
    Output: results.json
"""

import socket
import hashlib
import json
import csv
import argparse
import sys
import re
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from tabulate import tabulate
from tqdm import tqdm

# Paramiko available for future SSH-based management
try:
    import paramiko  # noqa: F401
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


# ---------------------------------------------------------------------------
# Logging — suppress during normal runs, only show in debug mode
# ---------------------------------------------------------------------------

log = logging.getLogger("pjlink")
log.addHandler(logging.NullHandler())


def setup_logging(debug: bool):
    """Configure logging. Only emit to stderr in debug mode."""
    log.handlers.clear()
    if debug:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
        ))
        log.addHandler(handler)
        log.setLevel(logging.DEBUG)
    else:
        log.addHandler(logging.NullHandler())
        log.setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# PJLink Client
# ---------------------------------------------------------------------------

class PJLinkError(Exception):
    pass


class PJLinkAuthError(PJLinkError):
    pass


class PJLinkClient:
    DEFAULT_PORT = 4352
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

    # -- Connection --

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.host, self.port))
            raw = self._receive_raw_line()
            greeting = raw.decode("utf-8", errors="replace")
            log.debug(f"[{self.host}] Greeting: {repr(greeting)}")
            self._parse_greeting(greeting)
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
            except OSError:
                pass
            finally:
                self.socket = None

    # -- Raw I/O --

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
                raise PJLinkError(f"No response from {self.host} (timeout)")
        log.debug(f"[{self.host}] RX: {repr(data)}")
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
        except (socket.timeout, OSError):
            pass
        finally:
            self.socket.settimeout(orig)

    def _compute_digest(self) -> str:
        if not self.security_enabled or not self.random_number:
            return ""
        return hashlib.md5(
            f"{self.random_number}{self.password}".encode("utf-8")
        ).hexdigest()

    def _send_raw(self, data: bytes):
        if not self.socket:
            raise PJLinkError("Not connected.")
        log.debug(f"[{self.host}] TX: {repr(data)}")
        self.socket.sendall(data)

    # -- Command sending --

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
        except (socket.timeout, OSError):
            pass
        return self._retry_command(cmd, param, header)

    def _retry_command(self, cmd, param, orig_hdr) -> str:
        alt = "%2" if orig_hdr == "%1" else "%1"
        for _, hdr, dig in [
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
            except (PJLinkError, socket.timeout, OSError):
                continue
        raise PJLinkError(f"No response for {cmd} after retries.")

    # -- Response parsing --

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
            return None, str(e)

    # -- Class detection --

    def detect_class(self) -> str:
        self.detected_class = "1"
        self.auth_sent = False
        try:
            v = self._send_command("CLSS", "?", "%1")
            if v and not v.startswith("ERROR"):
                self.detected_class = v.strip()
        except PJLinkError:
            self.detected_class = "1"
        if self.detected_class == "1":
            self.auth_sent = False
        return self.detected_class

    # -- Class 1 commands --

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

    # -- Class 2 commands --

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
        except PJLinkError:
            info["lamp_info"] = []
        try:
            ti, ts = self.get_lamp_hours_total()
            info["lamp_hours_total"] = ti
            info["lamp_hours_total_display"] = ts
        except PJLinkError:
            info["lamp_hours_total"] = -1
            info["lamp_hours_total_display"] = "N/A"
        try:
            info["lamp_hours_summary"] = self.get_lamp_hours_summary()
        except PJLinkError:
            info["lamp_hours_summary"] = "N/A"

    def _derive_fw(self, info) -> str:
        sv = info.get("software_version", "")
        if sv and isinstance(sv, str) and not sv.startswith("ERROR"):
            return sv
        oi = info.get("other_info", "")
        if oi and isinstance(oi, str) and not oi.startswith("ERROR"):
            return oi
        return "Not available"

    # -- Diagnostic --

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
# CSV
# ---------------------------------------------------------------------------

def load_csv(csv_path: str) -> list:
    projectors = []
    p = Path(csv_path)
    if not p.exists():
        print(f"\n\033[91mError: CSV not found: {csv_path}\033[0m")
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
            print("\n\033[91mError: CSV is empty\033[0m")
            sys.exit(1)
        col_map = {n.strip().lower(): n for n in reader.fieldnames}
        if "host" not in col_map:
            print(f"\n\033[91mError: CSV needs 'host' column. Found: {reader.fieldnames}\033[0m")
            sys.exit(1)
        for row in reader:
            host = row.get(col_map["host"], "").strip()
            if not host or host.startswith("#"):
                continue
            port = PJLinkClient.DEFAULT_PORT
            if "port" in col_map:
                ps = row.get(col_map["port"], "").strip()
                if ps:
                    try:
                        port = int(ps)
                    except ValueError:
                        pass
            pw = None
            if "password" in col_map:
                pw = row.get(col_map["password"], "").strip() or None
            projectors.append({"host": host, "port": port, "password": pw})
    return projectors


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------

def query_projector(host, port, password, timeout, query_all, diagnostic):
    result = {
        "host": host, "port": port,
        "query_timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "success", "error": None,
    }
    client = PJLinkClient(host=host, port=port, password=password, timeout=timeout)
    try:
        client.connect()
        if diagnostic:
            result["diagnostic"] = client.run_diagnostic()
            result["firmware_version"] = "See diagnostic"
            result["lamp_hours_total"] = -1
            result["lamp_hours_total_display"] = "See diagnostic"
            result["lamp_hours_summary"] = "See diagnostic"
        elif query_all:
            result.update(client.get_all_info())
        else:
            result.update(client.get_firmware_info())
    except PJLinkAuthError as e:
        result.update(status="auth_error", error=str(e), firmware_version="AUTH ERROR",
                      lamp_hours_total=-1, lamp_hours_total_display="N/A", lamp_hours_summary="N/A")
    except PJLinkError as e:
        result.update(status="error", error=str(e), firmware_version="ERROR",
                      lamp_hours_total=-1, lamp_hours_total_display="N/A", lamp_hours_summary="N/A")
    except Exception as e:
        result.update(status="error", error=f"{type(e).__name__}: {e}", firmware_version="ERROR",
                      lamp_hours_total=-1, lamp_hours_total_display="N/A", lamp_hours_summary="N/A")
    finally:
        client.disconnect()
    return result


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def save_to_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def truncate_error(err, max_len=30):
    if not err:
        return ""
    s = str(err)
    for pat, label in [
        (r"[Cc]onnection timed out", "Timed out"),
        (r"[Cc]onnection refused", "Conn refused"),
        (r"[Nn]o response .* timeout", "No response"),
        (r"[Nn]o route to host", "No route"),
        (r"[Nn]etwork is unreachable", "Net unreachable"),
        (r"[Nn]ame or service not known", "DNS failed"),
        (r"[Nn]etwork error", "Network error"),
        (r"[Aa]uthentication required", "Auth required"),
        (r"PJLINK ERRA", "Auth failed"),
        (r"ERRA", "Auth error"),
        (r"[Nn]ot a PJLink device", "Not PJLink"),
        (r"[Mm]alformed greeting", "Bad greeting"),
    ]:
        if re.search(pat, s):
            return label
    s = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', '', s)
    s = re.sub(r'\[Errno\s*-?\d+\]\s*', '', s)
    s = re.sub(r'^(Network error|Socket error)\s*:\s*', '', s, flags=re.IGNORECASE)
    s = re.sub(r'\s+', ' ', s).strip(': ')
    return (s[:max_len - 3] + "...") if len(s) > max_len else (s or "Error")


# -- ANSI color helpers --
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_results_table(results):
    """Print final results table using tabulate."""

    def clean(val):
        s = str(val) if val is not None else "N/A"
        if s in ("None", "-1", ""):
            return "N/A"
        if s.startswith("ERROR") or s in ("Not available", "AUTH ERROR", "See diagnostic"):
            return "N/A"
        return s

    def status_icon(r):
        s = r.get("status", "error")
        if s == "success":
            return f"{GREEN}\u2713 OK{RESET}"
        elif s == "auth_error":
            return f"{YELLOW}\u2717 AUTH ERR{RESET}"
        return f"{RED}\u2717 ERROR{RESET}"

    rows = []
    for r in results:
        rows.append([
            status_icon(r),
            r.get("host", "N/A"),
            r.get("port", ""),
            clean(r.get("manufacturer")),
            clean(r.get("product_name")),
            clean(r.get("firmware_version")),
            clean(r.get("lamp_hours_total_display")),
            clean(r.get("pjlink_class")),
            clean(r.get("power_status")),
            clean(r.get("projector_name")),
            truncate_error(r.get("error", "")),
        ])

    headers = [
        f"{BOLD}Status{RESET}",
        f"{BOLD}Host{RESET}",
        f"{BOLD}Port{RESET}",
        f"{BOLD}Manufacturer{RESET}",
        f"{BOLD}Model{RESET}",
        f"{BOLD}Firmware{RESET}",
        f"{BOLD}Lamp Hours{RESET}",
        f"{BOLD}Class{RESET}",
        f"{BOLD}Power{RESET}",
        f"{BOLD}Name{RESET}",
        f"{BOLD}Error{RESET}",
    ]

    table = tabulate(
        rows, headers=headers,
        tablefmt="pretty",
        stralign="left",
        numalign="right",
    )

    # Title banner
    # Find the width from the first line of the table
    first_line = table.split("\n")[0]
    # Strip ANSI codes to get true width
    raw_width = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    banner_width = max(raw_width, 60)

    print()
    print(f"{CYAN}{'=' * banner_width}{RESET}")
    title = "PJLink Projector Query Results \u2014 Firmware & Lamp Hours"
    pad = (banner_width - len(title)) // 2
    print(f"{CYAN}{' ' * pad}{BOLD}{title}{RESET}")
    print(f"{CYAN}{'=' * banner_width}{RESET}")
    print(table)

    # Stats
    total = len(results)
    ok = sum(1 for r in results if r["status"] == "success")
    auth = sum(1 for r in results if r["status"] == "auth_error")
    err = total - ok - auth

    lamp_vals = [
        r.get("lamp_hours_total", -1) for r in results
        if isinstance(r.get("lamp_hours_total"), int) and r.get("lamp_hours_total", -1) > 0
    ]

    print()
    print(
        f"  {BOLD}Total:{RESET} {total}  |  "
        f"{GREEN}{BOLD}Success:{RESET} {ok}  |  "
        f"{YELLOW}{BOLD}Auth Errors:{RESET} {auth}  |  "
        f"{RED}{BOLD}Failed:{RESET} {err}"
    )

    if lamp_vals:
        avg = sum(lamp_vals) / len(lamp_vals)
        print(
            f"  {CYAN}{BOLD}Lamp Hours{RESET} \u2014 "
            f"Avg: {avg:.0f}h  |  Min: {min(lamp_vals)}h  |  "
            f"Max: {max(lamp_vals)}h  |  Reported: {len(lamp_vals)}/{total}"
        )
    else:
        print(f"  {CYAN}Lamp Hours{RESET} \u2014 No data available")

    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

DEFAULT_CSV = "projectors.csv"
DEFAULT_OUTPUT = "results.json"


def main():
    parser = argparse.ArgumentParser(
        description="PJLink projector firmware & lamp hours query (Class 1 + 2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Defaults:
    Input CSV:   {DEFAULT_CSV}
    Output JSON: {DEFAULT_OUTPUT}

    Run with no arguments:  %(prog)s

CSV Format:
    host,port,password
    192.168.1.100,4352,mypassword
    192.168.1.101,,

Examples:
    %(prog)s
    %(prog)s -i my_projectors.csv -o my_results.json
    %(prog)s --all --debug
    %(prog)s --diagnostic --debug
        """,
    )

    parser.add_argument("-i", "--input", default=DEFAULT_CSV,
                        help=f"Input CSV (default: {DEFAULT_CSV})")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
                        help=f"Output JSON (default: {DEFAULT_OUTPUT})")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Timeout per device in seconds (default: 10)")
    parser.add_argument("--all", action="store_true", help="Query all commands")
    parser.add_argument("--diagnostic", action="store_true", help="Raw hex diagnostic")
    parser.add_argument("--debug", action="store_true", help="Debug logging")

    args = parser.parse_args()
    setup_logging(args.debug)

    csv_file = args.input
    output_file = args.output

    # Header
    print()
    print(f"  {CYAN}{BOLD}PJLink Projector Query{RESET}")
    print(f"  {CYAN}Firmware + Lamp Hours | Class 1 + 2{RESET}")
    print(f"  Input:  {csv_file}")
    print(f"  Output: {output_file}")
    print()

    projectors = load_csv(csv_file)
    if not projectors:
        print(f"{RED}No projectors found in CSV.{RESET}")
        sys.exit(1)

    total = len(projectors)
    results = []
    start = time.time()

    # -- TQDM progress bar: cyan, shows current host --
    bar_format = (
        "  {l_bar}{bar}{r_bar}"
    )

    with tqdm(
        total=total,
        bar_format=bar_format,
        colour="cyan",
        unit="dev",
        dynamic_ncols=True,
        file=sys.stderr,
        leave=True,
    ) as pbar:
        for p in projectors:
            host = p["host"]

            # Show current host in progress bar description
            pbar.set_description(f"\033[96m{host:<20}\033[0m")

            result = query_projector(
                host=host, port=p["port"], password=p["password"],
                timeout=args.timeout, query_all=args.all, diagnostic=args.diagnostic,
            )
            results.append(result)
            pbar.update(1)

        # Final state
        elapsed = time.time() - start
        pbar.set_description(f"\033[92m{'Complete':<20}\033[0m")

    # -- Build and save JSON --
    output_data = {
        "query_info": {
            "csv_file": str(Path(csv_file).resolve()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": "PJLink Class 1 + Class 2",
            "mode": "diagnostic" if args.diagnostic else "all" if args.all else "firmware+lamp",
            "total": total,
            "success": sum(1 for r in results if r["status"] == "success"),
            "errors": sum(1 for r in results if r["status"] != "success"),
            "elapsed_seconds": round(time.time() - start, 1),
        },
        "projectors": results,
    }

    save_to_json(output_data, output_file)

    # -- Print results table --
    if not args.diagnostic:
        print_results_table(results)
    else:
        print(f"\n{CYAN}Diagnostic data written to: {output_file}{RESET}")

    print(f"  {BOLD}Results saved:{RESET} {output_file}")
    print(f"  {BOLD}Elapsed:{RESET} {elapsed:.1f}s")
    print()

    if args.diagnostic:
        print(json.dumps(output_data, indent=2))


if __name__ == "__main__":
    main()
