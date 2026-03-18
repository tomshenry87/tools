#!/usr/bin/env python3
"""
PJLink Projector Firmware & Lamp Hours Query (Class 1 + Class 2)

Queries projectors via PJLink protocol for:
    - Firmware version (INFO for Class 1, SVER for Class 2)
    - Lamp hours (LAMP for all classes)
    - Manufacturer, model, and other device info

Supports:
    - Class 1 v1.00 (2013): auth digest on every command
    - Class 2 v2.00 (2017): auth digest on first command only, SVER/SNUM

Defaults:
    Input:  projectors.csv
    Output: results.json

CSV Format:
    host,port,password
    192.168.1.100,4352,mypassword
    192.168.1.101,,
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
import shutil
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Logging — custom handler that clears progress bar before writing log lines
# ---------------------------------------------------------------------------

class ProgressAwareHandler(logging.StreamHandler):
    """Log handler that clears the progress bar line before printing."""

    def __init__(self, progress_bar=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.progress_bar = progress_bar

    def emit(self, record):
        if self.progress_bar:
            self.progress_bar.clear_line()
        super().emit(record)
        if self.progress_bar:
            self.progress_bar.redraw()


# Set up logging with our custom handler
log = logging.getLogger("pjlink")
log.setLevel(logging.INFO)
_handler = ProgressAwareHandler()
_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
))
log.addHandler(_handler)
log.propagate = False


# ---------------------------------------------------------------------------
# Progress Bar
# ---------------------------------------------------------------------------

class ProgressBar:
    """
    Terminal progress bar with status text.

    [\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591]  3/5  60%  192.168.1.102 — querying...
    """

    FILL = "\u2588"   # █
    EMPTY = "\u2591"   # ░

    def __init__(self, total: int, bar_width: int = 30, enabled: bool = True):
        self.total = total
        self.current = 0
        self.bar_width = bar_width
        self.enabled = enabled and sys.stderr.isatty()
        self.status_text = ""
        self._last_line_len = 0

    def update(self, current: int, status: str = ""):
        """Update progress bar to position `current` with optional status text."""
        self.current = current
        self.status_text = status
        self.redraw()

    def advance(self, status: str = ""):
        """Advance progress by 1."""
        self.current += 1
        self.status_text = status
        self.redraw()

    def redraw(self):
        """Redraw the progress bar on the current line."""
        if not self.enabled:
            return

        pct = self.current / self.total if self.total > 0 else 0
        filled = int(self.bar_width * pct)
        empty = self.bar_width - filled

        bar = f"{self.FILL * filled}{self.EMPTY * empty}"
        counter = f"{self.current}/{self.total}"
        pct_str = f"{pct * 100:5.1f}%"

        line = f"\r  [{bar}] {counter:>7}  {pct_str}  {self.status_text}"

        # Pad with spaces to overwrite any previous longer line
        term_width = shutil.get_terminal_size((120, 24)).columns
        line = line[:term_width]
        padding = max(0, self._last_line_len - len(line))
        full_line = line + " " * padding

        sys.stderr.write(full_line)
        sys.stderr.flush()

        self._last_line_len = len(line)

    def clear_line(self):
        """Clear the progress bar line (for log messages to print cleanly)."""
        if not self.enabled:
            return
        term_width = shutil.get_terminal_size((120, 24)).columns
        sys.stderr.write("\r" + " " * term_width + "\r")
        sys.stderr.flush()

    def finish(self, final_text: str = "Done"):
        """Complete the progress bar and move to next line."""
        if not self.enabled:
            return
        self.current = self.total
        self.status_text = final_text
        self.redraw()
        sys.stderr.write("\n")
        sys.stderr.flush()


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

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.host, self.port))
            raw = self._receive_raw_line()
            greeting = raw.decode("utf-8", errors="replace")
            log.debug(f"[{self.host}] Greeting bytes: {raw.hex(' ')}")
            log.debug(f"[{self.host}] Greeting text:  {repr(greeting)}")
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
            log.debug(f"[{self.host}] No authentication required")
        elif parts[1] == "1":
            self.security_enabled = True
            if len(parts) < 3:
                raise PJLinkError(f"Auth greeting missing random: {repr(line)}")
            self.random_number = parts[2]
            log.debug(f"[{self.host}] Auth required, random: {self.random_number}")
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
            if data:
                log.debug(f"[{self.host}] Partial recv ({len(data)} bytes): {repr(data)}")
            else:
                raise PJLinkError(f"No response from {self.host} (timeout)")
        log.debug(f"[{self.host}] RX ({len(data)}b): hex=[{data.hex(' ')}] text={repr(data)}")
        return data

    def _drain_socket(self):
        if not self.socket:
            return
        original_timeout = self.socket.gettimeout()
        try:
            self.socket.settimeout(0.3)
            while True:
                chunk = self.socket.recv(self.BUFFER_SIZE)
                if not chunk:
                    break
                log.debug(f"[{self.host}] Drained: {repr(chunk)}")
        except (socket.timeout, OSError):
            pass
        finally:
            self.socket.settimeout(original_timeout)

    def _compute_digest(self) -> str:
        if not self.security_enabled or not self.random_number:
            return ""
        return hashlib.md5(
            f"{self.random_number}{self.password}".encode("utf-8")
        ).hexdigest()

    def _send_raw(self, data: bytes):
        if not self.socket:
            raise PJLinkError("Not connected.")
        log.debug(f"[{self.host}] TX ({len(data)}b): hex=[{data.hex(' ')}] text={repr(data)}")
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
            digest = self._compute_digest()
            packet_str = f"{digest}{cmd_str}" if digest else cmd_str
        elif force_digest is False:
            packet_str = cmd_str
        else:
            if self._should_prepend_digest():
                digest = self._compute_digest()
                packet_str = f"{digest}{cmd_str}" if digest else cmd_str
            else:
                packet_str = cmd_str
        return packet_str.encode("utf-8")

    def _send_and_receive(self, header, cmd, param="?", force_digest=None) -> str:
        packet = self._build_packet(header, cmd, param, force_digest)
        self._send_raw(packet)
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
        header = class_prefix if class_prefix else "%1"
        try:
            response = self._send_and_receive(header, cmd, param)
            if response:
                if "PJLINK" in response.upper() and "ERRA" in response.upper():
                    raise PJLinkAuthError("PJLINK ERRA")
                return self._parse_response(response, cmd)
            log.debug(f"[{self.host}] Empty response for {cmd}, retrying...")
        except socket.timeout:
            log.debug(f"[{self.host}] Timeout on {cmd}, retrying...")
        except OSError as e:
            log.debug(f"[{self.host}] Error on {cmd}: {e}")
        return self._retry_command(cmd, param, header)

    def _retry_command(self, cmd, param, original_header) -> str:
        alt_header = "%2" if original_header == "%1" else "%1"
        strategies = [
            ("drain+retry", original_header, None),
            ("force_digest", original_header, True),
            ("no_digest", original_header, False),
            ("alt_header", alt_header, None),
            ("alt_header+digest", alt_header, True),
            ("alt_header+no_digest", alt_header, False),
        ]
        for desc, header, digest in strategies:
            log.debug(f"[{self.host}] Retry {cmd}: {desc}")
            try:
                self._drain_socket()
                time.sleep(0.1)
                response = self._send_and_receive(header, cmd, param, digest)
                if not response:
                    continue
                if "PJLINK" in response.upper() and "ERRA" in response.upper():
                    continue
                parsed = self._parse_response(response, cmd)
                log.debug(f"[{self.host}] Success with {desc}: {repr(parsed)}")
                return parsed
            except PJLinkAuthError:
                continue
            except PJLinkError as e:
                log.debug(f"[{self.host}] {desc} failed: {e}")
                continue
            except (socket.timeout, OSError) as e:
                log.debug(f"[{self.host}] {desc} network error: {e}")
                continue
        raise PJLinkError(
            f"No response for {cmd} after all retries. "
            f"Device may not support this command."
        )

    def _parse_response(self, raw, expected_cmd) -> str:
        line = raw.strip("\r\n \t")
        log.debug(f"[{self.host}] Parse '{expected_cmd}': {repr(line)}")
        if not line:
            raise PJLinkError(f"Empty response for {expected_cmd}")
        if "PJLINK" in line.upper() and "ERRA" in line.upper():
            raise PJLinkAuthError("PJLINK ERRA")
        for c in ("1", "2"):
            prefix = f"%{c}{expected_cmd}="
            if prefix in line:
                value = line[line.index(prefix) + len(prefix):]
                return self._check_error(value.strip(), expected_cmd)
        line_upper = line.upper()
        for c in ("1", "2"):
            prefix_upper = f"%{c}{expected_cmd.upper()}="
            if prefix_upper in line_upper:
                idx = line_upper.index(prefix_upper)
                value = line[idx + len(prefix_upper):]
                return self._check_error(value.strip(), expected_cmd)
        match = re.search(r"%([12])([A-Za-z0-9]{4})=(.*)", line)
        if match:
            value = match.group(3).strip()
            actual = match.group(2).upper()
            if actual != expected_cmd.upper():
                log.debug(f"[{self.host}] Got {actual} instead of {expected_cmd}")
            return self._check_error(value, expected_cmd)
        if "=" in line:
            _, _, value = line.partition("=")
            value = value.strip()
            if value:
                log.debug(f"[{self.host}] Fallback parse for {expected_cmd}: {repr(value)}")
                return self._check_error(value, expected_cmd)
        raise PJLinkError(f"Cannot parse {expected_cmd}: {repr(raw)}")

    def _check_error(self, value, cmd) -> str:
        upper = value.strip().upper()
        if upper in self.ERROR_CODES:
            desc = self.ERROR_CODES[upper]
            log.warning(f"[{self.host}] {cmd}: {upper} ({desc})")
            return f"ERROR: {desc} ({upper})"
        return value

    def _safe_query(self, label, func):
        try:
            value = func()
            return value, None
        except PJLinkError as e:
            log.debug(f"[{self.host}] {label}: {e}")
            return None, str(e)

    def detect_class(self) -> str:
        self.detected_class = "1"
        self.auth_sent = False
        try:
            value = self._send_command("CLSS", "?", class_prefix="%1")
            if value and not value.startswith("ERROR"):
                self.detected_class = value.strip()
            else:
                self.detected_class = "1"
        except PJLinkError as e:
            log.warning(f"[{self.host}] CLSS failed ({e}), assuming Class 1")
            self.detected_class = "1"
        if self.detected_class != "1":
            log.info(f"[{self.host}] PJLink Class {self.detected_class}")
        else:
            log.info(f"[{self.host}] PJLink Class 1")
            self.auth_sent = False
        return self.detected_class

    # -- Class 1 commands --

    def get_power_status(self) -> str:
        value = self._send_command("POWR", "?", "%1")
        if value.startswith("ERROR"):
            return value
        return self.POWER_STATES.get(value.strip(), f"Unknown ({value})")

    def get_input(self) -> str:
        return self._send_command("INPT", "?", "%1")

    def get_mute_status(self) -> str:
        return self._send_command("AVMT", "?", "%1")

    def get_error_status(self) -> str:
        return self._send_command("ERST", "?", "%1")

    def get_error_status_parsed(self) -> dict:
        raw = self.get_error_status()
        if raw.startswith("ERROR"):
            return {"raw": raw}
        result = {"raw": raw}
        for i, name in enumerate(self.ERST_POSITIONS):
            if i < len(raw):
                result[name] = self.ERST_VALUES.get(raw[i], f"Unknown({raw[i]})")
        return result

    def get_lamp_info_raw(self) -> str:
        return self._send_command("LAMP", "?", "%1")

    def _normalize_lamp_response(self, raw: str) -> str:
        cleaned = raw.strip()
        log.debug(f"[{self.host}] Lamp raw before normalize: {repr(cleaned)}")
        cleaned = re.sub(r'[Ll][Aa][Mm][Pp]\s*\d+\s*:\s*', '', cleaned)
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        log.debug(f"[{self.host}] Lamp after normalize: {repr(cleaned)}")
        return cleaned

    def get_lamp_info_parsed(self) -> list:
        raw = self.get_lamp_info_raw()
        if raw.startswith("ERROR"):
            return [{"error": raw}]
        normalized = self._normalize_lamp_response(raw)
        if not normalized:
            return [{"raw": raw, "error": "Could not parse lamp data"}]
        lamps = []
        tokens = normalized.split()
        i = 0
        lamp_num = 1
        while i < len(tokens):
            try:
                hours_int = int(tokens[i])
            except ValueError:
                i += 1
                continue
            on = None
            status_str = "Unknown"
            if i + 1 < len(tokens) and tokens[i + 1] in ("0", "1"):
                on = tokens[i + 1] == "1"
                status_str = "On" if on else "Off"
                i += 2
            else:
                i += 1
            lamps.append({
                "lamp": lamp_num, "hours": f"{hours_int}h",
                "hours_int": hours_int, "on": on, "status": status_str,
            })
            lamp_num += 1
        if not lamps:
            return [{"raw": raw, "error": "Could not parse lamp data"}]
        return lamps

    def get_lamp_hours_total(self) -> tuple:
        lamps = self.get_lamp_info_parsed()
        total = 0
        count = 0
        for lamp in lamps:
            if "hours_int" in lamp:
                total += lamp["hours_int"]
                count += 1
            elif "error" in lamp:
                return -1, "N/A"
        if count == 0:
            return -1, "N/A"
        return total, f"{total}h"

    def get_lamp_hours_summary(self) -> str:
        lamps = self.get_lamp_info_parsed()
        parts = []
        for lamp in lamps:
            if "hours" in lamp:
                parts.append(f"Lamp {lamp['lamp']}: {lamp['hours']} ({lamp.get('status', '?')})")
            elif "error" in lamp:
                return lamp["error"]
        return "; ".join(parts) if parts else "N/A"

    def get_input_list(self) -> str:
        return self._send_command("INST", "?", "%1")

    def get_name(self) -> str:
        return self._send_command("NAME", "?", "%1")

    def get_manufacturer(self) -> str:
        return self._send_command("INF1", "?", "%1")

    def get_product_name(self) -> str:
        return self._send_command("INF2", "?", "%1")

    def get_other_info(self) -> str:
        return self._send_command("INFO", "?", "%1")

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

    # -- High-level queries --

    def get_firmware_info(self) -> dict:
        info = {}
        info["pjlink_class"] = self.detect_class()
        for key, func in [
            ("manufacturer", self.get_manufacturer),
            ("product_name", self.get_product_name),
            ("projector_name", self.get_name),
        ]:
            val, err = self._safe_query(key, func)
            info[key] = val if val is not None else f"ERROR: {err}"
        val, err = self._safe_query("other_info", self.get_other_info)
        info["other_info"] = val if val is not None else f"ERROR: {err}"
        if self.detected_class == "2":
            val, err = self._safe_query("software_version", self.get_software_version)
            info["software_version"] = val if val is not None else f"ERROR: {err}"
            val, err = self._safe_query("serial_number", self.get_serial_number)
            info["serial_number"] = val if val is not None else f"ERROR: {err}"
        info["firmware_version"] = self._derive_firmware_version(info)
        self._query_lamp_data(info)
        val, err = self._safe_query("power_status", self.get_power_status)
        info["power_status"] = val if val is not None else f"ERROR: {err}"
        return info

    def get_all_info(self) -> dict:
        info = {}
        info["pjlink_class"] = self.detect_class()
        for key, func in [
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
            val, err = self._safe_query(key, func)
            info[key] = val if val is not None else f"ERROR: {err}"
        self._query_lamp_data(info)
        try:
            info["error_status_parsed"] = self.get_error_status_parsed()
        except PJLinkError:
            pass
        if self.detected_class == "2":
            for key, func in [
                ("software_version", self.get_software_version),
                ("serial_number", self.get_serial_number),
                ("filter_usage", self.get_filter_usage),
                ("input_resolution", self.get_input_resolution),
                ("recommended_resolution", self.get_recommended_resolution),
            ]:
                val, err = self._safe_query(key, func)
                info[key] = val if val is not None else f"ERROR: {err}"
        info["firmware_version"] = self._derive_firmware_version(info)
        return info

    def _query_lamp_data(self, info: dict):
        val, err = self._safe_query("lamp_info_raw", self.get_lamp_info_raw)
        info["lamp_info_raw"] = val if val is not None else f"ERROR: {err}"
        try:
            info["lamp_info"] = self.get_lamp_info_parsed()
        except PJLinkError:
            info["lamp_info"] = []
        try:
            total_int, total_str = self.get_lamp_hours_total()
            info["lamp_hours_total"] = total_int
            info["lamp_hours_total_display"] = total_str
        except PJLinkError:
            info["lamp_hours_total"] = -1
            info["lamp_hours_total_display"] = "N/A"
        try:
            info["lamp_hours_summary"] = self.get_lamp_hours_summary()
        except PJLinkError:
            info["lamp_hours_summary"] = "N/A"

    def _derive_firmware_version(self, info: dict) -> str:
        sver = info.get("software_version", "")
        if sver and isinstance(sver, str) and not sver.startswith("ERROR"):
            return sver
        other = info.get("other_info", "")
        if other and isinstance(other, str) and not other.startswith("ERROR"):
            return other
        return "Not available"

    # -- Diagnostic --

    def run_diagnostic(self) -> dict:
        diag = {
            "host": self.host, "port": self.port,
            "security_enabled": self.security_enabled,
            "random_number": self.random_number, "commands": [],
        }
        tests = [
            ("%1", "CLSS"), ("%1", "POWR"), ("%1", "INF1"), ("%1", "INF2"),
            ("%1", "INFO"), ("%1", "NAME"), ("%1", "LAMP"), ("%1", "ERST"),
            ("%1", "INPT"), ("%1", "INST"), ("%1", "AVMT"),
            ("%2", "SVER"), ("%2", "SNUM"),
        ]
        for header, cmd in tests:
            entry = {"command": f"{header}{cmd} ?", "attempts": []}
            for use_digest in ([True, False] if self.security_enabled else [False]):
                attempt = {
                    "digest": use_digest, "sent_hex": None, "sent_text": None,
                    "recv_hex": None, "recv_text": None, "recv_length": 0,
                    "parsed": None, "error": None,
                }
                packet = self._build_packet(header, cmd, "?", force_digest=use_digest)
                attempt["sent_hex"] = packet.hex(" ")
                attempt["sent_text"] = repr(packet.decode("utf-8", errors="replace"))
                try:
                    self._drain_socket()
                    self._send_raw(packet)
                    time.sleep(0.2)
                    raw = self._receive_raw_line()
                    attempt["recv_hex"] = raw.hex(" ")
                    attempt["recv_text"] = repr(raw.decode("utf-8", errors="replace"))
                    attempt["recv_length"] = len(raw)
                    decoded = raw.decode("utf-8", errors="replace").strip()
                    if decoded:
                        try:
                            attempt["parsed"] = self._parse_response(decoded, cmd)
                        except PJLinkError as e:
                            attempt["parsed"] = f"PARSE_ERROR: {e}"
                        break
                    else:
                        attempt["error"] = "Empty response"
                except PJLinkError as e:
                    attempt["error"] = str(e)
                except Exception as e:
                    attempt["error"] = f"{type(e).__name__}: {e}"
                entry["attempts"].append(attempt)
            diag["commands"].append(entry)
        return diag


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def load_csv(csv_path: str) -> list:
    projectors = []
    csv_file = Path(csv_path)
    if not csv_file.exists():
        log.error(f"CSV not found: {csv_path}")
        sys.exit(1)
    with open(csv_file, "r", encoding="utf-8-sig") as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(f, dialect=dialect)
        if not reader.fieldnames:
            log.error("CSV is empty")
            sys.exit(1)
        col_map = {name.strip().lower(): name for name in reader.fieldnames}
        if "host" not in col_map:
            log.error(f"CSV needs 'host' column. Found: {reader.fieldnames}")
            sys.exit(1)
        for row_num, row in enumerate(reader, start=2):
            host = row.get(col_map["host"], "").strip()
            if not host or host.startswith("#"):
                continue
            port = PJLinkClient.DEFAULT_PORT
            if "port" in col_map:
                port_str = row.get(col_map["port"], "").strip()
                if port_str:
                    try:
                        port = int(port_str)
                    except ValueError:
                        pass
            password = None
            if "password" in col_map:
                password = row.get(col_map["password"], "").strip() or None
            projectors.append({"host": host, "port": port, "password": password})
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
        result["status"] = "auth_error"
        result["error"] = str(e)
        result["firmware_version"] = "AUTH ERROR"
        result["lamp_hours_total"] = -1
        result["lamp_hours_total_display"] = "AUTH ERROR"
        result["lamp_hours_summary"] = "AUTH ERROR"
    except PJLinkError as e:
        result["status"] = "error"
        result["error"] = str(e)
        result["firmware_version"] = "ERROR"
        result["lamp_hours_total"] = -1
        result["lamp_hours_total_display"] = "ERROR"
        result["lamp_hours_summary"] = "ERROR"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {e}"
        result["firmware_version"] = "ERROR"
        result["lamp_hours_total"] = -1
        result["lamp_hours_total_display"] = "ERROR"
        result["lamp_hours_summary"] = "ERROR"
        log.exception(f"[{host}] Unexpected error")
    finally:
        client.disconnect()
    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def save_to_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def truncate_error(error_str, max_len=30):
    if not error_str:
        return ""
    s = str(error_str)
    short_labels = [
        (r"[Cc]onnection timed out",       "Timed out"),
        (r"[Cc]onnection refused",          "Conn refused"),
        (r"[Nn]o response .* timeout",      "No response"),
        (r"[Nn]o route to host",            "No route"),
        (r"[Nn]etwork is unreachable",      "Net unreachable"),
        (r"[Nn]ame or service not known",   "DNS failed"),
        (r"[Nn]etwork error",               "Network error"),
        (r"[Aa]uthentication required",     "Auth required"),
        (r"PJLINK ERRA",                    "Auth failed"),
        (r"ERRA",                           "Auth error"),
        (r"[Nn]ot a PJLink device",         "Not PJLink"),
        (r"[Mm]alformed greeting",          "Bad greeting"),
    ]
    for pattern, label in short_labels:
        if re.search(pattern, s):
            return label
    s = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', '', s)
    s = re.sub(r'\[Errno\s*-?\d+\]\s*', '', s)
    s = re.sub(r'^(Network error|Socket error|Connection error)\s*:\s*', '', s, flags=re.IGNORECASE)
    s = re.sub(r'\s+', ' ', s).strip(': ')
    if not s:
        return "Error"
    if len(s) > max_len:
        return s[:max_len - 3] + "..."
    return s


def print_summary_table(results):
    columns = [
        ("Status",       "status",                  11),
        ("Host",         "host",                    16),
        ("Port",         "port",                     6),
        ("Manufacturer", "manufacturer",            14),
        ("Model",        "product_name",            16),
        ("Firmware",     "firmware_version",        18),
        ("Lamp Hours",   "lamp_hours_total_display", 12),
        ("Class",        "pjlink_class",             7),
        ("Power",        "power_status",            16),
        ("Name",         "projector_name",          16),
        ("Error",        "error",                   20),
    ]

    def clean_val(val):
        s = str(val) if val is not None else ""
        return "" if s in ("None", "-1") else s

    def format_status(r):
        s = r.get("status", "error")
        if s == "success":
            return "\u2713 OK"
        elif s == "auth_error":
            return "\u2717 AUTH ERR"
        return "\u2717 ERROR"

    def get_cell(r, col_key):
        if col_key == "status":
            return format_status(r)
        if col_key == "error":
            return truncate_error(r.get("error", ""))
        val = clean_val(r.get(col_key, ""))
        if val.startswith("ERROR") or val in (
            "Not available", "N/A", "AUTH ERROR", "See diagnostic"
        ):
            return "N/A"
        return val

    col_widths = []
    for header, key, min_w in columns:
        max_w = len(header)
        for r in results:
            max_w = max(max_w, len(get_cell(r, key)))
        col_widths.append(max(min_w, max_w))

    def sep():
        return "+" + "+".join(f"{'-' * (w + 2)}" for w in col_widths) + "+"

    def row(cells):
        return "|" + "|".join(
            f" {c:<{w}} " for c, w in zip(cells, col_widths)
        ) + "|"

    s = sep()
    bw = len(s)

    print()
    print("=" * bw)
    print("PJLink Projector Query Results \u2014 Firmware & Lamp Hours".center(bw))
    print("=" * bw)
    print(s)
    print(row([c[0] for c in columns]))
    print(s)
    for r in results:
        print(row([get_cell(r, c[1]) for c in columns]))
    print(s)

    total = len(results)
    ok = sum(1 for r in results if r["status"] == "success")
    auth = sum(1 for r in results if r["status"] == "auth_error")
    err = total - ok - auth

    lamp_values = [
        r.get("lamp_hours_total", -1) for r in results
        if isinstance(r.get("lamp_hours_total"), int) and r.get("lamp_hours_total", -1) > 0
    ]

    print(f"\nTotal: {total} | Success: {ok} | Auth Errors: {auth} | Failed: {err}")

    if lamp_values:
        avg_l = sum(lamp_values) / len(lamp_values)
        print(
            f"Lamp Hours \u2014 Avg: {avg_l:.0f}h | "
            f"Min: {min(lamp_values)}h | Max: {max(lamp_values)}h | "
            f"Reported: {len(lamp_values)}/{total}"
        )
    else:
        print("Lamp Hours \u2014 No data available")
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

    Run with no arguments to use defaults:
        %(prog)s

CSV Format:
    host,port,password
    192.168.1.100,4352,mypassword
    192.168.1.101,,

Examples:
    %(prog)s
    %(prog)s -i my_projectors.csv
    %(prog)s -o my_results.json
    %(prog)s -i projectors.csv -o results.json --all
    %(prog)s --diagnostic --debug
        """,
    )

    parser.add_argument("-i", "--input", default=DEFAULT_CSV,
                        help=f"Input CSV file (default: {DEFAULT_CSV})")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
                        help=f"Output JSON file (default: {DEFAULT_OUTPUT})")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Timeout per projector in seconds (default: 10)")
    parser.add_argument("--all", action="store_true", help="Query all commands")
    parser.add_argument("--diagnostic", action="store_true",
                        help="Diagnostic: raw hex dump of all commands")
    parser.add_argument("--debug", action="store_true", help="Debug logging")
    parser.add_argument("--no-progress", action="store_true",
                        help="Disable progress bar")

    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    csv_file = args.input
    output_file = args.output

    print("=" * 62)
    print("  PJLink Projector Query (Firmware + Lamp Hours)")
    print("  Class 1 + Class 2 compatible")
    print("=" * 62)
    print(f"  Input:      {csv_file}")
    print(f"  Output:     {output_file}")
    print(f"  Timeout:    {args.timeout}s")
    print(f"  Mode:       {'diagnostic' if args.diagnostic else 'all' if args.all else 'firmware+lamp'}")
    print(f"  Debug:      {args.debug}")
    print("=" * 62)

    projectors = load_csv(csv_file)
    if not projectors:
        log.error("No projectors in CSV.")
        sys.exit(1)

    total = len(projectors)
    log.info(f"Loaded {total} projector(s)")

    # -- Set up progress bar --
    progress = ProgressBar(
        total=total,
        bar_width=30,
        enabled=not args.no_progress and not args.debug,
    )

    # Wire progress bar into the log handler so log lines don't collide
    _handler.progress_bar = progress

    print()  # blank line before progress bar starts

    results = []
    start_time = time.time()

    for i, p in enumerate(projectors, 1):
        host = p["host"]
        port = p["port"]
        auth = "auth" if p["password"] else "no-auth"

        # Update progress bar: show current host being queried
        progress.update(i - 1, f"{host} \u2014 connecting...")

        log.info(f"[{i}/{total}] {host}:{port} ({auth})")

        # Update status to querying
        progress.update(i - 1, f"{host} \u2014 querying...")

        result = query_projector(
            host=host, port=port, password=p["password"],
            timeout=args.timeout, query_all=args.all, diagnostic=args.diagnostic,
        )
        results.append(result)

        # Update progress bar with result
        if result["status"] == "success":
            fw = result.get("firmware_version", "N/A")
            lamp = result.get("lamp_hours_summary", "N/A")
            model = result.get("product_name", "")
            mfr = result.get("manufacturer", "")
            progress.update(i, f"{host} \u2014 \u2713 {mfr} {model}")
            log.info(f"  -> {mfr} {model}")
            log.info(f"     Firmware:   {fw}")
            log.info(f"     Lamp Hours: {lamp}")
        else:
            short_err = truncate_error(result.get("error", ""))
            progress.update(i, f"{host} \u2014 \u2717 {short_err}")
            log.error(f"  -> {result['status']}: {result.get('error')}")

    elapsed = time.time() - start_time
    progress.finish(f"Complete \u2014 {total} devices in {elapsed:.1f}s")

    # Disconnect progress bar from log handler
    _handler.progress_bar = None

    # -- Build output --
    output_data = {
        "query_info": {
            "csv_file": str(Path(csv_file).resolve()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": "PJLink Class 1 + Class 2",
            "mode": (
                "diagnostic" if args.diagnostic
                else "all" if args.all
                else "firmware+lamp"
            ),
            "total": total,
            "success": sum(1 for r in results if r["status"] == "success"),
            "errors": sum(1 for r in results if r["status"] != "success"),
            "elapsed_seconds": round(elapsed, 1),
        },
        "projectors": results,
    }

    save_to_json(output_data, output_file)
    log.info(f"Saved to: {output_file}")

    if not args.diagnostic:
        print_summary_table(results)
    else:
        print("\nDiagnostic data written to:", output_file)

    print(f"Full results: {output_file}")

    if args.diagnostic:
        print("\n" + json.dumps(output_data, indent=2))


if __name__ == "__main__":
    main()
