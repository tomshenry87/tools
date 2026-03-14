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

Lamp response formats handled:
    Class 1:  "2340 1"
    Class 1:  "5432 1 3150 0"
    Class 2:  "Lamp 1: 2340 1"
    Class 2:  "Lamp 1: 5432 1 Lamp 2: 3150 0"

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
from datetime import datetime, timezone
from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pjlink")


class PJLinkError(Exception):
    pass


class PJLinkAuthError(PJLinkError):
    pass


class PJLinkClient:
    """
    PJLink client supporting Class 1 and Class 2.

    Class 1 auth: MD5 digest prepended to EVERY command
    Class 2 auth: MD5 digest prepended to FIRST command only
    """

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

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Raw I/O
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Command building and sending
    # ------------------------------------------------------------------

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
        response = raw.decode("utf-8", errors="replace").strip("\r\n \t")
        return response

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

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(self, raw, expected_cmd) -> str:
        line = raw.strip("\r\n \t")
        log.debug(f"[{self.host}] Parse '{expected_cmd}': {repr(line)}")

        if not line:
            raise PJLinkError(f"Empty response for {expected_cmd}")

        if "PJLINK" in line.upper() and "ERRA" in line.upper():
            raise PJLinkAuthError("PJLINK ERRA")

        # Strategy 1: exact prefix %1CMD= or %2CMD=
        for c in ("1", "2"):
            prefix = f"%{c}{expected_cmd}="
            if prefix in line:
                value = line[line.index(prefix) + len(prefix):]
                return self._check_error(value.strip(), expected_cmd)

        # Strategy 2: case insensitive
        line_upper = line.upper()
        for c in ("1", "2"):
            prefix_upper = f"%{c}{expected_cmd.upper()}="
            if prefix_upper in line_upper:
                idx = line_upper.index(prefix_upper)
                value = line[idx + len(prefix_upper):]
                return self._check_error(value.strip(), expected_cmd)

        # Strategy 3: any %X____= pattern
        match = re.search(r"%([12])([A-Za-z0-9]{4})=(.*)", line)
        if match:
            value = match.group(3).strip()
            actual = match.group(2).upper()
            if actual != expected_cmd.upper():
                log.debug(f"[{self.host}] Got {actual} instead of {expected_cmd}")
            return self._check_error(value, expected_cmd)

        # Strategy 4: find = sign
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

    # ------------------------------------------------------------------
    # Safe query wrapper
    # ------------------------------------------------------------------

    def _safe_query(self, label, func):
        try:
            value = func()
            return value, None
        except PJLinkError as e:
            log.debug(f"[{self.host}] {label}: {e}")
            return None, str(e)

    # ------------------------------------------------------------------
    # Class detection
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Class 1 commands
    # ------------------------------------------------------------------

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
        """LAMP query — returns raw response string."""
        return self._send_command("LAMP", "?", "%1")

    def _normalize_lamp_response(self, raw: str) -> str:
        """
        Normalize lamp response to consistent format.

        Class 2 devices often return:
            "Lamp 1: 2340 1"
            "Lamp 1: 5432 1 Lamp 2: 3150 0"
            "Lamp 1:2340 1"
            "Lamp1: 2340 1"

        Class 1 devices return:
            "2340 1"
            "5432 1 3150 0"

        This method strips all "Lamp N:" prefixes to produce
        a clean "hours status [hours status ...]" string.
        """
        cleaned = raw.strip()

        log.debug(f"[{self.host}] Lamp raw before normalize: {repr(cleaned)}")

        # Remove all variations of "Lamp N:" prefix
        # Handles: "Lamp 1:", "Lamp1:", "Lamp 1 :", "lamp 1:", "LAMP 1:"
        cleaned = re.sub(
            r'[Ll][Aa][Mm][Pp]\s*\d+\s*:\s*',
            '',
            cleaned,
        )

        # Collapse multiple spaces
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()

        log.debug(f"[{self.host}] Lamp after normalize: {repr(cleaned)}")

        return cleaned

    def get_lamp_info_parsed(self) -> list:
        """
        Parse LAMP response into structured data.

        Handles both Class 1 and Class 2 response formats:
            Class 1: "2340 1"  or  "5432 1 3150 0"
            Class 2: "Lamp 1: 2340 1"  or  "Lamp 1: 5432 1 Lamp 2: 3150 0"

        Returns list of dicts:
            [{"lamp": 1, "hours": "1234h", "hours_int": 1234, "on": true, "status": "On"}, ...]
        """
        raw = self.get_lamp_info_raw()

        if raw.startswith("ERROR"):
            return [{"error": raw}]

        # Normalize: strip "Lamp N:" prefixes
        normalized = self._normalize_lamp_response(raw)

        if not normalized:
            log.warning(f"[{self.host}] Lamp response empty after normalization: {repr(raw)}")
            return [{"raw": raw, "error": "Could not parse lamp data"}]

        lamps = []
        tokens = normalized.split()

        i = 0
        lamp_num = 1
        while i < len(tokens):
            hours_str = tokens[i]

            # Parse hours
            try:
                hours_int = int(hours_str)
            except ValueError:
                # Maybe there's a stray non-numeric token, skip it
                log.debug(f"[{self.host}] Skipping non-numeric lamp token: {repr(hours_str)}")
                i += 1
                continue

            # Parse on/off status (next token)
            on = None
            status_str = "Unknown"
            if i + 1 < len(tokens):
                status_token = tokens[i + 1]
                if status_token in ("0", "1"):
                    on = status_token == "1"
                    status_str = "On" if on else "Off"
                    i += 2
                else:
                    # No valid status token, just hours
                    log.debug(
                        f"[{self.host}] No status token for lamp {lamp_num}, "
                        f"got {repr(status_token)}"
                    )
                    i += 1
            else:
                # Last token, no status
                i += 1

            lamps.append({
                "lamp": lamp_num,
                "hours": f"{hours_int}h",
                "hours_int": hours_int,
                "on": on,
                "status": status_str,
            })
            lamp_num += 1

        if not lamps:
            log.warning(f"[{self.host}] Could not parse any lamps from: {repr(raw)}")
            return [{"raw": raw, "error": "Could not parse lamp data"}]

        log.debug(f"[{self.host}] Parsed {len(lamps)} lamp(s): {lamps}")
        return lamps

    def get_lamp_hours_total(self) -> tuple:
        """
        Get total lamp hours across all lamps.

        Returns (total_int, total_string):
            (5432, "5432h")  — success
            (-1, "N/A")     — error
        """
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
        """
        Get human-readable lamp hours summary.

        Single lamp:   "Lamp 1: 2340h (On)"
        Multi lamp:    "Lamp 1: 5432h (On); Lamp 2: 3150h (Off)"
        """
        lamps = self.get_lamp_info_parsed()
        parts = []
        for lamp in lamps:
            if "hours" in lamp:
                status = lamp.get("status", "Unknown")
                parts.append(f"Lamp {lamp['lamp']}: {lamp['hours']} ({status})")
            elif "error" in lamp:
                return lamp["error"]
            elif "raw" in lamp:
                return f"Raw: {lamp['raw']}"

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

    # ------------------------------------------------------------------
    # Class 2 commands
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # High-level queries
    # ------------------------------------------------------------------

    def get_firmware_info(self) -> dict:
        """Query firmware + lamp hours. Auto-detects class."""
        info = {}

        # Step 1: detect class (must be first command)
        info["pjlink_class"] = self.detect_class()

        # Step 2: device identity
        for key, func in [
            ("manufacturer", self.get_manufacturer),
            ("product_name", self.get_product_name),
            ("projector_name", self.get_name),
        ]:
            val, err = self._safe_query(key, func)
            info[key] = val if val is not None else f"ERROR: {err}"

        # Step 3: firmware — always try INFO
        val, err = self._safe_query("other_info", self.get_other_info)
        info["other_info"] = val if val is not None else f"ERROR: {err}"

        # Class 2: also try SVER and SNUM
        if self.detected_class == "2":
            val, err = self._safe_query("software_version", self.get_software_version)
            info["software_version"] = val if val is not None else f"ERROR: {err}"

            val, err = self._safe_query("serial_number", self.get_serial_number)
            info["serial_number"] = val if val is not None else f"ERROR: {err}"

        info["firmware_version"] = self._derive_firmware_version(info)

        # Step 4: lamp hours
        self._query_lamp_data(info)

        # Step 5: power status
        val, err = self._safe_query("power_status", self.get_power_status)
        info["power_status"] = val if val is not None else f"ERROR: {err}"

        return info

    def get_all_info(self) -> dict:
        """Query all available commands."""
        info = {}

        info["pjlink_class"] = self.detect_class()

        class1_queries = [
            ("power_status", self.get_power_status),
            ("manufacturer", self.get_manufacturer),
            ("product_name", self.get_product_name),
            ("projector_name", self.get_name),
            ("other_info", self.get_other_info),
            ("input_current", self.get_input),
            ("input_list", self.get_input_list),
            ("mute_status", self.get_mute_status),
            ("error_status", self.get_error_status),
        ]

        for key, func in class1_queries:
            val, err = self._safe_query(key, func)
            info[key] = val if val is not None else f"ERROR: {err}"

        # Lamp data
        self._query_lamp_data(info)

        # Error status parsed
        try:
            info["error_status_parsed"] = self.get_error_status_parsed()
        except PJLinkError:
            pass

        # Class 2
        if self.detected_class == "2":
            class2_queries = [
                ("software_version", self.get_software_version),
                ("serial_number", self.get_serial_number),
                ("filter_usage", self.get_filter_usage),
                ("input_resolution", self.get_input_resolution),
                ("recommended_resolution", self.get_recommended_resolution),
            ]
            for key, func in class2_queries:
                val, err = self._safe_query(key, func)
                info[key] = val if val is not None else f"ERROR: {err}"

        info["firmware_version"] = self._derive_firmware_version(info)

        return info

    def _query_lamp_data(self, info: dict):
        """Query and populate all lamp-related fields in info dict."""
        # Raw lamp response
        val, err = self._safe_query("lamp_info_raw", self.get_lamp_info_raw)
        info["lamp_info_raw"] = val if val is not None else f"ERROR: {err}"

        # Parsed lamp data
        try:
            info["lamp_info"] = self.get_lamp_info_parsed()
        except PJLinkError:
            info["lamp_info"] = []

        # Total hours
        try:
            total_int, total_str = self.get_lamp_hours_total()
            info["lamp_hours_total"] = total_int
            info["lamp_hours_total_display"] = total_str
        except PJLinkError:
            info["lamp_hours_total"] = -1
            info["lamp_hours_total_display"] = "N/A"

        # Summary string
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

    # ------------------------------------------------------------------
    # Diagnostic
    # ------------------------------------------------------------------

    def run_diagnostic(self) -> dict:
        diag = {
            "host": self.host,
            "port": self.port,
            "security_enabled": self.security_enabled,
            "random_number": self.random_number,
            "commands": [],
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
                    "digest": use_digest,
                    "sent_hex": None, "sent_text": None,
                    "recv_hex": None, "recv_text": None,
                    "recv_length": 0, "parsed": None, "error": None,
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
        "host": host,
        "port": port,
        "query_timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "success",
        "error": None,
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
            info = client.get_all_info()
            result.update(info)
        else:
            info = client.get_firmware_info()
            result.update(info)

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


def print_summary_table(results):
    w = {
        "host": 22, "mfr": 15, "model": 18,
        "fw": 22, "lamp": 22, "cls": 6, "pwr": 12, "status": 10,
    }
    total_w = sum(w.values()) + len(w) - 1

    header = (
        f"{'HOST':<{w['host']}} "
        f"{'MANUFACTURER':<{w['mfr']}} "
        f"{'MODEL':<{w['model']}} "
        f"{'FIRMWARE':<{w['fw']}} "
        f"{'LAMP HOURS':<{w['lamp']}} "
        f"{'CLASS':<{w['cls']}} "
        f"{'POWER':<{w['pwr']}} "
        f"{'STATUS':<{w['status']}}"
    )

    print("\n" + "=" * total_w)
    print(header)
    print("-" * total_w)

    for r in results:
        def clean(v, n):
            s = str(v or "N/A")
            if s.startswith("ERROR") or s in ("Not available", "-1", "N/A"):
                return "N/A"
            return s[:n]

        # Lamp display: use total_display with h suffix, fallback to summary
        lamp_display = r.get("lamp_hours_total_display", "N/A")
        if lamp_display in ("N/A", "ERROR", "AUTH ERROR", "See diagnostic", None):
            lamp_display = clean(r.get("lamp_hours_summary"), w["lamp"])
        else:
            lamp_display = str(lamp_display)[:w["lamp"]]

        print(
            f"{clean(r.get('host'), w['host']):<{w['host']}} "
            f"{clean(r.get('manufacturer'), w['mfr']):<{w['mfr']}} "
            f"{clean(r.get('product_name'), w['model']):<{w['model']}} "
            f"{clean(r.get('firmware_version'), w['fw']):<{w['fw']}} "
            f"{lamp_display:<{w['lamp']}} "
            f"{clean(r.get('pjlink_class'), w['cls']):<{w['cls']}} "
            f"{clean(r.get('power_status'), w['pwr']):<{w['pwr']}} "
            f"{str(r.get('status', ''))[:w['status']]:<{w['status']}}"
        )

    print("=" * total_w)

    total = len(results)
    ok = sum(1 for r in results if r["status"] == "success")
    auth = sum(1 for r in results if r["status"] == "auth_error")
    err = total - ok - auth

    # Lamp stats
    lamp_values = [
        r.get("lamp_hours_total", -1)
        for r in results
        if isinstance(r.get("lamp_hours_total"), int) and r.get("lamp_hours_total", -1) > 0
    ]
    if lamp_values:
        avg_lamp = sum(lamp_values) / len(lamp_values)
        lamp_stats = (
            f"Lamp Hours — "
            f"Avg: {avg_lamp:.0f}h | "
            f"Min: {min(lamp_values)}h | "
            f"Max: {max(lamp_values)}h | "
            f"Reported: {len(lamp_values)}/{total}"
        )
    else:
        lamp_stats = "Lamp Hours — No data available"

    print(f"\nDevices: {total} | Success: {ok} | Auth Errors: {auth} | Other Errors: {err}")
    print(lamp_stats)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="PJLink projector firmware & lamp hours query (Class 1 + 2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
CSV Format:
    host,port,password
    192.168.1.100,4352,mypassword
    192.168.1.101,,

Output includes:
    firmware_version       — from INFO (Class 1) or SVER (Class 2)
    lamp_hours_total       — total hours as integer
    lamp_hours_total_display — total hours with "h" suffix (e.g. "5432h")
    lamp_hours_summary     — per-lamp breakdown (e.g. "Lamp 1: 5432h (On)")
    lamp_info              — structured per-lamp data with hours_int and hours

Examples:
    %(prog)s projectors.csv
    %(prog)s projectors.csv -o results.json --all
    %(prog)s projectors.csv --diagnostic --debug
        """,
    )

    parser.add_argument("csv_file", help="CSV file with projector hosts")
    parser.add_argument("-o", "--output", default="projector_firmware.json")
    parser.add_argument("-t", "--timeout", type=int, default=10)
    parser.add_argument("--all", action="store_true", help="Query all commands")
    parser.add_argument("--diagnostic", action="store_true",
                        help="Diagnostic: raw hex dump of all commands")
    parser.add_argument("--debug", action="store_true", help="Debug logging")

    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    print("=" * 62)
    print("  PJLink Projector Query (Firmware + Lamp Hours)")
    print("  Class 1 + Class 2 compatible")
    print("=" * 62)
    print(f"  CSV:        {args.csv_file}")
    print(f"  Output:     {args.output}")
    print(f"  Timeout:    {args.timeout}s")
    print(f"  Mode:       {'diagnostic' if args.diagnostic else 'all' if args.all else 'firmware+lamp'}")
    print(f"  Debug:      {args.debug}")
    print("=" * 62)

    projectors = load_csv(args.csv_file)
    if not projectors:
        log.error("No projectors in CSV.")
        sys.exit(1)

    log.info(f"Loaded {len(projectors)} projector(s)\n")

    results = []

    for i, p in enumerate(projectors, 1):
        auth = "auth" if p["password"] else "no-auth"
        log.info(f"[{i}/{len(projectors)}] {p['host']}:{p['port']} ({auth})")

        result = query_projector(
            host=p["host"],
            port=p["port"],
            password=p["password"],
            timeout=args.timeout,
            query_all=args.all,
            diagnostic=args.diagnostic,
        )
        results.append(result)

        if result["status"] == "success":
            fw = result.get("firmware_version", "N/A")
            lamp = result.get("lamp_hours_summary", "N/A")
            model = result.get("product_name", "")
            mfr = result.get("manufacturer", "")
            log.info(f"  -> {mfr} {model}")
            log.info(f"     Firmware:   {fw}")
            log.info(f"     Lamp Hours: {lamp}")
        else:
            log.error(f"  -> {result['status']}: {result.get('error')}")

    # Build output
    output_data = {
        "query_info": {
            "csv_file": str(Path(args.csv_file).resolve()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": "PJLink Class 1 + Class 2",
            "mode": (
                "diagnostic" if args.diagnostic
                else "all" if args.all
                else "firmware+lamp"
            ),
            "total": len(results),
            "success": sum(1 for r in results if r["status"] == "success"),
            "errors": sum(1 for r in results if r["status"] != "success"),
        },
        "projectors": results,
    }

    save_to_json(output_data, args.output)
    log.info(f"Saved to: {args.output}")

    if not args.diagnostic:
        print_summary_table(results)
    else:
        print("\nDiagnostic data written to:", args.output)

    print(f"\nFull results: {args.output}")

    if args.diagnostic:
        print("\n" + json.dumps(output_data, indent=2))


if __name__ == "__main__":
    main()
