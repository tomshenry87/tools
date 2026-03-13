#!/usr/bin/env python3
"""
PJLink Class 1 Projector Information Retriever (CSV Batch Mode)

Strictly follows PJLink v1.00 (Class 1) specification:
    https://pjlink.jbmia.or.jp/english/data/5-1_PJLink_eng_20131210.pdf

Protocol summary:
    - TCP port 4352
    - Command:  %1<CMD> <param>\r
    - Response: %1<CMD>=<value>\r
    - Query:    parameter is "?"
    - Auth:     MD5(random_number + password) prepended to command

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
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pjlink")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class PJLinkError(Exception):
    """PJLink communication or protocol error."""
    pass


class PJLinkAuthError(PJLinkError):
    """Authentication error (ERRA)."""
    pass


# ---------------------------------------------------------------------------
# PJLink Class 1 Client
# ---------------------------------------------------------------------------
class PJLinkClient:
    """
    PJLink Class 1 client.

    Implements the command set defined in PJLink v1.00 specification
    sections 3 (communication protocol) and 4 (command definitions).

    Connection flow (spec section 3):
        1. Client connects to TCP port 4352
        2. Projector sends greeting:
             No auth:   "PJLINK 0\r"
             With auth:  "PJLINK 1 <random>\r"
        3. Client sends commands:
             No auth:   "%1<CMD> <param>\r"
             With auth:  "<md5digest>%1<CMD> <param>\r"
        4. Projector responds:
             Success:   "%1<CMD>=<value>\r"
             Error:     "%1<CMD>=ERRx\r"
             Auth fail: "PJLINK ERRA\r"
    """

    # Spec: TCP port 4352
    DEFAULT_PORT = 4352

    # Spec section 3: max password length is 32 bytes
    MAX_PASSWORD_LENGTH = 32

    # Reasonable buffer / timeout
    BUFFER_SIZE = 4096
    DEFAULT_TIMEOUT = 10

    # ------------------------------------------------------------------
    # PJLink Class 1 commands  (spec section 4)
    # Header is always "%1" for class 1.
    # Query parameter is always "?".
    # Command body is 4 upper-case ASCII characters.
    # ------------------------------------------------------------------
    # Spec 4.1  – Power control
    CMD_POWR = "POWR"
    # Spec 4.2  – Input switch
    CMD_INPT = "INPT"
    # Spec 4.3  – Mute
    CMD_AVMT = "AVMT"
    # Spec 4.4  – Error status
    CMD_ERST = "ERST"
    # Spec 4.5  – Lamp information
    CMD_LAMP = "LAMP"
    # Spec 4.6  – Input terminal list
    CMD_INST = "INST"
    # Spec 4.7  – Projector name
    CMD_NAME = "NAME"
    # Spec 4.8  – Manufacture name
    CMD_INF1 = "INF1"
    # Spec 4.9  – Product name
    CMD_INF2 = "INF2"
    # Spec 4.10 – Other information
    CMD_INFO = "INFO"
    # Spec 4.11 – Class information
    CMD_CLSS = "CLSS"

    # Spec 4.1: power status response values
    POWER_STATES = {
        "0": "Standby",
        "1": "Lamp On",
        "2": "Cooling",
        "3": "Warm-up",
    }

    # Spec section 3: error response codes
    ERROR_CODES = {
        "ERR1": "Undefined command",
        "ERR2": "Out of parameter",
        "ERR3": "Unavailable time",
        "ERR4": "Projector/Display failure",
    }

    # Spec 4.4: error status byte positions
    ERST_POSITIONS = [
        "fan",
        "lamp",
        "temperature",
        "cover_open",
        "filter",
        "other",
    ]
    ERST_VALUES = {
        "0": "OK",
        "1": "Warning",
        "2": "Error",
    }

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        password: str = None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.socket = None
        self.security_enabled = False
        self.random_number = None

        # Spec section 3: password must be <=32 bytes
        if self.password and len(self.password.encode("utf-8")) > self.MAX_PASSWORD_LENGTH:
            raise PJLinkError(
                f"Password exceeds maximum length of {self.MAX_PASSWORD_LENGTH} bytes"
            )

    # ------------------------------------------------------------------
    # Connection management  (spec section 3)
    # ------------------------------------------------------------------

    def connect(self):
        """
        Connect to the projector and process the greeting.

        Spec section 3:
            Projector sends one of:
                "PJLINK 0\r"                – security disabled
                "PJLINK 1 <random number>\r" – security enabled
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.host, self.port))

            greeting = self._receive_line()
            log.debug(f"[{self.host}] Greeting raw: {repr(greeting)}")
            self._parse_greeting(greeting)

        except socket.timeout:
            raise PJLinkError(
                f"Connection timed out: {self.host}:{self.port}"
            )
        except ConnectionRefusedError:
            raise PJLinkError(
                f"Connection refused: {self.host}:{self.port}"
            )
        except OSError as e:
            raise PJLinkError(
                f"Network error: {self.host}:{self.port}: {e}"
            )

    def _parse_greeting(self, greeting: str):
        """
        Parse PJLink greeting per spec section 3.

        Format:
            "PJLINK 0\r"                 – no authentication
            "PJLINK 1 <random number>\r" – authentication required
                random number: 8-byte random number (hex-like string)
        """
        line = greeting.strip()

        if not line.startswith("PJLINK"):
            raise PJLinkError(f"Invalid greeting (not PJLink): {repr(line)}")

        parts = line.split(None, 2)  # split on whitespace, max 3 parts

        if len(parts) < 2:
            raise PJLinkError(f"Malformed greeting: {repr(line)}")

        security_flag = parts[1]

        if security_flag == "0":
            # Spec: security disabled
            self.security_enabled = False
            log.debug(f"[{self.host}] Security disabled")

        elif security_flag == "1":
            # Spec: security enabled, third token is random number
            if len(parts) < 3:
                raise PJLinkError(
                    f"Auth greeting missing random number: {repr(line)}"
                )
            self.security_enabled = True
            self.random_number = parts[2]
            log.debug(
                f"[{self.host}] Security enabled, random: {self.random_number}"
            )

            if not self.password:
                raise PJLinkError(
                    "Projector requires authentication but no password provided."
                )

        elif security_flag == "ERRA":
            raise PJLinkAuthError("Authentication error in greeting (ERRA).")

        else:
            raise PJLinkError(f"Unknown security flag: {repr(line)}")

    def disconnect(self):
        """Close the TCP connection."""
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass
            finally:
                self.socket = None

    # ------------------------------------------------------------------
    # Low-level I/O
    # ------------------------------------------------------------------

    def _receive_line(self) -> str:
        """
        Read one line from the socket, terminated by CR (\\r).

        Spec section 3: all messages are terminated with CR (0x0D).
        """
        if not self.socket:
            raise PJLinkError("Not connected.")

        data = b""
        try:
            while True:
                byte = self.socket.recv(1)
                if not byte:
                    # Connection closed
                    break
                data += byte
                if byte == b"\r":
                    break
                # Safety: some devices may append LF after CR
                if byte == b"\n" and data.endswith(b"\r\n"):
                    break
                if len(data) > self.BUFFER_SIZE:
                    log.warning(f"[{self.host}] Response exceeded buffer, truncating")
                    break
        except socket.timeout:
            if data:
                log.debug(
                    f"[{self.host}] Timeout mid-receive, partial: {repr(data)}"
                )
            else:
                raise PJLinkError(f"Timeout receiving data from {self.host}")

        decoded = data.decode("utf-8", errors="replace")
        return decoded

    def _build_command(self, cmd_body: str, parameter: str = "?") -> bytes:
        """
        Build a PJLink Class 1 command packet.

        Spec section 3:
            Without auth: %1<CMD> <param>\r
            With auth:    <md5digest>%1<CMD> <param>\r

            md5digest = MD5(random_number + password)  (32 hex chars)
            Header:     "%1"  (class 1)
            Body:       4 upper-case characters
            Separator:  " " (0x20)
            Parameter:  command-dependent
            Terminator: CR (0x0D)
        """
        # Build the command string: %1<CMD> <param>\r
        command_str = f"%1{cmd_body} {parameter}\r"

        if self.security_enabled:
            # Spec section 3: MD5 hash of (random number + password)
            digest_input = f"{self.random_number}{self.password}"
            md5_hash = hashlib.md5(digest_input.encode("utf-8")).hexdigest()
            command_str = f"{md5_hash}{command_str}"

        log.debug(f"[{self.host}] TX: {repr(command_str)}")
        return command_str.encode("utf-8")

    def _send_command(self, cmd_body: str, parameter: str = "?") -> str:
        """
        Send a command and return the parsed response value.

        Returns the value portion of the response after "=".
        Raises PJLinkError on protocol or communication errors.
        """
        if not self.socket:
            raise PJLinkError("Not connected.")

        packet = self._build_command(cmd_body, parameter)

        try:
            self.socket.sendall(packet)
            response = self._receive_line()
            log.debug(f"[{self.host}] RX: {repr(response)}")
            return self._parse_response(response, cmd_body)

        except socket.timeout:
            raise PJLinkError(f"Timeout waiting for {cmd_body} response")
        except OSError as e:
            raise PJLinkError(f"Socket error during {cmd_body}: {e}")

    # ------------------------------------------------------------------
    # Response parsing  (spec section 3)
    # ------------------------------------------------------------------

    def _parse_response(self, raw: str, expected_cmd: str) -> str:
        """
        Parse a PJLink response and extract the value.

        Spec section 3 – response format:
            "%1<CMD>=<response data>\r"

        Error responses:
            "%1<CMD>=ERR1\r"  – Undefined command
            "%1<CMD>=ERR2\r"  – Out of parameter
            "%1<CMD>=ERR3\r"  – Unavailable time
            "%1<CMD>=ERR4\r"  – Projector/display failure

        Authorization error (not command-specific):
            "PJLINK ERRA\r"
        """
        # Strip whitespace and terminators
        line = raw.strip("\r\n \t")

        log.debug(f"[{self.host}] Parsing for {expected_cmd}: {repr(line)}")

        if not line:
            raise PJLinkError(f"Empty response for {expected_cmd}")

        # --- Check for authorization error (spec section 3) ---
        # "PJLINK ERRA\r" can come as response to any command
        if "PJLINK" in line and "ERRA" in line:
            raise PJLinkAuthError(
                "Authorization error (PJLINK ERRA). Check password."
            )

        # --- Standard response parsing ---
        # Expected: %1<CMD>=<value>
        # The "=" separates command from response data

        # Strategy 1: exact match  %1<CMD>=<value>
        expected_prefix = f"%1{expected_cmd}="
        if expected_prefix in line:
            idx = line.index(expected_prefix)
            value = line[idx + len(expected_prefix):]
            value = value.strip()
            return self._check_error_code(value, expected_cmd)

        # Strategy 2: case-insensitive match
        line_upper = line.upper()
        prefix_upper = expected_prefix.upper()
        if prefix_upper in line_upper:
            idx = line_upper.index(prefix_upper)
            value = line[idx + len(expected_prefix):]
            value = value.strip()
            return self._check_error_code(value, expected_cmd)

        # Strategy 3: match any %1____= pattern
        # Handles cases where projector might echo differently
        match = re.search(r"%1([A-Za-z0-9]{4})=(.*)", line)
        if match:
            actual_cmd = match.group(1).upper()
            value = match.group(2).strip()
            log.warning(
                f"[{self.host}] Expected {expected_cmd}, "
                f"got {actual_cmd} in response: {repr(line)}"
            )
            return self._check_error_code(value, expected_cmd)

        # Strategy 4: find '=' and take everything after it
        # Some projectors may have non-standard framing
        if "=" in line:
            _, _, value = line.partition("=")
            value = value.strip()
            if value:
                log.warning(
                    f"[{self.host}] Fallback parse for {expected_cmd}: "
                    f"found value after '=': {repr(value)}"
                )
                return self._check_error_code(value, expected_cmd)

        # Nothing worked
        raise PJLinkError(
            f"Cannot parse {expected_cmd} response: {repr(raw)}"
        )

    def _check_error_code(self, value: str, cmd: str) -> str:
        """
        Check if value is a PJLink error code (spec section 3).

        ERR1 – Undefined command
        ERR2 – Out of parameter
        ERR3 – Unavailable time
        ERR4 – Projector/Display failure
        """
        upper = value.strip().upper()
        if upper in self.ERROR_CODES:
            desc = self.ERROR_CODES[upper]
            log.warning(f"[{self.host}] {cmd} returned {upper}: {desc}")
            return f"ERROR: {desc} ({upper})"
        return value

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def _safe_query(self, label: str, query_func) -> tuple:
        """Run a query safely, returns (value, error_string_or_None)."""
        try:
            value = query_func()
            return value, None
        except PJLinkError as e:
            log.debug(f"[{self.host}] {label} failed: {e}")
            return None, str(e)

    # ------------------------------------------------------------------
    # Command implementations  (spec section 4)
    # ------------------------------------------------------------------

    def get_power_status(self) -> str:
        """
        Spec 4.1: POWR – Power control (query).

        Query:    %1POWR ?\r
        Response: %1POWR=<status>\r
            0 = Standby
            1 = Lamp on
            2 = Cooling
            3 = Warm-up
        """
        value = self._send_command(self.CMD_POWR)
        if value.startswith("ERROR"):
            return value
        return self.POWER_STATES.get(value, f"Unknown ({value})")

    def get_input(self) -> str:
        """
        Spec 4.2: INPT – Input switch (query).

        Query:    %1INPT ?\r
        Response: %1INPT=<input type><input number>\r
            Input type: 1=RGB, 2=VIDEO, 3=DIGITAL, 4=STORAGE, 5=NETWORK
        """
        return self._send_command(self.CMD_INPT)

    def get_mute_status(self) -> str:
        """
        Spec 4.3: AVMT – AV mute (query).

        Query:    %1AVMT ?\r
        Response: %1AVMT=<setting>\r
            11=Video mute on, 21=Audio mute on, 31=AV mute on
            10=Video mute off, 20=Audio mute off, 30=AV mute off
        """
        return self._send_command(self.CMD_AVMT)

    def get_error_status(self) -> str:
        """
        Spec 4.4: ERST – Error status query.

        Query:    %1ERST ?\r
        Response: %1ERST=<6 bytes>\r
            Byte positions: Fan, Lamp, Temperature, Cover open, Filter, Other
            Values: 0=OK, 1=Warning, 2=Error
        """
        return self._send_command(self.CMD_ERST)

    def get_error_status_parsed(self) -> dict:
        """Parse ERST response into a structured dict."""
        raw = self.get_error_status()
        if raw.startswith("ERROR"):
            return {"raw": raw}

        result = {"raw": raw}
        for i, name in enumerate(self.ERST_POSITIONS):
            if i < len(raw):
                code = raw[i]
                result[name] = self.ERST_VALUES.get(code, f"Unknown ({code})")
            else:
                result[name] = "N/A"
        return result

    def get_lamp_info(self) -> str:
        """
        Spec 4.5: LAMP – Lamp number / lighting hour query.

        Query:    %1LAMP ?\r
        Response: %1LAMP=<cumulative hours> <on/off>[<SP><hours><SP><on/off>...]\r
            on/off: 0=off, 1=on
            Multiple lamps separated by spaces.
        """
        return self._send_command(self.CMD_LAMP)

    def get_lamp_info_parsed(self) -> list:
        """Parse LAMP response into a list of lamp dicts."""
        raw = self.get_lamp_info()
        if raw.startswith("ERROR"):
            return [{"raw": raw}]

        lamps = []
        # Format: "hours1 status1 hours2 status2 ..."
        tokens = raw.split()
        for i in range(0, len(tokens) - 1, 2):
            try:
                hours = int(tokens[i])
                status = "On" if tokens[i + 1] == "1" else "Off"
                lamps.append({
                    "lamp_number": (i // 2) + 1,
                    "hours": hours,
                    "status": status,
                })
            except (ValueError, IndexError):
                lamps.append({"raw": " ".join(tokens[i:i + 2])})
        return lamps if lamps else [{"raw": raw}]

    def get_input_list(self) -> str:
        """
        Spec 4.6: INST – Input terminal list query.

        Query:    %1INST ?\r
        Response: %1INST=<input1> <input2> ...\r
        """
        return self._send_command(self.CMD_INST)

    def get_name(self) -> str:
        """
        Spec 4.7: NAME – Projector name query.

        Query:    %1NAME ?\r
        Response: %1NAME=<name (max 64 bytes)>\r
        """
        return self._send_command(self.CMD_NAME)

    def get_manufacturer(self) -> str:
        """
        Spec 4.8: INF1 – Manufacture name information query.

        Query:    %1INF1 ?\r
        Response: %1INF1=<manufacturer name (max 32 bytes)>\r
        """
        return self._send_command(self.CMD_INF1)

    def get_product_name(self) -> str:
        """
        Spec 4.9: INF2 – Product name information query.

        Query:    %1INF2 ?\r
        Response: %1INF2=<product name (max 32 bytes)>\r
        """
        return self._send_command(self.CMD_INF2)

    def get_other_info(self) -> str:
        """
        Spec 4.10: INFO – Other information query.

        Query:    %1INFO ?\r
        Response: %1INFO=<other info (max 32 bytes)>\r

        Note: This is the primary field where firmware version
        information is found in Class 1 devices, as the spec
        does not define a dedicated firmware version command.
        """
        return self._send_command(self.CMD_INFO)

    def get_class(self) -> str:
        """
        Spec 4.11: CLSS – Class information query.

        Query:    %1CLSS ?\r
        Response: %1CLSS=<class number>\r
            "1" for Class 1
        """
        return self._send_command(self.CMD_CLSS)

    # ------------------------------------------------------------------
    # High-level queries
    # ------------------------------------------------------------------

    def get_all_info(self) -> dict:
        """Query all Class 1 information commands."""
        info = {}

        queries = [
            ("pjlink_class", self.get_class),
            ("power_status", self.get_power_status),
            ("manufacturer", self.get_manufacturer),
            ("product_name", self.get_product_name),
            ("projector_name", self.get_name),
            ("other_info", self.get_other_info),
            ("input_current", self.get_input),
            ("input_list", self.get_input_list),
            ("mute_status", self.get_mute_status),
            ("lamp_info", self.get_lamp_info),
            ("error_status", self.get_error_status),
        ]

        for key, func in queries:
            value, error = self._safe_query(key, func)
            info[key] = value if value is not None else f"ERROR: {error}"

        # Parse structured data
        try:
            info["lamp_info_parsed"] = self.get_lamp_info_parsed()
        except PJLinkError:
            pass

        try:
            info["error_status_parsed"] = self.get_error_status_parsed()
        except PJLinkError:
            pass

        # Derive firmware version from available data
        info["firmware_version"] = self._derive_firmware_version(info)

        return info

    def get_firmware_info(self) -> dict:
        """Query only the commands relevant to identifying firmware."""
        info = {}

        queries = [
            ("pjlink_class", self.get_class),
            ("manufacturer", self.get_manufacturer),
            ("product_name", self.get_product_name),
            ("other_info", self.get_other_info),
        ]

        for key, func in queries:
            value, error = self._safe_query(key, func)
            info[key] = value if value is not None else f"ERROR: {error}"

        info["firmware_version"] = self._derive_firmware_version(info)

        return info

    def _derive_firmware_version(self, info: dict) -> str:
        """
        Derive firmware version from available Class 1 data.

        PJLink Class 1 does not have a dedicated firmware version command.
        The INFO command (spec 4.10 "Other information") is the field
        where manufacturers typically store firmware version information.
        """
        other_info = info.get("other_info", "")
        if other_info and not str(other_info).startswith("ERROR"):
            return other_info

        return "Not available (INFO field empty or errored)"


# ---------------------------------------------------------------------------
# CSV loading
# ---------------------------------------------------------------------------

def load_csv(csv_path: str) -> list:
    """
    Load projector list from CSV file.

    Required column: host
    Optional columns: port, password
    """
    projectors = []
    csv_file = Path(csv_path)

    if not csv_file.exists():
        log.error(f"CSV file not found: {csv_path}")
        sys.exit(1)

    with open(csv_file, "r", encoding="utf-8-sig") as f:
        # Auto-detect delimiter
        sample = f.read(4096)
        f.seek(0)

        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(f, dialect=dialect)

        if not reader.fieldnames:
            log.error("CSV file is empty or has no header row.")
            sys.exit(1)

        # Normalize column names
        original_to_clean = {name: name.strip().lower() for name in reader.fieldnames}
        clean_to_original = {v: k for k, v in original_to_clean.items()}

        log.debug(f"CSV columns: {reader.fieldnames}")

        if "host" not in clean_to_original:
            log.error(f"CSV must have a 'host' column. Found: {reader.fieldnames}")
            sys.exit(1)

        host_col = clean_to_original["host"]
        port_col = clean_to_original.get("port")
        pass_col = clean_to_original.get("password")

        for row_num, row in enumerate(reader, start=2):
            host = row.get(host_col, "").strip()

            if not host or host.startswith("#"):
                continue

            port = PJLinkClient.DEFAULT_PORT
            if port_col:
                port_str = row.get(port_col, "").strip()
                if port_str:
                    try:
                        port = int(port_str)
                    except ValueError:
                        log.warning(
                            f"Row {row_num}: invalid port '{port_str}', using 4352"
                        )

            password = None
            if pass_col:
                password = row.get(pass_col, "").strip() or None

            projectors.append({
                "host": host,
                "port": port,
                "password": password,
            })

    return projectors


# ---------------------------------------------------------------------------
# Projector query
# ---------------------------------------------------------------------------

def query_projector(
    host: str,
    port: int,
    password: str,
    timeout: int,
    query_all: bool,
) -> dict:
    """Query a single projector and return a result dict."""
    result = {
        "host": host,
        "port": port,
        "query_timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "success",
        "error": None,
    }

    client = PJLinkClient(
        host=host,
        port=port,
        password=password,
        timeout=timeout,
    )

    try:
        client.connect()

        if query_all:
            info = client.get_all_info()
        else:
            info = client.get_firmware_info()

        result.update(info)

    except PJLinkAuthError as e:
        result["status"] = "auth_error"
        result["error"] = str(e)
        result["firmware_version"] = "ERROR"

    except PJLinkError as e:
        result["status"] = "error"
        result["error"] = str(e)
        result["firmware_version"] = "ERROR"

    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Unexpected: {type(e).__name__}: {e}"
        result["firmware_version"] = "ERROR"
        log.exception(f"[{host}] Unexpected error")

    finally:
        client.disconnect()

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def save_to_json(data, output_file: str):
    """Write data to a JSON file."""
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def print_summary_table(results: list):
    """Print a formatted summary table."""
    col_w = {
        "host": 25,
        "mfr": 18,
        "model": 20,
        "fw": 24,
        "status": 12,
    }

    header = (
        f"{'HOST':<{col_w['host']}} "
        f"{'MANUFACTURER':<{col_w['mfr']}} "
        f"{'MODEL':<{col_w['model']}} "
        f"{'FIRMWARE / OTHER INFO':<{col_w['fw']}} "
        f"{'STATUS':<{col_w['status']}}"
    )
    line_len = sum(col_w.values()) + len(col_w) - 1

    print("\n" + "=" * line_len)
    print(header)
    print("-" * line_len)

    for r in results:
        def clean(val, max_len):
            s = str(val or "N/A")
            if s.startswith("ERROR") or s.startswith("Not available"):
                s = "N/A"
            return s[: max_len]

        host = str(r.get("host", "N/A"))[: col_w["host"]]
        mfr = clean(r.get("manufacturer"), col_w["mfr"])
        model = clean(r.get("product_name"), col_w["model"])
        fw = clean(r.get("firmware_version"), col_w["fw"])
        status = str(r.get("status", "N/A"))[: col_w["status"]]

        print(
            f"{host:<{col_w['host']}} "
            f"{mfr:<{col_w['mfr']}} "
            f"{model:<{col_w['model']}} "
            f"{fw:<{col_w['fw']}} "
            f"{status:<{col_w['status']}}"
        )

    print("=" * line_len)

    total = len(results)
    ok = sum(1 for r in results if r.get("status") == "success")
    auth_err = sum(1 for r in results if r.get("status") == "auth_error")
    err = total - ok - auth_err
    print(f"\nTotal: {total} | Success: {ok} | Auth Errors: {auth_err} | Other Errors: {err}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Query projector firmware/info via PJLink Class 1 (v1.00) "
            "from a CSV file."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
CSV Format (header row required):
    host,port,password
    192.168.1.100,4352,mypassword
    192.168.1.101,,
    projector3.local,,

    - 'host' column is required
    - 'port' is optional (default: 4352)
    - 'password' is optional (blank = no auth)

Note on firmware version:
    PJLink Class 1 does not define a dedicated firmware version command.
    The INFO command (section 4.10 "Other information") is used, as this
    is where most manufacturers store firmware version data.

Examples:
    %(prog)s projectors.csv
    %(prog)s projectors.csv -o results.json
    %(prog)s projectors.csv --all
    %(prog)s projectors.csv --debug
        """,
    )

    parser.add_argument(
        "csv_file",
        help="CSV file with projector hosts and passwords",
    )
    parser.add_argument(
        "-o", "--output",
        default="projector_firmware.json",
        help="Output JSON file (default: projector_firmware.json)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="Timeout per projector in seconds (default: 10)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Query all Class 1 commands (not just firmware-related)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging (shows raw protocol data)",
    )

    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    print("=" * 62)
    print("  PJLink Class 1 (v1.00) Projector Firmware Query")
    print("=" * 62)
    print(f"  CSV Input:   {args.csv_file}")
    print(f"  JSON Output: {args.output}")
    print(f"  Timeout:     {args.timeout}s")
    print(f"  Query All:   {args.all}")
    print(f"  Debug:       {args.debug}")
    print("=" * 62)

    # Load CSV
    log.info(f"Loading CSV: {args.csv_file}")
    projectors = load_csv(args.csv_file)

    if not projectors:
        log.error("No valid projector entries found in CSV.")
        sys.exit(1)

    log.info(f"Found {len(projectors)} projector(s) to query.\n")

    # Query each projector
    results = []

    for i, proj in enumerate(projectors, start=1):
        host = proj["host"]
        port = proj["port"]
        password = proj["password"]

        auth_note = "with auth" if password else "no auth"
        log.info(f"[{i}/{len(projectors)}] {host}:{port} ({auth_note})")

        result = query_projector(
            host=host,
            port=port,
            password=password,
            timeout=args.timeout,
            query_all=args.all,
        )
        results.append(result)

        if result["status"] == "success":
            fw = result.get("firmware_version", "N/A")
            mfr = result.get("manufacturer", "")
            model = result.get("product_name", "")
            log.info(f"  -> {mfr} {model} | Firmware/Info: {fw}")
        else:
            log.error(f"  -> {result['status']}: {result.get('error')}")

    # Build output document
    output_data = {
        "query_info": {
            "csv_file": str(Path(args.csv_file).resolve()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": "PJLink Class 1 v1.00",
            "spec_document": "5-1_PJLink_eng_20131210.pdf",
            "total_projectors": len(results),
            "successful": sum(1 for r in results if r["status"] == "success"),
            "errors": sum(1 for r in results if r["status"] != "success"),
        },
        "projectors": results,
    }

    # Save
    save_to_json(output_data, args.output)
    log.info(f"Results saved to: {args.output}")

    # Summary
    print_summary_table(results)

    print(f"\nJSON output written to: {args.output}")


if __name__ == "__main__":
    main()
