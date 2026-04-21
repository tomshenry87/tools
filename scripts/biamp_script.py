#!/usr/bin/env python3
"""
Biamp Tesira Firmware / Device Info Query Tool

Uses the Tesira Text Protocol (TTP) over raw TCP (default port 23).
Commands issued per device:
  DEVICE get version          -> firmware version string
  DEVICE get networkInfo      -> hostname and MAC address
  DEVICE get serialNumber     -> serial number
  DEVICE get uptimeSeconds    -> uptime in seconds

Protocol notes:
  - Each command is terminated with \\n
  - Successful responses begin with "+OK"
  - Error responses begin with "-ERR"
  - The device sends a welcome banner on connect; we discard it
  - No authentication by default (auth level None)
  - Responses arrive as a single line per command
"""

import csv
import json
import re
import sys
import os
import shutil
import socket
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
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
DEFAULT_CSV     = "secrets/biamp_firmware.csv"
OUTPUT_DIR      = "biamp_firmware/files"
DEFAULT_OUTPUT  = os.path.join(
    OUTPUT_DIR,
    f"results_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
)
DEFAULT_TIMEOUT = 10
DEFAULT_PORT    = 23
DEFAULT_WORKERS = 5

# Tesira TTP commands
CMD_VERSION     = "DEVICE get version\n"
CMD_SERIAL      = "DEVICE get serialNumber\n"
CMD_NETSTATUS   = "DEVICE get networkStatus\n"
CMD_FAULTS      = "DEVICE get activeFaultList\n"

BANNER_TIMEOUT  = 2.0   # seconds to wait for the welcome banner
RECV_BUFSIZE    = 4096


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
        (r"[Tt]imed out",                      "Timed out"),
        (r"[Cc]onnection refused",              "Conn refused"),
        (r"[Nn]o route to host",                "No route"),
        (r"[Nn]etwork is unreachable",          "Net unreachable"),
        (r"[Nn]ame or service not known",       "DNS failed"),
        (r"[Nn]etwork error",                   "Network error"),
        (r"-ERR.*[Aa]uth",                      "Auth required"),
        (r"-ERR.*[Pp]ermission",                "Permission denied"),
        (r"-ERR",                               "Command error"),
        (r"[Nn]o welcome banner",               "Not a Tesira device"),
        (r"[Nn]ot a Tesira",                    "Not supported"),
        (r"[Mm]alformed",                       "Bad response"),
        (r"[Ee]mpty response",                  "No response"),
    ]:
        if re.search(pat, s):
            return label
    s = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', '', s)
    s = re.sub(r'\[Errno\s*-?\d+\]\s*', '', s)
    s = re.sub(r'\s+', ' ', s).strip(': ')
    return (s[:max_len - 3] + "...") if len(s) > max_len else (s or "Error")


def status_icon(r: dict) -> str:
    s = r.get("status", "error")
    if s == "success":
        return f"{GREEN}\u2713 OK{RESET}{WHITE}"
    elif s == "auth_error":
        return f"{YELLOW}\u2717 AUTH ERR{RESET}{WHITE}"
    return f"{RED}\u2717 ERROR{RESET}{WHITE}"



def format_fault_status(status: str) -> str:
    """Return a coloured fault status string for the table."""
    if status == "OK":
        return f"{GREEN}OK{RESET}{WHITE}"
    elif status == "FAULT":
        return f"{RED}FAULT{RESET}{WHITE}"
    return "N/A"


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
        for row in reader:
            host = row.get(col_map["host"], "").strip()
            if not host or host.startswith("#"):
                continue
            try:
                port = int(row.get(col_map.get("port", ""), DEFAULT_PORT) or DEFAULT_PORT)
            except (ValueError, TypeError):
                port = DEFAULT_PORT
            devices.append({"host": host, "port": port})
    if not devices:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No valid entries found in CSV.{RESET}")
        sys.exit(1)
    return devices


# ---------------------------------------------------------------------------
# Tesira TTP socket helpers
# ---------------------------------------------------------------------------

class TesiraConnection:
    """
    Manages a Telnet connection to a Biamp Tesira device.

    Tesira uses the Telnet protocol on port 23. On connect the device sends
    IAC negotiation bytes (0xFF sequences) before the welcome banner. A raw
    TCP socket must respond to these with IAC WONT / IAC DONT to unblock the
    device so it proceeds to send the banner and accept commands.

    IAC negotiation byte meanings:
      0xFF = IAC (Interpret As Command)
      0xFD = DO   -> we respond WONT (0xFC)
      0xFB = WILL -> we respond DONT (0xFE)
    """

    # Telnet control bytes
    IAC  = 0xFF
    WILL = 0xFB
    DO   = 0xFD
    WONT = 0xFC
    DONT = 0xFE

    def __init__(self, host: str, port: int, timeout: float):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self._sock   = None
        self._buf    = b""

    def connect(self):
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock.settimeout(self.timeout)
        self._negotiate_and_drain_banner()

    def _negotiate_and_drain_banner(self):
        """
        Handle Telnet IAC negotiation then wait for the welcome banner.
        The Tesira sends IAC DO <option> sequences before sending the banner.
        We respond to each with IAC WONT <option> (decline all options).
        Once negotiation is done the device sends the welcome banner; we
        wait for it then return so commands can be issued.
        """
        self._sock.settimeout(BANNER_TIMEOUT)
        try:
            while True:
                chunk = self._sock.recv(RECV_BUFSIZE)
                if not chunk:
                    break
                # Process IAC sequences out of the chunk before buffering
                clean, chunk = self._process_iac(chunk)
                self._buf += clean
                if b"Welcome to the Tesira Text Protocol Server" in self._buf:
                    break
        except socket.timeout:
            pass
        finally:
            self._sock.settimeout(self.timeout)

    def _process_iac(self, data: bytes) -> tuple:
        """
        Scan data for IAC sequences, respond to each, and return clean data
        (with IAC sequences stripped) alongside the original for buffering.
        Returns (clean_bytes, original_bytes).
        """
        clean = bytearray()
        i = 0
        while i < len(data):
            b = data[i]
            if b == self.IAC and i + 2 <= len(data):
                cmd    = data[i + 1] if i + 1 < len(data) else 0
                option = data[i + 2] if i + 2 < len(data) else 0
                if cmd == self.DO:
                    # Device asks us to DO something — we decline: IAC WONT option
                    self._sock.sendall(bytes([self.IAC, self.WONT, option]))
                    i += 3
                elif cmd == self.WILL:
                    # Device says it WILL do something — we say DONT: IAC DONT option
                    self._sock.sendall(bytes([self.IAC, self.DONT, option]))
                    i += 3
                else:
                    # Unknown IAC sequence — skip the 3 bytes
                    i += 3
            elif b == self.IAC:
                # Incomplete IAC at end of buffer — skip
                i += 1
            else:
                clean.append(b)
                i += 1
        return bytes(clean), data

    def _readline(self) -> str:
        """Read bytes until \\n, return decoded line (strips Telnet IAC bytes)."""
        while b"\n" not in self._buf:
            chunk = self._sock.recv(RECV_BUFSIZE)
            if not chunk:
                raise ConnectionError("Connection closed by remote host")
            clean, _ = self._process_iac(chunk)
            self._buf += clean
        idx  = self._buf.index(b"\n")
        line = self._buf[:idx + 1]
        self._buf = self._buf[idx + 1:]
        return line.decode("utf-8", errors="replace").strip()

    def send_command(self, cmd: str) -> str:
        """Send a TTP command and return the first +OK / -ERR response line."""
        self._sock.sendall(cmd.encode("utf-8"))
        # Read lines until we hit a response line starting with + or -
        for _ in range(20):
            line = self._readline()
            if line.startswith("+") or line.startswith("-"):
                return line
        raise Exception("No +OK/-ERR response received")

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None


def parse_ok_value(response: str) -> str:
    """
    Extract the value from a Tesira +OK response.
    Formats seen in the wild:
      +OK "value":"5.5.0.2"          (scalar responses)
      +OK {"key":"val", ...}         (networkInfo)
    """
    if not response.startswith("+OK"):
        raise Exception(f"Unexpected response: {response}")
    val = response[3:].strip()
    # Most common: "value":"..." - extract the string after the colon
    m = re.match(r'^\"value\"\s*:\s*\"([^\"]*)\"$', val)
    if m:
        return m.group(1)
    # Plain quoted string fallback
    if val.startswith('"') and val.endswith('"'):
        return val[1:-1]
    # Unquoted or JSON object - return as-is
    return val


def parse_fault_list(raw: str) -> tuple:
    """
    Parse DEVICE get activeFaultList response.
    Returns (fault_status, fault_details) where:
      fault_status  : "OK" if no faults, "FAULT" if any faults present
      fault_details : list of fault name strings

    No-fault response:
      [{"id":INDICATOR_NONE_IN_DEVICE "name":"No fault in device" "faults":[] ...}]
    Fault response:
      [{"id":INDICATOR_MAJOR_IN_DEVICE "name":"Major Fault in Device"
        "faults":[{"id":FAULT_DANTE_FLOW_INACTIVE "name":"one or more Dante flows inactive"}] ...}]
    """
    if not raw:
        return "N/A", []
    # If any entry has a non-empty faults array, extract the fault names
    fault_names = re.findall(r'"faults"\s*:\s*\[([^\]]+)\]', raw)
    details = []
    for block in fault_names:
        for name in re.findall(r'"name"\s*:\s*"([^"]+)"', block):
            details.append(name)
    if details:
        return "FAULT", details
    # Check for INDICATOR_NONE — explicit no-fault indicator
    if "INDICATOR_NONE" in raw:
        return "OK", []
    return "OK", []


def parse_network_status(raw: str) -> dict:
    """
    Parse DEVICE get networkStatus response.
    The value is a non-standard JSON-like object (unquoted enum values).
    We use regex to extract the fields we need.
    Expected structure contains:
      "hostname":"TesiraForteXXX"
      "networkInterfaceStatusWithName":[{"interfaceId":"control"
        "networkInterfaceStatus":{"macAddress":"78:45:01:43:3e:b7" ... "ip":"10.8.x.x"
    """
    result = {"hostname": "N/A", "mac_address": "N/A", "ip_address": "N/A"}
    if not raw:
        return result
    m = re.search(r'"hostname"\s*:\s*"([^"]+)"', raw)
    if m:
        result["hostname"] = m.group(1)
    # MAC is inside the first networkInterfaceStatus block
    m = re.search(r'"macAddress"\s*:\s*"([^"]+)"', raw)
    if m:
        result["mac_address"] = m.group(1)
    m = re.search(r'"ip"\s*:\s*"([^"]+)"', raw)
    if m:
        result["ip_address"] = m.group(1)
    return result



# ---------------------------------------------------------------------------
# Main query
# ---------------------------------------------------------------------------
def query_device(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Query a single Biamp Tesira device."""
    result = {
        "host":             host,
        "port":             port,
        "status":           "error",
        "firmware_version": "N/A",
        "device_name":      "N/A",
        "mac_address":      "N/A",
        "fault_status":     "N/A",
        "fault_details":    [],
        "serial":           "N/A",
        "error":            None,
        "query_timestamp":  datetime.now(timezone.utc).isoformat(),
    }

    conn = TesiraConnection(host, port, timeout)
    try:
        conn.connect()

        # --- Firmware version ---
        try:
            resp = conn.send_command(CMD_VERSION)
            result["firmware_version"] = parse_ok_value(resp)
        except Exception as e:
            result["firmware_version"] = "N/A"

        # --- Network status (hostname, MAC, IP) ---
        try:
            resp = conn.send_command(CMD_NETSTATUS)
            raw  = parse_ok_value(resp)
            net  = parse_network_status(raw)
            result["device_name"] = net.get("hostname", "N/A")
            result["mac_address"] = net.get("mac_address", "N/A")
        except Exception:
            pass

        # --- Serial number ---
        try:
            resp = conn.send_command(CMD_SERIAL)
            result["serial"] = parse_ok_value(resp)
        except Exception:
            pass



        # --- Active fault list ---
        try:
            resp = conn.send_command(CMD_FAULTS)
            raw  = parse_ok_value(resp)
            fault_status, fault_details = parse_fault_list(raw)
            result["fault_status"]  = fault_status
            result["fault_details"] = fault_details
        except Exception:
            pass

        result["status"] = "success"

    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = f"Connection refused to {host}:{port}"
    except OSError as e:
        msg = str(e)
        if "No route to host" in msg:
            result["error"] = "No route to host"
        elif "Network is unreachable" in msg:
            result["error"] = "Network is unreachable"
        elif "Name or service not known" in msg or "nodename nor servname" in msg:
            result["error"] = "Name or service not known"
        else:
            result["error"] = msg
    except Exception as e:
        result["error"] = str(e)
    finally:
        conn.close()

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def save_results_json(results: list, filepath: str, args, elapsed: float):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    ok  = sum(1 for r in results if r["status"] == "success")
    err = sum(1 for r in results if r["status"] == "error")
    auth = sum(1 for r in results if r["status"] == "auth_error")

    output = {
        "query_info": {
            "csv_file":        str(Path(args.input).resolve()) if not args.host else args.host,
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "protocol":        f"Biamp Tesira Text Protocol (TTP) on port {args.port}",
            "mode":            "No authentication",
            "workers":         args.workers,
            "total":           len(results),
            "success":         ok,
            "auth_errors":     auth,
            "errors":          err,
            "elapsed_seconds": round(elapsed, 2),
        },
        "dsp": results,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)


def print_results_table(results: list, output_file: str, elapsed: float,
                        workers: int, firmware_filter: str = None):
    """Render the results table following the project visual style guide."""

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
            clean(r["device_name"]),
            clean(r["firmware_version"]),
            clean(r["serial"]),
            clean(r.get("mac_address", "N/A")),
            format_fault_status(r.get("fault_status", "N/A")),
            truncate_error(r.get("error") or ""),
        ]
        table_data.append(row)

    headers = ["Status", "Host", "Device Name", "Firmware", "Serial", "MAC Address", "Faults", "Error"]

    table = tabulate(table_data, headers=headers,
                     tablefmt="pretty", stralign="left", numalign="right")

    first_line = table.split("\n")[0]
    raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw         = max(raw_width, 60)

    title = "Biamp Tesira \u2014 Firmware & Device Info"
    if firmware_filter:
        title += f"  \u2014  Mismatched: {len(display_results)}/{len(results)}"
    pad = (bw - len(title)) // 2

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
            f"{BOLD}Showing:{RESET}{WHITE} {len(display_results)} of {len(results)} devices"
        )
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}\u2717{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )



    print()
    print(f"  {BOLD}Results saved:{RESET}{WHITE} {output_file}")
    print(f"  {BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers)")
    print(f"{RESET}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Query Biamp Tesira devices for firmware version and device info via TTP.",
        epilog="""
Examples:
  python biamp_fw_query.py
  python biamp_fw_query.py -i my_devices.csv
  python biamp_fw_query.py --host 192.168.1.50
  python biamp_fw_query.py -i devices.csv -t 15 -o output.json -w 10
  python biamp_fw_query.py --host 192.168.1.50 --raw
  python biamp_fw_query.py --firmware 3.12.0.0

Protocol:
  Connects via raw TCP to port 23 (Tesira Text Protocol).
  No authentication — devices must have auth level set to None.
  Commands issued: DEVICE get version, networkInfo, serialNumber, uptimeSeconds.

Firmware filter:
  --firmware VERSION shows only devices NOT on that version in the terminal.
  The JSON output always contains all results.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-i", "--input",    default=DEFAULT_CSV,
        help=f"CSV file with 'host'/'port' columns (default: {DEFAULT_CSV})")
    parser.add_argument("--host",           default=None,
        help="Query a single host instead of reading a CSV")
    parser.add_argument("-o", "--output",   default=DEFAULT_OUTPUT,
        help=f"Output JSON file (default: timestamped in {OUTPUT_DIR})")
    parser.add_argument("-t", "--timeout",  type=int, default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-p", "--port",     type=int, default=DEFAULT_PORT,
        help=f"TCP port (default: {DEFAULT_PORT})")
    parser.add_argument("-w", "--workers",  type=int, default=DEFAULT_WORKERS,
        help=f"Number of concurrent workers (default: {DEFAULT_WORKERS})")
    parser.add_argument("--raw",            action="store_true", default=False,
        help="With --host: dump raw TTP responses for all commands.")
    parser.add_argument("--firmware",       default=None, metavar="VERSION",
        help="Only show devices whose firmware does NOT match VERSION (e.g. --firmware 3.12.0.0). JSON always contains all results.")

    args = parser.parse_args()

    term_width = get_terminal_width()

    import time
    start_time = time.monotonic()

    # -----------------------------------------------------------------------
    # Header block
    # -----------------------------------------------------------------------
    input_display = args.host if args.host else args.input
    print(f"{WHITE}")
    print(f"  {BOLD}Biamp Tesira \u2014 Firmware & Device Info Query Tool{RESET}{WHITE}")
    print(f"  Queries firmware, hostname, serial, MAC, and uptime via Tesira Text Protocol.")
    print(f"  Input:   {input_display}")
    print(f"  Output:  {args.output}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    print(f"  Port:    {args.port}")
    print(f"  Auth:    None")
    if args.firmware:
        print(f"  Filter:  Showing devices not on firmware {args.firmware}")
    print(f"{RESET}")

    # -----------------------------------------------------------------------
    # Single-host --raw dump
    # -----------------------------------------------------------------------
    if args.host and args.raw:
        print(f"{WHITE}Raw TTP responses for {args.host}:{args.port}{RESET}\n")
        commands = [
            ("DEVICE get version",     CMD_VERSION),
            ("DEVICE get networkStatus", CMD_NETSTATUS),
            ("DEVICE get serialNumber", CMD_SERIAL),
            ("DEVICE get activeFaultList", CMD_FAULTS),
        ]
        conn = TesiraConnection(args.host, args.port, args.timeout)
        try:
            conn.connect()
            for label, cmd in commands:
                try:
                    resp = conn.send_command(cmd)
                    print(f"{WHITE}--- {label} ---{RESET}")
                    print(resp)
                except Exception as e:
                    print(f"{WHITE}--- {label} --- {RED}ERROR:{RESET} {e}")
                print()
        except Exception as e:
            print(f"{RED}Connection failed:{RESET} {e}")
        finally:
            conn.close()
        return

    # -----------------------------------------------------------------------
    # Build device list
    # -----------------------------------------------------------------------
    displays = [{"host": args.host, "port": args.port}] if args.host else load_csv(args.input)

    # -----------------------------------------------------------------------
    # Progress bar + concurrent query loop
    # -----------------------------------------------------------------------
    bar_fmt = (
        f"  {WHITE}Scanning{RESET} "
        f"{CYAN}{{bar}}{RESET}"
        f" {WHITE}{{n_fmt}}/{{total_fmt}}{RESET}"
        f" {WHITE}[{{elapsed}}<{{remaining}}]{RESET}"
        f"  {WHITE}{{postfix}}{RESET}"
    )

    results      = []
    results_lock = threading.Lock()
    active_lock  = threading.Lock()
    latest_host  = {"value": ""}

    def do_query(d):
        with active_lock:
            latest_host["value"] = d["host"]
        return query_device(d["host"], d["port"], timeout=args.timeout)

    with tqdm(total=len(displays), bar_format=bar_fmt, ncols=term_width,
              dynamic_ncols=True, file=sys.stderr, leave=True) as pbar:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(do_query, d): d for d in displays}
            for fut in as_completed(futures):
                with results_lock:
                    results.append(fut.result())
                with active_lock:
                    pbar.set_postfix_str(latest_host["value"], refresh=False)
                pbar.update(1)

    elapsed = time.monotonic() - start_time
    pbar.set_postfix_str(f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s", refresh=True)

    # Re-sort results to match original input order
    host_order = {d["host"]: i for i, d in enumerate(displays)}
    results.sort(key=lambda r: host_order.get(r["host"], 0))

    print_results_table(results, args.output, elapsed, args.workers, args.firmware)
    save_results_json(results, args.output, args, elapsed)


if __name__ == "__main__":
    main()
