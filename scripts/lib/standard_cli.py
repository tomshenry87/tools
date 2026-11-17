"""
Standard command-line flags and helpers shared by every device query script.

Every script in scripts/ builds its parser with build_parser(), so the same
flags mean the same thing everywhere:

  Input
    -i, --input CSV        CSV of devices (default: secrets/<script>.csv)
    --host HOST            query HOST instead of the whole CSV (repeatable).
                           If HOST is listed in the CSV, that row's settings
                           (port, credentials, ...) are reused.
    -p, --port PORT        port for --host targets
    -u, --username USER    username for --host targets   (devices with logins)
    --password PASS        password for --host targets   (devices with logins)

  Output
    -o, --output FILE      results JSON (default: <output dir>/results_<YYYYMMDD>_<HHMMSS>.json)
    --firmware V [V ...]   table shows only devices NOT on one of these versions;
                           the JSON always has every device

  Connection
    -t, --timeout SEC      per-device timeout
    -w, --workers N        devices queried at once

  Troubleshooting
    --raw                  print each device's raw responses, then exit
                           (no table, no JSON)
    --debug                trace every connection, command and reply to stderr,
                           prefixed with the host; the normal run still happens

Output files are named results_<YYYYMMDD>_<HHMMSS>.json in local time, one
stamp per run (RUN_STAMP). The exact UTC time is inside the JSON.

Usage in a script:

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from lib import standard_cli as cli

    parser = cli.build_parser(
        script_file=__file__,
        description="Query Biamp Tesira DSPs ...",
        default_csv="secrets/biamp_firmware.csv",
        output_dir="biamp_firmware/files",
        default_port=23, default_timeout=10,
    )
    group = parser.add_argument_group("Biamp options")   # script-specific flags
    args = cli.parse_args(parser)
    devices = cli.select_devices(args, load_csv, lambda h: {"host": h, "port": 23})
"""

import argparse
import json
import logging
import os
import sys
import threading
from datetime import datetime
from pathlib import Path

# One timestamp per run, local time, used for every default output filename.
RUN_STAMP = datetime.now().strftime("%Y%m%d_%H%M%S")

# Credential styles a script can declare.
AUTH_NONE = "none"                    # no login (TTP, PJLink class w/o pass, ...)
AUTH_PASSWORD = "password"            # password only
AUTH_USER_PASSWORD = "user_password"  # username + password

WHITE = "\033[97m"
BOLD = "\033[1m"
RED = "\033[91m"
RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
def script_dir(script_file: str) -> Path:
    return Path(script_file).resolve().parent


def default_output(script_file: str, output_dir: str) -> str:
    """<scripts>/<output_dir>/results_<YYYYMMDD>_<HHMMSS>.json (local time)."""
    return str(script_dir(script_file) / output_dir / f"results_{RUN_STAMP}.json")


def ensure_parent(path) -> None:
    """Create the output file's folder if it does not exist yet."""
    parent = os.path.dirname(os.path.abspath(str(path)))
    os.makedirs(parent, exist_ok=True)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def build_parser(*, script_file: str, description: str, default_csv: str,
                 output_dir: str, default_port=None, default_timeout=10,
                 default_workers=5, auth: str = AUTH_NONE, timeout_type=int,
                 port_help: str = None, workers_help: str = None, timeout_help: str = None,
                 input_help: str = None, username_help: str = None, password_help: str = None,
                 host_help: str = None, raw_help: str = None,
                 debug_help: str = None, firmware_help: str = None,
                 epilog: str = "") -> argparse.ArgumentParser:
    """
    Return an ArgumentParser with the standard flags already added.

    default_csv and output_dir are relative to the script's folder, so the
    scripts behave the same whatever directory they are run from.
    The *_help arguments let a script explain how a standard flag applies to
    it (e.g. "not used: one cloud API call") without renaming the flag.
    """
    base = script_dir(script_file)
    csv_path = str(base / default_csv)
    out_default = default_output(script_file, output_dir)

    parser = argparse.ArgumentParser(
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    g_in = parser.add_argument_group("Input")
    g_in.add_argument("-i", "--input", default=csv_path, metavar="CSV",
        help=input_help or f"CSV of devices (default: {default_csv})")
    g_in.add_argument("--host", action="append", default=None, metavar="HOST",
        help=host_help or ("Query HOST instead of the whole CSV. Repeat for several "
                           "hosts. If HOST is in the CSV, that row's port and "
                           "credentials are reused."))
    port_default_txt = f" (default: {default_port})" if default_port is not None else ""
    g_in.add_argument("-p", "--port", type=int, default=None, metavar="PORT",
        help=port_help or f"Port for --host targets{port_default_txt}")
    if auth == AUTH_USER_PASSWORD:
        g_in.add_argument("-u", "--username", default=None, metavar="USER",
            help=username_help or "Username for --host targets (default: the CSV row's)")
    if auth in (AUTH_PASSWORD, AUTH_USER_PASSWORD):
        g_in.add_argument("--password", default=None, metavar="PASS",
            help=password_help or "Password for --host targets (default: the CSV row's)")

    g_out = parser.add_argument_group("Output")
    g_out.add_argument("-o", "--output", default=out_default, metavar="FILE",
        help=f"Results JSON (default: {output_dir}/results_<YYYYMMDD>_<HHMMSS>.json)")
    g_out.add_argument("--firmware", nargs="+", default=None, metavar="VERSION",
        help=firmware_help or ("Show only devices NOT on any of these firmware "
                               "versions in the table. The JSON always has every device."))

    g_conn = parser.add_argument_group("Connection")
    g_conn.add_argument("-t", "--timeout", type=timeout_type, default=default_timeout, metavar="SEC",
        help=timeout_help or f"Per-device timeout in seconds (default: {default_timeout})")
    g_conn.add_argument("-w", "--workers", type=int, default=default_workers, metavar="N",
        help=workers_help or f"Devices queried at once (default: {default_workers})")

    g_dbg = parser.add_argument_group("Troubleshooting")
    g_dbg.add_argument("--raw", action="store_true", default=False,
        help=raw_help or ("Print each device's raw responses, then exit without "
                          "the table or JSON. Works with --host or the whole CSV."))
    g_dbg.add_argument("--debug", action="store_true", default=False,
        help=debug_help or ("Trace every connection, command and reply to stderr, "
                            "prefixed with the host. The normal table and JSON still run."))

    # Old flag names kept working, hidden from --help.
    add_alias(parser, "--csv", dest="input")
    add_alias(parser, "--verbose", dest="debug", action="store_true")
    return parser


def add_alias(parser, *flags, dest, action="store", **kw):
    """Add a hidden, backward-compatible alias that writes to an existing dest."""
    parser.add_argument(*flags, dest=dest, action=action,
                        default=argparse.SUPPRESS, help=argparse.SUPPRESS, **kw)


def parse_args(parser, argv=None):
    """parse_args() plus the standard post-processing (turns on --debug)."""
    args = parser.parse_args(argv)
    if getattr(args, "debug", False):
        debug.enable()
    return args


# ---------------------------------------------------------------------------
# Device selection: --host vs CSV
# ---------------------------------------------------------------------------
def select_devices(args, load_csv, make_device, *, port_key="port",
                   username_key="username", password_key="password"):
    """
    Return the list of device dicts to query.

    CSV mode (no --host): load_csv(args.input), unchanged.
    --host mode: one device per --host. When the host appears in the CSV
    (case-insensitive), that row is reused so its port and credentials come
    along; otherwise make_device(host) builds it from the script's defaults.
    Explicit -p / -u / --password then override the row.
    """
    if not args.host:
        return load_csv(args.input)

    rows = {}
    if args.input and Path(args.input).exists():
        try:
            for row in load_csv(args.input):
                rows.setdefault(str(row.get("host", "")).strip().lower(), row)
        except SystemExit:
            rows = {}   # unreadable CSV is fine in --host mode

    devices = []
    for host in args.host:
        host = host.strip()
        row = rows.get(host.lower())
        dev = dict(row) if row else make_device(host)
        dev["host"] = host
        if args.port is not None:
            dev[port_key] = args.port
        if getattr(args, "username", None) is not None:
            dev[username_key] = args.username
        if getattr(args, "password", None) is not None:
            dev[password_key] = args.password
        debug.log(host, f"--host target ({'from CSV row' if row else 'not in CSV, defaults'}): "
                        f"{redact(dev)}")
        devices.append(dev)
    return devices


def input_label(args) -> str:
    """What to show on the header's Input line and in query_info.csv_file."""
    if args.host:
        return ", ".join(args.host)
    return str(Path(args.input).resolve())


# ---------------------------------------------------------------------------
# --firmware
# ---------------------------------------------------------------------------
def firmware_versions(args) -> list:
    return list(args.firmware or [])


def firmware_mismatches(results, versions, key="firmware_version"):
    """Rows whose firmware is not one of versions (errors included). No filter -> all rows."""
    if not versions:
        return list(results)
    wanted = {str(v).strip() for v in versions}
    def fw(r):
        return str(key(r) if callable(key) else r.get(key, "")).strip()
    return [r for r in results if fw(r) not in wanted]


def firmware_label(versions) -> str:
    return ", ".join(str(v) for v in versions)


# ---------------------------------------------------------------------------
# --debug
# ---------------------------------------------------------------------------
class DebugLog:
    """
    Thread-safe tracer for --debug. Lines go to stderr as
        [12:03:04.512 baker-102-dsp] sent: DEVICE get version
    and are routed through tqdm.write when tqdm is loaded so they don't
    tear the progress bar.
    """

    def __init__(self):
        self.enabled = False
        self._lock = threading.Lock()

    def enable(self):
        self.enabled = True
        logging.basicConfig(level=logging.DEBUG, stream=sys.stderr,
                            format="[%(asctime)s %(name)s] %(message)s")
        # Library chatter that drowns out the device exchange
        for noisy in ("paramiko.transport", "charset_normalizer"):
            logging.getLogger(noisy).setLevel(logging.INFO)

    def _emit(self, line: str):
        with self._lock:
            tq = sys.modules.get("tqdm")
            writer = getattr(getattr(tq, "tqdm", None), "write", None) if tq else None
            if writer:
                writer(line, file=sys.stderr)
            else:
                print(line, file=sys.stderr, flush=True)

    def log(self, host, msg):
        if not self.enabled:
            return
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        for i, part in enumerate(str(msg).splitlines() or [""]):
            prefix = f"[{ts} {host}]" if i == 0 else " " * (len(ts) + len(str(host)) + 3)
            self._emit(f"{prefix} {part}")

    def sent(self, host, data):
        self.log(host, f"sent: {show(data)}")

    def received(self, host, data):
        self.log(host, f"recv: {show(data)}")

    def hexdump(self, host, label, data: bytes, max_bytes: int = 256):
        if not self.enabled:
            return
        self.log(host, f"{label} ({len(data)} bytes)\n{hexdump(data, max_bytes)}")


debug = DebugLog()


def printable_text(data: bytes):
    """Decoded text if data is plain printable ASCII (plus CR/LF/tab), else None."""
    try:
        text = bytes(data).decode("ascii")
    except UnicodeDecodeError:
        return None
    return text if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in text) else None


def show(data, limit: int = 2000) -> str:
    """Printable form of a payload: text as-is (escaped), bytes as text or hex."""
    if isinstance(data, (bytes, bytearray)):
        text = printable_text(data)
        if text is None:
            return bytes(data[:limit]).hex(" ") + (" ..." if len(data) > limit else "")
        data = text
    if isinstance(data, (dict, list)):
        data = json.dumps(data, indent=2, default=str)
    s = str(data)
    s = s.replace("\r", "\\r").replace("\t", "\\t")
    if s.endswith("\n") and s.count("\n") == 1:
        s = s[:-1] + "\\n"   # one-line command/reply: show its terminator instead of dropping it
    return s if len(s) <= limit else s[:limit] + f" ... ({len(s)} chars)"


def hexdump(data: bytes, max_bytes: int = 256) -> str:
    data = bytes(data)
    lines = []
    for off in range(0, min(len(data), max_bytes), 16):
        chunk = data[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {off:04x}  {hx:<47}  {asc}")
    if len(data) > max_bytes:
        lines.append(f"  ... {len(data) - max_bytes} more bytes")
    return "\n".join(lines) if lines else "  (empty)"


def redact(dev: dict) -> dict:
    """Device dict safe for printing: secrets masked."""
    out = {}
    for k, v in dev.items():
        if any(s in k.lower() for s in ("pass", "psk", "secret", "community", "key", "pw")) and v:
            out[k] = "***"
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# --raw
# ---------------------------------------------------------------------------
def raw_header(host, port=None):
    target = f"{host}:{port}" if port not in (None, "") else str(host)
    print(f"\n{WHITE}{BOLD}===== {target} ====={RESET}")


def raw_item(label, data):
    """Print one raw response under a label. Bytes, str, dict and list are all fine."""
    print(f"{WHITE}--- {label} ---{RESET}")
    if isinstance(data, (bytes, bytearray)):
        text = printable_text(data)
        print(text if text is not None else hexdump(data, 4096))
    elif isinstance(data, (dict, list)):
        print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    else:
        print(data)


def raw_error(label, err):
    print(f"{WHITE}--- {label} --- {RED}ERROR:{RESET} {err}")


def run_raw(devices, dump_one):
    """
    --raw driver: call dump_one(device) for each device, one at a time so the
    output stays readable. dump_one prints with raw_item()/raw_error(); an
    exception it raises is printed and the next device continues.
    """
    for dev in devices:
        raw_header(dev.get("host"), dev.get("port"))
        try:
            dump_one(dev)
        except Exception as e:  # keep going on the next device
            raw_error("connection", e)
    print()
