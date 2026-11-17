#!/usr/bin/env python3
"""
Middle Atlantic RackLink Select Series — Device Info Query

Queries firmware version, serial number, model, MAC address, and outlet
states from RLNK-915R, RLNK-415R, and RLNK-215 PDUs via their JSON
settings endpoint at /assets/js/json/settings.json.

Usage:
    python3 rlink_script.py                                   # reads secrets/rlink_firmware.csv
    python3 rlink_script.py --host 192.168.1.200              # single device
    python3 rlink_script.py --host 192.168.1.200 -p 80 -u admin --password s3cret
    python3 rlink_script.py -i secrets/rlink_firmware.csv -w 10
    python3 rlink_script.py --firmware 1.14.02                # hide up-to-date devices
    python3 rlink_script.py --host 192.168.1.200 --raw        # print the settings JSON
    (run with --help for every flag; -p is the port, the password flag is --password)

Input CSV (default: secrets/rlink_firmware.csv):
    host,port,user_name,pw
    192.168.1.200,80,admin,admin
    192.168.1.201,443,admin,s3cret

Output: rlink_firmware/files/results_YYYYMMDD_HHMMSS.json (timestamped, auto-created)

Requirements:
    pip install tabulate tqdm
"""

import base64
import csv
import json
import os
import re
import shutil
import ssl
import sys
import threading
import time
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import standard_cli as cli  # noqa: E402  (standard flags, --debug/--raw helpers)

from tabulate import tabulate
from tqdm import tqdm

# ── ANSI Color Palette ───────────────────────────────────────────────
CYAN   = "\033[96m"   # Progress bar fill — reserved, nothing else
GREEN  = "\033[92m"   # Success states
RED    = "\033[91m"   # Failure / error states
YELLOW = "\033[93m"   # Auth-error states
WHITE  = "\033[97m"   # All body text, table content, labels
BOLD   = "\033[1m"    # Section headers, label emphasis
RESET  = "\033[0m"    # Always close every colour block

DEFAULT_CSV      = "secrets/rlink_firmware.csv"   # relative to this script's folder
OUTPUT_DIR       = "rlink_firmware/files"         # results_<YYYYMMDD>_<HHMMSS>.json
DEFAULT_PORT     = 80
DEFAULT_TIMEOUT  = 10
DEFAULT_WORKERS  = 5
DEFAULT_USERNAME = "admin"     # used when the CSV has no user_name / for --host not in the CSV
DEFAULT_PASSWORD = "admin"


# ── Shared Helpers ───────────────────────────────────────────────────

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
# HTTP status failures, missing settings paths, and TLS handshake errors.
PROTOCOL_ERROR_PATTERNS = [
    (r"HTTP 401|\b401\b",             "Auth failed"),
    (r"HTTP 403|\b403\b",             "Forbidden"),
    (r"HTTP 404|\b404\b",             "No settings path"),
    (r"[Ss]elf.signed",               "Self-signed cert"),
    (r"CERTIFICATE_VERIFY_FAILED",    "Cert verify failed"),
    (r"[Ss]slv3|handshake|SSLError|SSL", "TLS error"),
    (r"[Ii]nvalid JSON|JSONDecode",   "Bad JSON"),
    (r"[Cc]ould not connect",         "Unreachable"),
    (r"urlopen error",                "Unreachable"),
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


# ── CSV Loader ───────────────────────────────────────────────────────

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
            username = (row.get(col_map.get("user_name", ""), "") or "").strip() or DEFAULT_USERNAME
            password = (row.get(col_map.get("pw", ""), "") or "").strip() or DEFAULT_PASSWORD
            devices.append({
                "host": host,
                "port": port,
                "username": username,
                "password": password,
            })
    if not devices:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No valid entries found in CSV.{RESET}")
        sys.exit(1)
    return devices


# ── HTTP Fetch (protocol — do not change) ────────────────────────────

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def http_get(url: str, username: str, password: str,
             timeout: int = 10) -> tuple:
    """
    HTTP GET with Basic Auth.  Returns (status_code, body_text).
    """
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    req = urllib.request.Request(url, headers={
        "Authorization": f"Basic {creds}",
        "Accept-Encoding": "identity",
        "User-Agent": "RackLinkQuery/1.0",
    })
    host = urllib.parse.urlsplit(url).hostname or url
    # The Authorization header is never traced.
    cli.debug.log(host, f"GET {url} (Basic auth as {username!r}, timeout {timeout}s)")
    resp = urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx)
    body = resp.read().decode("utf-8", errors="replace")
    if cli.debug.enabled:
        cli.debug.log(host, f"HTTP {resp.status} {getattr(resp, 'reason', '')}, {len(body)} chars")
        cli.debug.received(host, _redacted_body(body))
    return resp.status, body


def _redacted_body(body: str):
    """settings.json for --debug with any secret-looking keys masked (see cli.redact)."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return body

    def walk(o):
        if isinstance(o, dict):
            return {k: walk(v) for k, v in cli.redact(o).items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o
    return walk(data)


# ── RackLink Query Logic (protocol — do not change) ──────────────────

SETTINGS_PATH = "/assets/js/json/settings.json"


def base_urls(host: str, port: int) -> list:
    """URL bases to try, in order: the scheme the port implies first, then the other."""
    if port == 80:
        return [f"http://{host}", f"https://{host}"]
    if port == 443:
        return [f"https://{host}", f"http://{host}"]
    return [f"https://{host}:{port}", f"http://{host}:{port}"]


def query_racklink(host: str, port: int = DEFAULT_PORT, username: str = "admin",
                   password: str = "admin", timeout: int = 10) -> dict:
    """
    Fetch /assets/js/json/settings.json from a RackLink Select Series PDU
    and extract firmware, serial, model, device name, MAC, and outlet states.
    """
    result = {
        "host": host,
        "port": port,
        "query_timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "error",
        "error": None,
        "manufacturer": "Middle Atlantic",
        "model": None,
        "device_name": None,
        "firmware_version": None,
        "serial": None,
        "mac": None,
        "outlets": [],
    }

    # Build URL candidates based on port
    candidates = base_urls(host, port)

    body = None
    for base_url in candidates:
        try:
            status, body = http_get(
                f"{base_url}{SETTINGS_PATH}", username, password, timeout
            )
            if status == 200 and body:
                break
            cli.debug.log(host, f"{base_url}: HTTP {status}, {len(body or '')} chars -- trying next")
        except urllib.error.HTTPError as e:
            cli.debug.log(host, f"{base_url}: HTTP {e.code} {e.reason}")
            if e.code in (401, 403):
                result["status"] = "auth_error"
                result["error"] = f"Authentication failed (HTTP {e.code})"
                cli.debug.log(host, f"result: auth_error ({result['error']})")
                return result
            body = None
            continue
        except Exception as e:
            cli.debug.log(host, f"{base_url}: {type(e).__name__}: {e}")
            body = None
            continue

    if not body:
        result["error"] = f"Could not connect to {host} via HTTPS or HTTP"
        cli.debug.log(host, f"result: error ({result['error']})")
        return result

    # Parse JSON
    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        result["error"] = f"Invalid JSON from settings endpoint: {e}"
        cli.debug.log(host, f"result: error ({result['error']})")
        return result

    # Extract fields from the JSON structure
    ds = data.get("deviceSettings", {})
    cs = data.get("cloudSettings", {})
    ns = data.get("networkSettings", {})

    result["model"] = ds.get("model") or None
    result["device_name"] = ds.get("deviceName") or None
    result["firmware_version"] = ds.get("firmware") or None
    result["mac"] = ns.get("macAddress") or None

    # Serial: cloudSettings.serial_number, formatted with underscore to dash
    sn = cs.get("serial_number", "")
    if sn:
        result["serial"] = sn.replace("_", "-")

    # Outlet names and states (JSON only, summarised in the table)
    outlets = data.get("Outlets", [])
    result["outlets"] = []
    for i, o in enumerate(outlets, start=1):
        name = urllib.parse.unquote(o.get("OutletName", f"Outlet {i}"))
        result["outlets"].append({
            "number": i,
            "name": name,
            "status": "on" if o.get("OutletStatus") else "off",
        })

    # Determine final status
    if any([result["model"], result["firmware_version"], result["serial"]]):
        result["status"] = "success"
    else:
        result["error"] = "Connected but settings JSON contained no device info"

    cli.debug.log(host, f"result: {result['status']}" + (f" ({result['error']})" if result["error"] else ""))
    return result


# ── Main ─────────────────────────────────────────────────────────────

def dump_raw(dev: dict, timeout: int):
    """--raw: GET settings.json the same way the query does and print each reply."""
    for base_url in base_urls(dev["host"], dev.get("port", DEFAULT_PORT)):
        url = f"{base_url}{SETTINGS_PATH}"
        try:
            status, body = http_get(url, dev["username"], dev["password"], timeout)
        except urllib.error.HTTPError as e:
            cli.raw_error(f"GET {url}", f"HTTP {e.code} {e.reason}")
            if e.code in (401, 403):
                return          # the query stops here too (auth_error)
            continue
        except Exception as e:
            cli.raw_error(f"GET {url}", f"{type(e).__name__}: {e}")
            continue
        try:
            shown = json.loads(body)        # pretty-printed when it parses
        except ValueError:
            shown = body
        cli.raw_item(f"GET {url}  (HTTP {status}, {len(body)} chars)", shown)
        if status == 200 and body:
            return              # the query uses the first URL that answers


def main():
    parser = cli.build_parser(
        script_file=__file__,
        description="Query Middle Atlantic RackLink Select Series PDUs",
        default_csv=DEFAULT_CSV,
        output_dir=OUTPUT_DIR,
        default_port=DEFAULT_PORT,
        default_timeout=DEFAULT_TIMEOUT,
        default_workers=DEFAULT_WORKERS,
        auth=cli.AUTH_USER_PASSWORD,
        port_help=(f"Port for --host targets (default: the CSV row's, else {DEFAULT_PORT}). "
                   "80 tries http:// then https://, 443 https:// then http://, "
                   "any other port https://HOST:PORT then http://HOST:PORT."),
        raw_help=("Print the settings.json each PDU sends back (and the error for each "
                  "URL that fails), then exit without the table or JSON. Works with "
                  "--host or the whole CSV."),
        epilog=f"""
Examples:
  python3 rlink_script.py                                  # whole CSV
  python3 rlink_script.py --host 192.168.1.200             # one PDU
  python3 rlink_script.py --host 192.168.1.200 -p 443 -u admin --password s3cret
  python3 rlink_script.py --host 192.168.1.200 --raw
  python3 rlink_script.py --host 192.168.1.200 --debug
  python3 rlink_script.py --firmware 1.14.02 1.14.03       # PDUs NOT on either version
  python3 rlink_script.py -i devices.csv -t 15 -w 10 -o out.json

Note: -p is now the PORT (the standard flag). The password flag is --password
  (it used to be -p/--password).

CSV columns: host,port,user_name,pw  (port, user_name and pw optional;
  defaults {DEFAULT_PORT}, {DEFAULT_USERNAME}/{DEFAULT_PASSWORD}). A --host that is not in the CSV
  uses the same defaults unless -p / -u / --password are given.
        """,
    )
    args = cli.parse_args(parser)

    # ── Output path ──────────────────────────────────────────────────
    output_file = str(Path(args.output).resolve())

    csv_file = cli.input_label(args)

    # ── Build device list (--host or CSV) ────────────────────────────
    devices = cli.select_devices(
        args, load_csv,
        lambda host: {"host": host, "port": DEFAULT_PORT,
                      "username": DEFAULT_USERNAME, "password": DEFAULT_PASSWORD})
    mode = "json_api_single_host" if args.host else "json_api"

    total = len(devices)

    # ── Header Block ─────────────────────────────────────────────────
    print(f"{WHITE}")
    print(f"  {BOLD}Middle Atlantic RackLink Select Series — Device Info Query{RESET}{WHITE}")
    print(f"  Queries RackLink PDUs for firmware, serial, and outlet states")
    print(f"  Input:   {csv_file}")
    print(f"  Output:  {'(none: --raw)' if args.raw else output_file}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    if args.debug:
        print(f"  Debug:   on (trace on stderr)")
    print(f"{RESET}")

    # ── --raw: dump what each PDU sends back, no table / JSON ────────
    if args.raw:
        cli.run_raw(devices, lambda d: dump_raw(d, args.timeout))
        return

    # ── Progress Bar + Threaded Scan ─────────────────────────────────
    active_lock = threading.Lock()
    latest_host = {"value": ""}
    results = []
    t_start = time.time()

    term_width = get_terminal_width()
    bar_fmt = (
        f"  {WHITE}Scanning{RESET} "
        f"{CYAN}{{bar}}{RESET}"
        f" {WHITE}{{n_fmt}}/{{total_fmt}}{RESET}"
        f" {WHITE}[{{elapsed}}<{{remaining}}]{RESET}"
        f"  {WHITE}{{postfix}}{RESET}"
    )

    def worker(dev):
        with active_lock:
            latest_host["value"] = dev["host"]
        return query_racklink(
            host=dev["host"],
            port=dev.get("port", DEFAULT_PORT),
            username=dev["username"],
            password=dev["password"],
            timeout=args.timeout,
        )

    with tqdm(
        total=total,
        bar_format=bar_fmt,
        ncols=term_width,
        dynamic_ncols=True,
        file=sys.stderr,
        leave=True,
    ) as pbar:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(worker, d): d for d in devices}
            for fut in as_completed(futures):
                results.append(fut.result())
                with active_lock:
                    host_display = latest_host["value"]
                pbar.set_postfix_str(host_display, refresh=False)
                pbar.update(1)

        elapsed = time.time() - t_start
        pbar.set_postfix_str(
            f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s",
            refresh=True,
        )

    # ── Sort results to match input order ────────────────────────────
    input_order = {d["host"]: i for i, d in enumerate(devices)}
    results.sort(key=lambda r: input_order.get(r["host"], 999999))

    # ── Counts and metrics ───────────────────────────────────────────
    ok = sum(1 for r in results if r["status"] == "success")
    auth = sum(1 for r in results if r["status"] == "auth_error")
    err = total - ok - auth

    fw_versions = [
        r["firmware_version"] for r in results
        if r["status"] == "success" and r["firmware_version"]
    ]

    outlets_on = sum(
        1 for r in results for o in r.get("outlets", [])
        if o.get("status") == "on"
    )
    outlets_total = sum(len(r.get("outlets", [])) for r in results)
    reporting = sum(1 for r in results if r.get("outlets"))

    # ── Filter displayed rows when --firmware is set ─────────────────
    if args.firmware:
        display_results = cli.firmware_mismatches(results, args.firmware)
        hidden = total - len(display_results)
    else:
        display_results = results
        hidden = 0

    headers = ["Status", "Host", "Manufacturer", "Model", "Firmware",
               "Serial", "MAC", "Device Name", "Outlets", "Error"]
    rows = []
    for r in display_results:
        outs = r.get("outlets", [])
        if outs:
            on_count = sum(1 for o in outs if o.get("status") == "on")
            outlet_state = f"{on_count}/{len(outs)} on"
        else:
            outlet_state = "N/A"
        rows.append([
            status_icon(r),
            clean(r["host"]),
            clean(r.get("manufacturer")),
            clean(r.get("model")),
            clean(r.get("firmware_version")),
            clean(r.get("serial")),
            clean(r.get("mac")),
            clean(r.get("device_name")),
            outlet_state,
            truncate_error(r.get("error")),
        ])

    table = tabulate(rows, headers=headers, tablefmt="pretty",
                     stralign="left", numalign="right")

    # ── Title Banner ─────────────────────────────────────────────────
    if rows:
        first_line = table.split("\n")[0]
        raw_width = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    else:
        raw_width = 60
    bw = max(raw_width, 60)

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    title = "RackLink Select Series Query Results — Firmware & Identity"
    pad = (bw - len(title)) // 2
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")

    if rows:
        for line in table.split("\n"):
            print(f"  {line}")
    else:
        print()
        print(f"  All {total} devices matched firmware {cli.firmware_label(args.firmware)} — none to display.")
        print()

    if hidden > 0:
        print()
        print(
            f"  {BOLD}Filter:{RESET}{WHITE} "
            f"Hiding {hidden} device{'s' if hidden != 1 else ''} "
            f"on firmware {cli.firmware_label(args.firmware)}"
        )

    # ── Summary Footer ───────────────────────────────────────────────
    print()
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}✓{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}✗{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}✗{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )

    if outlets_total:
        print(
            f"  {BOLD}Outlets{RESET}{WHITE} — "
            f"On: {outlets_on}  |  Total: {outlets_total}  |  "
            f"Reported: {reporting}/{total}"
        )
    else:
        print(f"  {BOLD}Outlets{RESET}{WHITE} — No data available")

    if fw_versions:
        unique = sorted(set(fw_versions))
        print(
            f"  {BOLD}Firmware Versions{RESET}{WHITE} — "
            f"Unique: {', '.join(unique)}  |  "
            f"Reported: {len(fw_versions)}/{total}"
        )
    else:
        print(f"  {BOLD}Firmware Versions{RESET}{WHITE} — No data available")

    print(f"{RESET}")

    # ── Footer Lines ─────────────────────────────────────────────────
    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {output_file}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({args.workers} workers){RESET}")
    print()

    # ── JSON Output ──────────────────────────────────────────────────
    cli.ensure_parent(output_file)
    output = {
        "query_info": {
            "csv_file": csv_file,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": "HTTP/HTTPS RackLink Settings JSON v1",
            "mode": mode,
            "workers": args.workers,
            "total": total,
            "success": ok,
            "errors": err + auth,
            "elapsed_seconds": round(elapsed, 2),
        },
        "pdus": results,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)


if __name__ == "__main__":
    main()
