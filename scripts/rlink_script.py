#!/usr/bin/env python3
"""
Middle Atlantic RackLink Select Series — Device Info Query

Queries firmware version, serial number, model, MAC address, and outlet
states from RLNK-915R, RLNK-415R, and RLNK-215 PDUs via their JSON
settings endpoint at /assets/js/json/settings.json.

Usage:
    python rlink_firmware.py                                  # reads secrets/rlink_firmware.csv
    python rlink_firmware.py --host 192.168.1.200             # single device
    python rlink_firmware.py --host 192.168.1.200 --port 80 -u admin -p s3cret
    python rlink_firmware.py -i secrets/rlink_firmware.csv -w 10
    python rlink_firmware.py --firmware 1.14.02               # hide up-to-date devices

Input CSV (default: secrets/rlink_firmware.csv):
    host,port,user_name,pw
    192.168.1.200,80,admin,admin
    192.168.1.201,443,admin,s3cret

Output: rlink_firmware/files/results_YYYYMMDD_HHMMSS.json (timestamped, auto-created)

Requirements:
    pip install tabulate tqdm
"""

import argparse
import base64
import csv
import json
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

DEFAULT_PORT = 80


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
            username = (row.get(col_map.get("user_name", ""), "") or "").strip() or "admin"
            password = (row.get(col_map.get("pw", ""), "") or "").strip() or "admin"
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
    resp = urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx)
    body = resp.read().decode("utf-8", errors="replace")
    return resp.status, body


# ── RackLink Query Logic (protocol — do not change) ──────────────────

SETTINGS_PATH = "/assets/js/json/settings.json"


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
    candidates = []
    if port == 80:
        candidates.append(f"http://{host}")
        candidates.append(f"https://{host}")
    elif port == 443:
        candidates.append(f"https://{host}")
        candidates.append(f"http://{host}")
    else:
        candidates.append(f"https://{host}:{port}")
        candidates.append(f"http://{host}:{port}")

    body = None
    for base_url in candidates:
        try:
            status, body = http_get(
                f"{base_url}{SETTINGS_PATH}", username, password, timeout
            )
            if status == 200 and body:
                break
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                result["status"] = "auth_error"
                result["error"] = f"Authentication failed (HTTP {e.code})"
                return result
            body = None
            continue
        except Exception:
            body = None
            continue

    if not body:
        result["error"] = f"Could not connect to {host} via HTTPS or HTTP"
        return result

    # Parse JSON
    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        result["error"] = f"Invalid JSON from settings endpoint: {e}"
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

    return result


# ── Main ─────────────────────────────────────────────────────────────

def main():
    script_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description="Query Middle Atlantic RackLink Select Series PDUs"
    )
    parser.add_argument("--host", help="Single device IP or hostname")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"Port for single host (default: {DEFAULT_PORT})")
    parser.add_argument("-u", "--username", default="admin",
                        help="Username for single host (default: admin)")
    parser.add_argument("-p", "--password", default="admin",
                        help="Password for single host (default: admin)")
    parser.add_argument("--firmware", metavar="VERSION",
                        help="Current firmware version — hides matching devices from table")
    parser.add_argument("-i", "--input",
                        default=str(script_dir / "secrets" / "rlink_firmware.csv"),
                        help="Input CSV file (default: secrets/rlink_firmware.csv)")
    parser.add_argument("-o", "--output", default=None,
                        help="Output JSON file (default: rlink_firmware/files/results_YYYYMMDD_HHMMSS.json)")
    parser.add_argument("-w", "--workers", type=int, default=5)
    parser.add_argument("-t", "--timeout", type=int, default=10)
    args = parser.parse_args()

    # ── Build output path with timestamp ─────────────────────────────
    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        output_file = str(out_path)
    else:
        out_dir = script_dir / "rlink_firmware" / "files"
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = str((out_dir / f"results_{stamp}.json").resolve())

    csv_file = str(Path(args.input).resolve())

    # ── Build device list ────────────────────────────────────────────
    if args.host:
        devices = [{
            "host": args.host,
            "port": args.port,
            "username": args.username,
            "password": args.password,
        }]
        mode = "json_api_single_host"
    else:
        devices = load_csv(args.input)
        mode = "json_api"

    total = len(devices)

    # ── Header Block ─────────────────────────────────────────────────
    print(f"{WHITE}")
    print(f"  {BOLD}Middle Atlantic RackLink Select Series — Device Info Query{RESET}{WHITE}")
    print(f"  Queries RackLink PDUs for firmware, serial, and outlet states")
    print(f"  Input:   {csv_file}")
    print(f"  Output:  {output_file}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    print(f"{RESET}")

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
        display_results = [
            r for r in results
            if r.get("firmware_version") != args.firmware
        ]
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
        print(f"  All {total} devices matched firmware {args.firmware} — none to display.")
        print()

    if hidden > 0:
        print()
        print(
            f"  {BOLD}Filter:{RESET}{WHITE} "
            f"Hiding {hidden} device{'s' if hidden != 1 else ''} "
            f"on firmware {args.firmware}"
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
