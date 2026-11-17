#!/usr/bin/env python3
"""
KBRemote (UKR) Touch Panel Fleet Query Tool

Queries the entire ELO touch panel fleet via the Unified Kiosk Remote
Management REST API. One authenticated HTTPS call returns every device.

API: https://kioskapi.azure-api.net/klr/api/device
Auth: single `api-key` header (no HMAC needed for UKR)
Docs: https://help.android-kiosk.com/en/article/unified-kiosk-remote-management-api-api-endpoints-1v7xygp/

Fields surfaced (per request):
  Make       (brand)
  Model      (model)
  Serial     (serial)
  MAC        (macAddress)
  Kiosk Ver  (kioskVersion)
  Android    (androidVersion)
  Provisioned (provisioned)

Plus lastSeen / online for staleness, name for the friendly host name.

Credentials lookup order:
  1. --api-key <key>           CLI flag
  2. $KBREMOTE_API_KEY         environment variable
  3. ~/.kbremote_api_key       text file containing the key
"""

import csv
import json
import re
import sys
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import standard_cli as cli  # noqa: E402  (standard flags, --debug/--raw helpers)

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library is required. Install with: pip install requests")
    sys.exit(1)

try:
    from tabulate import tabulate
except ImportError:
    print("ERROR: 'tabulate' library is required. Install with: pip install tabulate")
    sys.exit(1)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
OUTPUT_DIR       = "tp_firmware/files"          # results_<YYYYMMDD>_<HHMMSS>.json
DEFAULT_TIMEOUT  = 30
DEFAULT_KEYFILE  = os.path.expanduser("~/.kbremote_api_key")
DEFAULT_CSV      = "secrets/tp_firmware.csv"    # relative to this script's folder
API_BASE         = "https://kioskapi.azure-api.net/klr/api"
DEVICE_ENDPOINT  = f"{API_BASE}/device"
API_HOST         = urlparse(API_BASE).hostname  # --debug prefix for the API call itself

# How many seconds since lastSeen before a device is considered "stale"
STALE_AFTER_SECS = 86400  # 24 hours


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
    if val is None:
        return "N/A"
    s = str(val)
    if s in ("None", "-1", "", "null"):
        return "N/A"
    return s


def truncate_error(err, max_len: int = 30) -> str:
    """Map verbose exception messages to short readable labels."""
    if not err:
        return ""
    s = str(err)
    for pat, label in [
        (r"[Cc]onnection timed out",            "Timed out"),
        (r"[Cc]onnection refused",              "Conn refused"),
        (r"[Nn]o route to host",                "No route"),
        (r"[Nn]etwork is unreachable",          "Net unreachable"),
        (r"[Nn]ame or service not known",       "DNS failed"),
        (r"HTTP 401",                           "Auth failed"),
        (r"HTTP 403",                           "Forbidden"),
        (r"HTTP 404",                           "Not found"),
        (r"HTTP 429",                           "Rate limited"),
        (r"HTTP 5\d\d",                         "Server error"),
        (r"[Cc]ommand timed out",               "Cmd timeout"),
        (r"[Mm]alformed",                       "Bad response"),
    ]:
        if re.search(pat, s):
            return label
    s = re.sub(r'\s+', ' ', s).strip(': ')
    return (s[:max_len - 3] + "...") if len(s) > max_len else (s or "Error")


def parse_last_seen(s: str):
    """Parse the API's ISO-ish timestamp into a tz-aware datetime."""
    if not s:
        return None
    try:
        # API returns e.g. "2021-09-08T10:33:51.7061598" with no timezone — treat as UTC
        s2 = s.rstrip("Z")
        # Strip sub-second precision past 6 digits which Python's fromisoformat dislikes
        if "." in s2:
            base, frac = s2.split(".", 1)
            frac = frac[:6]
            s2 = f"{base}.{frac}"
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception as e:
        cli.debug.log(API_HOST, f"cannot parse lastSeen {s!r} ({e}); age shown as N/A")
        return None


def humanize_age(seconds: float) -> str:
    """Short human-readable age string."""
    if seconds is None:
        return "N/A"
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h"
    return f"{int(seconds // 86400)}d"


# ---------------------------------------------------------------------------
# CSV host loader (for --csv mode)
# ---------------------------------------------------------------------------
def load_csv_hosts(csv_path: str) -> list:
    """
    Read the same CSV format as the ADB script. Returns an ordered list of
    host strings (preserving input order, deduped, case preserved on output
    but matched case-insensitively downstream).
    """
    p = Path(csv_path)
    if not p.exists():
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} CSV not found: {csv_path}{RESET}")
        sys.exit(1)
    seen = set()
    hosts = []
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
            host = (row.get(col_map["host"], "") or "").strip()
            if not host or host.startswith("#"):
                continue
            key = host.lower()
            if key not in seen:
                seen.add(key)
                hosts.append(host)
    if not hosts:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No valid entries found in CSV.{RESET}")
        sys.exit(1)
    return hosts


def filter_devices_by_hosts(devices: list, csv_hosts: list) -> tuple:
    """
    Filter API devices down to those whose `name` matches a host in csv_hosts.
    Matching is case-insensitive exact match.

    Returns (matched_devices, unmatched_csv_hosts):
      - matched_devices  : list of device dicts, ordered to match the CSV
      - unmatched_csv_hosts : list of CSV hosts that didn't appear in the API
    """
    # Build a case-insensitive index of API device names → device dicts.
    # If duplicates exist on the API side, the first one wins (rare in practice).
    api_index = {}
    for d in devices:
        nm = (d.get("name") or "").strip()
        if nm and nm.lower() not in api_index:
            api_index[nm.lower()] = d
        elif nm:
            cli.debug.log(nm, f"duplicate KBRemote name: identifier {d.get('identifier')} ignored, "
                              f"keeping {api_index[nm.lower()].get('identifier')}")
    unnamed = sum(1 for d in devices if not (d.get("name") or "").strip())
    if unnamed:
        cli.debug.log(API_HOST, f"{unnamed} API device(s) have no name and can never match")

    matched   = []
    unmatched = []
    for h in csv_hosts:
        d = api_index.get(h.lower())
        if d:
            cli.debug.log(h, f"matched KBRemote device {d.get('name')!r} (identifier "
                             f"{d.get('identifier')}, online={d.get('online')}, "
                             f"androidVersion={d.get('androidVersion')}, kioskVersion={d.get('kioskVersion')})")
            matched.append(d)
        else:
            cli.debug.log(h, "no KBRemote device with this name (case-insensitive exact match)")
            unmatched.append(h)
    return matched, unmatched


def status_icon_for(device: dict) -> str:
    """
    Return a coloured status icon based on the device's reported state.

    Online: green check
    Offline but recent (< STALE_AFTER_SECS): yellow check (still trustworthy)
    Stale: red cross
    Never seen / no data: red cross
    """
    if device.get("_query_error"):
        return f"{RED}\u2717 ERROR{RESET}{WHITE}"
    if device.get("online"):
        return f"{GREEN}\u2713 OK{RESET}{WHITE}"
    age = device.get("_age_seconds")
    if age is not None and age < STALE_AFTER_SECS:
        return f"{YELLOW}\u2717 OFFLINE{RESET}{WHITE}"
    return f"{RED}\u2717 STALE{RESET}{WHITE}"


def fmt_provisioned(val) -> str:
    if val is True:
        return f"{GREEN}\u2713 yes{RESET}{WHITE}"
    if val is False:
        return f"{RED}\u2717 no{RESET}{WHITE}"
    return "N/A"


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
def resolve_api_key(cli_value: str, keyfile_path: str) -> str:
    """
    Resolve the API key from (in order): CLI flag, env var, keyfile.
    Errors out cleanly if none of the three is available.
    """
    if cli_value:
        cli.debug.log(API_HOST, "api key from --api-key")
        return cli_value.strip()

    env = os.environ.get("KBREMOTE_API_KEY", "").strip()
    if env:
        cli.debug.log(API_HOST, "api key from $KBREMOTE_API_KEY")
        return env

    p = Path(keyfile_path)
    if p.exists():
        content = p.read_text().strip()
        if content:
            cli.debug.log(API_HOST, f"api key from keyfile {p}")
            return content
        cli.debug.log(API_HOST, f"keyfile {p} is empty")

    print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} No KBRemote API key found.")
    print(f"  Provide one of:")
    print(f"    --api-key <key>           CLI flag")
    print(f"    KBREMOTE_API_KEY=<key>    environment variable")
    print(f"    {keyfile_path}            text file containing the key")
    print(f"  Get a key at: https://klr.android-kiosk.com/ApiKey{RESET}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# API call
# ---------------------------------------------------------------------------
def fetch_devices(api_key: str, timeout: int = DEFAULT_TIMEOUT,
                  identifier: str = None) -> list:
    """
    Single GET /api/device call. Returns a list of device dicts.

    If `identifier` is given, returns just that one device (still wrapped in a list).
    """
    url = DEVICE_ENDPOINT
    params = {}
    if identifier:
        params["identifier"] = identifier

    headers = {"api-key": api_key, "Accept": "application/json"}
    cli.debug.log(API_HOST, f"GET {url} params={params} timeout={timeout}s "
                            f"headers={cli.redact(headers)}")
    t0 = time.monotonic()
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=timeout, verify=True)
    except Exception as e:
        cli.debug.log(API_HOST, f"request failed after {time.monotonic() - t0:.2f}s: "
                                f"{type(e).__name__}: {e}")
        raise
    cli.debug.log(API_HOST, f"HTTP {resp.status_code} in {time.monotonic() - t0:.2f}s, "
                            f"{len(resp.content)} bytes, "
                            f"Content-Type {resp.headers.get('Content-Type')}")

    if resp.status_code == 401:
        raise Exception("HTTP 401 — API key rejected (check key is correct and active)")
    if resp.status_code == 403:
        raise Exception("HTTP 403 — API key lacks permission")
    if resp.status_code == 404:
        raise Exception("HTTP 404 — endpoint not found")
    if resp.status_code == 429:
        raise Exception("HTTP 429 — rate limited; wait and retry")
    if resp.status_code >= 500:
        raise Exception(f"HTTP {resp.status_code} — server error")
    resp.raise_for_status()

    data = resp.json()
    # Single-identifier responses may come back as an object instead of a list
    if isinstance(data, dict) and "identifier" in data:
        cli.debug.log(API_HOST, f"response: one device object ({data.get('name')!r})")
        return [data]
    if isinstance(data, list):
        cli.debug.log(API_HOST, f"response: list of {len(data)} devices")
        return data
    # Some endpoints wrap in {success, message, devices: [...]} — handle both shapes
    if isinstance(data, dict) and "devices" in data:
        cli.debug.log(API_HOST, f"response: wrapped object, {len(data['devices'])} devices")
        return data["devices"]
    cli.debug.log(API_HOST, f"response: unexpected shape, treated as no devices: {cli.show(data, 500)}")
    return []


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------
def enrich_devices(devices: list) -> list:
    """
    Add derived fields each row needs for display:
      _age_seconds  — seconds since lastSeen
      _age_human    — "5m", "3h", "2d" style string
    """
    now = datetime.now(timezone.utc)
    for d in devices:
        last_seen = parse_last_seen(d.get("lastSeen"))
        if last_seen:
            age = (now - last_seen).total_seconds()
            d["_age_seconds"] = age
            d["_age_human"]   = humanize_age(age)
        else:
            d["_age_seconds"] = None
            d["_age_human"]   = "N/A"
    return devices


def panel_record(d: dict, query_ts: str) -> dict:
    """
    Build the JSON record for one panel: the standard fields every script in
    this project emits (host / status / error / manufacturer / model / ...),
    followed by the raw KBRemote API fields.

    The fleet dashboard keys on `host` (building/room parsing) and `status`
    (success vs offline), so the API's `name` and `online` are mapped onto them.
    """
    if d.get("online"):
        status, error = "success", None
    elif d.get("_age_human") not in (None, "N/A"):
        status, error = "error", f"Offline — last seen {d['_age_human']} ago"
    else:
        status, error = "error", "Offline — never seen"

    android = d.get("androidVersion")
    record = {
        "host":            (d.get("name") or "").strip(),
        "status":          status,
        "error":           error,
        "manufacturer":    d.get("brand") or None,
        "model":           d.get("model") or None,
        "serial":          d.get("serial") or None,
        "mac":             d.get("macAddress") or None,
        "android_version": str(android) if android not in (None, "") else None,
        "kiosk_version":   d.get("kioskVersion") or None,
        "query_timestamp": query_ts,
    }
    # Raw API fields follow; screenshot payloads are dropped to keep the JSON small
    for k, v in d.items():
        if k != "applicationScreenshot" and k not in record:
            record[k] = v
    return record


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def save_results_json(devices: list, filepath: str, args, elapsed: float,
                      unmatched_csv_hosts: list = None):
    cli.ensure_parent(filepath)
    online = sum(1 for d in devices if d.get("online"))
    offline_recent = sum(
        1 for d in devices
        if not d.get("online")
        and d.get("_age_seconds") is not None
        and d["_age_seconds"] < STALE_AFTER_SECS
    )
    stale = len(devices) - online - offline_recent

    query_ts = datetime.now(timezone.utc).isoformat()
    cleaned = [panel_record(d, query_ts) for d in devices]

    output = {
        "query_info": {
            "source":            "KBRemote UKR API",
            "endpoint":          DEVICE_ENDPOINT,
            "timestamp":         query_ts,
            "protocol":          "KBRemote UKR REST API",
            "csv_filter":        cli.input_label(args) if not (args.all or args.identifier) else None,
            "total":             len(devices),
            "success":           online,
            "errors":            len(devices) - online,
            "online":            online,
            "offline_recent":    offline_recent,
            "stale":             stale,
            "stale_threshold_s": STALE_AFTER_SECS,
            "elapsed_seconds":   round(elapsed, 2),
        },
        "panels":              cleaned,
        "unmatched_csv_hosts": unmatched_csv_hosts or [],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)


def print_results_table(devices: list, output_file: str, elapsed: float,
                        kiosk_filter: str = None, android_filter: list = None,
                        sort_by: str = "name"):
    """Render the results table following the project visual style guide."""

    # Apply filters — mismatched rows shown only. Full data always in JSON.
    display = devices
    filter_descriptions = []
    if kiosk_filter:
        display = [d for d in display if d.get("kioskVersion") != kiosk_filter]
        filter_descriptions.append(f"Kiosk \u2260 {kiosk_filter}")
    if android_filter:   # --firmware: androidVersion is a touch panel's firmware
        display = cli.firmware_mismatches(display, android_filter, key="androidVersion")
        filter_descriptions.append(f"Android \u2260 {cli.firmware_label(android_filter)}")

    # Sort for predictable output
    if sort_by == "name":
        display = sorted(display, key=lambda d: (d.get("name") or "").lower())
    elif sort_by == "lastseen":
        # Most recently seen first, never-seen last
        display = sorted(display, key=lambda d: d.get("_age_seconds") or float("inf"))
    elif sort_by == "kiosk":
        display = sorted(display, key=lambda d: (d.get("kioskVersion") or "", (d.get("name") or "").lower()))

    table_data = []
    for d in display:
        row = [
            status_icon_for(d),
            clean(d.get("name")),
            clean(d.get("brand")),
            clean(d.get("model")),
            clean(d.get("serial")),
            clean(d.get("macAddress")),
            clean(d.get("kioskVersion")),
            clean(d.get("androidVersion")),
            fmt_provisioned(d.get("provisioned")),
            clean(d.get("_age_human")),
        ]
        table_data.append(row)

    headers = ["Status", "Name", "Make", "Model", "Serial",
               "MAC", "Kiosk Ver", "Android", "Provisioned", "Last Seen"]

    table = tabulate(table_data, headers=headers,
                     tablefmt="pretty", stralign="left", numalign="right")

    first_line = table.split("\n")[0]
    raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw         = max(raw_width, 60)

    title = "KBRemote (UKR) \u2014 Fleet Query Results"
    if filter_descriptions:
        title += f"  \u2014  {' & '.join(filter_descriptions)}: {len(display)}/{len(devices)}"
    pad = (bw - len(title)) // 2

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")
    for line in table.split("\n"):
        print(f"  {line}")

    # Recompute counts across the displayed (post-filter) set
    total = len(display)
    online = sum(1 for d in display if d.get("online"))
    offline_recent = sum(
        1 for d in display
        if not d.get("online")
        and d.get("_age_seconds") is not None
        and d["_age_seconds"] < STALE_AFTER_SECS
    )
    stale = total - online - offline_recent

    print()
    if filter_descriptions:
        print(
            f"  {BOLD}Filter:{RESET}{WHITE} {' & '.join(filter_descriptions)}  |  "
            f"{BOLD}Showing:{RESET}{WHITE} {len(display)} of {len(devices)} panels"
        )
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Online:{RESET}{WHITE} {online}  |  "
        f"{YELLOW}\u2717{RESET}{WHITE} {BOLD}Offline (recent):{RESET}{WHITE} {offline_recent}  |  "
        f"{RED}\u2717{RESET}{WHITE} {BOLD}Stale:{RESET}{WHITE} {stale}"
    )

    # Kiosk version distribution
    kv_counts = {}
    for d in display:
        kv = d.get("kioskVersion") or "N/A"
        kv_counts[kv] = kv_counts.get(kv, 0) + 1
    reported_kv = sum(c for k, c in kv_counts.items() if k != "N/A")
    if reported_kv:
        parts = "  |  ".join(
            f"{BOLD}{k}:{RESET}{WHITE} {c}"
            for k, c in sorted(kv_counts.items(), key=lambda kv: (-kv[1], kv[0]))
            if k != "N/A"
        )
        print(f"  {BOLD}Kiosk versions \u2014{RESET}{WHITE} {parts}  |  {BOLD}Reported:{RESET}{WHITE} {reported_kv}/{total}")
    else:
        print(f"  {BOLD}Kiosk versions \u2014{RESET}{WHITE} No data available")

    # Android version distribution
    av_counts = {}
    for d in display:
        av = str(d.get("androidVersion") or "N/A")
        av_counts[av] = av_counts.get(av, 0) + 1
    reported_av = sum(c for k, c in av_counts.items() if k != "N/A")
    if reported_av:
        parts = "  |  ".join(
            f"{BOLD}Android {k}:{RESET}{WHITE} {c}"
            for k, c in sorted(av_counts.items())
            if k != "N/A"
        )
        print(f"  {BOLD}Android versions \u2014{RESET}{WHITE} {parts}  |  {BOLD}Reported:{RESET}{WHITE} {reported_av}/{total}")
    else:
        print(f"  {BOLD}Android versions \u2014{RESET}{WHITE} No data available")

    # Provisioning status
    prov_yes = sum(1 for d in display if d.get("provisioned") is True)
    prov_no  = sum(1 for d in display if d.get("provisioned") is False)
    if prov_yes or prov_no:
        print(
            f"  {BOLD}Provisioning \u2014{RESET}{WHITE} "
            f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Provisioned:{RESET}{WHITE} {prov_yes}  |  "
            f"{RED}\u2717{RESET}{WHITE} {BOLD}Unprovisioned:{RESET}{WHITE} {prov_no}"
        )

    print()
    print(f"  {BOLD}Results saved:{RESET}{WHITE} {output_file}")
    print(f"  {BOLD}Elapsed:{RESET}{WHITE} {elapsed:.2f}s")
    print(f"{RESET}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
# Fields --raw leaves out: screenshot blobs (huge) and the ages enrich_devices() adds
RAW_SKIP_KEYS = {"applicationScreenshot", "_age_seconds", "_age_human"}

NOT_USED = "Not used: one cloud API call returns every panel"


def main():
    parser = cli.build_parser(
        script_file=__file__,
        description="Query the ELO touch panel fleet via the KBRemote UKR REST API.",
        default_csv=DEFAULT_CSV,
        output_dir=OUTPUT_DIR,
        default_timeout=DEFAULT_TIMEOUT,
        port_help=NOT_USED,
        workers_help=NOT_USED,
        timeout_help=f"HTTP request timeout in seconds (default: {DEFAULT_TIMEOUT})",
        host_help=("Show only the panel whose KBRemote device name is HOST, instead of "
                   "the CSV's panels (case-insensitive exact match, same as the CSV). "
                   "Repeat for several panels."),
        firmware_help=("Show only panels whose Android version (androidVersion, which the "
                       "dashboard treats as a panel's firmware) is NOT one of these, e.g. "
                       "--firmware 10 12. The JSON always has every panel. Old name: --android."),
        raw_help=("Print the API's JSON for the selected panels (screenshot blobs "
                  "stripped), then exit without the table or JSON file."),
        debug_help=("Trace the API request (method, URL, params, status, time, size, "
                    "device count) and each host-name match to stderr. The api-key is "
                    "never shown. The normal table and JSON still run."),
        epilog="""
Examples:
  python3 tp_script.py                              # panels in secrets/tp_firmware.csv
  python3 tp_script.py -i my_panels.csv             # use a different CSV
  python3 tp_script.py --host baker-213-room-schedule-display.openav.dartmouth.edu
  python3 tp_script.py --all                        # every device in the account
  python3 tp_script.py --identifier b60e7c95-d160-439d-8dc6-4c7e1648bd1a
  python3 tp_script.py --kiosk 1.4.6                # CSV panels NOT on this Kiosk version
  python3 tp_script.py --firmware 10 12             # CSV panels NOT on Android 10 or 12
  python3 tp_script.py --sort lastseen              # most recently seen first
  python3 tp_script.py --all --kiosk "1.4.6 (Build 131)"  # whole fleet, mismatched only
  python3 tp_script.py --raw                        # print the API JSON, no table/file
  python3 tp_script.py --debug                      # trace the API call + matching

Scope:
  One HTTPS GET returns every panel in the account; the results are then cut
  down to the panels named in the CSV (default) or by --host. --all keeps
  every panel; --identifier asks the API for a single device.
  -p/--port and -w/--workers are accepted for uniformity but not used.

Credentials:
  The API key is read from (in order):
    1. --api-key <key>           CLI flag
    2. $KBREMOTE_API_KEY         environment variable
    3. ~/.kbremote_api_key       text file with one line: the key

  Get a key at: https://klr.android-kiosk.com/ApiKey
        """,
        # -i/--input here is a list of panel names that scopes the results
        input_help=(f"CSV of panel host names to show (default: {DEFAULT_CSV}). "
                    "Matching is exact, case-insensitive, against the device's "
                    "KBRemote name. Unmatched hosts are reported as a warning. "
                    "Ignored with --all, --host or --identifier."),
    )
    cli.add_alias(parser, "--android", dest="firmware", nargs="+", metavar="VERSION")

    group = parser.add_argument_group("KBRemote options")
    group.add_argument("--api-key",    default=None,
        help="KBRemote API key (overrides env var and keyfile)")
    group.add_argument("--keyfile",    default=DEFAULT_KEYFILE,
        help=f"Path to file containing the API key (default: {DEFAULT_KEYFILE})")
    group.add_argument("--identifier", default=None,
        help="Query a single device by its KBRemote identifier (UUID) instead of the full fleet")
    group.add_argument("--all",        action="store_true", default=False,
        help="Show every device in the KBRemote account (no CSV / --host scoping).")
    group.add_argument("--kiosk",      default=None, metavar="VERSION",
        help="Only show panels whose kioskVersion does NOT match VERSION. JSON output always contains all results.")
    group.add_argument("--sort",       default="name", choices=["name", "lastseen", "kiosk"],
        help="Sort order for the table (default: name)")

    args = cli.parse_args(parser)

    start_time = time.monotonic()

    api_key = resolve_api_key(args.api_key, args.keyfile)

    # -----------------------------------------------------------------------
    # Header block
    # -----------------------------------------------------------------------
    print(f"{WHITE}")
    print(f"  {BOLD}KBRemote (UKR) \u2014 Fleet Query Tool{RESET}{WHITE}")
    print(f"  Queries every panel in your KBRemote account in one API call.")
    print(f"  Endpoint: {DEVICE_ENDPOINT}")
    print(f"  Output:   {'(none: --raw)' if args.raw else args.output}")
    print(f"  Timeout:  {args.timeout}s")
    print(f"  Auth:     api-key header (key length {len(api_key)} chars)")
    if args.identifier:
        print(f"  Scope:    single device {args.identifier}")
    elif args.all:
        print(f"  Scope:    full fleet (--all)")
    elif args.host:
        print(f"  Scope:    hosts {cli.input_label(args)} (--host)")
    else:
        print(f"  Scope:    hosts in {cli.input_label(args)}")
    if args.kiosk:
        print(f"  Filter:   Kiosk version \u2260 {args.kiosk}")
    if args.firmware:
        print(f"  Filter:   Android version \u2260 {cli.firmware_label(args.firmware)}")
    if args.debug:
        print(f"  Debug:    on (trace on stderr)")
    print(f"{RESET}")

    # -----------------------------------------------------------------------
    # Host list that scopes the results: --host names, else the CSV
    # (default behavior — unless --all or --identifier)
    # -----------------------------------------------------------------------
    csv_hosts = None
    scope_src = "--host" if args.host else "CSV"
    if not args.all and not args.identifier:
        rows = cli.select_devices(
            args,
            lambda path: [{"host": h} for h in load_csv_hosts(path)],
            lambda host: {"host": host},
        )
        csv_hosts, seen = [], set()
        for row in rows:                       # dedupe repeated --host names
            if row["host"].lower() not in seen:
                seen.add(row["host"].lower())
                csv_hosts.append(row["host"])
        cli.debug.log(API_HOST, f"scope: {len(csv_hosts)} host(s) from {scope_src}")
    else:
        cli.debug.log(API_HOST, "scope: " + (f"--identifier {args.identifier}" if args.identifier
                                             else "--all (no host filter)"))

    # -----------------------------------------------------------------------
    # Fetch
    # -----------------------------------------------------------------------
    try:
        devices = fetch_devices(api_key, timeout=args.timeout, identifier=args.identifier)
    except requests.exceptions.Timeout:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} Request timed out after {args.timeout}s{RESET}")
        sys.exit(1)
    except requests.exceptions.ConnectionError as e:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} Cannot connect to API: {e}{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} {e}{RESET}")
        sys.exit(1)

    elapsed = time.monotonic() - start_time

    if not devices:
        print(f"\n  {WHITE}{BOLD}Warning:{RESET}{WHITE} API returned no devices.{RESET}")
        sys.exit(0)

    devices = enrich_devices(devices)

    # -----------------------------------------------------------------------
    # Apply the CSV / --host filter (after enrich so age fields are still computed)
    # -----------------------------------------------------------------------
    unmatched_csv_hosts = []
    if csv_hosts is not None:
        api_total = len(devices)
        devices, unmatched_csv_hosts = filter_devices_by_hosts(devices, csv_hosts)
        print(f"{WHITE}")
        print(
            f"  {BOLD}{scope_src} scope:{RESET}{WHITE} {len(csv_hosts)} hosts in {scope_src}  |  "
            f"{BOLD}Matched:{RESET}{WHITE} {len(devices)}  |  "
            f"{BOLD}Unmatched:{RESET}{WHITE} {len(unmatched_csv_hosts)}  |  "
            f"{BOLD}API total:{RESET}{WHITE} {api_total}"
        )
        if unmatched_csv_hosts:
            print(f"  {YELLOW}{BOLD}Hosts in {scope_src} with no matching KBRemote device:{RESET}{WHITE}")
            for h in unmatched_csv_hosts:
                print(f"    \u2022 {h}")
        print(f"{RESET}")

    if not devices:
        print(f"\n  {WHITE}{BOLD}Warning:{RESET}{WHITE} No devices left after {scope_src} filter.{RESET}")
        sys.exit(0)

    # -----------------------------------------------------------------------
    # --raw mode: the API's JSON for the selected panels, no table / file
    # -----------------------------------------------------------------------
    if args.raw:
        cleaned = [{k: v for k, v in d.items() if k not in RAW_SKIP_KEYS} for d in devices]
        print(json.dumps(cleaned, indent=2, ensure_ascii=False))
        return

    # -----------------------------------------------------------------------
    # Render table + save JSON
    # -----------------------------------------------------------------------
    print_results_table(
        devices,
        args.output,
        elapsed,
        kiosk_filter=args.kiosk,
        android_filter=args.firmware,
        sort_by=args.sort,
    )
    save_results_json(devices, args.output, args, elapsed, unmatched_csv_hosts=unmatched_csv_hosts)


if __name__ == "__main__":
    main()
