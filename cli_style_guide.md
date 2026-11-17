# CLI Script Visual Style Guide

This document describes the terminal output style used across device query scripts in this project. Reference this file when building new scripts to ensure consistent visual appearance.

---

## ANSI Color Palette

Define these constants at the top of every script. Do not use any other colors.

```python
CYAN   = "\033[96m"   # Progress bar fill
GREEN  = "\033[92m"   # Success states
RED    = "\033[91m"   # Failure / error states
YELLOW = "\033[93m"   # Warning / auth error states
WHITE  = "\033[97m"   # All body text, table content, labels
BOLD   = "\033[1m"    # Section headers, label emphasis
RESET  = "\033[0m"    # Always close every color block
```

**Rules:**
- All printed text is wrapped in `WHITE` ... `RESET` — never leave the terminal in a color state
- `CYAN` is reserved exclusively for the progress bar
- `GREEN` / `RED` / `YELLOW` are used only for status indicators, never for body text
- `BOLD` is used for label text in summaries (e.g. `Total:`, `Lamp Hours —`) not for values

---

## Script Header Block

Print this immediately on launch, before any scanning begins. It gives the operator a quick confirmation of what is about to run.

```python
print(f"{WHITE}")
print(f"  {BOLD}<Script Title>{RESET}{WHITE}")
print(f"  <One line description of what it queries>")
print(f"  Input:   {csv_file}")
print(f"  Output:  {output_file}")
print(f"  Workers: {workers}")
print(f"  Timeout: {timeout}s")
print(f"{RESET}")
```

**Rules:**
- Two-space indent on every line
- Title is `BOLD`, rest of header is plain `WHITE`
- Always show Input, Output, Workers, and Timeout — add device-specific fields after these if needed

---

## Progress Bar

Use `tqdm` with a custom `bar_format`. The bar is cyan, all surrounding text is white. Only one host is shown in the postfix at a time — the most recently started worker.

```python
import shutil
import threading
from tqdm import tqdm

# Track only the most recently started host
active_lock = threading.Lock()
latest_host = {"value": ""}

def worker_task(device):
    with active_lock:
        latest_host["value"] = device["host"]
    # ... do work ...

term_width = shutil.get_terminal_size((120, 24)).columns

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
    # ... futures loop ...
    with active_lock:
        host_display = latest_host["value"]
    pbar.set_postfix_str(host_display, refresh=False)
    pbar.update(1)

# On completion, update postfix with elapsed time
pbar.set_postfix_str(
    f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s",
    refresh=True,
)
```

**Rules:**
- Progress bar writes to `sys.stderr` so it does not mix with table output on `stdout`
- `leave=True` keeps the completed bar visible after scanning finishes
- `dynamic_ncols=True` with `shutil.get_terminal_size` scales to the user's terminal width
- The word `Scanning` is always the label — change it only if the operation is not a scan (e.g. `Connecting`, `Uploading`)
- Postfix shows one IP or hostname only — never a list

---

## Results Table

Use `tabulate` with `tablefmt="pretty"`, `stralign="left"`, `numalign="right"`. Wrap the entire table output in `WHITE` ... `RESET`.

### Column Order Convention

Always follow this left-to-right column order. Omit columns that don't apply to the device type, but never reorder the ones you keep:

| Position | Column       | Notes                                              |
|----------|--------------|----------------------------------------------------|
| 1        | Status       | Icon + label — always first                        |
| 2        | Host         | IP or hostname — always second                     |
| 3        | Manufacturer | Device make                                        |
| 4        | Model        | Device model / product name                        |
| 5        | Firmware     | Version string or N/A                              |
| 6        | (Device-specific columns here)                                    |
| Last - 1 | Power/State  | Device operational state                           |
| Last     | Error        | Short error label — always last                    |

> **Do not include Port** in the table. It clutters the output and is recorded in the JSON.

### Status Icons

```python
def status_icon(r):
    s = r.get("status", "error")
    if s == "success":
        return f"{GREEN}\u2713 OK{RESET}{WHITE}"
    elif s == "auth_error":
        return f"{YELLOW}\u2717 AUTH ERR{RESET}{WHITE}"
    return f"{RED}\u2717 ERROR{RESET}{WHITE}"
```

| Status       | Icon          | Color  |
|--------------|---------------|--------|
| `success`    | `✓ OK`        | GREEN  |
| `auth_error` | `✗ AUTH ERR`  | YELLOW |
| `error`      | `✗ ERROR`     | RED    |

### Null / Error Value Cleaning

All values passed to the table must go through a `clean()` function. This prevents raw Python `None`, `-1`, or error strings from appearing in the table.

```python
def clean(val):
    s = str(val) if val is not None else "N/A"
    if s in ("None", "-1", ""):
        return "N/A"
    if s.startswith("ERROR") or s in ("Not available", "AUTH ERROR", "See diagnostic"):
        return "N/A"
    return s
```

### Title Banner

Print a banner above the table using `=` characters scaled to the table width:

```python
first_line = table.split("\n")[0]
raw_width = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
bw = max(raw_width, 60)

print(f"{WHITE}")
print(f"  {'=' * bw}")
title = "<Device Type> Query Results — <Key Metrics>"
pad = (bw - len(title)) // 2
print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
print(f"  {'=' * bw}")

for line in table.split("\n"):
    print(f"  {line}")
```

### Summary Footer

Print a summary line immediately after the table, then a device-specific metrics line:

```python
print()
print(
    f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
    f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
    f"{YELLOW}\u2717{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
    f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
)

# Device-specific metrics line (example: lamp hours)
if metric_vals:
    avg = sum(metric_vals) / len(metric_vals)
    print(
        f"  {BOLD}<Metric Name>{RESET}{WHITE} \u2014 "
        f"Avg: {avg:.0f}  |  Min: {min(metric_vals)}  |  "
        f"Max: {max(metric_vals)}  |  Reported: {len(metric_vals)}/{total}"
    )
else:
    print(f"  {BOLD}<Metric Name>{RESET}{WHITE} \u2014 No data available")

print(f"{RESET}")
```

---

## Footer Lines

After the table, print two closing lines with consistent formatting:

```python
print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {output_file}{RESET}")
print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({workers} workers){RESET}")
print()
```

---

## Error Label Truncation

All error messages shown in the table's Error column must pass through a `truncate_error()` function. This maps verbose exception messages to short, readable labels. Keep `max_len=30`.

```python
def truncate_error(err, max_len=30):
    if not err:
        return ""
    s = str(err)
    for pat, label in [
        (r"[Cc]onnection timed out",     "Timed out"),
        (r"[Cc]onnection refused",        "Conn refused"),
        (r"[Nn]o response .* timeout",    "No response"),
        (r"[Nn]o route to host",          "No route"),
        (r"[Nn]etwork is unreachable",    "Net unreachable"),
        (r"[Nn]ame or service not known", "DNS failed"),
        (r"[Nn]etwork error",             "Network error"),
        (r"[Aa]uthentication required",   "Auth required"),
        (r"PJLINK ERRA",                  "Auth failed"),
        (r"ERRA",                         "Auth error"),
        (r"[Nn]ot a .* device",           "Not supported"),
        (r"[Mm]alformed",                 "Bad response"),
    ]:
        if re.search(pat, s):
            return label
    s = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', '', s)
    s = re.sub(r'\[Errno\s*-?\d+\]\s*', '', s)
    s = re.sub(r'\s+', ' ', s).strip(': ')
    return (s[:max_len - 3] + "...") if len(s) > max_len else (s or "Error")
```

Add protocol-specific patterns at the top of the list for each new script.

---

## JSON Output Structure

Every script must write a JSON file with this top-level structure:

```json
{
  "query_info": {
    "csv_file": "<absolute path>",
    "timestamp": "<ISO 8601 UTC>",
    "protocol": "<protocol name and version>",
    "mode": "<mode string>",
    "workers": 5,
    "total": 10,
    "success": 9,
    "errors": 1,
    "elapsed_seconds": 12.4
  },
  "devices": [
    {
      "host": "192.168.1.10",
      "port": 4352,
      "query_timestamp": "<ISO 8601 UTC>",
      "status": "success",
      "error": null
    }
  ]
}
```

**Rules:**
- Top-level key for the device array should reflect the device type: `"projectors"`, `"switches"`, `"displays"`, etc.
- `status` is always one of: `"success"`, `"auth_error"`, `"error"`
- `error` is `null` on success, a string on failure
- Always use UTC timestamps in ISO 8601 format via `datetime.now(timezone.utc).isoformat()`
- Port is always saved to JSON even though it is not shown in the terminal table

---

## CSV Loader

Reuse this loader pattern across all scripts. It handles BOM encoding, auto-detects delimiters, and skips comment lines.

```python
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
            print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} CSV needs 'host' column.{RESET}")
            sys.exit(1)
        for row in reader:
            host = row.get(col_map["host"], "").strip()
            if not host or host.startswith("#"):
                continue
            # parse port, password, and any other columns here
            devices.append({"host": host})
    return devices
```

---

## Standard CLI Flags

Every script gets the same flags from the shared helper `scripts/lib/standard_cli.py`. Do not hand-write an argparse block. Build the parser with the helper, then add device-specific options in their own group:

```python
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import standard_cli as cli

parser = cli.build_parser(
    script_file=__file__,
    description="Query <devices> for <data>.",
    default_csv="secrets/<name>_firmware.csv",     # relative to scripts/
    output_dir="<name>_firmware/files",            # relative to scripts/
    default_port=23, default_timeout=10, default_workers=5,
    auth=cli.AUTH_NONE,      # or cli.AUTH_PASSWORD / cli.AUTH_USER_PASSWORD
)
opts = parser.add_argument_group("<Device> options")   # script-specific flags
args = cli.parse_args(parser)                          # also switches on --debug

devices = cli.select_devices(args, load_csv, lambda host: {"host": host, "port": 23})
if args.raw:
    cli.run_raw(devices, dump_raw)    # dump_raw(dev) prints with cli.raw_item()
    return
```

| Flag | Meaning |
|------|---------|
| `-i, --input CSV` | CSV of devices. Default `secrets/<name>.csv` |
| `--host HOST` | Query `HOST` instead of the whole CSV. Repeat for several hosts. If the host is in the CSV, its row (port, credentials) is reused |
| `-p, --port PORT` | Port for `--host` targets |
| `-u, --username USER` | Username for `--host` targets (devices that log in) |
| `--password PASS` | Password for `--host` targets (devices that log in) |
| `-o, --output FILE` | Results JSON. Default `<output_dir>/results_<YYYYMMDD>_<HHMMSS>.json` |
| `--firmware V [V ...]` | Table shows only devices **not** on one of these versions. The JSON always has every device |
| `-t, --timeout SEC` | Per-device timeout |
| `-w, --workers N` | Devices queried at once |
| `--raw` | Print each device's raw responses (what it actually sent back), then exit. No table, no JSON. Works with `--host` or the whole CSV |
| `--debug` | Trace every connection, command and reply to stderr, prefixed with the host. The normal table and JSON still run |

**Rules:**
- A standard flag that does not apply to a device stays in place, and its help text says why (pass `port_help=` / `workers_help=` to `build_parser`)
- Old flag names keep working as hidden aliases: `--csv` and `--verbose` are built in, and scripts add their own with `cli.add_alias()`
- `--debug` output goes through `cli.debug.log / sent / received / hexdump`. Never log passwords, PSKs, API keys, SNMP communities or auth headers (`cli.redact()` masks a device dict)
- An exception that a query swallows (`except: pass`) must at least `cli.debug.log()` it
- `--firmware` is a list: filter with `cli.firmware_mismatches()` and print with `cli.firmware_label()`
- `query_info.csv_file` and the header's `Input:` line use `cli.input_label(args)`

## Output File Names

All scripts name results files the same way, from one timestamp per run (`cli.RUN_STAMP`):

```
<output_dir>/results_<YYYYMMDD>_<HHMMSS>.json      e.g. results_20261117_094223.json
```

- The time is **local** time, so the name matches the wall clock. The exact UTC time is in `query_info.timestamp`
- No device prefix in the name: the folder says what the device is
- Call `cli.ensure_parent(path)` before writing, so a missing folder is created
- The dashboard picks the newest file in each folder from this timestamp

---

## Checklist for New Scripts

When building a new device query script, verify each item:

- [ ] ANSI constants defined at the top (`CYAN`, `GREEN`, `RED`, `YELLOW`, `WHITE`, `BOLD`, `RESET`)
- [ ] Header block printed on launch with Input, Output, Workers, Timeout
- [ ] `tqdm` progress bar using the standard `bar_fmt` with cyan fill on stderr
- [ ] Single host displayed in progress bar postfix (most recently started)
- [ ] `tabulate` table with `pretty` format, left-aligned strings, right-aligned numbers
- [ ] Port column excluded from table (present in JSON only)
- [ ] Column order follows the convention: Status → Host → Manufacturer → Model → Firmware → (custom) → State → Error
- [ ] `status_icon()` using `✓` / `✗` with GREEN / YELLOW / RED
- [ ] All table values pass through `clean()`
- [ ] Error column values pass through `truncate_error()` with protocol-specific patterns added
- [ ] Title banner width scaled to actual table width using `re.sub` to strip ANSI before measuring
- [ ] Summary footer with Total / Success / Auth Errors / Failed counts
- [ ] Device-specific metrics line in footer (or "No data available" fallback)
- [ ] Closing footer lines: `Results saved:` and `Elapsed:`
- [ ] JSON output follows the standard structure with `query_info` + device array
- [ ] Timestamps are UTC ISO 8601
- [ ] CSV loader handles BOM, auto-detects delimiter, skips `#` comment lines
- [ ] Parser built with `cli.build_parser()`; device-specific flags in their own argument group
- [ ] `--host`, `--raw` and `--debug` work, and `--raw` works for the whole CSV as well as `--host`
- [ ] No secrets in `--debug` output
- [ ] Default output file is `results_<YYYYMMDD>_<HHMMSS>.json` (local time) from the helper
