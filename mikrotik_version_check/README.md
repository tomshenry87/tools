# MikroTik RouterOS Version Checker

A concurrent SSH-based tool that queries MikroTik routers for their installed package versions, outputs a color-coded terminal table, and writes structured JSON results.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Input CSV Format](#input-csv-format)
- [Command-Line Arguments](#command-line-arguments)
- [Output](#output)
  - [Terminal Output](#terminal-output)
  - [JSON Output](#json-output)
- [Function Reference](#function-reference)
  - [load_csv](#load_csv)
  - [check_router](#check_router)
  - [check_all_routers](#check_all_routers)
  - [get_command_output](#get_command_output)
  - [parse_packages](#parse_packages)
  - [get_routeros_version](#get_routeros_version)
  - [strip_ansi](#strip_ansi)
  - [clean](#clean)
  - [truncate_error](#truncate_error)
  - [status_icon](#status_icon)
  - [print_results_table](#print_results_table)
- [Error Handling](#error-handling)
- [Troubleshooting](#troubleshooting)

---

## Requirements

- Python 3.10+
- MikroTik routers accessible over SSH (default port 22)

### Dependencies

```
paramiko
tabulate
tqdm
```

---

## Installation

```bash
pip install paramiko tabulate tqdm
```

Clone or download `mikrotik_checker.py` into your working directory.

---

## Quick Start

1. Create a `routers.csv` file in the same directory (see [Input CSV Format](#input-csv-format))
2. Run the script:

```bash
python3 mikrotik_checker.py
```

Results are printed to the terminal and saved to `results.json`.

---

## Input CSV Format

The script reads router credentials from a CSV file. The following column names are supported and are case-insensitive:

| Column     | Aliases                        | Required | Default |
|------------|--------------------------------|----------|---------|
| `host`     | `hostname`, `ip`, `address`    | Yes      | —       |
| `username` | —                              | No       | `admin` |
| `password` | —                              | No       | *(empty)* |
| `port`     | —                              | No       | `22`    |

### Example CSV

```csv
host,username,password,port
192.168.1.1,admin,secret,22
192.168.1.2,admin,hunter2,22
router.local,admin,,8022
# This line is a comment and will be skipped
10.0.0.1,netops,p@ssw0rd,22
```

**Notes:**
- Lines beginning with `#` are skipped
- Rows with no host value are skipped
- The delimiter is auto-detected — commas, semicolons, tabs, and pipes are all supported
- BOM-encoded UTF-8 files (common from Excel exports) are handled automatically

---

## Command-Line Arguments

```
usage: mikrotik_checker.py [-h] [--csv CSV] [--output OUTPUT]
                           [--workers WORKERS] [--timeout TIMEOUT]
                           [--verbose] [--include-raw]
```

| Argument        | Type  | Default          | Description                                          |
|-----------------|-------|------------------|------------------------------------------------------|
| `--csv`         | path  | `routers.csv`    | Path to the input CSV file                           |
| `--output`      | path  | `results.json`   | Path to write JSON results                           |
| `--workers`     | int   | `5`              | Number of concurrent SSH connections                 |
| `--timeout`     | int   | `15`             | Per-router connection and command timeout in seconds |
| `--verbose`     | flag  | off              | Enable DEBUG-level logging to stderr                 |
| `--include-raw` | flag  | off              | Include raw SSH output in the JSON for debugging     |

### Examples

Run with defaults:
```bash
python3 mikrotik_checker.py
```

Use a custom CSV and output file:
```bash
python3 mikrotik_checker.py --csv site_a.csv --output site_a_results.json
```

Increase concurrency and timeout for a large or slow network:
```bash
python3 mikrotik_checker.py --workers 20 --timeout 30
```

Debug a single router by isolating it in a CSV and using verbose + raw output:
```bash
python3 mikrotik_checker.py --csv one_router.csv --verbose --include-raw
```

---

## Output

### Terminal Output

On launch, the script prints a header block confirming the run parameters:

```
  MikroTik RouterOS Version Checker
  Connects via SSH and queries installed package versions
  Input:   routers.csv
  Output:  results.json
  Workers: 5
  Timeout: 15s
```

A live progress bar tracks scan progress, scaling to the terminal width and displaying the most recently contacted host:

```
  Scanning ████████████████░░░░ 8/10 [00:14<00:03]  192.168.1.9
```

After scanning completes, a results table is printed:

```
  ============================================================
          MikroTik RouterOS Query Results
  ============================================================
  +----------+-------------+------------------+-----------+-------+
  | Status   | Host        | RouterOS Version | Packages  | Error |
  +----------+-------------+------------------+-----------+-------+
  | ✓ OK     | 192.168.1.1 | 7.14.2           | routeros  |       |
  | ✓ OK     | 192.168.1.2 | 6.49.10          | routeros  |       |
  | ✗ ERROR  | 192.168.1.3 | N/A              | N/A       | Timed out |
  +----------+-------------+------------------+-----------+-------+

  Total: 3  |  ✓ Success: 2  |  ✗ Auth Errors: 0  |  ✗ Failed: 1
  RouterOS Versions — 6.49.10: 1  |  7.14.2: 1  |  Reported: 2/3

  Results saved: results.json
  Elapsed: 18.3s (5 workers)
```

**Status icons:**

| Icon         | Color  | Meaning                              |
|--------------|--------|--------------------------------------|
| `✓ OK`       | Green  | Packages parsed successfully         |
| `✗ AUTH ERR` | Yellow | SSH authentication failed            |
| `✗ ERROR`    | Red    | Connection failed or parse error     |

### JSON Output

Results are written to the output file with two top-level keys: `query_info` and `routers`.

```json
{
  "query_info": {
    "csv_file": "/home/user/routers.csv",
    "timestamp": "2024-11-15T10:23:45.123456+00:00",
    "protocol": "SSH / RouterOS CLI",
    "mode": "package version query",
    "workers": 5,
    "total": 3,
    "success": 2,
    "auth_errors": 0,
    "errors": 1,
    "elapsed_seconds": 18.3
  },
  "routers": [
    {
      "host": "192.168.1.1",
      "port": 22,
      "query_timestamp": "2024-11-15T10:23:46.001234+00:00",
      "status": "success",
      "routeros_version": "7.14.2",
      "packages": [
        { "name": "routeros", "version": "7.14.2" },
        { "name": "wireless", "version": "7.14.2" }
      ],
      "error": null
    },
    {
      "host": "192.168.1.3",
      "port": 22,
      "query_timestamp": "2024-11-15T10:23:47.882341+00:00",
      "status": "error",
      "routeros_version": null,
      "packages": [],
      "error": "SSH/network error: Connection timed out"
    }
  ]
}
```

**Status values:**

| Value        | Meaning                                      |
|--------------|----------------------------------------------|
| `success`    | At least one package was parsed successfully |
| `auth_error` | SSH authentication was rejected              |
| `error`      | Any other failure (network, parse, etc.)     |

When `--include-raw` is passed, each router entry also contains a `raw_output` field with the unprocessed SSH response — useful for diagnosing parse failures.

---

## Function Reference

### `load_csv`

```python
def load_csv(csv_path: str) -> list[dict]
```

Reads the input CSV and returns a list of router dicts. Handles BOM-encoded files, auto-detects the delimiter, normalizes column names to lowercase, and skips blank rows and `#` comment lines.

```python
routers = load_csv("routers.csv")
# [{"host": "192.168.1.1", "username": "admin", "password": "secret", "port": 22}, ...]
```

Exits with an error message if the file is not found, is empty, or has no recognizable host column.

---

### `check_router`

```python
def check_router(
    host: str,
    username: str = "admin",
    password: str = "",
    port: int = 22,
    timeout: int = 15,
    include_raw: bool = False,
) -> dict
```

Opens an SSH connection to a single router, runs `/system/package/print`, and returns a result dict. This is the core unit of work dispatched to each thread.

```python
result = check_router("192.168.1.1", username="admin", password="secret")

# On success:
# {
#   "host": "192.168.1.1",
#   "port": 22,
#   "query_timestamp": "2024-11-15T10:23:46+00:00",
#   "status": "success",
#   "routeros_version": "7.14.2",
#   "packages": [{"name": "routeros", "version": "7.14.2"}, ...],
#   "error": null
# }

# On auth failure:
# { "status": "auth_error", "error": "Authentication failed", ... }
```

The `disabled_algorithms` parameter passed to `paramiko.connect` disables `rsa-sha2-256` and `rsa-sha2-512` to improve compatibility with older RouterOS versions. If you are targeting only RouterOS 7.x, you can remove this parameter.

---

### `check_all_routers`

```python
def check_all_routers(
    routers: list[dict],
    output_path: Path,
    workers: int = 5,
    timeout: int = 15,
    include_raw: bool = False,
) -> None
```

Dispatches all routers to a `ThreadPoolExecutor`, collects results preserving CSV order, writes the JSON file, and calls `print_results_table`. The progress bar runs on `stderr` while table output goes to `stdout`.

```python
routers = load_csv("routers.csv")
check_all_routers(routers, Path("results.json"), workers=10, timeout=20)
```

---

### `get_command_output`

```python
def get_command_output(client: paramiko.SSHClient, command: str) -> str
```

Tries two SSH execution methods in order, returning the first non-empty response:

1. **`exec_command`** — the standard, clean approach. Works on most RouterOS versions.
2. **`invoke_shell`** — opens an interactive shell session. Used as a fallback for devices that do not respond to `exec_command`, with a 15-second polling loop.

```python
raw = get_command_output(client, "/system/package/print")
```

---

### `parse_packages`

```python
def parse_packages(raw: str) -> list[dict]
```

Extracts package name and version pairs from the raw SSH output using three strategies tried in order:

1. **Key-value pairs** — matches `name="..." version="..."` formatted output (RouterOS 7.x API-style).
2. **Indexed table rows** — matches `0  routeros  7.14.2` style columnar output, also capturing `X` (disabled) flags.
3. **Two-column fallback** — matches bare `name version` lines for minimal or stripped output.

Deduplicates results and skips header, prompt, and command-echo lines.

```python
packages = parse_packages(raw_ssh_output)
# [
#   {"name": "routeros", "version": "7.14.2"},
#   {"name": "wireless", "version": "7.14.2"},
#   {"name": "dhcp", "version": "7.14.2", "disabled": True}
# ]
```

Disabled packages (flagged with `X` in the RouterOS output) are marked with `"disabled": True` in the result.

---

### `get_routeros_version`

```python
def get_routeros_version(packages: list[dict]) -> str | None
```

Extracts the primary RouterOS version string from a parsed package list, using a priority order:

1. Any package whose name contains `routeros`
2. A package named exactly `system`
3. `None` if no suitable package is found

```python
version = get_routeros_version(packages)
# "7.14.2"
```

---

### `strip_ansi`

```python
def strip_ansi(text: str) -> str
```

Removes all ANSI escape sequences and non-printable control characters from a string. Applied to raw SSH output before parsing to prevent terminal color codes from corrupting regex matches.

```python
clean_text = strip_ansi("\033[96mrouteros\033[0m  7.14.2")
# "routeros  7.14.2"
```

---

### `clean`

```python
def clean(val) -> str
```

Sanitizes a value for display in the results table. Converts `None`, `-1`, empty strings, and known error strings to `"N/A"`.

```python
clean(None)        # "N/A"
clean(-1)          # "N/A"
clean("")          # "N/A"
clean("7.14.2")    # "7.14.2"
clean("ERROR ...")  # "N/A"
```

---

### `truncate_error`

```python
def truncate_error(err, max_len: int = 30) -> str
```

Maps verbose exception messages to short, readable labels for the table's Error column. Checks against a prioritized list of regex patterns — MikroTik/SSH-specific patterns are checked first, followed by generic network errors. Any unmatched message is stripped of IP addresses and errno codes, then truncated to `max_len` characters.

```python
truncate_error("Authentication failed")
# "Auth failed"

truncate_error("SSH/network error: Connection timed out (192.168.1.1:22)")
# "Timed out"

truncate_error("Some very long unexpected error message that goes on and on")
# "Some very long unexpected error..."
```

To add patterns for a new protocol, prepend entries to the pattern list at the top:

```python
for pat, label in [
    (r"your-new-pattern", "Short label"),  # add here
    (r"[Aa]uthentication failed", "Auth failed"),
    ...
]:
```

---

### `status_icon`

```python
def status_icon(r: dict) -> str
```

Returns a color-coded status string for a result dict, using the `status` field.

```python
status_icon({"status": "success"})    # "✓ OK"     (green)
status_icon({"status": "auth_error"}) # "✗ AUTH ERR" (yellow)
status_icon({"status": "error"})      # "✗ ERROR"  (red)
```

---

### `print_results_table`

```python
def print_results_table(
    results: list[dict],
    elapsed: float,
    workers: int,
    output_path: Path,
) -> None
```

Renders the full terminal output: title banner, results table, summary footer with per-status counts, RouterOS version breakdown, and closing footer lines. The banner width is calculated from the actual rendered table width after stripping ANSI codes, so it always aligns correctly regardless of content length.

---

## Error Handling

| Condition                        | `status`     | Error message           |
|----------------------------------|--------------|-------------------------|
| Wrong username or password       | `auth_error` | `Authentication failed` |
| Host unreachable / port closed   | `error`      | `Timed out` / `Conn refused` / etc. |
| Connected but no output returned | `error`      | `Router returned empty output` |
| Output received but unparseable  | `error`      | `Could not parse any packages from output` |
| DNS resolution failure           | `error`      | `DNS failed`            |
| Unexpected exception             | `error`      | Truncated exception text |

---

## Troubleshooting

**No packages parsed, but connection succeeds**

Run with `--include-raw --verbose` and inspect the `raw_output` field in the JSON. The router may be returning output in an unexpected format. Compare it against the three patterns in `parse_packages` and add a new regex branch if needed.

**SSH negotiation errors**

Older RouterOS versions (pre-6.45) use legacy SSH key algorithms. The script already disables `rsa-sha2-256` and `rsa-sha2-512` for broader compatibility. If you see `No matching key exchange method found`, you may need to extend `disabled_algorithms` with additional entries — check the paramiko documentation for available options.

**Progress bar and table output are interleaved**

The progress bar writes to `stderr` and the table writes to `stdout`. If you are redirecting output, redirect them separately:

```bash
python3 mikrotik_checker.py > results.txt 2> progress.txt
# or suppress the progress bar entirely:
python3 mikrotik_checker.py 2>/dev/null > results.txt
```

**Slow scans on large networks**

Increase `--workers`. Each worker holds one SSH connection open for up to `--timeout` seconds, so the practical ceiling is roughly `(total routers × avg_response_time) / workers`. Start at 10–20 workers and increase if your network and the target devices can handle the load.

```bash
python3 mikrotik_checker.py --workers 20 --timeout 10
```
