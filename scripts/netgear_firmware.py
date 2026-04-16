# Netgear M4250 Firmware & CPU Temp Checker

A command-line tool that connects to one or more Netgear M4250 routers over SSH, retrieves firmware version, CPU temperature, and total PoE power consumed, and outputs a formatted terminal table and a structured JSON report.

> **Note:** All examples use `python3`. On some systems Python 3 may also be invoked as `python` — verify with `python --version` before substituting.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Directory Structure](#directory-structure)
- [CSV Input Format](#csv-input-format)
- [Command-Line Arguments](#command-line-arguments)
- [Terminal Output](#terminal-output)
- [JSON Output](#json-output)
- [Functions Reference](#functions-reference)
- [Troubleshooting](#troubleshooting)

---

## Requirements

- Python 3.10+
- Netgear M4250 routers accessible over SSH
- The following Python packages:

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

Place `netgear_firmware.py` in your scripts directory and create the required input/output folders alongside it.

---

## Quick Start

```bash
# Run with all defaults
python3 netgear_firmware.py

# Specify a different CSV and output file
python3 netgear_firmware.py --csv secrets/netgear_firmware.csv --output netgear_firmware/files/results.json

# Increase concurrency and enable verbose logging
python3 netgear_firmware.py --workers 10 --verbose

# Only show routers not running the expected firmware version
python3 netgear_firmware.py --firmware 13.0.4.9

# Combine firmware filter with a custom CSV for an audit run
python3 netgear_firmware.py --firmware 13.0.4.9 --csv secrets/netgear_firmware.csv --output netgear_firmware/files/audit.json

# Include raw SSH output in the JSON for debugging
python3 netgear_firmware.py --include-raw
```

---

## Directory Structure

```
scripts/
├── netgear_firmware.py
├── secrets/
│   └── netgear_firmware.csv       # Router credentials (input)
└── netgear_firmware/
    └── files/
        └── results_2024-01-15_09-30-00.json   # Timestamped output
```

The `netgear_firmware/files/` directory is created automatically on first run if it does not exist.

---

## CSV Input Format

The script reads router credentials from `secrets/netgear_firmware.csv` by default. The file must have at minimum a `host` column. All other columns are optional and fall back to defaults if omitted.

### Supported Columns

| Column     | Required | Default | Description                         |
|------------|----------|---------|-------------------------------------|
| `host`     | Yes      | —       | IP address or hostname of the router |
| `username` | No       | `admin` | SSH login username                  |
| `password` | No       | `""`    | SSH login password                  |
| `port`     | No       | `22`    | SSH port number                     |

### Example CSV

```csv
host,username,password,port
192.168.1.10,admin,mypassword,22
192.168.1.11,admin,mypassword,22
192.168.1.12,admin,otherpassword,22
# This line is a comment and will be skipped
192.168.1.13,admin,mypassword,22
```

### CSV Format Notes

- The loader auto-detects delimiters — commas, semicolons, tabs, and pipes are all supported
- Files with a UTF-8 BOM (common when exported from Excel) are handled automatically
- Lines where the host field starts with `#` are treated as comments and skipped
- Column names are case-insensitive and leading/trailing whitespace is stripped

---

## Command-Line Arguments

```
usage: netgear_firmware.py [-h] [--csv CSV] [--output OUTPUT]
                            [--workers WORKERS] [--timeout TIMEOUT]
                            [--firmware FIRMWARE]
                            [--verbose] [--include-raw]
```

| Argument        | Default                                                   | Description                                                                      |
|-----------------|-----------------------------------------------------------|----------------------------------------------------------------------------------|
| `--csv`         | `secrets/netgear_firmware.csv`                            | Path to the input CSV file                                                       |
| `--output`      | `netgear_firmware/files/results_YYYY-MM-DD_HH-MM-SS.json` | Path to write the JSON results file                                              |
| `--workers`     | `5`                                                       | Number of concurrent SSH connections                                             |
| `--timeout`     | `20`                                                      | Per-router SSH connection timeout in seconds                                     |
| `--firmware`    | off                                                       | Only show routers whose firmware does not match this version (e.g. `13.0.4.9`)  |
| `--verbose`     | off                                                       | Enable DEBUG-level logging to stderr                                             |
| `--include-raw` | off                                                       | Append raw SSH command output to each router entry in the JSON                  |

### Examples

```bash
# Use 10 parallel workers with a 30-second timeout
python3 netgear_firmware.py --workers 10 --timeout 30

# Only show routers not running 13.0.4.9
python3 netgear_firmware.py --firmware 13.0.4.9

# Debug a single router by including raw output and enabling verbose logging
python3 netgear_firmware.py --csv secrets/netgear_firmware.csv --include-raw --verbose

# Write results to a custom filename
python3 netgear_firmware.py --output netgear_firmware/files/audit_2024-01-15.json
```

---

## Terminal Output

### Header Block

On launch, the script prints a confirmation header before any scanning begins:

```
  Netgear M4250 Firmware & CPU Temp Checker
  Query router firmware version and CPU temperature via SSH
  Input:   secrets/netgear_firmware.csv
  Output:  netgear_firmware/files/results_2024-01-15_09-30-00.json
  Workers: 5
  Timeout: 20s
```

When `--firmware` is active, a Filter line is appended:

```
  Filter:  firmware != 13.0.4.9
```

### Progress Bar

A live progress bar tracks scanning progress, showing the most recently completed host in the postfix. On finish it shows total elapsed time.

```
  Scanning ████████████████████ 12/12 [00:18<00:00]  Complete in 18.3s
```

- Written to `stderr` so it does not interfere with piped or redirected output
- Remains visible after scanning completes
- Width scales dynamically to the terminal width

### Results Table

After scanning, a formatted table is printed to `stdout`:

```
  ============================================================
      Netgear M4250 Query Results — Firmware & CPU Temp
  ============================================================
  +------------+---------------+-----------+----------+---------------+----------+
  | Status     | Host          | Firmware  | CPU Temp | Total PoE (W) | Error    |
  +------------+---------------+-----------+----------+---------------+----------+
  | ✓ OK       | 192.168.1.10  | M4250-10G2F-PoE+ | 13.0.4.9  | 109 °F   | 82.4 W        |          |
  | ✓ OK       | 192.168.1.11  | M4250-10G2F-PoE+ | 13.0.4.9  | 113 °F   | 91.0 W        |          |
  | ✗ ERROR    | 192.168.1.12  | N/A              | N/A       | N/A      | N/A           | Timed out|
  | ✗ AUTH ERR | 192.168.1.13  | N/A              | N/A       | N/A      | N/A           | Auth failed|
  +------------+---------------+-----------+----------+---------------+----------+

  Total: 4  |  ✓ Success: 2  |  ✗ Auth Errors: 1  |  ✗ Failed: 1
  CPU Temp (°F) — Avg: 111  |  Min: 109  |  Max: 113  |  Reported: 2/4
  Total PoE (W) — Avg: 86.7  |  Min: 82.4  |  Max: 91.0  |  Reported: 2/4

  Results saved: netgear_firmware/files/results_2024-01-15_09-30-00.json
  Elapsed: 18.3s (5 workers)
```

### Status Icons

| Status      | Display       | Meaning                              |
|-------------|---------------|--------------------------------------|
| `success`   | `✓ OK`        | Firmware and/or temp retrieved       |
| `auth_error`| `✗ AUTH ERR`  | SSH credentials were rejected        |
| `error`     | `✗ ERROR`     | Connection failed or parse error     |

### Firmware Filter

When `--firmware` is passed, only routers with a version mismatch appear in the table. Routers that failed to connect are excluded from the filtered view since they have no version to compare.

The banner title changes to reflect the expected version:

```
  ============================================================
       Netgear M4250 — Firmware Mismatch: expected 13.0.4.9
  ============================================================
```

A firmware summary line is added to the footer:

```
  Firmware Filter: 13.0.4.9  |  ✓ Matched: 10  |  ✗ Mismatched: 2
```

If every reachable router matches the expected version, the table is skipped and a single confirmation line is printed instead:

```
  ✓ All reachable routers are running firmware 13.0.4.9
```

> **Note:** The JSON output always contains all results regardless of the filter. The filter only affects what is shown in the terminal table.

---

## JSON Output

Results are written to a timestamped file under `netgear_firmware/files/` with a `query_info` metadata block and a `routers` array.

### Structure

```json
{
  "query_info": {
    "csv_file": "/path/to/netgear_firmware/files",
    "timestamp": "2024-01-15T14:32:00.123456+00:00",
    "protocol": "SSH / Netgear M4250 CLI",
    "mode": "firmware+temp",
    "workers": 5,
    "total": 4,
    "success": 2,
    "errors": 2,
    "elapsed_seconds": 18.3
  },
  "routers": [
    {
      "host": "192.168.1.10",
      "username": "admin",
      "port": 22,
      "query_timestamp": "2024-01-15T14:31:52.001234+00:00",
      "status": "success",
      "model": "M4250-10G2F-PoE+",
      "firmware_version": "13.0.4.9",
      "cpu_temp": "109 °F",
      "cpu_temp_value": 109.4,
      "poe_consumed": "82.4 W",
      "poe_consumed_value": 82.4,
      "error": null
    },
    {
      "host": "192.168.1.12",
      "username": "admin",
      "port": 22,
      "query_timestamp": "2024-01-15T14:31:58.004321+00:00",
      "status": "error",
      "model": null,
      "firmware_version": null,
      "cpu_temp": null,
      "cpu_temp_value": null,
      "poe_consumed": null,
      "poe_consumed_value": null,
      "error": "SSH/network error: Connection timed out"
    }
  ]
}
```

### Field Reference

#### `query_info`

| Field             | Type    | Description                                  |
|-------------------|---------|----------------------------------------------|
| `csv_file`        | string  | Path to the output directory                 |
| `timestamp`       | string  | UTC ISO 8601 time the run completed          |
| `protocol`        | string  | Always `"SSH / Netgear M4250 CLI"`           |
| `mode`            | string  | Always `"firmware+temp"`                     |
| `workers`         | integer | Number of concurrent workers used            |
| `total`           | integer | Total routers queried                        |
| `success`         | integer | Number of successful queries                 |
| `errors`          | integer | Number of failed queries                     |
| `elapsed_seconds` | float   | Total wall-clock runtime in seconds          |

#### Per-router entry (`routers[]`)

| Field               | Type           | Description                                               |
|---------------------|----------------|-----------------------------------------------------------|
| `host`              | string         | IP or hostname from the CSV                               |
| `username`          | string         | SSH username used                                         |
| `port`              | integer        | SSH port used                                             |
| `query_timestamp`   | string         | UTC ISO 8601 time this router was queried                 |
| `status`            | string         | `"success"`, `"auth_error"`, or `"error"`                 |
| `model`             | string or null | Parsed model string, e.g. `"M4250-10G2F-PoE+"`            |
| `firmware_version`  | string or null | Parsed firmware version string, e.g. `"13.0.4.9"`        |
| `cpu_temp`          | string or null | Formatted temperature string, e.g. `"109 °F"`            |
| `cpu_temp_value`    | float or null  | Raw numeric temperature in °F                            |
| `poe_consumed`      | string or null | Formatted PoE string, e.g. `"82.4 W"`                    |
| `poe_consumed_value`| float or null  | Raw numeric PoE watts                                     |
| `error`             | string or null | Error message on failure, `null` on success               |
| `raw_version`       | string         | Raw `show hardware` output — only with `--include-raw`    |
| `raw_environment`   | string         | Raw `show environment` output — only with `--include-raw` |
| `raw_poe`           | string         | Raw `show poe` output — only with `--include-raw`         |

---

## Functions Reference

### `load_csv(csv_path)`

Reads router credentials from a CSV file. Handles BOM encoding, auto-detects delimiters, and skips comment lines.

```python
routers = load_csv(Path("secrets/netgear_firmware.csv"))
# Returns:
# [{"host": "192.168.1.10", "username": "admin", "password": "pass", "port": 22}, ...]
```

---

### `check_router(host, username, password, port, timeout, include_raw)`

Connects to a single router via SSH and retrieves firmware version, CPU temperature, and total PoE power consumed. Returns a result dict.

```python
result = check_router(
    host="192.168.1.10",
    username="admin",
    password="mypassword",
    port=22,
    timeout=20,
    include_raw=False,
)
# Returns:
# {
#   "host": "192.168.1.10",
#   "status": "success",
#   "firmware_version": "13.0.4.9",
#   "cpu_temp": "109 °F",
#   "cpu_temp_value": 109.4,
#   "poe_consumed": "82.4 W",
#   "poe_consumed_value": 82.4,
#   "error": null
# }
```

---

### `parse_machine_model(raw)`

Extracts the machine model string from the raw output of `show hardware`. Since `show hardware` is already called to retrieve firmware version, no additional SSH command is required.

```python
raw = "Machine Model.................. M4250-10G2F-PoE+"
model = parse_machine_model(raw)
# Returns: "M4250-10G2F-PoE+"
```

---

### `parse_firmware_version(raw)`

Extracts the firmware version string from the raw output of `show hardware`. Tries multiple regex patterns to handle variation across firmware builds.

```python
raw = "Software Version...................  13.0.4.9"
version = parse_firmware_version(raw)
# Returns: "13.0.4.9"
```

Patterns tried in order: `Software Version`, `Firmware Version`, `Build Number`, then a generic `Version X.Y.Z` anywhere in the output.

---

### `parse_cpu_temp(raw)`

Extracts the CPU temperature from the raw output of `show environment | include Temp`. Returns a `(display_string, numeric_value)` tuple. The raw router value is in Celsius and is converted to Fahrenheit using `°F = °C × 9/5 + 32`.

```python
raw = "Temp (C)....................................... 40"
display, value = parse_cpu_temp(raw)
# Returns: ("104 °F", 104.0)
```

---

### `parse_poe_power(raw)`

Extracts the total PoE power consumed from the raw output of `show poe`. Returns a `(display_string, numeric_value)` tuple in watts.

```python
raw = "Total Power Consumed...........................  82.4 Watts"
display, value = parse_poe_power(raw)
# Returns: ("82.4 W", 82.4)
```

The display string is always formatted to one decimal place (e.g. `"82.4 W"`, `"120.0 W"`).

---

### `check_all_routers(routers, output_path, include_raw, max_workers, timeout, firmware_filter)`

Runs `check_router` concurrently across all routers using a `ThreadPoolExecutor`. Results are stored in CSV order regardless of completion order. Displays the progress bar during execution, writes the JSON file, then calls `print_results_table`.

```python
routers = load_csv(Path("secrets/netgear_firmware.csv"))
check_all_routers(
    routers=routers,
    output_path=Path("netgear_firmware/files/results_2024-01-15_09-30-00.json"),
    include_raw=False,
    max_workers=5,
    timeout=20,
    firmware_filter="13.0.4.9",
)
```

---

### `print_results_table(results, elapsed, firmware_filter)`

Renders the terminal results table, summary footer, and metrics lines. When `firmware_filter` is provided, only mismatched routers are shown. If all routers match, a single confirmation line is printed instead of the table.

```python
print_results_table(all_results, elapsed=18.3, firmware_filter="13.0.4.9")
```

---

### `status_icon(r)`

Returns a color-coded status string for the table's Status column.

```python
status_icon({"status": "success"})    # "✓ OK"       (green)
status_icon({"status": "auth_error"}) # "✗ AUTH ERR" (yellow)
status_icon({"status": "error"})      # "✗ ERROR"    (red)
```

---

### `clean(val)`

Normalizes a value for table display. Converts `None`, `"-1"`, empty strings, and known error strings to `"N/A"`.

```python
clean(None)         # "N/A"
clean("13.0.4.9")   # "13.0.4.9"
clean("")           # "N/A"
clean(-1)           # "N/A"
```

---

### `truncate_error(err, max_len=30)`

Maps verbose exception messages to short human-readable labels for the Error column. SSH-specific patterns are checked first, followed by generic network error patterns.

```python
truncate_error("Authentication failed")          # "Auth failed"
truncate_error("Connection timed out")           # "Timed out"
truncate_error("No route to host")               # "No route"
truncate_error("Could not parse firmware version from output")  # "Parse error"
truncate_error(None)                             # ""
```

---

### `strip_ansi(text)`

Strips all ANSI escape sequences and non-printable control characters from a string. Used to clean raw SSH terminal output before regex parsing.

```python
raw = "\033[96mSoftware Version....... 13.0.4.9\033[0m"
clean_text = strip_ansi(raw)
# Returns: "Software Version....... 13.0.4.9"
```

---

## Troubleshooting

**`Authentication failed` on all routers**
Verify the username and password columns in your CSV. If the router has an enable password configured, the `en` command will hang waiting for a prompt that is not currently handled.

**`Timed out` on reachable routers**
Try increasing `--timeout`. The default is 20 seconds; routers under load or on slow links may need 30–60 seconds.

**`Parse error` — firmware version not found**
Run with `--include-raw` and inspect the `raw_version` field in the JSON to see the actual `show hardware` output. The firmware may use a format not yet covered by `parse_firmware_version`.

**Total PoE shows `N/A` for all routers**
Run with `--include-raw` and check `raw_poe` in the JSON. The label on the router should read `Total Power Consumed...` with dots separating the label from the value. If the format differs, the regex in `parse_poe_power` may need adjusting.

**CPU Temp shows `N/A` for all routers**
Some M4250 firmware versions do not support the `| include` pipe filter. Run with `--include-raw` and check `raw_environment` in the JSON to see what the router is actually returning.

**Progress bar and table output are interleaved**
The progress bar writes to `stderr` and the table writes to `stdout`. If both are redirected to the same destination they will interleave. Redirect them separately:

```bash
python3 netgear_firmware.py > results.txt 2> progress.txt
```
