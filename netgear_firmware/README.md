# Netgear M4250 Firmware & CPU Temp Checker

A command-line tool that connects to one or more Netgear M4250 managed switches over SSH, retrieves firmware version and CPU temperature, and outputs a formatted terminal table and a structured JSON report.

> **Note:** All examples in this document use `python3`. On some systems Python 3 may also be invoked as `python` — verify with `python --version` before substituting.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CSV Input Format](#csv-input-format)
- [Command-Line Arguments](#command-line-arguments)
- [Terminal Output](#terminal-output)
- [JSON Output](#json-output)
- [Functions Reference](#functions-reference)
- [Troubleshooting](#troubleshooting)

---

## Requirements

- Python 3.10+
- Netgear M4250 switches accessible over SSH
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

Place `netgear_m4250_checker.py` and your `switches.csv` in the same directory.

---

## Quick Start

```bash
# Run with all defaults (reads switches.csv, writes results.json)
python3 netgear_firmware.py

# Specify a different CSV and output file
python3 netgear_firmware.py --csv my_switches.csv --output my_results.json

# Increase concurrency and enable verbose logging
python3 netgear_firmware.py --workers 10 --verbose

# Include raw SSH output in the JSON for debugging
python3 netgear_firmware.py --include-raw
```

---

## CSV Input Format

The script reads switch credentials from a CSV file. The file must have at minimum a `host` column. All other columns are optional and fall back to defaults if omitted.

### Supported Columns

| Column     | Required | Default | Description                        |
|------------|----------|---------|------------------------------------|
| `host`     | Yes      | —       | IP address or hostname of the switch |
| `username` | No       | `admin` | SSH login username                 |
| `password` | No       | `""`    | SSH login password                 |
| `port`     | No       | `22`    | SSH port number                    |

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
                            [--verbose] [--include-raw]
```

| Argument        | Default          | Description                                              |
|-----------------|------------------|----------------------------------------------------------|
| `--csv`         | `switches.csv`   | Path to the input CSV file                               |
| `--output`      | `results.json`   | Path to write the JSON results file                      |
| `--workers`     | `5`              | Number of concurrent SSH connections                     |
| `--timeout`     | `20`             | Per-switch SSH connection timeout in seconds             |
| `--verbose`     | off              | Enable DEBUG-level logging to stderr                     |
| `--include-raw` | off              | Append raw SSH command output to each device in the JSON |

### Examples

```bash
# Use 10 parallel workers with a 30-second timeout
python3 netgear_firmware.py --workers 10 --timeout 30

# Debug a single switch by including raw output and enabling verbose logging
python3 netgear_firmware.py --csv one_switch.csv --include-raw --verbose

# Write results to a timestamped file
python3 netgear_firmware.py --output results_2024-01-15.json
```

---

## Terminal Output

### Header Block

On launch, the script prints a confirmation header before any scanning begins:

```
  Netgear M4250 Firmware & CPU Temp Checker
  Query switch firmware version and CPU temperature via SSH
  Input:   switches.csv
  Output:  results.json
  Workers: 5
  Timeout: 20s
```

### Progress Bar

A live progress bar tracks scanning progress. It displays the most recently started host in the postfix and updates as each switch completes. On finish, it shows total elapsed time.

```
  Scanning ████████████████████ 12/12 [00:18<00:00]  Complete in 18.3s
```

- The bar is written to `stderr` so it does not interfere with piped or redirected output
- The bar remains visible after scanning completes (`leave=True`)
- Width scales dynamically to the terminal width

### Results Table

After scanning, a formatted table is printed to `stdout`:

```
  ============================================================
        Netgear M4250 Query Results — Firmware & CPU Temp
  ============================================================
  +----------+---------------+----------+----------+----------+
  | Status   | Host          | Firmware | CPU Temp | Error    |
  +----------+---------------+----------+----------+----------+
  | ✓ OK     | 192.168.1.10  | 12.0.20.7| 109 °F   |          |
  | ✓ OK     | 192.168.1.11  | 12.0.20.7| 113 °F   |          |
  | ✗ ERROR  | 192.168.1.12  | N/A      | N/A      | Timed out|
  | ✗ AUTH ERR| 192.168.1.13 | N/A      | N/A      | Auth failed|
  +----------+---------------+----------+----------+----------+

  Total: 4  |  ✓ Success: 2  |  ✗ Auth Errors: 1  |  ✗ Failed: 1
  CPU Temp (°F) — Avg: 111  |  Min: 109  |  Max: 113  |  Reported: 2/4

  Results saved: results.json
  Elapsed: 18.3s (5 workers)
```

### Status Icons

| Status      | Display      | Meaning                              |
|-------------|--------------|--------------------------------------|
| `success`   | `✓ OK`       | Firmware and/or temp retrieved       |
| `auth_error`| `✗ AUTH ERR` | SSH credentials were rejected        |
| `error`     | `✗ ERROR`    | Connection failed or parse error     |

---

## JSON Output

Results are written to the output file with a `query_info` metadata block and a `switches` array.

### Structure

```json
{
  "query_info": {
    "csv_file": "/path/to/switches.csv",
    "timestamp": "2024-01-15T14:32:00.123456+00:00",
    "protocol": "SSH / Netgear M4250 CLI",
    "mode": "firmware+temp",
    "workers": 5,
    "total": 4,
    "success": 2,
    "errors": 2,
    "elapsed_seconds": 18.3
  },
  "switches": [
    {
      "host": "192.168.1.10",
      "username": "admin",
      "port": 22,
      "query_timestamp": "2024-01-15T14:31:52.001234+00:00",
      "status": "success",
      "firmware_version": "12.0.20.7",
      "cpu_temp": "109 °F",
      "cpu_temp_value": 109.4,
      "error": null
    },
    {
      "host": "192.168.1.12",
      "username": "admin",
      "port": 22,
      "query_timestamp": "2024-01-15T14:31:58.004321+00:00",
      "status": "error",
      "firmware_version": null,
      "cpu_temp": null,
      "cpu_temp_value": null,
      "error": "SSH/network error: Connection timed out"
    }
  ]
}
```

### Field Reference

#### `query_info`

| Field             | Type    | Description                                  |
|-------------------|---------|----------------------------------------------|
| `csv_file`        | string  | Path to the input CSV                        |
| `timestamp`       | string  | UTC ISO 8601 time the run completed          |
| `protocol`        | string  | Always `"SSH / Netgear M4250 CLI"`           |
| `mode`            | string  | Always `"firmware+temp"`                     |
| `workers`         | integer | Number of concurrent workers used            |
| `total`           | integer | Total switches queried                       |
| `success`         | integer | Number of successful queries                 |
| `errors`          | integer | Number of failed queries                     |
| `elapsed_seconds` | float   | Total wall-clock runtime in seconds          |

#### Per-switch entry (`switches[]`)

| Field              | Type           | Description                                           |
|--------------------|----------------|-------------------------------------------------------|
| `host`             | string         | IP or hostname from the CSV                           |
| `username`         | string         | SSH username used                                     |
| `port`             | integer        | SSH port used                                         |
| `query_timestamp`  | string         | UTC ISO 8601 time this switch was queried             |
| `status`           | string         | `"success"`, `"auth_error"`, or `"error"`             |
| `firmware_version` | string or null | Parsed firmware version string, e.g. `"12.0.20.7"`   |
| `cpu_temp`         | string or null | Formatted temperature string, e.g. `"109 °F"`        |
| `cpu_temp_value`   | float or null  | Raw numeric temperature in °F for calculations       |
| `error`            | string or null | Error message on failure, `null` on success           |
| `raw_version`      | string         | Raw `show hardware` output — only present with `--include-raw` |
| `raw_environment`  | string         | Raw `show environment` output — only present with `--include-raw` |

---

## Functions Reference

### `load_csv(csv_path)`

Reads switch credentials from a CSV file. Handles BOM encoding, auto-detects delimiters, and skips comment lines.

```python
switches = load_csv(Path("switches.csv"))
# Returns a list of dicts:
# [{"host": "192.168.1.10", "username": "admin", "password": "pass", "port": 22}, ...]
```

---

### `check_switch(host, username, password, port, timeout, include_raw)`

Connects to a single switch via SSH and retrieves firmware version and CPU temperature. Returns a result dict.

```python
result = check_switch(
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
#   "firmware_version": "12.0.20.7",
#   "cpu_temp": "109 °F",
#   "cpu_temp_value": 109.4,
#   "error": null,
#   ...
# }
```

The function opens an interactive SSH shell (rather than using exec channels) because the M4250 CLI requires an interactive session for commands like `terminal length 0` and `en` (enable mode).

---

### `parse_firmware_version(raw)`

Extracts the firmware version string from the raw output of `show hardware`. Tries multiple regex patterns to handle variation across firmware builds.

```python
raw = """
  Software Version...................  12.0.20.7
  Boot Version.......................  1.0.0.8
"""
version = parse_firmware_version(raw)
# Returns: "12.0.20.7"
```

Patterns tried in order:
1. `Software Version....... X.Y.Z`
2. `Firmware Version: X.Y.Z`
3. `Build Number: N`
4. Generic `Version X.Y.Z` anywhere in the output

---

### `parse_cpu_temp(raw)`

Extracts the CPU temperature from the raw output of `show environment | include Temp`. Returns a tuple of `(display_string, numeric_value)` where the value is in °F.

```python
raw = "Temp (C)....................................... 40"
display, value = parse_cpu_temp(raw)
# Returns: ("104 °F", 104.0)
```

The raw switch output is in Celsius. The function converts to Fahrenheit using the standard formula: `°F = °C × 9/5 + 32`.

---

### `check_all_switches(switches, output_path, include_raw, max_workers, timeout)`

Runs `check_switch` concurrently across all switches using a `ThreadPoolExecutor`. Results are stored in order regardless of completion order. Displays the progress bar during execution, then calls `print_results_table` and writes the JSON output file.

```python
switches = load_csv(Path("switches.csv"))
check_all_switches(
    switches=switches,
    output_path=Path("results.json"),
    include_raw=False,
    max_workers=5,
    timeout=20,
)
```

---

### `print_results_table(results, elapsed)`

Renders the terminal results table, summary footer, and metrics line from a completed list of result dicts.

```python
print_results_table(all_results, elapsed=18.3)
```

---

### `status_icon(r)`

Returns a color-coded status string for use in the table's Status column.

```python
status_icon({"status": "success"})   # "✓ OK"   (green)
status_icon({"status": "auth_error"})# "✗ AUTH ERR" (yellow)
status_icon({"status": "error"})     # "✗ ERROR" (red)
```

---

### `clean(val)`

Normalizes a value for table display. Converts `None`, `"-1"`, empty strings, and known error strings to `"N/A"`.

```python
clean(None)          # "N/A"
clean("12.0.20.7")   # "12.0.20.7"
clean("")            # "N/A"
clean(-1)            # "N/A"
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

Strips all ANSI escape sequences and non-printable control characters from a string. Used to clean raw SSH terminal output before parsing.

```python
raw = "\033[96mSoftware Version....... 12.0.20.7\033[0m"
clean_text = strip_ansi(raw)
# Returns: "Software Version....... 12.0.20.7"
```

---

## Troubleshooting

**`Authentication failed` on all switches**
Verify the username and password columns in your CSV. If the switch has an enable password configured, the `en` command will hang — this is not currently handled automatically.

**`Timed out` on reachable switches**
Try increasing `--timeout`. Default is 20 seconds; switches under load or on slow links may need 30–60 seconds.

**`Parse error` — firmware version not found**
Run with `--include-raw` and inspect the `raw_version` field in the JSON to see the actual `show hardware` output from that switch. The firmware may use a format not yet covered by `parse_firmware_version`.

**CPU Temp shows `N/A` for all switches**
Some M4250 firmware versions do not support the `| include` pipe filter. Run with `--include-raw` and check `raw_environment` in the JSON. If the output is present but in a different format, the regex in `parse_cpu_temp` may need adjusting.

**Progress bar and table output are interleaved**
The progress bar writes to `stderr` and the table writes to `stdout`. If both are being redirected to the same destination (e.g. a log file via `2>&1`), they will interleave. Redirect them separately:

```bash
python3 netgear_firmware.py > results.txt 2> progress.txt
```
