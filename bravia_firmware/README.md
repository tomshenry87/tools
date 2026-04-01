# sony_fw_query.py

A concurrent command-line tool for querying Sony Bravia BZ40H/BZ40L professional displays over the network via the Sony BRAVIA REST API (JSON-RPC). Retrieves firmware version, power saving mode, MAC address, serial number, and more across an entire fleet in seconds.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CSV Input Format](#csv-input-format)
- [Authentication](#authentication)
- [Command-Line Reference](#command-line-reference)
- [Operating Modes](#operating-modes)
  - [Batch Mode (CSV)](#batch-mode-csv)
  - [Single Host Mode](#single-host-mode)
  - [Raw Dump Mode](#raw-dump-mode)
  - [Set Auth to None Mode](#set-auth-to-none-mode)
- [Terminal Output](#terminal-output)
  - [Header Block](#header-block)
  - [Progress Bar](#progress-bar)
  - [Results Table](#results-table)
  - [Summary Footer](#summary-footer)
- [JSON Output](#json-output)
- [Firmware Version Parsing](#firmware-version-parsing)
- [Power Saving Mode](#power-saving-mode)
- [Concurrent Workers](#concurrent-workers)
- [Fallback PSK](#fallback-psk)
- [API Version Negotiation](#api-version-negotiation)
- [Error Handling](#error-handling)
- [Function Reference](#function-reference)

---

## Requirements

- Python 3.8 or later
- Network access to the displays on port 80 (or 443 for HTTPS)
- IP Control enabled on each display

### Python Dependencies

```
requests
tabulate
tqdm
```

---

## Installation

```bash
# Clone or copy sony_fw_query.py to your working directory, then:
pip install requests tabulate tqdm
```

---

## Quick Start

**1. Create your input CSV:**

```csv
host,port
192.168.1.100,80
192.168.1.101,80
192.168.1.102,80
```

**2. Run the script:**

```bash
python sony_fw_query.py
```

**3. View results in the terminal and check `results.json` for the full output.**

---

## CSV Input Format

The script reads a CSV file containing one display per row. The `host` column is required; `port` is optional and defaults to `80`.

```csv
host,port
192.168.1.100,80
192.168.1.101,80
display-lobby.local,80
```

**Supported features of the CSV loader:**

- UTF-8 BOM encoding handled automatically (`utf-8-sig`)
- Delimiter auto-detection (comma, semicolon, tab, pipe)
- Rows beginning with `#` are treated as comments and skipped
- Leading/trailing whitespace stripped from all values
- Rows with an empty `host` field are silently skipped

**Example with comments:**

```csv
host,port
# Floor 1
192.168.1.100,80
192.168.1.101,80
# Floor 2
192.168.1.200,80
```

**Specifying a custom CSV path:**

```bash
python sony_fw_query.py -i /path/to/my_displays.csv
```

---

## Authentication

The Sony BRAVIA REST API supports two authentication modes. The script handles both, plus an automatic fallback.

### No Authentication (default)

Omits the `X-Auth-PSK` header entirely. This requires each display to be configured with:

```
Settings → Network & Internet → Local network setup → IP Control → Authentication → None
```

```bash
python sony_fw_query.py
```

### Pre-Shared Key (PSK)

Sends the PSK in the `X-Auth-PSK` header with every request. Configure on the display at:

```
Settings → Network & Internet → Local network setup → IP Control → Authentication → Normal and Pre-Shared Key
Settings → Network & Internet → Local network setup → IP Control → Pre-Shared Key → <your key>
```

```bash
python sony_fw_query.py -k MySecretKey
```

### Automatic Fallback PSK

If no PSK is provided (`-k` omitted) and a display returns HTTP 403, the script automatically retries the connection using the fallback PSK `"1234"`. On success, all subsequent API calls for that display use the fallback PSK. The JSON output records this in the `auth_note` field.

This is useful in mixed fleets where some displays have never had their PSK changed from the factory default.

The fallback PSK is defined as a constant at the top of the script and can be changed if needed:

```python
FALLBACK_PSK = "1234"
```

---

## Command-Line Reference

```
usage: sony_fw_query.py [-h] [-i INPUT] [--host HOST] [-o OUTPUT] [-k PSK]
                        [-t TIMEOUT] [-p PORT] [-w WORKERS]
                        [--set-auth-none] [--raw]
```

| Flag | Long form | Default | Description |
|------|-----------|---------|-------------|
| `-i` | `--input` | `displays.csv` | Path to CSV input file |
| | `--host` | — | Query a single host by IP or hostname |
| `-o` | `--output` | `results.json` | Path to JSON output file |
| `-k` | `--psk` | None | Pre-Shared Key for authentication |
| `-t` | `--timeout` | `10` | Per-request timeout in seconds |
| `-p` | `--port` | `80` | Port when using `--host` mode |
| `-w` | `--workers` | `5` | Number of concurrent worker threads |
| | `--set-auth-none` | False | Set IP control auth to None on all displays |
| | `--raw` | False | Dump raw API responses (requires `--host`) |

---

## Operating Modes

### Batch Mode (CSV)

The default mode. Reads a CSV file and queries all listed displays concurrently.

```bash
# Default CSV, default settings
python sony_fw_query.py

# Custom CSV and output file
python sony_fw_query.py -i building_a.csv -o building_a_results.json

# With PSK authentication
python sony_fw_query.py -i displays.csv -k 0000

# Increase timeout and workers for a slow or large network
python sony_fw_query.py -i displays.csv -t 20 -w 10

# Full example
python sony_fw_query.py -i displays.csv -k 0000 -t 15 -o output.json -w 8
```

---

### Single Host Mode

Query a single display directly without a CSV file. Useful for testing connectivity or inspecting a specific unit.

```bash
# Basic single host query
python sony_fw_query.py --host 192.168.1.100

# Single host with PSK and custom port
python sony_fw_query.py --host 192.168.1.100 -p 80 -k 0000

# Single host with custom output file
python sony_fw_query.py --host 192.168.1.100 -o display_100.json
```

---

### Raw Dump Mode

Requires `--host`. Sends `getSystemInformation` for every supported API version (`1.7`, `1.4`, `1.0`) and prints the raw JSON responses to the terminal. Also dumps `getInterfaceInformation`. Useful for discovering what fields a specific display firmware returns.

```bash
python sony_fw_query.py --host 192.168.1.100 --raw

python sony_fw_query.py --host 192.168.1.100 --raw -k 0000
```

**Example output:**

```
--- v1.7 ---
{
  "result": [{
    "generation": "5.6.0",
    "model": "FW-55BZ40H",
    "serial": "1234567",
    "macAddr": "aa:bb:cc:dd:ee:ff",
    "fwVersion": "PKG1.6.0.81.60.1.00.0960BBA",
    "androidOs": "12",
    "name": "BRAVIA",
    "product": "TV"
  }],
  "id": 1
}

--- v1.4 ---
{
  "error": [12, "not implemented"]
}
...
```

---

### Set Auth to None Mode

Uses the provided PSK to remotely set the IP Control authentication mode to `None` on every display in the CSV (or a single host). After this runs, the displays will accept REST API requests without any PSK.

Requires `-k` to be set.

```bash
# Set auth to None across all displays in CSV
python sony_fw_query.py --set-auth-none -k 0000

# Set auth to None on a single display
python sony_fw_query.py --set-auth-none -k 0000 --host 192.168.1.100

# Custom CSV with non-default PSK
python sony_fw_query.py --set-auth-none -k MyKey -i displays.csv
```

This calls `setRemoteDeviceSettings` with `target: accessPermission, value: off` on `/sony/system`, which is equivalent to navigating to:

```
Settings → Network & Internet → Local network setup → IP Control → Authentication → None
```

---

## Terminal Output

### Header Block

Printed immediately on launch before scanning begins:

```
  Sony Bravia BZ40H/BZ40L — Firmware Query Tool
  Queries firmware version and power saving mode via Sony REST API.
  Input:   displays.csv
  Output:  results.json
  Workers: 5
  Timeout: 10s
  Auth:    None (fallback: 1234)
  API:     1.7 -> 1.4 -> 1.0 (automatic fallback)
```

---

### Progress Bar

A cyan-filled progress bar rendered to `stderr` (does not mix with table output). Displays completion count, elapsed/remaining time, and the most recently started host.

```
  Scanning ████████████████░░░░  12/20 [00:08<00:05]  192.168.1.112
```

On completion:

```
  Scanning ████████████████████  20/20 [00:13<00:00]  Complete in 13.2s
```

---

### Results Table

Printed after all queries complete. Columns follow the project style guide convention:

| Column | Description |
|--------|-------------|
| Status | `✓ OK` (green), `✗ AUTH ERR` (yellow), `✗ ERROR` (red) |
| Host | IP address or hostname |
| Model | Display model (e.g. `FW-55BZ40H`) |
| Firmware | Parsed firmware version (e.g. `6.0.81.60`) or generation string |
| Serial | Device serial number |
| MAC Address | Active NIC MAC address |
| API Ver | API version that responded (`1.7`, `1.4`, or `1.0`) |
| Pwr Save | Human-readable power saving mode |
| Error | Short error label, or fallback PSK note if applicable |

> The `Port` column is intentionally excluded from the table — it is recorded in the JSON output.

---

### Summary Footer

```
  Total: 20  |  ✓ Success: 18  |  ✗ Auth Errors: 1  |  ✗ Failed: 1
  Power Saving — Off (disabled): 15  |  Low: 3  |  Reported: 18/20

  Results saved: results.json
  Elapsed: 13.2s (5 workers)
```

---

## JSON Output

Results are written to `results.json` (or the path specified via `-o`). The file has two top-level keys: `query_info` and `displays`.

```json
{
  "query_info": {
    "csv_file": "/absolute/path/to/displays.csv",
    "timestamp": "2025-04-01T14:22:00.123456+00:00",
    "protocol": "Sony BRAVIA REST API (JSON-RPC, versions 1.7, 1.4, 1.0)",
    "mode": "None (fallback: 1234)",
    "workers": 5,
    "total": 20,
    "success": 18,
    "auth_errors": 1,
    "errors": 1,
    "elapsed_seconds": 13.2
  },
  "displays": [
    {
      "host": "192.168.1.100",
      "port": 80,
      "status": "success",
      "model": "FW-55BZ40H",
      "serial": "1234567",
      "firmware_version": "6.0.81.60",
      "firmware_version_raw": "PKG1.6.0.81.60.1.00.0960BBA",
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "device_name": "BRAVIA",
      "interface_version": "5.6.0",
      "product_name": "TV",
      "generation": "5.6.0",
      "api_version_used": "1.7",
      "power_saving_mode": "off",
      "auth_note": null,
      "error": null,
      "query_timestamp": "2025-04-01T14:22:01.456789+00:00"
    },
    {
      "host": "192.168.1.101",
      "port": 80,
      "status": "success",
      "model": "FW-43BZ40L",
      "serial": "7654321",
      "firmware_version": "6.0.81.60",
      "firmware_version_raw": "PKG1.6.0.81.60.1.00.0960BBA",
      "mac_address": "aa:bb:cc:dd:ee:00",
      "device_name": "BRAVIA",
      "interface_version": "5.6.0",
      "product_name": "TV",
      "generation": "5.6.0",
      "api_version_used": "1.7",
      "power_saving_mode": "low",
      "auth_note": "fallback PSK '1234' used",
      "error": null,
      "query_timestamp": "2025-04-01T14:22:02.123456+00:00"
    },
    {
      "host": "192.168.1.102",
      "port": 80,
      "status": "error",
      "model": "N/A",
      "serial": "N/A",
      "firmware_version": "N/A",
      "firmware_version_raw": "N/A",
      "mac_address": "N/A",
      "device_name": "N/A",
      "interface_version": "N/A",
      "product_name": "N/A",
      "generation": "N/A",
      "api_version_used": "N/A",
      "power_saving_mode": "N/A",
      "auth_note": null,
      "error": "Connection timed out",
      "query_timestamp": "2025-04-01T14:22:12.654321+00:00"
    }
  ]
}
```

### Status Values

| Value | Meaning |
|-------|---------|
| `success` | Query completed successfully |
| `auth_error` | HTTP 403 — PSK required or incorrect |
| `error` | Connection failure or API error |

---

## Firmware Version Parsing

On API v1.7 devices, the `fwVersion` field contains a full build string in Sony's internal format. The script parses this into a short, human-readable version number for the table.

**Format:** `PKG<major>.<v1>.<v2>.<v3>.<v4>.<rest...>`

**Example:**

```
PKG1.6.0.81.60.1.00.0960BBA  →  6.0.81.60
```

The full raw string is preserved in `firmware_version_raw` in the JSON output. On v1.0/v1.4 devices where `fwVersion` is not available, the `generation` field (e.g. `5.0.1`) is used instead and `firmware_version_raw` is `N/A`.

---

## Power Saving Mode

Queried via `getPowerSavingMode` (v1.0) on `/sony/system`. This API requires no authentication (auth level: `None`), so it works regardless of the display's PSK setting. Failure does not affect the overall query status.

| API Value | Table Display |
|-----------|---------------|
| `off` | Off (disabled) |
| `low` | Low |
| `high` | High |
| `pictureOff` | Picture Off (panel off) |

Any undocumented value returned by the API is shown as-is rather than replaced with `N/A`, so unexpected values are visible in the output.

---

## Concurrent Workers

The script uses `concurrent.futures.ThreadPoolExecutor` to query multiple displays simultaneously. The default is **5 workers**, configurable via `-w`.

```bash
# Use 10 workers for a large fleet
python sony_fw_query.py -w 10

# Use 1 worker for sequential (debugging)
python sony_fw_query.py -w 1
```

**How it works:**

- One thread is spawned per display up to the worker limit
- Results are collected as futures complete (`as_completed`)
- A thread lock ensures the progress bar postfix always shows the most recently started host
- A second lock protects the results list from concurrent writes
- Results are re-sorted to match the original CSV input order before display and saving

**Tuning guidance:**

| Fleet Size | Recommended Workers |
|------------|---------------------|
| 1–20 | 5 (default) |
| 20–100 | 10 |
| 100+ | 15–20 |

Very high worker counts on slow networks may cause spurious timeouts. Increase `-t` alongside `-w` if needed.

---

## API Version Negotiation

`getSystemInformation` is attempted in descending version order: **v1.7 → v1.4 → v1.0**. The script tries the next version if the display returns error code `12` (not implemented) or `15` (unsupported version). Any other error is raised immediately.

| API Version | Key Field | Notes |
|-------------|-----------|-------|
| v1.7 | `fwVersion` | Full firmware build string, parsed to short form |
| v1.4 | `generation` | Intermediate; used as firmware identifier |
| v1.0 | `generation` | Oldest; generation string only |

The API version that ultimately responded is recorded in both the table (`API Ver` column) and the JSON (`api_version_used` field).

---

## Error Handling

All errors are non-fatal at the fleet level — a failure on one display does not stop queries to others. Each display's `status` and `error` fields reflect its individual outcome.

### Error Label Mapping

Verbose exception messages are mapped to short labels in the `Error` column:

| Exception | Table Label |
|-----------|-------------|
| Connection timed out | `Timed out` |
| Connection refused | `Conn refused` |
| No route to host | `No route` |
| Network unreachable | `Net unreachable` |
| DNS resolution failure | `DNS failed` |
| HTTP 403 | `Auth failed` |
| HTTP 404 | `IP ctrl disabled` |
| All API versions failed | `API unsupported` |
| Malformed response | `Bad response` |

### HTTP 404 — IP Control Not Enabled

If the display returns HTTP 404, IP Control is not enabled. Enable it at:

```
Settings → Network & Internet → Local network setup → IP Control → Simple IP control → On
```

### HTTP 403 — Authentication Required

If the display returns HTTP 403 with no PSK set, the fallback PSK `"1234"` is tried automatically. If that also fails, the display is marked `auth_error`. Resolve by either:

- Running `--set-auth-none -k <correct_psk>` to remove the PSK requirement
- Passing the correct PSK via `-k`

---

## Function Reference

### `load_csv(csv_path) → list`
Loads the input CSV. Handles BOM encoding, auto-detects delimiter, skips comment rows. Returns a list of `{"host": str, "port": int}` dicts.

### `query_display(host, port, psk, timeout) → dict`
Queries a single display. Calls `getSystemInformation` (with version fallback), `getInterfaceInformation`, `getNetworkSettings` (MAC fallback), and `getPowerSavingMode`. Returns a result dict with all fields populated.

### `get_system_information(host, port, psk, timeout) → (dict, str)`
Attempts `getSystemInformation` at v1.7, v1.4, v1.0 in order. Returns the result dict and the API version string that succeeded.

### `get_interface_information(host, port, psk, timeout) → dict`
Calls `getInterfaceInformation` v1.0. Returns the result dict or `{}` on error.

### `get_network_settings(host, port, psk, timeout) → list`
Calls `getNetworkSettings` v1.0 with `netif: ""` to retrieve all interfaces. Used as a fallback source for the MAC address when `getSystemInformation` does not return `macAddr`.

### `get_power_saving_mode(host, port, psk, timeout) → str`
Calls `getPowerSavingMode` v1.0. Returns the raw mode string (`"off"`, `"low"`, `"high"`, `"pictureOff"`) or `"N/A"` on any failure.

### `set_auth_none(host, port, psk, timeout) → (bool, str)`
Calls `setRemoteDeviceSettings` with `accessPermission: off` to remove the PSK requirement. Returns `(True, message)` on success or `(False, reason)` on failure.

### `call_sony_api(host, port, method, params, version, request_id, psk, timeout) → dict`
Generic JSON-RPC caller. Builds the URL, payload, and headers, then POSTs and returns the parsed response dict. Raises on non-2xx HTTP status.

### `parse_fw_version(raw) → str`
Parses a raw Sony `fwVersion` string to a short version number. Returns the raw string unchanged if parsing fails.

### `format_power_saving_mode(mode) → str`
Maps a raw power saving mode value to its human-readable label.

### `status_icon(result) → str`
Returns a coloured ANSI status string for a result dict based on its `status` field.

### `clean(val) → str`
Sanitises a value for table display. Converts `None`, `"-1"`, empty strings, and known error sentinels to `"N/A"`.

### `truncate_error(err, max_len) → str`
Maps a verbose exception message to a short label using regex patterns. Falls back to a truncated version of the raw string.

### `print_results_table(results, output_file, elapsed, workers)`
Renders the full results table, title banner, summary footer, and closing lines to stdout following the project visual style guide.

### `save_results_json(results, filepath, args, elapsed)`
Writes the `query_info` + `displays` JSON structure to the specified output file.
