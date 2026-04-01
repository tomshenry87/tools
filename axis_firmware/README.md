# AXIS VAPIX Camera Query Tool

A concurrent command-line tool that queries AXIS IP cameras via the official VAPIX API to retrieve firmware version, model information, MAC address, serial number, and live temperature readings. Results are displayed in a formatted terminal table and saved to a structured JSON file.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [CSV Input Format](#csv-input-format)
- [Terminal Output](#terminal-output)
- [JSON Output](#json-output)
- [Functions Reference](#functions-reference)
- [Error Handling](#error-handling)
- [Extending the Script](#extending-the-script)
- [Troubleshooting](#troubleshooting)

---

## Features

- **Concurrent querying** — queries multiple cameras simultaneously using a configurable thread pool
- **VAPIX API coverage** — uses three official AXIS VAPIX endpoints: `basicdeviceinfo.cgi`, `param.cgi`, and `temperaturecontrol.cgi`
- **Multi-sensor temperature support** — reads all available temperature sensors and selects the most relevant one for display, with full sensor data saved to JSON
- **Smart error classification** — distinguishes authentication failures from network errors, with short human-readable labels in the table
- **Resilient per-camera isolation** — a failure on one camera never aborts the others; MAC and temperature failures are non-fatal
- **Structured JSON output** — every run writes a `results.json` with a `query_info` metadata block and a full per-camera record
- **Consistent terminal style** — colour-coded status icons, live progress bar, summary statistics, and temperature aggregate metrics

---

## Requirements

- Python 3.10+
- AXIS cameras accessible over HTTPS with digest authentication enabled
- The following Python packages:

```
requests
urllib3
tabulate
tqdm
```

---

## Installation

```bash
git clone https://github.com/your-org/axis-vapix-query.git
cd axis-vapix-query
pip3 install -r requirements.txt
```

`requirements.txt`:

```
requests>=2.31.0
urllib3>=2.0.0
tabulate>=0.9.0
tqdm>=4.66.0
```

---

## Quick Start

1. Create a `cameras.csv` file in the same directory as the script (see [CSV Input Format](#csv-input-format)).
2. Run the script:

```bash
python3 axis_firmware.py
```

Output is printed to the terminal and saved to `results.json`.

---

## Configuration

All runtime options are defined as constants near the top of the script. Edit these directly before running.

```python
CSV_FILE    = "cameras.csv"   # Path to input CSV
OUTPUT_FILE = "results.json"  # Path to JSON output
MAX_WORKERS = 5               # Concurrent camera queries
TIMEOUT     = 10              # Per-request timeout in seconds
VERIFY_SSL  = False           # Set True if cameras have valid TLS certificates
```

**`MAX_WORKERS`** controls how many cameras are queried at the same time. With `TIMEOUT = 10`, a full failure sweep of 50 cameras takes approximately `ceil(50 / MAX_WORKERS) * TIMEOUT` seconds in the worst case. Increase `MAX_WORKERS` on fast, reliable networks; reduce it on congested or high-latency segments.

**`VERIFY_SSL`** is `False` by default because AXIS cameras ship with self-signed certificates. Set it to `True` and ensure your CA bundle is up to date if your cameras have been provisioned with valid certificates.

### Sensor Preference Order

The `PREFERRED_SENSORS` list controls which temperature sensor is shown in the table when a camera exposes multiple sensors. The first match wins.

```python
PREFERRED_SENSORS = ["main", "soc", "cpu", "board", "case"]
```

All sensors are always saved in full to the JSON output regardless of this setting. To prefer a different sensor — for example `"optics"` on a fisheye model — prepend it to the list:

```python
PREFERRED_SENSORS = ["optics", "main", "soc", "cpu", "board", "case"]
```

---

## CSV Input Format

The input file must be a UTF-8 CSV (BOM is handled automatically) with at minimum a `host` column. The delimiter is auto-detected — comma, semicolon, tab, and pipe are all supported.

### Minimum columns

```csv
host
192.168.1.10
192.168.1.11
```

When `username` or `password` are absent, `username` defaults to `root` and `password` defaults to an empty string.

### Full columns

```csv
host,username,password
192.168.1.10,root,mypassword
192.168.1.11,admin,secret
camera-lobby.local,root,
```

### Comment lines

Prefix any row with `#` to skip it:

```csv
host,username,password
192.168.1.10,root,pass1
# 192.168.1.11,root,pass2   <- skipped
192.168.1.12,root,pass3
```

### Notes

- Hostnames and IP addresses are both accepted in the `host` column
- Extra whitespace around values is stripped automatically
- Duplicate hosts are allowed but will appear as separate rows in the output

---

## Terminal Output

### Header block

Printed immediately on launch before any scanning begins:

```
  AXIS VAPIX Camera Query
  Queries firmware version and temperature via VAPIX API
  Input:   cameras.csv
  Output:  results.json
  Workers: 5
  Timeout: 10s
  Devices: 12
```

### Progress bar

A live progress bar shows scan progress, elapsed time, and the most recently started host:

```
  Scanning ████████████░░░░░░░░  7/12 [00:08<00:06]  192.168.1.17
```

On completion the postfix updates to:

```
  Scanning ████████████████████  12/12 [00:14<00:00]  ✓ Complete in 14.2s
```

### Results table

After scanning, a formatted table is printed with one row per camera:

```
  ===========================================================================
           AXIS Camera Query Results — Firmware & Temperature
  ===========================================================================
  +------------+----------------+-------------+----------+-------------------+
  | Status     | Host           | Model       | Firmware | Temperature       |
  +------------+----------------+-------------+----------+-------------------+
  | ✓ OK       | 192.168.1.10   | M4328-P     | 11.11.68 | 110.30°F (Main)   |
  | ✓ OK       | 192.168.1.11   | M3068-P     | 11.11.68 | 107.60°F (Main)   |
  | ✗ AUTH ERR | 192.168.1.12   | N/A         | N/A      | N/A               |
  | ✗ ERROR    | 192.168.1.13   | N/A         | N/A      | N/A               |
  +------------+----------------+-------------+----------+-------------------+
```

Status colours: **green** = success, **yellow** = authentication error, **red** = network or other error.

### Summary footer

```
  Total: 12  |  ✓ Success: 10  |  ✗ Auth Errors: 1  |  ✗ Failed: 1
  Temperature (°F) — Avg: 109.4  |  Min: 104.0  |  Max: 118.2  |  Reported: 10/12

  Results saved: results.json
  Elapsed: 14.2s (5 workers)
```

---

## JSON Output

Every run overwrites `results.json` with a top-level `query_info` metadata block followed by a `cameras` array.

### Top-level structure

```json
{
  "query_info": {
    "csv_file": "/home/user/axis-query/cameras.csv",
    "timestamp": "2025-03-14T10:22:01.443210+00:00",
    "protocol": "VAPIX 3 (HTTPS/Digest)",
    "mode": "firmware+temperature",
    "workers": 5,
    "total": 12,
    "success": 10,
    "auth_errors": 1,
    "errors": 1,
    "elapsed_seconds": 14.2
  },
  "cameras": [ ... ]
}
```

### Successful camera record

```json
{
  "host": "192.168.1.10",
  "query_timestamp": "2025-03-14T10:22:04.112000+00:00",
  "status": "success",
  "error": null,
  "firmware_version": "11.11.68",
  "model": "M4328-P",
  "serial_number": "ACCC8E123456",
  "mac_address": "AC:CC:8E:12:34:56",
  "build_date": "Mar 10 2025 10:00",
  "temperature_c": "43.50",
  "temperature_f": "110.30",
  "sensor_name": "Main",
  "all_sensors": [
    {
      "sensor_id": "S0",
      "sensor_name": "Main",
      "temperature_c": "43.50",
      "temperature_f": "110.30"
    },
    {
      "sensor_id": "S1",
      "sensor_name": "CPU",
      "temperature_c": "50.44",
      "temperature_f": "122.79"
    }
  ]
}
```

### Failed camera record

```json
{
  "host": "192.168.1.13",
  "query_timestamp": "2025-03-14T10:22:09.004000+00:00",
  "status": "error",
  "error": "Timed out",
  "firmware_version": "N/A",
  "model": "N/A",
  "serial_number": "N/A",
  "mac_address": "N/A",
  "build_date": "N/A",
  "temperature_c": "N/A",
  "temperature_f": "N/A",
  "sensor_name": "N/A",
  "all_sensors": []
}
```

### Status values

| Value        | Meaning                                      |
|--------------|----------------------------------------------|
| `success`    | All queries completed without error          |
| `auth_error` | HTTP 401 or 403 — credentials rejected       |
| `error`      | Network failure, timeout, or unexpected error |

---

## Functions Reference

### `load_csv(csv_path: str) -> list`

Loads and validates the camera CSV. Handles BOM encoding, auto-detects the delimiter, skips blank rows and `#` comment lines, and normalises column names to lowercase. Exits with an error message if the file is missing, empty, or lacks a `host` column.

```python
cameras = load_csv("cameras.csv")
# [{"host": "192.168.1.10", "username": "root", "password": "pass"}, ...]
```

---

### `get_firmware_and_model(host: str, auth: HTTPDigestAuth) -> dict`

Posts to `/axis-cgi/basicdeviceinfo.cgi` using the VAPIX Basic Device Information API (`getAllProperties` method). Strips noise words (`AXIS`, `Network Camera`, `Fixed Dome`, etc.) from the full product name before returning.

```python
auth = HTTPDigestAuth("root", "password")
info = get_firmware_and_model("192.168.1.10", auth)
# {
#   "firmware_version": "11.11.68",
#   "model": "M4328-P",
#   "serial_number": "ACCC8E123456",
#   "build_date": "Mar 10 2025 10:00"
# }
```

---

### `get_mac_address(host: str, auth: HTTPDigestAuth) -> str`

GETs `/axis-cgi/param.cgi?action=list&group=Network.eth0.MACAddress`. Parses the plain-text `key=value` response and returns the MAC string, or `"N/A"` if unparseable.

```python
mac = get_mac_address("192.168.1.10", auth)
# "AC:CC:8E:12:34:56"
```

---

### `get_temperature(host: str, auth: HTTPDigestAuth) -> dict`

GETs `/axis-cgi/temperaturecontrol.cgi?action=statusall`. Parses the `Sensor.SN.Field=value` plain-text response into a structured dict. Selects the best sensor for table display using `PREFERRED_SENSORS`; all sensors are preserved in `all_sensors`.

```python
temp = get_temperature("192.168.1.10", auth)
# {
#   "temperature_c": "43.50",
#   "temperature_f": "110.30",
#   "sensor_name": "Main",
#   "all_sensors": [
#     {"sensor_id": "S0", "sensor_name": "Main", "temperature_c": "43.50", "temperature_f": "110.30"},
#     {"sensor_id": "S1", "sensor_name": "CPU",  "temperature_c": "50.44", "temperature_f": "122.79"}
#   ]
# }
```

---

### `query_camera(row: dict) -> dict`

The per-camera worker function submitted to the thread pool. Calls `get_firmware_and_model`, `get_mac_address`, and `get_temperature` in sequence. MAC and temperature failures are non-fatal — the result is still marked `"success"` if firmware info was retrieved, with `mac_error` or `temp_error` fields added for diagnostics. Updates `_latest_host` for progress bar display.

```python
result = query_camera({"host": "192.168.1.10", "username": "root", "password": "pass"})
# {"host": "192.168.1.10", "status": "success", "firmware_version": "11.11.68", ...}
```

---

### `clean(val) -> str`

Normalises any value for safe table display. Converts `None`, `"None"`, `"-1"`, and empty strings to `"N/A"`. Strips known error sentinel strings.

```python
clean(None)          # "N/A"
clean("")            # "N/A"
clean("-1")          # "N/A"
clean("11.11.68")    # "11.11.68"
```

---

### `truncate_error(err, max_len=30) -> str`

Maps verbose exception messages to short readable labels using a regex pattern table. VAPIX-specific HTTP patterns (`401`, `403`, `404`) are checked first, followed by generic network patterns. Falls back to truncating at `max_len` characters with `...`.

```python
truncate_error("HTTP 401")                      # "Auth failed"
truncate_error("Connection timed out")          # "Timed out"
truncate_error("No route to host")              # "No route"
truncate_error("Some unexpected long error…")   # "Some unexpected lon..."
```

---

### `status_icon(r: dict) -> str`

Returns a colour-coded status string for the table's Status column based on the `"status"` key of a result dict.

```python
status_icon({"status": "success"})    # "✓ OK"     (green)
status_icon({"status": "auth_error"}) # "✗ AUTH ERR" (yellow)
status_icon({"status": "error"})      # "✗ ERROR"  (red)
```

---

### `format_temp(result: dict) -> str`

Formats the selected temperature for table display. Returns Fahrenheit with the sensor name in parentheses, or `"N/A"` if no temperature was retrieved.

```python
format_temp({"temperature_f": "110.30", "sensor_name": "Main"})  # "110.30°F (Main)"
format_temp({"temperature_f": "N/A",    "sensor_name": "N/A"})   # "N/A"
```

---

### `save_json(results: list, elapsed: float) -> None`

Writes the full result set to `OUTPUT_FILE` as formatted JSON. Computes `success`, `auth_errors`, and `errors` counts from the result list and includes them in the `query_info` block alongside run metadata.

---

## Error Handling

### Per-camera error isolation

Each camera is queried independently. An exception in one worker does not affect others. The main `try/except` in `query_camera` catches:

| Exception                          | Result status  | Error label    |
|------------------------------------|----------------|----------------|
| `HTTPError` with 401 or 403        | `auth_error`   | `Auth failed`  |
| `HTTPError` with other 4xx/5xx     | `error`        | `HTTP error`   |
| `ConnectTimeout`                   | `error`        | `Timed out`    |
| `ConnectionError`                  | `error`        | `Unreachable`  |
| Any other exception                | `error`        | Truncated text |

### Non-fatal sub-query failures

MAC address and temperature queries each run in their own `try/except` inside `query_camera`. A failure in either does not change the top-level `status` — the camera is still marked `success` if firmware info was retrieved. Diagnostic fields are added to the result:

```python
# If MAC query fails:
result["mac_error"] = "Timed out"

# If temperature query fails:
result["temp_error"] = "API not found"
```

Both fields appear in the JSON output but are not shown in the terminal table.

---

## Extending the Script

### Adding a new VAPIX endpoint

Add a new function following the same pattern as `get_firmware_and_model`:

```python
def get_video_settings(host: str, auth: HTTPDigestAuth) -> dict:
    url = f"https://{host}/axis-cgi/videostatus.cgi"
    resp = requests.get(url, auth=auth, timeout=TIMEOUT, verify=VERIFY_SSL)
    resp.raise_for_status()
    # parse and return a dict
    return {"resolution": "...", "framerate": "..."}
```

Then call it inside `query_camera` as a non-fatal block:

```python
try:
    video = get_video_settings(host, auth)
    result.update(video)
except Exception as ve:
    result["video_error"] = truncate_error(str(ve))
```

### Adding a new table column

Add the field to the `headers` list and the corresponding `rows.append(...)` call inside `print_table`, following the column order convention (Status → Host → Model → Firmware → custom columns → Error):

```python
headers = ["Status", "Host", "Model", "Firmware", "Resolution", "Framerate", "Temperature", "Error"]

rows.append([
    status_icon(r),
    clean(r.get("host")),
    clean(r.get("model")),
    clean(r.get("firmware_version")),
    clean(r.get("resolution")),    # new
    clean(r.get("framerate")),     # new
    clean(format_temp(r)),
    truncate_error(r.get("error") or ""),
])
```

### Adding a new error pattern

Prepend protocol-specific patterns to the list inside `truncate_error`:

```python
for pat, label in [
    # VAPIX-specific — add new patterns here
    (r"temperaturecontrol.*not supported", "No temp sensor"),
    (r"HTTP 401",                          "Auth failed"),
    ...
]:
```

---

## Troubleshooting

**All cameras show `✗ AUTH ERR`**
Verify the credentials in `cameras.csv`. AXIS cameras use HTTP Digest authentication — Basic auth credentials will not work. The default username on most AXIS cameras is `root`.

**All cameras show `Timed out`**
Check that the cameras are reachable from the host running the script and that HTTPS (port 443) is not blocked by a firewall. Try reducing `MAX_WORKERS` on congested networks.

**Temperature shows `N/A` but firmware is retrieved**
Not all AXIS camera models expose the `temperaturecontrol.cgi` API. Check the camera's VAPIX support page. A `temp_error` field in the JSON output will contain the specific failure reason.

**Table columns are misaligned in the terminal**
The table width is scaled to the terminal at launch via `shutil.get_terminal_size`. Resizing the terminal window mid-run may cause visual misalignment — re-run after resizing.

**`results.json` is missing entries**
The script preserves original CSV order after async completion using `host_order`. If a host appears more than once in `cameras.csv`, only the last occurrence's index is used for sorting — duplicate hosts will sort to their last CSV position.
