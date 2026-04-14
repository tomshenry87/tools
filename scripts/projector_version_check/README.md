# PJLink Projector Query Tool

A Python command-line tool for querying projectors and displays over the **PJLink protocol** (Class 1 and Class 2). Retrieves firmware version, lamp hours, manufacturer info, power status, and more — across an entire fleet concurrently.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CSV Input Format](#csv-input-format)
- [Command-Line Reference](#command-line-reference)
- [Query Modes](#query-modes)
- [Output](#output)
- [PJLink Class 1 vs Class 2](#pjlink-class-1-vs-class-2)
- [Understanding Firmware Results](#understanding-firmware-results)
- [Understanding Lamp Hours](#understanding-lamp-hours)
- [Authentication](#authentication)
- [Using as a Library](#using-as-a-library)
- [Troubleshooting](#troubleshooting)

---

## Features

- **PJLink Class 1 and Class 2** support with automatic class detection
- **Concurrent scanning** via a configurable thread pool for fast fleet-wide queries
- **Firmware version** retrieval — `SVER` for Class 2, `INFO` fallback for Class 1
- **Lamp hours** parsing for single and multi-lamp projectors
- **Live progress bar** showing the current host being scanned
- **Formatted terminal table** with per-device status, manufacturer, model, firmware, lamp hours, power state, and error summary
- **JSON output** with full structured results for downstream processing
- **Diagnostic mode** for raw protocol-level debugging
- **Password authentication** support (MD5 digest per PJLink spec)
- **Graceful error handling** with per-device status codes and short error labels

---

## Requirements

- Python 3.8 or later
- Network access to projectors on TCP port 4352 (default PJLink port)

### Python Dependencies

```
tabulate
tqdm
paramiko   # optional — imported but not required for core functionality
```

---

## Installation

```bash
# Clone or download the script, then install dependencies
pip3 install tabulate tqdm paramiko
```

---

## Quick Start

1. Create a `projectors.csv` file listing your devices:

```csv
host,port,password
192.168.1.10,4352,
192.168.1.11,4352,secret123
192.168.1.12,,
```

2. Run the script:

```bash
python3 pjlink_firmware.py
```

3. Results are printed to the terminal and saved to `results.json`.

---

## CSV Input Format

The input CSV must contain at minimum a `host` column. `port` and `password` are optional.

| Column     | Required | Default | Description                          |
|------------|----------|---------|--------------------------------------|
| `host`     | Yes      | —       | IP address or hostname               |
| `port`     | No       | `4352`  | TCP port (PJLink default is 4352)    |
| `password` | No       | None    | Plaintext password (hashed per spec) |

### Examples

Minimal (host only):
```csv
host
192.168.1.10
192.168.1.11
projector-lobby.local
```

Full:
```csv
host,port,password
192.168.1.10,4352,
192.168.1.11,4352,mypassword
192.168.1.12,4353,anotherpass
```

Lines beginning with `#` are treated as comments and skipped:
```csv
host,port,password
192.168.1.10,,
# 192.168.1.11,,   <- this device is skipped
192.168.1.12,,
```

The CSV parser auto-detects delimiters (`,` `;` `\t` `|`) and handles BOM-encoded files from Excel.

---

## Command-Line Reference

```
usage: pjlink_firmware.py [-h] [-i INPUT] [-o OUTPUT] [-t TIMEOUT] [-w WORKERS]
                          [--all] [--diagnostic] [--debug]
```

| Flag                   | Default           | Description                                        |
|------------------------|-------------------|----------------------------------------------------|
| `-i`, `--input`        | `projectors.csv`  | Path to input CSV file                             |
| `-o`, `--output`       | `results.json`    | Path to output JSON file                           |
| `-t`, `--timeout`      | `10`              | Per-device connection timeout in seconds           |
| `-w`, `--workers`      | `5`               | Number of concurrent worker threads                |
| `--all`                | off               | Query all available PJLink commands                |
| `--firmware VERSION [VERSION ...]` | off               | Only show devices where firmware doesn't match any provided version |
| `--diagnostic`         | off               | Run raw diagnostic mode (see below)                |
| `--debug`              | off               | Print protocol-level debug logs to stderr          |

### Usage Examples

```bash
# Use defaults (projectors.csv → results.json, 5 workers)
python3 pjlink_firmware.py

# Custom input/output files
python3 pjlink_firmware.py -i my_projectors.csv -o my_results.json

# Faster scan with 20 concurrent workers and a 5s timeout
python3 pjlink_firmware.py -w 20 -t 5

# Query every available PJLink command
python3 pjlink_firmware.py --all

# Run raw diagnostic output and save to file
python3 pjlink_firmware.py --diagnostic -o diag.json

# Enable debug logging to see raw protocol traffic
python3 pjlink_firmware.py --debug
```

---

## Query Modes

### Default Mode (firmware + lamp)

Queries the most useful fields for fleet management:

- PJLink class (`CLSS`)
- Manufacturer (`INF1`)
- Product name (`INF2`)
- Projector name (`NAME`)
- Other info / firmware (`INFO`)
- Software version — Class 2 only (`SVER`)
- Serial number — Class 2 only (`SNUM`)
- Lamp hours (`LAMP`)
- Power status (`POWR`)

### `--firmware VERSION` Mode

Filters the terminal table to show only devices where the firmware version does not exactly match the provided string. Connection errors and auth failures are suppressed from the table — only successfully queried devices with a mismatched version are shown. The full results for all devices are still written to the JSON output file regardless.

Accepts one or more space-separated version strings. A device is included in the filtered table only if its firmware does not match **any** of the provided versions.

```bash
python3 pjlink_firmware.py --firmware 1.07 1.08
```

The header block confirms which versions are being treated as current:

```
  Firmware Filter: showing mismatches against '1.07', '1.08'
```

The table title changes to reflect the filter:

```
  =====================================================
       PJLink Firmware Mismatch — Expected: 1.07, 1.08
  =====================================================
```

The summary footer shows the mismatch count and the expected version instead of the standard success/error breakdown.

**Comparison rules:**
- Exact string match only — `1.02` does not match `1.2`, `v1.02`, or `Firmware 1.02`
- Class 1 devices that return `N/A (Class 1)` are always included as a mismatch since their firmware cannot be confirmed
- Auth errors and connection failures are excluded from the filtered table but remain in the JSON

### `--all` Mode

Queries every supported command, adding:

- Current input (`INPT`)
- Available inputs (`INST`)
- AV mute status (`AVMT`)
- Error status (`ERST`)
- Filter usage — Class 2 only (`FILT`)
- Input resolution — Class 2 only (`IRES`)
- Recommended resolution — Class 2 only (`RRES`)

### `--diagnostic` Mode

Sends every command with all digest/header combinations and records the raw bytes sent and received. Useful for debugging devices that don't respond correctly. The terminal table is suppressed; full output is written to the JSON file and also printed to stdout.

Example diagnostic entry in JSON:
```json
{
  "command": "%1CLSS ?",
  "attempts": [
    {
      "digest": false,
      "sent": "b'%1CLSS ?\\r'",
      "recv": "b'%1CLSS=1\\r'",
      "parsed": "1",
      "error": null
    }
  ]
}
```

---

## Output

### Terminal Table

After scanning completes, a formatted table is printed with one row per device:

```
  ========================================================
       PJLink Projector Query Results — Firmware & Lamp Hours
  ========================================================
  +--------+---------------+--------------+------------+----------+-----+-------+------+-------+
  | Status | Host          | Manufacturer | Model      | Firmware | ... | Class | Power| Error |
  +--------+---------------+--------------+------------+----------+-----+-------+------+-------+
  | ✓ OK   | 192.168.1.10  | Epson        | EB-L1075U  | 1.02     | ... | 2     | ...  |       |
  | ✗ ERR  | 192.168.1.99  | N/A          | N/A        | N/A      | ... | N/A   | ...  | Timed out |
  +--------+---------------+--------------+------------+----------+-----+-------+------+-------+

  Total: 2  |  ✓ Success: 1  |  ✗ Auth Errors: 0  |  ✗ Failed: 1
  Lamp Hours — Avg: 1200h  |  Min: 1200h  |  Max: 1200h  |  Reported: 1/2
```

Status icons:
- `✓ OK` — query succeeded
- `✗ AUTH ERR` — device requires a password that was not provided or was incorrect
- `✗ ERROR` — connection failed or device did not respond

### JSON Output

The JSON file contains a `query_info` summary block and a `projectors` array with full per-device data.

```json
{
  "query_info": {
    "csv_file": "/home/user/projectors.csv",
    "timestamp": "2025-08-01T14:32:00+00:00",
    "protocol": "PJLink Class 1 + Class 2",
    "mode": "firmware+lamp",
    "workers": 5,
    "total": 10,
    "success": 9,
    "errors": 1,
    "elapsed_seconds": 12.4
  },
  "projectors": [
    {
      "host": "192.168.1.10",
      "port": 4352,
      "query_timestamp": "2025-08-01T14:32:01+00:00",
      "status": "success",
      "error": null,
      "pjlink_class": "2",
      "manufacturer": "Epson",
      "product_name": "EB-L1075U",
      "projector_name": "LOBBY-PROJ-01",
      "other_info": "Firmware 1.02",
      "software_version": "1.02",
      "serial_number": "X9A123456",
      "firmware_version": "1.02",
      "lamp_info_raw": "1200 1",
      "lamp_info": [
        { "lamp": 1, "hours": "1200h", "hours_int": 1200, "on": true, "status": "On" }
      ],
      "lamp_hours_total": 1200,
      "lamp_hours_total_display": "1200h",
      "lamp_hours_summary": "Lamp 1: 1200h (On)",
      "power_status": "Lamp On / Power On"
    }
  ]
}
```

---

## PJLink Class 1 vs Class 2

PJLink Class 1 is the original standard; Class 2 added additional commands. The script auto-detects which class a device supports using the `CLSS` command.

| Feature                    | Class 1       | Class 2         |
|----------------------------|---------------|-----------------|
| Power control (`POWR`)     | ✓             | ✓               |
| Lamp hours (`LAMP`)        | ✓             | ✓               |
| Manufacturer (`INF1`)      | ✓             | ✓               |
| Product name (`INF2`)      | ✓             | ✓               |
| Other info (`INFO`)        | ✓             | ✓               |
| Software version (`SVER`)  | ✗             | ✓               |
| Serial number (`SNUM`)     | ✗             | ✓               |
| Filter usage (`FILT`)      | ✗             | ✓               |
| Input resolution (`IRES`)  | ✗             | ✓               |

---

## Understanding Firmware Results

PJLink does not have a universal firmware command across both classes. The script handles this transparently:

| Class   | Source        | Notes                                                          |
|---------|---------------|----------------------------------------------------------------|
| Class 2 | `SVER`        | Dedicated software version command — reliable                  |
| Class 1 | `INFO`        | Free-form field — some manufacturers put firmware here, many do not |
| Class 1 | `N/A (Class 1)` | Returned when `INFO` is empty or unavailable — this is a protocol limitation, not a query failure |

If you see `N/A (Class 1)` in the Firmware column, the device simply does not expose firmware information via PJLink. Check the manufacturer's web interface or management software for firmware details.

---

## Understanding Lamp Hours

Lamp data is read from the `LAMP` command. The raw response format is pairs of `<hours> <status>` for each lamp:

```
# Single lamp, on, 1500 hours
1500 1

# Two lamps: lamp 1 on at 1500h, lamp 2 off at 200h
1500 1 200 0
```

The script parses this into structured per-lamp objects and also computes a total across all lamps. In the terminal table, the **total hours** across all lamps is displayed. The full per-lamp breakdown is available in the JSON output under `lamp_info`.

---

## Authentication

PJLink uses an MD5 digest challenge-response scheme. If a device requires a password:

1. The device sends a random number in its greeting: `PJLINK 1 <random>`
2. The client computes `MD5(<random> + <password>)` and prepends it to each command

Passwords must not exceed 32 bytes. Provide the **plaintext** password in the CSV — the script handles hashing automatically.

If a device returns `PJLINK ERRA`, authentication has failed. Check that the correct password is in the CSV for that host.

---

## Using as a Library

The `PJLinkClient` class can be imported and used directly in your own scripts.

### Basic connection and query

```python
from pjlink_query import PJLinkClient, PJLinkError, PJLinkAuthError

client = PJLinkClient(host="192.168.1.10", port=4352, password="secret", timeout=10)

try:
    client.connect()
    info = client.get_firmware_info()
    print(info["manufacturer"])        # e.g. "Epson"
    print(info["firmware_version"])    # e.g. "1.02" or "N/A (Class 1)"
    print(info["lamp_hours_summary"])  # e.g. "Lamp 1: 1200h (On)"
finally:
    client.disconnect()
```

### Query everything

```python
client.connect()
info = client.get_all_info()

print(info["pjlink_class"])       # "1" or "2"
print(info["power_status"])       # "Lamp On / Power On"
print(info["serial_number"])      # Class 2 only
print(info["lamp_hours_total"])   # integer, e.g. 1200
```

### Query individual commands

```python
client.connect()
client.detect_class()   # must call before class-2 commands

# Class 1 commands
print(client.get_power_status())    # "Lamp On / Power On"
print(client.get_manufacturer())    # "Epson"
print(client.get_product_name())    # "EB-L1075U"
print(client.get_name())            # "LOBBY-PROJ-01"
print(client.get_other_info())      # free-form string
print(client.get_lamp_info_raw())   # "1200 1"
print(client.get_lamp_hours_summary())  # "Lamp 1: 1200h (On)"

# Class 2 commands
print(client.get_software_version())        # "1.02"
print(client.get_serial_number())           # "X9A123456"
print(client.get_filter_usage())            # filter hours
print(client.get_input_resolution())        # "1920x1080"
print(client.get_recommended_resolution())  # "1920x1080"
```

### Parse lamp data

```python
client.connect()
lamps = client.get_lamp_info_parsed()

for lamp in lamps:
    print(f"Lamp {lamp['lamp']}: {lamp['hours']} — {lamp['status']}")
    # Lamp 1: 1200h — On
    # Lamp 2: 980h — Off

total_int, total_display = client.get_lamp_hours_total()
print(f"Total: {total_display}")   # "2180h"
```

### Run a diagnostic

```python
client.connect()
diag = client.run_diagnostic()

for cmd_entry in diag["commands"]:
    print(cmd_entry["command"])
    for attempt in cmd_entry["attempts"]:
        print(f"  sent:   {attempt['sent']}")
        print(f"  recv:   {attempt['recv']}")
        print(f"  parsed: {attempt['parsed']}")
```

---

## Troubleshooting

| Symptom                        | Likely Cause                                  | Fix                                                     |
|--------------------------------|-----------------------------------------------|---------------------------------------------------------|
| `Timed out` for all devices    | Wrong IP range or firewall blocking port 4352 | Verify network access with `telnet <host> 4352`         |
| `Conn refused`                 | PJLink not enabled on the projector           | Enable PJLink in the projector's network settings       |
| `Auth failed` / `Auth required`| Password missing or incorrect in CSV          | Add or correct the password column for that host        |
| `Not PJLink`                   | Port 4352 is open but not a PJLink device     | Confirm the correct IP and that PJLink is enabled       |
| Firmware shows `N/A (Class 1)` | Class 1 has no firmware command               | Expected — see [Understanding Firmware Results](#understanding-firmware-results) |
| Lamp hours show `N/A`          | Device is in standby or lamp command unsupported | Power on the projector or check `--diagnostic` output |
| All devices fail at once       | DNS resolution failure                        | Use IP addresses instead of hostnames, or fix DNS       |

### Enabling debug logging

To see every byte sent and received:

```bash
python3 pjlink_firmware.py --debug 2>debug.log
```

Debug output goes to stderr so it does not interfere with the progress bar or table output. Redirect to a file as shown above for easier inspection.
