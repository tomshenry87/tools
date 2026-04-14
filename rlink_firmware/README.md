# RackLink Select Series — Device Query Tool

A Python CLI tool for querying firmware version, serial number, model, and MAC address from **Middle Atlantic RackLink Select Series** PDUs (RLNK-915R, RLNK-415R, RLNK-215) over their browser-based web interface.

---

## Table of Contents

- [Overview](#overview)
- [Supported Devices](#supported-devices)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Input CSV Format](#input-csv-format)
- [Usage](#usage)
  - [CSV Batch Mode (default)](#csv-batch-mode-default)
  - [Single Host Mode](#single-host-mode)
  - [Firmware Filter](#firmware-filter)
  - [All CLI Arguments](#all-cli-arguments)
- [Output](#output)
  - [Terminal Table](#terminal-table)
  - [JSON File](#json-file)
- [Troubleshooting](#troubleshooting)
- [Notes](#notes)

---

## Overview

RackLink Select Series PDUs expose a browser-based web interface for monitoring and control. This tool authenticates against that interface, scrapes the HTML pages, and extracts key device identity fields. It is designed for AV integrators and IT administrators who need to audit firmware versions and serial numbers across a fleet of deployed PDUs.

The tool supports two input modes:

- **CSV batch mode** — reads a list of devices from `pdu.csv` and queries them concurrently.
- **Single host mode** — queries one device by IP via a CLI argument.

All results are written to `results.json` regardless of input mode. The terminal table can optionally filter out devices that are already on a target firmware version using the `--firmware` flag.

---

## Supported Devices

| Model      | Form Factor      | Outlets |
|------------|------------------|---------|
| RLNK-915R  | 1U Rackmount     | 9       |
| RLNK-415R  | Half Rack        | 4       |
| RLNK-215   | Compact / 0U     | 2       |

Other RackLink models (RLNK-1015V, RLNK-1615V, Premium+ series) may also work but have not been tested. The HTML parsing patterns are based on the Select Series web interface across firmware versions up to v2.0.1.

---

## How It Works

1. For each device, the script attempts to connect via **HTTPS first**, then falls back to **HTTP**.
2. It authenticates using HTTP Basic Auth with the credentials from the CSV or CLI arguments.
3. It fetches several known page paths across firmware versions (home, info, network, firmware pages).
4. It parses the returned HTML using regex patterns to extract:
   - **Model** (e.g. `RLNK-915R`)
   - **Device Name** (user-configured label)
   - **Firmware Version** (e.g. `2.0.1`)
   - **Serial Number**
   - **MAC Address**
5. Results are printed in a formatted terminal table and saved to `results.json`.

---

## Requirements

- Python 3.8 or higher
- Network access to the RackLink PDUs on their configured port (default 80 or 443)

### Python Packages

| Package         | Purpose                          | Install Method           |
|-----------------|----------------------------------|--------------------------|
| `tabulate`      | Terminal table formatting         | `pip install tabulate`   |
| `tqdm`          | Progress bar                     | `pip install tqdm`       |

All HTTP and HTML parsing is handled by Python's standard library (`urllib.request`, `html.parser`, `ssl`, `base64`) — no `requests` or `beautifulsoup4` needed.

---

## Installation

```bash
# Clone or copy rlink_firmware.py into your project directory
# Then install the two dependencies:
pip install tabulate tqdm
```

If your system blocks `pip install` (newer Debian/Ubuntu), these are likely already installed system-wide from your other scripts. If not:

```bash
sudo apt install python3-tabulate python3-tqdm
```

---

## Input CSV Format

Create a file called `pdu.csv` in the same directory as the script. The file must have a header row with the following columns:

| Column      | Required | Default | Description                        |
|-------------|----------|---------|------------------------------------|
| `host`      | Yes      | —       | IP address or hostname of the PDU  |
| `port`      | No       | `443`   | Web interface port                 |
| `user_name` | No       | `admin` | Login username                     |
| `pw`        | No       | `admin` | Login password                     |

### Example `pdu.csv`

```csv
host,port,user_name,pw
192.168.1.100,80,admin,admin
192.168.1.101,80,admin,admin
192.168.1.102,443,admin,s3cure!
10.0.50.200,80,admin,admin
```

### CSV Notes

- The loader handles UTF-8 BOM encoding automatically.
- Delimiters are auto-detected (comma, semicolon, tab, pipe).
- Rows where `host` is empty or starts with `#` are skipped, so you can comment out devices.
- Column name matching is case-insensitive.

---

## Usage

### CSV Batch Mode (default)

Read from `pdu.csv` in the current directory and write results to `results.json`:

```bash
python rlink_firmware.py
```

Specify a different input file:

```bash
python rlink_firmware.py -i /path/to/other_devices.csv
```

### Single Host Mode

Query one device without a CSV file:

```bash
python rlink_firmware.py --host 192.168.1.100
```

With custom port, username, and password:

```bash
python rlink_firmware.py --host 192.168.1.100 --port 80 -u admin -p s3cure!
```

### Firmware Filter

Pass `--firmware` with the current/target version to hide up-to-date devices from the terminal table. The JSON output still contains every device.

```bash
python rlink_firmware.py --firmware 2.0.1
```

This is useful when auditing a fleet — the table shows only the devices that still need updating, while `results.json` has the complete picture.

### All CLI Arguments

| Argument              | Short | Default          | Description                                         |
|-----------------------|-------|------------------|-----------------------------------------------------|
| `--host`              |       | —                | Single device IP or hostname (skips CSV)             |
| `--port`              |       | `443`            | Port for single host mode                            |
| `--username`          | `-u`  | `admin`          | Username for single host mode                        |
| `--password`          | `-p`  | `admin`          | Password for single host mode                        |
| `--firmware`          |       | —                | Hide devices matching this firmware from the table   |
| `--input`             | `-i`  | `pdu.csv`        | Input CSV file path                                  |
| `--output`            | `-o`  | `results.json`   | Output JSON file path                                |
| `--workers`           | `-w`  | `5`              | Number of concurrent threads                         |
| `--timeout`           | `-t`  | `10`             | Connection timeout in seconds per device             |

---

## Output

### Terminal Table

The script prints a formatted table to the terminal with the following columns:

| Column         | Description                                      |
|----------------|--------------------------------------------------|
| Status         | `✓ OK` (green), `✗ AUTH ERR` (yellow), or `✗ ERROR` (red) |
| Host           | IP address or hostname                           |
| Manufacturer   | Always "Middle Atlantic"                         |
| Model          | Detected model (e.g. RLNK-915R) or N/A          |
| Firmware       | Firmware version string or N/A                   |
| Serial Number  | Device serial number or N/A                      |
| MAC Address    | Device MAC address or N/A                        |
| Error          | Short error label if the query failed            |

A summary footer shows total counts, success/failure breakdown, and unique firmware versions found across the fleet.

### JSON File

Results are written to `results.json` (or the path specified with `-o`). The JSON always contains **all** queried devices, regardless of the `--firmware` filter.

```json
{
  "query_info": {
    "csv_file": "/path/to/pdu.csv",
    "timestamp": "2026-04-14T18:30:00.000000+00:00",
    "protocol": "HTTP/HTTPS (RackLink Web UI)",
    "mode": "web_scrape",
    "workers": 5,
    "total": 4,
    "success": 3,
    "errors": 1,
    "elapsed_seconds": 8.42
  },
  "pdus": [
    {
      "host": "192.168.1.100",
      "port": 80,
      "query_timestamp": "2026-04-14T18:30:01.000000+00:00",
      "status": "success",
      "error": null,
      "manufacturer": "Middle Atlantic",
      "model": "RLNK-915R",
      "device_name": "Server Room PDU",
      "firmware_version": "2.0.1",
      "serial_number": "MA2023045678",
      "mac_address": "00:1A:2B:3C:4D:5E"
    }
  ]
}
```

### JSON Fields

| Field              | Type        | Description                                        |
|--------------------|-------------|----------------------------------------------------|
| `host`             | string      | IP or hostname queried                             |
| `port`             | integer     | Port used for connection                           |
| `query_timestamp`  | string      | UTC ISO 8601 timestamp of the query                |
| `status`           | string      | `"success"`, `"auth_error"`, or `"error"`          |
| `error`            | string/null | Error message on failure, `null` on success        |
| `manufacturer`     | string      | Always `"Middle Atlantic"`                         |
| `model`            | string/null | Detected model identifier                          |
| `device_name`      | string/null | User-configured device label                       |
| `firmware_version` | string/null | Firmware version string                            |
| `serial_number`    | string/null | Device serial number                               |
| `mac_address`      | string/null | Device MAC address                                 |

---

## Troubleshooting

### Connection Errors

| Error Label     | Meaning                                                        | Fix                                                  |
|-----------------|----------------------------------------------------------------|------------------------------------------------------|
| Timed out       | Device did not respond within the timeout window               | Increase `-t`, verify device is powered and on network |
| Conn refused    | Device actively refused the connection                         | Verify port is correct, check if web UI is enabled    |
| Auth failed     | HTTP 401 — credentials were rejected                           | Check `user_name` and `pw` in CSV                    |
| Unreachable     | Could not reach device over HTTPS or HTTP                      | Verify IP, check VLANs, firewall rules               |
| Parse failed    | Connected successfully but could not extract data from HTML    | See "Parse Issues" below                             |

### Parse Issues

The script extracts data using regex patterns against the web interface HTML. If a device shows `✓ OK` but fields are `N/A`, the HTML structure may differ from what the patterns expect. To diagnose:

1. Open the device's web interface in a browser: `http://<ip>/`
2. View page source and search for the firmware version, serial number, etc.
3. Note the surrounding HTML structure.
4. Update the regex patterns in the `query_racklink()` function to match.

This is most likely to happen if:
- The device is running a very old firmware version with a different page layout.
- The device is a Premium+ model (RLNK-P series) rather than Select Series.

### Default Credentials

RackLink devices ship with `admin` / `admin` as the default credentials. If the password has been changed and you don't know it, pressing the **Restore Defaults** button on the physical device will reset credentials back to `admin` / `admin` (note: this also resets the device to DHCP).

---

## Notes

- **HTTPS / Self-Signed Certs** — Most RackLink devices use self-signed certificates. The script disables SSL verification to handle this. This is expected and safe on a local management network.
- **Firmware v2.0.1** — Middle Atlantic released this update in September 2025, adding HTTPS, SSH, and RackLink Cloud support. Devices on older firmware only serve HTTP.
- **Concurrency** — The default of 5 workers is conservative. For large fleets on a reliable network, you can safely increase to 10–20 with `-w`.
- **No REST API** — The Select Series does not expose a formal REST or SNMP API. This tool works by scraping the HTML web interface, which means it may need pattern updates if Middle Atlantic changes the page layout in future firmware versions.
