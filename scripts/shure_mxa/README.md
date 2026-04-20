# Shure MXA Microphone — Firmware Query Tool

Query Shure MXA-series ceiling and table array microphones for device information using the Shure Command Strings protocol.

## Supported Models

| Model   | Type                | Status     |
|---------|---------------------|------------|
| MXA920  | Ceiling array (S/R) | ✓ Verified |
| MXA910  | Ceiling array       | ✓ Supported |
| MXA710  | Linear array        | ✓ Supported |
| MXA310  | Table array         | ✓ Supported |

## What It Queries

The script connects to each device over TCP port 2202 and retrieves the following parameters using the official [Shure Command Strings](https://www.shure.com/en-US/docs/commandstrings/MXA920) protocol:

| Parameter                    | Description                        |
|------------------------------|------------------------------------|
| `DEVICE_ID`                  | Friendly name / device identifier  |
| `MODEL`                      | Hardware model (e.g. MXA920-S)     |
| `SERIAL_NUM`                 | Device serial number               |
| `CONTROL_MAC_ADDR`           | Control network MAC address        |
| `FW_VER`                     | Firmware version string            |
| `IP_ADDR_NET_AUDIO_PRIMARY`  | Primary Dante audio network IP     |
| `NA_DEVICE_NAME`             | Dante device name                  |
| `ENCRYPTION`                 | Encryption status (ON/OFF)         |

## Requirements

**Python 3.6+** with the following packages:

```bash
pip install tabulate tqdm
```

No additional libraries are needed — the script uses Python's built-in `socket` module for TCP communication.

## Quick Start

### 1. Create a CSV file

Create `secrets/shuremxa_firmware.csv` with your device hostnames or IPs:

```csv
host
192.168.1.10
192.168.1.11
my-mic-1.example.com
my-mic-2.example.com
```

### 2. Run the script

```bash
python3 shuremxa_firmware.py
```

The script will scan all devices, display a formatted results table in the terminal, and save a JSON report.

## Usage

```
usage: shuremxa_firmware.py [-h] [-i INPUT] [--host HOST] [-o OUTPUT]
                            [-t TIMEOUT] [-p PORT] [-w WORKERS] [--raw]
```

### Command-Line Arguments

| Argument              | Default                          | Description                                      |
|-----------------------|----------------------------------|--------------------------------------------------|
| `-i`, `--input`       | `secrets/shuremxa_firmware.csv`  | CSV file with device list                        |
| `--host`              | —                                | Query a single host (skips CSV)                  |
| `-o`, `--output`      | `shure_mxa/files/results_<timestamp>.json` | Output JSON file path              |
| `-t`, `--timeout`     | `10`                             | Connection timeout in seconds                    |
| `-p`, `--port`        | `2202`                           | TCP port (for `--host` mode)                     |
| `-w`, `--workers`     | `5`                              | Number of concurrent query threads               |
| `--raw`               | —                                | Dump raw command/response strings (with `--host`) |

## Examples

### Scan all devices from CSV

```bash
python3 shuremxa_firmware.py
```

### Scan with a custom CSV file

```bash
python3 shuremxa_firmware.py -i my_devices.csv
```

### Query a single device

```bash
python3 shuremxa_firmware.py --host 192.168.1.10
```

### Query a single device by hostname

```bash
python3 shuremxa_firmware.py --host my-mic-1.example.com
```

### Debug a device with raw output

```bash
python3 shuremxa_firmware.py --host 192.168.1.10 --raw
```

This shows the exact command sent and raw response for each parameter — useful for troubleshooting devices that return unexpected results.

Example raw output:

```
  Raw Command String responses from 192.168.1.10:2202:

  GET DEVICE_ID
    Raw:    < REP DEVICE_ID {MY-MIC-1                       } >
    Parsed: MY-MIC-1

  GET MODEL
    Raw:    < REP MODEL {MXA920-S                        } >
    Parsed: MXA920-S

  GET FW_VER
    Raw:    < REP FW_VER {1.5.22            } >
    Parsed: 1.5.22
```

### Increase timeout for slow networks

```bash
python3 shuremxa_firmware.py -t 20
```

### Use more workers for large device lists

```bash
python3 shuremxa_firmware.py -w 10
```

### Save results to a specific file

```bash
python3 shuremxa_firmware.py -o reports/scan_results.json
```

### Full example with all options

```bash
python3 shuremxa_firmware.py -i my_mics.csv -o reports/output.json -t 15 -w 10
```

## CSV Input Format

The CSV file requires one column and supports one optional column:

| Column | Required | Default | Description                              |
|--------|----------|---------|------------------------------------------|
| `host` | Yes      | —       | IP address or hostname of the MXA device |
| `port` | No       | `2202`  | TCP port for Command Strings protocol    |

### Minimal CSV

```csv
host
192.168.1.10
192.168.1.11
192.168.1.12
```

### CSV with port overrides

```csv
host,port
192.168.1.10,2202
192.168.1.11,2202
192.168.1.12,2203
```

### CSV features

- Handles BOM encoding (UTF-8-sig)
- Auto-detects delimiters (comma, semicolon, tab, pipe)
- Lines starting with `#` in the host column are skipped (comments)
- Column names are case-insensitive

## Terminal Output

The script displays a formatted table with color-coded status indicators:

```
  Shure MXA Microphone — Device Query Tool
  Queries device info via Shure Command Strings protocol (TCP).
  Input:   secrets/shuremxa_firmware.csv
  Output:  shure_mxa/files/results_20260417_050557.json
  Workers: 5
  Timeout: 10s

  Scanning ██████████████████████████████ 3/3 [00:04<00:00]  Complete in 4.2s

  =====================================================================================
                     Shure MXA Microphone — Device Query Results
  =====================================================================================
  +--------+-----------------+-----------+----------+----------+-------------+-------+
  | Status | Host            | Device ID | Model    | Firmware | Serial      | ...   |
  +--------+-----------------+-----------+----------+----------+-------------+-------+
  | ✓ OK   | 192.168.1.10    | ROOM-101  | MXA920-S | 1.5.22   | 2CE02800769 | ...   |
  | ✓ OK   | 192.168.1.11    | ROOM-102  | MXA910-60| 4.6.11   | 1AB03400123 | ...   |
  | ✗ ERR  | 192.168.1.12    | N/A       | N/A      | N/A      | N/A         | ...   |
  +--------+-----------------+-----------+----------+----------+-------------+-------+

  Total: 3  |  ✓ Success: 2  |  ✗ Auth Errors: 0  |  ✗ Failed: 1
  Encryption — OFF: 2  |  Reported: 2/3

  Results saved: shure_mxa/files/results_20260417_050557.json
  Elapsed: 4.2s (5 workers)
```

### Status Icons

| Icon         | Color  | Meaning                          |
|--------------|--------|----------------------------------|
| `✓ OK`       | Green  | Device responded successfully    |
| `✗ AUTH ERR` | Yellow | Authentication error             |
| `✗ ERROR`    | Red    | Connection failed or device error|

### Table Columns

| Column     | Description                                      |
|------------|--------------------------------------------------|
| Status     | Connection result icon                           |
| Host       | IP address or hostname from CSV                  |
| Device ID  | Friendly name configured on the device           |
| Model      | Hardware model string                            |
| Firmware   | Firmware version                                 |
| Serial     | Device serial number                             |
| MAC Address| Control network MAC address                      |
| Encryption | Encryption status (ON/OFF)                       |
| Error      | Short error label if the query failed            |

## JSON Output

Results are saved to a JSON file with this structure:

```json
{
  "query_info": {
    "csv_file": "/absolute/path/to/input.csv",
    "timestamp": "2026-04-17T05:05:57.123456+00:00",
    "protocol": "Shure Command Strings (TCP port 2202)",
    "mode": "csv",
    "workers": 5,
    "total": 3,
    "success": 2,
    "auth_errors": 0,
    "errors": 1,
    "elapsed_seconds": 4.2
  },
  "microphones": [
    {
      "host": "192.168.1.10",
      "port": 2202,
      "status": "success",
      "device_id": "ROOM-101",
      "model": "MXA920-S",
      "serial_number": "2CE02800769",
      "mac_address": "00:0E:DD:62:5F:78",
      "firmware_version": "1.5.22",
      "ip_address": "10.8.145.201",
      "dante_name": "ROOM-101-d",
      "encryption": "OFF",
      "error": null,
      "query_timestamp": "2026-04-17T05:05:57.123456+00:00"
    }
  ]
}
```

### JSON fields

| Field              | Type   | Description                                    |
|--------------------|--------|------------------------------------------------|
| `host`             | string | IP or hostname queried                         |
| `port`             | int    | TCP port used (always in JSON, not in table)   |
| `status`           | string | `"success"`, `"auth_error"`, or `"error"`      |
| `device_id`        | string | Device friendly name                           |
| `model`            | string | Hardware model                                 |
| `serial_number`    | string | Serial number                                  |
| `mac_address`      | string | Control MAC address                            |
| `firmware_version` | string | Firmware version                               |
| `ip_address`       | string | Primary Dante audio network IP                 |
| `dante_name`       | string | Dante device name                              |
| `encryption`       | string | Encryption status                              |
| `error`            | string | Error message (null on success)                |
| `query_timestamp`  | string | UTC ISO 8601 timestamp of the query            |

## Protocol Details

The script uses the **Shure Command Strings** protocol:

- **Transport:** TCP socket
- **Default port:** 2202
- **Authentication:** None required
- **Command format:** `< GET PARAMETER >\r\n`
- **Response format:** `< REP PARAMETER {value padded to fixed width} >`
- **Error response:** `< REP ERR >`

The protocol is the same interface used by Crestron, AMX, Extron, and other AV control systems.

### Important notes

- The first command sent via PuTTY or Telnet may return an error — this is expected behavior per Shure's documentation. The script handles this with a connection settle delay.
- Values in responses are padded with spaces to a fixed width and wrapped in curly braces (e.g., `{MXA920-S                        }`). The script strips this padding automatically.
- Some parameters like `CONTROL_MAC_ADDR` and `ENCRYPTION` return values without curly braces. The parser handles both formats.

## Troubleshooting

### All values show N/A but status is ✓ OK

The device connected but returned `< REP ERR >` for all commands. This usually means:

- **Wrong device type** — MXW access points and chargers connect on port 2202 but don't support MXA command strings. This script is for MXA microphones only.
- **Old file version** — Make sure you're running the latest version of the script. Check with: `head -5 shuremxa_firmware.py`

### Use `--raw` to debug

```bash
python3 shuremxa_firmware.py --host <problem_device> --raw
```

This shows the exact raw response from each command, making it easy to spot unexpected formats.

### Connection timed out

- Verify the device is reachable: `ping <host>`
- Verify port 2202 is open: `nc -zv <host> 2202`
- Increase timeout: `-t 20`

### DNS failed

- Check hostname resolution: `nslookup <hostname>`
- Try using the IP address directly with `--host`

## File Structure

```
├── shuremxa_firmware.py              # Main script
├── secrets/
│   └── shuremxa_firmware.csv         # Default input CSV (create this)
└── shure_mxa/
    └── files/
        └── results_<timestamp>.json  # Output JSON reports (auto-created)
```

## References

- [Shure MXA920 Command Strings](https://www.shure.com/en-US/docs/commandstrings/MXA920)
- [Shure MXA910 Command Strings](https://www.shure.com/en-US/docs/commandstrings/MXA910)
- [Shure MXA710 Command Strings](https://www.shure.com/en-US/docs/commandstrings/MXA710)
- [Shure MXA310 Command Strings](https://www.shure.com/en-US/docs/commandstrings/MXA310)
- [Shure Command Strings Index](https://www.shure.com/en-US/docs/commandstrings)
