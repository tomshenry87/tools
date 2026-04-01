# kramer_firmware.py

A CLI tool for bulk-querying Kramer VP-440H2 matrix switchers over TCP using the Kramer Protocol 3000. Connects to up to 5 devices concurrently, retrieves device identity fields, and outputs a formatted terminal table plus a structured JSON report.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Input File — switchers.csv](#input-file--switcherscsv)
- [Usage](#usage)
- [Command-Line Arguments](#command-line-arguments)
- [What Gets Queried](#what-gets-queried)
- [Terminal Output](#terminal-output)
- [JSON Output](#json-output)
- [Debug Mode](#debug-mode)
- [Function Reference](#function-reference)
- [Constants Reference](#constants-reference)
- [Style Guide Compliance](#style-guide-compliance)

---

## Requirements

- Python 3.8 or later
- Network access to the target devices on TCP port 5000 (default)

### Python dependencies

```
tabulate
tqdm
python-dateutil   # optional but recommended for robust date parsing
```

---

## Installation

```bash
# Clone or copy kramer_firmware.py into your working directory, then:
pip install tabulate tqdm python-dateutil
```

---

## Input File — switchers.csv

The script reads device targets from `switchers.csv` in the working directory.

### Minimum viable CSV

```csv
host
192.168.1.10
192.168.1.11
192.168.1.12
```

### With custom ports

```csv
host,port
192.168.1.10,5000
192.168.1.11,5001
switcher-lab-01.local,5000
```

**CSV loader behaviour:**

- BOM (`\ufeff`) is silently stripped — safe to export directly from Excel
- Delimiter is auto-detected (comma, semicolon, tab, or pipe)
- Column names are case-insensitive (`Host`, `HOST`, and `host` all work)
- Rows starting with `#` are skipped — use them as comments
- A `port` column is optional; missing or non-numeric values fall back to `DEFAULT_TCP_PORT` (5000)
- Hostnames and IP addresses are both accepted

```csv
host,port
192.168.1.10,5000
# this switcher is offline for maintenance
# 192.168.1.11,5000
switcher-rack-b.av.local,5000
```

---

## Usage

### Normal run — query all hosts in switchers.csv

```bash
python3 kramer_firmware.py
```

### Debug run — query all hosts with full hex/ASCII socket dumps

```bash
python3 kramer_firmware.py --debug
```

### Debug run — single host, all commands

```bash
python3 kramer_firmware.py --debug --host 192.168.1.10
```

### Debug run — single host, single command

```bash
python3 kramer_firmware.py --debug --host 192.168.1.10 --cmd firmware
python3 kramer_firmware.py --debug --host 192.168.1.10 --cmd model
python3 kramer_firmware.py --debug --host 192.168.1.10 --cmd serial
```

---

## Command-Line Arguments

| Argument | Type | Default | Description |
|---|---|---|---|
| `--debug` | flag | off | Enable hex+ASCII socket dump for every send/receive exchange |
| `--host IP` | string | — | Target a single host directly instead of reading switchers.csv. Requires `--debug` |
| `--port PORT` | int | 5000 | Override the TCP port for `--host` single-host probes |
| `--cmd CMD` | string | — | Probe only one command. Requires `--debug` and `--host`. Choices: `model`, `build_date`, `prot_ver`, `serial`, `firmware`, `mac` |

---

## What Gets Queried

Each device receives a Protocol 3000 handshake (`#\r`) followed by six scalar queries over a single persistent TCP connection.

| Key | Command sent | Response field |
|---|---|---|
| `model` | `#MODEL?\r` | Product model name |
| `build_date` | `#BUILD-DATE?\r` | Firmware build date (normalised to `yyyy/mm/dd`) |
| `prot_ver` | `#PROT-VER?\r` | Protocol 3000 version |
| `serial` | `#SN?\r` | Device serial number |
| `firmware` | `#VERSION?\r` | Firmware version string |
| `mac` | `#NET-MAC?\r` | Ethernet MAC address |

### Protocol 3000 framing

Commands are sent as ASCII with a carriage-return terminator:

```
#MODEL?\r
```

Responses follow the pattern:

```
~01@MODEL VP-440H2\r\n
```

The response parser uses per-field regular expressions to extract the value after the command echo, handling any two-digit device ID prefix.

---

## Terminal Output

### Header block

Printed immediately on launch before scanning begins:

```
  Kramer VP-440H2 Query Tool
  Protocol 3000 TCP device interrogation
  Input:   switchers.csv
  Output:  results.json
  Workers: 5
  Timeout: 8s
```

### Progress bar

A cyan `tqdm` bar writes to `stderr` so it does not mix with table output on `stdout`. The postfix shows the most recently started host.

```
  Scanning ████████████████████ 12/12 [00:04<00:00]  192.168.1.22
```

On completion the postfix updates to:

```
  Scanning ████████████████████ 12/12 [00:04<00:00]  ✓ Complete in 4.2s
```

### Results table

A `tabulate` `pretty`-format table with left-aligned strings and right-aligned numbers. Column order follows the project style guide convention.

```
+----------+--------------+-------------------+-----------+------------+--------------+----------+-------------------+-------+
| Status   | Host         | Model             | Firmware  | Build Date | Protocol Ver | Serial   | MAC               | Error |
+----------+--------------+-------------------+-----------+------------+--------------+----------+-------------------+-------+
| ✓ OK     | 192.168.1.10 | VP-440H2          | 1.02.0008 | 2024/07/12 | 3.0          | 12345678 | 00:11:22:33:44:55 |       |
| ✗ ERROR  | 192.168.1.99 | N/A               | N/A       | N/A        | N/A          | N/A      | N/A               | Timed out |
+----------+--------------+-------------------+-----------+------------+--------------+----------+-------------------+-------+
```

The **Port** column is intentionally excluded from the table — it is recorded in the JSON only.

### Summary footer

```
  Total: 12  |  ✓ Success: 11  |  ✗ Auth Errors: 0  |  ✗ Failed: 1
  MAC Addresses — Reported: 11/12

  Results saved: results.json
  Elapsed: 4.2s (5 workers)
```

---

## JSON Output

Results are saved to `results.json` with a standard two-section structure.

### Top-level structure

```json
{
  "query_info": {
    "csv_file": "/home/av/switchers.csv",
    "timestamp": "2024-11-01T14:32:00.123456+00:00",
    "protocol": "Kramer Protocol 3000",
    "mode": "sequential",
    "workers": 5,
    "total": 12,
    "success": 11,
    "errors": 1,
    "elapsed_seconds": 4.21
  },
  "switches": [
    { ... },
    { ... }
  ]
}
```

### Device entry — success

```json
{
  "host": "192.168.1.10",
  "port": 5000,
  "query_timestamp": "2024-11-01T14:32:01.456789+00:00",
  "status": "success",
  "error": null,
  "build_date": "2024/07/12",
  "model": "VP-440H2",
  "prot_ver": "3.0",
  "serial": "12345678",
  "firmware": "1.02.0008",
  "mac": "00:11:22:33:44:55"
}
```

### Device entry — failure

```json
{
  "host": "192.168.1.99",
  "port": 5000,
  "query_timestamp": "2024-11-01T14:32:09.000000+00:00",
  "status": "error",
  "error": "timed out",
  "build_date": "N/A",
  "model": "N/A",
  "prot_ver": "N/A",
  "serial": "N/A",
  "firmware": "N/A",
  "mac": "N/A"
}
```

**`status` is always one of:** `"success"` · `"auth_error"` · `"error"`

All timestamps are UTC ISO 8601, generated via `datetime.now(timezone.utc).isoformat()`.

---

## Debug Mode

Debug mode prints a full hex+ASCII dump of every byte sent and received on the socket. It is intended for diagnosing unresponsive devices or verifying protocol framing.

### Probe a single host — all commands

```bash
python3 query_kramer.py --debug --host 192.168.1.10
```

Sample output for one command:

```
  +-- SEND  '#VERSION?\r' (10 bytes) ----------------------------+
  | 0000  23 56 45 52 53 49 4F 4E 3F 0D                  |#VERSION?.|
  |  decoded : {CR}
  +--------------------------------------------------------------+

  +-- RECV  '#VERSION?\r' (22 bytes) ----------------------------+
  | 0000  7E 30 31 40 56 45 52 53 49 4F 4E 20 31 2E 30 32 |~01@VERSION 1.02|
  | 0010  2E 30 30 30 38 0D 0A                            |.0008{CR}{LF}  |
  |  decoded : ~01@VERSION 1.02.0008{CR}{LF}
  +--------------------------------------------------------------+

  parsed [firmware] => '1.02.0008'
```

### Probe a single command

```bash
python3 query_kramer.py --debug --host 192.168.1.10 --cmd serial
```

Available `--cmd` values: `model`, `build_date`, `prot_ver`, `serial`, `firmware`, `mac`

---

## Function Reference

### `load_csv(csv_path) -> list[dict]`

Loads device targets from a CSV file. Returns a list of `{"host": str, "port": int}` dicts.

- Handles UTF-8 BOM encoding automatically
- Auto-detects delimiter using `csv.Sniffer`
- Skips blank rows and rows where host starts with `#`
- Exits with a descriptive error if the file is missing, empty, or has no `host` column

```python
devices = load_csv("switchers.csv")
# [{"host": "192.168.1.10", "port": 5000}, ...]
```

---

### `query_device(host, port) -> dict`

Opens a TCP connection to one device, performs the Protocol 3000 handshake, sends all six scalar queries, and returns a result dict.

- Sets `status` to `"success"` only if the full query cycle completes without error
- On any socket exception, sets `status` to `"error"` and records the exception message in `error`
- Calls `normalise_date()` on the raw `build_date` response before returning

```python
result = query_device("192.168.1.10", 5000)
print(result["firmware"])   # "1.02.0008"
print(result["status"])     # "success"
```

---

### `send_query(sock, command, host="") -> str`

Sends a single Protocol 3000 command over an open socket and returns the decoded, stripped response string.

Uses a two-phase receive strategy:
1. **Blocking phase** — waits up to `RECV_TIMEOUT` seconds for a `\n`-terminated response
2. **Drain phase** — switches to non-blocking for `DRAIN_WINDOW` seconds to collect any additional buffered lines, then restores blocking mode

```python
raw = send_query(sock, "#VERSION?\r", host="192.168.1.10")
# "~01@VERSION 1.02.0008"
```

---

### `normalise_date(raw) -> str`

Normalises a raw date string from the device to `yyyy/mm/dd`. Uses `python-dateutil` when available, with a regex fallback for common formats.

Handled formats include:

| Input | Output |
|---|---|
| `2024-07-12` | `2024/07/12` |
| `12/07/2024` | `2024/07/12` |
| `20240712` | `2024/07/12` |
| `2024-07-12 14:32:00` | `2024/07/12` |

Returns the original string unchanged if all parsing attempts fail. Returns `"N/A"` unchanged.

```python
normalise_date("2024-07-12")   # "2024/07/12"
normalise_date("20240712")     # "2024/07/12"
normalise_date("unknown")      # "unknown"
```

---

### `status_icon(r) -> str`

Returns a coloured status string for use in the terminal table.

| `r["status"]` | Output |
|---|---|
| `"success"` | `✓ OK` (green) |
| `"auth_error"` | `✗ AUTH ERR` (yellow) |
| `"error"` | `✗ ERROR` (red) |

```python
icon = status_icon({"status": "success"})   # green "✓ OK"
```

---

### `clean(val) -> str`

Sanitises a value before it is placed in the terminal table. Converts `None`, `"-1"`, empty strings, and error-prefixed strings to `"N/A"`.

```python
clean(None)            # "N/A"
clean("")              # "N/A"
clean("-1")            # "N/A"
clean("ERROR: ...")    # "N/A"
clean("1.02.0008")     # "1.02.0008"
```

---

### `truncate_error(err, max_len=30) -> str`

Maps verbose exception messages to short human-readable labels for the table's Error column. Protocol 3000-specific patterns are checked first, followed by generic network error patterns.

```python
truncate_error("Connection timed out")          # "Timed out"
truncate_error("Connection refused")            # "Conn refused"
truncate_error("Name or service not known")     # "DNS failed"
truncate_error("No route to host")              # "No route"
truncate_error("")                              # ""
```

---

### `debug_probe(host, port, cmd_key)`

Connects to a single device, runs one or all queries, and prints the raw socket exchange alongside the parsed values. Called only when `--debug` and `--host` are both provided.

Raises `DebugProbeError` on any connection failure so that `main()` controls the process exit.

---

### `debug_print(host, label, data)`

Prints a formatted hex+ASCII dump of a raw bytes object. Only active when `DEBUG = True`. Used internally by `send_query` and `query_device`.

---

## Constants Reference

| Constant | Default | Description |
|---|---|---|
| `DEFAULT_TCP_PORT` | `5000` | TCP port used when no port column is present in the CSV |
| `CONNECT_TIMEOUT` | `8.0` | Seconds before a connection attempt times out |
| `RECV_TIMEOUT` | `8.0` | Seconds before a blocking `recv()` times out |
| `BUFFER_SIZE` | `4096` | Socket read buffer size in bytes |
| `SEND_PAUSE` | `0.02` | Seconds to wait after `sendall()` before the first `recv()` |
| `DRAIN_WINDOW` | `0.05` | Seconds of non-blocking drain after the first newline is received |
| `WORKERS` | `5` | Number of concurrent `ThreadPoolExecutor` workers |
| `CSV_FILE` | `"switchers.csv"` | Default input file path |
| `JSON_FILE` | `"results.json"` | Default output file path |

---

## Style Guide Compliance

This script conforms to the project CLI Script Visual Style Guide:

- ANSI palette: `CYAN`, `GREEN`, `RED`, `YELLOW`, `WHITE`, `BOLD`, `RESET`
- Header block printed on launch with Input, Output, Workers, Timeout
- `tqdm` progress bar on `stderr` with cyan fill, `Scanning` label, single-host postfix
- `tabulate` with `pretty` format, `stralign="left"`, `numalign="right"`
- Port excluded from table; present in JSON only
- Column order: Status → Host → Model → Firmware → Build Date → Protocol Ver → Serial → MAC → Error
- `status_icon()` with `✓` / `✗` and GREEN / YELLOW / RED
- All table values pass through `clean()`
- Error column values pass through `truncate_error()` with Protocol 3000-specific patterns
- Title banner width scaled to actual table width with ANSI stripped before measuring
- Summary footer with Total / Success / Auth Errors / Failed counts
- Closing `Results saved:` and `Elapsed:` lines
- JSON follows standard `query_info` + device array structure
- UTC ISO 8601 timestamps throughout
- CSV loader handles BOM, auto-detects delimiter, skips `#` comment lines
