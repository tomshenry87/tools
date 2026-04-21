# CyberPower UPS SNMP Query Tool

A Python 3 script for bulk querying CyberPower **OR700LCDRM1U** UPS units equipped with the **RMCARD205** network management card. Collects identity, firmware, battery, and calibration data via SNMPv2c and outputs a timestamped JSON report.

---

## Features

- Queries multiple UPS units concurrently from a CSV input file
- Collects model, serial number, MAC address, UPS firmware, card firmware, battery status, battery capacity, and runtime remaining
- Flags devices where annual runtime calibration is due
- Flags devices where battery replacement is recommended
- Outputs a timestamped JSON file with full results and query metadata
- Color-coded terminal table with summary statistics
- Single-host `--raw` mode for OID debugging

---

## Hardware

| Device | Model |
|---|---|
| UPS | CyberPower OR700LCDRM1U |
| Network Card | CyberPower RMCARD205 |
| Protocol | SNMPv2c — UDP port 161 |

> **Note:** Internal UPS temperature is not supported on the OR700LCDRM1U. That OID is only available on CyberPower's higher-end OL and PR series hardware.

---

## Requirements

### System packages (Debian / Raspberry Pi OS)

```bash
sudo apt install libsnmp-dev snmp-mibs-downloader python3-dev
```

### Python packages

```bash
pip3 install easysnmp tabulate tqdm
```

Or install everything from apt:

```bash
sudo apt install python3-easysnmp python3-tabulate python3-tqdm
```

---

## Setup

### 1. Clone the repo

```bash
git clone <repo-url>
cd <repo-directory>
```

### 2. Create the secrets directory and CSV

```bash
mkdir -p secrets
```

Create `secrets/ups_firmware.csv`:

```
host,community,port
192.168.1.50,public,161
192.168.1.51,public,161
wilson-219-ups.example.com,public,161
# Lines starting with # are skipped
```

**CSV columns:**

| Column | Required | Default | Description |
|---|---|---|---|
| `host` | Yes | — | IP address or hostname |
| `community` | No | `public` | SNMP read community string |
| `port` | No | `161` | UDP port |

> **Security note:** The `secrets/` directory is intended to be excluded from version control. Add it to your `.gitignore`.

### 3. SNMP community string

The SNMP community string is separate from the RMCARD205 web UI password. The read community defaults to `public` on most devices. You can verify or change it in the RMCARD205 web interface under:

> **Network Services → SNMP → Read Community**

---

## Usage

### Query all devices from CSV

```bash
python3 ups_script.py
```

### Specify a different CSV file

```bash
python3 ups_script.py -i /path/to/my_ups_list.csv
```

### Query a single host

```bash
python3 ups_script.py --host 192.168.1.50
```

### Raw OID dump (for debugging / verifying a device)

```bash
python3 ups_script.py --host 192.168.1.50 --raw
```

### Override community string for all devices

```bash
python3 ups_script.py -c mySecretCommunity
```

### Full options

```
usage: ups_script.py [-h] [-i INPUT] [--host HOST] [-o OUTPUT]
                     [-c COMMUNITY] [-t TIMEOUT] [-p PORT] [-w WORKERS] [--raw]

options:
  -i, --input      CSV file (default: secrets/ups_firmware.csv)
  --host           Query a single host instead of CSV
  -o, --output     Output JSON file (default: ups_firmware/files/results_TIMESTAMP.json)
  -c, --community  SNMP community string override (default: public)
  -t, --timeout    SNMP timeout in seconds (default: 10)
  -p, --port       UDP port for --host mode (default: 161)
  -w, --workers    Concurrent workers (default: 5)
  --raw            Dump all raw SNMP OID values for a single host and exit
```

---

## Output

### Terminal table

```
  ============================================================
       CyberPower OR700LCDRM1U — UPS Status Query Results
  ============================================================
  | Status  | Host           | Model          | Serial       | ... |
  +---------+----------------+----------------+--------------+-----+
  | ✓ OK    | 192.168.1.50   | OR700LCDRM1Ua  | GCCNX700102  | ... |
  | ⚠ WARN  | 192.168.1.51   | OR700LCDRM1Ua  | GCCNX700103  | ... |

  Total: 2  |  ✓ Success: 1  |  ⚠ Warnings: 1  |  ✗ Failed: 0
  Battery Capacity — Avg: 98%  |  Min: 95%  |  Max: 100%  |  Reported: 2/2
  Calibration — 1 device(s) due for annual runtime calibration  |  1 up to date
```

### Status indicators

| Icon | Meaning |
|---|---|
| `✓ OK` | Device healthy, all checks passed |
| `⚠ WARN` | Battery low or replace indicator active |
| `✗ ERROR` | Device unreachable or SNMP failed |

> Runtime calibration due (`Cal Due? = YES`) is **informational only** and does not change the device status to WARN.

### JSON output

Results are saved to `ups_firmware/files/results_YYYYMMDD_HHMMSS.json`:

```json
{
  "query_info": {
    "csv_file": "/home/user/scripts/secrets/ups_firmware.csv",
    "timestamp": "2026-04-21T02:59:37.123456+00:00",
    "protocol": "SNMPv2c — CPS-MIB (CyberPower) + MIB-II (RFC 1213)",
    "community": "public",
    "workers": 5,
    "total": 10,
    "success": 9,
    "warnings": 1,
    "errors": 0,
    "elapsed_seconds": 4.21
  },
  "ups": [
    {
      "host": "192.168.1.50",
      "port": 161,
      "status": "success",
      "model": "OR700LCDRM1Ua",
      "serial": "GCCNX7001022",
      "mac_address": "00:0C:15:07:0F:A4",
      "ups_firmware": "BF02114C4E13",
      "agent_firmware": "1.4.1",
      "battery_status": "normal",
      "battery_capacity_pct": 100,
      "runtime_remaining_raw": 60000,
      "runtime_remaining": "0h 10m",
      "replace_indicator": "ok",
      "calibration_status": "never_run",
      "calibration_date": "N/A",
      "calibration_needed": true,
      "error": null,
      "query_timestamp": "2026-04-21T02:59:37.123456+00:00"
    }
  ]
}
```

---

## Data Collected

| Field | OID | MIB |
|---|---|---|
| Model | `1.3.6.1.4.1.3808.1.1.1.1.1.1.0` | CPS-MIB `upsBaseIdentModel` |
| Serial number | `1.3.6.1.4.1.3808.1.1.1.1.2.3.0` | CPS-MIB `upsAdvanceIdentSerialNumber` |
| UPS firmware | `1.3.6.1.4.1.3808.1.1.1.1.2.1.0` | CPS-MIB `upsAdvanceIdentFirmwareRevision` |
| Card firmware | `1.3.6.1.4.1.3808.1.1.1.1.2.4.0` | CPS-MIB `upsAdvanceIdentAgentFirmwareRevision` |
| MAC address | `1.3.6.1.2.1.2.2.1.6.1` | MIB-II `ifPhysAddress.1` |
| Battery status | `1.3.6.1.4.1.3808.1.1.1.2.1.1.0` | CPS-MIB `upsBaseBatteryStatus` |
| Battery capacity | `1.3.6.1.4.1.3808.1.1.1.2.2.1.0` | CPS-MIB `upsAdvanceBatteryCapacity` |
| Runtime remaining | `1.3.6.1.4.1.3808.1.1.1.2.2.4.0` | CPS-MIB `upsAdvanceBatteryRunTimeRemaining` |
| Replace indicator | `1.3.6.1.4.1.3808.1.1.1.2.2.5.0` | CPS-MIB `upsAdvanceBatteryReplaceIndicator` |
| Calibration result | `1.3.6.1.4.1.3808.1.1.1.7.2.3.0` | CPS-MIB calibration result |
| Calibration date | `1.3.6.1.4.1.3808.1.1.1.7.2.4.0` | CPS-MIB calibration date |

---

## Runtime Calibration

The OR700LCDRM1U calculates estimated runtime based on a calibration it must perform under load. CyberPower recommends running this **once per year** or after any battery replacement.

The script flags `calibration_needed: true` if:
- Calibration has never been run, **or**
- The last recorded calibration date is 365 or more days ago

This flag is **informational only** — it appears in the `Cal Due?` table column and the footer summary but does not affect device status.

### How to run a calibration

Log into the RMCARD205 web interface and navigate to:

> **UPS → Diagnostics → Runtime Calibration → Start**

> ⚠️ A calibration discharges the battery to a low level. Run it only when the UPS is at 100% charge and attached servers can tolerate the process, or when equipment is not at risk.

---

## File Structure

```
.
├── ups_script.py               # Main script
├── README.md                   # This file
├── secrets/
│   └── ups_firmware.csv        # Device list (excluded from git)
└── ups_firmware/
    └── files/
        └── results_*.json      # Timestamped output files
```

### Recommended `.gitignore`

```
secrets/
ups_firmware/files/
__pycache__/
*.pyc
```

---

## Firewall Requirements

The script communicates outbound to each UPS over **UDP port 161**. Ensure no firewall blocks this between your monitoring host and the UPS management network.

| Direction | Protocol | Port | Purpose |
|---|---|---|---|
| Outbound | UDP | 161 | SNMP GET requests to RMCARD205 |

---

## Troubleshooting

**`Timed out` in the Error column**
- Device is unreachable or UDP 161 is blocked by a firewall
- Verify with: `snmpwalk -v2c -c public <host> 1.3.6.1.4.1.3808.1.1.1.1.1.1.0`

**`no such name error` for an OID**
- That OID is not supported on this hardware — the OR700LCDRM1U does not expose all OIDs present in the full CPS-MIB
- Use `--raw` mode to see exactly what each device returns

**Card firmware shows `N/A`**
- Confirmed working OID is `1.3.6.1.4.1.3808.1.1.1.1.2.4.0` — verify with `--raw`

**`easysnmp` fails to install**
- Ensure build tools are present: `sudo apt install python3-dev gcc libsnmp-dev`

**MAC address shows garbled characters**
- Normal — easysnmp returns `ifPhysAddress` as raw bytes. The script normalises this to `XX:XX:XX:XX:XX:XX` format automatically.
