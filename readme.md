# AV/Network Device Query Toolkit

A collection of Python scripts for querying firmware versions, temperatures, and other diagnostic data from AV and network infrastructure devices at scale. All scripts share a common design — CSV input, concurrent workers, a live progress bar, formatted table output, and JSON results export.

---

## Scripts

### `axis_vapix_query.py` — AXIS IP Cameras
Queries AXIS cameras over HTTPS using the VAPIX API. Retrieves firmware version, model, serial number, MAC address, and board/CPU temperature. Supports self-signed certificates and HTTP Digest authentication.

### `sony_fw_query.py` — Sony Bravia Professional Displays
Queries Sony Bravia BZ40H/BZ40L displays via the Sony REST API (JSON-RPC). Retrieves firmware version, model, serial, MAC address, and power saving mode. Handles PSK authentication with automatic fallback, and includes a utility mode to reset display authentication to None across a fleet.

### `query_kramer.py` — Kramer VP-440H2 HDMI Switchers
Queries Kramer VP-440H2 matrix switchers over TCP using Kramer Protocol 3000. Retrieves firmware version, model, build date, protocol version, serial number, and MAC address. Includes a hex/ASCII debug mode for troubleshooting protocol issues.

### `mikrotik_checker.py` — MikroTik Routers
Connects to MikroTik routers via SSH and queries installed RouterOS package versions. Reports the RouterOS version and full package list per device, with a version breakdown summary across the fleet.

### `netgear_m4250_checker.py` — Netgear M4250 Switches
Connects to Netgear M4250 managed switches via SSH. Retrieves firmware version and CPU temperature, with aggregate temperature statistics (avg/min/max) across the fleet.

### `pjlink_query.py` — PJLink Projectors
Queries projectors using the PJLink protocol (Class 1 and Class 2). Retrieves firmware version, lamp hours, manufacturer, model, power status, and projector name. Supports password authentication and includes a raw diagnostic mode.

---

## Common Features

- **Input:** CSV file with a `host` column (plus credentials where needed)
- **Concurrency:** Configurable worker threads for fast parallel scanning
- **Output:** Formatted CLI table + `results.json` with full detail
- **Error handling:** Distinguishes auth failures, timeouts, and unreachable hosts

## Dependencies

```
pip install requests tabulate tqdm paramiko urllib3
```
