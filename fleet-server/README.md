# Fleet Console Server

A lightweight web dashboard for monitoring AV fleet devices (cameras, switches, projectors, displays, routers, PDUs). Runs on a Pi4 and serves to your whole team.

## Quick Start

```bash
cd ~/tools/fleet-server
pip3 install -r requirements.txt
python3 server.py
```

Opens at `http://your-ip:5000`

## How It Works

1. Your scripts output JSON files to the `data/` directory
2. The server auto-detects device types (cameras, switches, projectors, etc.)
3. When multiple files exist for the same type, it picks the **newest** (by timestamp in filename)
4. The dashboard auto-refreshes every 60 seconds
5. Target firmware settings are saved to the server and persist across sessions

## Directory Structure

```
fleet-server/
├── server.py              # Flask API server
├── requirements.txt       # Python dependencies (just Flask)
├── fleet-console.service  # systemd service for auto-start
├── static/
│   └── index.html         # The dashboard (single file, loads React from CDN)
└── data/                  # Drop your JSON scan files here
    ├── axis_firmware_20260415_121522.json
    ├── results_20260414_171617.json
    ├── results_2026-04-14_15-42-24.json
    └── ...
```

## Configure Your Scripts

Point your scripts to output JSON to the data directory:

```bash
# Example: configure your scan scripts to save here
OUTPUT_DIR=~/tools/fleet-server/data
```

Files can have any name — the server detects the type by reading the JSON structure (looking for `cameras`, `switches`, `projectors`, `displays`, `routers`, `pdus` arrays). Timestamped filenames are recommended so the server picks the latest.

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Dashboard UI |
| `/api/data` | GET | All devices from newest files, merged |
| `/api/sources` | GET | List of active source files |
| `/api/all-files` | GET | All JSON files grouped by type |
| `/api/target-firmware` | GET | Saved target firmware settings |
| `/api/target-firmware` | POST | Save target firmware settings |

## Deploy on Pi4

### 1. Copy files to Pi

```bash
scp -r fleet-server/ pi@your-pi:~/tools/
```

### 2. Install Flask

```bash
ssh pi@your-pi
cd ~/tools/fleet-server
pip3 install -r requirements.txt
```

### 3. Test it

```bash
python3 server.py --port 5000
```

Visit `http://your-pi-ip:5000` from any browser on your network.

### 4. Auto-start on boot (systemd)

```bash
# Edit the service file if your username/paths differ
nano fleet-console.service

# Install and enable
sudo cp fleet-console.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable fleet-console
sudo systemctl start fleet-console

# Check status
sudo systemctl status fleet-console
```

### 5. Auto-update data with cron

Add your scan scripts to cron so the data stays fresh:

```bash
crontab -e
```

```cron
# Run scans every 15 minutes, output to fleet-server data dir
*/15 * * * * /home/tom/tools/scripts/scan_cameras.py --output /home/tom/tools/fleet-server/data/
*/15 * * * * /home/tom/tools/scripts/scan_switches.py --output /home/tom/tools/fleet-server/data/
# ... etc
```

## Command Line Options

```
python3 server.py --help

Options:
  --host       Host to bind to (default: 0.0.0.0)
  --port       Port to listen on (default: 5000)
  --data-dir   Directory containing JSON scan files (default: ./data)
  --debug      Enable debug mode
```
