#!/usr/bin/env python3
"""
Firmware Dashboard Server
A lightweight Flask server for the Firmware Dashboard.

Features:
- Reads JSON scan files from multiple source directories (sources.json)
- Auto-picks the newest file per device type
- Session-based authentication with admin/viewer roles
- Admin: can change firmware targets and config
- Viewer: read-only dashboard access

Usage:
    python3 server.py                        # defaults: port 5000
    python3 server.py --port 8080
    python3 server.py --host 0.0.0.0
    python3 server.py --setup                # re-run first-time setup
"""

import os
import re
import json
import argparse
import hashlib
import secrets
import getpass
from pathlib import Path
from datetime import datetime
from functools import wraps
from flask import Flask, jsonify, send_file, send_from_directory, request, session, redirect, url_for

app = Flask(__name__, static_folder="static")

# ─── Configuration ───
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCES_FILE = os.path.join(BASE_DIR, "sources.json")
TARGET_FW_FILE = os.path.join(BASE_DIR, "target_firmware.json")
USERS_FILE = os.path.join(BASE_DIR, "users.json")

# ─── Secret key (must be set at import time for Gunicorn) ───
_secret_file = os.path.join(BASE_DIR, ".secret_key")
if os.path.exists(_secret_file):
    with open(_secret_file, "r") as _f:
        app.secret_key = _f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(_secret_file, "w") as _f:
        _f.write(app.secret_key)
    os.chmod(_secret_file, 0o600)

ARRAY_KEY_TO_TYPE = {
    "cameras": "camera",
    "switches": "switch",
    "projectors": "projector",
    "displays": "display",
    "routers": "router",
    "pdus": "pdu",
}


# ─── Auth helpers ───

def hash_password(password, salt=None):
    """Hash a password with SHA-256 + salt."""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(password, stored):
    """Verify a password against a stored hash."""
    salt, hashed = stored.split(":", 1)
    return hash_password(password, salt) == stored


def load_users():
    """Load user accounts from users.json."""
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return {}


def save_users(users):
    """Save user accounts to users.json."""
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def setup_users():
    """Interactive first-time setup for user accounts."""
    print("\n═══ Firmware Dashboard — First Time Setup ═══\n")
    users = {}

    # Admin account
    print("Create ADMIN account (can change firmware targets & settings):")
    admin_user = input("  Admin username: ").strip()
    while not admin_user:
        admin_user = input("  Admin username (required): ").strip()
    admin_pass = getpass.getpass("  Admin password: ")
    while len(admin_pass) < 4:
        admin_pass = getpass.getpass("  Password too short (min 4 chars): ")
    users[admin_user] = {"password": hash_password(admin_pass), "role": "admin"}
    print(f"  ✓ Admin account '{admin_user}' created\n")

    # Viewer account
    print("Create VIEWER account (read-only dashboard access):")
    viewer_user = input("  Viewer username: ").strip()
    while not viewer_user:
        viewer_user = input("  Viewer username (required): ").strip()
    viewer_pass = getpass.getpass("  Viewer password: ")
    while len(viewer_pass) < 4:
        viewer_pass = getpass.getpass("  Password too short (min 4 chars): ")
    users[viewer_user] = {"password": hash_password(viewer_pass), "role": "viewer"}
    print(f"  ✓ Viewer account '{viewer_user}' created\n")

    save_users(users)
    print(f"  Saved to {USERS_FILE}\n")
    return users


def login_required(f):
    """Decorator: require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            # API calls get 401, page requests get redirected
            if request.path.startswith("/api/"):
                return jsonify({"error": "Not authenticated"}), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator: require admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "Not authenticated"}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


# ─── Data helpers ───

def load_sources():
    try:
        with open(SOURCES_FILE, "r") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return []


def detect_file_type(filepath):
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        for key, dtype in ARRAY_KEY_TO_TYPE.items():
            if key in data and isinstance(data[key], list):
                return dtype
        return "unknown"
    except (json.JSONDecodeError, IOError):
        return None


def extract_timestamp_from_filename(filename):
    patterns = [
        r"(\d{8}_\d{6})",
        r"(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})",
    ]
    for pattern in patterns:
        match = re.search(pattern, filename)
        if match:
            return match.group(1)
    return None


def get_file_sort_key(filepath):
    ts = extract_timestamp_from_filename(os.path.basename(filepath))
    if ts:
        return ts.replace("-", "").replace("_", "")
    return datetime.fromtimestamp(os.path.getmtime(filepath)).strftime("%Y%m%d%H%M%S")


def scan_all_sources():
    """Scan all source directories. Pick the newest file from EACH directory."""
    sources = load_sources()
    results = []  # list of (dtype, filepath) tuples

    dirs_to_scan = []
    for source in sources:
        if isinstance(source, str):
            dirs_to_scan.append(source)
        elif isinstance(source, dict):
            dirs_to_scan.append(source.get("path", ""))

    # Also include ./data as fallback
    data_dir = os.path.join(BASE_DIR, "data")
    if os.path.isdir(data_dir):
        dirs_to_scan.append(data_dir)

    for dir_path in dirs_to_scan:
        expanded = os.path.expanduser(dir_path)
        if not os.path.isdir(expanded):
            continue

        # Group files in THIS directory by type
        dir_files_by_type = {}
        for filepath in Path(expanded).glob("*.json"):
            if filepath.name.startswith("."):
                continue
            dtype = detect_file_type(str(filepath))
            if dtype and dtype != "unknown":
                if dtype not in dir_files_by_type:
                    dir_files_by_type[dtype] = []
                dir_files_by_type[dtype].append(str(filepath))

        # Pick newest of each type within this directory
        for dtype, filepaths in dir_files_by_type.items():
            filepaths.sort(key=get_file_sort_key, reverse=True)
            results.append((dtype, filepaths[0]))

    # Deduplicate by resolved path
    seen = set()
    unique = []
    for dtype, filepath in results:
        real = os.path.realpath(filepath)
        if real not in seen:
            seen.add(real)
            unique.append((dtype, filepath))

    return unique


def load_target_firmware():
    try:
        with open(TARGET_FW_FILE, "r") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return {}


def save_target_firmware(targets):
    with open(TARGET_FW_FILE, "w") as f:
        json.dump(targets, f, indent=2)


# ─── Login page ───

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Firmware Dashboard &mdash; Login</title>
<link href="https://fonts.googleapis.com/css2?family=EB+Garamond:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#f7f7f7;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:Arial,Helvetica,sans-serif}
.hbar{position:fixed;top:0;left:0;right:0;height:48px;background:#00693e;display:flex;align-items:center;padding:0 20px;gap:10px}
.hbar img{width:28px;height:28px;object-fit:contain;filter:brightness(0) invert(1)}
.hbar .t1{font-family:'EB Garamond',Georgia,serif;color:#fff;font-size:18px;font-weight:700}
.hbar .t2{color:rgba(255,255,255,0.5);font-size:11px;font-family:'JetBrains Mono',monospace}
.box{background:#fff;border:1px solid #e2e2e2;border-radius:8px;padding:36px;width:340px;box-shadow:0 2px 12px rgba(0,0,0,0.06);margin-top:60px}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:24px}
.logo img{width:36px;height:36px;object-fit:contain}
.lt{font-weight:700;font-size:18px;color:#1a1a1a;font-family:'EB Garamond',Georgia,serif}
.ls{font-size:11px;color:#707070;font-family:'JetBrains Mono',monospace}
label{display:block;font-size:11px;color:#707070;text-transform:uppercase;letter-spacing:0.8px;font-family:'JetBrains Mono',monospace;margin-bottom:6px;margin-top:16px}
input[type=text],input[type=password]{width:100%;padding:10px 12px;background:#f7f7f7;border:1px solid #e2e2e2;border-radius:6px;color:#1a1a1a;font-family:'JetBrains Mono',monospace;font-size:13px;outline:none}
input:focus{border-color:#00693e}
button{width:100%;margin-top:20px;padding:11px;border:none;border-radius:6px;background:#00693e;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
button:hover{opacity:0.9}
.err{margin-top:12px;padding:8px 12px;background:rgba(157,22,46,0.06);border:1px solid rgba(157,22,46,0.2);border-radius:6px;color:#9d162e;font-size:12px;font-family:'JetBrains Mono',monospace;display:none}
.err.show{display:block}
</style>
</head>
<body>
<div class="hbar">
  <img src="/static/d-pine.png" alt="">
  <span class="t1">Firmware Dashboard</span>
  <span class="t2">Design &amp; Engineering</span>
</div>
<div class="box">
  <div class="logo">
    <img src="/static/d-pine.png" alt="D">
    <div>
      <div class="lt">Sign In</div>
      <div class="ls">Design &amp; Engineering</div>
    </div>
  </div>
  <form method="POST" action="/login">
    <label>Username</label>
    <input type="text" name="username" autocomplete="username" autofocus required>
    <label>Password</label>
    <input type="password" name="password" autocomplete="current-password" required>
    <button type="submit">Sign In</button>
  </form>
  <div class="err ERRORCLASS">ERRORMSG</div>
</div>
</body>
</html>"""


# ─── Routes ───

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        html = LOGIN_HTML.replace("ERRORCLASS", "").replace("ERRORMSG", "")
        return html

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    users = load_users()

    if username in users and verify_password(password, users[username]["password"]):
        session["user"] = username
        session["role"] = users[username]["role"]
        return redirect("/")

    html = LOGIN_HTML.replace("ERRORCLASS", "show").replace("ERRORMSG", "Invalid username or password")
    return html, 401


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
@login_required
def index():
    return send_file("static/index.html")


@app.route("/api/me")
@login_required
def api_me():
    """Return current user info including role."""
    return jsonify({"user": session.get("user"), "role": session.get("role")})


@app.route("/api/sources")
@login_required
def api_sources():
    results = scan_all_sources()
    sources = []
    for dtype, filepath in results:
        stat = os.stat(filepath)
        sources.append({
            "type": dtype,
            "filename": os.path.basename(filepath),
            "path": filepath,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        })
    return jsonify(sources)


@app.route("/api/data")
@login_required
def api_data():
    results = scan_all_sources()
    result = {
        "sources": [],
        "devices": [],
        "target_firmware": load_target_firmware(),
        "user": session.get("user"),
        "role": session.get("role"),
        "scanned_at": datetime.now().isoformat(),
    }

    for dtype, filepath in results:
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            filename = os.path.basename(filepath)
            query_info = data.get("query_info", {})

            arr = None
            for key in ARRAY_KEY_TO_TYPE:
                if key in data and isinstance(data[key], list):
                    arr = data[key]
                    break
            if arr is None:
                continue

            result["sources"].append({
                "type": dtype,
                "filename": filename,
                "count": len(arr),
                "query_info": query_info,
            })

            for device in arr:
                device["_type"] = dtype
                device["_source"] = filename
                result["devices"].append(device)

        except (json.JSONDecodeError, IOError) as e:
            result["sources"].append({
                "type": dtype,
                "filename": os.path.basename(filepath),
                "error": str(e),
            })

    return jsonify(result)


@app.route("/api/target-firmware", methods=["GET"])
@login_required
def api_get_target_fw():
    return jsonify(load_target_firmware())


@app.route("/api/target-firmware", methods=["POST"])
@admin_required
def api_save_target_fw():
    targets = request.get_json()
    save_target_firmware(targets)
    return jsonify({"status": "saved", "targets": targets})


@app.route("/api/config", methods=["GET"])
@admin_required
def api_get_config():
    return jsonify({"sources": load_sources(), "sources_file": SOURCES_FILE})


@app.route("/api/config", methods=["POST"])
@admin_required
def api_save_config():
    data = request.get_json()
    sources = data.get("sources", [])
    with open(SOURCES_FILE, "w") as f:
        json.dump(sources, f, indent=2)
    return jsonify({"status": "saved", "sources": sources})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Dashboard Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    parser.add_argument("--setup", action="store_true", help="Re-run user setup")
    args = parser.parse_args()

    # User setup
    if args.setup or not os.path.exists(USERS_FILE):
        setup_users()

    # Create sources.json if missing
    if not os.path.exists(SOURCES_FILE):
        print(f"  Creating {SOURCES_FILE} — edit this to add your script output directories.\n")
        with open(SOURCES_FILE, "w") as f:
            json.dump([
                "~/tools/scripts/axis_firmware/files",
            ], f, indent=2)

    sources = load_sources()
    newest = scan_all_sources()
    users = load_users()

    print(f"""
╔════════════════════════════════════════════════╗
║         Firmware Dashboard Server              ║
╠════════════════════════════════════════════════╣
║  Dashboard:  http://{args.host}:{args.port}                ║
║  Config:     {os.path.basename(SOURCES_FILE):<34s}║
║  Users:      {len(users)} account(s)                       ║
╚════════════════════════════════════════════════╝
    """)

    print(f"  Accounts:")
    for uname, udata in users.items():
        print(f"    {uname:16s} [{udata['role']}]")
    print()

    print(f"  Source directories ({len(sources)}):")
    for s in sources:
        path = s if isinstance(s, str) else s.get("path", "")
        expanded = os.path.expanduser(path)
        exists = os.path.isdir(expanded)
        marker = "✓" if exists else "✗"
        print(f"    {marker} {path}")
    print()

    if newest:
        print(f"  Found {len(newest)} source file(s):")
        for dtype, filepath in newest:
            print(f"    {dtype:12s} → {os.path.basename(filepath)}")
    else:
        print("  No JSON files found. Check your paths in sources.json")
    print()

    app.run(host=args.host, port=args.port, debug=args.debug)
