#!/usr/bin/env python3
"""
MikroTik Router Version Checker
================================
Reads router credentials from routers.csv (default), connects via SSH,
runs /system/package/print, extracts name + version for each package,
writes results to results.json (default), and prints a summary table.

Usage:
    python3 mikrotik_checker.py
    python3 mikrotik_checker.py --verbose
    python3 mikrotik_checker.py --csv other_routers.csv --output other_results.json
    python3 mikrotik_checker.py --include-raw --verbose
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import shutil
import socket
import sys
import time
from pathlib import Path

try:
    import paramiko
except ImportError:
    sys.exit("ERROR: pip install paramiko")

try:
    from tabulate import tabulate
except ImportError:
    sys.exit("ERROR: pip install tabulate")

try:
    from tqdm import tqdm
except ImportError:
    sys.exit("ERROR: pip install tqdm")

# ──────────────────────────────────────────────
#  Terminal width detection
# ──────────────────────────────────────────────
TERMINAL_WIDTH = shutil.get_terminal_size().columns

# ──────────────────────────────────────────────
#  Colors — cyan accent ONLY for progress bar
# ──────────────────────────────────────────────
CYAN  = "\033[96m"
RESET = "\033[0m"

# ──────────────────────────────────────────────
#  Logging — plain white text, no colors
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("mikrotik_checker")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CSV reader
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def read_router_csv(csv_path: Path) -> list[dict]:
    routers: list[dict] = []
    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames:
            reader.fieldnames = [f.strip().lower() for f in reader.fieldnames]
        for row_num, row in enumerate(reader, start=2):
            row = {k: (v.strip() if v else "") for k, v in row.items()}
            host = (
                row.get("host") or row.get("hostname")
                or row.get("ip") or row.get("address")
            )
            if not host:
                continue
            routers.append({
                "host":     host,
                "username": row.get("username") or "admin",
                "password": row.get("password", ""),
                "port":     int(row.get("port") or 22),
            })
    return routers


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Strip ANSI escape codes
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def strip_ansi(text: str) -> str:
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    text = re.sub(r"\x1b\].*?\x07", "", text)
    text = re.sub(r"\x1b[()][AB012]", "", text)
    text = re.sub(r"\x1b.", "", text)
    text = re.sub(r"[\x00-\x08\x0e-\x1f\x7f]", "", text)
    return text


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SSH: get command output (tries TWO methods)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def get_command_output(client: paramiko.SSHClient, command: str) -> str:
    output = ""

    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=15)
        output = stdout.read().decode("utf-8", errors="replace")
        if output.strip():
            return output
    except Exception:
        pass

    try:
        channel = client.invoke_shell(width=200, height=50)
        time.sleep(2)
        if channel.recv_ready():
            channel.recv(65535)

        channel.send(command + "\n")
        time.sleep(3)

        raw = b""
        deadline = time.time() + 15
        while time.time() < deadline:
            if channel.recv_ready():
                raw += channel.recv(65535)
                time.sleep(0.5)
            else:
                time.sleep(0.5)
                if not channel.recv_ready():
                    break

        output = raw.decode("utf-8", errors="replace")
        channel.close()
    except Exception:
        pass

    return output


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Parse the output — extract NAME + VERSION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_packages(raw: str) -> list[dict]:
    clean = strip_ansi(raw)
    packages: list[dict] = []
    seen: set[str] = set()

    kv_matches = re.findall(
        r'name\s*=\s*"([^"]+)".*?version\s*=\s*"([^"]+)"',
        clean,
        re.IGNORECASE,
    )
    if kv_matches:
        for name, version in kv_matches:
            key = f"{name.strip()}|{version.strip()}"
            if key not in seen:
                seen.add(key)
                packages.append({
                    "name":    name.strip(),
                    "version": version.strip(),
                })
        return packages

    for line in clean.splitlines():
        stripped = line.strip()

        if not stripped:
            continue
        if stripped.startswith("#") or stripped.startswith("Columns"):
            continue
        if stripped.startswith("Flags"):
            continue
        if "/system" in stripped.lower():
            continue
        if stripped.endswith(">") or stripped.endswith("#"):
            continue

        m = re.match(
            r"^\s*(\d+)\s+"
            r"([X\s]{0,3})\s*"
            r"(\S+)\s+"
            r"(\d+\.\d+\S*)",
            stripped,
        )
        if m:
            name    = m.group(3).strip()
            version = m.group(4).strip()
            flags   = m.group(2).strip()
            key = f"{name}|{version}"
            if key not in seen:
                seen.add(key)
                pkg: dict = {"name": name, "version": version}
                if "X" in flags:
                    pkg["disabled"] = True
                packages.append(pkg)
            continue

        m = re.match(
            r"^\s*(\S+)\s+"
            r"(\d+\.\d+\S*)\s*$",
            stripped,
        )
        if m:
            name    = m.group(1).strip()
            version = m.group(2).strip()
            if name.lower() in ("name", "version", "#", "columns:", "flags:"):
                continue
            key = f"{name}|{version}"
            if key not in seen:
                seen.add(key)
                packages.append({"name": name, "version": version})

    return packages


def get_routeros_version(packages: list[dict]) -> str | None:
    for pkg in packages:
        if "routeros" in pkg["name"].lower():
            return pkg["version"]
    for pkg in packages:
        if pkg["name"].lower() == "system":
            return pkg["version"]
    if packages:
        return packages[0]["version"]
    return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Check ONE router (silent — no logging)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_router(
    host: str,
    username: str = "admin",
    password: str = "",
    port: int = 22,
    timeout: int = 15,
) -> dict:
    result: dict = {
        "host":              host,
        "username":          username,
        "port":              port,
        "success":           False,
        "routeros_version":  None,
        "packages":          [],
        "raw_output":        "",
        "error":             None,
    }

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
            disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]},
        )

        cmd = "/system/package/print"
        raw = get_command_output(client, cmd)
        result["raw_output"] = raw

        if not raw.strip():
            result["error"] = "Router returned empty output"
            return result

        packages = parse_packages(raw)
        result["packages"] = packages

        version = get_routeros_version(packages)
        result["routeros_version"] = version
        result["success"] = len(packages) > 0

        if not packages:
            result["error"] = "Could not parse any packages from output"

    except paramiko.AuthenticationException:
        result["error"] = "Authentication failed"
    except (paramiko.SSHException, socket.error) as exc:
        result["error"] = f"SSH/network error: {exc}"
    except Exception as exc:
        result["error"] = f"Unexpected error: {exc}"
    finally:
        client.close()

    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Print results table to console
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def print_results_table(results: list[dict]) -> None:
    tw = TERMINAL_WIDTH

    headers = [
        "Status",
        "Host",
        "Port",
        "Username",
        "RouterOS Version",
        "Packages",
        "Error",
    ]

    rows: list[list[str]] = []
    for r in results:
        status  = "OK" if r["success"] else "FAIL"
        version = r.get("routeros_version") or "N/A"

        pkg_list = r.get("packages", [])
        if pkg_list:
            pkg_strs = []
            for pkg in pkg_list:
                disabled = " [X]" if pkg.get("disabled") else ""
                pkg_strs.append(f"{pkg['name']}({pkg['version']}){disabled}")
            pkg_text = ", ".join(pkg_strs)
        else:
            pkg_text = "N/A"

        error = r.get("error") or ""

        rows.append([
            status,
            r["host"],
            str(r.get("port", 22)),
            r.get("username", "admin"),
            version,
            pkg_text,
            error,
        ])

    # Title
    print()
    print("=" * tw)
    print("MikroTik RouterOS — Package Version Query Results")
    print("=" * tw)

    # Table
    table_str = tabulate(
        rows,
        headers=headers,
        tablefmt="pretty",
        stralign="left",
        numalign="left",
    )
    print(table_str)

    # Summary
    ok   = sum(1 for r in results if r["success"])
    fail = len(results) - ok
    print("-" * tw)
    print(f"Total: {len(results)} | Success: {ok} | Failed: {fail}")
    print("=" * tw)
    print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Check ALL routers
#  ONE progress bar, scaled to terminal width,
#  no log messages breaking the bar
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_all_routers(
    routers: list[dict],
    output_path: Path,
    include_raw: bool = False,
) -> None:
    all_results: list[dict] = []

    # Progress bar scaled to full terminal width
    bar_width = max(40, TERMINAL_WIDTH - 2)

    with tqdm(
        total=len(routers),
        desc="Querying routers",
        bar_format=(
            "{l_bar}"
            f"{CYAN}{{bar}}{RESET}"
            "| {n_fmt}/{total_fmt} "
            "[{elapsed}<{remaining}] "
            "{postfix}"
        ),
        ncols=bar_width,
        unit="router",
    ) as pbar:
        for router in routers:
            # Show current host on the right side of the bar
            pbar.set_postfix_str(router["host"], refresh=True)

            result = check_router(
                host=router["host"],
                username=router["username"],
                password=router["password"],
                port=router["port"],
            )

            if not include_raw:
                result.pop("raw_output", None)

            all_results.append(result)
            pbar.update(1)

    # Clear line after progress bar finishes
    print()

    # Write JSON
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(all_results, fh, indent=2, ensure_ascii=False)

    # Print results table
    print_results_table(all_results)

    # Print output location
    print(f"Results saved to: {output_path}")
    print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "Check MikroTik router versions via SSH.\n"
            "Defaults: reads routers.csv, writes results.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--csv", type=Path, default=Path("routers.csv"),
        help="Input CSV file (default: routers.csv)",
    )
    p.add_argument(
        "--output", type=Path, default=Path("results.json"),
        help="Output JSON file (default: results.json)",
    )
    p.add_argument(
        "--verbose", action="store_true",
        help="DEBUG logging - shows raw output line by line",
    )
    p.add_argument(
        "--include-raw", action="store_true",
        help="Include raw SSH output in results.json for debugging",
    )
    args = p.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Startup banner
    tw = TERMINAL_WIDTH
    print()
    print("=" * tw)
    print("MikroTik RouterOS — Package Version Checker")
    print("=" * tw)
    print(f"  Input CSV  : {args.csv}")
    print(f"  Output JSON: {args.output}")
    print(f"  Terminal    : {tw} columns")
    print()

    if not args.csv.is_file():
        print(f"ERROR: Cannot find {args.csv}")
        print("Make sure the CSV exists with columns: host,username,password,port")
        sys.exit(1)

    routers = read_router_csv(args.csv)
    if not routers:
        print(f"ERROR: No routers found in {args.csv}")
        sys.exit(1)

    print(f"Loaded {len(routers)} router(s)")
    print()

    check_all_routers(routers, args.output, include_raw=args.include_raw)


if __name__ == "__main__":
    main()
