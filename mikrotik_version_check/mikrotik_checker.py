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
import socket
import sys
import time
from pathlib import Path

try:
    import paramiko
except ImportError:
    sys.exit("ERROR: pip install paramiko")

logging.basicConfig(
    level=logging.INFO,
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
                log.warning("Row %d: no host – skipping", row_num)
                continue
            routers.append({
                "host":     host,
                "username": row.get("username") or "admin",
                "password": row.get("password", ""),
                "port":     int(row.get("port") or 22),
            })
    log.info("Loaded %d router(s) from %s", len(routers), csv_path)
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
        log.debug("  Trying exec_command …")
        stdin, stdout, stderr = client.exec_command(command, timeout=15)
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        if err:
            log.debug("  stderr: %s", err.strip())
        if output.strip():
            log.debug("  exec_command returned %d bytes", len(output))
            return output
        log.debug("  exec_command empty, trying invoke_shell …")
    except Exception as exc:
        log.debug("  exec_command failed (%s), trying invoke_shell …", exc)

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
        log.debug("  invoke_shell returned %d bytes", len(output))
        channel.close()
    except Exception as exc:
        log.error("  invoke_shell also failed: %s", exc)

    return output


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Parse the output — extract NAME + VERSION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_packages(raw: str) -> list[dict]:
    clean = strip_ansi(raw)
    packages: list[dict] = []
    seen: set[str] = set()

    log.debug("  Cleaned output for parsing:")
    for i, line in enumerate(clean.splitlines()):
        log.debug("    [%d] %r", i, line)

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
        log.debug("  Pattern A found %d packages", len(packages))
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
                log.debug("  Pattern B matched: name=%s version=%s", name, version)
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
                log.debug("  Pattern C matched: name=%s version=%s", name, version)

    if packages:
        log.debug("  Total packages found: %d", len(packages))
    else:
        log.warning("  No packages could be parsed from the output")

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
#  Check ONE router
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
        log.info("[%s] Connecting (user=%s, port=%d) …", host, username, port)
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
        log.info("[%s] Running: %s", host, cmd)
        raw = get_command_output(client, cmd)
        result["raw_output"] = raw

        if not raw.strip():
            result["error"] = "Router returned empty output"
            log.warning("[%s] ✘  Empty output", host)
            return result

        packages = parse_packages(raw)
        result["packages"] = packages

        version = get_routeros_version(packages)
        result["routeros_version"] = version
        result["success"] = len(packages) > 0

        if packages:
            log.info("[%s] ✔  Found %d package(s):", host, len(packages))
            for pkg in packages:
                disabled = " (disabled)" if pkg.get("disabled") else ""
                log.info("[%s]    %-25s %s%s", host, pkg["name"], pkg["version"], disabled)
        else:
            result["error"] = "Could not parse any packages from output"
            log.warning("[%s] ✘  No packages parsed", host)
            log.warning("[%s]    Raw output:\n%s", host, raw)

    except paramiko.AuthenticationException:
        result["error"] = "Authentication failed"
        log.error("[%s] Auth failed", host)
    except (paramiko.SSHException, socket.error) as exc:
        result["error"] = f"SSH/network error: {exc}"
        log.error("[%s] %s", host, exc)
    except Exception as exc:
        result["error"] = f"Unexpected error: {exc}"
        log.exception("[%s] %s", host, exc)
    finally:
        client.close()

    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Print results table to console
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def print_results_table(results: list[dict]) -> None:
    """
    Print a bordered table matching this format:

    +----------+----------------+------+------------------+---------------------+
    | Status   | Host           | Port | RouterOS Version | Packages            |
    +----------+----------------+------+------------------+---------------------+
    | ✓ OK     | 10.0.0.1       | 22   | 7.16.2           | routeros(7.16.2)    |
    | ✗ FAIL   | 10.0.0.2       | 22   | N/A              | N/A                 |
    +----------+----------------+------+------------------+---------------------+
    Total: 2 | Success: 1 | Failed: 1
    """

    # ── Column definitions ──
    columns = [
        {"header": "Status",           "key": "status"},
        {"header": "Host",             "key": "host"},
        {"header": "Port",             "key": "port"},
        {"header": "Username",         "key": "username"},
        {"header": "RouterOS Version", "key": "version"},
        {"header": "Packages",         "key": "pkgs"},
        {"header": "Error",            "key": "error"},
    ]

    # ── Build row data ──
    rows: list[dict] = []
    for r in results:
        if r["success"]:
            status = "\u2713 OK"
        else:
            status = "\u2717 FAIL"

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

        rows.append({
            "status":   status,
            "host":     r["host"],
            "port":     str(r.get("port", 22)),
            "username": r.get("username", "admin"),
            "version":  version,
            "pkgs":     pkg_text,
            "error":    error,
        })

    # ── Calculate column widths ──
    widths: list[int] = []
    for col in columns:
        key = col["key"]
        header_len = len(col["header"])
        data_len = max((len(row[key]) for row in rows), default=0) if rows else 0
        widths.append(max(header_len, data_len))

    # Cap packages and error columns so table doesn't get too wide
    pkg_idx   = next(i for i, c in enumerate(columns) if c["key"] == "pkgs")
    error_idx = next(i for i, c in enumerate(columns) if c["key"] == "error")
    widths[pkg_idx]   = min(widths[pkg_idx], 50)
    widths[error_idx] = min(widths[error_idx], 30)

    # ── Build separator and row format ──
    def make_separator() -> str:
        parts = ["-" * (w + 2) for w in widths]
        return "+" + "+".join(parts) + "+"

    def make_row(values: list[str]) -> str:
        cells = []
        for i, val in enumerate(values):
            truncated = val[:widths[i]] if len(val) > widths[i] else val
            cells.append(f" {truncated:<{widths[i]}} ")
        return "|" + "|".join(cells) + "|"

    sep = make_separator()

    # ── Print title ──
    title = "MikroTik RouterOS — Package Version Query Results"
    title_width = len(sep)
    print()
    print("#", "=" * (title_width - 2))
    print(f"  {title}")
    print("#", "=" * (title_width - 2))

    # ── Print header ──
    print(sep)
    header_values = [col["header"] for col in columns]
    print(make_row(header_values))
    print(sep)

    # ── Print data rows ──
    for row in rows:
        row_values = [row[col["key"]] for col in columns]
        print(make_row(row_values))

    # ── Print bottom border ──
    print(sep)

    # ── Print summary ──
    ok   = sum(1 for r in results if r["success"])
    fail = len(results) - ok
    print(f"Total: {len(results)} | Success: {ok} | Failed: {fail}")
    print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Check ALL routers -> JSON + Table
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_all_routers(
    routers: list[dict],
    output_path: Path,
    include_raw: bool = False,
) -> None:
    all_results: list[dict] = []

    for idx, router in enumerate(routers, start=1):
        log.info("-- Router %d / %d --", idx, len(routers))
        result = check_router(
            host=router["host"],
            username=router["username"],
            password=router["password"],
            port=router["port"],
        )
        if not include_raw:
            result.pop("raw_output", None)
        all_results.append(result)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(all_results, fh, indent=2, ensure_ascii=False)

    log.info("Results written to %s", output_path)
    print_results_table(all_results)


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
        "--csv",
        type=Path,
        default=Path("routers.csv"),
        help="Input CSV file (default: routers.csv)",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=Path("results.json"),
        help="Output JSON file (default: results.json)",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="DEBUG logging - shows raw output line by line",
    )
    p.add_argument(
        "--include-raw",
        action="store_true",
        help="Include raw SSH output in results.json for debugging",
    )
    args = p.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.csv.is_file():
        log.error("Cannot find %s", args.csv)
        log.error("Make sure the CSV exists with columns: host,username,password,port")
        sys.exit(1)

    routers = read_router_csv(args.csv)
    if not routers:
        log.error("No routers found in %s", args.csv)
        sys.exit(1)

    check_all_routers(routers, args.output, include_raw=args.include_raw)


if __name__ == "__main__":
    main()
