#!/usr/bin/env python3
"""
Netgear M4250 Switch Version & CPU Temp Checker
=================================================
Reads switch credentials from switches.csv (default), connects via SSH,
runs `show version` and `show environment` (or `show process cpu`),
extracts firmware version and CPU temperature, writes results to
results.json (default), and prints a summary table.

Usage:
    python3 netgear_m4250_checker.py
    python3 netgear_m4250_checker.py --verbose
    python3 netgear_m4250_checker.py --csv other_switches.csv --output other_results.json
    python3 netgear_m4250_checker.py --include-raw --verbose

CSV columns: host, username, password, port (port defaults to 22)
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
from concurrent.futures import ThreadPoolExecutor, as_completed
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
log = logging.getLogger("netgear_m4250_checker")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CSV reader
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def read_switch_csv(csv_path: Path) -> list[dict]:
    switches: list[dict] = []
    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames:
            reader.fieldnames = [f.strip().lower() for f in reader.fieldnames]
        for row in reader:
            row = {k: (v.strip() if v else "") for k, v in row.items()}
            host = (
                row.get("host") or row.get("hostname")
                or row.get("ip") or row.get("address")
            )
            if not host:
                continue
            switches.append({
                "host":     host,
                "username": row.get("username") or "admin",
                "password": row.get("password", ""),
                "port":     int(row.get("port") or 22),
            })
    return switches


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
#  SSH shell helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _read_until_prompt(channel: paramiko.Channel, timeout: float = 15.0) -> str:
    """
    Read from an interactive SSH channel until a CLI prompt is detected
    or the timeout expires.  Netgear M4250 prompts end with '>' or '#'.
    """
    raw = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(65535)
            raw += chunk
            decoded = raw.decode("utf-8", errors="replace")
            # Prompt patterns: "(M4250-xx) >" / "(M4250-xx) #" / ">"  / "#"
            if re.search(r"[>#]\s*$", decoded.rstrip()):
                break
        else:
            time.sleep(0.3)
    return raw.decode("utf-8", errors="replace")


def open_shell(client: paramiko.SSHClient) -> paramiko.Channel:
    """Open an interactive shell and wait for the first prompt."""
    channel = client.invoke_shell(term="vt100", width=220, height=50)
    time.sleep(2)
    _read_until_prompt(channel, timeout=10)  # discard banner / MOTD
    return channel


def run_command(channel: paramiko.Channel, command: str, timeout: float = 20.0) -> str:
    """Send a command and return the output up to the next prompt."""
    channel.send(command + "\n")
    time.sleep(0.5)
    return _read_until_prompt(channel, timeout=timeout)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Parse firmware version from `show version`
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_firmware_version(raw: str) -> str | None:
    """
    `show hardware` on an M4250 typically includes lines like:
        Software Version...................  12.0.20.7
        Firmware Version:               12.0.20.7
    Also handles "Build" and "Image" variants seen on some firmware trains.
    """
    clean = strip_ansi(raw)

    patterns = [
        # "Software Version....... 12.0.20.7"
        r"software\s+version[\s.:]+(\S+)",
        # "Firmware Version:  12.0.20.7"
        r"firmware\s+version[\s.:]+(\S+)",
        # "Build Number:  20"  – less useful but a fallback
        r"build\s+number[\s.:]+(\S+)",
        # plain "Version X.Y.Z" anywhere
        r"\bversion[\s.:]+(\d+\.\d+[\d.]*)",
    ]
    for pat in patterns:
        m = re.search(pat, clean, re.IGNORECASE)
        if m:
            v = m.group(1).strip().rstrip(".,;")
            if v.lower() not in ("is", "the", "a", "not"):
                return v
    return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Parse CPU temperature from show environment
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_cpu_temp(raw: str) -> str | None:
    """
    Output of `show environment | include Temp` on M4250 returns lines like:
        Temp (C)....................................... 40
        Temperature traps range: 0 to 90 degrees (Celsius)
        Temperature Sensors:
        Unit     Sensor  Description       Temp (C)    State              Max_Temp (C)

    We want the first "Temp (C)" line which has the actual value after the dots.
    """
    clean = strip_ansi(raw)

    # Match "Temp (C)........ 40" — dots between label and number
    m = re.search(r"^Temp\s*\(C\)[.\s]+(\d+(?:\.\d+)?)\s*$", clean, re.IGNORECASE | re.MULTILINE)
    if m:
        return f"{m.group(1).strip()} °C"

    return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Check ONE switch
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_switch(
    host: str,
    username: str = "admin",
    password: str = "",
    port: int = 22,
    timeout: int = 20,
) -> dict:
    result: dict = {
        "host":              host,
        "username":          username,
        "port":              port,
        "success":           False,
        "firmware_version":  None,
        "cpu_temp":          None,
        "raw_version":       "",
        "raw_environment":   "",
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
        )

        channel = open_shell(client)

        # ── Elevate to privileged exec mode ───────────────────────────────
        run_command(channel, "en", timeout=10)

        # ── Disable paging so output isn't truncated ──────────────────────
        run_command(channel, "terminal length 0", timeout=5)

        # ── Firmware version ──────────────────────────────────────────────
        raw_ver = run_command(channel, "show hardware", timeout=20)
        result["raw_version"] = raw_ver
        firmware = parse_firmware_version(raw_ver)
        result["firmware_version"] = firmware

        # ── CPU temperature ───────────────────────────────────────────────
        raw_env = run_command(channel, "show environment | include Temp", timeout=20)
        result["raw_environment"] = raw_env
        cpu_temp = parse_cpu_temp(raw_env)
        result["cpu_temp"] = cpu_temp
        result["success"]  = firmware is not None

        if firmware is None:
            result["error"] = "Could not parse firmware version from output"

        # ── Graceful logout ───────────────────────────────────────────────
        run_command(channel, "exit", timeout=5)   # exit privileged exec mode
        run_command(channel, "quit", timeout=5)   # close the CLI session
        channel.close()

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
        "Firmware Version",
        "CPU Temp",
        "Error",
    ]

    rows: list[list[str]] = []
    for r in results:
        status   = "OK"   if r["success"] else "FAIL"
        firmware = r.get("firmware_version") or "N/A"
        cpu_temp = r.get("cpu_temp")         or "N/A"
        error    = r.get("error")            or ""

        rows.append([
            status,
            r["host"],
            str(r.get("port", 22)),
            r.get("username", "admin"),
            firmware,
            cpu_temp,
            error,
        ])

    print()
    print("=" * tw)
    print("Netgear M4250 — Firmware Version & CPU Temp Query Results")
    print("=" * tw)

    table_str = tabulate(
        rows,
        headers=headers,
        tablefmt="pretty",
        stralign="left",
        numalign="left",
    )
    print(table_str)

    ok   = sum(1 for r in results if r["success"])
    fail = len(results) - ok
    print("-" * tw)
    print(f"Total: {len(results)} | Success: {ok} | Failed: {fail}")
    print("=" * tw)
    print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Check ALL switches with progress bar
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_all_switches(
    switches: list[dict],
    output_path: Path,
    include_raw: bool = False,
    max_workers: int = 10,
) -> None:
    all_results: list[dict] = [None] * len(switches)  # preserve order

    bar_width = max(40, TERMINAL_WIDTH - 2)

    with tqdm(
        total=len(switches),
        desc="Querying switches",
        bar_format=(
            "{l_bar}"
            f"{CYAN}{{bar}}{RESET}"
            "| {n_fmt}/{total_fmt} "
            "[{elapsed}<{remaining}] "
            "{postfix}"
        ),
        ncols=bar_width,
        unit="switch",
    ) as pbar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_index = {
                executor.submit(
                    check_switch,
                    host=sw["host"],
                    username=sw["username"],
                    password=sw["password"],
                    port=sw["port"],
                ): i
                for i, sw in enumerate(switches)
            }

            for future in as_completed(future_to_index):
                idx = future_to_index[future]
                result = future.result()

                if not include_raw:
                    result.pop("raw_version",     None)
                    result.pop("raw_environment", None)

                all_results[idx] = result
                pbar.set_postfix_str(result["host"], refresh=True)
                pbar.update(1)

    print()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(all_results, fh, indent=2, ensure_ascii=False)

    print_results_table(all_results)
    print(f"Results saved to: {output_path}")
    print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "Check Netgear M4250 switch firmware versions and CPU temps via SSH.\n"
            "Defaults: reads routers.csv, writes results.json\n\n"
            "CSV columns: host, username, password, port"
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
        "--workers", type=int, default=10,
        help="Number of concurrent SSH connections (default: 10)",
    )
    p.add_argument(
        "--verbose", action="store_true",
        help="Enable DEBUG logging",
    )
    p.add_argument(
        "--include-raw", action="store_true",
        help="Include raw SSH output in results.json for debugging",
    )
    args = p.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tw = TERMINAL_WIDTH
    print()
    print("=" * tw)
    print("Netgear M4250 — Firmware Version & CPU Temp Checker")
    print("=" * tw)
    print(f"  Input CSV  : {args.csv}")
    print(f"  Output JSON: {args.output}")
    print(f"  Workers    : {args.workers}")
    print(f"  Terminal   : {tw} columns")
    print()

    if not args.csv.is_file():
        print(f"ERROR: Cannot find {args.csv}")
        print("Make sure the CSV exists with columns: host,username,password,port")
        sys.exit(1)

    switches = read_switch_csv(args.csv)
    if not switches:
        print(f"ERROR: No switches found in {args.csv}")
        sys.exit(1)

    print(f"Loaded {len(switches)} switch(es)")
    print()

    check_all_switches(switches, args.output, include_raw=args.include_raw, max_workers=args.workers)


if __name__ == "__main__":
    main()
