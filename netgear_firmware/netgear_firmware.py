#!/usr/bin/env python3
"""
Netgear M4250 Switch Version & CPU Temp Checker
=================================================
Reads switch credentials from switches.csv (default), connects via SSH,
runs `show hardware` and `show environment | include Temp`,
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
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
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
#  ANSI color palette
# ──────────────────────────────────────────────
CYAN   = "\033[96m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
WHITE  = "\033[97m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ──────────────────────────────────────────────
#  Logging — plain text, no colors
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("netgear_m4250_checker")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CSV loader
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def load_csv(csv_path: Path) -> list[dict]:
    if not csv_path.exists():
        print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} CSV not found: {csv_path}{RESET}")
        sys.exit(1)

    devices: list[dict] = []
    with csv_path.open("r", encoding="utf-8-sig") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(fh, dialect=dialect)
        if not reader.fieldnames:
            print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} CSV is empty{RESET}")
            sys.exit(1)

        col_map = {n.strip().lower(): n for n in reader.fieldnames}
        if "host" not in col_map:
            print(f"\n  {WHITE}{BOLD}Error:{RESET}{WHITE} CSV needs a 'host' column.{RESET}")
            sys.exit(1)

        for row in reader:
            host = row.get(col_map["host"], "").strip()
            if not host or host.startswith("#"):
                continue
            username = row.get(col_map.get("username", ""), "").strip() or "admin"
            password = row.get(col_map.get("password", ""), "").strip()
            try:
                port = int(row.get(col_map.get("port", ""), "") or 22)
            except ValueError:
                port = 22
            devices.append({
                "host":     host,
                "username": username,
                "password": password,
                "port":     port,
            })

    return devices


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Table helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def status_icon(r: dict) -> str:
    s = r.get("status", "error")
    if s == "success":
        return f"{GREEN}\u2713 OK{RESET}{WHITE}"
    if s == "auth_error":
        return f"{YELLOW}\u2717 AUTH ERR{RESET}{WHITE}"
    return f"{RED}\u2717 ERROR{RESET}{WHITE}"


def clean(val) -> str:
    s = str(val) if val is not None else "N/A"
    if s in ("None", "-1", ""):
        return "N/A"
    if s.startswith("ERROR") or s in ("Not available", "AUTH ERROR", "See diagnostic"):
        return "N/A"
    return s


def truncate_error(err, max_len: int = 30) -> str:
    if not err:
        return ""
    s = str(err)
    for pat, label in [
        # SSH-specific patterns first
        (r"[Aa]uthentication failed",     "Auth failed"),
        (r"[Aa]uthentication required",   "Auth required"),
        (r"[Nn]o existing session",       "No session"),
        (r"[Ss]SH.*[Ee]rror",            "SSH error"),
        (r"[Cc]ould not parse firmware",  "Parse error"),
        # Generic network patterns
        (r"[Cc]onnection timed out",      "Timed out"),
        (r"[Cc]onnection refused",        "Conn refused"),
        (r"[Nn]o response .* timeout",    "No response"),
        (r"[Nn]o route to host",          "No route"),
        (r"[Nn]etwork is unreachable",    "Net unreachable"),
        (r"[Nn]ame or service not known", "DNS failed"),
        (r"[Nn]etwork error",             "Network error"),
        (r"[Mm]alformed",                 "Bad response"),
    ]:
        if re.search(pat, s):
            return label
    s = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', '', s)
    s = re.sub(r'\[Errno\s*-?\d+\]\s*', '', s)
    s = re.sub(r'\s+', ' ', s).strip(': ')
    return (s[:max_len - 3] + "...") if len(s) > max_len else (s or "Error")


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
#  Parse firmware version from `show hardware`
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_firmware_version(raw: str) -> str | None:
    """
    `show hardware` on an M4250 typically includes lines like:
        Software Version...................  12.0.20.7
        Firmware Version:               12.0.20.7
    Also handles "Build" and "Image" variants seen on some firmware trains.
    """
    clean_text = strip_ansi(raw)
    patterns = [
        r"software\s+version[\s.:]+(\S+)",
        r"firmware\s+version[\s.:]+(\S+)",
        r"build\s+number[\s.:]+(\S+)",
        r"\bversion[\s.:]+(\d+\.\d+[\d.]*)",
    ]
    for pat in patterns:
        m = re.search(pat, clean_text, re.IGNORECASE)
        if m:
            v = m.group(1).strip().rstrip(".,;")
            if v.lower() not in ("is", "the", "a", "not"):
                return v
    return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Parse CPU temperature from `show environment`
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_cpu_temp(raw: str) -> tuple[str | None, float | None]:
    """
    Returns (display_string, numeric_value) or (None, None) if not found.
    Matches lines like:  Temp (C)........ 40
    """
    clean_text = strip_ansi(raw)
    m = re.search(
        r"^Temp\s*\(C\)[.\s]+(\d+(?:\.\d+)?)\s*$",
        clean_text,
        re.IGNORECASE | re.MULTILINE,
    )
    if m:
        val_c = float(m.group(1).strip())
        val_f = val_c * 9 / 5 + 32
        return f"{val_f:.0f} \u00b0F", val_f
    return None, None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Check ONE switch
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_switch(
    host: str,
    username: str = "admin",
    password: str = "",
    port: int = 22,
    timeout: int = 20,
    include_raw: bool = False,
) -> dict:
    queried_at = datetime.now(timezone.utc).isoformat()
    result: dict = {
        "host":             host,
        "username":         username,
        "port":             port,
        "query_timestamp":  queried_at,
        "status":           "error",
        "firmware_version": None,
        "cpu_temp":         None,
        "cpu_temp_value":   None,
        "error":            None,
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

        run_command(channel, "en",               timeout=10)
        run_command(channel, "terminal length 0", timeout=5)

        raw_ver = run_command(channel, "show hardware",                  timeout=20)
        raw_env = run_command(channel, "show environment | include Temp", timeout=20)

        if include_raw:
            result["raw_version"]     = raw_ver
            result["raw_environment"] = raw_env

        firmware = parse_firmware_version(raw_ver)
        temp_str, temp_val = parse_cpu_temp(raw_env)

        result["firmware_version"] = firmware
        result["cpu_temp"]         = temp_str
        result["cpu_temp_value"]   = temp_val

        if firmware is not None:
            result["status"] = "success"
            result["error"]  = None
        else:
            result["status"] = "error"
            result["error"]  = "Could not parse firmware version from output"

        run_command(channel, "exit", timeout=5)
        run_command(channel, "exit", timeout=5)
        channel.close()

    except paramiko.AuthenticationException:
        result["status"] = "auth_error"
        result["error"]  = "Authentication failed"
    except (paramiko.SSHException, socket.error) as exc:
        result["status"] = "error"
        result["error"]  = f"SSH/network error: {exc}"
    except Exception as exc:
        result["status"] = "error"
        result["error"]  = f"Unexpected error: {exc}"
    finally:
        client.close()

    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Print results table
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def print_results_table(results: list[dict], elapsed: float) -> None:
    headers = ["Status", "Host", "Firmware", "CPU Temp", "Error"]
    rows: list[list[str]] = []

    temp_vals: list[float] = []

    for r in results:
        rows.append([
            status_icon(r),
            clean(r.get("host")),
            clean(r.get("firmware_version")),
            clean(r.get("cpu_temp")),
            truncate_error(r.get("error")),
        ])
        tv = r.get("cpu_temp_value")
        if tv is not None:
            temp_vals.append(tv)

    table = tabulate(
        rows,
        headers=headers,
        tablefmt="pretty",
        stralign="left",
        numalign="right",
    )

    # Measure true width of first table line (strip ANSI before measuring)
    first_line = table.split("\n")[0]
    raw_width  = len(re.sub(r'\033\[[0-9;]*m', '', first_line))
    bw         = max(raw_width, 60)

    title = "Netgear M4250 Query Results \u2014 Firmware & CPU Temp"
    pad   = max(0, (bw - len(title)) // 2)

    print(f"{WHITE}")
    print(f"  {'=' * bw}")
    print(f"  {' ' * pad}{BOLD}{title}{RESET}{WHITE}")
    print(f"  {'=' * bw}")
    for line in table.split("\n"):
        print(f"  {line}")

    total = len(results)
    ok    = sum(1 for r in results if r["status"] == "success")
    auth  = sum(1 for r in results if r["status"] == "auth_error")
    err   = sum(1 for r in results if r["status"] == "error")

    print()
    print(
        f"  {BOLD}Total:{RESET}{WHITE} {total}  |  "
        f"{GREEN}\u2713{RESET}{WHITE} {BOLD}Success:{RESET}{WHITE} {ok}  |  "
        f"{YELLOW}\u2717{RESET}{WHITE} {BOLD}Auth Errors:{RESET}{WHITE} {auth}  |  "
        f"{RED}\u2717{RESET}{WHITE} {BOLD}Failed:{RESET}{WHITE} {err}"
    )

    if temp_vals:
        avg = sum(temp_vals) / len(temp_vals)
        print(
            f"  {BOLD}CPU Temp (\u00b0F){RESET}{WHITE} \u2014 "
            f"Avg: {avg:.0f}  |  "
            f"Min: {min(temp_vals):.0f}  |  "
            f"Max: {max(temp_vals):.0f}  |  "
            f"Reported: {len(temp_vals)}/{total}"
        )
    else:
        print(f"  {BOLD}CPU Temp (\u00b0F){RESET}{WHITE} \u2014 No data available")

    print(f"{RESET}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Check ALL switches with progress bar
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_all_switches(
    switches: list[dict],
    output_path: Path,
    include_raw: bool = False,
    max_workers: int = 10,
    timeout: int = 20,
) -> None:
    all_results: list[dict] = [None] * len(switches)  # preserve order

    active_lock  = threading.Lock()
    latest_host  = {"value": ""}
    t_start      = time.time()

    term_width = shutil.get_terminal_size((120, 24)).columns

    bar_fmt = (
        f"  {WHITE}Scanning{RESET} "
        f"{CYAN}{{bar}}{RESET}"
        f" {WHITE}{{n_fmt}}/{{total_fmt}}{RESET}"
        f" {WHITE}[{{elapsed}}<{{remaining}}]{RESET}"
        f"  {WHITE}{{postfix}}{RESET}"
    )

    with tqdm(
        total=len(switches),
        bar_format=bar_fmt,
        ncols=term_width,
        dynamic_ncols=True,
        file=sys.stderr,
        leave=True,
    ) as pbar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_index: dict = {}
            for i, sw in enumerate(switches):
                fut = executor.submit(
                    check_switch,
                    host=sw["host"],
                    username=sw["username"],
                    password=sw["password"],
                    port=sw["port"],
                    timeout=timeout,
                    include_raw=include_raw,
                )
                future_to_index[fut] = i
                with active_lock:
                    latest_host["value"] = sw["host"]

            for future in as_completed(future_to_index):
                idx    = future_to_index[future]
                result = future.result()
                all_results[idx] = result

                with active_lock:
                    host_display = latest_host["value"]
                pbar.set_postfix_str(host_display, refresh=False)
                pbar.update(1)

        elapsed = time.time() - t_start
        pbar.set_postfix_str(
            f"{GREEN}Complete{RESET}{WHITE} in {elapsed:.1f}s",
            refresh=True,
        )

    elapsed = time.time() - t_start

    # ── Write JSON ────────────────────────────────────────────────────────
    total  = len(all_results)
    ok     = sum(1 for r in all_results if r["status"] == "success")
    errors = total - ok

    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "query_info": {
            "csv_file":        str(output_path.parent),
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "protocol":        "SSH / Netgear M4250 CLI",
            "mode":            "firmware+temp",
            "workers":         max_workers,
            "total":           total,
            "success":         ok,
            "errors":          errors,
            "elapsed_seconds": round(elapsed, 2),
        },
        "switches": all_results,
    }
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    # ── Print table ───────────────────────────────────────────────────────
    print_results_table(all_results, elapsed)

    print(f"  {WHITE}{BOLD}Results saved:{RESET}{WHITE} {output_path}{RESET}")
    print(f"  {WHITE}{BOLD}Elapsed:{RESET}{WHITE} {elapsed:.1f}s ({max_workers} workers){RESET}")
    print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "Check Netgear M4250 switch firmware versions and CPU temps via SSH.\n"
            "Defaults: reads switches.csv, writes results.json\n\n"
            "CSV columns: host, username, password, port"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--csv", type=Path, default=Path("switches.csv"),
        help="Input CSV file (default: switches.csv)",
    )
    p.add_argument(
        "--output", type=Path, default=Path("results.json"),
        help="Output JSON file (default: results.json)",
    )
    p.add_argument(
        "--workers", type=int, default=5,
        help="Number of concurrent SSH connections (default: 5)",
    )
    p.add_argument(
        "--timeout", type=int, default=20,
        help="Per-switch SSH timeout in seconds (default: 20)",
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

    print(f"{WHITE}")
    print(f"  {BOLD}Netgear M4250 Firmware & CPU Temp Checker{RESET}{WHITE}")
    print(f"  Query switch firmware version and CPU temperature via SSH")
    print(f"  Input:   {args.csv}")
    print(f"  Output:  {args.output}")
    print(f"  Workers: {args.workers}")
    print(f"  Timeout: {args.timeout}s")
    print(f"{RESET}")

    switches = load_csv(args.csv)
    if not switches:
        print(f"  {WHITE}{BOLD}Error:{RESET}{WHITE} No switches found in {args.csv}{RESET}")
        sys.exit(1)

    print(f"  {WHITE}Loaded {BOLD}{len(switches)}{RESET}{WHITE} switch(es){RESET}\n")

    check_all_switches(
        switches,
        args.output,
        include_raw=args.include_raw,
        max_workers=args.workers,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()
