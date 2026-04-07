"""Preprocess all PCAPs into Zeek logs for a full-coverage agent run.

Runs Zeek on all PCAPs in parallel (one worker per PCAP), then merges the
results into a single sorted set of Zeek logs.

Usage:
    python preprocess_pcaps.py [pcap_dir] [output_dir] [--workers N]

Defaults:
    pcap_dir   = ../network/pcap
    output_dir = forensic_output/zeek_logs_full
    workers    = min(8, cpu_count)
"""

import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

DEFAULT_PCAP_DIR = Path(__file__).parent.parent / "network" / "pcap"
DEFAULT_OUTPUT_DIR = Path(__file__).parent / "forensic_output" / "zeek_logs_full"
ZEEK_BIN = "/opt/zeek/bin/zeek"
_DPD_COMPAT_SCRIPT = Path(__file__).parent / "dpd_compat.zeek"

_print_lock = Lock()


def _wsl_path(windows_path: Path) -> str:
    drive, tail = os.path.splitdrive(str(windows_path.resolve()))
    return f"/mnt/{drive.replace(':', '').lower()}{tail.replace(os.sep, '/')}"


# Extra Zeek policy scripts loaded on top of the default base scripts.
# - base/frameworks/software: enables software.log (host fingerprinting)
# - policy/protocols/http/software: populates software.log from HTTP User-Agent headers
# - policy/protocols/http/detect-webapps: additional web app fingerprinting
# - policy/protocols/conn/known-hosts: enables known_hosts.log
# - policy/protocols/conn/known-services: enables known_services.log
# NOTE: dpd.log was removed in Zeek 7.2 (PR #4200).  dpd_compat.zeek recreates
#       it for Zeek 8.x using the analyzer_failed event + AnalyzerViolationInfo API.
EXTRA_SCRIPTS = (
    "base/frameworks/software "
    "policy/protocols/http/software "
    "policy/protocols/http/detect-webapps "
    "policy/protocols/conn/known-hosts "
    "policy/protocols/conn/known-services"
)


def _zeek_command(pcap: Path, cwd: Path) -> list[str]:
    if sys.platform == "win32":
        wsl_pcap = _wsl_path(pcap)
        wsl_cwd = _wsl_path(cwd)
        wsl_dpd = _wsl_path(_DPD_COMPAT_SCRIPT)
        return ["wsl", "bash", "-c",
                f"cd '{wsl_cwd}' && {ZEEK_BIN} -r '{wsl_pcap}' {EXTRA_SCRIPTS} '{wsl_dpd}'"]
    return ["zeek", "-r", str(pcap.resolve())] + EXTRA_SCRIPTS.split() + [str(_DPD_COMPAT_SCRIPT)]


def _run_zeek_on_pcap(pcap: Path, scratch_dir: Path, index: int, total: int) -> tuple[Path, str | None]:
    """Run Zeek on a single PCAP into scratch_dir. Returns (scratch_dir, error_or_None)."""
    scratch_dir.mkdir(parents=True, exist_ok=True)
    cmd = _zeek_command(pcap, scratch_dir)
    try:
        result = subprocess.run(
            cmd,
            cwd=str(scratch_dir),
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return scratch_dir, "Zeek not found (check WSL / zeek installation)"

    if result.returncode != 0:
        err = result.stderr.strip()[:120]
        with _print_lock:
            print(f"  [{index}/{total}] WARN {pcap.name}: zeek exit {result.returncode} — {err}")
        return scratch_dir, err

    log_count = len(list(scratch_dir.glob("*.log")))
    with _print_lock:
        print(f"  [{index}/{total}] OK   {pcap.name}  ({log_count} log types)")
    return scratch_dir, None


def _load_log(path: Path) -> tuple[list[str], list[str]]:
    hdrs, rows = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#"):
                hdrs.append(line)
            else:
                s = line.rstrip("\n\r")
                if s:
                    rows.append(s)
    return hdrs, rows


def _ts_key(line: str) -> float:
    try:
        return float(line.split("\t", 1)[0])
    except (ValueError, IndexError):
        return 0.0


def _merge_scratches(scratch_dirs: list[Path], output_dir: Path) -> None:
    """Merge all per-PCAP scratch directories into output_dir."""
    headers: dict[str, list[str]] = {}
    data: dict[str, list[str]] = {}

    for sdir in scratch_dirs:
        for log_file in sdir.glob("*.log"):
            name = log_file.name
            hdrs, rows = _load_log(log_file)
            if not rows:
                continue
            if name not in headers:
                headers[name] = hdrs
                data[name] = []
            data[name].extend(rows)

    print(f"\n[MERGE] Sorting and writing {len(data)} log type(s) to {output_dir} ...")
    output_dir.mkdir(parents=True, exist_ok=True)

    for name, rows in sorted(data.items()):
        rows.sort(key=_ts_key)
        out_path = output_dir / name
        with open(out_path, "w", encoding="utf-8") as fh:
            for h in headers.get(name, []):
                fh.write(h)
            for r in rows:
                fh.write(r + "\n")
        size_mb = out_path.stat().st_size / 1_048_576
        print(f"  {name:<28} {len(rows):>10,} rows  ({size_mb:.1f} MB)")


def main():
    args = sys.argv[1:]
    workers = min(8, os.cpu_count() or 4)
    positional = []
    i = 0
    while i < len(args):
        if args[i] == "--workers" and i + 1 < len(args):
            workers = int(args[i + 1])
            i += 2
        else:
            positional.append(args[i])
            i += 1

    pcap_dir = Path(positional[0]) if len(positional) > 0 else DEFAULT_PCAP_DIR
    output_dir = Path(positional[1]) if len(positional) > 1 else DEFAULT_OUTPUT_DIR

    if not pcap_dir.is_dir():
        print(f"ERROR: PCAP directory not found: {pcap_dir}")
        sys.exit(1)

    pcaps = sorted(p for p in pcap_dir.iterdir() if p.suffix in {".pcap", ".pcapng"})
    if not pcaps:
        print(f"ERROR: No .pcap/.pcapng files in {pcap_dir}")
        sys.exit(1)

    scratch_base = output_dir / "_zeek_scratch"

    print(f"PCAP directory : {pcap_dir}")
    print(f"Output directory: {output_dir}")
    print(f"PCAPs found    : {len(pcaps)}")
    print(f"Workers        : {workers}")
    print()

    start = time.time()

    scratch_dirs: list[Path] = []
    errors = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                _run_zeek_on_pcap,
                pcap,
                scratch_base / f"pcap_{i:04d}",
                i,
                len(pcaps),
            ): pcap
            for i, pcap in enumerate(pcaps, 1)
        }
        for future in as_completed(futures):
            sdir, err = future.result()
            scratch_dirs.append(sdir)
            if err:
                errors += 1

    zeek_elapsed = time.time() - start
    minutes, seconds = divmod(int(zeek_elapsed), 60)
    print(f"\n[ZEEK] All {len(pcaps)} PCAPs processed in {minutes}m {seconds}s"
          f" ({errors} error(s))")

    _merge_scratches(scratch_dirs, output_dir)

    # Clean up scratch dirs
    shutil.rmtree(scratch_base, ignore_errors=True)

    total_elapsed = time.time() - start
    minutes, seconds = divmod(int(total_elapsed), 60)
    print(f"\nDone in {minutes}m {seconds}s. Logs written to: {output_dir}")
    print(f"\nTo run the agent on these logs:")
    print(f"  python -m agent {output_dir}")


if __name__ == "__main__":
    main()
