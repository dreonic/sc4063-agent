"""Utilities for ingesting PCAP files via Zeek and discovering Zeek log files."""

import subprocess
import sys
import tempfile
from pathlib import Path


def run_zeek(pcap_path: str, output_dir: str) -> Path:
    """Run 'zeek -r <pcap>' to produce log files, then sort each by timestamp.

    Args:
        pcap_path: Path to the PCAP file to analyze.
        output_dir: Directory where Zeek should write its log output.

    Returns:
        Path to the directory containing the sorted Zeek log files.

    Raises:
        FileNotFoundError: If the PCAP file or Zeek binary does not exist.
        RuntimeError: If the Zeek process exits with a non-zero return code.
    """
    pcap = Path(pcap_path)
    if not pcap.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    command = ["zeek", "-r", pcap.name]
    if sys.platform == "win32":
        command = ["wsl", "-e", "zeek", "-r", pcap.name]

    # Run Zeek against the PCAP
    try:
        result = subprocess.run(
            command,
            cwd=str(out_dir),
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise FileNotFoundError(
            "Zeek is not installed or not on PATH. "
            "Install Zeek (https://zeek.org/get-zeek/) or pre-process the PCAP "
            "with Zeek on a Linux/WSL machine and pass the resulting log directory instead."
        )
    if result.returncode != 0:
        raise RuntimeError(
            f"Zeek exited with code {result.returncode}: {result.stderr.strip()}"
        )

    # Sort every generated log file by the first (timestamp) column
    for log_file in out_dir.glob("*.log"):
        _sort_log_by_timestamp(log_file)

    return out_dir


def run_zeek_on_directory(pcap_dir: str, output_dir: str) -> Path:
    """Run Zeek on every PCAP file in a directory and merge the results.

    Each PCAP is processed sequentially. Log files of the same type are
    concatenated (data rows only — headers are written once) and then sorted
    by timestamp so the combined output looks like a single Zeek run.

    Args:
        pcap_dir: Directory containing ``.pcap`` / ``.pcapng`` files.
        output_dir: Directory where merged Zeek logs will be written.

    Returns:
        Path to the directory containing the merged, sorted log files.

    Raises:
        FileNotFoundError: If no PCAP files are found or Zeek is not installed.
        RuntimeError: If any Zeek invocation fails.
    """
    pcaps = sorted(
        p for p in Path(pcap_dir).iterdir()
        if p.suffix in (".pcap", ".pcapng")
    )
    if not pcaps:
        raise FileNotFoundError(f"No .pcap/.pcapng files found in: {pcap_dir}")

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[INGEST] Found {len(pcaps)} PCAP file(s) — running Zeek on each...")

    # Accumulate raw data lines per log type across all PCAPs
    # headers_per_type: log_name -> list of header lines (from first PCAP that produces it)
    headers_per_type: dict[str, list[str]] = {}
    data_per_type: dict[str, list[str]] = {}

    import shutil
    # Use a persistent scratch dir inside out_dir to avoid WSL file-handle
    # cleanup races that occur with TemporaryDirectory on Windows.
    scratch_base = out_dir / "_zeek_scratch"
    scratch_base.mkdir(parents=True, exist_ok=True)

    for i, pcap in enumerate(pcaps, 1):
        print(f"  [{i}/{len(pcaps)}] Processing {pcap.name} ...")
        pcap_scratch = scratch_base / f"pcap_{i:04d}"
        pcap_scratch.mkdir(exist_ok=True)

        pcap_full = str(pcap.resolve())
        if sys.platform == "win32":
            import os
            drive, tail = os.path.splitdrive(pcap_full)
            wsl_pcap = f"/mnt/{drive.replace(':', '').lower()}{tail.replace(os.sep, '/')}"
            scratch_full = str(pcap_scratch.resolve())
            drive2, tail2 = os.path.splitdrive(scratch_full)
            wsl_cwd = f"/mnt/{drive2.replace(':', '').lower()}{tail2.replace(os.sep, '/')}"
            command = ["wsl", "-e", "zeek", "-r", wsl_pcap]
            cwd_arg = wsl_cwd
        else:
            command = ["zeek", "-r", pcap_full]
            cwd_arg = str(pcap_scratch)

        if sys.platform == "win32":
            # Use the full Zeek binary path since non-interactive WSL bash
            # does not load .bashrc/.profile and /opt/zeek/bin is not on PATH.
            zeek_bin = "/opt/zeek/bin/zeek"
            full_command = ["wsl", "bash", "-c", f"cd '{cwd_arg}' && {zeek_bin} -r '{wsl_pcap}'"]
        else:
            full_command = command

        try:
            result = subprocess.run(
                full_command if sys.platform == "win32" else command,
                cwd=str(pcap_scratch),
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            shutil.rmtree(scratch_base, ignore_errors=True)
            raise FileNotFoundError(
                "Zeek is not installed or not on PATH. "
                "Install Zeek via WSL (https://zeek.org/get-zeek/) or pre-process PCAPs "
                "on a Linux/WSL machine and pass the log directory instead."
            )
        if result.returncode != 0:
            print(f"    Warning: Zeek exited {result.returncode} for {pcap.name}: "
                  f"{result.stderr.strip()[:200]}")
            shutil.rmtree(pcap_scratch, ignore_errors=True)
            continue

        for log_file in pcap_scratch.glob("*.log"):
            name = log_file.name
            hdrs: list[str] = []
            rows: list[str] = []
            with open(log_file, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("#"):
                        hdrs.append(line)
                    else:
                        stripped = line.rstrip("\n\r")
                        if stripped:
                            rows.append(stripped)

            if name not in headers_per_type:
                headers_per_type[name] = hdrs
                data_per_type[name] = []
            data_per_type[name].extend(rows)

        # Clean up scratch dir for this PCAP immediately to save disk space
        shutil.rmtree(pcap_scratch, ignore_errors=True)

    # Remove the scratch base
    shutil.rmtree(scratch_base, ignore_errors=True)

    if not data_per_type:
        raise RuntimeError("Zeek produced no log output for any PCAP in the directory.")

    print(f"[INGEST] Merging and sorting {len(data_per_type)} log type(s)...")

    for name, rows in data_per_type.items():
        rows.sort(key=lambda line: _ts_key(line))
        out_path = out_dir / name
        with open(out_path, "w", encoding="utf-8") as fh:
            for hline in headers_per_type.get(name, []):
                fh.write(hline)
            for row in rows:
                fh.write(row + "\n")

    print(f"[INGEST] Done. Merged logs written to: {out_dir}")
    return out_dir


def ingest_single_pcap(pcap_path: str, log_dir: str) -> dict[str, int]:
    """Run Zeek on a single PCAP and merge the results into an existing log directory.

    Args:
        pcap_path: Path to the PCAP file.
        log_dir: Path to the directory where Zeek logs are stored.

    Returns:
        A dictionary mapping log names (e.g. 'conn.log') to the number of new records added.
    """
    import shutil
    pcap = Path(pcap_path)
    out_dir = Path(log_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Use a scratch dir for the new Zeek run
    scratch_base = out_dir / "_zeek_scratch"
    scratch_base.mkdir(parents=True, exist_ok=True)
    pcap_scratch = scratch_base / "single_run"
    if pcap_scratch.exists():
        shutil.rmtree(pcap_scratch)
    pcap_scratch.mkdir()

    pcap_full = str(pcap.resolve())
    if sys.platform == "win32":
        import os
        drive, tail = os.path.splitdrive(pcap_full)
        wsl_pcap = f"/mnt/{drive.replace(':', '').lower()}{tail.replace(os.sep, '/')}"
        scratch_full = str(pcap_scratch.resolve())
        drive2, tail2 = os.path.splitdrive(scratch_full)
        wsl_cwd = f"/mnt/{drive2.replace(':', '').lower()}{tail2.replace(os.sep, '/')}"
        zeek_bin = "/opt/zeek/bin/zeek"
        command = ["wsl", "bash", "-c", f"cd '{wsl_cwd}' && {zeek_bin} -r '{wsl_pcap}'"]
    else:
        command = ["zeek", "-r", pcap_full]

    try:
        result = subprocess.run(
            command,
            cwd=str(pcap_scratch),
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        shutil.rmtree(scratch_base, ignore_errors=True)
        raise FileNotFoundError("Zeek not found. Please install Zeek/WSL.")

    if result.returncode != 0:
        err = result.stderr.strip()
        shutil.rmtree(scratch_base, ignore_errors=True)
        raise RuntimeError(f"Zeek failed: {err}")

    # Merge results
    stats: dict[str, int] = {}
    for log_file in pcap_scratch.glob("*.log"):
        name = log_file.name
        new_hdrs, new_rows = _load_log_parts(log_file)
        if not new_rows:
            continue

        target_path = out_dir / name
        if target_path.exists():
            old_hdrs, old_rows = _load_log_parts(target_path)
            combined_rows = old_rows + new_rows
            combined_rows.sort(key=_ts_key)
            with open(target_path, "w", encoding="utf-8") as fh:
                for h in old_hdrs: fh.write(h)
                for r in combined_rows: fh.write(r + "\n")
        else:
            new_rows.sort(key=_ts_key)
            with open(target_path, "w", encoding="utf-8") as fh:
                for h in new_hdrs: fh.write(h)
                for r in new_rows: fh.write(r + "\n")
        
        stats[name] = len(new_rows)

    shutil.rmtree(scratch_base, ignore_errors=True)
    return stats


def _load_log_parts(path: Path) -> tuple[list[str], list[str]]:
    """Helper to split a Zeek log into header lines and data rows."""
    hdrs = []
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                hdrs.append(line)
            else:
                s = line.rstrip("\n\r")
                if s: rows.append(s)
    return hdrs, rows


def _ts_key(line: str) -> float:
    """Extract epoch timestamp from the first TAB-delimited field."""
    try:
        return float(line.split("\t", 1)[0])
    except (ValueError, IndexError):
        return 0.0


def _sort_log_by_timestamp(log_path: Path) -> None:
    """Sort a single Zeek log file by its first column (timestamp) in place.

    Header lines (starting with ``#``) are preserved at the top of the file;
    data lines are sorted numerically on the first TAB-delimited field.
    """
    header_lines: list[str] = []
    data_lines: list[str] = []

    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#"):
                header_lines.append(line)
            else:
                stripped = line.rstrip("\n\r")
                if stripped:
                    data_lines.append(stripped)

    data_lines.sort(key=_ts_key)

    with open(log_path, "w", encoding="utf-8") as fh:
        for hline in header_lines:
            fh.write(hline)
        for dline in data_lines:
            fh.write(dline + "\n")


def find_zeek_logs(directory: str) -> list[Path]:
    """Find all ``*.log`` files in *directory*, returned sorted by name.

    Args:
        directory: Path to the directory to search.

    Returns:
        A sorted list of :class:`~pathlib.Path` objects for each log file found.

    Raises:
        FileNotFoundError: If the directory does not exist.
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        raise FileNotFoundError(f"Directory not found: {directory}")

    logs = list(dir_path.glob("*.log"))
    logs.sort(key=lambda p: p.name)
    return logs
