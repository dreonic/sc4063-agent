"""Smart Zeek TSV log parser with field-aware reading and subprocess-based grep."""

from __future__ import annotations

import subprocess
from pathlib import Path


class ZeekLogReader:
    """Reads and parses Zeek TSV log files with field-aware parsing.

    On initialisation the Zeek header block is parsed so that every subsequent
    read or grep operation can return records as dictionaries keyed by the
    original field names.

    Attributes:
        path: The :class:`~pathlib.Path` to the Zeek log file.
        fields: Column names extracted from the ``#fields`` header line.
        types: Column types extracted from the ``#types`` header line.
        separator: The field separator (always ``\\t`` for standard Zeek logs).
        unset_field: The string representing an unset field (default ``-``).
        empty_field: The string representing an empty field (default ``(empty)``).
    """

    def __init__(self, log_path: Path) -> None:
        """Open a Zeek log and parse its header lines.

        Args:
            log_path: Path to the Zeek log file.

        Raises:
            FileNotFoundError: If the log file does not exist.
            ValueError: If required header lines (``#fields``, ``#types``) are missing.
        """
        self.path = Path(log_path)
        if not self.path.exists():
            raise FileNotFoundError(f"Log file not found: {log_path}")

        self.separator: str = "\t"
        self.unset_field: str = "-"
        self.empty_field: str = "(empty)"
        self.fields: list[str] = []
        self.types: list[str] = []

        self._parse_header()

    # ------------------------------------------------------------------
    # Header helpers
    # ------------------------------------------------------------------

    def _parse_header(self) -> None:
        """Read the leading ``#``-prefixed header block from the log file."""
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.rstrip("\n\r")
                if not line.startswith("#"):
                    break

                if line.startswith("#separator"):
                    # Value is a literal like \x09
                    sep_value = line.split(" ", 1)[1] if " " in line else "\t"
                    self.separator = sep_value.encode().decode("unicode_escape")
                elif line.startswith("#set_separator"):
                    pass  # not needed for basic parsing
                elif line.startswith("#empty_field"):
                    self.empty_field = line.split(self.separator, 1)[-1]
                elif line.startswith("#unset_field"):
                    self.unset_field = line.split(self.separator, 1)[-1]
                elif line.startswith("#fields"):
                    self.fields = line.split(self.separator)[1:]
                elif line.startswith("#types"):
                    self.types = line.split(self.separator)[1:]

        if not self.fields:
            raise ValueError(f"No #fields header found in {self.path}")
        if not self.types:
            raise ValueError(f"No #types header found in {self.path}")

    def read_header(self) -> tuple[list[str], list[str]]:
        """Return the parsed ``(fields, types)`` from the Zeek header.

        Returns:
            A 2-tuple of lists: field names and their corresponding Zeek types.
        """
        return list(self.fields), list(self.types)

    # ------------------------------------------------------------------
    # Line parsing
    # ------------------------------------------------------------------

    def _parse_line(self, line: str) -> dict | None:
        """Parse a single TAB-delimited data line into a field-keyed dict.

        Comment lines (starting with ``#``) and blank lines are silently
        skipped (returns ``None``).

        Args:
            line: A raw line from the Zeek log.

        Returns:
            A dict mapping field names to string values, or ``None`` if the
            line is a comment or otherwise non-data.
        """
        stripped = line.rstrip("\n\r")
        if not stripped or stripped.startswith("#"):
            return None

        parts = stripped.split(self.separator)
        record: dict[str, str] = {}
        for i, field_name in enumerate(self.fields):
            if i < len(parts):
                record[field_name] = parts[i]
            else:
                record[field_name] = self.unset_field
        return record

    # ------------------------------------------------------------------
    # Full / partial reads
    # ------------------------------------------------------------------

    def read_full(self) -> list[dict]:
        """Read the entire log file into a list of dicts keyed by field names.

        Comment lines (starting with ``#``) are skipped.

        Returns:
            A list of dictionaries, one per data line.
        """
        records: list[dict] = []
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                rec = self._parse_line(raw_line)
                if rec is not None:
                    records.append(rec)
        return records

    def read_head(self, n: int = 50) -> list[dict]:
        """Read the first *n* data lines from the log.

        Args:
            n: Maximum number of data lines to return (default 50).

        Returns:
            A list of up to *n* parsed records.
        """
        records: list[dict] = []
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                if len(records) >= n:
                    break
                rec = self._parse_line(raw_line)
                if rec is not None:
                    records.append(rec)
        return records

    # ------------------------------------------------------------------
    # Grep-based operations (subprocess for large files)
    # ------------------------------------------------------------------

    def grep(self, pattern: str, max_results: int = 10000) -> list[dict]:
        """Search for *pattern* using subprocess ``grep`` and return parsed results.

        The command pipeline is equivalent to::

            grep <pattern> <file> | head -<max_results>

        Args:
            pattern: The regular expression or fixed string to search for.
            max_results: Cap the number of returned lines (default 10 000).

        Returns:
            A list of parsed record dicts for each matching line.
        """
        try:
            grep_proc = subprocess.run(
                ["grep", pattern, str(self.path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            # grep not on PATH -- fall back to pure-Python search
            return self._grep_fallback(pattern, max_results, invert=False)

        lines = grep_proc.stdout.splitlines()
        records: list[dict] = []
        for line in lines[:max_results]:
            rec = self._parse_line(line)
            if rec is not None:
                records.append(rec)
        return records

    def grep_count(self, pattern: str) -> int:
        """Count lines matching *pattern*.

        Equivalent to ``grep -c <pattern> <file>``.

        Args:
            pattern: The pattern to count matches for.

        Returns:
            The number of matching lines.
        """
        try:
            result = subprocess.run(
                ["grep", "-c", pattern, str(self.path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            return self._grep_count_fallback(pattern)

        try:
            return int(result.stdout.strip())
        except ValueError:
            return 0

    def grep_exclude(self, pattern: str, max_results: int = 10000) -> list[dict]:
        """Return lines *not* matching *pattern* (inverted grep).

        Equivalent to ``grep -v <pattern> <file> | head -<max_results>``.

        Args:
            pattern: The pattern whose matches should be excluded.
            max_results: Cap the number of returned lines (default 10 000).

        Returns:
            A list of parsed record dicts for each non-matching data line.
        """
        try:
            grep_proc = subprocess.run(
                ["grep", "-v", pattern, str(self.path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            return self._grep_fallback(pattern, max_results, invert=True)

        lines = grep_proc.stdout.splitlines()
        records: list[dict] = []
        for line in lines[:max_results]:
            rec = self._parse_line(line)
            if rec is not None:
                records.append(rec)
        return records

    def count_data_lines(self) -> int:
        """Count non-comment lines in the log file.

        Equivalent to ``grep -cv '^#' <file>``.

        Returns:
            The number of data (non-comment) lines.
        """
        try:
            result = subprocess.run(
                ["grep", "-cv", "^#", str(self.path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            return self._count_data_lines_fallback()

        try:
            return int(result.stdout.strip())
        except ValueError:
            return 0

    # ------------------------------------------------------------------
    # Pure-Python fallbacks (when grep is not available)
    # ------------------------------------------------------------------

    def _grep_fallback(
        self, pattern: str, max_results: int, *, invert: bool
    ) -> list[dict]:
        """Pure-Python fallback for grep / grep -v."""
        import re

        compiled = re.compile(pattern)
        records: list[dict] = []
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                if raw_line.startswith("#"):
                    continue
                match = compiled.search(raw_line)
                keep = (match is None) if invert else (match is not None)
                if keep:
                    rec = self._parse_line(raw_line)
                    if rec is not None:
                        records.append(rec)
                        if len(records) >= max_results:
                            break
        return records

    def _grep_count_fallback(self, pattern: str) -> int:
        """Pure-Python fallback for grep -c."""
        import re

        compiled = re.compile(pattern)
        count = 0
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                if raw_line.startswith("#"):
                    continue
                if compiled.search(raw_line):
                    count += 1
        return count

    def _count_data_lines_fallback(self) -> int:
        """Pure-Python fallback for counting non-comment lines."""
        count = 0
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                if not raw_line.startswith("#"):
                    count += 1
        return count
