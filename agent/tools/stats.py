"""Aggregation, counting, and timeline utilities for parsed Zeek log records."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone


def count_by_field(records: list[dict], field: str) -> Counter:
    """Count occurrences of each value in *field*.

    Args:
        records: Parsed Zeek log records.
        field: The key to tally.

    Returns:
        A :class:`~collections.Counter` mapping each value to its count.
    """
    counter: Counter = Counter()
    for rec in records:
        value = rec.get(field)
        if value is not None:
            counter[value] += 1
    return counter


def top_n(records: list[dict], field: str, n: int = 10) -> list[tuple[str, int]]:
    """Return the top *n* most common values for *field*.

    Args:
        records: Parsed Zeek log records.
        field: The key to rank.
        n: Number of results to return (default 10).

    Returns:
        A list of ``(value, count)`` tuples in descending order of frequency.
    """
    return count_by_field(records, field).most_common(n)


def time_range(
    records: list[dict],
    ts_field: str = "ts",
) -> tuple[float, float]:
    """Return the earliest and latest timestamp from *records*.

    Args:
        records: Parsed Zeek log records.
        ts_field: The key containing epoch timestamps (default ``"ts"``).

    Returns:
        A ``(earliest, latest)`` tuple of floats.

    Raises:
        ValueError: If no valid timestamps are found in the records.
    """
    timestamps: list[float] = []
    for rec in records:
        raw = rec.get(ts_field, "")
        try:
            timestamps.append(float(raw))
        except (ValueError, TypeError):
            continue

    if not timestamps:
        raise ValueError(f"No valid timestamps found in field '{ts_field}'")

    return min(timestamps), max(timestamps)


def unique_values(records: list[dict], field: str) -> set[str]:
    """Return the set of unique values for *field*.

    Args:
        records: Parsed Zeek log records.
        field: The key to collect unique values from.

    Returns:
        A set of distinct string values.
    """
    return {rec[field] for rec in records if field in rec}


def cluster_by_time(
    records: list[dict],
    ts_field: str = "ts",
    gap_seconds: int = 3600,
) -> list[list[dict]]:
    """Cluster records into groups separated by time gaps exceeding *gap_seconds*.

    Records are first sorted by timestamp, then a new cluster is started
    whenever the gap between consecutive timestamps exceeds the threshold.

    Args:
        records: Parsed Zeek log records.
        ts_field: The key containing epoch timestamps (default ``"ts"``).
        gap_seconds: Minimum gap in seconds to start a new cluster
            (default 3600, i.e. one hour).

    Returns:
        A list of clusters, where each cluster is itself a list of record
        dicts in chronological order.
    """
    if not records:
        return []

    # Build (timestamp, record) pairs, skipping unparseable timestamps
    timed: list[tuple[float, dict]] = []
    for rec in records:
        raw = rec.get(ts_field, "")
        try:
            ts_val = float(raw)
        except (ValueError, TypeError):
            continue
        timed.append((ts_val, rec))

    if not timed:
        return []

    timed.sort(key=lambda pair: pair[0])

    clusters: list[list[dict]] = []
    current_cluster: list[dict] = [timed[0][1]]
    prev_ts = timed[0][0]

    for ts_val, rec in timed[1:]:
        if ts_val - prev_ts > gap_seconds:
            clusters.append(current_cluster)
            current_cluster = []
        current_cluster.append(rec)
        prev_ts = ts_val

    if current_cluster:
        clusters.append(current_cluster)

    return clusters


def epoch_to_human(ts: float) -> str:
    """Convert an epoch timestamp to a human-readable UTC string.

    Args:
        ts: Seconds since the Unix epoch (may include fractional seconds).

    Returns:
        A string in the format ``"YYYY-MM-DD HH:MM:SS UTC"``.

    Raises:
        ValueError: If *ts* cannot be converted to a valid datetime.
    """
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    except (OSError, OverflowError, ValueError) as exc:
        raise ValueError(f"Cannot convert timestamp {ts!r} to datetime") from exc
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def summarize_records(records: list[dict], key_fields: list[str]) -> str:
    """Create a text summary showing the distribution of *key_fields*.

    For each requested field the summary includes the number of unique values
    and the top-5 most common values with their counts.

    Args:
        records: Parsed Zeek log records.
        key_fields: The fields to include in the summary.

    Returns:
        A multi-line human-readable summary string.
    """
    if not records:
        return "No records to summarize."

    lines: list[str] = [f"Record count: {len(records)}"]

    # If timestamps are present, show the time window
    if "ts" in key_fields or any("ts" in f for f in key_fields):
        pass  # handled per-field below

    for field in key_fields:
        counter = count_by_field(records, field)
        n_unique = len(counter)
        top5 = counter.most_common(5)

        lines.append("")
        lines.append(f"--- {field} ({n_unique} unique) ---")
        for value, count in top5:
            lines.append(f"  {value}: {count}")
        if n_unique > 5:
            lines.append(f"  ... and {n_unique - 5} more")

    return "\n".join(lines)
