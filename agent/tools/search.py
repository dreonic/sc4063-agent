"""Higher-level forensic search operations over parsed Zeek log records."""

from __future__ import annotations

import ipaddress
from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .log_reader import ZeekLogReader


def is_external_ip(ip: str, internal_subnets: list[str]) -> bool:
    """Check whether *ip* is external (not belonging to any internal subnet).

    Private / reserved addresses that appear in *internal_subnets* are
    considered internal.  Unset or unparseable values (e.g. ``-``) are
    treated as **not** external.

    Args:
        ip: An IPv4 or IPv6 address string.
        internal_subnets: A list of CIDR strings representing internal
            networks (e.g. ``["10.0.0.0/8", "192.168.0.0/16"]``).

    Returns:
        ``True`` if the address is valid and does not fall within any of the
        supplied internal subnets, ``False`` otherwise.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False

    for subnet_str in internal_subnets:
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
            if addr in network:
                return False
        except (ValueError, TypeError):
            continue

    return True


def find_external_ips(
    records: list[dict],
    ip_field: str,
    internal_subnets: list[str],
) -> set[str]:
    """Extract all external IP addresses from *ip_field* across *records*.

    Args:
        records: Parsed Zeek log records (list of dicts).
        ip_field: The key whose values contain IP addresses.
        internal_subnets: CIDR strings for internal networks.

    Returns:
        A set of IP address strings that are classified as external.
    """
    external: set[str] = set()
    for rec in records:
        ip = rec.get(ip_field, "")
        if ip and is_external_ip(ip, internal_subnets):
            external.add(ip)
    return external


def find_connections_by_port(
    reader: "ZeekLogReader",
    port: int,
    direction: str = "dest",
) -> list[dict]:
    """Find connections to or from a specific port.

    Uses the reader's ``grep`` method so that the entire file does not have to
    be loaded into memory for large logs.

    Args:
        reader: A :class:`~.log_reader.ZeekLogReader` instance for a
            ``conn.log`` or similar log.
        port: The port number to search for.
        direction: ``"dest"`` to match the destination port field
            (``id.resp_p``), or ``"source"`` to match the originator port
            field (``id.orig_p``).

    Returns:
        A list of parsed records whose specified port field equals *port*.
    """
    port_str = str(port)
    # Grep for lines containing the port number, then filter precisely
    candidates = reader.grep(port_str)

    if direction == "dest":
        field = "id.resp_p"
    elif direction == "source":
        field = "id.orig_p"
    else:
        field = "id.resp_p"

    return [rec for rec in candidates if rec.get(field) == port_str]


def find_high_volume_sources(
    records: list[dict],
    source_field: str,
    threshold: int,
) -> list[tuple[str, int]]:
    """Find sources that appear more than *threshold* times.

    Args:
        records: Parsed Zeek log records.
        source_field: The key to aggregate on (e.g. ``"id.orig_h"``).
        threshold: Minimum number of occurrences to include a source.

    Returns:
        A list of ``(value, count)`` tuples sorted descending by count.
    """
    counter: Counter[str] = Counter()
    for rec in records:
        value = rec.get(source_field, "")
        if value and value != "-":
            counter[value] += 1

    return [
        (val, cnt)
        for val, cnt in counter.most_common()
        if cnt > threshold
    ]


def find_auth_failures(
    records: list[dict],
    success_field: str = "success",
) -> list[dict]:
    """Filter records where authentication failed.

    A failure is defined as the *success_field* being ``"F"`` (Zeek boolean
    false) or ``"-"`` (unset, i.e. no successful outcome recorded).

    Args:
        records: Parsed Zeek log records (e.g. from ``ssh.log``).
        success_field: The field indicating authentication success.

    Returns:
        Records where authentication did not succeed.
    """
    return [
        rec for rec in records
        if rec.get(success_field, "-") in ("F", "-")
    ]


def find_auth_successes(
    records: list[dict],
    success_field: str = "success",
) -> list[dict]:
    """Filter records where authentication succeeded.

    A success is defined as the *success_field* being ``"T"`` (Zeek boolean
    true).

    Args:
        records: Parsed Zeek log records.
        success_field: The field indicating authentication success.

    Returns:
        Records where authentication succeeded.
    """
    return [
        rec for rec in records
        if rec.get(success_field) == "T"
    ]


def group_by_field(records: list[dict], field: str) -> dict[str, list[dict]]:
    """Group records by the value of *field*.

    Args:
        records: Parsed Zeek log records.
        field: The key to group on.

    Returns:
        A dictionary mapping each distinct value to the list of records
        sharing that value.
    """
    groups: dict[str, list[dict]] = {}
    for rec in records:
        key = rec.get(field, "-")
        groups.setdefault(key, []).append(rec)
    return groups


def count_unique(records: list[dict], field: str) -> int:
    """Count the number of unique values for *field* across *records*.

    Args:
        records: Parsed Zeek log records.
        field: The key to count unique values for.

    Returns:
        The number of distinct values found.
    """
    return len({rec.get(field, "-") for rec in records})
