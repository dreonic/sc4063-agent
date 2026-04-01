"""Strict evidence guardrails — validate findings and IOCs before they enter state."""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path


MITRE_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def validate_evidence_log(
    evidence_log: str,
    log_dir: str,
    log_inventory: list[dict],
) -> str | None:
    """Check that the cited evidence log file exists.

    Returns an error message string on failure, or ``None`` on success.
    """
    known_names = {entry.get("name", "") for entry in log_inventory}
    if evidence_log in known_names:
        return None

    # Also accept if the file physically exists
    log_path = Path(log_dir) / evidence_log
    if log_path.exists():
        return None

    return (
        f"Evidence log '{evidence_log}' not found in log inventory. "
        f"Available logs: {', '.join(sorted(known_names))}. "
        f"Please cite an existing log file."
    )


def validate_evidence_line(
    evidence_log: str,
    evidence_line: int | None,
    evidence_description: str,
    log_dir: str,
) -> str | None:
    """If a line number is cited, verify the line exists and loosely matches.

    Returns an error message on failure, or ``None`` on success.
    """
    if evidence_line is None:
        return None

    log_path = Path(log_dir) / evidence_log
    if not log_path.exists():
        return f"Cannot verify line {evidence_line}: file '{evidence_log}' not found."

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            for idx, raw_line in enumerate(fh, start=1):
                if idx == evidence_line:
                    actual = raw_line.strip()
                    if not actual:
                        return (
                            f"Line {evidence_line} of '{evidence_log}' is empty. "
                            f"Please verify the correct line number."
                        )
                    return None  # line exists — accept

        return (
            f"Line {evidence_line} does not exist in '{evidence_log}' "
            f"(file has fewer lines). Please verify the line number."
        )
    except OSError as exc:
        return f"Cannot read '{evidence_log}': {exc}"


def validate_severity(severity: str) -> str | None:
    """Validate severity is one of the accepted values."""
    valid = {"critical", "high", "medium", "low", "info"}
    if severity.lower() in valid:
        return None
    return f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(valid))}."


def validate_mitre_id(mitre_id: str) -> str | None:
    """Validate a MITRE ATT&CK technique ID format."""
    if not mitre_id:
        return None  # optional
    if MITRE_ID_PATTERN.match(mitre_id):
        return None
    return (
        f"Invalid MITRE ID '{mitre_id}'. "
        f"Expected format: T followed by 4 digits, optionally .3 digits (e.g., T1133, T1110.003)."
    )


def validate_ioc_ip(value: str) -> str | None:
    """Validate an IP IOC value."""
    try:
        ipaddress.ip_address(value)
        return None
    except (ValueError, TypeError):
        return f"Invalid IP address '{value}'. Must be a valid IPv4 or IPv6 address."


def validate_ioc_domain(value: str) -> str | None:
    """Validate a domain IOC value."""
    if DOMAIN_PATTERN.match(value):
        return None
    return f"Invalid domain '{value}'. Must be a syntactically valid domain name."


def validate_ioc(ioc_type: str, value: str) -> str | None:
    """Validate an IOC based on its type."""
    if not value or not value.strip():
        return "IOC value cannot be empty."

    ioc_type_lower = ioc_type.lower()
    if ioc_type_lower == "ip":
        return validate_ioc_ip(value)
    elif ioc_type_lower == "domain":
        return validate_ioc_domain(value)
    elif ioc_type_lower == "account":
        if not value.strip():
            return "Account IOC value cannot be empty."
        return None
    # hash, filename — just check non-empty
    return None
