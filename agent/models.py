"""Data models for forensic analysis artifacts."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


# --- Enums ---

class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    ACCOUNT = "account"
    FILENAME = "filename"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LogCategory(Enum):
    FULL_READ = "full_read"       # < 10 MB
    SAMPLE_GREP = "sample_grep"   # 10–100 MB
    GREP_ONLY = "grep_only"       # > 100 MB


# --- Core Models ---

@dataclass
class LogFile:
    """Metadata for a single Zeek log file."""
    name: str
    path: Path
    size: int
    category: LogCategory
    fields: list[str] = field(default_factory=list)
    types: list[str] = field(default_factory=list)
    line_count: int = 0

    @property
    def size_human(self) -> str:
        if self.size >= 1_073_741_824:
            return f"{self.size / 1_073_741_824:.1f} GB"
        if self.size >= 1_048_576:
            return f"{self.size / 1_048_576:.1f} MB"
        if self.size >= 1024:
            return f"{self.size / 1024:.1f} KB"
        return f"{self.size} B"


@dataclass
class IOC:
    """Indicator of Compromise."""
    type: IOCType
    value: str
    context: str = ""
    first_seen: str = ""
    last_seen: str = ""
    source_phase: str = ""
    related_finding: str = ""


@dataclass
class TimelineEvent:
    """A single event in the attack timeline."""
    timestamp: float                   # Unix epoch
    timestamp_human: str = ""          # Human-readable UTC
    source_ip: str = ""
    dest_ip: str = ""
    phase: str = ""                    # e.g. "Initial Access", "Lateral Movement"
    description: str = ""
    evidence_ref: str = ""             # e.g. "rdp_sorted.log, line 42"
    mitre_id: str = ""


@dataclass
class MITREMapping:
    """MITRE ATT&CK technique mapping."""
    tactic: str                        # e.g. "Initial Access"
    technique: str                     # e.g. "External Remote Services"
    technique_id: str                  # e.g. "T1133"
    observed_evidence: str = ""


@dataclass
class Evidence:
    """A piece of evidence supporting a finding."""
    source_log: str
    description: str
    raw_data: str = ""                 # Snippet of the actual log lines
    search_query: str = ""             # The grep/search that found it


@dataclass
class Finding:
    """A forensic finding (e.g., 'Initial Access via RDP')."""
    id: str                            # e.g. "A", "B", "C"
    title: str
    finding_text: str
    severity: Severity = Severity.HIGH
    evidence: list[Evidence] = field(default_factory=list)
    mitre_mappings: list[MITREMapping] = field(default_factory=list)
    iocs_discovered: list[IOC] = field(default_factory=list)
    timeline_events: list[TimelineEvent] = field(default_factory=list)


@dataclass
class NetworkHost:
    """A host discovered in the network."""
    ip: str
    hostname: str = ""
    role: str = ""                     # e.g. "Domain Controller", "Workstation"
    is_internal: bool = True
    associated_accounts: list[str] = field(default_factory=list)


@dataclass
class PhaseResult:
    """Result from one analysis phase."""
    phase_name: str
    findings: list[Finding] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    timeline_events: list[TimelineEvent] = field(default_factory=list)
    raw_results: dict = field(default_factory=dict)
    summary: str = ""


@dataclass
class ForensicReport:
    """The complete forensic report — unified across all phases."""
    title: str = "Network Forensic Analysis Report"
    client: str = ""
    capture_window: str = ""
    data_source: str = ""
    network_hosts: list[NetworkHost] = field(default_factory=list)
    internal_subnet: str = ""
    domain: str = ""
    findings: list[Finding] = field(default_factory=list)
    all_iocs: list[IOC] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    mitre_mappings: list[MITREMapping] = field(default_factory=list)
    executive_summary: str = ""
    recommendations: list[str] = field(default_factory=list)
    log_inventory: list[LogFile] = field(default_factory=list)
    kill_chain_phases: list[str] = field(default_factory=list)
    cost_metrics: dict = field(default_factory=dict)
    investigation_notes: list[str] = field(default_factory=list)


def epoch_to_utc(ts: float) -> str:
    """Convert Unix epoch to human-readable UTC string."""
    try:
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError, OverflowError):
        return str(ts)
