"""
Phase 0 - Triage Analyzer
Inventory logs, parse headers, categorize by size, build network map.
"""

from pathlib import Path
from collections import Counter

from ..models import (
    LogFile, LogCategory, NetworkHost, IOC, IOCType,
    TimelineEvent, PhaseResult, Finding, Evidence, Severity,
    epoch_to_utc,
)
from ..config import Config
from ..tools.log_reader import ZeekLogReader


class TriageAnalyzer:
    """Phase 0: Inventory logs, parse headers, categorize by size, build network map."""

    def __init__(self, log_dir: Path, config: Config):
        self.log_dir = log_dir
        self.config = config

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def run(self) -> tuple[list[LogFile], list[NetworkHost], str, str]:
        """Returns (log_inventory, network_hosts, detected_subnet, detected_domain)."""
        print("[Phase 0] Starting triage analysis...")

        # 1. Discover and categorize log files
        log_inventory = self._build_inventory()
        print(f"  [Phase 0] Found {len(log_inventory)} log files")

        # 2. Build network map from NTLM data (if available)
        network_hosts, detected_domain = self._build_network_map(log_inventory)
        print(f"  [Phase 0] Identified {len(network_hosts)} network hosts")

        # 3. Auto-detect internal subnet from conn.log
        detected_subnet = self._detect_subnet(log_inventory)
        if detected_subnet:
            print(f"  [Phase 0] Detected internal subnet: {detected_subnet}")
        else:
            print("  [Phase 0] Could not auto-detect internal subnet; using config defaults")

        # 4. Print inventory table
        self._print_inventory(log_inventory)

        return log_inventory, network_hosts, detected_subnet, detected_domain

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_inventory(self) -> list[LogFile]:
        """List every *.log in log_dir, read its header, categorize by size."""
        inventory: list[LogFile] = []

        log_files = sorted(self.log_dir.glob("*.log"))
        for lp in log_files:
            try:
                size = lp.stat().st_size
            except OSError:
                continue

            category = self._categorize(size)

            fields: list[str] = []
            types: list[str] = []
            try:
                reader = ZeekLogReader(lp)
                fields = reader.fields
                types = reader.types
            except Exception:
                # If we cannot parse the header we still record the file
                pass

            inventory.append(LogFile(
                name=lp.name,
                path=lp,
                size=size,
                category=category,
                fields=fields,
                types=types,
            ))

        return inventory

    def _categorize(self, size: int) -> LogCategory:
        if size < self.config.full_read_max:
            return LogCategory.FULL_READ
        elif size < self.config.sample_grep_max:
            return LogCategory.SAMPLE_GREP
        return LogCategory.GREP_ONLY

    def _build_network_map(
        self, inventory: list[LogFile]
    ) -> tuple[list[NetworkHost], str]:
        """Parse ntlm.log (if present) to extract host information."""
        hosts: list[NetworkHost] = []
        detected_domain = ""

        ntlm = self._get_log("ntlm.log", inventory)
        if ntlm is None:
            return hosts, detected_domain

        try:
            reader = ZeekLogReader(ntlm.path)
            if ntlm.category == LogCategory.FULL_READ:
                records = reader.read_full()
            else:
                records = reader.read_head(500)
        except Exception as exc:
            print(f"  [Phase 0] Warning: could not read ntlm.log: {exc}")
            return hosts, detected_domain

        seen_ips: dict[str, NetworkHost] = {}

        for rec in records:
            ip = rec.get("id.orig_h", "") or rec.get("source_ip", "")
            hostname = rec.get("hostname", "") or rec.get("server_nb_computer_name", "")
            success = rec.get("success", "")
            domain = rec.get("server_tree_name", "") or rec.get("domainname", "")

            if domain and not detected_domain:
                # Take the first non-empty domain we encounter
                detected_domain = domain.strip().strip("\\").split("\\")[0]

            if ip and ip not in seen_ips:
                role = self._infer_role(hostname, rec)
                seen_ips[ip] = NetworkHost(
                    ip=ip,
                    hostname=hostname,
                    role=role,
                    is_internal=True,
                    associated_accounts=[],
                )

            # Track accounts associated with this IP
            if ip and ip in seen_ips:
                acct = rec.get("username", "") or rec.get("user", "")
                if acct and acct not in seen_ips[ip].associated_accounts:
                    seen_ips[ip].associated_accounts.append(acct)

            # Also record destination hosts
            dest_ip = rec.get("id.resp_h", "") or rec.get("dest_ip", "")
            dest_host = rec.get("server_nb_computer_name", "") or hostname
            if dest_ip and dest_ip not in seen_ips:
                dest_role = self._infer_role(dest_host, rec)
                seen_ips[dest_ip] = NetworkHost(
                    ip=dest_ip,
                    hostname=dest_host,
                    role=dest_role,
                    is_internal=True,
                    associated_accounts=[],
                )

        hosts = list(seen_ips.values())
        return hosts, detected_domain

    @staticmethod
    def _infer_role(hostname: str, record: dict) -> str:
        """Heuristic to determine host role from hostname and NTLM fields."""
        hn = hostname.upper()
        if any(tag in hn for tag in ("DC", "AD", "DOMAIN")):
            return "domain_controller"
        if any(tag in hn for tag in ("SRV", "SERVER", "SQL", "EXCH", "MAIL")):
            return "server"
        # If the host authenticated with a machine account (trailing $) it is likely a server
        user = record.get("username", "")
        if user.endswith("$"):
            return "server"
        return "workstation"

    def _detect_subnet(self, inventory: list[LogFile]) -> str:
        """Read first 100 lines of conn.log to find the most common /24 prefix."""
        conn = self._get_log("conn.log", inventory) or self._get_log("conn.log", inventory)
        if conn is None:
            return ""

        try:
            reader = ZeekLogReader(conn.path)
            records = reader.read_head(100)
        except Exception:
            return ""

        prefix_counter: Counter[str] = Counter()
        for rec in records:
            for field in ("id.orig_h", "id.resp_h"):
                ip = rec.get(field, "")
                if ip and ":" not in ip:  # skip IPv6
                    parts = ip.split(".")
                    if len(parts) == 4:
                        prefix = ".".join(parts[:3]) + ".0/24"
                        prefix_counter[prefix] += 1

        if not prefix_counter:
            return ""

        most_common_prefix, _ = prefix_counter.most_common(1)[0]
        return most_common_prefix

    @staticmethod
    def _get_log(name: str, inventory: list[LogFile]) -> LogFile | None:
        for lf in inventory:
            if lf.name == name:
                return lf
        return None

    def _print_inventory(self, inventory: list[LogFile]) -> None:
        """Print a human-readable inventory table."""
        print("\n  Log File Inventory")
        print("  " + "-" * 72)
        print(f"  {'Name':<30} {'Size':>12} {'Category':<14} {'Fields':>6}")
        print("  " + "-" * 72)

        for lf in sorted(inventory, key=lambda x: x.size, reverse=True):
            size_str = self._format_size(lf.size)
            cat_str = lf.category.name
            field_count = len(lf.fields) if lf.fields else 0
            print(f"  {lf.name:<30} {size_str:>12} {cat_str:<14} {field_count:>6}")

        print("  " + "-" * 72)
        total = sum(lf.size for lf in inventory)
        print(f"  Total: {len(inventory)} files, {self._format_size(total)}\n")

    @staticmethod
    def _format_size(size: int) -> str:
        if size >= 1_073_741_824:
            return f"{size / 1_073_741_824:.1f} GB"
        if size >= 1_048_576:
            return f"{size / 1_048_576:.1f} MB"
        if size >= 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size} B"
