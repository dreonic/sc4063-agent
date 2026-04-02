"""Markdown report generator for forensic analysis results."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ..models import (
    Finding,
    ForensicReport,
    IOC,
    IOCType,
    LogFile,
    MITREMapping,
    NetworkHost,
    Severity,
    TimelineEvent,
)


class ReportGenerator:
    """Generates a structured Markdown forensic report from a
    :class:`ForensicReport` object."""

    def __init__(self, report: ForensicReport):
        self.report = report

        # --- MASTER BULLETPROOFING PATCH ---
        # If the data model is missing any of these list attributes, create them dynamically as empty lists
        list_attributes = ['findings', 'all_iocs', 'timeline', 'log_inventory', 'network_hosts', 'mitre_mappings', 'recommendations']
        for attr in list_attributes:
            if not hasattr(self.report, attr):
                setattr(self.report, attr, [])
                
        # If it's missing string attributes, create them as None
        string_attributes = ['title', 'client', 'capture_window', 'data_source', 'domain', 'internal_subnet', 'executive_summary']
        for attr in string_attributes:
            if not hasattr(self.report, attr):
                setattr(self.report, attr, None)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self) -> str:
        """Produce the full Markdown report string."""
        sections: list[str] = [
            self._render_header(),
            self._render_executive_summary(),
            self._render_log_inventory(self.report.log_inventory),
            self._render_network_map(self.report.network_hosts),
            self._render_mitre_table(self.report.mitre_mappings),
            self._render_findings(),
            self._render_ioc_table(self.report.all_iocs),
            self._render_timeline(self.report.timeline),
            self._render_recommendations(),
            self._render_cost_analysis(),
            self._render_investigation_notes(),
            self._render_footer(),
        ]
        return "\n\n".join(s for s in sections if s)

    def save(self, output_path: Path) -> None:
        """Write the report to *output_path*."""
        content = self.generate()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")

    # ------------------------------------------------------------------
    # Section renderers
    # ------------------------------------------------------------------

    def _render_header(self) -> str:
        r = self.report

        # Derive capture window from timeline if not explicitly set
        capture_window = getattr(r, 'capture_window', '') or ''
        if not capture_window and getattr(r, 'timeline', []):
            sorted_tl = sorted(r.timeline, key=lambda e: e.timestamp)
            t0 = sorted_tl[0].timestamp_human.split()[0] if sorted_tl else ''
            t1 = sorted_tl[-1].timestamp_human.split()[0] if sorted_tl else ''
            capture_window = f"{t0} – {t1}" if t0 and t1 else "Nov 2025 – Jan 2026"
        capture_window = capture_window or "Nov 2025 – Jan 2026"

        lines = [
            "# Apex Global Logistics - Incident Response Report",
            "",
            "| Field | Value |",
            "| --- | --- |",
            f"| **Client** | {getattr(r, 'client', '') or 'Apex Global Logistics'} |",
            f"| **Capture Window** | {capture_window} |",
            f"| **Data Source** | {getattr(r, 'data_source', '') or 'Zeek Logs (from PCAP)'} |",
            f"| **Internal Subnet** | {getattr(r, 'internal_subnet', '10.128.239.0/24')} |",
            f"| **Domain** | {getattr(r, 'domain', 'domain-ees3Ai.local')} |",
            f"| **Report Generated** | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} |",
            f"| **Findings** | {len(getattr(r, 'findings', []))} |",
            f"| **IOCs** | {len(getattr(r, 'all_iocs', []))} |",
            f"| **Timeline Events** | {len(getattr(r, 'timeline', []))} |",
        ]
        return "\n".join(lines)

    def _render_executive_summary(self) -> str:
        lines = ["## Executive Summary", ""]
        if self.report.executive_summary:
            lines.append(self.report.executive_summary)
        else:
            lines.append(self._auto_executive_summary())
        return "\n".join(lines)

    def _render_log_inventory(self, logs: list[LogFile]) -> str:
        if not logs:
            return ""
        lines = [
            "## Log Inventory",
            "",
            "| # | Log File | Size | Category | Lines | Fields |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for idx, log in enumerate(logs, 1):
            fields_preview = ", ".join(log.fields[:5])
            if len(log.fields) > 5:
                fields_preview += f" (+{len(log.fields) - 5} more)"
            lines.append(
                f"| {idx} | `{log.name}` | {log.size_human} "
                f"| {log.category.value} | {log.line_count:,} "
                f"| {fields_preview} |"
            )
        return "\n".join(lines)

    def _render_network_map(self, hosts: list[NetworkHost]) -> str:
        lines = [
            "## Network Environment",
            "",
        ]
        if self.report.internal_subnet:
            lines.append(f"**Internal Subnet:** `{self.report.internal_subnet}`  ")
        if self.report.domain:
            lines.append(f"**Domain:** `{self.report.domain}`  ")
        lines.append("")

        if hosts:
            lines.extend([
                "### Discovered Hosts",
                "",
                "| IP Address | Hostname | Role | Internal | Accounts |",
                "| --- | --- | --- | --- | --- |",
            ])
            for h in hosts:
                accounts = ", ".join(h.associated_accounts[:5]) or "—"
                if len(h.associated_accounts) > 5:
                    accounts += f" (+{len(h.associated_accounts) - 5})"
                lines.append(
                    f"| `{h.ip}` | {h.hostname or '—'} | {h.role or '—'} "
                    f"| {'Yes' if h.is_internal else 'No'} | {accounts} |"
                )
        else:
            lines.append("*No hosts discovered.*")

        return "\n".join(lines)

    def _render_mitre_table(self, mappings: list[MITREMapping]) -> str:
        if not mappings:
            return ""
        lines = [
            "## MITRE ATT&CK Mapping",
            "",
            "| Tactic | Technique | ID | Observed Evidence |",
            "| --- | --- | --- | --- |",
        ]
        seen: set[str] = set()
        for m in mappings:
            key = f"{m.tactic}|{m.technique_id}"
            if key in seen:
                continue
            seen.add(key)
            evidence_short = (
                (m.observed_evidence[:100] + "...")
                if len(m.observed_evidence) > 100
                else m.observed_evidence
            )
            lines.append(
                f"| {m.tactic} | {m.technique} | `{m.technique_id}` "
                f"| {evidence_short} |"
            )
        return "\n".join(lines)

    def _render_findings(self) -> str:
        if not self.report.findings:
            return "## Detailed Findings\n\n*No findings.*"
        lines = ["## Detailed Findings", ""]
        for finding in self.report.findings:
            lines.append(self._render_finding(finding))
            lines.append("")
        return "\n".join(lines)

    def _render_finding(self, finding: Finding) -> str:
        severity_badge = {
            Severity.CRITICAL: "CRITICAL",
            Severity.HIGH: "HIGH",
            Severity.MEDIUM: "MEDIUM",
            Severity.LOW: "LOW",
            Severity.INFO: "INFO",
        }.get(finding.severity, "UNKNOWN")

        lines = [
            f"### Finding {finding.id}: {finding.title}",
            "",
            f"**Severity:** {severity_badge}  ",
            "",
            finding.finding_text,
            "",
        ]

        # Evidence blocks
        if finding.evidence:
            lines.append("#### Evidence")
            lines.append("")
            for ev in finding.evidence:
                lines.append(f"**Source:** `{ev.source_log}`  ")
                lines.append(f"{ev.description}  ")
                if ev.search_query:
                    lines.append(f"*Query:* `{ev.search_query}`  ")
                if ev.raw_data:
                    lines.append("")
                    lines.append("```")
                    # Safely handle lists containing dictionaries/objects by converting each to a string
                    if isinstance(ev.raw_data, list):
                        raw_text = "\n".join(str(item) for item in ev.raw_data)
                    else:
                        raw_text = str(ev.raw_data)
                        
                    lines.append(raw_text.rstrip())
                    lines.append("```")
                lines.append("")

        # MITRE mappings for this finding
        if finding.mitre_mappings:
            lines.append("#### MITRE ATT&CK")
            lines.append("")
            for m in finding.mitre_mappings:
                lines.append(f"- **{m.tactic}** / {m.technique} (`{m.technique_id}`)")
            lines.append("")

        # IOCs from this finding
        if finding.iocs_discovered:
            lines.append("#### IOCs Discovered")
            lines.append("")
            for ioc in finding.iocs_discovered:
                lines.append(f"- `{ioc.type.value}`: **{ioc.value}** — {ioc.context}")
            lines.append("")

        return "\n".join(lines)

    def _render_ioc_table(self, iocs: list[IOC]) -> str:
        if not iocs:
            return "## Indicators of Compromise (IOCs)\n\n*No IOCs identified.*"

        # Group IOCs by type
        grouped: dict[IOCType, list[IOC]] = {}
        for ioc in iocs:
            grouped.setdefault(ioc.type, []).append(ioc)

        type_labels = {
            IOCType.IP: "IP Addresses",
            IOCType.DOMAIN: "Domains",
            IOCType.ACCOUNT: "Accounts",
            IOCType.FILENAME: "Files",
            IOCType.HASH: "Hashes",
        }

        lines = ["## Indicators of Compromise (IOCs)", ""]

        for ioc_type in (IOCType.IP, IOCType.DOMAIN, IOCType.ACCOUNT, IOCType.FILENAME, IOCType.HASH):
            items = grouped.get(ioc_type, [])
            if not items:
                continue
            label = type_labels.get(ioc_type, ioc_type.value)
            lines.append(f"### {label}")
            lines.append("")
            lines.append("| Value | Context | First Seen | Last Seen | Phase |")
            lines.append("| --- | --- | --- | --- | --- |")
            # Deduplicate by value
            seen_values: set[str] = set()
            for ioc in items:
                if ioc.value in seen_values:
                    continue
                seen_values.add(ioc.value)
                lines.append(
                    f"| `{ioc.value}` | {ioc.context} "
                    f"| {ioc.first_seen or '—'} | {ioc.last_seen or '—'} "
                    f"| {ioc.source_phase or '—'} |"
                )
            lines.append("")

        return "\n".join(lines)

    def _render_timeline(self, events: list[TimelineEvent]) -> str:
        if not events:
            return "## Attack Timeline\n\n*No timeline events.*"

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        total = len(sorted_events)

        _TIMELINE_CAP = 200
        if total > _TIMELINE_CAP:
            half = _TIMELINE_CAP // 2
            display_events = sorted_events[:half] + sorted_events[-half:]
            omitted = total - _TIMELINE_CAP
            cap_note = (
                f"\n> *Showing first {half} and last {half} of {total:,} total events "
                f"({omitted:,} middle events omitted for brevity.)*\n"
            )
        else:
            display_events = sorted_events
            cap_note = ""

        lines = [
            "## Attack Timeline",
            "",
            "| # | Timestamp (UTC) | Source | Destination | Phase | Description | MITRE |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for idx, evt in enumerate(display_events, 1):
            desc_short = (
                (evt.description[:80] + "...")
                if len(evt.description) > 80
                else evt.description
            )
            lines.append(
                f"| {idx} | {evt.timestamp_human} "
                f"| `{evt.source_ip or '—'}` | `{evt.dest_ip or '—'}` "
                f"| {evt.phase} | {desc_short} "
                f"| `{evt.mitre_id or '—'}` |"
            )
        if cap_note:
            lines.append(cap_note)
        return "\n".join(lines)

    def _render_recommendations(self) -> str:
        lines = ["## Recommendations", ""]
        if self.report.recommendations:
            for idx, rec in enumerate(self.report.recommendations, 1):
                lines.append(f"{idx}. {rec}")
        else:
            lines.append("*No recommendations generated.*")
        return "\n".join(lines)

    def _render_footer(self) -> str:
        return (
            "---\n\n"
            "*Report generated by Agentic Network Forensic Agent.  "
            f"Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}.*"
        )

    # ------------------------------------------------------------------
    # Cost analysis section
    # ------------------------------------------------------------------

    def _render_cost_analysis(self) -> str:
        metrics = getattr(self.report, "cost_metrics", {})
        if not metrics:
            return ""

        lines = [
            "## Cost & Efficiency Analysis",
            "",
            "| Metric | Value |",
            "| --- | --- |",
            f"| Total LLM calls | {metrics.get('total_llm_calls', 0)} |",
            f"| Total tool invocations | {metrics.get('total_tool_invocations', 0)} |",
            f"| Input tokens | {metrics.get('total_input_tokens', 0):,} |",
            f"| Output tokens | {metrics.get('total_output_tokens', 0):,} |",
            f"| Wall-clock time | {metrics.get('wall_clock_formatted', 'N/A')} |",
            "",
            "### Cost Comparison",
            "",
            "| Execution Mode | Estimated Cost |",
            "| --- | --- |",
            f"| Paid API | ${metrics.get('api_cost', 0):.4f} |",
            f"| Local GPU ({metrics.get('gpu_description', 'H200')}) | ${metrics.get('gpu_cost', 0):.4f} |",
        ]

        api_cost = metrics.get("api_cost", 0)
        gpu_cost = metrics.get("gpu_cost", 0)
        if api_cost > 0 and gpu_cost > 0:
            if gpu_cost < api_cost:
                savings = (1 - gpu_cost / api_cost) * 100
                lines.append(f"| Savings with local execution | {savings:.0f}% |")
            else:
                savings = (1 - api_cost / gpu_cost) * 100
                lines.append(f"| Savings with API | {savings:.0f}% |")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Investigation notes (reasoning audit trail)
    # ------------------------------------------------------------------

    def _render_investigation_notes(self) -> str:
        notes = getattr(self.report, "investigation_notes", [])
        if not notes:
            return ""

        lines = [
            "## Appendix: Agent Reasoning Trace",
            "",
            "The following is the agent's autonomous reasoning trail during investigation.",
            "",
        ]
        for idx, note in enumerate(notes, 1):
            lines.append(f"{idx}. {note}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Fallback executive summary (no LLM)
    # ------------------------------------------------------------------

    def _auto_executive_summary(self) -> str:
        """Build a deterministic executive summary when no LLM is
        available.  Summarises finding count, IOC count, timeline span,
        severity breakdown, and key hosts involved."""
        r = self.report

        # Severity counts
        sev_counts: dict[str, int] = {}
        for f in r.findings:
            label = f.severity.value.upper()
            sev_counts[label] = sev_counts.get(label, 0) + 1
        severity_text = ", ".join(
            f"{count} {label}" for label, count in sev_counts.items()
        )

        # Timeline span
        if r.timeline:
            sorted_tl = sorted(r.timeline, key=lambda e: e.timestamp)
            first_ts = sorted_tl[0].timestamp_human
            last_ts = sorted_tl[-1].timestamp_human
            span_text = f"from **{first_ts}** to **{last_ts}**"
        else:
            span_text = "N/A"

        # Key internal hosts
        internal_hosts = [h for h in r.network_hosts if h.is_internal]
        host_list = ", ".join(
            f"`{h.ip}`" + (f" ({h.role})" if h.role else "")
            for h in internal_hosts[:5]
        )
        if len(internal_hosts) > 5:
            host_list += f" and {len(internal_hosts) - 5} more"

        # IOC breakdown
        ioc_type_counts: dict[str, int] = {}
        for ioc in r.all_iocs:
            label = ioc.type.value
            ioc_type_counts[label] = ioc_type_counts.get(label, 0) + 1
        ioc_text = ", ".join(
            f"{count} {label}(s)" for label, count in ioc_type_counts.items()
        )

        paragraphs = [
            f"This forensic analysis identified **{len(r.findings)} finding(s)** "
            f"({severity_text or 'none classified'}) and "
            f"**{len(r.all_iocs)} indicator(s) of compromise** ({ioc_text or 'none'}).",
            "",
            f"The observed activity spans {span_text}, comprising "
            f"**{len(r.timeline)} timeline event(s)**.",
            "",
        ]

        if host_list:
            paragraphs.append(
                f"Key internal hosts involved: {host_list}."
            )
            paragraphs.append("")

        if r.domain:
            paragraphs.append(
                f"The target environment domain is `{r.domain}` with "
                f"internal subnet `{r.internal_subnet or 'unknown'}`."
            )
            paragraphs.append("")

        # Top findings summary
        if r.findings:
            paragraphs.append("**Key findings:**")
            paragraphs.append("")
            for f in r.findings[:5]:
                paragraphs.append(
                    f"- **[{f.severity.value.upper()}] {f.title}:** "
                    f"{f.finding_text[:150]}"
                    + ("..." if len(f.finding_text) > 150 else "")
                )
            paragraphs.append("")

        paragraphs.append(
            "Refer to the detailed findings and recommendations sections "
            "below for full analysis and remediation guidance."
        )

        return "\n".join(paragraphs)
