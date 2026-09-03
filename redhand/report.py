"""Terminal rendering.

The output has one job: make the difference between "confirmed exploited" and
"merely vulnerable" impossible to miss, because that distinction is the whole
of Article 14 and every other scanner blurs it.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime

from .classify import Assessment, Finding, Tier, early_warning_fields

_ANSI = {
    "red": "\033[31m",
    "yellow": "\033[33m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def _supports_colour(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *names: str) -> str:
        if not self.enabled or not names:
            return text
        prefix = "".join(_ANSI[n] for n in names if n in _ANSI)
        return f"{prefix}{text}{_ANSI['reset']}"


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M UTC")


def _finding_line(finding: Finding, style: _Style) -> str:
    colour = {
        Tier.CLOCK_RUNNING: ("red", "bold"),
        Tier.URGENT_REVIEW: ("yellow",),
        Tier.MONITOR: ("dim",),
    }.get(finding.tier, ())
    marker = style(finding.primary_cve, *colour)
    return f"  {marker}  {finding.component.label}\n      {finding.reason}"


def render(assessment: Assessment, stream=sys.stdout, show_monitor: bool = False) -> None:
    style = _Style(_supports_colour(stream))
    write = lambda line="": print(line, file=stream)

    doc = assessment.document
    subject = doc.subject or "(unnamed)"
    write()
    write(style(f"redhand  ~  {subject}", "bold"))
    write(
        style(
            f"{doc.format} {doc.spec_version or ''}".strip()
            + f"  ~  {assessment.components_checked} components checked"
            + f"  ~  {_stamp(assessment.scanned_at)}",
            "dim",
        )
    )
    write()

    running = assessment.clock_running
    urgent = assessment.urgent
    monitor = assessment.monitor

    if running:
        write(style(f"{Tier.CLOCK_RUNNING.headline.upper()}  ({len(running)})", "red", "bold"))
        write(style("  Confirmed exploited in the wild -- CISA KEV", "dim"))
        write()
        for finding in running:
            write(_finding_line(finding, style))
        write()

    if urgent:
        write(style(f"{Tier.URGENT_REVIEW.headline.upper()}  ({len(urgent)})", "yellow", "bold"))
        write(style("  Elevated exploitation probability, not yet confirmed", "dim"))
        write()
        # A single stale dependency can carry twenty of these. Showing them all
        # buries the section above it, which is the one that matters.
        shown = urgent if show_monitor else urgent[:8]
        for finding in shown:
            write(_finding_line(finding, style))
        if len(urgent) > len(shown):
            write(style(f"  ... and {len(urgent) - len(shown)} more (--all)", "dim"))
        write()

    if monitor:
        if show_monitor:
            write(style(f"{Tier.MONITOR.headline.upper()}  ({len(monitor)})", "dim"))
            write()
            for finding in monitor:
                write(_finding_line(finding, style))
            write()
        else:
            write(style(f"  {len(monitor)} further known vulnerabilities with no exploitation signal (--all to list)", "dim"))
            write()

    if assessment.unresolvable:
        write(style(f"CANNOT BE CHECKED  ({len(assessment.unresolvable)})", "bold"))
        write(style("  No package URL in the SBOM. An unknown, not a clear.", "dim"))
        write()
        for component in assessment.unresolvable[:10]:
            write(f"  {component.label}")
        if len(assessment.unresolvable) > 10:
            write(style(f"  ... and {len(assessment.unresolvable) - 10} more", "dim"))
        write()

    write(style("VERDICT", "bold"))
    write(f"  {assessment.verdict}")
    write()

    if running or urgent:
        deadlines = assessment.deadlines
        write(style("ARTICLE 14 CASCADE", "bold"))
        write(style("  Counted from the moment you became aware, which may predate this scan.", "dim"))
        write(f"  Early warning     {_stamp(deadlines['early_warning'])}   (24h)")
        write(f"  Notification      {_stamp(deadlines['notification'])}   (72h)")
        write(f"  Final report      {_stamp(deadlines['final_report'])}   (14d)")
        write()

    if running:
        write(style("WHAT THE EARLY WARNING MUST CARRY", "bold"))
        fields = early_warning_fields(running[0], assessment)
        width = max(len(k) for k in fields)
        for key, value in fields.items():
            write(f"  {key.replace('_', ' ').ljust(width)}   {value}")
        write()

    write(
        style(
            "This is an exposure indicator, not a conformity assessment and not "
            "legal advice.\nIt cannot tell whether vulnerable code is reachable in "
            "your product. That judgement\nis yours.",
            "dim",
        )
    )
    write()


def render_json(assessment: Assessment, stream=sys.stdout) -> None:
    payload = {
        "scanned_at": assessment.scanned_at.isoformat(),
        "subject": assessment.document.subject,
        "sbom_format": assessment.document.format,
        "components_checked": assessment.components_checked,
        "verdict": assessment.verdict,
        "counts": {
            "clock_running": len(assessment.clock_running),
            "urgent_review": len(assessment.urgent),
            "monitor": len(assessment.monitor),
            "unresolvable": len(assessment.unresolvable),
        },
        "findings": [
            {
                "tier": f.tier.value,
                "cve": f.primary_cve,
                "all_cves": list(f.cves),
                "advisory": f.vulnerability.id,
                "component": f.component.label,
                "purl": f.component.purl,
                "reason": f.reason,
                "epss": f.epss,
                "kev_date_added": f.kev.date_added if f.kev else None,
                "ransomware_linked": f.kev.ransomware if f.kev else None,
            }
            for f in assessment.findings
            if f.tier is not Tier.MONITOR
        ],
        "unresolvable": [c.label for c in assessment.unresolvable],
        "disclaimer": (
            "Exposure indicator only. Not a conformity assessment, not legal "
            "advice, and not a determination that no reporting obligation exists."
        ),
    }
    json.dump(payload, stream, indent=2)
    print(file=stream)
