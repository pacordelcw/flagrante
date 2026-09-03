"""Exposure classification for CRA Article 14.

The single most important design rule in this file: there is no "clear" tier.

Article 14 obliges a manufacturer to send an early warning within 24 hours of
becoming aware that a vulnerability *contained in their product* is *actively
exploited*. This tool can establish that a component carries a CVE, and that
the CVE is known to be exploited somewhere in the world. It cannot establish
that the vulnerable code path ships in, or is reachable from, a given product.

So every outcome here is an instruction to assess, never a permission to stand
down. A tool that tells a manufacturer they need not report, and is wrong,
costs them a fine of up to EUR 15 million. A tool that over-flags costs them
an afternoon. The asymmetry decides every threshold below.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum

from .sbom import Component, SBOMDocument
from .sources import KevEntry, Vulnerability

# EPSS is a probability of exploitation within 30 days. The vast majority of
# CVEs sit below 0.01; 0.10 is roughly the top few per cent of the corpus and
# is a widely used operational cut-off for "treat this as likely".
EPSS_ELEVATED = 0.10
EPSS_HIGH = 0.30

# Article 14 reporting cascade, from the moment of awareness.
EARLY_WARNING_HOURS = 24
NOTIFICATION_HOURS = 72
FINAL_REPORT_DAYS = 14


class Tier(str, Enum):
    """Ordered by urgency. Note the absence of anything meaning 'compliant'."""

    CLOCK_RUNNING = "clock_running"
    URGENT_REVIEW = "urgent_review"
    MONITOR = "monitor"
    UNRESOLVABLE = "unresolvable"

    @property
    def headline(self) -> str:
        return {
            Tier.CLOCK_RUNNING: "24-hour clock likely running",
            Tier.URGENT_REVIEW: "Assess today",
            Tier.MONITOR: "Track",
            Tier.UNRESOLVABLE: "Cannot be checked",
        }[self]

    @property
    def rank(self) -> int:
        return {
            Tier.CLOCK_RUNNING: 0,
            Tier.URGENT_REVIEW: 1,
            Tier.MONITOR: 2,
            Tier.UNRESOLVABLE: 3,
        }[self]


@dataclass
class Finding:
    component: Component
    vulnerability: Vulnerability
    tier: Tier
    cves: tuple[str, ...]
    kev: KevEntry | None = None
    epss: float | None = None

    @property
    def primary_cve(self) -> str:
        return self.cves[0] if self.cves else self.vulnerability.id

    @property
    def reason(self) -> str:
        if self.tier is Tier.CLOCK_RUNNING and self.kev is not None:
            ransom = ", linked to ransomware campaigns" if self.kev.ransomware else ""
            return (
                f"listed in CISA KEV since {self.kev.date_added} as exploited "
                f"in the wild{ransom}"
            )
        if self.tier is Tier.URGENT_REVIEW and self.epss is not None:
            return (
                f"EPSS {self.epss:.0%} probability of exploitation within 30 days "
                "-- not yet confirmed exploited, but above the threshold where "
                "confirmation often follows"
            )
        if self.epss is not None:
            return f"known vulnerability, EPSS {self.epss:.1%}"
        return "known vulnerability, no exploitation signal"


@dataclass
class Assessment:
    document: SBOMDocument
    findings: list[Finding] = field(default_factory=list)
    unresolvable: list[Component] = field(default_factory=list)
    scanned_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    components_checked: int = 0

    def of_tier(self, tier: Tier) -> list[Finding]:
        return [f for f in self.findings if f.tier is tier]

    def components_of_tier(self, tier: Tier) -> list[Component]:
        """Distinct components at a tier.

        One component routinely carries several CVEs, so counting findings and
        calling them components overstates the blast radius. In a tool whose
        only asset is being believed, that is not a rounding error.
        """
        seen: dict[str, Component] = {}
        for finding in self.of_tier(tier):
            key = finding.component.purl or finding.component.label
            seen.setdefault(key, finding.component)
        return list(seen.values())

    @property
    def clock_running(self) -> list[Finding]:
        return self.of_tier(Tier.CLOCK_RUNNING)

    @property
    def urgent(self) -> list[Finding]:
        return self.of_tier(Tier.URGENT_REVIEW)

    @property
    def monitor(self) -> list[Finding]:
        return self.of_tier(Tier.MONITOR)

    @property
    def deadlines(self) -> dict[str, datetime]:
        """Article 14 cascade, counted from now.

        Presented only when something is flagged, and always framed as counting
        from the moment of awareness -- which may well predate this scan.
        """
        return {
            "early_warning": self.scanned_at + timedelta(hours=EARLY_WARNING_HOURS),
            "notification": self.scanned_at + timedelta(hours=NOTIFICATION_HOURS),
            "final_report": self.scanned_at + timedelta(days=FINAL_REPORT_DAYS),
        }

    @property
    def verdict(self) -> str:
        """Deliberately never says 'compliant', 'clear', or 'no action needed'."""
        if self.clock_running:
            components = len(self.components_of_tier(Tier.CLOCK_RUNNING))
            vulns = len(self.clock_running)
            noun = "component" if components == 1 else "components"
            verb = "carries" if components == 1 else "carry"
            count = (
                "a vulnerability"
                if vulns == 1
                else f"{vulns} vulnerabilities"
            )
            return (
                f"{components} {noun} {verb} {count} confirmed exploited in the "
                "wild. If any of these ship in a product you place on the EU "
                "market, assess Article 14 reporting now."
            )
        if self.urgent:
            components = len(self.components_of_tier(Tier.URGENT_REVIEW))
            noun = "component" if components == 1 else "components"
            verb = "carries" if components == 1 else "carry"
            return (
                f"No confirmed-exploited component found, but {components} "
                f"{noun} {verb} a vulnerability with elevated exploitation "
                "probability. These are the ones that become Article 14 "
                "obligations first."
            )
        if self.unresolvable:
            return (
                "No exploitation signal among the components we could identify. "
                f"{len(self.unresolvable)} component(s) carried no package URL and "
                "could not be checked at all -- that is an unknown, not a clear."
            )
        return (
            "No exploitation signal found in this SBOM at this moment. That is a "
            "point-in-time observation about known feeds, not a determination "
            "that no reporting obligation exists."
        )


def _tier_for(kev: KevEntry | None, epss: float | None) -> Tier:
    if kev is not None:
        return Tier.CLOCK_RUNNING
    if epss is not None and epss >= EPSS_ELEVATED:
        return Tier.URGENT_REVIEW
    return Tier.MONITOR


def assess(
    document: SBOMDocument,
    osv_by_purl: dict[str, list[str]],
    vulnerabilities: dict[str, Vulnerability],
    kev: dict[str, KevEntry],
    epss: dict[str, float],
) -> Assessment:
    """Join component -> vulnerability -> exploitation status into findings."""
    result = Assessment(
        document=document,
        unresolvable=list(document.unresolvable),
        components_checked=len(document.identifiable),
    )

    # Several OSV advisories routinely alias the same CVE (a GHSA record and
    # the CVE record itself, say). Reporting that component/CVE pair twice
    # inflates the count and reads as a bug to anyone who knows the ecosystem,
    # so collapse on (component, CVE) and keep the most urgent tier seen.
    deduped: dict[tuple[str, str], Finding] = {}

    for component in document.identifiable:
        assert component.purl is not None
        for vuln_id in osv_by_purl.get(component.purl, []):
            vuln = vulnerabilities.get(vuln_id)
            if vuln is None:
                continue

            cves = vuln.cves
            kev_hit = next((kev[c] for c in cves if c in kev), None)
            scores = [epss[c] for c in cves if c in epss]
            epss_score = max(scores) if scores else None

            finding = Finding(
                component=component,
                vulnerability=vuln,
                tier=_tier_for(kev_hit, epss_score),
                cves=cves,
                kev=kev_hit,
                epss=epss_score,
            )

            key = (component.purl, finding.primary_cve)
            existing = deduped.get(key)
            if existing is None or finding.tier.rank < existing.tier.rank:
                deduped[key] = finding

    result.findings = list(deduped.values())

    result.findings.sort(
        key=lambda f: (
            f.tier.rank,
            -(f.epss or 0.0),
            f.component.name,
        )
    )
    return result


def early_warning_fields(finding: Finding, assessment: Assessment) -> dict[str, str]:
    """The content an Article 14(2)(a) early warning has to carry.

    Supplied so a manufacturer can see what the Single Reporting Platform will
    ask for. The blanks are the parts only they can fill -- deliberately left
    blank rather than guessed.
    """
    return {
        "vulnerability": finding.primary_cve,
        "component": finding.component.label,
        "exploitation_evidence": finding.reason,
        "product_affected": "<your product name and version>",
        "member_states_made_available": "<EU member states where the product is on the market>",
        "corrective_measures_taken": "<mitigations shipped or planned>",
        "manufacturer": "<legal manufacturer name and contact>",
        "awareness_timestamp": "<when you first became aware -- may predate this scan>",
        "submit_to": "ENISA Single Reporting Platform, and the CSIRT of your "
        "member state of main establishment",
    }
