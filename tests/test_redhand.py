"""Offline tests. No network: feeds are injected, so these stay deterministic
and runnable in CI without hitting OSV, CISA or FIRST.

The safety tests near the bottom are the important ones. They encode the rule
that the tool must never tell a manufacturer they are in the clear, which is
the single behaviour that could turn this from useful into harmful.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redhand.classify import Tier, assess
from redhand.sbom import SBOMError, parse
from redhand.sources import KevEntry, Vulnerability


def cyclonedx(components: list[dict], name: str = "unit-under-test") -> str:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"component": {"type": "application", "name": name}},
            "components": components,
        }
    )


def kev_entry(cve: str) -> KevEntry:
    return KevEntry(
        cve=cve,
        vendor="Example",
        product="Thing",
        name="Exploited in the wild",
        date_added="2024-01-15",
        due_date="2024-02-05",
        ransomware=True,
    )


def advisory(vuln_id: str, cve: str) -> Vulnerability:
    return Vulnerability(
        id=vuln_id, aliases=(cve,), summary="test advisory", severity="HIGH"
    )


class ParsingTests(unittest.TestCase):
    def test_reads_cyclonedx_with_group_prefix(self):
        doc = parse(
            cyclonedx(
                [
                    {
                        "name": "log4j-core",
                        "group": "org.apache.logging.log4j",
                        "version": "2.14.1",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    }
                ]
            )
        )
        self.assertEqual(doc.format, "CycloneDX")
        self.assertEqual(doc.components[0].name, "org.apache.logging.log4j/log4j-core")
        self.assertEqual(doc.components[0].ecosystem, "maven")

    def test_reads_nested_components(self):
        doc = parse(
            cyclonedx(
                [
                    {
                        "name": "outer",
                        "version": "1.0",
                        "purl": "pkg:npm/outer@1.0",
                        "components": [
                            {"name": "inner", "version": "2.0", "purl": "pkg:npm/inner@2.0"}
                        ],
                    }
                ]
            )
        )
        self.assertEqual({c.name for c in doc.components}, {"outer", "inner"})

    def test_reads_spdx_purl_from_external_refs(self):
        doc = parse(
            json.dumps(
                {
                    "spdxVersion": "SPDX-2.3",
                    "name": "spdx-subject",
                    "packages": [
                        {
                            "name": "lodash",
                            "versionInfo": "4.17.15",
                            "externalRefs": [
                                {
                                    "referenceType": "purl",
                                    "referenceLocator": "pkg:npm/lodash@4.17.15",
                                }
                            ],
                        }
                    ],
                }
            )
        )
        self.assertEqual(doc.format, "SPDX")
        self.assertEqual(doc.components[0].purl, "pkg:npm/lodash@4.17.15")

    def test_component_without_purl_is_unresolvable_not_dropped(self):
        doc = parse(cyclonedx([{"name": "blob", "version": "1.0"}]))
        self.assertEqual(len(doc.components), 1)
        self.assertEqual(len(doc.identifiable), 0)
        self.assertEqual(len(doc.unresolvable), 1)

    def test_rejects_non_json(self):
        with self.assertRaises(SBOMError):
            parse("this is not json")

    def test_rejects_unknown_format(self):
        with self.assertRaises(SBOMError):
            parse(json.dumps({"something": "else"}))


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.doc = parse(
            cyclonedx(
                [
                    {"name": "vulnlib", "version": "1.0", "purl": "pkg:npm/vulnlib@1.0"}
                ]
            )
        )

    def _assess(self, vulns, kev, epss):
        osv = {"pkg:npm/vulnlib@1.0": list(vulns)}
        return assess(self.doc, osv, vulns, kev, epss)

    def test_kev_match_starts_the_clock(self):
        result = self._assess(
            {"GHSA-a": advisory("GHSA-a", "CVE-2021-44228")},
            {"CVE-2021-44228": kev_entry("CVE-2021-44228")},
            {"CVE-2021-44228": 0.97},
        )
        self.assertEqual(len(result.clock_running), 1)
        self.assertIn("CISA KEV", result.clock_running[0].reason)

    def test_high_epss_without_kev_is_urgent_not_clock(self):
        result = self._assess(
            {"GHSA-b": advisory("GHSA-b", "CVE-2022-0001")},
            {},
            {"CVE-2022-0001": 0.55},
        )
        self.assertEqual(len(result.clock_running), 0)
        self.assertEqual(len(result.urgent), 1)

    def test_low_epss_is_monitor(self):
        result = self._assess(
            {"GHSA-c": advisory("GHSA-c", "CVE-2022-0002")},
            {},
            {"CVE-2022-0002": 0.001},
        )
        self.assertEqual(result.findings[0].tier, Tier.MONITOR)

    def test_same_cve_from_two_advisories_reported_once(self):
        """A GHSA record and the CVE record aliasing each other is routine."""
        result = self._assess(
            {
                "GHSA-dup": advisory("GHSA-dup", "CVE-2021-23337"),
                "CVE-2021-23337": advisory("CVE-2021-23337", "CVE-2021-23337"),
            },
            {},
            {"CVE-2021-23337": 0.21},
        )
        self.assertEqual(len(result.findings), 1)

    def test_counts_components_not_findings(self):
        """One component with two exploited CVEs is one component, not two."""
        result = self._assess(
            {
                "GHSA-x": advisory("GHSA-x", "CVE-2021-44228"),
                "GHSA-y": advisory("GHSA-y", "CVE-2021-45046"),
            },
            {
                "CVE-2021-44228": kev_entry("CVE-2021-44228"),
                "CVE-2021-45046": kev_entry("CVE-2021-45046"),
            },
            {},
        )
        self.assertEqual(len(result.clock_running), 2)
        self.assertEqual(len(result.components_of_tier(Tier.CLOCK_RUNNING)), 1)
        self.assertIn("1 component carries 2 vulnerabilities", result.verdict)


class SafetyTests(unittest.TestCase):
    """The rules that make this tool safe to publish.

    Every one of these encodes the same asymmetry: over-flagging costs a user
    an afternoon, under-flagging costs them up to EUR 15 million.
    """

    # Phrases that cannot occur inside a correctly hedged sentence. Bare
    # substrings like "no reporting" are deliberately absent: they also match
    # the safe framing "not a determination that no reporting obligation
    # exists", and a test that fires on the correct wording trains you to
    # ignore it.
    FORBIDDEN = [
        "you are compliant",
        "is compliant",
        "no action needed",
        "no action required",
        "no further action",
        "you are clear",
        "you do not need to report",
        "you need not report",
        "not required to report",
        "safe to ship",
    ]

    # Every verdict has to carry at least one of these, so a future edit cannot
    # quietly drop the hedging while still passing the FORBIDDEN check.
    REQUIRED_HEDGES = [
        "point-in-time",
        "not a determination",
        "not a clear",
        "assess",
    ]

    def _verdict_for(self, components):
        doc = parse(cyclonedx(components))
        return assess(doc, {}, {}, {}, {}).verdict.lower()

    def test_clean_sbom_never_claims_compliance(self):
        verdict = self._verdict_for(
            [{"name": "clean", "version": "1.0", "purl": "pkg:npm/clean@1.0"}]
        )
        for phrase in self.FORBIDDEN:
            self.assertNotIn(phrase, verdict, f"verdict must never say {phrase!r}")

    def test_clean_verdict_is_framed_as_point_in_time(self):
        verdict = self._verdict_for(
            [{"name": "clean", "version": "1.0", "purl": "pkg:npm/clean@1.0"}]
        )
        self.assertIn("point-in-time", verdict)

    def test_unresolvable_components_are_called_an_unknown(self):
        verdict = self._verdict_for([{"name": "blob", "version": "1.0"}])
        self.assertIn("not a clear", verdict)

    def test_no_tier_means_clear(self):
        self.assertNotIn(
            "clear", " ".join(t.headline.lower() for t in Tier)
        )

    def test_every_verdict_carries_a_hedge(self):
        """Including the ones that flag findings, not just the quiet one."""
        cases = [
            [{"name": "clean", "version": "1.0", "purl": "pkg:npm/clean@1.0"}],
            [{"name": "blob", "version": "1.0"}],
        ]
        for components in cases:
            verdict = self._verdict_for(components)
            self.assertTrue(
                any(h in verdict for h in self.REQUIRED_HEDGES),
                f"verdict lost its hedging: {verdict!r}",
            )

    def test_flagged_verdict_instructs_assessment_not_conclusion(self):
        doc = parse(
            cyclonedx([{"name": "v", "version": "1.0", "purl": "pkg:npm/v@1.0"}])
        )
        result = assess(
            doc,
            {"pkg:npm/v@1.0": ["GHSA-z"]},
            {"GHSA-z": advisory("GHSA-z", "CVE-2021-44228")},
            {"CVE-2021-44228": kev_entry("CVE-2021-44228")},
            {"CVE-2021-44228": 0.97},
        )
        verdict = result.verdict.lower()
        self.assertIn("assess", verdict)
        for phrase in self.FORBIDDEN:
            self.assertNotIn(phrase, verdict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
