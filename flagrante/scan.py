"""Orchestration: SBOM in, Assessment out.

Kept separate from the CLI so the web service and the GitHub Action can share
exactly the same path. Any divergence between what the CLI says and what the
hosted tool says would be a correctness bug, not a cosmetic one.
"""

from __future__ import annotations

from typing import Callable

from .classify import Assessment, assess
from .sbom import SBOMDocument, parse, parse_file
from .sources import fetch_epss, fetch_kev, query_osv

Progress = Callable[[str], None]


def _noop(_message: str) -> None:
    pass


def scan_document(
    document: SBOMDocument,
    progress: Progress = _noop,
    refresh_feeds: bool = False,
) -> Assessment:
    identifiable = document.identifiable
    progress(
        f"{len(document.components)} components read, "
        f"{len(identifiable)} with a package URL"
    )

    if not identifiable:
        # Nothing queryable. We still return an assessment so the caller can
        # report the unresolvable components, which is the whole story here.
        return assess(document, {}, {}, {}, {})

    purls = [c.purl for c in identifiable if c.purl]
    progress("querying OSV for known vulnerabilities")
    osv_by_purl, vulnerabilities = query_osv(purls)

    cves = sorted({cve for v in vulnerabilities.values() for cve in v.cves})
    progress(f"{len(vulnerabilities)} advisories, {len(cves)} distinct CVEs")

    progress("fetching CISA KEV (confirmed exploited)")
    kev = fetch_kev(refresh=refresh_feeds)

    epss: dict[str, float] = {}
    if cves:
        progress("fetching EPSS exploitation probabilities")
        epss = fetch_epss(cves)

    return assess(document, osv_by_purl, vulnerabilities, kev, epss)


def scan_file(path: str, progress: Progress = _noop, refresh_feeds: bool = False) -> Assessment:
    return scan_document(parse_file(path), progress, refresh_feeds)


def scan_text(raw: str | bytes, progress: Progress = _noop, refresh_feeds: bool = False) -> Assessment:
    return scan_document(parse(raw), progress, refresh_feeds)
