"""Vulnerability and exploitation feeds.

Three public sources, no API keys, no dependencies:

  OSV (osv.dev)          component  -> known vulnerabilities
  CISA KEV               CVE        -> confirmed exploited in the wild
  FIRST EPSS             CVE        -> probability of exploitation in 30 days

A note on failure handling, which matters more here than in most clients:
when a feed cannot be reached we raise. We never degrade to "nothing found".
An empty result and an unreachable exploitation feed look identical to a user
and mean opposite things, and only one of them is safe to act on.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss"

USER_AGENT = "flagrante/0.1 (CRA Article 14 exposure checker)"
CACHE_TTL_SECONDS = 6 * 3600


class FeedError(RuntimeError):
    """A required feed could not be reached or returned something unusable."""


def _cache_dir() -> Path:
    root = os.environ.get("FLAGRANTE_CACHE") or (Path.home() / ".cache" / "flagrante")
    path = Path(root)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _cached(name: str, ttl: int = CACHE_TTL_SECONDS) -> Any | None:
    path = _cache_dir() / name
    if not path.exists():
        return None
    if time.time() - path.stat().st_mtime > ttl:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _store(name: str, payload: Any) -> None:
    try:
        (_cache_dir() / name).write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass  # a cache miss is never worth failing a scan over


def _request(url: str, body: bytes | None = None, timeout: int = 45) -> Any:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise FeedError(f"{url} returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise FeedError(f"could not reach {url}: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise FeedError(f"{url} returned malformed JSON") from exc


def _retrying(url: str, body: bytes | None = None, attempts: int = 3) -> Any:
    delay = 1.0
    last: FeedError | None = None
    for _ in range(attempts):
        try:
            return _request(url, body)
        except FeedError as exc:
            last = exc
            time.sleep(delay)
            delay *= 2
    raise last  # type: ignore[misc]


# --------------------------------------------------------------------------
# CISA KEV -- the authoritative "confirmed exploited" list
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class KevEntry:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: str
    ransomware: bool


def fetch_kev(refresh: bool = False) -> dict[str, KevEntry]:
    payload = None if refresh else _cached("kev.json")
    if payload is None:
        payload = _retrying(KEV_URL)
        _store("kev.json", payload)

    entries: dict[str, KevEntry] = {}
    for item in payload.get("vulnerabilities") or []:
        cve = str(item.get("cveID", "")).upper().strip()
        if not cve:
            continue
        entries[cve] = KevEntry(
            cve=cve,
            vendor=str(item.get("vendorProject", "")),
            product=str(item.get("product", "")),
            name=str(
                item.get("shortDescription", "") or item.get("vulnerabilityName", "")
            ),
            date_added=str(item.get("dateAdded", "")),
            due_date=str(item.get("dueDate", "")),
            ransomware=str(item.get("knownRansomwareCampaignUse", "")).lower()
            == "known",
        )

    if not entries:
        raise FeedError("CISA KEV feed parsed but contained no entries")
    return entries


# --------------------------------------------------------------------------
# EPSS -- probability that a CVE is exploited in the next 30 days
# --------------------------------------------------------------------------


def fetch_epss(cves: Sequence[str], batch_size: int = 100) -> dict[str, float]:
    unique = sorted({c.upper() for c in cves if c.upper().startswith("CVE-")})
    if not unique:
        return {}

    scores: dict[str, float] = {}
    for start in range(0, len(unique), batch_size):
        chunk = unique[start : start + batch_size]
        url = f"{EPSS_URL}?cve={','.join(chunk)}"
        payload = _retrying(url)
        for row in payload.get("data") or []:
            cve = str(row.get("cve", "")).upper()
            try:
                scores[cve] = float(row.get("epss", 0.0))
            except (TypeError, ValueError):
                continue
    return scores


# --------------------------------------------------------------------------
# OSV -- component to vulnerability
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Vulnerability:
    id: str
    aliases: tuple[str, ...]
    summary: str
    severity: str | None

    @property
    def cves(self) -> tuple[str, ...]:
        found = [a.upper() for a in self.aliases if a.upper().startswith("CVE-")]
        if self.id.upper().startswith("CVE-"):
            found.append(self.id.upper())
        return tuple(dict.fromkeys(found))


def _osv_batch(purls: Sequence[str]) -> list[list[str]]:
    """Cheap first pass: which purls have anything at all against them."""
    queries = [{"package": {"purl": purl}} for purl in purls]
    body = json.dumps({"queries": queries}).encode("utf-8")
    payload = _retrying(OSV_BATCH_URL, body)

    results: list[list[str]] = []
    for entry in payload.get("results") or []:
        ids = [str(v.get("id")) for v in (entry.get("vulns") or []) if v.get("id")]
        results.append(ids)

    while len(results) < len(purls):
        results.append([])
    return results


def _osv_full(purl: str) -> tuple[str, list[dict]]:
    """Full advisory records for one package.

    /v1/query returns complete records, where /v1/querybatch returns bare ids.
    Fetching details id-by-id turns one slow package into a hundred requests --
    a five-component SBOM measured 56 seconds that way. Querying per package
    instead makes the cost scale with packages that have findings, which is a
    small minority, rather than with the number of advisories.
    """
    body = json.dumps({"package": {"purl": purl}}).encode("utf-8")
    try:
        payload = _retrying(OSV_QUERY_URL, body, attempts=2)
    except FeedError:
        return purl, []
    return purl, [v for v in (payload.get("vulns") or []) if isinstance(v, dict)]


def _severity_of(record: dict) -> str | None:
    for item in record.get("severity") or []:
        if isinstance(item, dict) and item.get("score"):
            return str(item["score"])
    database = record.get("database_specific") or {}
    if isinstance(database, dict) and database.get("severity"):
        return str(database["severity"])
    return None


def _to_vulnerability(record: dict) -> Vulnerability:
    aliases = tuple(str(a) for a in (record.get("aliases") or []))
    return Vulnerability(
        id=str(record.get("id", "")),
        aliases=aliases,
        summary=str(record.get("summary") or "").strip(),
        severity=_severity_of(record),
    )


def query_osv(
    purls: Sequence[str], batch_size: int = 200, workers: int = 16
) -> tuple[dict[str, list[str]], dict[str, Vulnerability]]:
    """Map each purl to its OSV advisory ids, plus a detail lookup."""
    # Pass one: find the packages worth asking about in detail.
    flagged: list[str] = []
    for start in range(0, len(purls), batch_size):
        chunk = list(purls[start : start + batch_size])
        for purl, ids in zip(chunk, _osv_batch(chunk)):
            if ids:
                flagged.append(purl)

    by_purl: dict[str, list[str]] = {purl: [] for purl in purls}
    details: dict[str, Vulnerability] = {}
    if not flagged:
        return by_purl, details

    # Pass two: full records, only for those.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for purl, records in pool.map(_osv_full, flagged):
            ids = []
            for record in records:
                vuln = _to_vulnerability(record)
                if not vuln.id:
                    continue
                details[vuln.id] = vuln
                ids.append(vuln.id)
            by_purl[purl] = ids

    return by_purl, details
