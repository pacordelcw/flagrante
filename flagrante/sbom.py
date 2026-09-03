"""SBOM parsing: CycloneDX and SPDX JSON -> a normalised component list.

Deliberately dependency-free. Both formats are read leniently: a malformed or
partially-populated SBOM should still yield whatever components it does carry,
because a manufacturer under time pressure is exactly who produces one.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable


class SBOMError(ValueError):
    """The input could not be read as a supported SBOM."""


@dataclass(frozen=True)
class Component:
    """One software component as named by the SBOM."""

    name: str
    version: str | None
    purl: str | None
    ecosystem: str | None = None
    licenses: tuple[str, ...] = field(default=())

    @property
    def label(self) -> str:
        return f"{self.name}@{self.version}" if self.version else self.name

    @property
    def identifiable(self) -> bool:
        """Whether this component can be looked up against a vulnerability feed.

        Without a purl we cannot query OSV reliably, and guessing an ecosystem
        from a bare name invites false negatives -- the one direction this tool
        must never fail in. Such components are reported as unresolvable rather
        than silently dropped.
        """
        return bool(self.purl)


@dataclass
class SBOMDocument:
    format: str
    spec_version: str | None
    components: list[Component]
    subject: str | None = None

    @property
    def identifiable(self) -> list[Component]:
        return [c for c in self.components if c.identifiable]

    @property
    def unresolvable(self) -> list[Component]:
        return [c for c in self.components if not c.identifiable]


_PURL_ECOSYSTEM = re.compile(r"^pkg:([a-zA-Z0-9._-]+)/")


def _ecosystem_from_purl(purl: str | None) -> str | None:
    if not purl:
        return None
    match = _PURL_ECOSYSTEM.match(purl)
    return match.group(1).lower() if match else None


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _cyclonedx_licenses(entry: dict) -> tuple[str, ...]:
    out: list[str] = []
    for item in entry.get("licenses") or []:
        if not isinstance(item, dict):
            continue
        lic = item.get("license")
        if isinstance(lic, dict):
            name = _clean(lic.get("id") or lic.get("name"))
            if name:
                out.append(name)
        expression = _clean(item.get("expression"))
        if expression:
            out.append(expression)
    return tuple(dict.fromkeys(out))


def _walk_cyclonedx(entries: Iterable[dict]) -> Iterable[dict]:
    """Yield components including nested ones, which CycloneDX permits."""
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        yield entry
        nested = entry.get("components")
        if isinstance(nested, list):
            yield from _walk_cyclonedx(nested)


def _parse_cyclonedx(doc: dict) -> SBOMDocument:
    components: list[Component] = []
    for entry in _walk_cyclonedx(doc.get("components") or []):
        name = _clean(entry.get("name"))
        if not name:
            continue
        group = _clean(entry.get("group"))
        if group and not name.startswith(group):
            name = f"{group}/{name}"
        purl = _clean(entry.get("purl"))
        components.append(
            Component(
                name=name,
                version=_clean(entry.get("version")),
                purl=purl,
                ecosystem=_ecosystem_from_purl(purl),
                licenses=_cyclonedx_licenses(entry),
            )
        )

    metadata = doc.get("metadata") or {}
    target = metadata.get("component") or {}
    subject = _clean(target.get("name")) if isinstance(target, dict) else None

    return SBOMDocument(
        format="CycloneDX",
        spec_version=_clean(doc.get("specVersion")),
        components=components,
        subject=subject,
    )


def _spdx_purl(entry: dict) -> str | None:
    for ref in entry.get("externalRefs") or []:
        if not isinstance(ref, dict):
            continue
        if str(ref.get("referenceType", "")).lower() == "purl":
            return _clean(ref.get("referenceLocator"))
    return None


def _parse_spdx(doc: dict) -> SBOMDocument:
    components: list[Component] = []
    for entry in doc.get("packages") or []:
        if not isinstance(entry, dict):
            continue
        name = _clean(entry.get("name"))
        if not name:
            continue
        version = _clean(entry.get("versionInfo"))
        purl = _spdx_purl(entry)
        declared = _clean(entry.get("licenseDeclared"))
        licenses = (declared,) if declared and declared != "NOASSERTION" else ()
        components.append(
            Component(
                name=name,
                version=version,
                purl=purl,
                ecosystem=_ecosystem_from_purl(purl),
                licenses=licenses,  # type: ignore[arg-type]
            )
        )

    return SBOMDocument(
        format="SPDX",
        spec_version=_clean(doc.get("spdxVersion")),
        components=components,
        subject=_clean(doc.get("name")),
    )


def parse(raw: str | bytes) -> SBOMDocument:
    """Read a CycloneDX or SPDX JSON SBOM.

    Raises SBOMError when the input is not JSON or carries no recognisable
    format marker, so the caller can tell the user what to hand us instead.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8-sig", errors="replace")

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SBOMError(f"not valid JSON ({exc.msg} at line {exc.lineno})") from exc

    if not isinstance(doc, dict):
        raise SBOMError("expected a JSON object at the top level")

    if doc.get("bomFormat") == "CycloneDX" or "specVersion" in doc:
        return _parse_cyclonedx(doc)
    if "spdxVersion" in doc or "SPDXID" in doc:
        return _parse_spdx(doc)

    raise SBOMError(
        "unrecognised SBOM format -- expected CycloneDX JSON (bomFormat) "
        "or SPDX JSON (spdxVersion). Generate one with syft or cdxgen."
    )


def parse_file(path: str) -> SBOMDocument:
    with open(path, "rb") as handle:
        return parse(handle.read())
