"""redhand -- which of your components start a CRA Article 14 24-hour clock."""

__version__ = "0.1.0"

from .classify import Assessment, Finding, Tier, assess, early_warning_fields
from .sbom import Component, SBOMDocument, SBOMError, parse, parse_file
from .scan import scan_document, scan_file, scan_text
from .sources import FeedError

__all__ = [
    "Assessment",
    "Component",
    "FeedError",
    "Finding",
    "SBOMDocument",
    "SBOMError",
    "Tier",
    "assess",
    "early_warning_fields",
    "parse",
    "parse_file",
    "scan_document",
    "scan_file",
    "scan_text",
    "__version__",
]
