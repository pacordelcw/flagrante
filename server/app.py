"""Hosted scanner — a stateless HTTP front for the same engine the CLI runs.

Two rules shape everything in this file.

**The SBOM never touches disk.** An SBOM is a complete inventory of a company's
software supply chain. Asking a manufacturer to upload one to a stranger is a
real ask, and the only honest answer to "what do you do with it" is "nothing".
It is parsed in memory, scanned, and dropped when the request ends. There is no
storage layer here to leak, because there is no storage layer.

**The web result cannot drift from the terminal result.** Both call
``flagrante.scan`` and both render through ``flagrante.html``. If the hosted answer
ever disagreed with the answer someone got locally, the tool would be worthless
for the one thing it exists to support.

Deliberately dependency-free, like the rest of the package: stdlib only, so the
container image is a Python base plus this repo and nothing else to audit.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flagrante import __version__
from flagrante.html import render_html
from flagrante.sbom import SBOMError, parse
from flagrante.scan import scan_document
from flagrante.sources import FeedError, fetch_kev

log = logging.getLogger("flagrante.server")

# A 5 MB SBOM is already enormous; beyond that something is wrong or hostile.
MAX_BODY_BYTES = 5 * 1024 * 1024

# Each identifiable component costs an OSV lookup, and each distinct advisory
# costs another. Past roughly a thousand components we would be holding a
# request open for minutes and leaning on a free public API, so we stop and say
# so rather than quietly truncating -- a silently partial scan is exactly the
# false reassurance this tool exists to avoid.
MAX_COMPONENTS = 1000

# When we reject an oversized upload we still have to consume the body, or the
# client is mid-write when we answer and sees a broken pipe instead of our 413.
# Draining is bounded so a hostile sender cannot make us read forever.
DRAIN_CEILING_BYTES = 24 * 1024 * 1024
DRAIN_CHUNK = 64 * 1024

ALLOWED_ORIGINS = {
    "https://flagrante.dev",
    "https://www.flagrante.dev",
    "http://127.0.0.1:8901",
    "http://localhost:8901",
}

# Coarse in-process limiter. Cloudflare in front is the real defence; this only
# stops one client from monopolising a single warm instance.
RATE_WINDOW_SECONDS = 60
RATE_MAX_REQUESTS = 12
_hits: dict[str, deque[float]] = {}
_hits_lock = threading.Lock()


def _rate_limited(client: str) -> bool:
    now = time.time()
    with _hits_lock:
        bucket = _hits.setdefault(client, deque())
        while bucket and now - bucket[0] > RATE_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= RATE_MAX_REQUESTS:
            return True
        bucket.append(now)
        if len(_hits) > 5000:  # bound memory on a long-lived instance
            for key in [k for k, v in _hits.items() if not v][:1000]:
                _hits.pop(key, None)
    return False


def _summary(assessment: Any) -> dict[str, Any]:
    """Counts and findings only.

    Note what is absent: the component list of the whole SBOM. Only components
    that actually carry an exploitation signal are named, because those are the
    ones the user needs to see. The rest of their inventory is their business.
    """
    return {
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
                "component": f.component.label,
                "reason": f.reason,
                "epss": f.epss,
                "ransomware_linked": f.kev.ransomware if f.kev else None,
            }
            for f in assessment.findings
            if f.tier.value in ("clock_running", "urgent_review")
        ],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = f"flagrante/{__version__}"
    protocol_version = "HTTP/1.1"

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        # Never log request bodies. Method, path and status only.
        log.info("%s %s", self.address_string(), fmt % args)

    def _origin(self) -> str | None:
        origin = self.headers.get("Origin")
        return origin if origin in ALLOWED_ORIGINS else None

    def _send(
        self,
        status: int,
        payload: Any,
        content_type: str = "application/json",
        close: bool = False,
    ) -> None:
        body = (
            json.dumps(payload).encode("utf-8")
            if content_type == "application/json"
            else str(payload).encode("utf-8")
        )
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if close:
            # We are answering without draining the request body, so the
            # connection cannot be reused -- say so, or the client sees a
            # broken pipe instead of the status we just sent.
            self.close_connection = True
            self.send_header("Connection", "close")
        origin = self._origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def _drain(self, length: int) -> bool:
        """Read and discard a rejected body. True if fully consumed."""
        if length > DRAIN_CEILING_BYTES:
            return False
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(DRAIN_CHUNK, remaining))
            if not chunk:
                return False
            remaining -= len(chunk)
        return True

    def _client(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "")
        return forwarded.split(",")[0].strip() or self.client_address[0]

    # -- routes -----------------------------------------------------------

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        origin = self._origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Max-Age", "86400")
            self.send_header("Vary", "Origin")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") in ("/health", "/healthz"):
            self._send(200, {"ok": True, "version": __version__})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/scan":
            self._send(404, {"error": "not found"})
            return

        if _rate_limited(self._client()):
            self._send(429, {"error": "too many scans from this address; wait a minute"})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._send(400, {"error": "bad Content-Length"})
            return

        if length <= 0:
            self._send(400, {"error": "send the SBOM as the request body"})
            return
        if length > MAX_BODY_BYTES:
            drained = self._drain(length)
            self._send(
                413,
                {
                    "error": f"SBOM larger than {MAX_BODY_BYTES // (1024 * 1024)} MB. "
                    "Run the CLI locally instead: pip install flagrante"
                },
                close=not drained,
            )
            return

        raw = self.rfile.read(length)

        try:
            document = parse(raw)
        except SBOMError as exc:
            self._send(400, {"error": f"cannot read that SBOM -- {exc}"})
            return

        identifiable = len(document.identifiable)
        if identifiable > MAX_COMPONENTS:
            self._send(
                413,
                {
                    "error": (
                        f"{identifiable} identifiable components exceeds the hosted "
                        f"limit of {MAX_COMPONENTS}. We will not run a partial scan "
                        "and report it as a whole one. Run it locally, unmetered: "
                        "pip install flagrante"
                    )
                },
            )
            return

        try:
            assessment = scan_document(document)
        except FeedError as exc:
            # The one failure mode that must never look like a clean result.
            log.warning("feed unavailable: %s", exc)
            self._send(
                503,
                {
                    "error": (
                        "an exploitation feed is unreachable, so we are refusing to "
                        "return a result. An empty answer and an unavailable feed "
                        "look identical and mean opposite things."
                    )
                },
            )
            return
        except Exception:  # pragma: no cover - defensive
            log.exception("scan failed")
            self._send(500, {"error": "the scan did not complete"})
            return

        self._send(
            200,
            {
                "result": _summary(assessment),
                "html": render_html(assessment),
            },
        )
        # `raw`, `document` and `assessment` fall out of scope here. Nothing was
        # written anywhere.


def main() -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    port = int(os.environ.get("PORT", "8080"))

    # Warm the KEV cache before accepting traffic so the first real scan is not
    # the one that pays for the feed download.
    try:
        entries = fetch_kev()
        log.info("KEV warm: %d entries", len(entries))
    except FeedError as exc:
        log.warning("KEV not warm at startup (%s); first scan will fetch it", exc)

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.daemon_threads = True
    log.info("flagrante %s listening on :%d", __version__, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
