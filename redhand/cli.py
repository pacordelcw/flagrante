"""Command line entry point."""

from __future__ import annotations

import argparse
import sys

from .classify import Tier
from .html import render_html
from .report import render, render_json
from .sbom import SBOMError
from .scan import scan_file, scan_text
from .sources import FeedError

EXIT_OK = 0
EXIT_CLOCK_RUNNING = 1
EXIT_URGENT = 2
EXIT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redhand",
        description=(
            "Find which components in an SBOM carry vulnerabilities confirmed "
            "exploited in the wild -- the ones that start a CRA Article 14 "
            "24-hour reporting clock."
        ),
        epilog=(
            "Generate an SBOM first, for example:  syft dir:. -o cyclonedx-json > sbom.json"
        ),
    )
    parser.add_argument(
        "sbom",
        nargs="?",
        default="-",
        help="path to a CycloneDX or SPDX JSON SBOM, or - for stdin",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--html",
        action="store_true",
        help="standalone shareable HTML result page, written to stdout",
    )
    parser.add_argument(
        "--all", action="store_true", help="also list vulnerabilities with no exploitation signal"
    )
    parser.add_argument(
        "--refresh", action="store_true", help="bypass the local feed cache"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="suppress progress messages"
    )
    parser.add_argument(
        "--fail-on",
        choices=["never", "exploited", "urgent"],
        default="exploited",
        help=(
            "exit non-zero when findings reach this level (default: exploited), "
            "so CI can gate a release"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    def progress(message: str) -> None:
        if not args.quiet and not args.json and not args.html:
            print(f"  {message}", file=sys.stderr)

    try:
        if args.sbom == "-":
            if sys.stdin.isatty():
                print(
                    "redhand: reading an SBOM from stdin; pass a file path or pipe one in.\n"
                    "         try:  syft dir:. -o cyclonedx-json | redhand",
                    file=sys.stderr,
                )
                return EXIT_ERROR
            assessment = scan_text(sys.stdin.read(), progress, args.refresh)
        else:
            assessment = scan_file(args.sbom, progress, args.refresh)

    except SBOMError as exc:
        print(f"redhand: cannot read that SBOM -- {exc}", file=sys.stderr)
        return EXIT_ERROR
    except FeedError as exc:
        # Never degrade to a clean result: an unreachable exploitation feed and
        # an empty one look identical and mean opposite things.
        print(
            f"redhand: {exc}\n"
            "         Refusing to report a result without the exploitation feeds.",
            file=sys.stderr,
        )
        return EXIT_ERROR
    except FileNotFoundError:
        print(f"redhand: no such file: {args.sbom}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_ERROR

    if args.json:
        render_json(assessment)
    elif args.html:
        sys.stdout.write(render_html(assessment))
    else:
        render(assessment, show_monitor=args.all)

    if args.fail_on == "never":
        return EXIT_OK
    if assessment.clock_running:
        return EXIT_CLOCK_RUNNING
    if args.fail_on == "urgent" and assessment.urgent:
        return EXIT_URGENT
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
