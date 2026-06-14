#!/usr/bin/env python3
"""APIGuard Python reporter CLI.

Reads an APIGuard JSON report (produced by the Go JSONReporter) and emits
an HTML or PDF report.

Usage:
    reporter.py --format html --input scan.json --output report.html
    reporter.py --format pdf  --input scan.json --output report.pdf
    cat scan.json | reporter.py --format html > report.html
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reporter",
        description="Generate HTML or PDF reports from APIGuard JSON scan output.",
    )
    p.add_argument(
        "--format",
        choices=["html", "pdf"],
        default="html",
        help="Output format (default: html).",
    )
    p.add_argument(
        "--input",
        "-i",
        metavar="FILE",
        help="Path to the JSON report file. Reads from stdin if omitted.",
    )
    p.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Path to write the output. Writes to stdout if omitted.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Read input.
    if args.input:
        try:
            with open(args.input, encoding="utf-8") as fh:
                report = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"reporter: failed to read input: {exc}", file=sys.stderr)
            return 1
    else:
        try:
            raw = sys.stdin.read()
            report = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(f"reporter: invalid JSON on stdin: {exc}", file=sys.stderr)
            return 1

    # Generate output.
    if args.format == "html":
        from html_reporter import generate  # noqa: PLC0415

        content: str | bytes = generate(report)
        mode = "w"
        encoding: str | None = "utf-8"
    else:
        from pdf_reporter import generate as pdf_generate  # noqa: PLC0415

        try:
            content = pdf_generate(report)
        except ImportError as exc:
            print(f"reporter: {exc}", file=sys.stderr)
            return 1
        mode = "wb"
        encoding = None

    # Write output.
    if args.output:
        try:
            if mode == "wb":
                assert isinstance(content, bytes)
                Path(args.output).write_bytes(content)
            else:
                assert isinstance(content, str)
                Path(args.output).write_text(content, encoding="utf-8")
        except OSError as exc:
            print(f"reporter: failed to write output: {exc}", file=sys.stderr)
            return 1
    else:
        if mode == "wb":
            sys.stdout.buffer.write(content)  # type: ignore[arg-type]
        else:
            sys.stdout.write(content)  # type: ignore[arg-type]

    return 0


if __name__ == "__main__":
    sys.exit(main())
