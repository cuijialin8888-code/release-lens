from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import audit, write_manifest
from .models import Report
from .sarif import render_sarif


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="release-lens",
        description="Evidence-first, read-only audits for release bundles.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    audit_parser = sub.add_parser("audit", help="audit a release directory without changing it")
    audit_parser.add_argument("path", type=Path)
    audit_parser.add_argument("--expected-version", metavar="VERSION", help="compare package metadata with VERSION")
    audit_parser.add_argument("--strict", action="store_true", help="treat warnings as errors")
    audit_parser.add_argument("--format", choices=("text", "json", "markdown", "sarif"), default="text")
    audit_parser.add_argument("--output", type=Path, help="write the selected report to a file")
    manifest_parser = sub.add_parser("manifest", help="write a SHA256SUMS file for release assets")
    manifest_parser.add_argument("path", type=Path)
    manifest_parser.add_argument("--output", type=Path, default=None, help="output path (default: PATH/SHA256SUMS)")
    return parser


def _text(report: Report) -> str:
    lines = [f"Release Lens 0.1.0 — {report.root}", ""]
    if report.expected_version:
        lines.append(f"Expected version: {report.expected_version}")
    lines.append(f"Artifacts: {len(report.artifacts)}")
    for artifact in report.artifacts:
        suffix = f" ({artifact.project_name} {artifact.version})" if artifact.project_name or artifact.version else ""
        lines.append(f"  {artifact.name}  [{artifact.kind}, {artifact.size} bytes]{suffix}")
    lines.append("")
    if report.findings:
        for finding in report.findings:
            evidence = f" — {finding.evidence}" if finding.evidence else ""
            lines.append(f"[{finding.severity.upper()}] {finding.code} {finding.message}{evidence}")
            if finding.next_step:
                lines.append(f"  next: {finding.next_step}")
    else:
        lines.append("PASS  No findings.")
    lines.extend(["", f"Summary: {report.errors} errors, {report.warnings} warnings, {report.infos} info"])
    return "\n".join(lines) + "\n"


def _markdown(report: Report) -> str:
    lines = ["# Release Lens report", "", f"- Root: `{report.root}`", f"- Read-only: `true`"]
    if report.expected_version:
        lines.append(f"- Expected version: `{report.expected_version}`")
    lines.extend(["", "## Artifacts", "", "| Name | Kind | Size | Version | SHA-256 |", "| --- | --- | ---: | --- | --- |"])
    for artifact in report.artifacts:
        lines.append(f"| `{artifact.name}` | {artifact.kind} | {artifact.size} | {artifact.version or '—'} | `{artifact.sha256}` |")
    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("No findings.")
    else:
        for finding in report.findings:
            evidence = f" — `{finding.evidence}`" if finding.evidence else ""
            lines.append(f"- **{finding.severity.upper()} `{finding.code}`**: {finding.message}{evidence}")
            if finding.next_step:
                lines.append(f"  - Next: {finding.next_step}")
    lines.extend(["", f"**Summary:** {report.errors} errors, {report.warnings} warnings, {report.infos} info."])
    return "\n".join(lines) + "\n"


def _render(report: Report, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report.as_dict(), ensure_ascii=False, indent=2) + "\n"
    if fmt == "markdown":
        return _markdown(report)
    if fmt == "sarif":
        return render_sarif(report)
    return _text(report)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "manifest":
        output = args.output or (args.path / "SHA256SUMS")
        try:
            count = write_manifest(args.path, output)
        except (OSError, ValueError) as exc:
            print(f"release-lens: {exc}", file=sys.stderr)
            return 2
        print(f"Wrote {output} covering {count} artifact(s).")
        return 0
    report = audit(args.path, args.expected_version, args.strict)
    rendered = _render(report, args.format)
    if args.output:
        try:
            args.output.write_text(rendered, encoding="utf-8", newline="\n")
        except OSError as exc:
            print(f"release-lens: cannot write report: {exc}", file=sys.stderr)
            return 2
    else:
        print(rendered, end="")
    return 1 if report.errors or (args.strict and report.warnings) else 0
