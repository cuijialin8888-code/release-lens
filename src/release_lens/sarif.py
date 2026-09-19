from __future__ import annotations

import json
from typing import Any

from . import __version__
from .models import Finding, Report

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _level(severity: str) -> str:
    return {"error": "error", "warning": "warning", "info": "note"}[severity]


def _rule(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.code,
        "name": finding.code,
        "shortDescription": {"text": finding.message},
        "fullDescription": {"text": finding.message},
        "defaultConfiguration": {"level": _level(finding.severity)},
        "help": {"text": finding.next_step or finding.message},
    }


def render_sarif(report: Report) -> str:
    """Render release findings as a SARIF 2.1.0 log."""

    rules: list[dict[str, Any]] = []
    seen_rules: set[str] = set()
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        if finding.code not in seen_rules:
            rules.append(_rule(finding))
            seen_rules.add(finding.code)
        result: dict[str, Any] = {
            "ruleId": finding.code,
            "level": _level(finding.severity),
            "message": {"text": finding.message},
            "properties": {
                "evidence": finding.evidence,
                "next_step": finding.next_step,
            },
        }
        results.append(result)

    payload = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "release-lens",
                        "informationUri": "https://github.com/cuijialin8888-code/release-lens",
                        "semanticVersion": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "root": report.root,
                    "expected_version": report.expected_version,
                    "artifact_count": len(report.artifacts),
                    "read_only": True,
                },
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
