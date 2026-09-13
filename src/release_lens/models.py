from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITIES = ("error", "warning", "info")


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    evidence: str = ""
    next_step: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"Unknown severity: {self.severity}")

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class Artifact:
    name: str
    kind: str
    size: int
    sha256: str
    version: str | None = None
    project_name: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    root: str
    expected_version: str | None = None
    artifacts: list[Artifact] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def errors(self) -> int:
        return sum(f.severity == "error" for f in self.findings)

    @property
    def warnings(self) -> int:
        return sum(f.severity == "warning" for f in self.findings)

    @property
    def infos(self) -> int:
        return sum(f.severity == "info" for f in self.findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": "release-lens",
            "version": "0.1.0",
            "root": self.root,
            "expected_version": self.expected_version,
            "read_only": True,
            "artifacts": [a.as_dict() for a in self.artifacts],
            "findings": [f.as_dict() for f in self.findings],
            "summary": {
                "artifacts": len(self.artifacts),
                "errors": self.errors,
                "warnings": self.warnings,
                "infos": self.infos,
            },
        }
