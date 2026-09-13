from __future__ import annotations

import hashlib
import re
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Iterable

from .models import Artifact, Finding, Report


HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")
GNU_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+[* ](.+?)\s*$")
BSD_RE = re.compile(r"^SHA256 \((.+)\) = ([0-9a-fA-F]{64})\s*$", re.I)
PLAIN_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+(.+?)\s*$")
CHECKSUM_NAMES = {"sha256sums", "sha256sums.txt", "checksums.txt", "sha256.txt"}


def _finding(code: str, severity: str, message: str, evidence: str = "", next_step: str = "") -> Finding:
    return Finding(code, severity, message, evidence, next_step)


def _normal_version(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value[1:] if value.startswith("v") else value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_member(name: str) -> bool:
    if not name or "\x00" in name:
        return False
    path = PurePosixPath(name.replace("\\", "/"))
    return not path.is_absolute() and ".." not in path.parts


def _metadata(raw: str) -> tuple[str | None, str | None]:
    message = Parser().parsestr(raw)
    return message.get("Name"), message.get("Version")


def _inspect_zip(path: Path) -> tuple[str | None, str | None, list[Finding]]:
    findings: list[Finding] = []
    project_name = version = None
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                findings.append(_finding("RLA004", "error", "Archive contains duplicate member names", path.name,
                                        "Rebuild the archive without duplicate entries."))
            for name in names:
                if not _safe_member(name):
                    findings.append(_finding("RLA004", "error", "Archive contains an unsafe path", f"{path.name}:{name}",
                                            "Remove absolute or parent-directory members before publishing."))
            metadata_names = [n for n in names if n.endswith(".dist-info/METADATA")]
            if metadata_names:
                project_name, version = _metadata(archive.read(metadata_names[0]).decode("utf-8", "replace"))
            if path.name.endswith(".whl"):
                record_names = [n for n in names if n.endswith(".dist-info/RECORD")]
                if not record_names:
                    findings.append(_finding("RLA105", "error", "Wheel has no dist-info/RECORD file", path.name,
                                            "Build the wheel with a standards-compliant packaging backend."))
                if not metadata_names:
                    findings.append(_finding("RLA104", "error", "Wheel has no dist-info/METADATA file", path.name,
                                            "Build the wheel with package metadata included."))
    except (OSError, zipfile.BadZipFile, UnicodeError) as exc:
        findings.append(_finding("RLA003", "error", "Cannot read ZIP or wheel archive", f"{path.name}: {exc}",
                                "Rebuild the artifact and rerun the audit."))
    return project_name, version, findings


def _inspect_tar(path: Path) -> tuple[str | None, str | None, list[Finding]]:
    findings: list[Finding] = []
    project_name = version = None
    try:
        with tarfile.open(path, "r:*") as archive:
            members = archive.getmembers()
            for member in members:
                if not _safe_member(member.name):
                    findings.append(_finding("RLA004", "error", "Archive contains an unsafe path", f"{path.name}:{member.name}",
                                            "Remove absolute or parent-directory members before publishing."))
                if member.issym() or member.islnk():
                    findings.append(_finding("RLA005", "warning", "Archive contains a link entry", f"{path.name}:{member.name}",
                                            "Review the link deliberately; avoid links in portable release bundles."))
            pkg_infos = [m for m in members if PurePosixPath(m.name).name == "PKG-INFO" and m.isfile()]
            if pkg_infos:
                handle = archive.extractfile(pkg_infos[0])
                if handle is not None:
                    project_name, version = _metadata(handle.read().decode("utf-8", "replace"))
            else:
                findings.append(_finding("RLA103", "warning", "Source archive has no PKG-INFO metadata", path.name,
                                        "Include package metadata when publishing a Python source distribution."))
    except (OSError, tarfile.TarError, UnicodeError) as exc:
        findings.append(_finding("RLA003", "error", "Cannot read source archive", f"{path.name}: {exc}",
                                "Rebuild the artifact and rerun the audit."))
    return project_name, version, findings


def _kind(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".whl"):
        return "wheel"
    if name.endswith((".tar.gz", ".tgz", ".tar")):
        return "sdist"
    if name.endswith(".zip"):
        return "zip"
    return "file"


def _is_checksum_file(path: Path) -> bool:
    name = path.name.lower()
    return name in CHECKSUM_NAMES or name.endswith((".sha256", ".sha256sum"))


def _parse_checksum_lines(path: Path) -> tuple[dict[str, str], list[Finding]]:
    records: dict[str, str] = {}
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return records, [_finding("RLA201", "error", "Cannot read checksum manifest", f"{path.name}: {exc}")]
    for line_number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        bsd_match = BSD_RE.match(line)
        gnu_match = GNU_RE.match(line)
        plain_match = PLAIN_RE.match(line)
        if bsd_match is not None:
            target, digest = bsd_match.groups()
        elif gnu_match is not None:
            digest, target = gnu_match.groups()
        elif plain_match is not None:
            digest, target = plain_match.groups()
        else:
            findings.append(_finding("RLA202", "error", "Malformed SHA-256 manifest line", f"{path.name}:{line_number}",
                                    "Use GNU coreutils, BSD, or '<hash>  <filename>' format."))
            continue
        target = target.lstrip("*")
        if not HASH_RE.fullmatch(digest):
            findings.append(_finding("RLA202", "error", "Invalid SHA-256 digest", f"{path.name}:{line_number}"))
            continue
        if target in records and records[target].lower() != digest.lower():
            findings.append(_finding("RLA203", "error", "Checksum manifest has conflicting duplicate entries", target,
                                    "Keep one digest per artifact."))
        records[target] = digest.lower()
    return records, findings


def _source_metadata(root: Path) -> tuple[str | None, str | None, str | None]:
    path = root / "pyproject.toml"
    if not path.is_file():
        return None, None, None
    try:
        import tomllib  # type: ignore[attr-defined]
    except ModuleNotFoundError:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            return None, None, f"Cannot read pyproject.toml: {exc}"
        section = False
        values: dict[str, str] = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line == "[project]"
                continue
            if not section or "=" not in line or line.startswith("#"):
                continue
            key, raw_value = (part.strip() for part in line.split("=", 1))
            if key in {"name", "version"}:
                match = re.fullmatch(r"[\"']([^\"']+)[\"'](?:\s*#.*)?", raw_value)
                if match:
                    values[key] = match.group(1)
        if "name" in values or "version" in values:
            return values.get("version"), values.get("name"), None
        return None, None, "Python 3.10 fallback could not find static [project] name/version"
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        return None, None, f"Cannot parse pyproject.toml: {exc}"
    project = data.get("project", {})
    name = project.get("name") if isinstance(project, dict) else None
    version = project.get("version") if isinstance(project, dict) else None
    return (str(version) if version is not None else None), (str(name) if name is not None else None), None


def _artifact(path: Path, findings: list[Finding]) -> Artifact:
    kind = _kind(path)
    project_name = version = None
    if kind in {"wheel", "zip"}:
        project_name, version, nested = _inspect_zip(path)
        findings.extend(nested)
    elif kind == "sdist":
        project_name, version, nested = _inspect_tar(path)
        findings.extend(nested)
    return Artifact(path.name, kind, path.stat().st_size, _sha256(path), version, project_name)


def _check_checksums(root: Path, files: list[Path], report: Report) -> None:
    manifests = [p for p in files if _is_checksum_file(p)]
    if not manifests:
        report.findings.append(_finding("RLA200", "warning", "No SHA-256 checksum manifest found", str(root),
                                        "Publish SHA256SUMS alongside release artifacts."))
        return
    by_name = {p.name: p for p in files}
    for manifest in manifests:
        records, findings = _parse_checksum_lines(manifest)
        report.findings.extend(findings)
        for target, expected in records.items():
            candidate = by_name.get(Path(target).name)
            if candidate is None:
                report.findings.append(_finding("RLA204", "error", "Checksum references a missing artifact",
                                                f"{manifest.name}: {target}", "Remove stale entries or restore the artifact."))
                continue
            actual = _sha256(candidate)
            if actual.lower() != expected.lower():
                report.findings.append(_finding("RLA205", "error", "Artifact checksum does not match manifest",
                                                f"{candidate.name}: expected {expected}, actual {actual}",
                                                "Regenerate the manifest after the final artifact is built."))
        covered = {Path(name).name for name in records}
        for file in files:
            if file == manifest or _is_checksum_file(file):
                continue
            if file.name not in covered:
                report.findings.append(_finding("RLA206", "warning", "Artifact is not covered by the checksum manifest",
                                                f"{manifest.name}: {file.name}", "Regenerate the manifest to cover every release asset."))


def audit(root: Path, expected_version: str | None = None, strict: bool = False) -> Report:
    root = root.expanduser().resolve()
    report = Report(str(root), expected_version)
    if not root.exists():
        report.findings.append(_finding("RLA001", "error", "Release directory does not exist", str(root)))
        return report
    if not root.is_dir():
        report.findings.append(_finding("RLA001", "error", "Audit target is not a directory", str(root)))
        return report
    files = sorted((p for p in root.iterdir() if p.is_file()), key=lambda p: p.name.lower())
    artifact_files = [p for p in files if not _is_checksum_file(p)]
    if not artifact_files:
        report.findings.append(_finding("RLA002", "error", "No release artifacts found", str(root),
                                        "Place wheel, source archive, or other release assets in the directory."))
    for path in artifact_files:
        report.artifacts.append(_artifact(path, report.findings))
    _check_checksums(root, files, report)

    normalized_expected = _normal_version(expected_version)
    versions = {a.version for a in report.artifacts if a.version}
    if len(versions) > 1:
        report.findings.append(_finding("RLA102", "error", "Release artifacts contain conflicting versions",
                                        ", ".join(sorted(versions)), "Build all assets from the same version."))
    if normalized_expected:
        for artifact in report.artifacts:
            if artifact.version and _normal_version(artifact.version) != normalized_expected:
                report.findings.append(_finding("RLA101", "error", "Artifact version does not match the expected release version",
                                                f"{artifact.name}: {artifact.version}; expected {expected_version}",
                                                "Rebuild the artifact or pass the correct expected version."))
    source_version, source_name, source_error = _source_metadata(root)
    if source_error:
        report.findings.append(_finding("RLA108", "warning", "Could not read project metadata version", source_error,
                                        "Pass --expected-version or use Python 3.11+ for built-in TOML parsing."))
    if source_version and versions and _normal_version(source_version) not in {_normal_version(v) for v in versions}:
        report.findings.append(_finding("RLA106", "error", "pyproject.toml version differs from artifact metadata",
                                        f"pyproject.toml: {source_version}; artifacts: {', '.join(sorted(versions))}",
                                        "Build from the same source version used by the release."))
    if source_name and report.artifacts:
        names = {a.project_name for a in report.artifacts if a.project_name}
        if names and source_name not in names and source_name.replace("-", "_") not in {n.replace("-", "_") for n in names}:
            report.findings.append(_finding("RLA107", "warning", "pyproject.toml project name differs from artifact metadata",
                                            f"pyproject.toml: {source_name}; artifacts: {', '.join(sorted(names))}",
                                            "Confirm that the release was built from the intended project."))
    if strict:
        report.findings = [
            Finding(f.code, "error" if f.severity == "warning" else f.severity, f.message, f.evidence, f.next_step)
            for f in report.findings
        ]
    return report


def write_manifest(root: Path, output: Path) -> int:
    root = root.expanduser().resolve()
    output = output.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Not a release directory: {root}")
    files = sorted((p for p in root.iterdir() if p.is_file() and p != output and not _is_checksum_file(p)), key=lambda p: p.name.lower())
    output.write_text("".join(f"{_sha256(p)}  {p.name}\n" for p in files), encoding="utf-8", newline="\n")
    return len(files)
