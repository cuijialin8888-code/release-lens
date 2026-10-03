<div align="center">
  <h1>release-lens</h1>
  <p><strong>Catch release-bundle mistakes before your users do.</strong></p>
  <p>Offline, deterministic audits for versions, archives, metadata, paths, and SHA-256 manifests.</p>
  <p>
    <a href="https://github.com/cuijialin8888-code/release-lens/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/cuijialin8888-code/release-lens/actions/workflows/ci.yml/badge.svg"></a>
    <img alt="Python 3.10+" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
    <img alt="Runtime dependencies: zero" src="https://img.shields.io/badge/runtime%20dependencies-0-10b981">
    <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-0f172a"></a>
  </p>
  <p><a href="README.zh-CN.md">简体中文</a> · <a href="#30-second-start">Quick start</a> · <a href="docs/design.md">Design and limits</a></p>
</div>

Publishing a release is easy. Publishing the wrong version, a broken wheel,
an archive with a parent-directory entry, or a stale checksum file is also easy.
`release-lens` turns the release directory into an auditable report before it
reaches users.

It is deliberately small and conservative:

- **Read-only audit:** `audit` never extracts, installs, imports, or executes an artifact.
- **Offline by default:** it reads only the directory you pass and uses Python's standard library.
- **Evidence first:** every finding has a stable `RLA###` code and local evidence.
- **Format friendly:** terminal, JSON, Markdown, and SARIF 2.1.0 output work in CI or a release checklist.

## 30-second start

Install from a source checkout or a versioned wheel:

```console
python -m pip install .
release-lens audit dist --expected-version 0.1.0
```

Example output:

```text
Release Lens 0.1.0 — /work/project/dist

Expected version: 0.1.0
Artifacts: 3
  release_lens-0.1.0-py3-none-any.whl  [wheel, 18542 bytes] (release-lens 0.1.0)
  release_lens-0.1.0.tar.gz             [sdist, 21408 bytes] (release-lens 0.1.0)
  SHA256SUMS                            [file, 256 bytes]

PASS  No findings.

Summary: 0 errors, 0 warnings, 0 info
```

For a machine-readable gate:

```console
release-lens audit dist --expected-version 0.1.0 --format json --strict
```

For a code-scanning-compatible CI artifact:

```console
release-lens audit dist --expected-version 0.1.0 --format sarif --output release-lens.sarif
```

Generate a manifest only when you explicitly request it:

```console
release-lens manifest dist
release-lens audit dist --expected-version 0.1.0
```

The audit exits with code `1` for errors, and with `--strict` also for warnings.

## What it checks

| Area | Checks |
| --- | --- |
| Version identity | Expected version, wheel/sdist metadata, and a local `pyproject.toml` project version |
| Python artifacts | Wheel `METADATA` and `RECORD`; sdist `PKG-INFO` |
| Archive safety | Absolute paths, parent-directory paths, duplicate ZIP names, and tar links |
| Integrity | GNU/BSD/plain SHA-256 manifests, missing entries, mismatches, and uncovered assets |
| Reporting | Stable finding codes, artifact digest/size, JSON, Markdown, SARIF, and terminal output |

## Safety boundary

`release-lens` does not claim that an artifact is safe, reproducible, signed,
or free of malicious code. It does not inspect every language ecosystem's
metadata and it does not contact GitHub, package indexes, or a key server.
Archive members are inspected without extraction. See
[the design and limitations](docs/design.md) before using the result as a
release policy.

## Portable archive and report safety

On `main` (unreleased), archive paths are checked for Windows drive-absolute, drive-relative, UNC, and rooted paths as well as POSIX traversal. Package metadata reads are capped at 1 MiB. Symbolic links in the release directory produce `RLA006` and are not read or hashed; manifest generation refuses linked bundles. Checksum references must name direct local assets: unsafe or nested paths produce `RLA207` and cannot count as coverage. Audit report output must be outside the release directory and must not follow symbolic links, so it cannot replace an audited artifact. Custom text manifest outputs remain supported; package-archive output destinations are refused.

## Development

The project has no runtime dependencies. From the repository root:

```console
python -m unittest discover -s tests -v
python -m compileall -q src tests
python -m release_lens --help
```

Contributions should preserve deterministic output, the read-only audit
boundary, stable finding codes, and Python 3.10 compatibility.

## License

MIT. See [LICENSE](LICENSE).
