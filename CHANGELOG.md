# Changelog

## [Unreleased]

- Harden cross-platform archive paths, bound metadata reads, reject linked release assets and non-local checksum references, and protect audited artifacts from report writes.

## 0.1.0 — 2026-09-13

- Initial public release.
- Added offline release-directory audits for wheel, sdist, ZIP, and generic assets.
- Added version, metadata, archive-path, duplicate-entry, and SHA-256 checks.
- Added terminal, JSON, Markdown, and explicit manifest generation commands.
