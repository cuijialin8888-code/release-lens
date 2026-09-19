# Maintenance checklist

Keep release-lens offline, deterministic, read-only during audits, and conservative about what a passing result can prove.

## Routine checks

- Run the unit-test matrix on Python 3.10 and 3.13 across Linux, macOS, and Windows.
- Run python -m compileall -q src tests and python -m release_lens --help.
- Audit a representative wheel, source distribution, and checksum manifest with --strict.
- Do not treat a successful audit as proof that an artifact is reproducible, signed, or free of malicious code.
- Review the release workflow separately from the offline audit path before changing publishing actions.

## Dependency and release review

- Keep GitHub Actions pinned to immutable commit SHAs.
- Exercise the release workflow before merging major publishing-action updates.
- Verify that generated SHA256SUMS does not include itself or other temporary manifest output.
- Keep release-flow uncertainty explicit when only the CI matrix has been exercised.

## Review log

- 2026-09-19: reviewed public main, open Issues/PRs, and recent Actions; no open Issues were present. Dependabot PR #4 (actions/checkout v7.0.1) passed the complete six-job matrix (34859566088) and was merged to main as 8bdff0c0f1b62ba30429f8a56d353da6fd099ca5. Dependabot PR #3 (softprops/action-gh-release v3.0.3) remains open pending exercised release-flow compatibility evidence.
