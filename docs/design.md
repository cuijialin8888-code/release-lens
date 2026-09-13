# Design and limitations

## Product boundary

Release Lens audits a directory that already contains release assets. It is a
pre-publication gate, not a package builder, publisher, malware scanner, or
reproducible-build verifier.

The core invariant is simple: the audit may read files and archive metadata,
but it must not execute commands, import the project, install a package,
extract an archive, or access a network service.

## Findings

Finding codes are stable within the 0.1 line:

| Codes | Meaning |
| --- | --- |
| `RLA001–RLA002` | Invalid target or no release assets |
| `RLA003–RLA005` | Unreadable or suspicious archive structure |
| `RLA101–RLA108` | Version or project identity mismatch or unavailable local metadata |
| `RLA103–RLA105` | Missing Python distribution metadata |
| `RLA200–RLA206` | Checksum manifest problems |

Warnings are useful evidence, not proof of safety. `--strict` promotes them to
the failing exit status and to error severity in reports.

## Archive handling

ZIP and tar members are inspected in place. Absolute names and names containing
`..` are errors. Tar links are warnings because their meaning depends on the
consumer and they can be surprising in a portable bundle. The implementation
does not follow links or materialize any archive member.

## Version handling

Wheel and sdist metadata are authoritative when present. A local
`pyproject.toml` version is compared when Python's built-in `tomllib` is
available (Python 3.11+). On Python 3.10, the audit remains usable but does not
parse TOML without an optional dependency. Pass `--expected-version` for an
explicit release gate.
