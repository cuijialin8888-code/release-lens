import contextlib
import hashlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from release_lens.audit import MAX_METADATA_BYTES, audit, write_manifest
from release_lens.cli import main


class ReleaseSafetyTests(unittest.TestCase):
    def test_manifest_rejects_hard_link_before_hashing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            root.mkdir()
            asset = root / "asset.txt"
            asset.write_bytes(b"preserve")
            output = Path(directory) / "manifest.txt"
            output.hardlink_to(asset)
            with mock.patch("release_lens.audit._sha256") as hash_asset:
                with self.assertRaisesRegex(ValueError, "hard link"):
                    write_manifest(root, output)
                hash_asset.assert_not_called()
            self.assertEqual(asset.read_bytes(), b"preserve")
            self.assertEqual(output.read_bytes(), b"preserve")

    def test_audit_rejects_hard_link_before_scanning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            root.mkdir()
            asset = root / "asset.txt"
            asset.write_bytes(b"preserve")
            output = Path(directory) / "report.txt"
            output.hardlink_to(asset)
            with mock.patch("release_lens.cli.audit", wraps=audit) as scan:
                with contextlib.redirect_stderr(io.StringIO()) as errors:
                    code = main(["audit", str(root), "--output", str(output)])
                self.assertEqual(code, 2)
                self.assertIn("hard link", errors.getvalue())
                scan.assert_not_called()
            self.assertEqual(asset.read_bytes(), b"preserve")
            self.assertEqual(output.read_bytes(), b"preserve")

    def test_audit_can_replace_an_ordinary_external_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            root.mkdir()
            asset = root / "asset.txt"
            asset.write_bytes(b"preserve")
            output = Path(directory) / "report.txt"
            output.write_bytes(b"old report")
            self.assertEqual(main(["audit", str(root), "--output", str(output)]), 0)
            self.assertIn("Release Lens", output.read_text(encoding="utf-8"))
            self.assertEqual(asset.read_bytes(), b"preserve")

    def test_manifest_cannot_follow_an_output_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            root.mkdir()
            (root / "asset.txt").write_bytes(b"asset")
            protected = Path(directory) / "original.txt"
            protected.write_bytes(b"preserve")
            output = Path(directory) / "linked-manifest.txt"
            try:
                output.symlink_to(protected)
            except OSError:
                self.skipTest("symbolic links unavailable")
            with self.assertRaises(ValueError):
                write_manifest(root, output)
            self.assertEqual(protected.read_bytes(), b"preserve")

    def test_windows_absolute_and_drive_relative_archive_members_are_unsafe(self):
        for member in ("C:/escape.txt", "C:escape.txt", "\\\\server\\share\\escape.txt", "\\escape.txt"):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with zipfile.ZipFile(root / "asset.zip", "w") as archive:
                    archive.writestr(member, "data")
                self.assertIn("RLA004", {finding.code for finding in audit(root).findings})

    def test_checksum_cannot_cover_asset_by_discarding_unsafe_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            asset = root / "asset.txt"
            asset.write_bytes(b"data")
            digest = hashlib.sha256(b"data").hexdigest()
            (root / "SHA256SUMS").write_text(f"{digest}  ../asset.txt\n", encoding="utf-8")
            codes = {finding.code for finding in audit(root).findings}
            self.assertIn("RLA207", codes)
            self.assertIn("RLA206", codes)

    def test_oversized_metadata_is_a_finding_and_is_not_parsed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with zipfile.ZipFile(root / "demo.whl", "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("demo.dist-info/METADATA", b"x" * (MAX_METADATA_BYTES + 1))
                archive.writestr("demo.dist-info/RECORD", "")
            report = audit(root)
            self.assertIn("RLA003", {finding.code for finding in report.findings})
            self.assertIsNone(report.artifacts[0].version)

    def test_audit_report_cannot_replace_an_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            asset = root / "asset.txt"
            asset.write_bytes(b"preserve")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["audit", str(root), "--output", str(asset)]), 2)
            self.assertEqual(asset.read_bytes(), b"preserve")

    def test_symlink_is_not_read_or_hashed_and_manifest_refuses_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            root.mkdir()
            protected = Path(directory) / "original.txt"
            protected.write_bytes(b"private")
            try:
                (root / "pyproject.toml").symlink_to(protected)
            except OSError:
                self.skipTest("symbolic links unavailable")
            report = audit(root)
            self.assertEqual(report.artifacts, [])
            self.assertIn("RLA006", {finding.code for finding in report.findings})
            self.assertNotIn("RLA108", {finding.code for finding in report.findings})
            with self.assertRaises(ValueError):
                write_manifest(root, root / "SHA256SUMS")
            self.assertFalse((root / "SHA256SUMS").exists())
            self.assertEqual(protected.read_bytes(), b"private")
