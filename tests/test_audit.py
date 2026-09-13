from __future__ import annotations

import hashlib
import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from release_lens.audit import audit, write_manifest


class AuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "pyproject.toml").write_text(
            '[project]\nname = "demo-package"\nversion = "1.2.3"\n', encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_wheel(self, name: str = "demo_package-1.2.3-py3-none-any.whl") -> Path:
        path = self.root / name
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("demo_package/__init__.py", "__version__ = '1.2.3'\n")
            archive.writestr(
                "demo_package-1.2.3.dist-info/METADATA",
                "Metadata-Version: 2.1\nName: demo-package\nVersion: 1.2.3\n\n",
            )
            archive.writestr("demo_package-1.2.3.dist-info/RECORD", "")
        return path

    def make_sdist(self) -> Path:
        path = self.root / "demo_package-1.2.3.tar.gz"
        payload = b"Metadata-Version: 2.1\nName: demo-package\nVersion: 1.2.3\n\n"
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo("demo-package-1.2.3/PKG-INFO")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        return path

    def test_valid_python_release_and_manifest_pass(self) -> None:
        self.make_wheel()
        self.make_sdist()
        write_manifest(self.root, self.root / "SHA256SUMS")
        report = audit(self.root, "v1.2.3")
        self.assertEqual(report.errors, 0)
        self.assertEqual(report.warnings, 0)
        self.assertEqual({a.kind for a in report.artifacts}, {"wheel", "sdist", "file"})

    def test_version_mismatch_is_error(self) -> None:
        self.make_wheel()
        report = audit(self.root, "2.0.0")
        self.assertIn("RLA101", {finding.code for finding in report.findings})
        self.assertGreaterEqual(report.errors, 1)

    def test_zip_parent_path_is_error(self) -> None:
        path = self.root / "bad.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("../escape.txt", "no")
        report = audit(self.root)
        codes = {finding.code for finding in report.findings}
        self.assertIn("RLA004", codes)

    def test_checksum_mismatch_is_error(self) -> None:
        wheel = self.make_wheel()
        (self.root / "SHA256SUMS").write_text("0" * 64 + "  " + wheel.name + "\n", encoding="utf-8")
        report = audit(self.root)
        self.assertIn("RLA205", {finding.code for finding in report.findings})

    def test_bsd_checksum_manifest_is_supported(self) -> None:
        wheel = self.make_wheel()
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        (self.root / "checksums.txt").write_text(
            f"SHA256 ({wheel.name}) = {digest}\n", encoding="utf-8"
        )
        report = audit(self.root)
        self.assertNotIn("RLA202", {finding.code for finding in report.findings})
        self.assertNotIn("RLA205", {finding.code for finding in report.findings})

    def test_uncovered_asset_is_warning_and_strict_promotes(self) -> None:
        wheel = self.make_wheel()
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        (self.root / "SHA256SUMS").write_text(f"{digest}  {wheel.name}\n", encoding="utf-8")
        self.make_sdist()
        report = audit(self.root)
        self.assertIn("RLA206", {finding.code for finding in report.findings})
        strict = audit(self.root, strict=True)
        self.assertEqual(strict.warnings, 0)
        self.assertGreaterEqual(strict.errors, 1)

    def test_custom_manifest_output_is_not_hashed_on_repeat(self) -> None:
        self.make_wheel()
        output = self.root / "manifest.txt"
        write_manifest(self.root, output)
        first = output.read_text(encoding="utf-8")
        write_manifest(self.root, output)
        self.assertEqual(first, output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
