from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from release_lens.cli import main


class CliTests(unittest.TestCase):
    def test_json_report_is_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["audit", str(root), "--format", "json"])
            self.assertEqual(code, 1)
            document = json.loads(output.getvalue())
            self.assertEqual(document["read_only"], True)
            self.assertEqual(document["summary"]["errors"], 1)

    def test_sarif_report_is_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["audit", str(root), "--format", "sarif"])
            document = json.loads(output.getvalue())
            self.assertEqual(code, 1)
            self.assertEqual(document["version"], "2.1.0")
            self.assertEqual(
                document["runs"][0]["tool"]["driver"]["name"], "release-lens"
            )
            self.assertEqual(document["runs"][0]["results"][0]["ruleId"], "RLA002")

    def test_manifest_command_writes_explicit_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "artifact.bin").write_bytes(b"release")
            output = root / "manifest.txt"
            self.assertEqual(main(["manifest", str(root), "--output", str(output)]), 0)
            self.assertIn("artifact.bin", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
