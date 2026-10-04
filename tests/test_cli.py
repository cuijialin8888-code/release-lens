from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from html.parser import HTMLParser
from pathlib import Path

from release_lens.cli import _markdown, main
from release_lens.models import Artifact, Finding, Report


class CodeTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text = ""

    def handle_data(self, data: str) -> None:
        self.text += data


class CliTests(unittest.TestCase):
    def test_markdown_artifact_cells_preserve_special_characters(self) -> None:
        name = "package|extra`<tag>&.zip"
        version = "1|2`<dev>&"
        report = Report(root="dist", artifacts=[Artifact(name, "zip", 1, "abc", version)])
        row = next(line for line in _markdown(report).splitlines() if "package" in line)
        cells = row.split("|")
        self.assertEqual(len(cells), 7, "artifact name must not create another column")
        for cell, expected in ((cells[1], name), (cells[4], version)):
            parser = CodeTextParser()
            parser.feed(cell.strip())
            self.assertEqual(parser.text, expected)
            self.assertIn("<code>", cell)
            self.assertNotIn("<tag>", cell)

    def test_markdown_context_and_evidence_cannot_add_lines_or_html(self) -> None:
        value = "dist`</code><img src=x>|\r\n# injected"
        report = Report(root=value, expected_version=value)
        report.findings.append(Finding("RLA004", "error", "Unsafe path", value))
        rendered = _markdown(report)
        self.assertNotIn("<img", rendered)
        self.assertNotIn("\r", rendered)
        self.assertNotIn("\n# injected", rendered)
        for line in rendered.splitlines():
            if "injected" in line:
                self.assertIn(r"\r\n# injected", line)

    def test_markdown_cli_keeps_archive_member_evidence_on_one_line(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with zipfile.ZipFile(root / "asset.zip", "w") as archive:
                archive.writestr("../bad`</code><img src=x>|\n# injected", "data")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["audit", str(root), "--format", "markdown"])
            rendered = output.getvalue()
            self.assertEqual(code, 1)
            self.assertIn("RLA004", rendered)
            self.assertNotIn("<img", rendered)
            self.assertNotIn("\n# injected", rendered)

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
