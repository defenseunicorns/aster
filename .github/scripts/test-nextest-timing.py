#!/usr/bin/env python3
"""Tests for the bounded nextest JUnit timing summary."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("summarize-nextest-junit.py")


class TimingSummaryTests(unittest.TestCase):
    def run_summary(
        self,
        report: str,
        *arguments: str,
    ) -> tuple[subprocess.CompletedProcess[str], bool, str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "junit.xml"
            output = root / "summary.md"
            source.write_text(report, encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--input",
                    str(source),
                    "--output",
                    str(output),
                    "--partition",
                    "test",
                    *arguments,
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            exists = output.exists()
            summary = output.read_text(encoding="utf-8") if exists else ""
        return result, exists, summary

    def test_reports_total_and_slowest_tests_in_descending_order(self):
        report = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="3" time="4.75">
  <testsuite name="aster-node::runtime" tests="2" time="4.5">
    <testcase classname="aster_node::runtime" name="fast_case" time="0.5" />
    <testcase classname="aster_node::runtime" name="slow|case" time="4.0" />
  </testsuite>
  <testsuite name="aster-core::api" tests="1" time="0.25">
    <testcase classname="aster_core::api" name="middle_case" time="0.25" />
  </testsuite>
</testsuites>
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "junit.xml"
            output = root / "summary.md"
            source.write_text(report, encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--input",
                    str(source),
                    "--output",
                    str(output),
                    "--partition",
                    "1/2",
                    "--limit",
                    "2",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            summary = output.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Tests recorded: 3", summary)
        self.assertIn("Cumulative test time: 4.750s", summary)
        self.assertLess(summary.index("slow\\|case"), summary.index("fast_case"))
        self.assertNotIn("middle_case", summary)

    def test_does_not_tag_duration_equal_to_target(self):
        report = """<testsuites>
  <testcase classname="aster_core::blob" name="at_target" time="10.000" />
</testsuites>
"""

        result, exists, summary = self.run_summary(
            report,
            "--problem-seconds",
            "10",
            "--github-annotations",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(exists)
        self.assertNotIn("Duration problems", summary)
        self.assertNotIn("::warning", result.stdout)

    def test_tags_every_duration_above_target_without_failing(self):
        report = """<testsuites>
  <testcase classname="aster_core::blob" name="barely_slow" time="10.001" />
  <testcase classname="aster_node::runtime" name="slower" time="12.5" />
  <testcase classname="aster_core::api" name="fast" time="0.5" />
</testsuites>
"""

        result, exists, summary = self.run_summary(
            report,
            "--problem-seconds",
            "10",
            "--github-annotations",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(exists)
        self.assertIn("Duration problems (> 10.000s)", summary)
        self.assertIn("aster_core::blob::barely_slow", summary)
        self.assertIn("aster_node::runtime::slower", summary)
        self.assertNotIn("aster_core::api::fast", summary.split("Duration problems", 1)[1])
        self.assertLess(
            summary.index("aster_node::runtime::slower"),
            summary.index("aster_core::blob::barely_slow"),
        )
        self.assertEqual(result.stdout.count("::warning"), 2)
        self.assertIn("target 10.000s", result.stdout)
        self.assertIn("10.001s", result.stdout)

    def test_rejects_negative_nan_infinite_empty_and_malformed_reports(self):
        for report in (
            "not XML",
            "<testsuites />",
            '<testsuites><testcase name="invalid" time="-0.001" /></testsuites>',
            '<testsuites><testcase name="invalid" time="nan" /></testsuites>',
            '<testsuites><testcase name="invalid" time="inf" /></testsuites>',
        ):
            with self.subTest(report=report):
                result, exists, summary = self.run_summary(
                    report,
                    "--problem-seconds",
                    "10",
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(exists)
                self.assertEqual(summary, "")


if __name__ == "__main__":
    unittest.main()
