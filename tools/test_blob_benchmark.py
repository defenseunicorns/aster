"""Regression tests for retained benchmark result validation."""
import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from blob_benchmark import main, parse_records, summarize, campaign


class MainPublication(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.output = self.root / "output"
        self.example = self.repo / "crates/aster-node/examples/blob_benchmark.rs"
        self.example.parent.mkdir(parents=True)
        self.example.write_text("// fixture source\n")
        (self.repo / "Cargo.toml").write_text('[profile.release]\nopt-level = "s"\n')
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        self.binary = self.root / "fixture"
        self.addCleanup(os.umask, os.umask(0o077))

    def run_fixture(self, change_source=False, campaign_name="default", size=16384):
        # A real subprocess emits a complete receipt; no transport/perf run is needed.
        script = (
            f"#!{sys.executable}\n"
            "import json, sys\n"
            "from pathlib import Path\n"
            "size = int(sys.argv[2])\n"
            "print('BENCH_RESULT ' + json.dumps(dict(status='complete', bytes=size, "
            "verified_bytes=size, source_sha256='fixture', receiver_sha256='fixture', "
            "transfer_until_visible_ns=100, transfer_until_ready_ns=123, "
            "publish_to_visible_ns=200, publish_to_settled_ns=223)))\n"
        )
        if change_source:
            script += f"Path({str(self.example)!r}).write_text('// changed during run\\n')\n"
        self.binary.write_text(script)
        self.binary.chmod(0o700)
        argv = ["blob_benchmark", "--variant", "fixture", str(self.repo), str(self.binary),
                "--output", str(self.output), "--state", str(self.root / "state"),
                "--campaign", campaign_name, "--sizes", str(size)]
        with patch.object(sys, "argv", argv):
            main()

    def test_matching_identity_publishes_read_back_summaries(self):
        self.run_fixture()
        before = json.loads((self.output / "metadata.json").read_text())["variants"]
        after = json.loads((self.output / "source-after.json").read_text())
        self.assertEqual(before, after)
        expected = [{"variant": "fixture", "bytes": 16384, "samples": 1,
                     "completed": 1, "visible_median_ns": 100,
                     "settled_median_ns": 123,
                     "publish_to_visible_median_ns": 200}]
        self.assertEqual(json.loads((self.output / "summary.json").read_text()), expected)
        with (self.output / "summary.csv").open(newline="") as source:
            self.assertEqual(list(csv.DictReader(source)),
                             [{key: str(value) for key, value in expected[0].items()}])

    def test_identity_mismatch_retains_evidence_without_publishing_summaries(self):
        with self.assertRaisesRegex(ValueError, "source or binary changed"):
            self.run_fixture(change_source=True)
        before = json.loads((self.output / "metadata.json").read_text())["variants"]
        after = json.loads((self.output / "source-after.json").read_text())
        self.assertNotEqual(before, after)
        self.assertEqual(len(list(self.output.glob("fixture-*.json"))), 1)
        for name in ("summary.json", "summary.csv"):
            with self.subTest(name=name):
                self.assertFalse((self.output / name).exists())

    def test_scale_campaign_selects_100_mib_and_records_profile(self):
        self.run_fixture(campaign_name="scale", size=100 * 1024 * 1024)
        metadata = json.loads((self.output / "metadata.json").read_text())
        self.assertEqual(metadata["campaign"], "scale")
        self.assertEqual(
            metadata["cases"],
            [[f"{100 * 1024 * 1024}-1", 100 * 1024 * 1024, 300]],
        )

    def test_campaign_rejects_a_size_not_listed_in_the_selected_profile(self):
        argv = [
            "blob_benchmark",
            "--variant", "fixture", str(self.repo), str(self.binary),
            "--output", str(self.output),
            "--state", str(self.root / "state"),
            "--campaign", "scale",
            "--sizes", "16384",
        ]
        with patch.object(sys, "argv", argv), self.assertRaises(SystemExit) as error:
            main()
        self.assertEqual(error.exception.code, 2)
        self.assertFalse(self.output.exists())



class Results(unittest.TestCase):
    def test_campaign_is_exactly_four_small_single_samples(self):
        self.assertEqual(campaign(), [(f"{size}-1", size, 300)
                                    for size in (16384, 65536, 262144, 1048576)])

    def test_scale_campaign_is_exactly_one_100_mib_sample(self):
        size = 100 * 1024 * 1024
        self.assertEqual(campaign("scale"), [(f"{size}-1", size, 300)])

    def test_profile5_campaign_is_exactly_one_gib_with_a_large_transfer_deadline(self):
        size = 1024 * 1024 * 1024
        self.assertEqual(campaign("profile5-1g"), [(f"{size}-1", size, 900)])

    def test_summary_counts_timeouts_but_never_pools_their_elapsed_time(self):
        runs = []
        for status, ns in [("complete", 30), ("complete", 10), ("transfer_timeout", 900)]:
            runs.append({"variant": "baseline", "exit_code": 0, "records": [{"type": "BENCH_RESULT", "data": {"status": status, "bytes": 8, "transfer_until_visible_ns": ns - 2, "transfer_until_ready_ns": ns, "publish_to_visible_ns": ns + 8}}]})
        rows = summarize(runs)
        self.assertEqual(rows, [{"variant": "baseline", "bytes": 8, "samples": 3,
                                "completed": 2, "visible_median_ns": 18,
                                "settled_median_ns": 20,
                                "publish_to_visible_median_ns": 28}])

    def test_missing_duplicate_and_unverified_results_fail_closed(self):
        for text in ["", 'BENCH_RESULT {"status":"transfer_timeout"}\n' * 2,
                     'BENCH_RESULT {"status":"complete","bytes":8,"verified_bytes":7,"source_sha256":"a","receiver_sha256":"b"}\n']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_records(text)

    def test_timeout_never_becomes_completed_throughput(self):
        records = parse_records('BENCH_RESULT {"status":"transfer_timeout","bytes":64,"transfer_ns":null,"verification_ns":null,"fetched_carrier_bytes":12}\n')
        self.assertEqual(records[-1]["data"]["status"], "transfer_timeout")
        self.assertIsNone(records[-1]["data"]["transfer_ns"])


if __name__ == "__main__":
    unittest.main()
