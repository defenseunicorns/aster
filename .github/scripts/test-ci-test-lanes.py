#!/usr/bin/env python3
"""Regression tests for bounded required and full scheduled test lanes."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"
FULL_MACOS_WORKFLOW = ROOT / ".github/workflows/macos-full.yml"
MACOS_COMPATIBILITY = ROOT / "tools/test-macos-compatibility.sh"
NEXTEST_CONFIG = ROOT / ".config/nextest.toml"
MISE_CONFIG = ROOT / "mise.toml"


def workflow_job(workflow: str, job: str, next_job: str) -> str:
    return workflow.split(f"  {job}:\n", 1)[1].split(f"\n  {next_job}:\n", 1)[0]


def mise_task(config: str, task: str) -> str:
    return config.split(f"[tasks.{task}]\n", 1)[1].split("\n[tasks.", 1)[0]


class RequiredMacosLaneTests(unittest.TestCase):
    def test_required_lane_compiles_every_target_then_runs_platform_contracts(self):
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        lane = workflow_job(workflow, "macos-tests", "rust-clippy")

        self.assertIn("name: macOS compatibility", lane)
        self.assertIn("runs-on: macos-15", lane)
        self.assertIn("timeout-minutes: 15", lane)
        self.assertIn("run: sh tools/test-macos-compatibility.sh", lane)
        self.assertNotIn(
            "cargo +1.97.1 test --locked --workspace --all-features\n",
            lane,
        )
        for duplicate in (
            "test_aster_tour_ui.py",
            "test_aster_mesh_playground.py",
            "test-linux-event-mvp-qualification.py",
            "test-aster-mesh-playground-real.sh",
        ):
            self.assertNotIn(duplicate, lane)

    def test_compatibility_runner_rejects_non_macos_hosts_before_cargo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "uname").write_text("#!/bin/sh\nprintf 'Linux\\n'\n")
            (root / "uname").chmod(0o700)
            cargo_log = root / "cargo-log"
            (root / "cargo").write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CARGO_LOG\"\n"
            )
            (root / "cargo").chmod(0o700)
            result = subprocess.run(
                ["sh", str(MACOS_COMPATIBILITY)],
                cwd=ROOT,
                env={
                    **os.environ,
                    "PATH": directory + os.pathsep + os.environ["PATH"],
                    "CARGO_LOG": str(cargo_log),
                },
                capture_output=True,
                text=True,
                timeout=15,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires macOS", result.stderr)
        self.assertFalse(cargo_log.exists(), "non-macOS host invoked Cargo")

    def test_compatibility_runner_compiles_workspace_and_selects_contracts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "uname").write_text("#!/bin/sh\nprintf 'Darwin\\n'\n")
            (root / "uname").chmod(0o700)
            cargo_log = root / "cargo-log"
            (root / "cargo").write_text(
                "#!/bin/sh\n"
                "printf '%s|%s\\n' \"${CARGO_TARGET_DIR:-unset}\" "
                "\"$*\" >> \"$CARGO_LOG\"\n"
            )
            (root / "cargo").chmod(0o700)
            result = subprocess.run(
                ["sh", str(MACOS_COMPATIBILITY)],
                cwd=ROOT,
                env={
                    **os.environ,
                    "PATH": directory + os.pathsep + os.environ["PATH"],
                    "CARGO_LOG": str(cargo_log),
                },
                capture_output=True,
                text=True,
                timeout=15,
            )
            commands = cargo_log.read_text().splitlines()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(commands), 4)
        target_roots = [command.split("|", 1)[0] for command in commands]
        arguments = [command.split("|", 1)[1] for command in commands]
        self.assertTrue(target_roots[0].endswith("/systemd-workspace"))
        self.assertTrue(target_roots[1].endswith("/compose-package"))
        self.assertEqual(target_roots[2:], target_roots[:2])
        self.assertIn(
            "--workspace --all-features --exclude aster-compose-credentials",
            arguments[0],
        )
        self.assertIn("-p aster-compose-credentials --all-features", arguments[1])
        self.assertTrue(all("--no-run" in command for command in arguments[:2]))
        self.assertNotIn("--no-run", arguments[2])
        self.assertNotIn("--no-run", arguments[3])
        self.assertTrue(all("platform_compat_" in command for command in arguments[2:]))
        self.assertIn(
            "--workspace --all-features --exclude aster-compose-credentials",
            arguments[2],
        )
        self.assertIn("-p aster-compose-credentials --all-features", arguments[3])


class FullMacosLaneTests(unittest.TestCase):
    def test_full_suite_is_non_required_and_scheduled(self):
        workflow = FULL_MACOS_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("schedule:", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("runs-on: macos-15", workflow)
        self.assertIn("timeout-minutes: 30", workflow)
        self.assertIn(
            "cargo +1.97.1 test --locked --workspace --all-features",
            workflow,
        )
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("merge_group:", workflow)


class RustTimingLaneTests(unittest.TestCase):
    def test_required_ci_never_selects_ignored_qualifications(self):
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        self.assertNotIn("--run-ignored", workflow)

    def test_mesh_qualification_tasks_are_exact_serial_ignored_only_runs(self):
        config = MISE_CONFIG.read_text(encoding="utf-8")
        control = mise_task(config, "qualify-control-mesh")
        ping_pong = mise_task(config, "qualify-ping-pong-mesh")

        for task in (control, ping_pong):
            self.assertIn("sh tools/with-test-resources.sh cargo nextest run", task)
            self.assertIn("--locked -p aster-node --all-features --test mesh_cli", task)
            self.assertIn("--run-ignored ignored-only", task)
            self.assertIn("--test-threads 1", task)

        control_test = (
            "four_real_processes_propagate_controls_without_authority_"
            "and_exclude_captured_leaf"
        )
        self.assertIn(f"-E 'test(={control_test})'", control)
        self.assertEqual(control.count("test(="), 1)
        self.assertIn(
            "-E 'test(=two_real_processes_use_the_same_stopped_state_ping_pong_plan) "
            "| test(=four_real_processes_default_to_ping_pong_and_restart_cleanly)'",
            ping_pong,
        )
        self.assertEqual(ping_pong.count("test(="), 2)

    def test_documented_ci_slices_and_scale_qualifications_match_required_selection(self):
        config = MISE_CONFIG.read_text(encoding="utf-8")

        for partition in (1, 2):
            task = mise_task(config, f"check-rust-ci-slice-{partition}")
            self.assertIn("sh tools/with-test-resources.sh cargo nextest run", task)
            self.assertIn("--profile ci --locked --workspace --all-features", task)
            self.assertIn("--test-threads 2", task)
            self.assertIn(f"--partition slice:{partition}/2", task)
            self.assertNotIn("--run-ignored", task)

        blob = mise_task(config, "qualify-generated-blob")
        self.assertIn("sh tools/with-test-resources.sh cargo nextest run", blob)
        self.assertIn("--locked -p aster-core --all-features", blob)
        self.assertIn("--run-ignored ignored-only", blob)
        self.assertIn(
            "test(=blob::tests::qualify_generated_100mb_blob_pipeline)", blob
        )

        for task_name, test_name in (
            (
                "qualify-local-blob-above-network-limit",
                "runtime::tests::qualify_valid_local_blob_above_network_limit",
            ),
            (
                "qualify-near-two-mib-events",
                "runtime::tests::qualify_current_stack_near_two_mib_events_each_direction",
            ),
        ):
            task = mise_task(config, task_name)
            self.assertIn("sh tools/with-test-resources.sh cargo nextest run", task)
            self.assertIn("--locked -p aster-node --all-features --lib", task)
            self.assertIn("--run-ignored ignored-only", task)
            self.assertIn("--test-threads 1", task)
            self.assertIn(f"-E 'test(={test_name})'", task)

    def test_partition_lane_retains_raw_timings_and_publishes_slowest_tests(self):
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        lane = workflow_job(workflow, "rust-tests", "msrv")

        self.assertIn("--profile ci", lane)
        self.assertIn("python3 .github/scripts/summarize-nextest-junit.py", lane)
        self.assertIn("$GITHUB_STEP_SUMMARY", lane)
        self.assertIn("--problem-seconds 10", lane)
        self.assertIn("--github-annotations", lane)
        self.assertIn("No JUnit report was produced", lane)
        self.assertIn("exit 1", lane)
        self.assertIn(
            "uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
            lane,
        )
        self.assertIn("target/nextest/ci/junit.xml", lane)
        self.assertIn("if-no-files-found: error", lane)
        self.assertIn("retention-days: 14", lane)

    def test_ci_profile_emits_bounded_junit_without_success_output(self):
        config = NEXTEST_CONFIG.read_text(encoding="utf-8")

        self.assertIn("[profile.ci]", config)
        self.assertIn('inherits = "default"', config)
        self.assertIn("fail-fast = false", config)
        self.assertIn("[profile.ci.junit]", config)
        self.assertIn('path = "junit.xml"', config)
        self.assertIn("store-success-output = false", config)
        self.assertIn("store-failure-output = true", config)
        self.assertIn('report-skipped = "none"', config)


class QualityLaneTests(unittest.TestCase):
    def test_fuzz_lane_installs_the_linux_bluez_build_prerequisite(self):
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        fuzz = workflow_job(workflow, "fuzz-smoke", "required")

        self.assertIn("- *install-linux-bluez-build-prerequisite", fuzz)

    def test_quality_reuses_foundation_core_without_repeating_gated_checks(self):
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        quality = workflow_job(workflow, "quality", "cargo-lockfiles")
        mise = MISE_CONFIG.read_text(encoding="utf-8")
        core = mise.split("[tasks.check-foundation-core]\n", 1)[1].split(
            "\n[tasks.check-compose-policy]", 1
        )[0]

        self.assertIn("needs: cargo-lockfiles", quality)
        self.assertIn("mise run check-foundation-core", quality)
        self.assertNotIn("mise run check-foundation\n", quality)
        self.assertEqual(quality.count("test_aster_compose_delivery.py"), 1)
        self.assertEqual(quality.count("test_inspect_aster_compose_oci.py"), 1)
        self.assertNotIn("check-cargo-lockfiles", core)
        self.assertNotIn("test-check-cargo-lockfiles", core)
        self.assertNotIn("test_aster_compose_delivery.py", core)
        self.assertNotIn("test_inspect_aster_compose_oci.py", core)

    def test_local_foundation_aggregate_keeps_lockfile_and_core_coverage(self):
        mise = MISE_CONFIG.read_text(encoding="utf-8")
        foundation = mise.split("[tasks.check-foundation]\n", 1)[1].split(
            "\n[tasks.check-lockfiles]", 1
        )[0]
        lockfiles = mise.split("[tasks.check-lockfiles]\n", 1)[1].split(
            "\n[tasks.check-foundation-core]", 1
        )[0]

        self.assertIn('{ task = "check-lockfiles" }', foundation)
        self.assertIn('{ task = "check-foundation-core" }', foundation)
        self.assertIn('{ task = "check-compose-policy" }', foundation)
        self.assertIn("sh tools/check-cargo-lockfiles.sh", lockfiles)
        self.assertIn("python3 tools/test-check-cargo-lockfiles.py", lockfiles)


if __name__ == "__main__":
    unittest.main()
