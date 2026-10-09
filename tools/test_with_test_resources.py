#!/usr/bin/env python3
import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "tools" / "with-test-resources.sh"


class WorkspaceCargoSplitTests(unittest.TestCase):
    def run_wrapper(self, arguments: list[str]) -> tuple[list[tuple[str, list[str]]], pathlib.Path]:
        with tempfile.TemporaryDirectory(prefix="aster-resource-wrapper-") as temporary:
            root = pathlib.Path(temporary)
            log = root / "cargo.log"
            fake_cargo = root / "cargo"
            fake_cargo.write_text(
                "#!/bin/sh\n"
                "printf '%s\\t' \"${CARGO_TARGET_DIR-}\" >> \"$ASTER_CARGO_LOG\"\n"
                "printf '%s ' \"$@\" >> \"$ASTER_CARGO_LOG\"\n"
                "printf '\\n' >> \"$ASTER_CARGO_LOG\"\n",
                encoding="utf-8",
            )
            fake_cargo.chmod(0o700)
            target = root / "target-cache"
            environment = os.environ.copy()
            environment.update(
                {
                    "ASTER_CARGO_LOG": str(log),
                    "CARGO_TARGET_DIR": str(target),
                    "PATH": f"{root}{os.pathsep}{environment['PATH']}",
                }
            )
            subprocess.run(
                ["sh", str(WRAPPER), *arguments],
                cwd=ROOT,
                env=environment,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            records = []
            for line in log.read_text(encoding="utf-8").splitlines():
                target_dir, argv = line.split("\t", 1)
                records.append((target_dir, argv.split()))
            return records, target

    def test_supported_workspace_forms_split_without_skipping_either_package(self) -> None:
        cases = [
            ["cargo", "test", "--locked", "--workspace", "--all-features"],
            ["cargo", "+1.97.1", "test", "--locked", "--workspace", "--all-features"],
            [
                "cargo",
                "test",
                "--offline",
                "--locked",
                "--no-run",
                "--workspace",
                "--all-features",
            ],
            [
                "cargo",
                "+1.97.1",
                "test",
                "--all-features",
                "--workspace",
                "--no-run",
                "--offline",
                "--locked",
            ],
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                records, target = self.run_wrapper(arguments)
                self.assertEqual(len(records), 2)
                self.assertEqual(
                    {records[0][0], records[1][0]},
                    {
                        str(target / "systemd-workspace"),
                        str(target / "compose-package"),
                    },
                )
                first, second = (records[0][1], records[1][1])
                toolchain = ["+1.97.1"] if "+1.97.1" in arguments else []
                optional = [flag for flag in ["--offline", "--no-run"] if flag in arguments]
                self.assertEqual(
                    first,
                    toolchain
                    + ["test", "--locked", *optional, "--workspace", "--all-features", "--exclude", "aster-compose-credentials"],
                )
                self.assertEqual(
                    second,
                    toolchain
                    + ["test", "--locked", *optional, "-p", "aster-compose-credentials", "--all-features"],
                )

    def test_unrelated_cargo_shape_is_executed_once_without_rewriting(self) -> None:
        arguments = ["cargo", "test", "--locked", "-p", "aster-agent"]
        records, target = self.run_wrapper(arguments)
        self.assertEqual(records, [(str(target), arguments[1:])])


if __name__ == "__main__":
    unittest.main()
