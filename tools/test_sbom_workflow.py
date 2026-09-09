#!/usr/bin/env python3
"""Exercise the artifact workflow's failure handling with deterministic tool doubles."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SbomWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        for name in ("Cargo.toml", "Cargo.lock", "LICENSE"):
            shutil.copy2(ROOT / name, self.repo / name)
        for folder in ("tools", "third-party"):
            (self.repo / folder).mkdir()
        shutil.copy2(ROOT / "tools/check-netlink-packet-core-patch.py", self.repo / "tools")
        shutil.copytree(ROOT / "third-party/netlink-packet-core-0.8.2-aster",
                        self.repo / "third-party/netlink-packet-core-0.8.2-aster")
        (self.repo / ".gitignore").write_text("/target/\n")
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
        self.bin = Path(self.temp.name) / "bin"
        self.bin.mkdir()
        self.tool("cargo", '''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
mode = os.environ.get("FAIL_MODE", "")
if "--version" in args:
    print("cargo-cyclonedx 0.5.9" if "cyclonedx" in args else "cargo 1.97.1")
elif args[0] == "build":
    if mode == "build": sys.exit("forced build failure")
    out = pathlib.Path(os.environ["CARGO_TARGET_DIR"]) / "x86_64-unknown-linux-gnu/release"
    out.mkdir(parents=True, exist_ok=True)
    for name in ["aster", "aster-agent"]:
        f = out / name
        f.write_text("#!/bin/sh\\nexit 0\\n")
        f.chmod(0o755)
elif args[0] == "cyclonedx":
    if mode == "generator": sys.exit("forced generator failure")
    if mode == "lock": pathlib.Path("Cargo.lock").write_text("changed")
    for package, name in [("aster-node", "aster"), ("aster-agent", "aster-agent")]:
        if mode == "missing" and name == "aster-agent": continue
        out = pathlib.Path("crates") / package
        out.mkdir(parents=True, exist_ok=True)
        doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
               "metadata": {"component": {"name": name}},
               "components": [{"name": "example", "licenses": [{"expression": "MIT"}]}]}
        if mode == "root": doc["metadata"]["component"]["name"] = "wrong"
        if mode == "licenses": doc["components"][0].pop("licenses")
        (out / (name + "_bin.cdx.json")).write_text(json.dumps(doc))
else: sys.exit("unexpected cargo command")
''')
        self.tool("rustc", "#!/bin/sh\necho 'rustc 1.97.1 (fixture)'\n")
        self.tool("cdx-ev", '''#!/bin/sh
if [ "$1" = --version ]; then echo 'cdx-ev, version 0.34.0'; exit 0; fi
if [ "${FAIL_MODE:-}" = validator ]; then echo "forced validator failure" >&2; exit 9; fi
''')
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"])
        self.env.pop("CARGO_TARGET_DIR", None)
        self.output = self.repo / "target/sbom/aster-linux-x86_64.tar"

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True,
                              capture_output=True, text=True)

    def tool(self, name, source):
        path = self.bin / name
        path.write_text(source)
        path.chmod(0o755)

    def run_workflow(self, mode=""):
        return subprocess.run(["bash", str(ROOT / "tools/build-sbom.sh")], cwd=self.repo,
                              env=dict(self.env, FAIL_MODE=mode), text=True, capture_output=True)

    def test_bundle_contains_executables_sboms_and_current_patch_source(self):
        result = self.run_workflow()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with tarfile.open(self.output) as bundle:
            names = {m.name.removeprefix("./") for m in bundle.getmembers()}
            self.assertTrue({"aster", "aster-agent", "aster.cdx.json", "aster-agent.cdx.json",
                             "SHA256SUMS", "BUILD.txt", "SCOPE.txt", "LICENSE",
                             "netlink-packet-core-0.8.2-aster.tar"} <= names)
            self.assertTrue(bundle.getmember("./aster").mode & 0o111)
            destination = Path(self.temp.name) / "unpacked"
            bundle.extractall(destination, filter="data")
        checked = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=destination,
                                 capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        self.assertIn(self.git("rev-parse", "HEAD").stdout.strip(),
                      (destination / "BUILD.txt").read_text())
        self.assertFalse((self.repo / "crates").exists(), "generator must use a source snapshot")

    def test_failures_never_leave_a_publishable_stale_bundle(self):
        for mode in ("build", "generator", "lock", "missing", "validator", "root", "licenses"):
            with self.subTest(mode=mode):
                self.output.parent.mkdir(parents=True, exist_ok=True)
                self.output.write_text("stale bundle")
                result = self.run_workflow(mode)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                messages = {"build": "forced build failure", "generator": "forced generator failure",
                            "lock": "Cargo.lock: FAILED", "missing": "aster-agent_bin.cdx.json",
                            "validator": "forced validator failure", "root": "wrong application root",
                            "licenses": "license declarations are missing"}
                self.assertIn(messages[mode], result.stdout + result.stderr)
                self.assertFalse(self.output.exists(), mode)
                self.assertEqual((self.repo / "Cargo.lock").read_bytes(), (ROOT / "Cargo.lock").read_bytes())

    def test_modified_tracked_source_is_rejected(self):
        (self.repo / "Cargo.toml").write_text("modified")
        result = self.run_workflow()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("commit", result.stderr.lower())
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
