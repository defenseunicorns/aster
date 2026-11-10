import hashlib
import base64
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "gate_h_faults.py"
SPEC = importlib.util.spec_from_file_location("aster_gate_h_faults", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
faults = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = faults
SPEC.loader.exec_module(faults)


def signature_cli_args():
    return [
        "--git-binary",
        "/tmp/git",
        "--ssh-keygen-binary",
        "/tmp/ssh-keygen",
        "--ssh-binary",
        "/tmp/ssh",
        "--allowed-signers",
        "/tmp/allowed-signers",
        "--signer-principal",
        "gate-h@example.test",
    ]


def make_signature_request(root: Path):
    tools = {}
    for name in ("git", "ssh-keygen", "ssh"):
        path = root / name
        path.write_bytes(f"fixture {name}\n".encode("utf-8"))
        path.chmod(0o700)
        tools[name] = path
    allowed_signers = root / "allowed-signers"
    allowed_signers.write_text(
        "gate-h@example.test ssh-ed25519 AAAATEST gate-h\n",
        encoding="utf-8",
    )
    return faults.gate_h_signature.SignatureRequest(
        git=tools["git"],
        ssh_keygen=tools["ssh-keygen"],
        ssh=tools["ssh"],
        allowed_signers=allowed_signers,
        principal="gate-h@example.test",
    )


def signed_module_fixture(root: Path, *, materialized: bool):
    files = []
    paths = {}
    for name, relative in faults.REEXEC_MODULE_PATHS.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        value = f"signed {name}\n".encode("utf-8")
        path.write_bytes(value)
        path.chmod(0o444 if materialized else 0o644)
        paths[name] = path
        files.append(
            {
                "path": relative,
                "mode": "100644",
                "git_blob": "a" * 40,
                "size_bytes": len(value),
                "sha256": hashlib.sha256(value).hexdigest(),
            }
        )
    return {"files": files}, paths


def signature_runner(state, calls):
    def run(argv, *, environment, stdin_value, timeout_seconds, context):
        del timeout_seconds
        calls.append(
            {
                "argv": list(argv),
                "environment": dict(environment),
                "stdin_value": stdin_value,
                "context": context,
            }
        )
        if argv[-1:] == ["-V"]:
            stdout = b""
            stderr = b"OpenSSH_9.9p1, LibreSSL 3.3.6\n"
        elif "-lf" in argv:
            stdout = (
                "256 "
                f"{state.get('allowed_fingerprint', 'SHA256:fixturefp')} "
                "gate-h@example.test (ED25519)\n"
            ).encode("utf-8")
            stderr = b""
        elif "for-each-ref" in argv:
            stdout = state.get("replacement_refs", b"")
            stderr = b""
        elif "config" in argv:
            stdout = state.get(
                "local_config", b"core.repositoryformatversion\n0\0"
            )
            stderr = b""
        elif "verify-commit" in argv:
            stdout = b""
            stderr = b"Good signature for gate-h@example.test\n"
        elif "log" in argv:
            stdout = (
                f"{state.get('status', 'G')}\0"
                f"{state.get('principal', 'gate-h@example.test')}\0"
                f"{state.get('fingerprint', 'SHA256:fixturefp')}\n"
            ).encode("utf-8")
            stderr = b""
        else:
            raise AssertionError(f"unexpected signature command: {argv}")
        receipt = {
            "context": context,
            "argv": list(argv),
            "cwd": str(faults.WORKSPACE),
            "environment": dict(environment),
            "stdin_mode": "devnull",
            "stdin_sha256": faults.sha256_bytes(b""),
            "stdin": faults.complete_stream(b""),
            "started_utc": "2026-08-21T00:00:00Z",
            "completed_utc": "2026-08-21T00:00:00Z",
            "duration_ms": 0,
            "timed_out": False,
            "returncode": 0,
            "terminal_returncode": 0,
            "process_group_reaped": True,
            "stdout_sha256": faults.sha256_bytes(stdout),
            "stderr_sha256": faults.sha256_bytes(stderr),
            "stdout": faults.complete_stream(stdout),
            "stderr": faults.complete_stream(stderr),
            "execution_error": None,
            "interrupted": False,
        }
        return receipt, stdout, stderr

    return run


class GateHFaultTests(unittest.TestCase):
    @staticmethod
    def passing_execution_provenance():
        environment = {
            key: f"test-{key.lower()}" for key in faults.FORMAL_ENVIRONMENT_KEYS
        }
        return {
            "passed": True,
            "environment": environment,
            "tools": {"cargo": {"path": "cargo"}},
        }

    @staticmethod
    def passing_signed_source_preparer(_freeze, execution, _timeout):
        receipt = {
            "passed": True,
            "export": {"path": str(faults.WORKSPACE)},
        }
        execution["signed_source"] = receipt
        execution["formal_feature_graph"] = {"passed": True}
        return receipt

    @staticmethod
    def passing_static_checks(_freeze):
        return {
            name: {
                "name": name,
                "argv": ["cargo", "tree"],
                "source_files": [],
                "source_region": None,
                "assertion": {"kind": "exact_count", "count": 1},
                "expected_returncode": 0,
                "passed": True,
            }
            for name in faults.STATIC_CHECK_NAMES
        }

    @staticmethod
    def passing_test_executable_build(_freeze, _timeout):
        executables = {
            package: {
                    "package": package,
                    "target_name": target,
                    "path": f"/tmp/{target}",
                    "sha256": (str(index) * 64),
                    "size_bytes": 1,
            }
            for index, (package, target) in enumerate(
                faults.TEST_TARGET_NAMES.items(), start=1
            )
        }
        return {
            "builds": {
                package: {
                    "package": package,
                    "argv": [
                        "cargo",
                        "test",
                        "--locked",
                        "-p",
                        package,
                        "--lib",
                        *faults.TEST_PACKAGE_FEATURE_ARGS[package],
                        "--no-run",
                        "--message-format=json",
                    ],
                    "source_files_sha256": "f" * 64,
                    "passed": True,
                }
                for package in faults.TEST_TARGET_NAMES
            },
            "executables": executables,
            "passed": True,
        }

    @staticmethod
    def passing_executable_verifier(binding):
        return binding.get("sha256")

    @staticmethod
    def passing_executed_binary_parser(command):
        return f"/tmp/{faults.TEST_TARGET_NAMES[command['package']]}"

    def test_fixed_plan_covers_every_mandatory_case_with_exact_filters(self):
        plan = faults.command_plan()
        self.assertEqual(faults.SCHEMA, "aster-gate-h-deterministic-faults/v2")
        self.assertEqual({entry["case"] for entry in plan}, faults.EXPECTED_CASES)
        self.assertEqual(len(faults.EXPECTED_CASES), 25)
        self.assertEqual(len(faults.TEST_SPECS), 40)
        self.assertEqual(len(plan), len(faults.TEST_SPECS))
        observed_case_counts = {
            case: sum(entry["case"] == case for entry in plan)
            for case in faults.EXPECTED_CASES
        }
        self.assertEqual(
            observed_case_counts,
            {
                "admission_authorization_failure": 1,
                "admission_panic_rollback": 2,
                "admission_resource_failure": 2,
                "admission_single_use": 4,
                "blob_quota_race": 1,
                "factory_panic_rollback": 1,
                "full_vector_connection_churn": 1,
                "identity_and_allowlist_conflicts": 5,
                "late_host_commit_rollback": 1,
                "lifecycle_replace_without_double_charge": 1,
                "mixed_bridge_control": 2,
                "mixed_ordinary_control": 2,
                "native_restart_replacement": 1,
                "parallel_resource_limits": 1,
                "peer_neutral_resume_unavailable_peer": 1,
                "process_owned_durable_item_probe": 2,
                "post_auth_capacity_rollback": 1,
                "preauthentication_cancellation": 2,
                "preauthentication_timeout": 2,
                "queued_generation_invalidation_and_recovery": 1,
                "reservation_precedes_allocation": 1,
                "runtime_commit_error_generation": 2,
                "supervisor_duplicate_no_cascade": 1,
                "supervisor_generation_cascade": 1,
                "unwind_resource_release": 1,
            },
        )
        self.assertEqual(
            len({(entry["package"], entry["test_name"]) for entry in plan}),
            len(plan),
        )
        test_names = {entry["test_name"] for entry in plan}
        self.assertIn(
            "mesh_host::tests::duplicate_candidate_never_publishes_peer_or_carrier_before_admission_commit",
            test_names,
        )
        self.assertNotIn(
            "mesh_host::tests::carrier_identity_cannot_be_reused_across_aster_peers",
            test_names,
        )
        self.assertEqual(
            dict(faults.TEST_PACKAGE_FEATURE_ARGS),
            {
                "aster-core": (
                    "--no-default-features",
                    "--features",
                    "adapter-sdk",
                ),
                "aster-host": (
                    "--no-default-features",
                    "--features",
                    "gate-h-formal",
                ),
                "aster-lab": (
                    "--no-default-features",
                    "--features",
                    "gate-h",
                ),
            },
        )
        with self.assertRaises(TypeError):
            faults.TEST_PACKAGE_FEATURE_ARGS["aster-host"] = (  # type: ignore[index]
                "--features",
                "default",
            )
        for entry in plan:
            self.assertEqual(entry["argv"][0:3], ["cargo", "test", "--locked"])
            self.assertIn("--lib", entry["argv"])
            package = entry["package"]
            self.assertEqual(
                entry["argv"][6:9],
                list(faults.TEST_PACKAGE_FEATURE_ARGS[package]),
            )
            self.assertEqual(
                entry["argv"][-3:],
                ["--exact", "--nocapture", "--test-threads=1"],
            )
            self.assertEqual(entry["argv"][-5], entry["test_name"])

    def test_source_freeze_binds_direct_engine_store_and_binary_entrypoint_sources(self):
        self.assertIn("crates/aster-core/src/engine.rs", faults.SOURCE_PATHS)
        self.assertIn("crates/aster-core/src/store.rs", faults.SOURCE_PATHS)
        self.assertIn("crates/aster-core/src/sync.rs", faults.SOURCE_PATHS)
        self.assertIn("docs/protocol.md", faults.SOURCE_PATHS)
        self.assertIn("rust-toolchain.toml", faults.SOURCE_PATHS)
        self.assertIn("mise.toml", faults.SOURCE_PATHS)
        self.assertIn("crates/aster-lab/src/main.rs", faults.SOURCE_PATHS)
        self.assertIn("crates/aster-lab/src/gate_h_main.rs", faults.SOURCE_PATHS)
        self.assertIn("crates/aster-ip/Cargo.toml", faults.SOURCE_PATHS)
        self.assertIn("crates/aster-ip/src/bin/aster-relay.rs", faults.SOURCE_PATHS)
        self.assertIn("crates/aster-ip/src/lib.rs", faults.SOURCE_PATHS)
        self.assertIn("crates/aster-ip/src/relay.rs", faults.SOURCE_PATHS)
        self.assertIn("lab/Dockerfile", faults.SOURCE_PATHS)
        self.assertIn("lab/gate_h_signature.py", faults.SOURCE_PATHS)
        self.assertIn("lab/gate_h_source.py", faults.SOURCE_PATHS)
        self.assertIn("lab/tests/test_gate_h_source.py", faults.SOURCE_PATHS)

    def test_signature_trust_binds_exact_tools_signers_config_and_ssh_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            request = make_signature_request(root)
            frozen = root / "frozen"
            frozen.mkdir()
            state = {}
            calls = []
            base_environment = {"HOME": str(root), "PATH": "/usr/bin:/bin"}
            trust = faults.gate_h_signature.prepare_signature_trust(
                request,
                workspace=faults.WORKSPACE,
                frozen_directory=frozen,
                base_environment=base_environment,
                run_command=signature_runner(state, calls),
            )
            self.assertEqual(trust["schema"], faults.gate_h_signature.SCHEMA)
            self.assertEqual(trust["principal"], request.principal)
            self.assertTrue(trust["passed"])
            self.assertEqual(set(trust["tools"]), {"git", "ssh", "ssh-keygen"})
            for name, binding in trust["tools"].items():
                self.assertEqual(binding["invocation"], str(getattr(request, name.replace("-", "_"))))
                self.assertTrue(Path(binding["path"]).is_absolute())
                self.assertEqual(
                    binding["sha256"], faults.gate_h_signature.sha256_file(Path(binding["path"]))
                )
            allowed = trust["allowed_signers"]
            self.assertEqual(
                base64.b64decode(allowed["base64"]), request.allowed_signers.read_bytes()
            )
            self.assertEqual(
                Path(allowed["frozen_path"]).read_bytes(), request.allowed_signers.read_bytes()
            )
            self.assertEqual(
                Path(allowed["frozen_path"]).stat().st_mode & 0o777, 0o400
            )
            self.assertEqual(
                trust["git_config"],
                [
                    {"key": "gpg.format", "value": "ssh"},
                    {
                        "key": "gpg.ssh.program",
                        "value": trust["tools"]["ssh-keygen"]["path"],
                    },
                    {
                        "key": "gpg.ssh.allowedSignersFile",
                        "value": allowed["frozen_path"],
                    },
                    {"key": "gpg.ssh.revocationFile", "value": "/dev/null"},
                    {"key": "gpg.minTrustLevel", "value": "fully"},
                ],
            )
            self.assertEqual(
                trust["git_environment"],
                {**base_environment, **faults.gate_h_signature.GIT_ENVIRONMENT},
            )
            self.assertEqual(trust["allowed_signer_fingerprints"], ["SHA256:fixturefp"])
            ssh_call = next(
                call for call in calls if call["context"] == "signature-trust:ssh-version"
            )
            self.assertEqual(
                ssh_call["argv"], [trust["tools"]["ssh"]["path"], "-V"]
            )
            local_call = next(
                call for call in calls if call["context"] == "signature-trust:local-config"
            )
            self.assertEqual(
                local_call["argv"][-5:],
                ["config", "--local", "--no-includes", "--null", "--list"],
            )
            exact = faults.gate_h_signature.git_argv(trust, ["status", "--porcelain"])
            self.assertEqual(exact[0], trust["tools"]["git"]["path"])
            self.assertEqual(exact[1], "--no-replace-objects")
            self.assertEqual(exact[-2:], ["status", "--porcelain"])
            self.assertIn(
                f"gpg.ssh.allowedSignersFile={allowed['frozen_path']}", exact
            )

    def test_signature_trust_rejects_local_controls_inputs_and_interruptions(self):
        signature = faults.gate_h_signature
        for config_key in (
            "include.path",
            "includeIf.gitdir:/tmp.path",
            "core.worktree",
            "core.useReplaceRefs",
            "extensions.worktreeConfig",
            "gpg.format",
            "gpg.ssh.revocationFile",
            "gpg.minTrustLevel",
            "user.signingKey",
        ):
            with self.subTest(config_key=config_key):
                with self.assertRaisesRegex(
                    signature.SignatureTrustError, "verification controls"
                ):
                    signature.parse_local_config(
                        f"{config_key}\nmalicious\0".encode("utf-8")
                    )
        with self.assertRaisesRegex(signature.SignatureTrustError, "Git controls"):
            signature.git_environment({"GIT_CONFIG_GLOBAL": "/tmp/ambient"})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            request = make_signature_request(root)
            symlink = root / "allowed-link"
            symlink.symlink_to(request.allowed_signers)
            bad_request = signature.SignatureRequest(
                git=request.git,
                ssh_keygen=request.ssh_keygen,
                ssh=request.ssh,
                allowed_signers=symlink,
                principal=request.principal,
            )
            frozen = root / "frozen"
            frozen.mkdir()
            with self.assertRaisesRegex(signature.SignatureTrustError, "regular file"):
                signature.prepare_signature_trust(
                    bad_request,
                    workspace=faults.WORKSPACE,
                    frozen_directory=frozen,
                    base_environment={"HOME": str(root)},
                    run_command=signature_runner({}, []),
                )
            unsafe = signature.SignatureRequest(
                git=request.git,
                ssh_keygen=request.ssh_keygen,
                ssh=request.ssh,
                allowed_signers=request.allowed_signers,
                principal="bad principal\n",
            )
            with self.assertRaisesRegex(signature.SignatureTrustError, "principal"):
                signature.prepare_signature_trust(
                    unsafe,
                    workspace=faults.WORKSPACE,
                    frozen_directory=frozen,
                    base_environment={"HOME": str(root)},
                    run_command=signature_runner({}, []),
                )

            interrupted = root / "interrupted"
            interrupted.mkdir()

            def interrupting_runner(*_args, **_kwargs):
                raise KeyboardInterrupt("signature setup interrupted")

            with self.assertRaises(KeyboardInterrupt):
                signature.prepare_signature_trust(
                    request,
                    workspace=faults.WORKSPACE,
                    frozen_directory=interrupted,
                    base_environment={"HOME": str(root)},
                    run_command=interrupting_runner,
                )

    def test_signature_verification_rejects_status_principal_fingerprint_and_tamper(self):
        signature = faults.gate_h_signature
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = make_signature_request(root)
            frozen = root / "frozen"
            frozen.mkdir()
            state = {}
            calls = []
            environment = {"HOME": str(root), "PATH": "/usr/bin:/bin"}
            runner = signature_runner(state, calls)
            trust = signature.prepare_signature_trust(
                request,
                workspace=faults.WORKSPACE,
                frozen_directory=frozen,
                base_environment=environment,
                run_command=runner,
            )
            verified = signature.verify_commit(
                "a" * 40,
                trust,
                workspace=faults.WORKSPACE,
                base_environment=environment,
                run_command=runner,
            )
            self.assertTrue(verified["passed"])
            self.assertEqual(verified["status"], "G")
            self.assertEqual(verified["principal"], request.principal)
            self.assertEqual(verified["fingerprint"], "SHA256:fixturefp")
            verify_argv = verified["verify_commit"]["argv"]
            self.assertEqual(verify_argv[-2:], ["verify-commit", "a" * 40])
            self.assertEqual(
                verified["status_query"]["argv"][-5:],
                [
                    "log",
                    "-1",
                    "--no-show-signature",
                    "--format=%G?%x00%GS%x00%GF",
                    "a" * 40,
                ],
            )
            signature.validate_signature_verification_receipt(
                verified,
                "a" * 40,
                trust,
                workspace=faults.WORKSPACE,
                base_environment=environment,
            )
            verification_tampers = []
            status_tamper = json.loads(json.dumps(verified))
            status_tamper["status"] = "B"
            verification_tampers.append(status_tamper)
            argv_tamper = json.loads(json.dumps(verified))
            argv_tamper["verify_commit"]["argv"][-1] = "b" * 40
            verification_tampers.append(argv_tamper)
            boolean_tamper = json.loads(json.dumps(verified))
            boolean_tamper["status_query"]["returncode"] = False
            verification_tampers.append(boolean_tamper)
            for value in verification_tampers:
                with self.assertRaises(signature.SignatureTrustError):
                    signature.validate_signature_verification_receipt(
                        value,
                        "a" * 40,
                        trust,
                        workspace=faults.WORKSPACE,
                        base_environment=environment,
                    )
            for field, value in (
                ("status", "B"),
                ("principal", "wrong@example.test"),
                ("fingerprint", "SHA256:wrong"),
            ):
                state.clear()
                state[field] = value
                with self.subTest(field=field), self.assertRaisesRegex(
                    signature.SignatureTrustError, "identity or fingerprint"
                ):
                    signature.verify_commit(
                        "a" * 40,
                        trust,
                        workspace=faults.WORKSPACE,
                        base_environment=environment,
                        run_command=runner,
                    )
            state.clear()
            state["replacement_refs"] = b"refs/replace/aaaaaaaa\n"
            with self.assertRaisesRegex(
                signature.SignatureTrustError, "replacement refs"
            ):
                signature.verify_commit(
                    "a" * 40,
                    trust,
                    workspace=faults.WORKSPACE,
                    base_environment=environment,
                    run_command=runner,
                )
            state.clear()
            state["local_config"] = b"core.repositoryformatversion\n1\0"
            with self.assertRaisesRegex(
                signature.SignatureTrustError, "config changed"
            ):
                signature.verify_commit(
                    "a" * 40,
                    trust,
                    workspace=faults.WORKSPACE,
                    base_environment=environment,
                    run_command=runner,
                )
            state.clear()
            request.allowed_signers.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(signature.SignatureTrustError, "bytes changed"):
                signature.verify_signature_source_unchanged(trust)

    def test_signature_tool_invocation_retarget_is_rejected_even_for_identical_bytes(self):
        signature = faults.gate_h_signature
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = make_signature_request(root)
            original_git = request.git
            git_invocation = root / "git-invocation"
            git_invocation.symlink_to(original_git)
            request = signature.SignatureRequest(
                git=git_invocation,
                ssh_keygen=request.ssh_keygen,
                ssh=request.ssh,
                allowed_signers=request.allowed_signers,
                principal=request.principal,
            )
            frozen = root / "frozen"
            frozen.mkdir()
            trust = signature.prepare_signature_trust(
                request,
                workspace=faults.WORKSPACE,
                frozen_directory=frozen,
                base_environment={"HOME": str(root), "PATH": "/usr/bin:/bin"},
                run_command=signature_runner({}, []),
            )
            replacement_git = root / "replacement-git"
            replacement_git.write_bytes(original_git.read_bytes())
            replacement_git.chmod(0o700)
            git_invocation.unlink()
            git_invocation.symlink_to(replacement_git)
            with self.assertRaisesRegex(
                signature.SignatureTrustError, "no longer resolves exactly"
            ):
                signature.verify_signature_inputs_unchanged(trust)

    def test_signature_trust_rebinds_embedded_bytes_without_old_target_or_source(self):
        signature = faults.gate_h_signature
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = make_signature_request(root)
            original = root / "original"
            original.mkdir()
            state = {}
            calls = []
            environment = {"HOME": str(root), "PATH": "/usr/bin:/bin"}
            runner = signature_runner(state, calls)
            trust = signature.prepare_signature_trust(
                request,
                workspace=faults.WORKSPACE,
                frozen_directory=original,
                base_environment=environment,
                run_command=runner,
            )
            original_frozen = Path(trust["allowed_signers"]["frozen_path"])
            original_frozen.chmod(0o600)
            original_frozen.unlink()
            request.allowed_signers.unlink()

            evidence_root = root / "evidence"
            evidence_root.mkdir()
            rebound = signature.rebind_signature_trust(
                trust,
                workspace=faults.WORKSPACE,
                frozen_directory=evidence_root,
                expected_principal=request.principal,
            )
            rebound_path = evidence_root / "gate-h-allowed-signers"
            self.assertEqual(
                rebound_path.read_bytes(),
                base64.b64decode(trust["allowed_signers"]["base64"]),
            )
            self.assertEqual(rebound_path.stat().st_mode & 0o777, 0o400)
            self.assertEqual(
                rebound["allowed_signers"]["created_frozen_path"],
                trust["allowed_signers"]["created_frozen_path"],
            )
            self.assertEqual(
                rebound["allowed_signers"]["frozen_path"], str(rebound_path)
            )
            self.assertNotEqual(rebound["git_config"], trust["git_config"])
            for key in set(trust) - {"allowed_signers", "git_config"}:
                self.assertEqual(rebound[key], trust[key])
            signature.validate_signature_trust_receipt(
                rebound,
                workspace=faults.WORKSPACE,
                expected_principal=request.principal,
                verify_tool_files=True,
                verify_frozen_file=True,
            )
            posthoc_environment = {
                "HOME": str(root),
                "PATH": "/bin",
                "POSTHOC_CONTEXT": "copied-evidence",
            }
            verified = signature.verify_commit(
                "a" * 40,
                rebound,
                workspace=faults.WORKSPACE,
                base_environment=posthoc_environment,
                run_command=runner,
            )
            self.assertTrue(verified["passed"])
            self.assertEqual(
                verified["verify_commit"]["environment"],
                {**posthoc_environment, **signature.GIT_ENVIRONMENT},
            )
            signature.validate_signature_verification_receipt(
                verified,
                "a" * 40,
                rebound,
                workspace=faults.WORKSPACE,
                base_environment=posthoc_environment,
            )
            with self.assertRaisesRegex(
                signature.SignatureTrustError, "already exists"
            ):
                signature.rebind_signature_trust(
                    trust,
                    workspace=faults.WORKSPACE,
                    frozen_directory=evidence_root,
                    expected_principal=request.principal,
                )

    def test_signature_trust_validation_rejects_tool_config_and_embedded_tamper(self):
        signature = faults.gate_h_signature
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = make_signature_request(root)
            frozen = root / "frozen"
            frozen.mkdir()
            environment = {"HOME": str(root), "PATH": "/usr/bin:/bin"}
            trust = signature.prepare_signature_trust(
                request,
                workspace=faults.WORKSPACE,
                frozen_directory=frozen,
                base_environment=environment,
                run_command=signature_runner({}, []),
            )
            cases = []
            config_tamper = json.loads(json.dumps(trust))
            config_tamper["git_config"][0]["value"] = "openpgp"
            cases.append((config_tamper, "configuration"))
            signer_tamper = json.loads(json.dumps(trust))
            signer_tamper["allowed_signers"]["base64"] = base64.b64encode(
                b"different\n"
            ).decode("ascii")
            cases.append((signer_tamper, "embedded bytes"))
            fingerprint_tamper = json.loads(json.dumps(trust))
            fingerprint_tamper["allowed_signer_fingerprints"] = ["SHA256:wrong"]
            cases.append((fingerprint_tamper, "fingerprint evidence"))
            principal_tamper = json.loads(json.dumps(trust))
            principal_tamper["principal"] = "wrong@example.test"
            cases.append((principal_tamper, "principal differs"))
            environment_tamper = json.loads(json.dumps(trust))
            environment_tamper["git_environment"]["GIT_NO_REPLACE_OBJECTS"] = "0"
            cases.append((environment_tamper, "environment differs"))
            replacement_tamper = json.loads(json.dumps(trust))
            replacement_tamper["replacement_refs"]["refs"] = [
                "refs/replace/aaaaaaaa"
            ]
            cases.append((replacement_tamper, "replacement refs"))
            returncode_bool = json.loads(json.dumps(trust))
            returncode_bool["ssh_version"]["returncode"] = False
            cases.append((returncode_bool, "command metadata differs"))
            terminal_returncode_bool = json.loads(json.dumps(trust))
            terminal_returncode_bool["ssh_version"]["terminal_returncode"] = False
            cases.append((terminal_returncode_bool, "command metadata differs"))
            for value, message in cases:
                with self.subTest(message=message), self.assertRaisesRegex(
                    signature.SignatureTrustError, message
                ):
                    signature.validate_signature_trust_receipt(
                        value,
                        workspace=faults.WORKSPACE,
                        expected_principal=request.principal,
                        verify_tool_files=True,
                        verify_frozen_file=True,
                    )

            frozen_path = Path(trust["allowed_signers"]["frozen_path"])
            frozen_path.chmod(0o600)
            frozen_path.write_text("tampered frozen input\n", encoding="utf-8")
            with self.assertRaisesRegex(
                signature.SignatureTrustError, "frozen allowed-signers bytes changed"
            ):
                signature.verify_signature_inputs_unchanged(trust)
            frozen_path.write_bytes(
                base64.b64decode(trust["allowed_signers"]["base64"])
            )
            frozen_path.chmod(0o400)
            request.git.write_bytes(b"changed git fixture\n")
            request.git.chmod(0o700)
            with self.assertRaisesRegex(
                signature.SignatureTrustError, "executable changed"
            ):
                signature.verify_signature_inputs_unchanged(trust)

    def test_external_signature_anchor_must_match_tools_signers_principal_and_fingerprint(self):
        signature = faults.gate_h_signature
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = make_signature_request(root)
            frozen = root / "frozen"
            frozen.mkdir()
            environment = {"HOME": str(root), "PATH": "/usr/bin:/bin"}
            trust = signature.prepare_signature_trust(
                request,
                workspace=faults.WORKSPACE,
                frozen_directory=frozen,
                base_environment=environment,
                run_command=signature_runner({}, []),
            )
            copied_anchor = root / "copied-allowed-signers"
            copied_anchor.write_bytes(request.allowed_signers.read_bytes())
            anchor_environment = {
                "HOME": str(root),
                "PATH": "/bin",
                "ANCHOR_CONTEXT": "live-posthoc",
            }
            anchored_request = signature.SignatureRequest(
                git=request.git,
                ssh_keygen=request.ssh_keygen,
                ssh=request.ssh,
                allowed_signers=copied_anchor,
                principal=request.principal,
            )
            anchor = signature.validate_signature_request_matches_trust(
                anchored_request,
                trust,
                workspace=faults.WORKSPACE,
                base_environment=anchor_environment,
                run_command=signature_runner({}, []),
            )
            self.assertTrue(anchor["passed"])
            self.assertEqual(anchor["schema"], signature.ANCHOR_SCHEMA)
            self.assertEqual(
                anchor["allowed_signers"]["sha256"],
                trust["allowed_signers"]["sha256"],
            )
            self.assertEqual(
                anchor["git_environment"],
                {**anchor_environment, **signature.GIT_ENVIRONMENT},
            )
            signature.validate_signature_anchor_receipt(
                anchor,
                trust,
                workspace=faults.WORKSPACE,
                base_environment=anchor_environment,
            )
            anchor_tampers = []
            anchor_bytes_tamper = json.loads(json.dumps(anchor))
            anchor_bytes_tamper["allowed_signers"]["base64"] = ""
            anchor_tampers.append(anchor_bytes_tamper)
            anchor_environment_tamper = json.loads(json.dumps(anchor))
            anchor_environment_tamper["git_environment"][
                "GIT_NO_REPLACE_OBJECTS"
            ] = "0"
            anchor_tampers.append(anchor_environment_tamper)
            anchor_returncode_tamper = json.loads(json.dumps(anchor))
            anchor_returncode_tamper["fingerprint_command"]["returncode"] = False
            anchor_tampers.append(anchor_returncode_tamper)
            for value in anchor_tampers:
                with self.assertRaises(signature.SignatureTrustError):
                    signature.validate_signature_anchor_receipt(
                        value,
                        trust,
                        workspace=faults.WORKSPACE,
                        base_environment=anchor_environment,
                    )

            copied_anchor.write_text("different anchor\n", encoding="utf-8")
            with self.assertRaisesRegex(
                signature.SignatureTrustError, "allowed-signers bytes differ"
            ):
                signature.validate_signature_request_matches_trust(
                    anchored_request,
                    trust,
                    workspace=faults.WORKSPACE,
                    base_environment=anchor_environment,
                    run_command=signature_runner({}, []),
                )
            copied_anchor.write_bytes(request.allowed_signers.read_bytes())

            other_git = root / "other-git"
            other_git.write_bytes(request.git.read_bytes())
            other_git.chmod(0o700)
            wrong_tool = signature.SignatureRequest(
                git=other_git,
                ssh_keygen=request.ssh_keygen,
                ssh=request.ssh,
                allowed_signers=copied_anchor,
                principal=request.principal,
            )
            with self.assertRaisesRegex(
                signature.SignatureTrustError, "tool identities differ"
            ):
                signature.validate_signature_request_matches_trust(
                    wrong_tool,
                    trust,
                    workspace=faults.WORKSPACE,
                    base_environment=anchor_environment,
                    run_command=signature_runner({}, []),
                )

            wrong_principal = signature.SignatureRequest(
                git=request.git,
                ssh_keygen=request.ssh_keygen,
                ssh=request.ssh,
                allowed_signers=copied_anchor,
                principal="wrong@example.test",
            )
            with self.assertRaisesRegex(
                signature.SignatureTrustError, "principal differs"
            ):
                signature.validate_signature_request_matches_trust(
                    wrong_principal,
                    trust,
                    workspace=faults.WORKSPACE,
                    base_environment=anchor_environment,
                    run_command=signature_runner({}, []),
                )

            with self.assertRaisesRegex(
                signature.SignatureTrustError, "fingerprints differ"
            ):
                signature.validate_signature_request_matches_trust(
                    anchored_request,
                    trust,
                    workspace=faults.WORKSPACE,
                    base_environment=anchor_environment,
                    run_command=signature_runner(
                        {"allowed_fingerprint": "SHA256:wrong"}, []
                    ),
                )

    def test_candidate_freeze_rejects_a_dirty_worktree_before_execution(self):
        with mock.patch.object(faults, "checked_git", return_value=" M source.rs"):
            with self.assertRaisesRegex(faults.GateHFaultError, "clean candidate"):
                faults.freeze_candidate(Path("/does/not/matter"))

    def test_source_binding_hashes_exact_worktree_bytes_without_filters(self):
        calls = []

        def checked_git(argv, _execution=None):
            calls.append(list(argv))
            return "a" * 40

        with mock.patch.object(
            faults, "SOURCE_PATHS", ("lab/gate_h_signature.py",)
        ), mock.patch.object(faults, "checked_git", side_effect=checked_git):
            bindings = faults.bind_source_files()
        self.assertEqual(len(bindings), 1)
        self.assertEqual(
            calls,
            [
                ["rev-parse", "HEAD:lab/gate_h_signature.py"],
                [
                    "hash-object",
                    "--no-filters",
                    "--",
                    "lab/gate_h_signature.py",
                ],
            ],
        )

    def test_signed_source_preparation_binds_receipt_sources_graph_and_export_cwd(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            export = target / "gate-h-signed-source"
            signed_source = {
                "passed": True,
                "export": {"path": str(export)},
            }
            execution = {
                "target_directory": {"path": str(target)},
                "signature_trust": {"principal": "gate-h@example.test"},
                "environment": {"FORMAL": "exact"},
                "tools": {"cargo": {"path": "/absolute/cargo"}},
            }
            freeze = {
                "candidate_commit": "a" * 40,
                "candidate_tree": "b" * 40,
                "source_files": [],
                "source_files_sha256": faults.canonical_sha256([]),
            }
            sources = [
                {
                    "path": "Cargo.toml",
                    "git_blob": "c" * 40,
                    "sha256": "d" * 64,
                    "size_bytes": 1,
                }
            ]
            graph = {"passed": True, "cwd": str(export)}
            with (
                mock.patch.object(
                    faults.gate_h_source,
                    "materialize_signed_tree",
                    return_value=signed_source,
                ) as materialize,
                mock.patch.object(
                    faults.gate_h_source,
                    "validate_signed_tree_receipt",
                    return_value=export,
                ) as validate,
                mock.patch.object(
                    faults, "bind_source_files", return_value=sources
                ) as bind_sources,
                mock.patch.object(
                    faults, "formal_feature_graph", return_value=graph
                ) as feature_graph,
            ):
                observed = faults.prepare_signed_source_execution(
                    freeze, execution, timeout_seconds=90
                )
            self.assertIs(observed, signed_source)
            self.assertIs(execution["signed_source"], signed_source)
            self.assertIs(execution["formal_feature_graph"], graph)
            self.assertEqual(faults.execution_workspace(execution), export)
            self.assertEqual(freeze["source_files"], sources)
            self.assertEqual(
                freeze["source_files_sha256"], faults.canonical_sha256(sources)
            )
            self.assertEqual(validate.call_count, 3)
            bind_sources.assert_called_once_with(execution, workspace=export)
            feature_graph.assert_called_once_with(
                Path("/absolute/cargo"), execution["environment"], workspace=export
            )
            self.assertEqual(
                materialize.call_args.kwargs["archive_path"],
                target / "gate-h-signed-source.tar",
            )
            self.assertEqual(
                materialize.call_args.kwargs["export_root"], export
            )

    def test_signed_source_tamper_is_rejected_during_post_test_integrity(self):
        execution = {
            "tools": {},
            "cargo_config": {"paths_checked": []},
            "signature_trust": {},
            "signed_source": {
                "passed": True,
                "export": {"path": "/absolute/signed-source"},
            },
        }
        with (
            mock.patch.object(
                faults.gate_h_signature, "verify_signature_inputs_unchanged"
            ),
            mock.patch.object(
                faults.gate_h_signature, "verify_signature_source_unchanged"
            ),
            mock.patch.object(
                faults.gate_h_source,
                "validate_signed_tree_receipt",
                side_effect=faults.gate_h_source.SignedSourceError(
                    "rematerialized export differs"
                ),
            ),
            self.assertRaisesRegex(
                faults.GateHFaultError, "signed source changed.*export differs"
            ),
        ):
            faults.verify_execution_provenance_unchanged(execution)

    def test_assume_unchanged_worktree_module_tamper_is_rejected_before_reexec(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            signed_source, paths = signed_module_fixture(root, materialized=False)
            paths["gate_h_faults"].write_bytes(b"unsigned hidden worktree bytes\n")
            with (
                mock.patch.object(faults, "__file__", str(paths["gate_h_faults"])),
                mock.patch.object(
                    faults.gate_h_signature,
                    "__file__",
                    str(paths["gate_h_signature"]),
                ),
                mock.patch.object(
                    faults.gate_h_source, "__file__", str(paths["gate_h_source"])
                ),
                mock.patch.object(faults, "__cached__", None, create=True),
                mock.patch.object(faults.gate_h_signature, "__cached__", None),
                mock.patch.object(faults.gate_h_source, "__cached__", None),
                self.assertRaisesRegex(
                    faults.GateHFaultError, "bytes or mode differ from signed source"
                ),
            ):
                # The byte comparison is independent of Git status/index flags, so
                # assume-unchanged cannot hide this mutation.
                faults._loaded_module_bindings(
                    signed_source, root=root, require_materialized_mode=False
                )

    def test_signed_export_rejects_import_from_mutable_worktree(self):
        with tempfile.TemporaryDirectory() as temporary:
            export = Path(temporary).resolve() / "export"
            worktree = Path(temporary).resolve() / "worktree"
            signed_source, paths = signed_module_fixture(export, materialized=True)
            _unused, worktree_paths = signed_module_fixture(
                worktree, materialized=False
            )
            with (
                mock.patch.object(faults, "__file__", str(paths["gate_h_faults"])),
                mock.patch.object(
                    faults.gate_h_signature,
                    "__file__",
                    str(worktree_paths["gate_h_signature"]),
                ),
                mock.patch.object(
                    faults.gate_h_source, "__file__", str(paths["gate_h_source"])
                ),
                mock.patch.object(faults, "__cached__", None, create=True),
                mock.patch.object(faults.gate_h_signature, "__cached__", None),
                mock.patch.object(faults.gate_h_source, "__cached__", None),
                self.assertRaisesRegex(
                    faults.GateHFaultError, "did not originate in the signed root"
                ),
            ):
                faults._loaded_module_bindings(
                    signed_source, root=export, require_materialized_mode=True
                )

    def test_signed_export_rejects_stale_pyc_and_accepts_exact_source_origins(self):
        with tempfile.TemporaryDirectory() as temporary:
            export = Path(temporary).resolve() / "export"
            signed_source, paths = signed_module_fixture(export, materialized=True)
            cached = export / "lab/__pycache__/gate_h_signature.fixture.pyc"
            cached.parent.mkdir()
            cached.write_bytes(b"stale bytecode")
            cached.chmod(0o444)
            with (
                mock.patch.object(faults, "__file__", str(paths["gate_h_faults"])),
                mock.patch.object(
                    faults.gate_h_signature,
                    "__file__",
                    str(paths["gate_h_signature"]),
                ),
                mock.patch.object(
                    faults.gate_h_source, "__file__", str(paths["gate_h_source"])
                ),
                mock.patch.object(faults, "__cached__", None, create=True),
                mock.patch.object(
                    faults.gate_h_signature, "__cached__", str(cached)
                ),
                mock.patch.object(faults.gate_h_source, "__cached__", None),
                self.assertRaisesRegex(faults.GateHFaultError, "stale bytecode"),
            ):
                faults._loaded_module_bindings(
                    signed_source, root=export, require_materialized_mode=True
                )
            self.assertEqual(
                faults._bytecode_paths(export),
                ["lab/__pycache__", "lab/__pycache__/gate_h_signature.fixture.pyc"],
            )
            cached.chmod(0o644)
            cached.unlink()
            cached.parent.rmdir()
            with (
                mock.patch.object(faults, "__file__", str(paths["gate_h_faults"])),
                mock.patch.object(
                    faults.gate_h_signature,
                    "__file__",
                    str(paths["gate_h_signature"]),
                ),
                mock.patch.object(
                    faults.gate_h_source, "__file__", str(paths["gate_h_source"])
                ),
                mock.patch.object(faults, "__cached__", None, create=True),
                mock.patch.object(
                    faults.gate_h_signature, "__cached__", str(cached)
                ),
                mock.patch.object(faults.gate_h_source, "__cached__", None),
            ):
                bindings = faults._loaded_module_bindings(
                    signed_source, root=export, require_materialized_mode=True
                )
            self.assertEqual(set(bindings), set(faults.REEXEC_MODULE_PATHS))
            self.assertTrue(
                all(binding["cached_path_absent"] for binding in bindings.values())
            )

    def test_bootstrap_reexecs_exact_signed_runner_before_formal_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            target = workspace / "target/gate-h-faults-v2"
            export = target / "gate-h-signed-source"
            (export / "lab").mkdir(parents=True)
            controller = export / "lab/gate_h_faults.py"
            controller.write_text("# signed runner\n", encoding="utf-8")
            environment = {
                key: f"fixture-{key.lower()}"
                for key in faults.FORMAL_ENVIRONMENT_KEYS
            }
            environment["CARGO_TARGET_DIR"] = str(target)
            execution = {
                "passed": True,
                "environment": environment,
                "target_directory": {"path": str(target)},
                "signature_trust": {"principal": "gate-h@example.test"},
            }
            freeze = {
                "candidate_commit": "a" * 40,
                "candidate_tree": "b" * 40,
            }
            signed_source = {
                "passed": True,
                "export": {"path": str(export)},
            }
            args = faults.parser().parse_args(
                [
                    "--candidate-binary",
                    str(workspace / "candidate"),
                    "--output",
                    str(workspace / "receipt.json"),
                    "--timeout-seconds",
                    "90",
                    *signature_cli_args(),
                ]
            )
            observed = {}

            def execve(path, argv, child_environment):
                observed.update(
                    {
                        "path": path,
                        "argv": list(argv),
                        "environment": dict(child_environment),
                    }
                )
                raise SystemExit(71)

            python = {
                "invocation": sys.executable,
                "path": str(Path(sys.executable).resolve()),
                "size_bytes": Path(sys.executable).resolve().stat().st_size,
                "sha256": faults.sha256_file(Path(sys.executable).resolve()),
            }
            with (
                mock.patch.object(faults, "WORKSPACE", workspace),
                mock.patch.object(faults, "CODE_ROOT", workspace),
                mock.patch.object(
                    faults, "collect_execution_provenance", return_value=execution
                ),
                mock.patch.object(faults, "freeze_candidate", return_value=freeze),
                mock.patch.object(
                    faults,
                    "materialize_signed_source_execution",
                    return_value=signed_source,
                ),
                mock.patch.object(
                    faults.gate_h_source,
                    "validate_signed_tree_receipt",
                    return_value=export,
                ),
                mock.patch.object(
                    faults,
                    "_loaded_module_bindings",
                    return_value={"gate_h_faults": {"sha256": "c" * 64}},
                ),
                mock.patch.object(faults, "_python_binding", return_value=python),
                mock.patch.object(faults, "formal_feature_graph") as graph,
                self.assertRaisesRegex(SystemExit, "71"),
            ):
                faults.bootstrap_signed_reexec(
                    args,
                    workspace / "receipt.json",
                    {},
                    execve=execve,
                )
            graph.assert_not_called()
            self.assertEqual(observed["path"], python["path"])
            self.assertEqual(
                observed["argv"][:6],
                [python["path"], "-B", "-E", "-s", "-S", str(controller)],
            )
            self.assertNotIn("PYTHONPATH", observed["environment"])
            self.assertEqual(
                observed["environment"]["PYTHONDONTWRITEBYTECODE"], "1"
            )
            self.assertEqual(
                observed["environment"][faults.SIGNED_CONTROLLER_ENV],
                str(controller),
            )
            handoff_path = target / "gate-h-fault-bootstrap.json"
            self.assertTrue(handoff_path.is_file())
            handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
            self.assertEqual(handoff["signed_source"], signed_source)
            self.assertEqual(
                handoff["payload_sha256"],
                faults.canonical_sha256(
                    {key: value for key, value in handoff.items() if key != "payload_sha256"}
                ),
            )

    def test_real_isolated_reexec_process_observes_the_exact_bound_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            controller = root / "environment_probe.py"
            controller.write_text(
                "import json, os, sys\n"
                "expected = json.loads(sys.argv[1])\n"
                "actual = dict(os.environ)\n"
                "print(json.dumps(actual, sort_keys=True))\n"
                "raise SystemExit(0 if actual == expected else 93)\n",
                encoding="utf-8",
            )
            execution = self.passing_execution_provenance()
            environment = faults._reexec_environment(
                execution, controller=controller
            )
            expected_cf = f"0x{os.getuid():X}:0x0:0x0"
            self.assertEqual(environment["__CF_USER_TEXT_ENCODING"], expected_cf)
            python = str(Path(sys.executable).resolve())
            argv = [
                python,
                *faults.REEXEC_FLAGS,
                str(controller),
                json.dumps(environment, sort_keys=True),
            ]
            receipt, stdout, stderr = faults.run_isolated_process(
                argv,
                environment=environment,
                stdin_value=None,
                timeout_seconds=30,
                context="test:signed-reexec-environment",
                cwd=root,
            )
            self.assertEqual(receipt["returncode"], 0, stderr)
            self.assertFalse(receipt["timed_out"])
            self.assertIsNone(receipt["execution_error"])
            self.assertEqual(json.loads(stdout), environment)
            self.assertEqual(receipt["environment"], environment)
            self.assertEqual(receipt["argv"], argv)

    def test_formal_build_and_test_children_use_the_signed_export_cwd(self):
        with tempfile.TemporaryDirectory() as temporary:
            export = Path(temporary) / "signed-source"
            export.mkdir()
            execution = {
                "signed_source": {
                    "passed": True,
                    "export": {"path": str(export)},
                },
                "environment": {"FORMAL": "exact"},
                "tools": {
                    "cargo": {"path": "/absolute/cargo"},
                },
            }
            process = mock.Mock()
            process.wait.return_value = 1
            process.returncode = 1
            with mock.patch.object(
                faults.subprocess, "Popen", return_value=process
            ) as popen:
                build = faults.build_one_test_executable(
                    {"source_files_sha256": "f" * 64},
                    "aster-host",
                    timeout_seconds=10,
                    execution=execution,
                )
                test = faults.execute_test(
                    faults.TEST_SPECS[0], timeout_seconds=10, execution=execution
                )
            self.assertEqual(build["cwd"], str(export))
            self.assertEqual(test["cwd"], str(export))
            self.assertEqual(popen.call_args_list[0].kwargs["cwd"], export)
            self.assertEqual(popen.call_args_list[1].kwargs["cwd"], export)

    def test_execution_provenance_rejects_an_ambient_cargo_target(self):
        with mock.patch.dict(
            faults.os.environ,
            {"CARGO_TARGET_DIR": "/tmp/ambient-cargo-target"},
            clear=False,
        ):
            with self.assertRaisesRegex(
                faults.GateHFaultError, "pre-existing CARGO_TARGET_DIR"
            ):
                faults.collect_execution_provenance()

    def test_candidate_freeze_rejects_an_unsigned_commit_before_execution(self):
        def git_result(argv, _execution=None):
            if argv[0] == "status":
                return ""
            if argv == ["rev-parse", "HEAD"]:
                return "a" * 40
            if argv == ["rev-parse", "HEAD^{tree}"]:
                return "b" * 40
            if argv[0] == "log":
                return "N\0\0"
            self.fail(f"unexpected git invocation: {argv}")

        with mock.patch.object(faults, "checked_git", side_effect=git_result):
            with self.assertRaisesRegex(faults.GateHFaultError, "signed candidate"):
                faults.freeze_candidate(Path("/does/not/matter"))

    def test_exact_test_witness_rejects_successful_zero_test_command(self):
        spec = faults.TEST_SPECS[0]
        passed, error = faults.exact_test_witness(
            spec,
            returncode=0,
            timed_out=False,
            stdout=b"running 0 tests\n\ntest result: ok. 0 passed; 0 failed\n",
            stderr=b"",
        )
        self.assertFalse(passed)
        self.assertIn("exactly one test", error)

    def test_exact_test_witness_requires_the_named_test_and_exact_summary(self):
        spec = faults.TEST_SPECS[0]
        output = (
            f"running 1 test\n"
            f"test {spec.test_name} ... ok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
            "63 filtered out; finished in 0.01s\n"
        ).encode()
        self.assertEqual(
            faults.exact_test_witness(
                spec,
                returncode=0,
                timed_out=False,
                stdout=output,
                stderr=b"",
            ),
            (True, None),
        )
        wrong = output.replace(spec.test_name.encode(), b"wrong::test")
        self.assertFalse(
            faults.exact_test_witness(
                spec,
                returncode=0,
                timed_out=False,
                stdout=wrong,
                stderr=b"",
            )[0]
        )

    def test_bounded_log_hashes_full_output_but_retains_only_bound(self):
        output = b"a" * (faults.MAX_RETAINED_LOG_BYTES + 17)
        retained = faults.bounded_log(output)
        self.assertTrue(retained["truncated"])
        self.assertEqual(retained["bytes"], len(output))
        self.assertLessEqual(
            len(retained["head"].encode()) + len(retained["tail"].encode()),
            faults.MAX_RETAINED_LOG_BYTES,
        )
        self.assertEqual(faults.sha256_bytes(output), hashlib.sha256(output).hexdigest())

    def test_complete_stream_retains_recomputable_bytes_under_a_hard_bound(self):
        output = b"exact cargo output\x00\xff"
        retained = faults.complete_stream(output)
        self.assertTrue(retained["complete"])
        self.assertEqual(base64.b64decode(retained["base64"]), output)
        oversized = faults.complete_stream(
            b"x" * (faults.MAX_COMPLETE_STREAM_BYTES + 1)
        )
        self.assertFalse(oversized["complete"])
        self.assertIsNone(oversized["base64"])

    def test_cargo_reported_test_executable_is_resolved_from_retained_stderr(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "aster_host-test"
            executable.write_bytes(b"test binary")
            executable.chmod(0o700)
            stderr = (
                "    Finished `test` profile\n"
                f"     Running unittests src/lib.rs ({executable})\n"
            ).encode()
            command = {"stderr": faults.complete_stream(stderr)}
            self.assertEqual(
                faults.cargo_reported_test_executable(command),
                str(executable.resolve()),
            )
            command["stderr"]["base64"] = base64.b64encode(
                stderr + f"     Running unittests other.rs ({executable})\n".encode()
            ).decode()
            self.assertIsNone(faults.cargo_reported_test_executable(command))

    def test_formal_graph_ignores_checkout_paths_but_rejects_provider_tokens(self):
        graph = (
            "aster-lab v0.1.0 (/checkout/iroh-in-ci/libp2p/crates/aster-lab) features=[gate-h]\n"
            "└── aster-host v0.1.0 (/checkout/iroh-in-ci/crates/aster-host) features=[gate-h-formal]\n"
        )
        for extra, passed in (
            ("", True),
            ("└── iroh v1.3.0 features=[]\n", False),
            ("└── libp2p-core v0.1.0 features=[]\n", False),
        ):
            with self.subTest(extra=extra), mock.patch.object(
                faults,
                "run_provenance_command",
                return_value={
                    "returncode": 0,
                    "timed_out": False,
                    "execution_error": None,
                    "stdout": faults.complete_stream((graph + extra).encode()),
                    "stderr": faults.complete_stream(b""),
                },
            ):
                result = faults.formal_feature_graph(Path("cargo"), {})
                self.assertEqual(result["passed"], passed)


    def test_generate_receipt_fails_closed_when_one_exact_witness_is_missing(self):
        freeze = {
            "candidate_commit": "a" * 40,
            "candidate_tree": "b" * 40,
            "worktree_clean": True,
            "worktree_status": [],
            "signature_status": "G",
            "signature_signer": "Gate H Test Signer",
            "signature_fingerprint": "c" * 40,
            "requirements_sha256": faults.REQUIREMENTS_SHA256,
            "proposal_0004_sha256": "d" * 64,
            "source_files": [],
            "source_files_sha256": hashlib.sha256(b"[]").hexdigest(),
            "candidate_binary": "/tmp/aster-lab",
            "candidate_binary_sha256": "e" * 64,
            "candidate_binary_size_bytes": 1,
        }

        def execute(spec, _timeout):
            witnessed = spec is not faults.TEST_SPECS[-1]
            return {
                "case": spec.case,
                "package": spec.package,
                "test_name": spec.test_name,
                "argv": spec.argv(),
                "returncode": 0,
                "timed_out": False,
                "stdout_sha256": "0" * 64,
                "stderr_sha256": "0" * 64,
                "exact_test_witnessed": witnessed,
            }

        with (
            mock.patch.object(faults, "freeze_candidate", return_value=freeze),
            mock.patch.object(faults, "verify_candidate_unchanged"),
            mock.patch.object(faults, "verify_execution_provenance_unchanged"),
        ):
            receipt = faults.generate_receipt(
                Path("/tmp/aster-lab"),
                timeout_seconds=10,
                executor=execute,
                static_executor=self.passing_static_checks,
                test_executable_builder=self.passing_test_executable_build,
                executable_verifier=self.passing_executable_verifier,
                executed_binary_parser=self.passing_executed_binary_parser,
                provenance_collector=self.passing_execution_provenance,
                signed_source_preparer=self.passing_signed_source_preparer,
            )
        self.assertFalse(receipt["passed"])
        self.assertFalse(receipt["cases"]["native_restart_replacement"])
        self.assertTrue(receipt["cases"]["admission_single_use"])
        self.assertEqual(receipt["schema"], faults.SCHEMA)
        self.assertEqual(receipt["candidate_commit"], "a" * 40)
        self.assertEqual(receipt["candidate_binary_sha256"], "e" * 64)

    def test_generate_receipt_fails_closed_on_post_test_source_change(self):
        freeze = {
            "candidate_commit": "a" * 40,
            "candidate_tree": "b" * 40,
            "worktree_clean": True,
            "worktree_status": [],
            "signature_status": "G",
            "signature_signer": "Gate H Test Signer",
            "signature_fingerprint": "c" * 40,
            "requirements_sha256": faults.REQUIREMENTS_SHA256,
            "proposal_0004_sha256": "d" * 64,
            "source_files": [],
            "source_files_sha256": hashlib.sha256(b"[]").hexdigest(),
            "candidate_binary": "/tmp/aster-lab",
            "candidate_binary_sha256": "e" * 64,
            "candidate_binary_size_bytes": 1,
        }

        def execute(spec, _timeout):
            return {
                "case": spec.case,
                "package": spec.package,
                "test_name": spec.test_name,
                "argv": spec.argv(),
                "returncode": 0,
                "timed_out": False,
                "stdout_sha256": "0" * 64,
                "stderr_sha256": "0" * 64,
                "exact_test_witnessed": True,
            }

        with (
            mock.patch.object(faults, "freeze_candidate", return_value=freeze),
            mock.patch.object(
                faults,
                "verify_candidate_unchanged",
                side_effect=faults.GateHFaultError("source changed"),
            ),
            mock.patch.object(faults, "verify_execution_provenance_unchanged"),
        ):
            receipt = faults.generate_receipt(
                Path("/tmp/aster-lab"),
                timeout_seconds=10,
                executor=execute,
                static_executor=self.passing_static_checks,
                test_executable_builder=self.passing_test_executable_build,
                executable_verifier=self.passing_executable_verifier,
                executed_binary_parser=self.passing_executed_binary_parser,
                provenance_collector=self.passing_execution_provenance,
                signed_source_preparer=self.passing_signed_source_preparer,
            )
        self.assertTrue(all(receipt["cases"].values()))
        self.assertFalse(receipt["source_integrity_after_tests"])
        self.assertEqual(receipt["integrity_error"], "source changed")
        self.assertFalse(receipt["passed"])

    def test_generate_receipt_fails_closed_on_static_ownership_regression(self):
        freeze = {
            "candidate_commit": "a" * 40,
            "candidate_tree": "b" * 40,
            "worktree_clean": True,
            "worktree_status": [],
            "signature_status": "G",
            "signature_signer": "Gate H Test Signer",
            "signature_fingerprint": "c" * 40,
            "requirements_sha256": faults.REQUIREMENTS_SHA256,
            "proposal_0004_sha256": "d" * 64,
            "source_files": [],
            "source_files_sha256": hashlib.sha256(b"[]").hexdigest(),
            "candidate_binary": "/tmp/aster-lab",
            "candidate_binary_sha256": "e" * 64,
            "candidate_binary_size_bytes": 1,
        }

        def execute(spec, _timeout):
            return {
                "case": spec.case,
                "package": spec.package,
                "returncode": 0,
                "timed_out": False,
                "exact_test_witnessed": True,
            }

        static_checks = self.passing_static_checks(freeze)
        static_checks["formal_graph_has_no_libp2p_or_iroh_dependency"]["passed"] = False
        with (
            mock.patch.object(faults, "freeze_candidate", return_value=freeze),
            mock.patch.object(faults, "verify_candidate_unchanged"),
            mock.patch.object(faults, "verify_execution_provenance_unchanged"),
        ):
            receipt = faults.generate_receipt(
                Path("/tmp/aster-lab"),
                timeout_seconds=10,
                executor=execute,
                static_executor=lambda _freeze: static_checks,
                test_executable_builder=self.passing_test_executable_build,
                executable_verifier=self.passing_executable_verifier,
                executed_binary_parser=self.passing_executed_binary_parser,
                provenance_collector=self.passing_execution_provenance,
                signed_source_preparer=self.passing_signed_source_preparer,
            )
        self.assertTrue(all(receipt["cases"].values()))
        self.assertFalse(receipt["static_checks_passed"])
        self.assertFalse(receipt["passed"])

    def test_formal_child_launches_reap_their_process_group_on_base_exception(self):
        fake_process = mock.Mock()
        fake_process.wait.side_effect = KeyboardInterrupt("ctrl-c")
        freeze = {"source_files_sha256": "f" * 64}
        for launch in (
            lambda: faults.build_one_test_executable(
                freeze, "aster-host", timeout_seconds=10
            ),
            lambda: faults.execute_test(faults.TEST_SPECS[0], timeout_seconds=10),
        ):
            fake_process.reset_mock()
            fake_process.wait.side_effect = KeyboardInterrupt("ctrl-c")
            with (
                mock.patch.object(faults.subprocess, "Popen", return_value=fake_process),
                mock.patch.object(
                    faults, "terminate_process_group", return_value=None
                ) as terminate,
                self.assertRaises(KeyboardInterrupt),
            ):
                launch()
            terminate.assert_called_once_with(fake_process)

        fake_process.reset_mock()
        fake_process.communicate.side_effect = KeyboardInterrupt("ctrl-c")
        with (
            mock.patch.object(faults.subprocess, "Popen", return_value=fake_process),
            mock.patch.object(
                faults, "terminate_process_group", return_value=None
            ) as terminate,
            self.assertRaises(KeyboardInterrupt),
        ):
            faults.run_provenance_command(
                ["/bound/cargo", "tree"],
                {"PATH": faults.FORMAL_SYSTEM_PATH},
            )
        terminate.assert_called_once_with(fake_process)

        fake_process.reset_mock()
        fake_process.communicate.side_effect = KeyboardInterrupt("ctrl-c")
        fake_process.returncode = -faults.signal.SIGTERM
        fake_process.poll.return_value = -faults.signal.SIGTERM
        with (
            mock.patch.object(faults.subprocess, "Popen", return_value=fake_process),
            mock.patch.object(
                faults, "terminate_process_group", return_value=None
            ) as terminate,
            self.assertRaises(KeyboardInterrupt) as caught,
        ):
            faults.checked_git(
                ["status"],
                execution={
                    "environment": {"GIT_CONFIG_NOSYSTEM": "1"},
                    "tools": {"git": {"path": "/bound/git"}},
                },
            )
        terminate.assert_called_once_with(fake_process)
        terminal = caught.exception.gate_h_interrupted_processes
        self.assertEqual(len(terminal), 1)
        self.assertEqual(terminal[0]["context"], "git")
        self.assertTrue(terminal[0]["process_group_reaped"])

    def test_keyboard_interrupt_reaps_real_child_and_retains_failed_receipt(self):
        original_popen = faults.subprocess.Popen
        spawned = []

        class InterruptingPopen:
            def __init__(self, *args, **kwargs):
                self.process = original_popen(*args, **kwargs)
                self.interrupted = False
                spawned.append(self.process)

            @property
            def pid(self):
                return self.process.pid

            def poll(self):
                return self.process.poll()

            def wait(self, timeout=None):
                if not self.interrupted:
                    self.interrupted = True
                    raise KeyboardInterrupt("ctrl-c")
                return self.process.wait(timeout=timeout)

        def interrupted_generate(_args, _output, progress):
            progress.update(
                {"phase": "exact_test_commands", "commands": []}
            )
            return faults.execute_test(faults.TEST_SPECS[0], timeout_seconds=30)

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "interrupted.json"
            try:
                with (
                    mock.patch.object(
                        faults.TestSpec,
                        "argv",
                        return_value=[
                            sys.executable,
                            "-c",
                            "import time; time.sleep(60)",
                        ],
                    ),
                    mock.patch.object(faults.subprocess, "Popen", InterruptingPopen),
                    mock.patch.object(
                        faults,
                        "bootstrap_signed_reexec",
                        side_effect=interrupted_generate,
                    ),
                    mock.patch.object(faults.sys, "stderr"),
                ):
                    returncode = faults.main(
                        [
                            "--candidate-binary",
                            "/tmp/candidate",
                            "--output",
                            str(output),
                            "--timeout-seconds",
                            "30",
                            *signature_cli_args(),
                        ]
                    )
                self.assertEqual(returncode, 130)
                self.assertTrue(output.is_file())
                receipt = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual(receipt["receipt_kind"], "interrupted")
                self.assertTrue(receipt["interrupted"])
                self.assertFalse(receipt["passed"])
                self.assertEqual(receipt["interruption"]["type"], "KeyboardInterrupt")
                payload = dict(receipt)
                digest = payload.pop("receipt_payload_sha256")
                self.assertEqual(digest, faults.canonical_sha256(payload))
                self.assertEqual(
                    receipt["partial_evidence_sha256"],
                    faults.canonical_sha256(receipt["partial_evidence"]),
                )
                self.assertEqual(
                    receipt["partial_evidence"]["phase"], "exact_test_commands"
                )
                self.assertEqual(len(spawned), 1)
                self.assertIsNotNone(spawned[0].poll())
                with self.assertRaises(ProcessLookupError):
                    os.kill(spawned[0].pid, 0)
                retained = output.read_bytes()
                with mock.patch.object(faults.sys, "stderr"):
                    self.assertEqual(
                        faults.main(
                            [
                                "--candidate-binary",
                                "/tmp/candidate",
                                "--output",
                                str(output),
                                *signature_cli_args(),
                            ]
                        ),
                        2,
                    )
                self.assertEqual(output.read_bytes(), retained)
            finally:
                for process in spawned:
                    if process.poll() is None:
                        os.killpg(process.pid, faults.signal.SIGKILL)
                        process.wait(timeout=5)

    def _assert_static_signal_is_reaped_and_retained(
        self,
        signum,
        expected_status,
        expected_type,
        *,
        repeat_signum=None,
    ):
        original_popen = faults.subprocess.Popen
        original_interruption_receipt = faults.interruption_receipt
        spawned = []
        test_case = self
        repeat_sent = False

        def receipt_with_optional_repeat(*args, **kwargs):
            nonlocal repeat_sent
            if repeat_signum is not None and not repeat_sent:
                repeat_sent = True
                os.kill(os.getpid(), repeat_signum)
            return original_interruption_receipt(*args, **kwargs)

        class SignalingPopen:
            def __init__(self, *args, **kwargs):
                self.process = original_popen(*args, **kwargs)
                self.signaled = False
                spawned.append(self.process)

            @property
            def pid(self):
                return self.process.pid

            @property
            def returncode(self):
                return self.process.returncode

            @property
            def stdin(self):
                return self.process.stdin

            def poll(self):
                return self.process.poll()

            def wait(self, timeout=None):
                return self.process.wait(timeout=timeout)

            def communicate(self, input=None, timeout=None):
                if not self.signaled:
                    self.signaled = True
                    os.kill(os.getpid(), signum)
                    test_case.fail("signal handler did not interrupt static execution")
                return self.process.communicate(input=input, timeout=timeout)

        source = b"exact interrupted static-check stdin\n"

        def interrupted_generate(_args, _output, progress):
            progress.update({"phase": "static_checks"})
            return faults.run_isolated_process(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                environment={"STATIC_FIXTURE_ENV": "exact"},
                stdin_value=source,
                timeout_seconds=30,
                context="static-check:interrupted_static_fixture",
                cwd=faults.WORKSPACE,
            )

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / f"static-{signum}.json"
            try:
                with (
                    mock.patch.object(faults.subprocess, "Popen", SignalingPopen),
                    mock.patch.object(
                        faults,
                        "bootstrap_signed_reexec",
                        side_effect=interrupted_generate,
                    ),
                    mock.patch.object(
                        faults,
                        "interruption_receipt",
                        side_effect=receipt_with_optional_repeat,
                    ),
                    mock.patch.object(faults.sys, "stderr"),
                ):
                    returncode = faults.main(
                        [
                            "--candidate-binary",
                            "/tmp/candidate",
                            "--output",
                            str(output),
                            *signature_cli_args(),
                        ]
                    )
                self.assertEqual(returncode, expected_status)
                self.assertTrue(output.is_file())
                receipt = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual(receipt["receipt_kind"], "interrupted")
                self.assertFalse(receipt["passed"])
                self.assertEqual(receipt["interruption"]["type"], expected_type)
                self.assertEqual(
                    receipt["interruption"]["repeated_signals"],
                    (
                        []
                        if repeat_signum is None
                        else [faults.signal.Signals(repeat_signum).name]
                    ),
                )
                terminal = receipt["partial_evidence"]["interrupted_processes"]
                self.assertEqual(len(terminal), 1)
                terminal = terminal[0]
                self.assertEqual(
                    terminal["context"], "static-check:interrupted_static_fixture"
                )
                self.assertEqual(
                    terminal["environment"], {"STATIC_FIXTURE_ENV": "exact"}
                )
                self.assertEqual(terminal["stdin_mode"], "bytes")
                self.assertEqual(terminal["stdin_sha256"], faults.sha256_bytes(source))
                self.assertEqual(
                    base64.b64decode(terminal["stdin"]["base64"]), source
                )
                self.assertTrue(terminal["process_group_reaped"])
                self.assertIsNotNone(terminal["terminal_returncode"])
                self.assertTrue(terminal["stdout"]["complete"])
                self.assertTrue(terminal["stderr"]["complete"])
                self.assertEqual(len(spawned), 1)
                self.assertIsNotNone(spawned[0].poll())
                with self.assertRaises(ProcessLookupError):
                    os.kill(spawned[0].pid, 0)
                retained = output.read_bytes()
                with self.assertRaisesRegex(
                    faults.GateHFaultError, "refusing to replace"
                ):
                    faults.write_new_json(output, {"passed": True})
                self.assertEqual(output.read_bytes(), retained)
            finally:
                for process in spawned:
                    if process.poll() is None:
                        os.killpg(process.pid, faults.signal.SIGKILL)
                        process.wait(timeout=5)

    def test_static_sigint_reaps_child_and_retains_nonpassing_receipt(self):
        self._assert_static_signal_is_reaped_and_retained(
            faults.signal.SIGINT, 130, "GateHSignalInterruption"
        )

    def test_static_sigterm_reaps_child_and_retains_nonpassing_receipt(self):
        self._assert_static_signal_is_reaped_and_retained(
            faults.signal.SIGTERM, 143, "GateHSignalInterruption"
        )

    def test_repeated_signal_cannot_preempt_static_failure_receipt(self):
        self._assert_static_signal_is_reaped_and_retained(
            faults.signal.SIGINT,
            130,
            "GateHSignalInterruption",
            repeat_signum=faults.signal.SIGTERM,
        )

    def test_main_does_not_mislabel_system_exit_as_an_interruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "not-an-interrupt.json"
            with mock.patch.object(
                faults, "bootstrap_signed_reexec", side_effect=SystemExit(17)
            ):
                with self.assertRaisesRegex(SystemExit, "17"):
                    faults.main(
                        [
                            "--candidate-binary",
                            "/tmp/candidate",
                            "--output",
                            str(output),
                            *signature_cli_args(),
                        ]
                    )
            self.assertFalse(output.exists())

    def test_main_retains_sigterm_receipt_returns_143_and_restores_handler(self):
        previous = faults.signal.getsignal(faults.signal.SIGTERM)

        def terminate_run(*_args, **_kwargs):
            os.kill(os.getpid(), faults.signal.SIGTERM)
            self.fail("the scoped SIGTERM handler did not interrupt execution")

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "sigterm.json"
            with (
                mock.patch.object(
                    faults, "bootstrap_signed_reexec", side_effect=terminate_run
                ),
                mock.patch.object(faults.sys, "stderr"),
            ):
                returncode = faults.main(
                    [
                        "--candidate-binary",
                        "/tmp/candidate",
                        "--output",
                        str(output),
                        *signature_cli_args(),
                    ]
                )
            self.assertEqual(returncode, 143)
            self.assertIs(faults.signal.getsignal(faults.signal.SIGTERM), previous)
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(receipt["receipt_kind"], "interrupted")
            self.assertFalse(receipt["passed"])
            self.assertEqual(
                receipt["interruption"],
                {
                    "message": "SIGTERM",
                    "repeated_signals": [],
                    "signal": "SIGTERM",
                    "signum": faults.signal.SIGTERM,
                    "type": "GateHSignalInterruption",
                },
            )
            payload = dict(receipt)
            digest = payload.pop("receipt_payload_sha256")
            self.assertEqual(digest, faults.canonical_sha256(payload))

    def test_write_new_json_never_replaces_an_existing_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "receipt.json"
            faults.write_new_json(output, {"passed": True})
            original = output.read_bytes()
            with self.assertRaisesRegex(faults.GateHFaultError, "refusing to replace"):
                faults.write_new_json(output, {"passed": False})
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(json.loads(original), {"passed": True})


if __name__ == "__main__":
    unittest.main()
