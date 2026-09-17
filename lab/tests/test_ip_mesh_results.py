import importlib.util
import base64
import hashlib
import json
import os
import io
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "ip_mesh_results.py"
SPEC = importlib.util.spec_from_file_location("aster_ip_mesh_results", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
results = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = results
SPEC.loader.exec_module(results)


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def write_evidence_index(root: Path):
    entries, aggregate = results.calculate_evidence_entries(root)
    write_json(
        root / "evidence-index.json",
        {
            "schema": results.EVIDENCE_INDEX_SCHEMA,
            "created_utc": "2026-08-21T00:00:00Z",
            "entry_count": len(entries),
            "aggregate_sha256": aggregate,
            "entries": entries,
        },
    )


def gate_h_process_quartet(root: Path, trial: int, role: str) -> dict[str, Path]:
    result_path = root / f"trial-{trial:02d}" / "result.json"
    trial_result = json.loads(result_path.read_text(encoding="utf-8"))
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    expected = results.expected_gate_h_process_commands(
        trial=trial,
        run_id=manifest["run_id"],
        duration_ms=manifest["duration_ms"],
        identities=trial_result["identities"],
        item_id=trial_result["item_id"],
        docker_binary=manifest["host_execution"]["tools"]["docker"][
            "invocation_path"
        ],
    )[role]
    matches = []
    for command_path in root.glob("process-*.command.json"):
        command = json.loads(command_path.read_text(encoding="utf-8"))
        if command.get("argv") == expected:
            matches.append(command_path)
    if len(matches) != 1:
        raise AssertionError(f"fixture has {len(matches)} {role} process commands")
    prefix = root / matches[0].name.removesuffix(".command.json")
    return {
        "command": prefix.with_suffix(".command.json"),
        "result": prefix.with_suffix(".result.json"),
        "stdout": prefix.with_suffix(".stdout.log"),
        "stderr": prefix.with_suffix(".stderr.log"),
    }


def rewrite_gate_h_fault_receipt(root: Path, value: dict):
    path = root / "gate-h-fault-receipt.json"
    write_json(path, value)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["gate_h_fault_receipt"]["sha256"] = results.sha256_file(path)
    write_json(manifest_path, manifest)
    write_evidence_index(root)


def node_receipt(
    *,
    elapsed=10,
    candidate=2,
    authenticated=4,
    resources=True,
    schema="aster-lab-libp2p-mesh-node/v2",
    provider_binary_sha256=None,
):
    value = {
        "schema": schema,
        "candidate_source": "aster-protected",
        "bounded_candidate_source": True,
        "protected_source_compiled_without_mdns": True,
        "libp2p_mdns": False,
        "libp2p_mdns_enabled": False,
        "mdns_rustsec_blocker": None,
        "provider_mdns_announcement_count_observable": False,
        "elapsed_ms": elapsed,
        "first_candidate_ms": candidate,
        "first_authenticated_ms": authenticated,
        "frames_received": 3,
        "frames_sent": 5,
        "bytes_received": 30,
        "bytes_sent": 50,
        "pump_calls": 7,
        "contact_failures": 1,
        "duplicate_contacts": 2,
        "active_contact_high_water": 1,
        "admitted_contact_high_water": 1,
        "candidates_discovered": 1,
        "discovery_announcements": 2,
    }
    if schema == results.LIBP2P_SHARED_NODE_SCHEMA:
        value["provider_binary_sha256"] = provider_binary_sha256
    if resources:
        value["experiment_resources"] = {
            "cpu_usage_usec": 100,
            "network_bytes": 200,
            "memory_current_bytes": 300,
            "memory_peak_bytes": 400,
            "memory_current_sample_phase": "exact-item-observation-before-process-wait",
            "memory_current_candidate_running": True,
            "durable_item_present_before_contact": True,
            "durable_item_first_observed_ms_from_process_launch": 0,
            "durable_probe_scope": "read-only exact ItemID row; 10 ms controller polling",
        }
    return value


def native_shared_node_receipt(*, clean=False):
    value = node_receipt()
    value.pop("candidate_source")
    for field in (
        "bounded_candidate_source",
        "protected_source_compiled_without_mdns",
        "libp2p_mdns",
        "libp2p_mdns_enabled",
        "mdns_rustsec_blocker",
        "provider_mdns_announcement_count_observable",
    ):
        value.pop(field)
    value.update(
        {
            "schema": results.NATIVE_SHARED_NODE_SCHEMA,
            "frame_counter_scope": "aster_protocol",
            "aster_frames_received": value["frames_received"],
            "aster_frames_sent": value["frames_sent"],
            "aster_bytes_received": value["bytes_received"],
            "aster_bytes_sent": value["bytes_sent"],
            "carrier_control_frames_received": 2,
            "carrier_control_frames_sent": 2,
            "carrier_control_bytes_received": 20,
            "carrier_control_bytes_sent": 20,
            "authorization_generation_checks": 2,
            "authorization_generation_mismatches": 0,
            "authorization_generation_unavailable": 0,
            "authorization_generation_current": 0,
            "durable_item_probe_id": "d" * 64,
            "durable_item_present": True,
            "gate_h_control_id": None,
            "gate_h_generation_before": None,
            "gate_h_generation_after": None,
            "gate_h_stale_target_peer": None,
            "gate_h_stale_target_contact": None,
            "gate_h_stale_queued_frames": 0,
            "gate_h_stale_send_frames_before": 0,
            "gate_h_stale_send_frames_after": 0,
            "gate_h_stale_send_bytes_before": 0,
            "gate_h_stale_send_bytes_after": 0,
            "gate_h_stale_zero_bytes_emitted": False,
            "gate_h_stale_contacts_retired": 0,
            "gate_h_provider_epoch_rotations": 0,
            "gate_h_fresh_target_contact": None,
            "gate_h_fresh_target_generation": None,
            "gate_h_fresh_aster_frames_sent": 0,
            "gate_h_fresh_aster_bytes_sent": 0,
            "gate_h_completed": False,
            "candidates_rejected_capacity": 0,
            "authenticated_peers": ["a" * 64],
            "admitted_peers": ["a" * 64],
            "durable_authority_open_count": 1,
            "sqlite_node_open_count": 1,
            "blob_authority_open_count": 1,
            "semantic_backend_construction_count": 1,
            "process_authority_construction_count": 1,
            "node_resource_rejected_claims": 0 if clean else 1,
        }
    )
    if clean:
        value["contact_failures"] = 0
        value["duplicate_contacts"] = 0
        value["unauthorized_peers"] = []
    value["admitted_contact_high_water"] = 2
    limits = dict(results.GATE_H_NATIVE_RESOURCE_LIMITS)
    current = {field: 0 for field in results.NODE_RESOURCE_FIELDS}
    current.update(results.GATE_H_NATIVE_PROVIDER_BASE)
    high_water = dict(current)
    for field, amount in results.GATE_H_NATIVE_ADMITTED_CONTACT.items():
        high_water[field] = high_water.get(field, 0) + 2 * amount
    high_water["candidates"] = 2
    value["node_resource_limits"] = limits
    value["node_resource_current"] = current
    value["node_resource_high_water"] = high_water
    rejections = {field: 0 for field in results.NODE_RESOURCE_FIELDS}
    if not clean:
        rejections["frames"] = 1
    value["node_resource_rejections"] = rejections
    return value


def _git_blob_id(value: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(value)}\0".encode("ascii") + value,
        usedforsecurity=False,
    ).hexdigest()


FAULT_SOURCE_BYTES = {
    relative: (results.gate_h_fault_contract.WORKSPACE / relative).read_bytes()
    for relative in results.gate_h_fault_contract.SOURCE_PATHS
}
SIGNED_SOURCE_BYTES = {
    **FAULT_SOURCE_BYTES,
    "lab/ip_mesh_experiment.py": (
        results.gate_h_fault_contract.WORKSPACE / "lab/ip_mesh_experiment.py"
    ).read_bytes(),
    "lab/ip_mesh_results.py": (
        results.gate_h_fault_contract.WORKSPACE / "lab/ip_mesh_results.py"
    ).read_bytes(),
}
SIGNED_SOURCE_BINDINGS = [
    {
        "path": relative,
        "mode": "100644",
        "git_blob": _git_blob_id(value),
        "size_bytes": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
    }
    for relative, value in sorted(SIGNED_SOURCE_BYTES.items())
]
SIGNED_SOURCE_TREE = results.gate_h_source._tree_id(SIGNED_SOURCE_BINDINGS)
SIGNATURE_PRINCIPAL = "gate-h@example.test"
SIGNATURE_FINGERPRINT = "SHA256:fixturefp"


def fake_candidate_blob(
    _commit: str, relative: str, **_checked_git
) -> tuple[str, bytes]:
    value = FAULT_SOURCE_BYTES[relative]
    return _git_blob_id(value), value


def _fault_stream_fields(field: str, value: bytes) -> dict:
    return {
        field: results.gate_h_fault_contract.complete_stream(value),
        f"{field}_sha256": hashlib.sha256(value).hexdigest(),
    }


def make_signature_request(root: Path, *, git: Path):
    inputs = root / "signature-inputs"
    inputs.mkdir()
    tools = {}
    for name in ("ssh-keygen", "ssh"):
        path = inputs / name
        path.write_bytes(f"fixture {name}\n".encode("utf-8"))
        path.chmod(0o700)
        tools[name] = path
    allowed_signers = inputs / "allowed-signers"
    allowed_signers.write_text(
        f"{SIGNATURE_PRINCIPAL} ssh-ed25519 AAAATEST gate-h\n",
        encoding="utf-8",
    )
    return results.gate_h_signature.SignatureRequest(
        git=git,
        ssh_keygen=tools["ssh-keygen"],
        ssh=tools["ssh"],
        allowed_signers=allowed_signers,
        principal=SIGNATURE_PRINCIPAL,
    )


def write_signed_source_archive(path: Path) -> None:
    directories = sorted(
        {
            Path(*Path(binding["path"]).parts[:index]).as_posix()
            for binding in SIGNED_SOURCE_BINDINGS
            for index in range(1, len(Path(binding["path"]).parts))
        }
    )
    with tarfile.open(
        path,
        mode="w",
        format=tarfile.PAX_FORMAT,
        pax_headers={"comment": "c" * 40},
    ) as archive:
        for relative in directories:
            member = tarfile.TarInfo(relative + "/")
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            archive.addfile(member)
        for binding in SIGNED_SOURCE_BINDINGS:
            value = SIGNED_SOURCE_BYTES[binding["path"]]
            member = tarfile.TarInfo(binding["path"])
            member.size = len(value)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(value))


def fake_signature_runner(
    argv, *, environment, stdin_value, timeout_seconds, context
):
    del timeout_seconds
    if argv[-1:] == ["-V"]:
        stdout = b""
        stderr = b"OpenSSH_9.9p1, LibreSSL 3.3.6\n"
    elif "-lf" in argv:
        stdout = (
            f"256 {SIGNATURE_FINGERPRINT} gate-h@example.test (ED25519)\n"
        ).encode("utf-8")
        stderr = b""
    elif "for-each-ref" in argv:
        stdout = b""
        stderr = b""
    elif "config" in argv:
        stdout = b"core.repositoryformatversion\n0\0"
        stderr = b""
    elif "verify-commit" in argv:
        stdout = b""
        stderr = b"Good signature for gate-h@example.test\n"
    elif "log" in argv:
        stdout = (
            f"G\0{SIGNATURE_PRINCIPAL}\0{SIGNATURE_FINGERPRINT}\n"
        ).encode("utf-8")
        stderr = b""
    elif context == "source-freeze:head":
        stdout = ("c" * 40 + "\n").encode("utf-8")
        stderr = b""
    elif context == "source-freeze:status":
        stdout = b""
        stderr = b""
    elif context == "candidate-tree":
        stdout = (SIGNED_SOURCE_TREE + "\n").encode("utf-8")
        stderr = b""
    elif context.startswith("candidate-blob-id:"):
        relative = context.removeprefix("candidate-blob-id:")
        stdout = (_git_blob_id(FAULT_SOURCE_BYTES[relative]) + "\n").encode(
            "utf-8"
        )
        stderr = b""
    elif context.startswith("candidate-blob:"):
        relative = context.removeprefix("candidate-blob:")
        stdout = FAULT_SOURCE_BYTES[relative]
        stderr = b""
    elif context == "signed-source:tree":
        stdout = (SIGNED_SOURCE_TREE + "\n").encode("utf-8")
        stderr = b""
    elif context == "signed-source:ls-tree":
        stdout = b"".join(
            (
                f"{binding['mode']} blob {binding['git_blob']} "
                f"{binding['size_bytes']:7d}\t{binding['path']}\0"
            ).encode("utf-8")
            for binding in SIGNED_SOURCE_BINDINGS
        )
        stderr = b""
    elif context == "signed-source:archive":
        output = next(
            argument.removeprefix("--output=")
            for argument in argv
            if argument.startswith("--output=")
        )
        write_signed_source_archive(Path(output))
        stdout = b""
        stderr = b""
    else:
        raise AssertionError(f"unexpected signature command: {context}: {argv}")
    stdin_bytes = b"" if stdin_value is None else stdin_value
    return (
        {
            "context": context,
            "argv": list(argv),
            "cwd": str(results.gate_h_fault_contract.WORKSPACE),
            "environment": dict(environment),
            "stdin_mode": "devnull" if stdin_value is None else "bytes",
            "stdin_sha256": hashlib.sha256(stdin_bytes).hexdigest(),
            "stdin": results.gate_h_fault_contract.complete_stream(stdin_bytes),
            "started_utc": "2026-08-21T00:00:00Z",
            "completed_utc": "2026-08-21T00:00:00Z",
            "duration_ms": 0,
            "timed_out": False,
            "returncode": 0,
            "terminal_returncode": 0,
            "process_group_reaped": True,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "stdout": results.gate_h_fault_contract.complete_stream(stdout),
            "stderr": results.gate_h_fault_contract.complete_stream(stderr),
            "execution_error": None,
            "interrupted": False,
        },
        stdout,
        stderr,
    )


def _fault_execution_record(
    argv: list[str], environment: dict[str, str], stdout: bytes
) -> dict:
    timestamp = "2026-08-21T00:00:00Z"
    return {
        "argv": argv,
        "cwd": str(results.gate_h_fault_contract.WORKSPACE.resolve()),
        "environment": environment,
        "started_utc": timestamp,
        "completed_utc": timestamp,
        "duration_ms": 0,
        "timed_out": False,
        "returncode": 0,
        **_fault_stream_fields("stdout", stdout),
        **_fault_stream_fields("stderr", b""),
        "execution_error": None,
    }


def passing_gate_h_execution_provenance() -> dict:
    contract = results.gate_h_fault_contract
    home = Path(os.environ.get("HOME", str(Path.home()))).resolve()
    cargo_home = Path(os.environ.get("CARGO_HOME", str(home / ".cargo"))).resolve()
    rustup_home = Path(os.environ.get("RUSTUP_HOME", str(home / ".rustup"))).resolve()
    fixture_tool = Path(sys.executable).resolve()
    rg_value = shutil.which("rg")
    if rg_value is None:
        raise AssertionError("Gate-H fixture requires rg")
    tool_paths = {
        "cargo": fixture_tool,
        "git": fixture_tool,
        "rg": Path(rg_value).resolve(),
        "rustc": fixture_tool,
        "rustdoc": fixture_tool,
        "rustup": fixture_tool,
    }
    target = (contract.WORKSPACE / "target/gate-h-faults-v2").resolve()
    environment = {
        "CARGO_HOME": str(cargo_home),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": str(target),
        "CARGO_TERM_COLOR": "never",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": contract.FORMAL_SYSTEM_PATH,
        "RUST_BACKTRACE": "0",
        "RUSTC": str(tool_paths["rustc"]),
        "RUSTDOC": str(tool_paths["rustdoc"]),
        "TMPDIR": "/tmp",
    }
    tools = {}
    for name, path in tool_paths.items():
        version = _fault_execution_record(
            [str(path), *contract.TOOL_VERSION_ARGS[name]],
            environment,
            f"fixture {name} version\n".encode("utf-8"),
        )
        tools[name] = {
            "name": name,
            "path": str(path),
            "sha256": results.sha256_file(path),
            "size_bytes": path.stat().st_size,
            "version": version,
        }
    resolution_environment = {
        "CARGO_HOME": str(cargo_home),
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": contract.FORMAL_SYSTEM_PATH,
        "RUSTUP_HOME": str(rustup_home),
    }
    resolution_commands = {}
    for name in ("cargo", "rustc", "rustdoc"):
        command = _fault_execution_record(
            [tools["rustup"]["path"], "which", name],
            resolution_environment,
            f"{tools[name]['path']}\n".encode("utf-8"),
        )
        command["resolved_path"] = tools[name]["path"]
        resolution_commands[name] = command
    graph_stdout = (
        "aster-lab v0.1.0 (/fixture/aster-lab) features=[gate-h]\n"
        "└── aster-host v0.1.0 (/fixture/aster-host) features=[gate-h-formal]\n"
    ).encode("utf-8")
    graph = _fault_execution_record(
        [
            tools["cargo"]["path"],
            "tree",
            "--locked",
            "-p",
            "aster-lab",
            "--no-default-features",
            "--features",
            "gate-h",
            "-e",
            "no-dev,features",
            "--format",
            contract.FEATURE_GRAPH_FORMAT,
        ],
        environment,
        graph_stdout,
    )
    graph.update(
        {
            "assertion": {
                "required_exact_counts": {
                    "aster_lab_gate_h": 1,
                    "aster_host_gate_h_formal": 1,
                },
                "forbidden_tokens": [
                    "legacy-single-contact-service",
                    "legacy-lab",
                    "libp2p*",
                    "iroh*",
                ],
            },
            "observed": {
                "required_exact_counts": {
                    "aster_lab_gate_h": 1,
                    "aster_host_gate_h_formal": 1,
                },
                "forbidden_tokens": [],
            },
            "passed": True,
        }
    )
    return {
        "environment": environment,
        "cargo_config": contract.cargo_config_absence(cargo_home),
        "target_directory": {
            "path": str(target),
            "initially_absent": True,
            "created_empty": True,
        },
        "rustup_resolution": {
            "environment": resolution_environment,
            "commands": resolution_commands,
        },
        "tools": tools,
        "formal_feature_graph": graph,
        "passed": True,
    }


def passing_gate_h_fault_receipt(
    binary_sha256: str,
    binary_size: int,
    *,
    execution_provenance: dict,
    signature_trust: dict,
    signature_verification: dict,
    signed_source: dict,
) -> dict:
    contract = results.gate_h_fault_contract
    source_files = [
        {
            "path": relative,
            "git_blob": _git_blob_id(FAULT_SOURCE_BYTES[relative]),
            "sha256": hashlib.sha256(FAULT_SOURCE_BYTES[relative]).hexdigest(),
            "size_bytes": len(FAULT_SOURCE_BYTES[relative]),
        }
        for relative in contract.SOURCE_PATHS
    ]
    source_by_path = {binding["path"]: binding for binding in source_files}
    source_digest = contract.canonical_sha256(source_files)
    execution_provenance["signature_trust"] = signature_trust
    environment = execution_provenance["environment"]
    tools = execution_provenance["tools"]
    source_workspace = Path(signed_source["export"]["path"])
    timestamp = "2026-08-21T00:00:00Z"

    executables = {}
    builds = {}
    for index, (package, target) in enumerate(
        contract.TEST_TARGET_NAMES.items(), start=1
    ):
        binding = {
            "package": package,
            "target_name": target,
            "manifest_path": str(
                (source_workspace / contract.TEST_PACKAGE_MANIFESTS[package]).resolve()
            ),
            "path": f"/tmp/gate-h-{target}",
            "sha256": f"{index}" * 64,
            "size_bytes": 1,
        }
        executables[package] = binding
        builds[package] = {
            "package": package,
            "argv": [
                tools["cargo"]["path"],
                "test",
                "--locked",
                "-p",
                package,
                "--lib",
                *contract.TEST_PACKAGE_FEATURE_ARGS[package],
                "--no-run",
                "--message-format=json",
            ],
            "cwd": str(source_workspace.resolve()),
            "environment": environment,
            "source_files_sha256": source_digest,
            "started_utc": timestamp,
            "completed_utc": timestamp,
            "duration_ms": 0,
            "timed_out": False,
            "returncode": 0,
            **_fault_stream_fields("stdout", b""),
            **_fault_stream_fields("stderr", b""),
            "execution_error": None,
            "parse_error": None,
            "build_finished": True,
            "executable": binding,
            "passed": True,
        }
    build_plan = [
        {
            "package": package,
            "argv": builds[package]["argv"],
            "source_files_sha256": source_digest,
        }
        for package in sorted(builds)
    ]

    plan = contract.command_plan(tools["cargo"]["path"])
    commands = []
    for spec, planned in zip(contract.TEST_SPECS, plan, strict=True):
        output = (
            "running 1 test\n"
            f"test {spec.test_name} ... ok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
            "63 filtered out; finished in 0.01s\n"
        ).encode("utf-8")
        binding = executables[spec.package]
        commands.append(
            {
                **planned,
                "cwd": str(source_workspace.resolve()),
                "environment": environment,
                "started_utc": timestamp,
                "completed_utc": timestamp,
                "duration_ms": 1,
                "timed_out": False,
                "returncode": 0,
                **_fault_stream_fields("stdout", output),
                **_fault_stream_fields("stderr", b""),
                "execution_error": None,
                "exact_test_witnessed": True,
                "witness_error": None,
                "test_executable": binding,
                "test_executable_sha256_before": binding["sha256"],
                "test_executable_sha256_after": binding["sha256"],
                "cargo_reported_test_executable": binding["path"],
                "test_executable_unchanged": True,
            }
        )

    static_checks = contract.execute_static_checks(
        {"source_files": source_files},
        execution=execution_provenance,
    )
    if not all(check["passed"] for check in static_checks.values()):
        raise AssertionError("test fixture requires the exact static Gate-H checks to pass")
    static_plan = [
        {
            "name": name,
            "argv": check["argv"],
            "source_files": check["source_files"],
            "source_region": check["source_region"],
            "assertion": check["assertion"],
            "expected_returncode": check["expected_returncode"],
        }
        for name, check in sorted(static_checks.items())
    ]
    cases = {case: True for case in sorted(contract.MANDATORY_CASES)}
    executable_digests = {
        package: binding["sha256"] for package, binding in executables.items()
    }
    return {
        "schema": results.GATE_H_FAULT_SCHEMA,
        "created_utc": timestamp,
        "candidate_commit": "c" * 40,
        "candidate_tree": SIGNED_SOURCE_TREE,
        "worktree_clean": True,
        "worktree_status": [],
        "signature_status": "G",
        "signature_signer": SIGNATURE_PRINCIPAL,
        "signature_fingerprint": SIGNATURE_FINGERPRINT,
        "signature_trust": signature_trust,
        "signature_verification": signature_verification,
        "signed_source": signed_source,
        "requirements_sha256": results.REQUIREMENTS_SHA256,
        "proposal_0004_sha256": source_by_path[
            "docs/proposals/0004-shared-node-libp2p-retest.md"
        ]["sha256"],
        "source_files": source_files,
        "source_files_sha256": source_digest,
        "candidate_binary": "/tmp/candidate-aster-lab",
        "candidate_binary_sha256": binary_sha256,
        "candidate_binary_size_bytes": binary_size,
        "execution_provenance": execution_provenance,
        "command_plan": plan,
        "command_plan_sha256": contract.canonical_sha256(plan),
        "timeout_seconds_per_command": 60,
        "cases": cases,
        "commands": commands,
        "static_checks": static_checks,
        "static_check_plan_sha256": contract.canonical_sha256(static_plan),
        "static_checks_passed": True,
        "static_checks_error": None,
        "test_executable_build": {
            "builds": builds,
            "executables": executables,
            "passed": True,
        },
        "test_executable_build_plan_sha256": contract.canonical_sha256(build_plan),
        "test_executables_passed": True,
        "test_executable_digests_after_tests": executable_digests,
        "test_executables_integrity_after_tests": True,
        "source_integrity_after_tests": True,
        "integrity_error": None,
        "passed": True,
    }


def make_run(
    root: Path,
    *,
    scenario="primary",
    trial_passes=(True,),
    include_last_trial=True,
    arm="libp2p",
    payload_bytes=1_024,
    corrected_retest=False,
):
    trial_count = len(trial_passes)
    run_id = "0123abcd"
    image = "aster-lab:validation"
    frozen_binary = root / "candidate-aster-lab"
    frozen_binary.parent.mkdir(parents=True, exist_ok=True)
    frozen_binary.write_bytes(b"test candidate binary")
    manifest = {
        "schema": results.EXPERIMENT_SCHEMA,
        "run_id": run_id,
        "arm": arm,
        "discovery_source": None if arm == "native" else "aster-protected",
        "scenario": scenario,
        "trials": trial_count,
        "duration_ms": 120_000 if scenario == "idle" else 6_000,
        "payload_bytes": payload_bytes,
        "seed": 10_000,
        "execute": True,
        "binary_sha256": results.sha256_file(frozen_binary),
        "image": image,
        "image_content": {"id": "sha256:" + "b" * 64, "repo_digests": []},
        "source_freeze": {
            "survey_baseline": results.SURVEY_BASELINE,
            "candidate_commit": "c" * 40,
            "candidate_tree": SIGNED_SOURCE_TREE,
            "worktree_clean": True,
            "worktree_status": [],
            "requirements_sha256": results.REQUIREMENTS_SHA256,
            "build_command": "cargo build --release --locked -p aster-lab",
        },
    }
    if scenario == "gate-h" or corrected_retest:
        manifest["source_freeze"].update(
            {
                "proposal_0004_baseline": results.PROPOSAL_0004_BASELINE,
                "experiment_proposal": "0004",
                "signature_status": "G",
                "signature_signer": SIGNATURE_PRINCIPAL,
                "signature_fingerprint": SIGNATURE_FINGERPRINT,
            }
        )
    provider_digest = None
    if corrected_retest and arm == "libp2p":
        frozen_provider = root / "candidate-aster-libp2p-node"
        frozen_provider.write_bytes(b"test corrected libp2p provider")
        provider_digest = results.sha256_file(frozen_provider)
        manifest.update(
            {
                "provider_source_binary": "/build/aster-libp2p-node",
                "provider_binary": str(frozen_provider.resolve()),
                "provider_binary_sha256": provider_digest,
                "provider_build_command": (
                    "cargo build --release --locked -p aster-libp2p-node"
                ),
            }
        )
    if scenario == "gate-h":
        tool_path = Path("/bin/echo").resolve(strict=True)
        tool_sha256 = results.sha256_file(tool_path)
        buildx_tool_path = Path("/usr/bin/true").resolve(strict=True)
        buildx_tool_sha256 = results.sha256_file(buildx_tool_path)
        docker_socket = root / "docker.sock"
        docker_host = f"unix://{docker_socket.resolve()}"
        (root / "docker-config").mkdir()
        (root / "host-tmp").mkdir()
        host_environment = (
            results.gate_h_experiment_contract.gate_h_host_environment(
                root=root, docker_host=docker_host, home=Path("/tmp")
            )
        )
        host_environment_sha256 = results.canonical_sha256(host_environment)
        version_outputs = {
            "python": ("Python 3.13.7\n", ""),
            "git": ("git version 2.39.5\n", ""),
            "docker": (
                json.dumps(
                    {
                        "Client": {"Version": "28.0.0"},
                        "Server": {"Version": "28.0.0"},
                    }
                )
                + "\n",
                "",
            ),
            "docker_buildx": (
                "github.com/docker/buildx v0.28.0 fixture\n",
                "",
            ),
        }
        version_suffixes = {
            "python": ["--version"],
            "git": ["version", "--build-options"],
            "docker": ["version", "--format", "{{json .}}"],
            "docker_buildx": ["buildx", "version"],
        }
        tools = {}
        command_records = []
        for sequence, name in enumerate(
            ("python", "git", "docker", "docker_buildx"), start=1
        ):
            binding_path = (
                buildx_tool_path if name == "docker_buildx" else tool_path
            )
            version_executable = (
                tool_path if name == "docker_buildx" else binding_path
            )
            version_argv = [str(version_executable), *version_suffixes[name]]
            stdout, stderr = version_outputs[name]
            version = {
                "argv": version_argv,
                "command_sequence": sequence,
                "started_utc": "2026-08-21T00:00:00Z",
                "completed_utc": "2026-08-21T00:00:01Z",
                "duration_ms": 1,
                "returncode": 0,
                "stdout": stdout,
                "stderr": stderr,
            }
            binding = {
                "requested_path": str(binding_path),
                "invocation_path": str(binding_path),
                "path": str(binding_path),
                "size_bytes": binding_path.stat().st_size,
                "sha256": results.sha256_file(binding_path),
                "version": version,
            }
            if name == "docker":
                binding["socket_path"] = str(docker_socket.resolve())
            tools[name] = binding
            command_records.append(
                {
                    "sequence": sequence,
                    "utc": "2026-08-21T00:00:00Z",
                    "argv": version_argv,
                    "returncode": 0,
                    "stdout": stdout,
                    "stderr": stderr,
                    "environment_sha256": host_environment_sha256,
                }
            )
        manifest["host_execution"] = {
            "schema": results.GATE_H_HOST_EXECUTION_SCHEMA,
            "controller_argv": [
                str(tool_path),
                *results.gate_h_experiment_contract.GATE_H_PYTHON_FLAGS,
                str(
                    (
                        root
                        / "gate-h-signed-source/lab/ip_mesh_experiment.py"
                    ).resolve()
                ),
                "--execute",
            ],
            "controller_environment": host_environment,
            "environment": host_environment,
            "environment_sha256": host_environment_sha256,
            "tools": tools,
            "docker_endpoint": {
                "strategy": "explicit-unix-socket",
                "host": docker_host,
                "socket_path": str(docker_socket.resolve()),
                "version": json.loads(version_outputs["docker"][0]),
            },
            "docker_config": {
                "path": str((root / "docker-config").resolve()),
                "created_fresh": True,
                "initial_entries": [],
                "buildx_plugin": {
                    "directory_path": str(
                        (root / "docker-config/cli-plugins").resolve()
                    ),
                    "path": str(
                        (
                            root
                            / "docker-config/cli-plugins/docker-buildx"
                        ).resolve()
                    ),
                    "target": str(buildx_tool_path),
                    "symlink_size_bytes": len(
                        os.fsencode(str(buildx_tool_path))
                    ),
                    "symlink_sha256": hashlib.sha256(
                        os.fsencode(str(buildx_tool_path))
                    ).hexdigest(),
                    "resolved_path": str(buildx_tool_path),
                    "executable_size_bytes": buildx_tool_path.stat().st_size,
                    "executable_sha256": buildx_tool_sha256,
                    "installed": True,
                },
            },
        }
        signature_request = make_signature_request(root, git=tool_path)
        live_signature_trust = results.gate_h_signature.prepare_signature_trust(
            signature_request,
            workspace=results.gate_h_fault_contract.WORKSPACE,
            frozen_directory=root.resolve(),
            base_environment=host_environment,
            run_command=fake_signature_runner,
        )
        live_signature_anchor = (
            results.gate_h_signature.validate_signature_request_matches_trust(
                signature_request,
                live_signature_trust,
                workspace=results.gate_h_fault_contract.WORKSPACE,
                base_environment=host_environment,
                run_command=fake_signature_runner,
            )
        )
        live_signature_verification = results.gate_h_signature.verify_commit(
            "c" * 40,
            live_signature_trust,
            workspace=results.gate_h_fault_contract.WORKSPACE,
            base_environment=host_environment,
            run_command=fake_signature_runner,
        )
        source_freeze_git_commands = []
        for context, arguments in (
            ("source-freeze:head", ["rev-parse", "HEAD"]),
            (
                "candidate-tree",
                ["rev-parse", f"{'c' * 40}^{{tree}}"],
            ),
            (
                "source-freeze:status",
                ["status", "--porcelain=v1", "--untracked-files=all"],
            ),
            (
                "candidate-blob-id:data-mesh-requirements.md",
                [
                    "rev-parse",
                    f"{'c' * 40}:data-mesh-requirements.md",
                ],
            ),
            (
                "candidate-blob:data-mesh-requirements.md",
                [
                    "cat-file",
                    "blob",
                    f"{'c' * 40}:data-mesh-requirements.md",
                ],
            ),
        ):
            command, _stdout, _stderr = fake_signature_runner(
                results.gate_h_signature.git_argv(
                    live_signature_trust, arguments
                ),
                environment=live_signature_trust["git_environment"],
                stdin_value=None,
                timeout_seconds=30,
                context=context,
            )
            source_freeze_git_commands.append(command)
        manifest.update(
            {
                "signature_request": {
                    "git": str(signature_request.git),
                    "ssh_keygen": str(signature_request.ssh_keygen),
                    "ssh": str(signature_request.ssh),
                    "allowed_signers": str(signature_request.allowed_signers),
                    "principal": signature_request.principal,
                },
                "signature_trust": live_signature_trust,
                "signature_anchor": live_signature_anchor,
                "signature_verification": live_signature_verification,
            }
        )
        manifest["source_freeze"].update(
            {
                "git_binary": str(tool_path),
                "host_environment_sha256": host_environment_sha256,
                "signature_verification": live_signature_verification,
                "signature_trust_sha256": results.canonical_sha256(
                    live_signature_trust
                ),
                "requirements_git_blob": _git_blob_id(
                    FAULT_SOURCE_BYTES["data-mesh-requirements.md"]
                ),
                "requirements_size_bytes": len(
                    FAULT_SOURCE_BYTES["data-mesh-requirements.md"]
                ),
                "git_commands": source_freeze_git_commands,
            }
        )
        signed_source = results.gate_h_source.materialize_signed_tree(
            "c" * 40,
            SIGNED_SOURCE_TREE,
            live_signature_trust,
            workspace=results.gate_h_fault_contract.WORKSPACE,
            archive_path=(root / "gate-h-signed-source.tar").resolve(),
            export_root=(root / "gate-h-signed-source").resolve(),
            base_environment=host_environment,
            run_command=fake_signature_runner,
        )
        signed_source_sha256 = results.gate_h_source.canonical_sha256(
            signed_source
        )
        manifest["signed_source"] = signed_source
        manifest["signed_source_sha256"] = signed_source_sha256
        handoff_path = root / "gate-h-export-handoff.json"
        handoff_path.write_text(
            json.dumps({"schema": results.gate_h_experiment_contract.GATE_H_EXPORT_HANDOFF_SCHEMA})
            + "\n",
            encoding="utf-8",
        )
        handoff_path.chmod(0o444)
        signed_by_path = {
            binding["path"]: binding for binding in signed_source["files"]
        }

        def exported_binding(relative, *, code_root=None, materialized=True):
            source = signed_by_path[relative]
            binding_root = (
                Path(signed_source["export"]["path"])
                if code_root is None
                else Path(code_root)
            )
            path = (binding_root / relative).resolve()
            cached = None
            return {
                "raw_path": str(path),
                "path": str(path),
                "relative_path": relative,
                "mode": source["mode"],
                "filesystem_mode": (
                    "0555" if source["mode"] == "100755" else "0444"
                )
                if materialized
                else ("0755" if source["mode"] == "100755" else "0644"),
                "size_bytes": source["size_bytes"],
                "sha256": source["sha256"],
                "cached_path": cached,
                "cached_path_absent": True,
            }

        export_execution = {
            "schema": results.GATE_H_EXPORT_EXECUTION_SCHEMA,
            "sentinel_sha256": hashlib.sha256(
                b"aster-gate-h-signed-controller-v1"
            ).hexdigest(),
            "repository_workspace": signed_source["workspace"],
            "code_root": signed_source["export"]["path"],
            "python": {
                "invocation": tools["python"]["invocation_path"],
                "path": tools["python"]["path"],
                "size_bytes": tools["python"]["size_bytes"],
                "sha256": tools["python"]["sha256"],
            },
            "argv": manifest["host_execution"]["controller_argv"],
            "environment": host_environment,
            "handoff": {
                "path": str(handoff_path.resolve()),
                "size_bytes": handoff_path.stat().st_size,
                "sha256": results.sha256_file(handoff_path),
                "payload_sha256": "a" * 64,
            },
            "runner": exported_binding("lab/ip_mesh_experiment.py"),
            "modules": {
                name: exported_binding(relative)
                for name, relative in results.gate_h_experiment_contract.GATE_H_EXPORT_MODULES.items()
            },
            "bootstrap_modules": {
                name: exported_binding(
                    relative,
                    code_root=results.gate_h_fault_contract.WORKSPACE,
                    materialized=False,
                )
                for name, relative in {
                    "ip_mesh_experiment": "lab/ip_mesh_experiment.py",
                    **results.gate_h_experiment_contract.GATE_H_EXPORT_MODULES,
                }.items()
            },
            "signature_anchor": live_signature_anchor,
            "sys_path": [
                str((Path(signed_source["export"]["path"]) / "lab").resolve()),
                "/fixture-python-stdlib",
            ],
            "bytecode": {
                "flags": {
                    "dont_write_bytecode": 1,
                    "ignore_environment": 1,
                    "no_site": 1,
                    "no_user_site": 1,
                },
                "pycache_or_pyc_before": [],
                "pycache_or_pyc_after": None,
            },
            "modules_after": None,
            "passed": False,
        }
        manifest["export_execution"] = export_execution
        build_argv = results.gate_h_build_argv(image)
        build_command = results.shlex.join(build_argv)
        manifest["source_freeze"]["build_command"] = build_command
        extracted_binary = root / "gate-h-image-aster-lab"
        extracted_binary.write_bytes(frozen_binary.read_bytes())
        binary_digest = results.sha256_file(frozen_binary)
        extraction_container = f"aster-mesh-{run_id}-t00-build-extract"
        build_cwd = signed_source["export"]["path"]
        command_records.extend(
            [
            {
                "sequence": 5,
                "utc": "2026-08-21T00:00:00Z",
                "argv": [str(tool_path), *build_argv[1:]],
                "cwd": build_cwd,
                "returncode": 0,
                "stdout": "built",
                "stderr": "",
                "environment_sha256": host_environment_sha256,
            },
            {
                "sequence": 6,
                "utc": "2026-08-21T00:00:00Z",
                "argv": [
                    str(tool_path),
                    "create",
                    "--name",
                    extraction_container,
                    image,
                ],
                "returncode": 0,
                "stdout": "container-id",
                "stderr": "",
                "environment_sha256": host_environment_sha256,
            },
            {
                "sequence": 7,
                "utc": "2026-08-21T00:00:00Z",
                "argv": [
                    str(tool_path),
                    "cp",
                    f"{extraction_container}:{results.GATE_H_IMAGE_BINARY_PATH}",
                    str(extracted_binary.resolve()),
                ],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "environment_sha256": host_environment_sha256,
            },
            {
                "sequence": 8,
                "utc": "2026-08-21T00:00:00Z",
                "argv": [str(tool_path), "rm", "--force", extraction_container],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "environment_sha256": host_environment_sha256,
            },
            ]
        )
        resource_cleanup_receipts = [
            {
                "schema": results.GATE_H_RESOURCE_CLEANUP_SCHEMA,
                "completed_utc": "2026-08-21T00:00:02Z",
                "reason": "gate-h-binary-extraction",
                "passed": True,
                "resources": [
                    {
                        "kind": "container",
                        "name": extraction_container,
                        "owner": "gate-h-binary-extraction",
                        "registration_sequence": 1,
                        "remove_attempts": [
                            {
                                "argv": [
                                    str(tool_path),
                                    "rm",
                                    "--force",
                                    extraction_container,
                                ],
                                "returncode": 0,
                            }
                        ],
                        "absence_check": None,
                        "settled": True,
                    }
                ],
                "remaining_registered_resources": 0,
                "deferred_signals": [],
            }
        ]
        command_sequence = 8
        registration_sequence = 1
        for trial in range(1, 11):
            registration_sequence += 5
            trial_root = root / f"trial-{trial:02d}"
            for role, offline_command in (
                (
                    "prepare",
                    [
                        "mesh-prepare",
                        "--root",
                        "/lab/run",
                        "--seed",
                        str(manifest["seed"] + trial),
                        "--payload-bytes",
                        str(payload_bytes),
                    ],
                ),
                (
                    "custody",
                    [
                        "mesh-verify-relay",
                        "--root",
                        "/lab/run",
                        "--invocation",
                        f"t{trial:02d}_gate_pre",
                    ],
                ),
                (
                    "delivery",
                    [
                        "mesh-consume",
                        "--root",
                        "/lab/run",
                        "--invocation",
                        f"t{trial:02d}_gate_post",
                    ],
                ),
            ):
                registration_sequence += 1
                name = f"aster-mesh-{run_id}-t{trial:02d}-offline-{role}"
                run_argv = [
                    str(tool_path),
                    "run",
                    "--rm",
                    "--name",
                    name,
                    "--pull=never",
                    "--network",
                    "none",
                    "--read-only",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,nodev,size=64m",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--mount",
                    (
                        f"type=bind,src={frozen_binary.resolve()},"
                        "dst=/experiment/aster-lab,readonly"
                    ),
                    "--mount",
                    f"type=bind,src={trial_root.resolve()},dst=/lab/run",
                    "--entrypoint",
                    "/experiment/aster-lab",
                    image,
                    *offline_command,
                ]
                remove_argv = [str(tool_path), "rm", "--force", name]
                enumerate_argv = [
                    str(tool_path),
                    "container",
                    "ls",
                    "--all",
                    "--filter",
                    f"name=^/{name}$",
                    "--format",
                    "{{.Names}}",
                ]
                for argv, returncode in (
                    (run_argv, 0),
                    (remove_argv, 1),
                    (enumerate_argv, 0),
                ):
                    command_sequence += 1
                    command_records.append(
                        {
                            "sequence": command_sequence,
                            "utc": "2026-08-21T00:00:02Z",
                            "argv": argv,
                            "returncode": returncode,
                            "stdout": "",
                            "stderr": "" if returncode == 0 else "No such container",
                            "environment_sha256": host_environment_sha256,
                        }
                    )
                resource_cleanup_receipts.append(
                    {
                        "schema": results.GATE_H_RESOURCE_CLEANUP_SCHEMA,
                        "completed_utc": "2026-08-21T00:00:02Z",
                        "reason": f"offline:{offline_command[0]}",
                        "passed": True,
                        "resources": [
                            {
                                "kind": "container",
                                "name": name,
                                "owner": f"offline:{offline_command[0]}",
                                "registration_sequence": registration_sequence,
                                "remove_attempts": [
                                    {"argv": remove_argv, "returncode": 1}
                                ],
                                "absence_check": {
                                    "argv": enumerate_argv,
                                    "returncode": 0,
                                    "retained_names": [],
                                },
                                "settled": True,
                            }
                        ],
                        "remaining_registered_resources": 5,
                        "deferred_signals": [],
                    }
                )
        (root / "gate-h-resource-cleanup.jsonl").write_text(
            "".join(
                json.dumps(receipt, sort_keys=True) + "\n"
                for receipt in resource_cleanup_receipts
            ),
            encoding="utf-8",
        )
        (root / "commands.jsonl").write_text(
            "".join(json.dumps(record) + "\n" for record in command_records),
            encoding="utf-8",
        )
        provenance_receipt = {
            "schema": results.GATE_H_BINARY_PROVENANCE_SCHEMA,
            "candidate_commit": "c" * 40,
            "build_argv": build_argv,
            "build_command": build_command,
            "build_cwd": build_cwd,
            "signed_source_sha256": signed_source_sha256,
            "build_command_sequence": 5,
            "image": image,
            "image_content": manifest["image_content"],
            "image_binary_path": results.GATE_H_IMAGE_BINARY_PATH,
            "extracted_binary_file": extracted_binary.name,
            "supplied_binary_sha256": binary_digest,
            "image_binary_sha256": binary_digest,
            "extraction": {
                "container": extraction_container,
                "create_sequence": 6,
                "copy_sequence": 7,
                "cleanup_sequence": 8,
                "cleanup_returncode": 0,
            },
        }
        provenance_path = root / "gate-h-binary-provenance.json"
        write_json(provenance_path, provenance_receipt)
        manifest["gate_h_binary_provenance"] = {
            "path": provenance_path.name,
            "sha256": results.sha256_file(provenance_path),
            "binary_sha256": binary_digest,
            "signed_source_sha256": signed_source_sha256,
        }
        fault_execution = passing_gate_h_execution_provenance()
        fault_signature_root = root / "fault-signature-trust"
        fault_signature_root.mkdir()
        fault_signature_trust = results.gate_h_signature.prepare_signature_trust(
            signature_request,
            workspace=results.gate_h_fault_contract.WORKSPACE,
            frozen_directory=fault_signature_root.resolve(),
            base_environment=fault_execution["environment"],
            run_command=fake_signature_runner,
        )
        fault_signed_source = results.gate_h_source.materialize_signed_tree(
            "c" * 40,
            SIGNED_SOURCE_TREE,
            fault_signature_trust,
            workspace=results.gate_h_fault_contract.WORKSPACE,
            archive_path=(root / "fault-signed-source.tar").resolve(),
            export_root=(root / "fault-signed-source").resolve(),
            base_environment=fault_execution["environment"],
            run_command=fake_signature_runner,
        )
        fault_execution["signed_source"] = fault_signed_source
        fault_execution["formal_feature_graph"]["cwd"] = fault_signed_source[
            "export"
        ]["path"]
        fault_export_root = Path(fault_signed_source["export"]["path"])
        fault_files = {
            item["path"]: item for item in fault_signed_source["files"]
        }

        def fault_module_binding(relative, *, root_path, materialized):
            source = fault_files[relative]
            path = (Path(root_path) / relative).resolve()
            return {
                "raw_path": str(path),
                "path": str(path),
                "relative_path": relative,
                "mode": source["mode"],
                "filesystem_mode": (
                    "0555" if source["mode"] == "100755" else "0444"
                )
                if materialized
                else ("0755" if source["mode"] == "100755" else "0644"),
                "size_bytes": source["size_bytes"],
                "sha256": source["sha256"],
                "cached_path": None,
                "cached_path_absent": True,
            }

        fault_modules = {
            name: fault_module_binding(
                relative, root_path=fault_export_root, materialized=True
            )
            for name, relative in results.gate_h_experiment_contract.GATE_H_EXPORT_MODULES.items()
        }
        fault_bootstrap_modules = {
            name: fault_module_binding(
                relative,
                root_path=results.gate_h_fault_contract.WORKSPACE,
                materialized=False,
            )
            for name, relative in results.gate_h_experiment_contract.GATE_H_EXPORT_MODULES.items()
        }
        fault_python = Path(sys.executable).resolve()
        fault_export_environment = {
            **fault_execution["environment"],
            "PYTHONDONTWRITEBYTECODE": "1",
            "ASTER_GATE_H_REPOSITORY_WORKSPACE": str(
                results.gate_h_fault_contract.WORKSPACE
            ),
            "ASTER_GATE_H_SIGNED_CONTROLLER": str(
                fault_export_root / "lab/gate_h_faults.py"
            ),
            "__CF_USER_TEXT_ENCODING": f"0x{os.getuid():X}:0x0:0x0",
        }
        fault_export_anchor = (
            results.gate_h_signature.validate_signature_request_matches_trust(
                signature_request,
                fault_signature_trust,
                workspace=results.gate_h_fault_contract.WORKSPACE,
                base_environment=fault_execution["environment"],
                run_command=fake_signature_runner,
            )
        )
        fault_export_execution = {
            "schema": results.GATE_H_EXPORT_EXECUTION_SCHEMA,
            "sentinel_sha256": "a" * 64,
            "repository_workspace": str(results.gate_h_fault_contract.WORKSPACE),
            "code_root": str(fault_export_root),
            "python": {
                "invocation": str(fault_python),
                "path": str(fault_python),
                "size_bytes": fault_python.stat().st_size,
                "sha256": results.sha256_file(fault_python),
            },
            "argv": [
                str(fault_python),
                *results.gate_h_experiment_contract.GATE_H_PYTHON_FLAGS,
                str(fault_export_root / "lab/gate_h_faults.py"),
                "--candidate-binary",
                str(frozen_binary.resolve()),
            ],
            "environment": fault_export_environment,
            "handoff": {
                "path": str(
                    results.gate_h_fault_contract.WORKSPACE
                    / "target/gate-h-faults-v2/gate-h-fault-bootstrap.json"
                ),
                "size_bytes": 1,
                "sha256": "b" * 64,
                "payload_sha256": "c" * 64,
            },
            "runner": fault_modules["gate_h_faults"],
            "modules": fault_modules,
            "bootstrap_modules": fault_bootstrap_modules,
            "signature_anchor": fault_export_anchor,
            "sys_path": [str(fault_export_root / "lab"), "/fixture-python-stdlib"],
            "bytecode": {
                "flags": {
                    "dont_write_bytecode": 1,
                    "ignore_environment": 1,
                    "no_site": 1,
                    "no_user_site": 1,
                },
                "pycache_or_pyc_before": [],
                "pycache_or_pyc_after": [],
            },
            "modules_after": fault_modules,
            "passed": True,
        }
        fault_execution["export_execution"] = fault_export_execution
        fault_signature_verification = results.gate_h_signature.verify_commit(
            "c" * 40,
            fault_signature_trust,
            workspace=results.gate_h_fault_contract.WORKSPACE,
            base_environment=fault_execution["environment"],
            run_command=fake_signature_runner,
        )
        fault_receipt = passing_gate_h_fault_receipt(
            binary_digest,
            frozen_binary.stat().st_size,
            execution_provenance=fault_execution,
            signature_trust=fault_signature_trust,
            signature_verification=fault_signature_verification,
            signed_source=fault_signed_source,
        )
        fault_receipt["export_execution"] = fault_export_execution
        fault_path = root / "gate-h-fault-receipt.json"
        write_json(fault_path, fault_receipt)
        fault_signature_anchor = (
            results.gate_h_signature.validate_signature_request_matches_trust(
                signature_request,
                fault_signature_trust,
                workspace=results.gate_h_fault_contract.WORKSPACE,
                base_environment=host_environment,
                run_command=fake_signature_runner,
            )
        )
        validation_git_commands = []
        candidate_git_specs = [
            ("candidate-tree", ["rev-parse", f"{'c' * 40}^{{tree}}"])
        ]
        for relative in results.gate_h_fault_contract.SOURCE_PATHS:
            candidate_git_specs.extend(
                (
                    (
                        f"candidate-blob-id:{relative}",
                        ["rev-parse", f"{'c' * 40}:{relative}"],
                    ),
                    (
                        f"candidate-blob:{relative}",
                        ["cat-file", "blob", f"{'c' * 40}:{relative}"],
                    ),
                )
            )
        for context, arguments in candidate_git_specs:
            command, _stdout, _stderr = fake_signature_runner(
                results.gate_h_signature.git_argv(
                    live_signature_trust, arguments
                ),
                environment=live_signature_trust["git_environment"],
                stdin_value=None,
                timeout_seconds=30,
                context=context,
            )
            validation_git_commands.append(command)
        manifest["gate_h_fault_receipt"] = {
            "path": fault_path.name,
            "sha256": results.sha256_file(fault_path),
            "cases": fault_receipt["cases"],
            "candidate_binary_sha256": binary_digest,
            "signature_anchor": fault_signature_anchor,
            "validation_git_commands": validation_git_commands,
        }
        write_json(
            root / "gate-h-signature-final.json",
            {
                "schema": results.GATE_H_SIGNATURE_FINAL_SCHEMA,
                "completed_utc": "2026-08-21T00:01:00Z",
                "principal": signature_request.principal,
                "signature_trust_sha256": results.canonical_sha256(
                    live_signature_trust
                ),
                "frozen_allowed_signers": {
                    "path": live_signature_trust["allowed_signers"][
                        "frozen_path"
                    ],
                    "size_bytes": live_signature_trust["allowed_signers"][
                        "frozen_size_bytes"
                    ],
                    "sha256": live_signature_trust["allowed_signers"][
                        "frozen_sha256"
                    ],
                },
                "tools": {
                    name: {
                        "path": binding["path"],
                        "size_bytes": binding["size_bytes"],
                        "sha256": binding["sha256"],
                    }
                    for name, binding in sorted(
                        live_signature_trust["tools"].items()
                    )
                },
                "passed": True,
            },
        )
        buildx_ref_name = "a" * 25
        buildx_ref = json.dumps(
            {
                "Target": "default",
                "LocalPath": str((root / "gate-h-signed-source").resolve()),
                "DockerfilePath": str(
                    (root / "gate-h-signed-source/lab/Dockerfile").resolve()
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        buildx_files = {
            ".lock": ("0600", b""),
            ".buildNodeID": ("0600", b"0123456789abcdef"),
            "activity/default": ("0600", b"2026-08-21T00:00:00Z"),
            f"refs/default/default/{buildx_ref_name}": ("0644", buildx_ref),
        }
        buildx_entries = [
            {"path": path, "kind": "directory", "mode": "0700"}
            for path in (
                ".",
                "activity",
                "defaults",
                "instances",
                "refs",
                "refs/default",
                "refs/default/default",
            )
        ]
        buildx_entries.extend(
            {
                "path": path,
                "kind": "file",
                "mode": mode,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "content_base64": base64.b64encode(data).decode("ascii"),
            }
            for path, (mode, data) in buildx_files.items()
        )
        buildx_entries.sort(key=lambda entry: entry["path"])
        buildx_state_cleanup = {
            "path": str((root / "docker-config/buildx").resolve()),
            "present_before": True,
            "inventory": {
                "path": str((root / "docker-config/buildx").resolve()),
                "entry_count": len(buildx_entries),
                "total_file_bytes": sum(len(data) for _, data in buildx_files.values()),
                "entries": buildx_entries,
                "entries_sha256": results.canonical_sha256(buildx_entries),
            },
            "removed": True,
            "errors": [],
            "passed": True,
        }
        write_json(
            root / "gate-h-host-execution-final.json",
            {
                "schema": results.GATE_H_HOST_EXECUTION_FINAL_SCHEMA,
                "completed_utc": "2026-08-21T00:01:00Z",
                "environment_sha256": host_environment_sha256,
                "docker_buildx_cleanup": {
                    "plugin_path": str(
                        (
                            root
                            / "docker-config/cli-plugins/docker-buildx"
                        ).resolve()
                    ),
                    "expected_target": str(buildx_tool_path),
                    "plugin_present_before": True,
                    "observed_target": str(buildx_tool_path),
                    "plugin_was_installed": True,
                    "plugin_removed": True,
                    "directory_path": str(
                        (root / "docker-config/cli-plugins").resolve()
                    ),
                    "directory_removed": True,
                    "state_cleanup": buildx_state_cleanup,
                    "errors": [],
                    "docker_config_entries": [],
                    "passed": True,
                },
                "docker_config_entries": [],
                "owned_processes": 0,
                "registered_docker_resources": 0,
                "passed": True,
            },
        )
        export_execution_after = json.loads(json.dumps(export_execution))
        export_execution_after["modules_after"] = export_execution_after["modules"]
        export_execution_after["bytecode"]["pycache_or_pyc_after"] = []
        export_execution_after["passed"] = True
        write_json(
            root / "gate-h-export-execution-final.json",
            {
                "schema": results.GATE_H_EXPORT_EXECUTION_SCHEMA,
                "completed_utc": "2026-08-21T00:01:00Z",
                "before_sha256": results.canonical_sha256(export_execution),
                "before": export_execution,
                "after": export_execution_after,
                "passed": True,
            },
        )

    def make_node_receipt(**kwargs):
        if corrected_retest and arm == "libp2p":
            kwargs.update(
                schema=results.LIBP2P_SHARED_NODE_SCHEMA,
                provider_binary_sha256=provider_digest,
            )
        return node_receipt(**kwargs)
    summary = {
        "schema": results.EXPERIMENT_SCHEMA,
        "arm": arm,
        "scenario": scenario,
        "requested_trials": trial_count,
        "passed_trials": sum(trial_passes),
        "all_passed": all(trial_passes),
        "results": [
            str(root / f"trial-{trial:02d}" / "result.json")
            for trial in range(1, trial_count + 1)
        ],
    }
    write_json(root / "manifest.json", manifest)
    write_json(root / "summary.json", summary)
    limit = trial_count if include_last_trial else trial_count - 1
    for trial, passed in enumerate(trial_passes[:limit], start=1):
        common = {
            "schema": results.EXPERIMENT_SCHEMA,
            "arm": arm,
            "scenario": scenario,
            "trial": trial,
            "passed": passed,
            "elapsed_ms": trial * 100,
        }
        if scenario == "gate-h":
            identities = {"a": "a" * 64, "b": "b" * 64, "c": "c" * 64}
            receipts = {
                role: native_shared_node_receipt(clean=True)
                for role in results.RECEIPT_ROLES[scenario]
            }
            expected = {
                "a": (identities["a"], [identities["b"]]),
                "b_pre": (
                    identities["b"],
                    [identities["a"], identities["c"]],
                ),
                "b_post": (identities["b"], [identities["c"]]),
                "c": (identities["c"], [identities["b"]]),
            }
            for role, (identity, peers) in expected.items():
                receipts[role].update(
                    {
                        "identity": identity,
                        "authenticated_peers": peers,
                        "admitted_peers": peers,
                        "unauthorized_peers": [],
                    }
                )
            carrier_ids = {
                "a": "1" * 64,
                "b_pre": "2" * 64,
                "b_post": "2" * 64,
                "c": "3" * 64,
            }
            for role, carrier_id in carrier_ids.items():
                receipts[role]["carrier_id"] = carrier_id
            receipts["b_pre"]["admitted_contact_high_water"] = 2
            control_bytes = b"signed Gate-H authorization control"
            control_digest = hashlib.sha256(control_bytes).hexdigest()
            authorization_control = {
                "authorization_control_id": control_digest,
                "authorization_control_subject": "9" * 64,
                "authorization_control_sha256": control_digest,
                "authorization_control_bytes": len(control_bytes),
            }
            control_path = root / f"trial-{trial:02d}" / "b" / (
                "gate-h-authorization-control.bin"
            )
            control_path.parent.mkdir(parents=True, exist_ok=True)
            control_path.write_bytes(control_bytes)
            control_path.chmod(0o600)
            receipts["b_pre"].update(
                {
                    "authorization_generation_current": 1,
                    "authorization_generation_mismatches": 1,
                    "gate_h_control_id": control_digest,
                    "gate_h_generation_before": 0,
                    "gate_h_generation_after": 1,
                    "gate_h_stale_target_peer": identities["c"],
                    "gate_h_stale_target_contact": 7,
                    "gate_h_stale_queued_frames": 2,
                    "gate_h_stale_send_frames_before": 4,
                    "gate_h_stale_send_frames_after": 4,
                    "gate_h_stale_send_bytes_before": 400,
                    "gate_h_stale_send_bytes_after": 400,
                    "gate_h_stale_zero_bytes_emitted": True,
                    "gate_h_stale_contacts_retired": 2,
                    "gate_h_provider_epoch_rotations": 1,
                    "gate_h_fresh_target_contact": 11,
                    "gate_h_fresh_target_generation": 1,
                    "gate_h_fresh_aster_frames_sent": 1,
                    "gate_h_fresh_aster_bytes_sent": 64,
                    "gate_h_completed": True,
                }
            )
            receipts["c"].update(
                {
                    "authorization_generation_current": 1,
                    "authorization_generation_mismatches": 1,
                }
            )
            b_events = [
                {
                    "event": "stale_frame_retained",
                    "peer": identities["c"],
                    "contact": 7,
                    "queued_frames": 2,
                    "blocked_attempts": 1,
                    "blocked_bytes": 64,
                    "sent_frames": 4,
                    "sent_bytes": 400,
                },
                {
                    "event": "authorization_control_applied",
                    "control_id": control_digest,
                    "generation_before": 0,
                    "generation_after": 1,
                    "contacts_invalidated": 2,
                },
                {
                    "event": "generation_checked",
                    "contact": 7,
                    "peer": identities["c"],
                    "result": "mismatch",
                    "expected_generation": 0,
                    "observed_generation": 1,
                },
                {
                    "event": "stale_generation_blocked",
                    "peer": identities["c"],
                    "contact": 7,
                    "queued_frames": 2,
                    "sent_frames_before": 4,
                    "sent_frames_after": 4,
                    "sent_bytes_before": 400,
                    "sent_bytes_after": 400,
                    "zero_bytes_emitted": True,
                },
                {"event": "stale_contacts_retired", "contacts": [7, 8], "count": 2},
                {
                    "event": "carrier_session_epoch_rotated",
                    "cause": "local-signed-control",
                    "generation": 1,
                    "carrier_id": carrier_ids["b_pre"],
                    "old_instance_nonce": "4" * 32,
                    "new_instance_nonce": "5" * 32,
                    "stale_contacts_retired": 2,
                },
                {
                    "event": "fresh_authorized_progress",
                    "peer": identities["c"],
                    "contact": 11,
                    "generation": 1,
                    "aster_frames_sent": 1,
                    "aster_bytes_sent": 64,
                },
            ]
            c_events = [
                {
                    "event": "generation_checked",
                    "contact": 9,
                    "peer": identities["b"],
                    "result": "mismatch",
                    "expected_generation": 0,
                    "observed_generation": 1,
                },
                {
                    "event": "authorization_generation_sessions_retired",
                    "generation": 1,
                    "trigger_contact": 9,
                    "contacts_retired": 1,
                },
                {
                    "event": "carrier_session_epoch_rotated",
                    "cause": "authorization-generation-changed",
                    "generation": 1,
                    "carrier_id": carrier_ids["c"],
                    "old_instance_nonce": "6" * 32,
                    "new_instance_nonce": "7" * 32,
                    "stale_contacts_retired": 1,
                },
            ]
            for role, events in (("b", b_events), ("c", c_events)):
                path = root / f"trial-{trial:02d}" / role / (
                    f"native-mesh-t{trial:02d}_gate_pre-events.jsonl"
                )
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    "".join(json.dumps(event) + "\n" for event in events),
                    encoding="utf-8",
                )
            process_commands = results.expected_gate_h_process_commands(
                trial=trial,
                run_id=run_id,
                duration_ms=6_000,
                identities=identities,
                item_id="d" * 64,
                docker_binary=str(tool_path),
            )
            sequence_base = 100 + (trial - 1) * 10
            sequence_offsets = {
                "b_pre": 1,
                "c_continuous": 3,
                "a_pre": 5,
                "b_post": 9,
            }
            for role, argv in process_commands.items():
                sequence = sequence_base + sequence_offsets[role]
                prefix = root / f"process-{sequence:05d}"
                write_json(
                    prefix.with_suffix(".command.json"),
                    {
                        "sequence": sequence,
                        "utc": "2026-08-21T00:00:00Z",
                        "argv": argv,
                        "environment_sha256": host_environment_sha256,
                    },
                )
                prefix.with_suffix(".stdout.log").write_text(
                    f"{role} completed\n", encoding="utf-8"
                )
                prefix.with_suffix(".stderr.log").write_text("", encoding="utf-8")
                write_json(
                    prefix.with_suffix(".result.json"),
                    {
                        "returncode": 0,
                        "completed_utc": "2026-08-21T00:00:01Z",
                        "timed_out": False,
                    },
                )
            live_control = (
                results.gate_h_experiment_contract.validate_gate_h_live_control_evidence(
                    control=authorization_control,
                    identities=identities,
                    receipts=receipts,
                    b_events=b_events,
                    c_events=c_events,
                )
            )
            common.update(
                {
                    "identities": identities,
                    "item_id": "d" * 64,
                    "envelope_id": "e" * 64,
                    "authorization_control": authorization_control,
                    "live_control": live_control,
                    "b_pre_emission_mode": "flash-only",
                    "pre_restart_all_three_admitted_ms": 100,
                    "b_pre_restart_custody_observed_ms": 200,
                    "b_pre_restart_admitted_contact_high_water": 2,
                    "durable_item_observations": {
                        "b_custody": {
                            "item_id": "d" * 64,
                            "present": True,
                            "elapsed_ms": 200,
                        },
                        "c_at_b_custody": {
                            "item_id": "d" * 64,
                            "present": False,
                            "elapsed_ms": 190,
                        },
                        "c_pre_restart": {
                            "item_id": "d" * 64,
                            "present": False,
                            "elapsed_ms": 225,
                        },
                    },
                    "c_item_absent_before_b_restart": True,
                    "publisher_offline_during_post_restart_delivery": True,
                    "post_restart_bc_admitted_ms": 125,
                    "c_post_restart_item_observed_ms": 275,
                    "fresh_process_authentication_after_restart": True,
                    "process_durations_ms": {
                        "a_pre": 6_000,
                        "b_pre": 6_000,
                        "c_continuous": 17_000,
                        "b_post": 6_000,
                    },
                    "c_pre_restart_admitted_contact_ids_for_b": [7],
                    "c_post_restart_new_admitted_contact_ids_for_b": [11],
                    "c_final_admitted_contact_ids_for_b": [7, 11],
                    "c_distinct_admitted_contacts_for_b": 2,
                    "internal_only_segmented_networks": True,
                    "pre_process_returncodes": {"a": 0, "b": 0},
                    "post_process_returncodes": {"b": 0, "c": 0},
                    "custody": {
                        "exact_envelope": True,
                        "application_unreadable": True,
                        "payload_absent_at_rest": True,
                        "payload_digest_absent_at_rest": True,
                    },
                    "delivery": {
                        "same_item": True,
                        "same_envelope": True,
                        "application_acknowledged": True,
                        "immediate_post_ack_deliveries": 0,
                        "post_restart_deliveries": 0,
                    },
                    "receipts": receipts,
                }
            )
        elif scenario == "primary":
            receipts = {
                role: make_node_receipt(elapsed=trial * 10 + offset)
                for offset, role in enumerate(results.RECEIPT_ROLES[scenario])
            }
            receipts["ab_b"]["experiment_resources"][
                "durable_item_present_before_contact"
            ] = False
            receipts["ab_b"]["experiment_resources"][
                "durable_item_first_observed_ms_from_process_launch"
            ] = trial * 20
            receipts["bc_c"]["experiment_resources"][
                "durable_item_present_before_contact"
            ] = False
            receipts["bc_c"]["experiment_resources"][
                "durable_item_first_observed_ms_from_process_launch"
            ] = trial * 30
            common["node_receipts"] = receipts
        elif scenario == "idle":
            common.update(
                {
                    "duration_ms": 120_000,
                    "settle_ms": 60_000,
                    "cpu_usage_usec_total": 120_000,
                    "cpu_usage_usec_settling": 60_000,
                    "cpu_percent_of_one_core_total": 0.1,
                    "settled_network_bytes": 1_000,
                    "settled_network_bytes_per_minute": 1_000.0,
                    "memory_current_after_settle_bytes": 2_000,
                    "memory_peak_bytes": 3_000,
                    "receipt": make_node_receipt(resources=False),
                }
            )
        elif scenario == "live-relay":
            identities = {"a": "a" * 64, "b": "b" * 64, "c": "c" * 64}
            receipts = {
                role: make_node_receipt()
                for role in results.RECEIPT_ROLES[scenario]
            }
            expected = {
                "a": [identities["b"]],
                "b": [identities["a"], identities["c"]],
                "c": [identities["b"]],
            }
            for role, receipt in receipts.items():
                receipt.update(
                    {
                        "identity": identities[role],
                        "authenticated_peers": expected[role],
                        "admitted_peers": expected[role],
                        "unauthorized_peers": [],
                    }
                )
            receipts["b"]["active_contact_high_water"] = 2
            receipts["b"]["admitted_contact_high_water"] = 2
            common.update(
                {
                    "identities": identities,
                    "item_id": "d" * 64,
                    "envelope_id": "e" * 64,
                    "bc_authenticated_before_a_started": True,
                    "bc_prerequisite_ms": 125,
                    "all_nodes_running_when_c_observed": True,
                    "c_item_observed_ms_from_process_launch": 450,
                    "b_commit_fanout_observed_before_c_verification": True,
                    "b_commit_fanout": {
                        "contact": 7,
                        "source_peer": "a" * 64,
                        "contacts_planned": 1,
                        "contacts_queued": 1,
                    },
                    "a_c_contact_count": 0,
                    "relay_active_contact_high_water": 2,
                    "relay_admitted_contact_high_water": 2,
                    "internal_only_segmented_networks": True,
                    "custody": {
                        "exact_envelope": True,
                        "application_unreadable": True,
                        "payload_absent_at_rest": True,
                        "payload_digest_absent_at_rest": True,
                    },
                    "delivery": {
                        "same_item": True,
                        "same_envelope": True,
                        "application_acknowledged": True,
                        "immediate_post_ack_deliveries": 0,
                        "post_restart_deliveries": 0,
                    },
                    "receipts": receipts,
                }
            )
            for role, observed in (("b", 350), ("c", 450)):
                resources = common["receipts"][role]["experiment_resources"]
                resources["durable_item_present_before_contact"] = False
                resources[
                    "durable_item_first_observed_ms_from_process_launch"
                ] = observed
        elif scenario == "receive-only":
            identities = {"a": "a" * 64, "b": "b" * 64}
            receipts = {
                role: make_node_receipt()
                for role in results.RECEIPT_ROLES[scenario]
            }
            for role, peer in (("a", "b"), ("b", "a")):
                receipts[role].update(
                    {
                        "identity": identities[role],
                        "authenticated_peers": [identities[peer]],
                        "admitted_peers": [identities[peer]],
                        "unauthorized_peers": [],
                    }
                )
            common.update(
                {
                    "identities": identities,
                    "item_id": "d" * 64,
                    "all_nodes_running_when_b_observed": True,
                    "b_item_observed_ms_from_process_launch": 275,
                    "discovery_announcements": 0,
                    "receive_only_control_bytes_allowed": True,
                    "custody": {
                        "exact_envelope": True,
                        "application_unreadable": True,
                        "payload_absent_at_rest": True,
                        "payload_digest_absent_at_rest": True,
                    },
                    "receipts": receipts,
                }
            )
            resources = common["receipts"]["b"]["experiment_resources"]
            resources["durable_item_present_before_contact"] = False
            resources["durable_item_first_observed_ms_from_process_launch"] = 275
        else:
            common["receipts"] = {
                role: make_node_receipt()
                for role in results.RECEIPT_ROLES[scenario]
            }
        write_json(root / f"trial-{trial:02d}" / "result.json", common)
        if scenario == "gate-h":
            prefix = f"aster-mesh-{run_id}-t{trial:02d}"
            write_json(
                root / f"trial-{trial:02d}" / "cleanup.json",
                {
                    "schema": results.GATE_H_CLEANUP_SCHEMA,
                    "trial": trial,
                    "passed": True,
                    "primary_error": None,
                    "commands": [
                        {
                            "argv": [str(tool_path), "rm", "--force", f"{prefix}-gate-a"],
                            "returncode": 0,
                        },
                        {
                            "argv": [str(tool_path), "rm", "--force", f"{prefix}-gate-b"],
                            "returncode": 0,
                        },
                        {
                            "argv": [str(tool_path), "rm", "--force", f"{prefix}-gate-c"],
                            "returncode": 0,
                        },
                        {
                            "argv": [str(tool_path), "network", "rm", f"{prefix}-live-ab"],
                            "returncode": 0,
                        },
                        {
                            "argv": [str(tool_path), "network", "rm", f"{prefix}-live-bc"],
                            "returncode": 0,
                        },
                    ],
                },
            )
    write_evidence_index(root)


class IpMeshResultsTests(unittest.TestCase):
    def setUp(self):
        # These receipts use a synthetic Git runner and source tree. Give them
        # matching private metadata instead of inspecting the checkout's .git
        # (which is a file in linked worktrees, and may have local attributes).
        workspace_directory = tempfile.TemporaryDirectory()
        self.addCleanup(workspace_directory.cleanup)
        workspace = Path(workspace_directory.name).resolve()
        (workspace / ".git/info").mkdir(parents=True)
        inspect_attributes = results.gate_h_source._info_attributes_state

        def fixture_attributes(requested_workspace):
            self.assertEqual(requested_workspace, results.REPOSITORY_WORKSPACE)
            return inspect_attributes(workspace)

        attributes_patch = mock.patch.object(
            results.gate_h_source,
            "_info_attributes_state",
            side_effect=fixture_attributes,
        )
        attributes_patch.start()
        self.addCleanup(attributes_patch.stop)
        signature_runner_patch = mock.patch.object(
            results.gate_h_experiment_contract,
            "run_gate_h_signature_command",
            side_effect=fake_signature_runner,
        )
        signature_runner_patch.start()
        self.addCleanup(signature_runner_patch.stop)
        candidate_blob_patch = mock.patch.object(
            results.gate_h_experiment_contract,
            "checked_candidate_blob",
            side_effect=fake_candidate_blob,
        )
        candidate_blob_patch.start()
        self.addCleanup(candidate_blob_patch.stop)
        candidate_tree_patch = mock.patch.object(
            results.gate_h_experiment_contract,
            "checked_candidate_tree",
            return_value=SIGNED_SOURCE_TREE,
        )
        candidate_tree_patch.start()
        self.addCleanup(candidate_tree_patch.stop)
        candidate_signature_patch = mock.patch.object(
            results.gate_h_experiment_contract,
            "checked_candidate_signature",
            return_value=("G", SIGNATURE_PRINCIPAL, SIGNATURE_FINGERPRINT),
        )
        candidate_signature_patch.start()
        self.addCleanup(candidate_signature_patch.stop)

    def test_native_v2_resource_profile_is_validated_and_sampled(self):
        receipt = native_shared_node_receipt()
        results.validate_provider_profile(
            receipt,
            arm="native",
            discovery_source=None,
            context="native",
        )
        samples = results.Samples()
        results.collect_receipt(
            receipt,
            "native",
            "native",
            samples,
            1_024,
            None,
        )
        distributions = samples.result()
        self.assertEqual(
            distributions["node_resource_high_water_admitted_contacts"]["p50"],
            2,
        )
        self.assertEqual(
            distributions["node_resource_rejected_claims"]["p50"], 1
        )
        self.assertEqual(
            distributions["node_resource_rejections_frames"]["p50"], 1
        )
        self.assertEqual(distributions["aster_frames_received"]["p50"], 3)
        self.assertEqual(distributions["carrier_control_bytes_sent"]["p50"], 20)
        self.assertEqual(
            distributions["authorization_generation_checks"]["p50"], 2
        )

        invalid = json.loads(json.dumps(receipt))
        invalid["node_resource_current"]["tasks"] = 9
        with self.assertRaisesRegex(results.ResultsError, "tasks"):
            results.validate_provider_profile(
                invalid,
                arm="native",
                discovery_source=None,
                context="native",
            )

        invalid = json.loads(json.dumps(receipt))
        invalid["process_authority_construction_count"] = 2
        with self.assertRaisesRegex(results.ResultsError, "does not equal one"):
            results.validate_provider_profile(
                invalid,
                arm="native",
                discovery_source=None,
                context="native",
            )

        invalid = json.loads(json.dumps(receipt))
        invalid["node_resource_rejections"]["tasks"] = 1
        with self.assertRaisesRegex(results.ResultsError, "per-category"):
            results.validate_provider_profile(
                invalid,
                arm="native",
                discovery_source=None,
                context="native",
            )

        invalid = json.loads(json.dumps(receipt))
        invalid["frames_sent"] += 1
        with self.assertRaisesRegex(results.ResultsError, "aliases"):
            results.validate_provider_profile(
                invalid,
                arm="native",
                discovery_source=None,
                context="native",
            )

        invalid = json.loads(json.dumps(receipt))
        invalid["authorization_generation_checks"] = 0
        with self.assertRaisesRegex(results.ResultsError, "no authorization"):
            results.validate_provider_profile(
                invalid,
                arm="native",
                discovery_source=None,
                context="native",
            )

    def test_gate_h_native_v2_requires_exact_clean_resource_proof(self):
        receipt = native_shared_node_receipt(clean=True)
        results.validate_gate_h_native_receipt(
            receipt, context="gate-h", expected_item_id="d" * 64
        )

        invalid = json.loads(json.dumps(receipt))
        invalid["node_resource_limits"]["tasks"] = 4
        with self.assertRaisesRegex(results.ResultsError, "exact native"):
            results.validate_gate_h_native_receipt(
                invalid, context="gate-h", expected_item_id="d" * 64
            )

        invalid = json.loads(json.dumps(receipt))
        invalid["node_resource_current"]["descriptors"] = 0
        with self.assertRaisesRegex(results.ResultsError, "provider base"):
            results.validate_gate_h_native_receipt(
                invalid, context="gate-h", expected_item_id="d" * 64
            )

        invalid = json.loads(json.dumps(receipt))
        invalid["node_resource_high_water"]["frames"] = 6_817
        with self.assertRaisesRegex(results.ResultsError, "admitted-contact"):
            results.validate_gate_h_native_receipt(
                invalid, context="gate-h", expected_item_id="d" * 64
            )

        invalid = json.loads(json.dumps(receipt))
        invalid["candidates_rejected_capacity"] = 1
        with self.assertRaisesRegex(results.ResultsError, "not clean"):
            results.validate_gate_h_native_receipt(
                invalid, context="gate-h", expected_item_id="d" * 64
            )

        invalid = json.loads(json.dumps(receipt))
        invalid["durable_item_probe_id"] = "e" * 64
        with self.assertRaisesRegex(results.ResultsError, "wrong durable ItemID"):
            results.validate_gate_h_native_receipt(
                invalid, context="gate-h", expected_item_id="d" * 64
            )

        invalid = json.loads(json.dumps(receipt))
        invalid["durable_item_present"] = False
        with self.assertRaisesRegex(results.ResultsError, "did not observe"):
            results.validate_gate_h_native_receipt(
                invalid, context="gate-h", expected_item_id="d" * 64
            )

    def test_gate_h_retains_exact_fresh_pre_restart_absence_observation(self):
        observations = {
            "b_custody": {
                "item_id": "d" * 64,
                "present": True,
                "elapsed_ms": 200,
            },
            "c_at_b_custody": {
                "item_id": "d" * 64,
                "present": False,
                "elapsed_ms": 190,
            },
            "c_pre_restart": {
                "item_id": "d" * 64,
                "present": False,
                "elapsed_ms": 225,
            },
        }
        results.validate_gate_h_durable_item_observations(
            observations,
            expected_item_id="d" * 64,
            context="gate-h observations",
        )

        stale = json.loads(json.dumps(observations))
        stale["c_pre_restart"]["elapsed_ms"] = 190
        with self.assertRaisesRegex(results.ResultsError, "fresh C absence"):
            results.validate_gate_h_durable_item_observations(
                stale,
                expected_item_id="d" * 64,
                context="gate-h observations",
            )

        wrong = json.loads(json.dumps(observations))
        wrong["c_pre_restart"]["item_id"] = "e" * 64
        with self.assertRaisesRegex(results.ResultsError, "wrong durable ItemID"):
            results.validate_gate_h_durable_item_observations(
                wrong,
                expected_item_id="d" * 64,
                context="gate-h observations",
            )

    def test_gate_h_requires_and_validates_the_combined_ten_trial_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "gate-h"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            run = results.aggregate([root])["runs"][0]
            self.assertEqual(run["passed_trials"], 10)
            self.assertTrue(run["all_passed"])
            self.assertEqual(len(run["gate_h_process_launches"]), 10)
            self.assertEqual(
                run["gate_h_resource_cleanup"]["receipt_count"], 31
            )
            launch_sequences = [
                sequence
                for launch in run["gate_h_process_launches"]
                for sequence in launch["sequences"].values()
            ]
            self.assertEqual(len(launch_sequences), 40)
            self.assertEqual(len(set(launch_sequences)), 40)
            self.assertGreater(
                max(launch_sequences) - min(launch_sequences) + 1,
                len(launch_sequences),
                "the passing fixture deliberately proves global gaps are allowed",
            )
            self.assertEqual(
                run["distributions"]["gate_h_c_item_observed_ms"]["p50"],
                275,
            )

            result_path = root / "trial-01" / "result.json"
            value = json.loads(result_path.read_text(encoding="utf-8"))
            original = json.loads(json.dumps(value))
            value["c_post_restart_new_admitted_contact_ids_for_b"] = []
            value["c_final_admitted_contact_ids_for_b"] = [7]
            value["c_distinct_admitted_contacts_for_b"] = 1
            result_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(results.ResultsError, "fresh B contact"):
                results.aggregate([root])

            original["process_durations_ms"]["c_continuous"] = 6_000
            result_path.write_text(json.dumps(original), encoding="utf-8")
            with self.assertRaisesRegex(results.ResultsError, "continuous-C"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "short-gate-h"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 9,
                arm="native",
                payload_bytes=1_048_576,
            )
            with self.assertRaisesRegex(results.ResultsError, "exactly ten"):
                results.aggregate([root])

    def test_gate_h_rejects_failed_legacy_dirty_and_unbound_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "failed"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 9 + (False,),
                arm="native",
                payload_bytes=1_048_576,
            )
            with self.assertRaisesRegex(results.ResultsError, "10/10 clean"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "legacy"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            path = root / "trial-01" / "result.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["receipts"]["a"]["schema"] = "aster-lab-native-mesh-node/v1"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(results.ResultsError, "native v2"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "dirty"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            path = root / "trial-01" / "result.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["receipts"]["b_pre"]["duplicate_contacts"] = 1
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(results.ResultsError, "not clean"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "cleanup"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            path = root / "trial-01" / "cleanup.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["commands"][1]["returncode"] = 1
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(results.ResultsError, "cleanup command"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "binary"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            (root / "gate-h-image-aster-lab").write_bytes(b"tampered")
            with self.assertRaisesRegex(results.ResultsError, "retained image binary"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "command"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            path = root / "commands.jsonl"
            records = [json.loads(line) for line in path.read_text().splitlines()]
            records[0]["argv"].append("--unallowlisted")
            path.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(results.ResultsError, "command log"):
                results.aggregate([root])

    def test_gate_h_rejects_tampered_resource_registry_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "resource-name"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            path = root / "gate-h-resource-cleanup.jsonl"
            receipts = [json.loads(line) for line in path.read_text().splitlines()]
            receipts[1]["resources"][0]["name"] = (
                "aster-mesh-0123abcd-t01-offline-unknown"
            )
            path.write_text(
                "".join(json.dumps(receipt) + "\n" for receipt in receipts),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(results.ResultsError, "unexpected or duplicated"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "unnamed-offline"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            path = root / "commands.jsonl"
            records = [json.loads(line) for line in path.read_text().splitlines()]
            offline = next(
                record
                for record in records
                if record["argv"][1:3] == ["run", "--rm"]
            )
            name_index = offline["argv"].index("--name")
            del offline["argv"][name_index : name_index + 2]
            path.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(results.ResultsError, "named offline invocation"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "registered-resource"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            path = root / "gate-h-host-execution-final.json"
            final = json.loads(path.read_text(encoding="utf-8"))
            final["registered_docker_resources"] = 1
            path.write_text(json.dumps(final), encoding="utf-8")
            with self.assertRaisesRegex(results.ResultsError, "did not pass"):
                results.aggregate([root])

    def test_gate_h_process_launches_require_exact_quartets_and_command_bijection(self):
        def make_gate_h_root(parent: Path, label: str) -> Path:
            root = parent / label
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            return root

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)

            root = make_gate_h_root(parent, "missing-stream")
            gate_h_process_quartet(root, 1, "a_pre")["stdout"].unlink()
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "incomplete or extra quartet"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "orphan-extra")
            (root / "process-orphan.log").write_text("orphan", encoding="utf-8")
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "unexpected Gate-H process"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "filename-sequence")
            command_path = gate_h_process_quartet(root, 1, "b_pre")["command"]
            command = json.loads(command_path.read_text(encoding="utf-8"))
            command["sequence"] += 1
            write_json(command_path, command)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "filename sequence"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "global-sequence-collision")
            paths = gate_h_process_quartet(root, 1, "b_pre")
            renamed = {
                kind: root
                / f"process-00001.{suffix}"
                for kind, suffix in {
                    "command": "command.json",
                    "result": "result.json",
                    "stdout": "stdout.log",
                    "stderr": "stderr.log",
                }.items()
            }
            for kind, path in paths.items():
                path.rename(renamed[kind])
            command = json.loads(renamed["command"].read_text(encoding="utf-8"))
            command["sequence"] = 1
            write_json(renamed["command"], command)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "reuse global sequences"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "command-keys")
            command_path = gate_h_process_quartet(root, 1, "c_continuous")[
                "command"
            ]
            command = json.loads(command_path.read_text(encoding="utf-8"))
            command["unbound"] = True
            write_json(command_path, command)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "exact command keys"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "argv")
            command_path = gate_h_process_quartet(root, 1, "a_pre")["command"]
            command = json.loads(command_path.read_text(encoding="utf-8"))
            command["argv"].append("--unallowlisted")
            write_json(command_path, command)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "exact a_pre process"):
                results.aggregate([root])

    def test_gate_h_process_launch_results_are_complete_and_reconcile_returncodes(self):
        def make_gate_h_root(parent: Path, label: str) -> Path:
            root = parent / label
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            return root

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)

            root = make_gate_h_root(parent, "result-keys")
            result_path = gate_h_process_quartet(root, 1, "b_post")["result"]
            process_result = json.loads(result_path.read_text(encoding="utf-8"))
            process_result["sequence"] = 999
            write_json(result_path, process_result)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "exact result keys"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "timeout")
            result_path = gate_h_process_quartet(root, 1, "b_pre")["result"]
            process_result = json.loads(result_path.read_text(encoding="utf-8"))
            process_result["timed_out"] = True
            write_json(result_path, process_result)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "timed_out"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "completion")
            result_path = gate_h_process_quartet(root, 1, "c_continuous")["result"]
            process_result = json.loads(result_path.read_text(encoding="utf-8"))
            process_result["completed_utc"] = ""
            write_json(result_path, process_result)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "completed_utc"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "returncode")
            result_path = gate_h_process_quartet(root, 1, "a_pre")["result"]
            process_result = json.loads(result_path.read_text(encoding="utf-8"))
            process_result["returncode"] = 1
            write_json(result_path, process_result)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "returncode"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "map-reconciliation")
            trial_result_path = root / "trial-01" / "result.json"
            trial_result = json.loads(trial_result_path.read_text(encoding="utf-8"))
            trial_result["post_process_returncodes"] = {"b": 0, "c": 1}
            write_json(trial_result_path, trial_result)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "do not reconcile"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "regular-stream")
            paths = gate_h_process_quartet(root, 1, "b_post")
            paths["stderr"].unlink()
            paths["stderr"].symlink_to(paths["stdout"])
            with self.assertRaisesRegex(results.ResultsError, "not a regular file"):
                results.aggregate([root])

    def test_gate_h_fault_receipt_is_bound_to_complete_logs_and_commit_blobs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "fault-timeout"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            path = root / "gate-h-fault-receipt.json"
            receipt = json.loads(path.read_text(encoding="utf-8"))
            receipt["timeout_seconds_per_command"] = 1_801
            rewrite_gate_h_fault_receipt(root, receipt)
            manifest = json.loads((root / "manifest.json").read_text())
            binary = root / "candidate-aster-lab"
            with self.assertRaisesRegex(
                results.gate_h_experiment_contract.ExperimentError,
                "invalid command timeout",
            ):
                results.gate_h_experiment_contract.validate_gate_h_fault_receipt(
                    path,
                    expected_commit="c" * 40,
                    expected_binary_sha256=results.sha256_file(binary),
                    expected_binary_size=binary.stat().st_size,
                    expected_signature_status="G",
                    expected_signature_signer=SIGNATURE_PRINCIPAL,
                    expected_signature_fingerprint=SIGNATURE_FINGERPRINT,
                    git_binary=manifest["host_execution"]["tools"]["git"][
                        "invocation_path"
                    ],
                    environment=manifest["host_execution"]["environment"],
                )
            with self.assertRaisesRegex(results.ResultsError, "invalid command timeout"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "fault-feature-profile"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            path = root / "gate-h-fault-receipt.json"
            receipt = json.loads(path.read_text(encoding="utf-8"))
            host_build = receipt["test_executable_build"]["builds"]["aster-host"]
            host_build["argv"][host_build["argv"].index("gate-h-formal")] = (
                "legacy-single-contact-service"
            )
            build_plan = [
                {
                    "package": package,
                    "argv": build["argv"],
                    "source_files_sha256": build["source_files_sha256"],
                }
                for package, build in sorted(
                    receipt["test_executable_build"]["builds"].items()
                )
            ]
            receipt["test_executable_build_plan_sha256"] = (
                results.gate_h_fault_contract.canonical_sha256(build_plan)
            )
            rewrite_gate_h_fault_receipt(root, receipt)
            with self.assertRaisesRegex(results.ResultsError, "build is malformed"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "fault-stream"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            path = root / "gate-h-fault-receipt.json"
            receipt = json.loads(path.read_text(encoding="utf-8"))
            receipt["commands"][0]["stdout"]["base64"] = "AA=="
            rewrite_gate_h_fault_receipt(root, receipt)
            with self.assertRaisesRegex(results.ResultsError, "size or digest"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "candidate-blob"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )

            def altered_blob(commit, relative, **checked_git):
                object_id, value = fake_candidate_blob(
                    commit, relative, **checked_git
                )
                if relative == "crates/aster-host/src/shared_node.rs":
                    return object_id, value + b"\nchanged after candidate\n"
                return object_id, value

            with mock.patch.object(
                results.gate_h_experiment_contract,
                "checked_candidate_blob",
                side_effect=altered_blob,
            ):
                with self.assertRaisesRegex(results.ResultsError, "source binding differs"):
                    results.aggregate([root])

    def test_gate_h_fault_returncodes_reject_boolean_aliases(self):
        def direct_validate(root: Path) -> None:
            manifest = json.loads((root / "manifest.json").read_text())
            binary = root / "candidate-aster-lab"
            results.gate_h_experiment_contract.validate_gate_h_fault_receipt(
                root / "gate-h-fault-receipt.json",
                expected_commit="c" * 40,
                expected_binary_sha256=results.sha256_file(binary),
                expected_binary_size=binary.stat().st_size,
                expected_signature_status="G",
                expected_signature_signer=SIGNATURE_PRINCIPAL,
                expected_signature_fingerprint=SIGNATURE_FINGERPRINT,
                git_binary=manifest["host_execution"]["tools"]["git"][
                    "invocation_path"
                ],
                environment=manifest["host_execution"]["environment"],
            )

        for label in ("build-false", "test-false", "static-true"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / label
                make_run(
                    root,
                    scenario="gate-h",
                    trial_passes=(True,) * 10,
                    arm="native",
                    payload_bytes=1_048_576,
                )
                path = root / "gate-h-fault-receipt.json"
                receipt = json.loads(path.read_text(encoding="utf-8"))
                if label == "build-false":
                    receipt["test_executable_build"]["builds"]["aster-core"][
                        "returncode"
                    ] = False
                elif label == "test-false":
                    receipt["commands"][0]["returncode"] = False
                else:
                    static = receipt["static_checks"][
                        next(iter(receipt["static_checks"]))
                    ]
                    static["returncode"] = True
                    static["expected_returncode"] = True
                rewrite_gate_h_fault_receipt(root, receipt)
                with self.assertRaisesRegex(
                    results.gate_h_experiment_contract.ExperimentError,
                    "malformed|failed",
                ):
                    direct_validate(root)
                with self.assertRaisesRegex(
                    results.ResultsError, "non-boolean integer"
                ):
                    results.aggregate([root])

    def test_gate_h_fault_receipt_rejects_execution_provenance_tampering(self):
        def make_gate_h_root(parent: Path, label: str) -> Path:
            root = parent / label
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            return root

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)

            root = make_gate_h_root(parent, "ambient-environment")
            path = root / "gate-h-fault-receipt.json"
            receipt = json.loads(path.read_text(encoding="utf-8"))
            receipt["execution_provenance"]["environment"]["RUSTFLAGS"] = (
                "-C target-cpu=native"
            )
            rewrite_gate_h_fault_receipt(root, receipt)
            with self.assertRaisesRegex(results.ResultsError, "allowlisted"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "export-text-encoding")
            path = root / "gate-h-fault-receipt.json"
            receipt = json.loads(path.read_text(encoding="utf-8"))
            receipt["execution_provenance"]["export_execution"]["environment"][
                "__CF_USER_TEXT_ENCODING"
            ] = "0x0:0x0:0x0"
            receipt["export_execution"]["environment"][
                "__CF_USER_TEXT_ENCODING"
            ] = "0x0:0x0:0x0"
            rewrite_gate_h_fault_receipt(root, receipt)
            with self.assertRaisesRegex(
                results.ResultsError, "exported controller provenance differs"
            ):
                results.aggregate([root])

            root = make_gate_h_root(parent, "target-directory")
            path = root / "gate-h-fault-receipt.json"
            receipt = json.loads(path.read_text(encoding="utf-8"))
            alternate_target = str(
                (results.gate_h_fault_contract.WORKSPACE / "target/not-formal").resolve()
            )
            receipt["execution_provenance"]["environment"][
                "CARGO_TARGET_DIR"
            ] = alternate_target
            receipt["execution_provenance"]["target_directory"][
                "path"
            ] = alternate_target
            rewrite_gate_h_fault_receipt(root, receipt)
            with self.assertRaisesRegex(results.ResultsError, "wrong fixed target"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "tool-identity")
            path = root / "gate-h-fault-receipt.json"
            receipt = json.loads(path.read_text(encoding="utf-8"))
            receipt["execution_provenance"]["tools"]["cargo"]["sha256"] = "f" * 64
            rewrite_gate_h_fault_receipt(root, receipt)
            with self.assertRaisesRegex(results.ResultsError, "executable binding differs"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "feature-graph")
            path = root / "gate-h-fault-receipt.json"
            receipt = json.loads(path.read_text(encoding="utf-8"))
            graph = receipt["execution_provenance"]["formal_feature_graph"]
            stdout = base64.b64decode(graph["stdout"]["base64"], validate=True)
            graph.update(
                _fault_stream_fields("stdout", stdout + b"legacy-lab\n")
            )
            rewrite_gate_h_fault_receipt(root, receipt)
            with self.assertRaisesRegex(results.ResultsError, "provider-tainted"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "feature-graph-static-projection")
            path = root / "gate-h-fault-receipt.json"
            receipt = json.loads(path.read_text(encoding="utf-8"))
            receipt["static_checks"][
                "formal_graph_has_no_libp2p_or_iroh_dependency"
            ]["duration_ms"] += 1
            rewrite_gate_h_fault_receipt(root, receipt)
            with self.assertRaisesRegex(
                results.ResultsError, "resolved feature-graph provenance"
            ):
                results.aggregate([root])

            root = make_gate_h_root(parent, "feature-graph-stderr")
            path = root / "gate-h-fault-receipt.json"
            receipt = json.loads(path.read_text(encoding="utf-8"))
            stderr_fields = _fault_stream_fields(
                "stderr", b"cargo emitted a non-fatal warning\n"
            )
            receipt["execution_provenance"]["formal_feature_graph"].update(
                stderr_fields
            )
            receipt["static_checks"][
                "formal_graph_has_no_libp2p_or_iroh_dependency"
            ].update(stderr_fields)
            rewrite_gate_h_fault_receipt(root, receipt)
            results.aggregate([root])

            root = make_gate_h_root(parent, "build-environment")
            path = root / "gate-h-fault-receipt.json"
            receipt = json.loads(path.read_text(encoding="utf-8"))
            del receipt["test_executable_build"]["builds"]["aster-host"][
                "environment"
            ]["TMPDIR"]
            rewrite_gate_h_fault_receipt(root, receipt)
            with self.assertRaisesRegex(results.ResultsError, "deterministic environment"):
                results.aggregate([root])

    def test_gate_h_host_execution_rejects_environment_tool_and_command_tampering(self):
        def make_gate_h_root(parent: Path, label: str) -> Path:
            root = parent / label
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            return root

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)

            root = make_gate_h_root(parent, "ambient-controller")
            path = root / "manifest.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["host_execution"]["controller_environment"][
                "DOCKER_CONTEXT"
            ] = "ambient"
            write_json(path, manifest)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "allowlisted"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "tool-digest")
            path = root / "manifest.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["host_execution"]["tools"]["docker"]["sha256"] = "f" * 64
            write_json(path, manifest)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "executable binding"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "buildx-tool-digest")
            path = root / "manifest.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["host_execution"]["tools"]["docker_buildx"][
                "sha256"
            ] = "f" * 64
            write_json(path, manifest)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "executable binding"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "buildx-plugin")
            path = root / "manifest.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["host_execution"]["docker_config"]["buildx_plugin"][
                "symlink_sha256"
            ] = "f" * 64
            write_json(path, manifest)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "Docker config"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "buildx-state-inventory")
            path = root / "gate-h-host-execution-final.json"
            final = json.loads(path.read_text(encoding="utf-8"))
            inventory = final["docker_buildx_cleanup"]["state_cleanup"][
                "inventory"
            ]
            inventory["entries"][0]["mode"] = "0755"
            write_json(path, final)
            write_evidence_index(root)
            with self.assertRaisesRegex(
                results.ResultsError, "buildx state entry inventory differs"
            ):
                results.aggregate([root])

            root = make_gate_h_root(parent, "docker-server")
            path = root / "manifest.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["host_execution"]["docker_endpoint"]["version"]["Server"][
                "Version"
            ] = "tampered"
            write_json(path, manifest)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "endpoint receipt"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "process-environment")
            command_path = gate_h_process_quartet(root, 1, "b_pre")["command"]
            command = json.loads(command_path.read_text(encoding="utf-8"))
            command["environment_sha256"] = "f" * 64
            write_json(command_path, command)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "host environment"):
                results.aggregate([root])

    def test_gate_h_signature_trust_rejects_anchor_and_posthoc_tampering(self):
        def make_gate_h_root(parent: Path, label: str) -> Path:
            root = parent / label
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            return root

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)

            root = make_gate_h_root(parent, "request")
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["signature_request"]["git"] = "/usr/bin/false"
            write_json(manifest_path, manifest)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "signature request"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "anchor")
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["signature_anchor"]["allowed_signer_fingerprints"] = [
                "SHA256:attacker"
            ]
            write_json(manifest_path, manifest)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "signature evidence"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "verification-bool")
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["signature_verification"]["verify_commit"][
                "returncode"
            ] = False
            manifest["source_freeze"]["signature_verification"] = manifest[
                "signature_verification"
            ]
            write_json(manifest_path, manifest)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "signature evidence"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "retained-signers")
            retained = root / "gate-h-allowed-signers"
            retained.chmod(0o600)
            retained.write_bytes(retained.read_bytes() + b"attacker\n")
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "allowed-signers"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "final-receipt")
            final_path = root / "gate-h-signature-final.json"
            final = json.loads(final_path.read_text(encoding="utf-8"))
            final["signature_trust_sha256"] = "f" * 64
            write_json(final_path, final)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "final signature"):
                results.aggregate([root])

            root = make_gate_h_root(parent, "fault-self-nomination")
            fault_path = root / "gate-h-fault-receipt.json"
            fault = json.loads(fault_path.read_text(encoding="utf-8"))
            fault["signature_trust"]["principal"] = "attacker@example.test"
            fault["execution_provenance"]["signature_trust"] = json.loads(
                json.dumps(fault["signature_trust"])
            )
            fault["signature_signer"] = "attacker@example.test"
            fault["signature_verification"]["principal"] = (
                "attacker@example.test"
            )
            rewrite_gate_h_fault_receipt(root, fault)
            with self.assertRaisesRegex(
                results.ResultsError, "signature|signed source"
            ):
                results.aggregate([root])

    def test_gate_h_live_control_rejects_file_generation_and_event_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "control-file"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            path = root / "trial-01" / "b" / "gate-h-authorization-control.bin"
            path.write_bytes(path.read_bytes() + b"tamper")
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "prepared control differs"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "generation"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            path = root / "trial-01" / "result.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["receipts"]["b_post"]["authorization_generation_current"] = 1
            write_json(path, value)
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "fresh B-post"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "carrier-event"
            make_run(
                root,
                scenario="gate-h",
                trial_passes=(True,) * 10,
                arm="native",
                payload_bytes=1_048_576,
            )
            path = (
                root
                / "trial-01"
                / "c"
                / "native-mesh-t01_gate_pre-events.jsonl"
            )
            events = [json.loads(line) for line in path.read_text().splitlines()]
            events[-1]["carrier_id"] = "8" * 64
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            write_evidence_index(root)
            with self.assertRaisesRegex(results.ResultsError, "continuous-C rotation"):
                results.aggregate([root])

    def test_primary_aggregation_reports_passes_and_distributions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            make_run(root, trial_passes=(True, False))

            aggregate = results.aggregate([root])
            run = aggregate["runs"][0]

            self.assertEqual(aggregate["requested_trials"], 2)
            self.assertEqual(aggregate["passed_trials"], 1)
            self.assertFalse(aggregate["all_passed"])
            self.assertEqual(run["sample_scopes"]["node_receipts"], 12)
            self.assertEqual(
                run["sample_scopes"]["durable_item_absent_before_contact_receipts"],
                4,
            )
            self.assertEqual(run["distributions"]["trial_elapsed_ms"]["p50"], 100)
            self.assertEqual(run["distributions"]["trial_elapsed_ms"]["p95"], 200)
            self.assertEqual(run["distributions"]["frames_total"]["mean"], 8)
            self.assertEqual(
                run["distributions"]["durable_item_newly_observed_ms"]["sample_count"],
                4,
            )
            self.assertEqual(
                run["distributions"]["application_payload_throughput_bps"][
                    "sample_count"
                ],
                4,
            )
            self.assertAlmostEqual(
                run["distributions"][
                    "network_amplification_bytes_per_payload_byte"
                ]["p50"],
                200 / 1_024,
            )

    def test_corrected_libp2p_v3_binds_every_receipt_to_frozen_provider(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "corrected"
            make_run(root, corrected_retest=True)
            run = results.aggregate([root])["runs"][0]
            self.assertEqual(
                run["node_receipt_schemas"], [results.LIBP2P_SHARED_NODE_SCHEMA]
            )
            self.assertEqual(
                run["provider_binary_sha256"],
                results.sha256_file(root / "candidate-aster-libp2p-node"),
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "legacy-receipt"
            make_run(root, corrected_retest=True)
            path = root / "trial-01" / "result.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["node_receipts"]["ab_a"]["schema"] = (
                "aster-lab-libp2p-mesh-node/v2"
            )
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(results.ResultsError, "not a v3"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "receipt-tamper"
            make_run(root, corrected_retest=True)
            path = root / "trial-01" / "result.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["node_receipts"]["ab_a"]["provider_binary_sha256"] = "0" * 64
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(results.ResultsError, "frozen provider"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "provider-tamper"
            make_run(root, corrected_retest=True)
            (root / "candidate-aster-libp2p-node").write_bytes(b"tampered")
            with self.assertRaisesRegex(results.ResultsError, "frozen provider"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "manifest-tamper"
            make_run(root, corrected_retest=True)
            path = root / "manifest.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["provider_binary_sha256"] = "0" * 64
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(results.ResultsError, "frozen provider"):
                results.aggregate([root])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "archived"
            make_run(root)
            run = results.aggregate([root])["runs"][0]
            self.assertEqual(
                run["node_receipt_schemas"],
                ["aster-lab-libp2p-mesh-node/v2"],
            )
            self.assertIsNone(run["provider_binary_sha256"])

    def test_idle_aggregation_computes_settled_cpu(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "idle"
            make_run(root, scenario="idle")

            run = results.aggregate([root])["runs"][0]

            self.assertEqual(
                run["distributions"]["idle_cpu_usage_usec_settled"]["p50"], 60_000
            )
            self.assertEqual(
                run["distributions"]["idle_cpu_percent_of_one_core_settled"]["p50"],
                0.1,
            )
            self.assertEqual(
                run["distributions"]["idle_settled_network_bytes_per_minute"]["p50"],
                1_000.0,
            )

    def test_live_relay_requires_concurrent_observation_and_reports_latency(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "live"
            make_run(root, scenario="live-relay")

            run = results.aggregate([root])["runs"][0]

            self.assertEqual(
                run["distributions"]["live_bc_prerequisite_ms"]["p50"], 125
            )
            self.assertEqual(
                run["distributions"]["live_c_item_observed_ms"]["p50"], 450
            )
            self.assertEqual(
                run["sample_scopes"]["durable_item_absent_before_contact_receipts"],
                2,
            )

            path = root / "trial-01" / "result.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["all_nodes_running_when_c_observed"] = False
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(results.ResultsError, "all node processes"):
                results.aggregate([root])

            value["all_nodes_running_when_c_observed"] = True
            value["b_commit_fanout"]["source_peer"] = "c" * 64
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(results.ResultsError, "publisher A"):
                results.aggregate([root])

    def test_receive_only_requires_live_ingestion_and_zero_discovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "receive"
            make_run(root, scenario="receive-only")

            run = results.aggregate([root])["runs"][0]
            self.assertEqual(
                run["distributions"]["receive_only_b_item_observed_ms"]["p50"],
                275,
            )

            path = root / "trial-01" / "result.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["discovery_announcements"] = 1
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(results.ResultsError, "emitted discovery"):
                results.aggregate([root])

    def test_missing_trial_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "missing"
            make_run(root, trial_passes=(True, True), include_last_trial=False)

            with self.assertRaisesRegex(results.ResultsError, "trial directories differ"):
                results.aggregate([root])

    def test_unknown_receipt_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "schema"
            make_run(root)
            path = root / "trial-01" / "result.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["node_receipts"]["ab_a"]["schema"] = "unknown/v1"
            path.write_text(json.dumps(value), encoding="utf-8")

            with self.assertRaisesRegex(results.ResultsError, "not recognized"):
                results.aggregate([root])

    def test_malformed_metric_is_rejected_instead_of_omitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "metric"
            make_run(root)
            path = root / "trial-01" / "result.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["node_receipts"]["ab_a"]["pump_calls"] = None
            path.write_text(json.dumps(value), encoding="utf-8")

            with self.assertRaisesRegex(results.ResultsError, "pump_calls"):
                results.aggregate([root])

    def test_missing_exact_item_observation_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "missing-item"
            make_run(root)
            path = root / "trial-01" / "result.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["node_receipts"]["ab_b"]["experiment_resources"][
                "durable_item_first_observed_ms_from_process_launch"
            ] = None
            path.write_text(json.dumps(value), encoding="utf-8")

            with self.assertRaisesRegex(results.ResultsError, "never observed"):
                results.aggregate([root])

    def test_provider_profile_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "profile"
            make_run(root)
            path = root / "trial-01" / "result.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["node_receipts"]["ab_a"]["candidate_source"] = "provider-mdns"
            path.write_text(json.dumps(value), encoding="utf-8")

            with self.assertRaisesRegex(results.ResultsError, "candidate_source"):
                results.aggregate([root])

    def test_provider_profile_requires_strict_boolean_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "profile-type"
            make_run(root)
            path = root / "trial-01" / "result.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["node_receipts"]["ab_a"]["bounded_candidate_source"] = 1
            path.write_text(json.dumps(value), encoding="utf-8")

            with self.assertRaisesRegex(
                results.ResultsError, "bounded_candidate_source"
            ):
                results.aggregate([root])

    def test_dirty_source_freeze_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "dirty"
            make_run(root)
            path = root / "manifest.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["source_freeze"]["worktree_clean"] = False
            value["source_freeze"]["worktree_status"] = [" M Cargo.toml"]
            path.write_text(json.dumps(value), encoding="utf-8")

            with self.assertRaisesRegex(results.ResultsError, "clean worktree"):
                results.aggregate([root])

    def test_unindexed_evidence_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "unindexed"
            make_run(root)
            (root / "unexpected.txt").write_text("not retained in index", encoding="utf-8")

            with self.assertRaisesRegex(results.ResultsError, "does not match"):
                results.aggregate([root])


if __name__ == "__main__":
    unittest.main()
