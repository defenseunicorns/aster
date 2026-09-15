#!/usr/bin/env python3
"""Generate the fail-closed deterministic fault receipt for Proposal 0004 Gate H.

The command set is intentionally fixed.  A successful receipt can only be
created from a clean, signed candidate commit after every named Rust unit test
runs exactly once.  The receipt binds the commit, relevant source blobs, the
requirements document, Proposal 0004, and the native candidate binary.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import MappingProxyType
from typing import Any, Callable, Sequence

try:
    import gate_h_signature
    import gate_h_source
except ModuleNotFoundError:  # Imported as ``lab.gate_h_faults`` in tests.
    from lab import gate_h_signature
    from lab import gate_h_source


CODE_ROOT = Path(__file__).resolve().parents[1]
_REPOSITORY_WORKSPACE_VALUE = os.environ.get("ASTER_GATE_H_REPOSITORY_WORKSPACE")
WORKSPACE = (
    Path(_REPOSITORY_WORKSPACE_VALUE).resolve()
    if _REPOSITORY_WORKSPACE_VALUE
    else CODE_ROOT
)
SCHEMA = "aster-gate-h-deterministic-faults/v2"
EXPORT_EXECUTION_SCHEMA = "aster-gate-h-export-execution/v1"
SIGNED_CONTROLLER_ENV = "ASTER_GATE_H_SIGNED_CONTROLLER"
REPOSITORY_WORKSPACE_ENV = "ASTER_GATE_H_REPOSITORY_WORKSPACE"
REEXEC_FLAGS = ("-B", "-E", "-s", "-S")
REEXEC_MODULE_PATHS = MappingProxyType(
    {
        "gate_h_faults": "lab/gate_h_faults.py",
        "gate_h_signature": "lab/gate_h_signature.py",
        "gate_h_source": "lab/gate_h_source.py",
    }
)
REQUIREMENTS_SHA256 = "e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987"
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
MAX_RETAINED_LOG_BYTES = 16 * 1024
MAX_COMPLETE_STREAM_BYTES = 4 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 1_800
TEST_TARGET_NAMES = {
    "aster-core": "aster_mesh",
    "aster-host": "aster_host",
    "aster-lab": "aster_lab",
}
TEST_PACKAGE_MANIFESTS = {
    "aster-core": "crates/aster-core/Cargo.toml",
    "aster-host": "crates/aster-host/Cargo.toml",
    "aster-lab": "crates/aster-lab/Cargo.toml",
}
TEST_PACKAGE_FEATURE_ARGS = MappingProxyType(
    {
        "aster-core": ("--no-default-features", "--features", "adapter-sdk"),
        "aster-host": ("--no-default-features", "--features", "gate-h-formal"),
        "aster-lab": ("--no-default-features", "--features", "gate-h"),
    }
)
FORMAL_ENVIRONMENT_KEYS = frozenset(
    {
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_DIR",
        "CARGO_TERM_COLOR",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "RUST_BACKTRACE",
        "RUSTC",
        "RUSTDOC",
        "TMPDIR",
    }
)
FORMAL_SYSTEM_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
TOOL_VERSION_ARGS = MappingProxyType(
    {
        "cargo": ("--version", "--verbose"),
        "rustc": ("--version", "--verbose"),
        "rustdoc": ("--version", "--verbose"),
        "rg": ("--version",),
        "git": ("--version", "--build-options"),
        "rustup": ("--version",),
    }
)
FEATURE_GRAPH_FORMAT = "{p} features=[{f}]"


class GateHFaultError(RuntimeError):
    """A controlled, fail-closed Gate-H fault-runner error."""


class GateHSignalInterruption(KeyboardInterrupt):
    """A catchable operator signal converted into a controlled interruption."""

    def __init__(self, signum: int, previous_signal_mask: set[signal.Signals]):
        self.signum = signum
        self.previous_signal_mask = previous_signal_mask
        super().__init__(signal.Signals(signum).name)


@dataclass(frozen=True)
class TestSpec:
    """One exact Rust test that contributes to one mandatory Gate-H case."""

    case: str
    package: str
    test_name: str

    def argv(self, cargo_executable: str = "cargo") -> list[str]:
        return [
            cargo_executable,
            "test",
            "--locked",
            "-p",
            self.package,
            "--lib",
            *TEST_PACKAGE_FEATURE_ARGS[self.package],
            self.test_name,
            "--",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ]


@dataclass(frozen=True)
class SourceRegion:
    """Exact UTF-8 source interval supplied to an ``rg`` assertion on stdin."""

    path: str
    start_marker: str
    end_marker: str
    start_line: int
    value: bytes

    def receipt(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "start_marker": self.start_marker,
            "end_marker": self.end_marker,
            "start_line": self.start_line,
            "bytes": len(self.value),
            "sha256": sha256_bytes(self.value),
        }


# The fixed plan mirrors Proposal 0004's mandatory admission and aggregate-
# budget regressions (lines 143-150 and 176-181), then binds the generation,
# durable-quota, queued-control, and native-restart witnesses used by Gate H.
# Admission single-use deliberately has four witnesses.  Together they cover
# abort and commit replay, commit-after-close, and simultaneous preparations
# for one peer.
TEST_SPECS = (
    TestSpec(
        "admission_single_use",
        "aster-host",
        "mesh_host::tests::prepared_admission_is_invisible_until_commit_and_abort_is_fail_closed",
    ),
    TestSpec(
        "admission_single_use",
        "aster-host",
        "mesh_host::tests::prepared_admission_commits_once_after_durable_authorization",
    ),
    TestSpec(
        "admission_single_use",
        "aster-host",
        "mesh_host::tests::closing_contact_invalidates_prepared_admission_without_binding_identity",
    ),
    TestSpec(
        "admission_single_use",
        "aster-host",
        "mesh_host::tests::simultaneous_preparations_for_one_peer_issue_exactly_one_live_token",
    ),
    TestSpec(
        "admission_authorization_failure",
        "aster-host",
        "node_admission::tests::authorization_failure_restores_host_and_resource_state",
    ),
    TestSpec(
        "admission_resource_failure",
        "aster-host",
        "node_admission::tests::resource_failure_never_invokes_durable_authorization",
    ),
    TestSpec(
        "admission_resource_failure",
        "aster-host",
        "node_admission::tests::concurrent_claim_makes_resource_rollback_fail_closed_without_host_admission",
    ),
    TestSpec(
        "admission_panic_rollback",
        "aster-host",
        "node_admission::tests::panicking_authorization_rolls_back_before_resuming_unwind",
    ),
    TestSpec(
        "admission_panic_rollback",
        "aster-host",
        "shared_node::tests::panicking_durable_admission_retires_driver_link_host_and_all_contact_leases",
    ),
    TestSpec(
        "preauthentication_timeout",
        "aster-host",
        "shared_node::tests::authentication_timeout_retires_session_lease_and_host_contact_before_error",
    ),
    TestSpec(
        "preauthentication_timeout",
        "aster-host",
        "shared_node::tests::pending_connection_deadline_wakes_and_releases_host_and_resource_reservation",
    ),
    TestSpec(
        "identity_and_allowlist_conflicts",
        "aster-host",
        "shared_node::tests::peer_allowlist_rejects_before_host_resource_or_durable_admission",
    ),
    TestSpec(
        "identity_and_allowlist_conflicts",
        "aster-host",
        "mesh_host::tests::duplicate_candidate_never_publishes_peer_or_carrier_before_admission_commit",
    ),
    TestSpec(
        "identity_and_allowlist_conflicts",
        "aster-host",
        "mesh_host::tests::manual_binding_mismatch_fails_closed",
    ),
    TestSpec(
        "identity_and_allowlist_conflicts",
        "aster-host",
        "mesh_host::tests::carrier_match_is_only_a_scheduling_hint_and_fresh_admission_remains_required",
    ),
    TestSpec(
        "identity_and_allowlist_conflicts",
        "aster-host",
        "mesh_host::tests::carrier_identity_neither_authorizes_nor_rejects_a_fresh_aster_peer",
    ),
    TestSpec(
        "preauthentication_cancellation",
        "aster-host",
        "shared_node::tests::explicit_preauthentication_close_drops_inflight_session_and_releases_owned_leases",
    ),
    TestSpec(
        "preauthentication_cancellation",
        "aster-host",
        "shared_node::tests::explicit_pending_connection_cancellation_releases_host_and_resource_reservation",
    ),
    TestSpec(
        "late_host_commit_rollback",
        "aster-host",
        "shared_node::tests::late_host_commit_failure_after_durable_admission_releases_every_partial_grant",
    ),
    TestSpec(
        "reservation_precedes_allocation",
        "aster-host",
        "shared_node::tests::contact_link_factory_runs_only_after_preauthentication_capacity_reservation",
    ),
    TestSpec(
        "factory_panic_rollback",
        "aster-host",
        "shared_node::tests::panicking_contact_link_factory_releases_session_host_and_preauthentication_lease",
    ),
    TestSpec(
        "parallel_resource_limits",
        "aster-host",
        "node_budget::tests::parallel_barrier_race_is_atomic_at_every_resource_limit",
    ),
    TestSpec(
        "unwind_resource_release",
        "aster-host",
        "node_budget::tests::lease_drop_during_unwind_releases_capacity_for_recovery",
    ),
    TestSpec(
        "full_vector_connection_churn",
        "aster-host",
        "node_budget::tests::repeated_full_vector_connection_churn_never_leaks_or_exceeds_limits",
    ),
    TestSpec(
        "lifecycle_replace_without_double_charge",
        "aster-host",
        "node_budget::tests::lifecycle_replace_is_atomic_under_capacity_failure_and_churn",
    ),
    TestSpec(
        "post_auth_capacity_rollback",
        "aster-host",
        "shared_node::tests::second_authenticated_contact_capacity_failure_retires_every_partial_grant",
    ),
    TestSpec(
        "blob_quota_race",
        "aster-core",
        "runtime::reference_semantic::tests::concurrent_sessions_share_one_blob_quota_without_orphan_allocation",
    ),
    TestSpec(
        "mixed_ordinary_control",
        "aster-core",
        "runtime::reference_semantic::tests::mixed_signed_control_activation_invalidates_before_rejected_input_error",
    ),
    TestSpec(
        "mixed_ordinary_control",
        "aster-core",
        "runtime::reference_semantic::tests::ordinary_mixed_activation_invalidates_once_and_duplicate_does_not_bump",
    ),
    TestSpec(
        "mixed_bridge_control",
        "aster-core",
        "runtime::reference_semantic::tests::mixed_bridge_control_activation_invalidates_before_rejected_input_error",
    ),
    TestSpec(
        "mixed_bridge_control",
        "aster-core",
        "runtime::reference_semantic::tests::bridge_mixed_activation_invalidates_once_and_duplicate_does_not_bump",
    ),
    TestSpec(
        "runtime_commit_error_generation",
        "aster-core",
        "runtime::tests::commit_error_with_durable_authorization_change_preserves_checkpoint_and_reauthenticates",
    ),
    TestSpec(
        "runtime_commit_error_generation",
        "aster-core",
        "runtime::tests::commit_error_with_unavailable_authorization_generation_fails_closed_without_receipt",
    ),
    TestSpec(
        "peer_neutral_resume_unavailable_peer",
        "aster-core",
        "runtime::tests::peer_neutral_durable_want_skips_unavailable_peer_and_resumes_with_another",
    ),
    TestSpec(
        "process_owned_durable_item_probe",
        "aster-core",
        "runtime::reference_semantic::tests::authority_checks_exact_durable_item_without_opening_payload",
    ),
    TestSpec(
        "process_owned_durable_item_probe",
        "aster-host",
        "shared_node::tests::supervisor_checks_exact_item_through_its_existing_authority",
    ),
    TestSpec(
        "supervisor_generation_cascade",
        "aster-host",
        "shared_node::tests::pump_generation_change_invalidates_and_wakes_every_admitted_contact",
    ),
    TestSpec(
        "supervisor_duplicate_no_cascade",
        "aster-host",
        "shared_node::tests::rejected_admin_result_after_generation_change_invalidates_all_but_duplicate_does_not",
    ),
    TestSpec(
        "queued_generation_invalidation_and_recovery",
        "aster-lab",
        "mesh_experiment::tests::native_gate_h_signed_control_queued_generation_invalidation_and_recovery",
    ),
    TestSpec(
        "native_restart_replacement",
        "aster-lab",
        "mesh_experiment::tests::same_address_carrier_restart_replaces_and_reauthenticates_one_session",
    ),
)

MANDATORY_CASES = frozenset(spec.case for spec in TEST_SPECS)
EXPECTED_CASES = frozenset(
    {
        "admission_single_use",
        "admission_authorization_failure",
        "admission_resource_failure",
        "admission_panic_rollback",
        "preauthentication_timeout",
        "identity_and_allowlist_conflicts",
        "preauthentication_cancellation",
        "late_host_commit_rollback",
        "reservation_precedes_allocation",
        "factory_panic_rollback",
        "parallel_resource_limits",
        "unwind_resource_release",
        "full_vector_connection_churn",
        "lifecycle_replace_without_double_charge",
        "post_auth_capacity_rollback",
        "blob_quota_race",
        "mixed_ordinary_control",
        "mixed_bridge_control",
        "runtime_commit_error_generation",
        "peer_neutral_resume_unavailable_peer",
        "process_owned_durable_item_probe",
        "supervisor_generation_cascade",
        "supervisor_duplicate_no_cascade",
        "queued_generation_invalidation_and_recovery",
        "native_restart_replacement",
    }
)
if MANDATORY_CASES != EXPECTED_CASES:  # pragma: no cover - import-time invariant
    raise RuntimeError("Gate-H command plan does not cover the mandatory case set")


# These are the direct implementation and baseline inputs exercised by the
# fixed commands.  The candidate commit/tree bind the rest of the repository.
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "mise.toml",
    "data-mesh-requirements.md",
    "docs/protocol.md",
    "docs/proposals/0004-shared-node-libp2p-retest.md",
    "crates/aster-core/Cargo.toml",
    "crates/aster-core/src/engine.rs",
    "crates/aster-core/src/runtime.rs",
    "crates/aster-core/src/runtime/reference_semantic.rs",
    "crates/aster-core/src/store.rs",
    "crates/aster-core/src/sync.rs",
    "crates/aster-host/Cargo.toml",
    "crates/aster-host/src/lib.rs",
    "crates/aster-host/src/mesh_host.rs",
    "crates/aster-host/src/node_admission.rs",
    "crates/aster-host/src/node_budget.rs",
    "crates/aster-host/src/shared_node.rs",
    "crates/aster-ip/Cargo.toml",
    "crates/aster-ip/src/bin/aster-relay.rs",
    "crates/aster-ip/src/lib.rs",
    "crates/aster-ip/src/relay.rs",
    "crates/aster-lab/Cargo.toml",
    "crates/aster-lab/src/gate_h_main.rs",
    "crates/aster-lab/src/lib.rs",
    "crates/aster-lab/src/main.rs",
    "crates/aster-lab/src/mesh_experiment.rs",
    "lab/Dockerfile",
    "lab/gate_h_faults.py",
    "lab/gate_h_signature.py",
    "lab/gate_h_source.py",
    "lab/tests/test_gate_h_source.py",
)

STATIC_CHECK_NAMES = frozenset(
    {
        "provider_contact_path_has_no_durable_open_or_credentials",
        "provider_precomposition_has_no_durable_open_or_credentials",
        "provider_has_no_per_contact_open_helper",
        "contact_driver_never_owns_the_durable_backend",
        "common_contact_driver_uses_a_weak_authority_session",
        "native_shared_open_constructs_each_durable_owner_once",
        "native_process_constructs_one_runtime_authority",
        "runtime_authority_exposes_no_closure_api",
        "runtime_authority_public_surface_is_typed",
        "host_event_has_no_authenticated_admission_bypass",
        "mesh_host_admission_coordinator_is_crate_private",
        "node_admission_coordinator_is_crate_private",
        "admission_coordinator_has_no_public_reexport",
        "ip_provider_has_no_runtime_or_durable_authority",
        "shared_supervisor_owns_all_driver_session_and_pump_controls",
        "factory_is_the_only_public_contact_open_seam",
        "candidate_status_identity_hint_is_untrusted",
        "formal_gate_h_feature_graph_excludes_legacy_service",
        "legacy_contact_and_lab_surfaces_are_cfg_gated",
        "legacy_service_controls_are_confined_to_gated_module",
        "legacy_lab_controls_are_confined_to_gated_module",
        "host_nongated_production_has_no_legacy_service_controls",
        "lab_nongated_production_has_no_legacy_service_controls",
        "gate_h_binary_has_no_legacy_command_reachability",
        "gate_h_docker_build_is_no_default_and_candidate_aliased",
        "formal_graph_has_no_libp2p_or_iroh_dependency",
    }
)
TYPED_AUTHORITY_METHODS = frozenset(
    {
        "new",
        "session",
        "invalidate_authorization_generation",
        "authorization_generation",
        "durable_item_present",
        "blob_quota_snapshot",
        "apply_authorization_control",
    }
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256_bytes(encoded)


def attach_interrupted_process_receipt(
    interruption: BaseException, receipt: dict[str, Any]
) -> None:
    retained = getattr(interruption, "gate_h_interrupted_processes", None)
    if not isinstance(retained, list):
        retained = []
        try:
            setattr(interruption, "gate_h_interrupted_processes", retained)
        except BaseException:
            return
    retained.append(receipt)


def run_isolated_process(
    argv: Sequence[str],
    *,
    environment: dict[str, str] | None,
    stdin_value: bytes | None,
    timeout_seconds: int,
    context: str,
    cwd: Path = WORKSPACE,
) -> tuple[dict[str, Any], bytes | None, bytes | None]:
    """Run one captured child session with fail-closed group cleanup."""

    command = list(argv)
    started_utc = utc_now()
    started = time.monotonic_ns()
    timed_out = False
    execution_error: str | None = None
    returncode = 127
    terminal_returncode: int | None = None
    process_group_reaped: bool | None = None
    interruption: BaseException | None = None
    stdin_bytes = b"" if stdin_value is None else stdin_value
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL if stdin_value is None else subprocess.PIPE,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
            try:
                process.communicate(input=stdin_value, timeout=timeout_seconds)
                returncode = process.returncode
                terminal_returncode = process.returncode
                process_group_reaped = process.poll() is not None
            except subprocess.TimeoutExpired:
                timed_out = True
                returncode = 124
                interruption = terminate_process_group(process)
                terminal_returncode = process.returncode
                process_group_reaped = process.poll() is not None
            except BaseException as error:
                interruption = error
                terminate_process_group(process)
                returncode = (
                    process.returncode
                    if isinstance(process.returncode, int)
                    else 130
                )
                terminal_returncode = process.returncode
                process_group_reaped = process.poll() is not None
            try:
                process_stdin = getattr(process, "stdin", None)
                if process_stdin is not None:
                    process_stdin.close()
            except BaseException as error:
                interruption = interruption or error
        except OSError as error:
            execution_error = str(error)
            stderr_file.write(str(error).encode("utf-8", errors="replace"))
            stderr_file.flush()
        completed_utc = utc_now()
        duration_ms = max(0, (time.monotonic_ns() - started) // 1_000_000)
        stdout_sha256, stdout_evidence, stdout = capture_file(stdout_file)
        stderr_sha256, stderr_evidence, stderr = capture_file(stderr_file)
    receipt = {
        "context": context,
        "argv": command,
        "cwd": str(cwd),
        "environment": None if environment is None else dict(environment),
        "stdin_mode": "devnull" if stdin_value is None else "bytes",
        "stdin_sha256": sha256_bytes(stdin_bytes),
        "stdin": complete_stream(stdin_bytes),
        "started_utc": started_utc,
        "completed_utc": completed_utc,
        "duration_ms": duration_ms,
        "timed_out": timed_out,
        "returncode": returncode,
        "terminal_returncode": terminal_returncode,
        "process_group_reaped": process_group_reaped,
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "stdout": stdout_evidence,
        "stderr": stderr_evidence,
        "execution_error": execution_error,
        "interrupted": interruption is not None,
    }
    if interruption is not None:
        receipt["interruption"] = {
            "type": type(interruption).__name__,
            "message": str(interruption),
            "signum": getattr(interruption, "signum", None),
        }
        attach_interrupted_process_receipt(interruption, receipt)
        raise interruption
    return receipt, stdout, stderr


def checked_git(
    argv: Sequence[str], execution: dict[str, Any] | None = None
) -> str:
    if execution is not None and isinstance(execution.get("signature_trust"), dict):
        command = gate_h_signature.git_argv(execution["signature_trust"], argv)
        environment = execution["signature_trust"]["git_environment"]
    else:
        command = [
            "git" if execution is None else execution["tools"]["git"]["path"],
            *argv,
        ]
        environment = None if execution is None else execution["environment"]
    receipt, stdout, stderr = run_isolated_process(
        command,
        environment=environment,
        stdin_value=None,
        timeout_seconds=30,
        context="git",
    )
    if (
        receipt["timed_out"] is True
        or receipt["execution_error"] is not None
        or stdout is None
        or stderr is None
    ):
        raise GateHFaultError(f"unable to run {' '.join(command)}")
    decoded_stdout = stdout.decode("utf-8", errors="replace")
    decoded_stderr = stderr.decode("utf-8", errors="replace")
    if receipt["returncode"] != 0:
        detail = decoded_stderr.strip() or decoded_stdout.strip()
        raise GateHFaultError(
            f"git preflight failed ({receipt['returncode']}): "
            f"{' '.join(command)}: {detail}"
        )
    return decoded_stdout.rstrip("\r\n")


def execution_workspace(execution: dict[str, Any] | None) -> Path:
    """Return the exact read-only signed source root for formal child work."""

    if execution is None:
        return WORKSPACE
    signed_source = execution.get("signed_source")
    if not isinstance(signed_source, dict):
        return WORKSPACE
    export = signed_source.get("export")
    path_value = export.get("path") if isinstance(export, dict) else None
    if not isinstance(path_value, str) or not Path(path_value).is_absolute():
        raise GateHFaultError("formal signed-source export path is malformed")
    return Path(path_value)


def command_plan(cargo_executable: str = "cargo") -> list[dict[str, Any]]:
    return [
        {
            "case": spec.case,
            "package": spec.package,
            "test_name": spec.test_name,
            "argv": spec.argv(cargo_executable),
        }
        for spec in TEST_SPECS
    ]


def source_binding(freeze: dict[str, Any], relative: str) -> dict[str, Any]:
    matches = [entry for entry in freeze["source_files"] if entry["path"] == relative]
    if len(matches) != 1:
        raise GateHFaultError(f"source freeze has no unique binding for {relative}")
    return matches[0]


def source_region(
    relative: str,
    start_marker: str,
    end_marker: str,
    *,
    workspace: Path = WORKSPACE,
) -> SourceRegion:
    path = workspace / relative
    value = path.read_text(encoding="utf-8")
    if value.count(start_marker) != 1 or value.count(end_marker) != 1:
        raise GateHFaultError(
            f"static-check source markers are not unique in {relative}: "
            f"{start_marker!r}, {end_marker!r}"
        )
    start = value.index(start_marker)
    end = value.index(end_marker, start + len(start_marker))
    return SourceRegion(
        path=relative,
        start_marker=start_marker,
        end_marker=end_marker,
        start_line=value.count("\n", 0, start) + 1,
        value=value[start:end].encode("utf-8"),
    )


def bind_source_files(
    execution: dict[str, Any] | None = None,
    *,
    workspace: Path | None = None,
) -> list[dict[str, Any]]:
    source_workspace = execution_workspace(execution) if workspace is None else workspace
    bindings = []
    for relative in SOURCE_PATHS:
        path = source_workspace / relative
        if path.is_symlink() or not path.is_file():
            raise GateHFaultError(f"required Gate-H source is absent or a symlink: {relative}")
        blob = checked_git(["rev-parse", f"HEAD:{relative}"], execution)
        hash_path = relative if source_workspace == WORKSPACE else str(path)
        worktree_blob = checked_git(
            ["hash-object", "--no-filters", "--", hash_path], execution
        )
        if not HEX_40.fullmatch(blob) or worktree_blob != blob:
            raise GateHFaultError(
                f"Gate-H source does not match the candidate commit: {relative}"
            )
        bindings.append(
            {
                "path": relative,
                "git_blob": blob,
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    return bindings


def freeze_candidate(
    candidate_binary: Path, execution: dict[str, Any] | None = None
) -> dict[str, Any]:
    status = checked_git(
        ["status", "--porcelain=v1", "--untracked-files=all"], execution
    )
    if status:
        raise GateHFaultError("formal Gate-H faults require a clean candidate worktree")

    commit = checked_git(["rev-parse", "HEAD"], execution)
    tree = checked_git(["rev-parse", "HEAD^{tree}"], execution)
    if not HEX_40.fullmatch(commit) or not HEX_40.fullmatch(tree):
        raise GateHFaultError("candidate HEAD or tree is not a full lowercase object ID")

    signature_verification: dict[str, Any] | None = None
    if execution is not None and isinstance(execution.get("signature_trust"), dict):
        try:
            signature_verification = gate_h_signature.verify_commit(
                commit,
                execution["signature_trust"],
                workspace=WORKSPACE,
                base_environment=execution["environment"],
                run_command=run_isolated_process,
            )
        except gate_h_signature.SignatureTrustError as error:
            raise GateHFaultError(
                f"candidate signature trust verification failed: {error}"
            ) from error
        signature_status = signature_verification["status"]
        signature_signer = signature_verification["principal"]
        signature_fingerprint = signature_verification["fingerprint"]
    else:
        signature = checked_git(
            ["log", "-1", "--format=%G?%x00%GS%x00%GF", commit], execution
        ).split("\0")
        if len(signature) != 3:
            raise GateHFaultError("git returned a malformed candidate signature receipt")
        signature_status, signature_signer, signature_fingerprint = signature
        if (
            signature_status != "G"
            or not signature_signer.strip()
            or not signature_fingerprint.strip()
        ):
            raise GateHFaultError(
                "formal Gate-H faults require a valid signed candidate commit"
            )

    requirements = WORKSPACE / "data-mesh-requirements.md"
    requirements_sha256 = sha256_file(requirements)
    if requirements_sha256 != REQUIREMENTS_SHA256:
        raise GateHFaultError("requirements digest differs from the Proposal 0004 baseline")

    if candidate_binary.is_symlink():
        raise GateHFaultError("candidate binary must not be a symlink")
    try:
        resolved_binary = candidate_binary.resolve(strict=True)
        binary_stat = resolved_binary.stat()
    except OSError as error:
        raise GateHFaultError(f"candidate binary is unavailable: {candidate_binary}") from error
    if not stat.S_ISREG(binary_stat.st_mode) or not os.access(resolved_binary, os.X_OK):
        raise GateHFaultError("candidate binary must be a regular executable file")

    sources = bind_source_files(execution)
    proposal = WORKSPACE / "archive/research/proposals/0004-shared-node-libp2p-retest.md"
    return {
        "candidate_commit": commit,
        "candidate_tree": tree,
        "worktree_clean": True,
        "worktree_status": [],
        "signature_status": signature_status,
        "signature_signer": signature_signer,
        "signature_fingerprint": signature_fingerprint,
        "signature_verification": signature_verification,
        "requirements_sha256": requirements_sha256,
        "proposal_0004_sha256": sha256_file(proposal),
        "source_files": sources,
        "source_files_sha256": canonical_sha256(sources),
        "candidate_binary": str(resolved_binary),
        "candidate_binary_sha256": sha256_file(resolved_binary),
        "candidate_binary_size_bytes": binary_stat.st_size,
    }


def bounded_log(value: bytes) -> dict[str, Any]:
    if len(value) <= MAX_RETAINED_LOG_BYTES:
        return {
            "bytes": len(value),
            "truncated": False,
            "text": value.decode("utf-8", errors="replace"),
        }
    half = MAX_RETAINED_LOG_BYTES // 2
    return {
        "bytes": len(value),
        "truncated": True,
        "head": value[:half].decode("utf-8", errors="replace"),
        "tail": value[-half:].decode("utf-8", errors="replace"),
    }


def complete_stream(value: bytes) -> dict[str, Any]:
    complete = len(value) <= MAX_COMPLETE_STREAM_BYTES
    return {
        "bytes": len(value),
        "complete": complete,
        "base64": base64.b64encode(value).decode("ascii") if complete else None,
        "preview": bounded_log(value),
    }


def capture_file(stream: Any) -> tuple[str, dict[str, Any], bytes | None]:
    digest = hashlib.sha256()
    total = 0
    retained = bytearray()
    head = bytearray()
    tail = bytearray()
    half = MAX_RETAINED_LOG_BYTES // 2
    stream.seek(0)
    for chunk in iter(lambda: stream.read(64 * 1024), b""):
        digest.update(chunk)
        total += len(chunk)
        if len(retained) <= MAX_COMPLETE_STREAM_BYTES:
            remaining = MAX_COMPLETE_STREAM_BYTES + 1 - len(retained)
            retained.extend(chunk[:remaining])
        if len(head) < half:
            head.extend(chunk[: half - len(head)])
        tail.extend(chunk)
        if len(tail) > half:
            del tail[:-half]
    is_complete = total <= MAX_COMPLETE_STREAM_BYTES
    full = bytes(retained) if is_complete else None
    preview = (
        bounded_log(full)
        if full is not None
        else {
            "bytes": total,
            "truncated": True,
            "head": bytes(head).decode("utf-8", errors="replace"),
            "tail": bytes(tail).decode("utf-8", errors="replace"),
        }
    )
    evidence = {
        "bytes": total,
        "complete": is_complete,
        "base64": base64.b64encode(full).decode("ascii") if full is not None else None,
        "preview": preview,
    }
    return digest.hexdigest(), evidence, full


def resolved_executable(path_value: str | Path, name: str) -> Path:
    path = Path(path_value)
    if not path.is_absolute():
        raise GateHFaultError(f"{name} executable path is not absolute: {path}")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise GateHFaultError(f"{name} executable is unavailable: {path}") from error
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise GateHFaultError(f"{name} executable is not a regular executable: {resolved}")
    return resolved


def run_provenance_command(
    argv: list[str],
    environment: dict[str, str],
    timeout_seconds: int = 30,
    *,
    cwd: Path = WORKSPACE,
) -> dict[str, Any]:
    receipt, _, _ = run_isolated_process(
        argv,
        environment=environment,
        stdin_value=None,
        timeout_seconds=timeout_seconds,
        context="execution-provenance",
        cwd=cwd,
    )
    return {
        key: receipt[key]
        for key in (
            "argv",
            "cwd",
            "environment",
            "started_utc",
            "completed_utc",
            "duration_ms",
            "timed_out",
            "returncode",
            "stdout_sha256",
            "stderr_sha256",
            "stdout",
            "stderr",
            "execution_error",
        )
    }


def cargo_config_absence(cargo_home: Path) -> dict[str, Any]:
    directories = [WORKSPACE, *WORKSPACE.parents, cargo_home]
    checked = []
    seen = set()
    for directory in directories:
        cargo_directory = directory if directory == cargo_home else directory / ".cargo"
        for filename in ("config", "config.toml"):
            candidate = (cargo_directory / filename).absolute()
            value = str(candidate)
            if value in seen:
                continue
            seen.add(value)
            checked.append(value)
            if candidate.exists() or candidate.is_symlink():
                raise GateHFaultError(
                    f"formal Gate-H faults reject Cargo configuration: {candidate}"
                )
    return {"paths_checked": checked, "all_absent": True}


def tool_binding(
    name: str, path: Path, environment: dict[str, str]
) -> dict[str, Any]:
    version = run_provenance_command(
        [str(path), *TOOL_VERSION_ARGS[name]], environment
    )
    if (
        version["returncode"] != 0
        or version["timed_out"] is not False
        or version["execution_error"] is not None
        or version["stdout"]["complete"] is not True
        or version["stderr"]["complete"] is not True
        or version["stdout"]["bytes"] == 0
    ):
        raise GateHFaultError(f"unable to bind the exact {name} tool version")
    return {
        "name": name,
        "path": str(path),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "version": version,
    }


def formal_feature_graph(
    cargo_path: Path,
    environment: dict[str, str],
    *,
    workspace: Path = WORKSPACE,
) -> dict[str, Any]:
    argv = [
        str(cargo_path),
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
        FEATURE_GRAPH_FORMAT,
    ]
    result = run_provenance_command(
        argv, environment, timeout_seconds=120, cwd=workspace
    )
    encoded = result["stdout"].get("base64")
    try:
        stdout = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        stdout = ""
    required = {
        "aster_lab_gate_h": len(
            re.findall(r"(?m)^aster-lab v[^\r\n]+ features=\[gate-h\]$", stdout)
        ),
        "aster_host_gate_h_formal": len(
            re.findall(
                r"(?m)aster-host v[^\r\n]+ features=\[gate-h-formal\]$", stdout
            )
        ),
    }
    forbidden = sorted(
        set(
            re.findall(
                r"(?i)\b(?:legacy-single-contact-service|legacy-lab|libp2p|iroh)[a-z0-9_-]*\b",
                stdout,
            )
        )
    )
    assertion = {
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
    }
    passed = (
        result["returncode"] == 0
        and result["timed_out"] is False
        and result["execution_error"] is None
        and result["stdout"]["complete"] is True
        and result["stderr"]["complete"] is True
        and required == assertion["required_exact_counts"]
        and forbidden == []
    )
    return {
        **result,
        "assertion": assertion,
        "observed": {
            "required_exact_counts": required,
            "forbidden_tokens": forbidden,
        },
        "passed": passed,
    }


def execute_formal_feature_graph_assertion(
    *,
    name: str,
    freeze: dict[str, Any],
    source_paths: Sequence[str],
    execution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Expose the resolved formal graph as a source-bound static receipt."""

    if execution is None:
        raise GateHFaultError(
            "formal Cargo feature graph assertion requires execution provenance"
        )
    graph = execution.get("formal_feature_graph")
    required_fields = {
        "argv",
        "cwd",
        "environment",
        "started_utc",
        "completed_utc",
        "duration_ms",
        "timed_out",
        "returncode",
        "stdout_sha256",
        "stderr_sha256",
        "stdout",
        "stderr",
        "execution_error",
        "assertion",
        "observed",
        "passed",
    }
    if not isinstance(graph, dict) or set(graph) != required_fields:
        raise GateHFaultError("formal Cargo feature graph receipt is malformed")
    return {
        "name": name,
        "argv": graph["argv"],
        "cwd": graph["cwd"],
        "environment": graph["environment"],
        "source_files": [source_binding(freeze, path) for path in source_paths],
        "source_region": None,
        "assertion": graph["assertion"],
        "observed": graph["observed"],
        "expected_returncode": 0,
        "started_utc": graph["started_utc"],
        "completed_utc": graph["completed_utc"],
        "duration_ms": graph["duration_ms"],
        "timed_out": graph["timed_out"],
        "returncode": graph["returncode"],
        "stdout_sha256": graph["stdout_sha256"],
        "stderr_sha256": graph["stderr_sha256"],
        "stdout": graph["stdout"],
        "stderr": graph["stderr"],
        "execution_error": graph["execution_error"],
        "passed": graph["passed"],
    }


def collect_execution_provenance(
    signature_request: gate_h_signature.SignatureRequest | None = None,
) -> dict[str, Any]:
    if "CARGO_TARGET_DIR" in os.environ:
        raise GateHFaultError(
            "formal Gate-H faults reject a pre-existing CARGO_TARGET_DIR"
        )
    home_value = os.environ.get("HOME")
    if not home_value or not Path(home_value).is_absolute():
        raise GateHFaultError("formal Gate-H faults require an absolute HOME")
    home = Path(home_value).resolve()
    cargo_home_value = os.environ.get("CARGO_HOME", str(home / ".cargo"))
    rustup_home_value = os.environ.get("RUSTUP_HOME", str(home / ".rustup"))
    cargo_home = Path(cargo_home_value)
    rustup_home = Path(rustup_home_value)
    if not cargo_home.is_absolute() or not rustup_home.is_absolute():
        raise GateHFaultError("Cargo and rustup homes must be absolute")
    rustup_candidate = cargo_home / "bin/rustup"
    if not rustup_candidate.is_file():
        discovered = shutil.which("rustup")
        if discovered is None:
            raise GateHFaultError("rustup is unavailable for pinned toolchain resolution")
        rustup_candidate = Path(discovered)
    rustup = resolved_executable(rustup_candidate, "rustup")
    discovery_environment = {
        "CARGO_HOME": str(cargo_home),
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": FORMAL_SYSTEM_PATH,
        "RUSTUP_HOME": str(rustup_home),
    }
    resolution: dict[str, dict[str, Any]] = {}
    resolved_tools: dict[str, Path] = {}
    for name in ("cargo", "rustc", "rustdoc"):
        command = run_provenance_command(
            [str(rustup), "which", name], discovery_environment
        )
        encoded = command["stdout"].get("base64")
        try:
            output = base64.b64decode(encoded, validate=True).decode("utf-8").strip()
        except (TypeError, ValueError, UnicodeError):
            output = ""
        if (
            command["returncode"] != 0
            or command["timed_out"] is not False
            or command["execution_error"] is not None
            or not output
            or "\n" in output
        ):
            raise GateHFaultError(f"rustup could not resolve the pinned {name}")
        resolved_tools[name] = resolved_executable(output, name)
        command["resolved_path"] = str(resolved_tools[name])
        resolution[name] = command
    if signature_request is None:
        raise GateHFaultError("formal Gate-H faults require explicit signature trust inputs")
    rg_value = shutil.which("rg")
    if rg_value is None:
        raise GateHFaultError("formal Gate-H faults require rg")
    resolved_tools["rg"] = resolved_executable(rg_value, "rg")
    try:
        git_binding = gate_h_signature.bind_executable(signature_request.git, "git")
    except gate_h_signature.SignatureTrustError as error:
        raise GateHFaultError(f"invalid formal Git executable: {error}") from error
    resolved_tools["git"] = Path(git_binding["path"])
    resolved_tools["rustup"] = rustup
    config_absence = cargo_config_absence(cargo_home)
    target_directory = (WORKSPACE / "target/gate-h-faults-v2").resolve()
    if target_directory.exists() or target_directory.is_symlink():
        raise GateHFaultError(
            f"formal Cargo target directory already exists: {target_directory}"
        )
    try:
        target_directory.mkdir(mode=0o700)
    except OSError as error:
        raise GateHFaultError("unable to create the formal Cargo target directory") from error
    if not target_directory.is_dir() or any(target_directory.iterdir()):
        raise GateHFaultError("formal Cargo target directory was not created empty")
    environment = {
        "CARGO_HOME": str(cargo_home),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": str(target_directory),
        "CARGO_TERM_COLOR": "never",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": FORMAL_SYSTEM_PATH,
        "RUST_BACKTRACE": "0",
        "RUSTC": str(resolved_tools["rustc"]),
        "RUSTDOC": str(resolved_tools["rustdoc"]),
        "TMPDIR": "/tmp",
    }
    if set(environment) != FORMAL_ENVIRONMENT_KEYS:
        raise GateHFaultError("formal execution environment does not match its allowlist")
    tools = {
        name: tool_binding(name, resolved_tools[name], environment)
        for name in sorted(resolved_tools)
    }
    try:
        signature_trust = gate_h_signature.prepare_signature_trust(
            signature_request,
            workspace=WORKSPACE,
            frozen_directory=target_directory,
            base_environment=environment,
            run_command=run_isolated_process,
        )
    except gate_h_signature.SignatureTrustError as error:
        raise GateHFaultError(f"formal signature trust setup failed: {error}") from error
    return {
        "environment": environment,
        "cargo_config": config_absence,
        "target_directory": {
            "path": str(target_directory),
            "initially_absent": True,
            "created_empty": True,
        },
        "rustup_resolution": {
            "environment": discovery_environment,
            "commands": resolution,
        },
        "tools": tools,
        "signature_trust": signature_trust,
        "passed": True,
    }


def materialize_signed_source_execution(
    freeze: dict[str, Any],
    execution: dict[str, Any],
    timeout_seconds: int,
) -> dict[str, Any]:
    """Materialize the signed tree without executing any formal test work."""

    target = Path(execution["target_directory"]["path"])
    archive_path = target / "gate-h-signed-source.tar"
    export_root = target / "gate-h-signed-source"
    try:
        receipt = gate_h_source.materialize_signed_tree(
            freeze["candidate_commit"],
            freeze["candidate_tree"],
            execution["signature_trust"],
            workspace=WORKSPACE,
            archive_path=archive_path,
            export_root=export_root,
            base_environment=execution["environment"],
            run_command=run_isolated_process,
            timeout_seconds=timeout_seconds,
        )
        gate_h_source.validate_signed_tree_receipt(
            receipt,
            workspace=WORKSPACE,
            trust=execution["signature_trust"],
            verify_archive_file=True,
            verify_export=True,
        )
    except gate_h_source.SignedSourceError as error:
        raise GateHFaultError(f"formal signed-source export failed: {error}") from error
    execution["signed_source"] = receipt
    return receipt


def activate_signed_source_execution(
    freeze: dict[str, Any],
    execution: dict[str, Any],
    receipt: dict[str, Any],
) -> Path:
    """Validate the export and run every source-dependent proof from it."""

    try:
        source_workspace = gate_h_source.validate_signed_tree_receipt(
            receipt,
            workspace=WORKSPACE,
            trust=execution["signature_trust"],
            verify_archive_file=True,
            verify_export=True,
        )
    except gate_h_source.SignedSourceError as error:
        raise GateHFaultError(f"formal signed-source export failed: {error}") from error
    execution["signed_source"] = receipt
    sources = bind_source_files(execution, workspace=source_workspace)
    freeze["source_files"] = sources
    freeze["source_files_sha256"] = canonical_sha256(sources)
    feature_graph = formal_feature_graph(
        Path(execution["tools"]["cargo"]["path"]),
        execution["environment"],
        workspace=source_workspace,
    )
    if not feature_graph["passed"]:
        raise GateHFaultError("formal Cargo feature graph is incomplete or provider-tainted")
    execution["formal_feature_graph"] = feature_graph
    try:
        gate_h_source.validate_signed_tree_receipt(
            receipt,
            workspace=WORKSPACE,
            trust=execution["signature_trust"],
            verify_archive_file=True,
            verify_export=True,
        )
    except gate_h_source.SignedSourceError as error:
        raise GateHFaultError(
            f"formal signed-source export changed during feature resolution: {error}"
        ) from error
    return source_workspace


def prepare_signed_source_execution(
    freeze: dict[str, Any],
    execution: dict[str, Any],
    timeout_seconds: int,
) -> dict[str, Any]:
    """Compatibility wrapper used by injected/unit receipt generation."""

    receipt = materialize_signed_source_execution(freeze, execution, timeout_seconds)
    activate_signed_source_execution(freeze, execution, receipt)
    return receipt


def execute_rg_assertion(
    *,
    name: str,
    argv: list[str],
    freeze: dict[str, Any],
    source_paths: Sequence[str],
    assertion: dict[str, Any],
    region: SourceRegion | None = None,
    execution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    argv = list(argv)
    if execution is not None:
        argv[0] = execution["tools"]["rg"]["path"]
    environment = None if execution is None else dict(execution["environment"])
    workspace = execution_workspace(execution)
    isolated, stdout, stderr = run_isolated_process(
        argv,
        environment=environment,
        stdin_value=None if region is None else region.value,
        timeout_seconds=30,
        context=f"static-check:{name}",
        cwd=workspace,
    )
    decoded = b"" if stdout is None else stdout
    decoded = decoded.decode("utf-8", errors="replace")
    lines = [line for line in decoded.splitlines() if line]
    kind = assertion["kind"]
    expected_returncode = 1 if kind == "absent" else 0
    observed: dict[str, Any] = {"match_count": len(lines)}
    assertion_passed = False
    if kind == "absent":
        assertion_passed = len(lines) == 0
    elif kind == "exact_count":
        assertion_passed = len(lines) == assertion["count"]
    elif kind == "token_counts":
        expected_counts = assertion["counts"]
        observed_counts = {
            token: decoded.count(token) for token in expected_counts
        }
        observed["token_counts"] = observed_counts
        expected_match_count = assertion.get("match_count")
        assertion_passed = observed_counts == expected_counts and (
            expected_match_count is None or len(lines) == expected_match_count
        )
    elif kind == "method_set":
        methods = re.findall(r"pub(?: const)? fn ([a-z_][a-z0-9_]*)", decoded)
        observed["methods"] = methods
        expected_methods = assertion["methods"]
        assertion_passed = (
            len(methods) == len(expected_methods)
            and sorted(methods) == sorted(expected_methods)
        )
    else:  # pragma: no cover - plan construction invariant
        raise GateHFaultError(f"unknown static assertion kind: {kind}")

    passed = (
        isolated["timed_out"] is False
        and isolated["execution_error"] is None
        and isolated["returncode"] == expected_returncode
        and stdout is not None
        and stderr == b""
        and assertion_passed
    )
    return {
        "name": name,
        "argv": argv,
        "cwd": str(workspace),
        "environment": environment,
        "source_files": [source_binding(freeze, path) for path in source_paths],
        "source_region": None if region is None else region.receipt(),
        "assertion": assertion,
        "observed": observed,
        "expected_returncode": expected_returncode,
        "started_utc": isolated["started_utc"],
        "completed_utc": isolated["completed_utc"],
        "duration_ms": isolated["duration_ms"],
        "timed_out": isolated["timed_out"],
        "returncode": isolated["returncode"],
        "stdout_sha256": isolated["stdout_sha256"],
        "stderr_sha256": isolated["stderr_sha256"],
        "stdout": isolated["stdout"],
        "stderr": isolated["stderr"],
        "execution_error": isolated["execution_error"],
        "passed": passed,
    }


def execute_static_checks(
    freeze: dict[str, Any],
    execute_rg_assertion: Callable[..., dict[str, Any]] = execute_rg_assertion,
    execute_formal_graph_assertion: Callable[..., dict[str, Any]] = (
        execute_formal_feature_graph_assertion
    ),
    execution: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    if execution is not None:
        assertion_executor = execute_rg_assertion

        def execute_rg_assertion(**kwargs: Any) -> dict[str, Any]:
            return assertion_executor(**kwargs, execution=execution)

    workspace = execution_workspace(execution)

    root_manifest_path = "Cargo.toml"
    lock_path = "Cargo.lock"
    core_manifest_path = "crates/aster-core/Cargo.toml"
    host_manifest_path = "crates/aster-host/Cargo.toml"
    mesh_path = "crates/aster-lab/src/mesh_experiment.rs"
    host_lib_path = "crates/aster-host/src/lib.rs"
    mesh_host_path = "crates/aster-host/src/mesh_host.rs"
    node_admission_path = "crates/aster-host/src/node_admission.rs"
    shared_path = "crates/aster-host/src/shared_node.rs"
    runtime_path = "crates/aster-core/src/runtime/reference_semantic.rs"
    ip_manifest_path = "crates/aster-ip/Cargo.toml"
    ip_source_paths = [
        "crates/aster-ip/src/bin/aster-relay.rs",
        "crates/aster-ip/src/lib.rs",
        "crates/aster-ip/src/relay.rs",
    ]
    lab_manifest_path = "crates/aster-lab/Cargo.toml"
    lab_lib_path = "crates/aster-lab/src/lib.rs"
    gate_h_main_path = "crates/aster-lab/src/gate_h_main.rs"
    docker_path = "lab/Dockerfile"
    legacy_host_start_marker = (
        '#[cfg(feature = "legacy-single-contact-service")]\n'
        "#[rustfmt::skip]\n"
        "mod legacy_single_contact_service {"
    )
    legacy_lab_start_marker = (
        '#[cfg(feature = "legacy-lab")]\n'
        "#[rustfmt::skip]\n"
        "mod legacy_lab {"
    )
    provider_precomposition_region = source_region(
        mesh_path,
        "struct NativeContactLink {",
        "fn open_native_shared_supervisor(",
        workspace=workspace,
    )
    provider_region = source_region(
        mesh_path,
        "fn apply_native_actions(",
        "fn ip_mesh_application_options(",
        workspace=workspace,
    )
    native_open_region = source_region(
        mesh_path,
        "fn open_native_shared_supervisor_with_limits(",
        "/// Runs one bounded native MeshHost-composed IP mesh node.",
        workspace=workspace,
    )
    authority_region = source_region(
        runtime_path,
        "impl ReferenceSemanticRuntimeAuthority {",
        "impl ReferenceSemanticRuntimeSession {",
        workspace=workspace,
    )
    host_event_region = source_region(
        mesh_host_path,
        "pub enum HostEvent {",
        "/// Work for a connectivity provider. No action contains application data.",
        workspace=workspace,
    )
    candidate_status_region = source_region(
        mesh_host_path,
        "pub struct CandidateStatus {",
        "/// Bounded host status. This is not a global convergence claim.",
        workspace=workspace,
    )
    shared_supervisor_region = source_region(
        shared_path,
        "pub struct SharedNodeContactSupervisor {",
        "#[cfg(test)]\nmod tests {",
        workspace=workspace,
    )
    legacy_host_region = source_region(
        host_lib_path,
        legacy_host_start_marker,
        "#[cfg(test)]\nmod tests {",
        workspace=workspace,
    )
    legacy_lab_region = source_region(
        lab_lib_path,
        legacy_lab_start_marker,
        "#[cfg(test)]\nmod tests {",
        workspace=workspace,
    )
    host_nongated_region = source_region(
        host_lib_path,
        "//! Process-owned, offline-first composition host for Aster Mesh.",
        '#[cfg(feature = "legacy-single-contact-service")]\n'
        "pub use legacy_single_contact_service::{",
        workspace=workspace,
    )
    lab_nongated_region = source_region(
        lab_lib_path,
        "//! Deterministic and real-process laboratories for Aster Mesh.",
        '#[cfg(feature = "legacy-lab")]\npub mod live;',
        workspace=workspace,
    )
    gate_h_binary_region = source_region(
        gate_h_main_path,
        "#![forbid(unsafe_code)]",
        "#[cfg(test)]\nmod tests {",
        workspace=workspace,
    )

    checks = [
        execute_rg_assertion(
            name="provider_contact_path_has_no_durable_open_or_credentials",
            argv=[
                "rg",
                "-n",
                "-e",
                r"open_reference_node\s*\(",
                "-e",
                r"ReferenceSemanticRuntime(?:Authority|Backend|Session)",
                "-e",
                r"ProvisioningBundle|UnprotectedProvisioning|credential(?:s|_path)?|\.bundle",
                "-e",
                "open_native_shared_supervisor",
                "-e",
                r"RuntimeDriver|admit_authenticated|require_external_admission",
                "-e",
                r"(?:NodeResourceBudget::new|\.try_reserve\s*\()",
                "-",
            ],
            freeze=freeze,
            source_paths=[mesh_path],
            region=provider_region,
            assertion={"kind": "absent", "count": 0},
        ),
        execute_rg_assertion(
            name="provider_precomposition_has_no_durable_open_or_credentials",
            argv=[
                "rg",
                "-n",
                "-e",
                r"open_reference_node\s*\(",
                "-e",
                r"ReferenceSemanticRuntime(?:Authority|Backend|Session)",
                "-e",
                r"BlobTransferStore|RuntimeDriver|admit_authenticated|require_external_admission",
                "-e",
                r"ProvisioningBundle|UnprotectedProvisioning|credential(?:s|_path)?|\.bundle",
                "-e",
                r"(?:NodeResourceBudget::new|\.try_reserve\s*\()",
                "-",
            ],
            freeze=freeze,
            source_paths=[mesh_path],
            region=provider_precomposition_region,
            assertion={"kind": "absent", "count": 0},
        ),
        execute_rg_assertion(
            name="provider_has_no_per_contact_open_helper",
            argv=[
                "rg",
                "-n",
                r"^\s*fn (?:open|create|initialize)_native_contact(?:_|\()",
                mesh_path,
            ],
            freeze=freeze,
            source_paths=[mesh_path],
            assertion={"kind": "absent", "count": 0},
        ),
        execute_rg_assertion(
            name="contact_driver_never_owns_the_durable_backend",
            argv=[
                "rg",
                "-n",
                "-U",
                "-e",
                r"RuntimeDriver\s*<\s*ReferenceSemanticRuntimeBackend\s*>",
                "-e",
                r"\.(?:backend|backend_mut|into_backend)\s*\(",
                "-e",
                r"^\s+pub(?:\([^)]*\))?\s+(?:const\s+)?fn\s+(?:authority|runtime_authority|backend|backend_mut|into_backend)\b",
                "-",
            ],
            freeze=freeze,
            source_paths=[shared_path],
            region=shared_supervisor_region,
            assertion={"kind": "absent", "count": 0},
        ),
        execute_rg_assertion(
            name="common_contact_driver_uses_a_weak_authority_session",
            argv=[
                "rg",
                "-n",
                "--fixed-strings",
                "type SharedContactDriver = RuntimeDriver<ReferenceSemanticRuntimeSession>;",
                shared_path,
            ],
            freeze=freeze,
            source_paths=[shared_path],
            assertion={"kind": "exact_count", "count": 1},
        ),
        execute_rg_assertion(
            name="native_shared_open_constructs_each_durable_owner_once",
            argv=[
                "rg",
                "-n",
                "-e",
                r"open_reference_node\s*\(",
                "-e",
                r"BlobTransferStore::open_with_config\s*\(",
                "-e",
                r"ReferenceSemanticRuntimeBackend::new\s*\(",
                "-e",
                r"ReferenceSemanticRuntimeAuthority::new\s*\(",
                "-e",
                r"SharedNodeContactSupervisor::new\(",
                "-",
            ],
            freeze=freeze,
            source_paths=[mesh_path],
            region=native_open_region,
            assertion={
                "kind": "token_counts",
                "match_count": 5,
                "counts": {
                    "open_reference_node(": 1,
                    "BlobTransferStore::open_with_config": 1,
                    "ReferenceSemanticRuntimeBackend::new(node, blobs)": 1,
                    "ReferenceSemanticRuntimeAuthority::new(backend)": 1,
                    "SharedNodeContactSupervisor::new(": 1,
                },
            },
        ),
        execute_rg_assertion(
            name="native_process_constructs_one_runtime_authority",
            argv=[
                "rg",
                "-n",
                "--fixed-strings",
                "ReferenceSemanticRuntimeAuthority::new(",
                mesh_path,
            ],
            freeze=freeze,
            source_paths=[mesh_path],
            assertion={"kind": "exact_count", "count": 1},
        ),
        execute_rg_assertion(
            name="runtime_authority_exposes_no_closure_api",
            argv=[
                "rg",
                "-n",
                r"Fn(?:Once|Mut)?|dyn\s+Fn|impl\s+Fn",
                "-",
            ],
            freeze=freeze,
            source_paths=[runtime_path],
            region=authority_region,
            assertion={"kind": "absent", "count": 0},
        ),
        execute_rg_assertion(
            name="runtime_authority_public_surface_is_typed",
            argv=[
                "rg",
                "-n",
                r"^    pub(?: const)? fn [a-z_][a-z0-9_]*",
                "-",
            ],
            freeze=freeze,
            source_paths=[runtime_path],
            region=authority_region,
            assertion={
                "kind": "method_set",
                "methods": sorted(TYPED_AUTHORITY_METHODS),
            },
        ),
        execute_rg_assertion(
            name="host_event_has_no_authenticated_admission_bypass",
            argv=[
                "rg",
                "-n",
                "-e",
                r"\b(?:AsterAuthenticated|aster_authenticated|authenticated_peer)\b",
                "-e",
                "non-authoritative scheduling hint",
                "-e",
                "atomic admission transaction",
                "-",
            ],
            freeze=freeze,
            source_paths=[mesh_host_path],
            region=host_event_region,
            assertion={
                "kind": "token_counts",
                "match_count": 2,
                "counts": {
                    "AsterAuthenticated": 0,
                    "aster_authenticated": 0,
                    "authenticated_peer": 0,
                    "non-authoritative scheduling hint": 1,
                    "atomic admission transaction": 1,
                },
            },
        ),
        execute_rg_assertion(
            name="mesh_host_admission_coordinator_is_crate_private",
            argv=[
                "rg",
                "-n",
                "-e",
                r"^pub(?:\(crate\))? struct Admission(?:Token|Preparation)\b",
                "-e",
                r"^\s+pub(?:\(crate\))? fn (?:prepare|commit|abort)_authenticated\b",
                mesh_host_path,
            ],
            freeze=freeze,
            source_paths=[mesh_host_path],
            assertion={
                "kind": "token_counts",
                "match_count": 5,
                "counts": {
                    "pub(crate) struct Admission": 2,
                    "pub(crate) fn ": 3,
                    "pub struct Admission": 0,
                    "pub fn ": 0,
                },
            },
        ),
        execute_rg_assertion(
            name="node_admission_coordinator_is_crate_private",
            argv=[
                "rg",
                "-n",
                "-e",
                r"^pub(?:\(crate\))? enum AdmissionTransaction\b",
                "-e",
                r"^pub(?:\(crate\))? fn transact_authenticated<",
                node_admission_path,
            ],
            freeze=freeze,
            source_paths=[node_admission_path],
            assertion={
                "kind": "token_counts",
                "match_count": 2,
                "counts": {
                    "pub(crate) enum AdmissionTransaction": 1,
                    "pub(crate) fn transact_authenticated": 1,
                    "pub enum AdmissionTransaction": 0,
                    "pub fn transact_authenticated": 0,
                },
            },
        ),
        execute_rg_assertion(
            name="admission_coordinator_has_no_public_reexport",
            argv=[
                "rg",
                "-n",
                r"\b(?:AdmissionTransaction|transact_authenticated)\b",
                "-",
            ],
            freeze=freeze,
            source_paths=[host_lib_path],
            assertion={"kind": "absent", "count": 0},
        ),
        execute_rg_assertion(
            name="ip_provider_has_no_runtime_or_durable_authority",
            argv=[
                "rg",
                "-n",
                "-e",
                r"open_reference_node\s*\(",
                "-e",
                r"BlobTransferStore|ReferenceSemanticRuntime(?:Backend|Authority|Session)",
                "-e",
                r"RuntimeDriver|admit_authenticated|require_external_admission",
                "-e",
                r"ProvisioningBundle|UnprotectedProvisioning|credential(?:s|_path)?|\.bundle",
                "-e",
                r"(?:NodeResourceBudget::new|\.try_reserve\s*\()",
                "-e",
                r"\.(?:backend|backend_mut|into_backend)\s*\(",
                *ip_source_paths,
            ],
            freeze=freeze,
            source_paths=ip_source_paths,
            assertion={"kind": "absent", "count": 0},
        ),
        execute_rg_assertion(
            name="shared_supervisor_owns_all_driver_session_and_pump_controls",
            argv=[
                "rg",
                "-n",
                "-e",
                r"self\.authority\.session\(\)",
                "-e",
                r"RuntimeDriver::[a-z_][a-z0-9_]*\s*\(",
                "-e",
                r"\.(?:require_external_admission|admit_authenticated)\(\)",
                "-e",
                r"managed\.driver\.pump\(",
                "-",
            ],
            freeze=freeze,
            source_paths=[shared_path],
            region=shared_supervisor_region,
            assertion={
                "kind": "token_counts",
                "match_count": 6,
                "counts": {
                    "self.authority.session()": 1,
                    "RuntimeDriver::": 2,
                    "RuntimeDriver::initiator_with_limits(": 1,
                    "RuntimeDriver::responder_with_start_and_limits(": 1,
                    ".require_external_admission()": 1,
                    ".admit_authenticated()": 1,
                    "managed.driver.pump(": 1,
                },
            },
        ),
        execute_rg_assertion(
            name="factory_is_the_only_public_contact_open_seam",
            argv=[
                "rg",
                "-n",
                r"^\s+pub(?:\([^)]*\))?\s+(?:async\s+)?fn\s+open_contact",
                "-",
            ],
            freeze=freeze,
            source_paths=[shared_path],
            region=shared_supervisor_region,
            assertion={
                "kind": "token_counts",
                "match_count": 1,
                "counts": {
                    "fn open_contact": 1,
                    "fn open_contact_with_factory": 1,
                },
            },
        ),
        execute_rg_assertion(
            name="candidate_status_identity_hint_is_untrusted",
            argv=[
                "rg",
                "-n",
                "-e",
                r"\b(?:authenticated_peer|previously_bound_peer_hint)\b",
                "-e",
                "Non-authoritative",
                "-e",
                "never evidence",
                "-",
            ],
            freeze=freeze,
            source_paths=[mesh_host_path],
            region=candidate_status_region,
            assertion={
                "kind": "token_counts",
                "match_count": 3,
                "counts": {
                    "authenticated_peer": 0,
                    "previously_bound_peer_hint": 1,
                    "Non-authoritative": 1,
                    "never evidence": 1,
                },
            },
        ),
        execute_rg_assertion(
            name="formal_gate_h_feature_graph_excludes_legacy_service",
            argv=[
                "rg",
                "-n",
                "--fixed-strings",
                "-e",
                'aster-core = { version = "=0.1.0", path = "../aster-core", features = ["adapter-sdk"] }',
                "-e",
                'aster-host = { version = "=0.1.0", path = "../aster-host", default-features = false }',
                "-e",
                'default = ["legacy-single-contact-service"]',
                "-e",
                "legacy-single-contact-service = []",
                "-e",
                "gate-h-formal = []",
                "-e",
                'default = ["legacy-lab"]',
                "-e",
                'legacy-lab = ["aster-host/legacy-single-contact-service"]',
                "-e",
                'gate-h = ["aster-host/gate-h-formal"]',
                "-e",
                'path = "src/main.rs"',
                "-e",
                'required-features = ["legacy-lab"]',
                "-e",
                'path = "src/gate_h_main.rs"',
                "-e",
                'required-features = ["gate-h"]',
                host_manifest_path,
                lab_manifest_path,
            ],
            freeze=freeze,
            source_paths=[host_manifest_path, lab_manifest_path],
            assertion={
                "kind": "token_counts",
                "match_count": 13,
                "counts": {
                    'aster-core = { version = "=0.1.0", path = "../aster-core", features = ["adapter-sdk"] }': 2,
                    'aster-host = { version = "=0.1.0", path = "../aster-host", default-features = false }': 1,
                    'default = ["legacy-single-contact-service"]': 1,
                    "legacy-single-contact-service = []": 1,
                    "gate-h-formal = []": 1,
                    'default = ["legacy-lab"]': 1,
                    'legacy-lab = ["aster-host/legacy-single-contact-service"]': 1,
                    'gate-h = ["aster-host/gate-h-formal"]': 1,
                    'path = "src/main.rs"': 1,
                    'required-features = ["legacy-lab"]': 1,
                    'path = "src/gate_h_main.rs"': 1,
                    'required-features = ["gate-h"]': 1,
                },
            },
        ),
        execute_rg_assertion(
            name="legacy_contact_and_lab_surfaces_are_cfg_gated",
            argv=[
                "rg",
                "-n",
                "--fixed-strings",
                "-e",
                '#[cfg(feature = "legacy-single-contact-service")]',
                "-e",
                "pub use legacy_single_contact_service::{",
                "-e",
                "mod legacy_single_contact_service {",
                "-e",
                '#[cfg(feature = "legacy-lab")]',
                "-e",
                "pub mod live;",
                "-e",
                "pub use legacy_lab::*;",
                "-e",
                "mod legacy_lab {",
                host_lib_path,
                lab_lib_path,
            ],
            freeze=freeze,
            source_paths=[host_lib_path, lab_lib_path],
            assertion={
                "kind": "token_counts",
                "match_count": 10,
                "counts": {
                    '#[cfg(feature = "legacy-single-contact-service")]': 2,
                    "pub use legacy_single_contact_service::{": 1,
                    "mod legacy_single_contact_service {": 1,
                    '#[cfg(feature = "legacy-lab")]': 3,
                    "pub mod live;": 1,
                    "pub use legacy_lab::*;": 1,
                    "mod legacy_lab {": 1,
                },
            },
        ),
        execute_rg_assertion(
            name="legacy_service_controls_are_confined_to_gated_module",
            argv=[
                "rg",
                "-n",
                "--fixed-strings",
                "-e",
                "type ContactDriver = RuntimeDriver<PeerBoundBackend>;",
                "-e",
                "struct ConfiguredCarrier {",
                "-e",
                "struct PeerBoundBackend {",
                "-e",
                "impl RuntimeBackend for PeerBoundBackend {",
                "-e",
                "pub fn configure_peer_carrier<",
                "-e",
                "pub fn begin_sync(",
                "-e",
                "driver.pump(",
                "-e",
                "pub fn pause_sync(",
                "-e",
                "pub fn next_wakeup(",
                "-e",
                "ServiceState::Active",
                "-",
            ],
            freeze=freeze,
            source_paths=[host_lib_path],
            region=legacy_host_region,
            assertion={
                "kind": "token_counts",
                "match_count": 21,
                "counts": {
                    "type ContactDriver = RuntimeDriver<PeerBoundBackend>;": 1,
                    "struct ConfiguredCarrier {": 1,
                    "struct PeerBoundBackend {": 1,
                    "impl RuntimeBackend for PeerBoundBackend {": 1,
                    "pub fn configure_peer_carrier<": 1,
                    "pub fn begin_sync(": 1,
                    "driver.pump(": 1,
                    "pub fn pause_sync(": 1,
                    "pub fn next_wakeup(": 1,
                    "ServiceState::Active": 12,
                },
            },
        ),
        execute_rg_assertion(
            name="legacy_lab_controls_are_confined_to_gated_module",
            argv=[
                "rg",
                "-n",
                "--fixed-strings",
                "-e",
                "use aster_host::{MeshService, ServiceOptions, SyncProfile};",
                "-e",
                "MeshService::open(",
                "-e",
                ".begin_sync(",
                "-e",
                "pub fn run_transfer(",
                "-e",
                "pub fn run_route_only_event(",
                "-e",
                "pub fn run_blob_recovery(",
                "-e",
                "pub fn run_shard(",
                "-",
            ],
            freeze=freeze,
            source_paths=[lab_lib_path],
            region=legacy_lab_region,
            assertion={
                "kind": "token_counts",
                "match_count": 33,
                "counts": {
                    "use aster_host::{MeshService, ServiceOptions, SyncProfile};": 1,
                    "MeshService::open(": 12,
                    ".begin_sync(": 16,
                    "pub fn run_transfer(": 1,
                    "pub fn run_route_only_event(": 1,
                    "pub fn run_blob_recovery(": 1,
                    "pub fn run_shard(": 1,
                },
            },
        ),
        execute_rg_assertion(
            name="host_nongated_production_has_no_legacy_service_controls",
            argv=[
                "rg",
                "-n",
                "-e",
                r"\b(?:MeshService|ContactDriver|PeerBoundBackend|ConfiguredCarrier)\b",
                "-e",
                r"ServiceState::Active|\bbegin_sync\b|driver\.pump\(",
                "-e",
                r"\b(?:configure_peer_carrier|pause_sync|next_wakeup)\b",
                "-",
            ],
            freeze=freeze,
            source_paths=[host_lib_path],
            region=host_nongated_region,
            assertion={"kind": "absent", "count": 0},
        ),
        execute_rg_assertion(
            name="lab_nongated_production_has_no_legacy_service_controls",
            argv=[
                "rg",
                "-n",
                "-e",
                r"\b(?:MeshService|ServiceOptions|SyncProfile|begin_sync)\b",
                "-e",
                r"\b(?:run_transfer|run_route_only_event|run_blob_recovery|run_shard)\b",
                "-",
            ],
            freeze=freeze,
            source_paths=[lab_lib_path],
            region=lab_nongated_region,
            assertion={"kind": "absent", "count": 0},
        ),
        execute_rg_assertion(
            name="gate_h_binary_has_no_legacy_command_reachability",
            argv=[
                "rg",
                "-n",
                "-e",
                r"\b(?:MeshService|PeerBoundBackend|begin_sync|run_live_node|LiveCarrier|legacy_lab)\b",
                "-e",
                r'"(?:node-udp|node-rendezvous|node-discovery|node-relay|rendezvous|infra|transfer|route-only-event|blob-recovery|scale|shard-worker)"',
                "-",
            ],
            freeze=freeze,
            source_paths=[gate_h_main_path],
            region=gate_h_binary_region,
            assertion={"kind": "absent", "count": 0},
        ),
        execute_rg_assertion(
            name="gate_h_docker_build_is_no_default_and_candidate_aliased",
            argv=[
                "rg",
                "-n",
                "--fixed-strings",
                "-e",
                "ARG LAB_ASTER_FEATURES=aster-lab/default",
                "-e",
                "ARG LAB_ASTER_BINARY=aster-lab",
                "-e",
                '--bin "${LAB_ASTER_BINARY}"',
                "-e",
                "--no-default-features",
                "-e",
                '--features "${LAB_ASTER_FEATURES}"',
                "-e",
                'cp "/work/target/release/${LAB_ASTER_BINARY}"',
                "-e",
                "/work/target/release/candidate-aster-lab",
                "-e",
                "COPY --from=build /work/target/release/candidate-aster-lab /usr/local/bin/aster-lab",
                docker_path,
            ],
            freeze=freeze,
            source_paths=[docker_path],
            assertion={
                "kind": "token_counts",
                "match_count": 8,
                "counts": {
                    "ARG LAB_ASTER_FEATURES=aster-lab/default": 1,
                    "ARG LAB_ASTER_BINARY=aster-lab": 1,
                    '--bin "${LAB_ASTER_BINARY}"': 1,
                    "--no-default-features": 1,
                    '--features "${LAB_ASTER_FEATURES}"': 1,
                    'cp "/work/target/release/${LAB_ASTER_BINARY}"': 1,
                    "/work/target/release/candidate-aster-lab": 2,
                    "COPY --from=build /work/target/release/candidate-aster-lab /usr/local/bin/aster-lab": 1,
                },
            },
        ),
        execute_formal_graph_assertion(
            name="formal_graph_has_no_libp2p_or_iroh_dependency",
            freeze=freeze,
            source_paths=[
                root_manifest_path,
                lock_path,
                core_manifest_path,
                host_manifest_path,
                ip_manifest_path,
                lab_manifest_path,
            ],
            execution=execution,
        ),
    ]
    result = {check["name"]: check for check in checks}
    if set(result) != STATIC_CHECK_NAMES:
        raise GateHFaultError("static-check plan does not cover its exact mandatory set")
    return result


def static_check_contract(
    rg_executable: str = "rg", cargo_executable: str = "cargo"
) -> dict[str, dict[str, Any]]:
    """Return the immutable expected static plan without executing tools."""

    def record_contract(
        *,
        name: str,
        argv: list[str],
        freeze: dict[str, Any],
        source_paths: Sequence[str],
        assertion: dict[str, Any],
        region: SourceRegion | None = None,
    ) -> dict[str, Any]:
        del freeze
        argv = [rg_executable, *argv[1:]]
        return {
            "name": name,
            "argv": argv,
            "source_paths": list(source_paths),
            "region": (
                None
                if region is None
                else (region.start_marker, region.end_marker)
            ),
            "assertion": assertion,
        }

    def record_formal_graph_contract(
        *,
        name: str,
        freeze: dict[str, Any],
        source_paths: Sequence[str],
        execution: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del freeze, execution
        return {
            "name": name,
            "argv": [
                cargo_executable,
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
                FEATURE_GRAPH_FORMAT,
            ],
            "source_paths": list(source_paths),
            "region": None,
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
        }

    return execute_static_checks(
        {},
        execute_rg_assertion=record_contract,
        execute_formal_graph_assertion=record_formal_graph_contract,
    )


def build_one_test_executable(
    freeze: dict[str, Any],
    package: str,
    timeout_seconds: int,
    execution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if package not in TEST_TARGET_NAMES:  # pragma: no cover - fixed-plan invariant
        raise GateHFaultError(f"unknown Rust test package: {package}")
    argv = [
        "cargo" if execution is None else execution["tools"]["cargo"]["path"],
        "test",
        "--locked",
        "-p",
        package,
        "--lib",
        *TEST_PACKAGE_FEATURE_ARGS[package],
        "--no-run",
        "--message-format=json",
    ]
    environment = (
        {"CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0"}
        if execution is None
        else dict(execution["environment"])
    )
    process_environment = os.environ.copy() if execution is None else environment
    if execution is None:
        process_environment.update(environment)
    workspace = execution_workspace(execution)
    started_utc = utc_now()
    started = time.monotonic_ns()
    timed_out = False
    execution_error: str | None = None
    returncode = 127
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                argv,
                cwd=workspace,
                env=process_environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
            try:
                returncode = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                pending_interrupt = terminate_process_group(process)
                returncode = 124
                if pending_interrupt is not None:
                    raise pending_interrupt
            except BaseException:
                terminate_process_group(process)
                raise
        except OSError as error:
            execution_error = str(error)
        completed_utc = utc_now()
        duration_ms = max(0, (time.monotonic_ns() - started) // 1_000_000)
        stdout_sha256, stdout_evidence, stdout = capture_file(stdout_file)
        stderr_sha256, stderr_evidence, stderr = capture_file(stderr_file)

    executable_binding: dict[str, Any] | None = None
    parse_error: str | None = None
    build_finished = False
    if stdout is None or stderr is None:
        parse_error = "cargo build output exceeded the retained stream bound"
    elif returncode == 0 and not timed_out and execution_error is None:
        try:
            for raw_line in stdout.decode("utf-8").splitlines():
                message = json.loads(raw_line)
                if message.get("reason") == "build-finished":
                    build_finished = message.get("success") is True
                    continue
                if message.get("reason") != "compiler-artifact":
                    continue
                target = message.get("target")
                profile = message.get("profile")
                executable = message.get("executable")
                if (
                    not isinstance(target, dict)
                    or target.get("kind") != ["lib"]
                    or not isinstance(profile, dict)
                    or profile.get("test") is not True
                    or not isinstance(executable, str)
                ):
                    continue
                target_name = target.get("name")
                manifest_path = message.get("manifest_path")
                expected_manifest = str(
                    (workspace / TEST_PACKAGE_MANIFESTS[package]).resolve()
                )
                if (
                    target_name != TEST_TARGET_NAMES[package]
                    or manifest_path != expected_manifest
                ):
                    continue
                raw_path = Path(executable)
                if not raw_path.is_absolute():
                    raw_path = workspace / raw_path
                if raw_path.is_symlink():
                    raise GateHFaultError(
                        f"cargo emitted a symlink for the {package} test executable"
                    )
                path = raw_path.resolve(strict=True)
                if (
                    executable_binding is not None
                    or not path.is_file()
                    or not os.access(path, os.X_OK)
                ):
                    raise GateHFaultError(
                        f"cargo emitted an invalid or duplicate {package} test executable"
                    )
                executable_binding = {
                    "package": package,
                    "target_name": target_name,
                    "manifest_path": manifest_path,
                    "path": str(path),
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
        except (GateHFaultError, json.JSONDecodeError, OSError, UnicodeError) as error:
            parse_error = str(error)

    passed = (
        returncode == 0
        and not timed_out
        and execution_error is None
        and stdout_evidence["complete"] is True
        and stderr_evidence["complete"] is True
        and build_finished
        and parse_error is None
        and executable_binding is not None
    )
    return {
        "package": package,
        "argv": argv,
        "cwd": str(workspace),
        "environment": environment,
        "source_files_sha256": freeze["source_files_sha256"],
        "started_utc": started_utc,
        "completed_utc": completed_utc,
        "duration_ms": duration_ms,
        "timed_out": timed_out,
        "returncode": returncode,
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "stdout": stdout_evidence,
        "stderr": stderr_evidence,
        "execution_error": execution_error,
        "parse_error": parse_error,
        "build_finished": build_finished,
        "executable": executable_binding,
        "passed": passed,
    }


def build_test_executables(
    freeze: dict[str, Any],
    timeout_seconds: int,
    execution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    builds = {
        package: build_one_test_executable(
            freeze, package, timeout_seconds, execution
        )
        for package in TEST_TARGET_NAMES
    }
    executables = {
        package: build["executable"]
        for package, build in builds.items()
        if build.get("passed") is True and isinstance(build.get("executable"), dict)
    }
    return {
        "builds": builds,
        "executables": executables,
        "passed": set(executables) == set(TEST_TARGET_NAMES)
        and all(build.get("passed") is True for build in builds.values()),
    }


def test_executable_digest(binding: dict[str, Any]) -> str | None:
    path_value = binding.get("path")
    expected = binding.get("sha256")
    if not isinstance(path_value, str) or not isinstance(expected, str):
        return None
    path = Path(path_value)
    try:
        if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
            return None
        return sha256_file(path)
    except OSError:
        return None


def cargo_reported_test_executable(command: dict[str, Any]) -> str | None:
    stderr = command.get("stderr")
    if not isinstance(stderr, dict) or stderr.get("complete") is not True:
        return None
    encoded = stderr.get("base64")
    if not isinstance(encoded, str):
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeError):
        return None
    matches = re.findall(
        r"(?m)^\s*Running unittests .+ \(([^()\r\n]+)\)\s*$", decoded
    )
    if len(matches) != 1:
        return None
    path = Path(matches[0])
    if not path.is_absolute():
        cwd_value = command.get("cwd")
        if not isinstance(cwd_value, str) or not Path(cwd_value).is_absolute():
            return None
        path = Path(cwd_value) / path
    try:
        return str(path.resolve(strict=True))
    except OSError:
        return None


def exact_test_witness(
    spec: TestSpec, *, returncode: int, timed_out: bool, stdout: bytes, stderr: bytes
) -> tuple[bool, str | None]:
    if timed_out:
        return False, "command exceeded its deadline"
    if returncode != 0:
        return False, f"command returned {returncode}"
    combined = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
    running = re.findall(r"(?m)^running (\d+) test(?:s)?\s*$", combined)
    if running != ["1"]:
        return False, f"test harness did not report exactly one test: {running!r}"
    expected_test = re.compile(
        rf"(?m)^test {re.escape(spec.test_name)} \.\.\. ok\s*$"
    )
    if len(expected_test.findall(combined)) != 1:
        return False, "test harness did not report the exact named test as passing"
    summary = re.compile(
        r"(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored; "
        r"0 measured; \d+ filtered out; finished in .+\s*$"
    )
    if len(summary.findall(combined)) != 1:
        return False, "test harness did not report an exact one-test success summary"
    return True, None


def terminate_process_group(
    process: subprocess.Popen[Any],
) -> BaseException | None:
    """Terminate a child session and reap its leader despite further interrupts."""

    pending_interrupt: BaseException | None = None

    def remember(error: BaseException) -> None:
        nonlocal pending_interrupt
        if pending_interrupt is None:
            pending_interrupt = error

    def signal_group(value: int) -> None:
        try:
            os.killpg(process.pid, value)
        except ProcessLookupError:
            pass
        except BaseException as error:  # Cleanup must finish before propagation.
            remember(error)

    def group_is_alive() -> bool:
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False
        except BaseException as error:  # Treat uncertainty as still active.
            remember(error)
            return True

    signal_group(signal.SIGTERM)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        leader_reaped = process.poll() is not None
        if leader_reaped and not group_is_alive():
            return pending_interrupt
        if not leader_reaped:
            try:
                process.wait(timeout=min(0.1, max(0.01, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                pass
            except BaseException as error:
                remember(error)
        else:
            try:
                time.sleep(0.01)
            except BaseException as error:
                remember(error)

    signal_group(signal.SIGKILL)
    while process.poll() is None:
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            signal_group(signal.SIGKILL)
        except BaseException as error:
            remember(error)
            signal_group(signal.SIGKILL)
    return pending_interrupt


def execute_test(
    spec: TestSpec,
    timeout_seconds: int,
    execution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    argv = spec.argv(
        "cargo" if execution is None else execution["tools"]["cargo"]["path"]
    )
    environment = (
        {"CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0"}
        if execution is None
        else dict(execution["environment"])
    )
    process_environment = os.environ.copy() if execution is None else environment
    if execution is None:
        process_environment.update(environment)
    workspace = execution_workspace(execution)
    started_utc = utc_now()
    started = time.monotonic_ns()
    timed_out = False
    returncode = 127
    execution_error: str | None = None
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                argv,
                cwd=workspace,
                env=process_environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
            try:
                returncode = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                pending_interrupt = terminate_process_group(process)
                returncode = 124
                if pending_interrupt is not None:
                    raise pending_interrupt
            except BaseException:
                terminate_process_group(process)
                raise
        except OSError as error:
            execution_error = str(error)
        completed_utc = utc_now()
        duration_ms = max(0, (time.monotonic_ns() - started) // 1_000_000)
        stdout_sha256, stdout_evidence, stdout = capture_file(stdout_file)
        stderr_sha256, stderr_evidence, stderr = capture_file(stderr_file)
    if stdout is None or stderr is None:
        witnessed = False
        witness_error = "command output exceeded the retained stream bound"
    else:
        witnessed, witness_error = exact_test_witness(
            spec,
            returncode=returncode,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
        )
    return {
        "case": spec.case,
        "package": spec.package,
        "test_name": spec.test_name,
        "argv": argv,
        "cwd": str(workspace),
        "environment": environment,
        "started_utc": started_utc,
        "completed_utc": completed_utc,
        "duration_ms": duration_ms,
        "timed_out": timed_out,
        "returncode": returncode,
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "stdout": stdout_evidence,
        "stderr": stderr_evidence,
        "execution_error": execution_error,
        "exact_test_witnessed": witnessed,
        "witness_error": witness_error,
    }


def verify_candidate_unchanged(
    freeze: dict[str, Any], execution: dict[str, Any] | None = None
) -> None:
    if checked_git(["rev-parse", "HEAD"], execution) != freeze["candidate_commit"]:
        raise GateHFaultError("candidate HEAD changed while Gate-H faults ran")
    if checked_git(["rev-parse", "HEAD^{tree}"], execution) != freeze["candidate_tree"]:
        raise GateHFaultError("candidate tree changed while Gate-H faults ran")
    status = checked_git(
        ["status", "--porcelain=v1", "--untracked-files=all"], execution
    )
    if status:
        raise GateHFaultError("candidate worktree changed while Gate-H faults ran")
    if bind_source_files(execution) != freeze["source_files"]:
        raise GateHFaultError("bound Gate-H source files changed while faults ran")
    binary = Path(freeze["candidate_binary"])
    if not binary.is_file() or sha256_file(binary) != freeze["candidate_binary_sha256"]:
        raise GateHFaultError("candidate binary changed while Gate-H faults ran")


CommandExecutor = Callable[[TestSpec, int], dict[str, Any]]
StaticExecutor = Callable[[dict[str, Any]], dict[str, dict[str, Any]]]
TestExecutableBuilder = Callable[[dict[str, Any], int], dict[str, Any]]
ExecutableVerifier = Callable[[dict[str, Any]], str | None]
ExecutedBinaryParser = Callable[[dict[str, Any]], str | None]
ProvenanceCollector = Callable[[], dict[str, Any]]
SignedSourcePreparer = Callable[
    [dict[str, Any], dict[str, Any], int], dict[str, Any]
]


def verify_execution_provenance_unchanged(execution: dict[str, Any]) -> None:
    for name, binding in execution["tools"].items():
        path = Path(binding["path"])
        if (
            path.is_symlink()
            or not path.is_file()
            or not os.access(path, os.X_OK)
            or path.stat().st_size != binding["size_bytes"]
            or sha256_file(path) != binding["sha256"]
        ):
            raise GateHFaultError(f"bound {name} executable changed while faults ran")
    for value in execution["cargo_config"]["paths_checked"]:
        path = Path(value)
        if path.exists() or path.is_symlink():
            raise GateHFaultError("Cargo configuration appeared while faults ran")
    try:
        gate_h_signature.verify_signature_inputs_unchanged(
            execution["signature_trust"]
        )
        gate_h_signature.verify_signature_source_unchanged(
            execution["signature_trust"]
        )
    except gate_h_signature.SignatureTrustError as error:
        raise GateHFaultError(f"signature trust input changed: {error}") from error
    try:
        source_workspace = gate_h_source.validate_signed_tree_receipt(
            execution["signed_source"],
            workspace=WORKSPACE,
            trust=execution["signature_trust"],
            verify_archive_file=True,
            verify_export=True,
        )
    except (KeyError, gate_h_source.SignedSourceError) as error:
        raise GateHFaultError(f"signed source changed while faults ran: {error}") from error
    if source_workspace != execution_workspace(execution):
        raise GateHFaultError("signed-source execution root changed while faults ran")


def generate_receipt(
    candidate_binary: Path,
    *,
    timeout_seconds: int,
    executor: CommandExecutor | None = None,
    static_executor: StaticExecutor | None = None,
    test_executable_builder: TestExecutableBuilder | None = None,
    executable_verifier: ExecutableVerifier = test_executable_digest,
    executed_binary_parser: ExecutedBinaryParser = cargo_reported_test_executable,
    provenance_collector: ProvenanceCollector = collect_execution_provenance,
    signed_source_preparer: SignedSourcePreparer = prepare_signed_source_execution,
    prepared_state: tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None = None,
    export_execution: dict[str, Any] | None = None,
    progress: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if progress is None:
        progress = {}
    progress.update(
        {
            "schema": SCHEMA,
            "phase": "execution_provenance",
            "candidate_binary_requested": str(candidate_binary.absolute()),
            "timeout_seconds_per_command": timeout_seconds,
        }
    )
    if prepared_state is None:
        execution = provenance_collector()
        progress["execution_provenance"] = execution
        if (
            execution.get("passed") is not True
            or set(execution.get("environment", {})) != FORMAL_ENVIRONMENT_KEYS
        ):
            raise GateHFaultError("formal execution provenance is incomplete")
        progress["phase"] = "candidate_freeze"
        freeze = freeze_candidate(candidate_binary, execution)
        progress["candidate_freeze"] = freeze
        progress["phase"] = "signed_source_export"
        signed_source = signed_source_preparer(freeze, execution, timeout_seconds)
        progress["signed_source"] = signed_source
    else:
        execution, bootstrap_freeze, signed_source = prepared_state
        progress["execution_provenance"] = execution
        progress["signed_source"] = signed_source
        progress["phase"] = "trusted_candidate_freeze"
        freeze = freeze_candidate(candidate_binary, execution)
        immutable_keys = (
            "candidate_commit",
            "candidate_tree",
            "candidate_binary",
            "candidate_binary_sha256",
            "candidate_binary_size_bytes",
        )
        if any(freeze.get(key) != bootstrap_freeze.get(key) for key in immutable_keys):
            raise GateHFaultError("trusted candidate freeze differs from bootstrap")
        progress["candidate_freeze"] = freeze
        progress["phase"] = "trusted_signed_source_activation"
        activate_signed_source_execution(freeze, execution, signed_source)
    if (
        signed_source.get("passed") is not True
        or execution.get("signed_source") != signed_source
        or execution.get("formal_feature_graph", {}).get("passed") is not True
    ):
        raise GateHFaultError("formal signed-source execution context is incomplete")
    cargo_path = execution["tools"]["cargo"]["path"]
    plan = command_plan(cargo_path)
    progress["command_plan"] = plan
    progress["command_plan_sha256"] = canonical_sha256(plan)
    if executor is None:
        executor = lambda spec, timeout: execute_test(spec, timeout, execution)
    if static_executor is None:
        static_executor = lambda frozen: execute_static_checks(
            frozen, execution=execution
        )
    if test_executable_builder is None:
        test_executable_builder = lambda frozen, timeout: build_test_executables(
            frozen, timeout, execution
        )
    progress["phase"] = "static_checks"
    static_checks_error: str | None = None
    try:
        static_checks = static_executor(freeze)
    except GateHFaultError as error:
        static_checks = {}
        static_checks_error = str(error)
    progress["static_checks"] = static_checks
    progress["static_checks_error"] = static_checks_error
    progress["phase"] = "test_executable_build"
    test_executable_build = test_executable_builder(freeze, timeout_seconds)
    progress["test_executable_build"] = test_executable_build
    executable_bindings = test_executable_build.get("executables")
    if not isinstance(executable_bindings, dict):
        executable_bindings = {}
    test_builds = test_executable_build.get("builds")
    test_builds = test_builds if isinstance(test_builds, dict) else {}
    test_executable_build_plan = [
        {
            "package": package,
            "argv": build.get("argv"),
            "source_files_sha256": build.get("source_files_sha256"),
        }
        for package, build in sorted(test_builds.items())
        if isinstance(build, dict)
    ]
    commands: list[dict[str, Any]] = []
    progress["commands"] = commands
    progress["phase"] = "exact_test_commands"
    for spec in TEST_SPECS:
        binding = executable_bindings.get(spec.package)
        binding = binding if isinstance(binding, dict) else {}
        before = executable_verifier(binding)
        command = executor(spec, timeout_seconds)
        after = executable_verifier(binding)
        reported_executable = executed_binary_parser(command)
        expected_digest = binding.get("sha256")
        executable_unchanged = (
            isinstance(expected_digest, str)
            and HEX_64.fullmatch(expected_digest) is not None
            and before == expected_digest
            and after == expected_digest
            and reported_executable == binding.get("path")
        )
        command["test_executable"] = binding or None
        command["test_executable_sha256_before"] = before
        command["test_executable_sha256_after"] = after
        command["cargo_reported_test_executable"] = reported_executable
        command["test_executable_unchanged"] = executable_unchanged
        if not executable_unchanged:
            command["exact_test_witnessed"] = False
            command["witness_error"] = "bound Rust test executable is absent or changed"
        commands.append(command)
        progress["commands_completed"] = len(commands)
    cases = {
        case: all(
            command.get("case") == case
            and command.get("returncode") == 0
            and command.get("timed_out") is False
            and command.get("exact_test_witnessed") is True
            for command in commands
            if command.get("case") == case
        )
        and sum(command.get("case") == case for command in commands)
        == sum(spec.case == case for spec in TEST_SPECS)
        for case in sorted(MANDATORY_CASES)
    }
    static_checks_passed = (
        static_checks_error is None
        and set(static_checks) == STATIC_CHECK_NAMES
        and all(check.get("passed") is True for check in static_checks.values())
    )
    final_test_executable_digests = {
        package: executable_verifier(binding)
        for package, binding in executable_bindings.items()
        if isinstance(binding, dict)
    }
    test_executables_integrity_after_tests = (
        set(final_test_executable_digests) == set(TEST_TARGET_NAMES)
        and all(
            final_test_executable_digests.get(package) == binding.get("sha256")
            for package, binding in executable_bindings.items()
            if isinstance(binding, dict)
        )
    )
    test_executables_passed = (
        test_executable_build.get("passed") is True
        and set(test_builds) == set(TEST_TARGET_NAMES)
        and all(
            isinstance(build, dict) and build.get("passed") is True
            for build in test_builds.values()
        )
        and set(executable_bindings) == set(TEST_TARGET_NAMES)
        and all(command["test_executable_unchanged"] for command in commands)
        and test_executables_integrity_after_tests
    )
    static_plan = [
        {
            "name": name,
            "argv": check.get("argv"),
            "source_files": check.get("source_files"),
            "source_region": check.get("source_region"),
            "assertion": check.get("assertion"),
            "expected_returncode": check.get("expected_returncode"),
        }
        for name, check in sorted(static_checks.items())
    ]

    integrity_error: str | None = None
    progress["phase"] = "post_test_integrity"
    try:
        if export_execution is not None:
            finalize_export_execution(export_execution, signed_source)
        verify_candidate_unchanged(freeze, execution)
        verify_execution_provenance_unchanged(execution)
    except GateHFaultError as error:
        integrity_error = str(error)

    passed = (
        all(cases.values())
        and static_checks_passed
        and test_executables_passed
        and integrity_error is None
    )
    progress["phase"] = "complete"
    return {
        "schema": SCHEMA,
        "created_utc": utc_now(),
        "candidate_commit": freeze["candidate_commit"],
        "candidate_tree": freeze["candidate_tree"],
        "worktree_clean": freeze["worktree_clean"],
        "worktree_status": freeze["worktree_status"],
        "signature_status": freeze["signature_status"],
        "signature_signer": freeze["signature_signer"],
        "signature_fingerprint": freeze["signature_fingerprint"],
        "signature_trust": execution.get("signature_trust"),
        "signature_verification": freeze.get("signature_verification"),
        "requirements_sha256": freeze["requirements_sha256"],
        "proposal_0004_sha256": freeze["proposal_0004_sha256"],
        "source_files": freeze["source_files"],
        "source_files_sha256": freeze["source_files_sha256"],
        "candidate_binary": freeze["candidate_binary"],
        "candidate_binary_sha256": freeze["candidate_binary_sha256"],
        "candidate_binary_size_bytes": freeze["candidate_binary_size_bytes"],
        "execution_provenance": execution,
        "export_execution": export_execution,
        "signed_source": signed_source,
        "command_plan": plan,
        "command_plan_sha256": canonical_sha256(plan),
        "timeout_seconds_per_command": timeout_seconds,
        "cases": cases,
        "commands": commands,
        "static_checks": static_checks,
        "static_check_plan_sha256": canonical_sha256(static_plan),
        "static_checks_passed": static_checks_passed,
        "static_checks_error": static_checks_error,
        "test_executable_build": test_executable_build,
        "test_executable_build_plan_sha256": canonical_sha256(
            test_executable_build_plan
        ),
        "test_executables_passed": test_executables_passed,
        "test_executable_digests_after_tests": final_test_executable_digests,
        "test_executables_integrity_after_tests": test_executables_integrity_after_tests,
        "source_integrity_after_tests": integrity_error is None,
        "integrity_error": integrity_error,
        "passed": passed,
    }


def write_new_json(path: Path, value: dict[str, Any]) -> None:
    if path.is_symlink():
        raise GateHFaultError(f"refusing to replace receipt symlink: {path}")
    if not path.parent.is_dir():
        raise GateHFaultError(f"receipt parent directory does not exist: {path.parent}")
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        with path.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise GateHFaultError(f"refusing to replace existing receipt: {path}") from error


def _signed_source_file(
    signed_source: dict[str, Any], relative: str
) -> dict[str, Any]:
    matches = [
        value
        for value in signed_source.get("files", [])
        if isinstance(value, dict) and value.get("path") == relative
    ]
    if len(matches) != 1:
        raise GateHFaultError(f"signed source has no unique file identity: {relative}")
    return matches[0]


def _loaded_source_binding(
    raw_value: Any,
    *,
    relative: str,
    root: Path,
    signed_source: dict[str, Any],
    require_materialized_mode: bool,
    cached_value: Any,
) -> dict[str, Any]:
    if not isinstance(raw_value, str) or not raw_value:
        raise GateHFaultError(f"loaded module has no raw source path: {relative}")
    raw_path = Path(raw_value)
    expected_path = root / relative
    if not raw_path.is_absolute() or raw_path != expected_path:
        raise GateHFaultError(f"loaded module did not originate in the signed root: {relative}")
    try:
        metadata = raw_path.lstat()
        resolved = raw_path.resolve(strict=True)
    except OSError as error:
        raise GateHFaultError(f"loaded module source is unavailable: {relative}") from error
    if raw_path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or resolved != raw_path:
        raise GateHFaultError(f"loaded module source path is not exact: {relative}")
    signed = _signed_source_file(signed_source, relative)
    expected_executable = signed.get("mode") == "100755"
    actual_executable = bool(stat.S_IMODE(metadata.st_mode) & 0o111)
    expected_materialized_mode = 0o555 if expected_executable else 0o444
    if (
        signed.get("mode") not in ("100644", "100755")
        or actual_executable != expected_executable
        or (require_materialized_mode and stat.S_IMODE(metadata.st_mode) != expected_materialized_mode)
        or metadata.st_size != signed.get("size_bytes")
        or sha256_file(raw_path) != signed.get("sha256")
    ):
        raise GateHFaultError(f"loaded module bytes or mode differ from signed source: {relative}")
    cached_path: str | None = cached_value if isinstance(cached_value, str) else None
    if (
        require_materialized_mode
        and cached_path is not None
        and (Path(cached_path).exists() or Path(cached_path).is_symlink())
    ):
        raise GateHFaultError(f"loaded module has a stale bytecode file: {relative}")
    return {
        "raw_path": raw_value,
        "path": str(resolved),
        "relative_path": relative,
        "mode": signed["mode"],
        "filesystem_mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "size_bytes": metadata.st_size,
        "sha256": signed["sha256"],
        "cached_path": cached_path,
        "cached_path_absent": cached_path is None
        or (not Path(cached_path).exists() and not Path(cached_path).is_symlink()),
    }


def _loaded_module_bindings(
    signed_source: dict[str, Any],
    *,
    root: Path,
    require_materialized_mode: bool,
) -> dict[str, dict[str, Any]]:
    raw_modules = {
        "gate_h_faults": (__file__, globals().get("__cached__")),
        "gate_h_signature": (
            getattr(gate_h_signature, "__file__", None),
            getattr(gate_h_signature, "__cached__", None),
        ),
        "gate_h_source": (
            getattr(gate_h_source, "__file__", None),
            getattr(gate_h_source, "__cached__", None),
        ),
    }
    return {
        name: _loaded_source_binding(
            raw,
            relative=REEXEC_MODULE_PATHS[name],
            root=root,
            signed_source=signed_source,
            require_materialized_mode=require_materialized_mode,
            cached_value=cached,
        )
        for name, (raw, cached) in raw_modules.items()
    }


def _bytecode_paths(root: Path) -> list[str]:
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.name == "__pycache__" or path.suffix in (".pyc", ".pyo")
    )


def _python_binding() -> dict[str, Any]:
    invocation = Path(sys.executable)
    try:
        path = invocation.resolve(strict=True)
        metadata = path.stat()
    except OSError as error:
        raise GateHFaultError("formal Python executable is unavailable") from error
    if not path.is_absolute() or path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise GateHFaultError("formal Python executable is not an exact regular file")
    return {
        "invocation": str(invocation),
        "path": str(path),
        "size_bytes": metadata.st_size,
        "sha256": sha256_file(path),
    }


def _original_cli_argv(args: argparse.Namespace, *, output: Path) -> list[str]:
    return [
        "--candidate-binary",
        str(args.candidate_binary.absolute()),
        "--output",
        str(output),
        "--git-binary",
        str(args.git_binary),
        "--ssh-keygen-binary",
        str(args.ssh_keygen_binary),
        "--ssh-binary",
        str(args.ssh_binary),
        "--allowed-signers",
        str(args.allowed_signers),
        "--signer-principal",
        args.signer_principal,
        "--timeout-seconds",
        str(args.timeout_seconds),
    ]


def _reexec_environment(
    execution: dict[str, Any], *, controller: Path
) -> dict[str, str]:
    environment = dict(execution["environment"])
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            REPOSITORY_WORKSPACE_ENV: str(WORKSPACE),
            SIGNED_CONTROLLER_ENV: str(controller),
            "__CF_USER_TEXT_ENCODING": f"0x{os.getuid():X}:0x0:0x0",
        }
    )
    return environment


def bootstrap_signed_reexec(
    args: argparse.Namespace,
    output: Path,
    progress: dict[str, Any],
    *,
    execve: Callable[[str, list[str], dict[str, str]], Any] = os.execve,
) -> None:
    """Materialize the signed tree, then replace this mutable bootstrap process."""

    signature_request = gate_h_signature.SignatureRequest(
        git=args.git_binary,
        ssh_keygen=args.ssh_keygen_binary,
        ssh=args.ssh_binary,
        allowed_signers=args.allowed_signers,
        principal=args.signer_principal,
    )
    progress["phase"] = "bootstrap_execution_provenance"
    execution = collect_execution_provenance(signature_request)
    progress["execution_provenance"] = execution
    progress["phase"] = "bootstrap_candidate_freeze"
    freeze = freeze_candidate(args.candidate_binary, execution)
    progress["candidate_freeze"] = freeze
    progress["phase"] = "bootstrap_signed_source_export"
    signed_source = materialize_signed_source_execution(
        freeze, execution, args.timeout_seconds
    )
    progress["signed_source"] = signed_source
    try:
        export_root = gate_h_source.validate_signed_tree_receipt(
            signed_source,
            workspace=WORKSPACE,
            trust=execution["signature_trust"],
            verify_archive_file=True,
            verify_export=True,
        )
    except gate_h_source.SignedSourceError as error:
        raise GateHFaultError(f"formal signed-source export failed: {error}") from error
    # Catch assume-unchanged and stale-source execution before the mutable
    # bootstrap can launch any formal graph/build/test/static-check work.
    bootstrap_modules = _loaded_module_bindings(
        signed_source, root=WORKSPACE, require_materialized_mode=False
    )
    controller = export_root / REEXEC_MODULE_PATHS["gate_h_faults"]
    sentinel = os.urandom(32).hex()
    python = _python_binding()
    handoff_payload = {
        "schema": "aster-gate-h-fault-bootstrap/v1",
        "repository_workspace": str(WORKSPACE),
        "bootstrap_code_root": str(CODE_ROOT),
        "candidate_binary_requested": str(args.candidate_binary.absolute()),
        "output": str(output),
        "timeout_seconds": args.timeout_seconds,
        "sentinel_sha256": sha256_bytes(sentinel.encode("ascii")),
        "execution_provenance": execution,
        "candidate_freeze": freeze,
        "signed_source": signed_source,
        "bootstrap_modules": bootstrap_modules,
        "python": python,
    }
    handoff = {
        **handoff_payload,
        "payload_sha256": canonical_sha256(handoff_payload),
    }
    target = Path(execution["target_directory"]["path"])
    handoff_path = target / "gate-h-fault-bootstrap.json"
    write_new_json(handoff_path, handoff)
    handoff_sha256 = sha256_file(handoff_path)
    argv = [
        python["path"],
        *REEXEC_FLAGS,
        str(controller),
        *_original_cli_argv(args, output=output),
        "--signed-reexec-handoff",
        str(handoff_path),
        "--signed-reexec-handoff-sha256",
        handoff_sha256,
        "--signed-reexec-sentinel",
        sentinel,
    ]
    environment = _reexec_environment(execution, controller=controller)
    progress["phase"] = "signed_export_reexec"
    progress["reexec"] = {
        "python": python,
        "argv": argv,
        "environment": environment,
        "handoff_sha256": handoff_sha256,
    }
    try:
        execve(python["path"], argv, environment)
    except OSError as error:
        raise GateHFaultError(f"unable to execute signed Gate-H runner: {error}") from error
    raise GateHFaultError("signed Gate-H runner unexpectedly returned from exec")


def _read_bootstrap_handoff(
    path: Path, expected_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(expected_sha256, str) or HEX_64.fullmatch(expected_sha256) is None:
        raise GateHFaultError("signed re-exec handoff digest is malformed")
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size < 2
            or metadata.st_size > 64 * 1024 * 1024
            or sha256_file(path) != expected_sha256
        ):
            raise GateHFaultError("signed re-exec handoff file identity differs")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateHFaultError("signed re-exec handoff is unreadable") from error
    keys = {
        "schema",
        "repository_workspace",
        "bootstrap_code_root",
        "candidate_binary_requested",
        "output",
        "timeout_seconds",
        "sentinel_sha256",
        "execution_provenance",
        "candidate_freeze",
        "signed_source",
        "bootstrap_modules",
        "python",
        "payload_sha256",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise GateHFaultError("signed re-exec handoff keys differ")
    payload = dict(value)
    payload_sha256 = payload.pop("payload_sha256")
    if (
        value["schema"] != "aster-gate-h-fault-bootstrap/v1"
        or not isinstance(payload_sha256, str)
        or payload_sha256 != canonical_sha256(payload)
    ):
        raise GateHFaultError("signed re-exec handoff payload differs")
    binding = {
        "path": str(path),
        "size_bytes": metadata.st_size,
        "sha256": expected_sha256,
        "payload_sha256": payload_sha256,
    }
    return value, binding


def _validate_export_sys_path(export_root: Path) -> list[str]:
    values = list(sys.path)
    expected_first = str(export_root / "lab")
    if not values or values[0] != expected_first or any(not value for value in values):
        raise GateHFaultError("signed runner sys.path does not start at its export lab")
    for value in values[1:]:
        path = Path(value)
        try:
            path.relative_to(WORKSPACE)
        except ValueError:
            continue
        raise GateHFaultError("signed runner sys.path contains mutable repository code")
    return values


def validate_signed_reexec(
    args: argparse.Namespace,
    output: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validate the bootstrap and prove this interpreter loaded signed sources."""

    if (
        args.signed_reexec_handoff is None
        or args.signed_reexec_handoff_sha256 is None
        or args.signed_reexec_sentinel is None
    ):
        raise GateHFaultError("signed re-exec arguments are incomplete")
    handoff_path = args.signed_reexec_handoff
    if not handoff_path.is_absolute():
        raise GateHFaultError("signed re-exec handoff path is not absolute")
    handoff, handoff_binding = _read_bootstrap_handoff(
        handoff_path, args.signed_reexec_handoff_sha256
    )
    if (
        handoff["repository_workspace"] != str(WORKSPACE)
        or handoff["candidate_binary_requested"]
        != str(args.candidate_binary.absolute())
        or handoff["output"] != str(output)
        or handoff["timeout_seconds"] != args.timeout_seconds
        or handoff["sentinel_sha256"]
        != sha256_bytes(args.signed_reexec_sentinel.encode("utf-8"))
    ):
        raise GateHFaultError("signed re-exec handoff does not match this invocation")
    execution = handoff["execution_provenance"]
    signed_source = handoff["signed_source"]
    bootstrap_freeze = handoff["candidate_freeze"]
    if (
        not isinstance(execution, dict)
        or execution.get("passed") is not True
        or set(execution.get("environment", {})) != FORMAL_ENVIRONMENT_KEYS
        or not isinstance(signed_source, dict)
        or execution.get("signed_source") != signed_source
        or not isinstance(bootstrap_freeze, dict)
    ):
        raise GateHFaultError("signed re-exec bootstrap evidence is incomplete")
    target = (WORKSPACE / "target/gate-h-faults-v2").resolve()
    if (
        execution.get("target_directory", {}).get("path") != str(target)
        or execution["environment"].get("CARGO_TARGET_DIR") != str(target)
        or handoff_path != target / "gate-h-fault-bootstrap.json"
    ):
        raise GateHFaultError("signed re-exec target directory differs")
    signature_request = gate_h_signature.SignatureRequest(
        git=args.git_binary,
        ssh_keygen=args.ssh_keygen_binary,
        ssh=args.ssh_binary,
        allowed_signers=args.allowed_signers,
        principal=args.signer_principal,
    )
    try:
        signature_anchor = gate_h_signature.validate_signature_request_matches_trust(
            signature_request,
            execution["signature_trust"],
            workspace=WORKSPACE,
            base_environment=execution["environment"],
            run_command=run_isolated_process,
        )
        export_root = gate_h_source.validate_signed_tree_receipt(
            signed_source,
            workspace=WORKSPACE,
            trust=execution["signature_trust"],
            verify_archive_file=True,
            verify_export=True,
        )
    except (
        gate_h_signature.SignatureTrustError,
        gate_h_source.SignedSourceError,
    ) as error:
        raise GateHFaultError(f"signed re-exec trust validation failed: {error}") from error
    if (
        CODE_ROOT != export_root
        or Path(handoff["bootstrap_code_root"]) != WORKSPACE
        or signed_source.get("commit") != bootstrap_freeze.get("candidate_commit")
        or signed_source.get("tree") != bootstrap_freeze.get("candidate_tree")
    ):
        raise GateHFaultError("signed re-exec code root or candidate identity differs")
    controller = export_root / REEXEC_MODULE_PATHS["gate_h_faults"]
    environment = _reexec_environment(execution, controller=controller)
    if dict(os.environ) != environment:
        raise GateHFaultError("signed runner process environment differs")
    python = _python_binding()
    historical_python = handoff["python"]
    if (
        not isinstance(historical_python, dict)
        or {key: historical_python.get(key) for key in ("path", "size_bytes", "sha256")}
        != {key: python.get(key) for key in ("path", "size_bytes", "sha256")}
    ):
        raise GateHFaultError("signed runner Python executable identity differs")
    expected_argv = [
        python["path"],
        *REEXEC_FLAGS,
        str(controller),
        *_original_cli_argv(args, output=output),
        "--signed-reexec-handoff",
        str(handoff_path),
        "--signed-reexec-handoff-sha256",
        args.signed_reexec_handoff_sha256,
        "--signed-reexec-sentinel",
        args.signed_reexec_sentinel,
    ]
    if list(getattr(sys, "orig_argv", [])) != expected_argv:
        raise GateHFaultError("signed runner Python argv differs")
    flags = {
        "dont_write_bytecode": sys.flags.dont_write_bytecode,
        "ignore_environment": sys.flags.ignore_environment,
        "no_site": sys.flags.no_site,
        "no_user_site": sys.flags.no_user_site,
    }
    if flags != {
        "dont_write_bytecode": 1,
        "ignore_environment": 1,
        "no_site": 1,
        "no_user_site": 1,
    }:
        raise GateHFaultError("signed runner Python isolation flags differ")
    pyc_before = _bytecode_paths(export_root)
    if pyc_before:
        raise GateHFaultError("signed runner export contains bytecode")
    modules = _loaded_module_bindings(
        signed_source, root=export_root, require_materialized_mode=True
    )
    sys_path = _validate_export_sys_path(export_root)
    export_execution = {
        "schema": EXPORT_EXECUTION_SCHEMA,
        "sentinel_sha256": handoff["sentinel_sha256"],
        "repository_workspace": str(WORKSPACE),
        "code_root": str(export_root),
        "python": python,
        "argv": expected_argv,
        "environment": environment,
        "handoff": handoff_binding,
        "runner": modules["gate_h_faults"],
        "modules": modules,
        "bootstrap_modules": handoff["bootstrap_modules"],
        "signature_anchor": signature_anchor,
        "sys_path": sys_path,
        "bytecode": {
            "flags": flags,
            "pycache_or_pyc_before": pyc_before,
            "pycache_or_pyc_after": None,
        },
        "modules_after": None,
        "passed": False,
    }
    execution["export_execution"] = export_execution
    return execution, bootstrap_freeze, signed_source, export_execution


def finalize_export_execution(
    export_execution: dict[str, Any], signed_source: dict[str, Any]
) -> None:
    export_root = Path(export_execution["code_root"])
    modules_after = _loaded_module_bindings(
        signed_source, root=export_root, require_materialized_mode=True
    )
    pyc_after = _bytecode_paths(export_root)
    handoff_path = Path(export_execution["handoff"]["path"])
    if (
        modules_after != export_execution["modules"]
        or pyc_after
        or _validate_export_sys_path(export_root) != export_execution["sys_path"]
        or _python_binding() != export_execution["python"]
        or dict(os.environ) != export_execution["environment"]
        or not handoff_path.is_file()
        or handoff_path.is_symlink()
        or handoff_path.stat().st_size != export_execution["handoff"]["size_bytes"]
        or sha256_file(handoff_path) != export_execution["handoff"]["sha256"]
    ):
        raise GateHFaultError("signed runner origin changed while faults ran")
    export_execution["modules_after"] = modules_after
    export_execution["bytecode"]["pycache_or_pyc_after"] = pyc_after
    export_execution["passed"] = True


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--candidate-binary", type=Path, required=True)
    value.add_argument("--output", type=Path, required=True)
    value.add_argument("--git-binary", type=Path, required=True)
    value.add_argument("--ssh-keygen-binary", type=Path, required=True)
    value.add_argument("--ssh-binary", type=Path, required=True)
    value.add_argument("--allowed-signers", type=Path, required=True)
    value.add_argument("--signer-principal", required=True)
    value.add_argument("--signed-reexec-handoff", type=Path, help=argparse.SUPPRESS)
    value.add_argument("--signed-reexec-handoff-sha256", help=argparse.SUPPRESS)
    value.add_argument("--signed-reexec-sentinel", help=argparse.SUPPRESS)
    value.add_argument(
        "--timeout-seconds",
        type=int,
        default=600,
        help="per-test deadline in seconds (default: 600)",
    )
    return value


def interruption_receipt(
    candidate_binary: Path,
    *,
    timeout_seconds: int,
    interruption: BaseException,
    partial_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a retained fail-closed record when the formal run is interrupted."""

    partial = {} if partial_evidence is None else partial_evidence
    candidate_path = candidate_binary.absolute()
    candidate_binding: dict[str, Any] | None = None
    try:
        if (
            not candidate_path.is_symlink()
            and candidate_path.is_file()
            and os.access(candidate_path, os.X_OK)
        ):
            candidate_binding = {
                "path": str(candidate_path),
                "sha256": sha256_file(candidate_path),
                "size_bytes": candidate_path.stat().st_size,
            }
    except OSError:
        candidate_binding = None
    completed_commands = partial.get("commands")
    if not isinstance(completed_commands, list):
        completed_commands = []
    repeated_signals = sorted(
        signal.Signals(value).name
        for value in set(signal.sigpending()) & {signal.SIGINT, signal.SIGTERM}
    )
    payload = {
        "schema": SCHEMA,
        "receipt_kind": "interrupted",
        "created_utc": utc_now(),
        "candidate_binary_requested": str(candidate_path),
        "candidate_binary_observed": candidate_binding,
        "requirements_sha256": REQUIREMENTS_SHA256,
        "timeout_seconds_per_command": timeout_seconds,
        "interrupted": True,
        "interruption": {
            "type": type(interruption).__name__,
            "message": str(interruption),
            "signum": getattr(interruption, "signum", None),
            "signal": (
                signal.Signals(interruption.signum).name
                if isinstance(interruption, GateHSignalInterruption)
                else None
            ),
            "repeated_signals": repeated_signals,
        },
        "partial_evidence": partial,
        "partial_evidence_sha256": canonical_sha256(partial),
        "cases": {case: False for case in sorted(MANDATORY_CASES)},
        "commands": completed_commands,
        "static_checks_passed": False,
        "test_executables_passed": False,
        "source_integrity_after_tests": False,
        "integrity_error": "Gate-H deterministic fault execution was interrupted",
        "passed": False,
    }
    return {**payload, "receipt_payload_sha256": canonical_sha256(payload)}


def retain_interruption_receipt(
    output: Path,
    candidate_binary: Path,
    *,
    timeout_seconds: int,
    interruption: BaseException,
    partial_evidence: dict[str, Any] | None = None,
) -> BaseException | None:
    write_error: BaseException | None = None
    previous_mask: set[signal.Signals] | None = None
    try:
        previous_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM}
        )
        receipt = interruption_receipt(
            candidate_binary,
            timeout_seconds=timeout_seconds,
            interruption=interruption,
            partial_evidence=partial_evidence,
        )
        write_new_json(output, receipt)
    except BaseException as error:
        write_error = error
    finally:
        if previous_mask is not None and not isinstance(
            interruption, GateHSignalInterruption
        ):
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            except BaseException as error:
                write_error = write_error or error
    if write_error is not None:
        print(
            f"gate-h-faults: unable to retain interruption receipt: {write_error}",
            file=sys.stderr,
        )
    return write_error


def run_main_execution(args: argparse.Namespace, output: Path) -> int:
    progress: dict[str, Any] = {}
    try:
        if args.signed_reexec_handoff is None:
            bootstrap_signed_reexec(args, output, progress)
            raise GateHFaultError("signed runner re-exec unexpectedly returned")
        execution, bootstrap_freeze, signed_source, export_execution = (
            validate_signed_reexec(args, output)
        )
        progress["export_execution"] = export_execution
        receipt = generate_receipt(
            args.candidate_binary,
            timeout_seconds=args.timeout_seconds,
            progress=progress,
            prepared_state=(execution, bootstrap_freeze, signed_source),
            export_execution=export_execution,
        )
    except GateHFaultError as error:
        print(f"gate-h-faults: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt as interruption:
        interrupted_processes = getattr(
            interruption, "gate_h_interrupted_processes", None
        )
        if isinstance(interrupted_processes, list):
            progress["interrupted_processes"] = interrupted_processes
        retain_interruption_receipt(
            output,
            args.candidate_binary,
            timeout_seconds=args.timeout_seconds,
            interruption=interruption,
            partial_evidence=progress,
        )
        print(
            f"gate-h-faults: interrupted by {type(interruption).__name__}",
            file=sys.stderr,
        )
        if isinstance(interruption, GateHSignalInterruption):
            return 128 + interruption.signum
        return 130
    try:
        write_new_json(output, receipt)
    except GateHFaultError as error:
        print(f"gate-h-faults: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt as interruption:
        # An exclusive output may already contain a partial write. Never replace it.
        if not output.exists() and not output.is_symlink():
            retain_interruption_receipt(
                output,
                args.candidate_binary,
                timeout_seconds=args.timeout_seconds,
                interruption=interruption,
                partial_evidence={
                    "schema": SCHEMA,
                    "phase": "receipt_write",
                    "candidate_binary_requested": str(args.candidate_binary.absolute()),
                    "timeout_seconds_per_command": args.timeout_seconds,
                },
            )
        print(
            f"gate-h-faults: interrupted while retaining receipt by "
            f"{type(interruption).__name__}",
            file=sys.stderr,
        )
        if isinstance(interruption, GateHSignalInterruption):
            return 128 + interruption.signum
        return 130
    print(
        json.dumps(
            {
                "output": str(output),
                "candidate_commit": receipt["candidate_commit"],
                "candidate_binary_sha256": receipt["candidate_binary_sha256"],
                "cases": receipt["cases"],
                "passed": receipt["passed"],
            },
            sort_keys=True,
        )
    )
    return 0 if receipt["passed"] else 1


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    reexec_values = (
        args.signed_reexec_handoff,
        args.signed_reexec_handoff_sha256,
        args.signed_reexec_sentinel,
    )
    if any(value is not None for value in reexec_values) != all(
        value is not None for value in reexec_values
    ):
        print("gate-h-faults: signed re-exec arguments are incomplete", file=sys.stderr)
        return 2
    trusted_reexec = all(value is not None for value in reexec_values)
    if not trusted_reexec and (
        SIGNED_CONTROLLER_ENV in os.environ or REPOSITORY_WORKSPACE_ENV in os.environ
    ):
        print("gate-h-faults: refusing ambient signed-runner environment", file=sys.stderr)
        return 2
    if trusted_reexec and (
        not isinstance(args.signed_reexec_sentinel, str)
        or HEX_64.fullmatch(args.signed_reexec_sentinel) is None
        or os.environ.get(SIGNED_CONTROLLER_ENV)
        != str(CODE_ROOT / REEXEC_MODULE_PATHS["gate_h_faults"])
    ):
        print("gate-h-faults: signed re-exec sentinel or controller differs", file=sys.stderr)
        return 2
    if args.timeout_seconds < 1 or args.timeout_seconds > MAX_TIMEOUT_SECONDS:
        print(
            f"gate-h-faults: --timeout-seconds must be in 1..{MAX_TIMEOUT_SECONDS}",
            file=sys.stderr,
        )
        return 2
    signature_paths = (
        args.git_binary,
        args.ssh_keygen_binary,
        args.ssh_binary,
        args.allowed_signers,
    )
    if any(not path.is_absolute() for path in signature_paths):
        print("gate-h-faults: signature trust paths must be absolute", file=sys.stderr)
        return 2
    if not gate_h_signature.SAFE_PRINCIPAL.fullmatch(args.signer_principal):
        print("gate-h-faults: --signer-principal is empty or unsafe", file=sys.stderr)
        return 2
    output = args.output.resolve()
    if output.exists() or output.is_symlink():
        print(f"gate-h-faults: refusing to replace existing receipt: {output}", file=sys.stderr)
        return 2
    controlled_signals = {signal.SIGINT, signal.SIGTERM}
    signal_state: dict[str, GateHSignalInterruption] = {}

    def interrupt_handler(signum: int, _frame: Any) -> None:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, controlled_signals)
        interruption = GateHSignalInterruption(signum, previous_mask)
        signal_state["interruption"] = interruption
        raise interruption

    previous_sigint = signal.signal(signal.SIGINT, interrupt_handler)
    previous_sigterm = signal.signal(signal.SIGTERM, interrupt_handler)
    try:
        return run_main_execution(args, output)
    finally:
        interruption = signal_state.get("interruption")
        if interruption is None:
            signal.signal(signal.SIGINT, previous_sigint)
            signal.signal(signal.SIGTERM, previous_sigterm)
        else:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            while True:
                pending = set(signal.sigpending()) & controlled_signals
                if not pending:
                    break
                for signum in sorted(pending):
                    signal.sigwait({signum})
            signal.pthread_sigmask(
                signal.SIG_SETMASK, interruption.previous_signal_mask
            )
            signal.signal(signal.SIGINT, previous_sigint)
            signal.signal(signal.SIGTERM, previous_sigterm)


if __name__ == "__main__":
    raise SystemExit(main())
