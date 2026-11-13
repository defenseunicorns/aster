#!/usr/bin/env python3
"""Fail-closed runner for Aster's IP-mesh provider experiments.

The runner is dry-run by default.  ``--execute`` creates only resources whose
names contain this run's random identifier, records every command and topology
receipt, and removes those exact resources after each phase.  Candidate nodes
run on Docker ``--internal`` networks.  An inert supervisor installs a local
default route so broadcast candidate discovery and ordinary IP stacks behave
consistently, while the Aster process itself executes with an empty Linux
capability bounding set.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import shutil
import signal
import stat
import sqlite3
import subprocess
import sys
import time
from typing import Any, Literal, Sequence

try:
    import gate_h_faults as gate_h_fault_contract
    import gate_h_signature
    import gate_h_source
except ModuleNotFoundError:  # Imported as ``lab.ip_mesh_experiment`` in tests.
    from lab import gate_h_faults as gate_h_fault_contract
    from lab import gate_h_signature
    from lab import gate_h_source


CODE_ROOT = Path(__file__).resolve().parents[1]
_REPOSITORY_WORKSPACE_VALUE = os.environ.get(
    "ASTER_GATE_H_REPOSITORY_WORKSPACE"
)
WORKSPACE = (
    Path(_REPOSITORY_WORKSPACE_VALUE).resolve()
    if os.environ.get("ASTER_GATE_H_SIGNED_CONTROLLER") not in (None, "", "0")
    and isinstance(_REPOSITORY_WORKSPACE_VALUE, str)
    and Path(_REPOSITORY_WORKSPACE_VALUE).is_absolute()
    else CODE_ROOT
)
DEFAULT_IMAGE = "aster-lab:validation"
SCHEMA = "aster-ip-mesh-phase-a/v1"
EVIDENCE_INDEX_SCHEMA = "aster-ip-mesh-evidence-index/v1"
GATE_H_FAULT_SCHEMA = gate_h_fault_contract.SCHEMA
GATE_H_FAULT_MAX_TIMEOUT_SECONDS = 1_800
GATE_H_BINARY_PROVENANCE_SCHEMA = "aster-gate-h-binary-provenance/v1"
GATE_H_CLEANUP_SCHEMA = "aster-gate-h-cleanup/v1"
GATE_H_RESOURCE_CLEANUP_SCHEMA = "aster-gate-h-resource-cleanup/v1"
GATE_H_SIGNATURE_FINAL_SCHEMA = "aster-gate-h-signature-final/v1"
GATE_H_HOST_EXECUTION_SCHEMA = "aster-gate-h-host-execution/v1"
GATE_H_HOST_EXECUTION_FINAL_SCHEMA = "aster-gate-h-host-execution-final/v1"
GATE_H_EXPORT_EXECUTION_SCHEMA = "aster-gate-h-export-execution/v1"
GATE_H_EXPORT_HANDOFF_SCHEMA = "aster-gate-h-export-handoff/v1"
GATE_H_DOCKER_BUILDX_PLUGIN_RELATIVE_PATH = "cli-plugins/docker-buildx"
GATE_H_DOCKER_BUILDX_STATE_RELATIVE_PATH = "buildx"
GATE_H_DOCKER_BUILDX_STATE_MAX_ENTRIES = 11
GATE_H_DOCKER_BUILDX_STATE_MAX_FILE_BYTES = 4_096
GATE_H_DOCKER_BUILDX_STATE_MAX_TOTAL_BYTES = 16_384
GATE_H_DOCKER_BUILDX_REF = re.compile(r"[a-z0-9]{25}")
SURVEY_BASELINE = "56ea19d89e537a351ceded446c2d38f5313d118b"
PROPOSAL_0004_BASELINE = "26c24a65c125406ed59493e5fc82a31bebb16d02"
REQUIREMENTS_SHA256 = "e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987"
ARMS = ("native", "iroh", "libp2p")
IROH_PRE_INCOMING_BLOCKER = (
    "iroh-1.0.3-noq-pre-incoming-defaults-max-65536-total-buffer-100-mib"
)
NATIVE_SHARED_NODE_SCHEMA = "aster-lab-native-mesh-node/v2"
LIBP2P_SHARED_NODE_SCHEMA = "aster-lab-libp2p-mesh-node/v3"
GATE_H_NODE_BUFFER_BYTES = 8 * 1024 * 1024
GATE_H_IMAGE_BINARY_PATH = "/usr/local/bin/aster-lab"
NODE_RESOURCE_FIELDS = (
    "candidates",
    "pending_connections",
    "pre_authentication_contacts",
    "admitted_contacts",
    "streams",
    "tasks",
    "frames",
    "inbound_bytes",
    "outbound_bytes",
    "descriptors",
    "relay_reservations",
)
NATIVE_SHARED_NODE_CONSTRUCTION_FIELDS = (
    "sqlite_node_open_count",
    "blob_authority_open_count",
    "semantic_backend_construction_count",
    "process_authority_construction_count",
)
NATIVE_PROTOCOL_COUNTER_FIELDS = (
    "aster_frames_received",
    "aster_frames_sent",
    "aster_bytes_received",
    "aster_bytes_sent",
    "carrier_control_frames_received",
    "carrier_control_frames_sent",
    "carrier_control_bytes_received",
    "carrier_control_bytes_sent",
    "authorization_generation_checks",
    "authorization_generation_mismatches",
    "authorization_generation_unavailable",
)
NODE_COMMAND = {
    "native": "mesh-native-node",
    "iroh": "mesh-iroh-node",
    "libp2p": "mesh-libp2p-node",
}
RESOURCE = re.compile(r"^aster-mesh-[a-z0-9-]{1,52}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_32 = re.compile(r"^[0-9a-f]{32}$")
IROH_ENDPOINT_ID = re.compile(r"^[0-9a-z]{32,128}$")
GATE_H_FAULT_CASES = gate_h_fault_contract.EXPECTED_CASES
GATE_H_NATIVE_RESOURCE_LIMITS = {
    "candidates": 8,
    "pending_connections": 2,
    "pre_authentication_contacts": 2,
    "admitted_contacts": 2,
    "streams": 2,
    "tasks": 3,
    "frames": 8_192,
    "inbound_bytes": GATE_H_NODE_BUFFER_BYTES,
    "outbound_bytes": GATE_H_NODE_BUFFER_BYTES,
    "descriptors": 1,
    "relay_reservations": 0,
}
GATE_H_NATIVE_PROVIDER_BASE = {
    "tasks": 1,
    "frames": 5_632,
    "inbound_bytes": 65_507,
    "descriptors": 1,
}
GATE_H_NATIVE_ADMITTED_CONTACT = {
    "admitted_contacts": 1,
    "streams": 1,
    "tasks": 1,
    "frames": 593,
    "inbound_bytes": 2 * 1_024 * 1_024,
    "outbound_bytes": 1_024 * 1_024,
}
GATE_H_CLEAN_ZERO_COUNTERS = (
    "contact_failures",
    "duplicate_contacts",
    "candidates_rejected_capacity",
    "node_resource_rejected_claims",
)
GATE_H_CONTROL_PATH = "/lab/node/gate-h-authorization-control.bin"
GATE_H_FLASH_ONLY_EMISSION_MODE = "flash-only"
GATE_H_LIVE_FIELDS = (
    "gate_h_control_id",
    "gate_h_generation_before",
    "gate_h_generation_after",
    "gate_h_stale_target_peer",
    "gate_h_stale_target_contact",
    "gate_h_stale_queued_frames",
    "gate_h_stale_send_frames_before",
    "gate_h_stale_send_frames_after",
    "gate_h_stale_send_bytes_before",
    "gate_h_stale_send_bytes_after",
    "gate_h_stale_zero_bytes_emitted",
    "gate_h_stale_contacts_retired",
    "gate_h_provider_epoch_rotations",
    "gate_h_fresh_target_contact",
    "gate_h_fresh_target_generation",
    "gate_h_fresh_aster_frames_sent",
    "gate_h_fresh_aster_bytes_sent",
    "gate_h_completed",
)
GATE_H_HOST_ENVIRONMENT_KEYS = frozenset(
    {
        "BUILDKIT_PROGRESS",
        "ASTER_GATE_H_HERMETIC",
        "ASTER_GATE_H_REPOSITORY_WORKSPACE",
        "ASTER_GATE_H_SIGNED_CONTROLLER",
        "DOCKER_BUILDKIT",
        "DOCKER_CLI_HINTS",
        "DOCKER_CONFIG",
        "DOCKER_HOST",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONCOERCECLOCALE",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONHASHSEED",
        "PYTHONNOUSERSITE",
        "PYTHONSAFEPATH",
        "PYTHONUTF8",
        "TMPDIR",
        "__CF_USER_TEXT_ENCODING",
    }
)
GATE_H_HOST_PATH = "/usr/bin:/bin"
GATE_H_EXPORT_MODULES = {
    "gate_h_faults": "lab/gate_h_faults.py",
    "gate_h_signature": "lab/gate_h_signature.py",
    "gate_h_source": "lab/gate_h_source.py",
}
GATE_H_CONTROLLER_RELATIVE_PATH = "lab/ip_mesh_experiment.py"
GATE_H_PYTHON_FLAGS = ("-B", "-E", "-s", "-S")


class ExperimentError(RuntimeError):
    """A controlled experiment failure with retained evidence."""


class ControlledInterruption(BaseException):
    """A host termination signal converted into bounded evidence finalization."""

    def __init__(self, signum: int) -> None:
        super().__init__(f"received signal {signum}")
        self.signum = signum


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def gate_h_export_root(root: Path) -> Path:
    return (root.resolve() / "gate-h-signed-source").resolve()


def gate_h_export_controller(root: Path) -> Path:
    return gate_h_export_root(root) / GATE_H_CONTROLLER_RELATIVE_PATH


def _gate_h_bytecode_paths(export_root: Path) -> list[str]:
    """Enumerate bytecode artifacts without ever importing one of them."""

    values: list[str] = []
    for path in export_root.rglob("*"):
        relative = path.relative_to(export_root).as_posix()
        if path.name == "__pycache__" or (
            path.is_file() and path.suffix in (".pyc", ".pyo")
        ):
            values.append(relative)
    return sorted(values, key=lambda value: value.encode("utf-8"))


def _path_is_equal_to_or_beneath(path: Path, root: Path) -> bool:
    resolved_path = path.resolve()
    resolved_root = root.resolve()
    return resolved_path == resolved_root or resolved_root in resolved_path.parents


def _gate_h_export_file_binding(
    *,
    raw_file: str,
    relative_path: str,
    export_root: Path,
    signed_source: dict[str, Any],
    cached_path: str | None,
    require_materialized_mode: bool = True,
) -> dict[str, Any]:
    """Bind one loaded Python source file to the signed Git-tree inventory."""

    path = Path(raw_file)
    try:
        resolved = path.resolve(strict=True)
        expected = (export_root / relative_path).resolve(strict=True)
        source_files = signed_source["files"]
        source_binding = next(
            binding
            for binding in source_files
            if isinstance(binding, dict) and binding.get("path") == relative_path
        )
        file_stat = path.lstat()
    except (KeyError, OSError, StopIteration, TypeError) as error:
        raise ExperimentError(
            f"Gate-H exported Python source is unavailable: {relative_path}"
        ) from error
    if (
        resolved != expected
        or not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_size != source_binding.get("size_bytes")
        or sha256_file(resolved) != source_binding.get("sha256")
    ):
        raise ExperimentError(
            f"Gate-H exported Python source differs: {relative_path}"
        )
    expected_executable = source_binding.get("mode") == "100755"
    actual_mode = stat.S_IMODE(file_stat.st_mode)
    expected_mode = 0o555 if expected_executable else 0o444
    if (
        source_binding.get("mode") not in ("100644", "100755")
        or bool(actual_mode & 0o111) != expected_executable
        or (require_materialized_mode and actual_mode != expected_mode)
        or (
            require_materialized_mode
            and cached_path is not None
            and (Path(cached_path).exists() or Path(cached_path).is_symlink())
        )
    ):
        raise ExperimentError(
            f"Gate-H exported Python source mode differs: {relative_path}"
        )
    return {
        "raw_path": raw_file,
        "path": str(resolved),
        "relative_path": relative_path,
        "mode": source_binding["mode"],
        "filesystem_mode": f"{actual_mode:04o}",
        "size_bytes": file_stat.st_size,
        "sha256": source_binding["sha256"],
        "cached_path": cached_path,
        "cached_path_absent": cached_path is None
        or (not Path(cached_path).exists() and not Path(cached_path).is_symlink()),
    }


def gate_h_export_execution_snapshot(
    *,
    signed_source: dict[str, Any],
    python_binding: dict[str, Any],
    environment: dict[str, str],
    raw_argv: Sequence[str],
    handoff: dict[str, Any],
    sentinel_sha256: str,
    signature_anchor: dict[str, Any],
    bootstrap_modules: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Prove this interpreter loaded every Gate-H module from the signed export."""

    export_root = Path(signed_source["export"]["path"]).resolve()
    bytecode = _gate_h_bytecode_paths(export_root)
    if bytecode:
        raise ExperimentError("Gate-H signed export contains Python bytecode")
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
        raise ExperimentError("Gate-H signed controller isolation flags differ")
    controller = _gate_h_export_file_binding(
        raw_file=__file__,
        relative_path=GATE_H_CONTROLLER_RELATIVE_PATH,
        export_root=export_root,
        signed_source=signed_source,
        cached_path=globals().get("__cached__"),
    )
    modules = {}
    for name, relative_path in GATE_H_EXPORT_MODULES.items():
        module = sys.modules.get(name)
        raw_file = getattr(module, "__file__", None)
        if not isinstance(raw_file, str):
            raise ExperimentError(f"Gate-H exported module is not loaded: {name}")
        cached = getattr(module, "__cached__", None)
        if isinstance(cached, str) and Path(cached).exists():
            raise ExperimentError(f"Gate-H exported module used bytecode: {name}")
        modules[name] = _gate_h_export_file_binding(
                raw_file=raw_file,
                relative_path=relative_path,
                export_root=export_root,
                signed_source=signed_source,
                cached_path=cached if isinstance(cached, str) else None,
        )
    expected_script_root = str((export_root / "lab").resolve())
    observed_sys_path = [str(value) for value in sys.path]
    if not observed_sys_path or Path(observed_sys_path[0]).resolve() != Path(
        expected_script_root
    ):
        raise ExperimentError("Gate-H signed controller has the wrong import root")
    forbidden_roots = {str(WORKSPACE.resolve()), str(CODE_ROOT.resolve())} - {
        str(export_root)
    }
    for value in observed_sys_path:
        if not value:
            continue
        path = Path(value)
        if _path_is_equal_to_or_beneath(path, export_root):
            continue
        if any(
            _path_is_equal_to_or_beneath(path, Path(root))
            for root in forbidden_roots
        ):
            raise ExperimentError(
                "Gate-H signed controller sys.path admits the worktree"
            )
    python = {
        "invocation": python_binding["invocation_path"],
        "path": python_binding["path"],
        "size_bytes": python_binding["size_bytes"],
        "sha256": python_binding["sha256"],
    }
    expected_argv = [
        python["invocation"],
        *GATE_H_PYTHON_FLAGS,
        controller["path"],
        *raw_argv,
    ]
    if list(getattr(sys, "orig_argv", [])) != expected_argv:
        raise ExperimentError("Gate-H signed controller Python argv differs")
    return {
        "schema": GATE_H_EXPORT_EXECUTION_SCHEMA,
        "sentinel_sha256": sentinel_sha256,
        "repository_workspace": str(WORKSPACE.resolve()),
        "code_root": str(export_root),
        "python": python,
        "argv": expected_argv,
        "environment": dict(environment),
        "handoff": handoff,
        "runner": controller,
        "modules": modules,
        "bootstrap_modules": bootstrap_modules,
        "signature_anchor": signature_anchor,
        "sys_path": observed_sys_path,
        "bytecode": {
            "flags": flags,
            "pycache_or_pyc_before": bytecode,
            "pycache_or_pyc_after": None,
        },
        "modules_after": None,
        "passed": False,
    }


def gate_h_bootstrap_module_bindings(
    signed_source: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Expose assume-unchanged worktree tampering before the signed handoff."""

    values = {
        "ip_mesh_experiment": _gate_h_export_file_binding(
            raw_file=__file__,
            relative_path=GATE_H_CONTROLLER_RELATIVE_PATH,
            export_root=WORKSPACE,
            signed_source=signed_source,
            cached_path=globals().get("__cached__"),
            require_materialized_mode=False,
        )
    }
    for name, relative_path in GATE_H_EXPORT_MODULES.items():
        module = sys.modules.get(name)
        raw_file = getattr(module, "__file__", None)
        if not isinstance(raw_file, str):
            raise ExperimentError(f"Gate-H bootstrap module is not loaded: {name}")
        cached = getattr(module, "__cached__", None)
        values[name] = _gate_h_export_file_binding(
            raw_file=raw_file,
            relative_path=relative_path,
            export_root=WORKSPACE,
            signed_source=signed_source,
            cached_path=cached if isinstance(cached, str) else None,
            require_materialized_mode=False,
        )
    return values


def _resolved_executable(path: Path, *, label: str) -> Path:
    if not path.is_absolute():
        raise ExperimentError(f"{label} executable path is not absolute")
    try:
        resolved = path.resolve(strict=True)
        if (
            resolved.is_symlink()
            or not resolved.is_file()
            or not os.access(resolved, os.X_OK)
        ):
            raise ExperimentError(f"{label} executable is not a regular executable")
    except OSError as error:
        raise ExperimentError(f"{label} executable is unavailable: {path}") from error
    return resolved


def _tool_file_binding(path: Path, *, label: str) -> dict[str, Any]:
    resolved = _resolved_executable(path, label=label)
    return {
        "requested_path": str(path),
        "invocation_path": os.path.abspath(path),
        "path": str(resolved),
        "size_bytes": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }


def gate_h_host_environment(
    *,
    root: Path,
    docker_host: str,
    home: Path,
    repository_workspace: Path = WORKSPACE,
    signed_controller: bool = True,
) -> dict[str, str]:
    """Return the complete host environment admitted by formal Gate H."""

    docker_config = (root / "docker-config").resolve()
    temporary = (root / "host-tmp").resolve()
    return {
        "ASTER_GATE_H_HERMETIC": "1",
        "ASTER_GATE_H_REPOSITORY_WORKSPACE": str(repository_workspace.resolve()),
        "ASTER_GATE_H_SIGNED_CONTROLLER": str(gate_h_export_controller(root))
        if signed_controller
        else "0",
        "BUILDKIT_PROGRESS": "plain",
        "DOCKER_BUILDKIT": "1",
        "DOCKER_CLI_HINTS": "false",
        "DOCKER_CONFIG": str(docker_config),
        "DOCKER_HOST": docker_host,
        "HOME": str(home.resolve()),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": GATE_H_HOST_PATH,
        "PYTHONCOERCECLOCALE": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONUTF8": "1",
        "TMPDIR": str(temporary),
        "__CF_USER_TEXT_ENCODING": f"0x{os.getuid():X}:0x0:0x0",
    }


def validate_gate_h_docker_host(value: str) -> Path:
    prefix = "unix://"
    if not isinstance(value, str) or not value.startswith(prefix):
        raise ExperimentError("formal Gate H requires an explicit unix:// Docker host")
    socket_path = Path(value.removeprefix(prefix))
    if not socket_path.is_absolute():
        raise ExperimentError("formal Gate-H Docker socket path is not absolute")
    try:
        mode = socket_path.stat().st_mode
    except OSError as error:
        raise ExperimentError(
            f"formal Gate-H Docker socket is unavailable: {socket_path}"
        ) from error
    if not stat.S_ISSOCK(mode):
        raise ExperimentError("formal Gate-H Docker host is not a Unix socket")
    return socket_path


def _signal_process_group(process: subprocess.Popen[Any], signum: int) -> None:
    try:
        os.killpg(process.pid, signum)
    except OSError:
        try:
            if signum == signal.SIGTERM:
                process.terminate()
            else:
                process.kill()
        except OSError:
            pass


@contextmanager
def deferred_interrupt_signals() -> Any:
    """Defer and consume repeated INT/TERM while a child is being reaped."""

    interrupt_signals = {signal.SIGINT, signal.SIGTERM}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, interrupt_signals)
    deferred: list[int] = []
    try:
        yield deferred
    finally:
        pending = signal.sigpending() & interrupt_signals
        for pending_signal in sorted(pending):
            signal.sigwait({pending_signal})
            deferred.append(pending_signal)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def bounded_subprocess_run(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
    text: bool,
    timeout: float | None,
) -> subprocess.CompletedProcess[Any]:
    """Run one child in its own group and always reap it before propagating."""

    process = subprocess.Popen(
        list(args),
        cwd=cwd,
        env=environment,
        text=text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    def reap_after_interruption(signum: int) -> tuple[Any, Any, list[int]]:
        with deferred_interrupt_signals() as deferred:
            _signal_process_group(process, signum)
            try:
                output = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                _signal_process_group(process, signal.SIGKILL)
                output = process.communicate()
        return output[0], output[1], deferred

    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        stdout, stderr, _deferred = reap_after_interruption(signal.SIGKILL)
        raise subprocess.TimeoutExpired(
            list(args), timeout, output=stdout, stderr=stderr
        ) from error
    except BaseException as error:
        stdout, stderr, deferred = reap_after_interruption(signal.SIGTERM)
        result = subprocess.CompletedProcess(
            list(args),
            process.returncode
            if process.returncode is not None
            else -signal.SIGKILL,
            stdout,
            stderr,
        )
        try:
            error._aster_completed_process = result  # type: ignore[attr-defined]
            error._aster_deferred_signals = deferred  # type: ignore[attr-defined]
        except (AttributeError, TypeError):
            pass
        raise
    return subprocess.CompletedProcess(
        list(args), process.returncode, stdout, stderr
    )


def gate_h_formal_execution(args: argparse.Namespace) -> bool:
    return bool(
        getattr(args, "execute", False)
        and getattr(args, "scenario", None) == "gate-h"
    )


def gate_h_host_bindings(
    args: argparse.Namespace, *, signed_controller: bool
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Resolve formal tools and construct the exact controller/child environment."""

    docker_argument = getattr(args, "docker_binary", None)
    docker_buildx_argument = getattr(args, "docker_buildx_binary", None)
    git_argument = getattr(args, "git_binary", None)
    docker_host = getattr(args, "docker_host", None)
    if not isinstance(docker_argument, Path) or not docker_argument.is_absolute():
        raise ExperimentError("formal Gate H requires absolute --docker-binary")
    if (
        not isinstance(docker_buildx_argument, Path)
        or not docker_buildx_argument.is_absolute()
    ):
        raise ExperimentError(
            "formal Gate H requires absolute --docker-buildx-binary"
        )
    if not isinstance(git_argument, Path) or not git_argument.is_absolute():
        raise ExperimentError("formal Gate H requires absolute --git-binary")
    if not isinstance(docker_host, str):
        raise ExperimentError("formal Gate H requires --docker-host")
    socket_path = validate_gate_h_docker_host(docker_host)
    python_path = Path(sys.executable)
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    tools = {
        "python": _tool_file_binding(python_path, label="Python"),
        "docker": _tool_file_binding(docker_argument, label="Docker"),
        "docker_buildx": _tool_file_binding(
            docker_buildx_argument, label="Docker buildx"
        ),
        "git": _tool_file_binding(git_argument, label="Git"),
    }
    environment = gate_h_host_environment(
        root=args.root.resolve(),
        docker_host=docker_host,
        home=home,
        repository_workspace=WORKSPACE,
        signed_controller=signed_controller,
    )
    if set(environment) != GATE_H_HOST_ENVIRONMENT_KEYS:
        raise ExperimentError("formal Gate-H host environment allowlist is incomplete")
    tools["docker"]["socket_path"] = str(socket_path)
    return tools, environment


def gate_h_signature_request(
    args: argparse.Namespace,
) -> gate_h_signature.SignatureRequest:
    return gate_h_signature.SignatureRequest(
        git=args.git_binary,
        ssh_keygen=args.ssh_keygen_binary,
        ssh=args.ssh_binary,
        allowed_signers=args.allowed_signers,
        principal=args.signer_principal,
    )


def gate_h_signature_request_receipt(
    request: gate_h_signature.SignatureRequest,
) -> dict[str, str]:
    """Retain the exact external trust-anchor arguments selected by the caller."""

    return {
        "git": str(request.git),
        "ssh_keygen": str(request.ssh_keygen),
        "ssh": str(request.ssh),
        "allowed_signers": str(request.allowed_signers),
        "principal": request.principal,
    }


def ensure_gate_h_controller_environment(
    args: argparse.Namespace,
    raw_argv: Sequence[str],
    *,
    signed_controller: bool,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Re-exec formal Gate H so the controller itself has no ambient inputs."""

    tools, environment = gate_h_host_bindings(
        args, signed_controller=signed_controller
    )
    if os.environ.get("ASTER_GATE_H_HERMETIC") != "1":
        python = tools["python"]["invocation_path"]
        os.execve(
            python,
            [
                python,
                *GATE_H_PYTHON_FLAGS,
                str(Path(__file__).resolve()),
                *raw_argv,
            ],
            environment,
        )
        raise AssertionError("os.execve returned")  # pragma: no cover
    if dict(os.environ) != environment:
        unexpected = sorted(set(os.environ) - set(environment))
        missing = sorted(set(environment) - set(os.environ))
        changed = sorted(
            key
            for key in set(environment) & set(os.environ)
            if os.environ[key] != environment[key]
        )
        raise ExperimentError(
            "formal Gate-H controller environment differs from its allowlist: "
            f"unexpected={unexpected}, missing={missing}, changed={changed}"
        )
    if Path(sys.executable).resolve() != Path(tools["python"]["path"]):
        raise ExperimentError("formal Gate-H controller uses the wrong Python binary")
    return tools, environment


def _version_receipt(
    runner: "Runner", argv: Sequence[str], *, timeout: float = 30
) -> dict[str, Any]:
    started = utc_now()
    before = time.monotonic()
    result = runner.run(argv, timeout=timeout)
    return {
        "argv": list(result.args),
        "command_sequence": runner.sequence,
        "started_utc": started,
        "completed_utc": utc_now(),
        "duration_ms": int((time.monotonic() - before) * 1_000),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _gate_h_docker_buildx_plugin_binding(
    runner: "Runner",
) -> dict[str, Any]:
    """Bind the exact buildx symlink installed in the isolated Docker config."""

    if runner.environment is None or runner.docker_buildx_binding is None:
        raise ExperimentError("formal Gate-H Docker buildx plugin is unbound")
    docker_config = Path(runner.environment["DOCKER_CONFIG"])
    plugin_directory = docker_config / "cli-plugins"
    plugin = docker_config / GATE_H_DOCKER_BUILDX_PLUGIN_RELATIVE_PATH
    target = runner.docker_buildx_binding["invocation_path"]
    try:
        link_stat = plugin.lstat()
        observed_target = os.readlink(plugin)
        resolved = plugin.resolve(strict=True)
    except OSError as error:
        raise ExperimentError(
            "formal Gate-H Docker buildx plugin symlink is unavailable"
        ) from error
    target_bytes = os.fsencode(target)
    if (
        not plugin_directory.is_dir()
        or plugin_directory.is_symlink()
        or not stat.S_ISLNK(link_stat.st_mode)
        or observed_target != target
        or link_stat.st_size != len(target_bytes)
        or resolved != Path(runner.docker_buildx_binding["path"])
        or resolved.stat().st_size
        != runner.docker_buildx_binding["size_bytes"]
        or sha256_file(resolved) != runner.docker_buildx_binding["sha256"]
        or sorted(path.name for path in plugin_directory.iterdir())
        != ["docker-buildx"]
    ):
        raise ExperimentError(
            "formal Gate-H Docker buildx plugin symlink differs"
        )
    return {
        "directory_path": str(plugin_directory),
        "path": str(plugin),
        "target": target,
        "symlink_size_bytes": link_stat.st_size,
        "symlink_sha256": hashlib.sha256(target_bytes).hexdigest(),
        "resolved_path": str(resolved),
        "executable_size_bytes": resolved.stat().st_size,
        "executable_sha256": sha256_file(resolved),
        "installed": True,
    }


def install_gate_h_docker_buildx_plugin(runner: "Runner") -> dict[str, Any]:
    """Populate an otherwise empty Docker config with only the bound buildx."""

    if runner.environment is None or runner.docker_buildx_binding is None:
        raise ExperimentError("formal Gate-H Docker buildx plugin is unbound")
    docker_config = Path(runner.environment["DOCKER_CONFIG"])
    if (
        not docker_config.is_dir()
        or docker_config.is_symlink()
        or any(docker_config.iterdir())
    ):
        raise ExperimentError("fresh Gate-H Docker config is not initially empty")
    plugin_directory = docker_config / "cli-plugins"
    plugin = docker_config / GATE_H_DOCKER_BUILDX_PLUGIN_RELATIVE_PATH
    runner._docker_buildx_plugin_install_started = True
    try:
        plugin_directory.mkdir(mode=0o700)
        os.symlink(runner.docker_buildx_binding["invocation_path"], plugin)
    except OSError as error:
        raise ExperimentError(
            "formal Gate-H Docker buildx plugin could not be installed"
        ) from error
    binding = _gate_h_docker_buildx_plugin_binding(runner)
    runner._docker_buildx_plugin_installed = True
    return binding


def _gate_h_docker_buildx_state_inventory(
    runner: "Runner",
) -> dict[str, Any] | None:
    """Bind the bounded buildx state written inside the isolated Docker config."""

    if runner.environment is None:
        raise ExperimentError("formal Gate-H Docker buildx state is unbound")
    docker_config = Path(runner.environment["DOCKER_CONFIG"])
    state = docker_config / GATE_H_DOCKER_BUILDX_STATE_RELATIVE_PATH
    if not state.exists() and not state.is_symlink():
        return None
    try:
        root_stat = state.lstat()
    except OSError as error:
        raise ExperimentError("Docker buildx state cannot be inspected") from error
    if not stat.S_ISDIR(root_stat.st_mode) or state.is_symlink():
        raise ExperimentError("Docker buildx state is not an exact directory")

    expected_directories = {
        ".",
        "activity",
        "defaults",
        "instances",
        "refs",
        "refs/default",
        "refs/default/default",
    }
    expected_fixed_files = {
        ".lock": (0o600, 0),
        ".buildNodeID": (0o600, 16),
        "activity/default": (0o600, 20),
    }
    try:
        descendants = sorted(
            state.rglob("*"), key=lambda path: path.relative_to(state).as_posix()
        )
    except OSError as error:
        raise ExperimentError("Docker buildx state cannot be enumerated") from error
    if len(descendants) + 1 > GATE_H_DOCKER_BUILDX_STATE_MAX_ENTRIES:
        raise ExperimentError("Docker buildx state exceeds the entry bound")

    observed_directories: set[str] = set()
    observed_files: dict[str, tuple[Path, os.stat_result]] = {}
    for path in [state, *descendants]:
        relative = "." if path == state else path.relative_to(state).as_posix()
        try:
            item_stat = path.lstat()
        except OSError as error:
            raise ExperimentError("Docker buildx state entry cannot be inspected") from error
        if stat.S_ISLNK(item_stat.st_mode):
            raise ExperimentError("Docker buildx state contains a symlink")
        if stat.S_ISDIR(item_stat.st_mode):
            if stat.S_IMODE(item_stat.st_mode) != 0o700:
                raise ExperimentError("Docker buildx state directory mode differs")
            observed_directories.add(relative)
        elif stat.S_ISREG(item_stat.st_mode):
            if item_stat.st_nlink != 1:
                raise ExperimentError("Docker buildx state file has multiple links")
            if item_stat.st_size > GATE_H_DOCKER_BUILDX_STATE_MAX_FILE_BYTES:
                raise ExperimentError("Docker buildx state file exceeds the byte bound")
            observed_files[relative] = (path, item_stat)
        else:
            raise ExperimentError("Docker buildx state contains a non-regular entry")

    if observed_directories != expected_directories:
        raise ExperimentError("Docker buildx state directory layout differs")
    dynamic_refs = sorted(set(observed_files) - set(expected_fixed_files))
    if (
        len(dynamic_refs) != 1
        or not dynamic_refs[0].startswith("refs/default/default/")
        or GATE_H_DOCKER_BUILDX_REF.fullmatch(dynamic_refs[0].rsplit("/", 1)[1])
        is None
    ):
        raise ExperimentError("Docker buildx state ref layout differs")

    total_bytes = 0
    entries: list[dict[str, Any]] = []
    for relative in sorted(observed_directories):
        entries.append({"path": relative, "kind": "directory", "mode": "0700"})
    for relative, (path, item_stat) in sorted(observed_files.items()):
        expected = expected_fixed_files.get(relative)
        expected_mode = 0o644 if expected is None else expected[0]
        if stat.S_IMODE(item_stat.st_mode) != expected_mode:
            raise ExperimentError("Docker buildx state file mode differs")
        data = path.read_bytes()
        if len(data) != item_stat.st_size:
            raise ExperimentError("Docker buildx state file changed during inspection")
        if expected is not None and len(data) != expected[1]:
            raise ExperimentError("Docker buildx fixed metadata size differs")
        total_bytes += len(data)
        entries.append(
            {
                "path": relative,
                "kind": "file",
                "mode": f"{expected_mode:04o}",
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "content_base64": base64.b64encode(data).decode("ascii"),
            }
        )
    if total_bytes > GATE_H_DOCKER_BUILDX_STATE_MAX_TOTAL_BYTES:
        raise ExperimentError("Docker buildx state exceeds the aggregate byte bound")

    files = {entry["path"]: entry for entry in entries if entry["kind"] == "file"}
    try:
        node_id = base64.b64decode(files[".buildNodeID"]["content_base64"], validate=True)
        activity = base64.b64decode(
            files["activity/default"]["content_base64"], validate=True
        )
        ref = json.loads(
            base64.b64decode(files[dynamic_refs[0]]["content_base64"], validate=True)
        )
    except (ValueError, KeyError, json.JSONDecodeError) as error:
        raise ExperimentError("Docker buildx state metadata is malformed") from error
    signed_source = str((runner.root / "gate-h-signed-source").resolve())
    if (
        re.fullmatch(rb"[a-z0-9]{16}", node_id) is None
        or re.fullmatch(rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", activity) is None
        or ref
        != {
            "Target": "default",
            "LocalPath": signed_source,
            "DockerfilePath": f"{signed_source}/lab/Dockerfile",
        }
    ):
        raise ExperimentError("Docker buildx state metadata differs")

    entries.sort(key=lambda entry: entry["path"])
    return {
        "path": str(state),
        "entry_count": len(entries),
        "total_file_bytes": total_bytes,
        "entries": entries,
        "entries_sha256": canonical_sha256(entries),
    }


def _cleanup_gate_h_docker_buildx_state(runner: "Runner") -> dict[str, Any]:
    """Inventory, revalidate, and remove only the owned buildx state tree."""

    if runner.environment is None:
        raise ExperimentError("formal Gate-H Docker buildx cleanup is unbound")
    state = (
        Path(runner.environment["DOCKER_CONFIG"])
        / GATE_H_DOCKER_BUILDX_STATE_RELATIVE_PATH
    )
    errors: list[str] = []
    inventory: dict[str, Any] | None = None
    present_before = state.exists() or state.is_symlink()
    if present_before:
        try:
            inventory = _gate_h_docker_buildx_state_inventory(runner)
            if inventory is None:
                raise ExperimentError("Docker buildx state disappeared during inspection")
            if _gate_h_docker_buildx_state_inventory(runner) != inventory:
                raise ExperimentError("Docker buildx state changed before cleanup")
            files = [
                entry for entry in inventory["entries"] if entry["kind"] == "file"
            ]
            directories = [
                entry
                for entry in inventory["entries"]
                if entry["kind"] == "directory" and entry["path"] != "."
            ]
            for entry in files:
                path = state / entry["path"]
                data = path.read_bytes()
                item_stat = path.lstat()
                if (
                    not stat.S_ISREG(item_stat.st_mode)
                    or item_stat.st_nlink != 1
                    or f"{stat.S_IMODE(item_stat.st_mode):04o}" != entry["mode"]
                    or len(data) != entry["size_bytes"]
                    or hashlib.sha256(data).hexdigest() != entry["sha256"]
                ):
                    raise ExperimentError("Docker buildx state changed before deletion")
                path.unlink()
            for entry in sorted(
                directories, key=lambda item: item["path"].count("/"), reverse=True
            ):
                (state / entry["path"]).rmdir()
            state.rmdir()
        except (ExperimentError, OSError) as error:
            errors.append(f"Docker buildx state cleanup failed: {error}")
    removed = not state.exists() and not state.is_symlink()
    return {
        "path": str(state),
        "present_before": present_before,
        "inventory": inventory,
        "removed": removed,
        "errors": errors,
        "passed": not errors and removed,
    }


def cleanup_gate_h_docker_buildx_plugin(runner: "Runner") -> dict[str, Any]:
    """Remove the exact plugin and bounded state from the isolated config."""

    if runner.environment is None or runner.docker_buildx_binding is None:
        raise ExperimentError("formal Gate-H Docker buildx cleanup is unbound")
    docker_config = Path(runner.environment["DOCKER_CONFIG"])
    plugin_directory = docker_config / "cli-plugins"
    plugin = docker_config / GATE_H_DOCKER_BUILDX_PLUGIN_RELATIVE_PATH
    expected_target = runner.docker_buildx_binding["invocation_path"]
    errors: list[str] = []
    if runner._docker_buildx_cleanup_receipt is not None:
        try:
            entries = sorted(path.name for path in docker_config.iterdir())
        except OSError as error:
            entries = ["<unavailable>"]
            cached = dict(runner._docker_buildx_cleanup_receipt)
            cached["errors"] = [*cached["errors"], str(error)]
            cached["docker_config_entries"] = entries
            cached["passed"] = False
            return cached
        if entries:
            cached = dict(runner._docker_buildx_cleanup_receipt)
            cached["errors"] = [
                *cached["errors"],
                "Docker config changed after buildx cleanup",
            ]
            cached["docker_config_entries"] = entries
            cached["passed"] = False
            return cached
        return dict(runner._docker_buildx_cleanup_receipt)
    if not docker_config.is_dir() or docker_config.is_symlink():
        return {
            "plugin_path": str(plugin),
            "expected_target": expected_target,
            "plugin_present_before": False,
            "observed_target": None,
            "plugin_was_installed": runner._docker_buildx_plugin_installed,
            "plugin_removed": runner._docker_buildx_plugin_removed,
            "directory_path": str(plugin_directory),
            "directory_removed": runner._docker_buildx_plugin_directory_removed,
            "errors": ["Docker config path is not an exact directory"],
            "docker_config_entries": ["<unavailable>"],
            "passed": False,
        }
    if (plugin_directory.exists() or plugin_directory.is_symlink()) and (
        not plugin_directory.is_dir() or plugin_directory.is_symlink()
    ):
        return {
            "plugin_path": str(plugin),
            "expected_target": expected_target,
            "plugin_present_before": False,
            "observed_target": None,
            "plugin_was_installed": runner._docker_buildx_plugin_installed,
            "plugin_removed": runner._docker_buildx_plugin_removed,
            "directory_path": str(plugin_directory),
            "directory_removed": runner._docker_buildx_plugin_directory_removed,
            "errors": ["Docker cli-plugins path is not an exact directory"],
            "docker_config_entries": sorted(
                path.name for path in docker_config.iterdir()
            ),
            "passed": False,
        }
    state_cleanup = _cleanup_gate_h_docker_buildx_state(runner)
    errors.extend(state_cleanup["errors"])
    plugin_present_before = plugin.exists() or plugin.is_symlink()
    observed_target: str | None = None
    if plugin.is_symlink():
        try:
            observed_target = os.readlink(plugin)
            runner._docker_buildx_plugin_seen = True
            runner._docker_buildx_plugin_observed_target = observed_target
            if (
                observed_target != expected_target
                or plugin.resolve(strict=True)
                != Path(runner.docker_buildx_binding["path"])
            ):
                errors.append("Docker buildx plugin target differs")
            else:
                plugin.unlink()
                runner._docker_buildx_plugin_removed = True
        except OSError as error:
            errors.append(f"Docker buildx plugin removal failed: {error}")
    elif plugin.exists():
        errors.append("Docker buildx plugin path is not a symlink")
    elif (
        runner._docker_buildx_plugin_installed
        and not runner._docker_buildx_plugin_removed
    ):
        errors.append("installed Docker buildx plugin disappeared before cleanup")

    directory_removed = False
    if plugin_directory.exists() or plugin_directory.is_symlink():
        if not plugin_directory.is_dir() or plugin_directory.is_symlink():
            errors.append("Docker cli-plugins path is not an exact directory")
        else:
            try:
                if any(plugin_directory.iterdir()):
                    errors.append("Docker cli-plugins directory contains extra entries")
                else:
                    plugin_directory.rmdir()
                    directory_removed = True
                    runner._docker_buildx_plugin_directory_removed = True
            except OSError as error:
                errors.append(f"Docker cli-plugins directory removal failed: {error}")
    try:
        config_entries = sorted(path.name for path in docker_config.iterdir())
    except OSError as error:
        config_entries = []
        errors.append(f"Docker config enumeration failed: {error}")
    receipt = {
        "plugin_path": str(plugin),
        "expected_target": expected_target,
        "plugin_present_before": (
            plugin_present_before or runner._docker_buildx_plugin_seen
        ),
        "observed_target": (
            observed_target
            if observed_target is not None
            else runner._docker_buildx_plugin_observed_target
        ),
        "plugin_was_installed": runner._docker_buildx_plugin_installed,
        "plugin_removed": runner._docker_buildx_plugin_removed,
        "directory_path": str(plugin_directory),
        "directory_removed": (
            directory_removed or runner._docker_buildx_plugin_directory_removed
        ),
        "state_cleanup": state_cleanup,
        "errors": errors,
        "docker_config_entries": config_entries,
        "passed": not errors and not config_entries,
    }
    runner._docker_buildx_cleanup_receipt = dict(receipt)
    return receipt


def collect_gate_h_host_execution(
    runner: "Runner",
    *,
    tools: dict[str, dict[str, Any]],
    environment: dict[str, str],
    controller_argv: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Retain exact controller, Git, and Docker client/server identities."""

    docker_config = Path(environment["DOCKER_CONFIG"])
    if (
        not docker_config.is_dir()
        or docker_config.is_symlink()
        or any(docker_config.iterdir())
    ):
        raise ExperimentError("fresh Gate-H Docker config was not initially empty")
    buildx_plugin = install_gate_h_docker_buildx_plugin(runner)
    versions = {
        "python": _version_receipt(
            runner, [tools["python"]["invocation_path"], "--version"]
        ),
        "git": _version_receipt(
            runner,
            [tools["git"]["invocation_path"], "version", "--build-options"],
        ),
        "docker": _version_receipt(
            runner,
            [
                tools["docker"]["invocation_path"],
                "version",
                "--format",
                "{{json .}}",
            ],
        ),
        "docker_buildx": _version_receipt(
            runner,
            [tools["docker"]["invocation_path"], "buildx", "version"],
        ),
    }
    try:
        docker_version = json.loads(versions["docker"]["stdout"])
    except json.JSONDecodeError as error:
        raise ExperimentError("Docker version receipt is not JSON") from error
    if (
        not isinstance(docker_version, dict)
        or not isinstance(docker_version.get("Client"), dict)
        or not isinstance(docker_version.get("Server"), dict)
    ):
        raise ExperimentError("Docker version receipt lacks client and server objects")
    for name, version in versions.items():
        if not version["stdout"].strip() and not version["stderr"].strip():
            raise ExperimentError(f"{name} version receipt is empty")
        tools[name]["version"] = version
    if _gate_h_docker_buildx_plugin_binding(runner) != buildx_plugin:
        raise ExperimentError("Gate-H Docker buildx plugin changed during preflight")
    return {
        "schema": GATE_H_HOST_EXECUTION_SCHEMA,
        "controller_argv": list(controller_argv)
        if controller_argv is not None
        else [
            tools["python"]["invocation_path"],
            str(Path(__file__).resolve()),
            *sys.argv[1:],
        ],
        "controller_environment": dict(os.environ),
        "environment": environment,
        "environment_sha256": canonical_sha256(environment),
        "tools": tools,
        "docker_endpoint": {
            "strategy": "explicit-unix-socket",
            "host": environment["DOCKER_HOST"],
            "socket_path": tools["docker"]["socket_path"],
            "version": docker_version,
        },
        "docker_config": {
            "path": environment["DOCKER_CONFIG"],
            "created_fresh": True,
            "initial_entries": [],
            "buildx_plugin": buildx_plugin,
        },
    }


def finalize_gate_h_host_execution(runner: "Runner") -> dict[str, Any]:
    """Write the append-only final host-environment and process-leak receipt."""

    if runner.environment is None:
        raise ExperimentError("formal Gate-H runner has no exact environment")
    docker_buildx_cleanup = cleanup_gate_h_docker_buildx_plugin(runner)
    entries = docker_buildx_cleanup["docker_config_entries"]
    receipt = {
        "schema": GATE_H_HOST_EXECUTION_FINAL_SCHEMA,
        "completed_utc": utc_now(),
        "environment_sha256": runner.environment_sha256,
        "docker_buildx_cleanup": docker_buildx_cleanup,
        "docker_config_entries": entries,
        "owned_processes": len(runner._owned_processes),
        "registered_docker_resources": len(runner._docker_resources),
        "passed": (
            docker_buildx_cleanup["passed"]
            and not entries
            and not runner._owned_processes
            and not runner._docker_resources
        ),
    }
    path = runner.root / "gate-h-host-execution-final.json"
    if not path.exists():
        write_json(path, receipt)
    return receipt


def finalize_gate_h_host_execution_signal_safe(runner: "Runner") -> dict[str, Any]:
    """Finish owned host cleanup before surfacing a first or repeated signal."""

    with deferred_interrupt_signals() as deferred:
        receipt = finalize_gate_h_host_execution(runner)
    if deferred:
        raise ControlledInterruption(deferred[0])
    return receipt


def finalize_gate_h_signature_trust(
    root: Path, trust: dict[str, Any], *, principal: str
) -> dict[str, Any]:
    """Revalidate every live trust input after all formal trials."""

    try:
        gate_h_signature.validate_signature_trust_receipt(
            trust,
            workspace=WORKSPACE,
            expected_principal=principal,
            verify_tool_files=True,
            verify_frozen_file=True,
        )
        gate_h_signature.verify_signature_inputs_unchanged(trust)
        gate_h_signature.verify_signature_source_unchanged(trust)
    except gate_h_signature.SignatureTrustError as error:
        raise ExperimentError(f"formal signature trust changed: {error}") from error
    allowed = trust["allowed_signers"]
    receipt = {
        "schema": GATE_H_SIGNATURE_FINAL_SCHEMA,
        "completed_utc": utc_now(),
        "principal": principal,
        "signature_trust_sha256": canonical_sha256(trust),
        "frozen_allowed_signers": {
            "path": allowed["frozen_path"],
            "size_bytes": allowed["frozen_size_bytes"],
            "sha256": allowed["frozen_sha256"],
        },
        "tools": {
            name: {
                "path": binding["path"],
                "size_bytes": binding["size_bytes"],
                "sha256": binding["sha256"],
            }
            for name, binding in sorted(trust["tools"].items())
        },
        "passed": True,
    }
    write_json(root / "gate-h-signature-final.json", receipt)
    return receipt


def _bound_git_argv(args: Sequence[str], git_binary: str | None) -> list[str]:
    value = list(args)
    if not value or value[0] != "git":
        raise ExperimentError("local source-freeze command is not a Git command")
    if git_binary is not None:
        value[0] = git_binary
    return value


def run_gate_h_signature_command(
    argv: Sequence[str],
    *,
    environment: dict[str, str],
    stdin_value: bytes | None,
    timeout_seconds: int,
    context: str,
) -> tuple[dict[str, Any], bytes | None, bytes | None]:
    """Use the shared reaping/capture contract for signature-trust commands."""

    return gate_h_fault_contract.run_isolated_process(
        argv,
        environment=environment,
        stdin_value=stdin_value,
        timeout_seconds=timeout_seconds,
        context=context,
    )


def _signature_git_command(
    args: Sequence[str],
    *,
    signature_trust: dict[str, Any],
    command_log: list[dict[str, Any]] | None,
    context: str,
) -> tuple[bytes, bytes]:
    argv = gate_h_signature.git_argv(signature_trust, list(args)[1:])
    receipt, stdout, stderr = run_gate_h_signature_command(
        argv,
        environment=signature_trust["git_environment"],
        stdin_value=None,
        timeout_seconds=30,
        context=context,
    )
    if command_log is not None:
        command_log.append(receipt)
    if (
        isinstance(receipt.get("returncode"), bool)
        or receipt.get("returncode") != 0
        or receipt.get("terminal_returncode") != 0
        or receipt.get("timed_out") is not False
        or receipt.get("execution_error") is not None
        or receipt.get("process_group_reaped") is not True
        or receipt.get("interrupted") is not False
        or stdout is None
        or stderr is None
    ):
        raise ExperimentError(f"hermetic Git command failed: {context}")
    return stdout, stderr


def checked_local_command(
    args: Sequence[str],
    *,
    cwd: Path,
    git_binary: str | None = None,
    environment: dict[str, str] | None = None,
    signature_trust: dict[str, Any] | None = None,
    command_log: list[dict[str, Any]] | None = None,
    context: str = "checked-git",
) -> str:
    if signature_trust is not None:
        stdout, _stderr = _signature_git_command(
            args,
            signature_trust=signature_trust,
            command_log=command_log,
            context=context,
        )
        try:
            return stdout.decode("utf-8").rstrip("\r\n")
        except UnicodeError as error:
            raise ExperimentError(f"hermetic Git output is not UTF-8: {context}") from error
    actual_args = _bound_git_argv(args, git_binary)
    result = bounded_subprocess_run(
        actual_args,
        cwd=cwd,
        environment=environment,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise ExperimentError(
            f"local preflight failed ({result.returncode}): {' '.join(actual_args)}: "
            f"{result.stderr.strip()}"
        )
    return result.stdout.strip()


def checked_candidate_blob(
    commit: str,
    relative: str,
    *,
    git_binary: str | None = None,
    environment: dict[str, str] | None = None,
    signature_trust: dict[str, Any] | None = None,
    command_log: list[dict[str, Any]] | None = None,
) -> tuple[str, bytes]:
    object_id = checked_local_command(
        ["git", "rev-parse", f"{commit}:{relative}"],
        cwd=WORKSPACE,
        git_binary=git_binary,
        environment=environment,
        signature_trust=signature_trust,
        command_log=command_log,
        context=f"candidate-blob-id:{relative}",
    )
    if signature_trust is not None:
        stdout, _stderr = _signature_git_command(
            ["git", "cat-file", "blob", f"{commit}:{relative}"],
            signature_trust=signature_trust,
            command_log=command_log,
            context=f"candidate-blob:{relative}",
        )
        return object_id, stdout
    actual_args = _bound_git_argv(
        ["git", "cat-file", "blob", f"{commit}:{relative}"], git_binary
    )
    try:
        result = bounded_subprocess_run(
            actual_args,
            cwd=WORKSPACE,
            environment=environment,
            text=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ExperimentError(
            f"cannot read candidate source blob {commit}:{relative}: {error}"
        ) from error
    if result.returncode != 0:
        raise ExperimentError(
            f"cannot read candidate source blob {commit}:{relative}"
        )
    return object_id, result.stdout


def checked_candidate_tree(
    commit: str,
    *,
    git_binary: str | None = None,
    environment: dict[str, str] | None = None,
    signature_trust: dict[str, Any] | None = None,
    command_log: list[dict[str, Any]] | None = None,
) -> str:
    tree = checked_local_command(
        ["git", "rev-parse", f"{commit}^{{tree}}"],
        cwd=WORKSPACE,
        git_binary=git_binary,
        environment=environment,
        signature_trust=signature_trust,
        command_log=command_log,
        context="candidate-tree",
    )
    if not HEX_40.fullmatch(tree):
        raise ExperimentError("candidate commit has no exact tree object ID")
    return tree


def checked_candidate_signature(
    commit: str,
    *,
    git_binary: str | None = None,
    environment: dict[str, str] | None = None,
    signature_trust: dict[str, Any] | None = None,
    command_log: list[dict[str, Any]] | None = None,
) -> tuple[str, str, str]:
    if signature_trust is not None:
        verification = gate_h_signature.verify_commit(
            commit,
            signature_trust,
            workspace=WORKSPACE,
            base_environment={
                key: value
                for key, value in signature_trust["git_environment"].items()
                if key not in gate_h_signature.GIT_ENVIRONMENT
            },
            run_command=run_gate_h_signature_command,
        )
        return (
            verification["status"],
            verification["principal"],
            verification["fingerprint"],
        )
    signature = checked_local_command(
        ["git", "log", "-1", "--format=%G?%x00%GS%x00%GF", commit],
        cwd=WORKSPACE,
        git_binary=git_binary,
        environment=environment,
    ).split("\0")
    if len(signature) != 3:
        raise ExperimentError("candidate commit has no exact signature receipt")
    status, signer, fingerprint = signature
    if status != "G" or not signer.strip() or not fingerprint.strip():
        raise ExperimentError("candidate commit does not have a valid trusted signature")
    return status, signer, fingerprint


def source_freeze(
    *,
    execute: bool,
    build_command: str | None,
    git_binary: str | None = None,
    environment: dict[str, str] | None = None,
    signature_trust: dict[str, Any] | None = None,
) -> dict[str, Any]:
    git_commands: list[dict[str, Any]] = []
    command_args = {
        "cwd": WORKSPACE,
        "git_binary": git_binary,
        "environment": environment,
        "signature_trust": signature_trust,
        "command_log": git_commands,
    }
    commit = checked_local_command(
        ["git", "rev-parse", "HEAD"],
        context="source-freeze:head",
        **command_args,
    )
    if not HEX_40.fullmatch(commit):
        raise ExperimentError("git HEAD is not a full lowercase commit ID")
    candidate_tree = checked_candidate_tree(
        commit,
        git_binary=git_binary,
        environment=environment,
        signature_trust=signature_trust,
        command_log=git_commands,
    )
    status = checked_local_command(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        context="source-freeze:status",
        **command_args,
    )
    if execute and status:
        raise ExperimentError("formal execution requires a clean candidate worktree")
    _requirements_blob, requirements_bytes = checked_candidate_blob(
        commit,
        "data-mesh-requirements.md",
        git_binary=git_binary,
        environment=environment,
        signature_trust=signature_trust,
        command_log=git_commands,
    )
    requirements_sha256 = hashlib.sha256(requirements_bytes).hexdigest()
    if requirements_sha256 != REQUIREMENTS_SHA256:
        raise ExperimentError("requirements baseline digest differs from Proposal 0003")
    if execute and (not isinstance(build_command, str) or not build_command.strip()):
        raise ExperimentError("formal execution requires a nonempty --build-command")
    signature_verification: dict[str, Any] | None = None
    if signature_trust is not None:
        if environment is None:
            raise ExperimentError("formal signature verification has no base environment")
        try:
            signature_verification = gate_h_signature.verify_commit(
                commit,
                signature_trust,
                workspace=WORKSPACE,
                base_environment=environment,
                run_command=run_gate_h_signature_command,
            )
        except gate_h_signature.SignatureTrustError as error:
            raise ExperimentError(
                f"formal candidate signature verification failed: {error}"
            ) from error
        signature_status = signature_verification["status"]
        signature_signer = signature_verification["principal"]
        signature_fingerprint = signature_verification["fingerprint"]
    else:
        signature = checked_local_command(
            ["git", "log", "-1", "--format=%G?%x00%GS%x00%GF", commit],
            context="source-freeze:signature-status",
            **command_args,
        ).split("\0")
        if len(signature) != 3:
            raise ExperimentError("git did not return an exact commit signature receipt")
        signature_status, signature_signer, signature_fingerprint = signature
    if execute and (
        signature_status != "G"
        or not signature_signer.strip()
        or not signature_fingerprint.strip()
    ):
        raise ExperimentError("formal execution requires a valid signed candidate commit")
    return {
        "survey_baseline": SURVEY_BASELINE,
        "proposal_0004_baseline": PROPOSAL_0004_BASELINE,
        "experiment_proposal": "0004",
        "candidate_commit": commit,
        "candidate_tree": candidate_tree,
        "worktree_clean": not bool(status),
        "worktree_status": status.splitlines(),
        "requirements_sha256": requirements_sha256,
        "requirements_git_blob": _requirements_blob,
        "requirements_size_bytes": len(requirements_bytes),
        "build_command": build_command,
        "signature_status": signature_status,
        "signature_signer": signature_signer,
        "signature_fingerprint": signature_fingerprint,
        "signature_verification": signature_verification,
        "signature_trust_sha256": None
        if signature_trust is None
        else canonical_sha256(signature_trust),
        "git_commands": git_commands,
        "git_binary": git_binary,
        "host_environment_sha256": None
        if environment is None
        else canonical_sha256(environment),
    }


def _validate_fault_stream(
    owner: dict[str, Any], field: str, *, context: str
) -> bytes:
    value = owner.get(field)
    digest = owner.get(f"{field}_sha256")
    if (
        not isinstance(value, dict)
        or value.get("complete") is not True
        or isinstance(value.get("bytes"), bool)
        or not isinstance(value.get("bytes"), int)
        or value["bytes"] < 0
        or not isinstance(value.get("base64"), str)
        or not isinstance(value.get("preview"), dict)
        or value["preview"].get("bytes") != value["bytes"]
        or not isinstance(digest, str)
        or not HEX_64.fullmatch(digest)
    ):
        raise ExperimentError(f"{context}.{field} is not a complete retained stream")
    try:
        decoded = base64.b64decode(value["base64"], validate=True)
    except ValueError as error:
        raise ExperimentError(f"{context}.{field} is not valid base64") from error
    if len(decoded) != value["bytes"] or hashlib.sha256(decoded).hexdigest() != digest:
        raise ExperimentError(f"{context}.{field} does not match its size or digest")
    if value["preview"] != gate_h_fault_contract.bounded_log(decoded):
        raise ExperimentError(f"{context}.{field} has the wrong bounded preview")
    return decoded


def _validate_fault_executable_binding(
    value: Any, *, package: str, context: str, workspace: Path = WORKSPACE
) -> dict[str, Any]:
    expected_keys = {
        "package",
        "target_name",
        "manifest_path",
        "path",
        "sha256",
        "size_bytes",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("package") != package
    ):
        raise ExperimentError(f"{context} has no exact {package} executable binding")
    expected_target = gate_h_fault_contract.TEST_TARGET_NAMES[package]
    if value.get("target_name") != expected_target:
        raise ExperimentError(f"{context} names the wrong {package} test target")
    expected_manifest = str(
        (workspace / gate_h_fault_contract.TEST_PACKAGE_MANIFESTS[package]).resolve()
    )
    if value.get("manifest_path") != expected_manifest:
        raise ExperimentError(f"{context} names the wrong {package} manifest")
    path = value.get("path")
    digest = value.get("sha256")
    size = value.get("size_bytes")
    if (
        not isinstance(path, str)
        or not Path(path).is_absolute()
        or not isinstance(digest, str)
        or not HEX_64.fullmatch(digest)
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size <= 0
    ):
        raise ExperimentError(f"{context} has a malformed {package} executable binding")
    return value


def _validate_fault_execution_metadata(
    value: dict[str, Any],
    *,
    context: str,
    environment: dict[str, str] | None = None,
    cwd: Path = WORKSPACE,
) -> None:
    duration = value.get("duration_ms")
    if isinstance(duration, bool) or not isinstance(duration, int) or duration < 0:
        raise ExperimentError(f"{context}.duration_ms is not a nonnegative integer")
    if value.get("cwd") != str(cwd.resolve()):
        raise ExperimentError(f"{context} names the wrong working directory")
    expected_environment = (
        {"CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0"}
        if environment is None
        else environment
    )
    if value.get("environment") != expected_environment:
        raise ExperimentError(f"{context} has the wrong deterministic environment")
    for field in ("started_utc", "completed_utc"):
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise ExperimentError(f"{context}.{field} is absent")


def _validate_fault_export_execution(
    value: Any,
    *,
    execution_environment: dict[str, str],
    signed_source: dict[str, Any],
) -> None:
    expected_keys = {
        "schema",
        "sentinel_sha256",
        "repository_workspace",
        "code_root",
        "python",
        "argv",
        "environment",
        "handoff",
        "runner",
        "modules",
        "bootstrap_modules",
        "signature_anchor",
        "sys_path",
        "bytecode",
        "modules_after",
        "passed",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("schema") != GATE_H_EXPORT_EXECUTION_SCHEMA
        or not isinstance(value.get("sentinel_sha256"), str)
        or HEX_64.fullmatch(value["sentinel_sha256"]) is None
        or value.get("passed") is not True
    ):
        raise ExperimentError("Gate-H fault export execution is incomplete")
    export_root = Path(signed_source["export"]["path"])
    expected_environment = {
        **execution_environment,
        "PYTHONDONTWRITEBYTECODE": "1",
        "ASTER_GATE_H_REPOSITORY_WORKSPACE": str(WORKSPACE),
        "ASTER_GATE_H_SIGNED_CONTROLLER": str(
            export_root / "lab/gate_h_faults.py"
        ),
        "__CF_USER_TEXT_ENCODING": f"0x{os.getuid():X}:0x0:0x0",
    }
    python = value.get("python")
    if (
        value.get("repository_workspace") != str(WORKSPACE)
        or value.get("code_root") != str(export_root)
        or value.get("environment") != expected_environment
        or not isinstance(python, dict)
        or set(python) != {"invocation", "path", "size_bytes", "sha256"}
        or not Path(str(python.get("path"))).is_absolute()
        or not isinstance(python.get("size_bytes"), int)
        or isinstance(python.get("size_bytes"), bool)
        or python["size_bytes"] <= 0
        or not isinstance(python.get("sha256"), str)
        or HEX_64.fullmatch(python["sha256"]) is None
    ):
        raise ExperimentError("Gate-H fault exported controller provenance differs")
    source_files = {
        item["path"]: item
        for item in signed_source.get("files", [])
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    modules = value.get("modules")
    if not isinstance(modules, dict) or set(modules) != set(GATE_H_EXPORT_MODULES):
        raise ExperimentError("Gate-H fault exported module inventory differs")
    for name, relative in GATE_H_EXPORT_MODULES.items():
        binding = modules[name]
        source = source_files.get(relative)
        expected_path = str(export_root / relative)
        if (
            not isinstance(binding, dict)
            or set(binding)
            != {
                "raw_path",
                "path",
                "relative_path",
                "mode",
                "filesystem_mode",
                "size_bytes",
                "sha256",
                "cached_path",
                "cached_path_absent",
            }
            or not isinstance(source, dict)
            or binding.get("raw_path") != expected_path
            or binding.get("path") != expected_path
            or binding.get("relative_path") != relative
            or binding.get("mode") != source.get("mode")
            or binding.get("filesystem_mode")
            != ("0555" if source.get("mode") == "100755" else "0444")
            or binding.get("size_bytes") != source.get("size_bytes")
            or binding.get("sha256") != source.get("sha256")
            or binding.get("cached_path_absent") is not True
        ):
            raise ExperimentError(f"Gate-H fault exported module differs: {relative}")
    if (
        value.get("runner") != modules["gate_h_faults"]
        or value.get("modules_after") != modules
        or value.get("bytecode")
        != {
            "flags": {
                "dont_write_bytecode": 1,
                "ignore_environment": 1,
                "no_site": 1,
                "no_user_site": 1,
            },
            "pycache_or_pyc_before": [],
            "pycache_or_pyc_after": [],
        }
    ):
        raise ExperimentError("Gate-H fault exported execution did not finish cleanly")
    argv = value.get("argv")
    if (
        not isinstance(argv, list)
        or len(argv) < 6
        or argv[:6]
        != [
            python["path"],
            *GATE_H_PYTHON_FLAGS,
            str(export_root / "lab/gate_h_faults.py"),
        ]
        or any(not isinstance(item, str) for item in argv)
    ):
        raise ExperimentError("Gate-H fault exported Python argv differs")
    sys_path = value.get("sys_path")
    if (
        not isinstance(sys_path, list)
        or not sys_path
        or sys_path[0] != str(export_root / "lab")
        or any(not isinstance(item, str) or not item for item in sys_path)
    ):
        raise ExperimentError("Gate-H fault exported sys.path differs")


def _validate_gate_h_execution_provenance(
    value: Any,
    *,
    verify_signed_source_files: bool = True,
) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "environment",
            "cargo_config",
            "target_directory",
            "rustup_resolution",
            "tools",
            "signature_trust",
            "signed_source",
            "export_execution",
            "formal_feature_graph",
            "passed",
        }
        or value.get("passed") is not True
    ):
        raise ExperimentError("Gate-H execution provenance is incomplete")
    environment = value.get("environment")
    expected_target_directory = str(
        (WORKSPACE / "target/gate-h-faults-v2").resolve()
    )
    if (
        not isinstance(environment, dict)
        or set(environment) != gate_h_fault_contract.FORMAL_ENVIRONMENT_KEYS
        or any(not isinstance(item, str) or not item for item in environment.values())
        or environment.get("PATH") != gate_h_fault_contract.FORMAL_SYSTEM_PATH
        or environment.get("CARGO_INCREMENTAL") != "0"
        or environment.get("CARGO_NET_OFFLINE") != "true"
        or environment.get("CARGO_TERM_COLOR") != "never"
        or environment.get("RUST_BACKTRACE") != "0"
        or environment.get("LANG") != "C"
        or environment.get("LC_ALL") != "C"
        or environment.get("TMPDIR") != "/tmp"
        or not Path(environment["HOME"]).is_absolute()
        or not Path(environment["CARGO_HOME"]).is_absolute()
        or not Path(environment["CARGO_TARGET_DIR"]).is_absolute()
    ):
        raise ExperimentError("Gate-H execution environment is not exact and allowlisted")
    if environment["CARGO_TARGET_DIR"] != expected_target_directory:
        raise ExperimentError("Gate-H execution environment names the wrong fixed target")
    target = value.get("target_directory")
    if target != {
        "path": environment["CARGO_TARGET_DIR"],
        "initially_absent": True,
        "created_empty": True,
    }:
        raise ExperimentError("Gate-H Cargo target directory was not created from empty")
    cargo_config = value.get("cargo_config")
    try:
        expected_cargo_config = gate_h_fault_contract.cargo_config_absence(
            Path(environment["CARGO_HOME"])
        )
    except gate_h_fault_contract.GateHFaultError as error:
        raise ExperimentError("Gate-H execution admits ambient Cargo configuration") from error
    if cargo_config != expected_cargo_config:
        raise ExperimentError("Gate-H Cargo configuration absence proof differs")

    if not isinstance(value.get("signature_trust"), dict) or not isinstance(
        value.get("signed_source"), dict
    ):
        raise ExperimentError("Gate-H signed source provenance is incomplete")
    try:
        source_workspace = gate_h_source.validate_signed_tree_receipt(
            value.get("signed_source"),
            workspace=WORKSPACE,
            trust=value.get("signature_trust"),
            verify_archive_file=verify_signed_source_files,
            verify_export=verify_signed_source_files,
        )
    except gate_h_source.SignedSourceError as error:
        raise ExperimentError(f"Gate-H signed source provenance is invalid: {error}") from error
    _validate_fault_export_execution(
        value.get("export_execution"),
        execution_environment=environment,
        signed_source=value["signed_source"],
    )

    tools = value.get("tools")
    if not isinstance(tools, dict) or set(tools) != set(
        gate_h_fault_contract.TOOL_VERSION_ARGS
    ):
        raise ExperimentError("Gate-H toolchain binding is incomplete")
    version_keys = {
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
    }
    for name, binding in sorted(tools.items()):
        if (
            not isinstance(binding, dict)
            or set(binding) != {"name", "path", "sha256", "size_bytes", "version"}
            or binding.get("name") != name
            or not isinstance(binding.get("path"), str)
            or not Path(binding["path"]).is_absolute()
            or not isinstance(binding.get("sha256"), str)
            or not HEX_64.fullmatch(binding["sha256"])
            or isinstance(binding.get("size_bytes"), bool)
            or not isinstance(binding.get("size_bytes"), int)
            or binding["size_bytes"] <= 0
        ):
            raise ExperimentError(f"Gate-H {name} executable binding is malformed")
        tool_path = Path(binding["path"])
        try:
            if (
                tool_path.is_symlink()
                or not tool_path.is_file()
                or not os.access(tool_path, os.X_OK)
                or tool_path.stat().st_size != binding["size_bytes"]
                or gate_h_fault_contract.sha256_file(tool_path) != binding["sha256"]
            ):
                raise ExperimentError(f"Gate-H {name} executable binding differs")
        except OSError as error:
            raise ExperimentError(f"Gate-H {name} executable is unavailable") from error
        version = binding.get("version")
        context = f"Gate-H {name} version"
        if (
            not isinstance(version, dict)
            or set(version) != version_keys
            or version.get("argv")
            != [binding["path"], *gate_h_fault_contract.TOOL_VERSION_ARGS[name]]
            or version.get("returncode") != 0
            or version.get("timed_out") is not False
            or version.get("execution_error") is not None
        ):
            raise ExperimentError(f"{context} receipt is malformed")
        _validate_fault_execution_metadata(
            version, context=context, environment=environment
        )
        stdout = _validate_fault_stream(version, "stdout", context=context)
        _validate_fault_stream(version, "stderr", context=context)
        if not stdout:
            raise ExperimentError(f"{context} output is empty")
    if (
        environment.get("RUSTC") != tools["rustc"]["path"]
        or environment.get("RUSTDOC") != tools["rustdoc"]["path"]
    ):
        raise ExperimentError("Gate-H Rust tool paths differ from the exact environment")

    resolution = value.get("rustup_resolution")
    if not isinstance(resolution, dict) or set(resolution) != {
        "environment",
        "commands",
    }:
        raise ExperimentError("Gate-H rustup resolution proof is malformed")
    resolution_environment = resolution.get("environment")
    if (
        not isinstance(resolution_environment, dict)
        or set(resolution_environment)
        != {"CARGO_HOME", "HOME", "LANG", "LC_ALL", "PATH", "RUSTUP_HOME"}
        or resolution_environment.get("CARGO_HOME") != environment["CARGO_HOME"]
        or resolution_environment.get("HOME") != environment["HOME"]
        or resolution_environment.get("LANG") != "C"
        or resolution_environment.get("LC_ALL") != "C"
        or resolution_environment.get("PATH")
        != gate_h_fault_contract.FORMAL_SYSTEM_PATH
        or not isinstance(resolution_environment.get("RUSTUP_HOME"), str)
        or not Path(resolution_environment["RUSTUP_HOME"]).is_absolute()
    ):
        raise ExperimentError("Gate-H rustup resolution environment is not exact")
    resolution_commands = resolution.get("commands")
    if not isinstance(resolution_commands, dict) or set(resolution_commands) != {
        "cargo",
        "rustc",
        "rustdoc",
    }:
        raise ExperimentError("Gate-H pinned Rust tool resolution is incomplete")
    for name, command in sorted(resolution_commands.items()):
        context = f"Gate-H rustup which {name}"
        if (
            not isinstance(command, dict)
            or set(command) != version_keys | {"resolved_path"}
            or command.get("argv")
            != [tools["rustup"]["path"], "which", name]
            or command.get("resolved_path") != tools[name]["path"]
            or command.get("returncode") != 0
            or command.get("timed_out") is not False
            or command.get("execution_error") is not None
        ):
            raise ExperimentError(f"{context} receipt is malformed")
        _validate_fault_execution_metadata(
            command, context=context, environment=resolution_environment
        )
        stdout = _validate_fault_stream(command, "stdout", context=context)
        _validate_fault_stream(command, "stderr", context=context)
        try:
            resolved = stdout.decode("utf-8").strip()
        except UnicodeError as error:
            raise ExperimentError(f"{context} output is not UTF-8") from error
        if resolved != tools[name]["path"]:
            raise ExperimentError(f"{context} output names the wrong executable")

    graph = value.get("formal_feature_graph")
    graph_keys = version_keys | {"assertion", "observed", "passed"}
    expected_graph_argv = [
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
        gate_h_fault_contract.FEATURE_GRAPH_FORMAT,
    ]
    expected_assertion = {
        "required_exact_counts": {
            "aster_lab_gate_h": 1,
            "aster_host_gate_h_formal": 1,
        },
        "forbidden_tokens": [
            "libp2p*",
            "iroh*",
        ],
    }
    if (
        not isinstance(graph, dict)
        or set(graph) != graph_keys
        or graph.get("argv") != expected_graph_argv
        or graph.get("assertion") != expected_assertion
        or graph.get("returncode") != 0
        or graph.get("timed_out") is not False
        or graph.get("execution_error") is not None
        or graph.get("passed") is not True
    ):
        raise ExperimentError("Gate-H resolved Cargo feature graph is malformed")
    _validate_fault_execution_metadata(
        graph,
        context="Gate-H Cargo feature graph",
        environment=environment,
        cwd=source_workspace,
    )
    graph_stdout = _validate_fault_stream(
        graph, "stdout", context="Gate-H Cargo feature graph"
    )
    _validate_fault_stream(graph, "stderr", context="Gate-H Cargo feature graph")
    try:
        graph_text = graph_stdout.decode("utf-8")
    except UnicodeError as error:
        raise ExperimentError("Gate-H Cargo feature graph is not UTF-8") from error
    observed = {
        "required_exact_counts": {
            "aster_lab_gate_h": len(
                re.findall(
                    r"(?m)^aster-lab v[^\r\n]+ features=\[gate-h\]$", graph_text
                )
            ),
            "aster_host_gate_h_formal": len(
                re.findall(
                    r"(?m)aster-host v[^\r\n]+ features=\[gate-h-formal\]$",
                    graph_text,
                )
            ),
        },
        "forbidden_tokens": sorted(
            set(
                re.findall(
                    r"(?i)\b(?:libp2p|iroh)[a-z0-9_-]*\b",
                    graph_text,
                )
            )
        ),
    }
    if graph.get("observed") != observed or observed != {
        "required_exact_counts": expected_assertion["required_exact_counts"],
        "forbidden_tokens": [],
    }:
        raise ExperimentError("Gate-H resolved Cargo feature graph is provider-tainted")
    return environment, tools


def validate_gate_h_fault_receipt(
    path: Path,
    *,
    expected_commit: str,
    expected_binary_sha256: str,
    expected_binary_size: int,
    expected_signature_status: str,
    expected_signature_signer: str,
    expected_signature_fingerprint: str,
    git_binary: str | None = None,
    environment: dict[str, str] | None = None,
    signature_trust: dict[str, Any] | None = None,
    signature_request: gate_h_signature.SignatureRequest | None = None,
    signed_source: dict[str, Any] | None = None,
    verify_fault_signed_source_files: bool = True,
) -> dict[str, Any]:
    """Validate the deterministic fault proof bound to a Gate-H candidate."""

    if not path.is_file():
        raise ExperimentError(f"Gate-H fault receipt is absent: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ExperimentError("Gate-H fault receipt is not valid JSON") from error
    if not isinstance(value, dict) or value.get("schema") != GATE_H_FAULT_SCHEMA:
        raise ExperimentError("Gate-H fault receipt has the wrong schema")
    if value.get("candidate_commit") != expected_commit:
        raise ExperimentError("Gate-H fault receipt is not bound to the candidate commit")
    execution_environment, execution_tools = _validate_gate_h_execution_provenance(
        value.get("execution_provenance"),
        verify_signed_source_files=verify_fault_signed_source_files,
    )
    execution_workspace = Path(
        value["execution_provenance"]["signed_source"]["export"]["path"]
    )
    fault_signature_trust = value.get("signature_trust")
    fault_signature_anchor: dict[str, Any] | None = None
    fault_signature_verification = value.get("signature_verification")
    fault_signed_source = value.get("signed_source")
    if (
        not isinstance(fault_signed_source, dict)
        or value["execution_provenance"].get("signed_source")
        != fault_signed_source
        or value.get("export_execution")
        != value["execution_provenance"].get("export_execution")
    ):
        raise ExperimentError("Gate-H fault signed source/export copies differ")
    if signed_source is not None:
        immutable_source_fields = (
            "commit",
            "tree",
            "files",
            "files_sha256",
        )
        if any(
            fault_signed_source.get(field) != signed_source.get(field)
            for field in immutable_source_fields
        ) or any(
            fault_signed_source.get(owner, {}).get(field)
            != signed_source.get(owner, {}).get(field)
            for owner, fields in (
                ("archive", ("size_bytes", "sha256")),
                ("export", ("file_count", "total_bytes")),
            )
            for field in fields
        ):
            raise ExperimentError(
                "Gate-H fault signed source differs from the live signed source"
            )
    validation_git_commands: list[dict[str, Any]] = []
    if signature_trust is not None:
        if environment is None or signature_request is None:
            raise ExperimentError("Gate-H live signature anchor is incomplete")
        try:
            gate_h_signature.validate_signature_trust_receipt(
                signature_trust,
                workspace=WORKSPACE,
                expected_principal=signature_request.principal,
                verify_tool_files=True,
                verify_frozen_file=True,
            )
            if (
                not isinstance(fault_signature_trust, dict)
                or value["execution_provenance"].get("signature_trust")
                != fault_signature_trust
            ):
                raise gate_h_signature.SignatureTrustError(
                    "fault signature trust copies differ"
                )
            gate_h_signature.validate_signature_trust_receipt(
                fault_signature_trust,
                workspace=WORKSPACE,
                expected_principal=signature_request.principal,
                verify_tool_files=True,
                verify_frozen_file=False,
            )
            fault_signature_anchor = (
                gate_h_signature.validate_signature_request_matches_trust(
                    signature_request,
                    fault_signature_trust,
                    workspace=WORKSPACE,
                    base_environment=environment,
                    run_command=run_gate_h_signature_command,
                )
            )
            verified = gate_h_signature.verify_commit(
                expected_commit,
                signature_trust,
                workspace=WORKSPACE,
                base_environment=environment,
                run_command=run_gate_h_signature_command,
            )
        except gate_h_signature.SignatureTrustError as error:
            raise ExperimentError(
                f"Gate-H fault signature trust differs from the live anchor: {error}"
            ) from error
        verified_signature = (
            verified["status"],
            verified["principal"],
            verified["fingerprint"],
        )
        if (
            not isinstance(fault_signature_verification, dict)
            or fault_signature_verification.get("commit") != expected_commit
            or fault_signature_verification.get("status") != verified["status"]
            or fault_signature_verification.get("principal")
            != verified["principal"]
            or fault_signature_verification.get("fingerprint")
            != verified["fingerprint"]
            or fault_signature_verification.get("passed") is not True
        ):
            raise ExperimentError(
                "Gate-H fault signature verification differs from the live verification"
            )
        checked_git = {
            "git_binary": git_binary,
            "environment": environment,
            "signature_trust": signature_trust,
            "command_log": validation_git_commands,
        }
    else:
        checked_git = {"git_binary": git_binary, "environment": environment}
        verified_signature = checked_candidate_signature(expected_commit, **checked_git)
    if (
        value.get("candidate_tree")
        != checked_candidate_tree(expected_commit, **checked_git)
        or value.get("worktree_clean") is not True
        or value.get("worktree_status") != []
        or value.get("signature_status") != "G"
        or not isinstance(value.get("signature_signer"), str)
        or not value["signature_signer"].strip()
        or not isinstance(value.get("signature_fingerprint"), str)
        or not value["signature_fingerprint"].strip()
        or value.get("signature_status") != expected_signature_status
        or value.get("signature_signer") != expected_signature_signer
        or value.get("signature_fingerprint") != expected_signature_fingerprint
        or verified_signature
        != (
            expected_signature_status,
            expected_signature_signer,
            expected_signature_fingerprint,
        )
    ):
        raise ExperimentError("Gate-H fault receipt has no signed clean source freeze")
    if value.get("requirements_sha256") != REQUIREMENTS_SHA256:
        raise ExperimentError("Gate-H fault receipt has the wrong requirements baseline")
    if (
        value.get("candidate_binary_sha256") != expected_binary_sha256
        or value.get("candidate_binary_size_bytes") != expected_binary_size
        or not isinstance(value.get("candidate_binary"), str)
        or not Path(value["candidate_binary"]).is_absolute()
    ):
        raise ExperimentError("Gate-H fault receipt names the wrong candidate binary")
    source_files = value.get("source_files")
    if (
        not isinstance(source_files, list)
        or [binding.get("path") for binding in source_files if isinstance(binding, dict)]
        != list(gate_h_fault_contract.SOURCE_PATHS)
    ):
        raise ExperimentError("Gate-H fault receipt has the wrong bound source set")
    candidate_sources: dict[str, bytes] = {}
    for binding in source_files:
        relative = binding["path"]
        candidate_blob_id, candidate_bytes = checked_candidate_blob(
            expected_commit, relative, **checked_git
        )
        candidate_sources[relative] = candidate_bytes
        if (
            set(binding) != {"path", "git_blob", "sha256", "size_bytes"}
            or not isinstance(binding.get("git_blob"), str)
            or not HEX_40.fullmatch(binding["git_blob"])
            or not isinstance(binding.get("sha256"), str)
            or not HEX_64.fullmatch(binding["sha256"])
            or isinstance(binding.get("size_bytes"), bool)
            or not isinstance(binding.get("size_bytes"), int)
            or binding["size_bytes"] < 0
            or candidate_blob_id != binding.get("git_blob")
            or len(candidate_bytes) != binding.get("size_bytes")
            or hashlib.sha256(candidate_bytes).hexdigest() != binding.get("sha256")
        ):
            raise ExperimentError(f"Gate-H fault source binding differs: {relative}")
    source_by_path = {binding["path"]: binding for binding in source_files}
    if (
        source_by_path["data-mesh-requirements.md"]["sha256"]
        != REQUIREMENTS_SHA256
        or value.get("proposal_0004_sha256")
        != source_by_path["docs/proposals/0004-shared-node-libp2p-retest.md"][
            "sha256"
        ]
    ):
        raise ExperimentError("Gate-H requirements or Proposal-0004 source digest differs")
    if value.get("source_files_sha256") != gate_h_fault_contract.canonical_sha256(
        source_files
    ):
        raise ExperimentError("Gate-H fault source binding digest differs")

    plan = gate_h_fault_contract.command_plan(execution_tools["cargo"]["path"])
    if value.get("command_plan") != plan or value.get(
        "command_plan_sha256"
    ) != gate_h_fault_contract.canonical_sha256(plan):
        raise ExperimentError("Gate-H fault receipt has the wrong exact command plan")
    timeout_seconds = value.get("timeout_seconds_per_command")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds < 1
        or timeout_seconds > GATE_H_FAULT_MAX_TIMEOUT_SECONDS
    ):
        raise ExperimentError("Gate-H fault receipt has an invalid command timeout")
    if value.get("passed") is not True:
        raise ExperimentError("Gate-H deterministic fault proof did not pass")
    cases = value.get("cases")
    if not isinstance(cases, dict) or set(cases) != GATE_H_FAULT_CASES:
        raise ExperimentError("Gate-H fault receipt has the wrong mandatory case set")
    if any(case is not True for case in cases.values()):
        raise ExperimentError("Gate-H fault receipt contains a failed mandatory case")
    build = value.get("test_executable_build")
    if not isinstance(build, dict) or build.get("passed") is not True:
        raise ExperimentError("Gate-H test executable build did not pass")
    builds = build.get("builds")
    executables = build.get("executables")
    packages = set(gate_h_fault_contract.TEST_TARGET_NAMES)
    if not isinstance(builds, dict) or set(builds) != packages:
        raise ExperimentError("Gate-H receipt has the wrong executable build set")
    if not isinstance(executables, dict) or set(executables) != packages:
        raise ExperimentError("Gate-H receipt has the wrong test executable set")
    bindings: dict[str, dict[str, Any]] = {}
    for package in sorted(packages):
        binding = _validate_fault_executable_binding(
            executables[package],
            package=package,
            context="Gate-H test build",
            workspace=execution_workspace,
        )
        bindings[package] = binding
        build_receipt = builds[package]
        expected_build_argv = [
            execution_tools["cargo"]["path"],
            "test",
            "--locked",
            "-p",
            package,
            "--lib",
            *gate_h_fault_contract.TEST_PACKAGE_FEATURE_ARGS[package],
            "--no-run",
            "--message-format=json",
        ]
        if (
            not isinstance(build_receipt, dict)
            or build_receipt.get("package") != package
            or build_receipt.get("argv") != expected_build_argv
            or isinstance(build_receipt.get("returncode"), bool)
            or not isinstance(build_receipt.get("returncode"), int)
            or build_receipt.get("returncode") != 0
            or build_receipt.get("timed_out") is not False
            or build_receipt.get("execution_error") is not None
            or build_receipt.get("parse_error") is not None
            or build_receipt.get("build_finished") is not True
            or build_receipt.get("executable") != binding
            or build_receipt.get("source_files_sha256")
            != value["source_files_sha256"]
            or build_receipt.get("passed") is not True
        ):
            raise ExperimentError(f"Gate-H {package} test executable build is malformed")
        _validate_fault_execution_metadata(
            build_receipt,
            context=f"Gate-H {package} build",
            environment=execution_environment,
            cwd=execution_workspace,
        )
        _validate_fault_stream(
            build_receipt, "stdout", context=f"Gate-H {package} build"
        )
        _validate_fault_stream(
            build_receipt, "stderr", context=f"Gate-H {package} build"
        )
    build_plan = [
        {
            "package": package,
            "argv": builds[package].get("argv"),
            "source_files_sha256": builds[package].get("source_files_sha256"),
        }
        for package in sorted(packages)
    ]
    if value.get(
        "test_executable_build_plan_sha256"
    ) != gate_h_fault_contract.canonical_sha256(build_plan):
        raise ExperimentError("Gate-H test executable build plan digest differs")

    commands = value.get("commands")
    if not isinstance(commands, list) or len(commands) != len(plan):
        raise ExperimentError("Gate-H fault receipt has the wrong executed command count")
    recomputed_cases = {case: True for case in GATE_H_FAULT_CASES}
    for index, (command, expected) in enumerate(zip(commands, plan, strict=True)):
        context = f"Gate-H fault command {index}"
        if not isinstance(command, dict):
            raise ExperimentError(f"{context} is not an object")
        _validate_fault_execution_metadata(
            command,
            context=context,
            environment=execution_environment,
            cwd=execution_workspace,
        )
        package = expected["package"]
        stdout = _validate_fault_stream(command, "stdout", context=context)
        stderr = _validate_fault_stream(command, "stderr", context=context)
        witnessed, _ = gate_h_fault_contract.exact_test_witness(
            gate_h_fault_contract.TEST_SPECS[index],
            returncode=command.get("returncode"),
            timed_out=command.get("timed_out"),
            stdout=stdout,
            stderr=stderr,
        )
        if (
            command.get("case") != expected["case"]
            or command.get("package") != package
            or command.get("test_name") != expected["test_name"]
            or command.get("argv") != expected["argv"]
            or isinstance(command.get("returncode"), bool)
            or not isinstance(command.get("returncode"), int)
            or command.get("returncode") != 0
            or command.get("timed_out") is not False
            or command.get("execution_error") is not None
            or command.get("exact_test_witnessed") is not True
            or command.get("witness_error") is not None
            or not witnessed
            or command.get("test_executable") != bindings[package]
            or command.get("test_executable_sha256_before")
            != bindings[package]["sha256"]
            or command.get("test_executable_sha256_after")
            != bindings[package]["sha256"]
            or command.get("cargo_reported_test_executable")
            != bindings[package]["path"]
            or command.get("test_executable_unchanged") is not True
        ):
            raise ExperimentError(f"{context} is malformed, unbound, or failed")
        recomputed_cases[expected["case"]] = (
            recomputed_cases[expected["case"]] and witnessed
        )
    if cases != recomputed_cases:
        raise ExperimentError("Gate-H fault case map differs from exact command witnesses")

    static_checks = value.get("static_checks")
    if (
        not isinstance(static_checks, dict)
        or set(static_checks) != set(gate_h_fault_contract.STATIC_CHECK_NAMES)
        or value.get("static_checks_passed") is not True
        or value.get("static_checks_error") is not None
    ):
        raise ExperimentError("Gate-H static ownership proof is incomplete")
    expected_static_checks = gate_h_fault_contract.static_check_contract(
        execution_tools["rg"]["path"], execution_tools["cargo"]["path"]
    )

    def expected_region_receipt(
        path: str, markers: tuple[str, str] | None
    ) -> dict[str, Any] | None:
        if markers is None:
            return None
        try:
            source_text = candidate_sources[path].decode("utf-8")
            start_marker, end_marker = markers
            if (
                source_text.count(start_marker) != 1
                or source_text.count(end_marker) != 1
            ):
                raise ExperimentError(
                    "Gate-H candidate no longer has exact static-check markers"
                )
            start = source_text.index(start_marker)
            end = source_text.index(end_marker, start + len(start_marker))
        except (UnicodeError, ValueError) as error:
            raise ExperimentError(
                "Gate-H candidate has an invalid static-check source region"
            ) from error
        region_bytes = source_text[start:end].encode("utf-8")
        return {
            "path": path,
            "start_marker": start_marker,
            "end_marker": end_marker,
            "start_line": source_text.count("\n", 0, start) + 1,
            "bytes": len(region_bytes),
            "sha256": hashlib.sha256(region_bytes).hexdigest(),
        }

    static_plan = []
    for name, check in sorted(static_checks.items()):
        context = f"Gate-H static check {name}"
        expected_check = expected_static_checks[name]
        expected_source_files = [
            source_by_path[path] for path in expected_check["source_paths"]
        ]
        expected_static_returncode = (
            1 if expected_check["assertion"].get("kind") == "absent" else 0
        )
        expected_region = expected_region_receipt(
            expected_check["source_paths"][0], expected_check["region"]
        )
        if (
            not isinstance(check, dict)
            or check.get("name") != name
            or check.get("argv") != expected_check["argv"]
            or check.get("timed_out") is not False
            or isinstance(check.get("returncode"), bool)
            or not isinstance(check.get("returncode"), int)
            or isinstance(check.get("expected_returncode"), bool)
            or not isinstance(check.get("expected_returncode"), int)
            or check.get("expected_returncode")
            != expected_static_returncode
            or check.get("returncode") != check.get("expected_returncode")
            or check.get("execution_error") is not None
            or check.get("passed") is not True
            or check.get("assertion") != expected_check["assertion"]
            or not isinstance(check.get("observed"), dict)
            or check.get("source_files") != expected_source_files
            or check.get("source_region") != expected_region
        ):
            raise ExperimentError(f"{context} is malformed or failed")
        if name == "formal_graph_has_no_libp2p_or_iroh_dependency":
            graph = value["execution_provenance"]["formal_feature_graph"]
            expected_projection = {
                "name": name,
                "argv": graph["argv"],
                "cwd": graph["cwd"],
                "environment": graph["environment"],
                "source_files": expected_source_files,
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
            if check != expected_projection:
                raise ExperimentError(
                    f"{context} differs from resolved feature-graph provenance"
                )
        region = check.get("source_region")
        if region is not None:
            if (
                not isinstance(region, dict)
                or set(region)
                != {
                    "path",
                    "start_marker",
                    "end_marker",
                    "start_line",
                    "bytes",
                    "sha256",
                }
                or region.get("path") not in candidate_sources
                or not isinstance(region.get("start_marker"), str)
                or not isinstance(region.get("end_marker"), str)
            ):
                raise ExperimentError(f"{context} has a malformed source region")
            try:
                source_text = candidate_sources[region["path"]].decode("utf-8")
            except UnicodeError as error:
                raise ExperimentError(f"{context} source region is not UTF-8") from error
            start_marker = region["start_marker"]
            end_marker = region["end_marker"]
            if source_text.count(start_marker) != 1 or source_text.count(end_marker) != 1:
                raise ExperimentError(f"{context} source-region markers are not unique")
            start = source_text.index(start_marker)
            end = source_text.index(end_marker, start + len(start_marker))
            region_bytes = source_text[start:end].encode("utf-8")
            if (
                region.get("start_line") != source_text.count("\n", 0, start) + 1
                or region.get("bytes") != len(region_bytes)
                or region.get("sha256") != hashlib.sha256(region_bytes).hexdigest()
            ):
                raise ExperimentError(f"{context} source region differs from the candidate")
        _validate_fault_execution_metadata(
            check,
            context=context,
            environment=execution_environment,
            cwd=execution_workspace,
        )
        stdout = _validate_fault_stream(check, "stdout", context=context)
        stderr = _validate_fault_stream(check, "stderr", context=context)
        if stderr and name != "formal_graph_has_no_libp2p_or_iroh_dependency":
            raise ExperimentError(f"{context} retained unexpected stderr")
        decoded = stdout.decode("utf-8", errors="replace")
        lines = [line for line in decoded.splitlines() if line]
        assertion = check["assertion"]
        observed = check["observed"]
        kind = assertion.get("kind")
        assertion_passed = False
        recomputed_observed: dict[str, Any] = {"match_count": len(lines)}
        if name == "formal_graph_has_no_libp2p_or_iroh_dependency":
            required = {
                "aster_lab_gate_h": len(
                    re.findall(
                        r"(?m)^aster-lab v[^\r\n]+ features=\[gate-h\]$", decoded
                    )
                ),
                "aster_host_gate_h_formal": len(
                    re.findall(
                        r"(?m)aster-host v[^\r\n]+ features=\[gate-h-formal\]$",
                        decoded,
                    )
                ),
            }
            forbidden = sorted(
                set(
                    re.findall(
                        r"(?i)\b(?:libp2p|iroh)[a-z0-9_-]*\b",
                        decoded,
                    )
                )
            )
            recomputed_observed = {
                "required_exact_counts": required,
                "forbidden_tokens": forbidden,
            }
            assertion_passed = (
                assertion
                == {
                    "required_exact_counts": {
                        "aster_lab_gate_h": 1,
                        "aster_host_gate_h_formal": 1,
                    },
                    "forbidden_tokens": [
                        "libp2p*",
                        "iroh*",
                    ],
                }
                and recomputed_observed
                == {
                    "required_exact_counts": assertion["required_exact_counts"],
                    "forbidden_tokens": [],
                }
                and check.get("expected_returncode") == 0
            )
        elif kind == "absent" and assertion == {"kind": "absent", "count": 0}:
            assertion_passed = not lines and check.get("expected_returncode") == 1
        elif kind == "exact_count" and isinstance(assertion.get("count"), int):
            assertion_passed = (
                len(lines) == assertion["count"]
                and check.get("expected_returncode") == 0
            )
        elif kind == "token_counts" and isinstance(assertion.get("counts"), dict):
            counts = assertion["counts"]
            if all(
                isinstance(token, str) and isinstance(count, int)
                for token, count in counts.items()
            ):
                recomputed_observed["token_counts"] = {
                    token: decoded.count(token) for token in counts
                }
                assertion_passed = (
                    recomputed_observed["token_counts"] == counts
                    and (
                        assertion.get("match_count") is None
                        or assertion["match_count"] == len(lines)
                    )
                    and check.get("expected_returncode") == 0
                )
        elif kind == "method_set" and isinstance(assertion.get("methods"), list):
            methods = re.findall(r"pub(?: const)? fn ([a-z_][a-z0-9_]*)", decoded)
            recomputed_observed["methods"] = methods
            assertion_passed = (
                len(methods) == len(assertion["methods"])
                and sorted(methods) == sorted(assertion["methods"])
                and set(methods) == set(gate_h_fault_contract.TYPED_AUTHORITY_METHODS)
                and check.get("expected_returncode") == 0
            )
        if not assertion_passed or observed != recomputed_observed:
            raise ExperimentError(f"{context} assertion is not reproduced by its output")
        static_plan.append(
            {
                "name": name,
                "argv": check.get("argv"),
                "source_files": check.get("source_files"),
                "source_region": check.get("source_region"),
                "assertion": check.get("assertion"),
                "expected_returncode": check.get("expected_returncode"),
            }
        )
    if value.get("static_check_plan_sha256") != gate_h_fault_contract.canonical_sha256(
        static_plan
    ):
        raise ExperimentError("Gate-H static ownership plan digest differs")

    expected_digests = {
        package: binding["sha256"] for package, binding in bindings.items()
    }
    if (
        value.get("test_executables_passed") is not True
        or value.get("test_executable_digests_after_tests") != expected_digests
        or value.get("test_executables_integrity_after_tests") is not True
        or value.get("source_integrity_after_tests") is not True
        or value.get("integrity_error") is not None
    ):
        raise ExperimentError("Gate-H post-test source or executable integrity failed")
    if fault_signature_anchor is not None:
        value["_validated_signature_anchor"] = fault_signature_anchor
        value["_validation_git_commands"] = validation_git_commands
    return value


def evidence_index(
    root: Path, *, excluded_names: frozenset[str] | None = None
) -> dict[str, Any]:
    excluded = (
        frozenset({"evidence-index.json"})
        if excluded_names is None
        else excluded_names
    )
    entries: list[dict[str, Any]] = []
    aggregate = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.name in excluded:
            continue
        if path.is_symlink():
            raise ExperimentError(f"evidence tree contains a symlink: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        digest = sha256_file(path)
        aggregate.update(relative.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(str(size).encode("ascii"))
        aggregate.update(b"\0")
        aggregate.update(digest.encode("ascii"))
        aggregate.update(b"\n")
        entries.append({"path": relative, "size": size, "sha256": digest})
    return {
        "schema": EVIDENCE_INDEX_SCHEMA,
        "created_utc": utc_now(),
        "entry_count": len(entries),
        "aggregate_sha256": aggregate.hexdigest(),
        "entries": entries,
    }


def write_exclusive(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(data)
        if not data.endswith("\n"):
            stream.write("\n")


def write_json(path: Path, value: Any) -> None:
    write_exclusive(path, json.dumps(value, indent=2, sort_keys=True))


class Runner:
    def __init__(
        self,
        root: Path,
        execute: bool,
        *,
        environment: dict[str, str] | None = None,
        docker_binary: str | None = None,
        docker_buildx_binding: dict[str, Any] | None = None,
    ) -> None:
        self.root = root
        self.execute = execute
        self.sequence = 0
        self.environment = None if environment is None else dict(environment)
        self.environment_sha256 = (
            None if environment is None else canonical_sha256(self.environment)
        )
        self.docker_binary = docker_binary
        self.docker_buildx_binding = (
            None if docker_buildx_binding is None else dict(docker_buildx_binding)
        )
        self._docker_buildx_plugin_install_started = False
        self._docker_buildx_plugin_installed = False
        self._docker_buildx_plugin_removed = False
        self._docker_buildx_plugin_seen = False
        self._docker_buildx_plugin_observed_target: str | None = None
        self._docker_buildx_plugin_directory_removed = False
        self._docker_buildx_cleanup_receipt: dict[str, Any] | None = None
        self._owned_processes: dict[int, subprocess.Popen[str]] = {}
        self._docker_resources: dict[tuple[str, str], dict[str, Any]] = {}
        self._docker_resource_sequence = 0

    def resolve_args(self, args: Sequence[str]) -> list[str]:
        actual = list(args)
        if actual and actual[0] == "docker" and self.docker_binary is not None:
            actual[0] = self.docker_binary
        return actual

    def register_docker_resource(
        self, kind: str, name: str, *, owner: str
    ) -> tuple[str, str]:
        """Reserve an exact Docker resource name before a daemon-side create."""

        if kind not in ("container", "network"):
            raise ExperimentError(f"unsupported Docker resource kind: {kind}")
        if not RESOURCE.fullmatch(name):
            raise ExperimentError(f"invalid managed Docker resource name: {name}")
        key = (kind, name)
        if key in self._docker_resources:
            raise ExperimentError(f"Docker resource is already registered: {kind} {name}")
        self._docker_resource_sequence += 1
        self._docker_resources[key] = {
            "kind": kind,
            "name": name,
            "owner": owner,
            "registration_sequence": self._docker_resource_sequence,
        }
        return key

    def settle_docker_resource(self, kind: str, name: str) -> None:
        self._docker_resources.pop((kind, name), None)

    def _docker_resource_commands(
        self, kind: str, name: str
    ) -> tuple[list[str], list[str]]:
        if kind == "container":
            return (
                ["docker", "rm", "--force", name],
                [
                    "docker",
                    "container",
                    "ls",
                    "--all",
                    "--filter",
                    f"name=^/{name}$",
                    "--format",
                    "{{.Names}}",
                ],
            )
        if kind == "network":
            return (
                ["docker", "network", "rm", name],
                [
                    "docker",
                    "network",
                    "ls",
                    "--filter",
                    f"name=^{name}$",
                    "--format",
                    "{{.Name}}",
                ],
            )
        raise ExperimentError(f"unsupported Docker resource kind: {kind}")

    def confirm_docker_resource_absent(self, kind: str, name: str) -> bool:
        """Settle a failed removal only after Docker proves the name is absent."""

        _remove, enumerate_exact_name = self._docker_resource_commands(kind, name)
        result = self.run(enumerate_exact_name, check=False)
        retained_names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if result.returncode == 0 and not retained_names:
            self.settle_docker_resource(kind, name)
            return True
        return False

    def cleanup_registered_docker_resources(
        self,
        *,
        reason: str,
        resources: Sequence[tuple[str, str]] | None = None,
    ) -> tuple[dict[str, Any], BaseException | None]:
        """Force-remove registered names, receipt every attempt, and never leak a signal.

        Signals are blocked for the entire drain.  An injected ``BaseException``
        is retained, the exact operation is retried, and the original exception
        is returned only after every selected resource is removed or proven absent.
        """

        selected = (
            list(reversed(self._docker_resources))
            if resources is None
            else list(resources)
        )
        outcomes: list[dict[str, Any]] = []
        first_error: BaseException | None = None
        with deferred_interrupt_signals() as deferred:
            for key in selected:
                binding = self._docker_resources.get(key)
                if binding is None:
                    continue
                kind, name = key
                remove, enumerate_exact_name = self._docker_resource_commands(kind, name)
                remove_attempts: list[dict[str, Any]] = []
                remove_result: subprocess.CompletedProcess[str] | None = None
                for _attempt in range(2):
                    try:
                        remove_result = self.run(remove, check=False)
                        remove_attempts.append(
                            {
                                "argv": self.resolve_args(remove),
                                "returncode": remove_result.returncode,
                            }
                        )
                        break
                    except BaseException as error:
                        if first_error is None:
                            first_error = error
                        remove_attempts.append(
                            {
                                "argv": self.resolve_args(remove),
                                "returncode": None,
                                "error_type": type(error).__name__,
                                "error": str(error),
                            }
                        )

                absent_check: dict[str, Any] | None = None
                settled = remove_result is not None and remove_result.returncode == 0
                if not settled:
                    enumeration_result: subprocess.CompletedProcess[str] | None = None
                    for _attempt in range(2):
                        try:
                            enumeration_result = self.run(
                                enumerate_exact_name, check=False
                            )
                            retained_names = [
                                line.strip()
                                for line in enumeration_result.stdout.splitlines()
                                if line.strip()
                            ]
                            absent_check = {
                                "argv": self.resolve_args(enumerate_exact_name),
                                "returncode": enumeration_result.returncode,
                                "retained_names": retained_names,
                            }
                            break
                        except BaseException as error:
                            if first_error is None:
                                first_error = error
                            absent_check = {
                                "argv": self.resolve_args(enumerate_exact_name),
                                "returncode": None,
                                "error_type": type(error).__name__,
                                "error": str(error),
                            }
                    settled = (
                        enumeration_result is not None
                        and enumeration_result.returncode == 0
                        and not retained_names
                    )
                if settled:
                    self.settle_docker_resource(kind, name)
                outcomes.append(
                    {
                        **binding,
                        "remove_attempts": remove_attempts,
                        "absence_check": absent_check,
                        "settled": settled,
                    }
                )
            pending_before_receipt = sorted(
                signal.sigpending() & {signal.SIGINT, signal.SIGTERM}
            )
            receipt = {
                "schema": GATE_H_RESOURCE_CLEANUP_SCHEMA,
                "completed_utc": utc_now(),
                "reason": reason,
                "passed": all(outcome["settled"] for outcome in outcomes),
                "resources": outcomes,
                "remaining_registered_resources": len(self._docker_resources),
                "deferred_signals": pending_before_receipt,
            }
            receipt_path = self.root / "gate-h-resource-cleanup.jsonl"
            with receipt_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(receipt, sort_keys=True) + "\n")

        if deferred and first_error is None:
            first_error = ControlledInterruption(deferred[0])
        return receipt, first_error

    def record(
        self,
        args: Sequence[str],
        result: subprocess.CompletedProcess[str],
        *,
        cwd: Path | None = None,
    ) -> None:
        self.sequence += 1
        record = {
            "sequence": self.sequence,
            "utc": utc_now(),
            "argv": list(args),
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        if self.environment_sha256 is not None:
            record["environment_sha256"] = self.environment_sha256
        if cwd is not None:
            record["cwd"] = str(cwd.resolve())
        with (self.root / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")

    def run(
        self,
        args: Sequence[str],
        *,
        check: bool = True,
        timeout: float | None = 120,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        actual_args = self.resolve_args(args)
        if not self.execute:
            result = subprocess.CompletedProcess(actual_args, 0, "", "")
            self.record(actual_args, result, cwd=cwd)
            return result
        try:
            result = bounded_subprocess_run(
                actual_args,
                cwd=cwd,
                environment=self.environment,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            def timeout_text(value: str | bytes | None) -> str:
                if value is None:
                    return ""
                if isinstance(value, bytes):
                    return value.decode("utf-8", errors="replace")
                return value

            result = subprocess.CompletedProcess(
                actual_args,
                124,
                timeout_text(error.stdout),
                timeout_text(error.stderr),
            )
            self.record(actual_args, result, cwd=cwd)
            raise ExperimentError(
                f"command exceeded its {timeout}-second deadline: {' '.join(actual_args)}"
            ) from error
        except BaseException as error:
            interrupted = getattr(error, "_aster_completed_process", None)
            if isinstance(interrupted, subprocess.CompletedProcess):
                self.record(actual_args, interrupted, cwd=cwd)
            raise
        self.record(actual_args, result, cwd=cwd)
        if check and result.returncode != 0:
            raise ExperimentError(
                f"command failed ({result.returncode}): {' '.join(actual_args)}: "
                f"{result.stderr.strip()}"
            )
        return result

    def popen(self, args: Sequence[str]) -> subprocess.Popen[str]:
        if not self.execute:
            raise ExperimentError("process launch is unavailable in dry-run mode")
        actual_args = self.resolve_args(args)
        self.sequence += 1
        prefix = self.root / f"process-{self.sequence:05d}"
        command_path = prefix.with_suffix(".command.json")
        stdout = prefix.with_suffix(".stdout.log").open("x", encoding="utf-8")
        stderr = prefix.with_suffix(".stderr.log").open("x", encoding="utf-8")
        command = {"sequence": self.sequence, "utc": utc_now(), "argv": actual_args}
        if self.environment_sha256 is not None:
            command["environment_sha256"] = self.environment_sha256
        write_json(command_path, command)
        try:
            process = subprocess.Popen(
                actual_args,
                text=True,
                stdout=stdout,
                stderr=stderr,
                env=self.environment,
                start_new_session=True,
            )
        except BaseException:
            stdout.close()
            stderr.close()
            raise
        process._aster_stdout = stdout  # type: ignore[attr-defined]
        process._aster_stderr = stderr  # type: ignore[attr-defined]
        process._aster_prefix = prefix  # type: ignore[attr-defined]
        self._owned_processes[id(process)] = process
        return process

    def _close_process_streams(self, process: subprocess.Popen[str]) -> None:
        for stream_name in ("_aster_stdout", "_aster_stderr"):
            stream = getattr(process, stream_name, None)
            if stream is not None and not stream.closed:
                stream.close()

    def _record_process_result(
        self,
        process: subprocess.Popen[str],
        *,
        returncode: int,
        timed_out: bool,
        interrupted: bool,
    ) -> None:
        self._close_process_streams(process)
        result_path = process._aster_prefix.with_suffix(  # type: ignore[attr-defined]
            ".result.json"
        )
        if not result_path.exists():
            receipt = {
                "returncode": returncode,
                "completed_utc": utc_now(),
                "timed_out": timed_out,
            }
            if interrupted:
                receipt["interrupted"] = True
            write_json(result_path, receipt)
        self._owned_processes.pop(id(process), None)

    def wait_process(
        self,
        process: subprocess.Popen[str],
        timeout: float,
        *,
        check: bool = True,
    ) -> int:
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            returncode = process.wait(timeout=5)
            timed_out = True
        self._record_process_result(
            process,
            returncode=returncode,
            timed_out=timed_out,
            interrupted=False,
        )
        if timed_out:
            raise ExperimentError("candidate node exceeded its bounded process deadline")
        if check and returncode != 0:
            raise ExperimentError(f"candidate node exited {returncode}")
        return returncode

    def terminate_owned_processes(self) -> list[int]:
        """Boundedly terminate, wait, and receipt every still-owned process."""

        with deferred_interrupt_signals() as deferred:
            processes = list(self._owned_processes.values())
            for process in processes:
                if process.poll() is None:
                    _signal_process_group(process, signal.SIGTERM)
            for process in processes:
                if id(process) not in self._owned_processes:
                    continue
                timed_out = False
                try:
                    returncode = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _signal_process_group(process, signal.SIGKILL)
                    returncode = process.wait()
                self._record_process_result(
                    process,
                    returncode=returncode,
                    timed_out=timed_out,
                    interrupted=True,
                )
        return deferred


def finalize_processes(
    runner: Runner,
    processes: dict[str, subprocess.Popen[str]] | Sequence[subprocess.Popen[str]],
) -> None:
    """Retain every candidate exit code after its container has been stopped."""

    values = processes.values() if isinstance(processes, dict) else processes
    for process in values:
        try:
            runner.wait_process(process, 5, check=False)
        except ExperimentError:
            # wait_process records a bounded timeout before raising.  Cleanup
            # must continue so one wedged docker exec cannot hide other exits.
            continue


def finalize_failure_evidence(
    root: Path, args: argparse.Namespace, error: BaseException
) -> dict[str, Any] | None:
    """Commit a fail-closed root even when a trial aborts before summary."""

    if not root.is_dir():
        return None
    failure_path = root / "failure.json"
    if not failure_path.exists():
        write_json(
            failure_path,
            {
                "schema": SCHEMA,
                "completed_utc": utc_now(),
                "arm": getattr(args, "arm", None),
                "scenario": getattr(args, "scenario", None),
                "error_type": type(error).__name__,
                "error": str(error),
            },
        )
    index_path = root / "evidence-index.json"
    if index_path.exists():
        index_path = root / "failure-evidence-index.json"
    if not index_path.exists():
        write_json(
            index_path,
            evidence_index(root, excluded_names=frozenset({index_path.name})),
        )
    return {
        "failure": str(failure_path),
        "evidence_index": str(index_path),
        "evidence_index_sha256": sha256_file(index_path),
    }


def docker_available(runner: Runner) -> None:
    runner.run(["docker", "version", "--format", "{{.Server.Version}}"])


def inspect_image(runner: Runner, image: str) -> dict[str, Any] | None:
    if not runner.execute:
        return None
    result = runner.run(["docker", "image", "inspect", image])
    try:
        values = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ExperimentError("Docker image inspection returned invalid JSON") from error
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise ExperimentError("Docker image inspection did not return exactly one image")
    value = values[0]
    image_id = value.get("Id")
    repo_digests = value.get("RepoDigests", [])
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise ExperimentError("Docker image inspection did not expose a content ID")
    if not isinstance(repo_digests, list) or any(
        not isinstance(item, str) for item in repo_digests
    ):
        raise ExperimentError("Docker image inspection returned malformed repo digests")
    return {"id": image_id, "repo_digests": sorted(repo_digests)}


def gate_h_build_argv(image: str) -> list[str]:
    """Return the sole source-build command accepted by the formal Gate-H lane."""

    if not isinstance(image, str) or not image or any(character.isspace() for character in image):
        raise ExperimentError("Gate-H image reference must be a nonempty token")
    return [
        "docker",
        "build",
        "--pull=false",
        "--build-arg",
        "LAB_ASTER_FEATURES=aster-lab/gate-h",
        "--build-arg",
        "LAB_ASTER_BINARY=aster-gate-h",
        "--tag",
        image,
        "--file",
        "lab/Dockerfile",
        ".",
    ]


def gate_h_build_command(image: str) -> str:
    return shlex.join(gate_h_build_argv(image))


def build_and_verify_gate_h_binary(
    runner: Runner,
    *,
    image: str,
    source_binary: Path,
    candidate_commit: str,
    run_id: str,
    build_context: Path,
    signed_source_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the signed tree and bind the supplied binary to the image output."""

    build_argv = gate_h_build_argv(image)
    if (
        not build_context.is_absolute()
        or build_context.is_symlink()
        or not build_context.is_dir()
        or not HEX_64.fullmatch(signed_source_sha256)
    ):
        raise ExperimentError("Gate-H signed source build context is invalid")
    supplied_digest = sha256_file(source_binary)
    runner.run(build_argv, timeout=1_800, cwd=build_context)
    build_sequence = runner.sequence
    image_content = inspect_image(runner, image)
    if image_content is None:
        raise ExperimentError("Gate-H image build produced no inspectable image")

    extraction_container = resource_name(run_id, 0, "build", "extract")
    extracted_binary = runner.root / "gate-h-image-aster-lab"
    extraction_resource = runner.register_docker_resource(
        "container", extraction_container, owner="gate-h-binary-extraction"
    )
    create: subprocess.CompletedProcess[str] | None = None
    create_sequence: int | None = None
    cleanup_receipt: dict[str, Any] | None = None
    cleanup_error: BaseException | None = None
    primary_error: BaseException | None = None
    copy_sequence: int | None = None
    try:
        create = runner.run(
            ["docker", "create", "--name", extraction_container, image]
        )
        create_sequence = runner.sequence
        if not create.stdout.strip():
            raise ExperimentError("Gate-H image extraction created no container ID")
        runner.run(
            [
                "docker",
                "cp",
                f"{extraction_container}:{GATE_H_IMAGE_BINARY_PATH}",
                str(extracted_binary),
            ]
        )
        copy_sequence = runner.sequence
    except BaseException as error:
        primary_error = error
    finally:
        cleanup_receipt, cleanup_error = runner.cleanup_registered_docker_resources(
            reason="gate-h-binary-extraction",
            resources=(extraction_resource,),
        )
    cleanup_sequence = runner.sequence
    cleanup_outcomes = (
        [] if cleanup_receipt is None else cleanup_receipt.get("resources", [])
    )
    cleanup_attempts = (
        []
        if not cleanup_outcomes
        else cleanup_outcomes[0].get("remove_attempts", [])
    )
    cleanup_returncode = (
        None if not cleanup_attempts else cleanup_attempts[-1].get("returncode")
    )
    cleanup_failed = (
        cleanup_error is not None
        or cleanup_receipt is None
        or cleanup_receipt.get("passed") is not True
        or cleanup_returncode != 0
    )
    if primary_error is not None and not isinstance(primary_error, Exception):
        raise primary_error
    if cleanup_error is not None and not isinstance(cleanup_error, Exception):
        raise cleanup_error
    if cleanup_failed:
        message = "Gate-H image extraction container cleanup failed"
        if primary_error is not None:
            raise ExperimentError(
                f"Gate-H image extraction primary failure ({type(primary_error).__name__}: "
                f"{primary_error}); {message}"
            ) from primary_error
        if cleanup_error is not None:
            raise ExperimentError(f"{message}: {cleanup_error}") from cleanup_error
        raise ExperimentError(message)
    if primary_error is not None:
        raise primary_error
    if create_sequence is None or copy_sequence is None:
        raise ExperimentError("Gate-H image extraction lacks a complete command receipt")
    if not extracted_binary.is_file():
        raise ExperimentError(
            f"Gate-H image omits {GATE_H_IMAGE_BINARY_PATH}"
        )
    extracted_digest = sha256_file(extracted_binary)
    if sha256_file(source_binary) != supplied_digest:
        raise ExperimentError("supplied Gate-H binary changed during source build")
    if extracted_digest != supplied_digest:
        raise ExperimentError(
            "supplied Gate-H binary differs from the signed source image build"
        )

    receipt = {
        "schema": GATE_H_BINARY_PROVENANCE_SCHEMA,
        "candidate_commit": candidate_commit,
        "build_argv": build_argv,
        "build_command": shlex.join(build_argv),
        "build_cwd": str(build_context),
        "signed_source_sha256": signed_source_sha256,
        "build_command_sequence": build_sequence,
        "image": image,
        "image_content": image_content,
        "image_binary_path": GATE_H_IMAGE_BINARY_PATH,
        "extracted_binary_file": extracted_binary.name,
        "supplied_binary_sha256": supplied_digest,
        "image_binary_sha256": extracted_digest,
        "extraction": {
            "container": extraction_container,
            "create_sequence": create_sequence,
            "copy_sequence": copy_sequence,
            "cleanup_sequence": cleanup_sequence,
            "cleanup_returncode": cleanup_returncode,
        },
    }
    receipt_path = runner.root / "gate-h-binary-provenance.json"
    write_json(receipt_path, receipt)
    return image_content, {
        "path": receipt_path.name,
        "sha256": sha256_file(receipt_path),
        "binary_sha256": supplied_digest,
        "signed_source_sha256": signed_source_sha256,
    }


def validate_input(
    args: argparse.Namespace, *, allow_existing_root: bool = False
) -> None:
    if args.root.exists() and not allow_existing_root:
        raise ExperimentError(f"evidence root already exists: {args.root}")
    if allow_existing_root and (
        not args.root.is_dir() or args.root.is_symlink()
    ):
        raise ExperimentError(f"evidence root changed at signed handoff: {args.root}")
    binary = args.binary.resolve()
    if not binary.is_file():
        raise ExperimentError(f"candidate binary is absent: {binary}")
    if args.scenario == "gate-h" and args.arm != "native":
        raise ExperimentError("--scenario gate-h is the provider-free native control")
    provider_binary = getattr(args, "provider_binary", None)
    provider_build_command = getattr(args, "provider_build_command", None)
    if args.arm == "libp2p":
        if provider_binary is None or not provider_binary.resolve().is_file():
            raise ExperimentError("libp2p requires an exact --provider-binary")
        if provider_binary.resolve() == binary:
            raise ExperimentError(
                "libp2p requires distinct common-host and provider binary paths"
            )
        if getattr(args, "execute", False) and (
            not isinstance(provider_build_command, str)
            or not provider_build_command.strip()
        ):
            raise ExperimentError(
                "formal libp2p execution requires --provider-build-command"
            )
    elif provider_binary is not None or provider_build_command is not None:
        raise ExperimentError(
            "provider binary/build options apply only to --arm libp2p"
        )
    if args.trials < 1 or args.trials > 30:
        raise ExperimentError("--trials must be in 1..30")
    if args.payload_bytes < 64 or args.payload_bytes > 1_048_576:
        raise ExperimentError("--payload-bytes must be in 64..1048576")
    discovery_source = getattr(args, "discovery_source", None)
    if args.arm in ("iroh", "libp2p"):
        if discovery_source not in ("provider-mdns", "aster-protected"):
            raise ExperimentError(
                f"{args.arm} requires explicit --discovery-source "
                "provider-mdns or aster-protected"
            )
    elif discovery_source is not None:
        raise ExperimentError(
            "--discovery-source applies only to --arm iroh or libp2p"
        )
    if args.scenario == "manual" and args.arm not in ARMS:
        raise ExperimentError("--scenario manual requires a supported provider arm")
    if args.scenario == "gate-h" and args.trials != 10:
        raise ExperimentError("--scenario gate-h requires exactly 10 trials")
    if args.scenario == "gate-h" and args.payload_bytes != 1_048_576:
        raise ExperimentError("--scenario gate-h requires a 1048576-byte payload")
    if args.scenario == "gate-h" and getattr(args, "execute", False):
        expected_build = gate_h_build_command(args.image)
        if getattr(args, "build_command", None) != expected_build:
            raise ExperimentError(
                "formal Gate-H execution requires the exact allowlisted build command: "
                f"{expected_build}"
            )
        docker_binary = getattr(args, "docker_binary", None)
        docker_buildx_binary = getattr(args, "docker_buildx_binary", None)
        git_binary = getattr(args, "git_binary", None)
        ssh_keygen_binary = getattr(args, "ssh_keygen_binary", None)
        ssh_binary = getattr(args, "ssh_binary", None)
        allowed_signers = getattr(args, "allowed_signers", None)
        signer_principal = getattr(args, "signer_principal", None)
        docker_host = getattr(args, "docker_host", None)
        if not isinstance(docker_binary, Path) or not docker_binary.is_absolute():
            raise ExperimentError("formal Gate H requires absolute --docker-binary")
        if (
            not isinstance(docker_buildx_binary, Path)
            or not docker_buildx_binary.is_absolute()
        ):
            raise ExperimentError(
                "formal Gate H requires absolute --docker-buildx-binary"
            )
        if not isinstance(git_binary, Path) or not git_binary.is_absolute():
            raise ExperimentError("formal Gate H requires absolute --git-binary")
        if not isinstance(ssh_keygen_binary, Path) or not ssh_keygen_binary.is_absolute():
            raise ExperimentError("formal Gate H requires absolute --ssh-keygen-binary")
        if not isinstance(ssh_binary, Path) or not ssh_binary.is_absolute():
            raise ExperimentError("formal Gate H requires absolute --ssh-binary")
        if not isinstance(allowed_signers, Path) or not allowed_signers.is_absolute():
            raise ExperimentError("formal Gate H requires absolute --allowed-signers")
        if (
            not isinstance(signer_principal, str)
            or gate_h_signature.SAFE_PRINCIPAL.fullmatch(signer_principal) is None
        ):
            raise ExperimentError("formal Gate H requires a safe --signer-principal")
        if not isinstance(docker_host, str) or not docker_host.startswith("unix://"):
            raise ExperimentError("formal Gate H requires explicit --docker-host")
    fault_receipt = getattr(args, "gate_h_fault_receipt", None)
    if args.scenario == "gate-h":
        if fault_receipt is None or not fault_receipt.resolve().is_file():
            raise ExperimentError("--scenario gate-h requires --gate-h-fault-receipt")
    elif fault_receipt is not None:
        raise ExperimentError("--gate-h-fault-receipt applies only to --scenario gate-h")
    maximum_duration = 1_200_000 if args.scenario == "idle" else 60_000
    if args.duration_ms < 1_000 or args.duration_ms > maximum_duration:
        raise ExperimentError(
            f"--duration-ms must be in 1000..{maximum_duration} for {args.scenario}"
        )
    if args.scenario == "gate-h" and args.duration_ms < 6_000:
        raise ExperimentError("--scenario gate-h requires at least 6000 ms per phase")
    if args.scenario == "idle" and (
        args.settle_ms < 0 or args.settle_ms >= args.duration_ms
    ):
        raise ExperimentError("--settle-ms must be nonnegative and below --duration-ms")


def resource_name(run_id: str, trial: int, phase: str, role: str | None = None) -> str:
    suffix = f"-{role}" if role else ""
    value = f"aster-mesh-{run_id}-t{trial:02d}-{phase}{suffix}"
    if not RESOURCE.fullmatch(value):
        raise ExperimentError(f"generated invalid resource name: {value}")
    return value


def network_spec(arm: str, trial: int, phase: str) -> tuple[str, str, str]:
    # Networks are removed before reuse, but distinct trial octets make the
    # topology receipts easier to audit and prevent accidental cross-trial paths.
    arm_base = {"native": 10, "iroh": 80, "libp2p": 150}[arm]
    third = arm_base + trial * 2 + (1 if phase in ("bc", "live-bc") else 0)
    if third > 249:
        raise ExperimentError("trial index exhausts the reserved experiment CIDR")
    second = {
        "disabled": 254,
        "idle": 252,
        "multi": 251,
        "live-ab": 250,
        "live-bc": 250,
    }.get(phase, 253)
    return (
        f"10.{second}.{third}.0/24",
        f"10.{second}.{third}.1",
        f"10.{second}.{third}.255",
    )


def create_network(
    runner: Runner, arm: str, run_id: str, trial: int, phase: str
) -> tuple[str, str, str]:
    name = resource_name(run_id, trial, phase)
    subnet, gateway, broadcast = network_spec(arm, trial, phase)
    runner.run(
        [
            "docker",
            "network",
            "create",
            "--internal",
            "--driver",
            "bridge",
            "--subnet",
            subnet,
            "--gateway",
            gateway,
            "--label",
            "com.defenseunicorns.aster-lab.managed=true",
            "--label",
            f"com.defenseunicorns.aster-lab.run-id={run_id}",
            "--label",
            f"com.defenseunicorns.aster-lab.role={phase}",
            name,
        ]
    )
    return name, gateway, broadcast


def create_node_container(
    runner: Runner,
    *,
    args: argparse.Namespace,
    run_id: str,
    trial: int,
    phase: str,
    role: str,
    node_root: Path,
    bundle: Path,
    network: str,
    address: str,
    gateway: str,
) -> str:
    name = resource_name(run_id, trial, phase, role)
    capabilities = ["--cap-add", "NET_ADMIN"]
    if args.capture:
        capabilities.extend(
            [
                "--cap-add",
                "NET_RAW",
                "--cap-add",
                "SETUID",
                "--cap-add",
                "SETGID",
            ]
        )
    mounts = [
        "--mount",
        f"type=bind,src={args.binary.resolve()},dst=/experiment/aster-lab,readonly",
    ]
    if args.arm == "libp2p":
        mounts.extend(
            [
                "--mount",
                (
                    f"type=bind,src={args.provider_binary.resolve()},"
                    "dst=/experiment/aster-libp2p-node,readonly"
                ),
            ]
        )
    runner.run(
        [
            "docker",
            "run",
            "--detach",
            "--pull=never",
            "--name",
            name,
            "--hostname",
            role,
            "--network",
            network,
            "--ip",
            address,
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--pids-limit",
            "256",
            "--memory",
            "512m",
            "--cpus",
            "1",
            "--cap-drop",
            "ALL",
            *capabilities,
            "--security-opt",
            "no-new-privileges",
            "--label",
            "com.defenseunicorns.aster-lab.managed=true",
            "--label",
            f"com.defenseunicorns.aster-lab.run-id={run_id}",
            "--label",
            f"com.defenseunicorns.aster-lab.role={role}",
            *mounts,
            "--mount",
            f"type=bind,src={node_root.resolve()},dst=/lab/node",
            "--mount",
            f"type=bind,src={bundle.resolve()},dst=/lab/node.bundle,readonly",
            "--entrypoint",
            "/usr/bin/sleep",
            args.image,
            "infinity",
        ]
    )
    runner.run(
        [
            "docker",
            "exec",
            name,
            "/usr/sbin/ip",
            "route",
            "add",
            "default",
            "via",
            gateway,
            "dev",
            "eth0",
        ]
    )
    return name


def node_exec_command(
    *,
    args: argparse.Namespace,
    container: str,
    invocation: str,
    expected_peer: str,
    broadcast: str,
    discovery_enabled: bool = True,
    manual_peers: str = "",
    emission_mode: str | None = None,
    duration_ms: int | None = None,
    gate_h_control: str | None = None,
    gate_h_stale_target_peer: str | None = None,
    durable_item_probe: str | None = None,
) -> list[str]:
    if emission_mode is None:
        emission_mode = "normal" if discovery_enabled or manual_peers else "constrained"
    if emission_mode not in (
        "normal",
        "constrained",
        "receive-only",
        GATE_H_FLASH_ONLY_EMISSION_MODE,
    ):
        raise ExperimentError(f"unsupported emission mode: {emission_mode}")
    if (gate_h_control is None) != (gate_h_stale_target_peer is None):
        raise ExperimentError("Gate-H control path and stale target must be configured together")
    if gate_h_control is not None and (
        args.arm != "native"
        or emission_mode != GATE_H_FLASH_ONLY_EMISSION_MODE
        or gate_h_control != GATE_H_CONTROL_PATH
        or not isinstance(gate_h_stale_target_peer, str)
        or not HEX_64.fullmatch(gate_h_stale_target_peer)
    ):
        raise ExperimentError("Gate-H live-control command is malformed or non-native")
    if durable_item_probe is not None and (
        args.arm != "native" or not HEX_64.fullmatch(durable_item_probe)
    ):
        raise ExperimentError("native durable ItemID probe is malformed")
    if emission_mode == GATE_H_FLASH_ONLY_EMISSION_MODE and gate_h_control is None:
        raise ExperimentError("flash-only emission is reserved for paired Gate-H control")
    executable = (
        "/experiment/aster-libp2p-node"
        if args.arm == "libp2p"
        else "/experiment/aster-lab"
    )
    command = [
        "docker",
        "exec",
        container,
        "/usr/bin/setpriv",
        "--nnp",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        executable,
        NODE_COMMAND[args.arm],
        "--root",
        "/lab/node",
        "--bundle",
        "/lab/node.bundle",
        "--invocation",
        invocation,
        "--expected-peers",
        expected_peer,
        "--duration-ms",
        str(args.duration_ms if duration_ms is None else duration_ms),
        "--max-candidates",
        "8",
        "--max-active-contacts",
        "2",
    ]
    if args.arm == "native":
        command.extend(
            [
                "--discovery-token",
                "/lab/node/discovery.token",
                "--bind",
                "0.0.0.0:47101",
                "--discovery-target",
                f"{broadcast}:47101",
            ]
        )
    if args.arm == "native":
        command.extend(
            [
                "--discovery-enabled",
                str(discovery_enabled).lower(),
                "--emission-mode",
                emission_mode,
            ]
        )
        if manual_peers:
            command.extend(["--manual-peers", manual_peers])
        if gate_h_control is not None:
            command.extend(
                [
                    "--gate-h-control",
                    gate_h_control,
                    "--gate-h-stale-target-peer",
                    gate_h_stale_target_peer,
                ]
            )
        if durable_item_probe is not None:
            command.extend(["--durable-item-probe", durable_item_probe])
    elif args.arm == "iroh":
        discovery_source = (
            getattr(args, "discovery_source", None) or "aster-protected"
        )
        command.extend(
            [
                "--bind",
                "0.0.0.0:47101",
                "--discovery-enabled",
                str(discovery_enabled).lower(),
                "--discovery-source",
                discovery_source,
                "--emission-mode",
                emission_mode,
            ]
        )
        if discovery_source == "aster-protected":
            command.extend(
                [
                    "--discovery-token",
                    "/lab/node/discovery.token",
                    "--discovery-bind",
                    "0.0.0.0:47102",
                    "--discovery-target",
                    f"{broadcast}:47102",
                ]
            )
        if manual_peers:
            command.extend(["--manual-peers", manual_peers])
    elif args.arm == "libp2p":
        discovery_source = (
            getattr(args, "discovery_source", None) or "provider-mdns"
        )
        command.extend(
            [
                "--bind",
                "0.0.0.0:47101",
                "--discovery-enabled",
                str(discovery_enabled).lower(),
                "--discovery-source",
                discovery_source,
                "--emission-mode",
                emission_mode,
            ]
        )
        if discovery_source == "aster-protected":
            command.extend(
                [
                    "--discovery-token",
                    "/lab/node/discovery.token",
                    "--discovery-target",
                    f"{broadcast}:47101",
                ]
            )
        if manual_peers:
            command.extend(["--manual-peers", manual_peers])
    return command


def gate_h_process_durations(duration_ms: int) -> dict[str, int]:
    """Return the bounded process windows for one two-phase Gate-H trial."""

    if isinstance(duration_ms, bool) or not isinstance(duration_ms, int) or duration_ms <= 0:
        raise ExperimentError("Gate-H duration must be a positive integer")
    return {
        "a_pre": duration_ms,
        "b_pre": duration_ms,
        "c_continuous": duration_ms * 2 + 5_000,
        "b_post": duration_ms,
    }


def gate_h_relay_manual_peers(
    identities: dict[str, str], addresses: dict[str, str]
) -> str:
    """Return B's exact dual-segment pre-restart route set."""

    return (
        f"{identities['a']}@{addresses['a']}:47101,"
        f"{identities['c']}@{addresses['c']}:47101"
    )


def initialize_iroh_carrier(
    runner: Runner, args: argparse.Namespace, trial_root: Path, role: str
) -> str:
    """Create/read one provider key offline without granting Aster authority."""
    result = runner.run(
        [
            "docker",
            "run",
            "--rm",
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
            f"type=bind,src={args.binary.resolve()},dst=/experiment/aster-lab,readonly",
            "--mount",
            f"type=bind,src={trial_root.resolve()},dst=/lab/run",
            "--entrypoint",
            "/experiment/aster-lab",
            args.image,
            "mesh-iroh-carrier-id",
            "--root",
            f"/lab/run/{role}",
        ],
        timeout=120,
    )
    endpoint_id = result.stdout.strip()
    if not IROH_ENDPOINT_ID.fullmatch(endpoint_id):
        raise ExperimentError("Iroh carrier initializer emitted a malformed EndpointId")
    return endpoint_id


def run_offline(
    runner: Runner,
    args: argparse.Namespace,
    trial_root: Path,
    command: Sequence[str],
    *,
    container_name: str | None = None,
) -> dict[str, Any]:
    resource: tuple[str, str] | None = None
    if container_name is not None:
        resource = runner.register_docker_resource(
            "container",
            container_name,
            owner=f"offline:{command[0] if command else 'unknown'}",
        )
    name_args = [] if container_name is None else ["--name", container_name]
    result: subprocess.CompletedProcess[str] | None = None
    primary_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    try:
        result = runner.run(
            [
                "docker",
                "run",
                "--rm",
                *name_args,
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
                f"type=bind,src={args.binary.resolve()},dst=/experiment/aster-lab,readonly",
                "--mount",
                f"type=bind,src={trial_root.resolve()},dst=/lab/run",
                "--entrypoint",
                "/experiment/aster-lab",
                args.image,
                *command,
            ],
            timeout=120,
        )
    except BaseException as error:
        primary_error = error
    finally:
        if resource is not None:
            _receipt, cleanup_error = runner.cleanup_registered_docker_resources(
                reason=f"offline:{command[0] if command else 'unknown'}",
                resources=(resource,),
            )
    if primary_error is not None:
        raise primary_error
    if cleanup_error is not None:
        raise cleanup_error
    if result is None:
        raise ExperimentError("offline command lacks a completed process receipt")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ExperimentError(f"offline command emitted invalid JSON: {result.stdout}") from error
    if not isinstance(value, dict):
        raise ExperimentError("offline command receipt is not a JSON object")
    return value


def inspect_topology(runner: Runner, network: str, containers: Sequence[str]) -> dict[str, Any]:
    network_value = json.loads(runner.run(["docker", "network", "inspect", network]).stdout)
    container_values = [
        json.loads(runner.run(["docker", "inspect", container]).stdout)[0]
        for container in containers
    ]
    return {
        "network": network_value[0],
        "containers": container_values,
    }


def remove_resources(runner: Runner, containers: Sequence[str], network: str) -> None:
    for container in containers:
        runner.run(["docker", "rm", "--force", container], check=False)
    runner.run(["docker", "network", "rm", network], check=False)


def cleanup_gate_h_resources(
    runner: Runner,
    *,
    trial_root: Path,
    trial: int,
    containers: Sequence[str],
    networks: Sequence[str | None],
    primary_error: BaseException | None = None,
) -> None:
    """Remove every Gate-H resource, retaining all outcomes before failing closed."""

    outcomes: list[dict[str, Any]] = []
    first_cleanup_error: BaseException | None = None
    commands = (
        *(
            ("container", container, ["docker", "rm", "--force", container])
            for container in containers
        ),
        *(
            ("network", network, ["docker", "network", "rm", network])
            for network in networks
            if network is not None
        ),
    )
    with deferred_interrupt_signals() as deferred:
        for kind, name, command in commands:
            actual_command = (
                runner.resolve_args(command)
                if hasattr(runner, "resolve_args")
                else list(command)
            )
            result: subprocess.CompletedProcess[str] | None = None
            attempt_errors: list[dict[str, str]] = []
            for _attempt in range(2):
                try:
                    result = runner.run(command, check=False)
                    break
                except BaseException as error:
                    if first_cleanup_error is None:
                        first_cleanup_error = error
                    attempt_errors.append(
                        {
                            "error_type": type(error).__name__,
                            "error": str(error),
                        }
                    )
            if result is None:
                outcome: dict[str, Any] = {
                    "argv": actual_command,
                    "returncode": 124,
                    "error": "cleanup command did not complete after bounded retry",
                }
            else:
                outcome = {
                    "argv": actual_command,
                    "returncode": result.returncode,
                }
                if result.returncode == 0 and hasattr(
                    runner, "settle_docker_resource"
                ):
                    runner.settle_docker_resource(kind, name)
                elif hasattr(runner, "confirm_docker_resource_absent"):
                    try:
                        runner.confirm_docker_resource_absent(kind, name)
                    except BaseException as error:
                        if first_cleanup_error is None:
                            first_cleanup_error = error
                        attempt_errors.append(
                            {
                                "error_type": type(error).__name__,
                                "error": str(error),
                            }
                        )
            if attempt_errors:
                outcome["interrupted_attempts"] = attempt_errors
            outcomes.append(outcome)
        passed = bool(outcomes) and all(
            outcome["returncode"] == 0 for outcome in outcomes
        )
        write_json(
            trial_root / "cleanup.json",
            {
                "schema": GATE_H_CLEANUP_SCHEMA,
                "trial": trial,
                "passed": passed,
                "primary_error": None
                if primary_error is None
                else {
                    "error_type": type(primary_error).__name__,
                    "error": str(primary_error),
                },
                "commands": outcomes,
            },
        )

    if primary_error is not None and not isinstance(primary_error, Exception):
        return
    if first_cleanup_error is not None and not isinstance(
        first_cleanup_error, Exception
    ):
        raise first_cleanup_error
    if deferred:
        raise ControlledInterruption(deferred[0])
    if not passed:
        cleanup_message = "Gate-H container or network cleanup failed"
        if primary_error is not None:
            if not isinstance(primary_error, Exception):
                return
            raise ExperimentError(
                f"Gate-H primary failure ({type(primary_error).__name__}: "
                f"{primary_error}); {cleanup_message}"
            ) from primary_error
        raise ExperimentError(cleanup_message)


def finalize_gate_h_trial_resources(
    runner: Runner,
    *,
    trial_root: Path,
    trial: int,
    processes: Sequence[subprocess.Popen[str]],
    containers: Sequence[str],
    networks: Sequence[str | None],
    primary_error: BaseException | None,
) -> None:
    """Defer first and repeated signals until all process/resource receipts exist."""

    finalization_error: BaseException | None = None
    with deferred_interrupt_signals() as deferred:
        try:
            finalize_processes(runner, processes)
        except BaseException as error:
            finalization_error = error
        try:
            runner.terminate_owned_processes()
        except BaseException as error:
            if finalization_error is None:
                finalization_error = error
        try:
            cleanup_gate_h_resources(
                runner,
                trial_root=trial_root,
                trial=trial,
                containers=containers,
                networks=networks,
                primary_error=primary_error
                if primary_error is not None
                else finalization_error,
            )
        except BaseException as error:
            if finalization_error is None:
                finalization_error = error

    if primary_error is not None and not isinstance(primary_error, Exception):
        return
    if finalization_error is not None and not isinstance(
        finalization_error, Exception
    ):
        raise finalization_error
    if deferred:
        raise ControlledInterruption(deferred[0])
    if finalization_error is not None:
        raise finalization_error


def copy_discovery_token(trial_root: Path, role: str) -> None:
    source = trial_root / "private" / "discovery.token"
    destination = trial_root / role / "discovery.token"
    if destination.exists():
        return
    destination.write_bytes(source.read_bytes())
    destination.chmod(0o600)


def needs_discovery_token(args: argparse.Namespace) -> bool:
    return (
        args.arm == "native"
        or getattr(args, "discovery_source", None) == "aster-protected"
    )


def provider_receipt_digest(args: argparse.Namespace) -> str | None:
    """Return the frozen provider digest required in corrected v3 receipts."""

    if args.arm != "libp2p":
        return None
    value = getattr(args, "provider_binary_sha256", None)
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ExperimentError("libp2p execution has no frozen provider binary digest")
    return value


def validate_provider_profile(
    receipt: dict[str, Any],
    *,
    arm: str,
    discovery_source: str | None,
    provider_binary_sha256: str | None = None,
    native_receipt_mode: Literal["final", "live-status"] = "final",
) -> None:
    """Fail closed when provider evidence does not prove the selected profile."""
    if arm == "native":
        if provider_binary_sha256 is not None:
            raise ExperimentError("native receipt unexpectedly selected a provider binary")
        validate_native_shared_node_profile(
            receipt, mode=native_receipt_mode
        )
        return
    if arm == "iroh":
        if provider_binary_sha256 is not None:
            raise ExperimentError("Iroh receipt unexpectedly selected a provider binary")
        if receipt.get("schema") != "aster-lab-iroh-mesh-node/v2":
            raise ExperimentError("Iroh receipt does not use the required v2 schema")
        if receipt.get("candidate_source") != discovery_source:
            raise ExperimentError(
                "Iroh receipt candidate source differs from the selected profile"
            )
        if receipt.get("public_defaults") is not False:
            raise ExperimentError("Iroh receipt does not prove public defaults absent")
        if receipt.get("pre_incoming_boundedness_blocker") != IROH_PRE_INCOMING_BLOCKER:
            raise ExperimentError("Iroh receipt drops the pre-Incoming boundedness blocker")
        if receipt.get("phase1_scale_eligible") is not False:
            raise ExperimentError("Iroh receipt overclaims Phase-1 scale eligibility")
        if not isinstance(receipt.get("path_events_integrated"), bool):
            raise ExperimentError("Iroh receipt drops path-event integration status")
        if discovery_source == "aster-protected":
            expected = {
                "iroh_mdns": False,
                "iroh_mdns_compiled": False,
                "discovery_announcement_count_observable": True,
                "mdns_boundedness_blocker": None,
                "requirements_eligible_discovery": True,
            }
            profile = "protected"
        elif discovery_source == "provider-mdns":
            expected = {
                "iroh_mdns": True,
                "iroh_mdns_compiled": True,
                "discovery_announcement_count_observable": False,
                "mdns_boundedness_blocker": (
                    "uncapped-pre-host-iroh-mdns-address-cache-and-callback-tasks"
                ),
                "requirements_eligible_discovery": False,
            }
            profile = "technical provider-mDNS"
        else:
            raise ExperimentError("Iroh receipt has no selected provider profile")
        for field, expected_value in expected.items():
            if receipt.get(field) != expected_value:
                raise ExperimentError(
                    f"Iroh receipt does not prove the {profile} profile: {field}"
                )
        return
    if arm != "libp2p":
        raise ExperimentError(f"unknown provider arm: {arm}")
    if receipt.get("schema") != LIBP2P_SHARED_NODE_SCHEMA:
        raise ExperimentError("libp2p receipt does not use the required v3 schema")
    if (
        not isinstance(provider_binary_sha256, str)
        or not HEX_64.fullmatch(provider_binary_sha256)
    ):
        raise ExperimentError("libp2p receipt has no frozen provider binary digest")
    receipt_provider_sha256 = receipt.get("provider_binary_sha256")
    if (
        not isinstance(receipt_provider_sha256, str)
        or not HEX_64.fullmatch(receipt_provider_sha256)
    ):
        raise ExperimentError("libp2p receipt has no valid provider_binary_sha256")
    if receipt_provider_sha256 != provider_binary_sha256:
        raise ExperimentError(
            "libp2p receipt provider_binary_sha256 differs from the frozen provider"
        )
    if receipt.get("candidate_source") != discovery_source:
        raise ExperimentError(
            "libp2p receipt candidate source differs from the selected profile"
        )
    if not isinstance(receipt.get("libp2p_mdns_enabled"), bool):
        raise ExperimentError(
            "libp2p receipt does not classify provider-mDNS runtime enablement"
        )
    if discovery_source == "aster-protected":
        expected = {
            "bounded_candidate_source": True,
            "protected_source_compiled_without_mdns": True,
            "libp2p_mdns": False,
            "libp2p_mdns_enabled": False,
            "mdns_rustsec_blocker": None,
            "provider_mdns_announcement_count_observable": False,
        }
        profile = "protected"
    elif discovery_source == "provider-mdns":
        expected = {
            "bounded_candidate_source": False,
            "protected_source_compiled_without_mdns": False,
            "libp2p_mdns": True,
            "mdns_rustsec_blocker": "RUSTSEC-2026-0119",
            "provider_mdns_announcement_count_observable": False,
        }
        profile = "technical provider-mDNS"
    else:
        raise ExperimentError("libp2p receipt has no selected provider profile")
    for field, value in expected.items():
        actual = receipt.get(field)
        if isinstance(value, bool) or value is None:
            matches = actual is value
        else:
            matches = isinstance(actual, type(value)) and actual == value
        if not matches:
            raise ExperimentError(
                f"libp2p receipt does not prove the {profile} profile: {field}"
            )


def _strict_nonnegative_integer(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ExperimentError(f"native receipt {field} must be a nonnegative integer")
    return value


def _native_resource_object(receipt: dict[str, Any], field: str) -> dict[str, int]:
    value = receipt.get(field)
    if not isinstance(value, dict):
        raise ExperimentError(f"native receipt {field} must be an object")
    if set(value) != set(NODE_RESOURCE_FIELDS):
        raise ExperimentError(f"native receipt {field} has the wrong resource fields")
    return {
        name: _strict_nonnegative_integer(value[name], field=f"{field}.{name}")
        for name in NODE_RESOURCE_FIELDS
    }


def validate_native_shared_node_profile(
    receipt: dict[str, Any],
    *,
    mode: Literal["final", "live-status"] = "final",
) -> None:
    """Require the provider-free shared-node Gate-H evidence contract."""
    if mode not in ("final", "live-status"):
        raise ExperimentError("native receipt validation mode is unsupported")
    if receipt.get("schema") != NATIVE_SHARED_NODE_SCHEMA:
        raise ExperimentError("native receipt does not use the shared-node v2 schema")
    if receipt.get("durable_authority_open_count") != 1:
        raise ExperimentError("native receipt does not prove one durable authority open")
    if receipt.get("frame_counter_scope") != "aster_protocol":
        raise ExperimentError("native receipt does not scope frame counters to Aster")
    counters = {
        field: _strict_nonnegative_integer(receipt.get(field), field=field)
        for field in NATIVE_PROTOCOL_COUNTER_FIELDS
    }
    legacy_frames_received = _strict_nonnegative_integer(
        receipt.get("frames_received"), field="frames_received"
    )
    legacy_frames_sent = _strict_nonnegative_integer(
        receipt.get("frames_sent"), field="frames_sent"
    )
    if (
        legacy_frames_received != counters["aster_frames_received"]
        or legacy_frames_sent != counters["aster_frames_sent"]
    ):
        raise ExperimentError("native receipt legacy frame aliases differ from Aster frames")
    checks = counters["authorization_generation_checks"]
    if (
        counters["authorization_generation_mismatches"]
        + counters["authorization_generation_unavailable"]
        > checks
    ):
        raise ExperimentError(
            "native receipt authorization generation outcomes exceed checks"
        )
    for field in NATIVE_SHARED_NODE_CONSTRUCTION_FIELDS:
        if receipt.get(field) != 1:
            raise ExperimentError(
                f"native receipt does not prove exactly one {field}"
            )
    admitted = receipt.get("admitted_peers")
    if (
        not isinstance(admitted, list)
        or any(not isinstance(peer, str) or not HEX_64.fullmatch(peer) for peer in admitted)
        or len(admitted) != len(set(admitted))
    ):
        raise ExperimentError("native receipt has malformed admitted peer evidence")

    limits = _native_resource_object(receipt, "node_resource_limits")
    current = _native_resource_object(receipt, "node_resource_current")
    high_water = _native_resource_object(receipt, "node_resource_high_water")
    if checks == 0:
        authenticated = receipt.get("authenticated_peers")
        admitted_contact_high_water = _strict_nonnegative_integer(
            receipt.get("admitted_contact_high_water"),
            field="admitted_contact_high_water",
        )
        empty_pre_admission = (
            mode == "live-status"
            and authenticated == []
            and admitted == []
            and admitted_contact_high_water == 0
            and current["admitted_contacts"] == 0
            and high_water["admitted_contacts"] == 0
        )
        if not empty_pre_admission:
            raise ExperimentError(
                "native receipt performed no authorization generation checks"
            )
    for field in NODE_RESOURCE_FIELDS:
        if current[field] > high_water[field] or high_water[field] > limits[field]:
            raise ExperimentError(
                f"native receipt node resource ordering is invalid for {field}"
            )
    for field in NODE_RESOURCE_FIELDS[:-1]:
        if limits[field] == 0:
            raise ExperimentError(f"native receipt node resource limit is zero for {field}")
    if limits["relay_reservations"] != 0:
        raise ExperimentError("native control unexpectedly reserves connectivity relays")
    if (
        limits["inbound_bytes"] != GATE_H_NODE_BUFFER_BYTES
        or limits["outbound_bytes"] != GATE_H_NODE_BUFFER_BYTES
    ):
        raise ExperimentError("native receipt does not prove the Gate-H aggregate byte ceilings")
    _strict_nonnegative_integer(
        receipt.get("node_resource_rejected_claims"),
        field="node_resource_rejected_claims",
    )
    rejections = _native_resource_object(receipt, "node_resource_rejections")
    if sum(rejections.values()) != receipt["node_resource_rejected_claims"]:
        raise ExperimentError(
            "native receipt aggregate resource rejections differ from per-category counts"
        )


def validate_gate_h_native_receipt(
    receipt: dict[str, Any], *, label: str, expected_item_id: str
) -> None:
    """Require the exact clean native accounting contract for one Gate-H process."""

    if receipt.get("schema") != NATIVE_SHARED_NODE_SCHEMA:
        raise ExperimentError(f"{label} does not use the native v2 receipt schema")
    validate_native_shared_node_profile(receipt)
    limits = _native_resource_object(receipt, "node_resource_limits")
    if limits != GATE_H_NATIVE_RESOURCE_LIMITS:
        raise ExperimentError(f"{label} has the wrong exact native resource limits")
    current = _native_resource_object(receipt, "node_resource_current")
    high_water = _native_resource_object(receipt, "node_resource_high_water")
    for field, floor in GATE_H_NATIVE_PROVIDER_BASE.items():
        if current[field] < floor:
            raise ExperimentError(
                f"{label} does not retain the native provider base lease for {field}"
            )

    admitted_high_water = _strict_nonnegative_integer(
        receipt.get("admitted_contact_high_water"),
        field="admitted_contact_high_water",
    )
    for field in NODE_RESOURCE_FIELDS:
        floor = GATE_H_NATIVE_PROVIDER_BASE.get(field, 0) + (
            admitted_high_water * GATE_H_NATIVE_ADMITTED_CONTACT.get(field, 0)
        )
        if high_water[field] < floor:
            raise ExperimentError(
                f"{label} node resource high-water omits admitted-contact {field}"
            )

    for field in GATE_H_CLEAN_ZERO_COUNTERS:
        if _strict_nonnegative_integer(receipt.get(field), field=field) != 0:
            raise ExperimentError(f"{label} is not clean: {field} is nonzero")
    unauthorized = receipt.get("unauthorized_peers")
    if not isinstance(unauthorized, list) or unauthorized:
        raise ExperimentError(f"{label} is not clean: unauthorized peers were retained")
    rejections = _native_resource_object(receipt, "node_resource_rejections")
    if any(rejections.values()):
        raise ExperimentError(f"{label} is not clean: node resource rejection is nonzero")
    if not HEX_64.fullmatch(expected_item_id):
        raise ExperimentError(f"{label} expected ItemID is malformed")
    if receipt.get("durable_item_probe_id") != expected_item_id:
        raise ExperimentError(f"{label} observed the wrong durable ItemID")
    if receipt.get("durable_item_present") is not True:
        raise ExperimentError(f"{label} did not observe the exact durable ItemID")


def prepared_gate_h_authorization_control(
    prepare: dict[str, Any], trial_root: Path, identities: dict[str, str]
) -> dict[str, Any]:
    """Bind the node-local signed control bytes to the prepare receipt."""

    if not isinstance(prepare, dict):
        raise ExperimentError("Gate-H authorization control receipt is not an object")
    control = {
        field: prepare.get(field)
        for field in (
            "authorization_control_id",
            "authorization_control_subject",
            "authorization_control_sha256",
            "authorization_control_bytes",
        )
    }
    for field in (
        "authorization_control_id",
        "authorization_control_subject",
        "authorization_control_sha256",
    ):
        if not isinstance(control[field], str) or not HEX_64.fullmatch(control[field]):
            raise ExperimentError(f"Gate-H preparation emitted malformed {field}")
    if control["authorization_control_id"] != control["authorization_control_sha256"]:
        raise ExperimentError("Gate-H control ID is not the sealed control SHA-256")
    if control["authorization_control_subject"] in set(identities.values()):
        raise ExperimentError("Gate-H control subject aliases a topology identity")
    control_bytes = control["authorization_control_bytes"]
    if (
        isinstance(control_bytes, bool)
        or not isinstance(control_bytes, int)
        or control_bytes < 1
        or control_bytes > 1_048_576
    ):
        raise ExperimentError("Gate-H preparation emitted an invalid control byte count")
    path = trial_root / "b" / "gate-h-authorization-control.bin"
    if path.is_symlink() or not path.is_file():
        raise ExperimentError("Gate-H prepared control is absent, irregular, or a symlink")
    if path.stat().st_mode & 0o777 != 0o600:
        raise ExperimentError("Gate-H prepared control does not have mode 0600")
    if path.stat().st_size != control_bytes or sha256_file(path) != control[
        "authorization_control_sha256"
    ]:
        raise ExperimentError("Gate-H prepared control differs from its receipt")
    return control


def _unique_gate_h_event(
    events: Sequence[dict[str, Any]],
    event_name: str,
    *,
    label: str,
    predicate: Any = None,
) -> tuple[int, dict[str, Any]]:
    matches = [
        (index, event)
        for index, event in enumerate(events)
        if event.get("event") == event_name
        and (predicate is None or predicate(event))
    ]
    if len(matches) != 1:
        raise ExperimentError(
            f"{label} must contain exactly one {event_name} event, got {len(matches)}"
        )
    return matches[0]


def validate_gate_h_live_control_evidence(
    *,
    control: dict[str, Any],
    identities: dict[str, str],
    receipts: dict[str, dict[str, Any]],
    b_events: Sequence[dict[str, Any]],
    c_events: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    """Validate the real-process signed-control/stale-frame/fresh-progress chain."""

    if set(identities) != {"a", "b", "c"} or any(
        not isinstance(identity, str) or not HEX_64.fullmatch(identity)
        for identity in identities.values()
    ):
        raise ExperimentError("Gate-H live control has malformed topology identities")
    if set(receipts) != {"a", "b_pre", "b_post", "c"}:
        raise ExperimentError("Gate-H live control has the wrong receipt roles")
    if not isinstance(control, dict) or set(control) != {
        "authorization_control_id",
        "authorization_control_subject",
        "authorization_control_sha256",
        "authorization_control_bytes",
    }:
        raise ExperimentError("Gate-H live control has a malformed control binding")
    for field in (
        "authorization_control_id",
        "authorization_control_subject",
        "authorization_control_sha256",
    ):
        if not isinstance(control.get(field), str) or not HEX_64.fullmatch(control[field]):
            raise ExperimentError(f"Gate-H live control has malformed {field}")
    if control["authorization_control_id"] != control["authorization_control_sha256"]:
        raise ExperimentError("Gate-H live control ID is not its sealed-byte SHA-256")
    if control["authorization_control_subject"] in set(identities.values()):
        raise ExperimentError("Gate-H live control subject aliases a topology identity")
    control_bytes = control.get("authorization_control_bytes")
    if (
        isinstance(control_bytes, bool)
        or not isinstance(control_bytes, int)
        or control_bytes < 1
        or control_bytes > 1_048_576
    ):
        raise ExperimentError("Gate-H live control has an invalid byte count")

    generations: dict[str, int] = {}
    for role, receipt in receipts.items():
        generations[role] = _strict_nonnegative_integer(
            receipt.get("authorization_generation_current"),
            field=f"{role}.authorization_generation_current",
        )
    if generations["b_pre"] != 1 or generations["c"] != 1:
        raise ExperimentError("Gate-H B-pre and continuous C must both finish at generation 1")
    if generations["a"] not in (0, 1) or generations["b_post"] != 0:
        raise ExperimentError("Gate-H A or fresh B-post has an impossible generation")

    defaults = {
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
    }
    for role in ("a", "b_post", "c"):
        if any(receipts[role].get(field) != expected for field, expected in defaults.items()):
            raise ExperimentError(f"Gate-H {role} unexpectedly claims local control evidence")

    b_receipt = receipts["b_pre"]
    carrier_ids: dict[str, str] = {}
    for role in ("b_pre", "b_post", "c"):
        carrier_id = receipts[role].get("carrier_id")
        if not isinstance(carrier_id, str) or not HEX_64.fullmatch(carrier_id):
            raise ExperimentError(f"Gate-H {role} has a malformed stable carrier ID")
        carrier_ids[role] = carrier_id
    if carrier_ids["b_pre"] != carrier_ids["b_post"]:
        raise ExperimentError("Gate-H B restart changed its stable carrier identity")
    exact = {
        "gate_h_control_id": control["authorization_control_id"],
        "gate_h_generation_before": 0,
        "gate_h_generation_after": 1,
        "gate_h_stale_target_peer": identities["c"],
        "gate_h_stale_zero_bytes_emitted": True,
        "gate_h_stale_contacts_retired": 2,
        "gate_h_provider_epoch_rotations": 1,
        "gate_h_fresh_target_generation": 1,
        "gate_h_completed": True,
    }
    if any(b_receipt.get(field) != expected for field, expected in exact.items()):
        raise ExperimentError("Gate-H B-pre receipt differs from the signed-control contract")
    integer_fields = (
        "gate_h_stale_target_contact",
        "gate_h_fresh_target_contact",
        "gate_h_stale_queued_frames",
        "gate_h_stale_send_frames_before",
        "gate_h_stale_send_frames_after",
        "gate_h_stale_send_bytes_before",
        "gate_h_stale_send_bytes_after",
        "gate_h_fresh_aster_frames_sent",
        "gate_h_fresh_aster_bytes_sent",
    )
    numbers = {
        field: _strict_nonnegative_integer(b_receipt.get(field), field=field)
        for field in integer_fields
    }
    if numbers["gate_h_stale_queued_frames"] == 0:
        raise ExperimentError("Gate-H B-pre retained no stale outbound frame")
    if (
        numbers["gate_h_stale_send_frames_before"]
        != numbers["gate_h_stale_send_frames_after"]
        or numbers["gate_h_stale_send_bytes_before"]
        != numbers["gate_h_stale_send_bytes_after"]
    ):
        raise ExperimentError("Gate-H stale frame changed carrier send counters")
    if (
        numbers["gate_h_fresh_aster_frames_sent"] == 0
        or numbers["gate_h_fresh_aster_bytes_sent"] == 0
    ):
        raise ExperimentError("Gate-H fresh generation made no Aster progress")
    if numbers["gate_h_stale_target_contact"] == numbers["gate_h_fresh_target_contact"]:
        raise ExperimentError("Gate-H fresh progress reused the stale contact")

    b_matches = [
        _unique_gate_h_event(b_events, "stale_frame_retained", label="Gate-H B-pre"),
        _unique_gate_h_event(b_events, "authorization_control_applied", label="Gate-H B-pre"),
        _unique_gate_h_event(
            b_events,
            "generation_checked",
            label="Gate-H B-pre",
            predicate=lambda event: event.get("result") == "mismatch",
        ),
        _unique_gate_h_event(b_events, "stale_generation_blocked", label="Gate-H B-pre"),
        _unique_gate_h_event(b_events, "stale_contacts_retired", label="Gate-H B-pre"),
        _unique_gate_h_event(
            b_events,
            "carrier_session_epoch_rotated",
            label="Gate-H B-pre",
            predicate=lambda event: event.get("cause") == "local-signed-control",
        ),
        _unique_gate_h_event(b_events, "fresh_authorized_progress", label="Gate-H B-pre"),
    ]
    if [index for index, _ in b_matches] != sorted(index for index, _ in b_matches):
        raise ExperimentError("Gate-H B-pre control events are out of order")
    (
        stale_event,
        control_event,
        mismatch_event,
        blocked_event,
        retired_event,
        b_rotation_event,
        fresh_event,
    ) = [event for _, event in b_matches]
    stale_contact = numbers["gate_h_stale_target_contact"]
    fresh_contact = numbers["gate_h_fresh_target_contact"]
    if (
        stale_event.get("peer") != identities["c"]
        or stale_event.get("contact") != stale_contact
        or stale_event.get("queued_frames") != numbers["gate_h_stale_queued_frames"]
        or stale_event.get("sent_frames")
        != numbers["gate_h_stale_send_frames_before"]
        or stale_event.get("sent_bytes") != numbers["gate_h_stale_send_bytes_before"]
        or not isinstance(stale_event.get("blocked_attempts"), int)
        or isinstance(stale_event.get("blocked_attempts"), bool)
        or stale_event["blocked_attempts"] <= 0
        or not isinstance(stale_event.get("blocked_bytes"), int)
        or isinstance(stale_event.get("blocked_bytes"), bool)
        or stale_event["blocked_bytes"] <= 0
        or control_event.get("control_id") != control["authorization_control_id"]
        or control_event.get("generation_before") != 0
        or control_event.get("generation_after") != 1
        or control_event.get("contacts_invalidated") != 2
        or mismatch_event.get("peer") != identities["c"]
        or mismatch_event.get("contact") != stale_contact
        or mismatch_event.get("expected_generation") != 0
        or mismatch_event.get("observed_generation") != 1
        or blocked_event.get("peer") != identities["c"]
        or blocked_event.get("contact") != stale_contact
        or blocked_event.get("queued_frames") != numbers["gate_h_stale_queued_frames"]
        or blocked_event.get("sent_frames_before")
        != numbers["gate_h_stale_send_frames_before"]
        or blocked_event.get("sent_frames_after")
        != numbers["gate_h_stale_send_frames_after"]
        or blocked_event.get("sent_bytes_before")
        != numbers["gate_h_stale_send_bytes_before"]
        or blocked_event.get("sent_bytes_after")
        != numbers["gate_h_stale_send_bytes_after"]
        or blocked_event.get("zero_bytes_emitted") is not True
        or retired_event.get("count") != 2
        or not isinstance(retired_event.get("contacts"), list)
        or any(
            isinstance(contact, bool) or not isinstance(contact, int) or contact < 0
            for contact in retired_event["contacts"]
        )
        or len(set(retired_event["contacts"])) != 2
        or stale_contact not in retired_event["contacts"]
        or b_rotation_event.get("generation") != 1
        or b_rotation_event.get("carrier_id") != carrier_ids["b_pre"]
        or b_rotation_event.get("stale_contacts_retired") != 2
        or fresh_event.get("peer") != identities["c"]
        or fresh_event.get("contact") != fresh_contact
        or fresh_event.get("generation") != 1
        or fresh_event.get("aster_frames_sent")
        != numbers["gate_h_fresh_aster_frames_sent"]
        or fresh_event.get("aster_bytes_sent")
        != numbers["gate_h_fresh_aster_bytes_sent"]
    ):
        raise ExperimentError("Gate-H B-pre event chain differs from its receipt")
    for event, label in ((b_rotation_event, "B-pre"),):
        old_nonce = event.get("old_instance_nonce")
        new_nonce = event.get("new_instance_nonce")
        if (
            not isinstance(old_nonce, str)
            or not HEX_32.fullmatch(old_nonce)
            or not isinstance(new_nonce, str)
            or not HEX_32.fullmatch(new_nonce)
            or old_nonce == new_nonce
        ):
            raise ExperimentError(f"Gate-H {label} did not retain an exact epoch rotation")

    c_matches = [
        _unique_gate_h_event(
            c_events,
            "generation_checked",
            label="Gate-H continuous C",
            predicate=lambda event: event.get("result") == "mismatch",
        ),
        _unique_gate_h_event(
            c_events,
            "authorization_generation_sessions_retired",
            label="Gate-H continuous C",
        ),
        _unique_gate_h_event(
            c_events,
            "carrier_session_epoch_rotated",
            label="Gate-H continuous C",
            predicate=lambda event: event.get("cause")
            == "authorization-generation-changed",
        ),
    ]
    if [index for index, _ in c_matches] != sorted(index for index, _ in c_matches):
        raise ExperimentError("Gate-H continuous-C generation events are out of order")
    c_mismatch, c_retired, c_rotation = [event for _, event in c_matches]
    c_mismatch_contact = c_mismatch.get("contact")
    if (
        c_mismatch.get("peer") != identities["b"]
        or isinstance(c_mismatch_contact, bool)
        or not isinstance(c_mismatch_contact, int)
        or c_mismatch_contact < 0
        or c_mismatch.get("expected_generation") != 0
        or c_mismatch.get("observed_generation") != 1
        or c_retired.get("generation") != 1
        or c_retired.get("trigger_contact") != c_mismatch_contact
        or c_retired.get("contacts_retired") != 1
        or c_rotation.get("generation") != 1
        or c_rotation.get("carrier_id") != carrier_ids["c"]
        or c_rotation.get("stale_contacts_retired") != 1
    ):
        raise ExperimentError("Gate-H continuous-C rotation differs from generation 1")
    old_nonce = c_rotation.get("old_instance_nonce")
    new_nonce = c_rotation.get("new_instance_nonce")
    if (
        not isinstance(old_nonce, str)
        or not HEX_32.fullmatch(old_nonce)
        or not isinstance(new_nonce, str)
        or not HEX_32.fullmatch(new_nonce)
        or old_nonce == new_nonce
    ):
        raise ExperimentError("Gate-H continuous C did not retain an exact epoch rotation")

    return {
        "authorization_generations": generations,
        "b_pre_receipt": {field: b_receipt.get(field) for field in GATE_H_LIVE_FIELDS},
        "event_witnesses": {
            "b_pre": [event for _, event in b_matches],
            "c_continuous": [event for _, event in c_matches],
        },
    }


def read_final_receipt(
    trial_root: Path,
    role: str,
    arm: str,
    invocation: str,
    *,
    discovery_source: str | None = None,
    provider_binary_sha256: str | None = None,
) -> dict[str, Any]:
    path = trial_root / role / f"{arm}-mesh-{invocation}-final.json"
    if not path.is_file():
        raise ExperimentError(f"missing node final receipt: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ExperimentError(f"node receipt is not an object: {path}")
    validate_provider_profile(
        value,
        arm=arm,
        discovery_source=discovery_source,
        provider_binary_sha256=provider_binary_sha256,
    )
    return value


def read_status_receipt(
    trial_root: Path,
    role: str,
    arm: str,
    invocation: str,
    *,
    discovery_source: str | None = None,
    provider_binary_sha256: str | None = None,
) -> dict[str, Any] | None:
    """Read an atomically replaced live status receipt when it is available."""
    path = trial_root / role / f"{arm}-mesh-{invocation}-status.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as error:
        raise ExperimentError(f"live node status is invalid JSON: {path}") from error
    if not isinstance(value, dict):
        raise ExperimentError(f"live node status is not an object: {path}")
    validate_provider_profile(
        value,
        arm=arm,
        discovery_source=discovery_source,
        provider_binary_sha256=provider_binary_sha256,
        native_receipt_mode="live-status" if arm == "native" else "final",
    )
    return value


def receipt_has_exact_peer_evidence(
    receipt: dict[str, Any], expected: set[str], *, arm: str
) -> bool:
    """Require duplicate-free exact peer sets and provider admission evidence."""
    authenticated = receipt.get("authenticated_peers")
    if (
        not isinstance(authenticated, list)
        or any(not isinstance(peer, str) for peer in authenticated)
        or len(authenticated) != len(expected)
        or set(authenticated) != expected
    ):
        return False
    admitted = receipt.get("admitted_peers")
    return (
        isinstance(admitted, list)
        and all(isinstance(peer, str) for peer in admitted)
        and len(admitted) == len(expected)
        and set(admitted) == expected
    )


def require_exact_peer_evidence(
    receipt: dict[str, Any], expected: set[str], *, arm: str, label: str
) -> None:
    if not receipt_has_exact_peer_evidence(receipt, expected, arm=arm):
        raise ExperimentError(
            f"{label} did not authenticate and admit exactly the expected peer set"
        )


def admitted_contact_high_water(receipt: dict[str, Any], *, label: str) -> int:
    """Return an exact semantic-admission overlap witness."""
    value = receipt.get("admitted_contact_high_water")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ExperimentError(
            f"{label} receipt has no valid admitted-contact high-water mark"
        )
    return value


def wait_for_authenticated_pair(
    *,
    trial_root: Path,
    arm: str,
    invocation: str,
    first_role: str,
    second_role: str,
    first_identity: str,
    second_identity: str,
    first_process: subprocess.Popen[str],
    second_process: subprocess.Popen[str],
    timeout: float,
    discovery_source: str | None = None,
    provider_binary_sha256: str | None = None,
) -> int:
    """Wait until live status proves exact mutual authentication and admission."""
    started = time.monotonic()
    deadline = started + timeout
    while time.monotonic() < deadline:
        first = read_status_receipt(
            trial_root,
            first_role,
            arm,
            invocation,
            discovery_source=discovery_source,
            provider_binary_sha256=provider_binary_sha256,
        )
        second = read_status_receipt(
            trial_root,
            second_role,
            arm,
            invocation,
            discovery_source=discovery_source,
            provider_binary_sha256=provider_binary_sha256,
        )
        if first is not None and second is not None:
            if receipt_has_exact_peer_evidence(
                first, {second_identity}, arm=arm
            ) and receipt_has_exact_peer_evidence(
                second, {first_identity}, arm=arm
            ):
                return int((time.monotonic() - started) * 1_000)
        if first_process.poll() is not None or second_process.poll() is not None:
            raise ExperimentError(
                "node exited before the prerequisite exact peer evidence was live"
            )
        time.sleep(0.025)
    raise ExperimentError("timed out waiting for the prerequisite exact peer evidence")


def wait_for_exact_peer_sets(
    *,
    trial_root: Path,
    arm: str,
    invocation: str,
    identities: dict[str, str],
    expected: dict[str, set[str]],
    processes: dict[str, subprocess.Popen[str]],
    timeout: float,
    discovery_source: str | None = None,
    provider_binary_sha256: str | None = None,
) -> int:
    """Wait until every named live process proves its exact admitted peer set."""

    if set(identities) != set(expected) or set(expected) != set(processes):
        raise ExperimentError("exact-peer wait role sets differ")
    started = time.monotonic()
    deadline = started + timeout
    while time.monotonic() < deadline:
        receipts = {
            role: read_status_receipt(
                trial_root,
                role,
                arm,
                invocation,
                discovery_source=discovery_source,
                provider_binary_sha256=provider_binary_sha256,
            )
            for role in processes
        }
        if all(receipt is not None for receipt in receipts.values()) and all(
            receipt_has_exact_peer_evidence(
                receipts[role], expected[role], arm=arm
            )
            and receipts[role].get("identity") == identities[role]
            for role in processes
        ):
            return int((time.monotonic() - started) * 1_000)
        early = {
            role: process.poll()
            for role, process in processes.items()
            if process.poll() is not None
        }
        if early:
            detail = ",".join(
                f"{role}={returncode}" for role, returncode in sorted(early.items())
            )
            raise ExperimentError(
                f"node exited before the exact admitted peer set was live: {detail}"
            )
        time.sleep(0.025)
    raise ExperimentError("timed out waiting for the exact admitted peer sets")


def read_event_log(
    path: Path, *, allow_incomplete_tail: bool = False
) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    events = []
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    if allow_incomplete_tail and lines and not lines[-1].endswith(("\n", "\r")):
        lines.pop()
    for line_number, line in enumerate(lines, start=1):
        line = line.rstrip("\r\n")
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ExperimentError(
                f"node event log has invalid JSON at {path}:{line_number}"
            ) from error
        if not isinstance(value, dict):
            raise ExperimentError(
                f"node event log entry is not an object at {path}:{line_number}"
            )
        events.append(value)
    return events


def inventory_fanout_from_peer(
    path: Path, expected_peer: str
) -> dict[str, Any] | None:
    """Return the first commit fan-out sourced from an admitted peer contact."""
    contacts: dict[int, str] = {}
    planned: dict[int, int] = {}
    for event in read_event_log(path, allow_incomplete_tail=True):
        if event.get("event") in ("admission_committed", "admitted"):
            contact = event.get("contact")
            peer = event.get("peer")
            if (
                isinstance(contact, int)
                and not isinstance(contact, bool)
                and isinstance(peer, str)
            ):
                contacts[contact] = peer
            continue
        if event.get("event") == "inventory_changed":
            contact = event.get("contact")
            targets = event.get("contacts_planned")
            if (
                isinstance(contact, int)
                and not isinstance(contact, bool)
                and isinstance(targets, int)
                and not isinstance(targets, bool)
                and targets >= 1
                and contacts.get(contact) == expected_peer
            ):
                planned[contact] = targets
            continue
        if event.get("event") != "inventory_fanout_queued":
            continue
        contact = event.get("contact")
        queued = event.get("contacts_queued")
        if (
            isinstance(contact, int)
            and not isinstance(contact, bool)
            and isinstance(queued, int)
            and not isinstance(queued, bool)
            and queued >= 1
            and contact in planned
        ):
            return {
                "contact": contact,
                "source_peer": expected_peer,
                "contacts_planned": planned[contact],
                "contacts_queued": queued,
            }
    return None


def admitted_contacts_from_peer(path: Path, expected_peer: str) -> set[int]:
    """Return distinct task-confirmed contact IDs admitted for one Aster peer."""

    contacts: set[int] = set()
    for event in read_event_log(path, allow_incomplete_tail=True):
        contact = event.get("contact")
        if (
            event.get("event") in ("admission_committed", "admitted")
            and event.get("peer") == expected_peer
            and isinstance(contact, int)
            and not isinstance(contact, bool)
            and contact >= 0
        ):
            contacts.add(contact)
    return contacts


def durable_item_present(database: Path, item_id: bytes) -> bool:
    """Read one exact durable identity directly without opening its payload.

    Gate H uses this only for stopped-node preconditions. Its live observations
    use the node's authority-backed atomic status receipt because cross-host
    bind-mount locking is not a safe live-read boundary.
    """
    if len(item_id) != 32:
        raise ExperimentError("expected ItemID is not 32 bytes")
    if not database.is_file():
        return False
    try:
        connection = sqlite3.connect(
            f"file:{database}?mode=ro", uri=True, timeout=0.05
        )
        try:
            row = connection.execute(
                "SELECT 1 FROM items WHERE item_id = ? LIMIT 1", (item_id,)
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.OperationalError as error:
        if "locked" in str(error).lower() or "busy" in str(error).lower():
            return False
        raise ExperimentError(f"durable ItemID probe failed: {error}") from error
    return row == (1,)


def native_status_durable_item_present(
    receipt: dict[str, Any] | None,
    item_id: bytes,
    *,
    label: str,
) -> bool | None:
    """Read one exact in-process durable ItemID observation from live status."""

    if receipt is None:
        return None
    if len(item_id) != 32:
        raise ExperimentError("expected ItemID is not 32 bytes")
    if receipt.get("durable_item_probe_id") != item_id.hex():
        raise ExperimentError(f"{label} reports the wrong durable ItemID probe")
    present = receipt.get("durable_item_present")
    if not isinstance(present, bool):
        raise ExperimentError(f"{label} has no typed durable ItemID observation")
    return present


def validate_pair(
    *,
    first: dict[str, Any],
    second: dict[str, Any],
    expected_first: str,
    expected_second: str,
    arm: str,
    automatic_discovery: bool = True,
) -> None:
    if first.get("identity") != expected_first or second.get("identity") != expected_second:
        raise ExperimentError("node receipt identity differs from provisioning")
    require_exact_peer_evidence(
        first, {expected_second}, arm=arm, label="first node"
    )
    require_exact_peer_evidence(
        second, {expected_first}, arm=arm, label="second node"
    )
    if first.get("unauthorized_peers") or second.get("unauthorized_peers"):
        raise ExperimentError("pair receipt contains an unauthorized authenticated peer")
    discovered = int(first.get("candidates_discovered", 0)) + int(
        second.get("candidates_discovered", 0)
    )
    if automatic_discovery and discovered < 1:
        raise ExperimentError("automatic discovery produced no candidate for the pair")
    if not automatic_discovery and discovered != 0:
        raise ExperimentError("manual pair unexpectedly used automatic discovery")


def validate_libp2p_protected_alias_pair(
    first: dict[str, Any], second: dict[str, Any]
) -> None:
    """Require exact carrier-locator coalescing in the protected pair."""
    aliases = 0
    failures = 0
    for receipt in (first, second):
        alias_count = receipt.get("carrier_locator_aliases_coalesced")
        failure_count = receipt.get("contact_failures")
        if (
            not isinstance(alias_count, int)
            or isinstance(alias_count, bool)
            or alias_count < 0
            or not isinstance(failure_count, int)
            or isinstance(failure_count, bool)
            or failure_count < 0
        ):
            raise ExperimentError("libp2p alias receipt counters are malformed")
        aliases += alias_count
        failures += failure_count
    if aliases < 1:
        raise ExperimentError(
            "protected libp2p pair did not exercise exact carrier-locator coalescing"
        )
    if failures != 0:
        raise ExperimentError(
            "protected libp2p carrier-locator coalescing recorded a retry/contact failure"
        )


def protected_discovery_announcement_count(receipt: dict[str, Any]) -> int:
    """Read the arm-specific protected-discovery counter without false defaults."""

    for field in ("discovery_announcements", "protected_announcement_events_observed"):
        if field not in receipt:
            continue
        value = receipt[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ExperimentError(f"node receipt {field} counter is malformed")
        return value
    raise ExperimentError("node receipt omits a protected-discovery announcement counter")


def run_pair(
    runner: Runner,
    args: argparse.Namespace,
    *,
    run_id: str,
    trial: int,
    trial_root: Path,
    phase: str,
    first_role: str,
    second_role: str,
    expected_first: str,
    expected_second: str,
    invocation: str,
    manual: bool = False,
    manual_carrier_ids: dict[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    network, gateway, broadcast = create_network(runner, args.arm, run_id, trial, phase)
    subnet, _, _ = network_spec(args.arm, trial, phase)
    third = subnet.split(".")[2]
    second = subnet.split(".")[1]
    first_address = f"10.{second}.{third}.10"
    second_address = f"10.{second}.{third}.11"
    containers: list[str] = []
    capture_process: subprocess.Popen[str] | None = None
    processes: dict[str, subprocess.Popen[str]] = {}
    try:
        if args.arm in ARMS and needs_discovery_token(args):
            copy_discovery_token(trial_root, first_role)
            copy_discovery_token(trial_root, second_role)
        first_container = create_node_container(
            runner,
            args=args,
            run_id=run_id,
            trial=trial,
            phase=phase,
            role=first_role,
            node_root=trial_root / first_role,
            bundle=trial_root / "private" / f"{first_role}.bundle",
            network=network,
            address=first_address,
            gateway=gateway,
        )
        containers.append(first_container)
        second_container = create_node_container(
            runner,
            args=args,
            run_id=run_id,
            trial=trial,
            phase=phase,
            role=second_role,
            node_root=trial_root / second_role,
            bundle=trial_root / "private" / f"{second_role}.bundle",
            network=network,
            address=second_address,
            gateway=gateway,
        )
        containers.append(second_container)
        topology = inspect_topology(runner, network, containers)
        write_json(trial_root / f"topology-{invocation}.json", topology)

        if args.capture:
            capture_process = runner.popen(
                [
                    "docker",
                    "exec",
                    first_container,
                    "/usr/bin/tcpdump",
                    "-i",
                    "eth0",
                    "-s",
                    "0",
                    "-U",
                    "-Z",
                    "root",
                    "-w",
                    f"/lab/node/{args.arm}-mesh-{invocation}.pcap",
                ]
            )
            time.sleep(0.5)

        first_manual_id = expected_second
        second_manual_id = expected_first
        if manual_carrier_ids is not None:
            first_manual_id = manual_carrier_ids[second_role]
            second_manual_id = manual_carrier_ids[first_role]
        first_command = node_exec_command(
            args=args,
            container=first_container,
            invocation=invocation,
            expected_peer=expected_second,
            broadcast=broadcast,
            discovery_enabled=not manual,
            manual_peers=(
                f"{first_manual_id}@{second_address}:47101" if manual else ""
            ),
        )
        second_command = node_exec_command(
            args=args,
            container=second_container,
            invocation=invocation,
            expected_peer=expected_first,
            broadcast=broadcast,
            discovery_enabled=not manual,
            manual_peers=(
                f"{second_manual_id}@{first_address}:47101" if manual else ""
            ),
        )
        resource_before = {
            first_role: read_resource_counters(runner, first_container),
            second_role: read_resource_counters(runner, second_container),
        }
        expected_item = (trial_root / "expected-item-id.bin").read_bytes()
        durable_before = {
            first_role: durable_item_present(
                trial_root / first_role / "state.sqlite", expected_item
            ),
            second_role: durable_item_present(
                trial_root / second_role / "state.sqlite", expected_item
            ),
        }
        process_started: dict[str, float] = {}
        process_started[first_role] = time.monotonic()
        first_process = runner.popen(first_command)
        processes[first_role] = first_process
        process_started[second_role] = time.monotonic()
        second_process = runner.popen(second_command)
        processes[second_role] = second_process
        timeout = args.duration_ms / 1000 + 20
        observed_ms: dict[str, int | None] = {
            first_role: 0 if durable_before[first_role] else None,
            second_role: 0 if durable_before[second_role] else None,
        }
        observation_deadline = time.monotonic() + timeout
        while time.monotonic() < observation_deadline:
            pending = False
            for role, process in processes.items():
                if observed_ms[role] is None:
                    if durable_item_present(
                        trial_root / role / "state.sqlite", expected_item
                    ):
                        observed_ms[role] = int(
                            (time.monotonic() - process_started[role]) * 1_000
                        )
                    elif process.poll() is None:
                        pending = True
            if not pending:
                break
            time.sleep(0.01)
        missing = [
            role
            for role in (first_role, second_role)
            if not durable_before[role] and observed_ms[role] is None
        ]
        if missing:
            early_exits = {
                role: returncode
                for role, process in processes.items()
                if (returncode := process.poll()) is not None
            }
            detail = (
                "; candidate processes exited early: "
                + ",".join(
                    f"{role}={returncode}"
                    for role, returncode in sorted(early_exits.items())
                )
                if early_exits
                else ""
            )
            raise ExperimentError(
                "exact source ItemID was not durably observed by "
                + ",".join(missing)
                + detail
            )
        early_exits = {
            role: returncode
            for role, process in processes.items()
            if (returncode := process.poll()) is not None
        }
        if early_exits:
            raise ExperimentError(
                "exact source ItemID observation did not occur while both candidates were live; "
                + "candidate processes exited early: "
                + ",".join(
                    f"{role}={returncode}"
                    for role, returncode in sorted(early_exits.items())
                )
            )
        resource_live = {
            first_role: read_resource_counters(runner, first_container),
            second_role: read_resource_counters(runner, second_container),
        }
        runner.wait_process(first_process, timeout)
        runner.wait_process(second_process, timeout)
        resource_after = {
            first_role: read_resource_counters(runner, first_container),
            second_role: read_resource_counters(runner, second_container),
        }
        if capture_process is not None:
            runner.run(
                [
                    "docker",
                    "exec",
                    first_container,
                    "/usr/bin/pkill",
                    "--signal",
                    "INT",
                    "--exact",
                    "tcpdump",
                ]
            )
            runner.wait_process(capture_process, 10)
            capture_process = None
        first_receipt = read_final_receipt(
            trial_root,
            first_role,
            args.arm,
            invocation,
            discovery_source=getattr(args, "discovery_source", None),
            provider_binary_sha256=provider_receipt_digest(args),
        )
        second_receipt = read_final_receipt(
            trial_root,
            second_role,
            args.arm,
            invocation,
            discovery_source=getattr(args, "discovery_source", None),
            provider_binary_sha256=provider_receipt_digest(args),
        )
        for role, receipt in ((first_role, first_receipt), (second_role, second_receipt)):
            before = resource_before[role]
            after = resource_after[role]
            receipt["experiment_resources"] = {
                "cpu_usage_usec": after["cpu_usage_usec"] - before["cpu_usage_usec"],
                "network_bytes": after["network_bytes"] - before["network_bytes"],
                "memory_current_bytes": resource_live[role]["memory_current_bytes"],
                "memory_peak_bytes": after["memory_peak_bytes"],
                "memory_current_sample_phase": "exact-item-observation-before-process-wait",
                "memory_current_candidate_running": True,
                "counter_scope": "whole container cgroup; all non-loopback interfaces",
                "durable_item_present_before_contact": durable_before[role],
                "durable_item_first_observed_ms_from_process_launch": observed_ms[role],
                "durable_probe_scope": "read-only exact ItemID row; 10 ms controller polling",
            }
        validate_pair(
            first=first_receipt,
            second=second_receipt,
            expected_first=expected_first,
            expected_second=expected_second,
            arm=args.arm,
            automatic_discovery=not manual,
        )
        if (
            not manual
            and args.arm == "libp2p"
            and getattr(args, "discovery_source", None) == "aster-protected"
        ):
            validate_libp2p_protected_alias_pair(first_receipt, second_receipt)
        # The retained native v1 receipt predates the manual lane and stays
        # byte-schema compatible. Its discovery-disabled authentication proof
        # above is sufficient; upstream-arm receipts expose the extra count.
        if manual and args.arm in ("iroh", "libp2p") and (
            first_receipt.get("manual_candidates") != 1
            or second_receipt.get("manual_candidates") != 1
        ):
            raise ExperimentError("manual pair did not retain exactly one configured candidate")
        return first_receipt, second_receipt, topology
    finally:
        if capture_process is not None:
            runner.run(
                [
                    "docker",
                    "exec",
                    containers[0],
                    "/usr/bin/pkill",
                    "--signal",
                    "INT",
                    "--exact",
                    "tcpdump",
                ],
                check=False,
            )
            try:
                runner.wait_process(capture_process, 10)
            except ExperimentError:
                pass
        remove_resources(runner, containers, network)
        finalize_processes(runner, processes)


def run_trial(
    runner: Runner, args: argparse.Namespace, run_id: str, trial: int
) -> dict[str, Any]:
    trial_root = args.root / f"trial-{trial:02d}"
    trial_root.mkdir(parents=True)
    prepare = run_offline(
        runner,
        args,
        trial_root,
        [
            "mesh-prepare",
            "--root",
            "/lab/run",
            "--seed",
            str(args.seed + trial),
            "--payload-bytes",
            str(args.payload_bytes),
        ],
    )
    identities = {role: prepare[name] for role, name in (("a", "publisher"), ("b", "relay"), ("c", "consumer"))}
    if any(not isinstance(value, str) or not HEX_64.fullmatch(value) for value in identities.values()):
        raise ExperimentError("preparation emitted malformed node identities")

    started = time.monotonic()
    ab_a, ab_b, topology_ab = run_pair(
        runner,
        args,
        run_id=run_id,
        trial=trial,
        trial_root=trial_root,
        phase="ab",
        first_role="a",
        second_role="b",
        expected_first=identities["a"],
        expected_second=identities["b"],
        invocation=f"t{trial:02d}_ab",
    )
    custody = run_offline(
        runner,
        args,
        trial_root,
        ["mesh-verify-relay", "--root", "/lab/run", "--invocation", f"t{trial:02d}_ab"],
    )
    if not all(
        custody.get(field) is True
        for field in (
            "exact_envelope",
            "application_unreadable",
            "payload_absent_at_rest",
            "payload_digest_absent_at_rest",
        )
    ):
        raise ExperimentError("route-only custody verifier did not pass every gate")

    bc_b, bc_c, topology_bc = run_pair(
        runner,
        args,
        run_id=run_id,
        trial=trial,
        trial_root=trial_root,
        phase="bc",
        first_role="b",
        second_role="c",
        expected_first=identities["b"],
        expected_second=identities["c"],
        invocation=f"t{trial:02d}_bc",
    )
    delivery = run_offline(
        runner,
        args,
        trial_root,
        ["mesh-consume", "--root", "/lab/run", "--invocation", f"t{trial:02d}_bc"],
    )
    if not all(
        delivery.get(field) is True
        for field in ("same_item", "same_envelope", "application_acknowledged")
    ) or delivery.get("immediate_post_ack_deliveries") != 0 or delivery.get("post_restart_deliveries") != 0:
        raise ExperimentError("consumer delivery/acknowledgement verifier failed")

    dup_a, dup_b, topology_dup = run_pair(
        runner,
        args,
        run_id=run_id,
        trial=trial,
        trial_root=trial_root,
        phase="ab",
        first_role="a",
        second_role="b",
        expected_first=identities["a"],
        expected_second=identities["b"],
        invocation=f"t{trial:02d}_dup",
    )
    duplicate = run_offline(
        runner,
        args,
        trial_root,
        ["mesh-verify-duplicate", "--root", "/lab/run", "--invocation", f"t{trial:02d}_dup"],
    )
    if duplicate.get("duplicate_suppression") is not True:
        raise ExperimentError("duplicate suppression verifier failed")

    capture_receipts = []
    if args.capture:
        canaries = {
            "payload": (trial_root / "expected-payload.bin").read_bytes(),
            "logical_key": (trial_root / "expected-logical-key.bin").read_bytes(),
            "publisher_raw": (trial_root / "expected-publisher-id.bin").read_bytes(),
            "publisher_hex": identities["a"].encode(),
            "topic": b"lab.ip-mesh.commands",
            "scope": b"lab/ip-mesh",
        }
        for role, invocation in (
            ("a", f"t{trial:02d}_ab"),
            ("b", f"t{trial:02d}_bc"),
            ("a", f"t{trial:02d}_dup"),
        ):
            path = trial_root / role / f"{args.arm}-mesh-{invocation}.pcap"
            if not path.is_file() or path.stat().st_size <= 24:
                raise ExperimentError(f"packet capture is absent or empty: {path}")
            captured = path.read_bytes()
            findings = [name for name, canary in canaries.items() if canary in captured]
            capture_receipts.append(
                {
                    "path": str(path),
                    "bytes": len(captured),
                    "sha256": sha256_file(path),
                    "plaintext_findings": findings,
                }
            )
            if findings:
                raise ExperimentError(
                    f"protected canary appeared in carrier capture {path}: {findings}"
                )

    if ab_a.get("carrier_id") != dup_a.get("carrier_id"):
        raise ExperimentError("A carrier identity did not persist across restart")
    if not (ab_b.get("carrier_id") == bc_b.get("carrier_id") == dup_b.get("carrier_id")):
        raise ExperimentError("B carrier identity did not persist across both handoffs")

    # The two phase networks were independently created and destroyed, and
    # their container sets never contain both A and C.
    for topology in (topology_ab, topology_bc, topology_dup):
        if topology["network"].get("Internal") is not True:
            raise ExperimentError("candidate network is not internal-only")
    for topology in (topology_ab, topology_dup):
        roles = {
            container["Config"]["Labels"]["com.defenseunicorns.aster-lab.role"]
            for container in topology["containers"]
        }
        if roles != {"a", "b"}:
            raise ExperimentError("A/B topology contains an unexpected role")
    roles = {
        container["Config"]["Labels"]["com.defenseunicorns.aster-lab.role"]
        for container in topology_bc["containers"]
    }
    if roles != {"b", "c"}:
        raise ExperimentError("B/C topology contains an unexpected role")

    result = {
        "schema": SCHEMA,
        "arm": args.arm,
        "trial": trial,
        "passed": True,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "identities": identities,
        "item_id": prepare.get("item_id"),
        "envelope_id": prepare.get("envelope_id"),
        "a_c_contact_count": 0,
        "internal_only_networks": True,
        "custody": custody,
        "delivery": delivery,
        "duplicate": duplicate,
        "captures": capture_receipts,
        "node_receipts": {"ab_a": ab_a, "ab_b": ab_b, "bc_b": bc_b, "bc_c": bc_c, "dup_a": dup_a, "dup_b": dup_b},
    }
    write_json(trial_root / "result.json", result)
    return result


def run_discovery_disabled_trial(
    runner: Runner, args: argparse.Namespace, run_id: str, trial: int
) -> dict[str, Any]:
    trial_root = args.root / f"trial-{trial:02d}"
    trial_root.mkdir(parents=True)
    prepare = run_offline(
        runner,
        args,
        trial_root,
        [
            "mesh-prepare",
            "--root",
            "/lab/run",
            "--seed",
            str(args.seed + trial),
            "--payload-bytes",
            str(args.payload_bytes),
        ],
    )
    identities = {"a": prepare["publisher"], "b": prepare["relay"]}
    network, gateway, broadcast = create_network(
        runner, args.arm, run_id, trial, "disabled"
    )
    subnet, _, _ = network_spec(args.arm, trial, "disabled")
    second = subnet.split(".")[1]
    third = subnet.split(".")[2]
    containers: list[str] = []
    started = time.monotonic()
    try:
        if args.arm in ARMS and needs_discovery_token(args):
            copy_discovery_token(trial_root, "a")
            copy_discovery_token(trial_root, "b")
        for role, address in (
            ("a", f"10.{second}.{third}.10"),
            ("b", f"10.{second}.{third}.11"),
        ):
            containers.append(
                create_node_container(
                    runner,
                    args=args,
                    run_id=run_id,
                    trial=trial,
                    phase="disabled",
                    role=role,
                    node_root=trial_root / role,
                    bundle=trial_root / "private" / f"{role}.bundle",
                    network=network,
                    address=address,
                    gateway=gateway,
                )
            )
        topology = inspect_topology(runner, network, containers)
        write_json(trial_root / "topology-disabled.json", topology)
        processes = []
        for role, container, expected in (
            ("a", containers[0], identities["b"]),
            ("b", containers[1], identities["a"]),
        ):
            processes.append(
                runner.popen(
                    node_exec_command(
                        args=args,
                        container=container,
                        invocation=f"t{trial:02d}_disabled",
                        expected_peer=expected,
                        broadcast=broadcast,
                        discovery_enabled=False,
                    )
                )
            )
        timeout = args.duration_ms / 1000 + 20
        for process in processes:
            runner.wait_process(process, timeout)
        receipts = {
            role: read_final_receipt(
                trial_root,
                role,
                args.arm,
                f"t{trial:02d}_disabled",
                discovery_source=getattr(args, "discovery_source", None),
                provider_binary_sha256=provider_receipt_digest(args),
            )
            for role in ("a", "b")
        }
        for role, receipt in receipts.items():
            if receipt.get("identity") != identities[role]:
                raise ExperimentError("disabled-discovery identity differs")
            if receipt.get("candidates_discovered") != 0:
                raise ExperimentError("disabled discovery admitted a candidate")
            if receipt.get("authenticated_peers"):
                raise ExperimentError("disabled discovery established an Aster peer")
            if receipt.get("frames_received") != 0 or receipt.get("frames_sent") != 0:
                raise ExperimentError("disabled discovery exchanged candidate frames")
        if topology["network"].get("Internal") is not True:
            raise ExperimentError("disabled-discovery network is not internal-only")
        result = {
            "schema": SCHEMA,
            "scenario": "discovery-disabled",
            "arm": args.arm,
            "trial": trial,
            "passed": True,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "candidate_count": 0,
            "authenticated_peer_count": 0,
            "frame_count": 0,
            "receipts": receipts,
        }
        write_json(trial_root / "result.json", result)
        return result
    finally:
        remove_resources(runner, containers, network)


def run_manual_trial(
    runner: Runner, args: argparse.Namespace, run_id: str, trial: int
) -> dict[str, Any]:
    if args.arm not in ARMS:
        raise ExperimentError("the focused manual-peer lane requires a supported arm")
    trial_root = args.root / f"trial-{trial:02d}"
    trial_root.mkdir(parents=True)
    prepare = run_offline(
        runner,
        args,
        trial_root,
        [
            "mesh-prepare",
            "--root",
            "/lab/run",
            "--seed",
            str(args.seed + trial),
            "--payload-bytes",
            str(args.payload_bytes),
        ],
    )
    identities = {"a": prepare["publisher"], "b": prepare["relay"]}
    manual_carrier_ids = None
    if args.arm == "iroh":
        manual_carrier_ids = {
            role: initialize_iroh_carrier(runner, args, trial_root, role)
            for role in ("a", "b")
        }
    started = time.monotonic()
    first, second, topology = run_pair(
        runner,
        args,
        run_id=run_id,
        trial=trial,
        trial_root=trial_root,
        phase="manual",
        first_role="a",
        second_role="b",
        expected_first=identities["a"],
        expected_second=identities["b"],
        invocation=f"t{trial:02d}_manual",
        manual=True,
        manual_carrier_ids=manual_carrier_ids,
    )
    result = {
        "schema": SCHEMA,
        "scenario": "manual",
        "arm": args.arm,
        "trial": trial,
        "passed": True,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "automatic_candidates": 0,
        "manual_candidates": 2,
        "identities": identities,
        "internal_only_network": topology["network"].get("Internal") is True,
        "receipts": {"a": first, "b": second},
    }
    write_json(trial_root / "result.json", result)
    return result


def run_receive_only_trial(
    runner: Runner, args: argparse.Namespace, run_id: str, trial: int
) -> dict[str, Any]:
    """Prove silent discovery plus authenticated inbound Aster ingestion.

    A is a normal manual dialer. B has the same pre-provisioned peer locator but
    runs with automatic discovery disabled and the receive-only Aster emission
    policy, so it cannot initiate the contact; it must nevertheless accept A,
    authenticate it, and durably ingest A's exact source ItemID.
    Authentication and mandatory connection control bytes are allowed; this
    scenario does not mislabel the mode as zero-RF operation.
    """
    trial_root = args.root / f"trial-{trial:02d}"
    trial_root.mkdir(parents=True)
    prepare = run_offline(
        runner,
        args,
        trial_root,
        [
            "mesh-prepare",
            "--root",
            "/lab/run",
            "--seed",
            str(args.seed + trial),
            "--payload-bytes",
            str(args.payload_bytes),
        ],
    )
    identities = {"a": prepare["publisher"], "b": prepare["relay"]}
    if any(
        not isinstance(value, str) or not HEX_64.fullmatch(value)
        for value in identities.values()
    ):
        raise ExperimentError("preparation emitted malformed node identities")

    carrier_ids = dict(identities)
    if args.arm == "iroh":
        carrier_ids = {
            role: initialize_iroh_carrier(runner, args, trial_root, role)
            for role in ("a", "b")
        }

    network, gateway, broadcast = create_network(
        runner, args.arm, run_id, trial, "receive"
    )
    subnet, _, _ = network_spec(args.arm, trial, "receive")
    second, third = subnet.split(".")[1:3]
    addresses = {
        "a": f"10.{second}.{third}.10",
        "b": f"10.{second}.{third}.11",
    }
    invocation = f"t{trial:02d}_receive"
    containers: list[str] = []
    processes: dict[str, subprocess.Popen[str]] = {}
    started = time.monotonic()
    try:
        if needs_discovery_token(args):
            copy_discovery_token(trial_root, "a")
            copy_discovery_token(trial_root, "b")
        for role in ("a", "b"):
            containers.append(
                create_node_container(
                    runner,
                    args=args,
                    run_id=run_id,
                    trial=trial,
                    phase="receive",
                    role=role,
                    node_root=trial_root / role,
                    bundle=trial_root / "private" / f"{role}.bundle",
                    network=network,
                    address=addresses[role],
                    gateway=gateway,
                )
            )
        topology = inspect_topology(runner, network, containers)
        write_json(trial_root / "topology-receive-only.json", topology)

        expected_item = (trial_root / "expected-item-id.bin").read_bytes()
        durable_before = {
            role: durable_item_present(
                trial_root / role / "state.sqlite", expected_item
            )
            for role in ("a", "b")
        }
        if durable_before != {"a": True, "b": False}:
            raise ExperimentError(
                "receive-only precondition differs: only A may hold the source ItemID"
            )
        resource_before = {
            role: read_resource_counters(runner, container)
            for role, container in zip(("a", "b"), containers, strict=True)
        }

        commands = {
            "a": node_exec_command(
                args=args,
                container=containers[0],
                invocation=invocation,
                expected_peer=identities["b"],
                broadcast=broadcast,
                discovery_enabled=False,
                manual_peers=f"{carrier_ids['b']}@{addresses['b']}:47101",
                emission_mode="normal",
            ),
            "b": node_exec_command(
                args=args,
                container=containers[1],
                invocation=invocation,
                expected_peer=identities["a"],
                broadcast=broadcast,
                discovery_enabled=False,
                manual_peers=f"{carrier_ids['a']}@{addresses['a']}:47101",
                emission_mode="receive-only",
            ),
        }
        process_started: dict[str, float] = {}
        process_started["b"] = time.monotonic()
        processes["b"] = runner.popen(commands["b"])
        time.sleep(0.25)
        process_started["a"] = time.monotonic()
        processes["a"] = runner.popen(commands["a"])

        observed_ms: int | None = None
        all_nodes_running_when_observed = False
        deadline = process_started["a"] + args.duration_ms / 1_000
        while time.monotonic() < deadline:
            if durable_item_present(trial_root / "b" / "state.sqlite", expected_item):
                observed_ms = int(
                    (time.monotonic() - process_started["b"]) * 1_000
                )
                all_nodes_running_when_observed = all(
                    process.poll() is None for process in processes.values()
                )
                break
            if any(process.poll() is not None for process in processes.values()):
                break
            time.sleep(0.01)
        if observed_ms is None:
            early_exits = {
                role: returncode
                for role, process in processes.items()
                if (returncode := process.poll()) is not None
            }
            detail = (
                "; candidate processes exited early: "
                + ",".join(
                    f"{role}={returncode}"
                    for role, returncode in sorted(early_exits.items())
                )
                if early_exits
                else ""
            )
            raise ExperimentError(
                "receive-only node did not durably ingest the exact source ItemID"
                + detail
            )
        if not all_nodes_running_when_observed:
            raise ExperimentError(
                "receive-only ingestion was observed only after a node exited"
            )
        resource_live = {
            role: read_resource_counters(runner, container)
            for role, container in zip(("a", "b"), containers, strict=True)
        }

        timeout = args.duration_ms / 1_000 + 20
        runner.wait_process(processes["a"], timeout)
        runner.wait_process(processes["b"], timeout)
        resource_after = {
            role: read_resource_counters(runner, container)
            for role, container in zip(("a", "b"), containers, strict=True)
        }
        receipts = {
            role: read_final_receipt(
                trial_root,
                role,
                args.arm,
                invocation,
                discovery_source=getattr(args, "discovery_source", None),
                provider_binary_sha256=provider_receipt_digest(args),
            )
            for role in ("a", "b")
        }
        for role, receipt in receipts.items():
            before = resource_before[role]
            after = resource_after[role]
            receipt["experiment_resources"] = {
                "cpu_usage_usec": after["cpu_usage_usec"] - before["cpu_usage_usec"],
                "network_bytes": after["network_bytes"] - before["network_bytes"],
                "memory_current_bytes": resource_live[role]["memory_current_bytes"],
                "memory_peak_bytes": after["memory_peak_bytes"],
                "memory_current_sample_phase": "exact-item-observation-before-process-wait",
                "memory_current_candidate_running": True,
                "counter_scope": "whole container cgroup; all non-loopback interfaces",
                "durable_item_present_before_contact": durable_before[role],
                "durable_item_first_observed_ms_from_process_launch": (
                    0 if role == "a" else observed_ms
                ),
                "durable_probe_scope": "read-only exact ItemID row; 10 ms controller polling",
            }

        require_exact_peer_evidence(
            receipts["a"], {identities["b"]}, arm=args.arm, label="normal sender"
        )
        require_exact_peer_evidence(
            receipts["b"], {identities["a"]}, arm=args.arm, label="receive-only node"
        )
        if any(receipt.get("unauthorized_peers") for receipt in receipts.values()):
            raise ExperimentError("receive-only trial retained an unauthorized peer")
        if any(
            protected_discovery_announcement_count(receipt) != 0
            for receipt in receipts.values()
        ):
            raise ExperimentError("discovery-disabled receive-only trial emitted discovery")
        if any(
            receipt.get("discovery_enabled_final") is not False
            for receipt in receipts.values()
            if "discovery_enabled_final" in receipt
        ):
            raise ExperimentError("provider discovery remained enabled")
        if receipts["b"].get("frames_received", 0) < 1:
            raise ExperimentError("receive-only node recorded no inbound Aster frames")

        custody = run_offline(
            runner,
            args,
            trial_root,
            ["mesh-verify-relay", "--root", "/lab/run", "--invocation", invocation],
        )
        if not all(
            custody.get(field) is True
            for field in (
                "exact_envelope",
                "application_unreadable",
                "payload_absent_at_rest",
                "payload_digest_absent_at_rest",
            )
        ):
            raise ExperimentError("receive-only route custody did not pass every gate")
        if topology["network"].get("Internal") is not True:
            raise ExperimentError("receive-only network is not internal-only")

        result = {
            "schema": SCHEMA,
            "scenario": "receive-only",
            "arm": args.arm,
            "trial": trial,
            "passed": True,
            "elapsed_ms": int((time.monotonic() - started) * 1_000),
            "identities": identities,
            "item_id": prepare.get("item_id"),
            "all_nodes_running_when_b_observed": all_nodes_running_when_observed,
            "b_item_observed_ms_from_process_launch": observed_ms,
            "discovery_announcements": 0,
            "receive_only_control_bytes_allowed": True,
            "custody": custody,
            "receipts": receipts,
        }
        write_json(trial_root / "result.json", result)
        return result
    finally:
        remove_resources(runner, containers, network)
        finalize_processes(runner, processes)


def read_container_integer(runner: Runner, container: str, path: str) -> int:
    value = runner.run(["docker", "exec", container, "/usr/bin/cat", path]).stdout.strip()
    try:
        parsed = int(value)
    except ValueError as error:
        raise ExperimentError(f"container counter is not an integer: {path}") from error
    if parsed < 0:
        raise ExperimentError(f"container counter is negative: {path}")
    return parsed


def read_cpu_usage_usec(runner: Runner, container: str) -> int:
    text = runner.run(
        ["docker", "exec", container, "/usr/bin/cat", "/sys/fs/cgroup/cpu.stat"]
    ).stdout
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == "usage_usec":
            return int(fields[1])
    raise ExperimentError("cgroup cpu.stat has no usage_usec")


def sum_non_loopback_network_bytes(value: Any) -> int:
    if not isinstance(value, list):
        raise ExperimentError("ip link statistics are not an array")
    total = 0
    observed = 0
    for link in value:
        if not isinstance(link, dict) or not isinstance(link.get("ifname"), str):
            raise ExperimentError("ip link statistics contain a malformed interface")
        if link["ifname"] == "lo":
            continue
        statistics = link.get("stats64", link.get("stats"))
        if not isinstance(statistics, dict):
            raise ExperimentError(
                f"ip link statistics are absent for {link['ifname']}"
            )
        try:
            received = statistics["rx"]["bytes"]
            sent = statistics["tx"]["bytes"]
        except (KeyError, TypeError) as error:
            raise ExperimentError(
                f"ip link byte counters are malformed for {link['ifname']}"
            ) from error
        if (
            isinstance(received, bool)
            or not isinstance(received, int)
            or received < 0
            or isinstance(sent, bool)
            or not isinstance(sent, int)
            or sent < 0
        ):
            raise ExperimentError(
                f"ip link byte counters are invalid for {link['ifname']}"
            )
        total += received + sent
        observed += 1
    if observed == 0:
        raise ExperimentError("no non-loopback interface was measured")
    return total


def read_network_bytes(runner: Runner, container: str) -> int:
    result = runner.run(
        ["docker", "exec", container, "/usr/sbin/ip", "-j", "-s", "link", "show"]
    )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ExperimentError("ip link statistics are invalid JSON") from error
    return sum_non_loopback_network_bytes(value)


def read_resource_counters(runner: Runner, container: str) -> dict[str, int]:
    return {
        "cpu_usage_usec": read_cpu_usage_usec(runner, container),
        "network_bytes": read_network_bytes(runner, container),
        "memory_current_bytes": read_container_integer(
            runner, container, "/sys/fs/cgroup/memory.current"
        ),
        "memory_peak_bytes": read_container_integer(
            runner, container, "/sys/fs/cgroup/memory.peak"
        ),
    }


def run_idle_trial(
    runner: Runner, args: argparse.Namespace, run_id: str, trial: int
) -> dict[str, Any]:
    if args.duration_ms < args.settle_ms + 60_000:
        raise ExperimentError("idle duration must include settling plus at least one measured minute")
    trial_root = args.root / f"trial-{trial:02d}"
    trial_root.mkdir(parents=True)
    prepare = run_offline(
        runner,
        args,
        trial_root,
        [
            "mesh-prepare",
            "--root",
            "/lab/run",
            "--seed",
            str(args.seed + trial),
            "--payload-bytes",
            str(args.payload_bytes),
        ],
    )
    network, gateway, broadcast = create_network(runner, args.arm, run_id, trial, "idle")
    subnet, _, _ = network_spec(args.arm, trial, "idle")
    second, third = subnet.split(".")[1:3]
    containers: list[str] = []
    started = time.monotonic()
    try:
        if args.arm in ARMS and needs_discovery_token(args):
            copy_discovery_token(trial_root, "a")
        container = create_node_container(
            runner,
            args=args,
            run_id=run_id,
            trial=trial,
            phase="idle",
            role="a",
            node_root=trial_root / "a",
            bundle=trial_root / "private" / "a.bundle",
            network=network,
            address=f"10.{second}.{third}.10",
            gateway=gateway,
        )
        containers.append(container)
        topology = inspect_topology(runner, network, containers)
        write_json(trial_root / "topology-idle.json", topology)
        process = runner.popen(
            node_exec_command(
                args=args,
                container=container,
                invocation=f"t{trial:02d}_idle",
                expected_peer="",
                broadcast=broadcast,
                discovery_enabled=True,
            )
        )
        cpu_start = read_cpu_usage_usec(runner, container)
        time.sleep(args.settle_ms / 1000)
        cpu_settled = read_cpu_usage_usec(runner, container)
        network_settled = read_network_bytes(runner, container)
        memory_settled = read_container_integer(
            runner, container, "/sys/fs/cgroup/memory.current"
        )
        remaining = args.duration_ms - args.settle_ms
        runner.wait_process(process, remaining / 1000 + 20)
        cpu_final = read_cpu_usage_usec(runner, container)
        network_final = read_network_bytes(runner, container)
        memory_peak = read_container_integer(
            runner, container, "/sys/fs/cgroup/memory.peak"
        )
        pids_final = read_container_integer(
            runner, container, "/sys/fs/cgroup/pids.current"
        )
        receipt = read_final_receipt(
            trial_root,
            "a",
            args.arm,
            f"t{trial:02d}_idle",
            discovery_source=getattr(args, "discovery_source", None),
            provider_binary_sha256=provider_receipt_digest(args),
        )
        total_cpu_percent = (cpu_final - cpu_start) / (args.duration_ms * 10.0)
        settled_minutes = remaining / 60_000
        settled_network_bytes = network_final - network_settled
        settled_bytes_per_minute = settled_network_bytes / settled_minutes
        passed = (
            receipt.get("identity") == prepare.get("publisher")
            and not receipt.get("authenticated_peers")
            and receipt.get("frames_received") == 0
            and receipt.get("frames_sent") == 0
            and total_cpu_percent < 1.0
            and settled_bytes_per_minute <= 4_096
        )
        result = {
            "schema": SCHEMA,
            "scenario": "idle",
            "arm": args.arm,
            "trial": trial,
            "passed": passed,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "duration_ms": args.duration_ms,
            "settle_ms": args.settle_ms,
            "cpu_usage_usec_total": cpu_final - cpu_start,
            "cpu_usage_usec_settling": cpu_settled - cpu_start,
            "cpu_percent_of_one_core_total": total_cpu_percent,
            "settled_network_bytes": settled_network_bytes,
            "settled_network_bytes_per_minute": settled_bytes_per_minute,
            "network_counter_scope": "all non-loopback interfaces, rx+tx including link-layer bytes",
            "memory_current_after_settle_bytes": memory_settled,
            "memory_peak_bytes": memory_peak,
            "pids_after_node_exit": pids_final,
            "receipt": receipt,
        }
        write_json(trial_root / "result.json", result)
        return result
    finally:
        remove_resources(runner, containers, network)


def run_multi_peer_trial(
    runner: Runner, args: argparse.Namespace, run_id: str, trial: int
) -> dict[str, Any]:
    trial_root = args.root / f"trial-{trial:02d}"
    trial_root.mkdir(parents=True)
    prepare = run_offline(
        runner,
        args,
        trial_root,
        [
            "mesh-prepare",
            "--root",
            "/lab/run",
            "--seed",
            str(args.seed + trial),
            "--payload-bytes",
            str(args.payload_bytes),
        ],
    )
    identities = {
        "a": prepare["publisher"],
        "b": prepare["relay"],
        "c": prepare["consumer"],
    }
    network, gateway, broadcast = create_network(runner, args.arm, run_id, trial, "multi")
    subnet, _, _ = network_spec(args.arm, trial, "multi")
    second, third = subnet.split(".")[1:3]
    containers: list[str] = []
    started = time.monotonic()
    try:
        if args.arm in ARMS and needs_discovery_token(args):
            for role in ("a", "b", "c"):
                copy_discovery_token(trial_root, role)
        for index, role in enumerate(("a", "b", "c"), start=10):
            containers.append(
                create_node_container(
                    runner,
                    args=args,
                    run_id=run_id,
                    trial=trial,
                    phase="multi",
                    role=role,
                    node_root=trial_root / role,
                    bundle=trial_root / "private" / f"{role}.bundle",
                    network=network,
                    address=f"10.{second}.{third}.{index}",
                    gateway=gateway,
                )
            )
        topology = inspect_topology(runner, network, containers)
        write_json(trial_root / "topology-multi.json", topology)
        expected = {
            "a": identities["b"],
            "b": f"{identities['a']},{identities['c']}",
            "c": identities["b"],
        }
        processes = [
            runner.popen(
                node_exec_command(
                    args=args,
                    container=container,
                    invocation=f"t{trial:02d}_multi",
                    expected_peer=expected[role],
                    broadcast=broadcast,
                )
            )
            for role, container in zip(("a", "b", "c"), containers, strict=True)
        ]
        timeout = args.duration_ms / 1000 + 20
        for process in processes:
            runner.wait_process(process, timeout)
        receipts = {
            role: read_final_receipt(
                trial_root,
                role,
                args.arm,
                f"t{trial:02d}_multi",
                discovery_source=getattr(args, "discovery_source", None),
                provider_binary_sha256=provider_receipt_digest(args),
            )
            for role in ("a", "b", "c")
        }
        relay_peers = set(receipts["b"].get("authenticated_peers", []))
        expected_relay_peers = {identities["a"], identities["c"]}
        expected_peers = {
            "a": {identities["b"]},
            "b": expected_relay_peers,
            "c": {identities["b"]},
        }
        passed = (
            all(
                receipt_has_exact_peer_evidence(
                    receipts[role], expected_peers[role], arm=args.arm
                )
                for role in ("a", "b", "c")
            )
            and admitted_contact_high_water(receipts["b"], label="B") >= 2
        )
        result = {
            "schema": SCHEMA,
            "scenario": "multi-peer",
            "arm": args.arm,
            "trial": trial,
            "passed": passed,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "relay_expected_peers": sorted(expected_relay_peers),
            "relay_authenticated_peers": sorted(relay_peers),
            "relay_active_contact_high_water": receipts["b"].get(
                "active_contact_high_water"
            ),
            "relay_admitted_contact_high_water": admitted_contact_high_water(
                receipts["b"], label="B"
            ),
            "endpoint_unexpected_peer_observations": {
                role: receipts[role].get("unauthorized_peers", []) for role in ("a", "c")
            },
            "receipts": receipts,
        }
        write_json(trial_root / "result.json", result)
        return result
    finally:
        remove_resources(runner, containers, network)


def run_live_relay_trial(
    runner: Runner, args: argparse.Namespace, run_id: str, trial: int
) -> dict[str, Any]:
    """Prove live A->B->C custody across two isolated IP segments.

    B and C must authenticate while A is still offline.  A is launched only
    after that prerequisite is retained in both live status receipts.  The
    exact source ItemID must then appear at C while all three processes remain
    alive, which exercises cross-contact inventory notification rather than a
    restart-rehydration shortcut.
    """
    if args.duration_ms < 6_000:
        raise ExperimentError("live-relay duration must be at least 6000 ms")
    trial_root = args.root / f"trial-{trial:02d}"
    trial_root.mkdir(parents=True)
    prepare = run_offline(
        runner,
        args,
        trial_root,
        [
            "mesh-prepare",
            "--root",
            "/lab/run",
            "--seed",
            str(args.seed + trial),
            "--payload-bytes",
            str(args.payload_bytes),
        ],
    )
    identities = {
        "a": prepare["publisher"],
        "b": prepare["relay"],
        "c": prepare["consumer"],
    }
    if any(
        not isinstance(value, str) or not HEX_64.fullmatch(value)
        for value in identities.values()
    ):
        raise ExperimentError("preparation emitted malformed node identities")

    carrier_ids = dict(identities)
    if args.arm == "iroh":
        carrier_ids = {
            role: initialize_iroh_carrier(runner, args, trial_root, role)
            for role in ("a", "b", "c")
        }

    subnet_ab, _, _ = network_spec(args.arm, trial, "live-ab")
    subnet_bc, _, _ = network_spec(args.arm, trial, "live-bc")
    ab_second, ab_third = subnet_ab.split(".")[1:3]
    bc_second, bc_third = subnet_bc.split(".")[1:3]
    addresses = {
        "a": f"10.{ab_second}.{ab_third}.10",
        "b_ab": f"10.{ab_second}.{ab_third}.11",
        "b_bc": f"10.{bc_second}.{bc_third}.10",
        "c": f"10.{bc_second}.{bc_third}.11",
    }
    containers: list[str] = []
    processes: dict[str, subprocess.Popen[str]] = {}
    process_started: dict[str, float] = {}
    started = time.monotonic()
    invocation = f"t{trial:02d}_live"
    network_ab: str | None = None
    network_bc: str | None = None
    try:
        expected_item = (trial_root / "expected-item-id.bin").read_bytes()
        network_ab, gateway_ab, broadcast_ab = create_network(
            runner, args.arm, run_id, trial, "live-ab"
        )
        network_bc, gateway_bc, broadcast_bc = create_network(
            runner, args.arm, run_id, trial, "live-bc"
        )
        if needs_discovery_token(args):
            for role in ("a", "b", "c"):
                copy_discovery_token(trial_root, role)

        a_container = create_node_container(
            runner,
            args=args,
            run_id=run_id,
            trial=trial,
            phase="live",
            role="a",
            node_root=trial_root / "a",
            bundle=trial_root / "private" / "a.bundle",
            network=network_ab,
            address=addresses["a"],
            gateway=gateway_ab,
        )
        containers.append(a_container)
        b_container = create_node_container(
            runner,
            args=args,
            run_id=run_id,
            trial=trial,
            phase="live",
            role="b",
            node_root=trial_root / "b",
            bundle=trial_root / "private" / "b.bundle",
            network=network_ab,
            address=addresses["b_ab"],
            gateway=gateway_ab,
        )
        containers.append(b_container)
        c_container = create_node_container(
            runner,
            args=args,
            run_id=run_id,
            trial=trial,
            phase="live",
            role="c",
            node_root=trial_root / "c",
            bundle=trial_root / "private" / "c.bundle",
            network=network_bc,
            address=addresses["c"],
            gateway=gateway_bc,
        )
        containers.append(c_container)
        runner.run(
            [
                "docker",
                "network",
                "connect",
                "--ip",
                addresses["b_bc"],
                network_bc,
                b_container,
            ]
        )

        topology_ab = inspect_topology(runner, network_ab, (a_container, b_container))
        topology_bc = inspect_topology(runner, network_bc, (b_container, c_container))
        write_json(trial_root / "topology-live-ab.json", topology_ab)
        write_json(trial_root / "topology-live-bc.json", topology_bc)

        commands = {
            "a": node_exec_command(
                args=args,
                container=a_container,
                invocation=invocation,
                expected_peer=identities["b"],
                broadcast=broadcast_ab,
                discovery_enabled=False,
                manual_peers=f"{carrier_ids['b']}@{addresses['b_ab']}:47101",
            ),
            "b": node_exec_command(
                args=args,
                container=b_container,
                invocation=invocation,
                expected_peer=f"{identities['a']},{identities['c']}",
                broadcast=broadcast_ab,
                discovery_enabled=False,
                manual_peers=(
                    f"{carrier_ids['a']}@{addresses['a']}:47101,"
                    f"{carrier_ids['c']}@{addresses['c']}:47101"
                ),
            ),
            "c": node_exec_command(
                args=args,
                container=c_container,
                invocation=invocation,
                expected_peer=identities["b"],
                broadcast=broadcast_bc,
                discovery_enabled=False,
                manual_peers=f"{carrier_ids['b']}@{addresses['b_bc']}:47101",
            ),
        }
        resource_before = {
            role: read_resource_counters(runner, container)
            for role, container in zip(
                ("a", "b", "c"), containers, strict=True
            )
        }
        durable_before = {
            role: durable_item_present(
                trial_root / role / "state.sqlite", expected_item
            )
            for role in ("a", "b", "c")
        }
        if durable_before != {"a": True, "b": False, "c": False}:
            raise ExperimentError(
                "live-relay precondition differs: only A may hold the source ItemID"
            )

        # Establish and retain B<->C before A is allowed to enter the topology.
        for role in ("b", "c"):
            process_started[role] = time.monotonic()
            processes[role] = runner.popen(commands[role])
        prerequisite_ms = wait_for_authenticated_pair(
            trial_root=trial_root,
            arm=args.arm,
            invocation=invocation,
            first_role="b",
            second_role="c",
            first_identity=identities["b"],
            second_identity=identities["c"],
            first_process=processes["b"],
            second_process=processes["c"],
            timeout=min(10.0, args.duration_ms / 2_000),
            discovery_source=getattr(args, "discovery_source", None),
            provider_binary_sha256=provider_receipt_digest(args),
        )
        process_started["a"] = time.monotonic()
        processes["a"] = runner.popen(commands["a"])

        observed_ms: dict[str, int | None] = {"a": 0, "b": None, "c": None}
        all_nodes_running_when_c_observed = False
        fanout_evidence: dict[str, Any] | None = None
        b_events_path = (
            trial_root / "b" / f"{args.arm}-mesh-{invocation}-events.jsonl"
        )
        observation_deadline = min(process_started["b"], process_started["c"]) + (
            args.duration_ms / 1_000
        )
        while time.monotonic() < observation_deadline:
            now = time.monotonic()
            for role in ("b", "c"):
                if observed_ms[role] is None and durable_item_present(
                    trial_root / role / "state.sqlite", expected_item
                ):
                    observed_ms[role] = int((now - process_started[role]) * 1_000)
                    if role == "c":
                        all_nodes_running_when_c_observed = all(
                            process.poll() is None for process in processes.values()
                        )
            if fanout_evidence is None:
                fanout_evidence = inventory_fanout_from_peer(
                    b_events_path, identities["a"]
                )
            if (
                observed_ms["b"] is not None
                and observed_ms["c"] is not None
                and fanout_evidence is not None
            ):
                break
            if any(process.poll() is not None for process in processes.values()):
                break
            time.sleep(0.01)
        if observed_ms["b"] is None or observed_ms["c"] is None:
            early_exits = {
                role: returncode
                for role, process in processes.items()
                if (returncode := process.poll()) is not None
            }
            detail = (
                "; candidate processes exited early: "
                + ",".join(
                    f"{role}={returncode}"
                    for role, returncode in sorted(early_exits.items())
                )
                if early_exits
                else ""
            )
            raise ExperimentError(
                "exact source ItemID did not propagate through both live contacts"
                + detail
            )
        if not all_nodes_running_when_c_observed:
            raise ExperimentError(
                "C observed the source ItemID only after a node process had exited"
            )
        if fanout_evidence is None:
            raise ExperimentError(
                "B did not record a commit from A fanned out to another live contact"
            )
        resource_live = {
            role: read_resource_counters(runner, container)
            for role, container in zip(
                ("a", "b", "c"), containers, strict=True
            )
        }

        timeout = args.duration_ms / 1_000 + 20
        for role in ("a", "b", "c"):
            runner.wait_process(processes[role], timeout)
        resource_after = {
            role: read_resource_counters(runner, container)
            for role, container in zip(
                ("a", "b", "c"), containers, strict=True
            )
        }
        receipts = {
            role: read_final_receipt(
                trial_root,
                role,
                args.arm,
                invocation,
                discovery_source=getattr(args, "discovery_source", None),
                provider_binary_sha256=provider_receipt_digest(args),
            )
            for role in ("a", "b", "c")
        }
        for role, receipt in receipts.items():
            before = resource_before[role]
            after = resource_after[role]
            receipt["experiment_resources"] = {
                "cpu_usage_usec": after["cpu_usage_usec"] - before["cpu_usage_usec"],
                "network_bytes": after["network_bytes"] - before["network_bytes"],
                "memory_current_bytes": resource_live[role]["memory_current_bytes"],
                "memory_peak_bytes": after["memory_peak_bytes"],
                "memory_current_sample_phase": "exact-item-observation-before-process-wait",
                "memory_current_candidate_running": True,
                "counter_scope": "whole container cgroup; all non-loopback interfaces",
                "durable_item_present_before_contact": durable_before[role],
                "durable_item_first_observed_ms_from_process_launch": observed_ms[role],
                "durable_probe_scope": "read-only exact ItemID row; 10 ms controller polling",
            }

        require_exact_peer_evidence(
            receipts["a"], {identities["b"]}, arm=args.arm, label="A"
        )
        require_exact_peer_evidence(
            receipts["b"],
            {identities["a"], identities["c"]},
            arm=args.arm,
            label="B",
        )
        require_exact_peer_evidence(
            receipts["c"], {identities["b"]}, arm=args.arm, label="C"
        )
        if any(receipt.get("unauthorized_peers") for receipt in receipts.values()):
            raise ExperimentError("live relay retained an unauthorized peer")
        if admitted_contact_high_water(receipts["b"], label="B") < 2:
            raise ExperimentError(
                "B never retained two semantically admitted contacts concurrently"
            )
        if args.arm in ("iroh", "libp2p"):
            manual_counts = {
                role: receipt.get("manual_candidates")
                for role, receipt in receipts.items()
            }
            if manual_counts != {"a": 1, "b": 2, "c": 1}:
                raise ExperimentError(
                    f"live relay manual candidate counts differ: {manual_counts}"
                )

        custody = run_offline(
            runner,
            args,
            trial_root,
            ["mesh-verify-relay", "--root", "/lab/run", "--invocation", invocation],
        )
        if not all(
            custody.get(field) is True
            for field in (
                "exact_envelope",
                "application_unreadable",
                "payload_absent_at_rest",
                "payload_digest_absent_at_rest",
            )
        ):
            raise ExperimentError("live route-only custody did not pass every gate")
        delivery = run_offline(
            runner,
            args,
            trial_root,
            ["mesh-consume", "--root", "/lab/run", "--invocation", invocation],
        )
        if not all(
            delivery.get(field) is True
            for field in ("same_item", "same_envelope", "application_acknowledged")
        ) or delivery.get("immediate_post_ack_deliveries") != 0 or delivery.get(
            "post_restart_deliveries"
        ) != 0:
            raise ExperimentError("live consumer delivery/acknowledgement failed")

        def network_members(topology: dict[str, Any]) -> set[str]:
            members = topology["network"].get("Containers", {})
            return {entry["Name"] for entry in members.values()}

        if network_members(topology_ab) != {a_container, b_container}:
            raise ExperimentError("A/B segment contains an unexpected container")
        if network_members(topology_bc) != {b_container, c_container}:
            raise ExperimentError("B/C segment contains an unexpected container")
        if (
            topology_ab["network"].get("Internal") is not True
            or topology_bc["network"].get("Internal") is not True
        ):
            raise ExperimentError("live relay segment is not internal-only")

        result = {
            "schema": SCHEMA,
            "scenario": "live-relay",
            "arm": args.arm,
            "trial": trial,
            "passed": True,
            "elapsed_ms": int((time.monotonic() - started) * 1_000),
            "identities": identities,
            "item_id": prepare.get("item_id"),
            "envelope_id": prepare.get("envelope_id"),
            "bc_authenticated_before_a_started": True,
            "bc_prerequisite_ms": prerequisite_ms,
            "all_nodes_running_when_c_observed": all_nodes_running_when_c_observed,
            "b_commit_fanout_observed_before_c_verification": True,
            "b_commit_fanout": fanout_evidence,
            "c_item_observed_ms_from_process_launch": observed_ms["c"],
            "relay_active_contact_high_water": receipts["b"].get(
                "active_contact_high_water"
            ),
            "relay_admitted_contact_high_water": admitted_contact_high_water(
                receipts["b"], label="B"
            ),
            "a_c_contact_count": 0,
            "internal_only_segmented_networks": True,
            "custody": custody,
            "delivery": delivery,
            "receipts": receipts,
        }
        write_json(trial_root / "result.json", result)
        return result
    finally:
        finalize_processes(runner, processes)
        if network_ab is not None:
            remove_resources(runner, containers, network_ab)
        elif containers:
            for container in containers:
                runner.run(["docker", "rm", "--force", container], check=False)
        if network_bc is not None:
            runner.run(["docker", "network", "rm", network_bc], check=False)


def _run_gate_h_trial_body(
    runner: Runner, args: argparse.Namespace, run_id: str, trial: int
) -> dict[str, Any]:
    """Run the provider-free, combined real-process shared-node proof.

    The first B process uses the lab-only Flash/control-serving mode so it can
    authenticate A and C, request Routine-or-higher inbound data, and take
    route-only custody without forwarding A's Immediate Event. A and the first
    B process then exit while C remains continuously running.
    Custody is verified while B is stopped, after which a fresh B process must
    authenticate to that same C process and deliver from B's unchanged durable
    store.  A remains offline, so the post-restart delivery cannot use an A-to-C
    shortcut or re-fetch from the publisher.
    """

    if args.arm != "native":
        raise ExperimentError("Gate H must use the provider-free native control")
    if args.duration_ms < 6_000:
        raise ExperimentError("Gate H requires at least 6000 ms per process phase")
    process_durations = gate_h_process_durations(args.duration_ms)

    trial_root = args.root / f"trial-{trial:02d}"
    trial_root.mkdir(parents=True)
    prepare = run_offline(
        runner,
        args,
        trial_root,
        [
            "mesh-prepare",
            "--root",
            "/lab/run",
            "--seed",
            str(args.seed + trial),
            "--payload-bytes",
            str(args.payload_bytes),
        ],
        container_name=resource_name(run_id, trial, "offline", "prepare"),
    )
    identities = {
        "a": prepare["publisher"],
        "b": prepare["relay"],
        "c": prepare["consumer"],
    }
    if any(
        not isinstance(identity, str) or not HEX_64.fullmatch(identity)
        for identity in identities.values()
    ):
        raise ExperimentError("Gate-H preparation emitted malformed identities")
    authorization_control = prepared_gate_h_authorization_control(
        prepare, trial_root, identities
    )

    expected_item = (trial_root / "expected-item-id.bin").read_bytes()
    subnet_ab, _, _ = network_spec(args.arm, trial, "live-ab")
    subnet_bc, _, _ = network_spec(args.arm, trial, "live-bc")
    ab_second, ab_third = subnet_ab.split(".")[1:3]
    bc_second, bc_third = subnet_bc.split(".")[1:3]
    addresses = {
        "a": f"10.{ab_second}.{ab_third}.10",
        "b_ab": f"10.{ab_second}.{ab_third}.11",
        "b_bc": f"10.{bc_second}.{bc_third}.10",
        "c": f"10.{bc_second}.{bc_third}.11",
    }
    containers = [
        resource_name(run_id, trial, "gate", role) for role in ("a", "b", "c")
    ]
    all_processes: list[subprocess.Popen[str]] = []
    network_ab: str | None = resource_name(run_id, trial, "live-ab")
    network_bc: str | None = resource_name(run_id, trial, "live-bc")
    started = time.monotonic()
    pre_invocation = f"t{trial:02d}_gate_pre"
    post_invocation = f"t{trial:02d}_gate_post"
    primary_error: BaseException | None = None
    try:
        network_ab, gateway_ab, broadcast_ab = create_network(
            runner, args.arm, run_id, trial, "live-ab"
        )
        network_bc, gateway_bc, broadcast_bc = create_network(
            runner, args.arm, run_id, trial, "live-bc"
        )
        for role in ("a", "b", "c"):
            copy_discovery_token(trial_root, role)

        a_container = create_node_container(
            runner,
            args=args,
            run_id=run_id,
            trial=trial,
            phase="gate",
            role="a",
            node_root=trial_root / "a",
            bundle=trial_root / "private" / "a.bundle",
            network=network_ab,
            address=addresses["a"],
            gateway=gateway_ab,
        )
        b_container = create_node_container(
            runner,
            args=args,
            run_id=run_id,
            trial=trial,
            phase="gate",
            role="b",
            node_root=trial_root / "b",
            bundle=trial_root / "private" / "b.bundle",
            network=network_ab,
            address=addresses["b_ab"],
            gateway=gateway_ab,
        )
        c_container = create_node_container(
            runner,
            args=args,
            run_id=run_id,
            trial=trial,
            phase="gate",
            role="c",
            node_root=trial_root / "c",
            bundle=trial_root / "private" / "c.bundle",
            network=network_bc,
            address=addresses["c"],
            gateway=gateway_bc,
        )
        if [a_container, b_container, c_container] != containers:
            raise ExperimentError("Gate-H container names differ from the cleanup plan")
        runner.run(
            [
                "docker",
                "network",
                "connect",
                "--ip",
                addresses["b_bc"],
                network_bc,
                b_container,
            ]
        )

        topology_ab = inspect_topology(runner, network_ab, (a_container, b_container))
        topology_bc = inspect_topology(runner, network_bc, (b_container, c_container))
        write_json(trial_root / "topology-gate-h-ab.json", topology_ab)
        write_json(trial_root / "topology-gate-h-bc.json", topology_bc)
        if {
            role: durable_item_present(trial_root / role / "state.sqlite", expected_item)
            for role in ("a", "b", "c")
        } != {"a": True, "b": False, "c": False}:
            raise ExperimentError("Gate-H precondition differs: only A may hold the item")
        expected_item_hex = expected_item.hex()

        pre_commands = {
            "a": node_exec_command(
                args=args,
                container=a_container,
                invocation=pre_invocation,
                expected_peer=identities["b"],
                broadcast=broadcast_ab,
                discovery_enabled=False,
                manual_peers=f"{identities['b']}@{addresses['b_ab']}:47101",
                duration_ms=process_durations["a_pre"],
                durable_item_probe=expected_item_hex,
            ),
            "b": node_exec_command(
                args=args,
                container=b_container,
                invocation=pre_invocation,
                expected_peer=f"{identities['a']},{identities['c']}",
                broadcast=broadcast_ab,
                discovery_enabled=False,
                emission_mode=GATE_H_FLASH_ONLY_EMISSION_MODE,
                manual_peers=gate_h_relay_manual_peers(identities, addresses),
                duration_ms=process_durations["b_pre"],
                gate_h_control=GATE_H_CONTROL_PATH,
                gate_h_stale_target_peer=identities["c"],
                durable_item_probe=expected_item_hex,
            ),
            "c": node_exec_command(
                args=args,
                container=c_container,
                invocation=pre_invocation,
                expected_peer=identities["b"],
                broadcast=broadcast_bc,
                discovery_enabled=False,
                manual_peers=f"{identities['b']}@{addresses['b_bc']}:47101",
                duration_ms=process_durations["c_continuous"],
                durable_item_probe=expected_item_hex,
            ),
        }
        pre_processes = {
            role: runner.popen(pre_commands[role]) for role in ("b", "c", "a")
        }
        all_processes.extend(pre_processes.values())
        pre_admitted_ms = wait_for_exact_peer_sets(
            trial_root=trial_root,
            arm=args.arm,
            invocation=pre_invocation,
            identities=identities,
            expected={
                "a": {identities["b"]},
                "b": {identities["a"], identities["c"]},
                "c": {identities["b"]},
            },
            processes=pre_processes,
            timeout=min(10.0, args.duration_ms / 1_000),
        )

        custody_observed_ms: int | None = None
        c_status_elapsed_at_custody = -1
        durable_item_observations: dict[str, dict[str, Any]] | None = None
        observation_started = time.monotonic()
        deadline = observation_started + (args.duration_ms / 1_000)
        while time.monotonic() < deadline:
            b_status = read_status_receipt(
                trial_root, "b", args.arm, pre_invocation
            )
            c_status = read_status_receipt(
                trial_root, "c", args.arm, pre_invocation
            )
            c_present = native_status_durable_item_present(
                c_status, expected_item, label="Gate-H live C"
            )
            if c_present is True:
                raise ExperimentError("Gate-H Flash-only B forwarded the Event before restart")
            b_present = native_status_durable_item_present(
                b_status, expected_item, label="Gate-H live B"
            )
            if b_present is True and c_status is not None:
                custody_observed_ms = int(
                    (time.monotonic() - observation_started) * 1_000
                )
                b_status_elapsed_at_custody = _strict_nonnegative_integer(
                    b_status.get("elapsed_ms"), field="Gate-H live B elapsed_ms"
                )
                c_status_elapsed_at_custody = _strict_nonnegative_integer(
                    c_status.get("elapsed_ms"), field="Gate-H live C elapsed_ms"
                )
                durable_item_observations = {
                    "b_custody": {
                        "item_id": expected_item_hex,
                        "present": True,
                        "elapsed_ms": b_status_elapsed_at_custody,
                    },
                    "c_at_b_custody": {
                        "item_id": expected_item_hex,
                        "present": False,
                        "elapsed_ms": c_status_elapsed_at_custody,
                    },
                }
                break
            early = {
                role: process.poll()
                for role, process in pre_processes.items()
                if process.poll() is not None
            }
            if early:
                raise ExperimentError(
                    "Gate-H node exited before B retained durable custody: "
                    + ",".join(
                        f"{role}={returncode}"
                        for role, returncode in sorted(early.items())
                    )
                )
            time.sleep(0.01)
        if custody_observed_ms is None:
            raise ExperimentError("Gate-H B did not retain the exact ItemID before restart")
        if durable_item_observations is None:
            raise ExperimentError("Gate-H did not retain exact custody status evidence")
        if not all(process.poll() is None for process in pre_processes.values()):
            raise ExperimentError("Gate-H custody was not observed with all three nodes live")

        pre_returncodes = {
            role: runner.wait_process(
                pre_processes[role], process_durations[f"{role}_pre"] / 1_000 + 20
            )
            for role in ("a", "b")
        }
        if pre_processes["c"].poll() is not None:
            raise ExperimentError("Gate-H C exited before B could restart")
        fresh_c_status: dict[str, Any] | None = None
        freshness_deadline = time.monotonic() + 1.0
        while time.monotonic() < freshness_deadline:
            candidate = read_status_receipt(
                trial_root, "c", args.arm, pre_invocation
            )
            if candidate is not None and _strict_nonnegative_integer(
                candidate.get("elapsed_ms"), field="Gate-H live C elapsed_ms"
            ) > c_status_elapsed_at_custody:
                fresh_c_status = candidate
                break
            if pre_processes["c"].poll() is not None:
                raise ExperimentError("Gate-H C exited before its fresh absence proof")
            time.sleep(0.025)
        if fresh_c_status is None:
            raise ExperimentError("Gate-H C did not refresh its pre-restart item proof")
        if native_status_durable_item_present(
            fresh_c_status, expected_item, label="Gate-H pre-restart C"
        ):
            raise ExperimentError("Gate-H C received the item before B restarted")
        fresh_c_elapsed = _strict_nonnegative_integer(
            fresh_c_status.get("elapsed_ms"), field="Gate-H live C elapsed_ms"
        )
        durable_item_observations["c_pre_restart"] = {
            "item_id": expected_item_hex,
            "present": False,
            "elapsed_ms": fresh_c_elapsed,
        }
        pre_receipts = {
            role: read_final_receipt(trial_root, role, args.arm, pre_invocation)
            for role in ("a", "b")
        }
        for role, receipt in pre_receipts.items():
            validate_gate_h_native_receipt(
                receipt,
                label=f"Gate-H {role.upper()} pre-restart receipt",
                expected_item_id=expected_item_hex,
            )
        require_exact_peer_evidence(
            pre_receipts["a"], {identities["b"]}, arm=args.arm, label="Gate-H A"
        )
        require_exact_peer_evidence(
            pre_receipts["b"],
            {identities["a"], identities["c"]},
            arm=args.arm,
            label="Gate-H B before restart",
        )
        if admitted_contact_high_water(pre_receipts["b"], label="Gate-H B") < 2:
            raise ExperimentError("Gate-H B did not hold two admitted contacts concurrently")
        if any(receipt.get("unauthorized_peers") for receipt in pre_receipts.values()):
            raise ExperimentError("Gate-H pre-restart receipt retained an unauthorized peer")

        custody = run_offline(
            runner,
            args,
            trial_root,
            ["mesh-verify-relay", "--root", "/lab/run", "--invocation", pre_invocation],
            container_name=resource_name(run_id, trial, "offline", "custody"),
        )
        if not all(
            custody.get(field) is True
            for field in (
                "exact_envelope",
                "application_unreadable",
                "payload_absent_at_rest",
                "payload_digest_absent_at_rest",
            )
        ):
            raise ExperimentError("Gate-H route-only custody did not pass every gate")

        c_event_path = (
            trial_root / "c" / f"{args.arm}-mesh-{pre_invocation}-events.jsonl"
        )
        c_pre_restart_contacts = admitted_contacts_from_peer(
            c_event_path, identities["b"]
        )
        if not c_pre_restart_contacts:
            raise ExperimentError(
                "Gate-H C had no admitted B contact immediately before restart"
            )
        post_command = node_exec_command(
            args=args,
            container=b_container,
            invocation=post_invocation,
            expected_peer=identities["c"],
            broadcast=broadcast_bc,
            discovery_enabled=False,
            manual_peers=f"{identities['c']}@{addresses['c']}:47101",
            duration_ms=process_durations["b_post"],
            durable_item_probe=expected_item_hex,
        )
        post_process = runner.popen(post_command)
        all_processes.append(post_process)
        post_admission_started = time.monotonic()
        post_admitted_ms: int | None = None
        c_new_contacts: set[int] = set()
        post_deadline = post_admission_started + min(10.0, args.duration_ms / 1_000)
        while time.monotonic() < post_deadline:
            b_status = read_status_receipt(
                trial_root, "b", args.arm, post_invocation
            )
            c_restarted_contacts = admitted_contacts_from_peer(
                c_event_path, identities["b"]
            )
            c_new_contacts = c_restarted_contacts - c_pre_restart_contacts
            if (
                b_status is not None
                and receipt_has_exact_peer_evidence(
                    b_status, {identities["c"]}, arm=args.arm
                )
                and c_new_contacts
            ):
                post_admitted_ms = int(
                    (time.monotonic() - post_admission_started) * 1_000
                )
                break
            if post_process.poll() is not None or pre_processes["c"].poll() is not None:
                raise ExperimentError(
                    "Gate-H node exited before fresh B/C authentication after restart"
                )
            time.sleep(0.025)
        if post_admitted_ms is None:
            raise ExperimentError(
                "Gate-H did not prove a second distinct C contact to restarted B"
            )
        delivery_started = time.monotonic()
        delivered_ms: int | None = None
        deadline = delivery_started + (args.duration_ms / 1_000)
        while time.monotonic() < deadline:
            c_status = read_status_receipt(
                trial_root, "c", args.arm, pre_invocation
            )
            if native_status_durable_item_present(
                c_status, expected_item, label="Gate-H post-restart C"
            ) is True:
                delivered_ms = int((time.monotonic() - delivery_started) * 1_000)
                break
            early = {
                role: process.poll()
                for role, process in {
                    "b": post_process,
                    "c": pre_processes["c"],
                }.items()
                if process.poll() is not None
            }
            if early:
                raise ExperimentError(
                    "Gate-H post-restart node exited before C received the item: "
                    + ",".join(
                        f"{role}={returncode}"
                        for role, returncode in sorted(early.items())
                    )
                )
            time.sleep(0.01)
        if delivered_ms is None:
            raise ExperimentError("Gate-H C did not receive the exact ItemID after B restart")
        if post_process.poll() is not None or pre_processes["c"].poll() is not None:
            raise ExperimentError("Gate-H delivery was not observed with B and C live")
        post_returncodes = {
            "b": runner.wait_process(
                post_process, process_durations["b_post"] / 1_000 + 20
            ),
            "c": runner.wait_process(
                pre_processes["c"],
                process_durations["c_continuous"] / 1_000 + 20,
            ),
        }
        c_final_contacts = admitted_contacts_from_peer(c_event_path, identities["b"])
        c_new_contacts = c_final_contacts - c_pre_restart_contacts
        if not c_new_contacts:
            raise ExperimentError(
                "Gate-H C final evidence lost the fresh post-restart B contact"
            )
        post_receipts = {
            "b": read_final_receipt(
                trial_root, "b", args.arm, post_invocation
            ),
            "c": read_final_receipt(
                trial_root, "c", args.arm, pre_invocation
            ),
        }
        for role, receipt in post_receipts.items():
            validate_gate_h_native_receipt(
                receipt,
                label=f"Gate-H {role.upper()} post-restart receipt",
                expected_item_id=expected_item_hex,
            )
        require_exact_peer_evidence(
            post_receipts["b"],
            {identities["c"]},
            arm=args.arm,
            label="Gate-H restarted B",
        )
        require_exact_peer_evidence(
            post_receipts["c"],
            {identities["b"]},
            arm=args.arm,
            label="Gate-H continuously running C",
        )
        if any(receipt.get("unauthorized_peers") for receipt in post_receipts.values()):
            raise ExperimentError("Gate-H post-restart receipt retained an unauthorized peer")

        b_events = read_event_log(
            trial_root / "b" / f"native-mesh-{pre_invocation}-events.jsonl"
        )
        c_events = read_event_log(c_event_path)
        live_control = validate_gate_h_live_control_evidence(
            control=authorization_control,
            identities=identities,
            receipts={
                "a": pre_receipts["a"],
                "b_pre": pre_receipts["b"],
                "b_post": post_receipts["b"],
                "c": post_receipts["c"],
            },
            b_events=b_events,
            c_events=c_events,
        )

        delivery = run_offline(
            runner,
            args,
            trial_root,
            ["mesh-consume", "--root", "/lab/run", "--invocation", post_invocation],
            container_name=resource_name(run_id, trial, "offline", "delivery"),
        )
        if not all(
            delivery.get(field) is True
            for field in ("same_item", "same_envelope", "application_acknowledged")
        ) or delivery.get("immediate_post_ack_deliveries") != 0 or delivery.get(
            "post_restart_deliveries"
        ) != 0:
            raise ExperimentError("Gate-H delivery, acknowledgement, or redelivery gate failed")

        def network_members(topology: dict[str, Any]) -> set[str]:
            return {
                entry["Name"]
                for entry in topology["network"].get("Containers", {}).values()
            }

        if network_members(topology_ab) != {a_container, b_container}:
            raise ExperimentError("Gate-H A/B segment contains an unexpected container")
        if network_members(topology_bc) != {b_container, c_container}:
            raise ExperimentError("Gate-H B/C segment contains an unexpected container")
        if (
            topology_ab["network"].get("Internal") is not True
            or topology_bc["network"].get("Internal") is not True
        ):
            raise ExperimentError("Gate-H segment is not internal-only")

        result = {
            "schema": SCHEMA,
            "scenario": "gate-h",
            "arm": args.arm,
            "trial": trial,
            "passed": True,
            "elapsed_ms": int((time.monotonic() - started) * 1_000),
            "identities": identities,
            "item_id": prepare.get("item_id"),
            "envelope_id": prepare.get("envelope_id"),
            "authorization_control": authorization_control,
            "live_control": live_control,
            "b_pre_emission_mode": GATE_H_FLASH_ONLY_EMISSION_MODE,
            "pre_restart_all_three_admitted_ms": pre_admitted_ms,
            "b_pre_restart_custody_observed_ms": custody_observed_ms,
            "b_pre_restart_admitted_contact_high_water": admitted_contact_high_water(
                pre_receipts["b"], label="Gate-H B"
            ),
            "durable_item_observations": durable_item_observations,
            "c_item_absent_before_b_restart": True,
            "publisher_offline_during_post_restart_delivery": True,
            "post_restart_bc_admitted_ms": post_admitted_ms,
            "c_post_restart_item_observed_ms": delivered_ms,
            "fresh_process_authentication_after_restart": True,
            "process_durations_ms": process_durations,
            "c_pre_restart_admitted_contact_ids_for_b": sorted(
                c_pre_restart_contacts
            ),
            "c_post_restart_new_admitted_contact_ids_for_b": sorted(c_new_contacts),
            "c_final_admitted_contact_ids_for_b": sorted(c_final_contacts),
            "c_distinct_admitted_contacts_for_b": len(c_final_contacts),
            "internal_only_segmented_networks": True,
            "pre_process_returncodes": pre_returncodes,
            "post_process_returncodes": post_returncodes,
            "custody": custody,
            "delivery": delivery,
            "receipts": {
                "a": pre_receipts["a"],
                "b_pre": pre_receipts["b"],
                "b_post": post_receipts["b"],
                "c": post_receipts["c"],
            },
        }
        write_json(trial_root / "result.json", result)
        return result
    except BaseException as error:
        primary_error = error
        raise
    finally:
        finalize_gate_h_trial_resources(
            runner,
            trial_root=trial_root,
            trial=trial,
            processes=all_processes,
            containers=containers,
            networks=(network_ab, network_bc),
            primary_error=primary_error,
        )


def run_gate_h_trial(
    runner: Runner, args: argparse.Namespace, run_id: str, trial: int
) -> dict[str, Any]:
    """Reserve the exact Gate-H cleanup plan before any daemon-side work."""

    trial_root = args.root / f"trial-{trial:02d}"
    containers = [
        resource_name(run_id, trial, "gate", role) for role in ("a", "b", "c")
    ]
    networks = (
        resource_name(run_id, trial, "live-ab"),
        resource_name(run_id, trial, "live-bc"),
    )
    primary_error: BaseException | None = None
    try:
        for container in containers:
            runner.register_docker_resource(
                "container", container, owner=f"gate-h-trial-{trial:02d}"
            )
        for network in networks:
            runner.register_docker_resource(
                "network", network, owner=f"gate-h-trial-{trial:02d}"
            )
        return _run_gate_h_trial_body(runner, args, run_id, trial)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_path = trial_root / "cleanup.json"
        if not cleanup_path.exists():
            trial_root.mkdir(parents=True, exist_ok=True)
            finalize_gate_h_trial_resources(
                runner,
                trial_root=trial_root,
                trial=trial,
                processes=(),
                containers=containers,
                networks=networks,
                primary_error=primary_error,
            )


def _gate_h_handoff_path(root: Path) -> Path:
    return root.resolve() / "gate-h-export-handoff.json"


def prepare_gate_h_export_handoff(
    args: argparse.Namespace,
    raw_argv: Sequence[str],
    *,
    tools: dict[str, dict[str, Any]],
    environment: dict[str, str],
) -> None:
    """Create the signed tree, then replace the mutable bootstrap process."""

    if any(
        value is not None
        for value in (
            args.gate_h_signed_reexec_handoff,
            args.gate_h_signed_reexec_handoff_sha256,
            args.gate_h_signed_reexec_sentinel,
        )
    ):
        raise ExperimentError("formal Gate-H bootstrap admits forged re-exec arguments")
    request = gate_h_signature_request(args)
    try:
        trust = gate_h_signature.prepare_signature_trust(
            request,
            workspace=WORKSPACE,
            frozen_directory=args.root.resolve(),
            base_environment=environment,
            run_command=run_gate_h_signature_command,
        )
        anchor = gate_h_signature.validate_signature_request_matches_trust(
            request,
            trust,
            workspace=WORKSPACE,
            base_environment=environment,
            run_command=run_gate_h_signature_command,
        )
    except gate_h_signature.SignatureTrustError as error:
        raise ExperimentError(
            f"formal Gate-H signature trust setup failed: {error}"
        ) from error
    freeze = source_freeze(
        execute=True,
        build_command=args.build_command,
        git_binary=tools["git"]["invocation_path"],
        environment=environment,
        signature_trust=trust,
    )
    try:
        signed_source = gate_h_source.materialize_signed_tree(
            freeze["candidate_commit"],
            freeze["candidate_tree"],
            trust,
            workspace=WORKSPACE,
            archive_path=(args.root / "gate-h-signed-source.tar").resolve(),
            export_root=gate_h_export_root(args.root),
            base_environment=environment,
            run_command=run_gate_h_signature_command,
        )
        gate_h_source.validate_signed_tree_receipt(
            signed_source,
            workspace=WORKSPACE,
            trust=trust,
            verify_archive_file=True,
            verify_export=True,
        )
    except gate_h_source.SignedSourceError as error:
        raise ExperimentError(
            f"formal Gate-H signed source export failed: {error}"
        ) from error
    bytecode = _gate_h_bytecode_paths(gate_h_export_root(args.root))
    if bytecode:
        raise ExperimentError("formal Gate-H signed source contains Python bytecode")
    bootstrap_modules = gate_h_bootstrap_module_bindings(signed_source)
    sentinel = secrets.token_hex(32)
    handoff_payload = {
        "schema": GATE_H_EXPORT_HANDOFF_SCHEMA,
        "created_utc": utc_now(),
        "repository_workspace": str(WORKSPACE.resolve()),
        "environment": environment,
        "tools": tools,
        "signature_request": gate_h_signature_request_receipt(request),
        "signature_trust": trust,
        "signature_anchor": anchor,
        "source_freeze": freeze,
        "signed_source": signed_source,
        "signed_source_sha256": gate_h_source.canonical_sha256(signed_source),
        "sentinel_sha256": hashlib.sha256(sentinel.encode("ascii")).hexdigest(),
        "bootstrap_modules": bootstrap_modules,
        "bytecode": bytecode,
        "passed": True,
    }
    handoff = {
        **handoff_payload,
        "payload_sha256": canonical_sha256(handoff_payload),
    }
    handoff_path = _gate_h_handoff_path(args.root)
    write_json(handoff_path, handoff)
    handoff_path.chmod(0o444)
    handoff_sha256 = sha256_file(handoff_path)
    controller = gate_h_export_controller(args.root)
    if not controller.is_file() or controller.is_symlink():
        raise ExperimentError("formal Gate-H signed controller is unavailable")
    final_environment = gate_h_host_environment(
        root=args.root.resolve(),
        docker_host=args.docker_host,
        home=Path(environment["HOME"]),
        repository_workspace=WORKSPACE,
        signed_controller=True,
    )
    if final_environment != environment:
        raise ExperimentError("formal Gate-H bootstrap and signed environments differ")
    python = tools["python"]["invocation_path"]
    os.execve(
        python,
        [
            python,
            *GATE_H_PYTHON_FLAGS,
            str(controller),
            *raw_argv,
            "--gate-h-signed-reexec-handoff",
            str(handoff_path),
            "--gate-h-signed-reexec-handoff-sha256",
            handoff_sha256,
            "--gate-h-signed-reexec-sentinel",
            sentinel,
        ],
        final_environment,
    )
    raise AssertionError("os.execve returned")  # pragma: no cover


def load_gate_h_export_handoff(
    args: argparse.Namespace,
    raw_argv: Sequence[str],
    *,
    tools: dict[str, dict[str, Any]],
    environment: dict[str, str],
) -> tuple[
    dict[str, Any],
    gate_h_signature.SignatureRequest,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    str,
    Path,
]:
    """Independently validate the mutable bootstrap's handoff from signed code."""

    handoff_path = args.gate_h_signed_reexec_handoff
    expected_handoff_sha256 = args.gate_h_signed_reexec_handoff_sha256
    sentinel = args.gate_h_signed_reexec_sentinel
    if (
        not isinstance(handoff_path, Path)
        or handoff_path != _gate_h_handoff_path(args.root)
        or not isinstance(expected_handoff_sha256, str)
        or HEX_64.fullmatch(expected_handoff_sha256) is None
        or not isinstance(sentinel, str)
        or re.fullmatch(r"[0-9a-f]{64}", sentinel) is None
    ):
        raise ExperimentError("formal Gate-H signed re-exec arguments differ")
    try:
        handoff_stat = handoff_path.lstat()
        raw = handoff_path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise ExperimentError("formal Gate-H export handoff is unavailable") from error
    expected_keys = {
        "schema",
        "created_utc",
        "repository_workspace",
        "environment",
        "tools",
        "signature_request",
        "signature_trust",
        "signature_anchor",
        "source_freeze",
        "signed_source",
        "signed_source_sha256",
        "sentinel_sha256",
        "bootstrap_modules",
        "bytecode",
        "passed",
        "payload_sha256",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("schema") != GATE_H_EXPORT_HANDOFF_SCHEMA
        or value.get("passed") is not True
        or handoff_path.is_symlink()
        or not stat.S_ISREG(handoff_stat.st_mode)
        or stat.S_IMODE(handoff_stat.st_mode) != 0o444
        or hashlib.sha256(raw).hexdigest() != expected_handoff_sha256
        or value.get("repository_workspace") != str(WORKSPACE.resolve())
        or value.get("environment") != environment
        or value.get("tools") != tools
        or value.get("bytecode") != []
        or value.get("sentinel_sha256")
        != hashlib.sha256(sentinel.encode("ascii")).hexdigest()
    ):
        raise ExperimentError("formal Gate-H export handoff differs")
    payload = dict(value)
    payload_sha256 = payload.pop("payload_sha256")
    if payload_sha256 != canonical_sha256(payload):
        raise ExperimentError("formal Gate-H export handoff payload differs")
    request = gate_h_signature_request(args)
    if value.get("signature_request") != gate_h_signature_request_receipt(request):
        raise ExperimentError("formal Gate-H export signature request differs")
    trust = value.get("signature_trust")
    anchor = value.get("signature_anchor")
    freeze = value.get("source_freeze")
    signed_source = value.get("signed_source")
    if not all(
        isinstance(item, dict) for item in (trust, anchor, freeze, signed_source)
    ):
        raise ExperimentError("formal Gate-H export handoff is incomplete")
    try:
        gate_h_signature.validate_signature_trust_receipt(
            trust,
            workspace=WORKSPACE,
            expected_principal=request.principal,
            verify_tool_files=True,
            verify_frozen_file=True,
        )
        gate_h_signature.validate_signature_anchor_receipt(
            anchor,
            trust,
            workspace=WORKSPACE,
            base_environment=environment,
        )
        verification = freeze.get("signature_verification")
        gate_h_signature.validate_signature_verification_receipt(
            verification,
            freeze.get("candidate_commit"),
            trust,
            workspace=WORKSPACE,
            base_environment=environment,
        )
        signed_source_root = gate_h_source.validate_signed_tree_receipt(
            signed_source,
            workspace=WORKSPACE,
            trust=trust,
            verify_archive_file=True,
            verify_export=True,
        )
    except (
        gate_h_signature.SignatureTrustError,
        gate_h_source.SignedSourceError,
    ) as error:
        raise ExperimentError(
            f"formal Gate-H export handoff validation failed: {error}"
        ) from error
    if (
        signed_source.get("commit") != freeze.get("candidate_commit")
        or signed_source.get("tree") != freeze.get("candidate_tree")
        or freeze.get("signature_trust_sha256") != canonical_sha256(trust)
        or value.get("signed_source_sha256")
        != gate_h_source.canonical_sha256(signed_source)
        or signed_source_root != gate_h_export_root(args.root)
    ):
        raise ExperimentError("formal Gate-H export handoff identity differs")
    bootstrap_modules = value.get("bootstrap_modules")
    expected_bootstrap_paths = {
        "ip_mesh_experiment": GATE_H_CONTROLLER_RELATIVE_PATH,
        **GATE_H_EXPORT_MODULES,
    }
    if not isinstance(bootstrap_modules, dict) or set(
        bootstrap_modules
    ) != set(expected_bootstrap_paths):
        raise ExperimentError("formal Gate-H bootstrap module inventory differs")
    for name, relative_path in expected_bootstrap_paths.items():
        binding = bootstrap_modules[name]
        if not isinstance(binding, dict) or binding != _gate_h_export_file_binding(
            raw_file=str((WORKSPACE / relative_path).resolve()),
            relative_path=relative_path,
            export_root=WORKSPACE,
            signed_source=signed_source,
            cached_path=binding.get("cached_path")
            if isinstance(binding, dict)
            else None,
            require_materialized_mode=False,
        ):
            raise ExperimentError(
                f"formal Gate-H bootstrap module identity differs: {relative_path}"
            )
    handoff_binding = {
        "path": str(handoff_path),
        "size_bytes": handoff_stat.st_size,
        "sha256": expected_handoff_sha256,
        "payload_sha256": payload_sha256,
    }
    execution = gate_h_export_execution_snapshot(
        signed_source=signed_source,
        python_binding=tools["python"],
        environment=environment,
        raw_argv=raw_argv,
        handoff=handoff_binding,
        sentinel_sha256=value["sentinel_sha256"],
        signature_anchor=anchor,
        bootstrap_modules=bootstrap_modules,
    )
    return (
        execution,
        request,
        trust,
        anchor,
        freeze,
        signed_source,
        value["signed_source_sha256"],
        signed_source_root,
    )


def finalize_gate_h_export_execution(
    root: Path,
    *,
    before: dict[str, Any],
    signed_source: dict[str, Any],
    python_binding: dict[str, Any],
    environment: dict[str, str],
    raw_argv: Sequence[str],
) -> dict[str, Any]:
    """Retain immutable before/after proof for the signed Python controller."""

    handoff = before["handoff"]
    handoff_path = Path(handoff["path"])
    if (
        handoff_path != _gate_h_handoff_path(root)
        or not handoff_path.is_file()
        or handoff_path.is_symlink()
        or handoff_path.stat().st_size != handoff["size_bytes"]
        or sha256_file(handoff_path) != handoff["sha256"]
    ):
        raise ExperimentError("formal Gate-H exported controller handoff changed")
    current = gate_h_export_execution_snapshot(
        signed_source=signed_source,
        python_binding=python_binding,
        environment=environment,
        raw_argv=raw_argv,
        handoff=handoff,
        sentinel_sha256=before["sentinel_sha256"],
        signature_anchor=before["signature_anchor"],
        bootstrap_modules=before["bootstrap_modules"],
    )
    if current != before:
        raise ExperimentError("formal Gate-H exported controller changed while running")
    after = json.loads(json.dumps(current))
    after["modules_after"] = after["modules"]
    after["bytecode"]["pycache_or_pyc_after"] = []
    after["passed"] = True
    receipt = {
        "schema": GATE_H_EXPORT_EXECUTION_SCHEMA,
        "completed_utc": utc_now(),
        "before_sha256": canonical_sha256(before),
        "before": before,
        "after": after,
        "passed": True,
    }
    write_json(root / "gate-h-export-execution-final.json", receipt)
    return receipt


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--arm", choices=ARMS, required=True)
    value.add_argument(
        "--scenario",
        choices=(
            "primary",
            "gate-h",
            "discovery-disabled",
            "manual",
            "receive-only",
            "idle",
            "multi-peer",
            "live-relay",
        ),
        default="primary",
    )
    value.add_argument("--binary", type=Path, required=True)
    value.add_argument("--provider-binary", type=Path)
    value.add_argument("--root", type=Path, required=True)
    value.add_argument("--trials", type=int, default=30)
    value.add_argument("--duration-ms", type=int, default=6_000)
    value.add_argument("--payload-bytes", type=int, default=1_024)
    value.add_argument(
        "--discovery-source",
        choices=("provider-mdns", "aster-protected"),
        help="required for iroh/libp2p: literal provider mDNS or requirements-eligible protected discovery",
    )
    value.add_argument("--settle-ms", type=int, default=120_000)
    value.add_argument("--seed", type=int, default=10_000)
    value.add_argument("--image", default=DEFAULT_IMAGE)
    value.add_argument(
        "--docker-binary",
        type=Path,
        help="absolute Docker client path required for formal Gate H",
    )
    value.add_argument(
        "--docker-buildx-binary",
        type=Path,
        help="absolute Docker buildx plugin path required for formal Gate H",
    )
    value.add_argument(
        "--git-binary",
        type=Path,
        help="absolute Git path required for formal Gate H",
    )
    value.add_argument(
        "--ssh-keygen-binary",
        type=Path,
        help="absolute ssh-keygen path required for formal Gate H",
    )
    value.add_argument(
        "--ssh-binary",
        type=Path,
        help="absolute ssh path required for formal Gate H",
    )
    value.add_argument(
        "--allowed-signers",
        type=Path,
        help="absolute allowed-signers file required for formal Gate H",
    )
    value.add_argument(
        "--signer-principal",
        help="exact SSH signing principal required for formal Gate H",
    )
    value.add_argument(
        "--docker-host",
        help="explicit unix:// Docker endpoint required for formal Gate H",
    )
    value.add_argument(
        "--build-command",
        help="exact command used to produce the candidate binary; required with --execute",
    )
    value.add_argument(
        "--provider-build-command",
        help="exact command used to produce the corrected libp2p provider binary",
    )
    value.add_argument("--capture", action="store_true")
    value.add_argument("--gate-h-fault-receipt", type=Path)
    value.add_argument(
        "--gate-h-signed-reexec-handoff", type=Path, help=argparse.SUPPRESS
    )
    value.add_argument(
        "--gate-h-signed-reexec-handoff-sha256", help=argparse.SUPPRESS
    )
    value.add_argument(
        "--gate-h-signed-reexec-sentinel", help=argparse.SUPPRESS
    )
    value.add_argument("--execute", action="store_true")
    return value


def require_clean_gate_h_cohort(results: Sequence[dict[str, Any]]) -> None:
    if (
        len(results) != 10
        or sum(result.get("passed") is True for result in results) != 10
        or any(result.get("passed") is not True for result in results)
    ):
        raise ExperimentError("Gate-H cohort is not 10/10 clean")


def finalize_runner_after_failure(
    runner: Runner, *, formal_gate_h: bool
) -> tuple[list[BaseException], list[int]]:
    """Drain every owned child/resource before a failure can leave the process."""

    errors: list[BaseException] = []
    with deferred_interrupt_signals() as deferred:
        try:
            runner.terminate_owned_processes()
        except BaseException as error:
            errors.append(error)
        if formal_gate_h:
            try:
                _receipt, cleanup_error = (
                    runner.cleanup_registered_docker_resources(
                        reason="outer-controller-failure"
                    )
                )
                if cleanup_error is not None:
                    errors.append(cleanup_error)
            except BaseException as error:
                errors.append(error)
            try:
                finalize_gate_h_host_execution(runner)
            except BaseException as error:
                errors.append(error)
    return errors, deferred


def main(argv: Sequence[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = parser().parse_args(raw_argv)
    runner: Runner | None = None
    formal_tools: dict[str, dict[str, Any]] | None = None
    formal_environment: dict[str, str] | None = None
    export_execution: dict[str, Any] | None = None
    previous_sigint: Any = None
    previous_sigterm: Any = None
    try:
        formal_signed_controller = gate_h_formal_execution(args) and (
            Path(__file__).resolve() == gate_h_export_controller(args.root)
        )
        validate_input(args, allow_existing_root=formal_signed_controller)
        if gate_h_formal_execution(args):
            formal_tools, formal_environment = ensure_gate_h_controller_environment(
                args, raw_argv, signed_controller=True
            )
            previous_sigint = signal.getsignal(signal.SIGINT)
            previous_sigterm = signal.getsignal(signal.SIGTERM)

            def controlled_interruption(signum: int, _frame: Any) -> None:
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                raise ControlledInterruption(signum)

            signal.signal(signal.SIGINT, controlled_interruption)
            signal.signal(signal.SIGTERM, controlled_interruption)
        if formal_signed_controller:
            if not args.root.is_dir() or args.root.is_symlink():
                raise ExperimentError("formal Gate-H evidence root changed at handoff")
        else:
            args.root.mkdir(parents=True)
        if formal_environment is not None:
            if formal_signed_controller:
                for field in ("DOCKER_CONFIG", "TMPDIR"):
                    path = Path(formal_environment[field])
                    if not path.is_dir() or path.is_symlink():
                        raise ExperimentError(
                            f"formal Gate-H {field} changed at signed handoff"
                        )
            else:
                Path(formal_environment["DOCKER_CONFIG"]).mkdir()
                Path(formal_environment["TMPDIR"]).mkdir()
        if (
            gate_h_formal_execution(args)
            and not formal_signed_controller
            and formal_tools is not None
            and formal_environment is not None
        ):
            prepare_gate_h_export_handoff(
                args,
                raw_argv,
                tools=formal_tools,
                environment=formal_environment,
            )
            raise AssertionError("signed Gate-H re-exec returned")  # pragma: no cover

        signature_request: gate_h_signature.SignatureRequest | None = None
        signature_trust: dict[str, Any] | None = None
        signature_anchor: dict[str, Any] | None = None
        signed_source: dict[str, Any] | None = None
        signed_source_sha256: str | None = None
        signed_source_root: Path | None = None
        if formal_signed_controller:
            if formal_tools is None or formal_environment is None:
                raise ExperimentError("formal Gate-H signed controller is unbound")
            (
                export_execution,
                signature_request,
                signature_trust,
                signature_anchor,
                freeze,
                signed_source,
                signed_source_sha256,
                signed_source_root,
            ) = load_gate_h_export_handoff(
                args,
                raw_argv,
                tools=formal_tools,
                environment=formal_environment,
            )
        runner = Runner(
            args.root,
            args.execute,
            environment=formal_environment,
            docker_binary=None
            if formal_tools is None
            else formal_tools["docker"]["invocation_path"],
            docker_buildx_binding=None
            if formal_tools is None
            else formal_tools["docker_buildx"],
        )
        host_execution = None
        if formal_tools is not None and formal_environment is not None:
            host_execution = collect_gate_h_host_execution(
                runner,
                tools=formal_tools,
                environment=formal_environment,
                controller_argv=None
                if export_execution is None
                else export_execution["argv"],
            )
        source_binary = args.binary.resolve()
        source_provider_binary = (
            args.provider_binary.resolve()
            if getattr(args, "provider_binary", None) is not None
            else None
        )
        if not formal_signed_controller:
            freeze = source_freeze(
                execute=args.execute,
                build_command=getattr(args, "build_command", None),
                git_binary=None
                if formal_tools is None
                else formal_tools["git"]["invocation_path"],
                environment=formal_environment,
                signature_trust=signature_trust,
            )
        fault_receipt_source = getattr(args, "gate_h_fault_receipt", None)
        fault_receipt = None
        if fault_receipt_source is not None:
            fault_receipt = validate_gate_h_fault_receipt(
                fault_receipt_source.resolve(),
                expected_commit=freeze["candidate_commit"],
                expected_binary_sha256=sha256_file(source_binary),
                expected_binary_size=source_binary.stat().st_size,
                expected_signature_status=freeze["signature_status"],
                expected_signature_signer=freeze["signature_signer"],
                expected_signature_fingerprint=freeze["signature_fingerprint"],
                git_binary=None
                if formal_tools is None
                else formal_tools["git"]["invocation_path"],
                environment=formal_environment,
                signature_trust=signature_trust,
                signature_request=signature_request,
                signed_source=signed_source,
            )
        run_id = secrets.token_hex(4)
        docker_available(runner)
        gate_h_binary_provenance: dict[str, Any] | None = None
        if args.execute and args.scenario == "gate-h":
            if signed_source_root is None or signed_source_sha256 is None:
                raise ExperimentError("formal Gate-H signed source context is absent")
            image, gate_h_binary_provenance = build_and_verify_gate_h_binary(
                runner,
                image=args.image,
                source_binary=source_binary,
                candidate_commit=freeze["candidate_commit"],
                run_id=run_id,
                build_context=signed_source_root,
                signed_source_sha256=signed_source_sha256,
            )
            try:
                gate_h_source.validate_signed_tree_receipt(
                    signed_source,
                    workspace=WORKSPACE,
                    trust=signature_trust,
                    verify_archive_file=True,
                    verify_export=True,
                )
            except gate_h_source.SignedSourceError as error:
                raise ExperimentError(
                    f"formal Gate-H signed source changed during build: {error}"
                ) from error
        else:
            image = inspect_image(runner, args.image)
        frozen_binary = args.root / "candidate-aster-lab"
        shutil.copyfile(source_binary, frozen_binary)
        frozen_binary.chmod(0o555)
        args.binary = frozen_binary
        if (
            gate_h_binary_provenance is not None
            and sha256_file(frozen_binary)
            != gate_h_binary_provenance["binary_sha256"]
        ):
            raise ExperimentError("frozen Gate-H binary differs after provenance check")
        frozen_provider_binary: Path | None = None
        args.provider_binary_sha256 = None
        if source_provider_binary is not None:
            frozen_provider_binary = args.root / "candidate-aster-libp2p-node"
            shutil.copyfile(source_provider_binary, frozen_provider_binary)
            frozen_provider_binary.chmod(0o555)
            args.provider_binary = frozen_provider_binary
            args.provider_binary_sha256 = sha256_file(frozen_provider_binary)
        frozen_fault_receipt: Path | None = None
        if fault_receipt_source is not None:
            frozen_fault_receipt = args.root / "gate-h-fault-receipt.json"
            shutil.copyfile(fault_receipt_source.resolve(), frozen_fault_receipt)
            frozen_fault_receipt.chmod(0o444)
        manifest = {
            "schema": SCHEMA,
            "created_utc": utc_now(),
            "run_id": run_id,
            "arm": args.arm,
            "scenario": args.scenario,
            "source_binary": str(source_binary),
            "binary": str(frozen_binary.resolve()),
            "binary_sha256": sha256_file(args.binary.resolve()),
            "provider_source_binary": None
            if source_provider_binary is None
            else str(source_provider_binary),
            "provider_binary": None
            if frozen_provider_binary is None
            else str(frozen_provider_binary.resolve()),
            "provider_binary_sha256": None
            if frozen_provider_binary is None
            else args.provider_binary_sha256,
            "provider_build_command": getattr(args, "provider_build_command", None),
            "image": args.image,
            "image_content": image,
            "trials": args.trials,
            "duration_ms": args.duration_ms,
            "payload_bytes": args.payload_bytes,
            "discovery_source": args.discovery_source,
            "seed": args.seed,
            "execute": args.execute,
            "source_freeze": freeze,
            "host_execution": host_execution,
            "export_execution": export_execution,
            "signature_request": None
            if signature_request is None
            else gate_h_signature_request_receipt(signature_request),
            "signature_trust": signature_trust,
            "signature_anchor": signature_anchor,
            "signature_verification": freeze.get("signature_verification"),
            "signed_source": signed_source,
            "signed_source_sha256": signed_source_sha256,
            "gate_h_fault_receipt": None
            if frozen_fault_receipt is None
            else {
                "path": frozen_fault_receipt.name,
                "sha256": sha256_file(frozen_fault_receipt),
                "cases": fault_receipt["cases"],
                "candidate_binary_sha256": fault_receipt[
                    "candidate_binary_sha256"
                ],
                "signature_anchor": fault_receipt.get(
                    "_validated_signature_anchor"
                ),
                "validation_git_commands": fault_receipt.get(
                    "_validation_git_commands"
                ),
            },
            "gate_h_binary_provenance": gate_h_binary_provenance,
        }
        write_json(args.root / "manifest.json", manifest)
        if not args.execute:
            print(json.dumps({**manifest, "dry_run": True}, indent=2, sort_keys=True))
            return 0
        results = []
        for trial in range(1, args.trials + 1):
            if args.scenario == "primary":
                result = run_trial(runner, args, run_id, trial)
            elif args.scenario == "gate-h":
                result = run_gate_h_trial(runner, args, run_id, trial)
            elif args.scenario == "discovery-disabled":
                result = run_discovery_disabled_trial(runner, args, run_id, trial)
            elif args.scenario == "manual":
                result = run_manual_trial(runner, args, run_id, trial)
            elif args.scenario == "receive-only":
                result = run_receive_only_trial(runner, args, run_id, trial)
            elif args.scenario == "idle":
                result = run_idle_trial(runner, args, run_id, trial)
            elif args.scenario == "multi-peer":
                result = run_multi_peer_trial(runner, args, run_id, trial)
            else:
                result = run_live_relay_trial(runner, args, run_id, trial)
            results.append(result)
            print(
                f"{args.arm} {args.scenario} trial {trial}/{args.trials}: "
                f"{'passed' if result['passed'] else 'failed'}",
                flush=True,
            )
        summary = {
            "schema": SCHEMA,
            "completed_utc": utc_now(),
            "arm": args.arm,
            "scenario": args.scenario,
            "requested_trials": args.trials,
            "passed_trials": sum(1 for result in results if result["passed"]),
            "all_passed": all(result["passed"] for result in results),
            "results": [str(args.root / f"trial-{index:02d}" / "result.json") for index in range(1, args.trials + 1)],
        }
        write_json(args.root / "summary.json", summary)
        if args.scenario == "gate-h":
            require_clean_gate_h_cohort(results)
            if signature_trust is None or signature_request is None:
                raise ExperimentError("formal Gate-H signature trust was not retained")
            finalize_gate_h_signature_trust(
                args.root,
                signature_trust,
                principal=signature_request.principal,
            )
            final_host = finalize_gate_h_host_execution_signal_safe(runner)
            if final_host.get("passed") is not True:
                raise ExperimentError(
                    "formal Gate-H host execution did not finish hermetically"
                )
            if (
                export_execution is None
                or signed_source is None
                or formal_tools is None
                or formal_environment is None
            ):
                raise ExperimentError(
                    "formal Gate-H exported controller evidence is absent"
                )
            finalize_gate_h_export_execution(
                args.root,
                before=export_execution,
                signed_source=signed_source,
                python_binding={
                    "invocation_path": export_execution["python"]["invocation"],
                    "path": export_execution["python"]["path"],
                    "size_bytes": export_execution["python"]["size_bytes"],
                    "sha256": export_execution["python"]["sha256"],
                },
                environment=formal_environment,
                raw_argv=raw_argv,
            )
        index = evidence_index(args.root)
        write_json(args.root / "evidence-index.json", index)
        print(
            json.dumps(
                {
                    **summary,
                    "evidence_index_sha256": sha256_file(
                        args.root / "evidence-index.json"
                    ),
                    "evidence_aggregate_sha256": index["aggregate_sha256"],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (KeyboardInterrupt, ControlledInterruption) as error:
        finalization_errors: list[BaseException] = []
        if runner is not None:
            finalization_errors, _deferred = finalize_runner_after_failure(
                runner, formal_gate_h=gate_h_formal_execution(args)
            )
            for final_error in finalization_errors:
                print(
                    f"ip-mesh experiment host finalization: {final_error}",
                    file=sys.stderr,
                )
        retained: dict[str, Any] | None = None
        try:
            retained = finalize_failure_evidence(args.root, args, error)
        except (ExperimentError, OSError, ValueError) as evidence_error:
            print(
                f"ip-mesh experiment evidence finalization: {evidence_error}",
                file=sys.stderr,
            )
        suffix = f"; retained={json.dumps(retained, sort_keys=True)}" if retained else ""
        returncode = (
            128 + error.signum
            if isinstance(error, ControlledInterruption)
            else 130
        )
        print(
            f"ip-mesh experiment: interrupted (exit {returncode}){suffix}",
            file=sys.stderr,
        )
        return returncode
    except SystemExit:
        if runner is not None:
            finalize_runner_after_failure(
                runner, formal_gate_h=gate_h_formal_execution(args)
            )
        raise
    except (ExperimentError, OSError, ValueError, subprocess.SubprocessError) as error:
        finalization_errors = []
        deferred: list[int] = []
        if runner is not None:
            finalization_errors, deferred = finalize_runner_after_failure(
                runner, formal_gate_h=gate_h_formal_execution(args)
            )
            for final_error in finalization_errors:
                print(
                    f"ip-mesh experiment host finalization: {final_error}",
                    file=sys.stderr,
                )
        if deferred:
            interruption = ControlledInterruption(deferred[0])
            retained: dict[str, Any] | None = None
            try:
                retained = finalize_failure_evidence(args.root, args, interruption)
            except (ExperimentError, OSError, ValueError) as evidence_error:
                print(
                    f"ip-mesh experiment evidence finalization: {evidence_error}",
                    file=sys.stderr,
                )
            suffix = (
                f"; retained={json.dumps(retained, sort_keys=True)}"
                if retained
                else ""
            )
            returncode = 128 + interruption.signum
            print(
                f"ip-mesh experiment: interrupted (exit {returncode}){suffix}",
                file=sys.stderr,
            )
            return returncode
        retained: dict[str, Any] | None = None
        try:
            retained = finalize_failure_evidence(args.root, args, error)
        except (ExperimentError, OSError, ValueError) as evidence_error:
            print(
                f"ip-mesh experiment evidence finalization: {evidence_error}",
                file=sys.stderr,
            )
        suffix = f"; retained={json.dumps(retained, sort_keys=True)}" if retained else ""
        print(f"ip-mesh experiment: {error}{suffix}", file=sys.stderr)
        return 2
    except BaseException as error:
        if runner is not None:
            finalization_errors, _deferred = finalize_runner_after_failure(
                runner, formal_gate_h=gate_h_formal_execution(args)
            )
            for final_error in finalization_errors:
                print(
                    f"ip-mesh experiment host finalization: {final_error}",
                    file=sys.stderr,
                )
        try:
            finalize_failure_evidence(args.root, args, error)
        except BaseException as evidence_error:
            print(
                f"ip-mesh experiment evidence finalization: {evidence_error}",
                file=sys.stderr,
            )
        raise
    finally:
        if previous_sigint is not None:
            signal.signal(signal.SIGINT, previous_sigint)
        if previous_sigterm is not None:
            signal.signal(signal.SIGTERM, previous_sigterm)


if __name__ == "__main__":
    raise SystemExit(main())
