#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run one bounded real Event through isolated veth links and a WAN namespace."""

from __future__ import annotations

import argparse
import base64
import binascii
from collections.abc import Callable
from contextlib import contextmanager, ExitStack
import fcntl
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any


SCENARIO_SCHEMA = "aster-path-delivery-scenario/v1"
PLAN_SCHEMA = "aster-path-delivery-plan/v1"
RECEIPT_SCHEMA = "aster-path-delivery-receipt/v1"
MAX_SCENARIO_BYTES = 16 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 64
FIELDS = {"schema", "id", "seed", "operation_key", "logical_key", "payload"}
LAB = "aster-path-delivery"
LAB_LOCK = Path("/run/lock") / LAB / "owner.lock"
RECOVERY_DIRECTORY = LAB_LOCK.parent / "recovery"
RECOVERY_LOCATOR = "recovery=/run/lock/aster-path-delivery/recovery"
FIXED_NETEM = {
    "limit": 1000,
    "delay": "40ms",
    "jitter": "5ms",
    "packet_loss": 1.0,
    "rate": 100000,
}


class ScenarioError(ValueError):
    """One sanitized delivery-scenario validation failure."""


class ExecutionError(RuntimeError):
    """One sanitized delivery execution failure."""


@contextmanager
def _lab_lock(path: Path):
    """Hold exclusive ownership of the fixed lab name without following links."""

    try:
        path.parent.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise ExecutionError("path-delivery lock directory is unavailable") from error
    try:
        directory_metadata = path.parent.lstat()
    except OSError as error:
        raise ExecutionError("path-delivery lock directory is unavailable") from error
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(directory_metadata.st_mode)
        or directory_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(directory_metadata.st_mode) != 0o700
    ):
        raise ExecutionError("path-delivery lock directory is not trusted")

    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise ExecutionError("path-delivery ownership lock is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ExecutionError("path-delivery lock file is not trusted")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ExecutionError("another path-delivery execution is active") from error
        try:
            path_metadata = path.lstat()
        except OSError as error:
            raise ExecutionError("path-delivery lock file identity changed") from error
        if (
            path.is_symlink()
            or path_metadata.st_dev != metadata.st_dev
            or path_metadata.st_ino != metadata.st_ino
            or path_metadata.st_uid != metadata.st_uid
            or stat.S_IMODE(path_metadata.st_mode) != 0o600
        ):
            raise ExecutionError("path-delivery lock file identity changed")
        yield
    finally:
        os.close(descriptor)


def _pinned_docker(run: Callable) -> Callable:
    def pinned(argv: list[str], timeout: float) -> bytes:
        if argv[1:3] != ["--host", "unix:///var/run/docker.sock"]:
            argv = [argv[0], "--host", "unix:///var/run/docker.sock", *argv[1:]]
        return run(argv, timeout)
    return pinned


class OwnedDocker:
    """Resources for the fixed delivery run, never authorized by container name."""

    def __init__(self, docker: str, directory: Path, run: Callable):
        metadata = directory.lstat()
        if (directory.is_symlink() or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700):
            raise ExecutionError("owner-directory-untrusted")
        self.docker, self.directory, self.run = docker, directory, _pinned_docker(run)
        self.containers: list[str] = []
        self.networks: list[str] = []
        self.label = "aster.path-delivery=" + os.urandom(16).hex()
        self.absence_confirmed = False
        self.create_ambiguous = False
        self.phase = "prepare"
        self.persist()

    def persist(self) -> None:
        """Atomically retain only ownership metadata, never credential contents."""
        data = {"schema": "aster-path-delivery-ownership/v1", "label": self.label,
                "phase": self.phase, "containers": self.containers, "networks": self.networks,
                "create_ambiguous": self.create_ambiguous}
        raw = json.dumps(data, sort_keys=True).encode() + b"\n"
        fd, temporary = tempfile.mkstemp(prefix="ownership-", suffix=".next", dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.directory / "ownership.json")
            parent = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            # Never consume another (possibly interrupted) writer's temporary.
            if os.path.exists(temporary):
                os.unlink(temporary)


    def cleanup(self) -> list[str]:
        errors = []
        for kind, ids, remove, listing in (
            ("container", self.containers, ["rm", "--force"], ["ps", "--all"]),
            ("network", self.networks, ["network", "rm"], ["network", "ls"]),
        ):
            for identity in reversed(ids):
                try:
                    self.run([self.docker, *remove, identity], 30)
                except (ExecutionError, OSError):
                    errors.append(kind + "-remove")
                try:
                    raw = self.run([self.docker, *listing, "--quiet", "--no-trunc",
                                    "--filter", "id=" + identity], 30)
                    if raw != b"":
                        raise ExecutionError("resource-remains")
                except (ExecutionError, OSError):
                    errors.append(kind + "-absence")
            try:
                if self.run([self.docker, *listing, "--quiet", "--no-trunc",
                             "--filter", "label=" + self.label], 30) != b"":
                    raise ExecutionError("labelled-remains")
            except (ExecutionError, OSError):
                errors.append(kind + "-labelled-remains")
        if self.create_ambiguous:
            errors.append("create-completion-unknown")
        self.absence_confirmed = not any("remove" not in error for error in errors)
        self.phase = "absent" if self.absence_confirmed else "recovery-required"
        try:
            self.persist()
        except (OSError, ExecutionError):
            errors.append("ownership-persist")
            self.absence_confirmed = False
        return errors

    def create(self, role: str, network: list[str], command: list[str], caps: tuple[str, ...] = ()) -> str:
        if role not in ("wan", "node-a", "node-b", "provision", "node-a-setup", "node-b-setup", "wan-setup"):
            raise ExecutionError("role-invalid")
        expected_caps = ("CHOWN",) if role == "provision" else ("NET_ADMIN",) if role.endswith("-setup") else ()
        if caps != expected_caps:
            raise ExecutionError("role-capabilities")
        cid: str | None = None
        cidfile = self.directory / (role + ".cid")
        if cidfile.exists() or cidfile.is_symlink():
            raise ExecutionError("cidfile-exists")
        self.create_ambiguous = True
        self.phase = role + "-create"
        self.persist()
        try:
            self.run([
                self.docker, "create", "--cidfile", str(cidfile),
                "--label", self.label, "--cap-drop", "ALL", "--user", "0:0" if caps else "10001:10001",
                "--security-opt", "no-new-privileges", "--log-driver", "none",
                *[part for cap in caps for part in ("--cap-add", cap)],
                *network, "aster-path-delivery:local", *command,
            ], 30)
        finally:
            if cidfile.exists() or cidfile.is_symlink():
                try:
                    fd = os.open(cidfile, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(fd, "rb") as handle:
                        metadata = os.fstat(handle.fileno())
                        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                                or metadata.st_uid != os.geteuid()
                                or stat.S_IMODE(metadata.st_mode) != 0o600):
                            raise ExecutionError("cidfile-untrusted")
                        cid = _docker_id(handle.read(66))
                    self.containers.append(cid)
                    self.persist()
                except OSError:
                    raise ExecutionError("cidfile-untrusted") from None
        if cid is None:
            raise ExecutionError("cidfile-missing")
        self.create_ambiguous = False
        self.phase = "created"
        self.persist()
        return cid


def _docker_id(raw: bytes) -> str:
    if re.fullmatch(rb"[0-9a-f]{64}\n?", raw) is None:
        raise ExecutionError("docker-id-invalid")
    return raw.decode("ascii").rstrip("\n")


@contextmanager
def _namespace_files(owned: OwnedDocker, holders: dict[str, str]):
    """Pin owned, distinct Linux netns files; never target a reusable PID/name."""
    with ExitStack() as stack:
        files = {}
        host = os.stat("/proc/self/ns/net")
        identities = {(host.st_dev, host.st_ino)}
        for role, cid in holders.items():
            if cid not in owned.containers:
                raise ExecutionError("namespace-unowned")
            # Ask only for non-secret ownership and namespace metadata.
            template = ('{"id":{{json .Id}},"labels":{{json .Config.Labels}},'
                        '"running":{{json .State.Running}},'
                        '"network":{{json .HostConfig.NetworkMode}},'
                        '"key":{{json .NetworkSettings.SandboxKey}}}')
            argv = [owned.docker, "inspect", "--format", template, cid]
            info = _strict_json(owned.run(argv, 5), "namespace")
            label, value = owned.label.split("=", 1)
            if (not isinstance(info, dict) or info.get("id") != cid
                    or info.get("running") is not True or info.get("network") != "none"
                    or not isinstance(info.get("labels"), dict)
                    or info["labels"].get(label) != value
                    or not isinstance(info.get("key"), str)
                    or re.fullmatch(r"/var/run/docker/netns/[0-9a-f]{12,64}", info["key"]) is None):
                raise ExecutionError("namespace-identity")
            fd = os.open(info["key"], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
            stack.callback(os.close, fd)
            # Linux nsfs NS_GET_NSTYPE (_IO(0xb7, 3)), CLONE_NEWNET.
            if fcntl.ioctl(fd, 0xb703) != 0x40000000:
                raise ExecutionError("namespace-type")
            metadata = os.fstat(fd)
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in identities:
                raise ExecutionError("namespace-shared")
            identities.add(identity)
            current = os.stat(info["key"], follow_symlinks=False)
            if ((current.st_dev, current.st_ino) != identity
                    or _strict_json(owned.run(argv, 5), "namespace") != info):
                raise ExecutionError("namespace-changed")
            # The bounded host ip child opens this pinned descriptor, not a
            # container PID or a Docker path which could be replaced later.
            files[role] = f"/proc/{os.getpid()}/fd/{fd}"
        yield files


def _text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ScenarioError(f"{label} must be text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise ScenarioError(f"{label} is not valid UTF-8") from error
    if not encoded or len(encoded) > maximum or any(byte < 32 or byte == 127 for byte in encoded):
        raise ScenarioError(f"{label} is outside its supported bounds")
    return value


def _exceeds_json_nesting(raw: bytes) -> bool:
    """Bound container depth before decoding, independent of Python recursion.

    The caller checks bytes first. JSON syntax/UTF-8 validation stays with the
    decoder; only ASCII structural bytes outside strings affect this bound.
    """
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 92:  # backslash
                escaped = True
            elif byte == 34:  # quote
                in_string = False
        elif byte == 34:
            in_string = True
        elif byte in (91, 123):  # [ {
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return True
        elif byte in (93, 125):  # ] }
            depth -= 1
    return False


def _strict_json(raw: bytes, label: str) -> Any:
    if len(raw) > MAX_OUTPUT_BYTES:
        raise ExecutionError(f"{label} exceeds the byte bound")
    if _exceeds_json_nesting(raw):
        raise ExecutionError(f"{label} exceeds the nesting bound")

    def object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ExecutionError(f"{label} contains a duplicate field")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ExecutionError(f"{label} is malformed")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=object_from_pairs,
            parse_constant=reject_constant,
        )
    except ExecutionError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ExecutionError(f"{label} is malformed") from error


def compile_scenario(raw: bytes) -> dict[str, object]:
    """Validate the event input and return the single fixed delivery plan."""

    if len(raw) > MAX_SCENARIO_BYTES:
        raise ScenarioError("scenario exceeds the byte bound")
    if _exceeds_json_nesting(raw):
        raise ScenarioError("scenario exceeds the nesting bound")

    def object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ScenarioError("scenario contains a duplicate field")
            value[key] = item
        return value

    def reject_constant(_value: str) -> None:
        raise ScenarioError("scenario is not valid UTF-8 JSON")

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=object_from_pairs,
            parse_constant=reject_constant,
        )
    except ScenarioError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ScenarioError("scenario is not valid UTF-8 JSON") from error
    if not isinstance(document, dict) or document.get("schema") != SCENARIO_SCHEMA:
        raise ScenarioError("scenario has an unsupported schema")
    if set(document) != FIELDS:
        raise ScenarioError("scenario fields do not match the delivery contract")
    scenario_id = _text(document["id"], "scenario id", 64)
    if scenario_id != "event-delivery-netem":
        raise ScenarioError("scenario id is unsupported")
    if type(document["seed"]) is not int or document["seed"] != 104729:
        raise ScenarioError("scenario seed is unsupported")
    return {
        "schema": PLAN_SCHEMA,
        "scenario_id": scenario_id,
        "seed": document["seed"],
        "operation_key": _text(document["operation_key"], "operation key", 256),
        "logical_key": _text(document["logical_key"], "logical key", 4096),
        "payload": _text(document["payload"], "payload", 4096),
        "netem": dict(FIXED_NETEM),
    }


def _run_command(argv: list[str], timeout: float) -> bytes:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            argv,
            umask=0o077,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdout is None or process.stderr is None:
            raise ExecutionError("delivery command capture is unavailable")
        stdout = bytearray()
        captured = 0
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, True)
            selector.register(process.stderr, selectors.EVENT_READ, False)
            while selector.get_map():
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    raise ExecutionError("delivery command timed out")
                events = selector.select(remaining_time)
                if not events:
                    raise ExecutionError("delivery command timed out")
                for key, _mask in events:
                    allowance = MAX_OUTPUT_BYTES - captured
                    chunk = os.read(key.fd, min(64 * 1024, allowance + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    captured += min(len(chunk), allowance)
                    if key.data:
                        stdout.extend(chunk[:allowance])
                    if len(chunk) > allowance:
                        raise ExecutionError("delivery command output exceeds the byte bound")
        returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
        if returncode != 0:
            raise ExecutionError(f"delivery command failed with exit status {returncode}")
        return bytes(stdout)
    except ExecutionError:
        if process is not None and process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                pass
        raise
    except (OSError, subprocess.SubprocessError) as error:
        if process is not None and process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                pass
        raise ExecutionError("delivery command could not be executed") from error
    finally:
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


def _canonical_event_id(raw: bytes) -> str:
    try:
        value = raw.decode("ascii").strip()
        decoded = base64.b64decode(value, validate=True)
    except (UnicodeError, binascii.Error, ValueError) as error:
        raise ExecutionError("publisher returned a malformed Event ID") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ExecutionError("publisher returned a malformed Event ID")
    return value


def _validate_status(raw: bytes) -> dict[str, object]:
    document = _strict_json(raw, "agent status")
    if not isinstance(document, dict):
        raise ExecutionError("agent status is malformed")
    for field in ("identity", "missionAuthority"):
        value = document.get(field)
        if not isinstance(value, str):
            raise ExecutionError("agent status is malformed")
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ExecutionError("agent status is malformed") from error
        if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
            raise ExecutionError("agent status is malformed")
    sync = document.get("sync")
    if (
        not isinstance(sync, str)
        or not sync
        or len(sync) > 64
        or any(ord(character) < 32 or ord(character) == 127 for character in sync)
    ):
        raise ExecutionError("agent status is malformed")
    return document


def _event_exec(docker: str, node: str, action: str, plan: dict[str, object], event_id: str | None = None) -> list[str]:
    argv = [
        docker,
        "exec",
        "--user",
        "10001:10001",
        node,
        "python3",
        "/usr/local/libexec/aster/aster_lan_mvp.py",
        action,
        "--token-file",
        "/clab/state/client.token",
        "--topic",
        "mesh.messages",
        "--scope",
        "demo/playground",
    ]
    if action == "subscribe":
        argv.extend(["--operation-key", "path-delivery-subscription"])
    elif action == "publish":
        argv.extend([
            "--operation-key", str(plan["operation_key"]),
            "--logical-key", str(plan["logical_key"]),
            "--payload", str(plan["payload"]),
            "--id-only",
        ])
    elif action == "wait" and event_id is not None:
        argv.extend([
            "--logical-key", str(plan["logical_key"]),
            "--event-id", event_id,
            "--wait-seconds", "45",
            "--poll-seconds", "0.25",
        ])
    return argv


def execute_direct(raw: bytes, *, docker: Path, ip: Path, run: Callable = _run_command) -> dict[str, object]:
    """Use preflight-validated tools; no link endpoint enters the host netns."""
    plan = compile_scenario(raw)
    directory = RECOVERY_DIRECTORY
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        raise ExecutionError("recovery-pending " + RECOVERY_LOCATOR) from None
    host_run = run
    run = _pinned_docker(run)
    try:
        owned = OwnedDocker(str(docker), directory, run)
    except (OSError, ExecutionError):
        # No daemon action precedes the initial ownership checkpoint.
        raise ExecutionError("ownership-initialize " + RECOVERY_LOCATOR) from None
    exe = str(docker)
    lib = "/usr/local/libexec/aster/"
    stage = "prepare"
    primary = None
    code = "none"
    observed = []
    event_id = ""

    def transient(role, options, command, cap):
        cid = owned.create(role, options, command, (cap,))
        output = run([exe, "start", "--attach", cid], 90)
        if run([exe, "wait", cid], 5) != b"0\n":
            raise ExecutionError("helper-exit")
        run([exe, "rm", cid], 30)
        if run([exe, "ps", "--all", "--quiet", "--no-trunc", "--filter", "id=" + cid], 30) != b"":
            raise ExecutionError("helper-remains")
        owned.containers.remove(cid)
        return output

    try:
        lab = directory / "lab"
        lab.mkdir(mode=0o700)
        for node in ("node-a", "node-b"):
            (lab / node).mkdir(mode=0o700)
        stage = "wan-create"
        wan = owned.create("wan", ["--network", "none",
                                  "--sysctl", "net.ipv4.ip_forward=1"], ["sleep", "600"])
        run([exe, "start", wan], 30)
        nodes = {}
        for role in ("node-a", "node-b"):
            stage = role + "-create"
            nodes[role] = owned.create(role, ["--network", "none",
                                             "--volume", str(lab / role) + ":/clab"], ["sleep", "600"])
            run([exe, "start", nodes[role]], 30)
        stage = "veth-create"
        with _namespace_files(owned, {"wan": wan, **nodes}) as namespaces:
            owned.create_ambiguous = True
            owned.phase = stage
            owned.persist()
            for segment, role in ((1, "node-a"), (2, "node-b")):
                host_run([str(ip), "link", "add", "name", "eth0", "netns", namespaces[role],
                          "type", "veth", "peer", "name", f"wan{segment}",
                          "netns", namespaces["wan"]], 5)
            owned.create_ambiguous = False
            owned.phase = "created"
            owned.persist()
        stage = "provision"
        transient("provision", ["--network", "none", "--volume", str(lab) + ":/lab"],
                  [lib + "delivery-provision.py"], "CHOWN")
        for role, cid in nodes.items():
            stage = role + "-route"
            transient(role + "-setup", ["--network", "container:" + cid],
                      [lib + "delivery-network-init.py", role], "NET_ADMIN")
            stage = role + "-agent"
            run([exe, "exec", "--detach", "--user", "10001:10001", cid,
                 lib + "delivery-agent.py", role], 30)
            stage = role + "-readiness"
            for attempt in range(40):
                try:
                    _validate_status(run([exe, "exec", "--user", "10001:10001", cid,
                                          "python3", lib + "aster_lan_mvp.py", "status",
                                          "--token-file", "/clab/state/client.token"], 2))
                    break
                except ExecutionError:
                    if attempt == 39:
                        raise ExecutionError("readiness-timeout") from None
                    time.sleep(0.25)
        stage = "capabilities"
        for role, cid in {**nodes, "wan": wan}.items():
            if run([exe, "exec", "--user", "10001:10001", cid,
                    lib + "delivery-agent.py", "verify", role], 5) != b"CAPABILITIES status=pass\n":
                raise ExecutionError("capability-mismatch")
        stage = "subscribe"
        run(_event_exec(exe, nodes["node-b"], "subscribe", plan), 30)
        stage = "netem"
        observed = _strict_json(transient("wan-setup", ["--network", "container:" + wan],
                               [lib + "delivery-wan.py", "configure"], "NET_ADMIN"), "netem")
        if (not isinstance(observed, list) or len(observed) != 2
                or any(not isinstance(row, dict)
                       or not isinstance(row.get("interface"), str)
                       or not isinstance(row.get("address"), str)
                       or any(row.get(key) != value for key, value in FIXED_NETEM.items())
                       for row in observed)
                or {row.get("address") for row in observed} != {"10.77.1.1", "10.77.2.1"}
                or len({row.get("interface") for row in observed}) != 2):
            raise ExecutionError("netem-readback")
        stage = "publish"
        event_id = _canonical_event_id(run(_event_exec(exe, nodes["node-a"], "publish", plan), 30))
        stage = "event-oracle"
        event = _strict_json(run(_event_exec(exe, nodes["node-b"], "wait", plan, event_id), 60), "event")
        if (not isinstance(event, dict) or event.get("id") != event_id
                or event.get("logicalKey") != base64.b64encode(str(plan["logical_key"]).encode()).decode()
                or event.get("payload") != base64.b64encode(str(plan["payload"]).encode()).decode()):
            raise ExecutionError("event-mismatch")
    except (ExecutionError, OSError, ValueError) as error:
        primary = stage
        safe_codes = {"event-mismatch", "helper-exit", "helper-remains", "capability-mismatch",
                      "netem-readback", "cidfile-missing", "cidfile-untrusted", "docker-id-invalid",
                      "readiness-timeout"}
        code = str(error) if str(error) in safe_codes else "operation-failed"
        if str(error) == "delivery command timed out":
            code = "command-timeout"
    finally:
        errors = owned.cleanup()
        if owned.absence_confirmed:
            try:
                shutil.rmtree(directory)
                if directory.exists() or directory.is_symlink():
                    raise OSError()
            except OSError:
                errors.append("credential-directory")
    if primary or errors:
        raise ExecutionError("path-delivery failed: primary=" + (primary or "none")
                             + " code=" + code + " cleanup=" + (",".join(errors) or "pass")
                             + (" " + RECOVERY_LOCATOR if directory.exists() else "")) from None
    return {
        "schema": RECEIPT_SCHEMA, "scenario_id": plan["scenario_id"], "seed": plan["seed"],
        "status": "pass", "event_id": event_id, "event_oracle": "pass",
        "configured_netem": dict(FIXED_NETEM), "observed_netem": observed,
        "capabilities": "pass", "cleanup": "pass", "one_host_container_limitation": True,
        "not_run": ["recovery", "resource", "physical", "measured-latency", "actual-loss"],
    }


def _regular_executable(path: Path, name: str) -> Path:
    """Resolve only through root-controlled components, returning a canonical path.

    Validate each directory before looking below it, including both sides of
    symlinks. Resolving first would hide untrusted traversed directories/links.
    Linux symlink mode bits are not access controls; their owner and containing
    directory are. Root administrators remain trusted to maintain these paths.
    """
    if path.anchor != "/" or path.name != name:
        raise ExecutionError(f"{name} executable must be an exact absolute path")
    try:
        current = Path("/")
        metadata = current.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o022):
            raise ExecutionError(f"{name} executable ancestor is not trusted")
        pending = list(reversed(path.parts[1:]))
        links = 0
        while pending:
            part = pending.pop()
            if part == "..":
                current = current.parent
                continue
            candidate = current / part
            metadata = candidate.lstat()
            if metadata.st_uid != 0:
                raise ExecutionError(f"{name} executable path is not root-owned")
            if stat.S_ISLNK(metadata.st_mode):
                links += 1
                if links > 40:
                    raise ExecutionError(f"{name} executable has too many symlinks")
                target = Path(os.readlink(candidate))
                if target.is_absolute():
                    if target.anchor != "/":
                        raise ExecutionError(f"{name} executable symlink is not trusted")
                    current = Path("/")
                    pending.extend(reversed(target.parts[1:]))
                else:
                    pending.extend(reversed(target.parts))
                continue
            if metadata.st_mode & 0o022:
                raise ExecutionError(f"{name} executable path is writable by non-root")
            if pending and not stat.S_ISDIR(metadata.st_mode):
                raise ExecutionError(f"{name} executable ancestor is not a directory")
            current = candidate
        metadata = current.lstat()
    except OSError as error:
        raise ExecutionError(f"{name} executable is missing") from error
    if (current.name != name
            or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o022 or not os.access(current, os.X_OK)):
        raise ExecutionError(f"{name} executable is not an exact regular executable")
    return current


def _system_executable(name: str) -> Path:
    """Search fixed system locations, never the invoking root user's PATH."""
    directories = {"ip": ("/usr/sbin", "/usr/bin", "/sbin", "/bin"),
                   "docker": ("/usr/bin", "/usr/local/bin", "/bin")}
    for directory in directories[name]:
        try:
            return _regular_executable(Path(directory) / name, name)
        except ExecutionError:
            continue
    raise ExecutionError(f"path-delivery requires trusted host {name} in a system location")


def preflight(docker: Path | None) -> tuple[Path, Path]:
    if platform.system() != "Linux":
        raise ExecutionError("path-delivery execution requires Linux")
    if os.geteuid() != 0:
        raise ExecutionError("path-delivery execution requires root")
    if os.environ.get("DOCKER_HOST") or os.environ.get("DOCKER_CONTEXT"):
        raise ExecutionError("path-delivery requires local default Docker")
    docker = _regular_executable(docker, "docker") if docker is not None else _system_executable("docker")
    host = _pinned_docker(_run_command)([str(docker), "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"], 10)
    if host != b"unix:///var/run/docker.sock\n":
        raise ExecutionError("path-delivery requires local default Docker")
    info = _strict_json(_pinned_docker(_run_command)([str(docker), "info", "--format", "{{json .}}"], 10), "docker-info")
    if (not isinstance(info, dict) or info.get("OSType") != "linux"
            or not isinstance(info.get("SecurityOptions"), list)
            or any("rootless" in str(option) or "userns" in str(option) for option in info["SecurityOptions"])):
        raise ExecutionError("path-delivery requires rootful non-remapped Docker")
    return docker, _system_executable("ip")


def _read_scenario(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ScenarioError("scenario must be a regular file")
        raw = handle.read(MAX_SCENARIO_BYTES + 1)
    if len(raw) > MAX_SCENARIO_BYTES:
        raise ScenarioError("scenario exceeds the byte bound")
    return raw


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--docker", type=Path)
    parsed = parser.parse_args(arguments)
    try:
        raw = _read_scenario(parsed.scenario)
        if parsed.execute:
            docker, ip = preflight(parsed.docker)
            with _lab_lock(LAB_LOCK):
                output = execute_direct(raw, docker=docker, ip=ip)
        else:
            output = compile_scenario(raw)
    except (OSError, UnicodeError):
        print("aster-path-delivery: input-io", file=sys.stderr)
        return 2
    except (ScenarioError, ExecutionError) as error:
        print(f"aster-path-delivery: {error}", file=sys.stderr)
        return 2
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
