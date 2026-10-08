#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for selected Linux Event-custody receipt tooling."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, TOOLS / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load("linux_custody_checker", "check-selected-linux-event-custody-receipt.py")
RUNNER = load("linux_custody_runner", "run-selected-linux-event-custody.py")


def identity(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def line(kind: str, contract: str, values: dict[str, str]) -> str:
    keys = CHECKER.RECORD_KEYS[contract]
    return "\t".join(["LINUX_CUSTODY", kind, *(f"{key}={values[key]}" for key in keys)])


def transcript_lines() -> list[str]:
    authority = identity("authority")
    actors = {
        name: {"carrier": identity(f"{name}-carrier"), "mission": identity(f"{name}-mission")}
        for name in CHECKER.PARTICIPANTS
    }
    ids = {label: identity(f"event-{label}") for label, *_rest in CHECKER.EVENT_SPECS}
    result = [line("META", "META", {
        "schema": CHECKER.TRANSCRIPT_SCHEMA, "claim": CHECKER.CLAIM,
        "platform": "linux", "custody_clock": "clock_boottime_suspend_inclusive",
        "participants": "3", "contacts": "2", "publication_model": "numbered-v1",
    })]
    for participant, access in zip(CHECKER.PARTICIPANTS, ("member", "route_only", "member")):
        result.append(line("PARTICIPANT", "PARTICIPANT", {
            "participant": participant, "access": access, "carrier": actors[participant]["carrier"],
            "mission": actors[participant]["mission"], "authority": authority,
            "provisioning": "independent_reference_bundle",
        }))
    seeded = "events:0,route:0,custody:0,retirements:0,quotas:1,selectors:1,pending:0,state:0,record:0,blob:0,control:0"
    for participant, mode in (("relay", "carry"), ("receiver", "consume")):
        result.append(line("SELECTOR", "SELECTOR", {"participant": participant, "mode": mode, "seeded_while": "stopped", "topic": "opaque.custody", "scope": "test/linux-event-custody", "inspection": seeded}))
    for phase, items in (("origin_to_relay", "4"), ("relay_to_receiver", "2")):
        result.append(line("QUOTA", "QUOTA", {"participant": "relay", "phase": phase, "scope": "test/linux-event-custody", "max_items": items, "max_bytes": "1048576", "exact_scope": "true"}))
    for label, sequence, priority, ttl, payload in CHECKER.EVENT_SPECS:
        result.append(line("EVENT", "EVENT", {"label": label, "id": ids[label], "publisher": actors["origin"]["mission"], "sequence": str(sequence), "priority": priority, "ttl_ms": ttl, "payload_sha256": hashlib.sha256(payload).hexdigest()}))
    result.extend([
        line("EXPIRY", "EXPIRY", {"event": ids["already_expired"], "phase": "before_first_contact", "offered": "false", "origin_retirements": "1", "origin_active_events": "5"}),
        line("CONTACT", "CONTACT", {"phase": "origin_to_relay", "initiator": "origin", "initiator_policy": "at_least_priority", "responder": "relay", "responder_policy": "receive_only", "offered": "4", "relay_fetched": "4", "routine_withheld": ids["routine"]}),
        line("STORE", "STORE3", {"phase": "after_origin_stop", "participant": "origin", "inspection": "events:5,route:0,custody:5,retirements:1,quotas:1,selectors:0,pending:0,state:0,record:0,blob:0,control:0"}),
        line("STORE", "STORE5", {"phase": "after_first_contact", "participant": "relay", "inspection": "events:0,route:4,custody:4,retirements:0,quotas:2,selectors:1,pending:0,state:0,record:0,blob:0,control:0", "content_events": "0", "route_cached": "4"}),
        line("REOPEN_MAINTENANCE", "REOPEN_MAINTENANCE", {
            "participant": "relay", "expired": ids["relay_expiring"],
            "expiry_runtime_quota_items": "4", "expiry_items_after": "3",
            "expiry_retirements_after": "1", "pressure_execution": "stopped_store",
            "pressure_demand_items": "2", "pressure_demand_bytes": "0",
            "pressure_demand_priority": "flash", "pressure_retired": ids["live_priority"],
            "pressure_items_after": "2", "retirements_after": "2",
            "quota_items_after": "2", "retirement_fence_persisted": "true",
        }),
        line("CONTACT", "CONTACT2", {"phase": "relay_to_receiver", "initiator": "relay", "initiator_policy": "normal", "responder": "receiver", "responder_policy": "receive_only", "offered": "2", "receiver_fetched": "2", "origin_runtime_active": "false"}),
        line("DELIVERY", "DELIVERY", {"order": "1", "event": ids["live_flash"], "priority": "flash", "poll_attempt": "1"}),
        line("DELIVERY", "DELIVERY", {"order": "2", "event": ids["live_immediate"], "priority": "immediate", "poll_attempt": "1"}),
        line("ABSENCE", "ABSENCE", {"already_expired": ids["already_expired"], "relay_expired": ids["relay_expiring"], "quota_pressure": ids["live_priority"], "below_floor": ids["routine"], "receiver_query_count": "2", "receiver_poll_count": "2"}),
        line("RECEIVE_ONLY", "RECEIVE_ONLY", {"participants": "relay,receiver", "initiated_contacts": "0", "event_data_offered": "0", "state_offered": "0", "record_offered": "0", "blob_offered": "0", "control_offered": "0"}),
        line("STORE", "STORE4", {"phase": "final", "participant": "relay", "inspection": "events:0,route:2,custody:2,retirements:2,quotas:2,selectors:1,pending:0,state:0,record:0,blob:0,control:0", "route_only": "true"}),
        line("STORE", "STORE4P", {"phase": "final", "participant": "receiver", "inspection": "events:2,route:0,custody:2,retirements:0,quotas:1,selectors:1,pending:2,state:0,record:0,blob:0,control:0", "pending_deliveries": "2"}),
        line("NAMESPACE_ZERO", "NAMESPACE_ZERO", {"participants": "origin,relay,receiver", "legacy": "0", "state": "0", "record": "0", "blob": "0", "control": "0", "exact": "true"}),
        line("SOCKET_FENCE", "SOCKET_FENCE", {"origin": "127.0.0.1:31001", "relay": "127.0.0.1:31002", "receiver": "127.0.0.1:31003", "origin_socket_held_during_second_contact": "true", "all_reacquired_after_stop": "true"}),
        line("RESULT", "RESULT", {"status": "pass", "records": "29", "bounded": "true", "payload_representation": "sha256_only", "secret_values_emitted": "false", "physical_network_claimed": "false", "global_convergence_claimed": "false"}),
    ])
    return result


def encoded(lines: list[str]) -> bytes:
    return ("\n".join(lines) + "\n").encode("ascii")


def mutate(lines: list[str], index: int, key: str, value: str) -> list[str]:
    changed = list(lines)
    fields = changed[index].split("\t")
    for offset, field in enumerate(fields):
        if field.startswith(f"{key}="):
            fields[offset] = f"{key}={value}"
            changed[index] = "\t".join(fields)
            return changed
    raise AssertionError(key)


class TranscriptContractTests(unittest.TestCase):
    def test_numbered_publication_diagnostics_are_exact_and_bounded(self) -> None:
        data = "".join(f"event_publication_group group_sequence={sequence} collected=1 cohorts=1 custody_writer_commits=1 event_writer_commits=1 total_writer_commits=2 accepted_new=1 exact_retries=0 failures=0 max_cohort_size=1 singleton_fallbacks=1\n" for sequence in range(1,5)).encode()
        CHECKER.validate_stderr(data, {})
        for invalid in (b"", data + b"unknown diagnostic\n", data.replace(b"total_writer_commits=2", b"total_writer_commits=1", 1)):
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.validate_stderr(invalid, {})

    def test_historical_v1_transcript_stays_distinct_from_numbered_v2(self) -> None:
        path = Path(__file__).parent / "historical/check-selected-linux-event-custody-receipt.py"
        spec = importlib.util.spec_from_file_location("historical_linux_custody", path)
        self.assertIsNotNone(spec)
        historical = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(historical)
        lines = transcript_lines()
        fields = [field for field in lines[0].split("\t") if not field.startswith("publication_model=")]
        lines[0] = "\t".join(fields).replace(CHECKER.TRANSCRIPT_SCHEMA, historical.TRANSCRIPT_SCHEMA)
        data = encoded(lines)
        historical.validate_transcript(data)
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.validate_transcript(data)
        self.assertEqual(historical.SCHEMA, "aster-selected-linux-event-custody-receipt/v1")
        self.assertNotIn("participants/origin/state/linux-custody-publication.redb", historical.SECRET_FILES)

    def setUp(self) -> None:
        self.lines = transcript_lines()

    def rejected(self, lines: list[str]) -> None:
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.validate_transcript(encoded(lines))

    def test_valid_transcript_and_runner_extraction(self) -> None:
        facts = CHECKER.validate_transcript(encoded(self.lines))
        self.assertEqual(facts["records"], 29)
        with tempfile.TemporaryDirectory() as parent:
            path = Path(parent) / "stdout"
            path.write_bytes(b"READY actor=parent\n" + encoded(self.lines) + b"STOP actor=parent\n")
            self.assertEqual(RUNNER.extract_transcript(path.read_bytes()), encoded(self.lines))

    def test_stdout_runtime_fact_extraction_and_unknown_line_rejection(self) -> None:
        fact_lines = [
            "schema=aster-linux-event-custody-runtime/v1", "kernel_sysname=Linux",
            "kernel_release=6.12.0", "kernel_version=test-kernel", "kernel_machine=aarch64",
            "boot_id=12345678-1234-1234-1234-123456789abc", "uptime=10.00 5.00",
            "clocksource=arch_sys_counter",
        ]
        prefixed = "".join(f"LINUX_CUSTODY_RUNTIME\t{value}\n" for value in fact_lines).encode("ascii")
        facts = ("\n".join(fact_lines) + "\n").encode("ascii")
        def terminal(kind: str, keys: tuple[str, ...]) -> bytes:
            return (kind + " " + " ".join(f"{key}=x" for key in keys) + "\n").encode("ascii")
        runtime = b"".join(terminal("READY", CHECKER.BASE.READY_KEYS) for _ in range(6))
        runtime += b"".join(terminal("CONTACT", CHECKER.BASE.CONTACT_KEYS) for _ in range(4))
        runtime += b"".join(terminal("STOP", CHECKER.BASE.STOP_KEYS) for _ in range(6))
        for kind, keys in CHECKER.CHILD_SCHEMAS.items():
            runtime += ("LINUX_CUSTODY_CHILD\t" + kind + "\t" + "\t".join(f"{key}=x" for key in keys) + "\n").encode("ascii")
        stdout = prefixed + runtime + encoded(self.lines)
        self.assertEqual(RUNNER.extract_runtime_facts(stdout), facts)
        CHECKER.validate_stdout(stdout, encoded(self.lines), facts)
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.validate_stdout(stdout + b"leaked secret\n", encoded(self.lines), facts)
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.validate_stdout(
                stdout.replace(b"READY selected=x", b"READY secret=leaked selected=x", 1),
                encoded(self.lines), facts,
            )

    def test_order_actor_set_and_canonicality_are_fail_closed(self) -> None:
        swapped = list(self.lines)
        swapped[6], swapped[7] = swapped[7], swapped[6]
        self.rejected(swapped)
        self.rejected(mutate(self.lines, 2, "participant", "carrier"))
        self.rejected(mutate(self.lines, 0, "participants", "03"))
        self.rejected(self.lines[:-1])
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.validate_transcript(encoded(self.lines).replace(b"\n", b"\r\n", 1))

    def test_ttl_quota_and_counters_are_fail_closed(self) -> None:
        for index, key, value in (
            (8, "ttl_ms", "501"), (9, "ttl_ms", "durable"),
            (6, "max_items", "5"), (7, "max_bytes", "1048577"),
            (15, "offered", "3"), (18, "retirements_after", "1"),
            (19, "receiver_fetched", "1"), (25, "pending_deliveries", "1"),
        ):
            with self.subTest(index=index, key=key):
                self.rejected(mutate(self.lines, index, key, value))

    def test_receive_only_and_expired_identifier_cross_bindings_are_fail_closed(self) -> None:
        for index, key, value in (
            (23, "initiated_contacts", "1"), (23, "state_offered", "1"),
            (14, "event", identity("wrong-expired")),
            (18, "expired", identity("wrong-relay-expired")),
            (22, "quota_pressure", identity("wrong-pressure")),
        ):
            with self.subTest(index=index, key=key):
                self.rejected(mutate(self.lines, index, key, value))


class ContainerTests(unittest.TestCase):
    def fixture(self):
        raw = Path("/private/tmp/raw-custody")
        execution = "/private/tmp/exec-custody"
        cid, image = identity("container"), f"sha256:{identity('image')}"
        uid, gid = 501, 20
        runtime = {
            "container_id": cid, "image_id": image, "exit_code": 0,
            "timeout_seconds": CHECKER.RUN_TIMEOUT_SECONDS, "uid": uid, "gid": gid,
            "platform": CHECKER.PLATFORM, "network": "none", "read_only_root": True,
            "cap_drop": ["ALL"], "no_new_privileges": True,
            "pids_limit": CHECKER.RUNTIME_PIDS, "memory_bytes": CHECKER.RUNTIME_MEMORY,
            "memory_swap_bytes": CHECKER.RUNTIME_MEMORY, "nano_cpus": CHECKER.RUNTIME_CPUS,
            "raw_mount": {"destination": "/evidence", "read_write": True, "owner_only": True},
        }
        command = ["/bin/sh", "-eu", "-c", CHECKER.RUNTIME_SCRIPT, "sh", f"/execution/{CHECKER.BINARY_NAME}", "/evidence"]
        document = {
            "Id": cid, "Image": image,
            "HostConfig": {
                "NetworkMode": "none", "ReadonlyRootfs": True,
                "PidsLimit": CHECKER.RUNTIME_PIDS, "Memory": CHECKER.RUNTIME_MEMORY,
                "MemorySwap": CHECKER.RUNTIME_MEMORY, "NanoCpus": CHECKER.RUNTIME_CPUS,
                "CgroupnsMode": "private", "Privileged": False, "CapDrop": ["ALL"],
                "CapAdd": None, "SecurityOpt": ["no-new-privileges:true"],
                "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=33554432,uid=501,gid=20"},
                "Devices": [], "DeviceRequests": None, "DeviceCgroupRules": None,
                "PortBindings": {}, "PublishAllPorts": False, "AutoRemove": False,
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "PidMode": "", "IpcMode": "private", "UTSMode": "",
            },
            "Config": {"User": "501:20", "Image": CHECKER.IMAGE, "Entrypoint": None, "Cmd": command},
            "Mounts": [
                {"Type": "bind", "Source": os.fspath(raw), "Destination": "/evidence", "RW": True},
                {"Type": "bind", "Source": execution, "Destination": "/execution", "RW": False},
            ],
            "State": {"Status": "exited", "Running": False, "Paused": False,
                      "Restarting": False, "OOMKilled": False, "Dead": False,
                      "Pid": 0, "ExitCode": 0, "Error": ""},
            "NetworkSettings": {"Ports": {}, "Networks": {"none": {}}},
        }
        return raw, execution, {"runtime": runtime}, document

    def test_exact_container_hardening_and_mount_isolation(self) -> None:
        raw, execution, run, document = self.fixture()
        facts = CHECKER.validate_container(document, run=run, raw_root=raw)
        self.assertEqual(facts["execution_source"], execution)
        for mutation in (
            lambda d: d["HostConfig"].__setitem__("NetworkMode", "default"),
            lambda d: d["HostConfig"].__setitem__("ReadonlyRootfs", False),
            lambda d: d["HostConfig"].__setitem__("PidsLimit", 0),
            lambda d: d["HostConfig"].__setitem__("CapDrop", []),
            lambda d: d["HostConfig"].__setitem__("SecurityOpt", []),
            lambda d: d["Mounts"][1].__setitem__("RW", True),
        ):
            with self.subTest(mutation=mutation):
                raw, _execution, run, document = self.fixture()
                mutation(document)
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.validate_container(document, run=run, raw_root=raw)

    def test_runner_argv_has_exact_runtime_hardening(self) -> None:
        argv = RUNNER.runtime_create_argv("/usr/bin/docker", Path("/private/tmp/raw"), Path("/private/tmp/exec"), 501, 20, "name")
        for option in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--cgroupns=private", "--pids-limit=128", "--memory=1073741824", "--memory-swap=1073741824", "--cpus=1"):
            self.assertIn(option, argv)
        self.assertIn("type=bind,src=/private/tmp/exec,dst=/execution,readonly", argv)

    def test_runner_copies_hardlinked_cargo_artifact_to_unique_execution_file(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            artifact = root / "artifact"
            cargo_alias = root / "cargo-alias"
            execution = root / "execution"
            artifact.write_bytes(b"selected Linux executable fixture")
            artifact.chmod(0o700)
            os.link(artifact, cargo_alias)
            self.assertEqual(artifact.stat().st_nlink, 2)

            digest = RUNNER.copy_built_executable(artifact, execution)

            self.assertEqual(digest, hashlib.sha256(artifact.read_bytes()).hexdigest())
            self.assertEqual(execution.read_bytes(), artifact.read_bytes())
            self.assertEqual(execution.stat().st_nlink, 1)
            self.assertTrue(execution.stat().st_mode & 0o111)


class InventoryAndProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "raw"
        self.root.mkdir(mode=0o700)
        for directory in sorted(CHECKER.EXPECTED_DIRECTORIES - {""}, key=lambda value: (value.count("/"), value)):
            (self.root / directory).mkdir(mode=0o700)
        for path, mode in CHECKER.PUBLIC_FILES.items():
            target = self.root / path
            data = b"x" if path != "stderr.log" else b""
            target.write_bytes(data)
            target.chmod(mode)
        for path, mode in CHECKER.SECRET_FILES.items():
            target = self.root / path
            size = CHECKER.IDENTITY_BYTES if path.endswith("identity.key") else 64
            target.write_bytes(b"s" * size)
            target.chmod(mode)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def inspect(self) -> None:
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            CHECKER.validate_inventory(descriptor)
        finally:
            os.close(descriptor)

    def test_exact_inventory_and_metadata_only_secret_bounds(self) -> None:
        self.inspect()
        extra = self.root / "extra"
        extra.write_bytes(b"x")
        extra.chmod(0o600)
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.inspect()

    def test_secret_size_mode_and_alias_are_rejected(self) -> None:
        identity_path = self.root / "participants/origin/state/identity.key"
        identity_path.write_bytes(b"short")
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.inspect()
        identity_path.write_bytes(b"s" * CHECKER.IDENTITY_BYTES)
        identity_path.chmod(0o644)
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.inspect()

    def test_canonical_json_source_binding_and_receipt_sanitization(self) -> None:
        authority = {
            "commit": "a" * 40, "tree": "b" * 40,
            "signature": {"status": "good", "fingerprint": "A" * 40},
            "admitted": {path: {"bytes": 1, "sha256": identity(path)} for path in CHECKER.ADMITTED_SOURCE_PATHS},
        }
        stored = {"commit": authority["commit"], "tree": authority["tree"], "signature": authority["signature"], "admitted": [{"path": path, **authority["admitted"][path]} for path in CHECKER.ADMITTED_SOURCE_PATHS]}
        CHECKER.validate_source_record(stored, authority)
        stored["tree"] = "c" * 40
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.validate_source_record(stored, authority)
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.render_receipt({"schema": CHECKER.SCHEMA, "id": identity("secret")})
        valid = CHECKER.render_receipt({"schema": CHECKER.SCHEMA, "status": "pass"})
        self.assertEqual(valid, CHECKER.canonical_json_bytes(json.loads(valid)))

    def test_public_pinned_image_digest_is_not_a_sanitized_runtime_identifier(self) -> None:
        evidence = {
            "run": {
                "run_id": "0123456789abcdef",
                "container": {
                    "container_id": identity("container"),
                    "image_id": CHECKER.IMAGE.split("@", 1)[1],
                    "execution_source": "/private/tmp/execution",
                },
            },
            "transcript": {"event_ids": [], "identity_values": [], "sockets": []},
            "facts": {"boot_id": "12345678-1234-1234-1234-123456789abc"},
            "terminal": {"sensitive": {"1", "17"}},
        }

        forbidden = CHECKER.sensitive_values(
            evidence,
            Path("/private/tmp/raw"),
            Path("/Users/reviewer/source"),
        )

        self.assertNotIn(CHECKER.IMAGE.split("@", 1)[1], forbidden)
        self.assertNotIn("1", forbidden)
        self.assertNotIn("17", forbidden)


if __name__ == "__main__":
    unittest.main()
