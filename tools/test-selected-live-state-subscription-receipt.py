#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for the selected live State-subscription receipt checker."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest


def read_source_without_bytecode(path: Path) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > 4 * 1024 * 1024
    ):
        raise RuntimeError(f"unsafe test subject source {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise RuntimeError(f"test subject changed while opening {path}")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise RuntimeError(f"test subject truncated while reading {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RuntimeError(f"test subject grew while reading {path}")
        final = os.fstat(descriptor)
        terminal = path.lstat()
        if (final.st_dev, final.st_ino, final.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) or (terminal.st_dev, terminal.st_ino, terminal.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise RuntimeError(f"test subject changed while reading {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load(filename: str, name: str) -> types.ModuleType:
    path = Path(__file__).with_name(filename)
    source = read_source_without_bytecode(path)
    module = types.ModuleType(name)
    module.__file__ = os.fspath(path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        code = compile(source, os.fspath(path), "exec", dont_inherit=True, optimize=0)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


CHECKER = load(
    "check-selected-live-state-subscription-receipt.py",
    "selected_live_state_subscription_receipt",
)
RUNNER = load(
    "run-selected-live-state-subscription.py",
    "selected_live_state_subscription_runner",
)


def identifier(number: int) -> str:
    return f"{number:064x}"


def tsv(kind: str, keys: tuple[str, ...], values: dict[str, str]) -> str:
    if set(values) != set(keys):
        raise AssertionError(f"fixture {kind} fields differ: {set(values) ^ set(keys)}")
    return "\t".join(
        [
            "LIVE_STATE_SUBSCRIPTION",
            kind.lower(),
            *(f"{key}={values[key]}" for key in keys),
        ]
    )


def terminal(prefix: str, keys: tuple[str, ...], values: dict[str, str]) -> str:
    if set(values) != set(keys):
        raise AssertionError(f"fixture {prefix} fields differ: {set(values) ^ set(keys)}")
    return " ".join([prefix, *(f"{key}={values[key]}" for key in keys)])


class Fixture:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or Path("/tmp/aster-state-subscription-synthetic")
        self.participants = {
            "publisher": {
                "carrier_id": identifier(1),
                "mission_id": identifier(3),
                "mission_authority": identifier(5),
            },
            "receiver": {
                "carrier_id": identifier(2),
                "mission_id": identifier(4),
                "mission_authority": identifier(5),
            },
        }
        self.subscription = identifier(10)
        self.tokens = {
            "initial": identifier(20),
            "attempt_one": identifier(21),
            "attempt_two": identifier(22),
            "tombstone": identifier(23),
        }
        self.states = {
            "left": self.state(
                identifier(11), "publisher", "1", "left", "false"
            ),
            "right": self.state(
                identifier(12), "receiver", "1", "right", "false"
            ),
            "successor": self.state(
                identifier(13), "publisher", "2", "successor", "false"
            ),
            "beta": self.state(
                identifier(14), "publisher", "3", "beta", "false"
            ),
            "gamma": self.state(
                identifier(15), "publisher", "4", "gamma", "false"
            ),
            "tombstone": self.state(
                identifier(16), "receiver", "2", "tombstone", "true"
            ),
        }
        self.shutdowns = {
            ("peerless_origins", "publisher"): self.shutdown_values(),
            ("peerless_origins", "receiver"): self.shutdown_values(),
            (
                "direct_convergence_and_successor",
                "publisher",
            ): self.shutdown_values(contacts=1, offered=3, fetched=1, inserted=1),
            (
                "direct_convergence_and_successor",
                "receiver",
            ): self.shutdown_values(contacts=1, offered=1, fetched=3, inserted=3),
            ("peerless_redelivery_ack", "receiver"): self.shutdown_values(),
            ("peerless_tombstone", "receiver"): self.shutdown_values(),
            (
                "direct_tombstone_propagation",
                "publisher",
            ): self.shutdown_values(contacts=1, offered=0, fetched=1, inserted=1),
            (
                "direct_tombstone_propagation",
                "receiver",
            ): self.shutdown_values(contacts=1, offered=1, fetched=0, inserted=0),
            ("final_peerless_reopen", "receiver"): self.shutdown_values(),
        }
        self.transcript_lines = self.build_transcript()
        self.transcript = ("\n".join(self.transcript_lines) + "\n").encode("ascii")
        self.stdout_lines = self.build_stdout()
        self.stdout = ("\n".join(self.stdout_lines + self.transcript_lines) + "\n").encode(
            "ascii"
        )

    def state(
        self,
        state_id: str,
        participant: str,
        counter: str,
        payload: str,
        tombstone: str,
    ) -> dict[str, str]:
        return {
            "id": state_id,
            "publisher": self.participants[participant]["mission_id"],
            "publisher_counter": counter,
            "payload_sha256": CHECKER.PAYLOAD_HASHES[payload],
            "tombstone": tombstone,
        }

    @staticmethod
    def shutdown_values(
        *, contacts: int = 0, offered: int = 0, fetched: int = 0, inserted: int = 0
    ) -> dict[str, int]:
        return {
            "contacts": contacts,
            "contact_errors": 0,
            "direct_contacts": contacts,
            "relay_contacts": 0,
            "unknown_path_contacts": 0,
            "data_offered": offered,
            "data_fetched": fetched,
            "data_inserted": inserted,
            "data_duplicates": 0,
            "data_remaining": 0,
            "mutable_remaining": 0,
            "deferred_mutable_lanes": 0,
        }

    def record(self, kind: str, values: dict[str, str]) -> str:
        keys = dict(CHECKER.EXPECTED_SEQUENCE)[kind]
        return tsv(kind, keys, values)

    def participant_record(self, name: str) -> str:
        return self.record(
            "PARTICIPANT",
            {
                "participant": name,
                **self.participants[name],
                "provisioning": "independent-reference-bundle",
            },
        )

    def peer_binding(self, local: str, remote: str) -> str:
        return self.record(
            "PEER_BINDING",
            {
                "local": local,
                "remote": remote,
                "local_carrier": self.participants[local]["carrier_id"],
                "local_mission": self.participants[local]["mission_id"],
                "remote_carrier": self.participants[remote]["carrier_id"],
                "remote_mission": self.participants[remote]["mission_id"],
                "mission_authenticated": "true",
            },
        )

    def phase(self, number: int) -> str:
        _, phase, actors, outcome = CHECKER.PHASES[number - 1]
        return self.record(
            "PHASE",
            {
                "index": str(number),
                "phase": phase,
                "actors": actors,
                "outcome": outcome,
            },
        )

    def subscription_record(self, phase: str, inserted: bool) -> str:
        return self.record(
            "SUBSCRIPTION",
            {
                "phase": phase,
                "participant": "receiver",
                "stream": "alpha",
                "id": self.subscription,
                "inserted": str(inserted).lower(),
                "durable": "true",
                "include_descendant_scopes": "false",
            },
        )

    def state_record(
        self,
        name: str,
        phase: str,
        participant: str,
        stream: str,
        marker: int,
    ) -> str:
        state = self.states[name]
        return self.record(
            "STATE",
            {
                "phase": phase,
                "participant": participant,
                "stream": stream,
                **state,
                "priority": "priority",
                "acceptance_marker": str(marker),
                "inserted": "true",
            },
        )

    def delivery(
        self,
        name: str,
        phase: str,
        stream: str,
        attempt: int,
        token_name: str,
    ) -> str:
        state = self.states[name]
        return self.record(
            "DELIVERY",
            {
                "phase": phase,
                "participant": "receiver",
                "stream": stream,
                "id": state["id"],
                "publisher": state["publisher"],
                "publisher_counter": state["publisher_counter"],
                "attempt": str(attempt),
                "token_sha256": self.tokens[token_name],
                "disposition": "current",
                "tombstone": state["tombstone"],
                "payload_sha256": state["payload_sha256"],
            },
        )

    def projection(
        self,
        phase: str,
        participant: str,
        stream: str,
        current_name: str,
        recoverable_names: tuple[str, ...] = (),
        disposition: str = "superseded",
    ) -> str:
        current = self.states[current_name]
        recoverable = sorted(
            (self.states[name] for name in recoverable_names), key=lambda item: item["id"]
        )
        return self.record(
            "PROJECTION",
            {
                "phase": phase,
                "participant": participant,
                "stream": stream,
                "current_id": current["id"],
                "current_publisher": current["publisher"],
                "current_counter": current["publisher_counter"],
                "current_disposition": "current",
                "current_tombstone": current["tombstone"],
                "current_payload_sha256": current["payload_sha256"],
                "recoverable_count": str(len(recoverable)),
                "recoverable_ids": "none"
                if not recoverable
                else ",".join(item["id"] for item in recoverable),
                "recoverable_dispositions": "none"
                if not recoverable
                else ",".join(disposition for _item in recoverable),
                "recoverable_tombstones": "none"
                if not recoverable
                else ",".join(item["tombstone"] for item in recoverable),
                "recoverable_payload_sha256": "none"
                if not recoverable
                else ",".join(item["payload_sha256"] for item in recoverable),
            },
        )

    def selector(self, phase: str, name: str, interested: bool) -> str:
        return self.record(
            "SELECTOR",
            {
                "phase": phase,
                "stream": name,
                "id": self.states[name]["id"],
                "publisher_retained": "true",
                "network_interested": str(interested).lower(),
                "receiver_retained": str(interested).lower(),
                "alpha_application_delivered": "false",
            },
        )

    def ack(
        self,
        kind: str,
        phase: str,
        name: str,
        token_name: str,
        token_attempt: int,
        disposition: str,
    ) -> str:
        return self.record(
            kind,
            {
                "phase": phase,
                "participant": "receiver",
                "id": self.states[name]["id"],
                "token_sha256": self.tokens[token_name],
                "token_attempt": str(token_attempt),
                "disposition": disposition,
            },
        )

    def empty(self, phase: str) -> str:
        return self.record(
            "EMPTY_POLL",
            {
                "phase": phase,
                "participant": "receiver",
                "deliveries": "0",
                "has_more": "false",
                "delivery_limit": "8",
                "scan_limit": "16",
            },
        )

    def shutdown(self, phase: str, participant: str) -> str:
        values = self.shutdowns[(phase, participant)]
        return self.record(
            "SHUTDOWN",
            {
                "phase": phase,
                "participant": participant,
                **{key: str(value) for key, value in values.items()},
                "excluded_class_counters": "all-zero",
            },
        )

    def build_transcript(self) -> list[str]:
        lines = [
            self.record(
                "RUN",
                {
                    "schema": CHECKER.TRANSCRIPT_SCHEMA,
                    "claim": CHECKER.CLAIM,
                    "participants": "2",
                    "processes": "3",
                    "actor_lifetimes": "10",
                    "maximum_concurrent_actors": "2",
                    "alpha_topic": "opaque",
                    "beta_topic": "opaque.beta",
                    "gamma_topic": "opaque.gamma",
                    "scope": "test/runtime-contact",
                },
            ),
            self.participant_record("publisher"),
            self.participant_record("receiver"),
            self.peer_binding("publisher", "receiver"),
            self.peer_binding("receiver", "publisher"),
            self.phase(1),
            self.subscription_record("peerless_origins", True),
            self.subscription_record("peerless_origins", False),
            self.state_record("left", "peerless_origins", "publisher", "alpha-left", 1),
            self.state_record("right", "peerless_origins", "receiver", "alpha-right", 1),
            self.delivery("right", "peerless_origins", "alpha-right", 1, "initial"),
            self.projection("peerless_origins", "publisher", "alpha", "left"),
            self.projection("peerless_origins", "receiver", "alpha", "right"),
            self.shutdown("peerless_origins", "publisher"),
            self.shutdown("peerless_origins", "receiver"),
            self.phase(2),
            self.subscription_record("direct_convergence_and_successor", False),
            self.projection(
                "direct_convergence_and_successor",
                "publisher",
                "alpha-concurrent",
                "right",
                ("left",),
                "concurrent",
            ),
            self.projection(
                "direct_convergence_and_successor",
                "receiver",
                "alpha-concurrent",
                "right",
                ("left",),
                "concurrent",
            ),
            self.state_record(
                "successor",
                "direct_convergence_and_successor",
                "publisher",
                "alpha-successor",
                3,
            ),
            self.projection(
                "direct_convergence_and_successor",
                "publisher",
                "alpha-successor",
                "successor",
                ("left", "right"),
            ),
            self.projection(
                "direct_convergence_and_successor",
                "receiver",
                "alpha-successor",
                "successor",
                ("left", "right"),
            ),
            self.state_record(
                "beta", "direct_convergence_and_successor", "publisher", "beta", 4
            ),
            self.state_record(
                "gamma", "direct_convergence_and_successor", "publisher", "gamma", 5
            ),
            self.selector("direct_convergence_and_successor", "beta", True),
            self.selector("direct_convergence_and_successor", "gamma", False),
            self.shutdown("direct_convergence_and_successor", "publisher"),
            self.shutdown("direct_convergence_and_successor", "receiver"),
            self.phase(3),
            self.subscription_record("forced_successor_delivery", False),
            self.projection(
                "forced_successor_delivery",
                "receiver",
                "alpha-successor-child-validated",
                "successor",
                ("left", "right"),
            ),
            self.delivery(
                "successor",
                "forced_successor_delivery",
                "alpha-successor",
                1,
                "attempt_one",
            ),
            self.record(
                "PROCESS_TERMINATION",
                {
                    "phase": "forced_successor_delivery",
                    "participant": "receiver",
                    "mechanism": "parent-child-kill",
                    "termination_signal": "sigkill",
                    "distinct_process": "true",
                    "after_flushed_poll": "true",
                    "graceful": "false",
                    "stop_record_expected": "false",
                    "stop_record_observed": "false",
                    "acknowledged": "false",
                    "token_persisted": "true",
                    "token_artifact_permissions": "owner-only",
                    "token_representation": "sha256-only",
                },
            ),
            self.phase(4),
            self.subscription_record("peerless_redelivery_ack", False),
            self.delivery(
                "successor",
                "peerless_redelivery_ack",
                "alpha-successor",
                2,
                "attempt_two",
            ),
            self.ack(
                "ACKNOWLEDGEMENT",
                "peerless_redelivery_ack",
                "successor",
                "attempt_one",
                1,
                "acknowledged",
            ),
            self.ack(
                "REACKNOWLEDGEMENT",
                "peerless_redelivery_ack",
                "successor",
                "attempt_two",
                2,
                "already_acknowledged",
            ),
            self.empty("peerless_redelivery_ack"),
            self.shutdown("peerless_redelivery_ack", "receiver"),
            self.phase(5),
            self.subscription_record("peerless_tombstone", False),
            self.state_record(
                "tombstone",
                "peerless_tombstone",
                "receiver",
                "alpha-tombstone",
                5,
            ),
            self.delivery(
                "tombstone",
                "peerless_tombstone",
                "alpha-tombstone",
                1,
                "tombstone",
            ),
            self.ack(
                "ACKNOWLEDGEMENT",
                "peerless_tombstone",
                "tombstone",
                "tombstone",
                1,
                "acknowledged",
            ),
            self.ack(
                "REACKNOWLEDGEMENT",
                "peerless_tombstone",
                "tombstone",
                "tombstone",
                1,
                "already_acknowledged",
            ),
            self.empty("peerless_tombstone"),
            self.projection(
                "peerless_tombstone",
                "receiver",
                "alpha-tombstone",
                "tombstone",
                ("left", "right", "successor"),
            ),
            self.shutdown("peerless_tombstone", "receiver"),
            self.phase(6),
            self.subscription_record("direct_tombstone_propagation", False),
            self.projection(
                "direct_tombstone_propagation",
                "publisher",
                "alpha-tombstone",
                "tombstone",
                ("left", "right", "successor"),
            ),
            self.projection(
                "direct_tombstone_propagation",
                "receiver",
                "alpha-tombstone",
                "tombstone",
                ("left", "right", "successor"),
            ),
            self.selector("direct_tombstone_propagation", "beta", True),
            self.selector("direct_tombstone_propagation", "gamma", False),
            self.empty("direct_tombstone_propagation"),
            self.shutdown("direct_tombstone_propagation", "publisher"),
            self.shutdown("direct_tombstone_propagation", "receiver"),
            self.phase(7),
            self.subscription_record("final_peerless_reopen", False),
            self.projection(
                "final_peerless_reopen",
                "receiver",
                "alpha-tombstone",
                "tombstone",
                ("left", "right", "successor"),
            ),
            self.selector("final_peerless_reopen", "beta", True),
            self.selector("final_peerless_reopen", "gamma", False),
            self.empty("final_peerless_reopen"),
            self.shutdown("final_peerless_reopen", "receiver"),
            self.record(
                "STORE_INSPECTION",
                {
                    "participant": "publisher",
                    "states": "6",
                    "state_acceptance_markers": "6",
                    "state_operations": "4",
                    "subscriptions": "0",
                    "pending_deliveries": "0",
                    "acknowledged_deliveries": "0",
                    "delivery_cursors": "0",
                    "selector_generation": "0",
                    "event_record_blob_opaque_control": "all-zero",
                },
            ),
            self.record(
                "STORE_INSPECTION",
                {
                    "participant": "receiver",
                    "states": "5",
                    "state_acceptance_markers": "5",
                    "state_operations": "2",
                    "subscriptions": "1",
                    "pending_deliveries": "0",
                    "acknowledged_deliveries": "1",
                    "delivery_cursors": "3",
                    "selector_generation": "1",
                    "event_record_blob_opaque_control": "all-zero",
                },
            ),
            self.record("BIND", {"participant": "publisher", "status": "reacquired"}),
            self.record("BIND", {"participant": "receiver", "status": "reacquired"}),
            self.record(
                "RESULT",
                {
                    "status": "pass",
                    "records": "70",
                    "phases": "7",
                    "participants": "2",
                    "processes": "3",
                    "actor_lifetimes": "10",
                    "maximum_concurrent_actors": "2",
                    "graceful_shutdowns": "9",
                    "forced_process_terminations": "1",
                    "closed_handles": "9",
                    "state_publications": "6",
                    "network_state_insertions": "5",
                    "deliveries": "4",
                    "acknowledgements": "2",
                    "reacknowledgements": "2",
                    "token_binding_checks": "8",
                    "malformed_token_rejected": "true",
                    "wrong_subscription_token_rejected": "true",
                    "wrong_state_token_rejected": "true",
                    "retired_token_rejected": "true",
                    "empty_polls": "4",
                    "subscription_insertions": "1",
                    "subscription_replays": "7",
                    "bind_reacquisitions": "2",
                    "payload_representation": "sha256-only",
                    "token_representation": "sha256-only",
                    "opaque_tokens_emitted": "false",
                    "secret_values_emitted": "false",
                    "physical_network_claimed": "false",
                    "global_convergence_claimed": "false",
                },
            ),
        ]
        if len(lines) != CHECKER.TRANSCRIPT_RECORDS:
            raise AssertionError(f"fixture produced {len(lines)} records")
        for index, line in enumerate(lines):
            expected_kind = CHECKER.EXPECTED_SEQUENCE[index][0]
            if line.split("\t", 2)[1] != expected_kind.lower():
                raise AssertionError(f"fixture record {index + 1} kind differs")
        return lines

    def ready(self, participant: str, pid: int, socket: str, peers: int) -> str:
        values = {
            "selected": "true",
            "pid": str(pid),
            **self.participants[participant],
            "sockets": socket,
            "state": CHECKER.encoded_path(
                self.root / "participants" / participant / "state"
            ),
            "peers": str(peers),
            "application": "relay",
            "carrier_route": "direct",
            "controlled_relay_url": "none",
            "controlled_relay_trust": "none",
            "controlled_relay_readiness": "not-applicable",
            "public_relay_fallback": "false",
            "hosted_discovery": "false",
            "nat_traversal": "not-claimed",
            "path_observation": "not-authorization",
            "mission_auth": "hybrid-pq",
            "provisioning": "unprotected-reference",
            "semantics": "source-authenticated-event",
            "reconciliation_classes": "event,state,record,blob-v5-opt-in",
            "controls": "source-authenticated-flash",
            "commit_before_activate": "true",
            "content_admission": "capability-gated",
        }
        return terminal("READY", CHECKER.SUPPORT.READY_KEYS, values)

    def contact(
        self, local: str, *, offered: int, fetched: int, inserted: int
    ) -> str:
        remote = "receiver" if local == "publisher" else "publisher"
        values = {key: "0" for key in CHECKER.SUPPORT.CONTACT_KEYS}
        values.update(
            {
                "direction": "out" if local == "publisher" else "in",
                "carrier_peer": self.participants[remote]["carrier_id"],
                "mission_peer": self.participants[remote]["mission_id"],
                "rounds": "1",
                "offered": str(offered),
                "fetched": str(fetched),
                "inserted": str(inserted),
                "handshake_frames": "1",
                "handshake_bytes": "64",
                "protected_frames": "1",
                "protected_bytes": "64",
                "carrier_path": "direct",
                "carrier_path_transitions_saturated": "false",
                "path_observation": "not-authorization",
                "mission_auth": "hybrid-pq",
                "semantics": "source-authenticated-event",
                "reconciliation_classes": "event,state,record,blob",
                "controls": "source-authenticated-flash",
                "content_admission": "capability-gated",
                "status": "pass",
            }
        )
        return terminal("CONTACT", CHECKER.SUPPORT.CONTACT_KEYS, values)

    def stop(self, phase: str, participant: str) -> str:
        shutdown = self.shutdowns[(phase, participant)]
        values = {key: "0" for key in CHECKER.SUPPORT.STOP_KEYS}
        values.update(
            {
                "lifecycle": "complete",
                "sync_status": "contacts_observed"
                if shutdown["contacts"]
                else "no_successful_contact",
                "carrier_id": self.participants[participant]["carrier_id"],
                "mission_id": self.participants[participant]["mission_id"],
                "contacts": str(shutdown["contacts"]),
                "direct_contacts": str(shutdown["direct_contacts"]),
                "path_observation": "not-authorization",
                "mission_auth": "hybrid-pq",
                "provisioning": "unprotected-reference",
                "semantics": "source-authenticated-event",
                "reconciliation_classes": "event,state,record,blob-v5",
                "controls_semantics": "source-authenticated-flash",
            }
        )
        return terminal("STOP", CHECKER.SUPPORT.STOP_KEYS, values)

    def child(self, kind: str) -> str:
        if kind == "ATTEMPT1_READY":
            keys = CHECKER.ATTEMPT_ONE_CHILD_KEYS
            values = {
                "participant": "receiver",
                "identity": self.participants["receiver"]["mission_id"],
                "subscription_id": self.subscription,
                "subscription_inserted": "false",
                "successor_id": self.states["successor"]["id"],
                "successor_publisher": self.participants["publisher"]["mission_id"],
                "successor_counter": "2",
                "successor_attempt": "1",
                "successor_token_sha256": self.tokens["attempt_one"],
                "successor_token_persisted": "true",
                "successor_payload_sha256": CHECKER.PAYLOAD_HASHES["successor"],
                "successor_disposition": "current",
                "successor_tombstone": "false",
                "old_left_absent": "true",
                "old_right_absent": "true",
                "beta_absent": "true",
                "gamma_query_empty": "true",
                "acknowledged": "false",
            }
        else:
            keys = CHECKER.ATTEMPT_TWO_CHILD_KEYS
            values = {
                "participant": "receiver",
                "identity": self.participants["receiver"]["mission_id"],
                "subscription_id": self.subscription,
                "subscription_inserted": "false",
                "successor_id": self.states["successor"]["id"],
                "successor_publisher": self.participants["publisher"]["mission_id"],
                "successor_counter": "2",
                "successor_attempt": "2",
                "successor_token_sha256": self.tokens["attempt_two"],
                "previous_token_sha256": self.tokens["attempt_one"],
                "tokens_distinct": "true",
                "previous_token_restored": "true",
                "malformed_token_rejected": "true",
                "wrong_subscription_token_rejected": "true",
                "wrong_state_token_rejected": "true",
                "retired_token_rejected": "true",
                "retired_token_sha256": self.tokens["initial"],
                "ack_token_attempt": "1",
                "reack_token_attempt": "2",
                "token_artifact_removed": "true",
                "successor_payload_sha256": CHECKER.PAYLOAD_HASHES["successor"],
                "successor_disposition": "current",
                "successor_tombstone": "false",
                "ack": "acknowledged",
                "reack": "already_acknowledged",
                "empty_deliveries": "0",
                "empty_has_more": "false",
                "closed_kind": "state_unavailable",
                "closed_operation": "state_query",
                "shutdown_contacts": "0",
                "shutdown_contact_errors": "0",
                "shutdown_direct_contacts": "0",
                "shutdown_relay_contacts": "0",
                "shutdown_unknown_path_contacts": "0",
                "shutdown_items": "0",
                "shutdown_events": "0",
                "shutdown_blobs": "0",
                "shutdown_data_offered": "0",
                "shutdown_data_fetched": "0",
                "shutdown_data_inserted": "0",
                "shutdown_data_duplicates": "0",
                "shutdown_data_remaining": "0",
                "shutdown_mutable_remaining": "0",
                "shutdown_deferred_mutable_lanes": "0",
            }
        return "\t".join(
            [
                "LIVE_STATE_SUBSCRIPTION_CHILD",
                kind,
                *(f"{key}={values[key]}" for key in keys),
            ]
        )

    def build_stdout(self) -> list[str]:
        return [
            self.ready("publisher", 100, "127.0.0.1:10001", 0),
            self.ready("receiver", 100, "127.0.0.1:10002", 0),
            self.stop("peerless_origins", "publisher"),
            self.stop("peerless_origins", "receiver"),
            self.ready("publisher", 100, "127.0.0.1:11001", 1),
            self.ready("receiver", 100, "127.0.0.1:11002", 1),
            self.contact("publisher", offered=3, fetched=1, inserted=1),
            self.contact("receiver", offered=1, fetched=3, inserted=3),
            self.stop("direct_convergence_and_successor", "publisher"),
            self.stop("direct_convergence_and_successor", "receiver"),
            self.ready("receiver", 101, "127.0.0.1:12001", 0),
            self.child("ATTEMPT1_READY"),
            self.ready("receiver", 102, "127.0.0.1:12002", 0),
            self.stop("peerless_redelivery_ack", "receiver"),
            self.child("ATTEMPT2_DONE"),
            self.ready("receiver", 100, "127.0.0.1:13001", 0),
            self.stop("peerless_tombstone", "receiver"),
            self.ready("publisher", 100, "127.0.0.1:11001", 1),
            self.ready("receiver", 100, "127.0.0.1:11002", 1),
            self.contact("publisher", offered=0, fetched=1, inserted=1),
            self.contact("receiver", offered=1, fetched=0, inserted=0),
            self.stop("direct_tombstone_propagation", "publisher"),
            self.stop("direct_tombstone_propagation", "receiver"),
            self.ready("receiver", 100, "127.0.0.1:14001", 0),
            self.stop("final_peerless_reopen", "receiver"),
        ]


def replace_field(line: str, key: str, value: str) -> str:
    parts = line.split("\t")
    replaced = False
    for index in range(2, len(parts)):
        if parts[index].startswith(f"{key}="):
            parts[index] = f"{key}={value}"
            replaced = True
            break
    if not replaced:
        raise AssertionError(f"missing field {key}")
    return "\t".join(parts)


class RawRootFixture:
    def __init__(self, parent: Path) -> None:
        parent.chmod(0o700)
        self.root = (parent / "raw").resolve()
        self.root.mkdir(mode=0o700)
        self.fixture = Fixture(self.root)
        self.binary = b"\x7fELFsynthetic-state-subscription-release\n"
        self.authority = {
            "commit": "1" * 40,
            "tree": "2" * 40,
            "signature": {"status": "good", "fingerprint": "A" * 40},
            "admitted": {
                relative: {
                    "bytes": len(f"synthetic:{relative}\n".encode("ascii")),
                    "sha256": hashlib.sha256(
                        f"synthetic:{relative}\n".encode("ascii")
                    ).hexdigest(),
                }
                for relative in CHECKER.ADMITTED_SOURCE_PATHS
            },
        }
        self._create_files()
        self._write_run_document()

    def mkdir(self, relative: str) -> None:
        target = self.root / relative
        target.mkdir(mode=0o700)
        target.chmod(0o700)

    def write(self, relative: str, data: bytes, mode: int) -> None:
        target = self.root / relative
        target.write_bytes(data)
        target.chmod(mode)

    def _create_files(self) -> None:
        for relative in (
            "binary",
            "participants",
            "participants/publisher",
            "participants/publisher/state",
            "participants/receiver",
            "participants/receiver/state",
        ):
            self.mkdir(relative)
        self.write(f"binary/{CHECKER.BINARY_NAME}", self.binary, 0o700)
        self.write("stdout.log", self.fixture.stdout, 0o600)
        self.write("stderr.log", b"", 0o600)
        self.write("transcript.tsv", self.fixture.transcript, 0o600)
        for participant in CHECKER.PARTICIPANTS:
            self.write(
                f"participants/{participant}/mission.bundle",
                f"mission-{participant}\n".encode("ascii"),
                0o600,
            )
            self.write(
                f"participants/{participant}/state/identity.key", b"K" * 32, 0o600
            )
            self.write(
                f"participants/{participant}/state/mesh.redb",
                f"store-{participant}\n".encode("ascii"),
                0o600,
            )

    def file_record(self, relative: str) -> dict[str, object]:
        data = (self.root / relative).read_bytes()
        return {
            "path": relative,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def inventory_file(self, relative: str) -> dict[str, object]:
        metadata = (self.root / relative).lstat()
        return {
            "path": relative,
            "bytes": metadata.st_size,
            "mode": metadata.st_mode & 0o777,
            "hard_links": metadata.st_nlink,
            "owner": metadata.st_uid,
        }

    def _write_run_document(self) -> None:
        public_paths = tuple(
            sorted(
                relative
                for relative in CHECKER.SUPPORT.EXPECTED_FILES
                if relative not in CHECKER.SUPPORT.SECRET_FILES
                and relative != "run.json"
            )
        )
        document = {
            "schema": CHECKER.RAW_SCHEMA,
            "claim": CHECKER.CLAIM,
            "run_id": hashlib.sha256(self.fixture.transcript).hexdigest()[:16],
            "source": {
                "commit": self.authority["commit"],
                "tree": self.authority["tree"],
                "signature": self.authority["signature"],
                "admitted": [
                    {"path": relative, **self.authority["admitted"][relative]}
                    for relative in CHECKER.ADMITTED_SOURCE_PATHS
                ],
            },
            "commands": {
                "build_argv": CHECKER.EXPECTED_BUILD_ARGV,
                "run_argv": [
                    os.fspath(self.root / "binary" / CHECKER.BINARY_NAME),
                    os.fspath(self.root),
                ],
            },
            "execution": {
                "exit_code": 0,
                "timeout_seconds": CHECKER.RUN_TIMEOUT_SECONDS,
                "worktree_clean_at_run": True,
                "source_binary_execution_link": (
                    "operator-attested-not-cryptographically-proven"
                ),
            },
            "artifacts": {
                "binary": self.file_record(f"binary/{CHECKER.BINARY_NAME}"),
                "stdout": self.file_record("stdout.log"),
                "stderr": self.file_record("stderr.log"),
                "transcript": self.file_record("transcript.tsv"),
            },
            "inventory": {
                "directories": [
                    {
                        "path": relative or ".",
                        "mode": 0o700,
                        "owner": (self.root / relative).lstat().st_uid
                        if relative
                        else self.root.lstat().st_uid,
                    }
                    for relative in sorted(CHECKER.SUPPORT.EXPECTED_DIRECTORIES)
                ],
                "public": [self.inventory_file(relative) for relative in public_paths],
                "participant_secret": [
                    self.inventory_file(relative)
                    for relative in sorted(CHECKER.SUPPORT.SECRET_FILES)
                ],
            },
            "tools": {
                role: {"path": relative, **self.authority["admitted"][relative]}
                for role, relative in CHECKER.TOOL_PATHS.items()
            },
        }
        self.write("run.json", CHECKER.canonical_json_bytes(document), 0o600)


class TranscriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()

    def validate_lines(self, lines: list[str]):
        return CHECKER.validate_transcript(("\n".join(lines) + "\n").encode("ascii"))

    def assert_rejected(self, lines: list[str]) -> None:
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate_lines(lines)

    def test_exact_transcript_is_accepted(self) -> None:
        facts = CHECKER.validate_transcript(self.fixture.transcript)
        self.assertEqual(facts["records"], 70)
        self.assertEqual(facts["token_binding_checks"], 8)

    def test_reordered_field_is_rejected(self) -> None:
        lines = self.fixture.transcript_lines.copy()
        parts = lines[31].split("\t")
        parts[-1], parts[-2] = parts[-2], parts[-1]
        lines[31] = "\t".join(parts)
        self.assert_rejected(lines)

    def test_wrong_payload_digest_is_rejected(self) -> None:
        lines = self.fixture.transcript_lines.copy()
        lines[19] = replace_field(lines[19], "payload_sha256", identifier(40))
        self.assert_rejected(lines)

    def test_duplicate_state_identity_is_rejected(self) -> None:
        lines = self.fixture.transcript_lines.copy()
        lines[23] = replace_field(
            lines[23], "id", self.fixture.states["beta"]["id"]
        )
        self.assert_rejected(lines)

    def test_wrong_concurrent_reduction_is_rejected(self) -> None:
        lines = self.fixture.transcript_lines.copy()
        lines[17] = replace_field(
            lines[17], "current_id", self.fixture.states["left"]["id"]
        )
        self.assert_rejected(lines)

    def test_selector_leak_is_rejected(self) -> None:
        lines = self.fixture.transcript_lines.copy()
        lines[25] = replace_field(lines[25], "receiver_retained", "true")
        self.assert_rejected(lines)

    def test_retry_token_reuse_is_rejected(self) -> None:
        lines = self.fixture.transcript_lines.copy()
        lines[35] = replace_field(
            lines[35], "token_sha256", self.fixture.tokens["attempt_one"]
        )
        self.assert_rejected(lines)

    def test_acknowledging_with_wrong_attempt_token_is_rejected(self) -> None:
        lines = self.fixture.transcript_lines.copy()
        lines[36] = replace_field(
            lines[36], "token_sha256", self.fixture.tokens["attempt_two"]
        )
        self.assert_rejected(lines)

    def test_missing_token_persistence_is_rejected(self) -> None:
        lines = self.fixture.transcript_lines.copy()
        lines[32] = replace_field(lines[32], "token_persisted", "false")
        self.assert_rejected(lines)

    def test_non_sigkill_termination_is_rejected(self) -> None:
        lines = self.fixture.transcript_lines.copy()
        lines[32] = replace_field(lines[32], "termination_signal", "sigterm")
        self.assert_rejected(lines)

    def test_missing_wrong_subscription_rejection_is_rejected(self) -> None:
        lines = self.fixture.transcript_lines.copy()
        lines[69] = replace_field(
            lines[69], "wrong_subscription_token_rejected", "false"
        )
        self.assert_rejected(lines)

    def test_transfer_accounting_mismatch_is_rejected(self) -> None:
        lines = self.fixture.transcript_lines.copy()
        lines[27] = replace_field(lines[27], "data_inserted", "2")
        self.assert_rejected(lines)

    def test_store_subscription_cursor_mismatch_is_rejected(self) -> None:
        lines = self.fixture.transcript_lines.copy()
        lines[66] = replace_field(lines[66], "delivery_cursors", "2")
        self.assert_rejected(lines)


class TerminalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()
        self.facts = CHECKER.validate_transcript(self.fixture.transcript)

    def validate_lines(self, runtime: list[str]) -> dict:
        stdout = ("\n".join(runtime + self.fixture.transcript_lines) + "\n").encode(
            "ascii"
        )
        return CHECKER.validate_terminal_stdout(
            stdout, self.fixture.transcript, self.fixture.root, self.facts
        )

    def test_exact_terminal_is_accepted(self) -> None:
        facts = CHECKER.validate_terminal_stdout(
            self.fixture.stdout,
            self.fixture.transcript,
            self.fixture.root,
            self.facts,
        )
        self.assertEqual(facts["ready_records"], 10)
        self.assertEqual(facts["stop_records"], 9)
        self.assertEqual(facts["child_coordination_records"], 2)
        self.assertEqual(facts["reconciliation"]["state_transfer"]["inserted"], 5)

    def test_forced_lifetime_stop_is_rejected(self) -> None:
        runtime = self.fixture.stdout_lines.copy()
        runtime.insert(12, self.fixture.stop("peerless_redelivery_ack", "receiver"))
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate_lines(runtime)

    def test_child_token_cross_binding_mismatch_is_rejected(self) -> None:
        runtime = self.fixture.stdout_lines.copy()
        runtime[11] = runtime[11].replace(
            self.fixture.tokens["attempt_one"], self.fixture.tokens["attempt_two"]
        )
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate_lines(runtime)

    def test_child_malformed_token_rejection_claim_is_enforced(self) -> None:
        runtime = self.fixture.stdout_lines.copy()
        runtime[14] = runtime[14].replace(
            "malformed_token_rejected=true", "malformed_token_rejected=false"
        )
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate_lines(runtime)

    def test_child_retired_token_cross_binding_is_enforced(self) -> None:
        runtime = self.fixture.stdout_lines.copy()
        runtime[14] = runtime[14].replace(
            f"retired_token_sha256={self.fixture.tokens['initial']}",
            f"retired_token_sha256={self.fixture.tokens['attempt_one']}",
        )
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate_lines(runtime)

    def test_contact_transfer_mismatch_is_rejected(self) -> None:
        runtime = self.fixture.stdout_lines.copy()
        runtime[6] = runtime[6].replace("inserted=1", "inserted=2")
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate_lines(runtime)

    def test_unprotected_contact_counters_are_rejected(self) -> None:
        runtime = self.fixture.stdout_lines.copy()
        runtime[6] = runtime[6].replace("protected_frames=1", "protected_frames=0")
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate_lines(runtime)

    def test_terminal_after_transcript_is_rejected(self) -> None:
        stdout = self.fixture.stdout + b"STOP forbidden\n"
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.validate_terminal_stdout(
                stdout, self.fixture.transcript, self.fixture.root, self.facts
            )


class RawRootTests(unittest.TestCase):
    def test_exact_raw_root_projects_one_sanitized_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw = RawRootFixture(Path(temporary))
            evidence = CHECKER.validate_raw_root(raw.root, raw.authority)
            receipt = CHECKER.build_receipt(raw.authority, evidence)
            encoded = CHECKER.render_receipt(
                receipt,
                forbidden_values=CHECKER.receipt_forbidden_values(
                    evidence, raw.root
                ),
                forbidden_pids=CHECKER.SUPPORT.receipt_forbidden_pids(evidence),
                forbidden_ports=CHECKER.SUPPORT.receipt_forbidden_ports(evidence),
            )
            self.assertLessEqual(len(encoded), CHECKER.RECEIPT_MAX_BYTES)
            for participant in raw.fixture.participants.values():
                for identifier_value in participant.values():
                    self.assertNotIn(identifier_value.encode("ascii"), encoded)

    def test_event_publication_diagnostics_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw = RawRootFixture(Path(temporary))
            raw.write("stderr.log", b"event_publication_group group_sequence=1\n", 0o600)
            with self.assertRaisesRegex(CHECKER.ReceiptViolation, "unclassified|classification"):
                CHECKER.validate_raw_root(raw.root, raw.authority)

    def test_extra_raw_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw = RawRootFixture(Path(temporary))
            raw.write("unexpected", b"x", 0o600)
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.validate_raw_root(raw.root, raw.authority)

    def test_secret_artifact_is_never_hashed_into_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw = RawRootFixture(Path(temporary))
            secret = (
                raw.root / "participants" / "receiver" / "state" / "identity.key"
            ).read_bytes()
            evidence = CHECKER.validate_raw_root(raw.root, raw.authority)
            encoded = CHECKER.render_receipt(
                CHECKER.build_receipt(raw.authority, evidence),
                forbidden_values=CHECKER.receipt_forbidden_values(evidence, raw.root),
            )
            self.assertNotIn(hashlib.sha256(secret).hexdigest().encode("ascii"), encoded)


class ArtifactTests(unittest.TestCase):
    def test_runner_extracts_only_exact_state_records(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            stdout = Path(temporary) / "stdout.log"
            stdout.write_bytes(fixture.stdout)
            self.assertEqual(RUNNER.extract_transcript(stdout), fixture.transcript)

    def test_runner_rejects_missing_record(self) -> None:
        fixture = Fixture()
        damaged = ("\n".join(fixture.stdout_lines + fixture.transcript_lines[:-1]) + "\n").encode(
            "ascii"
        )
        with tempfile.TemporaryDirectory() as temporary:
            stdout = Path(temporary) / "stdout.log"
            stdout.write_bytes(damaged)
            with self.assertRaises(RUNNER.RunnerFailure):
                RUNNER.extract_transcript(stdout)

    def test_all_admitted_paths_exist(self) -> None:
        missing = [
            relative
            for relative in CHECKER.ADMITTED_SOURCE_PATHS
            if not Path(relative).is_file()
        ]
        self.assertEqual(missing, [])

    def test_receipt_renderer_rejects_sensitive_digest(self) -> None:
        sensitive = identifier(61)
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.render_receipt(
                {"schema": CHECKER.SCHEMA, "value": sensitive},
                forbidden_values=[sensitive],
            )

    def test_canonical_receipt_is_deterministic(self) -> None:
        document = {"schema": CHECKER.SCHEMA, "status": "pass"}
        first = CHECKER.render_receipt(document)
        second = CHECKER.render_receipt({"status": "pass", "schema": CHECKER.SCHEMA})
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
