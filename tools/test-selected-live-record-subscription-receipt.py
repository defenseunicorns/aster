#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for the retained live Record-subscription receipt."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock


SCHEMA = "aster-selected-live-record-subscription-receipt/v1"
RAW_SCHEMA = "aster-selected-live-record-subscription-raw/v1"
TRANSCRIPT_SCHEMA = "aster-selected-live-record-subscription-transcript/v1"
CLAIM = (
    "selected-live-record-subscription-one-host-direct-iroh-whole-conflict-"
    "forced-receiver-process-termination-durable-redelivery-fresh-query-"
    "resolution-successor-acceptance"
)
BINARY = "aster-live-record-subscription-acceptance"
TRANSCRIPT_RECORDS = 53
TOKEN_BYTES = 89
ALPHA_TOPIC = "opaque"
BETA_TOPIC = "opaque.beta"
ROOT_SCOPE = "test/runtime-contact"
GAMMA_SCOPE = f"{ROOT_SCOPE}/withheld"
PAYLOADS = {
    "edit": b"disconnected Record edit",
    "tombstone": b"",
    "beta": b"network-interested application-unsubscribed Record",
    "gamma": b"application-matched network-uninterested Record",
    "resolution": b"guarded Record resolution",
}
PAYLOAD_HASHES = {key: hashlib.sha256(value).hexdigest() for key, value in PAYLOADS.items()}
KEY_HASHES = {
    "alpha": hashlib.sha256(b"acceptance/record/alpha-key").hexdigest(),
    "beta": hashlib.sha256(b"acceptance/record/beta-key").hexdigest(),
    "gamma": hashlib.sha256(b"acceptance/record/gamma-key").hexdigest(),
}
ALPHA_PROJECTION_KEY_HASH = hashlib.sha256(
    b"opaque\0test/runtime-contact\0acceptance/record/alpha-key"
).hexdigest()


def words(value: str) -> tuple[str, ...]:
    return tuple(value.split())


KEYS = {
    "RUN": words(
        """schema claim participants processes actor_lifetimes
        maximum_concurrent_processes maximum_concurrent_actors phases alpha_topic
        beta_topic root_scope gamma_scope application_descendants
        network_alpha_descendants network_beta_descendants"""
    ),
    "PARTICIPANT": words(
        "participant carrier_id mission_id mission_authority provisioning"
    ),
    "PEER_BINDING": words(
        "participant expected_carrier_peer expected_mission_peer"
    ),
    "PHASE": words("phase name actors outcome"),
    "SUBSCRIPTION": words(
        "phase participant id inserted topic scope include_descendant_scopes"
    ),
    "PUBLICATION": words(
        """phase participant label id publisher counter priority payload_sha256
        tombstone inserted"""
    ),
    "DELIVERY": words(
        """phase participant label subscription_id projection_id topic scope
        logical_key_sha256 current_id current_payload_sha256 current_tombstone
        current_disposition concurrent_ids conflict_siblings attempt token_sha256
        delivery_limit scan_limit has_more superseded_exposed
        resolution_guard_exposed acknowledged"""
    ),
    "PROJECTION": words(
        """phase participant label topic scope logical_key_sha256 current_id
        current_payload_sha256 current_tombstone current_disposition concurrent_ids
        superseded_ids conflict_siblings guard_siblings"""
    ),
    "SELECTOR": words(
        """phase label topic scope record_id network_interested application_matched
        receiver_retained delivered"""
    ),
    "RECEIPT": words(
        """phase participant contacts contact_errors direct_contacts relay_contacts
        unknown_path_contacts data_offered data_fetched data_inserted data_duplicates
        data_remaining mutable_remaining deferred_mutable_lanes items events blobs"""
    ),
    "CHILD_DELIVERY": words(
        """phase participant projection_id projection_key_sha256 siblings current_id
        concurrent_id attempt token_sha256 previous_token_sha256 delivery_limit
        scan_limit has_more superseded_exposed resolution_guard_exposed acknowledged"""
    ),
    "PROCESS_TERMINATION": words(
        """phase participant mechanism termination_signal distinct_process
        after_flushed_poll graceful stop_record_expected stop_record_observed
        acknowledged token_persisted token_artifact_mode token_artifact_fsynced"""
    ),
    "TOKEN_CHECKS": words(
        """phase token_bytes attempt_tokens_distinct attempt_one_restored
        malformed_token_rejected wrong_subscription_token_rejected
        wrong_projection_token_rejected retired_singleton_token_rejected
        token_artifacts_removed"""
    ),
    "ACKNOWLEDGEMENT": words(
        """phase participant projection projection_id ack reack ack_token_attempt
        reack_token_attempt old_projection_reack"""
    ),
    "EMPTY_POLL": words("phase participant label deliveries has_more"),
    "RESOLUTION": words(
        """phase participant id publisher counter priority payload_sha256 tombstone
        inserted retry_inserted retry_same guard_fresh_query guard_siblings"""
    ),
    "INSPECTION": words(
        """participant record_rows record_acceptance_markers record_operations
        subscriptions pending_deliveries acknowledged_deliveries delivery_cursors
        selector_generation other_namespaces_empty"""
    ),
    "BIND": words("participant reacquired"),
    "RESULT": words(
        """status records phases participants processes actor_lifetimes
        maximum_concurrent_processes maximum_concurrent_actors graceful_shutdowns
        forced_process_terminations record_publications network_record_insertions
        polls deliveries acknowledgements reacknowledgements subscription_insertions
        subscription_replays token_binding_checks empty_polls bind_reacquisitions
        query_only_superseded payload_representation token_representation
        opaque_tokens_emitted secret_values_emitted physical_network_claimed
        automatic_merge_claimed global_convergence_claimed long_retention_claimed"""
    ),
}

KINDS = words(
    """RUN PARTICIPANT PARTICIPANT PEER_BINDING PEER_BINDING PHASE SUBSCRIPTION
    SUBSCRIPTION PUBLICATION PUBLICATION DELIVERY PROJECTION PROJECTION RECEIPT
    RECEIPT PHASE SUBSCRIPTION PROJECTION PROJECTION PUBLICATION PUBLICATION
    SELECTOR SELECTOR RECEIPT RECEIPT PHASE SUBSCRIPTION CHILD_DELIVERY
    PROCESS_TERMINATION PHASE SUBSCRIPTION CHILD_DELIVERY TOKEN_CHECKS
    ACKNOWLEDGEMENT EMPTY_POLL RESOLUTION DELIVERY ACKNOWLEDGEMENT EMPTY_POLL
    PROJECTION RECEIPT PHASE SUBSCRIPTION PROJECTION SELECTOR SELECTOR EMPTY_POLL
    RECEIPT INSPECTION INSPECTION BIND BIND RESULT"""
)
EXPECTED_SEQUENCE = tuple((kind, KEYS[kind]) for kind in KINDS)
PHASES = (
    (1, "peerless_origins", "publisher+receiver", "unacknowledged-singleton"),
    (
        2,
        "direct_conflict_and_selectors",
        "publisher+receiver",
        "whole-conflict-and-withholding",
    ),
    (3, "forced_conflict_delivery", "receiver-child", "force-terminated"),
    (
        4,
        "peerless_redelivery_resolution",
        "receiver-child",
        "acknowledged-and-resolved",
    ),
    (5, "final_peerless_reopen", "receiver", "durable-resolved-empty"),
)
ORACLE_LIMITATIONS = (
    "operator-attested-source-binary-execution-link-not-cryptographically-proven",
    "selected-admitted-source-list-is-not-a-complete-reproducible-build-closure",
    "one-host-direct-loopback-same-implementation-observation",
    "participant-secret-artifacts-validated-by-metadata-only",
    "record-causal-observation-and-publication-order-are-producer-attested",
    "network-interest-and-application-subscription-are-separate-static-surfaces",
    "forced-sigkill-is-not-power-loss-or-filesystem-crash-recovery",
    "restart-observes-one-immediate-peerless-reopen-not-long-retention-compaction-or-garbage-collection",
)
ORACLE_NONCLAIMS = (
    "hidden-policy-lineage-disclosure-or-authorization-from-opaque-conflict-sibling-identifiers",
    "distinct-physical-hosts",
    "nat-or-internet-path",
    "controlled-or-public-relay",
    "btle-carrier",
    "mixed-implementation-or-mixed-carrier-interoperability",
    "scale-beyond-two-participants",
    "resource-thresholds-or-long-duration-soak",
    "event-state-or-blob-live-application-acceptance",
    "finite-ttl-retention-expiry-compaction-or-garbage-collection",
    "automatic-registered-policy-conflict-merge-or-resolution",
    "reproducible-build-or-cryptographic-source-to-execution-provenance",
    "release-acceptance-production-authorization-or-operational-readiness",
)
ATTEMPT_ONE_KEYS = words(
    """participant identity subscription_id subscription_inserted projection_id
    projection_topic projection_scope projection_key_sha256 edit_id tombstone_id
    current_id concurrent_id siblings attempt token_sha256 delivery_limit scan_limit
    has_more superseded_exposed resolution_guard_exposed token_persisted
    singleton_projection_changed beta_id beta_present gamma_empty acknowledged"""
)
ATTEMPT_TWO_KEYS = words(
    """participant identity subscription_id subscription_inserted projection_id
    projection_topic projection_scope projection_key_sha256 edit_id tombstone_id
    current_id concurrent_id siblings attempt token_sha256 delivery_limit scan_limit
    has_more superseded_exposed resolution_guard_exposed previous_token_sha256
    tokens_distinct previous_token_restored malformed_token_rejected
    wrong_subscription_token_rejected wrong_projection_token_rejected
    retired_singleton_token_rejected retired_singleton_token_sha256 ack_token_attempt
    reack_token_attempt conflict_ack conflict_reack post_conflict_empty
    guard_fresh_query guard_siblings resolution_id resolution_publisher
    resolution_counter resolution_inserted resolution_retry_inserted
    resolution_retry_same successor_projection_id successor_attempt
    successor_token_sha256 successor_ack successor_reack old_conflict_reack
    post_successor_empty superseded_ids beta_id beta_present gamma_empty
    token_artifacts_removed closed_kind closed_operation shutdown_contacts
    shutdown_contact_errors shutdown_direct_contacts shutdown_relay_contacts
    shutdown_unknown_path_contacts shutdown_items shutdown_events shutdown_blobs
    shutdown_data_offered shutdown_data_fetched shutdown_data_inserted
    shutdown_data_duplicates shutdown_data_remaining shutdown_mutable_remaining
    shutdown_deferred_mutable_lanes"""
)

ADMITTED_PATHS = tuple(
    sorted(
        words(
            """Cargo.lock Cargo.toml mise.toml
            crates/aster-core/Cargo.toml crates/aster-core/src/causal.rs
            crates/aster-core/src/crypto/reference.rs crates/aster-core/src/lib.rs
            crates/aster-core/src/provisioning.rs crates/aster-core/src/source_event.rs
            crates/aster-core/src/source_record.rs crates/aster-iroh/Cargo.toml
            crates/aster-iroh/src/lib.rs crates/aster-node/Cargo.toml
            crates/aster-node/examples/live_record_subscription_acceptance.rs
            crates/aster-node/src/application.rs
            crates/aster-node/src/application/record.rs crates/aster-node/src/frame.rs
            crates/aster-node/src/identity.rs crates/aster-node/src/lib.rs
            crates/aster-node/src/mission.rs crates/aster-node/src/runtime.rs
            crates/aster-redb-store/Cargo.toml crates/aster-redb-store/src/lib.rs
            crates/aster-redb-store/src/record_subscription.rs
            tools/check-selected-live-event-receipt.py
            tools/check-selected-live-record-subscription-receipt.py
            tools/run-selected-live-event.py
            tools/run-selected-live-record-subscription.py
            tools/test-selected-live-record-subscription-receipt.py"""
        )
    )
)


def read_source(path: Path) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or not 0 < before.st_size <= 4 * 1024 * 1024
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
        data = b""
        while len(data) < opened.st_size:
            chunk = os.read(descriptor, min(64 * 1024, opened.st_size - len(data)))
            if not chunk:
                raise RuntimeError(f"test subject truncated while reading {path}")
            data += chunk
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
        return data
    finally:
        os.close(descriptor)


def load(filename: str, name: str) -> types.ModuleType:
    path = Path(__file__).with_name(filename)
    module = types.ModuleType(name)
    module.__file__ = os.fspath(path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(
            compile(read_source(path), os.fspath(path), "exec", dont_inherit=True, optimize=0),
            module.__dict__,
        )
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


CHECKER = load(
    "check-selected-live-record-subscription-receipt.py",
    "selected_live_record_subscription_checker_under_test",
)
RUNNER = load(
    "run-selected-live-record-subscription.py",
    "selected_live_record_subscription_runner_under_test",
)


def identifier(number: int) -> str:
    return f"{number:064x}"


def token_digest(number: int) -> str:
    return hashlib.sha256(bytes([number]) * TOKEN_BYTES).hexdigest()


def line(kind: str, **values: object) -> str:
    string_values = {key: str(value).lower() if isinstance(value, bool) else str(value) for key, value in values.items()}
    if set(string_values) != set(KEYS[kind]):
        raise AssertionError(f"{kind} fixture fields differ: {set(string_values) ^ set(KEYS[kind])}")
    return "\t".join(
        [
            "LIVE_RECORD_SUBSCRIPTION",
            kind.lower(),
            *(f"{key}={string_values[key]}" for key in KEYS[kind]),
        ]
    )


def terminal(prefix: str, keys: tuple[str, ...], values: dict[str, str]) -> str:
    if set(values) != set(keys):
        raise AssertionError(f"{prefix} fixture fields differ: {set(values) ^ set(keys)}")
    return " ".join([prefix, *(f"{key}={values[key]}" for key in keys)])


def record_fields(value: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in value.split("\t")[2:])


def replace_field(value: str, key: str, replacement: str) -> str:
    parts = value.split("\t")
    for index, token in enumerate(parts[2:], 2):
        if token.startswith(f"{key}="):
            parts[index] = f"{key}={replacement}"
            return "\t".join(parts)
    raise AssertionError(f"fixture field {key} absent")


class Fixture:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or Path("/tmp/aster-record-subscription-synthetic")
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
        self.items = {
            "edit": self.item(11, "publisher", 1, "edit", False),
            "tombstone": self.item(12, "receiver", 1, "tombstone", True),
            "beta": self.item(13, "publisher", 2, "beta", False),
            "gamma": self.item(14, "publisher", 3, "gamma", False),
            "resolution": self.item(15, "receiver", 2, "resolution", False),
        }
        self.conflict_current = max(
            ("edit", "tombstone"), key=lambda name: self.items[name]["id"]
        )
        self.conflict_concurrent = min(
            ("edit", "tombstone"), key=lambda name: self.items[name]["id"]
        )
        self.projections = {
            "singleton": identifier(21),
            "conflict": identifier(22),
            "successor": identifier(23),
        }
        self.tokens = {
            "singleton": token_digest(31),
            "attempt_one": token_digest(32),
            "attempt_two": token_digest(33),
            "successor": token_digest(34),
        }
        self.siblings = ",".join(
            sorted((self.items["edit"]["id"], self.items["tombstone"]["id"]))
        )
        self.receipts = {
            ("peerless_origins", "publisher"): self.receipt_values(),
            ("peerless_origins", "receiver"): self.receipt_values(),
            (
                "direct_conflict_and_selectors",
                "publisher",
            ): self.receipt_values(contacts=1, offered=2, fetched=1, inserted=1),
            (
                "direct_conflict_and_selectors",
                "receiver",
            ): self.receipt_values(contacts=1, offered=1, fetched=2, inserted=2),
            ("peerless_redelivery_resolution", "receiver"): self.receipt_values(),
            ("final_peerless_reopen", "receiver"): self.receipt_values(),
        }
        self.transcript_lines = self.build_transcript()
        self.transcript = ("\n".join(self.transcript_lines) + "\n").encode("ascii")
        self.stdout_lines = self.build_stdout()
        self.stdout = (
            "\n".join(self.stdout_lines + self.transcript_lines) + "\n"
        ).encode("ascii")

    def item(
        self, number: int, participant: str, counter: int, payload: str, tombstone: bool
    ) -> dict[str, str]:
        return {
            "id": identifier(number),
            "publisher": self.participants[participant]["mission_id"],
            "counter": str(counter),
            "payload": PAYLOAD_HASHES[payload],
            "tombstone": str(tombstone).lower(),
        }

    @staticmethod
    def receipt_values(
        *, contacts: int = 0, offered: int = 0, fetched: int = 0, inserted: int = 0
    ) -> dict[str, str]:
        return {
            "contacts": str(contacts),
            "contact_errors": "0",
            "direct_contacts": str(contacts),
            "relay_contacts": "0",
            "unknown_path_contacts": "0",
            "data_offered": str(offered),
            "data_fetched": str(fetched),
            "data_inserted": str(inserted),
            "data_duplicates": "0",
            "data_remaining": "0",
            "mutable_remaining": "0",
            "deferred_mutable_lanes": "0",
            "items": "0",
            "events": "0",
            "blobs": "0",
        }

    def participant(self, name: str) -> str:
        return line(
            "PARTICIPANT",
            participant=name,
            **self.participants[name],
            provisioning="independent-node-bundle",
        )

    def binding(self, name: str, remote: str) -> str:
        return line(
            "PEER_BINDING",
            participant=name,
            expected_carrier_peer=self.participants[remote]["carrier_id"],
            expected_mission_peer=self.participants[remote]["mission_id"],
        )

    def phase(self, ordinal: int) -> str:
        number, name, actors, outcome = PHASES[ordinal - 1]
        return line("PHASE", phase=number, name=name, actors=actors, outcome=outcome)

    def subscription_line(self, phase: str, inserted: bool) -> str:
        return line(
            "SUBSCRIPTION",
            phase=phase,
            participant="receiver",
            id=self.subscription,
            inserted=inserted,
            topic=ALPHA_TOPIC,
            scope=ROOT_SCOPE,
            include_descendant_scopes=True,
        )

    def publication(self, name: str, phase: str, participant: str, label: str) -> str:
        item = self.items[name]
        return line(
            "PUBLICATION",
            phase=phase,
            participant=participant,
            label=label,
            id=item["id"],
            publisher=item["publisher"],
            counter=item["counter"],
            priority="priority",
            payload_sha256=item["payload"],
            tombstone=item["tombstone"],
            inserted=True,
        )

    def delivery(
        self,
        phase: str,
        label: str,
        projection: str,
        current: str,
        attempt: int,
        token: str,
        acknowledged: bool,
        concurrent: str = "none",
        siblings: str = "none",
    ) -> str:
        item = self.items[current]
        return line(
            "DELIVERY",
            phase=phase,
            participant="receiver",
            label=label,
            subscription_id=self.subscription,
            projection_id=self.projections[projection],
            topic=ALPHA_TOPIC,
            scope=ROOT_SCOPE,
            logical_key_sha256=KEY_HASHES["alpha"],
            current_id=item["id"],
            current_payload_sha256=item["payload"],
            current_tombstone=item["tombstone"],
            current_disposition="current",
            concurrent_ids=concurrent,
            conflict_siblings=siblings,
            attempt=attempt,
            token_sha256=self.tokens[token],
            delivery_limit=1,
            scan_limit=16,
            has_more=False,
            superseded_exposed=False,
            resolution_guard_exposed=False,
            acknowledged=acknowledged,
        )

    def projection(
        self,
        phase: str,
        participant: str,
        label: str,
        current: str,
        concurrent: str = "none",
        superseded: str = "none",
        conflict: str = "none",
    ) -> str:
        item = self.items[current]
        return line(
            "PROJECTION",
            phase=phase,
            participant=participant,
            label=label,
            topic=ALPHA_TOPIC,
            scope=ROOT_SCOPE,
            logical_key_sha256=KEY_HASHES["alpha"],
            current_id=item["id"],
            current_payload_sha256=item["payload"],
            current_tombstone=item["tombstone"],
            current_disposition="current",
            concurrent_ids=concurrent,
            superseded_ids=superseded,
            conflict_siblings=conflict,
            guard_siblings=conflict,
        )

    def selector(self, phase: str, name: str) -> str:
        beta = name == "beta"
        return line(
            "SELECTOR",
            phase=phase,
            label=name,
            topic=BETA_TOPIC if beta else ALPHA_TOPIC,
            scope=ROOT_SCOPE if beta else GAMMA_SCOPE,
            record_id=self.items[name]["id"],
            network_interested=beta,
            application_matched=not beta,
            receiver_retained=beta,
            delivered=False,
        )

    def receipt(self, phase: str, participant: str) -> str:
        return line(
            "RECEIPT",
            phase=phase,
            participant=participant,
            **self.receipts[(phase, participant)],
        )

    def child_delivery(self, attempt: int) -> str:
        first = attempt == 1
        return line(
            "CHILD_DELIVERY",
            phase="forced_conflict_delivery"
            if first
            else "peerless_redelivery_resolution",
            participant="receiver",
            projection_id=self.projections["conflict"],
            projection_key_sha256=ALPHA_PROJECTION_KEY_HASH,
            siblings=self.siblings,
            current_id=self.items[self.conflict_current]["id"],
            concurrent_id=self.items[self.conflict_concurrent]["id"],
            attempt=attempt,
            token_sha256=self.tokens["attempt_one" if first else "attempt_two"],
            previous_token_sha256="none" if first else self.tokens["attempt_one"],
            delivery_limit=1,
            scan_limit=16,
            has_more=False,
            superseded_exposed=False,
            resolution_guard_exposed=False,
            acknowledged=not first,
        )

    def ack(self, projection: str) -> str:
        conflict = projection == "conflict"
        return line(
            "ACKNOWLEDGEMENT",
            phase="peerless_redelivery_resolution",
            participant="receiver",
            projection=projection,
            projection_id=self.projections[projection],
            ack="acknowledged",
            reack="already_acknowledged",
            ack_token_attempt=1,
            reack_token_attempt=2 if conflict else 1,
            old_projection_reack="not-applicable"
            if conflict
            else "already_acknowledged",
        )

    @staticmethod
    def empty(phase: str, label: str) -> str:
        return line(
            "EMPTY_POLL",
            phase=phase,
            participant="receiver",
            label=label,
            deliveries=0,
            has_more=False,
        )

    def build_transcript(self) -> list[str]:
        p2 = "direct_conflict_and_selectors"
        p4 = "peerless_redelivery_resolution"
        records = [
            line(
                "RUN",
                schema=TRANSCRIPT_SCHEMA,
                claim=CLAIM,
                participants=2,
                processes=3,
                actor_lifetimes=7,
                maximum_concurrent_processes=2,
                maximum_concurrent_actors=2,
                phases=5,
                alpha_topic=ALPHA_TOPIC,
                beta_topic=BETA_TOPIC,
                root_scope=ROOT_SCOPE,
                gamma_scope=GAMMA_SCOPE,
                application_descendants=True,
                network_alpha_descendants=False,
                network_beta_descendants=False,
            ),
            self.participant("publisher"),
            self.participant("receiver"),
            self.binding("publisher", "receiver"),
            self.binding("receiver", "publisher"),
            self.phase(1),
            self.subscription_line("peerless_origins", True),
            self.subscription_line("peerless_origins", False),
            self.publication("edit", "peerless_origins", "publisher", "alpha-edit"),
            self.publication(
                "tombstone", "peerless_origins", "receiver", "alpha-tombstone"
            ),
            self.delivery(
                "peerless_origins",
                "alpha-singleton",
                "singleton",
                "tombstone",
                1,
                "singleton",
                False,
            ),
            self.projection(
                "peerless_origins", "publisher", "alpha-edit", "edit"
            ),
            self.projection(
                "peerless_origins", "receiver", "alpha-tombstone", "tombstone"
            ),
            self.receipt("peerless_origins", "publisher"),
            self.receipt("peerless_origins", "receiver"),
            self.phase(2),
            self.subscription_line(p2, False),
            self.projection(
                p2,
                "publisher",
                "alpha-conflict",
                self.conflict_current,
                self.items[self.conflict_concurrent]["id"],
                conflict=self.siblings,
            ),
            self.projection(
                p2,
                "receiver",
                "alpha-conflict",
                self.conflict_current,
                self.items[self.conflict_concurrent]["id"],
                conflict=self.siblings,
            ),
            self.publication("beta", p2, "publisher", "beta"),
            self.publication("gamma", p2, "publisher", "gamma"),
            self.selector(p2, "beta"),
            self.selector(p2, "gamma"),
            self.receipt(p2, "publisher"),
            self.receipt(p2, "receiver"),
            self.phase(3),
            self.subscription_line("forced_conflict_delivery", False),
            self.child_delivery(1),
            line(
                "PROCESS_TERMINATION",
                phase="forced_conflict_delivery",
                participant="receiver",
                mechanism="parent-child-kill",
                termination_signal="sigkill",
                distinct_process=True,
                after_flushed_poll=True,
                graceful=False,
                stop_record_expected=False,
                stop_record_observed=False,
                acknowledged=False,
                token_persisted=True,
                token_artifact_mode="0600",
                token_artifact_fsynced=True,
            ),
            self.phase(4),
            self.subscription_line(p4, False),
            self.child_delivery(2),
            line(
                "TOKEN_CHECKS",
                phase=p4,
                token_bytes=TOKEN_BYTES,
                attempt_tokens_distinct=True,
                attempt_one_restored=True,
                malformed_token_rejected=True,
                wrong_subscription_token_rejected=True,
                wrong_projection_token_rejected=True,
                retired_singleton_token_rejected=True,
                token_artifacts_removed=True,
            ),
            self.ack("conflict"),
            self.empty(p4, "post-conflict-ack"),
            line(
                "RESOLUTION",
                phase=p4,
                participant="receiver",
                id=self.items["resolution"]["id"],
                publisher=self.items["resolution"]["publisher"],
                counter=2,
                priority="immediate",
                payload_sha256=PAYLOAD_HASHES["resolution"],
                tombstone=False,
                inserted=True,
                retry_inserted=False,
                retry_same=True,
                guard_fresh_query=True,
                guard_siblings=self.siblings,
            ),
            self.delivery(
                p4,
                "resolved-successor",
                "successor",
                "resolution",
                1,
                "successor",
                True,
            ),
            self.ack("successor"),
            self.empty(p4, "post-successor-ack"),
            self.projection(
                p4,
                "receiver",
                "alpha-resolved-query",
                "resolution",
                superseded=self.siblings,
            ),
            self.receipt(p4, "receiver"),
            self.phase(5),
            self.subscription_line("final_peerless_reopen", False),
            self.projection(
                "final_peerless_reopen",
                "receiver",
                "alpha-resolved",
                "resolution",
                superseded=self.siblings,
            ),
            self.selector("final_peerless_reopen", "beta"),
            self.selector("final_peerless_reopen", "gamma"),
            self.empty("final_peerless_reopen", "durable-empty"),
            self.receipt("final_peerless_reopen", "receiver"),
            line(
                "INSPECTION",
                participant="publisher",
                record_rows=4,
                record_acceptance_markers=4,
                record_operations=3,
                subscriptions=0,
                pending_deliveries=0,
                acknowledged_deliveries=0,
                delivery_cursors=0,
                selector_generation=0,
                other_namespaces_empty=True,
            ),
            line(
                "INSPECTION",
                participant="receiver",
                record_rows=4,
                record_acceptance_markers=4,
                record_operations=2,
                subscriptions=1,
                pending_deliveries=0,
                acknowledged_deliveries=1,
                delivery_cursors=1,
                selector_generation=1,
                other_namespaces_empty=True,
            ),
            line("BIND", participant="publisher", reacquired=True),
            line("BIND", participant="receiver", reacquired=True),
            line(
                "RESULT",
                status="pass",
                records=53,
                phases=5,
                participants=2,
                processes=3,
                actor_lifetimes=7,
                maximum_concurrent_processes=2,
                maximum_concurrent_actors=2,
                graceful_shutdowns=6,
                forced_process_terminations=1,
                record_publications=5,
                network_record_insertions=3,
                polls=7,
                deliveries=4,
                acknowledgements=2,
                reacknowledgements=3,
                subscription_insertions=1,
                subscription_replays=5,
                token_binding_checks=4,
                empty_polls=3,
                bind_reacquisitions=2,
                query_only_superseded=2,
                payload_representation="sha256-only",
                token_representation="sha256-only",
                opaque_tokens_emitted=False,
                secret_values_emitted=False,
                physical_network_claimed=False,
                automatic_merge_claimed=False,
                global_convergence_claimed=False,
                long_retention_claimed=False,
            ),
        ]
        if len(records) != TRANSCRIPT_RECORDS:
            raise AssertionError(f"fixture emitted {len(records)} records")
        if tuple(value.split("\t", 2)[1].upper() for value in records) != KINDS:
            raise AssertionError("fixture record order differs")
        return records

    def find(self, kind: str, **matches: str) -> int:
        for index, value in enumerate(self.transcript_lines):
            if value.split("\t", 2)[1] == kind.lower():
                observed = record_fields(value)
                if all(observed.get(key) == expected for key, expected in matches.items()):
                    return index
        raise AssertionError(f"fixture record absent: {kind} {matches}")

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
        self, participant: str, *, offered: int, fetched: int, inserted: int
    ) -> str:
        remote = "receiver" if participant == "publisher" else "publisher"
        values = {key: "0" for key in CHECKER.SUPPORT.CONTACT_KEYS}
        values.update(
            {
                "direction": "out" if participant == "publisher" else "in",
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
        receipt = self.receipts[(phase, participant)]
        values = {key: "0" for key in CHECKER.SUPPORT.STOP_KEYS}
        values.update(
            {
                "lifecycle": "complete",
                "sync_status": "contacts_observed"
                if receipt["contacts"] != "0"
                else "no_successful_contact",
                "carrier_id": self.participants[participant]["carrier_id"],
                "mission_id": self.participants[participant]["mission_id"],
                "contacts": receipt["contacts"],
                "direct_contacts": receipt["direct_contacts"],
                "path_observation": "not-authorization",
                "mission_auth": "hybrid-pq",
                "provisioning": "unprotected-reference",
                "semantics": "source-authenticated-event",
                "reconciliation_classes": "event,state,record,blob-v5",
                "controls_semantics": "source-authenticated-flash",
            }
        )
        return terminal("STOP", CHECKER.SUPPORT.STOP_KEYS, values)

    def child(self, attempt: int) -> str:
        first = attempt == 1
        keys = ATTEMPT_ONE_KEYS if first else ATTEMPT_TWO_KEYS
        values = {
            "participant": "receiver",
            "identity": self.participants["receiver"]["mission_id"],
            "subscription_id": self.subscription,
            "subscription_inserted": "false",
            "projection_id": self.projections["conflict"],
            "projection_topic": ALPHA_TOPIC,
            "projection_scope": ROOT_SCOPE,
            "projection_key_sha256": ALPHA_PROJECTION_KEY_HASH,
            "edit_id": self.items["edit"]["id"],
            "tombstone_id": self.items["tombstone"]["id"],
            "current_id": self.items[self.conflict_current]["id"],
            "concurrent_id": self.items[self.conflict_concurrent]["id"],
            "siblings": self.siblings,
            "attempt": str(attempt),
            "token_sha256": self.tokens["attempt_one" if first else "attempt_two"],
            "delivery_limit": "1",
            "scan_limit": "16",
            "has_more": "false",
            "superseded_exposed": "false",
            "resolution_guard_exposed": "false",
        }
        if first:
            values.update(
                {
                    "token_persisted": "true",
                    "singleton_projection_changed": "true",
                    "beta_id": self.items["beta"]["id"],
                    "beta_present": "true",
                    "gamma_empty": "true",
                    "acknowledged": "false",
                }
            )
            kind = "ATTEMPT1_READY"
        else:
            values.update(
                {
                    "previous_token_sha256": self.tokens["attempt_one"],
                    "tokens_distinct": "true",
                    "previous_token_restored": "true",
                    "malformed_token_rejected": "true",
                    "wrong_subscription_token_rejected": "true",
                    "wrong_projection_token_rejected": "true",
                    "retired_singleton_token_rejected": "true",
                    "retired_singleton_token_sha256": self.tokens["singleton"],
                    "ack_token_attempt": "1",
                    "reack_token_attempt": "2",
                    "conflict_ack": "acknowledged",
                    "conflict_reack": "already_acknowledged",
                    "post_conflict_empty": "true",
                    "guard_fresh_query": "true",
                    "guard_siblings": self.siblings,
                    "resolution_id": self.items["resolution"]["id"],
                    "resolution_publisher": self.items["resolution"]["publisher"],
                    "resolution_counter": "2",
                    "resolution_inserted": "true",
                    "resolution_retry_inserted": "false",
                    "resolution_retry_same": "true",
                    "successor_projection_id": self.projections["successor"],
                    "successor_attempt": "1",
                    "successor_token_sha256": self.tokens["successor"],
                    "successor_ack": "acknowledged",
                    "successor_reack": "already_acknowledged",
                    "old_conflict_reack": "already_acknowledged",
                    "post_successor_empty": "true",
                    "superseded_ids": self.siblings,
                    "beta_id": self.items["beta"]["id"],
                    "beta_present": "true",
                    "gamma_empty": "true",
                    "token_artifacts_removed": "true",
                    "closed_kind": "state_unavailable",
                    "closed_operation": "record_query",
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
            )
            kind = "ATTEMPT2_DONE"
        if set(values) != set(keys):
            raise AssertionError(f"child fields differ: {set(values) ^ set(keys)}")
        return "\t".join(
            [
                "LIVE_RECORD_SUBSCRIPTION_CHILD",
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
            self.ready("receiver", 100, "127.0.0.1:11002", 1),
            self.ready("publisher", 100, "127.0.0.1:11001", 1),
            self.contact("publisher", offered=2, fetched=1, inserted=1),
            self.contact("receiver", offered=1, fetched=2, inserted=2),
            self.stop("direct_conflict_and_selectors", "publisher"),
            self.stop("direct_conflict_and_selectors", "receiver"),
            self.ready("receiver", 101, "127.0.0.1:12001", 0),
            self.child(1),
            self.ready("receiver", 102, "127.0.0.1:12002", 0),
            self.stop("peerless_redelivery_resolution", "receiver"),
            self.child(2),
            self.ready("receiver", 100, "127.0.0.1:13001", 0),
            self.stop("final_peerless_reopen", "receiver"),
        ]


class RawRootFixture:
    def __init__(self, parent: Path) -> None:
        parent.chmod(0o700)
        self.root = (parent / "raw").resolve()
        self.root.mkdir(mode=0o700)
        self.fixture = Fixture(self.root)
        self.binary = b"\x7fELFsynthetic-record-subscription-release\n"
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
                for relative in ADMITTED_PATHS
            },
        }
        self._create_files()
        self._write_document()

    def write(self, relative: str, data: bytes, mode: int) -> None:
        target = self.root / relative
        target.write_bytes(data)
        target.chmod(mode)

    def _create_files(self) -> None:
        directories = sorted(
            CHECKER.SUPPORT.EXPECTED_DIRECTORIES,
            key=lambda value: (len(Path(value).parts), value),
        )
        for relative in directories:
            if relative:
                (self.root / relative).mkdir(mode=0o700)
        self.write(f"binary/{BINARY}", self.binary, 0o700)
        self.write("stdout.log", self.fixture.stdout, 0o600)
        self.write("stderr.log", b"", 0o600)
        self.write("transcript.tsv", self.fixture.transcript, 0o600)
        for relative in sorted(CHECKER.SUPPORT.SECRET_FILES):
            if relative.endswith("identity.key"):
                content = hashlib.sha256(relative.encode("ascii")).digest()
            else:
                content = f"secret:{relative}\n".encode("ascii")
            self.write(relative, content, 0o600)

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

    def document(self) -> dict:
        return json.loads((self.root / "run.json").read_bytes())

    def save_document(self, document: dict) -> None:
        self.write("run.json", CHECKER.canonical_json_bytes(document), 0o600)

    def _write_document(self) -> None:
        public = tuple(
            sorted(
                path
                for path in CHECKER.SUPPORT.EXPECTED_FILES
                if path not in CHECKER.SUPPORT.SECRET_FILES and path != "run.json"
            )
        )
        document = {
            "schema": RAW_SCHEMA,
            "claim": CLAIM,
            "run_id": hashlib.sha256(self.fixture.transcript).hexdigest()[:16],
            "source": {
                "commit": self.authority["commit"],
                "tree": self.authority["tree"],
                "signature": self.authority["signature"],
                "admitted": [
                    {"path": path, **self.authority["admitted"][path]}
                    for path in ADMITTED_PATHS
                ],
            },
            "commands": {
                "build_argv": [
                    "cargo",
                    "build",
                    "--release",
                    "--locked",
                    "-p",
                    "aster-node",
                    "--example",
                    "live_record_subscription_acceptance",
                ],
                "run_argv": [
                    os.fspath(self.root / "binary" / BINARY),
                    os.fspath(self.root),
                ],
            },
            "execution": {
                "exit_code": 0,
                "timeout_seconds": 240,
                "worktree_clean_at_run": True,
                "source_binary_execution_link": (
                    "operator-attested-not-cryptographically-proven"
                ),
            },
            "artifacts": {
                "binary": self.file_record(f"binary/{BINARY}"),
                "stdout": self.file_record("stdout.log"),
                "stderr": self.file_record("stderr.log"),
                "transcript": self.file_record("transcript.tsv"),
            },
            "inventory": {
                "directories": [
                    {
                        "path": path or ".",
                        "mode": 0o700,
                        "owner": (self.root / path).lstat().st_uid
                        if path
                        else self.root.lstat().st_uid,
                    }
                    for path in sorted(CHECKER.SUPPORT.EXPECTED_DIRECTORIES)
                ],
                "public": [self.inventory_file(path) for path in public],
                "participant_secret": [
                    self.inventory_file(path)
                    for path in sorted(CHECKER.SUPPORT.SECRET_FILES)
                ],
            },
            "tools": {
                role: {"path": path, **self.authority["admitted"][path]}
                for role, path in CHECKER.TOOL_PATHS.items()
            },
        }
        self.save_document(document)

    def replace_transcript(self, transcript_lines: list[str]) -> None:
        transcript = ("\n".join(transcript_lines) + "\n").encode("ascii")
        stdout = (
            "\n".join(self.fixture.stdout_lines + transcript_lines) + "\n"
        ).encode("ascii")
        self.write("transcript.tsv", transcript, 0o600)
        self.write("stdout.log", stdout, 0o600)
        document = self.document()
        document["run_id"] = hashlib.sha256(transcript).hexdigest()[:16]
        document["artifacts"]["transcript"] = self.file_record("transcript.tsv")
        document["artifacts"]["stdout"] = self.file_record("stdout.log")
        for record in document["inventory"]["public"]:
            if record["path"] in ("transcript.tsv", "stdout.log"):
                record.update(self.inventory_file(record["path"]))
        self.save_document(document)


class TranscriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()

    def validate(self, transcript_lines: list[str]):
        return CHECKER.validate_transcript(
            ("\n".join(transcript_lines) + "\n").encode("ascii")
        )

    def reject(self, transcript_lines: list[str]) -> None:
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate(transcript_lines)

    def mutate(self, kind: str, key: str, value: str, **matches: str) -> list[str]:
        records = self.fixture.transcript_lines.copy()
        index = self.fixture.find(kind, **matches)
        records[index] = replace_field(records[index], key, value)
        return records


    def test_exact_transcript_is_accepted(self) -> None:
        facts = CHECKER.validate_transcript(self.fixture.transcript)
        self.assertEqual(facts["records"], 53)
        self.assertEqual(facts["processes"], 3)
        self.assertEqual(facts["actor_lifetimes"], 7)
        self.assertEqual(facts["network_record_insertions"], 3)

    def test_record_and_field_order_are_closed(self) -> None:
        records = self.fixture.transcript_lines.copy()
        parts = records[27].split("\t")
        parts[-1], parts[-2] = parts[-2], parts[-1]
        records[27] = "\t".join(parts)
        self.reject(records)
        records = self.fixture.transcript_lines.copy()
        records[27], records[28] = records[28], records[27]
        self.reject(records)

    def test_conflict_is_one_delivery_with_both_heads(self) -> None:
        self.reject(
            self.mutate(
                "CHILD_DELIVERY",
                "siblings",
                self.fixture.items["edit"]["id"],
                phase="forced_conflict_delivery",
            )
        )
        self.reject(
            self.mutate(
                "CHILD_DELIVERY",
                "concurrent_id",
                "none",
                phase="forced_conflict_delivery",
            )
        )
        self.reject(
            self.mutate(
                "CHILD_DELIVERY",
                "projection_id",
                identifier(60),
                phase="peerless_redelivery_resolution",
            )
        )

    def test_attempts_preserve_projection_and_rotate_token(self) -> None:
        records = self.fixture.transcript_lines.copy()
        for index in (27, 31):
            records[index] = replace_field(
                records[index], "projection_key_sha256", "f" * 64
            )
        self.reject(records)
        self.reject(
            self.mutate(
                "CHILD_DELIVERY",
                "attempt",
                "1",
                phase="peerless_redelivery_resolution",
            )
        )
        self.reject(
            self.mutate(
                "CHILD_DELIVERY",
                "token_sha256",
                self.fixture.tokens["attempt_one"],
                phase="peerless_redelivery_resolution",
            )
        )
        self.reject(
            self.mutate(
                "CHILD_DELIVERY",
                "previous_token_sha256",
                self.fixture.tokens["attempt_two"],
                phase="peerless_redelivery_resolution",
            )
        )

    def test_delivery_bounds_and_nondisclosure_are_exact(self) -> None:
        for kind, matches in (
            ("DELIVERY", {"label": "alpha-singleton"}),
            ("CHILD_DELIVERY", {"phase": "forced_conflict_delivery"}),
            ("CHILD_DELIVERY", {"phase": "peerless_redelivery_resolution"}),
            ("DELIVERY", {"label": "resolved-successor"}),
        ):
            for key, wrong in (
                ("delivery_limit", "2"),
                ("scan_limit", "17"),
                ("has_more", "true"),
                ("superseded_exposed", "true"),
                ("resolution_guard_exposed", "true"),
            ):
                with self.subTest(kind=kind, matches=matches, key=key):
                    self.reject(self.mutate(kind, key, wrong, **matches))

    def test_successor_is_new_projection_at_attempt_one(self) -> None:
        self.reject(
            self.mutate(
                "DELIVERY",
                "projection_id",
                self.fixture.projections["conflict"],
                label="resolved-successor",
            )
        )
        self.reject(self.mutate("DELIVERY", "attempt", "2", label="resolved-successor"))
        self.reject(
            self.mutate(
                "DELIVERY",
                "conflict_siblings",
                self.fixture.siblings,
                label="resolved-successor",
            )
        )

    def test_token_length_and_adversaries_are_exact(self) -> None:
        self.reject(self.mutate("TOKEN_CHECKS", "token_bytes", "88"))
        for key in (
            "attempt_tokens_distinct",
            "attempt_one_restored",
            "malformed_token_rejected",
            "wrong_subscription_token_rejected",
            "wrong_projection_token_rejected",
            "retired_singleton_token_rejected",
            "token_artifacts_removed",
        ):
            with self.subTest(key=key):
                self.reject(self.mutate("TOKEN_CHECKS", key, "false"))

    def test_ack_reack_and_old_projection_reack_are_exact(self) -> None:
        self.reject(
            self.mutate(
                "ACKNOWLEDGEMENT",
                "ack_token_attempt",
                "2",
                projection="conflict",
            )
        )
        self.reject(
            self.mutate(
                "ACKNOWLEDGEMENT", "reack", "acknowledged", projection="successor"
            )
        )
        self.reject(
            self.mutate(
                "ACKNOWLEDGEMENT",
                "old_projection_reack",
                "invalid_request",
                projection="successor",
            )
        )

    def test_resolution_requires_fresh_query_guard(self) -> None:
        self.reject(self.mutate("RESOLUTION", "guard_fresh_query", "false"))
        self.reject(
            self.mutate(
                "RESOLUTION",
                "guard_siblings",
                self.fixture.items["edit"]["id"],
            )
        )
        self.reject(self.mutate("RESOLUTION", "retry_same", "false"))

    def test_application_selector_does_not_expand_network_interest(self) -> None:
        self.reject(
            self.mutate(
                "SELECTOR",
                "application_matched",
                "false",
                phase="direct_conflict_and_selectors",
                label="gamma",
            )
        )
        self.reject(
            self.mutate(
                "SELECTOR",
                "network_interested",
                "true",
                phase="direct_conflict_and_selectors",
                label="gamma",
            )
        )
        self.reject(
            self.mutate(
                "SELECTOR",
                "receiver_retained",
                "true",
                phase="final_peerless_reopen",
                label="gamma",
            )
        )
        self.reject(
            self.mutate(
                "SELECTOR",
                "delivered",
                "true",
                phase="final_peerless_reopen",
                label="beta",
            )
        )

    def test_sigkill_happens_after_flush_without_stop(self) -> None:
        self.reject(
            self.mutate("PROCESS_TERMINATION", "termination_signal", "sigterm")
        )
        self.reject(
            self.mutate("PROCESS_TERMINATION", "after_flushed_poll", "false")
        )
        self.reject(
            self.mutate("PROCESS_TERMINATION", "stop_record_observed", "true")
        )
        self.reject(
            self.mutate("PROCESS_TERMINATION", "token_artifact_fsynced", "false")
        )

    def test_final_reopen_and_subscription_stats_are_exact(self) -> None:
        self.reject(
            self.mutate(
                "PROJECTION",
                "superseded_ids",
                self.fixture.items["edit"]["id"],
                phase="final_peerless_reopen",
            )
        )
        self.reject(
            self.mutate(
                "EMPTY_POLL",
                "deliveries",
                "1",
                phase="final_peerless_reopen",
            )
        )
        for key, wrong in (
            ("subscriptions", "2"),
            ("pending_deliveries", "1"),
            ("acknowledged_deliveries", "2"),
            ("delivery_cursors", "2"),
            ("selector_generation", "2"),
        ):
            with self.subTest(key=key):
                self.reject(
                    self.mutate("INSPECTION", key, wrong, participant="receiver")
                )

    def test_transfer_and_process_totals_are_exact(self) -> None:
        self.reject(
            self.mutate(
                "RECEIPT",
                "data_inserted",
                "3",
                phase="direct_conflict_and_selectors",
                participant="receiver",
            )
        )
        self.reject(self.mutate("RESULT", "network_record_insertions", "4"))
        self.reject(self.mutate("RESULT", "processes", "2"))
        self.reject(self.mutate("RESULT", "actor_lifetimes", "8"))

    def test_transcript_is_canonical_and_digest_only(self) -> None:
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.validate_transcript(self.fixture.transcript.rstrip(b"\n"))
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.validate_transcript(
                self.fixture.transcript.replace(b"\n", b"\r\n", 1)
            )
        self.assertNotIn((bytes([32]) * TOKEN_BYTES).hex().encode(), self.fixture.transcript)


class TerminalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()
        self.facts = CHECKER.validate_transcript(self.fixture.transcript)

    def validate(self, runtime: list[str]):
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
        self.assertEqual(facts["ready_records"], 7)
        self.assertEqual(facts["stop_records"], 6)
        self.assertEqual(facts["processes"], 3)
        self.assertEqual(facts["reconciliation"]["record_transfer"]["inserted"], 3)

    def test_forced_lifetime_has_no_stop(self) -> None:
        runtime = self.fixture.stdout_lines.copy()
        runtime.insert(
            12, self.fixture.stop("peerless_redelivery_resolution", "receiver")
        )
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate(runtime)

    def test_parent_and_two_children_are_distinct_processes(self) -> None:
        runtime = self.fixture.stdout_lines.copy()
        runtime[10] = runtime[10].replace("pid=101", "pid=100")
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate(runtime)
        runtime = self.fixture.stdout_lines.copy()
        runtime[12] = runtime[12].replace("pid=102", "pid=101")
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate(runtime)

    def test_child_projection_and_attempt_tokens_cross_bind(self) -> None:
        runtime = self.fixture.stdout_lines.copy()
        runtime[14] = runtime[14].replace(
            f"projection_id={self.fixture.projections['conflict']}",
            f"projection_id={identifier(61)}",
        )
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate(runtime)
        runtime = self.fixture.stdout_lines.copy()
        runtime[14] = runtime[14].replace(
            self.fixture.tokens["attempt_two"],
            self.fixture.tokens["attempt_one"],
            1,
        )
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate(runtime)

    def test_child_bounds_and_nondisclosure_cross_bind(self) -> None:
        for runtime_index in (11, 14):
            for key, wrong in (
                ("delivery_limit", "2"),
                ("scan_limit", "17"),
                ("has_more", "true"),
                ("superseded_exposed", "true"),
                ("resolution_guard_exposed", "true"),
            ):
                runtime = self.fixture.stdout_lines.copy()
                runtime[runtime_index] = runtime[runtime_index].replace(
                    f"{key}={record_fields(self.fixture.child(1 if runtime_index == 11 else 2))[key]}",
                    f"{key}={wrong}",
                )
                with self.subTest(index=runtime_index, key=key), self.assertRaises(
                    CHECKER.ReceiptViolation
                ):
                    self.validate(runtime)

    def test_child_token_adversaries_are_enforced(self) -> None:
        for key in (
            "malformed_token_rejected",
            "wrong_subscription_token_rejected",
            "wrong_projection_token_rejected",
            "retired_singleton_token_rejected",
        ):
            runtime = self.fixture.stdout_lines.copy()
            runtime[14] = runtime[14].replace(f"{key}=true", f"{key}=false")
            with self.subTest(key=key), self.assertRaises(CHECKER.ReceiptViolation):
                self.validate(runtime)

    def test_child_successor_uses_new_projection(self) -> None:
        runtime = self.fixture.stdout_lines.copy()
        runtime[14] = runtime[14].replace(
            f"successor_projection_id={self.fixture.projections['successor']}",
            f"successor_projection_id={self.fixture.projections['conflict']}",
        )
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate(runtime)

    def test_contact_transfer_and_protected_frames_are_enforced(self) -> None:
        runtime = self.fixture.stdout_lines.copy()
        runtime[6] = runtime[6].replace("inserted=1", "inserted=2")
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate(runtime)
        runtime = self.fixture.stdout_lines.copy()
        runtime[6] = runtime[6].replace("protected_frames=1", "protected_frames=0")
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.validate(runtime)

    def test_terminal_after_transcript_is_rejected(self) -> None:
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.validate_terminal_stdout(
                self.fixture.stdout + b"STOP forbidden\n",
                self.fixture.transcript,
                self.fixture.root,
                self.facts,
            )


class RawRootTests(unittest.TestCase):
    def test_exact_root_projects_one_redacted_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw = RawRootFixture(Path(temporary))
            evidence = CHECKER.validate_raw_root(raw.root, raw.authority)
            encoded = CHECKER.render_receipt(
                CHECKER.build_receipt(raw.authority, evidence),
                forbidden_values=CHECKER.receipt_forbidden_values(evidence, raw.root),
                forbidden_pids=CHECKER.SUPPORT.receipt_forbidden_pids(evidence),
                forbidden_ports=CHECKER.SUPPORT.receipt_forbidden_ports(evidence),
            )
            self.assertLessEqual(len(encoded), CHECKER.RECEIPT_MAX_BYTES)
            projected = json.loads(encoded)
            self.assertEqual(tuple(projected["limitations"]), ORACLE_LIMITATIONS)
            self.assertEqual(tuple(projected["nonclaims"]), ORACLE_NONCLAIMS)
            forbidden = {
                os.fspath(raw.root),
                raw.fixture.subscription,
                *raw.fixture.projections.values(),
                *raw.fixture.tokens.values(),
                *(item["id"] for item in raw.fixture.items.values()),
            }
            for participant in raw.fixture.participants.values():
                forbidden.update(participant.values())
            for value in forbidden:
                self.assertNotIn(value.encode("ascii"), encoded)

    def test_extra_raw_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw = RawRootFixture(Path(temporary))
            raw.write("unexpected", b"x", 0o600)
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.validate_raw_root(raw.root, raw.authority)

    def test_noncanonical_run_document_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw = RawRootFixture(Path(temporary))
            path = raw.root / "run.json"
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.validate_raw_root(raw.root, raw.authority)

    def test_semantic_mutation_is_rejected_with_fresh_artifact_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw = RawRootFixture(Path(temporary))
            records = raw.fixture.transcript_lines.copy()
            index = raw.fixture.find("TOKEN_CHECKS")
            records[index] = replace_field(records[index], "token_bytes", "88")
            raw.replace_transcript(records)
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.validate_raw_root(raw.root, raw.authority)

    def test_source_and_command_metadata_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw = RawRootFixture(Path(temporary))
            document = raw.document()
            document["source"]["admitted"][0]["sha256"] = identifier(63)
            raw.save_document(document)
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.validate_raw_root(raw.root, raw.authority)
        with tempfile.TemporaryDirectory() as temporary:
            raw = RawRootFixture(Path(temporary))
            document = raw.document()
            document["commands"]["build_argv"].append("--features=unreviewed")
            raw.save_document(document)
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.validate_raw_root(raw.root, raw.authority)

    def test_secret_content_and_digest_are_not_projected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw = RawRootFixture(Path(temporary))
            secret = (
                raw.root / "participants/receiver/state/identity.key"
            ).read_bytes()
            evidence = CHECKER.validate_raw_root(raw.root, raw.authority)
            encoded = CHECKER.render_receipt(
                CHECKER.build_receipt(raw.authority, evidence),
                forbidden_values=CHECKER.receipt_forbidden_values(evidence, raw.root),
            )
            self.assertNotIn(secret, encoded)
            self.assertNotIn(
                hashlib.sha256(secret).hexdigest().encode("ascii"), encoded
            )


class ArtifactTests(unittest.TestCase):
    def test_loaded_support_bytes_are_bound(self) -> None:
        self.assertEqual(
            RUNNER.SUPPORT.__loaded_source_sha256__,
            hashlib.sha256(Path(RUNNER.SUPPORT.__file__).read_bytes()).hexdigest(),
        )
        self.assertEqual(
            CHECKER.SUPPORT.__loaded_source_sha256__,
            hashlib.sha256(Path(CHECKER.SUPPORT.__file__).read_bytes()).hexdigest(),
        )

    def test_output_destination_excludes_raw_and_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            source = base / "source"
            raw = base / "raw"
            destination = base / "destination"
            for directory in (source, raw, destination):
                directory.mkdir(mode=0o700)
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.validate_output_destination(
                    raw / CHECKER.RECEIPT_NAME, raw, source
                )
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.validate_output_destination(
                    source / CHECKER.RECEIPT_NAME, raw, source
                )
            expected = destination / CHECKER.RECEIPT_NAME
            validated = CHECKER.validate_output_destination(expected, raw, source)
            self.assertIsNotNone(validated)
            assert validated is not None
            self.assertEqual(validated.path, expected)
            os.close(validated.parent_fd)
            symbolic = base / "symbolic"
            symbolic.symlink_to(destination, target_is_directory=True)
            with self.assertRaises(CHECKER.ReceiptViolation):
                CHECKER.validate_output_destination(
                    symbolic / CHECKER.RECEIPT_NAME, raw, source
                )

    def test_output_parent_replacement_cannot_redirect_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            source = base / "source"
            raw = base / "raw"
            destination = base / "destination"
            for directory in (source, raw, destination):
                directory.mkdir(mode=0o700)
            output = CHECKER.validate_output_destination(
                destination / CHECKER.RECEIPT_NAME, raw, source
            )
            assert output is not None
            parked = base / "parked"
            destination.rename(parked)
            destination.symlink_to(raw, target_is_directory=True)
            try:
                with self.assertRaises(CHECKER.ReceiptViolation):
                    CHECKER.write_projected_receipt(output, b"{}\n")
                self.assertFalse((raw / CHECKER.RECEIPT_NAME).exists())
            finally:
                os.close(output.parent_fd)

    def test_git_and_build_subprocess_environments_strip_injection(self) -> None:
        injected = {
            "DYLD_INSERT_LIBRARIES": "/tmp/forbidden.dylib",
            "LD_PRELOAD": "/tmp/forbidden.so",
            "PYTHONHOME": "/tmp/forbidden-python",
            "PYTHONPATH": "/tmp/forbidden-modules",
        }
        with mock.patch.dict(os.environ, injected, clear=False):
            for environment in (
                RUNNER.safe_git_environment(),
                CHECKER.SUPPORT._clean_git_environment(),
            ):
                for name in injected:
                    self.assertNotIn(name, environment)
                self.assertEqual(
                    environment["PATH"], os.confstr("CS_PATH") or "/bin:/usr/bin"
                )

            captured: dict[str, str] = {}

            def fake_run(*_args, **kwargs):
                captured.update(kwargs["env"])
                return types.SimpleNamespace(returncode=0)

            with mock.patch.object(
                RUNNER.SUPPORT.subprocess, "run", side_effect=fake_run
            ), mock.patch.object(
                RUNNER.SUPPORT, "require_regular_executable", return_value=None
            ):
                RUNNER.SUPPORT.build_release(Path("/tmp/record-source"))
            for name in injected:
                self.assertNotIn(name, captured)
            self.assertEqual(
                captured["CARGO_TARGET_DIR"], "/tmp/record-source/target"
            )

    def test_runner_extracts_only_exact_record_records(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            stdout = Path(temporary) / "stdout.log"
            stdout.write_bytes(fixture.stdout)
            self.assertEqual(RUNNER.extract_transcript(stdout), fixture.transcript)

    def test_runner_rejects_missing_or_duplicate_record(self) -> None:
        fixture = Fixture()
        for records in (
            fixture.transcript_lines[:-1],
            fixture.transcript_lines + [fixture.transcript_lines[-1]],
        ):
            damaged = (
                "\n".join(fixture.stdout_lines + list(records)) + "\n"
            ).encode("ascii")
            with tempfile.TemporaryDirectory() as temporary:
                stdout = Path(temporary) / "stdout.log"
                stdout.write_bytes(damaged)
                with self.assertRaises(RUNNER.RunnerFailure):
                    RUNNER.extract_transcript(stdout)


    def test_receipt_renderer_rejects_sensitive_value(self) -> None:
        sensitive = identifier(61)
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.render_receipt(
                {"schema": SCHEMA, "value": sensitive},
                forbidden_values=[sensitive],
            )

    def test_canonical_bytes_are_stable(self) -> None:
        self.assertEqual(
            CHECKER.canonical_json_bytes({"b": 2, "a": 1}),
            b'{"a":1,"b":2}\n',
        )
        first = CHECKER.render_receipt({"schema": SCHEMA, "status": "pass"})
        second = CHECKER.render_receipt({"status": "pass", "schema": SCHEMA})
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
