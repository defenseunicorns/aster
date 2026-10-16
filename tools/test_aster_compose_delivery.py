#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""No-daemon tests for the ordinary Compose delivery validator."""

from __future__ import annotations

import importlib.util
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("aster_compose_delivery.py")
SPEC = importlib.util.spec_from_file_location("aster_compose_delivery", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

REPOSITORY = MODULE_PATH.parents[1]
COMPOSE = REPOSITORY / "docker/compose-agent/compose.yaml"
REMOTE_MESH = REPOSITORY / "docker/compose-agent/compose.remote-mesh.yaml"
MISE = REPOSITORY / "mise.toml"
TOKEN_CANARY = "task6-token-canary-do-not-print-0000"
GENERATION = "generation-" + "a" * 64
AGENT_IMAGE = "registry.example/aster-agent@sha256:" + "b" * 64
ADMIN_IMAGE = "registry.example/aster-admin@sha256:" + "c" * 64
LOCAL_AGENT_IMAGE = "sha256:" + "d" * 64
LOCAL_ADMIN_IMAGE = "sha256:" + "e" * 64


def canonical_model():
    runtime = {
        "user": "${ASTER_UID:?required}:${ASTER_GID:?required}",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "pids_limit": 256,
        "tmpfs": [
            "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=0700,"
            "uid=${ASTER_UID:?required},gid=${ASTER_GID:?required}"
        ],
        "restart": "no",
        "logging": {"driver": "json-file", "options": {"max-size": "5m", "max-file": "3"}},
    }
    secrets = [
        {"source": "aster-client-token", "target": "/run/secrets/aster-client-token"},
        {"source": "aster-mission-activation", "target": "/run/secrets/aster-mission-activation"},
        {"source": "aster-provisioning-bundle", "target": "/run/secrets/aster-provisioning-bundle"},
    ]
    operator_token = {
        "source": "aster-operator-client-token",
        "target": "/run/secrets/aster-client-token",
    }
    config = [{"source": "aster-agent-config", "target": "/etc/aster/agent.json", "mode": 292}]
    config_digest = {"ASTER_AGENT_CONFIG_SHA256": "${ASTER_AGENT_CONFIG_SHA256:?required}"}
    state_bind = [{"type": "bind", "source": "${ASTER_STATE_DIR:?required}",
                   "target": "/var/lib/aster"}]
    transfer_bind = [{"type": "bind", "source": "${ASTER_TRANSFER_DIR:?required}",
                      "target": "/transfer"}]
    return {
        "x-aster-metadata": {
            "copyright": "Copyright 2026 Defense Unicorns, Inc.",
            "license": "SPDX-License-Identifier: Apache-2.0",
            "qualified_source": "canonical-json-form-yaml/v1",
        },
        "services": {
            "preflight": {
                **copy.deepcopy(runtime), "image": "${ASTER_AGENT_IMAGE_DIGEST:?required}",
                "pull_policy": "never",
                "environment": copy.deepcopy(config_digest),
                "network_mode": "none", "command": ["--check-config", "/etc/aster/agent.json"],
                "configs": copy.deepcopy(config), "secrets": copy.deepcopy(secrets),
            },
            "aster-agent": {
                **copy.deepcopy(runtime), "image": "${ASTER_AGENT_IMAGE_DIGEST:?required}",
                "pull_policy": "never",
                "environment": copy.deepcopy(config_digest),
                "command": ["--config", "/etc/aster/agent.json"], "configs": copy.deepcopy(config),
                "secrets": copy.deepcopy(secrets), "volumes": state_bind, "expose": ["8183/udp"],
                "stop_signal": "SIGTERM", "stop_grace_period": "40s", "restart": "on-failure:3",
                "healthcheck": {"test": ["CMD", "/usr/local/bin/aster-compose-healthcheck"],
                                "interval": "5s", "timeout": "3s", "retries": 12,
                                "start_period": "5s"},
                "depends_on": {"preflight": {"condition": "service_completed_successfully"}},
            },
            "verify": {
                **copy.deepcopy(runtime), "image": "${ASTER_ADMIN_IMAGE_DIGEST:?required}",
                "pull_policy": "never",
                "network_mode": "service:aster-agent",
                "command": ["/usr/local/bin/aster-compose-verify"],
                "configs": copy.deepcopy(config),
                "secrets": [copy.deepcopy(secrets[0])],
                "volumes": [{"type": "bind",
                             "source": "${ASTER_CREDENTIAL_GENERATION_DIR:?required}/manifest.json",
                             "target": "/run/aster-generation/manifest.json", "read_only": True}],
                "depends_on": {"aster-agent": {"condition": "service_healthy"}},
            },
            "asterctl": {
                **copy.deepcopy(runtime), "image": "${ASTER_ADMIN_IMAGE_DIGEST:?required}",
                "pull_policy": "never",
                "network_mode": "service:aster-agent",
                "entrypoint": ["/usr/local/bin/asterctl", "--token-file",
                               "/run/secrets/aster-client-token"],
                "command": ["status"],
                "secrets": [copy.deepcopy(operator_token)],
                "volumes": transfer_bind,
                "depends_on": {"aster-agent": {"condition": "service_healthy"}},
            },
        },
        "configs": {"aster-agent-config": {"file": "${ASTER_AGENT_CONFIG_FILE:?required}"}},
        "secrets": {
            "aster-client-token": {"file": "${ASTER_CREDENTIAL_GENERATION_DIR:?required}/aster-client-token"},
            "aster-mission-activation": {"file": "${ASTER_CREDENTIAL_GENERATION_DIR:?required}/aster-mission-activation"},
            "aster-provisioning-bundle": {"file": "${ASTER_CREDENTIAL_GENERATION_DIR:?required}/aster-provisioning-bundle"},
            "aster-operator-client-token": {"file": "${ASTER_TOKEN_INPUT:?required}"},
        },
    }


def canonical_json(model) -> str:
    return json.dumps(model, indent=2) + "\n"


def canonical_remote_mesh_model():
    return {
        "services": {
            "aster-agent": {
                "ports": [
                    "${ASTER_MESH_BIND_ADDRESS:?required}:"
                    "${ASTER_MESH_PUBLISHED_PORT:-8183}:8183/udp"
                ]
            }
        }
    }


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        self.generation = root / GENERATION
        self.generation.mkdir(mode=0o700)
        self.files = {
            "aster-client-token": TOKEN_CANARY.encode(),
            "aster-mission-activation": b"activation-canary",
            "aster-provisioning-bundle": b"bundle-canary",
        }
        for name, value in self.files.items():
            path = self.generation / name
            path.write_bytes(value)
            path.chmod(0o600)
        (self.generation / "manifest.json").write_text(
            json.dumps({"schema": "aster-compose-secret-generation/v1"}) + "\n"
        )
        (self.generation / "manifest.json").chmod(0o600)
        self.generation.chmod(0o500)
        self.model = canonical_model()
        self.compose = canonical_json(self.model)
        self.compose_path = root / "compose.yaml"
        self.compose_path.write_text(self.compose)
        self.config_path = root / "agent.json"
        self.config_path.write_text(json.dumps({"schema_version": 2}) + "\n")
        self.state = root / "state"
        self.state.mkdir(mode=0o700)
        self.transfer = root / "transfer"
        self.transfer.mkdir(mode=0o700)
        self.token_input = root / "client-token-input"
        self.token_input.write_text(TOKEN_CANARY)
        self.token_input.chmod(0o600)

    def env(self) -> dict[str, str]:
        return {
            "COMPOSE_PROJECT_NAME": "aster-test-a",
            "ASTER_AGENT_CONFIG_FILE": str(self.config_path),
            "ASTER_AGENT_CONFIG_SHA256": hashlib.sha256(
                self.config_path.read_bytes()
            ).hexdigest(),
            "ASTER_UID": str(os.getuid()),
            "ASTER_GID": str(os.getgid()),
            "ASTER_AGENT_IMAGE_DIGEST": AGENT_IMAGE,
            "ASTER_ADMIN_IMAGE_DIGEST": ADMIN_IMAGE,
            "ASTER_CREDENTIAL_GENERATION_DIR": str(self.generation),
            "ASTER_STATE_DIR": str(self.state),
            "ASTER_TRANSFER_DIR": str(self.transfer),
            "ASTER_TOKEN_INPUT": str(self.token_input),
        }

    def rewrite(self, old: str, new: str) -> None:
        text = self.compose_path.read_text()
        if old not in text:
            raise AssertionError(f"fixture mutation source absent: {old!r}")
        self.compose_path.write_text(text.replace(old, new, 1))

    def mutate(self, callback) -> None:
        model = copy.deepcopy(self.model)
        callback(model)
        self.compose_path.write_text(canonical_json(model))


class DeliveryTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self):
        for child in Path(self.temporary.name).glob("generation-*"):
            if child.is_dir():
                child.chmod(0o700)
        self.temporary.cleanup()

    def validate(self, env=None):
        return MODULE.build_plan(self.fixture.compose_path, env or self.fixture.env())

    def assert_rejected(self, code: str, env=None):
        with self.assertRaises(MODULE.ValidationError) as raised:
            self.validate(env)
        self.assertEqual(raised.exception.code, code)
        rendered = str(raised.exception)
        self.assertNotIn(str(self.fixture.generation), rendered)
        self.assertNotIn(TOKEN_CANARY, rendered)


class GenerationBoundaryTests(DeliveryTestCase):
    def test_accepts_one_real_immutable_generation_and_is_deterministic(self):
        first = self.validate().render()
        second = self.validate().render()
        self.assertEqual(first, second)
        self.assertIn('"schema":"aster-compose-delivery-plan/v1"', first)
        self.assertNotIn(str(self.fixture.generation), first)
        self.assertNotIn(TOKEN_CANARY, first)
        self.assertIn(
            '"config_sha256":"'
            + hashlib.sha256(self.fixture.config_path.read_bytes()).hexdigest()
            + '"',
            first,
        )
        self.assertNotIn(str(self.fixture.config_path), first)

    def test_requires_an_absolute_regular_schema_v2_config_file(self):
        cases = (
            (None, "config-file-required"),
            ("", "config-file-required"),
            ("agent.json", "config-file-absolute"),
            (str(self.fixture.root / "missing.json"), "config-file-invalid"),
        )
        for value, code in cases:
            with self.subTest(value=value):
                env = self.fixture.env()
                if value is None:
                    env.pop("ASTER_AGENT_CONFIG_FILE")
                else:
                    env["ASTER_AGENT_CONFIG_FILE"] = value
                self.assert_rejected(code, env)

        self.fixture.config_path.write_text(json.dumps({"schema_version": 1}) + "\n")
        self.assert_rejected("config-file-invalid")

    def test_requires_digest_bound_to_the_selected_config_bytes(self):
        for value, code in (
            (None, "config-digest-required"),
            ("not-a-digest", "config-digest-invalid"),
            ("0" * 64, "config-digest-mismatch"),
        ):
            with self.subTest(value=value):
                env = self.fixture.env()
                if value is None:
                    env.pop("ASTER_AGENT_CONFIG_SHA256")
                else:
                    env["ASTER_AGENT_CONFIG_SHA256"] = value
                self.assert_rejected(code, env)

    def test_rejects_noncanonical_config_source(self):
        self.fixture.mutate(
            lambda model: model["configs"]["aster-agent-config"].update(
                {"file": "./agent.example.json"}
            )
        )
        self.assert_rejected("compose-model-semantics-invalid")

    def test_checked_in_compose_is_the_accepted_canonical_json_model(self):
        self.assertEqual(COMPOSE.read_text(), canonical_json(canonical_model()))
        plan = MODULE.build_plan(COMPOSE, self.fixture.env())
        self.assertIn('"schema":"aster-compose-delivery-plan/v1"', plan.render())

    def test_rejects_unset_empty_relative_and_non_generation_directories(self):
        cases = ((None, "generation-directory-required"),
                 ("", "generation-directory-required"),
                 (GENERATION, "generation-directory-absolute"),
            (str(self.fixture.root), "generation-directory-immutable"))
        for value, code in cases:
            with self.subTest(value=value):
                env = self.fixture.env()
                if value is None:
                    env.pop("ASTER_CREDENTIAL_GENERATION_DIR")
                else:
                    env["ASTER_CREDENTIAL_GENERATION_DIR"] = value
                self.assert_rejected(code, env)

    def test_rejects_missing_files_and_manifest(self):
        for name in (*self.fixture.files, "manifest.json"):
            with self.subTest(name=name):
                path = self.fixture.generation / name
                saved = path.read_bytes()
                self.fixture.generation.chmod(0o700)
                path.unlink()
                self.fixture.generation.chmod(0o500)
                self.assert_rejected("generation-files-invalid")
                self.fixture.generation.chmod(0o700)
                path.write_bytes(saved)
                path.chmod(0o600)
                self.fixture.generation.chmod(0o500)

    def test_rejects_realpath_escape_sibling_and_mixed_generation_sources(self):
        sibling = self.fixture.root / ("generation-" + "d" * 64)
        sibling.mkdir(mode=0o700)
        for name in (*self.fixture.files, "manifest.json"):
            (sibling / name).write_bytes((self.fixture.generation / name).read_bytes())
            (sibling / name).chmod(0o600)
        sibling.chmod(0o500)
        mutations = (
            ("${ASTER_CREDENTIAL_GENERATION_DIR:?required}/aster-client-token",
             "../generation-sibling/aster-client-token"),
            ("${ASTER_CREDENTIAL_GENERATION_DIR:?required}/aster-mission-activation",
             str(sibling / "aster-mission-activation")),
            ("${ASTER_CREDENTIAL_GENERATION_DIR:?required}/aster-provisioning-bundle",
             "${ASTER_CREDENTIAL_GENERATION_DIR:?required}/../" + sibling.name
             + "/aster-provisioning-bundle"),
        )
        original = self.fixture.compose_path.read_text()
        for old, new in mutations:
            with self.subTest(new=new):
                self.fixture.compose_path.write_text(original.replace(old, new, 1))
                self.assert_rejected("generation-sources-invalid")

    def test_rejects_uid_gid_zero_non_numeric_and_file_owner_mismatch(self):
        for key, value, code in (
            ("ASTER_UID", "0", "runtime-identity-invalid"),
            ("ASTER_GID", "0", "runtime-identity-invalid"),
            ("ASTER_UID", "user", "runtime-identity-invalid"),
            ("ASTER_GID", "group", "runtime-identity-invalid"),
            ("ASTER_UID", str(os.getuid() + 1), "generation-ownership-invalid"),
            ("ASTER_GID", str(os.getgid() + 1), "generation-ownership-invalid"),
        ):
            with self.subTest(key=key, value=value):
                env = self.fixture.env()
                env[key] = value
                self.assert_rejected(code, env)

    def test_rejects_writable_or_symlinked_generation_directory(self):
        self.fixture.generation.chmod(0o700)
        self.assert_rejected("generation-directory-mode-invalid")
        self.fixture.generation.chmod(0o500)

        link = self.fixture.root / ("generation-" + "e" * 64)
        link.symlink_to(self.fixture.generation, target_is_directory=True)
        env = self.fixture.env()
        env["ASTER_CREDENTIAL_GENERATION_DIR"] = str(link)
        self.assert_rejected("generation-directory-immutable", env)

class StaticComposePolicyTests(DeliveryTestCase):
    def test_remote_mesh_override_is_exact_and_default_stays_closed(self):
        self.assertNotIn("ports", self.fixture.model["services"]["aster-agent"])
        self.assertEqual(
            REMOTE_MESH.read_text(),
            canonical_json(canonical_remote_mesh_model()),
        )
        with self.assertRaises(MODULE.ValidationError) as raised:
            MODULE.validate_remote_mesh_override(REMOTE_MESH, {})
        self.assertEqual(raised.exception.code, "mesh-bind-address-required")
        MODULE.validate_remote_mesh_override(
            REMOTE_MESH,
            {"ASTER_MESH_BIND_ADDRESS": "10.244.151.17"},
        )
        with self.assertRaises(MODULE.ValidationError) as raised:
            MODULE.validate_remote_mesh_override(
                REMOTE_MESH,
                {
                    "ASTER_MESH_BIND_ADDRESS": "10.244.151.17",
                    "ASTER_MESH_PUBLISHED_PORT": "0",
                },
            )
        self.assertEqual(raised.exception.code, "mesh-published-port-invalid")

    def test_requires_an_absolute_user_owned_private_state_directory(self):
        # Break caught: accepting a missing, indirect, or broadly accessible
        # state path would reintroduce privileged initialization or expose data.
        for value, code in (
            (None, "state-directory-required"),
            ("state", "state-directory-absolute"),
            (str(self.fixture.root / "missing"), "state-directory-invalid"),
        ):
            with self.subTest(value=value):
                env = self.fixture.env()
                if value is None:
                    env.pop("ASTER_STATE_DIR")
                else:
                    env["ASTER_STATE_DIR"] = value
                self.assert_rejected(code, env)

        self.fixture.state.chmod(0o755)
        self.assert_rejected("state-directory-mode-invalid")
        self.fixture.state.chmod(0o700)
        link = self.fixture.root / "state-link"
        link.symlink_to(self.fixture.state, target_is_directory=True)
        env = self.fixture.env()
        env["ASTER_STATE_DIR"] = str(link)
        self.assert_rejected("state-directory-invalid", env)

    def test_model_has_no_root_service_capability_or_named_state_volume(self):
        # Break caught: restoring the former initializer would require
        # container root/CAP_CHOWN despite the Docker-only operator contract.
        model = self.fixture.model
        self.assertEqual(
            set(model["services"]),
            {"aster-agent", "preflight", "verify", "asterctl"},
        )
        self.assertNotIn("volumes", model)
        for service in model["services"].values():
            self.assertNotEqual(service.get("user"), "0:0")
            self.assertNotIn("cap_add", service)
        self.assertEqual(
            model["services"]["aster-agent"]["volumes"],
            [{"type": "bind", "source": "${ASTER_STATE_DIR:?required}",
              "target": "/var/lib/aster"}],
        )

    def test_requires_a_conservative_explicit_project_name(self):
        for value in (None, "", "Aster Site", "-aster", "aster/site", "a" * 64):
            with self.subTest(value=value):
                env = self.fixture.env()
                if value is None:
                    env.pop("COMPOSE_PROJECT_NAME")
                else:
                    env["COMPOSE_PROJECT_NAME"] = value
                self.assert_rejected("project-name-invalid", env)

        plan = self.validate().render()
        self.assertIn('"project_name":"aster-test-a"', plan)

    def test_asterctl_is_one_shot_token_only_and_shares_agent_network(self):
        service = self.fixture.model["services"]["asterctl"]
        self.assertEqual(service["image"], "${ASTER_ADMIN_IMAGE_DIGEST:?required}")
        self.assertEqual(service["network_mode"], "service:aster-agent")
        self.assertEqual(
            service["entrypoint"],
            [
                "/usr/local/bin/asterctl",
                "--token-file",
                "/run/secrets/aster-client-token",
            ],
        )
        self.assertEqual(service["command"], ["status"])
        self.assertEqual(
            service["secrets"],
            [{"source": "aster-operator-client-token",
              "target": "/run/secrets/aster-client-token"}],
        )
        self.assertEqual(
            self.fixture.model["secrets"]["aster-client-token"],
            {"file": "${ASTER_CREDENTIAL_GENERATION_DIR:?required}/aster-client-token"},
        )
        self.assertEqual(
            self.fixture.model["secrets"]["aster-operator-client-token"],
            {"file": "${ASTER_TOKEN_INPUT:?required}"},
        )
        self.assertEqual(
            service["volumes"],
            [{"type": "bind", "source": "${ASTER_TRANSFER_DIR:?required}",
              "target": "/transfer"}],
        )
        self.assertEqual(
            service["depends_on"],
            {"aster-agent": {"condition": "service_healthy"}},
        )
        self.assertNotIn("configs", service)
        self.assertEqual(service["restart"], "no")

    def test_requires_an_absolute_user_owned_private_transfer_directory(self):
        for value, code in (
            (None, "transfer-directory-required"),
            ("transfer", "transfer-directory-absolute"),
            (str(self.fixture.root / "missing-transfer"), "transfer-directory-invalid"),
        ):
            with self.subTest(value=value):
                env = self.fixture.env()
                if value is None:
                    env.pop("ASTER_TRANSFER_DIR")
                else:
                    env["ASTER_TRANSFER_DIR"] = value
                self.assert_rejected(code, env)

        self.fixture.transfer.chmod(0o755)
        self.assert_rejected("transfer-directory-mode-invalid")
        self.fixture.transfer.chmod(0o700)
        link = self.fixture.root / "transfer-link"
        link.symlink_to(self.fixture.transfer, target_is_directory=True)
        env = self.fixture.env()
        env["ASTER_TRANSFER_DIR"] = str(link)
        self.assert_rejected("transfer-directory-invalid", env)

    def test_requires_an_owner_only_valid_plaintext_operator_token_input(self):
        for value, code in (
            (None, "operator-token-required"),
            ("client-token", "operator-token-absolute"),
            (str(self.fixture.root / "missing-token"), "operator-token-invalid"),
        ):
            with self.subTest(value=value):
                env = self.fixture.env()
                if value is None:
                    env.pop("ASTER_TOKEN_INPUT")
                else:
                    env["ASTER_TOKEN_INPUT"] = value
                self.assert_rejected(code, env)

        self.fixture.token_input.chmod(0o644)
        self.assert_rejected("operator-token-mode-invalid")
        self.fixture.token_input.chmod(0o600)

        link = self.fixture.root / "client-token-link"
        link.symlink_to(self.fixture.token_input)
        env = self.fixture.env()
        env["ASTER_TOKEN_INPUT"] = str(link)
        self.assert_rejected("operator-token-invalid", env)

        for value in (
            b"x" * 31,
            b"x" * 32 + b"/",
            b"\xff" * 32,
            b"x" * 259,
        ):
            with self.subTest(size=len(value)):
                self.fixture.token_input.write_bytes(value)
                self.assert_rejected("operator-token-contents-invalid")

    def test_rejects_mutable_or_missing_image_references(self):
        for key, value in (
            ("ASTER_AGENT_IMAGE_DIGEST", "registry.example/aster-agent:latest"),
            ("ASTER_ADMIN_IMAGE_DIGEST", "aster-admin:task5"),
            ("ASTER_AGENT_IMAGE_DIGEST", ""),
            ("ASTER_AGENT_IMAGE_DIGEST", "sha256:" + "A" * 64),
            ("ASTER_ADMIN_IMAGE_DIGEST", "sha256:" + "a" * 63),
            ("ASTER_ADMIN_IMAGE_DIGEST", "aster-admin"),
        ):
            with self.subTest(key=key, value=value):
                env = self.fixture.env()
                env[key] = value
                self.assert_rejected("image-reference-mutable", env)

    def test_accepts_registry_digests_and_immutable_local_image_ids(self):
        self.validate()
        env = self.fixture.env()
        env["ASTER_AGENT_IMAGE_DIGEST"] = LOCAL_AGENT_IMAGE
        env["ASTER_ADMIN_IMAGE_DIGEST"] = LOCAL_ADMIN_IMAGE
        plan = self.validate(env)
        self.assertEqual(plan.agent_image, LOCAL_AGENT_IMAGE)
        self.assertEqual(plan.admin_image, LOCAL_ADMIN_IMAGE)

    def test_requires_pull_policy_never_on_every_service(self):
        self.validate()
        for service in ("preflight", "aster-agent", "verify", "asterctl"):
            for value in (None, "missing", "always"):
                with self.subTest(service=service, value=value):
                    def mutation(model, service=service, value=value):
                        if value is None:
                            model["services"][service].pop("pull_policy")
                        else:
                            model["services"][service]["pull_policy"] = value

                    self.fixture.mutate(mutation)
                    self.assert_rejected("compose-model-semantics-invalid")

    def test_rejects_missing_or_unknown_security_relevant_keys(self):
        for key in ("read_only", "cap_drop", "security_opt", "pids_limit", "tmpfs",
                    "logging", "restart", "stop_signal", "stop_grace_period"):
            with self.subTest(key=key):
                service = "aster-agent"
                self.fixture.mutate(lambda model, key=key, service=service:
                                    model["services"][service].pop(key))
                self.assert_rejected("compose-model-semantics-invalid")
        self.fixture.mutate(lambda model: model["services"]["aster-agent"].update(
            {"unknown_security_control": True}))
        self.assert_rejected("compose-model-semantics-invalid")

    def test_rejects_literal_mutable_service_image_even_with_digest_env(self):
        self.fixture.mutate(lambda model: model["services"]["aster-agent"].update(
            {"image": "ubuntu:latest"}))
        self.assert_rejected("compose-model-semantics-invalid")

    def test_rejects_privileged_admin_cap_host_network_and_mismatched_user(self):
        mutations = (
            lambda model: model["services"]["aster-agent"].update({"privileged": True}),
            lambda model: model["services"]["aster-agent"].update({"cap_add": ["SYS_ADMIN"]}),
            lambda model: model["services"]["aster-agent"].update({"network_mode": "host"}),
            lambda model: model["services"]["aster-agent"].update({"user": "65534:65534"}),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(case=index):
                self.fixture.mutate(mutation)
                self.assert_rejected("compose-model-semantics-invalid")

    def test_rejects_env_file_secret_environment_and_extra_secret_grants(self):
        mutations = (
            lambda model: model["services"]["aster-agent"].update({"env_file": ["secrets.env"]}),
            lambda model: model["services"]["aster-agent"].update(
                {"environment": {"ASTER_CLIENT_TOKEN": TOKEN_CANARY}}),
            lambda model: model["services"]["aster-agent"]["secrets"].append(
                {"source": "evil", "target": "/run/secrets/evil"}),
            lambda model: model["secrets"].update({"evil": {"environment": "TOKEN"}}),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(case=index):
                self.fixture.mutate(mutation)
                self.assert_rejected(
                    "generation-sources-invalid" if index == 3
                    else "compose-model-semantics-invalid"
                )

    def test_rejects_credential_bytes_supplied_in_process_environment(self):
        for key in ("ASTER_CLIENT_TOKEN", "ASTER_MISSION_ACTIVATION",
                    "ASTER_PROVISIONING_BUNDLE"):
            with self.subTest(key=key):
                env = self.fixture.env()
                env[key] = TOKEN_CANARY
                self.assert_rejected("secret-environment-forbidden", env)

    def test_rejects_writable_relative_long_and_short_bind_mounts(self):
        mounts = (
            "./state:/var/lib/aster",
            "/tmp/state:/var/lib/aster:rw",
            "/var/run/docker.sock:/var/run/docker.sock:ro",
            {"type": "bind", "source": "./state", "target": "/var/lib/aster"},
            {"type": "bind", "source": "/tmp/state", "target": "/var/lib/aster", "read_only": False},
            {"type": "bind", "source": "/var/run/docker.sock",
             "target": "/var/run/docker.sock", "read_only": True},
        )
        for mount in mounts:
            with self.subTest(mount=mount):
                self.fixture.mutate(lambda model, mount=mount:
                                    model["services"]["aster-agent"]["volumes"].append(mount))
                self.assert_rejected("compose-model-semantics-invalid")

    def test_rejects_evil_secret_source_with_expected_path_only_in_decoy_extension(self):
        def mutation(model):
            model["secrets"]["aster-client-token"]["file"] = "${EVIL}/token"
            model["x-decoy"] = {
                "file": "${ASTER_CREDENTIAL_GENERATION_DIR:?required}/aster-client-token"
            }
        self.fixture.mutate(mutation)
        self.assert_rejected("generation-sources-invalid")

    def test_rejects_devices_namespaces_extra_capabilities_and_swarm_keys(self):
        mutations = (
            lambda model: model["services"]["aster-agent"].update({"devices": ["/dev/kmsg"]}),
            lambda model: model["services"]["aster-agent"].update({"pid": "host"}),
            lambda model: model["services"]["aster-agent"].update({"ipc": "host"}),
            lambda model: model["services"]["aster-agent"].update({"uts": "host"}),
            lambda model: model["services"]["aster-agent"].update({"cap_add": ["NET_ADMIN"]}),
            lambda model: model["services"]["aster-agent"].update({"deploy": {"replicas": 1}}),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(case=index):
                self.fixture.mutate(mutation)
                self.assert_rejected("compose-model-semantics-invalid")

    def test_rejects_duplicate_keys_alias_merge_and_general_yaml(self):
        malformed = (
            '{"services":{},"services":{},"configs":{},"secrets":{},"volumes":{}}\n',
            "services: &services\n  aster-agent: {}\n",
            "services:\n  aster-agent:\n    <<: *runtime\n",
            "---\nservices: {}\n",
        )
        for source in malformed:
            with self.subTest(source=source):
                self.fixture.compose_path.write_text(source)
                self.assert_rejected("compose-model-noncanonical")


class ScopeReductionTests(DeliveryTestCase):
    def test_module_exposes_plan_only_and_no_docker_execution_api(self):
        for name in (
            "execute", "qualify_execution_host", "OwnedResources",
            "_subprocess_runner", "_run_bounded", "ExecutionError",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(MODULE, name))

    def test_cli_rejects_removed_execution_flags(self):
        cases = (("--execute",), ("--evidence-parent", "/tmp/evidence"))
        for arguments in cases:
            with self.subTest(arguments=arguments):
                with self.assertRaises(SystemExit) as raised:
                    MODULE.main([str(COMPOSE), "--example-plan", *arguments])
                self.assertEqual(raised.exception.code, 2)

    def test_example_plan_ignores_ambient_docker_endpoint_settings(self):
        stdout = io.StringIO()
        ambient = {
            "DOCKER_HOST": "tcp://remote.example:2376",
            "DOCKER_CONTEXT": "production-remote",
            "DOCKER_DEFAULT_PLATFORM": "windows/amd64",
        }
        with mock.patch.dict(MODULE.os.environ, ambient, clear=True), \
                mock.patch.object(MODULE.sys, "stdout", stdout):
            result = MODULE.main([str(COMPOSE), "--example-plan"])
        self.assertEqual(result, 0)
        rendered = json.loads(stdout.getvalue())
        self.assertEqual(rendered["mode"], "plan")
        self.assertEqual(rendered["operations"], ["validate-static-model"])

    def test_mise_keeps_plan_task_and_has_no_compose_smoke_task(self):
        source = MISE.read_text()
        self.assertIn("[tasks.compose-agent-plan]", source)
        self.assertNotIn("[tasks.compose-agent-smoke]", source)
        self.assertNotIn(
            "aster_compose_delivery.py docker/compose-agent/compose.yaml --example-plan --execute",
            source,
        )


class RepositoryPolicyTests(unittest.TestCase):
    def test_blob_read_operator_docs_describe_portable_named_staging(self):
        for path in (
            REPOSITORY / "crates/asterctl/asterctl-blob-read.1",
            REPOSITORY / "crates/aster-agent/README.md",
        ):
            source = path.read_text()
            with self.subTest(path=path):
                self.assertIn("owner-controlled", source)
                self.assertIn("mode-0600", source)
                self.assertIn("best-effort", source)
                self.assertNotIn("O_TMPFILE", source)
                self.assertNotIn("anonymous temporary", source)
                self.assertNotIn("No named partial path exists", source)

    def test_cross_device_runbook_keeps_remote_mesh_override_on_cli_commands(self):
        runbook = (REPOSITORY / "docs/operator-guide.md").read_text()
        cross_device = runbook.split(
            "### Step 7: connect this Docker node to a test device", 1
        )[1].split("### Compose boundaries", 1)[0]
        self.assertNotIn("Use Step 5 above", cross_device)
        self.assertGreaterEqual(
            cross_device.count('-f "$ASTER_REMOTE_MESH_FILE"'),
            8,
        )
        for command in (" publish ", " query ", "blob-publish", "blob-read"):
            with self.subTest(command=command):
                self.assertIn(command, cross_device)

        remote_lifecycle = runbook.split(
            "Remote-mesh lifecycle commands:", 1
        )[1].split("`down` preserves", 1)[0]
        self.assertEqual(
            remote_lifecycle.count('-f "$ASTER_REMOTE_MESH_FILE"'),
            4,
        )
        for command in (
            "up -d --force-recreate aster-agent",
            "run --rm verify",
            "stop -t 40 aster-agent",
            "down",
        ):
            with self.subTest(command=command):
                self.assertIn(command, remote_lifecycle)

    def test_operator_runbook_has_artifact_only_compose_cli_examples(self):
        runbook = (REPOSITORY / "docs/operator-guide.md").read_text()
        required = (
            "compose.yaml",
            "compose.remote-mesh.yaml",
            "ASTER_TRANSFER_DIR",
            "aster_compose_delivery.py",
            "ASTER_ADMIN_IMAGE_DIGEST",
            'chmod 0500 "$ASTER_CREDENTIAL_GENERATION_DIR"',
            'docker compose -f "$ASTER_COMPOSE_FILE" run --rm asterctl',
            " publish ",
            " query ",
            "blob-publish",
            "blob-read",
            "--ttl-ms",
            "sha256sum",
            "up -d --force-recreate aster-agent",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, runbook)
        self.assertNotIn(
            "no supported interactive Event/Blob",
            runbook,
        )
        self.assertNotIn(
            "The scratch image has no shell, `curl`, or `asterctl`.",
            runbook,
        )

    def test_release_artifact_includes_the_daemon_free_validator(self):
        workflow = (REPOSITORY / ".github/workflows/build-compose-images.yml").read_text()
        self.assertIn(
            "cp tools/aster_compose_delivery.py "
            "target/compose-release/aster_compose_delivery.py",
            workflow,
        )
        self.assertIn(
            'validator:{file:"aster_compose_delivery.py",sha256:$validator_sha256}',
            workflow,
        )
        self.assertIn(
            "target/compose-release/aster_compose_delivery.py",
            workflow,
        )

    def test_release_artifact_records_remote_mesh_override_digest(self):
        workflow = (REPOSITORY / ".github/workflows/build-compose-images.yml").read_text()
        self.assertIn(
            "cp docker/compose-agent/compose.remote-mesh.yaml "
            "target/compose-release/compose.remote-mesh.yaml",
            workflow,
        )
        self.assertIn(
            "remote_mesh_digest=$(sha256sum "
            "docker/compose-agent/compose.remote-mesh.yaml",
            workflow,
        )
        self.assertIn(
            'remote_mesh_override:{file:"compose.remote-mesh.yaml",'
            "sha256:$remote_mesh_sha256}",
            workflow,
        )
        self.assertIn(
            "target/compose-release/compose.remote-mesh.yaml",
            workflow,
        )

    def test_admin_artifact_ships_asterctl_with_admin_bound_sbom(self):
        dockerfile = (REPOSITORY / "docker/compose-agent/Dockerfile.admin").read_text()
        workflow = (REPOSITORY / ".github/workflows/build-compose-images.yml").read_text()

        self.assertIn("-p asterctl", dockerfile)
        self.assertIn("--bin asterctl", dockerfile)
        self.assertIn(
            "/out/rootfs/usr/local/bin/asterctl",
            dockerfile,
        )
        self.assertIn(
            "cargo cyclonedx --format json --spec-version 1.5 --describe binaries \\\n"
            "            --manifest-path crates/asterctl/Cargo.toml",
            workflow,
        )
        self.assertIn(
            "bind_sbom target/compose-release/asterctl_bin.cdx.json "
            "asterctl \"$admin_digest\"",
            workflow,
        )
        self.assertIn(
            '"aster-compose-verify_bin.cdx.json","asterctl_bin.cdx.json"',
            workflow,
        )

    def test_runtime_dockerfiles_copy_one_prepared_rootfs(self):
        agent = (REPOSITORY / "docker/compose-agent/Dockerfile.agent").read_text()
        admin = (REPOSITORY / "docker/compose-agent/Dockerfile.admin").read_text()
        MODULE.validate_runtime_dockerfiles(agent, admin)

    def test_runtime_dockerfile_policy_rejects_overlapping_final_copy(self):
        agent = (REPOSITORY / "docker/compose-agent/Dockerfile.agent").read_text()
        admin = (REPOSITORY / "docker/compose-agent/Dockerfile.admin").read_text()
        mutation = agent.replace(
            "COPY --from=build /out/rootfs /",
            "COPY --from=build /out/rootfs /\n"
            "COPY --from=build /out/rootfs/usr/local/bin/aster-agent "
            "/usr/local/bin/aster-agent",
            1,
        )
        with self.assertRaises(MODULE.ValidationError) as raised:
            MODULE.validate_runtime_dockerfiles(mutation, admin)
        self.assertEqual(raised.exception.code, "compose-delivery-policy-invalid")

    def test_checked_in_task8_policy_is_complete_and_daemon_free(self):
        MODULE.validate_repository_policy(REPOSITORY)

    def test_policy_rejects_lifecycle_execution_and_qualified_host_claims(self):
        forbidden = (
            "use docker compose restart for rotation",
            "compose-agent-smoke",
            "--execute",
            "this delivery qualifies a Docker host",
        )
        for value in forbidden:
            with self.subTest(value=value):
                with self.assertRaises(MODULE.ValidationError) as raised:
                    MODULE.validate_policy_texts({"operator": value})
                self.assertEqual(raised.exception.code, "compose-delivery-policy-invalid")

    def test_policy_accepts_required_manual_operations_and_custody_limits(self):
        MODULE.validate_policy_texts({
            "operator": "\n".join((
                "docker build",
                "aster-compose-credential-admin create",
                "UID GID 0400 0600",
                "ASTER_STATE_DIR user-owned no root no sudo",
                "preflight network none no state",
                "docker compose config --format json",
                "docker compose up -d --force-recreate",
                "authenticated credential_generation verify",
                "rotation prior generation still authorized explicit rollback",
                "retention cleanup incident backup recovery encrypted persistent storage",
                "ASTER_AGENT_CONFIG_FILE ASTER_AGENT_CONFIG_SHA256 SHA256SUMS",
                "exactly one Aster agent; not a scaling template; project-qualified",
                "state.tar; logical destruction",
                "file-backed secrets bind mounts uid gid mode ignored",
                "Docker Swarm excluded",
                "no Docker host profile is qualified",
                "rootless Desktop remote context user namespace unqualified",
                "download uname -m sha256sum --check docker image load",
                "docker image inspect local image ID pull_policy never",
            )),
            "release": "\n".join((
                "digest-pinned OCI archives",
                "CycloneDX SBOM dependency license notices",
                "Compose digest architecture source revision builder versions provenance",
                "workflow_dispatch amd64 arm64 Docker-loadable",
                "generated evidence is not included until produced",
            )),
            "ci": "Compose-provider checks are daemon-free",
        })

    def test_release_workflow_is_pinned_bounded_and_nonexecuting(self):
        workflow = (REPOSITORY / ".github/workflows/build-compose-images.yml").read_text()
        ci = (REPOSITORY / ".github/workflows/ci.yml").read_text()
        matrix = (
            "    strategy:\n"
            "      fail-fast: false\n"
            "      matrix:\n"
            "        include:\n"
            "          - arch: amd64\n"
            "            platform: linux/amd64\n"
            "            runner: ubuntu-24.04\n"
            "          - arch: arm64\n"
            "            platform: linux/arm64\n"
            "            runner: ubuntu-24.04-arm\n"
        )
        self.assertEqual(workflow.count(matrix), 1)
        self.assertEqual(workflow.count("runs-on: ${{ matrix.runner }}"), 1)
        self.assertEqual(
            workflow.count(
                "docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069"
            ),
            1,
        )
        self.assertEqual(workflow.count("driver: docker-container"), 1)
        self.assertEqual(
            workflow.count(
                "image=moby/buildkit:buildx-stable-1@sha256:"
                "cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea"
            ),
            1,
        )
        self.assertEqual(
            workflow.count("--builder ${{ steps.buildx.outputs.name }}"), 4
        )
        self.assertEqual(workflow.count("--platform ${{ matrix.platform }}"), 4)
        self.assertEqual(workflow.count("--provenance=mode=max"), 2)
        self.assertEqual(workflow.count("--provenance=false"), 2)
        self.assertEqual(
            workflow.count("--build-arg SOURCE_DATE_EPOCH=946684800"), 4
        )
        self.assertEqual(workflow.count("--describe binaries"), 2)
        self.assertEqual(workflow.count("oci-artifact=true"), 2)
        self.assertEqual(workflow.count("--output type=docker"), 2)
        self.assertEqual(workflow.count("docker image load --input"), 2)
        self.assertEqual(workflow.count("docker image inspect --format '{{.Id}}'"), 2)
        self.assertEqual(workflow.count("--architecture \"${{ matrix.arch }}\""), 4)
        self.assertEqual(workflow.count("--expected-config-digest"), 4)
        self.assertEqual(workflow.count("--result-file"), 2)
        self.assertEqual(workflow.count("compose.remote-mesh.yaml"), 6)
        self.assertEqual(workflow.count("remote_mesh_sha256"), 3)
        self.assertEqual(workflow.count("aster_compose_delivery.py"), 6)
        self.assertEqual(workflow.count("validator_sha256"), 3)
        self.assertIn("aster-compose-image-release/v2", workflow)
        self.assertIn("docker_image_id", workflow)
        self.assertLess(
            workflow.index("Inspect OCI images and retain authenticated results"),
            workflow.index("Load Docker archives and bind exact image IDs"),
        )
        self.assertIn("aster-compose-images-${{ matrix.arch }}-${{ github.sha }}", workflow)
        self.assertNotIn("docker/setup-qemu-action", workflow)
        self.assertNotIn("--push", workflow)
        self.assertNotIn("ghcr.io", workflow)
        MODULE.validate_workflow_policy(workflow, ci)
        for old, new in (
            ("retention-days: 14", "retention-days: 0"),
            ("timeout-minutes: 60", "timeout-minutes: 0"),
            ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
             "actions/checkout@main"),
            ("docker buildx build", "docker run --rm"),
            (
                "docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069",
                "docker/setup-buildx-action@main",
            ),
            ("driver: docker-container", "driver: docker"),
            (
                "image=moby/buildkit:buildx-stable-1@sha256:"
                "cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea",
                "image=moby/buildkit:buildx-stable-1",
            ),
            (
                "--builder ${{ steps.buildx.outputs.name }}",
                "--builder default",
            ),
            ("runner: ubuntu-24.04-arm", "runner: ubuntu-24.04"),
            ("--platform ${{ matrix.platform }}", "--platform linux/amd64"),
            ("SOURCE_DATE_EPOCH=946684800", "SOURCE_DATE_EPOCH=0"),
            ("oci-artifact=true", "oci-artifact=false"),
            ("--output type=docker", "--output type=local"),
            ("docker image load --input", "docker import"),
            ("--expected-config-digest", "--unchecked-config-digest"),
            ("aster-compose-image-release/v2", "aster-compose-image-release/v1"),
            (
                "aster-compose-images-${{ matrix.arch }}-${{ github.sha }}",
                "aster-compose-images-${{ github.sha }}",
            ),
        ):
            with self.subTest(new=new):
                mutation = workflow.replace(old, new, 1)
                digest = hashlib.sha256(mutation.encode()).hexdigest()
                with mock.patch.object(MODULE, "COMPOSE_BUILD_WORKFLOW_SHA256", digest):
                    with self.assertRaises(MODULE.ValidationError):
                        MODULE.validate_workflow_policy(mutation, ci)

    def test_release_workflow_rejects_structural_and_command_obfuscation(self):
        workflow = (REPOSITORY / ".github/workflows/build-compose-images.yml").read_text()
        ci = (REPOSITORY / ".github/workflows/ci.yml").read_text()
        mutations = (
            workflow.replace("permissions:\n  contents: read", "permissions:\n  contents: write", 1),
            workflow.replace("    timeout-minutes: 60", "    permissions:\n      contents: write\n    timeout-minutes: 60", 1),
            workflow + "\n  hidden-job:\n    runs-on: ubuntu-latest\n    steps: []\n",
            workflow.replace("docker buildx build", "command docker run", 1),
            workflow.replace("docker buildx build", "env X=1 docker compose", 1),
            workflow.replace("docker buildx build", "docker exec", 1),
            workflow.replace("docker buildx build", "bash tools/hidden-lifecycle.sh", 1),
            workflow.replace("rustc -Vv", 'bash "$HIDDEN_LIFECYCLE"', 1),
            workflow.replace("--describe binaries", "--describe crate", 1),
            workflow.replace("aster-compose-agent_bin.cdx.json", "aster-compose-credentials.cdx.json", 1),
            workflow.replace("aster:oci-digest", "aster:unbound", 1),
            workflow.replace("all(has_license)", "all(.name)", 1),
            workflow.replace("inspect_aster_compose_oci.py", "missing-inspector.py", 1),
            workflow.replace("credential-canary-scan", "scan-disabled", 1),
            workflow.replace("release-manifest.json", "release-output.json", 1),
            workflow.replace("SHA256SUMS", "CHECKSUMS", 1),
            workflow.replace("agent.example.json", "agent.template.json", 1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(case=index):
                digest = hashlib.sha256(mutation.encode()).hexdigest()
                with mock.patch.object(MODULE, "COMPOSE_BUILD_WORKFLOW_SHA256", digest):
                    with self.assertRaises(MODULE.ValidationError):
                        MODULE.validate_workflow_policy(mutation, ci)

    def test_normal_ci_runs_both_daemon_free_compose_policy_suites(self):
        workflow = (REPOSITORY / ".github/workflows/build-compose-images.yml").read_text()
        ci = (REPOSITORY / ".github/workflows/ci.yml").read_text()
        with self.assertRaises(MODULE.ValidationError):
            MODULE.validate_workflow_policy(
                workflow,
                ci.replace("python3 tools/test_inspect_aster_compose_oci.py", "", 1),
            )
        MODULE.validate_workflow_policy(workflow, ci)

    def test_release_workflow_exact_bytes_reject_all_shell_indirection(self):
        workflow = (REPOSITORY / ".github/workflows/build-compose-images.yml").read_text()
        ci = (REPOSITORY / ".github/workflows/ci.yml").read_text()
        mutations = (
            workflow.replace("rustc -Vv", '"$TOOL" -Vv', 1),
            workflow.replace("rustc -Vv", "eval 'rustc -Vv'", 1),
            workflow.replace("rustc -Vv", "make release-provenance", 1),
            workflow.replace("rustc -Vv", 'tool=$(printf rustc); "$tool" -Vv', 1),
            workflow.replace("rustc -Vv", "env rustc -Vv", 1),
            workflow.replace("rustc -Vv", "id\n            rustc -Vv", 1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(case=index), self.assertRaises(MODULE.ValidationError):
                MODULE.validate_workflow_policy(mutation, ci)


if __name__ == "__main__":
    unittest.main()
