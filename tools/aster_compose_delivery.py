#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Validate Aster's Compose model and emit a deterministic redacted plan."""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from collections.abc import Mapping
from typing import Any


PLAN_SCHEMA = "aster-compose-delivery-plan/v1"
GENERATION_SCHEMA = "aster-compose-secret-generation/v1"
GENERATION_RE = re.compile(r"generation-[0-9a-f]{64}\Z")
REGISTRY_DIGEST_IMAGE_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
LOCAL_IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
PROJECT_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")
MAX_COMPOSE_BYTES = 256 * 1024
MAX_CONFIG_BYTES = 256 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
COMPOSE_BUILD_WORKFLOW_SHA256 = (
    "edad115d636c941bcd1cea12c61467958d82c4499222c4da10b7100526cef423"
)
SETUP_BUILDX_ACTION = (
    "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e"
)
BUILDKIT_IMAGE = (
    "moby/buildkit:buildx-stable-1@sha256:"
    "cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea"
)
GENERATION_FILES = (
    "aster-client-token",
    "aster-mission-activation",
    "aster-provisioning-bundle",
    "manifest.json",
)

POLICY_REQUIRED = {
    "operator": (
        "docker build",
        "aster-compose-credential-admin create",
        "uid", "gid", "0400", "0600",
        "aster_state_dir", "user-owned", "no root", "no sudo",
        "preflight", "network", "no state",
        "docker compose config --format json",
        "docker compose up -d --force-recreate",
        "authenticated", "credential_generation", "verify",
        "rotation", "prior generation", "still authorized", "explicit rollback",
        "retention", "cleanup", "incident", "backup", "recovery",
        "encrypted persistent storage",
        "aster_agent_config_file", "aster_agent_config_sha256", "sha256sums",
        "exactly one aster agent", "not a scaling template", "project-qualified",
        "state.tar", "logical destruction",
        "file-backed secrets", "bind mounts", "uid", "gid", "mode", "ignored",
        "docker swarm", "excluded",
        "no docker host profile is qualified",
        "rootless", "desktop", "remote context", "user namespace", "unqualified",
        "download", "uname -m", "sha256sum --check", "docker image load",
        "docker image inspect", "local image id", "pull_policy", "never",
    ),
    "release": (
        "digest-pinned", "oci archives", "cyclonedx", "sbom", "dependency",
        "license", "notices", "compose digest", "architecture", "source revision",
        "builder versions", "provenance",
        "workflow_dispatch", "amd64", "arm64", "docker-loadable",
        "generated evidence is not included until produced",
    ),
    "ci": ("compose-provider checks are daemon-free",),
}

POLICY_FORBIDDEN = (
    "use docker compose restart for rotation",
    "compose-agent-smoke",
    "--execute",
    "this delivery qualifies a docker host",
)


class ValidationError(ValueError):
    """A fixed, non-sensitive static-profile validation failure."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"compose-delivery validation={code}")


def validate_policy_texts(texts: Mapping[str, str]) -> None:
    """Validate the bounded documentation and release-policy contract."""

    delivery_scope = "\n".join(
        texts.get(section, "") for section in ("operator", "release")
    ).lower()
    if any(value in delivery_scope for value in POLICY_FORBIDDEN):
        raise ValidationError("compose-delivery-policy-invalid")
    for section, required in POLICY_REQUIRED.items():
        source = texts.get(section, "").lower()
        if any(value not in source for value in required):
            raise ValidationError("compose-delivery-policy-invalid")


def validate_workflow_policy(workflow: str, ci: str) -> None:
    """Validate release packaging and the daemon-free normal-CI hook."""

    if hashlib.sha256(workflow.encode()).hexdigest() != COMPOSE_BUILD_WORKFLOW_SHA256:
        raise ValidationError("compose-delivery-policy-invalid")
    if "\r" in workflow or "\t" in workflow:
        raise ValidationError("compose-delivery-policy-invalid")
    if not workflow.startswith('name: "Build: Compose images"\n\non:\n  workflow_dispatch:\n'):
        raise ValidationError("compose-delivery-policy-invalid")
    if len(re.findall(r"(?m)^permissions:$", workflow)) != 1:
        raise ValidationError("compose-delivery-policy-invalid")
    if "permissions:\n  contents: read\n" not in workflow or re.search(
        r"(?m)^    permissions:", workflow
    ):
        raise ValidationError("compose-delivery-policy-invalid")
    concurrency = (
        "concurrency:\n"
        "  group: build-compose-images-${{ github.ref }}\n"
        "  cancel-in-progress: true\n"
    )
    if workflow.count(concurrency) != 1:
        raise ValidationError("compose-delivery-policy-invalid")
    jobs_match = re.search(r"(?ms)^jobs:\n(?P<body>.*)\Z", workflow)
    if jobs_match is None:
        raise ValidationError("compose-delivery-policy-invalid")
    jobs = re.findall(r"(?m)^  ([a-zA-Z0-9_-]+):\s*$", jobs_match.group("body"))
    if jobs != ["package"] or len(re.findall(r"(?m)^    timeout-minutes: 60$", workflow)) != 1:
        raise ValidationError("compose-delivery-policy-invalid")
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
    if workflow.count(matrix) != 1 or workflow.count(
        "runs-on: ${{ matrix.runner }}"
    ) != 1:
        raise ValidationError("compose-delivery-policy-invalid")

    action_uses = re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", workflow)
    if not action_uses or any(
        not re.fullmatch(r"[^@]+@[0-9a-f]{40}", action) for action in action_uses
    ):
        raise ValidationError("compose-delivery-policy-invalid")
    buildx_setup = (
        "      - name: Set up pinned OCI-capable Buildx builder\n"
        "        id: buildx\n"
        f"        uses: {SETUP_BUILDX_ACTION} # v4.3.0\n"
        "        with:\n"
        "          driver: docker-container\n"
        "          driver-opts: |\n"
        f"            image={BUILDKIT_IMAGE}\n"
    )
    if workflow.count(buildx_setup) != 1:
        raise ValidationError("compose-delivery-policy-invalid")

    docker_commands = re.findall(r"\bdocker\s+([a-zA-Z0-9_-]+)", workflow)
    if docker_commands != [
        "buildx",
        "buildx",
        "buildx",
        "buildx",
        "image",
        "image",
        "image",
        "image",
        "version",
        "buildx",
    ]:
        raise ValidationError("compose-delivery-policy-invalid")
    if re.search(r"(?m)^\s+(?:bash|sh)(?:\s|$)", workflow) or re.search(
        r"(?m)^\s+\./", workflow
    ) or re.search(r"(?m)^\s+(?:source|\.)\s+", workflow) or re.search(
        r"\btools/[^\s]+\.sh\b", workflow
    ):
        raise ValidationError("compose-delivery-policy-invalid")
    python_targets = re.findall(r"\bpython3\s+([^\s\\]+)", workflow)
    if any(
        target not in {"-m", "tools/inspect_aster_compose_oci.py"}
        for target in python_targets
    ):
        raise ValidationError("compose-delivery-policy-invalid")

    sboms = (
        "aster-compose-agent_bin.cdx.json",
        "aster-compose-healthcheck_bin.cdx.json",
        "aster-compose-credential-admin_bin.cdx.json",
        "aster-compose-verify_bin.cdx.json",
    )
    required = (
        "--describe binaries",
        "--builder ${{ steps.buildx.outputs.name }}",
        "--platform ${{ matrix.platform }}",
        "--provenance=mode=max",
        "--provenance=false",
        "--build-arg SOURCE_DATE_EPOCH=946684800",
        "--output type=oci",
        "--output type=docker",
        "oci-artifact=true",
        '"name":"aster:oci-digest"',
        '"name":"aster:architecture"',
        "all(has_license)",
        "cdx-ev validate",
        "docker image load --input",
        "docker image inspect --format '{{.Id}}'",
        "aster-compose-image-release/v2",
        "oci_index_digest",
        "manifest_digest",
        "config_digest",
        "docker_image_id",
        "transport_tag",
        "tar -xOf",
        "release-manifest.json",
        "SHA256SUMS",
        "agent.example.json",
        "credential-canary-scan",
        "python3 tools/inspect_aster_compose_oci.py",
        "--profile agent",
        "--profile admin",
        '--architecture "${{ matrix.arch }}"',
        "--expected-config-digest",
        "--result-file",
        "aster-compose-agent-${{ matrix.arch }}.oci",
        "aster-compose-agent-${{ matrix.arch }}.docker.tar",
        "aster-compose-admin-${{ matrix.arch }}.oci",
        "aster-compose-admin-${{ matrix.arch }}.docker.tar",
        "aster-compose-images-${{ matrix.arch }}-${{ github.sha }}",
        "retention-days: 14",
    )
    if any(value not in workflow for value in (*required, *sboms)):
        raise ValidationError("compose-delivery-policy-invalid")
    if "aster-compose-credentials.cdx.json" in workflow:
        raise ValidationError("compose-delivery-policy-invalid")
    if any(workflow.count(sbom) < 3 for sbom in sboms):
        raise ValidationError("compose-delivery-policy-invalid")
    if any(value in workflow for value in (
        "docker/setup-qemu-action", "--push", "ghcr.io", "type=registry"
    )):
        raise ValidationError("compose-delivery-policy-invalid")
    if workflow.count("python3 tools/inspect_aster_compose_oci.py") != 4:
        raise ValidationError("compose-delivery-policy-invalid")
    if (
        workflow.count("--builder ${{ steps.buildx.outputs.name }}") != 4
        or workflow.count("--platform ${{ matrix.platform }}") != 4
        or workflow.count("--provenance=mode=max") != 2
        or workflow.count("--provenance=false") != 2
        or workflow.count("--build-arg SOURCE_DATE_EPOCH=946684800") != 4
        or workflow.count("oci-artifact=true") != 2
        or workflow.count("--output type=docker") != 2
        or workflow.count("docker image load --input") != 2
        or workflow.count("docker image inspect --format '{{.Id}}'") != 2
        or workflow.count('--architecture "${{ matrix.arch }}"') != 4
        or workflow.count("--expected-config-digest") != 4
        or workflow.count("--result-file") != 2
        or workflow.count("tar -xOf") != 2
        or workflow.count("aster-compose-image-release/v2") != 2
    ):
        raise ValidationError("compose-delivery-policy-invalid")
    if workflow.count("release-manifest.json") != 6 or workflow.count("SHA256SUMS") != 3:
        raise ValidationError("compose-delivery-policy-invalid")
    if workflow.count("agent.example.json") != 5:
        raise ValidationError("compose-delivery-policy-invalid")
    if (
        "Validate Compose-provider delivery policy without Docker" not in ci
        or "python3 tools/test_aster_compose_delivery.py" not in ci
        or "python3 tools/test_inspect_aster_compose_oci.py" not in ci
    ):
        raise ValidationError("compose-delivery-policy-invalid")


def validate_runtime_dockerfiles(agent: str, admin: str) -> None:
    """Require one exact, pre-modeled scratch rootfs layer per runtime image."""

    profiles = (
        (agent, ("aster-agent", "aster-compose-healthcheck")),
        (admin, ("aster-compose-credential-admin", "aster-compose-verify")),
    )
    for source, binaries in profiles:
        if "\r" in source or "\t" in source:
            raise ValidationError("compose-delivery-policy-invalid")
        stages = source.split("FROM scratch AS runtime\n")
        if len(stages) != 2:
            raise ValidationError("compose-delivery-policy-invalid")
        build, runtime = stages
        logical_build = " ".join(re.sub(r"\\\n\s*", " ", build).split())
        copy_lines = re.findall(r"(?m)^COPY .+$", runtime)
        if copy_lines != ["COPY --from=build /out/rootfs /"]:
            raise ValidationError("compose-delivery-policy-invalid")
        required = (
            "COPY LICENSE THIRD_PARTY_NOTICES.md ./",
            "install -d -m 0755 /out/rootfs/usr/local/bin "
            "/out/rootfs/usr/share/licenses/aster",
            "install -m 0444 LICENSE /out/rootfs/usr/share/licenses/aster/LICENSE",
            "install -m 0444 THIRD_PARTY_NOTICES.md "
            "/out/rootfs/usr/share/licenses/aster/THIRD_PARTY_NOTICES.md",
            *(f"/out/rootfs/usr/local/bin/{binary}" for binary in binaries),
        )
        if any(value not in logical_build for value in required):
            raise ValidationError("compose-delivery-policy-invalid")
        if logical_build.count("install -m 0555") != len(binaries):
            raise ValidationError("compose-delivery-policy-invalid")


def validate_repository_policy(repository: Path) -> None:
    """Check the checked-in Task 8 policy without invoking Docker."""

    paths = {
        "operator": (
            "docs/release/docker-compose.md",
            "docs/reference/aster-agent-config-v2.md",
            "docs/decisions/0044-compose-file-secret-provider.md",
            "docker/compose-agent/README.md",
        ),
        "release": (
            ".github/workflows/build-compose-images.yml",
            "docs/release/docker-compose.md",
        ),
        "ci": (".github/workflows/ci.yml", "docs/validation/ci.md"),
    }
    texts: dict[str, str] = {}
    try:
        for section, names in paths.items():
            texts[section] = "\n".join((repository / name).read_text() for name in names)
    except OSError as error:
        raise ValidationError("compose-delivery-policy-invalid") from error
    validate_policy_texts(texts)
    validate_workflow_policy(
        (repository / ".github/workflows/build-compose-images.yml").read_text(),
        (repository / ".github/workflows/ci.yml").read_text(),
    )
    validate_runtime_dockerfiles(
        (repository / "docker/compose-agent/Dockerfile.agent").read_text(),
        (repository / "docker/compose-agent/Dockerfile.admin").read_text(),
    )


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class GenerationSnapshot:
    directory: FileIdentity
    files: tuple[tuple[str, FileIdentity], ...]


@dataclass(frozen=True)
class DeliveryPlan:
    compose_sha256: str
    config_sha256: str
    uid: int
    gid: int
    agent_image: str
    admin_image: str
    project_name: str

    def render(self) -> str:
        public = {
            "admin_image": self.admin_image,
            "agent_image": self.agent_image,
            "compose_sha256": self.compose_sha256,
            "config_sha256": self.config_sha256,
            "credential_generation": "<redacted>",
            "gid": self.gid,
            "mode": "plan",
            "operations": ["validate-static-model"],
            "project_name": self.project_name,
            "schema": PLAN_SCHEMA,
            "uid": self.uid,
        }
        return json.dumps(public, sort_keys=True, separators=(",", ":")) + "\n"


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _strict_json(raw: bytes, error_code: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValidationError(error_code) from error


def _runtime_security() -> dict[str, Any]:
    return {
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
        "logging": {
            "driver": "json-file",
            "options": {"max-size": "5m", "max-file": "3"},
        },
    }


def _expected_compose_model() -> dict[str, Any]:
    runtime = _runtime_security()
    secrets = [
        {"source": "aster-client-token", "target": "/run/secrets/aster-client-token"},
        {"source": "aster-mission-activation", "target": "/run/secrets/aster-mission-activation"},
        {"source": "aster-provisioning-bundle", "target": "/run/secrets/aster-provisioning-bundle"},
    ]
    config = [{"source": "aster-agent-config", "target": "/etc/aster/agent.json", "mode": 292}]
    config_digest = {
        "ASTER_AGENT_CONFIG_SHA256": "${ASTER_AGENT_CONFIG_SHA256:?required}"
    }
    state_bind = [{
        "type": "bind",
        "source": "${ASTER_STATE_DIR:?required}",
        "target": "/var/lib/aster",
    }]
    return {
        "x-aster-metadata": {
            "copyright": "Copyright 2026 Defense Unicorns, Inc.",
            "license": "SPDX-License-Identifier: Apache-2.0",
            "qualified_source": "canonical-json-form-yaml/v1",
        },
        "services": {
            "preflight": {
                **copy.deepcopy(runtime),
                "image": "${ASTER_AGENT_IMAGE_DIGEST:?required}",
                "pull_policy": "never",
                "environment": copy.deepcopy(config_digest),
                "network_mode": "none",
                "command": ["--check-config", "/etc/aster/agent.json"],
                "configs": copy.deepcopy(config),
                "secrets": copy.deepcopy(secrets),
            },
            "aster-agent": {
                **copy.deepcopy(runtime),
                "image": "${ASTER_AGENT_IMAGE_DIGEST:?required}",
                "pull_policy": "never",
                "environment": copy.deepcopy(config_digest),
                "command": ["--config", "/etc/aster/agent.json"],
                "configs": copy.deepcopy(config),
                "secrets": copy.deepcopy(secrets),
                "volumes": state_bind,
                "expose": ["8183/udp"],
                "stop_signal": "SIGTERM",
                "stop_grace_period": "40s",
                "restart": "on-failure:3",
                "healthcheck": {
                    "test": ["CMD", "/usr/local/bin/aster-compose-healthcheck"],
                    "interval": "5s",
                    "timeout": "3s",
                    "retries": 12,
                    "start_period": "5s",
                },
                "depends_on": {
                    "preflight": {"condition": "service_completed_successfully"},
                },
            },
            "verify": {
                **copy.deepcopy(runtime),
                "image": "${ASTER_ADMIN_IMAGE_DIGEST:?required}",
                "pull_policy": "never",
                "network_mode": "service:aster-agent",
                "command": ["/usr/local/bin/aster-compose-verify"],
                "configs": copy.deepcopy(config),
                "secrets": [copy.deepcopy(secrets[0])],
                "volumes": [{
                    "type": "bind",
                    "source": "${ASTER_CREDENTIAL_GENERATION_DIR:?required}/manifest.json",
                    "target": "/run/aster-generation/manifest.json",
                    "read_only": True,
                }],
                "depends_on": {"aster-agent": {"condition": "service_healthy"}},
            },
        },
        "configs": {
            "aster-agent-config": {"file": "${ASTER_AGENT_CONFIG_FILE:?required}"}
        },
        "secrets": {
            "aster-client-token": {
                "file": "${ASTER_CREDENTIAL_GENERATION_DIR:?required}/aster-client-token"
            },
            "aster-mission-activation": {
                "file": "${ASTER_CREDENTIAL_GENERATION_DIR:?required}/aster-mission-activation"
            },
            "aster-provisioning-bundle": {
                "file": "${ASTER_CREDENTIAL_GENERATION_DIR:?required}/aster-provisioning-bundle"
            },
        },
    }


def _load_compose_model(raw: bytes) -> dict[str, Any]:
    model = _strict_json(raw, "compose-model-noncanonical")
    if not isinstance(model, dict) or raw != _canonical_json(model):
        raise ValidationError("compose-model-noncanonical")
    expected_sources = {
        "aster-client-token": {
            "file": "${ASTER_CREDENTIAL_GENERATION_DIR:?required}/aster-client-token"
        },
        "aster-mission-activation": {
            "file": "${ASTER_CREDENTIAL_GENERATION_DIR:?required}/aster-mission-activation"
        },
        "aster-provisioning-bundle": {
            "file": "${ASTER_CREDENTIAL_GENERATION_DIR:?required}/aster-provisioning-bundle"
        },
    }
    if model.get("secrets") != expected_sources:
        raise ValidationError("generation-sources-invalid")
    if model != _expected_compose_model():
        raise ValidationError("compose-model-semantics-invalid")
    return model


def _parse_identity(value: str | None) -> int:
    if value is None or not re.fullmatch(r"[0-9]+", value):
        raise ValidationError("runtime-identity-invalid")
    number = int(value)
    if number == 0 or number > 2**31 - 1:
        raise ValidationError("runtime-identity-invalid")
    return number


def _immutable_image_reference(value: str) -> bool:
    return bool(
        REGISTRY_DIGEST_IMAGE_RE.fullmatch(value)
        or LOCAL_IMAGE_ID_RE.fullmatch(value)
    )


def _capture_state_directory(raw_path: str | None, uid: int, gid: int) -> None:
    if not raw_path:
        raise ValidationError("state-directory-required")
    supplied = Path(raw_path)
    if not supplied.is_absolute():
        raise ValidationError("state-directory-absolute")
    try:
        lexical = supplied.lstat()
        resolved = supplied.resolve(strict=True)
    except OSError as error:
        raise ValidationError("state-directory-invalid") from error
    if stat.S_ISLNK(lexical.st_mode) or resolved != supplied or not stat.S_ISDIR(lexical.st_mode):
        raise ValidationError("state-directory-invalid")
    if lexical.st_uid != uid or lexical.st_gid != gid:
        raise ValidationError("state-directory-ownership-invalid")
    if stat.S_IMODE(lexical.st_mode) != 0o700:
        raise ValidationError("state-directory-mode-invalid")


def _identity(metadata: os.stat_result) -> FileIdentity:
    return FileIdentity(
        metadata.st_dev, metadata.st_ino, stat.S_IMODE(metadata.st_mode),
        metadata.st_uid, metadata.st_gid, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _read_fd_bounded(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > limit:
        raise ValidationError("generation-files-invalid")
    return data


def _capture_config(raw_path: str | None) -> str:
    if not raw_path:
        raise ValidationError("config-file-required")
    path = Path(raw_path)
    if not path.is_absolute():
        raise ValidationError("config-file-absolute")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_size <= 0
                or before.st_size > MAX_CONFIG_BYTES
            ):
                raise ValidationError("config-file-invalid")
            chunks: list[bytes] = []
            remaining = MAX_CONFIG_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            if len(raw) > MAX_CONFIG_BYTES or _identity(before) != _identity(after):
                raise ValidationError("config-file-invalid")
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ValidationError("config-file-invalid") from error
    config = _strict_json(raw, "config-file-invalid")
    if not isinstance(config, dict) or config.get("schema_version") != 2:
        raise ValidationError("config-file-invalid")
    return hashlib.sha256(raw).hexdigest()


def _capture_generation(raw_path: str | None, uid: int, gid: int) -> tuple[Path, GenerationSnapshot]:
    if not raw_path:
        raise ValidationError("generation-directory-required")
    supplied = Path(raw_path)
    if not supplied.is_absolute():
        raise ValidationError("generation-directory-absolute")
    try:
        lexical = supplied.lstat()
        resolved = supplied.resolve(strict=True)
    except OSError as error:
        raise ValidationError("generation-directory-invalid") from error
    if stat.S_ISLNK(lexical.st_mode) or resolved != supplied or not GENERATION_RE.fullmatch(resolved.name):
        raise ValidationError("generation-directory-immutable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(resolved, flags)
    except OSError as error:
        raise ValidationError("generation-directory-invalid") from error
    try:
        directory_before = os.fstat(directory_fd)
        if (not stat.S_ISDIR(directory_before.st_mode)
                or directory_before.st_uid != uid or directory_before.st_gid != gid):
            raise ValidationError("generation-ownership-invalid")
        if stat.S_IMODE(directory_before.st_mode) != 0o500:
            raise ValidationError("generation-directory-mode-invalid")
        if set(os.listdir(directory_fd)) != set(GENERATION_FILES):
            raise ValidationError("generation-files-invalid")
        identities: list[tuple[str, FileIdentity]] = []
        manifest_bytes = None
        for name in GENERATION_FILES:
            file_flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                file_flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(name, file_flags, dir_fd=directory_fd)
            except OSError as error:
                raise ValidationError("generation-files-invalid") from error
            try:
                before = os.fstat(descriptor)
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                        or before.st_uid != uid or before.st_gid != gid
                        or stat.S_IMODE(before.st_mode) not in (0o400, 0o600)):
                    raise ValidationError("generation-files-invalid")
                if name == "manifest.json":
                    manifest_bytes = _read_fd_bounded(descriptor, MAX_MANIFEST_BYTES)
                after = os.fstat(descriptor)
                if _identity(before) != _identity(after):
                    raise ValidationError("generation-files-unstable")
                identities.append((name, _identity(after)))
            finally:
                os.close(descriptor)
        directory_after = os.fstat(directory_fd)
        if _identity(directory_before) != _identity(directory_after):
            raise ValidationError("generation-files-unstable")
    except OSError as error:
        raise ValidationError("generation-files-invalid") from error
    finally:
        os.close(directory_fd)
    manifest = _strict_json(manifest_bytes or b"", "generation-files-invalid")
    if not isinstance(manifest, dict) or manifest.get("schema") != GENERATION_SCHEMA:
        raise ValidationError("generation-files-invalid")
    return resolved, GenerationSnapshot(_identity(directory_after), tuple(identities))


def build_plan(compose_path: Path, environment: Mapping[str, str]) -> DeliveryPlan:
    """Validate public inputs and return a deterministic daemon-free plan."""

    if any(environment.get(key) for key in (
        "ASTER_CLIENT_TOKEN", "ASTER_MISSION_ACTIVATION", "ASTER_PROVISIONING_BUNDLE"
    )):
        raise ValidationError("secret-environment-forbidden")
    project_name = environment.get("COMPOSE_PROJECT_NAME", "")
    if not PROJECT_NAME_RE.fullmatch(project_name):
        raise ValidationError("project-name-invalid")
    config_sha256 = _capture_config(environment.get("ASTER_AGENT_CONFIG_FILE"))
    supplied_config_sha256 = environment.get("ASTER_AGENT_CONFIG_SHA256")
    if supplied_config_sha256 is None:
        raise ValidationError("config-digest-required")
    if not re.fullmatch(r"[0-9a-f]{64}", supplied_config_sha256):
        raise ValidationError("config-digest-invalid")
    if supplied_config_sha256 != config_sha256:
        raise ValidationError("config-digest-mismatch")
    uid = _parse_identity(environment.get("ASTER_UID"))
    gid = _parse_identity(environment.get("ASTER_GID"))
    _capture_generation(
        environment.get("ASTER_CREDENTIAL_GENERATION_DIR"), uid, gid,
    )
    _capture_state_directory(environment.get("ASTER_STATE_DIR"), uid, gid)
    agent_image = environment.get("ASTER_AGENT_IMAGE_DIGEST", "")
    admin_image = environment.get("ASTER_ADMIN_IMAGE_DIGEST", "")
    if not _immutable_image_reference(agent_image) or not _immutable_image_reference(
        admin_image
    ):
        raise ValidationError("image-reference-mutable")
    try:
        resolved_compose = compose_path.resolve(strict=True)
        raw = resolved_compose.read_bytes()
    except OSError as error:
        raise ValidationError("compose-model-unavailable") from error
    if len(raw) > MAX_COMPOSE_BYTES:
        raise ValidationError("compose-model-noncanonical")
    _load_compose_model(raw)
    return DeliveryPlan(
        hashlib.sha256(raw).hexdigest(), config_sha256, uid, gid,
        agent_image, admin_image, project_name,
    )


def _example_environment() -> tuple[tempfile.TemporaryDirectory[str], dict[str, str]]:
    temporary = tempfile.TemporaryDirectory()
    generation = Path(temporary.name) / ("generation-" + "0" * 64)
    generation.mkdir(mode=0o700)
    for name in GENERATION_FILES[:-1]:
        (generation / name).write_bytes(("non-secret-example-" + name).encode())
        (generation / name).chmod(0o600)
    (generation / "manifest.json").write_text(json.dumps({"schema": GENERATION_SCHEMA}) + "\n")
    (generation / "manifest.json").chmod(0o600)
    generation.chmod(0o500)
    state = Path(temporary.name) / "state"
    state.mkdir(mode=0o700)
    uid = os.getuid() or 65534
    gid = os.getgid() or 65534
    if os.getuid() == 0:
        os.chown(generation, uid, gid)
        for name in GENERATION_FILES:
            os.chown(generation / name, uid, gid)
    environment = {
        "COMPOSE_PROJECT_NAME": "aster-example",
        "ASTER_AGENT_CONFIG_FILE": str(
            Path(__file__).resolve().parents[1]
            / "docker/compose-agent/agent.example.json"
        ),
        "ASTER_UID": str(uid),
        "ASTER_GID": str(gid),
        "ASTER_AGENT_IMAGE_DIGEST": "example.invalid/aster-agent@sha256:" + "1" * 64,
        "ASTER_ADMIN_IMAGE_DIGEST": "example.invalid/aster-admin@sha256:" + "2" * 64,
        "ASTER_CREDENTIAL_GENERATION_DIR": str(generation),
        "ASTER_STATE_DIR": str(state),
    }
    environment["ASTER_AGENT_CONFIG_SHA256"] = hashlib.sha256(
        Path(environment["ASTER_AGENT_CONFIG_FILE"]).read_bytes()
    ).hexdigest()
    return temporary, environment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compose", type=Path)
    parser.add_argument("--example-plan", action="store_true")
    args = parser.parse_args(argv)
    example = None
    try:
        if args.example_plan:
            example, environment = _example_environment()
        else:
            environment = dict(os.environ)
        plan = build_plan(args.compose, environment)
        sys.stdout.write(plan.render())
        return 0
    except ValidationError as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        if example is not None:
            Path(example.name).chmod(0o700)
            for child in Path(example.name).glob("generation-*"):
                child.chmod(0o700)
            example.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
