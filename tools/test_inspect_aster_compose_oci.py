#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for static Compose OCI archive inspection."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from typing import Callable


MODULE_PATH = Path(__file__).with_name("inspect_aster_compose_oci.py")
SPEC = importlib.util.spec_from_file_location("inspect_aster_compose_oci", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

AGENT_FILES = {
    "usr/local/bin/aster-agent": b"agent-binary",
    "usr/local/bin/aster-compose-healthcheck": b"health-binary",
    "usr/share/licenses/aster/LICENSE": b"Apache-2.0",
    "usr/share/licenses/aster/THIRD_PARTY_NOTICES.md": b"notices",
}
ADMIN_FILES = {
    "usr/local/bin/aster-compose-credential-admin": b"admin-binary",
    "usr/local/bin/aster-compose-verify": b"verify-binary",
    "usr/share/licenses/aster/LICENSE": b"Apache-2.0",
    "usr/share/licenses/aster/THIRD_PARTY_NOTICES.md": b"notices",
}
DIRECTORIES = (
    "usr",
    "usr/local",
    "usr/local/bin",
    "usr/share",
    "usr/share/licenses",
    "usr/share/licenses/aster",
)
SLSA_V1 = "https://slsa.dev/provenance/v1"
EMPTY_CONFIG_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"
ATTESTATION_ARTIFACT_TYPE = "application/vnd.docker.attestation.manifest.v1+json"


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def layer(
    files: dict[str, bytes],
    extra=None,
    *,
    member_mutator: Callable[[tarfile.TarInfo], None] | None = None,
    extra_directory: str | None = None,
    raw_padding: bytes = b"",
) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name in DIRECTORIES:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            if member_mutator is not None:
                member_mutator(info)
            archive.addfile(info)
        if extra_directory is not None:
            info = tarfile.TarInfo(extra_directory)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            archive.addfile(info)
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.mode = 0o555 if name.startswith("usr/local/bin/") else 0o444
            info.size = len(content)
            if member_mutator is not None:
                member_mutator(info)
            archive.addfile(info, io.BytesIO(content))
        if extra is not None:
            archive.addfile(extra)
    uncompressed = bytearray(raw.getvalue())
    if raw_padding:
        marker = next(iter(files.values()))
        padding_start = uncompressed.index(marker) + len(marker)
        uncompressed[padding_start:padding_start + len(raw_padding)] = raw_padding
    return gzip.compress(bytes(uncompressed), mtime=0)


class OciFixture:
    def __init__(
        self,
        root: Path,
        files: dict[str, bytes],
        *,
        architecture: str = "amd64",
        user: str = "10001:10001",
        extra=None,
        include_attestation: bool = True,
        extra_outer: dict[str, bytes] | None = None,
        extra_directory: str | None = None,
        member_mutator: Callable[[tarfile.TarInfo], None] | None = None,
        raw_padding: bytes = b"",
        config_mutator: Callable[[dict[str, object]], None] | None = None,
        statement_mutator: Callable[[dict[str, object]], None] | None = None,
        attestation_layer_mutator: Callable[[dict[str, object]], None] | None = None,
        attestation_manifest_mutator: Callable[[dict[str, object]], None] | None = None,
        attestation_descriptor_mutator: Callable[[dict[str, object]], None] | None = None,
        duplicate_attestation: bool = False,
        outer_descriptor_mutator: Callable[[dict[str, object]], None] | None = None,
        root_index_mutator: Callable[[dict[str, object]], None] | None = None,
    ):
        self.path = root / f"image-{id(self)}.oci"
        blobs: dict[str, bytes] = {}

        def descriptor(data: bytes, media_type: str) -> dict[str, object]:
            digest = hashlib.sha256(data).hexdigest()
            blobs[digest] = data
            return {"mediaType": media_type, "digest": "sha256:" + digest, "size": len(data)}

        layer_bytes = layer(
            files,
            extra,
            member_mutator=member_mutator,
            extra_directory=extra_directory,
            raw_padding=raw_padding,
        )
        layer_diff_id = "sha256:" + hashlib.sha256(gzip.decompress(layer_bytes)).hexdigest()
        layer_descriptor = descriptor(
            layer_bytes, "application/vnd.oci.image.layer.v1.tar+gzip"
        )
        image_config: dict[str, object] = {
            "User": user,
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "WorkingDir": "/",
        }
        if "usr/local/bin/aster-agent" in files:
            image_config.update({
                "Entrypoint": ["/usr/local/bin/aster-agent"],
                "Healthcheck": {
                    "Test": ["CMD", "/usr/local/bin/aster-compose-healthcheck"],
                    "Interval": 5_000_000_000,
                    "Timeout": 3_000_000_000,
                    "StartPeriod": 5_000_000_000,
                    "Retries": 12,
                },
            })
        if config_mutator is not None:
            config_mutator(image_config)
        config = encoded({
            "architecture": architecture,
            "os": "linux",
            "config": image_config,
            "rootfs": {"type": "layers", "diff_ids": [layer_diff_id]},
        })
        config_descriptor = descriptor(config, "application/vnd.oci.image.config.v1+json")
        self.config_digest = str(config_descriptor["digest"])
        manifest = encoded({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config_descriptor,
            "layers": [layer_descriptor],
        })
        image_descriptor = descriptor(
            manifest, "application/vnd.oci.image.manifest.v1+json"
        )
        image_descriptor["platform"] = {"os": "linux", "architecture": architecture}
        self.architecture = architecture
        self.image_manifest_digest = image_descriptor["digest"]
        manifests = [image_descriptor]
        if include_attestation:
            statement: dict[str, object] = {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{
                    "name": "_",
                    "digest": {"sha256": str(image_descriptor["digest"])[7:]},
                }],
                "predicateType": SLSA_V1,
                "predicate": {"buildDefinition": {"buildType": "test"}},
            }
            if statement_mutator is not None:
                statement_mutator(statement)
            attestation_layer = descriptor(encoded(statement), "application/vnd.in-toto+json")
            attestation_layer["annotations"] = {"in-toto.io/predicate-type": SLSA_V1}
            if attestation_layer_mutator is not None:
                attestation_layer_mutator(attestation_layer)
            empty_config = descriptor(b"{}", EMPTY_CONFIG_MEDIA_TYPE)
            empty_config["data"] = "e30="
            attestation: dict[str, object] = {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "artifactType": ATTESTATION_ARTIFACT_TYPE,
                "config": empty_config,
                "layers": [attestation_layer],
                "subject": {
                    "mediaType": image_descriptor["mediaType"],
                    "digest": image_descriptor["digest"],
                    "size": image_descriptor["size"],
                },
            }
            if attestation_manifest_mutator is not None:
                attestation_manifest_mutator(attestation)
            attestation_descriptor = descriptor(
                encoded(attestation), "application/vnd.oci.image.manifest.v1+json"
            )
            attestation_descriptor["platform"] = {"os": "unknown", "architecture": "unknown"}
            attestation_descriptor["annotations"] = {
                "vnd.docker.reference.type": "attestation-manifest",
                "vnd.docker.reference.digest": image_descriptor["digest"],
            }
            if attestation_descriptor_mutator is not None:
                attestation_descriptor_mutator(attestation_descriptor)
            manifests.append(attestation_descriptor)
            if duplicate_attestation:
                manifests.append(dict(attestation_descriptor))
        inner_index = encoded({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": manifests,
        })
        outer_descriptor = descriptor(
            inner_index, "application/vnd.oci.image.index.v1+json"
        )
        outer_descriptor["annotations"] = {
            "org.opencontainers.image.created": "2026-10-08T12:34:56Z",
        }
        if outer_descriptor_mutator is not None:
            outer_descriptor_mutator(outer_descriptor)
        root_index: dict[str, object] = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [outer_descriptor],
        }
        if root_index_mutator is not None:
            root_index_mutator(root_index)
        index = encoded(root_index)
        self.digest = "sha256:" + hashlib.sha256(inner_index).hexdigest()
        self.wrapper_digest = "sha256:" + hashlib.sha256(index).hexdigest()
        with tarfile.open(self.path, "w") as archive:
            for name, content in {
                "oci-layout": encoded({"imageLayoutVersion": "1.0.0"}),
                "index.json": index,
                **{"blobs/sha256/" + digest: content for digest, content in blobs.items()},
                **(extra_outer or {}),
            }.items():
                info = tarfile.TarInfo(name)
                info.mode = 0o444
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))

    def inspect(
        self,
        profile: str,
        expected_digest: str | None = None,
        *,
        artifacts=(),
    ):
        return MODULE.inspect_oci_archive(
            self.path,
            profile,
            self.architecture,
            expected_digest or self.digest,
            self.config_digest,
            artifacts=artifacts,
        )


class InspectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_accepts_exact_amd64_and_arm64_with_matching_config_digest(self):
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture):
                fixture = OciFixture(
                    self.root, AGENT_FILES, architecture=architecture
                )
                result = MODULE.inspect_oci_archive(
                    fixture.path,
                    "agent",
                    architecture,
                    fixture.digest,
                    fixture.config_digest,
                    artifacts=(),
                )
                self.assertEqual(result.architecture, architecture)
                self.assertEqual(result.config_digest, fixture.config_digest)

    def test_rejects_architecture_and_config_digest_mismatch(self):
        fixture = OciFixture(self.root, AGENT_FILES, architecture="arm64")
        cases = (
            ("amd64", fixture.config_digest),
            ("riscv64", fixture.config_digest),
            ("arm64", "sha256:" + "f" * 64),
        )
        for architecture, config_digest in cases:
            with self.subTest(
                architecture=architecture, config_digest=config_digest
            ), self.assertRaises(MODULE.InspectionError):
                MODULE.inspect_oci_archive(
                    fixture.path,
                    "agent",
                    architecture,
                    fixture.digest,
                    config_digest,
                    artifacts=(),
                )

    def test_cli_writes_authenticated_machine_readable_result(self):
        fixture = OciFixture(self.root, AGENT_FILES, architecture="arm64")
        result_file = self.root / "inspection.json"
        result = MODULE.main([
            "--profile", "agent",
            "--architecture", "arm64",
            "--archive", str(fixture.path),
            "--expected-digest", fixture.digest,
            "--expected-config-digest", fixture.config_digest,
            "--result-file", str(result_file),
        ])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(result_file.read_text()), {
            "architecture": "arm64",
            "config_digest": fixture.config_digest,
            "files": sorted(AGENT_FILES),
            "manifest_digest": fixture.image_manifest_digest,
            "oci_digest": fixture.digest,
            "profile": "agent",
            "schema": "aster-compose-oci-inspection/v1",
        })

    def test_cli_refuses_to_overwrite_result_file(self):
        fixture = OciFixture(self.root, AGENT_FILES)
        result_file = self.root / "inspection.json"
        result_file.write_text("preserve\n")
        result = MODULE.main([
            "--profile", "agent",
            "--architecture", "amd64",
            "--archive", str(fixture.path),
            "--expected-digest", fixture.digest,
            "--expected-config-digest", fixture.config_digest,
            "--result-file", str(result_file),
        ])
        self.assertEqual(result, 1)
        self.assertEqual(result_file.read_text(), "preserve\n")

    def test_accepts_exact_agent_and_admin_scratch_images_and_skips_attestation(self):
        for profile, files in (("agent", AGENT_FILES), ("admin", ADMIN_FILES)):
            with self.subTest(profile=profile):
                fixture = OciFixture(self.root, files)
                result = fixture.inspect(profile, fixture.digest, artifacts=())
                self.assertEqual(result.oci_digest, fixture.digest)
                self.assertEqual(result.manifest_digest, fixture.image_manifest_digest)
                self.assertEqual(result.files, tuple(sorted(files)))

    def test_accepts_exact_buildkit_scratch_defaults(self):
        fixture = OciFixture(
            self.root,
            AGENT_FILES,
            config_mutator=lambda value: value.update({
                "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
                "WorkingDir": "/",
            }),
        )
        result = fixture.inspect("agent", fixture.digest, artifacts=())
        self.assertEqual(result.profile, "agent")

    def test_authenticates_inner_index_digest_not_wrapper_index_hash(self):
        fixture = OciFixture(self.root, AGENT_FILES)
        self.assertNotEqual(fixture.wrapper_digest, fixture.digest)
        result = fixture.inspect("agent", fixture.digest, artifacts=())
        self.assertEqual(result.oci_digest, fixture.digest)
        with self.assertRaises(MODULE.InspectionError):
            fixture.inspect("agent", fixture.wrapper_digest, artifacts=())

    def test_accepts_buildx_root_reference_annotations(self):
        def add_buildx_annotations(value):
            value["annotations"].update({
                "io.containerd.image.name":
                    "docker.io/library/aster-compose-agent:diagnostic",
                "org.opencontainers.image.ref.name": "diagnostic",
            })

        fixture = OciFixture(
            self.root,
            AGENT_FILES,
            outer_descriptor_mutator=add_buildx_annotations,
        )
        result = fixture.inspect("agent", fixture.digest, artifacts=())
        self.assertEqual(result.oci_digest, fixture.digest)

    def test_rejects_malformed_outer_oci_layout_descriptor(self):
        def multiple_descriptors(value):
            value["manifests"].append(dict(value["manifests"][0]))

        def wrong_annotation(value):
            value["annotations"]["unexpected"] = "value"

        cases = (
            OciFixture(
                self.root,
                AGENT_FILES,
                root_index_mutator=lambda value: value.update(
                    {"mediaType": "application/vnd.oci.image.manifest.v1+json"}
                ),
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                root_index_mutator=multiple_descriptors,
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                outer_descriptor_mutator=lambda value: value.update(
                    {"mediaType": "application/vnd.oci.image.manifest.v1+json"}
                ),
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                outer_descriptor_mutator=wrong_annotation,
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                outer_descriptor_mutator=lambda value: value["annotations"].update(
                    {"org.opencontainers.image.ref.name": "latest"}
                ),
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                outer_descriptor_mutator=lambda value: value["annotations"].pop(
                    "org.opencontainers.image.created"
                ),
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                outer_descriptor_mutator=lambda value: value.update(
                    {"digest": "sha256:" + "f" * 64}
                ),
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                outer_descriptor_mutator=lambda value: value.update(
                    {"size": int(value["size"]) + 1}
                ),
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                outer_descriptor_mutator=lambda value: value.update(
                    {"platform": {"os": "linux", "architecture": "amd64"}}
                ),
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                outer_descriptor_mutator=lambda value: value["annotations"].update(
                    {"org.opencontainers.image.created": "not-rfc3339"}
                ),
            ),
        )
        for fixture in cases:
            with self.subTest(digest=fixture.digest), self.assertRaises(
                MODULE.InspectionError
            ):
                fixture.inspect("agent", fixture.digest, artifacts=())

    def test_rejects_wrong_user_extra_file_and_digest(self):
        cases = (
            (OciFixture(self.root, AGENT_FILES, user="0:0"), "agent", None),
            (OciFixture(self.root, {**AGENT_FILES, "bin/sh": b"shell"}), "agent", None),
        )
        for fixture, profile, digest in cases:
            with self.subTest(profile=profile):
                with self.assertRaises(MODULE.InspectionError):
                    fixture.inspect(profile, digest or fixture.digest, artifacts=())
        fixture = OciFixture(self.root, ADMIN_FILES)
        with self.assertRaises(MODULE.InspectionError):
            fixture.inspect("admin", "sha256:" + "f" * 64, artifacts=())

    def test_rejects_symlink_device_whiteout_and_unsafe_path(self):
        extras = []
        symlink = tarfile.TarInfo("usr/local/bin/link")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "/bin/sh"
        extras.append(symlink)
        device = tarfile.TarInfo("dev/tty0")
        device.type = tarfile.CHRTYPE
        extras.append(device)
        whiteout = tarfile.TarInfo("usr/local/bin/.wh.aster-agent")
        whiteout.size = 0
        extras.append(whiteout)
        unsafe = tarfile.TarInfo("../../escape")
        unsafe.size = 0
        extras.append(unsafe)
        for extra in extras:
            with self.subTest(name=extra.name):
                fixture = OciFixture(self.root, AGENT_FILES, extra=extra)
                with self.assertRaises(MODULE.InspectionError):
                    fixture.inspect("agent", fixture.digest, artifacts=())

    def test_rejects_canary_in_decompressed_image_and_retained_artifact(self):
        files = dict(AGENT_FILES)
        files["usr/local/bin/aster-agent"] = b"task6-token-canary-do-not-print"
        fixture = OciFixture(self.root, files)
        with self.assertRaises(MODULE.InspectionError):
            fixture.inspect("agent", fixture.digest, artifacts=())

        clean = OciFixture(self.root, AGENT_FILES)
        artifact = self.root / "metadata.json"
        artifact.write_text("62756e646c652d63616e617279")
        with self.assertRaises(MODULE.InspectionError):
            clean.inspect("agent", clean.digest, artifacts=(artifact,))

    def test_rejects_canary_in_embedded_provenance_attestation(self):
        fixture = OciFixture(
            self.root,
            AGENT_FILES,
            statement_mutator=lambda value: value.update(
                {"predicate": {"secret": "activation-canary"}}
            ),
        )
        with self.assertRaises(MODULE.InspectionError):
            fixture.inspect("agent", fixture.digest, artifacts=())

    def test_rejects_duplicate_key_json(self):
        with self.assertRaises(MODULE.InspectionError):
            MODULE._json(b'{"schemaVersion":2,"schemaVersion":1}')

    def test_requires_one_bound_buildkit_provenance_attestation(self):
        def wrong_reference(value):
            value["annotations"]["vnd.docker.reference.digest"] = "sha256:" + "f" * 64

        def wrong_platform(value):
            value["platform"] = {"os": "linux", "architecture": "amd64"}

        cases = (
            OciFixture(self.root, AGENT_FILES, include_attestation=False),
            OciFixture(self.root, AGENT_FILES, duplicate_attestation=True),
            OciFixture(
                self.root,
                AGENT_FILES,
                attestation_descriptor_mutator=wrong_reference,
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                attestation_descriptor_mutator=wrong_platform,
            ),
        )
        for fixture in cases:
            with self.subTest(digest=fixture.digest):
                with self.assertRaises(MODULE.InspectionError):
                    fixture.inspect("agent", fixture.digest, artifacts=())

    def test_rejects_malformed_buildkit_provenance_artifact(self):
        def bad_subject(value):
            value["subject"]["digest"] = "sha256:" + "e" * 64

        def bad_empty_config(value):
            value["config"]["mediaType"] = "application/json"

        def duplicate_layer(value):
            value["layers"].append(dict(value["layers"][0]))

        def bad_layer_annotation(value):
            value["annotations"]["in-toto.io/predicate-type"] = "https://spdx.dev/Document"

        def bad_statement_subject(value):
            value["subject"][0]["digest"]["sha256"] = "d" * 64

        cases = (
            OciFixture(
                self.root,
                AGENT_FILES,
                attestation_manifest_mutator=lambda value: value.update(
                    {"artifactType": "application/example"}
                ),
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                attestation_manifest_mutator=bad_subject,
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                attestation_manifest_mutator=bad_empty_config,
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                attestation_manifest_mutator=duplicate_layer,
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                attestation_layer_mutator=bad_layer_annotation,
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                statement_mutator=lambda value: value.update({"_type": "example"}),
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                statement_mutator=lambda value: value.update({"predicate": {}}),
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                statement_mutator=bad_statement_subject,
            ),
        )
        for fixture in cases:
            with self.subTest(digest=fixture.digest):
                with self.assertRaises(MODULE.InspectionError):
                    fixture.inspect("agent", fixture.digest, artifacts=())

    def test_accepts_slsa_provenance_v02(self):
        fixture = OciFixture(
            self.root,
            AGENT_FILES,
            statement_mutator=lambda value: value.update({
                "_type": "https://in-toto.io/Statement/v0.1",
                "predicateType": "https://slsa.dev/provenance/v0.2",
            }),
            attestation_layer_mutator=lambda value: value["annotations"].update({
                "in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2"
            }),
        )
        fixture.inspect("agent", fixture.digest, artifacts=())

    def test_scans_tar_stream_and_member_metadata_for_all_known_canaries(self):
        for canary in (
            "compose-admin-token-canary-7f61b8",
            "generation-unit-token-canary",
            "known-secret-canary",
        ):
            artifact = self.root / "retained.txt"
            artifact.write_text(canary)
            fixture = OciFixture(self.root, AGENT_FILES)
            with self.subTest(canary=canary), self.assertRaises(MODULE.InspectionError):
                fixture.inspect("agent", fixture.digest, artifacts=(artifact,))

        fixture = OciFixture(
            self.root,
            AGENT_FILES,
            member_mutator=lambda member: setattr(
                member, "uname", "generation-unit-token-canary"
            ),
        )
        with self.assertRaises(MODULE.InspectionError):
            fixture.inspect("agent", fixture.digest, artifacts=())

        fixture = OciFixture(
            self.root,
            AGENT_FILES,
            raw_padding=b"known-secret-canary",
        )
        with self.assertRaises(MODULE.InspectionError):
            fixture.inspect("agent", fixture.digest, artifacts=())

    def test_rejects_extra_directory_and_nonroot_layer_metadata(self):
        cases = (
            OciFixture(self.root, AGENT_FILES, extra_directory="var/cache"),
            OciFixture(
                self.root,
                AGENT_FILES,
                member_mutator=lambda member: setattr(member, "uid", 10001),
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                member_mutator=lambda member: setattr(member, "gid", 10001),
            ),
            OciFixture(
                self.root,
                AGENT_FILES,
                member_mutator=lambda member: setattr(
                    member, "mode", 0o700 if member.isdir() else member.mode
                ),
            ),
        )
        for fixture in cases:
            with self.subTest(digest=fixture.digest), self.assertRaises(MODULE.InspectionError):
                fixture.inspect("agent", fixture.digest, artifacts=())

    def test_rejects_profile_config_mismatch_and_unexpected_runtime_fields(self):
        cases = [
            (OciFixture(
                self.root,
                AGENT_FILES,
                config_mutator=lambda value: value.update(
                    {"Entrypoint": ["/usr/local/bin/aster-compose-credential-admin"]}
                ),
            ), "agent"),
            (OciFixture(
                self.root,
                AGENT_FILES,
                config_mutator=lambda value: value["Healthcheck"].update(
                    {"Test": ["CMD", "/usr/local/bin/aster-agent"]}
                ),
            ), "agent"),
            (OciFixture(
                self.root,
                ADMIN_FILES,
                config_mutator=lambda value: value.update(
                    {"Entrypoint": ["/usr/local/bin/aster-agent"]}
                ),
            ), "admin"),
        ]
        for key, value in (
            ("Cmd", ["unexpected"]),
            ("Env", ["SECRET=value"]),
            ("Volumes", {"/state": {}}),
            ("ExposedPorts", {"443/tcp": {}}),
            ("WorkingDir", "/tmp"),
            ("Shell", ["/bin/sh", "-c"]),
            ("StopSignal", "SIGKILL"),
        ):
            cases.append((OciFixture(
                self.root,
                AGENT_FILES,
                config_mutator=lambda config, key=key, value=value: config.update(
                    {key: value}
                ),
            ), "agent"))
        for fixture, profile in cases:
            with self.subTest(profile=profile), self.assertRaises(MODULE.InspectionError):
                fixture.inspect(profile, fixture.digest, artifacts=())

    def test_rejects_unreferenced_oci_blob_and_noncanonical_outer_path(self):
        hidden = gzip.compress(b"task6-token-canary-do-not-print", mtime=0)
        fixture = OciFixture(
            self.root,
            AGENT_FILES,
            extra_outer={"blobs/sha256/" + hashlib.sha256(hidden).hexdigest(): hidden},
        )
        with self.assertRaises(MODULE.InspectionError):
            fixture.inspect("agent", fixture.digest, artifacts=())

        fixture = OciFixture(
            self.root,
            AGENT_FILES,
            extra_outer={"unexpected//metadata": b"clean"},
        )
        with self.assertRaises(MODULE.InspectionError):
            fixture.inspect("agent", fixture.digest, artifacts=())


if __name__ == "__main__":
    unittest.main()
