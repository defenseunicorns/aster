#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Statically inspect one Aster Compose OCI archive without running it."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from typing import Any, Iterable


MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_LAYER_BYTES = 512 * 1024 * 1024
MAX_ROOTFS_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_OUTER_MEMBERS = 512
MAX_LAYER_MEMBERS = 256
MAX_ARTIFACTS = 64
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
RFC3339_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
IMAGE_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
IMAGE_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
EMPTY_CONFIG_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"
ATTESTATION_ARTIFACT_TYPE = "application/vnd.docker.attestation.manifest.v1+json"
IN_TOTO_MEDIA_TYPE = "application/vnd.in-toto+json"
SLSA_STATEMENTS = {
    "https://slsa.dev/provenance/v1": "https://in-toto.io/Statement/v1",
    "https://slsa.dev/provenance/v0.2": "https://in-toto.io/Statement/v0.1",
}
LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
}
EXPECTED_USER = "10001:10001"
SUPPORTED_ARCHITECTURES = ("amd64", "arm64")
EXPECTED_DIRECTORIES = {
    "usr": 0o755,
    "usr/local": 0o755,
    "usr/local/bin": 0o755,
    "usr/share": 0o755,
    "usr/share/licenses": 0o755,
    "usr/share/licenses/aster": 0o755,
}
EXPECTED_FILES = {
    "agent": {
        "usr/local/bin/aster-agent": 0o555,
        "usr/local/bin/aster-compose-healthcheck": 0o555,
        "usr/share/licenses/aster/LICENSE": 0o444,
        "usr/share/licenses/aster/THIRD_PARTY_NOTICES.md": 0o444,
    },
    "admin": {
        "usr/local/bin/aster-compose-credential-admin": 0o555,
        "usr/local/bin/aster-compose-verify": 0o555,
        "usr/share/licenses/aster/LICENSE": 0o444,
        "usr/share/licenses/aster/THIRD_PARTY_NOTICES.md": 0o444,
    },
}
CANARIES = (
    b"task6-token-canary-do-not-print",
    b"activation-canary",
    b"bundle-canary",
    b"compose-admin-token-canary-7f61b8",
    b"generation-unit-token-canary",
    b"known-secret-canary",
)
EXPECTED_CONFIG = {
    "agent": {
        "User": EXPECTED_USER,
        "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "Entrypoint": ["/usr/local/bin/aster-agent"],
        "WorkingDir": "/",
        "Healthcheck": {
            "Test": ["CMD", "/usr/local/bin/aster-compose-healthcheck"],
            "Interval": 5_000_000_000,
            "Timeout": 3_000_000_000,
            "StartPeriod": 5_000_000_000,
            "Retries": 12,
        },
    },
    "admin": {
        "User": EXPECTED_USER,
        "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "WorkingDir": "/",
    },
}


class InspectionError(ValueError):
    """A fixed static-inspection failure."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"compose-oci inspection={code}")


@dataclass(frozen=True)
class InspectionResult:
    oci_digest: str
    manifest_digest: str
    config_digest: str
    architecture: str
    profile: str
    files: tuple[str, ...]


def _canary_forms() -> tuple[bytes, ...]:
    forms: set[bytes] = set()
    for canary in CANARIES:
        forms.update((
            canary,
            canary.hex().encode(),
            canary.hex().upper().encode(),
            base64.b64encode(canary),
            base64.urlsafe_b64encode(canary),
            base64.urlsafe_b64encode(canary).rstrip(b"="),
        ))
    return tuple(sorted(forms))


CANARY_FORMS = _canary_forms()


def _scan(data: bytes) -> None:
    lowered = data.lower()
    if any(form.lower() in lowered for form in CANARY_FORMS):
        raise InspectionError("credential-canary-found")


def _json(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_JSON_BYTES:
        raise InspectionError("json-invalid")
    try:
        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    raise InspectionError("json-invalid")
                result[key] = item
            return result

        value = json.loads(data, object_pairs_hook=reject_duplicates)
    except InspectionError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InspectionError("json-invalid") from error
    if not isinstance(value, dict):
        raise InspectionError("json-invalid")
    return value


def _safe_name(name: str) -> str:
    if not name or "\0" in name or name.startswith("/"):
        raise InspectionError("archive-path-invalid")
    path = PurePosixPath(name)
    if str(path) != name or any(part in ("", ".", "..") for part in path.parts):
        raise InspectionError("archive-path-invalid")
    return str(path)


def _read_outer_member(
    archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo], name: str, limit: int
) -> bytes:
    member = members.get(name)
    if member is None or not member.isfile() or member.size > limit:
        raise InspectionError("oci-layout-invalid")
    extracted = archive.extractfile(member)
    if extracted is None:
        raise InspectionError("oci-layout-invalid")
    data = extracted.read(limit + 1)
    if len(data) != member.size or len(data) > limit:
        raise InspectionError("oci-layout-invalid")
    return data


def _descriptor_blob(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    descriptor: Any,
    limit: int,
    referenced: set[str],
) -> bytes:
    if not isinstance(descriptor, dict):
        raise InspectionError("descriptor-invalid")
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise InspectionError("descriptor-invalid")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size > limit:
        raise InspectionError("descriptor-invalid")
    blob_name = "blobs/sha256/" + digest[7:]
    data = _read_outer_member(archive, members, blob_name, limit)
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest[7:]:
        raise InspectionError("descriptor-invalid")
    referenced.add(blob_name)
    return data


def _valid_rfc3339(value: object) -> bool:
    if not isinstance(value, str) or not RFC3339_RE.fullmatch(value):
        return False
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _load_inner_index(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    root_index: dict[str, Any],
    expected_digest: str,
    referenced: set[str],
) -> dict[str, Any]:
    if (
        set(root_index) != {"schemaVersion", "mediaType", "manifests"}
        or root_index.get("schemaVersion") != 2
        or root_index.get("mediaType") != IMAGE_INDEX_MEDIA_TYPE
    ):
        raise InspectionError("oci-layout-invalid")
    manifests = root_index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise InspectionError("oci-layout-invalid")
    descriptor = manifests[0]
    if not isinstance(descriptor, dict) or set(descriptor) != {
        "mediaType", "digest", "size", "annotations"
    }:
        raise InspectionError("oci-layout-invalid")
    if (
        descriptor.get("mediaType") != IMAGE_INDEX_MEDIA_TYPE
        or descriptor.get("digest") != expected_digest
        or "platform" in descriptor
    ):
        raise InspectionError("image-digest-mismatch")
    annotations = descriptor.get("annotations")
    if not isinstance(annotations, dict):
        raise InspectionError("oci-layout-invalid")
    allowed_annotations = {
        "io.containerd.image.name",
        "org.opencontainers.image.created",
        "org.opencontainers.image.ref.name",
    }
    if (
        not set(annotations).issubset(allowed_annotations)
        or "org.opencontainers.image.created" not in annotations
        or not _valid_rfc3339(annotations.get("org.opencontainers.image.created"))
    ):
        raise InspectionError("oci-layout-invalid")
    image_name = annotations.get("io.containerd.image.name")
    reference_name = annotations.get("org.opencontainers.image.ref.name")
    if (image_name is None) != (reference_name is None):
        raise InspectionError("oci-layout-invalid")
    if image_name is not None and (
        not isinstance(image_name, str)
        or not isinstance(reference_name, str)
        or not image_name
        or not reference_name
        or len(image_name) > 1024
        or len(reference_name) > 128
        or any(character.isspace() or ord(character) < 0x20 for character in image_name)
        or any(character.isspace() or ord(character) < 0x20 for character in reference_name)
        or not image_name.endswith(":" + reference_name)
    ):
        raise InspectionError("oci-layout-invalid")

    inner_bytes = _descriptor_blob(
        archive, members, descriptor, MAX_JSON_BYTES, referenced
    )
    _scan(inner_bytes)
    inner = _json(inner_bytes)
    if (
        set(inner) != {"schemaVersion", "mediaType", "manifests"}
        or inner.get("schemaVersion") != 2
        or inner.get("mediaType") != IMAGE_INDEX_MEDIA_TYPE
    ):
        raise InspectionError("image-manifest-invalid")
    return inner


def _descriptor_core(descriptor: dict[str, Any]) -> dict[str, Any]:
    return {
        "mediaType": descriptor.get("mediaType"),
        "digest": descriptor.get("digest"),
        "size": descriptor.get("size"),
    }


def _select_descriptors(
    index: dict[str, Any], architecture: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 2:
        raise InspectionError("image-manifest-invalid")
    images = []
    attestations = []
    for descriptor in manifests:
        if not isinstance(descriptor, dict):
            raise InspectionError("image-manifest-invalid")
        platform = descriptor.get("platform")
        annotations = descriptor.get("annotations")
        if (
            descriptor.get("mediaType") == IMAGE_MANIFEST_MEDIA_TYPE
            and platform == {"os": "linux", "architecture": architecture}
            and not isinstance(annotations, dict)
        ):
            images.append(descriptor)
        if (
            descriptor.get("mediaType") == IMAGE_MANIFEST_MEDIA_TYPE
            and platform == {"os": "unknown", "architecture": "unknown"}
            and isinstance(annotations, dict)
            and annotations.get("vnd.docker.reference.type") == "attestation-manifest"
        ):
            attestations.append(descriptor)
    if len(images) != 1 or len(attestations) != 1:
        raise InspectionError("image-manifest-invalid")
    image = images[0]
    attestation = attestations[0]
    if attestation.get("annotations") != {
        "vnd.docker.reference.type": "attestation-manifest",
        "vnd.docker.reference.digest": image.get("digest"),
    }:
        raise InspectionError("provenance-invalid")
    return image, attestation


def _read_image_manifest(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    descriptor: dict[str, Any],
    referenced: set[str],
) -> dict[str, Any]:
    manifest_bytes = _descriptor_blob(
        archive, members, descriptor, MAX_JSON_BYTES, referenced
    )
    _scan(manifest_bytes)
    manifest = _json(manifest_bytes)
    if (
        manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") != IMAGE_MANIFEST_MEDIA_TYPE
    ):
        raise InspectionError("image-manifest-invalid")
    return manifest


def _validate_provenance(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    image_descriptor: dict[str, Any],
    attestation_descriptor: dict[str, Any],
    referenced: set[str],
) -> None:
    manifest = _read_image_manifest(
        archive, members, attestation_descriptor, referenced
    )
    if set(manifest) != {
        "schemaVersion", "mediaType", "artifactType", "config", "layers", "subject"
    } or manifest.get("artifactType") != ATTESTATION_ARTIFACT_TYPE:
        raise InspectionError("provenance-invalid")
    if manifest.get("subject") != _descriptor_core(image_descriptor):
        raise InspectionError("provenance-invalid")

    empty_digest = "sha256:" + hashlib.sha256(b"{}").hexdigest()
    empty_config = manifest.get("config")
    if empty_config != {
        "mediaType": EMPTY_CONFIG_MEDIA_TYPE,
        "digest": empty_digest,
        "size": 2,
        "data": "e30=",
    }:
        raise InspectionError("provenance-invalid")
    if _descriptor_blob(
        archive, members, empty_config, MAX_JSON_BYTES, referenced
    ) != b"{}":
        raise InspectionError("provenance-invalid")

    layers = manifest.get("layers")
    if not isinstance(layers, list) or len(layers) != 1:
        raise InspectionError("provenance-invalid")
    layer = layers[0]
    if not isinstance(layer, dict) or set(layer) != {
        "mediaType", "digest", "size", "annotations"
    } or layer.get("mediaType") != IN_TOTO_MEDIA_TYPE:
        raise InspectionError("provenance-invalid")
    annotations = layer.get("annotations")
    if not isinstance(annotations, dict):
        raise InspectionError("provenance-invalid")
    predicate_type = annotations.get("in-toto.io/predicate-type")
    if annotations != {"in-toto.io/predicate-type": predicate_type} or (
        predicate_type not in SLSA_STATEMENTS
    ):
        raise InspectionError("provenance-invalid")
    statement_bytes = _descriptor_blob(
        archive, members, layer, MAX_JSON_BYTES, referenced
    )
    _scan(statement_bytes)
    statement = _json(statement_bytes)
    if (
        set(statement) != {"_type", "subject", "predicateType", "predicate"}
        or statement.get("_type") != SLSA_STATEMENTS[predicate_type]
        or statement.get("predicateType") != predicate_type
        or not isinstance(statement.get("predicate"), dict)
        or not statement["predicate"]
    ):
        raise InspectionError("provenance-invalid")
    subjects = statement.get("subject")
    expected_sha = str(image_descriptor["digest"])[7:]
    if (
        not isinstance(subjects, list)
        or len(subjects) != 1
        or not isinstance(subjects[0], dict)
        or set(subjects[0]) != {"name", "digest"}
        or not isinstance(subjects[0].get("name"), str)
        or not subjects[0]["name"]
        or subjects[0].get("digest") != {"sha256": expected_sha}
    ):
        raise InspectionError("provenance-invalid")


def _scan_text(value: object) -> None:
    if value:
        _scan(str(value).encode("utf-8", "surrogateescape"))


def _read_layer(
    data: bytes, media_type: str
) -> tuple[dict[str, tuple[str, int, bytes]], str]:
    if media_type not in LAYER_MEDIA_TYPES or len(data) > MAX_LAYER_BYTES:
        raise InspectionError("layer-invalid")
    try:
        if media_type.endswith("+gzip"):
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
                uncompressed = compressed.read(MAX_ROOTFS_BYTES + 1)
        else:
            uncompressed = data
    except (OSError, EOFError) as error:
        raise InspectionError("layer-invalid") from error
    if len(uncompressed) > MAX_ROOTFS_BYTES:
        raise InspectionError("layer-invalid")
    _scan(uncompressed)
    diff_id = "sha256:" + hashlib.sha256(uncompressed).hexdigest()
    entries: dict[str, tuple[str, int, bytes]] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(uncompressed), mode="r:") as layer:
            members = layer.getmembers()
            if len(members) > MAX_LAYER_MEMBERS:
                raise InspectionError("layer-invalid")
            seen: set[str] = set()
            for member in members:
                for metadata in (
                    member.name,
                    member.linkname,
                    member.uname,
                    member.gname,
                    *member.pax_headers.keys(),
                    *member.pax_headers.values(),
                ):
                    _scan_text(metadata)
                name = _safe_name(member.name.rstrip("/") if member.isdir() else member.name)
                if name in seen or any(
                    part.startswith(".wh.") for part in PurePosixPath(name).parts
                ):
                    raise InspectionError("layer-entry-invalid")
                seen.add(name)
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.uname
                    or member.gname
                    or member.linkname
                    or member.pax_headers
                ):
                    raise InspectionError("layer-entry-invalid")
                if member.isdir():
                    if member.size != 0:
                        raise InspectionError("layer-entry-invalid")
                    entries[name] = ("directory", member.mode & 0o7777, b"")
                    continue
                if not member.isfile() or member.islnk() or member.issym():
                    raise InspectionError("layer-entry-invalid")
                if member.size < 0 or member.size > MAX_FILE_BYTES:
                    raise InspectionError("layer-entry-invalid")
                extracted = layer.extractfile(member)
                if extracted is None:
                    raise InspectionError("layer-entry-invalid")
                content = extracted.read(MAX_FILE_BYTES + 1)
                if len(content) != member.size or len(content) > MAX_FILE_BYTES:
                    raise InspectionError("layer-entry-invalid")
                total += len(content)
                if total > MAX_ROOTFS_BYTES:
                    raise InspectionError("layer-invalid")
                _scan(content)
                entries[name] = ("file", member.mode & 0o7777, content)
    except (tarfile.TarError, OSError) as error:
        raise InspectionError("layer-invalid") from error
    return entries, diff_id


def _scan_artifacts(paths: Iterable[Path]) -> None:
    paths = tuple(paths)
    if len(paths) > MAX_ARTIFACTS:
        raise InspectionError("artifact-invalid")
    for path in paths:
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ARTIFACT_BYTES:
                raise InspectionError("artifact-invalid")
            with path.open("rb") as handle:
                data = handle.read(MAX_ARTIFACT_BYTES + 1)
        except OSError as error:
            raise InspectionError("artifact-invalid") from error
        if len(data) != metadata.st_size or len(data) > MAX_ARTIFACT_BYTES:
            raise InspectionError("artifact-invalid")
        _scan(data)


def inspect_oci_archive(
    archive_path: Path,
    profile: str,
    architecture: str,
    expected_digest: str,
    expected_config_digest: str,
    *,
    artifacts: Iterable[Path],
) -> InspectionResult:
    if (
        profile not in EXPECTED_FILES
        or architecture not in SUPPORTED_ARCHITECTURES
        or not DIGEST_RE.fullmatch(expected_digest)
        or not DIGEST_RE.fullmatch(expected_config_digest)
    ):
        raise InspectionError("invocation-invalid")
    try:
        metadata = archive_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ARCHIVE_BYTES:
            raise InspectionError("oci-archive-invalid")
        archive = tarfile.open(archive_path, mode="r:")
    except (OSError, tarfile.TarError) as error:
        raise InspectionError("oci-archive-invalid") from error
    with archive:
        listed = archive.getmembers()
        if len(listed) > MAX_OUTER_MEMBERS:
            raise InspectionError("oci-layout-invalid")
        names: dict[str, tarfile.TarInfo] = {}
        for member in listed:
            name = _safe_name(member.name.rstrip("/") if member.isdir() else member.name)
            if name in names or (not member.isfile() and not member.isdir()):
                raise InspectionError("oci-layout-invalid")
            names[name] = member
        layout = _json(_read_outer_member(archive, names, "oci-layout", MAX_JSON_BYTES))
        if layout != {"imageLayoutVersion": "1.0.0"}:
            raise InspectionError("oci-layout-invalid")
        index_bytes = _read_outer_member(archive, names, "index.json", MAX_JSON_BYTES)
        referenced = {"oci-layout", "index.json"}
        _scan(index_bytes)
        root_index = _json(index_bytes)
        index = _load_inner_index(
            archive,
            names,
            root_index,
            expected_digest,
            referenced,
        )
        oci_digest = expected_digest
        descriptor, attestation_descriptor = _select_descriptors(index, architecture)
        manifest = _read_image_manifest(
            archive, names, descriptor, referenced
        )
        config_descriptor = manifest.get("config")
        if (
            not isinstance(config_descriptor, dict)
            or config_descriptor.get("mediaType") != CONFIG_MEDIA_TYPE
            or config_descriptor.get("digest") != expected_config_digest
        ):
            raise InspectionError("image-config-invalid")
        config_bytes = _descriptor_blob(
            archive, names, config_descriptor, MAX_JSON_BYTES, referenced
        )
        _scan(config_bytes)
        config = _json(config_bytes)
        if (
            config.get("os") != "linux"
            or config.get("architecture") != architecture
            or config.get("config") != EXPECTED_CONFIG[profile]
        ):
            raise InspectionError("image-config-invalid")
        layers = manifest.get("layers")
        rootfs = config.get("rootfs")
        if (
            not isinstance(layers, list)
            or not (1 <= len(layers) <= 64)
            or not isinstance(rootfs, dict)
            or rootfs.get("type") != "layers"
            or not isinstance(rootfs.get("diff_ids"), list)
            or len(rootfs["diff_ids"]) != len(layers)
        ):
            raise InspectionError("image-config-invalid")
        root_entries: dict[str, tuple[str, int, bytes]] = {}
        observed_diff_ids = []
        for layer_descriptor in layers:
            if not isinstance(layer_descriptor, dict):
                raise InspectionError("layer-invalid")
            media_type = layer_descriptor.get("mediaType")
            layer_bytes = _descriptor_blob(
                archive, names, layer_descriptor, MAX_LAYER_BYTES, referenced
            )
            layer_entries, diff_id = _read_layer(layer_bytes, media_type)
            if set(root_entries).intersection(layer_entries):
                raise InspectionError("layer-entry-invalid")
            root_entries.update(layer_entries)
            if sum(len(content) for _, _, content in root_entries.values()) > MAX_ROOTFS_BYTES:
                raise InspectionError("layer-invalid")
            observed_diff_ids.append(diff_id)
        if rootfs["diff_ids"] != observed_diff_ids:
            raise InspectionError("image-config-invalid")
        _validate_provenance(
            archive,
            names,
            descriptor,
            attestation_descriptor,
            referenced,
        )
        if {name for name, member in names.items() if member.isfile()} != referenced:
            raise InspectionError("oci-layout-invalid")

    expected = EXPECTED_FILES[profile]
    if set(root_entries) != set(expected).union(EXPECTED_DIRECTORIES):
        raise InspectionError("rootfs-allowlist-invalid")
    for name, expected_mode in EXPECTED_DIRECTORIES.items():
        if root_entries[name] != ("directory", expected_mode, b""):
            raise InspectionError("rootfs-allowlist-invalid")
    for name, expected_mode in expected.items():
        kind, mode, _ = root_entries[name]
        if kind != "file" or mode != expected_mode:
            raise InspectionError("rootfs-allowlist-invalid")
    _scan_artifacts(artifacts)
    return InspectionResult(
        expected_digest,
        descriptor["digest"],
        expected_config_digest,
        architecture,
        profile,
        tuple(sorted(expected)),
    )


def _write_result(path: Path, result: InspectionResult) -> None:
    payload = {
        "architecture": result.architecture,
        "config_digest": result.config_digest,
        "files": list(result.files),
        "manifest_digest": result.manifest_digest,
        "oci_digest": result.oci_digest,
        "profile": result.profile,
        "schema": "aster-compose-oci-inspection/v1",
    }
    try:
        with path.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
    except OSError as error:
        raise InspectionError("result-file-invalid") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=sorted(EXPECTED_FILES), required=True)
    parser.add_argument(
        "--architecture", choices=SUPPORTED_ARCHITECTURES, required=True
    )
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--expected-config-digest", required=True)
    parser.add_argument("--result-file", type=Path)
    parser.add_argument("--scan-artifact", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    try:
        result = inspect_oci_archive(
            args.archive,
            args.profile,
            args.architecture,
            args.expected_digest,
            args.expected_config_digest,
            artifacts=args.scan_artifact,
        )
        if args.result_file is not None:
            _write_result(args.result_file, result)
    except InspectionError as error:
        print(str(error), file=os.sys.stderr)
        return 1
    print(
        f"OCI_INSPECTION status=pass profile={result.profile} "
        f"architecture={result.architecture} config_digest={result.config_digest} "
        f"oci_digest={result.oci_digest} manifest_digest={result.manifest_digest} "
        f"files={len(result.files)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
