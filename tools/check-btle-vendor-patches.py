#!/usr/bin/env python3
"""Verify the exact source, patch, and Cargo provenance of BTLE forks."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADDED = {"ASTER-PATCH.diff", "ASTER-PATCH.md", "ASTER-UPSTREAM.sha256"}


@dataclass(frozen=True)
class Vendor:
    name: str
    version: str
    directory: str
    archive_sha256: str
    revision: str
    license_expression: str
    license_bindings: tuple[str, ...]
    notice_files: tuple[tuple[str, str], ...]
    patch_sha256: str
    source_archive_sha256: str
    patched: tuple[str, ...]


VENDORS = (
    Vendor(
        name="hmac",
        version="0.13.0",
        directory="third-party/hmac-0.13.0-aster",
        archive_sha256="6303bc9732ae41b04cb554b844a762b4115a61bfaa81e3e83050991eeb56863f",
        revision="0236c8eb50098dd7f277a71ab89caaeb1e7314df",
        license_expression="MIT OR Apache-2.0",
        license_bindings=("MIT OR Apache-2.0",),
        notice_files=(
            ("LICENSE-APACHE", "a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5"),
            ("LICENSE-MIT", "9e0dfd2dd4173a530e238cb6adb37aa78c34c6bc7444e0e10c1ab5d8881f63ba"),
        ),
        patch_sha256="c9962ca0b2c271f1bd3876567ab99571252e9bff4500fcdf7d09cee135c6e4c7",
        source_archive_sha256="a8c69874ba79751497be40c9dccf63b2a10b891441ba1a880bcbaa627cda61d6",
        patched=("src/block_api.rs",),
    ),
    Vendor(
        name="bluer",
        version="0.17.4",
        directory="third-party/bluer-0.17.4-aster",
        archive_sha256="af68112f5c60196495c8b0eea68349817855f565df5b04b2477916d09fb1a901",
        revision="8072d9cc6d034f1bfc464dda338d19a14f9badaf",
        license_expression="BSD-2-Clause",
        license_bindings=("BSD-2-Clause", "BSD-3-Clause", "GPL-2.0-only"),
        notice_files=(("LICENSE", "da053620434ccd59747d44b04e87e06464763f22db320bc71dc9b00b1e4db460"),),
        patch_sha256="ce4de362bf30ccc318c741694adfce8678c53202b44a5b4827a509ea681044af",
        source_archive_sha256="0d58bacf77348f871068fe9fe2f859cb5ec2ccb4ff81d7f6fa05f40477c6bb01",
        patched=("src/adapter.rs", "src/adv.rs", "src/lib.rs", "src/session.rs"),
    ),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_receipt(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    for line_number, line in enumerate(lines, start=1):
        checksum, separator, relative = line.partition("  ")
        if (
            not separator
            or len(checksum) != 64
            or any(character not in "0123456789abcdef" for character in checksum)
            or not relative
            or relative in entries
        ):
            raise ValueError(f"{path}: invalid receipt line {line_number}")
        entries[relative] = checksum
    if list(entries) != sorted(entries):
        raise ValueError(f"{path}: receipt paths are not sorted")
    return entries


def diff_paths(patch: bytes) -> tuple[str, ...]:
    lines = patch.decode("utf-8").splitlines()
    old = [line.removeprefix("--- a/") for line in lines if line.startswith("--- a/")]
    new = [line.removeprefix("+++ b/") for line in lines if line.startswith("+++ b/")]
    if old != new or len(old) != len(set(old)):
        raise ValueError("canonical patch has mismatched or duplicate paths")
    return tuple(old)


def canonical_diff(upstream: Path, vendor: Path, paths: tuple[str, ...]) -> bytes:
    output = bytearray()
    for relative in paths:
        result = subprocess.run(
            [
                "diff",
                "-u",
                "--label",
                f"a/{relative}",
                "--label",
                f"b/{relative}",
                str(upstream / relative),
                str(vendor / relative),
            ],
            check=False,
            capture_output=True,
        )
        if result.returncode != 1 or result.stderr:
            raise ValueError(f"{relative}: cannot reproduce canonical source diff")
        output.extend(result.stdout)
    return bytes(output)


def deterministic_archive_digest(vendor: Vendor) -> str:
    result = subprocess.run(
        [
            "tar",
            "--sort=name",
            "--format=ustar",
            "--mtime=@0",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "-cf",
            "-",
            "-C",
            str(ROOT / "third-party"),
            Path(vendor.directory).name,
        ],
        check=True,
        capture_output=True,
    )
    return digest(result.stdout)


def verify_git_preserves_bytes(path: Path) -> None:
    relative = path.relative_to(ROOT).as_posix()
    raw = subprocess.run(
        ["git", "hash-object", "--no-filters", str(path)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    filtered = subprocess.run(
        ["git", "hash-object", f"--path={relative}", str(path)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if raw != filtered:
        raise ValueError(f"Git attributes alter vendored bytes: {relative}")


def verify_vendor(vendor: Vendor) -> None:
    directory = ROOT / vendor.directory
    receipt = read_receipt(directory / "ASTER-UPSTREAM.sha256")
    patch_path = directory / "ASTER-PATCH.diff"
    patch = patch_path.read_bytes()
    if digest(patch) != vendor.patch_sha256:
        raise ValueError(f"{vendor.name}: canonical patch digest changed")
    if diff_paths(patch) != vendor.patched:
        raise ValueError(f"{vendor.name}: canonical patch path set changed")

    actual = {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*")
        if path.is_file()
    }
    expected = set(receipt) | ADDED
    if actual != expected:
        raise ValueError(
            f"{vendor.name}: vendored file-set drift: "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )

    for relative in receipt:
        verify_git_preserves_bytes(directory / relative)

    with tempfile.TemporaryDirectory(prefix=f"aster-{vendor.name}-upstream-") as temporary:
        upstream = Path(temporary)
        for relative in receipt:
            target = upstream / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(directory / relative, target)
        reverse = subprocess.run(
            ["patch", "--reverse", "--batch", "--silent", "-p1", "-i", str(patch_path)],
            cwd=upstream,
            check=False,
            capture_output=True,
            text=True,
        )
        if reverse.returncode != 0:
            raise ValueError(
                f"{vendor.name}: canonical patch does not reverse cleanly: "
                f"{reverse.stderr.strip() or reverse.stdout.strip()}"
            )
        for relative, expected_digest in receipt.items():
            if digest((upstream / relative).read_bytes()) != expected_digest:
                raise ValueError(f"{vendor.name}: {relative} does not reconstruct upstream")
        if canonical_diff(upstream, directory, vendor.patched) != patch:
            raise ValueError(f"{vendor.name}: ASTER-PATCH.diff is not canonical")

    note = (directory / "ASTER-PATCH.md").read_text(encoding="utf-8")
    for binding in (
        vendor.archive_sha256,
        vendor.revision,
        vendor.license_expression,
        vendor.patch_sha256,
    ):
        if binding not in note:
            raise ValueError(f"{vendor.name}: ASTER-PATCH.md is missing binding {binding}")
    for binding in vendor.license_bindings:
        if binding not in note:
            raise ValueError(f"{vendor.name}: ASTER-PATCH.md is missing license {binding}")
    for relative, expected_digest in vendor.notice_files:
        actual_digest = digest((directory / relative).read_bytes())
        if actual_digest != expected_digest or expected_digest not in note:
            raise ValueError(f"{vendor.name}: retained notice changed: {relative}")

    actual_archive_digest = deterministic_archive_digest(vendor)
    if actual_archive_digest != vendor.source_archive_sha256:
        raise ValueError(
            f"{vendor.name}: deterministic source archive changed: {actual_archive_digest}"
        )


def require_path_patches(manifest_path: Path, prefix: str) -> None:
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    patches = manifest.get("patch", {}).get("crates-io", {})
    for vendor in VENDORS:
        expected = f"{prefix}{vendor.directory}"
        if patches.get(vendor.name) != {"path": expected}:
            raise ValueError(f"{manifest_path}: {vendor.name} path patch must be {expected}")


def require_workspace_features() -> None:
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    dependencies = manifest["workspace"]["dependencies"]
    expected = {
        "hmac": {
            "version": "=0.13.0",
            "default-features": False,
            "features": ["zeroize"],
        },
        "bluer": {
            "version": "=0.17.4",
            "default-features": False,
            "features": ["bluetoothd", "l2cap"],
        },
    }
    for name, value in expected.items():
        if dependencies.get(name) != value:
            raise ValueError(f"Cargo.toml: exact {name} version/features changed")


def require_path_locks(lock_path: Path) -> None:
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    for vendor in VENDORS:
        packages = [
            package
            for package in lock["package"]
            if package["name"] == vendor.name and package["version"] == vendor.version
        ]
        if len(packages) != 1:
            raise ValueError(
                f"{lock_path}: expected one {vendor.name} {vendor.version}, found {len(packages)}"
            )
        if "source" in packages[0] or "checksum" in packages[0]:
            raise ValueError(f"{lock_path}: {vendor.name} {vendor.version} is not path-provenanced")


def require_sbom_pedigree() -> None:
    set_list_path = ROOT / "docs/release/sbom/2026-11-06-btle-vendor-pedigree.set.json"
    entries = json.loads(set_list_path.read_text(encoding="utf-8"))
    by_purl = {entry["id"]["purl"]: entry["set"] for entry in entries}
    if len(by_purl) != len(entries):
        raise ValueError(f"{set_list_path}: duplicate component purl")
    for vendor in VENDORS:
        purl = (
            f"pkg:cargo/{vendor.name}@{vendor.version}?download_url="
            f"file://../../{vendor.directory}"
        )
        component = by_purl.get(purl)
        if component is None:
            raise ValueError(f"{set_list_path}: missing {vendor.name} component")
        pedigree = component["pedigree"]
        patch = pedigree["patches"][0]["diff"]["text"]["content"].encode()
        if patch != (ROOT / vendor.directory / "ASTER-PATCH.diff").read_bytes():
            raise ValueError(f"{set_list_path}: {vendor.name} patch bytes changed")
        rendered = json.dumps(component, sort_keys=True)
        for binding in (
            vendor.archive_sha256,
            vendor.revision,
            vendor.license_expression,
            vendor.patch_sha256,
            vendor.source_archive_sha256,
            *(binding for binding in vendor.license_bindings),
            *(notice_digest for _, notice_digest in vendor.notice_files),
        ):
            if binding not in rendered:
                raise ValueError(f"{set_list_path}: {vendor.name} missing binding {binding}")


def main() -> int:
    try:
        for vendor in VENDORS:
            verify_vendor(vendor)
        require_path_patches(ROOT / "Cargo.toml", "")
        require_path_patches(ROOT / "fuzz/Cargo.toml", "../")
        require_workspace_features()
        require_path_locks(ROOT / "Cargo.lock")
        require_path_locks(ROOT / "fuzz/Cargo.lock")
        require_sbom_pedigree()
    except (
        KeyError,
        OSError,
        ValueError,
        subprocess.CalledProcessError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
    ) as error:
        print(f"BTLE vendor verification failed: {error}", file=sys.stderr)
        return 1

    print(
        "BTLE vendor verification passed: exact hmac/bluer sources, canonical patches, "
        "features, root/fuzz path patches, lock provenance, and SBOM pedigree"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
