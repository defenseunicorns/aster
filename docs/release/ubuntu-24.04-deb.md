# Ubuntu 24.04 Debian-package candidate



Status: package implementation under validation; no runtime qualification
or production authorization is claimed. Base: `feature/P0-3-SBOM` at `757e22a`.
Development branch: `feature/P0-3-deb-package`.

## Agreed target and first exit

One `aster` Debian binary package, built natively for Ubuntu 24.04 `amd64`
and `arm64` from the same reviewed source revision and Cargo.lock. Each
architecture needs its own build, SBOM, package dependency calculation,
checksums, and clean-system installation/runtime receipt. The first exit is
installation, protected service startup, local Event smoke, restart, and
removal on both targets. This does not close all of P0-3: reproducibility,
upgrade/rollback, release signatures and release-container work follow.

The architectures have [separate manual CI workflows](../ci.md#manual-ubuntu-debian-packages):
`Build: Ubuntu 24.04 deb amd64` and `Build: Ubuntu 24.04 deb arm64`.
Each runs the same native build, package checks and installation harness.
Arm64 qualification requires a successful arm64 run; workflow configuration
alone does not qualify it.

## Compatibility finding

Ubuntu Noble uses the systemd 255.4 line. The current
[provider v2](../../crates/aster-systemd-credentials/README.md) documents an
exact Debian 13 / Raspberry Pi / systemd 257 evaluation profile. It does not
qualify Ubuntu. Its loader still accepts the original service-owned `0400`
regular single-link credential file on `ramfs`, in addition to the narrowly
specified systemd 257 ACL/tmpfs presentation. Do not loosen these checks to
make packaging pass.

The Ubuntu source package `255.4-1ubuntu8.17` was inspected directly.
`mount_credentials_fs()` prefers `tmpfs,noswap` on supporting kernels, then
falls back to `ramfs`. `write_credential()` and `acquire_credentials()` produce
root-owned `0440` files and `0550` directories with a read/read-execute ACL for
the service UID. The mount receives `ro,nosuid,nodev,noexec,nosymfollow`.
These match the existing loader's `SystemdAclTmpfs` predicates; the loader
checks metadata, not a systemd version number. Thus the inspected interface is
compatible without upgrading systemd or relaxing the loader. Booted-target
execution and the full provider lifecycle remain separate acceptance tests.

The unit explicitly sets `RestrictSUIDSGID=no`: systemd 255's implementation
blocks `openat2()` with `ENOSYS`, including the loader's read-only,
symlink-rejecting directory open. The loader keeps its `openat2` checks;
`NoNewPrivileges=yes`, the fixed non-root account, empty capability sets and
filesystem protections remain enabled. See
[systemd v255 seccomp implementation](https://github.com/systemd/systemd/blob/v255/src/shared/seccomp-util.c),
`seccomp_restrict_sxid()` and `seccomp_restrict_suid_sgid()`.

Public sources consulted, 2026-09-10:

- [Ubuntu systemd source, version 255.4-1ubuntu8.17](https://git.launchpad.net/ubuntu/+source/systemd/tree/?h=ubuntu/noble-updates):
  `src/core/exec-credential.c`, `src/shared/mount-util.c`,
  `src/shared/acl-util.c`, and `debian/changelog`.
- [Ubuntu Noble systemd-creds manual](https://manpages.ubuntu.com/manpages/noble/man1/systemd-creds.1.html):
  `encrypt --with-key=host --name=... - -` is supported.
- [GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners):
  native `ubuntu-24.04` and `ubuntu-24.04-arm` runner labels.

Local validation: amd64 package installation/runtime and two-node Compose
checks passed. On 2026-09-14, native ARM64 package builds, protected systemd
startup, Event delivery/acknowledgement, restart, removal/purge preservation,
and same-runtime package upgrade/downgrade checks also passed. The package
configuration example now includes the required `storage.operations` limits.
See the [current validation record](2026-09-14-deb-observation.md) for artifact
hashes, retained evidence, test-helper failures and qualification limits.
Historical observations remain in [the earlier record](2026-09-10-deb-observation.md).

The separate [two-node package Compose smoke](../../docker/deb-test/README.md)
passed on amd64 and native ARM64, including offline backlog delivery and
persistence across container recreation. Compose does not qualify systemd or
the protected service. The full local `mise run check` passed on 2026-09-14;
the earlier contact-deadline failure did not recur in that run. GitHub Actions
package workflows remain unverified until their actual CI runs complete.

The probe below is an optional compatibility diagnostic, not a required
package-build or installation step.

## Target-machine probe

Run on each disposable, booted Ubuntu 24.04 target as an operator. Requires
`systemd-run`, `findmnt`, `stat`, and the existing `nobody` account. This
creates only a temporary public marker and transient service. It does not
read credentials, encrypt a bundle, create a systemd host key, or modify the
provider. `LoadCredential=` observes PID 1's file presentation only;
`LoadCredentialEncrypted=` and the real Aster loader require a subsequent
end-to-end test with non-production Aster test material.

```sh
sudo bash <<'PROBE'
set -euo pipefail
. /etc/os-release
test "$ID:$VERSION_ID" = ubuntu:24.04
case "$(dpkg --print-architecture)" in amd64|arm64) ;; *) exit 1;; esac
test "$(cat /proc/1/comm)" = systemd
stage=$(mktemp -d /run/aster-credential-probe.XXXXXXXX)
unit="${stage##*/}.service"
trap 'rm -f "$stage/public-marker"; rmdir "$stage"' EXIT
printf 'public compatibility probe\n' > "$stage/public-marker"
chmod 0600 "$stage/public-marker"
dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' systemd
uname -r
systemd-run --quiet --wait --pipe --collect --unit="$unit" \
  --property=User=nobody --property=NoNewPrivileges=yes \
  --property="LoadCredential=aster-provisioning.bundle:$stage/public-marker" \
  /bin/sh -eu -c '
    id
    stat -c "%F mode=%a uid=%u gid=%g links=%h" \
      "$CREDENTIALS_DIRECTORY" \
      "$CREDENTIALS_DIRECTORY/aster-provisioning.bundle"
    findmnt -T "$CREDENTIALS_DIRECTORY" -o TARGET,FSTYPE,OPTIONS
    if command -v getfacl >/dev/null; then
      getfacl -cp "$CREDENTIALS_DIRECTORY" \
        "$CREDENTIALS_DIRECTORY/aster-provisioning.bundle"
    fi
  '
PROBE
```

Retain the output with architecture and date. `ramfs` plus a service-owned
`0400` regular single-link file is a candidate for the original loader path.
For any tmpfs result, check every predicate in the existing loader; the word
`tmpfs` or a successful systemd command alone is insufficient. Neither this
probe nor an accepted metadata shape qualifies the v2 lifecycle on Ubuntu.

## Package composition

- `/usr/bin/aster` and `/usr/bin/aster-agent` use package-default features;
  no automatic discovery or acceptance-fixture binary.
- `/usr/sbin/aster-credential-admin` is the stopped-service root admin tool.
- `aster-agent.service` runs as a dedicated static `aster` user, with
  restrictive umask and no automatic activation on install or upgrade.
- Configuration is `/etc/aster/agent.json`. The example remains in the source
  checkout at `debian/agent.example.json`; no documentation, example, operational
  configuration or test provisioning is installed by the package.
- `/etc/aster/provisioning` and `/var/lib/aster/provisioning-systemd` are
  root-owned `0700` directories on local ext4, as required by the provider.
- `/var/lib/aster-agent` holds service-owned persistent node state.
- The encrypted input remains the provider's fixed
  `/etc/aster/provisioning/active/credential.cred`, delivered by PID 1 as
  `aster-provisioning.bundle`.
- The operator procedure for atomic reference handoff must decode the complete success
  output of an admin invocation that exited zero. It must set the final
  service UID and `0600`, and bind the configured load-operation ID. Never
  make provider-internal `active/reference` service-readable.
- Per-executable CycloneDX SBOMs include the administration executable too;
  preserve the existing overinclusive-Cargo qualification. Include project
  license and build records alongside the package, outside the `.deb`; complete
  dependency notices remain release work.
- Removal stops the service and preserves persistent state and provisioning.
  Purge must not silently destroy provisioning or claim physical erasure.

## Implementation sequence

1. Code-level Ubuntu compatibility is established above. Retain booted-target
   execution with the package; do not change existing Debian qualification claims.
2. Add `debian/control`, `debian/rules`, install lists, systemd unit,
   maintainer scripts and operator documentation. Use debhelper 13 and native
   `dpkg-buildpackage`; calculate shared-library dependencies from the actual
   binaries. Build with Rust 1.97.1 and locked offline Cargo inputs.
3. Document and test the existing admin CLI and manual reference handoff: reject nonzero admin exit,
   partial/invalid output and insecure paths; make replacement atomic;
   leave the service stopped on failure. Avoid a new provisioning backend.
4. Add native Ubuntu 24.04 CI jobs for amd64 and arm64, including SBOM
   validation and package payload checks. Provision tools separately from the
   offline build, using the approved dependency source and corporate CA.
5. On disposable booted targets, test install, missing-provisioning rejection,
   protected startup, health/readiness, local Event operation, restart, and
   removal with state preservation. Record package hash, exact systemd/kernel
   versions and architecture. Test privilege-bound operations on the target,
   not by treating chroot or mocked tests as PID-1 evidence.
6. Run repository checks and review the diff before committing. Do not move
   requirement evidence status until the corresponding receipts exist.

## Build and inspect

Build natively on each Ubuntu 24.04 architecture with Rust 1.97.1,
cargo-cyclonedx 0.5.9, and cdx-ev 0.34.0 on PATH. Debian build dependencies are
in `debian/control`; provisioning the Python validator additionally needs
`python3-venv`, `python3-dev`, and `libicu-dev`. Acquire tools through the
approved package source, then fetch the locked Cargo inputs before the offline
build. See the existing [SBOM workflow](sbom/README.md) for pinned tool setup.
Do not run a host-architecture build and label it as the other architecture.

```sh
cargo fetch --locked
umask 022
dpkg-buildpackage -b -us -uc
python3 tools/test_deb_package.py ../aster_*_$(dpkg --print-architecture).deb "$(dpkg --print-architecture)"
sha256sum ../aster_*.deb
```

The build produces three schema-validated Cargo SBOMs in
`target/deb-metadata`, outside the `.deb`, together with license/build records.
`BINARY-SHA256SUMS` hashes the three packaged executables after stripping;
verify these paths from `/` on an installed target. Preserve this metadata and
external `.buildinfo` and `.changes` alongside the package. The CI artifact
includes the metadata directory and an external checksum manifest.
The `.deb` contains no documentation, examples, SBOMs or build records.
BUILD.txt explicitly describes a working-tree
build, not a cryptographic source attestation. OS packages and Python
transitive dependencies are not fully locked; bit-for-bit repeatability,
complete native/toolchain license admission and signing remain open.

The separate manual `Build: Ubuntu 24.04 deb amd64` and
`Build: Ubuntu 24.04 deb arm64` workflows build and exercise their respective
targets. Neither publishes a release or changes requirement status. The disposable VM
harness is `tools/test-deb-install.sh`; it refuses existing Aster deployments,
uses only the repository non-production fixture, and intentionally leaves
preserved test state after package removal. Never run it on a deployed node.

## Install and provision an evaluation candidate

Follow the existing [provider operations procedure, Ubuntu 24.04 amd64
package annex](../implementation/raspberry-pi-provider-v2-operations.md#ubuntu-2404-amd64-package-annex).
Documentation stays in the repository and is not installed by the package.
The existing procedure supplies package paths, service account, first installation, host-key
setup, direct `aster-credential-admin` invocation, atomic reference/configuration
handoff and startup/readiness commands. Provider lifecycle and retry semantics
remain in that procedure. Native ARM64 evaluation results are recorded above; final device and production qualification remain open.

## Upgrade, removal, and remaining qualification

Upgrades stop the service before replacing executables and do not restart it
implicitly. Existing operator-selected boot enablement is preserved; only a
fresh install starts disabled. Stop it explicitly before operator maintenance as well. Keep the
previous package and an approved state/provider recovery plan; do not claim
arbitrary binary downgrade is safe for persistent state. Verify compatibility
and start explicitly after an upgrade. A tested upgrade/rollback matrix is
still pending.

`sudo apt remove aster` stops the service and removes binaries/unit files.
Persistent node state, configuration, provider ledger and encrypted generations
remain. Purge also does not perform provisioning destruction or remove the
service account: retained files must not be reassigned to a recycled UID.
Use the existing provider destroy lifecycle for authorized logical destruction;
package removal is not physical erasure. Provider backup/recovery and credential
rotation semantics remain those of provider v2.
