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

Local environment observed: x86_64; no effective capabilities and
`NoNewPrivs=1`. The existing Ubuntu 24.04 runtime chroot has no systemd
package. No usable ARM64 test machine or VM has been identified. Neither
target's PID-1 credential presentation has been tested in this task.

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
- Configuration is `/etc/aster/agent.json`. Install an example under
  `/usr/share/doc/aster/examples/`; no operational configuration or test
  provisioning is silently installed.
- `/etc/aster/provisioning` and `/var/lib/aster/provisioning-systemd` are
  root-owned `0700` directories on local ext4, as required by the provider.
- `/var/lib/aster-agent` holds service-owned persistent node state.
- The encrypted input remains the provider's fixed
  `/etc/aster/provisioning/active/credential.cred`, delivered by PID 1 as
  `aster-provisioning.bundle`.
- A package-owned atomic reference handoff must decode the complete success
  output of an admin invocation that exited zero. It must set the final
  service UID and `0600`, and bind the configured load-operation ID. Never
  make provider-internal `active/reference` service-readable.
- Per-executable CycloneDX SBOMs include the administration executable too;
  preserve the existing overinclusive-Cargo qualification. Include project
  license and build records; complete dependency notices remain release work.
- Removal stops the service and preserves persistent state and provisioning.
  Purge must not silently destroy provisioning or claim physical erasure.

## Implementation sequence

1. Code-level Ubuntu compatibility is established above. Retain booted-target
   execution with the package; do not change existing Debian qualification claims.
2. Add `debian/control`, `debian/rules`, install lists, systemd unit,
   maintainer scripts and operator documentation. Use debhelper 13 and native
   `dpkg-buildpackage`; calculate shared-library dependencies from the actual
   binaries. Build with Rust 1.97.1 and locked offline Cargo inputs.
3. Implement and test the reference handoff: reject nonzero admin exit,
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

The package includes three schema-validated Cargo SBOMs. Its internal
`/usr/share/doc/aster/SHA256SUMS` hashes installed binaries **after stripping**,
the helper, SBOMs, BUILD.txt and LICENSE; verify from `/`. Preserve the external
`.buildinfo` and `.changes` too. BUILD.txt explicitly describes a working-tree
build, not a cryptographic source attestation. OS packages and Python
transitive dependencies are not fully locked; bit-for-bit repeatability,
complete native/toolchain license admission and signing remain open.

The manual `Build: Ubuntu 24.04 deb` workflow builds and exercises both targets.
It does not publish a release or change requirement status. The disposable VM
harness is `tools/test-deb-install.sh`; it refuses existing Aster deployments,
uses only the repository non-production fixture, and intentionally leaves
preserved test state after package removal. Never run it on a deployed node.

## Install and provision an evaluation candidate

Use Ubuntu 24.04 with local ext4 for the provider directories. Install the
architecture-matching package with `sudo apt install ./aster_VERSION_ARCH.deb`.
Installation leaves the service disabled and stopped. It preserves an existing
configuration, node state, and provider state. No plaintext bundle or test
credential is shipped.

Copy `/usr/share/doc/aster/examples/agent.example.json` to
`/etc/aster/agent.json`, owned by `root:aster`, mode `0640`. Set the actual
approved peers and limits. Place the application bearer token through an
approved owner-only input mechanism at
`/etc/aster/agent-credentials/client-token`, owned by `aster:aster`, mode `0600`.
The example load ID is synthetic; the helper replaces it during provisioning.

On a fresh host, initialize systemd's host encryption key before the first
provisioning operation:

```sh
sudo systemd-creds setup
```

The provider requires this key before it opens its ledger. On an existing
deployment, a missing key is a recovery issue: restore the original host key
through the approved recovery procedure; do not generate a replacement to
work around a provisioning failure.

Ubuntu Minimal images may configure dpkg to exclude `/usr/share/doc/*`.
Retain `/usr/share/doc/aster` and `/usr/share/doc/aster/*` with dpkg
`path-include` rules before installation to use the packaged example and
SBOM files.

With the authorized Aster bundle already supplied on standard input, invoke
`/usr/sbin/aster-provision install --operation HEX64 --load-operation HEX64`
as root. The wrapper locks package provisioning, stops and confirms termination
of the agent, invokes the existing admin binary, and accepts only its complete
successful result. It atomically installs the service-owned reference and
updates the config load ID. It prints neither reference nor bundle. It leaves
the service stopped on success. `rotate` uses the same form and handoff.

Retain the operation IDs in the authorized operation record. On any error keep
the service stopped: the provider operation may already have committed. Retry
with exactly the same IDs and authorized input, or reconcile using the provider
procedure. Do not allocate a new operation just because handoff failed. Never
run the wrapper concurrently with direct admin commands. Keep other root
operators from starting the service while provisioning is in progress.

Then validate as the service user and start:

```sh
sudo -u aster /usr/bin/aster-agent --check-config /etc/aster/agent.json
sudo systemctl start aster-agent.service
curl --fail http://127.0.0.1:8182/readyz
```

Enable boot startup only after the candidate checks pass:
`sudo systemctl enable aster-agent.service`. Readiness is separate from
`systemctl start` success. The unit allows 40 seconds for stopping; the agent's
configured grace is at most 30 seconds. `systemctl reload aster-agent.service`
sends SIGHUP for bearer-token reload; it does not reload mesh configuration.

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
