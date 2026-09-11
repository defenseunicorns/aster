# Ubuntu 24.04 amd64 package observation — 2026-09-10



Candidate branch: `feature/P0-3-deb-package`, based on `757e22a` with
uncommitted packaging changes. This is an evaluation build, not a release
or a reproducibility receipt.

## Verified package build

`dpkg-buildpackage -b -nc -us -uc` completed in an isolated Ubuntu 24.04
amd64 rootfs with Rust 1.97.1, cargo-cyclonedx 0.5.9 and
cyclonedx-editor-validator 0.34.0. Cargo operated offline with the frozen
lockfile. `-nc` reused the local compilation cache; a clean second build
has not been compared.

Artifact: `aster_0.1.0-1~ubuntu24.04.1_amd64.deb`.
SHA-256: `b724e4472b150b51bcf64fe218792880626250693349bc8781ce8c65e3268c2c`.
The generated dependencies are `libc6 (>= 2.39)`, `libgcc-s1 (>= 4.2)`,
`systemd (>= 255.4)`, `adduser`, and `python3`.

`tools/test_deb_package.py` passed against the actual archive: all three
ELFs are amd64, all three CycloneDX inventories have the expected binary
roots and component licenses, installed checksums match after stripping,
and protected directories have the required package modes. The package
contains no operational configuration or provisioning bundle. Six helper
tests passed, including unsuccessful admin output, incomplete output,
symlink/hardlink destinations and duplicate configuration fields.

Local artifacts, `.buildinfo`, `.changes` and logs are retained under
`outputs/deb-package-2026-09-10` outside the worktree.

The first repository-check run inherited host `umask 0002`. The existing
`blob_terminal_zeroization_prevents_facade_reopen` fixture creates its root
with ambient permissions; zeroization rejected the resulting group-writable
directory. The failure reproduced alone and the same binary/test passed
with `umask 077`. No zeroization checks or Rust code were changed.

With private umask, static checks, Clippy, workspace Rust tests, real
mesh-playground/hello smoke tests, C/C++ headers and conformance checks
passed. Python bindings initially could not find the shared-cache FFI
library; after exposing the generated `target/debug` cache in the worktree,
all 12 binding tests passed. The remaining Go checks also passed.

The earlier full `mise run check` did not finish successfully: the lab suite reported 17 errors
across 202 tests. Thirteen error records require an exact `.git` directory
and reject a linked worktree; four require the absent Docker executable.
These checks were not bypassed or changed. Logs are
`check-private-umask.log`, `check-bindings-continuation.log` and
`check-go-continuation.log`; continuation runs do not constitute one
successful full `mise run check` invocation.

After transferring the unchanged packaging files into the main checkout on
`feature/P0-3-deb-package` and installing Docker CE 29.8.0 from Docker's
official Ubuntu Resolute stable repository, the lab suite passed all 202
tests with `umask 077` (57.340 seconds). See `lab-main-checkout.log`.
This resolves the 17 lab errors above; all check steps now have successful
results across the recorded runs, but no single complete successful
`mise run check` invocation is claimed. The lab test result alone does not
demonstrate real container execution. Docker access without sudo was later
verified after refreshing session group membership.

## Successful amd64 VM runtime receipt

The updated package passed `tools/test-deb-install.sh` in a clean booted
Ubuntu 24.04.4 amd64 VM: kernel `6.8.0-139-generic`, systemd
`255.4-1ubuntu8.17`, ext4, static service UID 104 / GID 106. The VM used
QEMU 8.2.2 with KVM, 2 CPUs and 2 GiB RAM. QEMU ran as UID 1001 in Docker
with only `/dev/kvm` and the dedicated test-artifact directory exposed;
no privileged container mode, host service installation or external network
was used. The guest received only the package, harness and public
non-production fixture through a cloud-init seed disk.

Verified outcomes: installation leaves the service disabled/inactive;
startup without provisioning fails; initial host-key setup and provisioning
succeed; configuration validation and protected service readiness succeed;
local Event publish/delivery/ack succeeds; service restart reaches readiness;
package removal stops the service and retains the state marker, active
encrypted credential and provider ledger. The unchanged loader accepted
systemd 255's credential presentation.

Final tested artifact is under `outputs/deb-package-2026-09-10/revision-03/`:
`aster_0.1.0-1~ubuntu24.04.1_amd64.deb`, SHA-256
`e8c68cfd5966017cdeded73bc312dd0c69edf3ac885485c602223ba398b6c3b2`.
The package payload test passed against this exact archive.
The full serial log is `runtime-amd64/serial-07.log` under the same output
root, SHA-256
`ecdcc2a2ec49ee198b68336630ac9b763a926930b5f11e92357cb86b890420be`;
it contains `ASTER_VM_TEST_EXIT=0`. The VM powered off and its Docker
container exited successfully.

Public environment input:
[Ubuntu Minimal 24.04 release 20260905](https://cloud-images.ubuntu.com/minimal/releases/noble/release-20260905/),
`ubuntu-24.04-minimal-cloudimg-amd64.img`, SHA-256
`46b0dbaffa6950a7da5ff2dc5ed34c46084610b3b6d1fae8f1ec2d7e953984a3`,
checked against Ubuntu's published SHA256SUMS. The local tools image ID is
`sha256:e98eeeb39db78348beca8f46247db0b993a63161d44483d1441eb413bf09321c`.
The Dockerfile, seed inputs, launch scripts and prior diagnostic logs are
retained in `runtime-amd64/`.

Earlier runs exposed and resolved these issues:

- Reset the expected startup failure before stopping the unit; systemd may
  unload it after stop, making a subsequent targeted reset fail.
- Ubuntu Minimal excludes documentation by default. The VM explicitly
  included `/usr/share/doc/aster` and its contents for package examples/SBOMs.
- A fresh host needs `systemd-creds setup` before provider administration.
  This prerequisite is now in the installation instructions and harness.
- `RestrictSUIDSGID=yes` returned `ENOSYS` for `openat2()` inside the unit.
  A metadata-only probe confirmed the expected UID ACLs and read-only
  noswap tmpfs mount. Setting `RestrictSUIDSGID=no` resolved the syscall
  conflict; loader checks, NoNewPrivileges, non-root identity and other
  unit protections remain intact. See the
  [systemd v255 implementation](https://github.com/systemd/systemd/blob/v255/src/shared/seccomp-util.c).

## Main integration and complete checkout check (2026-09-11)

The packaging branch was fast-forwarded to `origin/main` at
`e1545d51ed07bcae260c7787742e4576ceb49231`; the remote has no `master`
branch. The incoming changes affected documentation only, leaving the
Rust sources and Cargo manifests/lockfile used for the amd64 receipt unchanged.

A single complete `mise run check` invocation then exited 0 in the main
checkout, with `umask 077`, `CARGO_BUILD_JOBS=2`, `RUST_TEST_THREADS=4`,
the default Cargo target directory and Docker accessible without sudo.
This includes format/lint and workspace tests, real process smoke tests,
conformance checks, 12 Python binding tests, 202 laboratory tests, Go
binding/conformance tests and generated Go code validation. This later
result supersedes the earlier limitation about separate successful runs.
The log is `outputs/deb-package-2026-09-11/check.log`, SHA-256
`64faaf52d1f0a125bca1dd3eb828029e588f0078163304ea6051d3c3558a6a9b`.
Native arm64 build and runtime validation are deferred.

## Wrapper removal (2026-09-11)

The package-specific provisioning wrapper and its six tests were removed
following review. Operators now use the existing `aster-credential-admin`
and explicitly update the service reference/configuration. The disposable
VM harness calls that binary directly. The maintainer script uses POSIX shell
and standard system utilities; Python is no longer a runtime dependency.
The shell maintainer script passed first and repeated configuration, expected
owner/mode checks and rejection of writable or symlinked directories in an
isolated Ubuntu 24.04 container. Shell and embedded Python syntax checks passed.
The artifact hashes and VM receipt above describe the earlier package with
the wrapper; they do not certify a rebuilt package after this removal.

## Remaining evidence

This is one amd64 VM evaluation receipt, not a complete provider lifecycle
or production qualification. Native arm64 artifacts/runtime, credential
rotation and backup/recovery qualification, upgrade/rollback, reproducibility
and signing remain open. The manual CI workflow includes both native
architectures, but neither remote CI job has been executed for this change.
