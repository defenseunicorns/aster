# Continuous integration

The `CI` GitHub Actions workflow runs the repository's established validation
commands on pushes to `main`, pull requests targeting `main`, merge queues, and
manual dispatches. Each validation job reports its own status.

## Compose-provider checks

The Compose-provider checks are daemon-free: normal CI runs
`python3 tools/test_inspect_aster_compose_oci.py` to validate synthetic OCI
archive safety boundaries. These checks do not call the Docker CLI,
connect to a Docker socket, execute a lifecycle, clean up Docker resources, or
produce a host-qualification receipt.

This statement is intentionally scoped to the Compose-provider checks. Other
repository jobs, including the existing path-lab jobs, use Docker for their own
unrelated evaluation boundaries and are unchanged.

`.github/workflows/build-compose-images.yml` is a manual-only
`workflow_dispatch` packaging workflow. Native `ubuntu-24.04` `amd64` and
`ubuntu-24.04-arm` `arm64` jobs each produce one architecture-bound artifact
with OCI and Docker-loadable archives. Before upload, each job loads both
Docker archives and compares their local image IDs with authenticated OCI
config or selected-manifest digests;
it also retains architecture-bound SBOM, notice, digest, checksum, and
provenance evidence. This packaging validation does not start Aster or qualify
a Docker Engine, Compose implementation, filesystem, mount, user namespace, or
mandatory-access-control profile. The manual operator procedure is
[`docs/release/docker-compose.md`](../release/docker-compose.md).

## Find a section

| Need | Read |
|---|---|
| Understand the required GitHub checks | [Validation lanes](#validation-lanes) |
| Interpret selected-node test evidence | [Selected composition coverage](#selected-composition-coverage) |
| Review dependency and security caveats | [Security posture](#security-posture) |
| Run the checks on a workstation | [Running checks locally](#running-checks-locally) |

## Validation lanes

| Check | Runner | Purpose |
| --- | --- | --- |
| `Cargo lockfiles` | `ubuntu-24.04` | Checks every committed Cargo graph with `cargo fetch --locked` before Cargo builds start, and tests rejection of stale or missing lockfiles offline. |
| `quality` | `ubuntu-24.04` | Runs the exact-source Python process contract, Rust and Go formatting, Apache-2.0-only project-license and package checks, the selected-node dependency boundary, selected live-Event, live-mutable, live-State-subscription, live-Record-subscription, live-Blob, and live-Blob-subscription receipt checker tests, real-process smokes, C ABI build and C/C++ header checks, Rust/Python conformance, Python/Go binding tests, and lab-controller tests. |
| `Rust Clippy` | `ubuntu-24.04` | Runs locked Clippy for every workspace target and feature, with warnings denied. |
| `Rust tests (1/2)` and `Rust tests (2/2)` | `ubuntu-24.04` | Run two disjoint nextest partitions covering the complete locked, all-feature Rust workspace suite. Partition 1 also runs all workspace doctests with Cargo. Both start independently of Clippy and use the existing resource wrapper. |
| `macOS compatibility` | `macos-15` | Compiles and links every all-feature Rust workspace test target, then runs focused macOS/non-Linux custody-clock, finite-TTL, Blob staging/read, and credential-provider contracts. |
| `Rust 1.91 MSRV` | `ubuntu-24.04` | Checks every workspace target and feature with the declared minimum supported Rust version. |
| `dependency policy` | `ubuntu-24.04` | Applies `deny.toml` to the root and fuzz dependency graphs, and audits both lockfiles against a freshly downloaded RustSec database. |
| `age reference interoperability` | `ubuntu-24.04` | Installs exact `govulncheck` v1.6.0, runs `mise run age-reference-audit`, then runs `mise run age-reference-interop`: the Go oracle's reachable vulnerability and compiled-module license gates must pass before exact reference Go `filippo.io/age` v1.3.1 and the Rust provider exchange classic-X25519 artifacts in both directions, compare recovered plaintext, and agree on the recipient. |
| `bounded fuzz smoke` | `ubuntu-24.04` | Runs all nine fixed 10,000-case hostile-input campaigns with the pinned nightly toolchain and `cargo-fuzz`: semantic wire decode, fragment decode, reference-envelope inspection, selected mechanics-frame decode, selected Negentropy, classical-profile decode, systemd credential decode, systemd admin-record decode, and systemd backup decode. |

The `Cargo lockfiles` lane runs `sh tools/check-cargo-lockfiles.sh` against the
root, fuzz, and standalone conformance-runner manifests with Rust 1.97.1. It
reports each failing graph without regenerating lockfiles. Cargo build lanes
wait for it and are skipped if it fails.
Each build runner still acquires its own dependencies before offline checks.

Dependabot uses one Cargo configuration covering `/` and `/fuzz`, grouped by
`dependency-name`, to coordinate each dependency's version update in one PR.
This does not require the two lockfiles to contain identical graphs. GitHub's
cross-directory grouping applies to version updates, not security updates;
all PRs still face the lockfile gate. The actual next Dependabot run remains
the integration check for this shared-manifest layout. See the public
[Dependabot grouping reference](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#group-by-groups).

The Rust dependency downloads happen before Cargo validation is switched to
offline mode. The dependency-policy job is intentionally different: it obtains
current advisory data once, audits the root lockfile during that refresh, and
reuses the same database without another fetch for the fuzz lockfile. Its
vulnerability result therefore reflects the RustSec database available when
the workflow ran, rather than a permanently reproducible snapshot.

The Linux `Rust tests` lane downloads the public cargo-nextest 0.9.145
`x86_64-unknown-linux-gnu` release from `nextest-rs/nextest` and verifies the
pinned archive SHA-256 before execution. Nextest runs the same locked workspace
with all features, using `--partition slice:1/2` and `slice:2/2` to distribute
every test across two runners. See the public nextest 0.9.145
[partitioning documentation](https://nexte.st/docs/ci-features/partitioning/).
Because nextest does not execute Rust doctests, partition 1 runs the complete
workspace doctest set separately with Cargo. The `aster-node`
`mesh_cli` binary is assigned to a single-threaded nextest group so its
real-process tests cannot overlap each other on the same runner; the nextest
limit remains two workers per runner. Matrix fail-fast is disabled so a failed
partition does not cancel the other partition.

The required macOS lane does not repeat the OS-agnostic workspace suite already
covered by the two Linux partitions. It uses `cargo test --no-run` to retain
Apple ARM compile and link coverage for every all-feature test target, then
runs the platform contracts in `tools/test-macos-compatibility.sh`. The runner
uses the same systemd-workspace and Compose-package target directories for the
compile and execution phases. Each phase also uses the same Cargo package and
feature selection, so the focused contracts execute the already-linked test
binaries instead of compiling the dependency graph again. The complete macOS
workspace suite remains available in the separate `macOS full suite` workflow,
which runs weekly and on manual dispatch. That workflow is diagnostic and is
not part of the `CI` workflow.

### Test classes and timing evidence

Tests are grouped by the boundary they prove rather than by source-file size:

| Class | Boundary | Required PR lane |
| --- | --- | --- |
| Unit | Deterministic behavior inside one Rust component | Linux nextest partitions |
| Integration | Multiple in-process components or one public binary/API boundary | Linux nextest partitions or `quality` |
| Real process | Starts child Aster processes, binds sockets, or exercises restart/shutdown | Serialized nextest group or `quality` process smoke |
| Platform contract | OS-specific compile/link or fail-closed behavior | Focused required macOS lane and applicable Linux tests |
| Qualification | Validates retained evidence or a named evaluation profile | `quality`; claims remain limited to the named profile |
| Device/hardware | Exercises physical systems, packaging, networks, or resource brackets | Separate retained validation; never inferred from hosted CI |

The functional population uses three complementary evidence forms:

- **Default correctness tests** use the smallest deterministic fixture that
  crosses the semantic boundary. They run in the normal local and required-CI
  population.
- **Production-limit contracts** assert configured production constants and
  fail-closed validation without allocating production-scale fixtures merely
  to prove a constant.
- **Explicit qualification and benchmark commands** retain intentionally
  physical-scale, multi-process, or device workloads. They are named,
  runnable, excluded from default nextest selection, and documented with the
  environment to which their evidence applies.

Fixture minimization changes neither requirement credit nor capability
maturity. A requirement keeps credit only when its original behavioral
assertions remain in a default correctness test or the applicable retained
evidence; moving physical scale to qualification does not add credit, and
reducing a fixture without changing its semantic boundary does not remove it.

The two Linux nextest partitions use the `ci` profile in
`.config/nextest.toml`. Each partition writes one bounded JUnit report without
successful-test output, appends its twenty slowest tests to the Actions step
summary, and retains the raw report for 14 days. Partition reports remain
separate so skipped tests and repeated identifiers are not merged incorrectly.

The 10-second per-test target is advisory. Reports tag every finite duration
above the target, while durations at or below it remain untagged. Duration
problems do not terminate tests, make functional CI fail, create an allowlist,
or trigger retries. Missing, empty, malformed, negative, NaN, or infinite timing
evidence still fails closed because the measurement itself is invalid. Raw
JUnit remains the authoritative artifact, and an individual local or hosted
duration is an observation rather than a performance guarantee.

### CI critical-path profile (2026-09-17)

Recent successful Linux quality jobs took approximately 31--38 minutes. In
representative run `35188617562`, `mise run check` took 26 minutes 41 seconds;
the complete workspace test command accounted for 19 minutes 34 seconds, while
Clippy accounted for 2 minutes 13 seconds. Run `35198052279` completed quality
in 37 minutes 39 seconds after the resource-bound wrapper was corrected for its
two-CPU runner. These are hosted-run observations, not performance guarantees.

Three existing real-process demo tests were a material part of that serial test
time. Their phases used the topology-scaled duration as both a watchdog and the
normal completion mechanism even after the exact application/contact receipts
were durable. The parent now observes every active process's readiness, every
non-relay application receipt, and either every exact authenticated edge receipt
or the required denied-contact receipt. It then requests graceful shutdown.
The original child `--run-for` bound and the longer parent deadline remain as
failure watchdogs, and all stopped-state, exact-transfer, authorization, and
restart assertions remain. On the local 2026-09-17 comparison, the same three
tests completed in 69.90 seconds instead of approximately 229 seconds; this is
a development-host result, not hosted-CI or throughput evidence.

`mise run check` remains the complete local aggregate, in its established
command order:

1. `mise run check-foundation`
2. `mise run check-clippy`
3. `mise run check-workspace-tests`
4. `mise run check-integration`

The aggregate uses sequential `{ task = "..." }` run entries, supported by
the pinned [mise 2026.4.28](https://github.com/jdx/mise/blob/v2026.4.28/docs/tasks/running-tasks.md#execution-order),
instead of shell commands invoking mise. A failed step stops the sequence.

Hosted Linux CI runs `mise run check-clippy` alongside two nextest partitions,
while `quality` runs `check-foundation-core` and the integration segment. The
required `cargo-lockfiles` prerequisite owns the Cargo graph validation in CI;
the local `check-foundation` aggregate composes `check-lockfiles`,
`check-foundation-core`, and `check-compose-policy`, so local coverage remains
complete without repeating the prerequisite in `quality`. CI runs the Compose
OCI inspection suite separately from the foundation core so it executes once. Locally,
`mise run check-workspace-tests` executes the complete suite without
partitioning and then all doctests.
No test, feature set, receipt assertion, binding check,
conformance check, or process smoke is omitted. This removes the Clippy wait
before workspace tests and distributes test execution at the cost of extra
runner setup and potentially duplicated cold-cache compilation; compare cold
and warm hosted runs.

### Compiler cache

- The Linux `quality`, `Rust Clippy`, and `Rust tests` lanes use `sccache` v0.16.0 through
  `sccache-action` v0.0.11 in read-write mode. GitHub isolates pull-request
  writes to the PR merge ref, allowing a cold PR run to populate its cache and
  a rerun of the same PR to measure warm-cache performance without modifying
  the default-branch cache. Idle shutdown is disabled for these lanes so the
  action retains complete statistics through the long test-only tail of
  `Rust tests`; the runner still terminates the local daemon at job cleanup.
- The cache namespace is separated by operating system, architecture, Rust
  version, and an explicit manual generation. `sccache` additionally keys each
  compilation result by its compiler inputs. Incremental Rust compilation
  remains disabled.
- The bounded fuzz lane uses the separate
  `aster-linux-x86_64-nightly-2026-08-18-fuzz-v1` read-write namespace. This
  prevents sanitizer-instrumented nightly objects from mixing with the stable
  Rust cache while allowing repeated pull-request runs to reuse compatible
  fuzz compilation results. Its cache server remains alive through the
  campaigns so the action can report final hit and miss statistics.
- The required and full macOS lanes use the separate
  `aster-macos-arm64-rust-1.97.1-v1` read-write namespace and disables dev/test
  debug information. Apple ARM compiler objects remain isolated from Linux
  objects.
- The workflow does not archive the complete Cargo `target` directory. Cache
  eviction, storage limits, hit rates, transfer time, and compilation time
  remain visible in the Actions and `sccache` statistics.
- Public sources: `sccache` v0.16.0 / Apache-2.0,
  <https://github.com/mozilla/sccache>; `sccache-action` v0.0.11 / Apache-2.0,
  <https://github.com/mozilla-actions/sccache-action>.
### Repeated setup

Run [35365004599](https://github.com/edgesoftops/astertech/actions/runs/35365004599)
at `4c79230540a955e36f9e5cf680c7e4136726f469` provides the setup baseline:
`quality` took approximately 9m42s, including 3m25s building CPython; dependency
policy took 8m35s, including 8m03s installing `cargo-deny` and `cargo-audit`.
The longest lane was `Rust quality` at 23m11s despite 953 compiler-cache hits
and zero misses. These are observations from that run, not expected savings
or measurements of the setup caches below.

The workflow reuses two small, separate sets of installed tools through
SHA-pinned [`actions/cache` v6.1.0](https://github.com/actions/cache/tree/55cc8345863c7cc4c66a329aec7e433d2d1c52a9)
(MIT, CI-only):

- **CI Python:** cache only the installed CPython prefix, keyed by Ubuntu
  24.04, architecture, and a hash of the source-build script and CI workflow.
  There is no fallback key. A recipe change or cache miss runs the original
  checksum-verified source build. Native prerequisites are still installed
  and logged on every run. A hit must pass the same extension-import and
  close-from checks before PATH selection, then the existing direct/nested
  mise preflight and process contract tests. See [CI Python](ci-python.md).
- **Policy tools:** cache only `cargo-deny` and `cargo-audit`, keyed by Ubuntu
  24.04, architecture, Rust version, and both tool versions. A miss runs the
  existing locked Cargo installs; both versions are checked before use on
  every run. Advisory data and audit results are not cached: the database
  refresh, root/fuzz audits, and dependency-policy checks still run each time.
  Increment the key's `v1` suffix to force a rebuild with unchanged pins.

Caches are optional acceleration: an absent entry rebuilds the tools. Measure
a cold and warm hosted run before claiming a speedup. These setup changes
reduce repeated work in the affected lanes; separating Clippy and partitioning
the tests targets the previous longest lane. Shared checkout, mise, and sccache steps use YAML
anchors. The validation commands are retained.

### Deferred options

- Larger private-repository runners may reduce compile and test time, but their
  availability and recurring cost need an explicit operational decision.
- Real-Event delivery spends roughly 8 minutes building its isolated Docker
  image. It runs in parallel and is not the current required-check critical
  path, so prebuilt images remain separate work.
- Higher per-runner test concurrency is not adopted. Each of the two partitions
  keeps the existing worker and process-fixture limits.

## Manual Linux build

Run **Actions → Build: Linux x86_64 → Run workflow**, then choose a branch.
The workflow file must first be merged into the default branch for the button
to appear.

This independent workflow runs `mise run build` on Ubuntu 24.04 to build `aster`
(package `aster-node`) and `aster-agent` (package `aster-agent`) for
`x86_64-unknown-linux-gnu` in release mode. Download `aster-linux-x86_64-<commit SHA>`
from the run's **Artifacts** section; it contains `aster-linux-x86_64.tar` and
is retained for 14 days. The build is manual and is not part of the `CI` workflow.

## Manual Ubuntu Debian packages

Choose the required architecture in **Actions**, then **Run workflow** and
select the source branch:

| Workflow | Native runner | Package |
| --- | --- | --- |
| `Build: Ubuntu 24.04 deb amd64` | `ubuntu-24.04` | `aster_*_amd64.deb` |
| `Build: Ubuntu 24.04 deb arm64` | `ubuntu-24.04-arm` | `aster_*_arm64.deb` |

These are independent `workflow_dispatch` workflows. Starting one does not
start or cancel the other. Their files must be present on the default branch
for their manual launch buttons to appear. They are not part of the `CI` workflow.
The runner labels follow the [GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

Both use the same `debian/build.sh` and Debian rules: acquire locked Cargo
dependencies, build the native package offline, validate ELF architecture and
SBOM/checksum payloads, then install and exercise the protected service on the
disposable runner. They include `aster`, `aster-agent` and
`aster-credential-admin`. No cross-compilation or emulation is used.

In a successful run's **Artifacts** section, download `aster_<version>_<arch>.deb`
directly: the package is uploaded without an outer ZIP using SHA-pinned
[`actions/upload-artifact` v7](https://github.com/actions/upload-artifact/tree/043fb46d1a93c77aae656e7c1c64a875d1fc6a0a)
with `archive: false`. Build records are a separate
`aster-ubuntu24.04-<arch>-metadata-<commit SHA>` ZIP containing `.buildinfo`,
`.changes`, `SHA256SUMS` and `metadata/` with SBOMs, license/build records and
hashes of packaged binaries. Extract those records next to the downloaded `.deb`
to verify `SHA256SUMS`. Both artifacts are retained for 14 days. The `.deb`
contains no documentation. A configured workflow alone is not evidence of a
successful build or runtime test; keep the actual run result.
See the [package candidate](../release/ubuntu-24.04-deb.md) for build scope and
the [existing operations procedure](../mvp/raspberry-pi-provider-v2-operations.md#ubuntu-2404-amd64-package-annex)
for the currently documented amd64 installation procedure.

## Network reliability under contention

Run the bounded loopback diagnostic from the repository root:

```sh
python3 tools/test-network-contention.py --rounds 3 --cpu-workers 4 \
  --test-threads 4 --output /tmp/aster-network-contention-run
```

The output directory must be new. The runner builds the locked, offline,
all-feature node and Iroh library tests before starting CPU load. Each round
runs the complete Iroh suite concurrently with the selected Blob convergence,
State/Record convergence and resolution, Blob contact-fault, and progress
watchdog tests. Each binary also runs its selected tests in parallel. The
runner retains all output, commands, source identity, load settings and exit
codes in the output directory; it stops on failure rather than retrying to a
pass. CPU workers and test process groups are cleaned up on exit. A round has
an independent outer deadline, including if a test stops responding.

The full workspace test commands in `mise run check` and the macOS CI lane use
`tools/with-test-resources.sh`. The 256-pair relay fixture alone owns 1,024
socket descriptors, before its listener/runtime files and neighboring tests.
The wrapper applies the CI's owner-only `077` umask, disables incremental and
debug-info artifacts, and defaults Cargo build jobs to 2 and Rust test threads
to the smaller of 4 or the host's online CPU count. This keeps the two-core
Linux CI runner at its previously stable concurrency while preventing a
high-core developer host from multiplying the all-feature workspace test's
memory and disk demand without bound. Explicit caller overrides still win. It
also raises the child process's soft open-file limit to at least 4,096,
preserves a larger existing limit, and fails clearly if the hard limit cannot
support it. These execution bounds do not reduce fixture scale or change the
host's hard limit. For the same direct workspace runs, use:

```sh
sh tools/with-test-resources.sh cargo nextest run --locked --workspace --all-features --no-fail-fast --test-threads 2
sh tools/with-test-resources.sh cargo test --locked --workspace --all-features --doc
```

Because the systemd and Compose packages intentionally both deliver a binary
named `aster-agent`, this exact wrapper grammar (also with a pinned `+toolchain`
and optional `--offline`/`--no-run`) executes two package selections with
distinct target directories. The first excludes `aster-compose-credentials`;
the second tests it directly. This prevents Cargo's shared output filename from
making either package inspect the other package's binary. Other wrapper command
shapes are executed unchanged. The macOS compatibility runner constructs these
same two selections directly, first with `--no-run` and then with the
`platform_compat_` filter, and pins both phases to their matching target
directory. Keep those selections and target-directory assignments paired when
adding a macOS platform contract; using an unpartitioned target directory can
reintroduce the binary collision, while using a third directory discards the
compiled artifacts and repeats the build.

These tests keep exact data and zero-contact-error assertions. Blob waiting
tracks committed carrier prefixes. State/Record waiting counts each expected
version once per node; duplicate queries or oscillating observations cannot
reset its stall timer. Both also retain absolute deadlines. This is functional
reliability evidence under a declared synthetic CPU load, not a performance
benchmark, packet-loss test, target-hardware qualification, or hosted-CI result.

Blob convergence, State/Record convergence, and Record-resolution waiting each
allow 30 seconds without new durable progress, using the production
`CONTACT_DEADLINE` directly. Each absolute cap remains 60 seconds. This aligns
the budget lengths; the watchdog and contact timers start independently, so it
is not a guarantee of contact completion.
Resolution probes also check for contact errors and report authenticated-contact
counts against the pre-wait baseline. Contact counts do not extend the watchdog;
only newly observed expected versions do. Carrier deadlines and exact projection
assertions are unchanged.

Selected in-process node pairs bind their actual responder to port zero and
use its readiness-reported address to start the initiator. The responder owns
its socket throughout; the fixture does not reserve, release and reacquire a
port. The higher-identity responder needs only the peer's authenticated identity
for inbound contacts; its unused outbound address is never dialed. This reuses
the existing startup handoff without adding a public lifecycle API. The separate
CLI/process fixtures still have explicit topology/restart port requirements
and their existing per-binary serialization; this change does not claim to
eliminate every fixed-port fixture.

The rejected-request test checks both that a rejected local authorization never
invokes the payload writer and that a subsequent authorized exchange completes.
The receiver checks bytes incrementally. An observation timeout is a failure,
not evidence that no payload was sent.

The Linux `Rust tests` lane uses the CPU-aware test-thread cap from
`tools/with-test-resources.sh`. Narrow isolation in individual process fixtures
remains. Investigate errors before weakening zero-error assertions or
increasing carrier deadlines.

Historical local validation on 2026-09-08:

| Run | Environment and result |
|---|---|
| Contention diagnostic, network code `34699e8` | macOS ARM64, 18 logical CPUs, four CPU-load workers, four test threads per binary: three rounds passed; 102 Iroh and 33 selected node/progress test executions. |
| Contention diagnostic, network code `a0b7154` | Linux ARM64 container, two CPUs, two CPU-load workers, four test threads per binary: three rounds passed; 102 Iroh and 33 selected node/progress test executions. |
| Complete `mise run check` with the then-staged integration set and descriptor wrapper | Passed in an isolated full clone at `b746307`: formatting, policy/trace checks, Clippy, Rust workspace, real application smokes, conformance, Python bindings, all 202 lab tests, and Go bindings. |
| Parallel Linux workspace with the then-staged integration set and descriptor wrapper | 1,226 passed, seven existing ignored tests. Rust 1.97.1, default test parallelism, owner-only creation mask, test/dev debug info disabled. The approximately 2-GB VM required one build job and the pinned Rust image's bundled LLVM linker; these build settings did not serialize tests. |

For the complete local gate, use a full clone: the signed-source lab checks
require a real `.git` directory and reject linked worktree metadata. When
sharing `CARGO_TARGET_DIR`, also make the built FFI library available at the
checkout's expected `target/debug` path for the Python and Go binding checks.
The validation clone used an owner-only creation mask (`umask 077`).

The binding semantic-version and secure-umask fixes are now part of `main`.
The 2026-09-08 combined validation checkout also contained an experimental
mission-lock change while investigating two provisioning failures. That
historical composition is not a prerequisite for this network branch, and the
mission-lock change remains separately paused for ownership-contract review.

On 2026-09-10 this branch was composed with `main` at merge commit `31b7b24`
without the mission-lock change. Focused validation through the owner-only CI
shell passed the direct-Iroh Blob convergence/restart test in 11.5 seconds and
the State/Record convergence/resolution test in 28.6 seconds. Five Blob-progress
watchdog tests, three mutable-convergence watchdog tests, and both
authorization-before-write tests also passed. Formatting, descriptor-wrapper
syntax and behavior, and contention-runner parsing passed.

The first composed hosted run exposed a test-fixture race under parallel load:
the elected responder's production fallback timer could expire while the
preferred initiator was still completing its authenticated handshake. The
resulting intentional collision resolution recorded the aborted redundant
handshake as a failed contact. The shared direct-contact test helper now keeps
only its elected responder passive beyond both convergence phases; production
election, fallback timing, and zero-contact-error assertions are unchanged.
After that fixture change, the exact failed State/Record test passed, the
direct-Iroh Blob test passed in 11.7 seconds, and one four-worker/four-thread
contention round covering all three shared-helper scenarios plus the watchdog
suites passed in 31.8 seconds. This focused result does not replace the required
hosted CI run on the updated branch.

The Linux image was the repository's existing pinned Rust image,
`rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97`.
These are local workstation/container observations, not hosted Actions results
or new product-requirements acceptance evidence. Raw attempts, including the
low-descriptor-limit failure and linker-memory failures, were retained with the
implementation task; successful retries followed specific environment fixes.

## Selected composition coverage

`aster-profile`, `aster-redb-store`, `aster-negentropy`, `aster-iroh`, and
`aster-node` are workspace members. The quality lane therefore formats, lints,
and runs their unit and integration tests; the macOS lane tests them; the MSRV
lane checks every target and feature; and the dependency-policy lane audits
their locked graph. The MSRV is Rust 1.91 because the selected Iroh 1.0.3
carrier requires it. `aster-node` enables only `aster-core`'s bounded
`reference-session` feature in its normal graph; SQLite and `rusqlite` are not
present in the selected node's normal dependency graph.
`tools/check-selected-node-dependency-boundary.py` enforces that graph
mechanically: required selected crates and `reference-session` must remain
reachable, while `sqlite-store`, `adapter-sdk`, SQLite packages, the legacy
host/IP runtime, the lab, and the libp2p pilot must remain absent.

The normal node graph already reaches Iroh's client-side `iroh-relay` package;
it does not enable `iroh-relay/server`, `iroh-relay/test-utils`, or
`aster-iroh/test-utils`. The direct `rustls` 0.23.43 edge used to construct
explicit relay trust adds no package or version beyond the existing lock.
Only the dev/all-feature `aster-iroh/test-utils` fixture enables the
`iroh-relay` server and test features and their server/ACME package graph. The
expanded lock and test graph still requires the ordinary exact-license,
advisory, SBOM, supported-target, and release-admission review; a green fixture
test is not production server admission.

The retained parent PR-A/pre-subscription 2026-08-24 frozen-tree run passed 336
`aster-core`, 57 redb-store, 48 node-library, six node-binary, and ten
node-integration tests plus doc tests.
Formatting, Clippy with warnings denied, current-toolchain workspace validation,
and the Rust 1.91 every-target/every-feature check passed. Five bounded fuzz
targets completed 10,000 cases each (50,000 total) without a finding. These
counts are execution evidence for that parent snapshot, not PR-B/current-tree
evidence or release authorization.

PR B adds a separate selected Event subscription gate. Store tests cover
partial/wrong-kind migration, corrupt and terminal-open handling, canonical
Consume/Carry projection and selector generation, idempotent subscription replay
and conflict, attempts across reopen, idempotent semantic-ID acknowledgement,
gap delivery, zero-match cursor advance, inactive-pending retirement, and stale
plan/policy rejection. Frame tests enforce a maximum of 256 canonical selectors
and empty-as-receive-none. Application/runtime tests freshly source/content
verify poll candidates and prove that protected receiver interest transfers
subscribed `beta`, withholds authorized-unsubscribed `alpha`, and transfers
nothing when the durable selector set is empty. These are current code/test
claims only; no retained real-process PR-B root is identified here.

PR C extends that current-code gate through the running node's sole actor.
`SelectedEventHandle` covers async publish/query/subscribe/poll/ack,
idempotent unsubscribe, bounded authenticated gap inspection, and sanitized
peer/last-contact status. The selected store adds atomic selector removal,
delivery-ledger purge, monotonic selector generations, and policy-bound gap
plans that are freshly verified and race-rechecked before exposure. The
compiled `live_event_application` example exercises the public surface while
no peer is configured.

The PR-C validation set includes all of the following:

```sh
cargo check -p aster-node --all-targets
cargo test -p aster-node --all-targets --no-run
cargo clippy -p aster-node --all-targets -- -D warnings
cargo test -p aster-node application::tests
cargo test -p aster-node oversized_run_for_is_rejected_before_readiness_or_state_mutation
cargo test -p aster-node queued_live_zeroization_outranks_an_elapsed_run_for_deadline
cargo test -p aster-node run_for_preempts_a_saturated_application_queue_and_closes_every_caller
cargo test -p aster-node authenticated_contact_status_progresses_with_saturated_application_queues
cargo test -p aster-node live_selected_event_actor_is_peerless_durable_and_closes_admission
cargo test -p aster-node live_zeroization_closes_selected_event_admission_before_erasure
cargo test -p aster-node --test mesh_cli \
  offline_publish_later_real_process_sync_poll_ack_and_restart -- --exact
```

The application module has seven passing tests. Focused runtime cells prove
peerless live operations, reject an overflowing `run_for` before readiness or
state mutation, ensure a queued zeroization request outranks an already elapsed
deadline, preserve a nonzero operational interval under saturated application
callers, allow authenticated contact/status progress despite saturated callers
and continuously overdue one-nanosecond ticks, and close admission during
shutdown/zeroization. The focused Unix integration cell uses separate processes
and stores to publish with no configured peer, restart into a later
authenticated contact, poll and acknowledge at the receiver, and verify the
acknowledgement after receiver restart. The current-toolchain selected-code
suite passed 499 of 499 tests: 336 core, 68 node-library, six node-binary, 13
`mesh_cli`, and 76 selected-store tests; the examples had no tests.

A later timeout-only hardening gave the offline cell one shared 40-second
cold-start deadline across retries and kill/reap cleanup on publisher spawn
failure.
Against the final test bytes, that focused cell then passed twice on the current
toolchain and three times on Rust 1.91.

The separate exact-tree Rust 1.91.0 matrix then passed 499 of 499: core 336/336
(126.48s), node library 68/68 (28.43s), node binary 6/6 (0.02s), `mesh_cli`
13/13 (148.26s), and selected store 76/76 (31.81s); the examples had no tests.
These are separate executions; their timings are not pooled. No individual
offline-cell elapsed time or retained execution root is claimed.

The frozen SHA-256 identities are:

- `crates/aster-node/src/application.rs`: `2ad1b080bfed2ba654b0d29c0cd6eab5f1eb6f4799dbb09203dc18a085b713d0`
- `crates/aster-node/src/runtime.rs`: `81021e226bd413826e3afcea6adf7e8c6e0f22f547f59631a30238e1a015c6c2`
- `crates/aster-node/src/lib.rs`: `b3a684b32b474c5ee22d1c24e0e7bdb19ff2f9613ca42cf3cdf3ebda5262476c`
- `crates/aster-node/examples/live_event_application.rs`: `e31a456a98950d5439b3b6ecd6492f0cbdfb50ad827856c97041b9645d278f82`
- `crates/aster-node/tests/mesh_cli.rs`: `59c858c0bc559944546e88eefee550523fd64905e4b2779a9a3d1a7eb2b8ce0e`
- `crates/aster-redb-store/src/lib.rs`: `364e5a1d8d7f7b24ab75afe8ec2791023db83b11997bd07722c7d107a16a6a00`

At that frozen PR-C tree, this was current-code automated loopback evidence
only: no retained PR-C execution root or log artifact, physical system,
independent implementation, or release artifact is claimed.

The later stopped/local State, Record, and Blob gates are additive to that Event
surface and do not change its wire. Record validation covers the typed
source-envelope seam, bounded mission-bound tables and operation ledger,
shared Event/State/Record causal high-water, independent conflict-reducer
recomputation, explicit exact-sibling resolution guards, and the public stopped
facade/example. Representative focused commands are:

```sh
cargo test --locked -p aster-core source_record
cargo test --locked -p aster-redb-store record
cargo test --locked -p aster-node application::record::tests
cargo run --locked -p aster-node --example record_application -- \
  STATE_DIR MISSION_BUNDLE
```

The exact focused Record suites passed on both the pinned current toolchain and
Rust 1.91.0: core 7/7, selected store 7/7, and selected-node 8/8. The node tests
cover independently authenticated N-way heads, ordinary-publish conflict bypass
rejection, stale and changed guards without mutation, exact restart/rekey retry,
visible tombstones without delete-wins, post-rekey inactive-row verification,
valid metadata tamper with unchanged sealed bytes, sanitized errors, and writer
exclusion. Store tests additionally cover arrival independence, both complete-
ID directions, shared causal ledgers with disjoint class indexes, collision,
quota, schema/reopen, and terminal-state invariants. No test invokes a
registered application merge policy during ingest.

Automatic registered-policy merge, finite TTL design (the selected form is
rejected), expiry/garbage collection, selected-node bindings, physical
systems, mixed implementations, and scale remain open.

The subsequent stopped/local Blob gate adds a typed source-manifest capability,
mission-bound redb publication/operation/read-plan authority, a bounded
encrypted sibling depot, and synchronous `SelectedBlobNode` publish/read
streaming. Representative focused commands are:

```sh
cargo test --locked -p aster-core source_blob
cargo test --locked -p aster-redb-store blob
cargo test --locked -p aster-node application::blob::tests
cargo run --locked -p aster-node --example blob_application -- \
  STATE_DIR MISSION_BUNDLE INPUT OUTPUT
```

The core tests distinguish route-only from content authority, reject wrong
class/mission/source/epoch/group/route root, tampered manifest or envelope,
empty/flexible-chunk inputs, and a forged store completion whose wrong records
and final digest are mutually consistent. Store tests cover crash boundaries,
marked-file corruption without repair, schema migration/nonrepair, exact
operation conflict/caps/replay, policy/revocation/epoch ordering, cross-class
causal and identity collisions, aggregate quota rollback, terminal-before-
depot ordering, unfinished import handling, and bounded reopen audit. Node tests
cover multi-chunk bounded streaming, exact retry and changed-source conflict,
same-variant no-growth, rekey variant separation, source-valid wrong key/variant
claims, fresh inactive-candidate verification, stale read-plan rejection,
revocation, exclusive writer ownership, depot tamper, and terminal zeroization.

`BlobId` is exact object identity over plaintext bytes, the canonical chunk
profile, and media/schema identity metadata; it is not a metadata-independent
whole-byte identity. `BlobDepotLimits` reserve canonical ciphertext-file bytes
for every durable expected chunk record, count all durable per-chunk metadata
rows, and count every public or unpublished import variant. Retained unpublished
rows remain charged pending explicit GC; untracked hostile filesystem entries
and complete physical allocation are outside the counters. The public peak-buffer
field reports the core Blob engine's capacity; generic store adapters may use
additional independently chunk-bounded buffers, so it is not a whole-operation
memory measurement. No test in this gate is a Blob contact, remote/any-peer
resume, maximum-size acceptance, physical-storage result, retained execution
receipt, or release artifact.

The database is pinned to one fixed local depot owner on its first successful
Store open, not treated as a portable backup. Redb persists a domain-separated
commitment over a random owner token, canonical store path, and Unix
device/inode when available; the depot marker must carry the same binding
before any chunk/variant scan or reclaim. The first database to initialize a
parent’s depot wins, and another cannot adopt it. Moving/copying even an empty
bound database to another path fails on reopen. On Unix, a new inode also
fails, moving the depot with the database does not preserve the binding, and a
same-path replacement cannot adopt an existing depot. No supported
depot-rebind/restore path is claimed. Non-Unix keeps token-plus-canonical-path
binding but cannot distinguish a copied database restored over that same path,
so equivalent inode/rollback resistance is not claimed.
The owner-token/binding migration is all-or-none and admits missing fields only
for canonical empty Blob rows/counters with no fixed depot root; partial
fields, any logical Blob state, or any fixed depot root fail without repair.

The subsequent selected Event custody gate originally added semantic-v3
authenticated cumulative age; current semantic v4 inherits that format. The
gate also adds Linux finite Event TTL, priority-sensitive scheduling/retry, bounded
logical aggregate and exact-scope quotas, retirement/fences, constrained
emission, receive-only ingestion, protected lane-defer acknowledgement,
receiver-relative apply disposition, and generation-scoped sender suppression
receipts.
Representative focused commands are:

```sh
cargo test --locked -p aster-core --features reference-session custody
cargo test --locked -p aster-redb-store --lib custody
cargo test --locked -p aster-node --lib receive_only_v3
cargo test --locked -p aster-node --lib v3_preopen_stale_work
cargo test --locked -p aster-node --lib same_epoch_rekey_restart
```

The carrier test separately rejects in the callback after acquiring a QUIC
stream and before writing application bytes. Node tests cover ReceiveOnly blind
v3 offers without local inventory/control disclosure, threshold and priority
order, exact TTL boundaries, pre-open stale-work continuation, post-open
zero-byte/fatal rejection, live policy revision races, bounded contact defer,
same-epoch historical source lineage and v1 witness migration, cache warm/reuse,
and final query/poll expiry withholding. Store tests cover exact-scope quota
configuration, aggregate quota enforcement/rejection, authority reserve,
continuous/lost age, route promotion, retirement/lease drain, retry/receipt
settlement, sender/receiver visibility, crash-reopen cleanup, cardinality/audit
corruption, and one-transaction bounded scheduling.

This is current-code automated evidence, not a retained physical acceptance
receipt. That retained finite-TTL boundary is Linux/Event/v3-format only,
inherited in v3-v8; semantic-v8 Blob finite custody/lifecycle is separate
current-code evidence without retained credit.
receive-only is not physical RF silence. V1/v2 deterministic whole-contact
partials, generic cross-class priority eviction, selected State/Record custody
or future TTL design (the current finite form rejects), long-offline and
many-node scale, mixed implementations, operational provisioning with a
production backend or protected stock CLI/binding, and release gates remain
open. Caller-provided protected Rust `NodeConfig` construction is tracked by the
separate current-code gate below.
Networked Blob was outside that Event-custody receipt; the separate historical
v5 compatibility and current v7/v8 stream/lifecycle gates below do not relabel it.

The ordinary ready deadline is raised to 40 seconds; the cold offline
cell uses separate 90-second startup, 120-second contact, and 150-second
completion bounds.

The later frozen source slice adds caller-provided protected live bootstrap and
actor-owned live control administration. Its focused reproduction commands are:

```sh
cargo test --locked -p aster-core provisioning --lib
cargo test --locked -p aster-node mission::tests --lib
cargo test --locked -p aster-node control_admin::tests --lib
cargo test --locked -p aster-node --test protected_runtime -- --test-threads=1
cargo test --locked -p aster-node \
  protected_live_controls_refresh_policy_retry_exactly_and_close_on_shutdown --lib
cargo test --locked -p aster-node \
  live_control_pending_gap_returns_policy_unsettled_and_preserves_exact_retry --lib
cargo test --locked -p aster-node \
  saturated_cloned_live_control_retries_do_not_starve_event_status_or_publish --lib
cargo test --locked -p aster-node \
  cancelled_enqueued_live_control_remains_actor_owned_and_exactly_retryable --lib
cargo test --locked -p aster-node \
  live_self_revocation_returns_receipt_before_actor_teardown --lib
```

The `protected_runtime` integration target names twelve Unix cells covering
exact option/origin preservation, protected bytes and file artifacts, relative
path capture across provider/loader current-directory changes, invalid options,
uninspectable and terminal state before provider access, raw-inner rejection,
sanitized errors, missing artifacts, exact and mismatched secret-load receipts,
and lexical state-witness mutation. Focused core/mission tests additionally name
`secret_reference_is_bounded_canonical_versioned_and_redacted`,
`provisioning_origins_have_stable_nonidentifying_receipt_labels`, and
`protected_state_witness_is_lexical_and_clone_local`.

The live-control cells cover capacity-one pressure with a four-command yield
budget, policy refresh before response, nonfatal pending-policy deferral, exact
retry, graceful shutdown, self-revocation receipt-before-teardown, and
post-enqueue caller cancellation followed by stopped exact recovery. This is a
source-hashed current-code evidence boundary, not a retained execution root,
physical result, or additional `observed-bounded` credit. No production
provider, protected stock CLI/binding, cross-process admin IPC, or coordinated
provider destruction is added. The post-enqueue cancellation cell is Unix-only.

## Semantic-v7 Event page current-code gate

`V-EVENT-PAGES-V7` is an additive current-code gate. It checks semantic
`[8,7,6,5,4,3,2,1]` selection, v8/v7 page inheritance, and v7/v6 fallback,
canonical per-lane profile
negotiation, contextual record AAD, bounded ordered uni turns, receipt-free
durable, finite-TTL, mixed, route-only, and blind ReceiveOnly Event convergence,
finite custody-age admission without per-peer receipt/lease/retry state,
v7/v6 compatibility fallback, interruption with prefix preservation and
remainder-only reconnect, strict
priority/equal-tier rotation, and later-lane reserves. Receiver rejection limits
come only from exact serialization and protected-carrier bounds. Sender page
targets and peer-cursor allocation remain implementation details pending the
paired physical-device calibration; this gate supplies no retained performance,
physical, mixed-implementation, or production evidence. The checked-in
`conformance/vectors/event-pages-v7.tsv` corpus contains 18 canonical ACCEPT
rows and 6 representative malformed REJECT rows; the `aster-node` vector tests
regenerate it from the reference codecs and route every REJECT row through its
corresponding decoder.

The semantic-v4 State/Record gate is inherited unchanged through v8 and
is additive to those frozen slices. The frozen v6 gate used default/highest 6
with `[6, 5, 4, 3, 2, 1]`; the current default/highest is 8 with
`[8, 7, 6, 5, 4, 3, 2, 1]`. Semantic v6 preserves the historical v5 ordinary
frame allocation and adds only the mutually enabled Event-bridge mechanics
lane; selected Blob carrier IO now requires v7/v8 profile 4. Selected mutable
frames are absent in v1-v3 and selected bridge frames are absent in v1-v5.
Focused validation
must cover the complete State/Record class and direction grammar, including all
20 structured mutable tags in `selected_frame_decode`; exact offer
`MutableApplyResult`, fetch `MutableFetchResult` plus required exact
`MutableFetchResultAck`, and Finish/Finished remaining matching; missing,
duplicate, changed, cross-class, cross-direction, and out-of-order rejection;
and v1-v3 plus ReceiveOnly mutable absence. Normal and every AtLeast threshold
must still run mutable lanes because AtLeast is Event-only.

Store/runtime cells must additionally exercise the fatal 1 MiB structural
object limit and, for otherwise-valid authenticated objects, typed effective
ordinary-aggregate/per-class item or byte, 1,024-version per-logical-key
projection, and causal-frontier deferral without mutation. They also exercise
the exact 4,096-row and 16-MiB per-class boundaries, bounded-contact fair
progress, and the durable
peer/class/local Offer/Fetch cursor at 256 peers and 1,024 rows. Cursor CAS,
restart, stale-peer prune, additive-schema audit, malformed/overbound rejection,
ordinary-quota isolation, and terminal preservation are mandatory. Current
route-lineage tests must prove that a same-epoch replacement withholds historical
lineage from ordinary current projection/query and network inventory/transfer while exact
idempotent State publish and Record publish/resolution retries may recover the
committed result only through the strict cached/projection/historical path.
Selected finite State/Record TTL must reject.

Representative focused commands are:

```sh
cargo test --locked -p aster-node frame::tests
cargo test --locked -p aster-redb-store mutable_transfer_cursor
cargo test --locked -p aster-redb-store apply_stops_at_retained
cargo test --locked -p aster-redb-store state_and_record_frontier_capacity_errors_are_typed_and_transactional -- --exact
cargo test --locked -p aster-node runtime::tests::real_iroh_contact_converges_state_and_disconnected_record_siblings -- --exact
cargo test --locked -p aster-node same_epoch_rekey_restart
cargo check --locked --manifest-path fuzz/Cargo.toml --bin selected_frame_decode
```

Event last-contact status is
not State/Record convergence. The later live-application receipt below adds a
bounded two-participant result, not a scale result. Physical links, State/Record
relay, NAT, BTLE, resource brackets, mixed implementations, and release gates
remain open; the separate retained N=32 receipt is Event-only.

The current tree adds a live State/Record application gate after those frozen
stopped and network-mechanics slices. `RunningNode::selected_state()`
and `RunningNode::selected_records()` return cloneable handles backed by the
actor's one bounded Event/State/Record command queue. The cells cover peerless
live publish/query, exact idempotent retry and changed-intent conflict, shared
causal high-water, restart, graceful-shutdown admission closure, mixed-command
queue saturation, direct-Iroh convergence of disconnected State and Record
heads, ordinary-publish conflict preservation, live guarded Record resolution
and exact retry, protected same-epoch rekey recovery, and live zeroization
closing retained State/Record clones with sanitized `StateUnavailable`.

Representative focused commands are:

```sh
cargo test --locked -p aster-node runtime::tests::live_selected_state_and_record_are_durable_idempotent_and_close_admission -- --exact
cargo test --locked -p aster-node runtime::tests::live_mutable_handles_converge_disconnected_state_and_record_then_resolve -- --exact
cargo test --locked -p aster-node runtime::tests::protected_live_mutable_handles_cache_exact_retry_across_same_epoch_rekey -- --exact
cargo test --locked -p aster-node runtime::tests::run_for_preempts_a_saturated_application_queue_and_closes_every_caller -- --exact
python3 tools/test-selected-live-mutable-receipt.py
```

## Selected live State subscription retained gate

The gate separately proves that application delivery does not mutate network
receive policy: one configured-network-interest State remains durably retained
but application-unsubscribed, while one authorized State absent from configured
network interests remains withheld. These are static `NodeConfig` interests;
State subscription creation and replay do not change them.

Create a new owner-restricted raw root only from a clean good-signed checkout,
with the repository-pinned Python 3.13.7 and Rust 1.97.1 runtimes already
installed through `mise`, then project a canonical receipt. Select those
runtimes from a neutral directory and execute the source-bound tools by absolute
path; this avoids trusting checkout configuration merely to run the verifier:

```sh
ASTER_SOURCE=/path/to/clean-good-signed-aster-source
cd /private/tmp
ASTER_PYTHON="$(mise where python@3.13.7)/bin/python3"
mise exec python@3.13.7 rust@1.97.1 -- python3 "$ASTER_SOURCE/tools/run-selected-live-state-subscription.py" \
  --source "$ASTER_SOURCE" \
  --raw-root /private/tmp/aster-selected-live-state-subscription-new

install -d -m 700 /private/tmp/aster-live-state-subscription-projection
"$ASTER_PYTHON" "$ASTER_SOURCE/tools/check-selected-live-state-subscription-receipt.py" - \
  --raw-root /private/tmp/aster-selected-live-state-subscription-new \
  --source "$ASTER_SOURCE" \
  --output /private/tmp/aster-live-state-subscription-projection/selected-live-state-subscription-receipt.json
```

The delivery contract is positive-current-only. Its explicit current tombstone
is a State version, not a synthetic withdrawal; there is no materialized view,
transition feed, Current-to-None event, or dynamic `NodeConfig` interest
mutation.

## Selected live Record subscription retained gate

Create a fresh owner-restricted raw root only from a clean Good-signed checkout
using the pinned runtimes, then project its canonical receipt:

```sh
ASTER_SOURCE=/path/to/clean-good-signed-aster-source
cd /private/tmp
ASTER_PYTHON="$(mise where python@3.13.7)/bin/python3"
mise exec python@3.13.7 rust@1.97.1 -- python3 "$ASTER_SOURCE/tools/run-selected-live-record-subscription.py" \
  --source "$ASTER_SOURCE" \
  --raw-root /private/tmp/aster-selected-live-record-subscription-new

install -d -m 700 /private/tmp/aster-live-record-subscription-projection
"$ASTER_PYTHON" "$ASTER_SOURCE/tools/check-selected-live-record-subscription-receipt.py" - \
  --raw-root /private/tmp/aster-selected-live-record-subscription-new \
  --source "$ASTER_SOURCE" \
  --output /private/tmp/aster-live-record-subscription-projection/selected-live-record-subscription-receipt.json
```

## Selected live Event retained gate

The raw root is owner-only evidence containing participant mission bundles,
identity keys, and stores. Keep it outside source control. The runner/checker
inventory the participant secret files and publication journal by metadata only and never open, read, or hash
their contents. A new capture requires a clean, good-signed source checkout and
a fresh exclusive raw-root path:

```sh
python3 tools/run-selected-live-event.py \
  --source /path/to/clean-good-signed-aster-source \
  --raw-root /private/tmp/aster-selected-live-event-new

python3 tools/check-selected-live-event-receipt.py - \
  --raw-root /private/tmp/aster-selected-live-event-new \
  --source /path/to/clean-good-signed-aster-source \
  --output /private/tmp/event-receipt/selected-live-event-receipt.json
```

Current native Event and Linux custody captures use v2 receipts with an explicit
`numbered-v1` publication model and one private publication journal. The journal
is included in the exact inventory and inspected only by metadata. V2 also
classifies the exact bounded publication diagnostics retained from pipelining;
unknown stderr and inconsistent outcome or writer accounting fail validation. No new
physical or performance qualification follows from this producer migration.

The historical semantic-v5 direct Blob gate is retained as codec and
durable-storage compatibility evidence; Result/Ack/Finish is not current
carrier behavior. The current network gate requires semantic-v7/v8 profile 4,
the stdlib-only same-team construction oracle plus shared ABRS/ABRD/ABRE record vectors,
malformed schedule/hash/index/count/terminal
rejection, and v5/v6 pre-carrier failure. Provider
tests require a current 32-byte peer content proof plus route authority and
nonrevocation and reject route-only, wrong peer/topic/scope/epoch/authority,
tamper, stale proof, and same-epoch replacement. Store tests require source-
before-carrier staging, contiguous peer-neutral prefixes of at most 16 KiB,
64-MiB/1,024-chunk admission, 10,000-row/64-MiB staging bounds, exact depot plus
fresh full-content/current-lineage completion, and zero ordinary visibility
before atomic promotion. A new physical lineage for the same `(BlobID, content
group, numeric epoch)` must fail with `PhysicalLineageConflict`; republish or
resume requires an epoch advance. Current range streaming has no per-range
storage receipt; durable prefixes are the recovery authority, while a valid
schedule-bound terminal plus FIN authorizes completion and one cursor outcome.
Read-only, writable, and terminal-preservation opens must cross-audit
pending source/manifest route/carriers against the depot plan and completed
namespace, rejecting a changed plan, a self-consistent missing plan, or a
pending/completed collision without repair. Writable predecessor migration must add all
four network tables to the prior nine-table Blob group only as one absent group
under the owner-token/binding rules; read-only or partial-group open must not
migrate or repair it.

Startup cleanup must also begin from an authenticated source plus one durable
carrier range and remove exactly the pending source, cached claim, carrier
prefix, and network-staging accounting after each of same-epoch lineage
replacement, numeric epoch advance, and publisher revocation. It must retain
the exact non-public depot import and expected/committed chunk staging—including
rows, files, finalized digest, and reserved/committed accounting—charged to the
existing byte, chunk, and variant caps. Reopen must expose no ordinary pending
or published progress, permit exact-lineage resume, reject a different
same-epoch lineage without mutation, permit numeric epoch advance, and reject a
zero-lineage fence on every open path. Valid later Blob work must succeed and a
second reopen must preserve the same bounded quota charge.

Runtime races are part of the gate. One regression must pause exact restage
between fresh authentication and cache insertion while an abort wins, then
prove the shared source/store/cache lifecycle lock leaves neither an orphan
claim nor an unclaimed durable source and requires no restart. A terminal
content failure must abort only its exact pending source and leave the turn
cursor-neutral. Separately, the successful terminal source-rotation helper must
use a multi-carrier source whose manifest-last carrier is not its greatest ID
and select the later source after advancing to that maximum.

The final runtime gate is one small bounded three-node direct-Iroh case: source
and first receiver make only partial carrier progress, runtime/store/provider
cache ownership tears down, then after reopen a different eligible content peer
continues the same exact source/carrier complement to a fully verified visible
publication. Normal and AtLeast must run the lane because AtLeast is Event-only;
ReceiveOnly must perform zero Blob work. The separate live Blob gate covers an
actor-owned handle, peerless publication, later direct synchronization,
authenticated bounded page reads, restart, and closure, but remains current-code
same-implementation loopback automation.

Representative focused commands include:

```sh
cargo test --locked -p aster-core source_blob::tests::blob_peer_content_proof_is_exact_current_and_identity_bound -- --exact
cargo test --locked -p aster-core schema_v14_migrates_and_v5_provenance_survives_restart -- --exact
cargo test --locked -p aster-node frame::tests::blob
cargo test --locked -p aster-redb-store blob::tests::network_blob_stages_transfers_promotes_serves_and_reopens -- --exact
cargo test --locked -p aster-redb-store blob::tests::pending_blob_audit_binds_exact_manifest_route_and_carriers_on_all_open_paths -- --exact
cargo test --locked -p aster-redb-store blob::tests::predecessor_nine_table_blob_schema_migrates_network_additively_with_owner_tokens -- --exact
cargo test --locked -p aster-node runtime::tests::blob_source_carrier_reopen_resumes_exact_complement_from_different_peer -- --exact
cargo test --locked -p aster-node runtime::tests::stale_pending_blob_cleanup_removes_visibility_but_retains_reserved_staging -- --exact
cargo test --locked -p aster-node runtime::tests::pending_blob_abort_reconciles_concurrent_exact_restage_without_restart -- --exact
cargo test --locked -p aster-node runtime::tests::blob_lifecycle_lock_serializes_delayed_projection_insert_and_abort -- --exact
cargo test --locked -p aster-node runtime::tests::terminal_source_rotation_uses_maximum_object_before_later_candidate -- --exact
cargo test --locked -p aster-node runtime::tests::authenticated_peer_without_scope_grant_learns_no_event_id_and_cannot_fetch -- --exact
cargo check --locked --manifest-path fuzz/Cargo.toml --bin selected_frame_decode
```

The repair retains the bounded
non-public physical-lineage fence, serializes durable-source/cache transitions,
keeps terminal failures cursor-neutral, and uses the lexicographic maximum for
authorized terminal source rotation.
Strict workspace Rustdoc and a fresh isolated `aster-node` plus `aster-iroh`
documentation build are also part of the frozen gate; stale Cargo rmeta is not a
source change or an accepted substitute for the clean isolated build.

## Selected live Blob retained gate

The raw root is owner-only evidence and contains mission and identity material,
databases, depot metadata, and ciphertext. It must remain outside source
control. The checker inventories those private artifacts by metadata only and
does not open, read, or hash their contents. A fresh capture requires a clean,
good-signed source checkout and a new exclusive raw-root path:

```sh
python3 tools/run-selected-live-blob.py \
  --source /path/to/clean-good-signed-aster-source \
  --raw-root /private/tmp/aster-selected-live-blob-new

python3 tools/check-selected-live-blob-receipt.py - \
  --raw-root /private/tmp/aster-selected-live-blob-new \
  --source /path/to/clean-good-signed-aster-source \
  --output /private/tmp/aster-live-blob-projection/selected-live-blob-receipt.json
```

## Selected live Blob delivery retained gate

A fresh capture requires a clean Good-signed checkout and a new exclusive raw
root:

```sh
python3 tools/run-selected-live-blob-subscription.py \
  --source /path/to/clean-good-signed-aster-source \
  --raw-root /private/tmp/aster-selected-live-blob-subscription-new

python3 tools/check-selected-live-blob-subscription-receipt.py - \
  --raw-root /private/tmp/aster-selected-live-blob-subscription-new \
  --source /path/to/clean-good-signed-aster-source \
  --output /private/tmp/aster-live-blob-subscription-projection/selected-live-blob-subscription-receipt.json
```

The raw root contains private mission, identity, database, depot-marker, and
ciphertext artifacts and must stay outside source control; the checker inspects
them by metadata only. The source/binary/execution link remains
operator-attested, not cryptographically proven or reproducible. The receipt
observes no contact or network Blob activity and claims no transfer,
synchronization, peer/convergence status, selector withholding or
network-interest separation, exact-publication plaintext read,
power-loss/filesystem-crash recovery, long retention, TTL/expiry/GC, physical
or mixed implementation, resource threshold/soak, release artifact, or
production authorization.

## Controlled Iroh relay software gate

The controlled-relay slice is bound to signed code commit
`b0a1203f4f24c05edd31e5ce1ea0f3b7f9bd2f52`. Focused carrier tests cover exact
route/trust bounds, relay-only operation with pinned TLS, rejection of a valid
but unrelated CA without trust fallback, usable direct selection, direct
operation while the pinned relay is dead, wrong authenticated endpoint
identity, and bounded relay loss without public-relay substitution. Their exact
test names are:

- `controlled_route_and_trust_bounds_are_exact`
- `relay_only_exact_peer_succeeds_with_pinned_tls_trust`
- `relay_tls_rejects_a_valid_but_unrelated_ca_without_fallback`
- `usable_exact_direct_candidate_becomes_selected`
- `dead_pinned_relay_still_allows_the_exact_direct_candidate`
- `controlled_route_rejects_the_wrong_authenticated_identity`
- `relay_loss_is_bounded_and_has_no_public_relay_substitution`

CLI unit tests require an inseparable URL/trust choice, reject duplicate
relay-only and value flags without reflecting token-bearing values, and keep
the help text bounded and free of authority claims:

- `controlled_relay_flags_are_inseparable_and_trust_is_explicit`
- `relay_only_switch_rejects_duplicate_ambiguity`
- `controlled_relay_value_duplicates_are_rejected_without_echoing_values`
- `help_advertises_bounded_controlled_relay_without_authority_claims`

The serialized real-process cells use one local HTTPS relay with explicit DER
trust. They select Relay when the initiator's exact direct candidate is
unusable and the responder has IP disabled, complete Event transfer and an
equal-inventory no-op, prove an unavailable controlled relay does not block an
exact direct no-op, and reject partial/malformed/duplicate secret-bearing CLI
configuration before state or mission access:

- `controlled_relay_selected_when_direct_candidate_unusable_then_noops`
- `unavailable_controlled_relay_does_not_block_exact_direct_sync`
- `manual_node_rejects_partial_controlled_relay_before_state_or_mission_access`
- `manual_node_rejects_malformed_relay_root_before_state_or_mission_access`
- `manual_node_redacts_duplicate_token_bearing_relay_url_before_state_access`

The focused runtime test
`right_carrier_with_wrong_expected_mission_fails_before_inventory` separately
uses direct Iroh to prove wrong-expected-mission ordering before inventory. It
is not part of the relay-path process proof.

After the final harness correction, the focused relay Event E2E rerun passed
1/1 in 204.69 seconds. The frozen full-matrix receipt remains the serialized
`mesh_cli` result below. The exact final full-repository command was:

```sh
env CARGO_TARGET_DIR=/private/tmp/aster-controlled-relay-full-check \
  CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 mise run check
```

It ran outside the sandbox for loopback tests and exited zero. Visible
constituent timings were `aster-node` library 170/170 in 157.48 seconds,
`mesh_cli` 20/20 in 153.91 seconds, `aster-iroh` 13/13 in 9.28 seconds,
`aster-ip` 50/50 in 2.20 seconds, and `aster-lab` library 32/32 in 53.56
seconds. The remaining workspace suites and doctests, language bindings,
conformance, project-license, selected-dependency-boundary, and
dependency-exception-scope gates also passed. No trustworthy aggregate wall
time was retained.

The exact fresh all-feature documentation command was:

```sh
env RUSTDOCFLAGS=-Dwarnings \
  CARGO_TARGET_DIR=/private/tmp/aster-controlled-relay-rustdoc-final-20260825 \
  CARGO_BUILD_JOBS=2 \
  cargo doc --locked --workspace --all-features --no-deps
```

It exited zero in 57.67 seconds.

This is current one-host software evidence only. Initial direct and relay paths
may be probed in parallel, so it is not a temporal direct-first/fallback result;
authenticated Iroh NAT negotiation may also derive later direct paths, so it is
not representative-NAT acceptance. Path kind and a coalesced transition count
capped at 1,024 are observation-only diagnostics and never authorization or
success inputs. That source/test gate creates no retained receipt by itself and
grants no physical or representative-NAT, BTLE/cross-transport,
mixed-implementation, N=32, resource-bracket,
State/Record/Blob-over-controlled-relay, route-only Blob custody, release, or
`observed-bounded` credit.

The 57th test in that parent redb-store receipt is a Unix writable-open
durability adversary. Every new or existing writer, including a terminal
cleanup handle, must synchronize
the exact retained parent directory before becoming usable. An injected sync
failure exposes no Aster application table, and retry must pass a real barrier.
This is bounded host/filesystem evidence, not non-Unix or physical power-loss
assurance.

The `aster-node` integration suite serializes its process-heavy cells and runs
two real four-node mesh scenarios plus local software-zeroization and abrupt
process-loss cells through the full workspace test command in both the quality
and macOS lanes. The omitted-selector Ping/Pong cell is bounded to 120 seconds.
It requires an isolated peerless Ping publication; a separate two-process
transfer cohort for each forward edge; an isolated peerless Pong publication
that observes the already-durable Ping; a separate two-process transfer cohort
for each return edge; and an equal-inventory no-op. Every directed-edge cohort
must move exactly one pre-existing Event difference, emit no application Event,
and retain zero control counters. Every passing no-op contact must retain zero
for all six control and all five Event counters. The generic schedule has
`2N+1` cohorts and `5N-2` child processes: N=4 therefore uses nine cohorts and
18 processes, while N=32 uses 65 cohorts and 158 executions. The routine
integration cell remains N=4; N=32 is a manual acceptance run. A successful
integration root is removed; use the equivalent manual command when logs and a durable
receipt are needed:

```sh
ASTER_DEMO_PARENT="$(mktemp -d)"
cargo run --locked -p aster-node --bin aster -- \
  demo --nodes 4 --root "$ASTER_DEMO_PARENT/mesh"
```

A pass must finish with
`DEMO_RESULT status=pass scenario=ping-pong nodes=4 processes=18`,
`contacts=real-iroh`, `mission_auth=hybrid-pq`,
`provisioning=unprotected-reference`, `stores=independent-redb`,
`reconciliation=negentropy`, `producer_process_absent=true`,
`emitted_by=running-node-processes`, `restarts=pass`, `atomic_reaction=pass`,
`equal_inventory_noop=pass`, `transfers_each=2`,
`semantics=source-authenticated-event`, `payload_blind_relays=pass`, and
`ttl=durable-none`. Unit-test or demo success does
not override dependency-policy failure and does not authorize a production
release.

The explicit control cell is bounded to 120 seconds and runs:

```sh
ASTER_CONTROL_PARENT="$(mktemp -d)"
cargo run --locked -p aster-node --bin aster -- \
  demo --nodes 4 --scenario control --root "$ASTER_CONTROL_PARENT/mesh"
```

It requires two short-lived authority processes, source-authenticated chained
Flash controls, durable commit before activation, payload-blind control/Event
forwarding while the authority processes and authority carrier node are absent,
recipient-filtered epoch-two access, two denied captured-node cohorts,
epoch-two Ping/Pong among eligible members, restart replay, and an
equal-inventory no-op. The deterministic 23-process sequence is a causal
barrier: after the two-process control-forward cohort converges, node 2 runs
alone with zero peers and contacts to commit epoch-two Ping; only a later
two-process cohort moves that exact Event into node 1's route-only cache. Four
additional stopped-state barriers move that already-durable Ping to node 0,
commit causal Pong in a one-process zero-peer/zero-contact cohort, move Pong to
the relay, and return Pong to node 2. Every passing contact in the final no-op
must report zero for all six control and all five Event reconciliation counters.
Its terminal invariants include
`CONTROL_RESULT status=pass nodes=4`, `controls=2`,
`captured_epoch2_read=denied`, `captured_mesh_publication=denied`,
`captured_rejoin=denied`, `captured_local_signing=stale-only`, and
`DEMO_RESULT status=pass scenario=control nodes=4 processes=23`. The stale-only
field proves that this is exclusion, not local zeroization. A separate
cross-process test requires the exact-path redb writer lock to reject an
authority command while a node owns the same state and permit it after the node
stops.

The Unix zeroization cells are separate from that control scenario. One
same-UID CLI process requests destruction from a live child node. The node must
drain owned work, close its endpoint, terminally lock the redb store, invalidate
derived secret holders, and overwrite/synchronize/truncate the exact retained
mission-bundle and carrier-identity inodes to owner-only zero-length tombstones.
The receipt must say `mode=live state=complete`,
`data_rows_preserved=true`, `assurance=bounded-software`, and
`physical_sanitization=not-claimed`; the node must say
`STOP lifecycle=zeroized sync_status=terminal-lockout`. The test restores the
credential bytes into those same tombstone inodes and requires normal reopen of
the retained database to remain denied. An idempotent retry must report the
external change without erasing the restored data.

A second real child commits the Immediate-durability terminal marker and exits
abruptly before either artifact is erased. The CLI must resume the exact
recorded inode cleanup, preserve the existing data row, and finish both
zero-length tombstones. Additional library/store cells cover wrong mission
authority, path/inode replacement, symlink, hard-link, owner/mode, corrupt or
partial marker, phase ordering, and normal-open lockout. These checks establish
only a same-UID Unix software hook. They do not prove inode deletion,
deterministic remote observation of mid-flight stream teardown, physical or
copy-on-write sanitization, snapshot/swap/backup destruction, redb
rollback/replacement resistance, non-Unix support, remote triggering, or
independent platform assurance.

The node tests establish the existing `aster-core` four-flight hybrid session
over real loopback Iroh and exercise it in the selected runtime before
inventory. They require exact carrier-to-mission binding, protected mechanics
frames, plaintext and replay rejection, tamper rejection, wrong-carrier,
wrong-mission and cross-mission failure, and rejection of Fetch/Offer identifiers
outside the authenticated contact's independently negotiated difference. They
also cover the Event source-envelope seam, the control-envelope and
recipient-filtered-rekey seams, exact-versus-semantic identity, content versus
route capability, mission-bound redb acceptance, strict chained-control
ordering and pending gaps, atomic commit-before-activate, restart activation
replay, stale/revoked rejection, peer scope-route filtering, and durable
reaction replay. The real-process tests require successful protected contacts
on every eligible line edge and the expected failure on captured-node edges.
They remain bounded to Event, one control family/scope, and loopback. The
current code additionally has durable Event Consume/Carry selectors, live and
stopped-state poll/ack, idempotent unsubscribe, verified gap inspection,
bounded last-contact status, protected receiver-directed filtering, and
separate live and stopped State and Record projections plus stopped Blob
streaming and semantic-v7/v8 profile-4 Blob transfer/resume automation;
it does not turn the retained parent roots into PR-B, PR-C, State, Record, or
Blob receipts. Those retained parent tests do not claim networked State/Record
or Blob, remote Blob chunks, global convergence, generalized control
administration, non-Linux/cross-class finite-TTL custody, protected provisioning, platform-complete
zeroization assurance, admitted release cryptography, independent review, or
physical-network acceptance.

Two explicit `cargo deny` advisory ignores cover one bounded active pilot
graph. `RUSTSEC-2026-0173` covers unmaintained build-time
`proc-macro-error2` 2.0.1, and `RUSTSEC-2026-0374` covers unmaintained
compile-time configuration parser `basic-toml` 0.1.10, both in the
non-production age-provider pilot. RustSec reports no vulnerability and no
patched release for either package; current Rust separately emits
future-incompatibility `E0365` for `proc-macro-error2`. The ignores permit only
those exact informational findings. They do not suppress other advisories,
change exact package checksums, permit online execution after the acquisition
step, or authorize the provider for production. Decision 0018 records the
upstream `basic-toml` replacement, release gap, and removal gate.

[Decision 0027](../decisions/0027-libp2p-pilot-dependency-policy.md) admits
`BSD-2-Clause`, `ISC`, and `Zlib` for the reviewed external dependency graph;
first-party packages and distributed project files remain subject to the
separate byte-identical Apache-2.0 gate.

The companion scope gate fails if either ignored package's reverse graph
drifts, if either appears in the separately excluded fuzz graph, or if any
`paste` version reappears. Any change to a package chain or advisory
disposition requires a recorded pilot review.

The selected Iroh graph carries five exact-coordinate license exceptions
recorded by Decision 0028: `webpki-root-certs` and `webpki-roots` 1.0.10 use
`CDLA-Permissive-2.0`, while all-target browser-WASM
packages `async_io_stream` 0.3.3, `pharos` 0.5.3, and `ws_stream_wasm` 0.7.5 use
the OSI-approved `Unlicense`. Neither license is globally allowed. Package or
version drift fails closed, and the project-license gate hash-pins the complete
distribution notices and requires them in the lab image. The CDLA disposition
is a visible stakeholder deviation from the frozen OSI-only requirement, not a
claim of outside-counsel review or requirements credit. Passing this gate does
not by itself authorize a release, extend the earlier 1.0.9 evaluation
approval to the replacement coordinates, or declare browser-WASM supported.

[Decision 0045](../decisions/0045-remove-libp2p-test-oracle.md) supersedes
Decision 0029's retention policy. The experimental provider and only its lab
integration are removed; the rest of `aster-lab` remains.

The provider removal also removes the optional Hickory 0.25.2 lock entries.
The root audit no longer ignores `RUSTSEC-2026-0118` or `RUSTSEC-2026-0119`.
The dependency-exception scope gate now requires only the retained fixed
`hickory-proto` 0.26.2 lock entry and still rejects vulnerable active Hickory.
The unrelated age advisory disposition and exact license exceptions remain
unchanged.

Current-stack regressions in `aster-node::runtime::tests` separate default
serialization coverage from scale qualification. The default
`current_stack_near_two_mib_events_each_direction` test checks the exact
current-stack envelope boundary without a network transfer. The ignored
`qualify_current_stack_near_two_mib_events_each_direction` test uses production
mission-authenticated contacts over persistent direct-loopback Iroh endpoints
and sends two Events each way, each with `MAX_OBJECT_BYTES - 11 * 1024`
plaintext bytes. Run it explicitly with:

```sh
mise run qualify-near-two-mib-events
```

Budget two warm minutes, two CPU cores, 1 GiB of available memory, and 1 GiB of
temporary disk. The measured envelope overhead is checked to be above 10 KiB
and at most 11 KiB; every sealed Event must fit the existing object bound.
Exact source bytes and authenticated plaintext are checked at the receiver.
This is near-two-MiB payload volume per direction, not two exact one-MiB
plaintext Events, throughput evidence, or device qualification.
`current_stack_exact_64_kib_event_after_fresh_auth_reconnect` completes and
closes a contact, retains both endpoint identities and addresses, rejects a
fresh contact with the wrong expected mission identity without insertion, then
reauthenticates and delivers exact 64-KiB Events each way. Contacts do not overlap.
Existing resource tests remain; no replay scenario or telemetry is added.

The manual runtime-volume diagnostic and its workflow are preserved byte for
byte under `archive/diagnostics/runtime-volume/`; its active workflow and CI
caller are removed. The archived telemetry patch is historical, not a current
execution recipe or a port to the selected runtime. These changes grant no
requirements, target-resource, interoperability, or release credit.

The age interoperability lane keeps its independent Go module in
`tools/age-reference/go.mod` and `go.sum`. Its acquisition step canonicalizes
the module with `go mod tidy`, downloads the complete locked graph, and fails if
the final module files differ from the committed files. Exact `govulncheck`
v1.6.0 then performs canonical non-CGO Linux/amd64 source-mode analysis.
Reachable vulnerabilities fail; imported-but-unreachable findings remain
visible as upstream informational output and do not fail, and there is no local
Go suppression list. Offline interoperability execution resolves with
`-mod=readonly`, runs `go mod verify`, and fails unless the selected module is
exactly `filippo.io/age@v1.3.1`. It also enumerates the external modules
compiled for canonical non-CGO Linux/amd64, requires their coordinates to match
the committed receipt set, permits only Apache/BSD/MIT-compatible expressions,
and verifies each reviewed license file's SHA-256. Every resolved module
replacement is rejected before this comparison, so a local or alternate source
cannot inherit an admitted coordinate. It does not install or discover an
ambient age CLI.

Because `deny.toml` expresses an active advisory exception at workspace scope,
both the primary and dependency-policy gates also run
`tools/check-dependency-exception-scope.sh`. Its exact reverse-graph assertions
fail unless `proc-macro-error2` 2.0.1 and `basic-toml` 0.1.10 remain reachable
only through the isolated age-provider pilot. Each ignored package must occur
exactly once in the root lock with its reviewed version, crates.io registry
source, and archive checksum; both must be absent from fuzz. `paste` must remain
absent from the root lock and resolved workspace/fuzz graphs. The same gate
proves the vulnerable raw-lock Hickory pair remains inactive while allowing
Iroh's fixed 0.26.2 package. Adversarial checks force a fuzz graph command
failure, an active vulnerable Hickory package, reintroduced `paste` versions,
an expanded `basic-toml` reverse graph, `basic-toml` in fuzz, a second ignored
package version, an alternate package source, and a changed archive checksum;
each must fail closed.

## Security posture

The workflow is safe to run for pull requests from forks:

- It uses `pull_request`, never `pull_request_target`.
- Its only workflow permission is read-only repository contents.
- It runs exclusively on GitHub-hosted, fixed-version runner labels.
- It does not receive secrets, persist checkout credentials, execute
  submodules, or use shared Actions caches.
- Every third-party action is pinned to a full commit SHA.
- Concurrency cancels superseded runs for the same pull request or ref, and
  every job has a timeout.

The action and tool pins are:

| Component | Pin |
| --- | --- |
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` (`v7.0.1`) |
| `jdx/mise-action` | `c2a87611a18de5b3828c5652fe268e992400cb5c` (`v4.3.0`) |
| `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` (`v4.6.2`) |
| cargo-cyclonedx | `0.5.9` |
| CycloneDX Editor/Validator | `0.34.0` |
| mise | `2026.4.28` |
| Rust | `1.97.1` |
| Minimum supported Rust | `1.91.0` |
| Go | `1.26.7` |
| Python | `3.13.7` |
| ripgrep | `15.2.0` |
| Reference Go age oracle | `filippo.io/age v1.3.1` |
| `govulncheck` | `golang.org/x/vuln v1.6.0` |
| Fuzz nightly | `nightly-2026-08-18` |
| `cargo-fuzz` | `0.13.2` |
| `cargo-deny` | `0.20.2` |
| `cargo-audit` | `0.22.2` |

Dependabot is configured separately to propose updates to action, Cargo, and
the isolated Go oracle module pins. The exact govulncheck workflow pin remains a
manual reviewed update. An update remains untrusted until these checks pass and
a maintainer reviews the upstream release and the resulting dependency changes.

## Running checks locally

For the separate release-build/SBOM lane, provision its pinned tools and fetch
locked dependencies, then run `mise run build`. See the
[artifact workflow](../release/sbom/README.md#automated-build-and-artifact) for
prerequisites, output layout and inventory qualifications.

Install the repository toolchain and run the primary gate:

```sh
mise install
mise run check
```

For the normal edit/test loop, run the narrow owning package or exact identity
first, then the complete Rust population before handoff:

```sh
# Examples; replace the filter with the identity you changed.
cargo test --locked -p aster-node --all-features TEST_FILTER -- --exact
cargo test --locked -p aster-lab --all-features --test reconciliation_bakeoff TEST_FILTER -- --exact

# Complete default Rust tests and doctests, with two nextest workers.
mise run check-workspace-tests
```

The two required-CI Rust selections are reproducible independently. Each task
uses the `ci` nextest profile and writes its latest raw report to
`target/nextest/ci/junit.xml`; copy or summarize that file before running the
other slice because the second run replaces it.

```sh
mise run check-rust-ci-slice-1
python3 .github/scripts/summarize-nextest-junit.py \
  --input target/nextest/ci/junit.xml \
  --output /tmp/aster-rust-slice-1.md \
  --partition 1/2 --problem-seconds 10

mise run check-rust-ci-slice-2
python3 .github/scripts/summarize-nextest-junit.py \
  --input target/nextest/ci/junit.xml \
  --output /tmp/aster-rust-slice-2.md \
  --partition 2/2 --problem-seconds 10

# Reporter selection, warning, and malformed-input contracts.
python3 .github/scripts/test-nextest-timing.py
```

A `Duration problems (> 10.000s)` table or `Rust test duration` annotation is
an optimization tag. It does not fail, terminate, retry, or exclude the test.
Functional failures still fail normally, and malformed timing evidence fails
the reporting step because there is no valid measurement to retain. Compare
the JUnit test durations separately from job wall time: dependency downloads,
cold compilation, linking, and compiler-cache misses are setup/build time and
must not be reported as test execution time. Record both when profiling the CI
critical path.

The primary gate runs `tools/check-project-license.py`. It requires every
first-party Cargo package to declare exactly `Apache-2.0`, carry a byte-identical
copy of the canonical `LICENSE`, and include that text in its package archive.
The C, Go, and Python binding roots and the lab runtime image must carry the same
text. The gate also rejects alternate root license files or changed license
text.

Run the independent Go-oracle audit and classic-X25519
provisioning-artifact interoperability gates separately:

```sh
GOBIN=/tmp/aster-go-tools go install golang.org/x/vuln/cmd/govulncheck@v1.6.0
GOVULNCHECK=/tmp/aster-go-tools/govulncheck mise run age-reference-audit
mise run age-reference-interop
```

Keeping these commands outside `mise run check` makes the separately maintained
Go implementation, live vulnerability database, and network-fetched Go
dependency graph explicit. The required CI aggregator still fails unless the
combined lane succeeds. A pass covers the oracle's currently reachable known
vulnerabilities, reviewed compiled-module license receipts, and the outer age
file profile only; it is not independent Aster mesh interoperability,
persistent-custody evidence, or production authorization.

Run the bounded fuzz campaigns separately:

```sh
mise run fuzz-smoke
```

Mise installs the task's pinned `nightly-2026-08-18` and `cargo-fuzz` 0.13.2
prerequisites automatically. Linux runs all nine targets; macOS runs seven
portable targets and explicitly skips the two Linux-only systemd admin-record
and backup targets. Linux CI continues to run all nine.

The target names and their exact mechanics-only claim boundaries are
documented in [`fuzz/README.md`](../../fuzz/README.md). Fuzz success is not mission,
semantic-conformance, or release authorization by itself.

Check the declared MSRV with:

```sh
rustup toolchain install 1.91.0 --profile minimal
cargo +1.91.0 check --locked --workspace --all-targets --all-features
```

The online advisory scan is time-sensitive. To reproduce that lane's mechanics,
install the pinned tools, refresh the databases, and then apply the same policy
to both lockfiles:

```sh
cargo install --locked cargo-deny --version 0.20.2
cargo install --locked cargo-audit --version 0.22.2
cargo deny fetch all
CARGO_NET_OFFLINE=true sh ./tools/check-dependency-exception-scope.sh
cargo audit --file Cargo.lock
cargo deny --locked --offline check
cargo deny --manifest-path fuzz/Cargo.toml --config deny.toml --locked --offline check
cargo audit --no-fetch --file fuzz/Cargo.lock
```
