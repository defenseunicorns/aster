# Continuous integration

The `CI` GitHub Actions workflow runs the repository's established validation
commands on pushes to `main`, pull requests targeting `main`, merge queues, and
manual dispatches. Configure branch protection or a ruleset to require the
single stable check name **`CI / required`**.

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
| `quality` | `ubuntu-24.04` | Runs `mise run check`: Rust and Go formatting, Apache-2.0-only project-license and package checks, exact 348-row implementation-requirements traceability, the selected-node dependency boundary, vendored netlink source-equivalence and 13-test compatibility gates, the retained-libp2p-oracle boundary, selected live-Event, live-mutable, live-State-subscription, live-Record-subscription, live-Blob, and live-Blob-subscription receipt checker tests, Clippy with warnings denied, the full Rust workspace test suite, C ABI build and C/C++ header checks, Rust/Python conformance, Python/Go binding tests, and the lab-controller tests. |
| `macOS tests` | `macos-14` | Runs all Rust workspace tests on the supported Apple runner with Rust 1.97.1. |
| `Rust 1.91 MSRV` | `ubuntu-24.04` | Checks every workspace target and feature with the declared minimum supported Rust version. |
| `dependency policy` | `ubuntu-24.04` | Enforces the retained-libp2p-oracle boundary, applies `deny.toml` to the root and fuzz dependency graphs, and audits both lockfiles against a freshly downloaded RustSec database. |
| `age reference interoperability` | `ubuntu-24.04` | Installs exact `govulncheck` v1.6.0, runs `mise run age-reference-audit`, then runs `mise run age-reference-interop`: the Go oracle's reachable vulnerability and compiled-module license gates must pass before exact reference Go `filippo.io/age` v1.3.1 and the Rust provider exchange classic-X25519 artifacts in both directions, compare recovered plaintext, and agree on the recipient. |
| `bounded fuzz smoke` | `ubuntu-24.04` | Runs five fixed 10,000-case hostile-input campaigns with the pinned nightly toolchain and `cargo-fuzz`: semantic wire decode, fragment decode, reference-envelope inspection, selected mechanics-frame decode, and selected Negentropy state-machine/bounds exercise. |
| `Linux release build and SBOM` | `ubuntu-24.04` | Runs `mise run sbom`: builds `aster` (package `aster-node`) and `aster-agent` (package `aster-agent`) for `x86_64-unknown-linux-gnu` in release mode from the checked-out commit, generates and validates their CycloneDX SBOMs, checks Cargo.lock stability, and retains a tar bundle with checksums and scope/provenance notes for 14 days. |
| `required` | `ubuntu-24.04` | Fails unless every validation lane completed successfully; this is the branch-protection check. |

The Rust dependency downloads happen before Cargo validation is switched to
offline mode. The dependency-policy job is intentionally different: it obtains
current advisory data once, audits the root lockfile during that refresh, and
reuses the same database without another fetch for the fuzz lockfile. Its
vulnerability result therefore reflects the RustSec database available when
the workflow ran, rather than a permanently reproducible snapshot.

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

The final frozen-tree matrix passed 539 of 539 on each toolchain. The current
run comprised core 349/349 (44.44s), node library 81/81 (5.19s), node binary
6/6 (0.00s), `mesh_cli` 13/13 (135.87s), and selected store 90/90 (8.75s).
The separate Rust 1.91.0 run comprised the same counts in 45.77, 5.42, 0.01,
135.76, and 8.61 seconds respectively. Each run also had five zero-test targets;
their test-harness sums were 194.25 and 195.57 seconds. The executions and
timings are not pooled.

Strict all-target/all-feature Clippy with warnings denied passed on the current
and Rust 1.91 toolchains in 10.32 and 10.30 seconds. Formatting passed on both
in 0.73 and 0.85 seconds, and `git diff --check` passed in 0.03 seconds. The
complete dual-toolchain validation used 463.76 seconds wall time. After a
27.21-second disposable two-node fixture, the compiled Record example returned
`moving`, counter 3, one superseded revision, no concurrent head, no conflict,
and both insert flags true in 1.26 seconds; an exact 0.84-second rerun returned
the same semantic ID and projection with both insert flags false.

The exact Record source/dependency hashes are pinned in the
[requirements evidence](implementation/requirements-status.md#prior-selected-record-stopped-slice-automated-evidence).
This is the earlier stopped/local automated evidence, not a Record contact,
disconnected-process acceptance result, retained execution receipt, or release
artifact. At this frozen slice Record had no live handle or reconciliation
frames; the later semantic-v4 gate below adds frames but no live application
handle. Automatic registered-policy
merge, finite TTL design (the selected form is rejected), expiry/garbage
collection, selected-node bindings, physical
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

On the final frozen bytes, focused current-toolchain runs passed the six typed
source-Blob tests, the dedicated core reader retry-state adversary, all 28
selected-store Blob tests, and all seven selected-node Blob tests. The current
tracked-Cargo-target matrix passed 576 of 576 tests: core library 351/351
(44.68s), node library 88/88 (11.29s), node binary 6/6 (0.00s), `mesh_cli`
13/13 (153.69s), and selected store 118/118 (12.33s). The separate exact Rust
1.91.0 matrix passed the same 576 tests in 45.57, 28.63, 0.01, 153.99, and
12.44 seconds respectively. The core basic example and five node examples had
no tests. These totals count only the listed tracked Cargo targets; no
auxiliary non-workspace scratch harness is counted.

Strict workspace all-target Clippy with warnings denied passed on the current
and Rust 1.91 toolchains in 28.36 and 34.71 seconds. Current-toolchain Rustdoc
with warnings denied, `cargo fmt --all -- --check`, and `git diff --check`
also passed. A loopback-enabled current-toolchain `cargo test --workspace`
passed every runnable workspace suite; one performance experiment remained
explicitly ignored. The process-heavy node cells required loopback permission;
an earlier sandboxed attempt was denied by the host before those socket tests
could run and is not counted as a test failure or success.

The exact Blob source identities are pinned in the
[requirements evidence](implementation/requirements-status.md#prior-selected-blob-automated-evidence).
A disposable provisioned fixture then ran the compiled Blob example twice over
18,783 input bytes. The 4.792-second first run returned one chunk,
`inserted=true`, and Blob ID
`85c3f98504cc9e671212256c994698ce2d8c1e947aa5b3841d61a943d3660fde`;
the 0.714-second exact rerun returned the same ID with `inserted=false`. Both
outputs matched the input byte-for-byte at SHA-256
`f3d9ba32b0825abfec157aadf8c16581608220f48dd2a8f0a3a39bef29bdd966`.
The fixture is not retained, and this is local executable evidence rather than
a Blob contact, remote-resume result, physical-storage measurement, or release
receipt.

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
corruption, and one-transaction bounded scheduling. Exact final counts, timings,
and source hashes are recorded in the
[prior semantic-v3 custody requirements evidence](implementation/requirements-status.md#prior-semantic-v3-selected-event-custody-automated-evidence).

This is current-code automated evidence, not a retained physical acceptance
receipt. Finite TTL is Linux/Event/v3-format only, inherited in v3/v4/v5/v6;
receive-only is not physical RF silence. V1/v2 deterministic whole-contact
partials, generic cross-class priority eviction, selected State/Record custody
or future TTL design (the current finite form rejects), long-offline and
many-node scale, mixed implementations, operational provisioning with a
production backend or protected stock CLI/binding, and release gates remain
open. Caller-provided protected Rust `NodeConfig` construction is tracked by the
separate current-code gate below.
Networked Blob was outside that Event-custody receipt; the separate semantic-v5
software gate below does not relabel it.

The subsequent stopped protected-provisioning/control-administration Step 4
gate is pinned separately in the
[requirements evidence](implementation/requirements-status.md#prior-protected-provisioning-and-control-administration-automated-evidence).
On fresh isolated targets, current Rust 1.97.1 and Rust 1.91.0 each passed 927
executable workspace tests with zero failures and one deliberately ignored
performance experiment; every-target/every-feature Clippy and all 17 Rustdoc
crate-targets passed with warnings denied on both toolchains. The current and
Rust 1.91 real-process `mesh_cli` targets passed 13/13 in 144.36s and 139.03s,
respectively. The ordinary ready deadline is raised to 40 seconds; the cold offline
cell uses separate 90-second startup, 120-second contact, and 150-second
completion bounds. This historical freeze is stopped Rust automation, not a
protected live CLI/binding, production SecretStore, operational recovery or
destroy workflow, physical receipt, or release authorization.

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

At the exact source identities recorded in the
[requirements ledger](implementation/requirements-status.md#current-protected-live-startup-and-control-automated-evidence),
the reported current-code gates passed: core library 380/380 in 45.21s; node library
180/180 in 69.94s; protected-runtime integration 12/12 in 0.15s; node
all-target/all-feature check in 12m04s; strict node all-target/all-feature
Clippy with warnings denied in 25.84s; fresh-target workspace all-feature
no-dependency Rustdoc with warnings denied in 17.97s; and formatting plus diff
checks.

The final serialized gate over those source identities and the preceding frozen
documentation bytes ran outside the sandbox for real-Iroh loopback:

```sh
CARGO_TARGET_DIR=/private/tmp/aster-protected-admin-full-check CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 mise run check
# exit 0
```

The all-feature workspace tests and strict Clippy passed. Major test results
were core 388/388, node library 180/180, node main 12/12, `mesh_cli` 20/20,
`protected_runtime` 12/12, redb 166/166, `aster-iroh` 13/13, host 74/74, IP
50/50, lab 32/32, and FFI 13/13; all doctests also passed. C/C++ syntax,
conformance and Python wire checks, Python bindings 12/12, lab Python 162/162,
Go, license, dependency, and requirements gates were green. The requirements
gate remained 348 IDs, 119 mappings, and 78/37/233 statuses. This is a
non-retained current-code CI receipt: it creates no execution root, observed
credit, or status movement. The source freeze is signed commit
`164ccc1dbafd7fa954c06eb7cf555671ff597ba1`; no signed documentation commit is
claimed here.

The live-control cells cover capacity-one pressure with a four-command yield
budget, policy refresh before response, nonfatal pending-policy deferral, exact
retry, graceful shutdown, self-revocation receipt-before-teardown, and
post-enqueue caller cancellation followed by stopped exact recovery. This is a
source-hashed current-code evidence boundary, not a retained execution root,
physical result, or additional `observed-bounded` credit. No production
provider, protected stock CLI/binding, cross-process admin IPC, or coordinated
provider destruction is added. The post-enqueue cancellation cell is Unix-only.

The semantic-v4 State/Record gate is inherited unchanged by v5 and v6 and is
additive to those frozen slices. The handshake default/highest is 6 with
`[6, 5, 4, 3, 2, 1]`; semantic v6 preserves the v5 ordinary Event,
State/Record, and Blob lanes byte-for-byte and adds only the mutually enabled
Event-bridge mechanics lane. Selected mutable frames are absent in v1-v3,
selected Blob frames are absent in v1-v4, and selected bridge frames are absent
in v1-v5. Focused validation
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

The final source manifest, exact two-toolchain matrix results, binding gates,
and the disclosed pre-existing lab-oracle retry are pinned in the
[prior State/Record requirements evidence](implementation/requirements-status.md#prior-selected-state-and-record-network-automated-evidence).
That earlier network-mechanics matrix remains current-code automation only; it
does not itself create a retained execution root. Event last-contact status is
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

The separate v2
[`selected-live-mutable-6cabb4c.json`](implementation/evidence/selected-live-mutable-6cabb4c.json)
canonical receipt is 7,752 bytes with SHA-256
`054945ecf94e8bfba1b130f6a5f47e9b1e0e17ad69f3b1472085a1d10f05eeaa`
and binds the run to good-signature source commit `6cabb4c`. Its two distinct
participants and mission identities execute six actor lifetimes with at most
two concurrent. They publish State and Record while peerless, then eight direct
`CONTACT` records account exactly for 7/7/7 selected items
offered/fetched/inserted, zero remaining work, and zero Event/control/Blob
counters. State first selects the maximum of two heads as `Current` and retains
the other as `Concurrent`. A node-a successor observes and supersedes both;
after node-b observes that successor, its authenticated empty tombstone observes
and supersedes all three predecessors. Both actors select the tombstone as
current, and one immediate peerless restart reproduces the exact four-version
projection. Record retains two conflict siblings, rejects an ordinary publish
without changing them, resolves only under the exact guard, supersedes both
originals, retries without another insert, converges, and reproduces the result
after restart. Six graceful shutdowns complete, and four retained State/Record
handles fail closed.

The receipt records an operator-attested source/binary/execution link, not a
cryptographic or reproducible-build proof, and validates participant secret
artifacts by metadata only without opening, reading, or hashing their contents.
State causal observation and publication order are producer-attested. This is
one-host same-implementation loopback evidence, and the restart is one
immediate peerless reopen—not indefinite tombstone retention, compaction,
garbage collection, or delete-wins. It supplies no physical, NAT/Internet,
controlled/public-relay, BTLE, independent-implementation, scale beyond two,
resource-threshold, long-duration, Event/Blob-live, or release acceptance from
that State/Record receipt.
The separate retained State- and Record-subscription gates below add bounded
durable positive-current-version and whole-key active-head delivery. The Record
receipt moves only `DM-5.1-08`; selected-node bindings, finite TTL/GC, automatic
registered-policy Record merge, broader carriers/partitions, and release gates
remain open.
Its zero Blob counters
do not evidence the newer live Blob mechanism.

## Selected live State subscription retained gate

The v1
[`selected-live-state-subscription-8912fc3.json`](implementation/evidence/selected-live-state-subscription-8912fc3.json)
canonical receipt is 9,656 bytes with SHA-256
`7d0b568dd4d57c3f2967da55953896829261877513c59c51a0b274eeda69485f`
and binds the run to good-signature source commit `8912fc3`. Two participants
and three processes execute ten actor lifetimes across seven phases with at
most two concurrent actors. Nine lifetimes stop gracefully; the parent sends
one receiver child `SIGKILL` after its attempt-one durable poll is flushed and
before acknowledgement. Both participant binds are reacquired at the end.

Six durable State publications produce five network inserts, deterministic
concurrent-origin reduction, a causal successor, and an explicit current
tombstone. One exact-key application subscription is inserted once and replayed
seven times. Four deliveries include the local current origin, the successor at
attempt one, the same successor at attempt two in a fresh process, and the
current tombstone. Two acknowledgements, two idempotent reacknowledgements,
eight token-binding checks, and four empty polls cover superseded-pending
retirement, durable redelivery, token rotation, malformed and cross-binding
rejection, ancestor suppression, and final peerless reopen.

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

The checked-in receipt can be replayed byte-for-byte only with the installed
pinned Python runtime, the externally retained raw root, and a separate clean
checkout detached at the exact source. Pass both the source-bound checker and
the checked-in receipt by absolute path because the receipt postdates the
signed source freeze:

```sh
ASTER_SOURCE=/path/to/aster-source-detached-at-8912fc33571449d1beb4a4cb0f204b5dcd44e8c2
ASTER_RECEIPT=/absolute/path/to/current-aster-checkout/docs/implementation/evidence/selected-live-state-subscription-8912fc3.json
cd /private/tmp
ASTER_PYTHON="$(mise where python@3.13.7)/bin/python3"
"$ASTER_PYTHON" "$ASTER_SOURCE/tools/check-selected-live-state-subscription-receipt.py" \
  --raw-root /path/to/retained/selected-live-state-subscription-raw-root \
  --source "$ASTER_SOURCE" \
  "$ASTER_RECEIPT"
cd "$ASTER_SOURCE"
"$ASTER_PYTHON" tools/test-selected-live-state-subscription-receipt.py
```

The source/binary/execution link is operator-attested, not cryptographic or a
reproducible build. The six participant mission, identity, and store artifacts
are validated by metadata only and are never opened, read, or hashed by the
checker. State causal observation and publication order are producer-attested.
This is one-host, same-implementation, direct-loopback evidence only. It claims
no physical host or carrier, NAT/Internet, relay, BTLE, mixed implementation,
scale/resource/soak, Event/Record/Blob live acceptance, or release result.

The delivery contract is positive-current-only. Its explicit current tombstone
is a State version, not a synthetic withdrawal; there is no materialized view,
transition feed, Current-to-None event, or dynamic `NodeConfig` interest
mutation. The older mutable v2 receipt remains primary for its broader State
causal convergence observation.

## Selected live Record subscription retained gate

The v1
[`selected-live-record-subscription-0c11344.json`](implementation/evidence/selected-live-record-subscription-0c11344.json)
canonical receipt is 10,357 bytes with SHA-256
`ba0e2bf47291f7e87000b85fa280cc957f3710ac800def82a51fb9b4657a1b48`
and binds the run to Good-signed source commit
`0c1134411953f4bb52133b50aff9989cd4ce3930`. Two participants and three OS
processes execute seven actor lifetimes with at most two concurrent; six stop
gracefully, while the parent sends one receiver child `SIGKILL` after its
attempt-one conflict poll is durably flushed and before acknowledgement.

One subscription is inserted once and replayed five times. Seven polls produce
four deliveries and three empty results. The retained run first emits a
peerless Current tombstone, then emits one complete two-head edit/tombstone
conflict at `delivery_limit=1` and `scan_limit=16`. A fresh child replays the
same projection at attempt two with a distinct 89-byte token. Exact
acknowledgement/reacknowledgement succeeds, while malformed,
wrong-subscription, wrong-projection, and retired-singleton tokens fail closed.
A fresh exact query supplies the guard omitted from delivery, resolution inserts
once with an exact noninserting retry, and its successor uses a new projection;
both originals remain query-only Superseded history.

The gate separately proves that application delivery does not mutate network
receive policy: configured network-interested application-unmatched beta is
retained but undelivered, while application-matched network-uninterested gamma
is withheld. Final peerless reopen preserves that separation, the subscription,
the resolved Current successor, both query-only originals, and an empty queue.

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

Byte-for-byte replay requires the retained raw root and a separate clean
checkout detached at the exact signed source:

```sh
ASTER_SOURCE=/path/to/aster-source-detached-at-0c1134411953f4bb52133b50aff9989cd4ce3930
ASTER_RECEIPT=/absolute/path/to/current-aster-checkout/docs/implementation/evidence/selected-live-record-subscription-0c11344.json
cd /private/tmp
ASTER_PYTHON="$(mise where python@3.13.7)/bin/python3"
"$ASTER_PYTHON" "$ASTER_SOURCE/tools/check-selected-live-record-subscription-receipt.py" \
  --raw-root /path/to/retained/selected-live-record-subscription-raw-root \
  --source "$ASTER_SOURCE" \
  "$ASTER_RECEIPT"
cd "$ASTER_SOURCE"
"$ASTER_PYTHON" tools/test-selected-live-record-subscription-receipt.py
```

The source/binary/execution link is operator-attested, not cryptographic or a
reproducible build; admitted source is not a complete build closure. Secret
artifacts are metadata-only evidence and Record causal order is producer-
attested. This one-host same-implementation direct-loopback gate is not
power-loss recovery, long retention/TTL/GC, physical/NAT/relay/BTLE,
mixed-implementation, scale/resource/soak, binding, automatic-merge, or release
evidence. It moves only `DM-5.1-08`; `DM-7-11`, `DM-7-14`, `DM-7-15`, and
`DM-7-18` remain `implemented-uncredited`, and `DM-7-20` is unchanged.

## Selected live Event retained gate

The v1
[`selected-live-event-c464129.json`](implementation/evidence/selected-live-event-c464129.json)
canonical receipt is 9,573 bytes with SHA-256
`4d71d04e4ebcc9f63c0e84e7f11e83bf1f3d1ad2ca8608486cdcc875b6dfeef0`
and binds the run to signed source commit
`c464129d58c250dea2ecbf5f51d7ece0e5aab6d0`. Two distinct carrier and mission
identities execute seven actor lifetimes with at most two concurrent actors on
one same-implementation loopback host.

The publisher creates four durable Events while peerless: alpha sequences 1,
2, and 3 plus one authorized beta Event. One priority-threshold direct contact
delivers alpha 1 and 3 as attempt 1 and exposes authenticated half-open gap
`[2,3)`; routine alpha 2 and unsubscribed beta remain withheld. The parent then
forcibly terminates the receiver child after its two-item poll was flushed
without acknowledgement. A fresh receiver process reopens the durable
subscription, receives the same IDs as attempt 2, acknowledges and idempotently
re-acknowledges both, and reaches an empty poll. A normal direct contact later
delivers alpha 2 as attempt 1, closes the gap, and completes its ack/re-ack.

The beta query remains empty while unsubscribed. Creating a temporary beta
subscription advances the selector snapshot and observes
`PolicyChangedSinceContact`; exact removal and idempotent removal follow. The
run performs no fresh post-change contact and observes no beta delivery. Its two
`AwaitingAuthenticatedContact` observations have zero failed attempts, so this
receipt does not establish positive failed-contact propagation. Control,
State/Record, and Blob activity remain zero.

The raw root is owner-only evidence containing participant mission bundles,
identity keys, and stores. Keep it outside source control. The runner/checker
inventory those six secret files by metadata only and never open, read, or hash
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

Replaying the checked-in projection requires the externally retained raw root
and a clean checkout detached at its exact signed source:

```sh
python3 tools/check-selected-live-event-receipt.py \
  --raw-root /path/to/retained/selected-live-event-raw-root \
  --source /path/to/aster-source-detached-at-c464129d58c250dea2ecbf5f51d7ece0e5aab6d0 \
  docs/implementation/evidence/selected-live-event-c464129.json
python3 tools/test-selected-live-event-receipt.py
```

The source/binary/execution link remains operator-attested, not cryptographic
or reproducible-build proof. This gate claims no distinct physical hosts;
NAT/Internet, controlled/public relay, or BTLE path; mixed or independent
implementation; scale/resource/soak result; State, Record, or Blob acceptance;
post-policy fresh completion or beta delivery; indefinite retention/GC; release
artifact; or production authorization.

The semantic-v5 direct Blob gate is additive to the earlier stopped/local Blob
gate. It must cover all Blob interest/source/range/result/ack/finish frame bytes,
malformed and cross-tuple rejection, and v1-v4 zero-Blob behavior. Provider
tests require a current 32-byte peer content proof plus route authority and
nonrevocation and reject route-only, wrong peer/topic/scope/epoch/authority,
tamper, stale proof, and same-epoch replacement. Store tests require source-
before-carrier staging, contiguous peer-neutral prefixes of at most 16 KiB,
64-MiB/1,024-chunk admission, 10,000-row/64-MiB staging bounds, exact depot plus
fresh full-content/current-lineage completion, and zero ordinary visibility
before atomic promotion. A new physical lineage for the same `(BlobID, content
group, numeric epoch)` must fail with `PhysicalLineageConflict`; republish or
resume requires an epoch advance. Finish/Finished is only the requester's
remaining-count echo, while each exact Result/Ack binds accepted prefix
progress. Read-only, writable, and terminal-preservation opens must cross-audit
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
claim nor an unclaimed durable source and requires no restart. Another must use
a multi-carrier source whose manifest-last carrier is not its greatest ID and
prove terminal poison advances to the lexicographic maximum so a later source
is selected.

The final runtime gate is one small bounded three-node direct-Iroh case: source
and first receiver make only partial carrier progress, runtime/store/provider
cache ownership tears down, then after reopen a different eligible content peer
continues the same exact source/carrier complement to a fully verified visible
publication. Normal and AtLeast must run the lane because AtLeast is Event-only;
ReceiveOnly must perform zero Blob work. The separate live Blob gate covers an
actor-owned handle, peerless publication, later direct synchronization,
authenticated bounded page reads, restart, and closure, but remains current-code
same-implementation loopback automation. A separate retained peerless
Blob-delivery gate is described below; neither network gate supplies Blob
peer/convergence status, route-only Blob relay,
a 100+ MiB/RSS or resource test, physical-system or mixed-implementation
evidence, or release acceptance.

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
cargo test --locked -p aster-node runtime::tests::terminal_blob_poison_advances_scheduler_past_source_to_later_candidate -- --exact
cargo test --locked -p aster-node runtime::tests::authenticated_peer_without_scope_grant_learns_no_event_id_and_cannot_fetch -- --exact
cargo check --locked --manifest-path fuzz/Cargo.toml --bin selected_frame_decode
```

The exact three-node, cleanup, delayed-insert/abort, terminal multi-carrier,
all-open-path audit, and predecessor-migration results plus the frozen source
manifest are recorded in the [prior semantic-v5 Blob requirements evidence](implementation/requirements-status.md#prior-semantic-v5-direct-blob-network-automated-evidence).
Independent final audit found no remaining P0–P3. The repair retains the bounded
non-public physical-lineage fence, serializes durable-source/cache transitions,
and advances terminal cursor state to the lexicographic maximum. Exactly six
requirements moved to `implemented-uncredited`; this current-code automation
creates no retained Blob receipt or `observed-bounded` credit and does not
relabel historical Event/control evidence.
Strict workspace Rustdoc and a fresh isolated `aster-node` plus `aster-iroh`
documentation build are also part of the frozen gate; stale Cargo rmeta is not a
source change or an accepted substitute for the clean isolated build.

## Selected live Blob retained gate

The dated 2026-08-27 v2 retained gate supersedes the earlier v1 live-Blob
observation and only the statements above that no retained direct-Iroh Blob
resume receipt existed. The canonical
[`selected-live-blob-044d90f.json`](implementation/evidence/selected-live-blob-044d90f.json)
receipt is 10,728 bytes with SHA-256
`4fea2ffbd16608862a67167fb1b8fcb6d5d8b4b82c576aa9a6b7e25ee9c55909`
and binds the run to good-signature source commit
`044d90ff07c8e754b3d490cb810d42de3c915e3d`.

Three distinct participants execute 11 actor lifetimes in seven exact phases
with at most two concurrent actors. A live publisher creates one 98,304-byte
Blob while peerless, proves exact noninserting retry and changed-payload
conflict behavior, and reads its two bounded pages. A replica first receives
the complete Blob directly over Iroh. A receiver then takes exactly one contact
from the publisher, retains a non-public 16,384-byte carrier prefix across a
graceful actor/store/provider reopen, and takes exactly one contact from the
different eligible replica. That continuation preserves the first prefix,
advances it to 32,768 bytes without refetching the source, and remains
non-public until the replica supplies the exact remaining 65,870 bytes. The
three phases therefore reconstruct exactly 98,638 carrier bytes, equal to the
seeded transfer, before whole-Blob promotion and authenticated reads. A final
peerless graceful receiver reopen reproduces the same two-page read.

Thirty-two positive direct `CONTACT` records cross-bind per-contact and
terminal runtime accounting. Eleven graceful shutdowns and closed retained
handles, three bind reacquisitions, typed intermediate Store inspections, and
the final three-participant metadata-only inventory pass. Each participant
retains one two-chunk finalized variant with 98,642 committed ciphertext-file
bytes. Pending prefixes never enter ordinary visibility; exact authenticated
reads, durable rows, prefix persistence and advancement, transfer accounting,
and completed depot shape—not `blob_remaining` alone—provide the bounded
observation.

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

Replaying the checked-in receipt requires the externally retained raw root and
a separate clean checkout detached at the exact signed source commit:

```sh
python3 tools/check-selected-live-blob-receipt.py \
  --raw-root /path/to/retained/selected-live-blob-raw-root \
  --source /path/to/aster-source-detached-at-044d90ff07c8e754b3d490cb810d42de3c915e3d \
  docs/implementation/evidence/selected-live-blob-044d90f.json
python3 tools/test-selected-live-blob-receipt.py
```

The raw-root projection reproduced the checked-in receipt byte-for-byte, and
the independent-oracle fail-closed suite passed 45/45. The source-to-binary-to-
execution link remains operator-attested rather than cryptographically proven,
and the admitted source list is not a complete reproducible build closure. The
interruption and reopens are graceful same-process actor/store/provider events,
not process-crash or power-loss recovery. Intermediate Store inspection,
transcript timing, and source-removal order are producer-attested; unlink plus
parent sync is not physical-media sanitization. The receipt does not claim
distinct physical hosts; NAT, Internet, controlled/public relay, or BTLE paths;
an independent implementation; scale beyond three participants; resource
thresholds or long-duration soak; long-offline recovery; arbitrary-peer or
route-only Blob resume; Blob subscription, status, TTL, or garbage collection;
Event, State, or Record live-application acceptance; complete MVP acceptance;
a release artifact; or production authorization.

## Selected live Blob delivery retained gate

The dated 2026-08-27 v1 retained delivery gate supersedes only present-tense
statements that the metadata-only Blob queue had no retained acceptance. The
canonical
[`selected-live-blob-subscription-26e0a09.json`](implementation/evidence/selected-live-blob-subscription-26e0a09.json)
receipt is 10,269 bytes with SHA-256
`3d0c0b2da629282c56de5ae9dacc8920c9960defba083c6bff856e2c0612a675`
and binds Good-signed source commit
`26e0a090b9a6f644d96b38cfaa23f4e2139ad8b1`.

One participant executes three processes and four actor lifetimes on one
peerless host. Two exact publications share one `BlobId`. The attempt-one child
flushes an owner-only, fsynced unacknowledged token and is sent `SIGKILL`
without a graceful `STOP`; a fresh process receives the same publication as
attempt 2 and acknowledges it with the persisted attempt-one token. The run
also rejects a malformed token and a token bound to the other exact
publication, acknowledges and re-acknowledges both publications, then reopens
in the parent with one replayed subscription, zero pending, two acknowledged,
two cursors, and an empty poll. Store inspection binds two publications and
operations to one `BlobId`, one finalized variant, one chunk, and 207 committed
ciphertext bytes.

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

Replaying the checked-in receipt requires its externally retained raw root and
a clean checkout detached at the exact signed source commit:

```sh
python3 tools/check-selected-live-blob-subscription-receipt.py \
  --raw-root /path/to/retained/selected-live-blob-subscription-raw-root \
  --source /path/to/aster-source-detached-at-26e0a090b9a6f644d96b38cfaa23f4e2139ad8b1 \
  docs/implementation/evidence/selected-live-blob-subscription-26e0a09.json
python3 tools/test-selected-live-blob-subscription-receipt.py
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

## Selected Iroh namespace-NAT retained gate

The separate retained gate is bound to signed commit
`15f4e0b8e9f817508c14fcbb4b307d6949add557` and exact tree
`09d2f5bb037d694367e24ec50747aba8cac83b96`. On one Darwin arm64 host,
Docker 29.4.0 and OrbStack 2.2.3 ran two cells, each with two selected endpoints
behind distinct Docker Linux LAN/NAT-router namespaces. The cone cell disabled
relays and observed Direct plus 978 cross-NAT UDP packet observations. The
restrictive cell recorded three direct-drop packets, zero direct WAN
observations, Relay at both endpoints, two accepted allowlisted sessions, and
2,052 controlled-relay
HTTPS packet observations. Each cell delivered and acknowledged one exact
32-byte Event and repeated as an exact no-op.

The canonical checked-in receipt is
[`selected-iroh-nat-15f4e0b.json`](implementation/evidence/selected-iroh-nat-15f4e0b.json):
48,302 bytes, SHA-256
`55dc67ac606e92c44c2e36d959b23bc52880b483bdab21a7c2ec47487eee0393`.
The raw root contains external-restricted packet captures, mission bundles,
credentials, and encrypted state and must remain outside source control. Its
canary result covers exactly 26 enumerated finalized targets, not the complete
raw root or host. Runtime cleanup removed the cell containers, networks, and
namespaces; it does not claim deletion of the selected local image, global or
physical sanitization, or sanitization of retained encrypted state.

A future fresh run requires explicit mutation and build-network authorization:

```sh
python3 lab/orchestrate.py selected-iroh-nat-run \
  --execute --allow-build-network --profile all
```

Review of the frozen run requires access to its external-restricted raw root.
The validator binds the public receipt to the immutable signed Git objects and
all curated raw artifacts:

```sh
python3 tools/check-selected-iroh-nat-receipt.py \
  --raw-root /private/tmp/aster-selected-iroh-nat.zFpaqB/20260826T143559Z-selected-iroh-nat-50726015670670e9 \
  --source . \
  docs/implementation/evidence/selected-iroh-nat-15f4e0b.json
python3 tools/test-selected-iroh-nat-receipt.py
```

The raw-root projector independently reproduced the public receipt
byte-for-byte, and the synthetic fail-closed suite passed 38/38. The receipt
does not claim discovery or punching, temporal direct-first fallback,
representative or physical NAT, public Internet/relay operation, lab-network
exclusivity, a complete listener-wide pre-authentication cap, BTLE,
independent implementation or clock, resource thresholds, a hermetic build,
complete MVP, or release authorization. Exact identities, replay commands, and
status movements are in the
[requirements ledger](implementation/requirements-status.md#selected-iroh-nat-retained-receipt).

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
`ttl=durable-none`. The retained parent PR-A/pre-subscription 2026-08-24 N3,
default N4, and N8 observed loopback results and their exact claim boundaries
are recorded in
the [mesh CLI quickstart](quickstart/mesh-cli.md) and [requirements
status](implementation/requirements-status.md). Unit-test or demo success does
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

A separate retained parent PR-A/pre-subscription probe exercised the
Event/mission boundary across eight loopback nodes and 38 child processes in 17
causal cohorts. It is a manual
receipt, not a CI lane; seven nonempty stderr files preserve ten transient
duplicate-contact or connection-loss lines from the final no-op despite the
exact terminal convergence pass. All 228 passing no-op contacts reported all
11 counters zero. The command, root, artifact digest, and claim boundary are
recorded in the
[requirements status](implementation/requirements-status.md).

A separate 2026-08-25 manual gate used an operator-attested Cargo release-
profile binary run for the signed current-tree source at N=32 on one macOS
arm64 host over direct loopback. The no-dependency validator accepted 65/65
exact cohorts, 158/158 exact-named executions with distinct READY PIDs, 32 distinct
mission identities and stores, 30 payload-blind intermediates, and a final
zero-difference no-op with 32 distinct log-observed READY PIDs; all 158 child
stderr files were empty. No overlap timing or OS sampler proves simultaneity.
The 62 data-motion edge cohorts remained serial two-process
contacts. The raw retained root contains unprotected mission and carrier
identity material and is not a source artifact; only the sanitized checked-in
receipt is reviewable. This moves only `DM-9-21A` to `observed-bounded`. It is
not the at-least-100-node target, a distributed/physical topology, NAT,
controlled-relay, BTLE/cross-transport, mixed-implementation, resource-threshold,
or release evidence. The exact receipt and replay command are in the
[requirements status](implementation/requirements-status.md#selected-n32-retained-receipt).

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
streaming and semantic-v5 direct Blob transfer/resume automation;
it does not turn the retained parent roots into PR-B, PR-C, State, Record, or
Blob receipts. Those retained parent tests do not claim networked State/Record
or Blob, remote Blob chunks, global convergence, generalized control
administration, non-Linux/cross-class finite-TTL custody, protected provisioning, platform-complete
zeroization assurance, admitted release cryptography, independent review, or
physical-network acceptance.

One explicit `cargo deny` advisory ignore covers a bounded active pilot graph.
`RUSTSEC-2026-0173` covers unmaintained build-time `proc-macro-error2` 2.0.1 in
the non-production age-provider pilot. RustSec reports no vulnerability and no
patched release; current Rust separately emits future-incompatibility `E0365`.
The ignore permits that exact informational finding only. It does not suppress
other advisories, change exact package checksums, permit online execution after
the acquisition step, or authorize the provider for production.

The former `RUSTSEC-2024-0436` exception is retired. A path-patched exact
`netlink-packet-core` 0.8.2 preserves its API while resolving the dependency
key `paste` to maintained `pastey` 0.2.2. [Decision 0027](decisions/0027-libp2p-pilot-dependency-policy.md)
and the vendored [`ASTER-PATCH.md`](../third-party/netlink-packet-core-0.8.2-aster/ASTER-PATCH.md)
record the provenance and removal gate. CI now requires `paste` to be absent
from the lock, workspace, and fuzz graphs. It also verifies every retained
upstream file hash, reconstructs and checks the two exact manifest-only deltas,
rejects extra vendored files, and reruns all 13 upstream library unit tests from
a disposable dependency-minimized copy. The decision continues to admit
`BSD-2-Clause`, `ISC`, and `Zlib` for the reviewed external dependency graph;
first-party packages and distributed project files remain subject to the
separate byte-identical Apache-2.0 gate.

The companion scope gate fails if the remaining ignored package's reverse graph
drifts, if it appears in the separately excluded fuzz graph, or if any `paste`
version reappears. Any change to a package chain or advisory disposition
requires a recorded pilot review.

The selected Iroh graph carries five stakeholder-approved, exact-coordinate
license exceptions recorded by Decision 0028: `webpki-root-certs` and
`webpki-roots` 1.0.9 use `CDLA-Permissive-2.0`, while all-target browser-WASM
packages `async_io_stream` 0.3.3, `pharos` 0.5.3, and `ws_stream_wasm` 0.7.5 use
the OSI-approved `Unlicense`. Neither license is globally allowed. Package or
version drift fails closed, and the project-license gate hash-pins the complete
distribution notices and requires them in the lab image. The CDLA disposition
is a visible stakeholder deviation from the frozen OSI-only requirement, not a
claim of outside-counsel review or requirements credit. Passing this gate does
not by itself authorize a release or declare browser-WASM supported.

An advisory-independent retained-oracle gate separately parses locked,
offline, all-feature Cargo metadata. It requires
`aster-libp2p-provider` to remain unpublished and allows no dependency consumer
other than `aster-lab`'s optional `libp2p-candidate` feature. It also rejects
default or aliased activation, renamed or remote provider dependencies, and
local intermediary consumers outside the workspace. The provider remains
directly buildable as a workspace test package so explicit and workspace-wide
validation can exercise the retained oracle without activating it in a default
or shipping consumer. Mutation tests cover each escape route in both the
primary and dependency-policy lanes.

The root lockfile also contains `hickory-proto` and `hickory-resolver` 0.25.2
because the `libp2p` 0.56.0 aggregate manifest exposes DNS and mDNS as optional
features. Aster disables libp2p default features and enables neither optional
feature, so neither Hickory package is present in the resolved workspace graph,
including with every Aster workspace feature and target enabled. They are also
absent from the independent fuzz graph. The raw-lock tools cannot represent
that reachability distinction, so only the root raw-lock `cargo audit` command
narrowly ignores `RUSTSEC-2026-0118` and `RUSTSEC-2026-0119`. Feature-aware
`cargo deny` sees neither inactive package and carries no Hickory ignore.

This is a lock-only tooling disposition, not a runtime vulnerability waiver or
admission of DNS, mDNS, or Hickory. Before either ignore can be used,
`tools/check-dependency-exception-scope.sh` requires the affected lock-only
package set to remain exactly `hickory-proto`/`hickory-resolver` 0.25.2 and
permits the separately resolved, fixed 0.26.1 versions used by Iroh. It proves
that the affected 0.25.2 versions are absent from the full workspace and fuzz
dependency graphs. Its adversarial regression injects an active vulnerable
Hickory version and requires the gate to fail. Package/version drift or future
feature activation therefore blocks CI before the audit suppression is
applied. Remove both ignores when the aggregate libp2p lock no longer contains
the affected optional versions.

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
fail unless `proc-macro-error2` 2.0.1 remains reachable only through the
isolated age-provider pilot and `paste` remains absent from the root lock and
resolved workspace/fuzz graphs. The
ignored package must be absent from fuzz. The same gate proves the vulnerable
raw-lock Hickory pair remains inactive while allowing Iroh's fixed 0.26.1
packages. Adversarial wrappers force a fuzz graph command failure, an active
vulnerable Hickory package, and reintroduced `paste` versions; each must fail
closed.

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
locked dependencies, then run `mise run sbom`. See the
[artifact workflow](release/sbom/README.md#automated-build-and-artifact) for
prerequisites, output layout and inventory qualifications. Its orchestration
regression tests run in `mise run check` and can also be invoked directly with
`python3 tools/test_sbom_workflow.py`.


Install the repository toolchain and run the primary gate:

```sh
mise install
mise run check
```

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
rustup toolchain install nightly-2026-08-18 --profile minimal
cargo +nightly-2026-08-18 install --locked cargo-fuzz --version 0.13.2
mise run fuzz-smoke
```

The five target names and their exact mechanics-only claim boundaries are
documented in [`fuzz/README.md`](../fuzz/README.md). Fuzz success is not mission,
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
cargo audit --ignore RUSTSEC-2026-0118 --ignore RUSTSEC-2026-0119 --file Cargo.lock
cargo deny --locked --offline check
cargo deny --manifest-path fuzz/Cargo.toml --config deny.toml --locked --offline check
cargo audit --no-fetch --file fuzz/Cargo.lock
```
