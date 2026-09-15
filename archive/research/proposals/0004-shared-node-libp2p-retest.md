# Proposal 0004: Shared-node rust-libp2p retest

> ****

- Status: superseded — stopped before formal Phase 0; no arm selected and
  the rust-libp2p pilot rejected from the continuing stack
- Outcome date: 2026-08-23
- Result: [Proposal 0004 result](0004-shared-node-libp2p-retest-results.md)
- Date: 2026-08-21
- Owner: Aster Clean Team — execution authorized in the designated project
  task
- Requirements baseline:
  [`data-mesh-requirements.md`](../../data-mesh-requirements.md), SHA-256
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Observed proposal-writing base:
  `26c24a65c125406ed59493e5fc82a31bebb16d02`; execution must freeze a later
  clean shared-node checkpoint rather than treating this value as a candidate
  receipt
- Execution cap: 30 engineer-days; this is a stop limit, not an estimate
- Governing decision:
  [Decision 0024](../decisions/0024-refactor-durable-node-ownership-before-ip-provider-selection.md)
- Closure decision:
  [Decision 0029](../decisions/0029-close-proposal-0004-libp2p-pilot.md)
- Preserves: Decisions
  [0002](../decisions/0002-dependency-admission.md),
  0014 (“Build versus buy is governed by total assurance cost”; privileged local
  record, not part of this repository artifact),
  0015 (“Delete custom mechanism behind narrow library-backed seams”; privileged
  local record, not part of this repository artifact),
  [0022](../decisions/0022-ip-mesh-experiment-no-selection.md), and
  [0023](../decisions/0023-mesh-host-contract-no-libp2p-selection.md)

## Question

After correcting Aster's shared durable-owner, admission, authorization, and
aggregate-resource architecture, can an idiomatic rust-libp2p integration meet
every still-open IP mesh gate and replace more overlapping custom connectivity
mechanisms than its adapter and supply-chain surface add?

The two requirements-eligible arms are:

- **corrected native** — the shared-node host composed with Aster's native IP
  discovery, direct, traversal, and locally operated ciphertext-relay
  mechanisms; and
- **corrected libp2p protected** — the identical shared-node host composed with
  one persistent rust-libp2p Swarm, while Aster's bounded protected discovery
  remains the automatic candidate source.

The eligible outcome is exactly one of **keep corrected native**, **wrap
rust-libp2p**, or **none**. At most one production profile may remain. A separate
libp2p-mDNS lane is technical characterization only and can never win this
proposal.

This proposal does not reconsider Iroh. Decision 0024's Iroh-specific
pre-`Incoming` bound, path-change authorization, lifecycle, and compiler-floor
conditions have not been shown to have changed.

## Why this retest is materially different

Proposal 0003 correctly stopped all arms before NAT, relay, impairment, and
scale because every contact opened a complete durable authority before fresh
Aster authentication and because resource limits were contact-local. Those
were Aster composition defects, not a fair measurement of the carrier
providers.

The retained libp2p characterization nevertheless established a useful narrow
baseline: one persistent Swarm using TCP, Noise, Yamux, connection limits, and
one generic substream carried at least 10,000 Aster runtime frames; the archived
trial-14 regression passed; and its protected profile was smaller than the Iroh
profile. It did **not** compose or exercise Identify, AutoNAT, circuit relay, or
DCUtR, and it did not complete the 64 KiB application-delivery probe. This
proposal preserves those failures and reruns the complete Phase-1-through-5
matrix only after removing the common architecture confound.

### Historical execution state before closure

This section preserves the state and open gates as they stood while the
proposal was active. The dated outcome at the end of this document is the
current disposition.

The signed provider-free implementation contains the common shared durable
authority, non-clone contact sessions, transactional admission, authorization-
generation fanout, node-global resource accounting, and the bounded native
three-process Gate-H harness described below. That exact baseline has now
passed Gate H. Post-gate child work has activated a default-disabled libp2p
development candidate, also described below; neither the Gate-H result nor the
development candidate selects a production provider.

The first workload-reaching formal cohort is retained in
[`p0004-gate-h-retry-04`](../../evidence/ip_mesh_experiment/runs/p0004-gate-h-retry-04/failure.json).
Trials 1–3 completed cleanly. Trial 4 stopped when C reported
`contact_failures = 1` with `runtime backend failed: engine: envelope not
found` after authorization-generation rotation and same-address carrier
replacement. The retained failure receipt makes the cohort nonpassing; the
three completed trials are not Gate-H credit.

Diagnosis showed that native HELLO frames bound the full
`(carrier_id, instance_nonce)` tuple, while native DATA was demultiplexed only
by stable route. A delayed predecessor DATA datagram could therefore enter a
successor contact after either endpoint rotated its carrier instance. The
repair binds every DATA frame to both the exact sender and expected-receiver
carrier tuples and rejects unwrapped, malformed, or tuple-mismatched frames
before queueing, receive accounting, or `RuntimeDriver`. This is provider-local
epoch demultiplexing, not an authorization grant; fresh Aster authentication
remains mandatory.

The next signed live cohort is retained in
[`p0004-gate-h-retry-05`](../../evidence/ip_mesh_experiment/runs/p0004-gate-h-retry-05/failure.json).
It bound signed commit `797d11b8f88e53a8f03ebac5986d5afd3842dbcb` and
the pair-epoch repair. Trials 1–2 completed cleanly. Trial 3 stopped fail-closed
when C again reported `runtime backend failed: engine: envelope not found`;
the two completed trials are not Gate-H credit.

That failure had a different cause. The carrier pair and authorization
generation were current, but B's bounded peer-neutral durable partial-transfer
WANT was hydrated onto a fresh B–C contact before C held or advertised the exact
source. The reducer wrongly promoted that unadvertised WANT into a serve action;
the backend then correctly returned `envelope not found`, which is contact
fatal. The repair makes a serve action eligible only when the typed ObjectID is
in that contact's current authenticated, policy-filtered serve inventory. An
unadvertised or emission-suppressed WANT therefore reaches no backend and emits
no DATA, while the requester retains its bounded peer-neutral durable progress
for another eligible peer. A genuine post-selection backend failure—including
NotFound, authentication, authorization-generation, revocation, corruption,
or storage I/O—remains contact-fatal.

The retained post-cleanup live cohort
[`p0004-gate-h-retry-07`](../../evidence/ip_mesh_experiment/runs/p0004-gate-h-retry-07/failure.json)
completed trials 1–4, then stopped in trial 5 when B reported
`sqlite: database disk image is malformed`. The failed database's integrity
check found real page-allocation damage; the contact used current carrier
epochs and a fresh generation-1 admission, so this was neither predecessor
DATA nor the peer-neutral WANT defect. The controller had been opening the
Linux node's live WAL database from macOS through a bind mount every 10 ms to
observe custody. Cross-host SQLite mmap and lock coordination is not an
admissible live-read boundary. The repair exposes one typed exact-ItemID query
through the already-open process authority, records that observation in the
atomically replaced node status receipt, and confines direct controller SQLite
reads within Gate H to stopped-node preconditions. Retry 07 is diagnostic only.

The formal candidate is deliberately narrower than the compatibility build. It
is built from `aster-lab` with defaults disabled, feature `gate-h`, and binary
`aster-gate-h`. That feature selects `aster-host/gate-h-formal`; it does not
select `aster-host/legacy-single-contact-service`. Consequently the legacy
`MeshService` owner path and the legacy `aster-lab` CLI are not compiled into
the Gate-H candidate. The exact image build is:

```text
docker build --pull=false \
  --build-arg LAB_ASTER_FEATURES=aster-lab/gate-h \
  --build-arg LAB_ASTER_BINARY=aster-gate-h \
  --tag IMAGE --file lab/Dockerfile .
```

Inside that image build, Cargo executes the equivalent of:

```text
cargo build --locked --release -p aster-lab --bin aster-gate-h \
  --no-default-features --features aster-lab/gate-h
```

The formal controller accepts only this build shape, extracts the candidate
binary from the resulting image, and requires its digest to match the supplied
executable. This compile-time separation prevents the historical per-contact
durable-owner surface from serving as an unrecorded admission or execution
bypass. It does not remove that default compatibility surface from the wider
workspace and is not a production disposition.

Formal execution additionally requires absolute `--docker-binary`,
`--docker-buildx-binary`, `--git-binary`, `--ssh-keygen-binary`, and
`--ssh-binary` paths, an explicit `--docker-host unix:///...` endpoint, and
explicit `--allowed-signers` and `--signer-principal` inputs. The controller
proves its isolated Docker configuration starts empty, installs only an exact
hash-bound `cli-plugins/docker-buildx` symlink, retains Docker-mediated buildx
version discovery, and removes that link and its empty directory during normal
or interrupted finalization. It disables ambient Git configuration and
replacement objects, freezes the allowed-signers bytes, binds Git and OpenSSH
executable identities and versions, and re-verifies the exact commit,
principal, and fingerprint during collection and post-hoc aggregation.

The image and deterministic fault witnesses never consume the ambient
worktree. The controller creates a canonical archive of the exact signed Git
tree, checks its complete `ls-tree` inventory, modes, blob identities, archive
metadata, and reconstructed root tree ID, and materializes a read-only source
root containing no untracked or ignored inputs. Docker, Cargo, and static source
checks run only from that root; the archive, inventory, command receipts, and
pre/post integrity checks are retained and independently revalidated.

The mutable bootstrap may only establish signature trust, freeze the commit,
and materialize that signed tree. It then replaces itself through the resolved
Python interpreter with the controller from the read-only export, using exact
`-B -E -s -S` isolation flags and a digest-bound one-shot handoff. The fault
runner and post-hoc aggregator use the same signed-export boundary. Before and
after formal work they bind every loaded project module's origin, raw bytes,
Git and filesystem modes, interpreter flags, `sys.path`, and the absence of
`__pycache__`, `.pyc`, and `.pyo` inputs.

The isolated Docker configuration is also an owned bounded resource. Besides
the exact buildx plugin symlink, the controller inventories the buildx metadata
created by the image build with strict entry, type, mode, per-file, and
aggregate-byte bounds. It retains the complete bounded bytes and canonical
inventory digest, rejects links or unexpected layout without deleting them,
and removes only that verified state bottom-up. Normal completion and both
signal exits require the configuration directory to be empty; post-hoc
validation reconstructs the inventory before accepting the cleanup receipt.

The signed controller runs under a complete allowlisted environment, uses a
fresh evidence-local Docker config and temporary directory, and binds the
invocation and resolved identities, sizes, digests, and version output of
Python, Git, OpenSSH, and the Docker client/server to the run. Every synchronous
and asynchronous child is isolated, deadline-bounded, terminated, and reaped
before evidence finalization. `SIGINT` and `SIGTERM` therefore produce indexed,
nonpassing, append-only receipts and exit 130 and 143 respectively rather than
silently abandoning a cohort.

## Requirements traceability

The frozen baseline defines outcomes, not a singleton runtime or a specific
network library. The table separates direct requirements from the architecture
and experiment controls selected to demonstrate them.

| Proposal element | Direct requirements anchor | Relationship |
|---|---|---|
| Mutual authentication and revalidation before data exchange | Networks are untrusted ([§3](../../data-mesh-requirements.md#3-operating-environment--assumptions)); peers mutually authenticate before exchanging data ([§5.7](../../data-mesh-requirements.md#57-discovery--peering)); transport security grants no authority and revocation and freshness remain Aster obligations ([§6](../../data-mesh-requirements.md#6-security-requirements)). | Authentication before exchange is direct. Transactional admission, separate hard pending-connection and pre-authentication deadlines, expected-peer binding, and authorization-generation checks are Decision 0024 controls selected to make that obligation fail closed. |
| One durable owner with isolated contact sessions | Reachable nodes converge, durable data survives disconnection, and partial progress resumes with any peer ([§5.2](../../data-mesh-requirements.md#52-synchronization--consistency)); relay quotas are configurable ([§5.5](../../data-mesh-requirements.md#55-scoping--propagation-control)); revocation and rekey propagate through the mesh ([§6](../../data-mesh-requirements.md#6-security-requirements)). | Coherent durable, quota, and authorization outcomes are direct. Exactly one process-owned authority and non-clone borrowed sessions are the accepted implementation remedy, not baseline wording. |
| Node-global resource accounting | Configurable relay storage/bandwidth quotas are required ([§5.5](../../data-mesh-requirements.md#55-scoping--propagation-control)); the Tier-2 RAM, binary, single-core, idle, low-rate, scale, and bounded-storage targets apply to a node ([§9](../../data-mesh-requirements.md#9-performance--resource-targets)). | The aggregate measurable bound is direct. The exact counters and reservation protocol below are derived accounting controls. |
| Automatic and manual discovery under Aster emission policy | Automatic discovery where a carrier permits it, manual peering, discovery silence, and mutual authentication are required ([§5.7](../../data-mesh-requirements.md#57-discovery--peering)); receive-only and priority-based emission controls are required ([§5.4](../../data-mesh-requirements.md#54-priority--constrained-operation)). | The behavior is direct. Using protected Aster discovery for the eligible libp2p arm and isolating provider mDNS as technical-only are experiment choices made to keep hostile-input state and emission policy bounded. |
| Direct, NAT, relay, and path-recovery cells | Direct peer sync and intermittent store-and-forward are required ([§5.6](../../data-mesh-requirements.md#56-peer-to-peer--store-and-forward)); IP must operate across NAT, prefer infrastructure-free traversal where possible, and may use relay fallback without making it a local-mesh dependency ([§5.8](../../data-mesh-requirements.md#58-transports)); the corresponding NAT acceptance scenario is explicit ([§12](../../data-mesh-requirements.md#12-acceptance-scenarios-illustrative-the-release-must-pass-equivalents)). | The outcomes are direct. The controlled AutoNAT service, self-hosted circuit relay, DCUtR sequence, namespace topology, and fresh authentication on path/address replacement are falsifiable experiment controls. |
| Provider-neutral application and protocol boundary | Transports are pluggable without protocol changes ([§5.8](../../data-mesh-requirements.md#58-transports)); the public API does not expose transport selection or sync internals ([§7](../../data-mesh-requirements.md#7-developer-experience--embeddability)); independent implementations follow the protocol rather than the reference ([§8](../../data-mesh-requirements.md#8-implementation-constraints)). | The boundary is direct. The exact `MeshHost`/provider split and use of one persistent generic substream are implementation choices. |
| Buy-versus-build and one production profile | Dependencies must have OSI-approved, non-strong-copyleft licensing, maintenance, governance, security practice, and an SBOM; maintained FOSS is preferred when it meets requirements ([§8](../../data-mesh-requirements.md#8-implementation-constraints)). | The gates are direct. Comparing total assurance and requiring deletion of superseded native mechanism follow Decisions 0014 and 0015; dependency count alone is not a decision metric. |
| Live A→B→C, capture, revocation, and impairment evidence | Eventual convergence and resumability ([§5.2](../../data-mesh-requirements.md#52-synchronization--consistency)), multi-hop custody ([§5.6](../../data-mesh-requirements.md#56-peer-to-peer--store-and-forward)), source and metadata protection plus revocation/replay resistance ([§6](../../data-mesh-requirements.md#6-security-requirements)), and the illustrative release scenarios ([§12](../../data-mesh-requirements.md#12-acceptance-scenarios-illustrative-the-release-must-pass-equivalents)) are direct. | The exact cohorts, canaries, failure schedule, and receipts are experiment controls. Passing them informs a later decision; it does not alone close a product requirement. |

The bracketed values in the baseline remain stakeholder-validation placeholders
under [§14](../../data-mesh-requirements.md#14-open-items-for-the-team--stakeholders).
This proposal neither changes their status nor substitutes its screens for
release acceptance.

## Non-negotiable shared-node prerequisite

The following change is common Aster architecture, not provider-specific glue.
Its implementation is present, but it must be independently reviewed,
validated, and frozen before libp2p is activated as a candidate or restored to
the continuing dependency graph. A standalone, non-production adapter source
spike may be developed in parallel to validate a stable upstream API, but it
produces no acceptance or performance evidence and cannot enter the candidate
build until Gate H passes.

### One process-owned authority

Each Aster process opens exactly one durable `Node`, one semantic backend, and
one Blob-store/quota authority. Provider tasks, connection tasks, and contact
sessions cannot open SQLite, replay durable control state, scan Blob storage,
or construct a competing quota owner.

The authority is not cloneable as an independent durable owner. It may expose
bounded handles that route operations to that one owner. Contact execution must
not hold an authority lock across carrier I/O, timers, or application callbacks.

### Non-clone contact sessions

Each logical contact receives one non-clone session bound to an expected Aster
NodeID. The session owns only contact-scoped state, including route grants,
batch inventory grants and served state, bridge inventory grants and served
state, framing progress, cancellation, and its captured authorization
generation. Ending one session cannot clear, overwrite, or inherit another
session's grants.

Inventory, control, rekey, revocation, bridge-authorization, and durable Blob
quota changes have one authority and become coherently visible to every active
session. No carrier identity, libp2p `PeerId`, address, or relay reservation is
an Aster authorization cache.

Carrier observations may inform candidate grouping, deduplication, fairness,
and retry scheduling only. A carrier match may attach a previously observed
Aster NodeID as an untrusted scheduling hint; it neither authorizes nor rejects
the peer that subsequently authenticates. Reuse of an address or stable carrier
identity, including across process restart, never carries an admission grant
into a new contact.

For the native control, every DATA frame must be bound to the exact pair of
carrier instances observed for its logical contact: the full sender
`(carrier_id, instance_nonce)` and full expected-receiver tuple. A route,
socket, or stable carrier ID alone is insufficient. Replacement of either
tuple retires the predecessor contact. Predecessor, unwrapped, malformed, and
split-epoch frames must have zero queue, accounting, runtime, or backend
effect; progress resumes only after both endpoints bind the current pair and
complete fresh Aster authentication.

Durable partial-transfer progress is peer-neutral so it can resume with any
eligible peer, but that progress is not evidence that a particular peer holds
or may serve the object. Each hydrated WANT must be checked against that
contact's current authenticated, policy-filtered serve inventory before DATA is
produced. An ObjectID absent from that view—whether never advertised or
suppressed by the emission threshold—produces no serve action, backend call, or
DATA; the requester keeps its bounded peer-neutral progress. If an eligible
serve action does reach the backend, every authentication,
authorization-generation, NotFound, revocation, corruption, and storage-I/O
failure remains fatal.

Gate-H live durability evidence must come from the process-owned authority and
its atomic status receipt. During a Gate-H process run, the host controller must
never open that node's live SQLite WAL through a container bind mount. The probe
is exact-ItemID metadata only: it neither opens application payload nor creates
a second durable owner.

### Transactional admission

Admission is one fail-closed coordinator transition across `MeshHost`, the
node-global resource budget, and the runtime session:

1. candidate and carrier work first reserve aggregate pre-authentication
   capacity and a hard deadline;
2. carrier authentication yields only an untrusted locator, after which the
   peer completes fresh Aster mutual authentication;
3. `MeshHost` prepares an opaque admission token without publishing a peer
   binding or authenticated-contact state;
4. the resource lease atomically upgrades from pre-authentication to admitted
   contact/stream/task/frame/byte capacity, and the runtime revalidates the
   expected NodeID and current authorization generation;
5. only after every preparation succeeds does the coordinator commit one
   authenticated logical contact and allow synchronization bytes; and
6. timeout, close, duplicate election, identity conflict, capacity failure,
   stale generation, or any commit error aborts the token, releases all
   reservations, destroys the session, and leaves no partial binding, grant, or
   admitted state.

Token replay, commit after close, double commit, double abort, simultaneous open,
and failure at every boundary must have deterministic regression tests. Legacy
event paths that can publish authenticated state without this transaction are
not eligible for the experiment.

Outbound dials have a separate supervisor-owned pending-connection lease and
hard deadline before a carrier stream opens. Planning must reserve both the
Host pending-dial slot and aggregate pending-connection capacity before handing
work to a provider. Opening atomically replaces that claim with the complete
pre-authentication claim. Provider failure, explicit cancellation, or deadline
expiry settles the Host dial and releases the aggregate lease; the deadline is
part of the supervisor's next-wakeup calculation, not dependent on a provider
calling back eventually.

### Authorization-generation invalidation

The durable authority owns a monotonic authorization generation. Every
committed change that can affect exchange authority—including control,
revocation, rekey, and bridge authorization—advances it. A session captures the
generation only during committed admission and rechecks the authority
immediately before each authenticated outbound Aster flush.

A mismatch prevents the bytes from leaving, fails closed, and forces fresh
Aster authentication and authorization before synchronization resumes. A
generation check performed only when the contact starts, or only after a write,
does not pass. Tests must race a queued outbound frame against a committed
authorization change and prove zero stale-authority bytes are emitted.

### One aggregate resource budget

One node-global budget reserves and reports at least candidates, pending
connections, pre-authentication contacts, admitted contacts, streams, tasks,
queued frames, inbound and outbound buffered bytes, descriptors, and relay
reservations. Durable capacity and Blob quota are enforced by the same durable
owner. Every provider and native path uses the budget; per-contact bounds may
tighten it but cannot multiply it.

Reservations occur before allocation or task creation, transitions are atomic,
and all exits release them. The budget exposes current, configured maximum,
observed high-water, and rejection count per category. Tests must cover parallel
reservation at and over every bound, cancellation, panic/task termination where
recoverable, connection churn, and pre-authentication-to-admitted replacement
without a transient double charge.

## Gate H — provider-free live shared-node proof

Before adding any libp2p package, freeze and run a provider-free corrected-host
checkpoint using the bounded native LAN control:

- run A, B, and C as three real processes while B holds simultaneous live
  authenticated sessions with A and C against exactly one durable authority;
- publish at A, establish durable route-only custody at B, restart B, deliver
  the unchanged EnvelopeID and ItemID at C, application-acknowledge it, and
  prove no redelivery;
- while both B contacts are live, commit an authorization-changing control and
  prove a queued stale-generation outbound frame emits zero bytes, the affected
  contact fails closed, and an unaffected freshly authorized contact can make
  progress;
- race concurrent Blob reservations at the configured aggregate quota and prove
  no over-admission, counter divergence, or orphan allocation;
- force an admission-capacity failure after successful Aster authentication and
  prove no authenticated `MeshHost` binding, session grant, durable mutation,
  leaked task, or leaked resource lease remains; and
- retain static and runtime proof that B opened one SQLite node/backend and one
  Blob-store authority, not one per contact.

The live authorization race uses a lab-only, pair-bound `flash-only` B-pre
mode. It disables discovery, permits only Flash outbound material, and is valid
only when the exact authority-signed control and stale-target options are both
present. Inbound interest remains Routine-or-higher, so B can take route-only
custody of A's Immediate Event without forwarding that Event before restart.
It is a Gate-H instrumentation control derived from the required priority
threshold, not a new product mode or baseline requirement. This mode is not
receive-only and cannot be cited as receive-only proof.

The test supervisor now applies the configured emission mode rather than
silently substituting the default: B-pre is genuinely `flash-only`, and B-post
is a normal-emission restart. Any regression to a defaulted B-pre helper makes
the authorization-race witness invalid.

Ordinary receive-only keeps advertisements, discovery, inventory, and item data
silent while permitting only mandatory link, authentication, and
acknowledgement traffic needed to ingest, as specified by
[Decision 0004](../decisions/0004-radio-silence-semantics.md). The signed Flash
control advances the shared authorization generation; a frame already queued
for the named stale contact must remain at zero emitted bytes, that contact must
fail closed, and a freshly authorized contact must progress.

Each trial launches exactly four candidate processes in the reconstructable
order B-pre, C-continuous, A-pre, and B-post. The ten-trial cohort therefore
must retain exactly 40 process-evidence quartets. Each quartet consists of one
command record, one result record, one stdout file, and one stderr file under a
unique sequence. Aggregation reconstructs every expected argv, proves a
one-to-one mapping with no missing, orphaned, extra, or reused sequence,
requires a zero return code and no timeout, and reconciles those results with
the trial summaries. Summary return-code maps alone are not evidence.

The deterministic-fault contract currently defines 25 mandatory case names,
expanded into 40 exact one-test Cargo commands because admission single-use,
rollback, timeouts, identity handling, mixed-control commits, and generation
fanout require multiple independent witnesses. The command features also
compile-exclude the legacy service (`aster-host` uses `gate-h-formal` and
`aster-lab` uses `gate-h`, both with defaults disabled). A successful v2 fault
receipt additionally binds the clean signed commit and tree, requirements and
proposal digests, source blobs, exact executable path/size/digest, complete
bounded test streams, and static no-bypass checks. A case label without all of
its expanded commands is incomplete.

The `peer_neutral_resume_unavailable_peer` case binds one exact core test. It
must prove that a current authenticated contact whose served view lacks the
exact source emits no DATA and stays live without a backend serve call, while
the durable requester progress remains bounded and available for another
eligible peer.

The `process_owned_durable_item_probe` case binds exact core and host tests. It
must prove that committed and missing ItemIDs are distinguished through the
one existing semantic authority and supervisor without opening payload bytes
or creating another SQLite connection.

The gate is 10/10 clean runs plus deterministic fault tests. Any failure stops
the proposal before provider activation. An isolated retry may diagnose a
harness defect but cannot erase the original receipt or turn an incomplete
cohort into a pass.

The
[`retry-07` deterministic-fault receipt](../../evidence/ip_mesh_experiment/gate-h/p0004-gate-h-faults-retry-07.json)
passed 23 cases, 37 exact commands, and 26 static checks for signed commit
`797d11b8f88e53a8f03ebac5986d5afd3842dbcb`; it binds the pair-epoch repair but
predates the mandatory `peer_neutral_resume_unavailable_peer` case and its one
exact core test. The retained `retry-04` live cohort completed trials 1–3 and
failed trial 4 as described above. The retained signed `retry-05` cohort
completed trials 1–2 and failed trial 3 as described above. These receipts are
immutable diagnostic evidence and confer no Gate-H credit on the repaired
candidate. The repaired signed checkpoint must produce a matching fresh
25-case, 40-command, 26-static-check fault receipt and a fresh 10/10 cohort
before becoming the common baseline for either eligible arm.

Signed commit `dadce999c8052bfc20c8de5f6d8878b1ddb2f574` then produced the
[`retry-08` deterministic-fault receipt](../../evidence/ip_mesh_experiment/gate-h/p0004-gate-h-faults-retry-08.json),
which passed all 24 cases, 38 exact commands, and 26 static checks. Its
[`retry-06` live cohort](../../evidence/ip_mesh_experiment/runs/p0004-gate-h-retry-06/failure.json)
completed all 10 behavioral trials without a contact or protocol failure, but
the controller correctly withheld Gate-H credit because buildx left bounded
metadata in the otherwise-isolated Docker configuration and the final host
receipt was non-hermetic. That retained run is diagnostic only. The scoped
inventory-and-cleanup repair must itself be signed, fault-bound, and exercised
by another fresh 10/10 cohort before Gate H can pass.

Signed commit `2c5fab8a08cfa37f1a25aa513e80925b800bf40e` then produced the
[`retry-09` deterministic-fault receipt](../../evidence/ip_mesh_experiment/gate-h/p0004-gate-h-faults-retry-09.json),
which passed the then-current 24 cases, 38 commands, and 26 static checks and
bound the buildx cleanup. Its `retry-07` live cohort failed as described above,
so it confers no Gate-H credit. The process-owned durable-probe repair must now
produce a matching fresh 25-case, 40-command, 26-static-check receipt and a
fresh 10/10 cohort.

Signed commit `224fd940bc580a2f62dadbaa93a873b38935e10c` produced the
[`retry-10` deterministic-fault receipt](../../evidence/ip_mesh_experiment/gate-h/p0004-gate-h-faults-retry-10.json),
which passed all 25 mandatory cases, 40 exact Cargo commands, and 26 static
checks. Its candidate binary SHA-256 is
`2989cb11992f04a843bfd97004206097d9a7349ad73dc75e7d9525da187e59f5`.
The matching
[`retry-08` live summary](../../evidence/ip_mesh_experiment/runs/p0004-gate-h-retry-08/summary.json)
then passed all 10/10 combined real-process A/B/C trials, including the exact
1 MiB custody/restart/delivery chain, the live authorization-generation byte
barrier, process restart and fresh authentication, exact ItemID observations,
and zero clean-accounting failures. The controller reported evidence aggregate
SHA-256 `4cd435976e6544d20120e917da151be6a4f4177174d5265191cf3a1d546abe0b`
and evidence-index SHA-256
`7ac26490c89c124681c98a0c226c4592c2e03dba525802f311618454b39afee9`;
the independent post-hoc validator also returned `all_passed=true`, 10 passed,
and zero failed trials. Gate H is therefore complete for this exact baseline.
That result authorizes the corrected libp2p experiment only; it does not select
libp2p, change the requirements baseline, or grant production status.

### Historical post-Gate-H libp2p development checkpoint

The current post-gate tree adds a default-disabled
`aster-libp2p-provider` crate and an opt-in
`aster-lab/libp2p-candidate` test feature. The provider owns one persistent
Swarm, connection-attributed `/aster/sync/2` handlers, bounded length-delimited
framing, and carrier-mechanical state only. It does not own Aster candidates,
mission identity, authorization, retry policy, durable state, or a second
node-global resource budget. The lab coordinator retains a provider-base lease
from `SharedNodeContactSupervisor` before constructing each Swarm, then opens
the complete pre-authentication contact through `open_contact_with_factory`
before activating the selected stream.

The opt-in graph pins `libp2p 0.56.0` with TCP, Noise, Yamux, Identify,
connection/memory limits, relay client, DCUtR, and Tokio support, plus
`libp2p-autonat 0.15.0` with AutoNAT v1. It contains no Iroh,
`libp2p-mdns`, or `libp2p-stream`. Its only
`libp2p-request-response 0.29.0` path is the published AutoNAT v1
implementation. The formal `aster-lab/gate-h` graph remains provider-free and
contains none of those packages.

An unrestricted local development run used two persistent localhost
TCP/Noise/Yamux Swarms and one exact connection-attributed Aster stream per
side. Both shared supervisors freshly authenticated and admitted the remote
Aster identity. Four distinct 1 MiB items converged durably in both directions.
The run carried 44,355 A-to-C and 44,728 C-to-A actual `RuntimeDriver` frames;
for each direction, Link acceptance, provider submission, physical
`FrameSent`, remote provider receipt, and remote RuntimeDriver consumption were
exactly equal. Both 1,024-frame bounded Link queues reached their exact high
water and returned real full-queue `WouldBlock` 104 and 111 times. The provider
suite passed 20/20 tests, including repeated simultaneous dials, address-only
unknown-`PeerId` dialing, slow-writer recovery, truncated mid-frame close,
predecessor-state cancellation, live Identify exchange, and a controlled
AutoNAT-v1 `Unknown`-to-`Public` dial-back. A separately bounded localhost
relay test retained the exact reservation, relayed-carrier, circuit, DCUtR,
and fresh direct-carrier events at both clients. The complete opt-in lab
library suite passed 17/17. A SharedNode-owned direct replacement test kept the
predecessor physical connection live while dialing its successor, performed
the two-phase provider replacement, retired the old contact, reopened the
exact Host candidate as a new contact, and required fresh Aster authentication
before an interrupted 1 MiB item could finish. The same path passed the
Proposal 0002 trial-14 64 KiB payload size without the archived frame stall.
Strict clippy passed for the provider and combined candidate graph.

This is development evidence, not a Phase-0 receipt or complete Phase-1 pass.
Still required are a frozen source/SBOM/advisory receipt; Linux disposition of
unmaintained `paste 1.0.15`, reached only through
`libp2p-tcp -> if-watch -> netlink-packet-core`; packet proof that AutoNAT's
transitive request/response behavior never carries Aster data;
one combined supervisor-bound relayed-to-direct replacement proving that the
new path creates a new contact session and completes fresh Aster
authentication; replacement through address/process transitions; the complete
archived Proposal 0002 trial-14 process topology; and the remaining
Phase-2-through-5 experiments. The provider-only relay/DCUtR proof and the
full-node direct-replacement proof are deliberately separate development
witnesses and do not substitute for that combined row. No selection credit is
awarded until those rows pass.

## Eligible arms and provider boundary

### Corrected native

Compose the existing protected IP discovery, manual mapping, rendezvous,
hole-punch, UDP carrier, and locally operated ciphertext-relay components with
the common shared-node host. The arm may add bounded composition glue but may
not invent a new NAT, overlay, or authorization protocol.

### Corrected libp2p protected

Use one persistent `Swarm` per Aster process and the intended libp2p ownership
model. The initial exact candidate is registry-published `libp2p 0.56.0`,
default-disabled and already registered by the prior experiment. The prior
`libp2p-stream 0.4.0-alpha` helper is deliberately excluded: its peer-scoped
open/accept API neither selects nor reports the physical `ConnectionId`, so it
cannot prove which direct or relayed connection carried an Aster session during
DCUtR transition. The experiment instead owns a small, bounded
`NetworkBehaviour`/`ConnectionHandler` that negotiates one versioned Aster
protocol and reports `(PeerId, ConnectionId, path, stream)` to the common host.
This is libp2p's stable custom-protocol extension seam, not a second routing or
connection manager. Any version or feature change requires a new Phase-0
freeze and source-register record before use.

The eligible feature graph must contain only the mechanisms needed for:

- one frozen direct transport using TCP, Noise, and Yamux;
- one connection-aware custom stream behaviour and one full-duplex,
  long-lived Aster substream per logical contact;
- Identify for post-connection address enrichment;
- connection and memory/resource limits;
- bounded AutoNAT v1 using only the controlled experiment service; AutoNAT v2
  may replace it only if Phase 0 proves a hard cap on retained address-candidate
  state before enabling the feature;
- circuit-relay client behavior on Aster nodes and a separately operated,
  bounded experiment relay server R;
- DCUtR for relay-coordinated direct-connection upgrade; and
- the minimum Tokio/runtime support required by the Swarm.

No request/response behavior may carry Aster application or synchronization
traffic. AutoNAT v1's exact published implementation may retain its internal
`libp2p-request-response` dependency solely for controlled reachability probes;
that transitive mechanism must be named in the frozen graph and traffic
capture. Gossipsub, Kademlia, public bootstrap, public rendezvous, public
DNS/Pkarr discovery, and public relay presets must be absent from the exact
eligible graph and runtime traffic. Identify, AutoNAT, relay, and DCUtR events
enrich untrusted carrier state; they do not grant mission authority.

One substream carries many bounded Aster frames. Physical connection or
substream replacement, relay-to-direct upgrade, address/port change, and process
restart each create a new session and require fresh Aster authentication. The
Swarm owns connections and substreams; the adapter must not add a second peer
table, candidate scheduler, retry engine, relay policy, or authorization cache.
Network/provider tasks cannot own or open durable Aster state.

For libp2p, the equivalent binding is the exact observed `PeerId`, connection
ID, and negotiated substream generation. A stable `PeerId` or address cannot
route predecessor-stream bytes into a successor `RuntimeSession`; replacement
must close the predecessor before exposing the new stream to `RuntimeDriver`.

The custom handler must stay narrowly mechanical: negotiation, connection-ID
attribution, bounded framing, readiness, and close. It must have a named update
owner, compatibility tests, and a deletion plan. If it grows candidate,
authorization, durable-state, retry, or path policy, or if the exact published
graph cannot supply the remaining behaviours without a second large state
machine, the arm fails rather than being relabeled idiomatic.

### Libp2p provider-mDNS technical lane

Build provider mDNS as a separate feature and binary. It is not part of the
protected eligible graph and cannot contribute passes, code deletion, or
selection credit. The lane measures discovery traffic, state growth, emission
shutdown, candidate expiry, and hostile-cardinality behavior only.

The prior graph's Hickory advisories and pre-host growable discovery state are
known blockers, not waivers. Even if a later exact graph repairs them, this
proposal requires an explicit amendment before provider mDNS can become
requirements-eligible; no post-run promotion is allowed.

## Common configuration and controls

Freeze one versioned configuration with the same Aster provisioning, roles,
topics/scopes, payloads, emission modes, candidate limits, contact limits,
retry/deadline policy, global budget, Blob quota, locally controlled relay,
fault schedule, and acceptance timeouts. Provider-specific locator encodings may
differ, but their information, lifetime, exposure, and authority must be
reported.

All eligible runs use release binaries from the same compiler, target, base
image, topology, cgroup/process limits, and shared-node checkpoint. Trial order
is randomized and the seed retained. Arms do not run concurrently on the same
measurement host. A sentinel workload validates timing and packet-impairment
instrumentation before candidate measurements.

No acceptance network may reach public discovery, DNS/Pkarr, DHT, bootstrap,
rendezvous, AutoNAT, or relay services. Durable Aster relay B and ephemeral
connectivity relay R remain distinct; R never receives Aster custody or payload
authority.

The application receives the same high-level API and never selects a provider,
path, relay, address, or peer per item. Both arms expose the same automated
evidence command and manual multi-terminal walkthrough. The automatic LAN
demonstration receives no peer address, port, or carrier identity.

## Phase 0 — exact activation and freeze

From the signed Gate-H checkpoint, freeze for each arm:

- clean commits, dirty state, exact source archives and checksums, crate
  versions/features, lockfiles, target-specific normal/build trees, SBOMs,
  licenses, advisories, MSRV/toolchain, unsafe/native code, governance,
  vulnerability-reporting path, support policy, and update owner;
- release binary, debug-symbol policy, stripping command, target, size, digest,
  reproducible build command, and container/image digest;
- provider and experiment configuration, local relay server image/config,
  access controls, quotas, connection/rate limits, firewall/NAT rules, and proof
  that public services are absent; and
- a before/after mechanism inventory and the deletion patch expected if that
  arm wins.

An active reachable vulnerability, incompatible license, mandatory public
service, compiler-floor violation, unbounded hostile-input state, or missing
reporting/update owner blocks production selection. An isolated technical run
may continue only with the blocker labeled in advance; performance cannot waive
it.

OSI-approved permissive terms are evaluated against the actual requirement, not
treated as substantive failures merely because a local allowlist lacks an
entry. The allowlist and redistribution obligations must still be corrected and
receipt-bound before selection. Strong copyleft or proprietary licensing is a
hard gate. A non-software data-license expression or public-domain component is
classified separately and needs a written scope and distribution disposition;
it is not silently treated as either compatible or incompatible FOSS.

## Phase 1 — corrected architecture and persistent-stream proof

Independently review and dynamically prove for both eligible arms:

- exactly one process durable authority and Blob quota owner, with non-clone,
  contact-isolated sessions;
- transactional admission and expected-peer binding with no pre-commit durable
  sync or externally visible authenticated state;
- generation invalidation before every outbound flush;
- aggregate budget enforcement across every provider/native task and buffer;
- one owner for candidates, connections, logical contacts, retry, paths, and
  authorization state;
- readiness/I/O/deadline-driven work with no fixed fast pump loop;
- zero discovery transmission in constrained and receive-only modes;
- one Aster logical contact per peer despite simultaneous opens; and
- fresh Aster authentication after every replacement stream, path/address
  transition, and process restart.

The libp2p arm must carry at least 10,000 actual `RuntimeDriver` frames in each
direction over exactly one connection-attributed substream while no
request/response behavior carries Aster data. It must survive bounded
backpressure, slow reader/writer, cancellation, and mid-frame close without
unauthenticated commit, and it must pass the archived Proposal 0002 trial-14
regression. Identify, AutoNAT, relay, and DCUtR must be active behaviours with
bounded state, not merely lockfile entries.

Any shared-node or admission failure stops both arms. A provider-specific failure
stops only that arm if the common corrected-native control remains clean.

## Phase 2 — discovery, manual peering, and LAN custody

For every surviving eligible arm:

1. run 30/30 clean A→B, B restart, B→C trials preserving the source EnvelopeID
   and ItemID, route-only unreadability, application acknowledgement, and no
   redelivery;
2. run 10/10 automatic LAN-discovery trials with no peer locator or carrier
   identity in node configuration;
3. run 10/10 manual/pre-provisioned trials with automatic discovery disabled;
4. prove constrained and receive-only modes emit zero discovery bytes while
   receive-only accepts an authorized inbound contact; and
5. prove 100 provisioned candidates receive a contact opportunity within one
   configured cycle with service-count skew no greater than one.

The eligible libp2p arm uses Aster protected discovery in the automatic lane.
Provider mDNS results are reported separately and do not substitute for any row.
Settled normal-mode discovery remains at or below 4 KiB per node per minute
unless a stakeholder-ratified replacement is frozen before implementation. No
post-run threshold change is allowed.

## Phase 3 — controlled NAT, relay, and path lifecycle

Use reproducible network namespaces with retained interface, route, firewall,
translation, and capture receipts. Run 10/10 trials for each surviving arm in
each cell:

- same-LAN direct contact with every infrastructure process absent;
- permissive-NAT direct contact using information-equivalent offline hints;
- provider/native traversal coordinated only by experiment-owned
  infrastructure, labeled coordinated even if the final path is direct;
- restrictive-NAT fallback through locally operated connectivity relay R;
- relay loss followed by bounded reconnect and direct-path reconsideration; and
- address and port change with stable carrier identity but a new Aster session
  and fresh Aster authentication before data exchange.

The native arm may use only its existing rendezvous, punch, and opaque-relay
mechanisms plus bounded composition. The libp2p arm must retain explicit event
evidence for Identify address enrichment, AutoNAT status, circuit reservation
and relayed connection, DCUtR coordination, direct upgrade where the topology
permits it, relay loss, and the post-change Aster authentication. Compiled
features or a final direct socket without that sequence are not a pass.

## Phase 4 — impairment, security, scale, and measurements

Validate a hash-bound userspace packet schedule against a sentinel corpus; do
not use unsupported random-seed syntax. Every surviving arm then runs:

- 10/10 deterministic 1 KiB command trials at 3,000 bit/s and 50% loss within a
  predeclared ten-minute timeout;
- interruption/resume across a different peer, duplication, reordering,
  wall-clock jump, simultaneous open, carrier/path churn, and process restart;
- revoked and unauthorized peer, stale authorization generation,
  carrier-identity reuse, malformed/truncated/oversized frame, discovery flood,
  connection/stream flood, relay-reservation exhaustion, quota race, and every
  node-budget capacity case;
- unique payload, logical-key, publisher, topic, scope, priority, and control
  canary scans over packet captures and provider-owned caches/logs;
- one 100-real-process segmented-IP run and one 10,000-item Tier-2 run; and
- ten-minute and one-hour settled idle runs plus at least 30 successful 1 KiB,
  64 KiB, and 1 MiB direct and relayed transfer samples.

Report raw observations and p50/p95/p99 where the sample count supports them:

| Dimension | Required measurements |
|---|---|
| Correctness and recovery | discovery, carrier connect, Aster authentication, durable observation, custody, delivery, acknowledgement, redelivery, reconnect, resume, path-change, and failure reason |
| Custom code and mechanisms | product non-test/test lines added, changed, and deleted; lab/tooling separately; functions/modules and mechanism owner before/after; provider wrapper versus common shared-node code |
| Build and supply chain | stripped binary and incremental bytes, active and locked packages, compile time, SBOM, licenses, advisories, MSRV, unsafe/native surface, and reproducibility |
| Memory and boundedness | process/cgroup current and peak memory, 10,000-item steady state, provider caches, task/stream/descriptor counts, every global-budget current/high-water/rejection count, and Blob/quota high-water |
| CPU and idle | CPU time and percent of one core, wakeups/context switches where supported, startup work, ten-minute and one-hour settled idle, and evidence-tooling overhead control |
| Throughput and link cost | setup and time-to-first-durable-item, application goodput, carrier and total interface bytes, payload amplification, direct versus relayed distributions, and 1 KiB/64 KiB/1 MiB transfer time |
| Discovery and privacy | first-candidate latency, candidates and false candidates, provenance/expiry, normal and silent-mode bytes, address/relationship/timing exposure, capture and provider-state canary results |
| Scale and fairness | 100-candidate opportunity latency/skew, 100-process convergence and failures, concurrent-contact progress, relay reservations, and recovery after saturation |

Selection screens remain: less than 1% of one core at settled idle after
subtracting the measured evidence-control cost, no busy polling, no more than
10 MiB incremental stripped binary size, no more than 64 MiB steady RAM at
10,000 items with 32 MiB preferred, and zero protected-canary matches. CPU must
also be reported without subtraction so the adjustment is auditable. All node
budget maxima must hold under concurrency with zero over-admission.

The earlier upstream 64 KiB failures are mandatory regressions. A provider that
exits successfully before exact durable observation has failed the trial.

## Phase 5 — deletion, rollback, and disposition

Before selection, produce an actual reviewable deletion patch for each surviving
arm. Common shared-node architecture is charged equally. Provider-specific host
changes are charged to that arm. Test/lab code is separate and cannot reduce the
production mechanism score.

The libp2p arm passes buy-over-build only if its selection patch removes the
overlapping native production connection, traversal, and relay mechanisms it
actually replaces; adds fewer provider-specific product lines than it deletes;
and leaves no dormant native optional/default connectivity stack. Protected
Aster discovery is common policy mechanism in both eligible arms, is charged
equally, and is not falsely counted as libp2p deletion. A bounded native test
oracle may remain only when labeled and unreachable from production features.
If native wins, remove libp2p source, features, lockfile reachability, and
provider-only configuration and retain no dormant external stack.

### Rollback from each arm

Both arms start from independent copies of the signed Gate-H durable stores with
an identical partially transferred item. For each arm:

1. stop every node and local infrastructure process;
2. discard only experiment-created carrier keys, address caches, relay
   reservations, connection state, and arm-specific configuration;
3. remove/disable the arm's experiment delta and rebuild the signed Gate-H
   provider-free native LAN control, proving rejected external packages or
   experiment-only native composition are absent;
4. reopen the unchanged Aster SQLite and Blob stores without schema, wire,
   protocol, or application migration;
5. authenticate through the same provider-neutral host seam, resume the partial
   transfer, preserve the original full ItemID and EnvelopeID through A→B→C,
   and application-acknowledge it with no redelivery; and
6. retain the signed candidate and immutable evidence, then remove rejected arm
   code from the continuing branch.

The Gate-H control already contains the corrected durable owner, admission,
generation, and budget architecture. Rollback may never reintroduce the rejected
per-contact durable-owner design as a production default. It is a failure if it
deletes durable Aster truth, needs migration, retains overlapping production
mechanism, or cannot resume through the same seam.

## Evidence and provenance contract

Before consulting or using a new public source, component version, image, or
tool, register its exact URL/revision, access time, purpose, license, and result
in `evidence/SOURCE_REGISTER.csv`. Existing Proposal 0003 public-source records
may be reused only for the exact versions and claims they cover. No forbidden or
unregistered input may enter the experiment.

The provider behavior and version claims used to draft this proposal are
limited to registered entries BVB-613 through BVB-615, BVB-630, BVB-634 through
BVB-638, and the pre-execution recheck BVB-643.

Retain append-only, hash-bound evidence for every pass, failure, timeout,
interrupted run, retry, and outlier:

- signed start, Gate-H, candidate, deletion, and rollback commits plus clean or
  dirty state;
- exact commands, environment, tool versions, binaries, manifests, lockfiles,
  feature graphs, canonical signed-tree archives and inventories, read-only
  source materializations, images, configurations, and random seeds;
- the controller's exact Python re-execution environment, absolute Git and
  Docker and OpenSSH invocation and resolved executable identities, frozen
  allowed-signers bytes and exact signer principal/fingerprint, explicit Docker
  Unix socket, Docker client/server version receipt, and initially/finally
  empty isolated Docker configuration, plus the signed-export controller,
  fault-runner, and aggregator origins, raw bytes, modes, interpreter flags,
  import path, one-shot handoff, and pre/post bytecode-absence proofs;
- topology, namespace, interface, route, firewall/NAT, relay, process/cgroup,
  clock, and impairment receipts;
- structured events separating discovery, carrier authentication/connection,
  Aster authentication, admission prepare/commit/abort, generation check, local
  commit, custody, delivery, and application acknowledgement;
- all measurements listed in Phase 4 and before/after source/mechanism
  inventories;
- nonempty packet captures and provider-state scans; and
- removal builds, unchanged-store hashes where stable, partial-transfer identity,
  rollback outputs, evidence-index digest, and canonical aggregate digest.

Evidence tooling must record process exit status and terminal receipts before
teardown. Failed cohorts are never silently replaced by isolated reruns. Missing
tooling is **blocked**, expiration is **inconclusive/timeboxed**, and an observed
semantic, security, boundedness, rollback, or mandatory functional violation is
**failed**.

An interrupted formal run must terminate and reap every owned child, perform
scoped container/network cleanup, and retain an indexed failure receipt before
returning the signal-derived status. A second interrupt may not bypass that
bounded cleanup or overwrite the first terminal receipt.

The final report must name its exact requirements baseline, distinguish direct
requirements from Decision 0024 controls, link every claim to retained evidence,
and state stopped phases as stopped rather than zero-trial passes. A later
architecture decision selects one profile or none. Requirements traceability is
updated only for behavior actually implemented and verified; this proposal by
itself changes no requirement, conformance status, dependency admission,
production default, or capability claim.

## Stop limits and early-abort rules

| Work | Stop limit |
|---|---:|
| Shared-node implementation, review, and Gate H | 6 engineer-days |
| Exact activation, common harness, and owned relay freeze | 4 engineer-days |
| Corrected native composition | 3 engineer-days |
| Idiomatic libp2p integration and Phase 1 | 6 engineer-days |
| Discovery plus controlled NAT/relay lanes | 5 engineer-days total |
| Impairment, hostile input, scale, and resource runs | 4 engineer-days total |
| Deletion, rollback, report, and decision input | 2 engineer-days |

Stop the whole proposal if Gate H fails, the common host admits before
`MeshHost`, the resource budget, and the runtime session all commit,
stale-generation bytes leave the process, or aggregate
limits can be multiplied by contact count. Stop an arm if it changes Aster wire
or application semantics, requires a public service, cannot suppress discovery,
cannot bound pre-host or unauthenticated work, repeats the trial-14 or 64 KiB
failure, cannot exercise every mandatory NAT/relay cell, or lacks a credible
deletion and rollback patch by the end of Phase 3.

The provider-mDNS technical lane stops on its own timebox and never delays the
eligible protected profile.

## Selection and completion

All mandatory gates are non-compensable. Resource, code-size, or dependency
advantages cannot offset a correctness, authorization, boundedness, functional,
assurance, or rollback failure.

If both eligible arms pass, select one only if it is no worse across semantic
fit, security/assurance, bounded resources, link cost, privacy, operations,
mechanism deletion, migration, and rollback, and materially better on at least
one accepted dimension. Otherwise select **none**; do not create a post-hoc
weighted score or keep overlapping production stacks.

Completion appends a dated outcome without rewriting this hypothesis, produces
a separate result document and a new architecture decision, preserves all
failures and signed evidence, and removes every rejected experimental
integration. Until then Decision 0024 remains authoritative and no IP provider,
dependency, requirement, conformance scenario, MVP status, or deployment
profile is selected.

## Outcome — 2026-08-23

Proposal 0004 is closed as superseded before its formal Phase-0 freeze and
Phase-1 comparison. Gate H passed only for the provider-free shared-node
baseline. The corrected-native arm and the default-disabled rust-libp2p arm did
not produce the frozen comparative Phase-0 receipt or complete Phase-1 result;
Phases 2–5, the deletion comparison, and rollback fixture were not reached.
Consequently no arm passed or failed the full proposal, and no arm is selected
from it.

The final rust-libp2p development checkpoint passed its bounded localhost test
suite and remains preserved in this closure's version-controlled tree. Its
exact source files are:

- `crates/aster-lab/src/mesh_experiment/libp2p_candidate.rs` — SHA-256
  `7b12a8f028593729a36a1bc524cff09939c803bc168b36959e6fb576d6dfa1fe`;
- `crates/aster-libp2p-provider/src/adapter.rs` — SHA-256
  `eb9ab9ef50cf248042872f993d114c37c0af4399792945426b9504061503ec22`.

The lab source hash includes a watchdog-only stabilization made after a slow
shared CI runner exhausted the original 120-second bound while continuing far
beyond the required frame count. The bound is now 300 seconds; the workload
and every delivery, durability, backpressure, stream, identity, and resource
assertion are unchanged. This is a deadlock bound, not throughput credit.

It is retained only as a
publish-disabled, opt-in test oracle under
[Decision 0027](../decisions/0027-libp2p-pilot-dependency-policy.md). It grants
no requirement, conformance, compatibility, dependency-admission, capability,
or production credit and must be removed or explicitly reauthorized by that
decision's deadline.

Proposal 0005 and Proposal 0006 independently moved the program to a
requirements-first engineering baseline. Rust-libp2p is therefore rejected
from the continuing selected-stack implementation, default, deployment, and
production lanes. This is a portfolio disposition, not a claim that
rust-libp2p failed gates that were never run. See the
[separate result](0004-shared-node-libp2p-retest-results.md) and
[Decision 0029](../decisions/0029-close-proposal-0004-libp2p-pilot.md).
