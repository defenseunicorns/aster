# Security Architecture and Threat Model

- Version: 0.1.0
- Status: reference design; production security and integration gates unsatisfied
- Profile policy: [Decision 0033](decisions/0033-policy-selected-security-profiles.md)
  and its [requirements disposition](validation/security-profile-requirements-disposition.md)

This document primarily describes suite/profile `0x0001` and the stock selected
runtime. The additive, evaluation-only profile `0x0002` boundary is documented
separately in [Classical P-256 / Iroh-QUIC security profile](classical-iroh-security-profile.md).
Decision 0033 makes metadata exposure and classical versus hybrid-PQ use
policy-selectable; neither profile reinterprets the other's bytes or evidence.

## Find a section

| Question | Read |
|---|---|
| What is protected, and from whom? | [Assets and adversary](#assets-and-adversary) and [trust boundaries](#trust-boundaries) |
| How are provisioning artifacts and persistent keys handled? | [Provisioning artifact and persistent-key custody](#provisioning-artifact-and-persistent-key-custody) |
| Which controls are mandatory? | [Mandatory controls](#mandatory-controls) and [key access matrix](#key-access-matrix) |
| What do revocation and zeroization mean? | [Authority custody](#authority-custody-and-control-continuity) and [revocation meaning](#revocation-meaning) |
| How is availability bounded? | [Causal evidence](#causal-evidence-and-bounded-state) and [availability controls](#availability-controls) |
| What blocks production authorization? | [Mesh cryptographic provider status](#mesh-cryptographic-provider-status) and [security test gates](#security-test-gates) |

## Implemented profile boundary

Two versioned profile implementations now exist, with deliberately different
supported surfaces and integration maturity. Profile `0x0002` is a bounded
Event/control evaluation slice, not a complete MVP/product profile:

| Profile | Implemented boundary | Runtime status |
|---|---|---|
| `0x0001` `hybrid-pq-aster-record-v1` | Hybrid source/control objects, four-flight mission session, and `ASTRFR01` application records through semantic v6 | Stock selected node/runtime |
| `0x0002` `classical-p256-iroh-quic-v1` | Provisioned singleton policy, P-256 semantic-v1 Event/control objects, Iroh TLS-exporter-bound mission session, and raw QUIC application exchanges | Additive library/two-node mission path; not selected by stock `run_node` or CLI |

Profile `0x0002` has no ML-DSA or ML-KEM operation in its runtime path and adds
no Aster application-record layer over QUIC. It still performs P-256 mission
authorization and separately protects sealed source Event bytes at rest.
Combined builds retain the profile-`0x0001` code and PQ dependencies. Its exact
metadata budget, five-second open-connection keepalive behavior, persistent
policy-binding limitations, unsupported forms, and remaining release gates are
declared in the profile boundary document.

## Assets and adversary

Protected assets are item plaintext, protected routing metadata, publisher
authenticity, causal history, authorization state, key epochs, provisioning
artifacts, identity/routing/content seeds, backups containing those values, and
availability within declared quotas. The adversary may observe, drop, delay,
duplicate, reorder, replay, modify, and inject traffic on every carrier; run an
untrusted rendezvous/relay; capture old packets; later possess a revoked device;
or obtain a copied local artifact, backup, crash dump, or accidentally committed
file.

The design does not hide protocol presence, timing, packet size, direction, or RF
energy. It cannot stop an authorized reader from disclosing plaintext, a routing
member from observing protected metadata it is entitled to decrypt, or a captured
device from reading data for which it already obtained keys.

## Trust boundaries

```text
provisioning authority
  -> offline authority-root hybrid key signs node credentials and roles
  -> unique ControlAuthority identity keys append delegated controls
  -> one mission control chain keyed by the stable authority root identifier
  -> independent scope routing grants
  -> independent topic/readership content grants

source item
  -> source AES-GCM content encryption
  -> ECDSA + ML-DSA singleton authentication, or exact batch proof + item path
  -> scope routing wrapper
  -> optional authorized target-scope wrapper preserving the source carrier
  -> pairwise protected session
  -> untrusted IP/BTLE/rendezvous/relay carrier
```

The adapter API has a broadcast capability bit, but no complete protected
broadcast replication capsule or repair protocol is implemented.

### Controlled Iroh connectivity relay

The selected carrier can use one exact operator-pinned HTTPS relay origin below
the peer QUIC and Aster hybrid mission session. The URL is limited to 2 KiB and
must have a host, the root path, and no user information, query, or fragment.
The operator must explicitly select embedded WebPKI trust or provide
one to eight DER CA roots, each at most 64 KiB and 256 KiB combined. Explicit
roots replace WebPKI. There is no insecure mode, trust fallback, hosted lookup,
public/default relay substitution, or port mapping.

The exact remote Iroh endpoint ID is still authenticated independently of relay
TLS, and the hybrid mission identity is authenticated independently before
inventory. Neither relay TLS nor Iroh endpoint identity grants mission
membership, route/content access, source authority, receipt validity, or
synchronization success. Direct-plus-relay startup does not wait for relay
readiness; relay-only requires readiness and disables IP. Iroh may probe an
initial direct locator and the relay in parallel and may learn a later
authenticated direct path through NAT negotiation. Initial locators are not
lifetime pins, and no direct-first or NAT-acceptance property follows from the
configured route or path witness alone.

Direct/Relay path telemetry retains only the last observed path and a coalesced
transition count capped at 1,024. Ordinary closure preserves the last
observation; missing or continuity-lost observation becomes Unknown and records
loss of fidelity. These fields are operational diagnostics and are never
authorization or success inputs.

### Nearby discovery metadata boundary

The default selected Iroh endpoint installs no address lookup. An explicitly
feature-gated demo/evaluation mode may install the official Iroh mDNS provider
for at most 30 seconds under normal emission policy. Its DNS-SD records carry
only the Iroh carrier identity and direct IP address hints. Aster configures no
lookup user data, and node names, mission identities, authorities, topic/scope,
priority, membership, inventory, and payload are not discovery metadata.

This is best-effort metadata minimization, not metadata secrecy. Any on-link
observer can still infer Aster service presence, stable carrier identity during
that identity's lifetime, IP/port, timing, and packet sizes. The mission
handshake and protected Event metadata begin only after Iroh authenticates an
exact provisioned carrier identity. Discovery never grants admission.

Continuous discovery is deliberately not selected: prior measurement found
material recurring traffic, and the provider's internal peer maps are not
hostile-cardinality bounded. Expiry or shutdown clears the provider, while
invitation mode produces no recurring discovery traffic. See
[Nearby discovery FOSS selection](evaluations/0005/nearby-discovery-selection.md).

The controlled Iroh relay is transport infrastructure, not an Aster mission
node: it has no Aster store or route grant. The payload-blind Aster Event relay
below is instead a mission node with route-only Event custody, and route-only
Blob relay/custody remains unimplemented. Current real-process controlled-relay
evidence is one-host and Event-only. A separate focused direct-Iroh runtime test
proves that a wrong expected mission fails before inventory; it is not part of
the relay-path process proof. Neither source/test result creates retained,
physical, representative-NAT, BTLE, mixed-implementation, N=32,
State/Record/Blob-over-relay, or release credit.

A separately frozen retained receipt observes the selected Event carrier in two
Docker Linux namespace cells on one Darwin arm64 host. One cell disables every
relay and selects Direct across two software NAT routers with static
operator-known mappings. The restrictive cell records direct drops and selects
the exact DER-pinned controlled relay. Each cell delivers and acknowledges one
exact 32-byte Event and repeats as an exact no-op. The public receipt contains
only bounded sanitized data and packet tuple/count metadata; the raw pcaps,
mission bundles, credentials, and encrypted stores remain external-restricted.
Its canary scan covers exactly 26 enumerated finalized targets, not every file
or the whole host. This is not discovery/punching, a temporal fallback sequence,
representative or physical NAT, public Internet/relay operation, independent
implementation, packet-capture confidentiality acceptance, complete-MVP, or
release evidence. See the [receipt and replay boundary](validation/requirements-status.md#selected-iroh-nat-retained-receipt).

Aster application relays are not content readers by default. The implemented
semantic-version-2/3/v4/v5/v6 bridge similarly limits a bridge to rule-specific endpoint routing grants and
an authority-signed directed-edge authorization. It rewraps the exact immutable
format-2 source carrier without content access, preserves the source signature
and origin scope, and exposes a distinct authenticated current scope. A target
reader still needs the exact origin scope/topic/content-epoch grant; target
membership, bridge authority, and target content grants cannot substitute for
it. The remaining cross-implementation and physical acceptance gates are in
[conformance.md](validation/conformance.md).

The exact protected bytes, signature messages, KDF inputs, and bounds are
normative in [envelope.md](envelope.md).

## Provisioning artifact and persistent-key custody

`ASTRPB03` is a checksum-protected plaintext inner representation containing
secret material. Separate `ProvisioningProtector` and
`ProvisioningUnprotector` interfaces keep authority-side recipient encryption
apart from node-side identity/private-key decryption. Each top-level protect or
open operation completes local, size, and magic prechecks first: failure makes
zero provider calls, while passing all prechecks makes exactly one protector or
unprotector attempt. Aster neither retries nor falls back internally; a caller
may explicitly start a new operation. The recovered plaintext is bounded to
125,877 bytes and held in a redacted non-cloneable container whose owned
allocation is zeroized on explicit erase and drop.
Protected artifacts are bounded to one MiB. Provider errors retain only safe
typed categories, and failure cannot fall back to interpreting the artifact as
plaintext.

The interface does not itself guarantee encryption. In addition to behavioral
test providers, the repository ships an isolated `aster-provisioning-age` pilot
using exactly pinned Rust `age` 0.11.5 with `default-features = false`. The
configuration accepts only 1–16 classic X25519 recipients or identities; it
does not expose passphrases, SSH identities, plugins, tagged hardware
recipients, or any post-quantum recipient profile. Its
streaming path remains inside Aster's outer and recovered-plaintext bounds and
must authenticate through EOF before plaintext can be returned. A narrow
`age-core` custom-identity wrapper examines age's parsed stanza metadata and
requires 1–16 X25519 stanzas, rejects scrypt and more than one extension stanza,
and does so before attempting any identity unwrap. This bounds peer-controlled
work without implementing a second file parser.

Standard age adds one mandatory GREASE/unknown stanza to non-scrypt files. The
parser does not label it separately, so the wrapper permits one non-scrypt
unknown stanza and cannot prove that it is GREASE rather than another meaningful
extension recipient. The provider never executes or loads such an extension,
and decryption still requires a matching X25519 stanza, but strict byte-level
X25519/GREASE-only classification remains an upstream-API residual.

Memory clearing is best-effort and specifically bounded. The provider clears
the plaintext/ciphertext buffers owned by its Aster wrapper and returns no
partial plaintext after authentication failure. Rust `age` 0.11.5 does not
comprehensively zeroize its internal plaintext encryption buffer or every
intermediate created while decoding an X25519 identity. No claim extends to
those upstream temporaries, allocator/compiler copies, crash dumps, swap, or
complete process-memory erasure. This residual is separate from successful
ciphertext authentication and is another production-review gate.

This is an experimental Rust-only provider, not an operational default. Rust
`age` describes pre-1.0 releases as beta software for testing and its repository
has no detected security-policy file. The plugin feature is disabled, and
0.11.5 includes the plugin-execution fix first released in 0.11.1 for
`GHSA-4fg7-vxc8-qx5w`. Bidirectional interoperability with exact
reference Go age v1.3.1 is a required batch gate, not a mesh-interoperability or
security-audit claim. [Decision 0018](decisions/0018-age-provisioning-provider.md)
records the dependency graph, sources, exception, and exit gates.

The pilot graph also contains build-time `proc-macro-error2` 2.0.1 through
`i18n-embed-fl` 0.9.4. RustSec `RUSTSEC-2026-0173` marks it unmaintained and
lists no patched release; the advisory is informational and reports no
vulnerability. Current Rust separately reports future-incompatibility `E0365`.
The exact advisory is ignored by dependency policy only for this bounded pilot,
with locked checksums and offline validation after dependency acquisition. It
is not a reported runtime vulnerability, but build-time code can influence the
produced binary. It therefore remains an unresolved supply-chain and
compiler-lifecycle risk and independently prohibits production admission.

The profile is X25519 and ChaCha20-Poly1305 based. It provides no post-quantum
artifact-confidentiality or FIPS 140-3 validation claim. The raw
`ApplicationNode::open`, `MeshService::open`, FFI, Go, and Python paths remain
unprotected compatibility/test ingestion. The stock `aster node`,
`control-revoke`, and `control-rekey` CLI paths also still require an owner-only
unprotected-reference bundle. A Rust embedding can instead construct a live
`NodeConfig` from a protected file, protected bytes, or an exact opaque provider
reference. Every successful path still retains the recovered canonical bundle
as zeroizing plaintext in the running process.

`NodeConfig`, stopped `SelectedEventNode`, and stopped `SelectedControlAdmin`
compose the protection boundary. `NodeConfig::open_protected`,
`NodeConfig::from_protected_bytes`, and `NodeConfig::open_secret_ref` take a
private, fully validated `NodeConfigOptions` value, reject durable terminal state
before provider invocation or state creation, expose only sanitized errors, and
never fall back from provider rejection to plaintext parsing. The stopped
surfaces accept the equivalent protected sources. These entry points are
caller-supplied Rust APIs, not stock CLI or C/Go/Python binding paths, and they
do not select or admit a provider.

Runtime `READY` and `STOP` receipts expose only the stable non-identifying
origin labels `provider-protected-artifact` and `provider-secret-reference`.
They do not expose a path, provider identity, operation ID, or opaque reference,
and they are not provisioning, custody, or destruction receipts.

Persistent custody now has a provider-neutral contract, not a production
backend. A versioned, bounded `ProvisioningSecretRef` carries an opaque backend
locator or capability; its debug output is redacted, but opacity does not make
it public. Separate caller-chosen install, load, and destroy operation IDs bind
retries. Checked helpers reject a zeroized install before backend invocation
and validate the exact install operation; load and destroy validate both the
exact operation and caller-supplied reference. A
successful load transfers a bounded Aster-owned zeroizing plaintext value for
immediate ingestion. A mismatched load result is dropped and zeroized before
the sanitized rejection returns.

A `ProvisioningDestroyReceipt` records only the trusted backend's assertion
that its logical destruction contract and durable tombstone completed. Aster
checks the echoed operation and reference but cannot independently prove the
backend's durability. `NotFound` is explicitly indeterminate, and neither
`Destroyed` nor a receipt proves physical flash erasure, snapshot/backup/swap
removal, remanence protection, or media sanitization. No selected workflow yet
coordinates live-node drain, store terminalization, reference destruction, and
recovery policy. A live node created from protected or secret-reference
provisioning can shut down gracefully, but the selected same-UID local
software-zeroization path has no provider destroyer and cannot destroy the
provider artifact, opaque reference, or provider-held secret.

For the selected unprotected-reference path on Unix, local zeroization closes
all application admission, joins the live Blob worker, terminally locks the
mission-bound store, and overwrites/synchronizes/truncates the retained mission
bundle and carrier-identity files. Redb rows and the encrypted Blob depot are
deliberately preserved for terminal-safe audit. Destroying the retained
mission/content secrets makes that depot unavailable through normal operation;
this is bounded cryptographic shredding, not proof that ciphertext files,
filesystem history, swap, snapshots, backups, or physical media were erased.

Relative state and protected-file paths for live `NodeConfig` construction and
the stopped Event/admin opens are resolved against one captured absolute
current directory before a caller provider or loader can change the process
current directory. The live config retains that exact absolute lexical state
pathname and rejects later public-field mutation before state creation. This is
not an inode, parent-directory, symlink-resolution, rename-history, database
identity, or rollback witness. Protected file reads separately retain no-follow
and opened-file identity checks on Unix; equivalent non-Unix path-swap
assurance, parent-directory symlink/rename races across every boundary,
database rollback or replacement, and a supported restore/rebind procedure
remain open.

A production backend still needs platform or hardware key policy,
authentication/access control, unattended-start decisions, recovery and backup
procedures, rollback handling, operation-ledger retirement, and verified
failure behavior. The in-memory fixture tests only the API model; it is not
evidence of backend durability, secrecy, or erasure. This model does not defend
secrets against a fully compromised running process or root, unlocked-memory
inspection, swap, DMA, backups, or crash dumps unless the selected platform and
deployment add those controls.

## Mandatory controls

The suite-specific controls below remain mandatory for current complete suite
`0x0001`. The profile-invariant controls and applicability of future profiles
are recorded separately in the
[security-profile requirements disposition](validation/security-profile-requirements-disposition.md).

- Canonical ordered semantic-version and complete-suite offers, with selection
  bound into the transcript, KDF, key confirmations, and hybrid authentication;
  there is no algorithm-by-algorithm mixing. The stable framing/profile remains
  `1`, the default semantic offer is `[6, 5, 4, 3, 2, 1]`, and profile 1 has one registered
  complete suite.
- Both classical and PQ signatures verify; failure is indistinguishable on wire.
- A compact semantic-version-2/3/v4/v5/v6 batch item is never authenticated by its P-256
  suffix alone: the exact proof credential, authority hybrid signature, source
  hybrid root signature, ciphertext commitment, Merkle path, and item signature
  must all verify. Missing proof means bounded pending state, never delivery.
- Selected Event/RouteEvent semantic-v3-format custody claims, used by v3, v4, v5, and v6 sessions, use a distinct
  session-record AAD, bind the exact transfer/source fields, exchange, nonzero
  policy revision, session ID, and checked cumulative age, and are
  replay-checked before store admission.
- Protected v3-format Event interests used in v3/v4/v5/v6 bind an opaque receiver
  selector generation.
  Receipts suppress only that generation; `Satisfied` hides Carry versus
  successful Consume, while `ContentAcceptancePending` reveals only that the
  offered object still lacks receiver-required content acceptance. The value is
  not a Byzantine peer-state high-water: an authenticated peer can still lie
  about its own retention or restore its own older state.
- Durable partial-transfer progress preserves its first-admission semantic
  version. Unknown provenance fails closed, and v2/v3/v4/v5/v6-only objects cannot be
  resumed or served through a selected-v1 session after restart.
- Hybrid ephemeral establishment, transcript binding, explicit key confirmation,
  direction/purpose labels, and no 0-RTT data.
- Anonymous mission proof before responder P-256/ML-KEM work; responder and
  initiator credential contexts protected under hybrid-derived keys.
- AES-GCM keys/nonces are purpose separated; a key/nonce pair is never reused.
- Session replay windows, ItemID idempotency, publisher counters, control-chain
  sequence/hash, and key epochs reject replay as new work.
- `ASTRPB03` field bundles never contain the authority-root signing seed.
  Format-2 controls require a root-signed ControlAuthority credential and the
  delegated identity's hybrid signature; signer identity is persisted and
  checked against the applied revocation state before activation.
- Selected recipient-package rekey authenticates the signed registry and every
  canonical recipient credential before key generation. A fresh rekey cannot
  select or activate a recipient that is already revoked when that request is
  evaluated. An exact same-signer historical duplicate may still recover its
  original durable receipt after a recipient is later revoked. After any
  revocation, a new legacy
  recipient-less scope-epoch control is rejected; an authenticated one that
  predates revocation may remain historical. Revocation and rekey are still two
  separate administrator transactions, not an automatic or atomic remediation
  workflow.
- A running authority exposes the same bounded operations through
  `SelectedControlHandle`. Its queue capacity is one, the actor processes at
  most four control commands before yielding, and each command takes the same
  policy write lease as other policy mutation. An authenticated pending gap is
  a deferred, nonterminal policy condition: fresh publication returns the
  sanitized `PolicyUnsettled` category while an exact historical retry remains
  recoverable. Dropping or cancelling a caller after enqueue does not retract
  actor-owned work; it may still commit, so the caller must retain and exactly
  retry the request. If a self-revocation commits but its response is lost, the
  live actor closes and receipt recovery requires stopped `SelectedControlAdmin`
  after teardown. There is no cross-process control-admin IPC.
- Authenticated control predecessor/rollback poison purges its pending
  descendants and records a durable rejected-sequence fence. Descendants cannot
  activate past that fence until a valid alternate fills the rejected
  sequence. An idempotent administrative retry is labeled local only when the
  historical effect and persisted local signer match exactly.
- Decode bounds precede allocation. Malformed input cannot panic the safe core.
- Adapter endpoint handles are routing-only local hints; only the authenticated
  session NodeID may authorize peer state, grants, inventory, or DATA.
- Local discovery requires a fresh receiver challenge cryptographically bound to
  the announcement and response role, then locally matched to the apparent
  source socket, before an address becomes a candidate. All discovery packets
  are strict, zero-padded 64-byte records, so a response does not amplify the
  request by payload or ordinary IP/UDP wire size. Discovery does not register a
  DATA route or authenticate a peer.
- UDP DATA from an unregistered source socket is dropped before route
  construction or core delivery. One receive poll processes at most 64
  datagrams before yielding, so ignored traffic cannot monopolize one host pump
  call. Manual provisioning or an explicit embedding decision must register a
  discovery/rendezvous candidate first.
- Adapter routes remain untrusted local routing hints after registration. A
  configured or fully authenticated route is exact, including anonymous versus
  routed delivery; a mismatch is discarded before fragment decoding and neither
  rebinds nor tears down the contact. Before an unknown route is authenticated,
  each of at most 16 incomplete transfers retains its own exact route, so
  cross-route fragments cannot assemble together and one incomplete fragment
  cannot globally pin the contact. Partial route and reassembly state idle for
  ten minutes is evicted together. A successfully verified logical handshake
  flight establishes the candidate route used for the next reply; full session
  authentication commits it. Malformed or inconsistent fragments, conflicting
  completed transfer identifiers, route mismatches, and records that fail
  session authentication are discardable carrier input. One runtime pump
  handles at most 64 such failures before yielding. Authorization and peer state
  derive only from the cryptographically authenticated session identity.
- The runtime handshake receive path validates against the current
  cryptographic state without consuming that state until the flight succeeds. A
  forged or malformed ServerHello, ClientAuth, or ServerFinished is discarded
  while the exact prior state and its bounded retained outbound flight remain
  available for retransmission. `MeshService` retains one zeroizing in-process
  canonical bundle copy for backend rebuilds; the runtime creates no additional
  serialized or persistent recovery copy. Failures after record
  authentication--including wire, synchronization, backend, and internal
  contract errors--remain fatal to the containing contact rather than being
  hidden as carrier noise.
- A Blob source signature binds BlobID, chunk count, and route Merkle root.
  Route-only relays accept `ASTRBT01` carriers only after ciphertext hash,
  source-envelope association, and bounded Merkle-proof verification; readers
  additionally require the protected manifest record and content AEAD. The
  high-level and FFI deduplication/read path re-inspects the sealed source
  envelope and rejects a mismatched route root or chunk count even when BlobID
  and manifest bytes match.
- Unauthenticated partial state is peer-neutral but has per-object and global
  byte/count/extent limits in an isolated staging partition.
- Plaintext payload is not written to the protocol store; blobs stream.
- Secrets use best-effort memory zeroization and platform key-destruction hooks.
  Provider-neutral SecretStore helpers bind exact install/load/destroy operation
  receipts and opaque references, but no production backend, recovery policy,
  coordinated drain/destroy path, or physical-erasure assurance follows from
  that contract.

## Key access matrix

| Role | Session | Routing | Content | Publish | Bridge | Authority |
|---|---:|---:|---:|---:|---:|---:|
| consumer | yes | joined scopes | granted groups | optional | no | no |
| Aster Event relay | yes | carried scopes | no by default | no | no | no |
| bridge | yes | authorized edge endpoints | no by default | no source authorship | explicit directed edges | no |
| publisher | yes | origin scopes | required groups | explicit | no | no |
| authority | policy | policy | fresh recipient packages or legacy activation | control records | grants | yes |

Holding one scope or content seed cannot derive another. Parent/child scope names
do not imply key access.

## Authority custody and control continuity

The authority-root signing key remains in the provisioning helper and signs
credentials and the administrative recipient registry. It is not copied into
`ASTRPB03` bundles. Each fielded ControlAuthority receives a unique node identity
seed and a root-signed credential carrying the ControlAuthority role. Ordinary
and scope-epoch controls embed that credential and are signed by the delegated
identity over `ASTRCA02` format-2 bytes. Bridge authorization format `2` uses the
parallel `ASTRBCA2` delegated authentication wrapper. Capturing one authority
node therefore permits forgery as that delegated signer until its revocation is
applied, but it does not reveal the root signing key or the private keys of other
delegated signers.

Both ordinary and bridge stores persist the authenticated signer. Ordinary
controls share one chain head keyed by stable `authority_id`; bridge
authorizations use their own semantic-v2/v3/v4/v5/v6 chain, also keyed by that stable root
identifier. Neither creates a per-signer history. A signer revoked in the
contiguous applied prefix cannot contribute another link. If activation reaches
a staged link signed by an identity revoked earlier in that prefix, the
implementation rejects and removes that link and its entire unapplied dependent
suffix; a live signer must recreate the suffix from the last applied head.
Bridge authorization liveness additionally requires current-process
reauthentication, the applied enabled generation high-water, and no revocation
of the authority root identifier, delegated signer, or bridge identity.

Revocation of the stable `authority_id` is intentionally terminal. The
authority-revocation record itself may apply as the final contiguous ordinary
link while the authority is still live. In that same transaction, every
ordinary and bridge chain is purged from its earliest unapplied row belonging to
that authority, and affected active bridge routes and queued route work are
removed. Subsequent publish reservation, ordinary admission/activation, and
bridge admission/activation reject when either the stable authority or the
delegated signer is revoked. There is no root override, sequence reset, or
in-band recovery after stable-authority revocation in this version.

These chains are single-writer authenticated logs, not consensus. Safe rotation
requires external coordination: provision the replacement signer, give it the
trusted exact current sequence/envelope head, stop the former writer, and append
the handoff/revocation without a concurrent claim. A second valid signer can
recover after loss or compromise only if it knows that exact head. Concurrent
valid signers can create a fork at the same sequence, which fails closed. The
offline root has no implemented in-band override. Total history loss, deliberate
fork replacement, or recovery without a trusted head requires a separately
specified root-signed control epoch and an externally retained chain high-water;
those mechanisms and an operator recovery workflow remain production gates.

Schema 11 adds signer attribution. Migration from schema 10 succeeds only when
both legacy control tables are empty. If either contains rows, open fails closed
with an explicit migration-required error pending a signed cutover/import design
or a fresh store; the implementation will not infer a signer for old controls.

## Revocation meaning

A root-credentialed, delegated-hybrid-signed monotonic control record propagates
through normal durable sync at FLASH priority. After contiguous application, an
honest node rejects the identity. ScopeEpoch
format `1` distributes a fresh route key and fresh topic keys only to one through
128 named recipients. Each recipient package combines a fresh P-256 ECDH share
and ML-KEM-768 encapsulation, binds the full control-chain and package-set
context, and conceals a random per-recipient salt used by the visible topic-grant
commitment. A recipient installs only its matching authenticated package; an
omitted or locally revoked node removes any pre-placed key for that scope/epoch
and installs nothing. Package authentication and decapsulation complete before
that mutation, and only a durably applied control activates. The signed
recipient set also authorizes routing for the new epoch. Route-only recipients
receive no content keys. Exact bytes and bounds are in
[envelope.md](envelope.md) §6.

The signed public recipient registry is an administrative artifact, not a mesh
object. An authority restart preserves append-only behavior after importing it,
but rollback detection after complete authority-store replacement additionally
requires an operator-held registry-generation high-water mark. High-level
application and language-binding rekey calls exist, but public-registry import/
management does not yet constitute a full administration workflow. Legacy
ScopeEpoch format `0` still activates a pre-provisioned key and
does not provide capture exclusion. Disconnected nodes cannot enforce a
revocation they have not received, and no rekey can erase an old captured key or
plaintext. A captured holder of the old common control-route key can observe
format-1 package metadata, recipient identifiers, and sizes. Salted grant
commitments prevent that omitted holder from testing topic dictionaries, and
the hybrid recipient package withholds the fresh epoch keys.

## Causal evidence and bounded state

Schema 12 scopes publication frontiers to exact `(topic, origin scope)` domains.
Only an accepted item's own dot advances the local frontier; its signed
predecessor vector is not imported as local observation. This is a deliberate
trust boundary: source authentication identifies the publisher of a causal
claim but cannot prove that the publisher truthfully or completely observed the
claimed predecessors.

Each domain loads the pointwise maximum of its exact rows and the reserved
SQLite-only legacy sentinel `('', '')`. Empty topic and scope names are invalid
on the protocol, so admitted data cannot occupy that sentinel. Schema-11
node-global observations migrate verbatim into the sentinel, which is then
read-only under normal acceptance. The exact-plus-sentinel union is capped at
4,096 distinct publishers per domain, and a new publisher at the boundary fails
the same transaction that would accept the item. The aggregate number of
domains and frontier rows is not bounded.

This bounds cross-scope pollution but does not establish transitive causality.
For example, after A publishes `A1`, B observes it and publishes `B1`, and C
receives only `B1`, C's next publication includes B's directly observed dot but
not A's dot. Later `A1` can appear concurrent with C's item. The node-global
accepted-dot ledger and the publisher/topic/scope Event-sequence ledger still
survive normal garbage collection, are outside item quota, and have no aggregate
bound or pruning protocol. Per-key or per-stream domains, transitive propagation
with safe trust semantics, and bounded authenticated retirement/checkpointing
remain production security and availability gates. No minimum-context clamp is
claimed or implemented.

### Selected semantic-v4 mutable availability and lineage

State and Record reconciliation is enabled only after the hybrid mission
session selects semantic version 4, 5, or 6. The v1-v3 Event compatibility paths do not
accept, act on, or expose mutable interests, inventory, IDs, objects, results,
or finish counts. Within v4/v5/v6, State and Record and both receiver directions are distinct
authenticated lanes. Cross-class/direction substitution, result/ack mismatch,
and finish-remainder mismatch fail the contact.

The selected node rechecks mission, source, route/content authority, revocation,
scope epoch, interest, exact identity, and current source route lineage under
one contact policy lease. Same-epoch key replacement does not delete historical
rows. It withholds the replaced lineage from ordinary current projection/query
and from network inventory or transfer. Exact idempotent State publish and
Record publish/resolution retries may recover their committed historical result
only after strict cached/projection/historical verification; this exception is
not general read or forwarding authority.

Authenticated capacity saturation is explicit. State and Record each admit no
more than 4,096 rows or 16 MiB of encoded source bytes, and no object exceeds
1 MiB. `DeferredCapacity` applies only to an otherwise-valid authenticated
object blocked by effective ordinary-aggregate or per-class item/byte capacity,
the 1,024-version per-logical-key projection bound, or the causal-frontier
bound; existing mutable data is not evicted. An object over 1 MiB is
structurally invalid and fatal, not deferred. Integrity, policy, lineage, and
other structural errors remain fatal and cannot be disguised as capacity.
Offer returns exact `MutableApplyResult`; Fetch returns exact
`MutableFetchResult` and requires exact `MutableFetchResultAck`;
Finish/Finished bind exact remaining.

The durable fair-start cursor is reserved metadata keyed by authenticated
mission peer, class, and local Offer/Fetch mode. It is compare-and-set only
after the exact authenticated outcome, bounded to 256 configured peers and
1,024 rows, and pruned for stale configured peers before sockets open. A stale
cursor race is nonfatal, but it cannot overwrite the winner. These bounds
contain metadata growth and prevent a fixed lexicographic prefix from starving
later IDs across repeated partial contacts; they are not evidence of physical
resource sufficiency or adversarial-link liveness.

Normal and `AtLeast` run the v4/v5/v6 State/Record lanes because `AtLeast` is an Event-only
threshold. `ReceiveOnly` initiates no contact and discloses no mutable interest,
inventory, ID, or object. Event last-contact status is deliberately separate
and is not evidence that State/Record converged. Selected State/Record finite
TTL is structurally rejected; no mutable forwarding-age/expiry security claim
is made.

### Selected semantic-v5 Blob authorization, staging, and visibility

Selected Blob transfer is enabled only after the completed hybrid mission
session selects semantic version 5 or 6. Versions 1 through 4 emit and accept
zero selected Blob frames. V5 inherits all earlier Event and State/Record
security rules, and v6 inherits that complete ordinary-lane behavior unchanged,
without changing stable wire/profile, envelope, carrier, or ABI version 1.

The selected network path is direct between content-capable peers. A protected
exact `(topic, scope, epoch)` interest includes an opaque 32-byte
`BlobPeerContentProof` minted from the claimant's current content grant and
bound to mission authority and authenticated NodeID. The sender requires both
that proof and the peer's current exact route grant; route authority never
implies content authority. It also rechecks durable revocation and control
policy. Copying a proof to another identity, changing topic/scope/epoch or
authority, tampering with it, or replacing the content key at the same epoch
invalidates it. The proof is repeated and rechecked on every range fetch. This
does not select the broader route-only Blob relay design.

Two independent lineage bindings close same-epoch substitution. Source route
lineage binds the current authenticated routing grant. A domain-separated
physical lineage binds the exact current content grant plus mission,
scope/topic, and epoch. Pending source installation, carrier service, content
verification, and publication promotion require the exact lineages committed
by the plan; a provider-minted `CurrentBlobLineage` proves that both are still
current at promotion. Historical same-epoch rows may remain durable for audit
or exact local retry, but are not advertised, served, or promoted as current
network publications. Redb does not transparently replace them: a new physical
lineage for the same `(BlobID, content group, numeric epoch)` fails with
`PhysicalLineageConflict`. Republishing or resuming that Blob after same-epoch
key replacement under a different physical lineage requires advancing the
numeric epoch. Terminal or stale cleanup does not erase this witness. It retires
pending source and prefix visibility while retaining the exact depot import,
expected or committed chunk rows, any chunk files and finalized digest, and
their reserved/committed accounting. That bounded non-public staging remains
owner/backing-bound, audited on every open path, and charged to the existing
byte, chunk, and variant caps. Exact-lineage retry may resume it; a missing
physical lineage is corruption, and another lineage at the same numeric epoch
still conflicts.

The source envelope and complete manifest plan are authenticated and staged
before any carrier range is requested. Prefix progress is durable under the
exact `(source transfer ID, carrier ObjectID)` and is not owned by a peer or
session, so any later authenticated, nonrevoked content-capable peer proving the
same current selector may continue the exact complement. A range is at most 16
KiB. Network admission is capped at 64 MiB plaintext and 1,024 chunks; pending
metadata and prefixes are capped at 10,000 rows and 64 MiB. Capacity failure is
typed deferral and does not evict accepted data or overwrite existing progress.
Conflicting prefixes and identity, proof, manifest, lineage, AEAD, digest, and
whole-Blob failures fail closed for the affected exact work.

Terminal poison of a multi-carrier source advances the durable peer scheduler
to the lexicographically greatest canonical carrier ID across that source. It
MUST NOT use manifest-last as a proxy for the greatest ID, because that can
strand a later eligible source behind adversarial manifest order.

The authenticated source cache and durable pending-source lifecycle are one
serialized security boundary. Staging, sender-cache repair, terminal or stale
abort, and post-abort reconciliation use the same local lifecycle lock without
holding it over network I/O. Reconciliation removes the retired claim, rereads
the exact durable projection, and freshly authenticates any concurrent exact
restage before reinsertion. This prevents a delayed cache write from reviving an
aborted source or an abort from deleting the winner's authenticated claim.

BlobCarrierFinish reports the requester's remaining count and Finished only
echoes it. That pair closes sequencing; it is not independent evidence of the
requester's disk state. Exact BlobRangeResult/BlobRangeResultAck tuples are the
peer-visible evidence for each accepted durable prefix.

Pending bytes confer no publication authority. Promotion requires the exact
pending plan, all verified canonical carriers, a matching physical depot
completion, a fresh provider-owned `VerifiedBlobContentCompletion` obtained by
streaming/decrypting/authenticating every chunk and whole Blob, and the fresh
current-lineage proof. Redb compares those bindings and installs all ordinary
publication/index/counter rows while deleting pending rows in one transaction.
Until that transaction commits, the Blob is absent from ordinary inventory,
query, read, and serving surfaces. An interrupted or failed verification cannot
publish a prefix or a merely carrier-complete object.

All redb open modes cross-audit the pending source, its exact manifest route and
carrier set, the depot expected plan, and the completed publication namespace.
A self-consistent missing depot plan, changed canonical carrier record, or one
source present as both pending and completed is corruption and fails without
repair. Writable predecessor migration is likewise all-or-none: the four v5
network tables may be added to the prior nine-table Blob schema only when the
group is wholly absent and owner attribution is valid; read-only and partial-
group opens never create or repair tables.

The application boundary uses the same authority rather than a second Blob
store. `RunningNode::selected_blobs()` returns a cloneable handle whose publish
operation accepts ownership only of a nonempty regular file positioned at byte
zero and caps it at 64 MiB/1,024 fixed 64-KiB chunks. The source length is
checked across both bounded passes so a concurrent change cannot silently
change the authenticated intent. A read returns one freshly authenticated
`1..=64 KiB` plaintext page in a zeroize-on-drop allocation and rechecks policy,
source selection, current lineage, and the exact depot completion capability
around decryption. The shared application lane is capped at 32 commands and a
single joined Blob worker accepts at most one queued Blob command; saturation
is explicit and shutdown/zeroization joins ownership rather than detaching key-
bearing work. A blocking syscall in a hostile regular-file provider can still
delay that join, so no fixed teardown-latency claim is made.

Blob application delivery is a separate durable metadata ledger, not a second
content path. A selector is mission-local intent and cannot add network
interest, route authority, content authority, or a depot capability. Poll
rebinds every candidate to its startup-authenticated projection and current
policy, then exact-loads and rechecks each deliverable source envelope and
completed depot before committing an attempt, but returns no plaintext,
manifest, sealed envelope, key, nonce, chunk, carrier state, or path. Delivery
identity is the source-authenticated semantic publication ID rather than
`BlobId`, so distinct publishers/counters/priorities sharing immutable content
cannot consume one another's work. Opaque acknowledgement tokens bind the
subscription incarnation, publication, tenure, and attempt; durable cursors
prevent removed/recreated-selector ABA. An earlier issued nonzero attempt at or
below the durable high-water remains valid within the same pending publication
tenure for crash-safe acknowledgement; wrong-tenure, wrong-incarnation,
cross-binding, malformed, and future/unissued tokens fail closed. Ledger counts
are bounded and structurally audited.

Ordinary application failures are sanitized. A durable row/cache mismatch,
invalid authenticated depot capability, page-integrity failure, or post-commit
verification contradiction is `FatalBlobCoherence`: the worker closes shared
admission and terminates the actor rather than serving through divergent
authorities. This is a local fail-closed mechanism, not retained network or
release acceptance.

Normal and `AtLeast` run this lane because `AtLeast` is Event-only;
`ReceiveOnly` sends, requests, stages, promotes, and counts zero Blob work.
The local delivery-ledger counts are not Blob peer, contact, transfer-progress,
or convergence status. A
[retained 10,269-byte Blob-delivery receipt](validation/evidence/selected-live-blob-subscription-26e0a09.json)
(SHA-256
`3d0c0b2da629282c56de5ae9dacc8920c9960defba083c6bff856e2c0612a675`,
Good-signed source `26e0a09`) observes one peerless participant across three
processes and four actor lifetimes. After a flushed unacknowledged attempt-one
poll, the child receives `SIGKILL`; a fresh process receives attempt 2 and
acknowledges it with the persisted attempt-one token, rejects a token bound to
the other exact publication sharing the same `BlobId`, settles both, and leaves
the final reopened ledger empty. This adds no network, peer-status,
selector-withholding, or network-interest-separation claim. Route-only Blob
relay or custody, Blob TTL/expiry/garbage collection,
metadata-independent whole-byte identity/deduplication, or retained large-file,
power-loss/filesystem-crash, physical, mixed-implementation, resource/soak,
and release-acceptance claims remain open.

### Selected semantic-v6 Event-bridge isolation

Semantic v6 inherits all v5 ordinary-lane security behavior unchanged and adds
only the selected Event-bridge mechanics lane. A v1-v5 peer negotiates its
highest common older version and receives no bridge frame. At v6, every
endpoint exchanges only a protected canonical enabled bit first; route state is
exchanged only when both mission-authenticated endpoints have explicitly
enabled the static bridge role.

Every offer carries exact source-envelope and bridge-route-wrapper bytes inside
the existing replay-checked `ASTRFR01` channel. The receiver recomputes the
claimed wrapper digest, freshly authenticates the source, complete delegated
authorization chain, wrapper hop chain, current scope/epoch policy, and local
topic/priority selection before committing a route. Authentication, integrity,
stale-policy, and identity failures fail the contact. `NotSelected` is the sole
nonfatal policy miss and commits no route; other successful dispositions report
the receiver's durable active, alternate, or duplicate result without exposing
its broader inventory.

The forwarding path materializes and transmits only sealed source/wrapper bytes
and does not open payload plaintext. A content-authorized target may open a
freshly verified route only after its durable commit; the selected receipt logs
only payload length and SHA-256 and never the payload bytes. The current static
composition fails closed when its captured control-policy snapshot changes.
Dynamic join/leave administration, automatic authorization replacement,
finite-TTL bridge age, generalized bridge quotas/scale, physical-network
capture evidence, independent interoperability, and production authorization
remain outside this version statement.

## Availability controls

Inventory roots are constant size and exact tree descent is bounded. Control
records, current epochs, and retained tombstone fences have reserved quota.
Priority does not bypass authentication or bounds. An INTEREST is rejected
before backend work if it exceeds 256 topics, 256 scopes, or 4,096
topic-by-scope combinations. An admitted filter causes one metadata-only
inventory query, not a Cartesian series of store queries, and does not
materialize sealed payload or causal/application fields into the Rust
projection. The policy-filtered source snapshot has a 100,000-object ceiling.
SQLite stops at cap plus one and rejects the selection if that row exists; the
generic node facade also rejects an over-limit result from a custom store. Equal
Merkle roots prevent further wire descent but do not avoid this local selection
and hashing step, so local reconciliation work is snapshot-size proportional,
not difference proportional.

For a selected root containing no more than both peers' OFFER limits (256 by
default), the sender can return the complete canonical identifier set. The
receiver requires the current expected root probe, exact advertised count, and
a reconstructed Merkle root equal to the authenticated `SUMMARY` before it
creates wants or retires traversal state. A bounded history recognizes exact
delayed authenticated responses as no-ops; malformed or mismatched responses do
not retire the probe retry. This removes deep wire traversal for small
snapshots, not the O(k) identifier validation or O(N) local snapshot build.
Larger snapshots retain the 66-level exact tree path.

Discovery holds at most 128 recent local announcements, 256 pending challenges,
and 1,024 emitted-response records; each class is pruned at 30 seconds before
lookup or reuse. Pending records use `(exact source socket, announcement)` and
retain a fresh challenge; only a matching response from that socket consumes the
record. Emitted responses use `(exact source socket, announcement, challenge)`.
A replay from another socket therefore cannot collide with or directly consume
the legitimate socket's exact record. Pending and emitted-response admission is
additionally limited to 8 and 32 records, respectively, per canonical source
IP; IPv4 and its IPv4-mapped IPv6 form share one quota. This contains
source-port churn while preserving the global 256/1,024 bounds, but distributed
replay can fill those shared caches and delay legitimate discovery until the
30-second expiry; large shared-NAT populations also contend for the same
per-source limits. It blocks passive replay redirection but not an active,
bidirectional live relay of the challenge and response; only the subsequent
hybrid handshake authenticates the peer.

Advertisement, challenge, and response packets are all strict, zero-padded
64-byte records, so reflected discovery traffic does not exceed the inducing
packet by payload size or ordinary IPv4/IPv6 UDP wire size. Equal sizing does not
prove source ownership. A captured valid announcement—or an announcement made
by a discovery-token holder—with a spoofed source can still consume that
apparent victim's bounded per-source pending quota and the global quota. Public
or hostile-link deployments require source anti-spoofing and ingress rate
controls.

Rendezvous rejects a zero pairing token. Client attempts are bounded at 128,
expire after 120 seconds, and bind the expected server per token. A server peer
response is consumed once; only its selected endpoint may then present the
corresponding punch, except for an endpoint explicitly authorized with
`accept_punch`. Failed registration sends restore prior client state. The server
examines at most 64 datagrams per poll, retains at most 4,096 waiting tokens and
64 per canonical source IP, and maintains those source counts incrementally.
The absolute 120-second waiting lifetime cannot be refreshed by duplicate
registration. Registration is a strict 160-byte packet with 127 zero padding
bytes; the prior 33- and 64-byte forms fail closed. Under a conservative
48-byte IPv6 UDP/IP-header model, the 208-byte registration wire cost exceeds
the largest 181-byte reflected response-plus-punch chain: a 52-byte IPv6 peer
response and 33-byte punch, each with a 48-byte header.

Before sending either reply, the server atomically reserves their exact
combined payload size from one global 4,096-byte bucket refilling at 1,024 bytes
per second and from a 1,024-byte bucket refilling at 256 bytes per second for
each distinct canonical source IP. Endpoints sharing one canonical IP charge
that source once; different sources each pay the full pair. Source-budget state
is capped at 4,096 entries and expires after 120 idle seconds. Missing state is
created only after every required bucket can pay. A denied reservation spends
nothing; a send failure conservatively spends the reservation but preserves
waiting and source-count invariants for retry. These controls bound state,
per-poll work, repeated completed-pair egress, and one canonical source's share
without byte amplification. Shared-NAT clients share a budget. Rotating spoofed
source IPs can still fill the finite source-budget table, and these controls do
not prove a UDP source address was not spoofed; public exposure still requires
deployment anti-spoofing and rate controls. The visible high-entropy token
remains a capability, not peer authentication.

The TCP ciphertext relay defaults to 256 active pairs, 64 accepted sockets per
source IP across validation/waiting/active states, and a 120-second active-pair
idle timeout reset by actual I/O. Client queues are independently bounded in
both directions at 256 frames and 4 MiB. `send` only performs nonblocking local
queue admission; saturation returns `WouldBlock`, while asynchronous write
failure closes the link and makes later sends fail. One pair whose endpoints
share a public NAT normally consumes two source admissions. Operators can raise
that limit for large shared NATs, trading away some per-source denial-of-service
containment while retaining the global active-pair bound. Inbound clients must
complete a four-byte frame header within 120 seconds. A body gets 30 seconds
plus its encoded length at 1,024 bits per second, or 542 seconds for the maximum
65,535-byte frame; expiry closes the link and releases its bounded queue state.
Zero or monotonic-clock-unrepresentable active-pair idle durations fail
configuration, and runtime deadline construction is checked.

These relay bounds are containment, not complete slow-client resistance. Any
successful byte transfer resets the active idle timer, so coordinated sources
can retain the finite global slots by sending periodic traffic; a healthy pair
that is completely quiet for the configured interval is also disconnected and
must be re-established by its embedding. Deployment-layer source controls and
reconnection policy remain release gates.

A stateless pre-response cookie format is not implemented, so amplification
resistance for the large PQ response remains a deployment/release gate.
Discovery and rendezvous rate limits
belong to their carrier profiles and are not provided by the fixed handshake.
The mission proof prevents a party without mission material from creating a new
accepted flight 1, but a captured valid flight 1 remains replayable and can
trigger a fresh bounded response. On an unknown responder it can also pin that
session's candidate adapter route even though flight 1 does not establish the
initiator's full peer identity; rate limiting and contact replacement are still
required.

The reference gives unauthenticated staging a nominal 25% partition of
`max_bytes`, capped at 64 MiB, and reserves the remainder for committed records.
It admits at most 4 MiB per staged object, `min(max_items, 10,000)` staged
objects, 4,095 extents per object, and 65,536 extents globally. Staging
exhaustion rejects the new extent without evicting either prior staging or a
committed item. Thus an authenticated or unauthenticated sender can deny its own
new partial admission but cannot use staged bytes to force committed-data
priority eviction.

Terminal full-object length, identity, source-authentication, ciphertext, route,
or policy failure atomically purges only the offending typed ObjectID and resets
its WANT to unknown length/no ranges. Transient Store, I/O, and missing-chunk
failures retain progress. This distinction prevents a malicious first peer from
persistently poisoning a later honest peer's same-object recovery without using
transient local failures as a staging-erasure oracle.

The runtime retains a failed backend range for another attempt and implements a
bounded monotonic retransmission loop with priority deadlines, causal retirement,
and adapter retry floors. The Rust application host owns and pumps configured
link instances and wakes the runtime on local inventory change. Current tests
use controlled in-memory links; they do not establish general congestion-control
behavior, permanent-loss progress, a concrete BTLE controller, or a physical
live-carrier path.

Flight 1 proves possession of a shared mission proof key anonymously; it is not
a per-credential revocation check. A captured or revoked node that retains that
key can create fresh flight-1 ephemerals, derive the hybrid secret, and decrypt
the responder identity in flight 2. Its own revoked credential is rejected after
encrypted flight 3/backend authorization, and no DATA is accepted. Rejecting a
revoked client before revealing protected flight 2 would require a
per-credential protected flight-1 identifier/proof or rotation of the shared
mission proof key. This residual authorized-member exposure is distinct from the
solved passive-observer credential leak.

## Mesh cryptographic provider status

The reference provider uses `aes-gcm`, `hkdf`, `sha2`, `p256`, `ml-kem`, and
`ml-dsa` at the exact registered versions. This proves neither independent audit
nor FIPS 140-3 validation. The public API cannot select primitives; an internal
provider boundary allows a CMVP-backed module.

Production use of suite `0x0001` is blocked until deployment assurance
identifies a current CMVP certificate, exact module/version/operational
environment and approved mode, coverage for all suite operations, self-tests,
and an independently reviewed hybrid combiner. Every future production profile
has its own applicable module and review gate; a hybrid-PQ module gate does not
apply to a profile that excludes PQ.

## Security test gates

Listing a production gate is not evidence that it has passed. Independent NIST
algorithm-vector validation remains required; the checked-in, reference-generated
protocol conformance vectors do not satisfy that gate.

The retained selected N=32 Event run is likewise a scale-boundary observation,
not broader security acceptance. It used one macOS arm64 host, direct loopback,
one binary/implementation, one scope/authority/topic, and unprotected-reference
provisioning. Its raw root contains mission bundles and carrier identity keys
and must remain outside source control; the checked-in receipt contains only a
bounded sanitized manifest. The run adds no physical, distributed, NAT,
controlled-relay, BTLE/cross-transport, packet-capture, mixed-implementation,
resource-threshold, cryptographic-module, or release claim.

- Bit-level tamper of every envelope/handshake field.
- signature stripping and classical/PQ downgrade attempts.
- stripping the current `[6, 5, 4, 3, 2, 1]` offer to `[5, 4, 3, 2, 1]`,
  `[4, 3, 2, 1]`, `[3, 2, 1]`, `[2, 1]`, or `[1]`,
  and the retained `[2, 1]` compatibility offer to `[1]`; the initiator must reject even though
  membership checks alone would accept the selected lower version.
- malformed public keys/ciphertexts and implicit-rejection behavior.
- nonce uniqueness across concurrency, crash, rollback, and epoch change.
- replay windows and old control/key epochs.
- packet-capture canary scan for payload and routing fields.
- relay/bridge negative decryption tests.
- The repository ships `wire_decode`, `fragment_decode`, and
  `envelope_inspect` fuzz targets plus allocation-limit tests; an FFI fuzz target
  remains a production gate.
- Aster-owned zeroization hook invocation and post-zeroize handle rejection;
  this does not assert clearing of upstream age internals.
- age-provider ordinary/binary/maximum-size and real-bundle round trips;
  one-to-sixteen recipient/identity bounds, duplicate rejection, sanitized
  configuration errors, redacted secret debug output, and multi-recipient
  recovery; incoming no-X25519, over-16-X25519, scrypt, and multiple-extension
  stanza-set rejection before identity unwrap while accepting standard GREASE;
  wrong-identity, malformed-header,
  stanza/header-MAC/body/final-byte, truncation, and trailing-data rejection;
  bounded output and recovered
  plaintext; randomized ciphertext; and failure without partial plaintext
  release.
- bidirectional outer-file interoperability with exact reference Go age v1.3.1;
  this checks only the classic X25519 age file profile.
- dependency-policy confirmation that the sole ignored advisory is the
  pilot-scoped informational `RUSTSEC-2026-0173`, with no additional advisory
  or vulnerability exception.

The semantic-version tamper gate proves only on-path transcript downgrade
resistance. Client offers are mission-proof bound; honest responder selections
are transcript/KDF/confirmation/authentication bound. The handshake has no
authenticated responder capability ceiling, authority-signed mission minimum,
or durable per-identity semantic high-water. Consequently, a valid older or
modified responder can authenticate semantic `1`. Downgrade-sensitive
production authorization MUST fail closed until the signed floor, high-water,
explicit rollback authorization, and independently authored mixed-version
validation exist.

Packet-capture success means protected payload, topic, scope, priority, and
publisher credential canaries are absent from Aster carrier bytes. It does not
claim resistance to correlation by link/network identifiers established before
the first Aster flight—including IP addresses and a rendezvous pairing token
visible to the rendezvous service—nor does it hide timing, direction, sizes, RF
energy, or protocol presence. Local discovery sends a fresh nonce and truncated
HKDF proof, never the provisioned discovery token itself. Its subsequent
challenge and response are also truncated token-derived proofs; they establish
live reachability at the apparent socket, not identity or resistance to an
active real-time relay.

The reference now has a passing runtime capture subtest that reassembles all
four tiny-MTU handshake flights and verifies that neither peer's mission,
credential, credential body, NodeID, nor route-grant commitments occur in the
clear. This satisfies the handshake portion of the capture gate, not the broader
physical-carrier traffic-analysis boundary.

The canonical batch codec, provider authentication, and explicit atomic
source/store/application path reduce the transferred verification closure for a
semantic-version-2/3/v4/v5/v6 batch. The default retained-dual policy preserves v1
compatibility at extra signing/storage cost; explicit batch-only cannot reach a
selected-v1 peer. Reference peer proof-first, compact-first pending/restart,
v1-rejection, and Blob-carrier tests pass; the required 3 kbps end-to-end
measurement, physical-carrier validation, and an independent SUT remain open.
Recipient-excluding rekey is implemented in the core fixed profile, with the
external registry high-water and missing administration workflow limitations
above. Typed Blob-carrier relay and different-peer ranged resume are verified in
the in-memory reference runtime, while a separate 101 MiB local streaming case
passes with bounded component buffers. A combined 100+ MiB different-peer run
with measured process RSS and physical live-carrier validation remains open. See
[envelope.md](envelope.md) §§5.4, 6, and 10.

Report vulnerabilities through the private process in `.github/SECURITY.md`.
Do not include mission data or credentials in a public issue.
