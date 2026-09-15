# Zenoh Arm D: durable edge fabric plus protected-object overlay

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.


## Result

Zenoh 1.10.0 plus its 1.10.0 RocksDB backend is a credible FOSS buy for
transport routing, pub/sub/query, durable latest-value storage, and
later-contact anti-entropy. It is not a replicated mission-data model. The
minimal encrypted-object overlay proved relay payload blindness in a bounded
test, but the requirements-critical causality, conflict, data-class, policy,
membership, and transfer-progress semantics remain outside Zenoh.

The BVB-853 immutable-key sibling-overlay run closes the remaining Arm D
disproof spike. It preserved both encrypted concurrent siblings, but only
because a task-authored layer moved identity, key layout, conflict semantics,
and application-effect policy outside Zenoh. Arm D therefore stops as a whole
replica composition under Proposal 0005's dominance early exit. Zenoh remains
a conditional component buy for routing, replication, query/pub-sub, and
RocksDB-backed storage when those mechanisms delete enough work to justify its
footprint and duplicate ownership.

## Exact freeze

| Surface | Freeze |
|---|---|
| Zenoh | tag 1.10.0, commit `c479f0c1102d7321c2fa83f515bddede92014cce`, archive SHA-256 `84f49e5702eed7897597aad9869116df88e405c24054481be801040db25d59f3` (BVB-704) |
| Zenoh graph | lock SHA-256 `0542e2e8a1ac7e7dccc0cfe62166adf0121cb01e64130be2733aba31982a2d55`, 559 packages, zero git (BVB-708) |
| RocksDB backend | tag 1.10.0, commit `8dbaadf1e2a1c9a0b76c6038a2250bb9024a299f`, archive SHA-256 `805cb694f117e8b29468bdb7b8e6b67f363029a943d468a7734b0fd0938a7b07` (BVB-706) |
| Backend graph | lock SHA-256 `1682e7c01d6c65c6bb32ec2c73468a50e0a406d33dda22659bb3d50b11ac2e09`, 429 packages, zero git (BVB-707) |
| Licenses | upstream projects declare EPL-2.0 OR Apache-2.0; transitive admission remains pending |

The separately built backend initially failed daemon plugin compatibility.
Building it with `zenoh_backend_traits` default features disabled aligned the
backend with the selected host feature set. This is a one-line evaluator-only
manifest patch, preserved in
`backend-build-compatibility.patch` (archived); it is not a
claim that the unmodified release combination works in this build shape.

## Executed evidence

### Durable local restart

Run `arm-d-restart-003` published a value to an infrastructure-free local
daemon, terminated it, restarted the same RocksDB store, and queried the exact
value. This is bounded evidence for offline-first local durability and restart
recovery, not multi-node convergence.

### Partition, full restart, and later first contact

Run `arm-d-partition-restart-003` started durable A and B stores without a
connection, published only at A, and verified B did not expose the item. Both
daemons stopped and restarted from the same stores. B then initiated the first
contact with A. After reconciliation A stopped; B alone returned the exact
item. This locally demonstrates latest-value later-contact reconciliation and
infrastructure-free direct operation.

The backend emitted: `no data_info in database, however payload data exists`
and described the state as possibly legacy/dirty and unsupported for
replication. The observed value still arrived, but that warning is a production
hold and receives no reliability credit.

### Protected carrier-neutral object

Run `arm-d-protected-object-002` repeated the partition/restart/contact topology
with the exact 471-byte `arm-a-protected-object-v1` fixture. The retrieved bytes
and source fixture both hash to
`bbeb061ba784f6c481420e59603b06b807d60e93ab2c493f6568f3136e3265ac`.
An authorized endpoint verified the inner Ed25519 source signature and
XChaCha20-Poly1305 protection; a no-key endpoint verified the signature but
rejected decryption. Scans of B's RocksDB and daemon logs found neither the
plaintext marker nor the fixture content-key marker.

This establishes the composition seam and bounded DM-6-04 through DM-6-07
behavior for a classical fixture only. It grants no NIST, hybrid-PQ, FIPS,
membership, replay, metadata-protection, zeroization, or production-security
credit. The Zenoh key expression remained plaintext, so protected forwarding
metadata (DM-6-09 through DM-6-12) is not met by this composition.

### Transient history and concurrent conflict

Run `arm-d-conflict-history-001` published two sequential values to one A key
while A and B were partitioned, and separately published different concurrent
values to the same key at A and B. After both stores restarted and contacted,
each was stopped and restarted alone before it was queried.

- Both stores exposed only the later sequential value. The earlier value was
  not available through the query API.
- Both exposed `zenoh-arm-d-conflict-from-b` as the sole concurrent-value
  winner. `zenoh-arm-d-conflict-from-a` was not exposed, and no conflict
  annotation appeared.
- Raw RocksDB files still contained some prior marker bytes; raw implementation
  bytes are not a supported superseded-version recovery or conflict API.

This is the intended Phase 1 gap quantification: raw Zenoh latest-value
replication does not buy Event history, Record sibling preservation,
application-visible conflict annotation, or policy-governed superseded-version
recovery (DM-5.3-06 through DM-5.3-10). It does not establish whether Zenoh's
winner rule is causality- or wall-clock-correct; DM-5.2-09, DM-5.2-10, and
DM-5.2-14 remain unknown rather than inferred.

### Minimal encrypted durable local-first overlay

Run `arm-d-immutable-overlay-002` (BVB-853) stored the two BVB-825 encrypted
carrier objects under immutable SHA-256-derived version keys at partitioned A
and B stores. Duplicate puts were repeated before both stores stopped,
restarted, contacted, stopped again, and restarted in isolation. Each final
isolated store returned both siblings exactly once. The recovered object hashes
were
`20ed2fc4aee4b44f84daa1bdf37e213a14bd951995a97e05165ae7fff42acc24`
and
`46a279b6bcb1b91ccae973497f96f2e4e51e3e936c7ada232699d67f10dc1831`.
The external conflict annotation recorded `sibling_count=2` and `state=conflict`.
Scans of the durable and log surfaces found none of the frozen plaintext probe
terms.

All 45 entries in the run's `SHA256SUMS` validate; that manifest hashes to
`3d9c407f148dd1648f56a2843ecbbdd5242972c3f31e37a91ff98847554f46c4`.
The conflict annotation hashes to
`ee9c53c419e7b8953b9b0761de7d6907b1d41b770413b17d22c4121197f91658`.

This is a bounded pass for the overlay seam, not native Zenoh conflict credit.
Zenoh owned routing, replication, and RocksDB persistence. The custom layer
owned immutable key construction, object identity, the encrypted carrier
profile, sibling enumeration, conflict annotation, and duplicate/application
effects. It did not demonstrate causal State arbitration, Event gaps, Record
merge policy, tombstone lifecycle, temporal A-B-restart-B-C relay, replay state,
membership/rekey, protected key expressions, or any-peer Blob progress.

## Requirements classification

| Requirement surface | Result | Scope |
|---|---|---|
| DM-5.2-01/02 reachable convergence | partial | one latest-value key, two local daemons, one later contact |
| DM-5.2-03 restart resync | met | immediate local restart only; duration curve unrun |
| DM-5.2-04 durable preservation | partial | current value preserved; overwritten/event history not provided |
| DM-5.2-09/10/14 causality and clock independence | unknown | test observed one winner but not the arbitration basis |
| DM-5.3-06/07/09/10 conflict preservation | bounded overlay pass; not native | immutable keys preserved two siblings; custom enumeration and annotation own the semantics |
| DM-5.6-02 infrastructure-free direct operation | met | loopback/manual peering demonstration |
| DM-5.6-03 temporal multi-hop | unknown | A-to-B later contact is not an A-B, restart, B-C chain |
| DM-6-04/05/06/07 protected object and blind store | met, bounded | classical carrier-neutral fixture and exact scans |
| DM-6-09 through DM-6-12 protected mesh metadata | not met | key expression remained transport-visible |
| DM-12-05 payload-blind temporal relay | partial | opaque durable carry and plaintext-probe absence proved; three-node relay topology unrun |

## Responsibility and residual surface

Zenoh can own live routing, sessions, pub/sub/query, plugin operations, and a
durable latest-value replica. It cannot own the final mission replica contract
without adding a convergent encrypted item layer that supplies:

- the four State/Event/Record/Blob rules, causal ordering, gaps, tombstones,
  conflict siblings/annotations, and policy-controlled history;
- durable partial and any-peer transfer progress;
- priority, TTL, scope, quota, bridge, eviction, and emission semantics;
- source and membership-layer object protection, identity binding, replay,
  revocation/rekey, and zeroization; and
- a BTLE/tiny-MTU/file framing profile and independent conformance surface.

That overlay is not a small codec. It is most of the requirements-specific
replica and security protocol. The executed minimal overlay confirms that Zenoh
does not advance as a whole composition. Retain it only as a conditional
routing/replication/storage component when another selected protocol already
owns the missing semantics and the composition deletes more lifecycle work than
it duplicates.

## No-credit boundaries

No result here proves general temporal multi-hop, duplicate/loop suppression,
any-peer Blob resume, priority/TTL, capture-level metadata privacy, hostile
input behavior, interoperability, resource targets, governance admission, or
production readiness. All raw sources, archives, dependency caches, build
outputs, databases, and logs remain locally preserved and ignored.
