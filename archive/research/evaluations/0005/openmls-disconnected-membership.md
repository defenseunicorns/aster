# OpenMLS 0.8.1 disconnected-membership comparator

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.


- Status: bounded executable pass registered by BVB-735
- Registered source/graph/execution inputs: BVB-712, BVB-726, BVB-727,
  BVB-735
- Exact release: `openmls-v0.8.1` at
  `47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6` (MIT)
- Exact archive SHA-256:
  `29427912c8190c029340194f56178266a04fc76658c03b5ebdad3df23e5d92f0`
- Candidate receipt:
  archived `receipts/execution.md`
- Machine-readable summary:
  archived `results/summary.json`

## Decision result

**BUY a bounded classical MLS membership component; do not buy it as the whole
security or dissemination profile.** The exact locked/offline OpenMLS graph
executed group creation/join, protected application messages, provider-backed
restart, removal and epoch advance, awareness-bounded exclusion, a narrow MLS
message replay rejection, and application-assisted recovery from a
concurrent-commit fork.

This materially reduces custom group-state and epoch-cryptography code. It
does not eliminate the custom composition around signed membership authority,
durable control-object dissemination, scope mapping, hybrid source objects,
outer protected forwarding metadata, general replay/idempotence, key custody,
or recovery policy.

## What executed

The runner used the stable classical
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` ciphersuite and the exact
154-package graph authorized by BVB-726/BVB-727. No Git dependency, network
access, or lockfile mutation occurred.

Three separate process phases exchanged only serialized files and persisted
provider state:

1. A created a group, added B/C, and emitted one protected application
   message. The process exited after persisting each provider.
2. Fresh processes reloaded all providers/groups. B/C decrypted the message.
   A removed B; C and B accepted the removal commit; B became inactive. C
   decrypted a newer-epoch message and B did not.
3. Fresh processes reloaded again. C rejected the exact already-processed MLS
   message, then sent a fresh message that A processed and removed B did not.
   A stale pre-removal B snapshot rejected the future-epoch message, then
   accepted the delayed removal commit and became inactive.

A separate comparator created a real concurrent-commit fork: A and B each
merged their own add-C commit, and C joined A's branch. The confirmation tags
proved A/C and B differed. Application code then identified the A/C partition,
supplied a fresh B key package, invoked `recover_fork_by_readding`, and observed
A/B/C convergence.

## Requirement credit

| Requirement outcome | Bounded evidence | Credit |
|---|---|---|
| Membership and group-key evolution | Add, remove, epoch advance, protected application data | Component credit |
| Exclusion after accepted authorized state | B became inactive after processing the removal commit and rejected newer-epoch traffic | Component credit; authority and control-object authentication policy remain outside the library fixture |
| Restart without live service | Provider/group state loaded across two complete process boundaries; file-only fixture needed no DS/AS process | Library feasibility only; no delivery architecture credit |
| Delayed control | Stale B rejected a future-epoch application, then accepted the delayed removal commit and became inactive | Narrow control-ordering evidence; no long-partition or rollback curve |
| Replay after restart | C rejected one exact already-processed MLS application message after persisted reload | Narrow MLS sender-ratchet credit only |
| Concurrent fork recovery | Explicit partition selection plus fresh key package and re-add helper converged A/B/C | Manual recovery mechanism credit; no automatic detection/convergence |

The throughput, loss, offline-duration, and overhead anchors remain WAG
measurement axes. This run did not vary them and cannot eliminate OpenMLS on
those axes.

## Exact gaps and no-credit boundary

- **No automatic partition convergence.** Application code must learn which
  members are in each partition, select the retained branch, obtain fresh key
  packages, and distribute the resulting commit/Welcome.
- **No delivery or authentication service.** Serialized files were a harness,
  not a durable mesh/DTN implementation. No DS/AS outage integration was run.
- **No complete disconnected revoke/rekey profile.** The run proves effect
  after accepted control, not authority rules, signed membership-object
  ordering, concurrent removals, rollback, rejoin/lost-authority policy, scope
  key mapping, or long-partition retention.
- **Classical only.** The executed stable suite is X25519/Ed25519 with
  AES-128-GCM/SHA-256. It provides no hybrid KEM or mandatory classical+PQ
  signature credit.
- **No FIPS/CMVP credit.** The RustCrypto composition is not an identified
  validated module/OE/service boundary.
- **No custody or zeroization credit.** The fixture memory store persists its
  entire map as base64 values in plaintext JSON. It proves reload mechanics,
  not secure storage, rollback resistance, deletion, or key destruction.
- **No general replay/idempotence credit.** MLS sender-ratchet rejection does
  not define durable item identity, carrier duplicate handling, bounded replay
  retention, compaction, or snapshot rollback behavior.
- **No outer metadata protection.** MLS protected application data does not by
  itself define the relay-visible topic/scope/priority/routing envelope.
- **No production-security credit.** Parser/resource bounds, independent
  interoperability, hostile faulting, audit coverage, and operational
  admission remain open.

## Minimum custom delta and next decisive composition

Treat OpenMLS as one replaceable membership/key-evolution component behind the
already executed nested COSE source object, not as its replacement. The next
decisive experiment should carry serialized MLS commits, Welcomes, key
packages, and protected application objects through the leading temporal
carrier arm with non-overlapping contacts and full relay/endpoint restart.
It should then:

1. bind each control object to the normalized membership authority and
   monotonic no-clock state;
2. partition an excluded member before control distribution and measure
   behavior before and after every node accepts the newer epoch;
3. create conflicting add/remove commits and execute the explicit recovery
   policy without losing already authorized durable application objects;
4. replay every control/application object through multiple paths after
   restart and rollback; and
5. inventory exactly which metadata remains outside MLS protection.

If that composition requires a live DS/AS for local/direct correctness or
cannot recover required forks without discarding authorized durable data,
OpenMLS should remain a narrower connected-group component. Otherwise it is
the leading FOSS buy for classical group-state machinery while the hybrid,
authority, replay, metadata, and custody layers remain separate work.
