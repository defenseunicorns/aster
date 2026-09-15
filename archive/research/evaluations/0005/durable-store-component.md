# Durable local data plane: redb versus SQLite

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.

Status: **component arm complete; partial evidence; neither component admitted**

Authority: `data-mesh-requirements.md` only, SHA-256
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.
Aster compatibility received zero weight. Bracketed values were measured as
curves, not treated as elimination thresholds.

## Outcome first

Advance **redb 4.2.0** as the greenfield embedded-store candidate. Retain
**SQLite 3.53.2 through rusqlite 0.40.2** as a mature operational oracle and as
an implementation detail already owned by candidates such as p2panda, but do
not select it for a new greenfield composition while the requirement literally
requires every dependency to use an OSI-approved license. SQLite's
public-domain status is permissive, but it is not an OSI-approved license.

This is a deliberately narrow decision. A database can own transactional local
bytes. It cannot own mesh reconciliation, temporal forwarding, Blob transfer,
priority/TTL/eviction policy, or application delivery semantics.

## Exact comparison

The locked comparator is registered by BVB-763 and corrected by BVB-764. Its
14 packages comprise 13 checksummed registry packages plus one local runner,
with no git dependencies. The release binary SHA-256 is
`7ff867d6727c2a9b08e30e25eea5756f02ccf913a8f3b7904c2b0a05136cefb5`.

`store-001` used 10,000 deterministic metadata rows and one 16 MiB object split
into 256 independently stored 64 KiB chunks. For both backends it proved:

- clean close and independent-process reopen with byte verification;
- forced process death with an uncommitted atomic write leaves neither marker;
- forced process death after commit preserves both atomic markers;
- duplicate insertion under the same chunk key leaves one stored chunk;
- native integrity checking succeeds after both crash points; and
- a concurrent writer is rejected/bounded rather than admitted silently.

These are process-failure results, **not** power-cut, torn-sector, disk-full, or
flash-wear results. The duplicate-key result is a storage primitive, not proof
that duplicate application delivery is harmless.

The observed difference was concurrency scope: SQLite admitted a separate
reader while a writer held an uncommitted transaction; redb's file lock denied
the second process entirely. The reference library is expected to own one
in-process database handle, so this does not eliminate redb. It does matter if
the optional out-of-process agent and linked library are expected to share one
file directly; the cleaner design is one store-owning process with IPC.

## Measured curve

`store-curves-002` held metadata at 10,000 rows and varied deterministic Blob
content. These are single-host observations, not targets or benchmarks:

| Blob input | redb file | SQLite file | redb seed / verify | SQLite seed / verify |
|---:|---:|---:|---:|---:|
| 1 MiB | 2,887,680 B | 1,474,560 B | 0.07 / 0.03 s | 0.01 / 0.01 s |
| 16 MiB | 67,375,104 B | 17,326,080 B | 0.08 / 0.03 s | 0.04 / 0.02 s |
| 64 MiB | 135,008,256 B | 68,050,944 B | 0.16 / 0.07 s | 0.16 / 0.05 s |
| 128 MiB | 269,488,128 B | 135,684,096 B | 0.21 / 0.12 s | 0.31 / 0.09 s |

redb's growth allocation made its files roughly twice the large input in this
fixture, and the 16 MiB point landed on a larger allocation step. SQLite stayed
close to payload plus metadata. That is meaningful storage-capacity decision
data, not evidence of a correctness failure. Peak RSS remains unknown because
the sandbox denied the host query used by the first curve harness; the failed
`store-curves-001` run is preserved and receives no credit. The runner itself
generates and verifies one 64 KiB chunk at a time, so it does not buffer the
complete Blob, but this does not prove the eventual framework's RAM behavior.

The exact 14-package lock had zero vulnerabilities and zero informational
warnings under the clean tracked RustSec database commit
`bf5c0d245a92671908518d7e765914d437954ed6` (1,225 advisories). This is a dated
scan, not production admission.

## Requirements boundary

The arm supplies bounded component evidence toward durable byte preservation
(`DM-5.2-04`), chunk-at-a-time storage mechanics (`DM-5.1-12`, `DM-9-13`,
`DM-9-14`), and same-key physical deduplication mechanics (`DM-5.1-15`). Those
cells remain only **partial** at whole-stack level.

It supplies no credit for Blob content addressing or any-peer transfer resume,
offline resynchronization, priority/TTL/quota eviction, bounded local-store
policy, replication, temporal relaying, encryption, metadata protection,
schema migration, or application idempotence. Those responsibilities must be
owned above the selected store and tested as part of one composition.

## Delete/delete/delete consequence

Do not add a second generic database beside whichever primary candidate already
owns durable replica state. Use:

- the candidate-native store when evaluating p2panda, Zenoh, Willow, or another
  integrated replica; or
- redb as the one durable owner in the frozen greenfield composition.

Adding redb below p2panda's SQLite or Zenoh's RocksDB would duplicate crash
recovery, retry, expiry, pruning, and migration state—the exact kind of custom
architecture this evaluation is intended to delete.

Evidence summary:
archived `summary.json`.

