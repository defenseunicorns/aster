# Blob transfer and operating-envelope arm

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.

>
> Requirements-first research evidence only. `data-mesh-requirements.md` is
> the sole architecture authority. Current Aster implementation, architecture,
> wire, APIs, stores, and compatibility received zero weight. Bracketed values
> are measured curves rather than candidate-elimination thresholds.

Status: **arm complete; partial but decisive evidence; no component admitted**

## Outcome first

Retain **BLAKE3 1.8.7 only as a permissive research/control identity oracle**.
It proves the storage and resume shape, but receives no normative credit under
`DM-6-24` or `DM-6-28`. Unless stakeholders explicitly scope those rules away
from content identities, the final whole-content and chunk identity defaults
must use a NIST-standardized, FIPS-approved hash through the selected
cryptographic provider. Buy **redb 4.2.0 only for small durable Blob
manifest/checkpoint metadata** in the greenfield control. Do **not** place
complete Blob bytes in redb: measured process RSS and database allocation rose
with Blob size even though evaluator code handled one chunk at a time.

The smallest architecture that survived the curve keeps one durable progress
owner in the Blob layer, keys it only by content identity and missing chunks,
and streams bytes through files. A carrier moves bounded frames and reports
link characteristics; it does not get its own persistent Blob downloader,
retry database, or peer-bound checkpoint. That division is what allows a
second eligible peer over another carrier to continue the same transfer.

This does not mean the task-authored split store is selected product code. It
is an architecture control proving where redb helps, where it hurts, and what
custom residue remains. The next implementation choice should first try to buy
that residue from a maintained content store. The frozen candidates do not yet
close it:

- p2panda v0.7.1's released `p2panda-blobs` package is a dependency-free stub;
  its module root links none of the stale implementation files, so it receives
  no executable Blob credit;
- Willow25 0.7.5 remains a credible composition-specific FOSS buy for payload
  identity, persistent prefix storage, and verified slices, but BVB-738 found
  no executable Confidential Sync/WTP and no durable partial or any-peer resume;
- redb buys transactional metadata but fails the measured byte-store RAM curve;
  and
- no frozen component owns the requirements-specific priority/TTL/reference,
  physical-quota, security-binding, and carrier-neutral resume lifecycle.

## Requirements and responsibility audit

The Blob layer must own more than a hash helper:

1. immutable content identity and a normative chunk/manifest profile;
2. streaming import, transfer, verification, and export without whole-Blob RAM;
3. durable missing-set progress that survives restart and is independent of
   peer, session, and carrier;
4. duplicate content suppression and safe retry of an interrupted chunk;
5. logical and physical storage accounting, quotas, priority eviction, TTL,
   references, and garbage collection; and
6. binding into source-object security and protected member metadata.

Items 1 through 4 were exercised in the bounded profile. Item 5 is only a
logical policy probe. Item 6 belongs to the selected security composition and
was deliberately not duplicated here. Detailed dispositions are in
[`requirements-map.csv`](../../../../docs/evaluations/0005/requirement-maps/blob.csv).

## Exact freeze

The BVB-796 graph, BVB-797 warning correction, BVB-804 split-store extension,
BVB-807 license correction, and BVB-810 Clippy cleanup contain 11 packages: ten exact checksummed
registry packages and one local comparator, with no git dependencies. Direct
dependencies are BLAKE3 1.8.7 and redb 4.2.0. The final release binary is
1,178,752 bytes with SHA-256
`866cd3dbf6fc859f009b38917cb68c950d01c8acb0bfd93213f5c633d98a89af`.

BLAKE3's exact license expression is
`CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception`; this evaluation uses
the selectable Apache-2.0 option. License eligibility does not resolve
algorithm eligibility: BLAKE3 remains a research/control mechanism and receives
no NIST/FIPS requirement credit. redb is `MIT OR Apache-2.0`. The exact lock had
zero vulnerabilities and zero informational warnings against RustSec
commit `bf5c0d245a92671908518d7e765914d437954ed6` containing 1,225 advisories.
This dated scan is not production admission.

The exact source and artifact identities are preserved in
archived `source-freeze.tsv`.

## Restart, peer, and carrier result

For each 1, 16, 64, 128, and 256 MiB Blob, the evaluator:

1. created two independent byte-identical source files and a manifest containing
   one whole-content BLAKE3 identity plus per-chunk BLAKE3 identities;
2. accepted one quarter of the 256 KiB chunks from `peer-a` through a modeled
   128-byte-MTU, 50%-loss carrier;
3. fully received and synchronized the next chunk file, then exited with code
   77 **before** its durable redb marker;
4. reopened the database in another process and observed exactly the committed
   quarter, while the unmarked file extent remained harmless orphan work;
5. used `peer-b` and a modeled 1,200-byte-MTU, 50%-loss carrier to retransmit the
   unmarked chunk and continue only the missing set; and
6. streamed the completed content into a new file, verified the whole identity,
   compared every output byte, then repeated the complete transfer from peer B.

All five cases passed. The duplicate transfer sent zero frames and zero bytes.
The durable markers after the crash represented exactly 262,144; 4,194,304;
16,777,216; 33,554,432; and 67,108,864 bytes. The file was one unmarked
256 KiB chunk longer in every case, demonstrating rather than concealing the
crash-reconciliation boundary.

This is component-level evidence for content-addressed chunk resume across
restart, peer, and carrier labels. The carrier itself is a deterministic local
model, and peer eligibility/authentication is not proven.

## The decisive store comparison

The same content, chunk size, forced exit point, source files, loss model, and
verification were used for both layouts.

| Blob | redb byte-store file | redb byte-store resume RSS | split metadata + content files | split resume RSS | split verify RSS |
|---:|---:|---:|---:|---:|---:|
| 1 MiB | 3,149,824 B | 5,554,176 B | 65,536 + 1,048,576 B | 3,407,872 B | 2,949,120 B |
| 16 MiB | 35,131,392 B | 39,698,432 B | 73,728 + 16,777,216 B | 4,325,376 B | 2,965,504 B |
| 64 MiB | 138,416,128 B | 144,211,968 B | 98,304 + 67,108,864 B | 4,685,824 B | 3,047,424 B |
| 128 MiB | 289,411,072 B | 283,557,888 B | 176,128 + 134,217,728 B | 4,653,056 B | 3,112,960 B |
| 256 MiB | 601,886,720 B | 561,676,288 B | 258,048 + 268,435,456 B | 5,292,032 B | 3,194,880 B |

The redb byte-store transfer touched its memory-mapped content pages, so peak
RSS grew to 535.7 MiB at the 256 MiB endpoint and streaming verification reached
536.5 MiB. A one-chunk evaluator buffer therefore did not make the process RAM
independent. This role fails `DM-9-14` in the measured composition.

The split transfer grew from 3.25 MiB to 5.05 MiB RSS while Blob size grew
256-fold; verification grew from 2.81 MiB to 3.05 MiB. Its content file was
exactly the Blob size, and metadata was 258,048 bytes at the largest endpoint.
This advances the split responsibility boundary, not the evaluator code, to
power-loss and lifecycle testing.

The result also corrects the earlier durable-store arm's unknown-RSS gap:
redb remains a good greenfield candidate for small replica/checkpoint state,
but its allocation model should not automatically own large streamed content.

## Loss curve

An 8 MiB Blob with 64 KiB chunks used the 1,200-byte modeled MTU. Each dropped
frame was retransmitted until received.

| Modeled loss | Wire bytes | Wire / payload | Projected time at 3 kbps |
|---:|---:|---:|---:|
| 0% | 8,560,640 | 1.021 | 6.34 h |
| 10% | 9,543,680 | 1.138 | 7.07 h |
| 30% | 12,227,440 | 1.458 | 9.06 h |
| 50% | 16,853,680 | 2.009 | 12.48 h |
| 70% | 28,025,040 | 3.341 | 20.76 h |

Every cell completed, so 50% is useful decision data rather than an exclusion
gate. The projection also makes clear that a large Blob on a 3 kbps link takes
hours even without control traffic. Policy must be able to decline, defer, or
move such work to another carrier; no architecture can erase the information
volume.

The model has perfect local missing-frame knowledge and omits ACK/NACK bytes,
RTT, congestion, contact-window expiry, correlated loss, and other traffic. It
therefore gives no real high-loss-link acceptance credit. FEC should remain a
measured optional strategy, especially for broadcast repair, rather than a new
mandatory state machine introduced from this idealized result.

## MTU curve

A 4 MiB Blob at 30% modeled loss used a fixed 24-byte evaluation header.

| Modeled MTU | Frames sent | Wire bytes | Wire / payload |
|---:|---:|---:|---:|
| 48 B | 249,716 | 11,985,520 | 2.858 |
| 64 B | 150,134 | 9,606,344 | 2.290 |
| 128 B | 57,965 | 7,412,040 | 1.767 |
| 512 B | 12,489 | 6,362,720 | 1.517 |
| 1,200 B | 5,176 | 6,184,320 | 1.474 |
| 1,500 B | 4,158 | 6,149,484 | 1.466 |

This demonstrates why the final profile needs compact fragmentation on the
smallest carrier, but 24 bytes is not a selected header and no practicality
threshold has been accepted. The carrier arm must replace this model with
physical BTLE/IP accounting, including feedback and security overhead.

## Quota and eviction probe

A 2 MiB logical content quota first held one priority-0 and one priority-3
1 MiB Blob. Admission of a priority-2 Blob evicted exactly the priority-0 Blob
and retained priorities 3 and 2. A later priority-0 Blob was blocked with zero
accepted chunks. Repeating the retained Blob changed neither wire bytes nor
database bytes.

This is only partial credit. redb's physical file remained at its 4,722,688-byte
high-water mark before and after eviction, and the blocked Blob still added a
zero-byte metadata entry. A content-byte counter does not bound physical disk,
manifests, incomplete work, temporary files, or reference metadata. The final
owner needs one accounting rule covering all of them, a reserve for atomic
commit, and deterministic collection.

## Buy, build, delete

| Responsibility | Decision | Why |
|---|---|---|
| Whole and chunk digest research oracle | **Retain BLAKE3 for research/control only** | Exact permissive FOSS implementation, streaming API, clean frozen graph; no `DM-6-24`/`DM-6-28` credit |
| Normative whole and chunk digest | **Buy from selected cryptographic provider** | Must be NIST-standardized and FIPS-approved unless stakeholders explicitly narrow the content-identity scope |
| Atomic small checkpoint metadata | **Buy redb** in the greenfield control | Process-restart evidence and small split metadata curve |
| Complete Blob bytes in redb | **Delete** | Measured RSS and physical allocation scale with content |
| p2panda v0.7.1 Blob package | **Do not count** | Released package does not link an implementation |
| Willow payload store/slices | **Advance conditionally** | Strong FOSS mechanism in a Willow composition; resume runtime still missing |
| Durable Blob progress per carrier | **Delete** | One content-keyed Blob owner must survive every carrier and peer |
| Normative manifest/profile and security binding | **Build or find** | No frozen FOSS component owns requirements semantics |
| Physical quota, references, TTL, GC, crash reconciliation | **Build or find** | Must cover files plus metadata as one lifecycle |
| ARQ/FEC scheduling | **Defer selection to real-link curve** | Not a correctness invariant and current model omits decisive costs |

This boundary keeps the connectivity comparison open without assigning it the
wrong job. Iroh, libp2p, Quinn, BTLE, or a future file carrier may carry the
same Blob frames; none should become the authoritative persistent missing-set
owner. If a future integrated FOSS Blob component owns storage, resume, and
lifecycle completely, it should replace this entire split—not be wrapped by a
second progress database.

## Remaining gates

Before production selection, the next Blob implementation must pass:

1. power-cut and kill-at-every-boundary tests, including file sync, marker
   commit, completion rename, directory sync, disk full, and corrupted chunks;
2. a physical-byte quota covering complete, partial, orphan, temporary,
   manifest, index, and reserve bytes, with TTL, reference, and priority rules;
3. the selected COSE/source-object and member-metadata profile, including a
   versioned NIST/FIPS digest suite, manifest/content-identity binding, hostile
   peers, downgrade protection, and replay;
4. actual IP and BTLE streams with carrier changes, disconnects, backpressure,
   reverse-control accounting, and fair priority scheduling;
5. any-peer continuation among independently authenticated nodes, including a
   corrupt or lying source; and
6. ARQ versus range repair versus FEC curves under burst loss, asymmetric links,
   broadcast receivers, bounded contact windows, and energy accounting.

Raw sources, source copies, databases, content files, exports, timing output,
and receipt files remain locally preserved under ignored run directories. The
redb-byte and split receipt-manifest SHA-256 values are respectively
`832d868d57ba22073ae3c2bdb078a67d371fec453917d408da18c4fb60a3ea5a`
and `3d9f330432e302005535f5b7d39e30f3f6621c6933cd9699110a924b674a7fbe`.
The reviewable non-normalized result is
archived `summary.json`.
