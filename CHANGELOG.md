# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Optional `before_acceptance_marker` filter for `QueryEvents` RPC call
- `asterctl unsubscribe` command to remove an Event subscription by ID.
- subsriptions option for asterctl to get Event subscriptions list
- `ListEventSubscriptions` RPC to list the node's Event subscriptions with their IDs, operation keys, and topic/scope filters.
- `asterctl` CLI utility.
- Local delivery and transfer status for State, Record, and Blob operations.
- Numbered Event publication with durable operation tracking and crash-safe recovery.
- Separately bounded, non-evictable Blob physical-lineage and publication-replay
  fences; typed publication/pending-source variant references; and exact
  lifecycle accounting with audit-first atomic predecessor migration.
- Persistent six-class Blob maintenance discovery with independently nonzero
  row/file/byte budgets, durable fair cursors, and automatic bounded startup and
  periodic background turns.
- Bounded Blob pressure recovery for the exact rejected publication,
  network-staging, or depot partition. It evicts only strictly lower-priority
  work in deterministic incomplete-before-completed order, then expiry class
  and finite deadline, exact completion fraction, acceptance order, and exact
  identity, and never skips an oversized first
  atomic candidate, reconciles local caches, and retries admission once.
  Deletion remains manifest-backed and resumable, with depot capacity charged
  until physical finalization.
- Rust selected-Blob finite publication options, exact original-TTL echoes,
  page-bounded lifecycle checks, and tagged content/retirement delivery with
  separately bound acknowledgement tokens. C FFI Blob lifetime fields remain
  unchanged.
- Additive local `PublishBlob` and `ReadBlob` Protobuf/RPC streams and
  `asterctl blob-publish`/`blob-read` commands for durable or finite-TTL file
  publication and authenticated read to a new file. Transfers use bounded
  native HTTP/2 frames/pages, exact operation-key recovery and original-TTL
  output. The current 64-MiB backend admission and 30-second agent stream cap
  are implementation limits, not wire guarantees; Blob subscription commands,
  FFI lifetime controls, large-file qualification, and release acceptance are
  not included.

### Changed

- Removed `MeshService` and updated tests.
- Restored runtime-volume diagnostics using Aster/Iroh.

- Faster Blob transfers. Breaking change: both nodes must be updated.
- Replaced libp2p-based tests with Event delivery and reconnection tests using Iroh. Removed the unused libp2p provider and its dependencies.
- Fixed a test failure caused by `iroh` in the checkout directory name.
- Upgrade dependencies: Iroh 1.3.0 (public DNS disabled)
- Reduced CI turnaround with Rust compiler caching and partitioned nextest runs.
- Prefiltered Event query candidates before authentication to avoid unnecessary verification work.
- Aligned the wire and envelope contract with semantic protocol version 6.
- Bounded indexed Event-custody expiry and retirement to a resumable 1,024-dependency-unit cleanup pass. Pressure eviction still scans all retained custody rows while keeping at most 1,024 candidates in scratch memory. New local and selected-reconciliation Events schedule coalesced prompt contact attempts, with failed attempts falling back to periodic retry; bridge propagation is unchanged. Custody schema v1/v2 stores require recreation, and the supporting measurements are current-code engineering evidence rather than target qualification.
- Reused custody authorization decisions within each send attempt.
- Continued accumulating only provable monotonic custody intervals after exact
  clock-continuity loss. Finite Event/RouteEvent rows remain withheld below TTL,
  re-anchor through the existing bounded expiration index across restarts, and
  expire once their conservative lower bound reaches TTL. The change is
  wire-neutral.
- Made local Blob admission, network staging, publication promotion, and pending
  abort transactionally update their lifecycle fences, typed roots, counters,
  and ordinary visibility without changing semantic-v5 wire bytes or durable
  publication behavior.
- Deliberately changed the Rust `BlobDeliveryPage::deliveries` field from
  `Vec<BlobDelivery>` to `Vec<BlobDeliveryItem>` so one bounded page can carry
  either content metadata or a retirement notice. This is a Rust source
  compatibility break; callers must match the tagged delivery item.

### Security
- Bounded abandoned received Profile-5 uploads with a receiver-local 30-day
  idle-retention lease refreshed by durable checkpoint progress, reclaimed
  interrupted atomic pack-marker temporaries during writable recovery, and
  bound local upload expiry to the exact custody-continuity generation. This
  changes only the unreleased Profile-5 upload encoding; incompatible
  development depots still require reset or Blob reimport.


- Updated ctutils to 0.4.5 and crypto-bigint to 0.7.9 to address RUSTSEC-2026-0385 and RUSTSEC-2026-0387.
- Created Unix publication journals with owner-only permissions and rejected insecure existing journal files.

- Restricted `asterctl` plaintext RPC to loopback addresses before credential or payload loading.

- Hardened inbound handshakes and health admission against resource exhaustion.
