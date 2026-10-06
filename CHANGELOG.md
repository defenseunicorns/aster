# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `asterctl unsubscribe` command to remove an Event subscription by ID.
- subsriptions option for asterctl to get Event subscriptions list
- `ListEventSubscriptions` RPC to list the node's Event subscriptions with their IDs, operation keys, and topic/scope filters.
- `asterctl` CLI utility.
- Local delivery and transfer status for State, Record, and Blob operations.
- Numbered Event publication with durable operation tracking and crash-safe recovery.

### Changed

- Upgrade dependencies: Iroh 1.3.0 (public DNS disabled)
- Reduced CI turnaround with Rust compiler caching and partitioned nextest runs.
- Prefiltered Event query candidates before authentication to avoid unnecessary verification work.
- Aligned the wire and envelope contract with semantic protocol version 6.

### Security

- Created Unix publication journals with owner-only permissions and rejected insecure existing journal files.

- Restricted `asterctl` plaintext RPC to loopback addresses before credential or payload loading.

- Hardened inbound handshakes and health admission against resource exhaustion.
