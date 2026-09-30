# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `asterctl` CLI utility.
- Local delivery and transfer status for State, Record, and Blob operations.
- Numbered Event publication with durable operation tracking and crash-safe recovery.

### Changed

- Reduced CI turnaround with Rust compiler caching and partitioned nextest runs.
- Bounded custody maintenance scans and wake processing to keep background work predictable.
- Reused custody authorization decisions within each send attempt.

### Security

- Hardened inbound handshakes and health admission against resource exhaustion.

