# Aster patch provenance

- Upstream package: `bluer` 0.17.4 from crates.io.
- Crate archive SHA-256: `af68112f5c60196495c8b0eea68349817855f565df5b04b2477916d09fb1a901`.
- Upstream VCS revision: `8072d9cc6d034f1bfc464dda338d19a14f9badaf`.
- Manifest license: `BSD-2-Clause`.
- Complete vendored license inventory: primary source under `BSD-2-Clause`;
  assigned-number database under `BSD-3-Clause`; copied/adapted BlueZ API
  documentation under `GPL-2.0-only`. The complete notice is retained as
  `LICENSE`, SHA-256
  `da053620434ccd59747d44b04e87e06464763f22db320bc71dc9b00b1e4db460`.
- Per-file upstream receipt: `ASTER-UPSTREAM.sha256`.
- Canonical patch: `ASTER-PATCH.diff`, SHA-256
  `ce4de362bf30ccc318c741694adfce8678c53202b44a5b4827a509ea681044af`.

The upstream-code delta is limited to `src/adapter.rs`, `src/adv.rs`,
`src/lib.rs`, and `src/session.rs`. It adds cancellation-independent owners for
advertisement registration/unregistration and exclusive discovery start/stop,
persistent owned termination waiters, a first-wins terminal session latch, and
an idempotent explicit session close used to force owner loss during bounded
shutdown.
Discovery ownership is published only after FIFO ingress barriers surround an
authoritative `Discovering` property read.
The D-Bus ingress and subscriber queues are bounded to 256 items; overflow
retains `IngressOverflow`, aborts the D-Bus resource, closes subscribers, and
rejects later subscriptions. Existing shared discovery and drop compatibility
remain available. The fork contains no mission identity, roster admission,
transport selection, durable store, Aster protocol, or operator policy.

Remove the patch when an upstream release offers equivalent acknowledged
ownership, terminal notification, and bounded-ingress behavior and Aster can
qualify that exact release. Run `python3 tools/check-btle-vendor-patches.py`
for source equivalence and `sh tools/test-btle-vendor-patches.sh` for the
upstream library tests and Aster-specific lifecycle tests.
Those tests independently mutate advertisement cleanup, discovery cleanup,
definite discovery-absence handling, and the 256-item bound. Every mutation
runs with an isolated Cargo target and must be rejected. This Ring 2 source
snapshot retains the complete upstream notice. Production packaging remains
gated on release review of the BSD-3-Clause database and GPL-2.0-only API
documentation obligations; this provenance record does not grant release
admission.
