#

# CM4 provider and Event engineering spike — 2026-09-09

## Disposition

Status: pass as pre-candidate engineering evidence; not a G3/G4 qualification
annex and not a release authorization.

Three fresh physical Raspberry Pi Compute Module 4 nodes ran the consolidated
Event-agent and D06 provider implementation on the exact Raspberry Pi reference
2026-06-18 / Debian 13 `trixie` / kernel `6.18.39+rpt-rpi-v8` / systemd
`257.13-1~deb13u1` / `aarch64` profile. The final tested `aster-agent` binary
was an ARM64 release build with SHA-256
`fef803b982d3d53c1cbbe0d5c373fee37d08b5d7777a1d539e11464b96010592`.

No bearer token, carrier identity, mission identity, operation ID, opaque
reference, Event ID, provisioning plaintext, or protected backup bytes are
retained in this record.

## Passed behavior

- The statically selected systemd provider started and restarted the
  unprivileged agent on all three nodes with the systemd 257 root-owned
  ACL/read-only-`tmpfs`/`noswap` credential presentation.
- Authenticated status reported the configured/effective Normal and
  ReceiveOnly modes and bounded store, publish-operation, and delivery
  capacity.
- Authenticated publish, exact query, subscription, poll, stream, and
  acknowledgement paths completed against the real agent process.
- Normal-to-ReceiveOnly Event transfer completed in both carrier-identity
  orderings after the receiving node had an exact durable subscription.
- A ReceiveOnly node retained a local publish without transferring it to its
  Normal peer, and two ReceiveOnly nodes retained their own publishes without
  transferring either Event to the other node during the observation window.
- A valid bearer-token reload authorized the new token, rejected the old
  token, and retained the process identity. An invalid replacement retained
  the prior working token and Ready state.
- An exact Event remained queryable after clean service stop/start.
- The root administration lane completed idempotent install, rotation and
  retry, rotated-credential restart, backup and byte-identical retry, corrupt
  credential startup failure, recovery and retry, Previous destruction and
  retry, Active destruction and retry, and missing-credential startup failure.
- The final reviewed ARM64 artifact was installed by verified compressed and
  uncompressed digests and reached HTTP 200 readiness on all three nodes.

Focused local verification passed 119 provider-library tests, 16 provider-CLI
tests, one provider process integration test, and the agent/provider static
composition test. Requirements trace validation reported 348 matrix IDs and
137 exact selected mappings.

## Initial measurements

With the final artifact Ready, each process used five threads. Current/high-
water RSS was 15,752 KiB, 15,816 KiB, and 15,708 KiB across the three nodes.
Synthetic state directories were 364,576 bytes, 622,624 bytes, and 180,256
bytes after their different test roles. systemd did not expose
`MemoryCurrent`/`MemoryPeak` for this temporary unit, so `/proc` supplied the
RSS observations. These are small-run observations, not sizing evidence.

## Findings and remaining blockers

- The original D06 mode-`0400`/`ramfs` assumption does not match systemd 257 on
  the selected image. The exact accepted presentation is now recorded in the
  [systemd 257 amendment](../../superpowers/specs/2026-09-09-systemd-257-credential-presentation-amendment.md).
- `systemd-creds list` labels the ACL-backed mode-`0440` presentation
  `insecure`. Aster therefore makes only its narrower independently checked
  ACL/mount/no-swap claim. Security and Deployment approval of the immutable
  amendment remains the evaluation-blocking E01 gate.
- A provider rotation using a bundle from a newly generated, unrelated mission
  was correctly rejected by protected state bootstrap. Provider lifecycle
  rotation was rerun successfully with the retained mission authority and a
  fresh provider generation/load operation. Mission-authority migration is a
  separate workflow and is not implied by D06 rotation.
- The final native `.deb`, hardened service unit/control surface, signed
  annex, reproducible artifact/provenance binding, and two-mandatory-node G4
  run remain open. This spike used a temporary lab unit.
- The generated-Go qualification client and full 1,024-operation capacity
  workload were not run here.
- ReceiveOnly is zero Event transfer/non-disclosure, not physical radio
  silence; authenticated link, handshake, acknowledgement, and response
  traffic remains allowed.
- The software-backed systemd host key produced an encrypted-media warning.
  This is accepted only for the named MVP evaluation and makes no physical
  custody or erasure claim.
- ZeroTier control sessions experienced intermittent high latency and SSH
  disconnects. Retried commands were bound by retained inputs and receipts;
  this is a test-harness reliability finding, not evidence of product data loss.
