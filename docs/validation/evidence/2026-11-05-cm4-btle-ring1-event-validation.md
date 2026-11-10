# CM4 BTLE Ring-1 Event validation — 2026-11-04 through 2026-11-05

Status: **bounded physical engineering evidence; no hardware qualification,
requirement credit, or production authorization**.

## Hardware and source

- Two ARM64 Raspberry Pi Compute Module 4 devices.
- Debian 13; Linux `6.18.39+rpt-rpi-v8`; BlueZ 5.82.
- Broadcom BCM4345C0, firmware build `0382`, `hci_uart_bcm`.
- Signed validation head `0325d131b05b278912777e97a2976d4007c97eff`;
  deployed `aster-btle-event` SHA-256
  `4bd4c28ef82dedcdfc0c6cc11edfc67f08c831256bc79f467b2839767f441fbe`.

The original build log was not retained, so source-to-binary provenance is
operator-attested. Both devices verified the same executable digest.

## Scenario and result

One node published a 65,536-byte Event before BTLE availability; the receiver
had an exact durable subscription. A prior fixed-role contact observed
directional MTU 672 and successful semantic-v9/profile `[2,1,1,5,1]` transfer.
The retained unattended run then observed:

- startup with both controllers powered off;
- later controller availability without polling;
- one protected Event fetched and durably inserted;
- receiver controller loss and recovery without process restart;
- later zero-work contacts; and
- an application query returning exactly one matching Event with byte-identical
  payload (SHA-256
  `de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31`).

No single retained run binds the 65,536-byte payload to the MTU observation.
Point resource observations were roughly 14.8–17.0 MiB RSS, 9–10 threads, and
16–20 file descriptors; they are not thresholds or variance measurements.

## Limitation

Fresh processes could not reopen the retained ACL until a controller power
epoch changed. The follow-up
[diagnostic](2026-11-06-cm4-btle-clean-restart-diagnostic.md) bound this to
CVE-2026-72333 in the affected kernel, not Aster process state. This record
therefore demonstrates Event delivery, controller-epoch recovery, durable
receipt, and deduplication only for the exact stack. It does not establish
process-only restart, discovery, other data classes, support, or production
readiness.
