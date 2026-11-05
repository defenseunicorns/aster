# CM4 BTLE Ring-1 Event validation — 2026-11-04 through 2026-11-05

Status: **bounded physical engineering evidence; Ring-1 review-ready, not
qualification, requirement credit, or production authorization**.

## Outcome

Two physical ARM64 Compute Module 4 devices exchanged one protected 65,536-byte
Event over Linux LE L2CAP CoC using the unchanged semantic-v9 contact. The
source published durably before BTLE was available, the receiver had an exact
durable `Consume` subscription, and the receiver's local application query
later returned exactly one Event with the source Event ID and byte-identical
payload.

The unattended evaluator also started with both controllers powered off,
observed controller availability without polling, recovered from a receiver
controller power cycle without a process restart, and completed later zero-work
contacts. This demonstrates the original Ring-1 purpose: one real non-IP
adapter carrying the existing protected Event protocol through the
adapter-neutral ordered-contact boundary.

One platform limitation remains explicit. After both evaluators stopped
cleanly, BlueZ 5.82 still reported the unpaired peer ACL as connected. Fresh
evaluator processes reached `Available` and selected complementary roles, but
their contacts timed out until the receiver controller entered a new power
epoch. The next contact then completed with zero Event work, and the application
still exposed exactly one Event. The observation proves restart durability and
deduplication, but not seamless process-only radio recovery on this
kernel/BlueZ/controller combination. The evaluator does not hide that behavior
by disconnecting peers or mutating controller power.

## Source and artifact binding

| Field | Observation |
| --- | --- |
| Validation source head | signed `0325d131b05b278912777e97a2976d4007c97eff` |
| Last production-code revision | `0f76e0f483f4a300a18ae9a4e65d0e45ae5590c1` |
| Source relationship | no non-document file changed between the production revision and reviewed head |
| ARM64 `aster-btle-event` SHA-256 | `4bd4c28ef82dedcdfc0c6cc11edfc67f08c831256bc79f467b2839767f441fbe` |
| ARM64 `aster-agent` SHA-256 | `72166c2b79852863f0baba4b5998f07f39d18698efb25b22a8315f3b86b841cd` |
| ARM64 `asterctl` SHA-256 | `e7d3c7e5d0149e66f4a17ead25853b43f52a12112c4109df9bcdccba9fa460c4` |
| Toolchain | Rust/Cargo 1.97.1; target `aarch64-unknown-linux-gnu` |

The deployed executable hashes matched on both devices before execution. Exact
Bluetooth addresses, mission identities, state paths, tokens, and bundle bytes
were retained only in the owner-only temporary lab and are intentionally absent
from this record.

The original ARM64 build command, builder image/sysroot, and build log were not
retained. The source-to-artifact relationship is therefore operator-attested
from build timing and the unchanged non-document tree, not cryptographic
provenance or an independently reproducible build. The hashes bind the two
devices to the same deployed artifacts only.

## Devices and configuration

Both participants reported:

- Debian GNU/Linux 13 (`trixie`), ARM64;
- Linux `6.18.39+rpt-rpi-v8`;
- BlueZ `5.82`;
- Broadcom `BCM4345C0`, patched firmware build `0382`;
- kernel driver `hci_uart_bcm`;
- one `hci0` controller with a public address; and
- dynamic LE PSM `0x81`.

The lower complete mission node ID derived the initiator role and the higher ID
derived the listener role. No role option, discovery, pairing, IP mesh contact,
or carrier fallback participated. The successful-contact cadence was one
second for bounded deduplication observation. A five-second cadence was used
only for the process-restart diagnostic.

## Physical observations

### Fixed-role carrier receipt

At signed source `6485841e0358259d2e1415737bdc4baf0ea4ce6a`, the same two
devices completed an earlier fixed-role BTLE-only contact with negotiated
directional MTU 672 and one 65,536-byte Event. Both receipts reported semantic
version 9, profile IDs `[2, 1, 1, 5, 1]`, canonical transfer-profile digest
parity, `duplicates=0`, and no Blob work. The source reported `offered=1`; the
receiver reported `fetched=1` and `inserted=1`.

That earlier operator observation did not retain the deployed binary digest or
machine-readable receipt. It supplies the negotiated-MTU observation for this
hardware combination, not a qualification artifact or supported MTU floor.
The later unattended run below retained the Event size but did not expose its
negotiated MTU, so no single retained artifact or run binds the payload-size and
MTU observations together.

### Unattended lifecycle receipt

With controllers powered off, both deployed evaluators remained running and
reported `ControllerUnpowered`. Initial snapshots were:

| Participant role | RSS (KiB) | Threads | File descriptors |
| --- | ---: | ---: | ---: |
| Initiator | 15,068 | 10 | 16 |
| Listener | 14,764 | 10 | 16 |

After controller power-on, the source completed with `offered=1, fetched=0,
inserted=0`; the receiver completed with `offered=0, fetched=1, inserted=1`.
Later contacts on both sides reported `offered=0, fetched=0, inserted=0`.

Powering off the receiver controller during continued operation produced
bounded contact failures followed by `ControllerUnpowered`. Restoring that
controller produced a new availability epoch and zero-work contacts without
restarting either evaluator.

After clean evaluator shutdown and restart, both processes reached `Available`
but contact attempts timed out while BlueZ still reported the unpaired peer ACL
as connected. A receiver controller power cycle cleared that platform state;
both restarted evaluators then completed a zero-work contact. Their post-restart
snapshots were 16,808/16,996 KiB RSS, nine threads each, and 19/20 file
descriptors. These are point observations, not idle, peak, variance, capacity,
or energy measurements.

Finally, a local receiver application query returned exactly one Event. Its ID
matched the source publication receipt, and its payload was exactly 65,536 zero
bytes with SHA-256
`de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31`.

## Cleanup and claim boundary

Both evaluators and both preparation/query agents stopped cleanly. The two
owner-only remote roots, including disposable mission bundles, tokens, stores,
journals, payload, and copied binaries, were deleted. Both controllers were
restored to `Powered: no`. Sanitized evaluator lifecycle logs were retained
locally for review; raw credentials, addresses, identities, and application
logs were not retained in this repository.

This evidence makes the Linux/Linux Event-only non-IP adapter slice review-ready
at Ring 1. It does not establish a supported target, production daemon,
discovery or selection policy, seamless process-only radio recovery, multi-peer
operation, State/Record/Blob execution, cross-transport acceptance, throughput
or resource threshold, mixed implementation, or production readiness. It
changes no atomic requirement status.
