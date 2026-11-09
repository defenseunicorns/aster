# Android/Linux BTLE Ring-1 Event validation — 2026-11-06

Status: **bounded physical interoperability evidence; not Android support,
hardware qualification, requirement credit, or production authorization**.

## Outcome

A Pixel 9 Pro XL foreground validator initiated one protected semantic-v9 Event
contact to a Linux listener over LE L2CAP CoC. The Linux node had retained one
65,536-byte Event before the transport became available. Android authenticated
the expected mission peer, reconciled exactly one Event, durably inserted it,
and reported no Blob work. Linux independently reported a complete contact and
`event_validation=true`.

This validates the existing non-IP ordered-contact seam with one Android/Linux
device pair. It does not change the Aster protocol, transport selection, or the
Linux-only supported-product boundary.

A later cold-start investigation on this same Linux controller/kernel found an
intermittent USB HCI packet-order race below Aster. The
[early-ACL diagnostic](2026-11-09-android-linux-btle-early-acl-diagnostic.md)
preserves this successful run but prevents treating the exact host stack as
qualified for unattended cold Android initiation.

## Source, APK, and platform observation

| Field | Observation |
| --- | --- |
| Validated source head | signed `43830f16a858c02479067b9201a5c61bd2f8c5ce` |
| Android debug APK SHA-256 | `806af92a640547f21c1236436b0f2dd54e6d5f446f8255728c42535e441da7c1` |
| Android device | Pixel 9 Pro XL; Android 17 / API 37; 2026-10-05 security patch; ARM64; 4,096-byte pages |
| Linux host | x86-64; Linux 7.0.0-42-generic; BlueZ 5.85 |
| Linux controller | Realtek USB Bluetooth Radio `0bda:5852`; public controller identity |
| Android toolchain | Gradle 9.6.0; JDK 17.0.21; SDK 37; NDK 28.2; platform-tools 37.0.1 |

The APK was built from the source tree after the writer-exclusion fix and
installed directly for this bounded run. The exact build invocation and log
were not retained as repository artifacts, so the source-to-APK relationship
is operator-attested rather than cryptographic provenance or an independently
reproducible build record. The hash identifies the local APK installed for the
run. Exact Bluetooth addresses, mission identities, bundles, state, and device
serial are intentionally excluded.

## Regression found and corrected

The first clean Android attempt established the carrier but failed before the
mission handshake with `Store(ProcessExclusiveLockUnavailable)`. This was not
database corruption or stale app state. Commit `2e9e21c` had narrowed the
retained `flock` writer guard from all Unix targets to Linux to avoid a macOS
lock conflict. Android consequently used the redb fallback, whose aliased file
descriptor open could not prove an independently held writer lock.

The validated source keeps macOS on that fallback and restores the retained
`flock` guard and exact-backing proof only for Linux and Android. A clean app
state then completed the contact. The focused Linux lock test, all 23 Android
Rust tests, nine Android JVM tests, Android cross-build, formatting, and strict
`aster-redb-store` Clippy passed. The earlier unsanitized diagnostic APK was
replaced before the successful run and no diagnostic code was committed.

## Physical observation

The fixed-role listener used dynamic LE PSM 128 and an exact Android random
address observed by BlueZ; no wildcard peer admission, scan, discovery,
pairing, Internet path, or fallback participated. The Android application was
cleared before the successful attempt and copied the owner-provided mission
bundle into its private state.

The terminal receipts agreed on semantic version 9, transfer profiles
`[2, 1, 1, 5, 1]`, and canonical digest
`ace5ad78fa87203940221abc2a906144bfb0cad74fcafc5089b575971d63596f`.
Android reported:

- expected-peer and profile-digest matches;
- connected-socket maximum packet sizes of 672 bytes transmit and 65,535 bytes
  receive;
- one Event entry, 76,015 Event-page bytes, and one durable insert;
- the 65,536-byte Event larger than its receive packet bound; and
- no Blob attempt.

Linux reported one offered Event, no contact error, the reciprocal directional
MTUs, one Event-page entry sent, profile validation, and Event validation. The
contact completed without an IP socket or alternate carrier.

## Claim boundary

This one foreground run does not establish Android packaging or lifecycle
support, background execution, discovery, address-privacy automation,
multi-peer operation, retry/soak behavior, performance thresholds, radio
security, State/Record/Blob execution, cross-transport fallback, broad Linux
or Android hardware support, or production readiness. It demonstrates only
that the exact evaluation stack carried one existing protected v9 Event over a
real Android/Linux non-IP contact.
