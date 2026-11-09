# Android/Linux BTLE text Event validation — 2026-11-09

Status: **bounded warm-state physical interoperability evidence; not cold-host
qualification, Android support, requirement credit, or production
authorization**.

## Outcome

A clean-installed Pixel 9 Pro XL foreground validator durably published the
short text `pixel-final-btle-event-2026-11-09` before opening a carrier. It then
initiated one protected semantic-v9 Event contact to the fixed Linux listener
over LE L2CAP CoC. Linux authenticated the expected mission peer, durably
inserted the text Event, and printed its terminal-safe receipt. Android received
and durably inserted the Linux node's previously retained 65,536-byte Event.

The Android and Linux receipts agreed on Event ID
`f6624edfa01a9fc62384c4fa04202045448d83006ee4083712f4973758670d61`
and payload SHA-256
`63ffed0d4ba612843004b0086f4750130840a41bdce3db7458c8e3af3e964c89`.
The Android process remained alive after completion and the system crash report
contained no new entry.

## Source, artifacts, and platform

| Field | Observation |
| --- | --- |
| Validated source commit | signed `ff1dcc05f909a4d25c09c264326a5bdbd668d80d` |
| Android debug APK SHA-256 | `6dbbef87a5c144994878cd7cb110400543fabbf3b34652f1eb47c95f354a88ca` |
| Linux listener SHA-256 | `04b8d22dabec949c63fb2aa0fa1fa316d226816cd99f7a2b057683ad56d3d4fe` |
| Sanitized Linux log SHA-256 | `a775fbcd967837c2c147f86fa9b9898847fafd816caf1a025868a95ec1440162` |
| Local Android completion hierarchy SHA-256 | `9660058aeeb19820d51e7596851c82f0c4adfb28cc74746100d852b2b4f49c73` |
| Android device | Pixel 9 Pro XL; Android 17; 2026-10-05 security patch; ARM64 |
| Linux host | x86-64; Linux 7.0.0-42-generic; BlueZ 5.85 |
| Linux controller | Realtek USB Bluetooth Radio `0bda:5852`; public identity |
| Carrier | LE L2CAP CoC; dynamic PSM 128; exact random Pixel peer address |

The APK was rebuilt after the dedicated native preparation-worker change. The
later commit operation changed documentation and repository metadata but not
the production inputs used by that APK. Exact Bluetooth addresses, mission
identities, device serial, bundles, tokens, state, and raw UI hierarchy are
intentionally excluded from the repository.

## Manual acceptance receipts

Linux reported one offered, fetched, and durably inserted Android Event with
zero duplicates. Its `BTLE_RING1_EVENT` line contained the exact text above and
the Event ID and payload digest recorded in the outcome. The final Linux receipt
reported:

- semantic version 9;
- transfer profiles `[2, 1, 1, 5, 1]` and canonical digest
  `ace5ad78fa87203940221abc2a906144bfb0cad74fcafc5089b575971d63596f`;
- one Event entry and 10,564 Event-page bytes received;
- one Event entry and 76,015 Event-page bytes sent;
- directional packet bounds of 65,535 bytes send and 672 bytes receive;
- the retained Event larger than the directional packet bound; and
- profile and Event validation true.

Android independently reported the same semantic version, profiles, canonical
profile digest, Event ID, and payload digest; expected-peer and digest matches;
one outbound Event entry; one received Event entry and durable insert; the
65,536-byte Event larger than its receive packet bound; and no Blob work.

## Stack correction exercised

An earlier clean app attempt aborted while full local node/store preparation ran
on an Android JVM executor thread. The symbolized path showed stack exhaustion
inside the semantic-table audit. Linux normally gives this full-node path an
8 MiB stack, while the Android executor stack was smaller.

The validated APK runs that preparation on one joined native worker with a
fixed 8 MiB stack. One active preparation bounds the reservation to one worker,
and the value does not scale with Event input. This physical run establishes
sufficiency for this exact fresh-state success path; 8 MiB is a conservative
repository-established bound, not a measured minimum or protocol field. It does
not establish hard preemption of a blocked syscall, low-memory behavior, or
universal stack sufficiency.

## Claim boundary

The Linux controller was already warm through an unrelated mouse connection.
As documented in the separate early-ACL diagnostic, that changes the observed
ordering race on this controller/kernel combination but is not an operational
workaround. This run therefore does not qualify unattended cold Android
initiation. Cold qualification remains open for a corrected kernel or an
unaffected controller.

This single foreground run also does not establish background execution,
discovery, address-privacy automation, retry/soak behavior, multi-peer use,
performance thresholds, broad hardware support, or production readiness. It
establishes only that the exact evaluated warm-state stack carried matching
protected v9 Events in both directions and rendered the Android text Event in
the Linux terminal without a protocol change or IP fallback.
