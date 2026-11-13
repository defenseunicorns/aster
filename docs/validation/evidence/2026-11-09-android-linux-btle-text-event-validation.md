# Android/Linux BTLE physical validation summary — 2026-11-06 and 2026-11-09

Status: **bounded foreground warm-state interoperability evidence; no cold-host
qualification, Android support, requirement credit, or production authorization**.

## Hardware and source

- Pixel 9 Pro XL; Android 17/API 37; ARM64.
- x86-64 Linux `7.0.0-42-generic`; BlueZ 5.85.
- Realtek USB Bluetooth Radio `0bda:5852`; LE L2CAP CoC PSM 128.
- Final text-Event source commit
  `ff1dcc05f909a4d25c09c264326a5bdbd668d80d`;
  APK SHA-256
  `6dbbef87a5c144994878cd7cb110400543fabbf3b34652f1eb47c95f354a88ca`;
  Linux listener SHA-256
  `04b8d22dabec949c63fb2aa0fa1fa316d226816cd99f7a2b057683ad56d3d4fe`.

The retained commit predates the repository's reduction from local dependency
forks to stock BlueR and HMAC. This evidence therefore does not qualify the
current stock BlueR lifecycle or cleanup behavior, including BlueZ
unregistration, RF cessation, or bounded upstream D-Bus ingress.

## Physical results

On 2026-11-06, a clean foreground Android validator authenticated the expected
Linux mission peer and durably inserted Linux's retained 65,536-byte Event over
the non-IP semantic-v9 contact. Both sides reported profiles `[2,1,1,5,1]`,
digest parity, one Event, and no Blob attempt.

On 2026-11-09, a clean-installed app durably published the short text
`pixel-final-btle-event-2026-11-09` before carrier availability. Linux
authenticated Android, durably inserted the Event, and printed its terminal-safe
receipt; Android again inserted Linux's 65,536-byte Event. Both sides agreed on
Event ID
`f6624edfa01a9fc62384c4fa04202045448d83006ee4083712f4973758670d61`
and payload SHA-256
`63ffed0d4ba612843004b0086f4750130840a41bdce3db7458c8e3af3e964c89`.
The observed directional packet bounds were 65,535 and 672 bytes, so the large
Event crossed the smaller bound. The validated app used one 8 MiB native
preparation-worker stack after an earlier smaller JVM-executor stack overflow;
that value is sufficient for this path, not a universal minimum.

## Cold-controller limitation

A separate 2026-11-09 packet trace on the same host showed the cold failure:
inbound ATT and CoC requests arrived about 1.3 ms before HCI LE Enhanced
Connection Complete and were discarded by Linux. With an unrelated mouse
connection already active, Connection Complete preceded the requests and the
same Aster path succeeded. The mouse is a diagnostic trigger, not an operational
workaround.

This exact controller/kernel combination is not qualified for unattended cold
Android initiation. Qualification requires an accepted early-ACL kernel fix or
an unaffected controller and repeated cold contacts with durable application
receipt. Aster adds no controller reset, warm-up dependency, or protocol
fallback.

## Boundary

These runs establish only exact-stack foreground, warm-state, bidirectional
Event interoperability and Linux terminal rendering. They do not establish
background operation, discovery, retry/soak behavior, broad hardware support,
performance thresholds, other data classes, packaging, or production readiness.
