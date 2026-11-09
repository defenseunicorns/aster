# Android BTLE text Event design

## Intent

Complete the originally requested human-visible Android validation path: a user
enters a short text message in the foreground Android evaluator, presses one
action, and sees that exact source-authenticated Event printed by the Linux
Ring-1 terminal after transfer over BTLE.

## Goals

- Publish the entered text durably on Android before carrier availability is
  required.
- Reuse the selected numbered Event API, semantic v9, and the existing
  transport-neutral ordered contact.
- Transfer the Event Android to Linux while retaining the existing
  Linux-to-Android Event validation in the same contact.
- Print the received text safely and visibly in the Linux terminal with the
  authenticated publisher, Event sequence, Event ID, and payload digest.
- Prove exact payload equality with automated tests and one physical Pixel to
  Linux run.

## Non-goals

- No chat UI, retained message list, background Android service, discovery,
  automatic reconnect, or multi-message live session.
- No new Aster protocol field, semantic version, transport fallback, delivery
  receipt, or generic transport lifecycle.
- No production Android support or expansion of the Ring-1 evidence boundary.

## Constraints

- One action publishes one non-empty UTF-8 string of at most 1,024 encoded
  bytes. The exact bytes are preserved; whitespace and Unicode are not
  normalized.
- Topic remains `mesh.messages`; scope remains `demo/playground`; the logical
  key is the fixed evaluation value `android-btle-ring1/text/v1`.
- Android uses a private numbered-publication journal under its existing state
  directory. A dedicated foreground-operation worker invokes a synchronous,
  natively cancellable local-preparation step before requesting Bluetooth
  permission, checking adapter availability, or creating a socket. Publication
  and journal acknowledgement therefore complete before any carrier attempt,
  so a missing carrier never undoes local publication.
- Local preparation has a 30-second foreground deadline covering native node
  startup, journal/store work, publication, subscription, and shutdown. The
  value matches the existing maximum foreground adapter operation, giving the
  operator one consistent retry interval without adding another lifecycle
  class. Java and native code enforce the same bound, and cancellation is
  retained across queued-worker/native-registration races. This is Android
  implementation policy, not a protocol timeout.
- Full node/store preparation runs on a dedicated native worker with an 8 MiB
  stack. The bound matches the conventional Linux and existing native full-node
  test stack after the smaller Android JVM executor stack overflowed on the
  Pixel. It is a conservative implementation bound, not a measured minimum or
  protocol field. The single active preparation permits only one fixed
  per-operation virtual-memory reservation; it does not scale with message
  input.
- The existing 65,536-byte Linux Event remains part of the validation contact,
  preserving the negotiated-MTU observation and prior Linux-to-Android path.
- If the operator changes the message after an unavailable carrier, the next
  contact may reconcile a bounded backlog of retained Android Events. Android
  therefore requires positive outbound Event evidence rather than an exact
  count of one. Success additionally requires zero remaining, deferred-lane,
  and unscheduled Event work. Linux snapshots the selector before contact and
  prints the greatest newly inserted sequence only after those zero-work
  checks, so the printed Event corresponds to the latest retained message. An
  incomplete bounded contact retains progress but reports failure for retry.
- Linux creates an exact durable Consume subscription before opening the
  contact, queries only Events from the configured Android mission identity,
  and selects the greatest Event sequence for the fixed selector.
- Terminal text is JSON-escaped before output. Control characters cannot forge
  terminal fields or log lines.
- Errors remain categorized and sanitized; user text is emitted only by the
  intentional successful terminal Event line.

## Approaches considered

1. **Publish through the in-process selected Event API before contact
   (selected).** This reuses durable numbered publication, keeps the app
   offline-first, and exercises the same runtime as every other carrier.
2. Run a local ConnectRPC agent inside Android. This adds a second process/API
   boundary and packaging complexity with no validation benefit.
3. Carry the text as adapter metadata or a new handshake field. This would
   incorrectly turn an application Event into transport protocol and violate
   the no-v10/no-protocol-change boundary.

## User flow

The form adds one `Message` input. The existing button becomes **Send and
validate**. On press, the app validates the form, durably publishes the text
through the in-process native preparation boundary, then requests any required
Bluetooth permission and opens the LE CoC. Cancellation is routed to the exact
active local preparation or contact operation. The contact then
runs the bidirectional v9 Event contact. Android reports
the locally committed Event ID/digest and contact counters. Linux prints one
line shaped as:

```text
BTLE_RING1_EVENT status=received publisher=<node-id> sequence=<n> id=<event-id> payload_sha256=<digest> text="<JSON-escaped text>"
```

The terminal line is the human-visible cross-device result. It is evaluation
output, not a remote delivery receipt exposed to Android.

## Acceptance

- Empty input and UTF-8 payloads over 1,024 bytes fail before Bluetooth work.
- Quotes, newlines, controls, and non-ASCII text survive exact payload transfer
  and remain one safely escaped terminal line.
- Android local publication is durable before contact and uses monotonically
  numbered application operations across runs.
- A clean bidirectional contact reports one Android Event sent and the existing
  large Linux Event received; Linux queries and prints the exact Android text.
- Replaying contact does not create a second semantic Event.
- The Android/JVM, Android/Rust, Linux harness, formatting, Clippy, and relevant
  integration tests pass before physical validation.
