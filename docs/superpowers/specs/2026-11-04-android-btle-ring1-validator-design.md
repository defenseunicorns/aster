# Android BTLE Ring-1 Validator Design

- Status: proposed implementation design
- Scope: foreground Android-to-Linux semantic-v9 Event validation
- Product claim: none; evaluation tooling only

## Outcome

Add a minimal Android application that proves one real protected Aster Event can
move between an Android phone and the existing Linux Ring-1 harness over a
non-IP LE L2CAP credit-based channel. The run must retain the existing mission,
semantic-v9, transfer-profile, Event, and durable-store bytes and rules.

Success means the Android side reports:

- the Bluetooth socket connected through the public Android LE CoC API;
- the expected Linux mission identity authenticated before inventory;
- semantic version 9 and transfer profiles `[2, 1, 1, 5, 1]` with the canonical
  digest;
- exactly one Event page entry received and durably inserted;
- no Blob attempt; and
- Event bytes larger than the Android receive packet size reported for the
  connected socket.

This is cross-platform engineering evidence. It does not add requirement
credit, production support, discovery, background operation, or a new protocol.

## Fixed evaluation topology

The Android application is the fixed initiator. The Linux process is the
existing fixed listener and has one protected Event durably published before
contact. The operator supplies:

- the current Linux Bluetooth address;
- the fixed Ring-1 dynamic-range PSM;
- an Android mission bundle selected with the system document picker; and
- the exact expected Linux mission node ID.

The app copies the selected mission bundle into its private files directory and
stores all Aster state under a private application directory. It neither scans
nor advertises. It requests only the Bluetooth connect permission needed by the
declared Android version and makes no pairing or link-encryption security claim.

## Onion boundary

The layers remain:

1. **Android UI and lifecycle.** A single foreground Activity owns permission,
   manual configuration, connect/cancel controls, and bounded status display.
2. **Android platform adapter.** Kotlin opens
   `BluetoothDevice.createInsecureL2capChannel(psm)`, records the connected
   socket's maximum transmit and receive packet sizes, and pumps the socket
   streams through one process-local Unix stream socket pair.
3. **Android native adapter.** A narrow JNI library accepts the transferred Unix
   descriptor and immutable run configuration, wraps it as asynchronous byte
   I/O, and constructs the existing `BleL2capContact`.
4. **Transport-neutral Aster node.** The existing mission handshake,
   `OrderedEventContactHandle`, v9 profile negotiation, Event reconciliation,
   authentication, and durable store run unchanged.

The Unix socket pair is an implementation detail of the Android adapter. It is
not a carrier, fallback, authorization signal, durable authority, or protocol
surface. Bluetooth addresses remain unauthenticated transient locator evidence.

## Native API

The JNI surface is deliberately validator-specific and asynchronous:

- `start(config, transferredFd, callback) -> runId`
- `cancel(runId)`

Only one run may be active. `start` validates all string lengths, PSM and packet
sizes, state paths, mission bundle size, and expected node ID before starting a
dedicated Rust runtime thread. The callback returns sanitized phase updates and
one terminal success or failure result. It never returns keys, protected frames,
mission bytes, or raw peer input.

The terminal success value contains the bounded receipt fields required above,
plus sent/received Event page bytes and entries. Rust, not Kotlin, decides
whether the receipt satisfies the exact Ring-1 v9 profile.

## Lifecycle and failure handling

Leaving the Activity, pressing Cancel, permission revocation, Bluetooth-off,
socket failure, native failure, or the 30-second contact deadline closes both
ends of the bridge and the Bluetooth socket. A failed or cancelled stream is
never reused because its ordered turn position is unknown.

The Activity remains responsive while connect, pumping, and the native session
run on bounded background executors. Rotation does not claim continuity: the
minimal validator locks to portrait and treats process or Activity destruction
as cancellation. Durable Aster state remains available for a later explicit
run, but the Bluetooth attempt and JNI callback state do not.

## User experience

The one screen contains mission-bundle selection, Linux address, PSM, expected
mission node ID, `Connect and validate`, and `Cancel`. It shows these ordered
phases:

`ready -> connecting -> carrier connected -> authenticating -> reconciling -> complete`

Completion shows semantic version, profile IDs and digest match, Android
packet sizes, Event entry/byte counts, durable insertion count, and the
larger-than-receive-packet assertion. Failures use bounded categories such as
permission, configuration, unavailable, timeout, authentication, protocol,
storage, or internal; raw secrets and peer-controlled strings are omitted.

## Verification boundary

Host-side tests cover configuration parsing, one-active-run admission, result
validation, cancellation, and sanitized failure mapping. Existing
`aster-ble-l2cap` tests remain the authority for record framing and hostile
stream behavior. Android JVM tests cover permission decisions, form validation,
phase reduction, and receipt rendering without Bluetooth hardware.

The physical acceptance run uses one Android API 29+ device and one Linux
controller, with IP contact disabled for the peer. It retains app/Linux logs,
APK and Rust source identities, Android/device/controller versions, PSM,
packet-size observations, and both terminal receipts. A local build without an
Android SDK/NDK can review and run portable Rust tests but cannot create a valid
APK or physical evidence.

## Explicit exclusions

Scanning, advertising, dynamic PSM discovery, Android listener mode, background
service operation, reconnection policy, pairing UX, controller management,
State, Record, Blob execution, GATT, transport selection or fallback, automatic
carrier selection, production packaging, and support-registry admission remain
out of scope.
