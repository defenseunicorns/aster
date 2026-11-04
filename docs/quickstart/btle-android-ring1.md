# Android-to-Linux BTLE Ring-1 Event validation

This evaluation path runs one foreground Android initiator against the fixed-role
Linux Ring-1 listener over an LE L2CAP credit-based channel. It is intended to
produce cross-platform engineering evidence for one protected semantic-v9 Event.
It is not a production app, daemon, supported transport, or requirement-credit
path.

The Android app does not scan, advertise, use GATT, request Internet access, or
select a fallback carrier. The Linux harness and Android native library start the
transport-neutral Aster runtime in-process. Pairing and Bluetooth link encryption
grant no Aster authority; the mission handshake authenticates the expected
mission node ID before inventory.

On each attempt, the native validator creates or replays its private durable
exact `Consume` subscription for `mesh.messages` at `demo/playground` before
admitting the BTLE contact. A fresh app state therefore needs no separate
subscription command. This fixed selector is an evaluation implementation
detail, not a semantic-v9 field or a production subscription UX.

## Fixed topology and prerequisites

- Android is the initiator; Linux is the listener.
- Use one Linux host with a BlueZ-visible LE controller and one Android API 29+
  arm64 device whose current Bluetooth address and address type can be supplied
  to the fixed Linux harness.
- The Android build is pinned to JDK 17, Gradle 9.6.0, Android SDK 37, Android
  NDK 28.2.13676358, and the Rust `aarch64-linux-android` target.
- The current native build script supports the NDK `linux-x86_64` or
  `darwin-x86_64` prebuilt layout. SDK Build Tools and Platform Tools (`adb`)
  are also required.
- The Linux and Android nodes need separate unprotected-reference mission bundles
  issued by the same evaluation authority and authorized for one common Event
  topic and scope.
- Choose one LE PSM from 128 through 255. The examples below use 128 (`0x80`).
- No Aster IP contact may be configured between these two mission peers. The
  commands below publish through a peerless, loopback-bound Linux agent, stop it,
  and then start the BTLE-only harness.

The initial Linux driver validates an exact peer Bluetooth address. If the phone
exposes only a rotating address that the operator cannot resolve and hold for the
attempt, this profile is blocked on that device. Do not weaken the listener to a
wildcard peer. Record the observed address and whether it is public or random.

## Build the Linux tools and create disposable identities

Run from the repository root on Linux:

```sh
mise install
cargo build --locked \
  -p aster-node -p aster-agent -p asterctl -p aster-ble-linux \
  --bin aster --bin aster-agent --bin asterctl --bin aster-btle-ring1

ASTER_BTLE_LAB="$(mktemp -d)"
chmod 700 "$ASTER_BTLE_LAB"
./target/debug/aster playground-init --nodes 2 --root "$ASTER_BTLE_LAB/mesh" \
  | tee "$ASTER_BTLE_LAB/provisioning.log"
```

Retain the two `PLAYGROUND_NODE` lines. In this guide, node 0 is Linux and node
1 is Android:

```text
LINUX_MISSION_ID=<node-0 mission_id>
ANDROID_MISSION_ID=<node-1 mission_id>
```

The relevant bundle paths are:

```text
<lab>/mesh/node-0/mission.unprotected-reference.bundle
<lab>/mesh/node-1/mission.unprotected-reference.bundle
```

These are disposable plaintext test credentials. Keep the lab directory
owner-only, do not commit it, and remove every copied bundle after the run.

## Publish one Event while Linux has no peer

Create a 65,536-byte payload. This is larger than the app's accepted maximum LE
packet size, so the protected Event page must span the Android receive packet
size rather than relying on a typical controller MTU.

```sh
dd if=/dev/zero of="$ASTER_BTLE_LAB/event.bin" bs=65536 count=1
openssl rand -hex 32 > "$ASTER_BTLE_LAB/client.token"
chmod 600 "$ASTER_BTLE_LAB/client.token"

./target/debug/asterctl publication-init \
  --journal "$ASTER_BTLE_LAB/publication.redb" \
  --client-id android-btle-ring1/v1

./target/debug/aster-agent \
  --state "$ASTER_BTLE_LAB/mesh/node-0" \
  --mesh-bind 127.0.0.1:0 \
  --listen 127.0.0.1:8181 \
  --mission-bundle-unprotected-reference \
    "$ASTER_BTLE_LAB/mesh/node-0/mission.unprotected-reference.bundle" \
  --client-token-file "$ASTER_BTLE_LAB/client.token" \
  > "$ASTER_BTLE_LAB/agent.log" 2>&1 &
ASTER_AGENT_PID=$!
```

After `agent.log` contains `AGENT status=ready`, publish exactly once:

```sh
./target/debug/asterctl --token-file "$ASTER_BTLE_LAB/client.token" --json publish \
  --journal "$ASTER_BTLE_LAB/publication.redb" \
  --client-id android-btle-ring1/v1 \
  --topic mesh.messages --scope demo/playground \
  < "$ASTER_BTLE_LAB/event.bin" \
  | tee "$ASTER_BTLE_LAB/publication.json"

kill -INT "$ASTER_AGENT_PID"
wait "$ASTER_AGENT_PID"
```

Do not start the listener until the agent has stopped cleanly and released the
state. The successful publication is a durable local commit; it does not claim
delivery.

## Build and install the Android validator

Install the pinned tools explicitly; this repository does not download them or
include a Gradle wrapper. Set `ANDROID_HOME` (or `ANDROID_SDK_ROOT`) to the SDK
containing platform 37 and NDK 28.2.13676358, then run:

```sh
rustup target add aarch64-linux-android
cd examples/android-btle-ring1
gradle --version
gradle :app:testDebugUnitTest :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
cd ../..
```

`gradle --version` must report exactly Gradle 9.6.0 and a JDK 17 runtime. The
build fails closed for another Gradle or NDK version. The generated native
library and APK stay under `app/build/` and must not be committed.

Copy the node-1 evaluation bundle to a location available to Android's system
document picker, for example:

```sh
adb push \
  "$ASTER_BTLE_LAB/mesh/node-1/mission.unprotected-reference.bundle" \
  /sdcard/Download/aster-android-ring1.bundle
```

## Prepare the radio and Android form

Record the exact source commit, APK digest, Android build/device, Linux kernel,
BlueZ, controller, addresses, address types, and PSM. Useful read-only Linux
observations include `bluetoothctl show`, `btmgmt -i hci0 info`, and `uname -a`.
Power and configure the controller before starting Aster; the harness never
powers a controller implicitly.

Set the values observed for the selected devices:

```text
LINUX_ADAPTER=hci0
LINUX_BT_ADDRESS=<Linux controller address>
LINUX_BT_ADDRESS_TYPE=public|random
ANDROID_BT_ADDRESS=<Android address observed by Linux>
ANDROID_BT_ADDRESS_TYPE=public|random
PSM=128
```

Open **Aster BTLE Ring-1** before starting the listener and enter:

- Linux Bluetooth address: `LINUX_BT_ADDRESS`;
- LE PSM: decimal `128`;
- expected Linux mission node ID: `LINUX_MISSION_ID`; and
- mission bundle: select `aster-android-ring1.bundle` through the picker and
  wait for the copy to complete.

Do not press **Connect and validate** yet.

## Start the listener and connect within 30 seconds

The fixed listener's platform-open deadline is 30 seconds. Start it in a second
terminal only after the Android form is ready:

```sh
./target/debug/aster-btle-ring1 \
  --role listener \
  --adapter "$LINUX_ADAPTER" \
  --local-address "$LINUX_BT_ADDRESS" \
  --local-address-type "$LINUX_BT_ADDRESS_TYPE" \
  --peer-address "$ANDROID_BT_ADDRESS" \
  --peer-address-type "$ANDROID_BT_ADDRESS_TYPE" \
  --psm "$PSM" \
  --state "$ASTER_BTLE_LAB/mesh/node-0" \
  --mission-bundle \
    "$ASTER_BTLE_LAB/mesh/node-0/mission.unprotected-reference.bundle" \
  --mission-peer "$ANDROID_MISSION_ID" \
  --require-event-larger-than-mtu yes \
  2>&1 | tee "$ASTER_BTLE_LAB/linux-ring1.log"
```

Promptly press **Connect and validate** and keep the Activity in the foreground.
If the listener reaches its deadline first, restart it and make a fresh app
attempt; a timed-out stream is never reused. The expected progression is:

```text
ready -> connecting -> carrier connected -> authenticating -> reconciling -> complete
```

A valid Android completion must report semantic 9, profiles `2,1,1,5,1`, a
64-hex-character canonical profile digest, `peer_match=true`,
`digest_match=true`, one received Event entry, one durable insert,
`larger_than_rx=true`, and `no_blob=true`. The Linux terminal must independently
print `BTLE_RING1 status=complete`, the same semantic/profile result, one Event
sent, no profile drift, and `event_validation=true`.

Retain the Linux log and an Android screenshot or UI hierarchy showing the
bounded terminal summary. Also retain `git rev-parse HEAD` and
`sha256sum examples/android-btle-ring1/app/build/outputs/apk/debug/app-debug.apk`
with the environment observations. These artifacts are evaluation evidence
only; do not add credentials, state, payloads, APKs, or raw device logs to the
repository.

## Connection-recovery diagnostic

Run this as an alternative fresh setup, not after the successful acceptance run
above. Create a new disposable two-node lab and pre-published Event, clear the
app's evaluation data with
`adb shell pm clear org.defenseunicorns.aster.btlering1`, reopen it, and select
the new node-1 bundle. On that setup's first contact, interrupt only while the
app is still `connecting` or `authenticating`, before it enters `reconciling`.
Restart the Linux listener and make a fresh app attempt. That retry becomes the
setup's first successful delivery and must produce the normal one-insert
acceptance fields.

This UI is not sufficient to prove deduplication across an arbitrary
interruption. Cancellation can race a durable insertion before the terminal
callback; a later contact can then correctly insert zero rows, while this
validator intentionally requires one new insert and reports failure. If the
interruption boundary is unknown, discard the evaluation state and reprovision
before repeating the one-Event acceptance run. A deduplication claim requires
separate retained store instrumentation and is outside this quickstart.

## Cancel and clean up

The **Cancel** button, Activity destruction, a carrier failure, or the bounded
deadline closes the Bluetooth socket and native session. The failed stream is
never reused; start a fresh listener and a fresh app attempt.

After retaining only sanitized evidence, uninstall the app, remove the shared
bundle copy, and delete the exact disposable lab directory:

```sh
adb uninstall org.defenseunicorns.aster.btlering1
adb shell rm /sdcard/Download/aster-android-ring1.bundle
printf 'remove disposable lab: %s\n' "$ASTER_BTLE_LAB"
rm -r -- "$ASTER_BTLE_LAB"
```

## What this does not establish

This run does not establish production readiness, background operation,
discovery, pairing authority, rotating-address support, reconnection policy,
controller hot-plug, State/Record/Blob transfer, transport selection or
fallback, all-class scheduling, packaging/support status, performance, scale,
or independent interoperability. Until the APK build and physical run succeed
and both terminal receipts are retained, the Android path remains an unverified
evaluation scaffold.
