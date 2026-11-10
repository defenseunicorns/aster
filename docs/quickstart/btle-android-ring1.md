# Android-to-Linux BTLE text Event validation

This runbook sends a short text Event from a foreground Android evaluator to a
fixed Linux listener over LE L2CAP CoC. Linux prints the authenticated text,
Event ID, and digest; Android also receives Linux's retained 65,536-byte Event.
It is evaluation-only: no discovery, background service, IP fallback, pairing
authority, support row, requirement credit, or production claim.

## Acceptance sequence

1. Build the Linux harness and Android APK from the same source tree; record the
   source commit and SHA-256 of both artifacts.
2. Create a fresh two-node lab. Publish the Linux 65,536-byte Event while no
   peer is configured, then stop the local agent.
3. Clean-install or clear the Android app, import only the Android mission
   bundle, and enter a unique text message of at most 1,024 UTF-8 bytes.
4. Resolve the phone's current LE address/type on Linux. Start the exact-address
   Linux listener, press **Send and validate**, and keep the app foregrounded.
5. Accept only matching Android/Linux receipts and the exact terminal-safe text
   line described below.
6. Retain sanitized evidence, then remove the bundle, app data, and lab.

## Prerequisites

- Linux with a BlueZ-visible LE controller and an Android API 29+ arm64 device.
- JDK 17, Gradle 9.6.0, Android SDK 37, NDK 28.2.13676358, Platform Tools, and
  Rust target `aarch64-linux-android`.
- One Linux and one Android mission bundle from the same evaluation authority,
  authorized for `mesh.messages` in `demo/playground`.
- One LE PSM from 128 through 255; examples use 128.
- No Aster IP contact between these peers.

The listener requires the exact current phone address and address type. If a
rotating address cannot be observed and held for the attempt, this fixed-locator
profile is blocked; do not weaken it to wildcard admission.

The evaluated Realtek/Linux stack has a cold-controller race in which ACL data
can arrive before HCI Connection Complete and be discarded. An unrelated mouse
made the path warm during diagnosis, but that is not an operational workaround.
Treat success on that stack as warm-state evidence and repeat cold qualification
on a corrected kernel or unaffected controller.

## Build and create a disposable lab

From the repository root:

```sh
mise install
cargo test -p aster-ble-linux --bin aster-btle-ring1 --no-fail-fast
cargo build --locked \
  -p aster-node -p aster-agent -p asterctl -p aster-ble-linux \
  --bin aster --bin aster-agent --bin asterctl --bin aster-btle-ring1

ASTER_BTLE_LAB="$(mktemp -d)"
chmod 700 "$ASTER_BTLE_LAB"
./target/debug/aster playground-init --nodes 2 --root "$ASTER_BTLE_LAB/mesh" \
  | tee "$ASTER_BTLE_LAB/provisioning.log"
```

Node 0 is Linux and node 1 is Android. Record their `mission_id` values:

```text
LINUX_MISSION_ID=<node-0 mission_id>
ANDROID_MISSION_ID=<node-1 mission_id>
```

The bundles are:

```text
<lab>/mesh/node-0/mission.unprotected-reference.bundle
<lab>/mesh/node-1/mission.unprotected-reference.bundle
```

They are disposable plaintext credentials. Keep the lab owner-only and never
commit or retain the bundles.

## Publish the Linux Event before contact

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

After `AGENT status=ready` appears:

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

Do not start the BTLE listener until the agent has released the state. This
receipt proves local durability, not peer delivery.

## Build and install Android

```sh
rustup target add aarch64-linux-android
cd examples/android-btle-ring1
gradle --version
gradle :app:testDebugUnitTest :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
cd ../..

adb push \
  "$ASTER_BTLE_LAB/mesh/node-1/mission.unprotected-reference.bundle" \
  /sdcard/Download/aster-android-ring1.bundle
```

`gradle --version` must report Gradle 9.6.0 on JDK 17. Set `ANDROID_HOME` or
`ANDROID_SDK_ROOT` to SDK 37 with NDK 28.2.13676358. Build output stays under
`app/build/` and must not be committed.

## Configure the radio and form

Record source commit, artifact hashes, Android build/device, Linux kernel,
BlueZ, controller, addresses/types, and PSM. Power/configure the controller
using the host procedure; Aster does not power it.

```text
LINUX_ADAPTER=hci0
LINUX_BT_ADDRESS=<Linux controller address>
LINUX_BT_ADDRESS_TYPE=public|random
ANDROID_BT_ADDRESS=<Android address observed by Linux>
ANDROID_BT_ADDRESS_TYPE=public|random
PSM=128
```

Open **Aster BTLE Ring-1** and enter:

- a non-empty message of at most 1,024 UTF-8 bytes;
- Linux Bluetooth address and decimal PSM 128;
- `LINUX_MISSION_ID`; and
- `aster-android-ring1.bundle` through the document picker.

Wait for the bundle copy and do not press **Send and validate** yet.

## Run the contact

The listener has a 30-second open deadline:

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

Immediately press **Send and validate**. If the deadline expires, start a fresh
listener and app attempt; never reuse the timed-out stream.

## Verify

Android must report `complete`, a non-empty publication ID, a 64-hex payload
digest, positive outbound Event count, semantic 9, profiles `2,1,1,5,1`, profile
digest and peer matches, one received/durably inserted Event,
`larger_than_rx=true`, and `no_blob=true`.

Linux must report:

- one fetched and inserted Android Event with zero duplicates;
- `BTLE_RING1 status=complete` with semantic/profile and Event validation true;
- one large Event sent; and
- exactly one line matching:

```text
BTLE_RING1_EVENT status=received publisher=<ANDROID_MISSION_ID> sequence=<n> id=<event-id> payload_sha256=<sha256> text="<entered text>"
```

The Linux Event ID and digest must equal Android's publication receipt, and the
rendered text must preserve the entered UTF-8 bytes under terminal-safe JSON
escaping. If prior unavailable attempts left a bounded backlog, require zero
remaining, deferred-lane, and unscheduled work and compare the greatest newly
inserted sequence with the current Android receipt.

Retain only the source commit, artifact hashes, platform/controller versions,
address types/PSM, sanitized Linux log, and Android screenshot or UI hierarchy.
Do not retain credentials, state, payloads, APKs, raw device logs, addresses,
mission IDs, or device serials in the repository.

## Clean up and claim boundary

```sh
adb uninstall org.defenseunicorns.aster.btlering1
adb shell rm /sdcard/Download/aster-android-ring1.bundle
rm -r -- "$ASTER_BTLE_LAB"
```

The retained
[Android/Linux physical summary](../validation/evidence/2026-11-09-android-linux-btle-text-event-validation.md)
records the exact warm-state Pixel/Linux result and cold-controller limitation.
This run does not establish background operation, discovery, pairing authority,
reconnection policy, controller hot-plug, State/Record/Blob transfer, automatic
selection/fallback, packaging, performance, scale, broad interoperability, or
production readiness.
