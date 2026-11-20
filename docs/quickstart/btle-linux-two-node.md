# Two-node Linux BTLE Event evaluation

Clean Room — Privileged

This procedure evaluates the packaged Linux Event path with rostered discovery,
automatic controller selection, and no configured IP carrier. It produces
bounded lab evidence for one exact platform row; it does not create a support
row or production authorization.

## Initial reference profile

| Component | Required value |
| --- | --- |
| Hardware | Two ARM64 Raspberry Pi Compute Module 4 devices with Broadcom BCM4345C0 controllers |
| OS | Debian 13, 64-bit |
| Kernel | Distribution kernel containing the CVE-2026-72333 fix; retained reference `6.18.60+rpt-rpi-v8` |
| BlueZ | `5.82` |
| Controller firmware | Broadcom build `0382` |
| Aster | The same signed source commit and arm64 Debian package bytes on both nodes |
| Topology | One disposable two-member mission; each node names only the other mission `NodeId` in `btle.peer` |
| Carrier | Rostered `BleL2capV1`; `mesh.peers` empty, no relay, and loopback-only mesh bind |
| Data | One precommitted 65,536-byte Event and one exact durable receiver subscription |

This is an initial reproducibility target, not a permanent hardware allowlist.
Additional hardware becomes a separate evidence row after the same procedure
passes. The Orin/BlueZ 5.72 result is a negative software row, not a hardware
exclusion: that BlueZ release omits the production roster ServiceData on
receive. Repeat rostered discovery there only after upgrading to BlueZ 5.76 or
newer.

Rostered mode is required because it covers the production discovery path.
Fixed mode may isolate radio, kernel, or handshake faults, but fixed-mode
success does not pass this procedure.

## Prerequisites and clean-node preflight

The staging host needs the reviewed `aster` CLI from the same signed source
commit as the node packages. Each node needs the reviewed arm64 package,
`bluez=5.82` (including `bluetoothctl`), `curl`, `openssl`, and `python3`.
Install no alternate Aster build or Bluetooth supervisor during the run.

The package creates an empty `/var/lib/aster-agent` directory. On each freshly
imaged node, keep the service stopped and require that directory to remain
empty and that every final authority or evaluation path is absent:

```console
set -euo pipefail
sudo systemctl stop aster-agent.service
test "$(systemctl show --property=ActiveState --value aster-agent.service)" = inactive
test "$(systemctl show --property=SubState --value aster-agent.service)" = dead
test "$(systemctl show --property=MainPID --value aster-agent.service)" = 0
test "$(systemctl show --property=ControlPID --value aster-agent.service)" = 0
sudo test ! -L /var/lib/aster-agent
sudo test "$(stat -c '%U:%G:%a' /var/lib/aster-agent)" = aster:aster:700
test -z "$(sudo find /var/lib/aster-agent -mindepth 1 -maxdepth 1 -print -quit)"
for path in \
  /etc/aster/agent.json \
  /etc/aster/agent-credentials/client-token \
  /etc/aster/agent-credentials/mission-reference \
  /etc/aster/btle-evaluation-provider-operations \
  /etc/aster/btle-evaluation-provider-reference \
  /etc/credstore.encrypted/aster-btle-roster \
  /var/lib/aster-btle-evaluation \
  /usr/local/libexec/aster-btle-evaluation-receiver.py; do
  if sudo test -e "$path" || sudo test -L "$path"; then
    printf 'refusing existing path: %s\n' "$path" >&2
    exit 1
  fi
done

refuse_stage_residue() {
  local directory=$1 pattern=$2 found
  test ! -d "$directory" || {
    found=$(sudo find "$directory" -maxdepth 1 -name "$pattern" -print -quit)
    if test -n "$found"; then
      printf 'refusing staged path: %s\n' "$found" >&2
      exit 1
    fi
  }
}
refuse_stage_residue /var/lib/aster-agent '.identity.key.*'
refuse_stage_residue /etc/aster '.btle-provider-operations.*'
refuse_stage_residue /etc/aster '.btle-install-result.*'
refuse_stage_residue /etc/aster '.btle-provider-reference.*'
refuse_stage_residue /etc/aster '.agent.json.*'
refuse_stage_residue /etc/aster/agent-credentials '.mission-reference.*'
refuse_stage_residue /etc/credstore.encrypted '.aster-btle-roster.*'
refuse_stage_residue /usr/local/libexec '.aster-btle-receiver.*'
unset -f refuse_stage_residue
```

Also require that the protected provider has no live reference from an earlier
run. If any check fails, inspect and dispose of the prior run through its
authorized procedure; do not overwrite, rename, or reuse its files.

## Provision two clean nodes

1. Record the signed source commit, package SHA-256 and version, kernel, BlueZ,
   controller, firmware, and driver identity from each node. Verify that both
   nodes installed the same package bytes. Keep the package service stopped.
2. Create one disposable two-member mission on a clean staging host. Run the
   generator once, not once per node:

   ```console
   umask 077
   aster playground-init --nodes 2 --root /tmp/aster-btle-two-node
   ```

   Assign `node-0` to Node A and `node-1` to Node B. Transfer each owner-only
   directory through the lab's approved secure channel. Record each public
   mission `NodeId` privately for the opposite node's configuration.
3. On each node, create the application token exactly as described in
   [operator runbook Step 2](../operator-guide.md#step-2-create-the-application-token).
   Recheck that the final token path is absent immediately before that
   root-only first-install recipe. Do not use the historical fixed-IP
   provisioning script from the earlier two-Pi lab.
4. Install and hand off the protected mission reference with the exact Debian
   arm64 sequence below.
5. Before the state is opened for the first time, install that node's carrier
   identity in its final state directory:

   ```console
   set -euo pipefail
   identity_stage=''
   cleanup_identity_stage() {
     test -z "$identity_stage" || {
       sudo rm -f -- "$identity_stage"
       sudo sync -f /var/lib/aster-agent || true
     }
   }
   abort_identity_stage() {
     trap - EXIT INT TERM HUP
     cleanup_identity_stage || true
     exit "$1"
   }
   trap cleanup_identity_stage EXIT
   trap 'abort_identity_stage 130' INT
   trap 'abort_identity_stage 143' TERM
   trap 'abort_identity_stage 129' HUP
   identity_stage=$(sudo mktemp /var/lib/aster-agent/.identity.key.XXXXXX)
   sudo install -o aster -g aster -m 0600 \
     /owner-only/node-N/identity.key "$identity_stage"
   sudo sync -f "$identity_stage"
   sudo test ! -e /var/lib/aster-agent/identity.key
   sudo ln "$identity_stage" /var/lib/aster-agent/identity.key
   sudo rm -- "$identity_stage"
   sudo sync -f /var/lib/aster-agent
   identity_stage=''
   trap - EXIT INT TERM HUP
   unset -f cleanup_identity_stage abort_identity_stage
   ```

Do not copy an initialized Aster state directory between nodes. Each node must
create its database on its final filesystem path.

### Install and hand off the protected mission reference

This is the concrete Debian 13 arm64 package handoff for this profile. It
applies the shared provider
[install contract](../mvp/raspberry-pi-provider-v2-operations.md#1-install-a-protected-reference)
without relying on the separate Ubuntu annex. Enter one root maintenance shell
with `sudo -i`, run every block in this subsection in that same shell, and
substitute that node's owner-only bundle path. Direct root execution preserves
descriptor 3 for the administration command.

Initialize the host credential key before opening the provider. Never replace
an existing key:

```console
set -euo pipefail
umask 077
test -e /var/lib/systemd/credential.secret || systemd-creds setup
test -s /var/lib/systemd/credential.secret
stat --format='%U:%G %a %n' /var/lib/systemd/credential.secret
```

Allocate and durably retain fresh operation IDs before invoking the provider.
The record is root-only and must not be copied into logs or tickets:

```console
operations_stage=''
cleanup_operations_stage() {
  test -z "$operations_stage" || {
    rm -f -- "$operations_stage"
    sync -f /etc/aster || true
  }
}
abort_operations_stage() {
  trap - EXIT INT TERM HUP
  cleanup_operations_stage || true
  exit "$1"
}
trap cleanup_operations_stage EXIT
trap 'abort_operations_stage 130' INT
trap 'abort_operations_stage 143' TERM
trap 'abort_operations_stage 129' HUP
install_operation=$(openssl rand -hex 32)
load_operation=$(openssl rand -hex 32)
operations_stage=$(mktemp /etc/aster/.btle-provider-operations.XXXXXX)
printf 'INSTALL_OPERATION=%s\nLOAD_OPERATION=%s\n' \
  "$install_operation" "$load_operation" | tee "$operations_stage" >/dev/null
chown root:root "$operations_stage"
chmod 0600 "$operations_stage"
sync -f "$operations_stage"
test ! -e /etc/aster/btle-evaluation-provider-operations
ln "$operations_stage" /etc/aster/btle-evaluation-provider-operations
rm -- "$operations_stage"
sync -f /etc/aster
operations_stage=''
trap - EXIT INT TERM HUP
unset -f cleanup_operations_stage abort_operations_stage
```

Open the exact bundle on descriptor 3, capture the private result, and validate
the complete success line before decoding anything. A nonzero result may have
committed; retain the operation IDs and exact bundle for an exact retry.

```console
bundle=/owner-only/node-N/mission.unprotected-reference.bundle
test -f "$bundle" && test ! -L "$bundle" && test "$(stat -c %a "$bundle")" = 600
admin_result=''
reference_stage=''
reference_record_stage=''
cleanup_provider_stage() {
  exec 3<&- 2>/dev/null || true
  for stage in "$admin_result" "$reference_stage" "$reference_record_stage"; do
    test -z "$stage" || rm -f -- "$stage"
  done
  sync -f /etc/aster || true
  sync -f /etc/aster/agent-credentials || true
}
abort_provider_stage() {
  trap - EXIT INT TERM HUP
  cleanup_provider_stage || true
  exit "$1"
}
trap cleanup_provider_stage EXIT
trap 'abort_provider_stage 130' INT
trap 'abort_provider_stage 143' TERM
trap 'abort_provider_stage 129' HUP
admin_result=$(mktemp /etc/aster/.btle-install-result.XXXXXX)
exec 3< "$bundle"
/usr/sbin/aster-credential-admin install \
  --operation "$install_operation" --load-operation "$load_operation" \
  <&3 > "$admin_result"
exec 3<&-
test "$(wc -l < "$admin_result")" -eq 1
grep -Eq '^INSTALL disposition=(installed|existing) generation=[1-9][0-9]* reference=([0-9a-f]{2})+$' \
  "$admin_result"
reference_hex=$(sed -n 's/^.* reference=//p' "$admin_result")
```

Retain the exact future destruction input in a separate root-only record, then
publish the decoded service reference without replacing an existing file:

```console
reference_record_stage=$(mktemp /etc/aster/.btle-provider-reference.XXXXXX)
printf 'REFERENCE=%s\n' "$reference_hex" | \
  tee "$reference_record_stage" >/dev/null
chown root:root "$reference_record_stage"
chmod 0600 "$reference_record_stage"
sync -f "$reference_record_stage"
test ! -e /etc/aster/btle-evaluation-provider-reference
ln "$reference_record_stage" /etc/aster/btle-evaluation-provider-reference
rm -- "$reference_record_stage"
sync -f /etc/aster
reference_record_stage=''

reference_stage=$(mktemp \
  /etc/aster/agent-credentials/.mission-reference.XXXXXX)
printf '%s' "$reference_hex" | tr 'a-f' 'A-F' | \
  basenc --base16 --decode | tee "$reference_stage" >/dev/null
chown aster:aster "$reference_stage"
chmod 0600 "$reference_stage"
sync -f "$reference_stage"
test ! -e /etc/aster/agent-credentials/mission-reference
ln "$reference_stage" /etc/aster/agent-credentials/mission-reference
rm -- "$reference_stage"
reference_stage=''
sync -f /etc/aster/agent-credentials

rm -- "$admin_result"
sync -f /etc/aster
admin_result=''
unset reference_hex
trap - EXIT INT TERM HUP
unset -f cleanup_provider_stage abort_provider_stage
```

Keep `install_operation` and `load_operation` in the root shell. Substitute the
exact `load_operation` value into the configuration below without printing it.

## Create the disposable roster credential

On a clean staging host, generate one short-lived `ASTRBD02` artifact in an
owner-only directory. Substitute a fresh nonzero 64-hex deployment scope. The
script writes the secret artifact but never prints it.

```console
umask 077
install -d -m 0700 /tmp/aster-btle-roster
python3 - /tmp/aster-btle-roster/roster.plain DEPLOYMENT_SCOPE_ID_HEX64 <<'PY'
import os
import struct
import sys
import time

path, scope_hex = sys.argv[1:]
scope = bytes.fromhex(scope_hex)
if len(scope) != 32 or not any(scope):
    raise SystemExit("deployment scope must be a nonzero 32-byte hex value")
issued = int(time.time()) - 1
artifact = b"".join((
    b"ASTRBD02",
    struct.pack(">Q", 1),
    b"\x01",
    struct.pack(">Q", issued),
    struct.pack(">Q", issued + 21600),
    b"\x00" * 8,
    scope,
    struct.pack(">I", 1),
    os.urandom(32),
))
with open(path, "xb") as stream:
    stream.write(artifact)
os.chmod(path, 0o600)
PY
```

Copy the plaintext to an owner-only temporary path on each node. Reuse the
host key initialized before the provider operation; a missing key now aborts
the run. Verify it and explicitly select host-key encryption:

```console
set -euo pipefail
roster_stage_dir=''
cleanup_roster_stage() {
  test -z "$roster_stage_dir" || {
    sudo rm -f -- "$roster_stage_dir/credential"
    sudo rmdir -- "$roster_stage_dir" 2>/dev/null || true
    sudo sync -f /etc/credstore.encrypted || true
  }
}
abort_roster_stage() {
  trap - EXIT INT TERM HUP
  cleanup_roster_stage || true
  exit "$1"
}
trap cleanup_roster_stage EXIT
trap 'abort_roster_stage 130' INT
trap 'abort_roster_stage 143' TERM
trap 'abort_roster_stage 129' HUP
sudo test -s /var/lib/systemd/credential.secret
sudo stat --format='%U:%G %a %n' /var/lib/systemd/credential.secret
sudo install -d -o root -g root -m 0700 /etc/credstore.encrypted
sudo test ! -e /etc/credstore.encrypted/aster-btle-roster
sudo test ! -L /etc/credstore.encrypted/aster-btle-roster
test -z "$(sudo find /etc/credstore.encrypted -maxdepth 1 \
  -name '.aster-btle-roster.*' -print -quit)"
roster_stage_dir=$(sudo mktemp -d /etc/credstore.encrypted/.aster-btle-roster.XXXXXX)
roster_stage="${roster_stage_dir:?}/credential"
sudo systemd-creds encrypt --with-key=host --name=aster-btle-roster \
  /owner-only/roster.plain "$roster_stage"
sudo chmod 0600 "$roster_stage"
sudo sync -f "$roster_stage"
sudo test ! -e /etc/credstore.encrypted/aster-btle-roster
sudo ln "$roster_stage" /etc/credstore.encrypted/aster-btle-roster
sudo rm -- "$roster_stage"
sudo rmdir -- "$roster_stage_dir"
sudo sync -f /etc/credstore.encrypted
roster_stage_dir=''
trap - EXIT INT TERM HUP
unset roster_stage
unset -f cleanup_roster_stage abort_roster_stage
sudo rm -- /owner-only/roster.plain
```

Record the selected `host` encryption mode and any warning, but never credential
bytes. Host-key encryption on the same unencrypted media does not protect the
roster secret from an offline reader of that media, its backups, or snapshots.

Remove the staging copy after both encrypted credentials are installed. The
six-hour lease bounds one prepared evaluation; it is not a protocol value or a
production rotation interval. Finish and dispose of the run before expiry. If
it expires, destroy the disposable mission and state and begin a fresh run. Do
not replace the sequence-1/generation-1 credential over initialized state; its
durable roster checkpoint correctly rejects that rollback or secret
substitution.

## Install the complete no-IP configuration

Install this complete configuration on each node. Substitute that node's
retained provider load operation, the other node's mission `NodeId`, and the
shared roster deployment scope. There is no controller name, Bluetooth
address, address type, or PSM in production configuration.

```json
{
  "schema_version": 1,
  "state": {"directory": "/var/lib/aster-agent"},
  "application": {"listen": "127.0.0.1:8181"},
  "health": {"listen": "127.0.0.1:8182"},
  "mesh": {
    "bind": "127.0.0.1:0",
    "emission_policy": "normal",
    "sync_interval_ms": 500,
    "blob_interests": [],
    "peers": []
  },
  "btle": {
    "enabled": true,
    "peer": "PEER_MISSION_NODE_ID_HEX64",
    "deployment_scope_id": "DEPLOYMENT_SCOPE_ID_HEX64",
    "policy": "rostered",
    "emission_policy": "normal",
    "priority": 100,
    "credential": "aster-btle-roster"
  },
  "credentials": {
    "client_token_file": "/etc/aster/agent-credentials/client-token",
    "mission_secret_ref_file": "/etc/aster/agent-credentials/mission-reference",
    "mission_load_id": "LOAD_OPERATION_ID_HEX64"
  },
  "storage": {
    "max_items": 10000,
    "max_payload_bytes": 67108864,
    "blob_depot": {
      "max_bytes": 67108864,
      "max_chunks": 4096,
      "max_variants": 64
    },
    "operations": {
      "max_records": 1000000,
      "max_logical_bytes": 201326592,
      "emergency_reserve": 10000
    }
  },
  "limits": {
    "max_connections": 64,
    "max_unauthenticated_connections": 8,
    "max_header_bytes": 16384,
    "first_authentication_timeout_ms": 5000,
    "max_in_flight_requests": 64,
    "shutdown_grace_ms": 30000
  }
}
```

`priority: 100` is only a stable nonzero local evaluation value. With no IP
peer it cannot choose between carriers and has no protocol or support meaning.
Save the substituted JSON as owner-only `/owner-only/agent.json`. Publish it
without replacing an existing configuration, then validate it without starting
the service:

```console
set -euo pipefail
config_stage=''
cleanup_config_stage() {
  test -z "$config_stage" || {
    sudo rm -f -- "$config_stage"
    sudo sync -f /etc/aster || true
  }
}
abort_config_stage() {
  trap - EXIT INT TERM HUP
  cleanup_config_stage || true
  exit "$1"
}
trap cleanup_config_stage EXIT
trap 'abort_config_stage 130' INT
trap 'abort_config_stage 143' TERM
trap 'abort_config_stage 129' HUP
config_stage=$(sudo mktemp /etc/aster/.agent.json.XXXXXX)
sudo install -o root -g aster -m 0640 /owner-only/agent.json "$config_stage"
sudo -u aster /usr/bin/aster-agent --check-config "$config_stage"
sudo sync -f "$config_stage"
sudo test ! -e /etc/aster/agent.json
sudo ln "$config_stage" /etc/aster/agent.json
sudo rm -- "$config_stage"
sudo sync -f /etc/aster
config_stage=''
trap - EXIT INT TERM HUP
unset -f cleanup_config_stage abort_config_stage
sudo -u aster /usr/bin/aster-agent --check-config /etc/aster/agent.json
```

## Install bounded observation helpers

Run the following Bash definitions in one privileged maintenance shell on each
node. Every status assertion is restricted to records after a fresh journal
cursor and to the current systemd invocation.

```bash
set -euo pipefail

capture_cursor() {
  journalctl --lines=0 --show-cursor --no-pager | sed -n 's/^-- cursor: //p'
}

wait_ready() {
  for _ in $(seq 1 30); do
    if curl --fail --silent --noproxy '*' --max-time 2 --output /dev/null \
      http://127.0.0.1:8182/readyz; then
      return 0
    fi
    sleep 1
  done
  return 1
}

remember_invocation() {
  invocation=$(systemctl show --property=InvocationID --value aster-agent.service)
  restart_count=$(systemctl show --property=NRestarts --value aster-agent.service)
  test -n "$invocation" && test -n "$restart_count"
}

assert_same_invocation() {
  test "$invocation" = \
    "$(systemctl show --property=InvocationID --value aster-agent.service)"
  test "$restart_count" = \
    "$(systemctl show --property=NRestarts --value aster-agent.service)"
}

wait_btle_status() {
  local cursor=$1 invocation=$2 availability=$3 reason=$4 record
  for _ in $(seq 1 30); do
    record=$(journalctl --unit=aster-agent.service --boot --output=cat \
      --after-cursor="$cursor" _SYSTEMD_INVOCATION_ID="$invocation" \
      --no-pager | grep -F '"operation":"btle_status"' | tail -1 || true)
    if BTLE_RECORD="$record" python3 - "$availability" "$reason" <<'PY'
import json
import os
import sys

try:
    record = json.loads(os.environ["BTLE_RECORD"])
except (KeyError, json.JSONDecodeError):
    raise SystemExit(1)
if record.get("availability") != sys.argv[1] or record.get("reason") != sys.argv[2]:
    raise SystemExit(1)
PY
    then
      printf '%s\n' "$record"
      return 0
    fi
    sleep 1
  done
  return 1
}
```

On the receiver, install this disposable loopback application client under a
root-owned path that the service cannot modify. It polls one exact subscription,
validates the Event, acknowledges delivery, and can later prove that no
unacknowledged redelivery remains. It never prints the bearer token or payload.

```console
set -euo pipefail
sudo install -d -o root -g root -m 0755 /usr/local/libexec
helper_stage=''
cleanup_helper_stage() {
  test -z "$helper_stage" || {
    sudo rm -f -- "$helper_stage"
    sudo sync -f /usr/local/libexec || true
  }
}
abort_helper_stage() {
  trap - EXIT INT TERM HUP
  cleanup_helper_stage || true
  exit "$1"
}
trap cleanup_helper_stage EXIT
trap 'abort_helper_stage 130' INT
trap 'abort_helper_stage 143' TERM
trap 'abort_helper_stage 129' HUP
helper_stage=$(sudo mktemp /usr/local/libexec/.aster-btle-receiver.XXXXXX)
sudo install -o root -g root -m 0755 /dev/stdin "$helper_stage" <<'PY'
#!/usr/bin/env python3
import base64
import hashlib
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path("/var/lib/aster-btle-evaluation")
TOKEN = Path("/etc/aster/agent-credentials/client-token")
JOURNAL = ROOT / "receiver.redb"
SUBSCRIPTION = ROOT / "subscription-id"
EXPECTED = ROOT / "expected.json"
CLIENT_ID = "btle-two-node-receiver/v1"
ENDPOINT = "http://127.0.0.1:8181/aster.application.v1alpha1.AsterApplicationService/"
TOPIC = "mesh.messages"
SCOPE = "demo/playground"

def rpc(method, body):
    request = urllib.request.Request(
        ENDPOINT + method,
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Connect-Protocol-Version": "1",
            "Authorization": "Bearer " + TOKEN.read_text().strip(),
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"{method} returned HTTP {error.code}") from None

def recovered_client():
    result = subprocess.run([
        "/usr/bin/asterctl", "--token-file", str(TOKEN), "--json",
        "publication-recover", "--journal", str(JOURNAL),
        "--client-id", CLIENT_ID,
    ], check=True, capture_output=True, timeout=15)
    return json.loads(result.stdout)["client"]

def deliveries(client):
    return rpc("PollEvents", {
        "client": client,
        "subscriptionId": SUBSCRIPTION.read_text().strip(),
        "deliveryLimit": 8,
        "scanLimit": 32,
    }).get("deliveries", [])

def wait_for_event():
    expected = json.loads(EXPECTED.read_text())
    client = recovered_client()
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        for delivery in deliveries(client):
            event = delivery["event"]
            payload = base64.b64decode(event["payload"], validate=True)
            if event["topic"] != TOPIC or event["scope"] != SCOPE:
                raise RuntimeError("subscription returned the wrong selector")
            digest = hashlib.sha256(payload).hexdigest()
            if len(payload) != 65536 or digest != expected["payload_sha256"]:
                raise RuntimeError("Event payload does not match")
            if event["id"] != expected["event_id"]:
                raise RuntimeError("Event ID does not match")
            rpc("AcknowledgeEvent", {
                "client": client,
                "subscriptionId": SUBSCRIPTION.read_text().strip(),
                "eventId": event["id"],
            })
            print(json.dumps({
                "acknowledged": True,
                "event_id": event["id"],
                "payload_bytes": len(payload),
                "payload_sha256": digest,
            }, sort_keys=True))
            return
        time.sleep(0.5)
    raise RuntimeError("matching Event did not arrive within 120 seconds")

def require_empty():
    client = recovered_client()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if deliveries(client):
            raise RuntimeError("unexpected delivery after acknowledgement")
        time.sleep(0.5)
    print('{"delivery_queue_empty":true}')

if sys.argv[1:] == ["wait"]:
    wait_for_event()
elif sys.argv[1:] == ["empty"]:
    require_empty()
else:
    raise SystemExit("usage: btle-receiver.py wait|empty")
PY
sudo test ! -e /usr/local/libexec/aster-btle-evaluation-receiver.py
sudo ln "$helper_stage" /usr/local/libexec/aster-btle-evaluation-receiver.py
sudo rm -- "$helper_stage"
sudo sync -f /usr/local/libexec
helper_stage=''
trap - EXIT INT TERM HUP
unset -f cleanup_helper_stage abort_helper_stage
helper_sha256=$(sha256sum \
  /usr/local/libexec/aster-btle-evaluation-receiver.py | cut -d' ' -f1)
```

Keep `helper_sha256` in the root maintenance shell and the protected run record.
Verify it immediately before every use below.

## Run the evaluation

### 1. Start locally while BTLE is unavailable

Keep BlueZ running. On each node, require the sole controller to be present but
set `Powered=false`; do not physically detach it:

```console
sudo systemctl is-active bluetooth.service
sudo bluetoothctl power off
bluetoothctl show | grep -Eq '^[[:space:]]*Powered: no$'
cursor=$(capture_cursor)
sudo systemctl start aster-agent.service
remember_invocation
wait_ready
wait_btle_status "$cursor" "$invocation" unavailable controller_unpowered
assert_same_invocation
```

Readiness proves local service availability, not BTLE availability.

### 2. Prepare durable application state before radio contact

On the receiver, create its run-owned directory, journal, and exact durable
subscription:

```console
sudo install -d -o aster -g aster -m 0700 /var/lib/aster-btle-evaluation
sudo -u aster /usr/bin/asterctl publication-init \
  --journal /var/lib/aster-btle-evaluation/receiver.redb \
  --client-id btle-two-node-receiver/v1
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token --json subscribe \
  --journal /var/lib/aster-btle-evaluation/receiver.redb \
  --client-id btle-two-node-receiver/v1 \
  --scope demo/playground --operation-key btle-two-node-subscription/v1 \
  mesh.messages \
  | sudo -u aster tee /var/lib/aster-btle-evaluation/subscription.json >/dev/null
sudo -u aster python3 - <<'PY'
import json
from pathlib import Path

root = Path("/var/lib/aster-btle-evaluation")
value = json.loads((root / "subscription.json").read_text())["subscriptionId"]
(root / "subscription-id").write_text(value + "\n")
(root / "subscription-id").chmod(0o600)
PY
```

On the publisher, generate a synthetic high-entropy 65,536-byte payload,
initialize its journal, and commit the Event while the controller remains
powered off:

```console
sudo install -d -o aster -g aster -m 0700 /var/lib/aster-btle-evaluation
sudo -u aster dd if=/dev/urandom \
  of=/var/lib/aster-btle-evaluation/payload.bin bs=65536 count=1 status=none
sudo -u aster chmod 0600 /var/lib/aster-btle-evaluation/payload.bin
sudo -u aster /usr/bin/asterctl publication-init \
  --journal /var/lib/aster-btle-evaluation/publisher.redb \
  --client-id btle-two-node-publisher/v1
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token --json publish \
  --journal /var/lib/aster-btle-evaluation/publisher.redb \
  --client-id btle-two-node-publisher/v1 \
  --topic mesh.messages --scope demo/playground --priority routine \
  < /var/lib/aster-btle-evaluation/payload.bin \
  | sudo -u aster tee /var/lib/aster-btle-evaluation/publication.json >/dev/null
sudo -u aster python3 - <<'PY'
import hashlib
import json
from pathlib import Path

root = Path("/var/lib/aster-btle-evaluation")
result = json.loads((root / "publication.json").read_text())["result"]
summary = {
    "event_id": result["receipt"]["eventId"],
    "operation_sequence": result["operationSequence"],
    "payload_sha256": hashlib.sha256((root / "payload.bin").read_bytes()).hexdigest(),
}
(root / "expected.json").write_text(json.dumps(summary, sort_keys=True) + "\n")
(root / "expected.json").chmod(0o600)
PY
```

Persist `expected.json` as the publisher application receipt, then acknowledge
its exact operation sequence:

```console
sequence=$(sudo -u aster python3 -c \
  'import json; print(json.load(open("/var/lib/aster-btle-evaluation/expected.json"))["operation_sequence"])')
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token publication-ack \
  --journal /var/lib/aster-btle-evaluation/publisher.redb \
  --client-id btle-two-node-publisher/v1 --sequence "$sequence"
unset sequence
```

Transfer only that summary to the receiver through an approved out-of-band operator channel as
`/var/lib/aster-btle-evaluation/expected.json`, owned by `aster:aster` mode
`0600`. Do not transfer the payload. This metadata transfer is not an Aster
carrier and must not add an IP peer or relay to either configuration.

### 3. Enable BTLE and prove delivery

Immediately before powering each controller on, capture a new cursor. Require
the fresh current-invocation record:

```console
cursor=$(capture_cursor)
sudo bluetoothctl power on
bluetoothctl show | grep -Eq '^[[:space:]]*Powered: yes$'
wait_btle_status "$cursor" "$invocation" available available
assert_same_invocation
```

On the receiver, wait for and acknowledge the Event:

```console
printf '%s  %s\n' "$helper_sha256" \
  /usr/local/libexec/aster-btle-evaluation-receiver.py | sha256sum -c -
sudo -u aster python3 \
  /usr/local/libexec/aster-btle-evaluation-receiver.py wait \
  | sudo -u aster tee /var/lib/aster-btle-evaluation/delivery.json
```

Query the exact selector and require one matching Event, not merely a contact
or availability record:

```console
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token --json query \
  --topic mesh.messages --scope demo/playground --limit 2 \
  | sudo -u aster tee /var/lib/aster-btle-evaluation/query.json >/dev/null
sudo -u aster python3 - <<'PY'
import base64
import hashlib
import json
from pathlib import Path

root = Path("/var/lib/aster-btle-evaluation")
expected = json.loads((root / "expected.json").read_text())
events = json.loads((root / "query.json").read_text())
if len(events) != 1:
    raise SystemExit("expected exactly one matching Event")
event = events[0]
payload = base64.b64decode(event["payload"], validate=True)
if event["id"] != expected["event_id"] or len(payload) != 65536:
    raise SystemExit("Event identity or size mismatch")
if hashlib.sha256(payload).hexdigest() != expected["payload_sha256"]:
    raise SystemExit("Event digest mismatch")
print("exact_query_match=true")
PY
```

Because `mesh.peers` is empty, no relay exists, the mesh bind is loopback-only,
and the Event was committed while both controllers were powered off, successful
remote delivery in this profile can only use the admitted BTLE adapter.

### 4. Prove controller and service recovery

On one node, capture a cursor, set the sole controller `Powered=false`, and
require the service to remain ready while a fresh status record becomes
unavailable. Then capture another cursor, power it on, and require availability
again without republishing:

```console
cursor=$(capture_cursor)
sudo bluetoothctl power off
bluetoothctl show | grep -Eq '^[[:space:]]*Powered: no$'
wait_ready
wait_btle_status "$cursor" "$invocation" unavailable controller_unpowered
assert_same_invocation

cursor=$(capture_cursor)
sudo bluetoothctl power on
bluetoothctl show | grep -Eq '^[[:space:]]*Powered: yes$'
wait_btle_status "$cursor" "$invocation" available available
assert_same_invocation
```

On each node, capture a cursor, restart the service, obtain its new invocation
ID, and require bounded readiness and availability:

```console
cursor=$(capture_cursor)
sudo systemctl restart aster-agent.service
remember_invocation
wait_ready
wait_btle_status "$cursor" "$invocation" available available
assert_same_invocation
```

On the receiver, query again with the exact query check above and require the
same single Event. Then prove the acknowledged subscription has no redelivery:

```console
printf '%s  %s\n' "$helper_sha256" \
  /usr/local/libexec/aster-btle-evaluation-receiver.py | sha256sum -c -
sudo -u aster python3 \
  /usr/local/libexec/aster-btle-evaluation-receiver.py empty
```

## Retain and clean up

Retain only a concise sanitized summary: source/package identity, exact
platform row, address-type class, Event size and digest, current-invocation
unavailable/available/restart records, application receipt, bounded resource
observations, and cleanup receipts. Do not retain hostnames, machine IDs,
Bluetooth addresses, adapter names, PSMs, mission or peer IDs, credential bytes,
raw state, payload files, or unfiltered logs. Do not delete the host journal;
retain only the selected exported records and leave journal lifecycle to the
host.

For cleanup, first stop and disable `aster-agent.service` on both nodes and
confirm `ActiveState=inactive`, `SubState=dead`, `MainPID=0`, and `ControlPID=0`.
For every live provider reference, follow
[Logically destroy a provider reference](../mvp/raspberry-pi-provider-v2-operations.md#7-logically-destroy-a-provider-reference)
with a fresh retained operation ID and keep its destruction receipt. After a
valid receipt, remove the service handoff
`/etc/aster/agent-credentials/mission-reference` and the root-only
`/etc/aster/btle-evaluation-provider-reference`. Add the destroy operation ID
and receipt to `/etc/aster/btle-evaluation-provider-operations`; retain those
install, load, and destroy records so an interrupted operation can be retried
exactly. The provider ledger and its tombstone remain until a separate
authorized provider-ledger cleanup procedure; do not delete that ledger as
lab-file cleanup. Logical destruction does not prove erasure from media,
backups, snapshots, swap, or copied filesystems.

Inspect the exact run-owned paths before deleting them. Remove only the
disposable source inputs, `/etc/credstore.encrypted/aster-btle-roster`, the
exact retained roster staging directory if encryption failed, the evaluation
configuration and token, `/usr/local/libexec/aster-btle-evaluation-receiver.py`,
exported evidence, and the exact state and evaluation directories created on
that node. Remove a failed identity, configuration, or helper stage only by its
exact retained path. Never delete by wildcard, remove the host journal, replace
or remove the systemd host key, or delete the provider ledger as cleanup.
Record any cleanup failure as a failed run.

A complete run closes the repeatable-setup gap only for its exact package and
platform row. It does not qualify hostile discovery, resource limits, multiple
controllers, another Linux stack, another data type, or production release
authorization.
