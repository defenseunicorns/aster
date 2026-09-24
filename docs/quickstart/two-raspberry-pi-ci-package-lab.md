#

# Two Raspberry Pis: install a CI package and exchange Aster Events

This is a worked example of the lab run on 23 September 2026. It starts with two clean Raspberry Pi 4B systems running 64-bit Raspberry Pi OS (Debian 13), with systemd 257, local ext4 storage, working network access between the boards, and an account that can use sudo. Raspberry Pi #1 was called skyhold at 192.168.1.100; Raspberry Pi #2 was wyvern at 192.168.1.101. Substitute your own addresses for a new lab.

The goal is simple: install the same CI-built arm64 package on both boards, give them one shared **disposable test mission** with distinct identities, start the packaged protected service, and send an Event each way. This procedure is for a clean evaluation lab. The generated mission bundles are unprotected source material until imported; they are not production-issued credentials.

## What the pieces do

- The **CI package** supplies the Aster CLI, the Event agent, the credential administrator, and the systemd service.
- A **carrier identity** identifies a transport endpoint. A **mission node ID** identifies its member in the mission. An exact peer entry binds both IDs to a network address.
- The **protected provider** imports each node's mission bundle and gives the agent an opaque reference. The raw bundle is removed after provisioning.
- The **agent** listens on loopback TCP 8181 for authenticated application calls, loopback TCP 8182 for health, and UDP 8183 for mesh traffic. A bearer token is held in a file readable by the service account.
- A subscription must exist before the test Event is published. Polling checks the delivered payload and acknowledges the Event.

## 1. Get the exact CI package

The package came from the successful main-branch [Build: .deb arm64 run 35210078468](https://github.com/edgesoftops/astertech/actions/runs/35210078468), source commit 71669176bef2d96a6aa34abaae004ad40142b135. GitHub retains this workflow's artifacts for 14 days, so for a later reproduction choose a newer successful main run and use its artifact ID and checksum.

On a machine with GitHub CLI access, the artifact was downloaded as follows. This workflow uploads the deb with archive=false, so the artifact endpoint returns the deb bytes directly.

~~~sh
mkdir -p /tmp/aster-two-pi-ci-35210078468
gh api repos/edgesoftops/astertech/actions/artifacts/10492125757/zip \
  > /tmp/aster-two-pi-ci-35210078468/aster_0.1.0~alpha.1-1_arm64.deb
printf '%s  %s\n' \
  5739c2b4debfd7d6d91d466706239410520e7bf68d0701ae9132f4761aa56905 \
  /tmp/aster-two-pi-ci-35210078468/aster_0.1.0~alpha.1-1_arm64.deb \
  | shasum -a 256 -c -
~~~

The separate build-record artifact was downloaded and its checksum manifest checked too:

~~~sh
gh run download 35210078468 --repo edgesoftops/astertech \
  --name aster-deb-arm64-metadata-71669176bef2d96a6aa34abaae004ad40142b135 \
  --dir /tmp/aster-two-pi-ci-35210078468
(cd /tmp/aster-two-pi-ci-35210078468 && shasum -a 256 -c SHA256SUMS)
~~~

Copy the verified deb to /tmp/aster_0.1.0~alpha.1-1_arm64.deb on **each** Pi. For example, from that same machine:

~~~sh
scp /tmp/aster-two-pi-ci-35210078468/aster_0.1.0~alpha.1-1_arm64.deb \
  skyhold:/tmp/
scp /tmp/aster-two-pi-ci-35210078468/aster_0.1.0~alpha.1-1_arm64.deb \
  wyvern:/tmp/
~~~

On **each Pi**, check the copied bytes and install:

~~~sh
printf '%s  %s\n' \
  5739c2b4debfd7d6d91d466706239410520e7bf68d0701ae9132f4761aa56905 \
  /tmp/aster_0.1.0~alpha.1-1_arm64.deb | sha256sum -c -
sudo apt-get install /tmp/aster_0.1.0~alpha.1-1_arm64.deb
dpkg-query -W aster
sudo dpkg --verify aster
sudo dpkg --audit
~~~

The expected package is aster 0.1.0~alpha.1-1 for arm64. Silent dpkg verification and audit mean no package-integrity or package-state issue was reported. The service is deliberately inactive and disabled at this point; it has no mission configuration yet.

## 2. Create the disposable two-member mission

On **Pi #1**, create one mission so both nodes share an authority, scope, topic, and epoch. Running the generator separately on each Pi would make two unrelated missions.

~~~sh
umask 077
aster playground-init --nodes 2 --root /tmp/aster-two-pi-lab
~~~

This run printed two PLAYGROUND_NODE lines. The first was assigned to Pi #1 and the second to Pi #2:

| Node | Carrier ID | Mission node ID |
| --- | --- | --- |
| Pi #1 | 9ac0be97953146aa9313c172c37bec209d3c0d51565795ab6a46c517ac16eff9 | 4070cae9f498279d6a700b7db282195c213bcf6d5a4bfec2b1d24e6fa4a1e498 |
| Pi #2 | b1057ddfecbb768426c1f75316476c09e63c69df3c876a759d79cc43b427964e | aca5df2a0c0263f8b05fe1e47d1a7478773d1089a7dc66b2476a1e8f25518b01 |

These are public identifiers, not key bytes. A new run creates new IDs; update the peer entries in the provisioning script below for that run.

Copy only node-1's directory to **Pi #2**, preserving its owner-only permissions. In this run the transfer was performed from Pi #1:

~~~sh
tar -C /tmp/aster-two-pi-lab -cf - node-1 \
  | ssh wyvern 'umask 077; mkdir -p /tmp/aster-two-pi-lab; tar -C /tmp/aster-two-pi-lab -xf -'
~~~

Pi #1 uses /tmp/aster-two-pi-lab/node-0. Pi #2 uses /tmp/aster-two-pi-lab/node-1. Each contains identity.key and mission.unprotected-reference.bundle. Treat both files as sensitive. The bundle is an unprotected **test input** at this stage.

## 3. Import into the protected provider and start the agents

The provisioning script in [Appendix A](#appendix-a-provisioning-script) was copied to /tmp/aster-two-pi-provision.sh on each Pi. Read its guard checks before using it: it is specific to this clean lab, these two IP addresses, and the IDs above. It refuses an existing setup so it cannot silently overwrite a provisioned node.

On **Pi #1**, then **Pi #2**, run:

~~~sh
sudo install -o root -g root -m 0700 \
  /tmp/aster-two-pi-provision.sh /root/aster-two-pi-provision.sh
sudo /root/aster-two-pi-provision.sh
~~~

The script allocates and retains fresh operation IDs, initializes the systemd host credential key if absent, imports the local test bundle while the service is stopped, and verifies the provider's complete success line. It decodes the returned opaque reference into a service-owned mode-0600 handoff file, installs the matching carrier identity, creates a separate bearer token, writes the strict agent JSON, checks that JSON as the aster service account, starts the service, and waits for /readyz.

The peer entries have the form **peer carrier ID @ peer IP:8183 = peer mission node ID**. Pi #1 points to Pi #2 and vice versa. The application API and health listeners stay on loopback; only mesh UDP binds to all interfaces.

The observed success lines on both boards were:

~~~text
Protected provider install: pass
Strict agent configuration: pass
Protected service /readyz: HTTP 200
~~~

On **each Pi**, make an independent health check:

~~~sh
systemctl is-active aster-agent.service
curl -sS -o /dev/null -w 'livez=%{http_code}\n' \
  http://127.0.0.1:8182/livez
curl -sS -o /dev/null -w 'readyz=%{http_code}\n' \
  http://127.0.0.1:8182/readyz
~~~

The observed result was active, livez=200, readyz=200 on both. Readiness says this *local* agent can serve its application API; it does not by itself prove a peer connection or Event delivery.

## 4. Prove Event delivery in both directions

The short local client in [Appendix B](#appendix-b-event-probe) was copied to /tmp/aster-two-pi-probe.py on each Pi. It reads the bearer token as the aster account, calls only the loopback application API, and never prints the token. Its subscription ID is stored under /var/lib/aster-agent so it survives process restart.

Run **prepare** on both Pis before publishing:

~~~sh
# Pi #1
sudo -u aster python3 /tmp/aster-two-pi-probe.py prepare

# Pi #2
sudo -u aster python3 /tmp/aster-two-pi-probe.py prepare
~~~

Then send Pi #1 to Pi #2:

~~~sh
# Pi #1
sudo -u aster python3 /tmp/aster-two-pi-probe.py publish "hello from skyhold"

# Pi #2
sudo -u aster python3 /tmp/aster-two-pi-probe.py poll "hello from skyhold"
~~~

And send Pi #2 to Pi #1:

~~~sh
# Pi #2
sudo -u aster python3 /tmp/aster-two-pi-probe.py publish "hello from wyvern"

# Pi #1
sudo -u aster python3 /tmp/aster-two-pi-probe.py poll "hello from wyvern"
~~~

The observed Event IDs matched at the publisher and receiver in each direction:

| Direction | Published and acknowledged Event ID |
| --- | --- |
| Pi #1 → Pi #2 | 80//qmIZEFyhuPRm9abHtDufayajZfrAQGVQESgXPQ8= |
| Pi #2 → Pi #1 | lXh5ytiouA5m0oA1nNLfoRBeyhpcPTg0djUuq95xkc8= |

The client also decoded and compared each payload, checked the topic mesh.messages and scope demo/playground, then acknowledged the delivery. This is the cross-node proof that /readyz alone cannot supply. A new publication will have a different Event ID. Do not repeat prepare against an existing subscription file; the script deliberately refuses.

## 5. Remove raw inputs and verify boot startup

After both directions passed, the unprotected source bundles and temporary source identity keys were removed from /tmp/aster-two-pi-lab on both Pis. The agent's service-owned identity and protected provider state were kept. Use the exact paths for your run, and inspect the directory first:

~~~sh
# Pi #1
find /tmp/aster-two-pi-lab -mindepth 1 -maxdepth 3 -printf '%P %y %m %u:%g\n'
rm /tmp/aster-two-pi-lab/node-{0,1}/{identity.key,mission.unprotected-reference.bundle}
rmdir /tmp/aster-two-pi-lab/node-{0,1} /tmp/aster-two-pi-lab

# Pi #2
find /tmp/aster-two-pi-lab -mindepth 1 -maxdepth 3 -printf '%P %y %m %u:%g\n'
rm /tmp/aster-two-pi-lab/node-1/{identity.key,mission.unprotected-reference.bundle}
rmdir /tmp/aster-two-pi-lab/node-1 /tmp/aster-two-pi-lab
~~~

The package had left the service disabled. On **each Pi, one at a time**, enable it and reboot:

~~~sh
sudo systemctl enable aster-agent.service
sudo reboot
~~~

After each Pi returned, check:

~~~sh
systemctl is-enabled aster-agent.service
systemctl is-active aster-agent.service
curl -sS -o /dev/null -w 'readyz=%{http_code}\n' \
  http://127.0.0.1:8182/readyz
journalctl -u aster-agent.service -b --no-pager -o cat | tail -12
~~~

Both boards came back with enabled, active, and readyz=200. Their boot journals recorded fresh starting and ready transitions and peer contact. The protected startup path therefore worked again after reboot, using the retained provider state rather than the deleted raw bundles.

## What this test establishes

The *same* CI package passed checksum and installation checks on two arm64 Raspberry Pi 4Bs; each imported its own disposable mission bundle through the packaged protected provider; both agents became ready, exchanged and acknowledged Events in both directions, and started ready after reboot.

This is bounded engineering evidence. The selected evaluation profile is a specific CM4 system, while this lab used Pi 4Bs. It does not extend formal qualification or production authorization. systemd-creds also warned that /var/lib/systemd/credential.secret was on unencrypted media. The provider path worked, but this setup does not prove protection against an attacker who can read the SD card. The lab did not test rotation, revoke/rekey, backup/recovery, long soak, network partition, or independent interoperability.

For the service and provider contract, see [the agent configuration reference](../reference/aster-agent-config-v1.md), [provider operations](../mvp/raspberry-pi-provider-v2-operations.md), and [the CI package workflow](../../.github/workflows/build-deb-arm64.yml).

## Appendix A: provisioning script

This is the script used for this specific clean lab. It contains no secret values, but its IP addresses and peer identifiers are fixed. It is intentionally **not** a general-purpose re-provisioning tool.

~~~bash
#!/usr/bin/env bash
set -euo pipefail
umask 077

if (( EUID != 0 )); then
  echo 'Run this script with sudo.' >&2
  exit 1
fi
if systemctl is-active --quiet aster-agent.service; then
  echo 'Aster service is already active; refusing first-install setup.' >&2
  exit 1
fi
if [[ $(dpkg-query -W -f='${Version}' aster) != '0.1.0~alpha.1-1' ]]; then
  echo 'Unexpected Aster package version.' >&2
  exit 1
fi

addresses=" $(hostname -I) "
case "$addresses" in
  *' 192.168.1.100 '*)
    node=0
    peer='b1057ddfecbb768426c1f75316476c09e63c69df3c876a759d79cc43b427964e@192.168.1.101:8183=aca5df2a0c0263f8b05fe1e47d1a7478773d1089a7dc66b2476a1e8f25518b01'
    ;;
  *' 192.168.1.101 '*)
    node=1
    peer='9ac0be97953146aa9313c172c37bec209d3c0d51565795ab6a46c517ac16eff9@192.168.1.100:8183=4070cae9f498279d6a700b7db282195c213bcf6d5a4bfec2b1d24e6fa4a1e498'
    ;;
  *)
    echo 'Unexpected local address; refusing setup.' >&2
    exit 1
    ;;
esac

source_dir="/tmp/aster-two-pi-lab/node-$node"
bundle="$source_dir/mission.unprotected-reference.bundle"
identity="$source_dir/identity.key"
for path in "$bundle" "$identity"; do
  [[ -f $path && ! -L $path && $(stat -c %a "$path") == 600 ]] || {
    echo 'Missing or insecure lab input.' >&2
    exit 1
  }
done
[[ $(stat -c %s "$identity") == 32 ]] || {
  echo 'Invalid carrier identity length.' >&2
  exit 1
}
for path in /etc/aster/agent.json /etc/aster/agent-credentials/client-token \
  /etc/aster/agent-credentials/mission-reference /var/lib/aster-agent/identity.key \
  /etc/aster/lab-install-operations; do
  [[ ! -e $path && ! -L $path ]] || {
    echo 'Existing Aster setup state; refusing first-install setup.' >&2
    exit 1
  }
done

if [[ ! -e /var/lib/systemd/credential.secret ]]; then
  systemd-creds setup >/dev/null
fi
[[ -f /var/lib/systemd/credential.secret ]] || {
  echo 'systemd host credential key is unavailable.' >&2
  exit 1
}

install_operation=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
load_operation=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
printf 'INSTALL_OPERATION=%s\nLOAD_OPERATION=%s\n' \
  "$install_operation" "$load_operation" > /etc/aster/lab-install-operations
chmod 0600 /etc/aster/lab-install-operations
sync -f /etc/aster/lab-install-operations

admin_result=$(mktemp /etc/aster/.lab-install-result.XXXXXX)
reference_stage=''
token_stage=''
config_stage=''
cleanup() {
  for path in "$admin_result" "$reference_stage" "$token_stage" "$config_stage"; do
    [[ -z $path ]] || rm -f -- "$path"
  done
}
trap cleanup EXIT

exec 3< "$bundle"
/usr/sbin/aster-credential-admin install \
  --operation "$install_operation" --load-operation "$load_operation" \
  <&3 > "$admin_result"
exec 3<&-
[[ $(wc -l < "$admin_result") == 1 ]] || {
  echo 'Unexpected provider result; keep service stopped.' >&2
  exit 1
}
grep -Eq '^INSTALL disposition=(installed|existing) generation=[1-9][0-9]* reference=([0-9a-f]{2})+$' "$admin_result" || {
  echo 'Invalid provider result; keep service stopped.' >&2
  exit 1
}
echo 'Protected provider install: pass'

reference_stage=$(mktemp /etc/aster/agent-credentials/.mission-reference.XXXXXX)
sed -n 's/^.* reference=//p' "$admin_result" | tr 'a-f' 'A-F' | \
  basenc --base16 --decode > "$reference_stage"
chown aster:aster "$reference_stage"
chmod 0600 "$reference_stage"
sync -f "$reference_stage"
mv -T "$reference_stage" /etc/aster/agent-credentials/mission-reference
reference_stage=''
sync -f /etc/aster/agent-credentials

install -o aster -g aster -m 0600 "$identity" /var/lib/aster-agent/identity.key
sync -f /var/lib/aster-agent/identity.key

token_stage=$(mktemp /etc/aster/agent-credentials/.client-token.XXXXXX)
python3 -c 'import secrets; print(secrets.token_hex(32))' > "$token_stage"
chown aster:aster "$token_stage"
chmod 0600 "$token_stage"
sync -f "$token_stage"
mv -T "$token_stage" /etc/aster/agent-credentials/client-token
token_stage=''
sync -f /etc/aster/agent-credentials

config_stage=$(mktemp /etc/aster/.agent.json.XXXXXX)
python3 - "$config_stage" "$load_operation" "$peer" <<'PY'
import json
import sys

path, load_operation, peer = sys.argv[1:]
config = {
    "schema_version": 1,
    "state": {"directory": "/var/lib/aster-agent"},
    "application": {"listen": "127.0.0.1:8181"},
    "health": {"listen": "127.0.0.1:8182"},
    "mesh": {
        "bind": "0.0.0.0:8183",
        "emission_policy": "normal",
        "sync_interval_ms": 500,
        "peers": [peer],
    },
    "credentials": {
        "client_token_file": "/etc/aster/agent-credentials/client-token",
        "mission_secret_ref_file": "/etc/aster/agent-credentials/mission-reference",
        "mission_load_id": load_operation,
    },
    "storage": {
        "max_items": 10000,
        "max_payload_bytes": 67108864,
        "operations": {
            "max_records": 1000000,
            "max_logical_bytes": 201326592,
            "emergency_reserve": 10000,
        },
    },
}
with open(path, "w", encoding="utf-8") as output:
    json.dump(config, output, indent=2)
    output.write("\n")
PY
chown root:aster "$config_stage"
chmod 0640 "$config_stage"
/usr/sbin/runuser -u aster -- /usr/bin/aster-agent --check-config "$config_stage"
sync -f "$config_stage"
mv -T "$config_stage" /etc/aster/agent.json
config_stage=''
sync -f /etc/aster

echo 'Strict agent configuration: pass'
systemctl start aster-agent.service
ready=no
for _ in $(seq 1 30); do
  if curl --silent --fail --max-time 2 --output /dev/null http://127.0.0.1:8182/readyz; then
    ready=yes
    break
  fi
  sleep 1
done
[[ $ready == yes ]] || {
  echo 'Agent did not become ready; keep lab input for diagnosis.' >&2
  exit 1
}
echo 'Protected service /readyz: HTTP 200'
~~~

## Appendix B: Event probe

This was a disposable local client, not a package component. It uses Python's standard library and prints Event IDs and pass/fail results, never the bearer token.

~~~python
#!/usr/bin/env python3
"""Disposable local ConnectRPC client for the two-Pi Aster Event lab."""

import base64
import json
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

TOKEN = Path('/etc/aster/agent-credentials/client-token')
SUBSCRIPTION = Path('/var/lib/aster-agent/lab-subscription-id')
ENDPOINT = 'http://127.0.0.1:8181/aster.application.v1alpha1.AsterApplicationService/'
TOPIC = 'mesh.messages'
SCOPE = 'demo/playground'


def encoded(value: bytes) -> str:
    return base64.b64encode(value).decode('ascii')


def rpc(method: str, body: dict) -> dict:
    token = TOKEN.read_text(encoding='ascii').strip()
    request = urllib.request.Request(
        ENDPOINT + method,
        data=json.dumps(body).encode('utf-8'),
        headers={
            'Content-Type': 'application/json',
            'Connect-Protocol-Version': '1',
            'Authorization': 'Bearer ' + token,
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f'{method} returned HTTP {error.code}') from None


def prepare() -> None:
    if SUBSCRIPTION.exists():
        raise RuntimeError('lab subscription already exists; inspect before reusing')
    result = rpc('CreateEventSubscription', {
        'operationKey': encoded(secrets.token_bytes(24)),
        'topic': TOPIC,
        'scope': SCOPE,
    })
    subscription_id = result['subscriptionId']
    with SUBSCRIPTION.open('x', encoding='ascii') as output:
        output.write(subscription_id + '\n')
    SUBSCRIPTION.chmod(0o600)
    print('subscription_created=true')


def publish(message: str) -> None:
    payload = message.encode('utf-8')
    result = rpc('PublishEvent', {
        'operationKey': encoded(secrets.token_bytes(24)),
        'topic': TOPIC,
        'scope': SCOPE,
        'priority': 'PRIORITY_ROUTINE',
        'logicalKey': encoded(secrets.token_bytes(16)),
        'payload': encoded(payload),
    })
    print(f"published_id={result['id']}")


def poll(message: str) -> None:
    expected = message.encode('utf-8')
    subscription_id = SUBSCRIPTION.read_text(encoding='ascii').strip()
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        result = rpc('PollEvents', {
            'subscriptionId': subscription_id,
            'deliveryLimit': 8,
            'scanLimit': 32,
        })
        for delivery in result.get('deliveries', []):
            event = delivery['event']
            actual = base64.b64decode(event['payload'], validate=True)
            if actual != expected:
                continue
            if event['topic'] != TOPIC or event['scope'] != SCOPE:
                raise RuntimeError('matching payload arrived with wrong selector')
            rpc('AcknowledgeEvent', {
                'subscriptionId': subscription_id,
                'eventId': event['id'],
            })
            print(f"received_and_acknowledged_id={event['id']}")
            return
        time.sleep(0.5)
    raise RuntimeError('matching Event did not arrive within 60 seconds')


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == 'prepare':
        prepare()
    elif len(sys.argv) == 3 and sys.argv[1] == 'publish':
        publish(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == 'poll':
        poll(sys.argv[2])
    else:
        raise SystemExit('usage: aster-two-pi-probe.py prepare|publish MESSAGE|poll MESSAGE')


if __name__ == '__main__':
    main()
~~~
