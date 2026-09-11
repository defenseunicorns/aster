#!/usr/bin/env bash
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Run only on a disposable, booted Ubuntu 24.04 VM.
set -euo pipefail
[[ $EUID == 0 && $# == 1 ]]
. /etc/os-release
[[ $ID:$VERSION_ID == ubuntu:24.04 ]]
[[ $(cat /proc/1/comm) == systemd ]]
for path in /etc/aster /var/lib/aster /var/lib/aster-agent; do
    [[ ! -e $path && ! -L $path ]] || { echo 'Refusing an existing Aster deployment' >&2; exit 1; }
done
root=$(cd "$(dirname "$0")/.." && pwd)
package=$(realpath "$1")
dpkg -i "$package"
trap 'systemctl stop aster-agent.service || true' EXIT
! systemctl is-active --quiet aster-agent.service
! systemctl is-enabled --quiet aster-agent.service
# Missing configuration/provisioning must never produce a running service.
if systemctl start aster-agent.service; then
    echo 'Unexpected startup without provisioning' >&2
    exit 1
fi
systemctl reset-failed aster-agent.service
systemctl stop aster-agent.service
install -o root -g aster -m 0640 /usr/share/doc/aster/examples/agent.example.json /etc/aster/agent.json
python3 - <<'PY'
import os, pwd, secrets
account = pwd.getpwnam("aster")
fd = os.open("/etc/aster/agent-credentials/client-token", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as stream:
    stream.write(secrets.token_hex(32) + "\n")
    os.fchown(stream.fileno(), account.pw_uid, account.pw_gid)
PY
# These public test identifiers and fixture are exclusively for this disposable test.
operation=$(printf '%064d' 1)
load=$(printf '%064d' 2)
# The provider binds its ledger to the existing systemd host key.
# This harness has already refused any existing Aster deployment.
systemd-creds setup >/dev/null
/usr/sbin/aster-provision install --operation "$operation" --load-operation "$load" \
    < "$root/bindings/testdata/non-production-provisioning.bundle"
runuser -u aster -- /usr/bin/aster-agent --check-config /etc/aster/agent.json
systemctl start aster-agent.service
wait_ready() {
    python3 - <<'PY'
import time, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for _ in range(100):
    try:
        with opener.open("http://127.0.0.1:8182/readyz", timeout=1) as response:
            if response.status == 200:
                break
    except OSError:
        pass
    time.sleep(0.1)
else:
    raise SystemExit("readiness timeout")
PY
}
wait_ready
python3 - <<'PY'
import json, urllib.request
from pathlib import Path
token = Path("/etc/aster/agent-credentials/client-token").read_text().strip()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def rpc(method, data):
    req = urllib.request.Request(
        "http://127.0.0.1:8181/aster.application.v1alpha1.AsterApplicationService/" + method,
        json.dumps(data).encode(), headers={"Content-Type": "application/json",
        "Connect-Protocol-Version": "1", "Authorization": "Bearer " + token})
    with opener.open(req, timeout=10) as response:
        return json.load(response)
rpc("GetStatus", {})
sub = rpc("CreateEventSubscription", {"operationKey": "ZGViaWFuLXN1YnNjcmlwdGlvbg==",
    "topic": "chat.events", "scope": "mission/team/alpha"})["subscriptionId"]
event = rpc("PublishEvent", {"operationKey": "ZGViaWFuLXB1Ymxpc2g=", "topic": "chat.events",
    "scope": "mission/team/alpha", "priority": "PRIORITY_ROUTINE",
    "logicalKey": "YXNzZXQtNw==", "payload": "cmVhZHk="})
page = rpc("PollEvents", {"subscriptionId": sub, "deliveryLimit": 8, "scanLimit": 32})
assert any(d["event"]["id"] == event["id"] for d in page["deliveries"])
rpc("AcknowledgeEvent", {"subscriptionId": sub, "eventId": event["id"]})
print("Protected local Event publish/delivery/ack: OK")
PY
systemctl restart aster-agent.service
wait_ready
printf 'preserve\n' > /var/lib/aster-agent/package-test-marker
dpkg --remove aster
! systemctl is-active --quiet aster-agent.service
test "$(cat /var/lib/aster-agent/package-test-marker)" = preserve
test -f /etc/aster/provisioning/active/credential.cred
test -f /var/lib/aster/provisioning-systemd/ledger
trap - EXIT
printf 'Installation, protected service, restart, removal and state preservation: OK\n'
