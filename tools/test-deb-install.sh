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
install -o root -g aster -m 0640 "$root/debian/agent.example.json" /etc/aster/agent.json
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
# Follow the existing operations playbook's shell handoff. Only the input
# fixture and automated edit of the staged configuration are test-specific.
INSTALL_OPERATION=$operation
LOAD_OPERATION=$load
exec 3< "$root/bindings/testdata/non-production-provisioning.bundle"
test "$(systemctl show aster-agent.service --property=ActiveState --value)" = inactive
test "$(systemctl show aster-agent.service --property=SubState --value)" = dead
test "$(systemctl show aster-agent.service --property=MainPID --value)" = 0
test "$(systemctl show aster-agent.service --property=ControlPID --value)" = 0
umask 077
admin_result=$(mktemp /etc/aster/.install-result.XXXXXX)
/usr/sbin/aster-credential-admin install \
  --operation "$INSTALL_OPERATION" --load-operation "$LOAD_OPERATION" \
  <&3 > "$admin_result"
exec 3<&-
test "$(wc -l < "$admin_result")" -eq 1
grep -Eq '^INSTALL disposition=(installed|existing) generation=[1-9][0-9]* reference=([0-9a-f]{2})+$' "$admin_result"
reference_stage=$(mktemp /etc/aster/agent-credentials/.mission-reference.XXXXXX)
sed -n 's/^.* reference=//p' "$admin_result" | tr 'a-f' 'A-F' | \
  basenc --base16 --decode > "$reference_stage"
chown aster:aster "$reference_stage"
chmod 0600 "$reference_stage"
sync -f "$reference_stage"
mv -T "$reference_stage" /etc/aster/agent-credentials/mission-reference
sync -f /etc/aster/agent-credentials
rm -- "$admin_result"
config_stage=$(mktemp /etc/aster/.agent.json.XXXXXX)
cp --preserve=mode,ownership /etc/aster/agent.json "$config_stage"
# Automate only the operator's editor step against the staged configuration.
python3 - "$config_stage" "$LOAD_OPERATION" <<'PYTEST'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
config = json.loads(path.read_text())
config["credentials"]["mission_load_id"] = sys.argv[2]
path.write_text(json.dumps(config, indent=2) + "\n")
PYTEST
runuser -u aster -- /usr/bin/aster-agent --check-config "$config_stage"
sync -f "$config_stage"
mv -T "$config_stage" /etc/aster/agent.json
sync -f /etc/aster
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
import json, urllib.request, subprocess
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
journal = ["--journal", "/var/lib/aster-agent/debian-publication.redb", "--client-id", "debian-install-smoke"]
subprocess.run(["asterctl", "publication-init", *journal], check=True, capture_output=True)
publication = subprocess.run(["asterctl", "--json", "--token-file", "/etc/aster/agent-credentials/client-token",
    "--host", "127.0.0.1", "--port", "8181", "publish", *journal, "--topic", "chat.events",
    "--scope", "mission/team/alpha", "--logical-key", "asset-7", "ready"], check=True, capture_output=True)
event_id = json.loads(publication.stdout)["result"]["receipt"]["eventId"]
page = rpc("PollEvents", {"subscriptionId": sub, "deliveryLimit": 8, "scanLimit": 32})
assert any(d["event"]["id"] == event_id for d in page["deliveries"])
rpc("AcknowledgeEvent", {"subscriptionId": sub, "eventId": event_id})
subprocess.run(["asterctl", "--token-file", "/etc/aster/agent-credentials/client-token", "--host", "127.0.0.1",
    "--port", "8181", "publication-ack", *journal, "--sequence", "1"], check=True, capture_output=True)
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
