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
lock_holder_pid=
cleanup() {
    if [[ -n $lock_holder_pid ]]; then
        kill "$lock_holder_pid" 2>/dev/null || true
        wait "$lock_holder_pid" 2>/dev/null || true
        lock_holder_pid=
    fi
    systemctl stop aster-agent.service || true
}
trap cleanup EXIT

btle_authority_directory=/run/aster-agent
btle_authority_lock=$btle_authority_directory/btle-authority.lock
btle_tmpfiles_policy=/usr/lib/tmpfiles.d/aster.conf
btle_postinst=/var/lib/dpkg/info/aster.postinst

btle_access_acl() {
    LC_ALL=C getfacl --access --absolute-names --omit-header -- "$1"
}

btle_default_acl() {
    LC_ALL=C getfacl --default --absolute-names --omit-header -- "$1"
}

assert_btle_authority_ancestor() {
    [[ ! -L /run && -d /run ]]
    [[ $(stat -c '%u:%g:%a' -- /run) == 0:0:755 ]]
    [[ $(btle_access_acl /run) == $'user::rwx\ngroup::r-x\nother::r-x' ]]
    [[ -z $(btle_default_acl /run) ]]
}

assert_btle_authority_lock() {
    assert_btle_authority_ancestor
    [[ ! -L $btle_authority_directory && -d $btle_authority_directory ]]
    [[ $(stat -c '%u:%g:%a' -- "$btle_authority_directory") == 0:0:755 ]]
    [[ $(btle_access_acl "$btle_authority_directory") == \
        $'user::rwx\ngroup::r-x\nother::r-x' ]]
    [[ -z $(btle_default_acl "$btle_authority_directory") ]]
    [[ ! -L $btle_authority_lock && -f $btle_authority_lock ]]
    [[ $(stat -c '%u:%g:%a:%s:%h' -- "$btle_authority_lock") == 0:0:440:0:1 ]]
    [[ $(btle_access_acl "$btle_authority_lock") == \
        $'user::r--\nuser:aster:r--\ngroup::---\nmask::r--\nother::---' ]]
    [[ -z $(btle_default_acl "$btle_authority_lock") ]]
}

recreate_btle_authority_lock() {
    rm -f -- "$btle_authority_lock"
    systemd-tmpfiles --create "$btle_tmpfiles_policy"
    assert_btle_authority_lock
}

recreate_btle_authority_hierarchy() {
    rm -f -- "$btle_authority_lock"
    if [[ -L $btle_authority_directory ]]; then
        rm -f -- "$btle_authority_directory"
    elif [[ -d $btle_authority_directory ]]; then
        rmdir -- "$btle_authority_directory"
    fi
    [[ ! -e $btle_authority_directory && ! -L $btle_authority_directory ]]
    systemd-tmpfiles --create "$btle_tmpfiles_policy"
    assert_btle_authority_lock
}

assert_unsafe_anchor_rejected() {
    if "$btle_postinst" configure; then
        echo "Unsafe BTLE authority fixture was accepted: $1" >&2
        exit 1
    fi
}

assert_unsafe_directory_rejected() {
    if "$btle_postinst" configure; then
        echo "Unsafe BTLE authority directory fixture was accepted: $1" >&2
        exit 1
    fi
}

assert_btle_authority_lock
# The service account can open and exclusively lock the root-owned anchor, but
# a second process cannot share authority while that lock remains held. The
# coprocess pipe gives a bounded readiness/release handshake without polling.
coproc BTLE_LOCK_HOLDER {
    exec timeout --kill-after=1s 5s runuser -u aster -- sh -c \
        'exec 9<"$1"; flock -n 9; printf "ready\n"; IFS= read -r release' \
        sh "$btle_authority_lock"
}
lock_holder_pid=$BTLE_LOCK_HOLDER_PID
IFS= read -r -t 3 lock_status <&"${BTLE_LOCK_HOLDER[0]}"
[[ $lock_status == ready ]]
! runuser -u aster -- sh -c 'exec 9<"$1"; flock -n 9' sh "$btle_authority_lock"
printf 'release\n' >&"${BTLE_LOCK_HOLDER[1]}"
wait "$lock_holder_pid"
lock_holder_pid=

# The named ACL grants only read/lock access; the trusted parent prevents path
# replacement by the service identity.
! runuser -u aster -- sh -c ': >"$1"' sh "$btle_authority_lock"
! runuser -u aster -- truncate -s 1 "$btle_authority_lock"
! runuser -u aster -- chmod 0600 "$btle_authority_lock"
! runuser -u aster -- mv "$btle_authority_lock" "$btle_authority_lock.moved"
! runuser -u aster -- rm "$btle_authority_lock"
assert_btle_authority_lock

# A boot-style tmpfiles invocation recreates the safely deleted volatile
# hierarchy, not only the lock file.
recreate_btle_authority_hierarchy

# A valid upgrade is accepted without changing custody.
"$btle_postinst" configure
assert_btle_authority_lock

# The fixed /run ancestor is never mutated. Exercise unsafe replaceable child
# directory profiles and prove pre-helper rejection leaves each unchanged.
rm -f -- "$btle_authority_lock"
rmdir -- "$btle_authority_directory"
symlink_directory_target=$(mktemp -d)
ln -s -- "$symlink_directory_target" "$btle_authority_directory"
assert_unsafe_directory_rejected symlink
[[ -L $btle_authority_directory && \
    $(readlink -- "$btle_authority_directory") == "$symlink_directory_target" ]]
rm -f -- "$btle_authority_directory"
rmdir -- "$symlink_directory_target"
recreate_btle_authority_hierarchy

rm -f -- "$btle_authority_lock"
chown aster:aster "$btle_authority_directory"
assert_unsafe_directory_rejected wrong-owner
[[ $(stat -c '%u:%g' -- "$btle_authority_directory") == \
    "$(id -u aster):$(id -g aster)" ]]
recreate_btle_authority_hierarchy

rm -f -- "$btle_authority_lock"
chmod 0775 "$btle_authority_directory"
assert_unsafe_directory_rejected wrong-mode
[[ $(stat -c '%a' -- "$btle_authority_directory") == 775 ]]
recreate_btle_authority_hierarchy

rm -f -- "$btle_authority_lock"
setfacl -m u:aster:r-x,m::r-x "$btle_authority_directory"
[[ $(stat -c '%a' -- "$btle_authority_directory") == 755 ]]
unsafe_access_acl=$(btle_access_acl "$btle_authority_directory")
assert_unsafe_directory_rejected access-acl
[[ $(btle_access_acl "$btle_authority_directory") == "$unsafe_access_acl" ]]
recreate_btle_authority_hierarchy

rm -f -- "$btle_authority_lock"
setfacl -d -m u::rwx,u:aster:rwx,g::r-x,m::rwx,o::r-x "$btle_authority_directory"
unsafe_default_acl=$(btle_default_acl "$btle_authority_directory")
assert_unsafe_directory_rejected default-acl
[[ -n $unsafe_default_acl ]]
[[ $(btle_default_acl "$btle_authority_directory") == "$unsafe_default_acl" ]]
recreate_btle_authority_hierarchy

# Pre-helper validation must reject unsafe existing objects before debhelper's
# tmpfiles snippet can normalize them.
rm -f -- "$btle_authority_lock"
symlink_target=$(mktemp)
printf 'unchanged\n' >"$symlink_target"
ln -s -- "$symlink_target" "$btle_authority_lock"
assert_unsafe_anchor_rejected symlink
[[ -L $btle_authority_lock && $(readlink -- "$btle_authority_lock") == "$symlink_target" ]]
[[ $(cat "$symlink_target") == unchanged ]]
rm -f -- "$btle_authority_lock" "$symlink_target"
recreate_btle_authority_lock

rm -f -- "$btle_authority_lock"
hardlink_fixture=$btle_authority_directory/hardlink-fixture
install -o root -g root -m 0440 /dev/null "$hardlink_fixture"
setfacl -m u::r--,u:aster:r--,g::---,m::r--,o::--- "$hardlink_fixture"
ln -- "$hardlink_fixture" "$btle_authority_lock"
assert_unsafe_anchor_rejected hardlink
[[ $(stat -c '%h' -- "$hardlink_fixture") == 2 ]]
rm -f -- "$btle_authority_lock" "$hardlink_fixture"
recreate_btle_authority_lock

printf 'not-empty' >"$btle_authority_lock"
chown root:root "$btle_authority_lock"
chmod 0440 "$btle_authority_lock"
setfacl -m u::r--,u:aster:r--,g::---,m::r--,o::--- "$btle_authority_lock"
assert_unsafe_anchor_rejected non-empty
[[ $(cat "$btle_authority_lock") == not-empty ]]
recreate_btle_authority_lock

rm -f -- "$btle_authority_lock"
install -o root -g root -m 0440 /dev/null "$btle_authority_lock"
wrong_acl=$(btle_access_acl "$btle_authority_lock")
assert_unsafe_anchor_rejected wrong-acl
[[ $(btle_access_acl "$btle_authority_lock") == "$wrong_acl" ]]
recreate_btle_authority_lock

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
journal = ["--journal", "/var/lib/aster-agent/debian-publication.redb", "--client-id", "debian-install-smoke"]
subprocess.run(["asterctl", "publication-init", *journal], check=True, capture_output=True)
sub_response = subprocess.run(["asterctl", "--json", "--token-file", "/etc/aster/agent-credentials/client-token",
    "--host", "127.0.0.1", "--port", "8181", "subscribe", *journal,
    "--operation-key", "debian-subscription", "--scope", "mission/team/alpha", "chat.events"], check=True, capture_output=True)
sub = json.loads(sub_response.stdout)["subscriptionId"]
publication = subprocess.run(["asterctl", "--json", "--token-file", "/etc/aster/agent-credentials/client-token",
    "--host", "127.0.0.1", "--port", "8181", "publish", *journal, "--topic", "chat.events",
    "--scope", "mission/team/alpha", "--logical-key", "asset-7", "ready"], check=True, capture_output=True)
event_id = json.loads(publication.stdout)["result"]["receipt"]["eventId"]
recovered = subprocess.run(["asterctl", "--json", "--token-file", "/etc/aster/agent-credentials/client-token",
    "--host", "127.0.0.1", "--port", "8181", "publication-recover", *journal], check=True, capture_output=True)
client = json.loads(recovered.stdout)["client"]
page = rpc("PollEvents", {"client": client, "subscriptionId": sub, "deliveryLimit": 8, "scanLimit": 32})
assert any(d["event"]["id"] == event_id for d in page["deliveries"])
rpc("AcknowledgeEvent", {"client": client, "subscriptionId": sub, "eventId": event_id})
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
