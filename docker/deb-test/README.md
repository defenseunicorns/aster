# Test a ready-built Aster Debian package



This separate two-node Compose smoke installs **the supplied `.deb`** with apt
into Ubuntu 24.04 containers. It does not build Rust, enable nearby discovery,
or change the package's features. Both agents run the installed
`/usr/bin/aster-agent`, as the package-created `aster` user. Peers are explicitly
bound to the other node's carrier ID, IP address, and mission identity.

## Run

Requirements: Linux, Python 3.11+, `dpkg-deb`, Docker Engine with Compose, and
permission to access the daemon. The Docker daemon architecture must match the
package (`amd64` or `arm64`); this runner does not qualify emulated execution.
The first image build needs access to the official Ubuntu image and apt
repositories. Ubuntu `24.04` is pinned by digest in `Dockerfile`; apt runtime
dependencies follow the configured Ubuntu repositories. This is not a
reproducible-image or signed-release claim.

From the repository root:

```sh
mise run deb-compose -- --deb /absolute/path/to/aster.deb
```

Mise is optional when Python is already installed:

```sh
python3 tools/aster_deb_compose.py --deb /absolute/path/to/aster.deb
```

The package is copied into a private, uniquely named `/tmp/aster-deb-test-*`
directory before inspection. The build, metadata, and SHA-256 all use that same
copy. This directory contains a standalone `compose.json`, a `compose.sh` wrapper, build inputs,
`package.json`, `receipt.json`, and bounded container logs. It is printed at
startup and retained after cleanup; move it elsewhere if longer-lived evidence
is required, because the OS may clean `/tmp`.

Validate inputs and Compose interpolation without contacting the Docker daemon:

```sh
mise run deb-compose -- --deb /absolute/path/to/aster.deb --config-only
```

The private internal bridge defaults to `172.29.240.0/24` with A at `.2` and B
at `.3`. If that subnet overlaps an existing Docker network, select an unused
private IPv4 subnet; the runner derives both addresses and peer configuration:

```sh
mise run deb-compose -- --deb /absolute/path/to/aster.deb --subnet 172.29.241.0/24
```

## What passes

1. Apt installs the `.deb`, its maintainer scripts, and dependencies. The image
   build runs the packaged CLI help commands; both running nodes must report
   the expected installed package name, version, and architecture.
2. A one-shot initializer generates a fresh two-member test mission, separate
   private state volumes and client tokens, and exact static peer bindings.
3. Both agents become ready and create durable Event subscriptions.
4. An Event published at A arrives at B with the exact ID, logical key, and
   payload.
5. B stops; A accepts two more Events. A is then stopped and recreated while B
   remains absent. Both queued Events must still be queryable on A.
6. B returns and receives both queued Events from A.
7. Both nodes stop. B alone is recreated with peers disabled and the same
   volume; all three Events must still be queryable locally.

Every controlled stop requires the clean lifecycle receipt and zero container
exit code. The normal run removes only its own containers, network, volumes,
and image tag. A failed or interrupted run attempts the same cleanup. A cleanup
failure makes the overall result fail; `status: pass` is emitted only after
successful completion. The runner never performs a global Docker prune.

## Keep the stand for manual tests

```sh
mise run deb-compose -- --deb /absolute/path/to/aster.deb --keep
```

After a passing smoke both nodes restart with static peers and their existing
subscriptions/state. Failed runs are cleaned up even with `--keep`. Use the
exact directory printed by the runner in place of `RUN_DIRECTORY`. The wrapper
pins the project name even if your shell exports `COMPOSE_PROJECT_NAME`:

```sh
RUN_DIRECTORY/compose.sh ps
RUN_DIRECTORY/compose.sh logs -f
RUN_DIRECTORY/compose.sh exec -T a python3 /opt/aster-test/aster_lan_mvp.py status --token-file /state/client.token
RUN_DIRECTORY/compose.sh exec -T a python3 /opt/aster-test/aster_lan_mvp.py publish --token-file /state/client.token --operation-key manual/1 --logical-key manual/1 --payload 'hello'
RUN_DIRECTORY/compose.sh exec -T b python3 /opt/aster-test/aster_lan_mvp.py query --token-file /state/client.token --logical-key manual/1
RUN_DIRECTORY/compose.sh stop b
RUN_DIRECTORY/compose.sh start b
```

Use a new operation key for each new publication. The API stays on loopback
inside each container; no host ports are published. Only synthetic test data
belongs here. Provisioning is explicitly the existing unprotected-reference
test path, not protected operational provisioning.

Transfer is asynchronous: an immediate query can still be empty. Repeat it or
use the helper's `wait --event-id ID_FROM_PUBLISH --logical-key manual/1` command
with the same `--token-file` to wait for that exact Event.

When finished:

```sh
RUN_DIRECTORY/compose.sh down --volumes --rmi all
```

Do not rerun the initializer against retained volumes: it refuses existing
state. Start the runner again for a fresh test project.

## Boundary

This verifies the installed package's CLI/Event behavior on two containers,
including restart persistence and static direct peers. It does not boot
systemd, exercise the packaged service unit/hardening or protected provider,
test package upgrade/removal, or replace physical CM4 acceptance. Use
[`tools/test-deb-install.sh`](../../tools/test-deb-install.sh) in a disposable
booted Ubuntu VM for the existing protected-service installation/lifecycle
test. The discovery and hierarchy Compose scenarios remain separate.

Offline controller regressions:

```sh
python3 tools/test_aster_deb_compose.py
```

These are included in `mise run check`. Package cases require `dpkg-deb` and
the project-isolation case requires the Docker Compose CLI, but no daemon.
Those cases report skips when the corresponding tool is unavailable, so the
general check remains usable on non-Debian or Docker-free developer machines.
