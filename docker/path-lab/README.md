# Aster path-lab

The path-lab is a bounded Linux-only network-emulation scaffold for the
Linux/Event customer-readiness profile. It uses Containerlab only for topology
orchestration and Linux `netem` for packet-path impairment. Product nodes and
additional `nftables`, address, interface, relay, and process lifecycle actions
are intentionally deferred to later focused increments.

This initial smoke proves only that:

- one exact scenario is parsed into non-shell argument vectors;
- the three-node linked topology deploys;
- delay, jitter, loss, and rate are applied to the selected interface;
- Containerlab JSON read-back matches the configured values; and
- the topology is destroyed before a passing receipt is emitted.

It is not Aster delivery evidence, a retained customer receipt, a NAT or relay
result, a resource-bound result, or physical-network qualification.
The scenario seed identifies this manifest and is retained for later actions;
Containerlab `0.79.0` does not expose a packet-loss RNG seed through its netem
command, so this smoke does not claim a deterministic packet-loss sequence.

## Public tool boundary

- Containerlab `0.79.0`, BSD-3-Clause, from
  <https://github.com/srl-labs/containerlab/releases/tag/v0.79.0>.
- Linux amd64 tarball SHA-256:
  `f90d36d58bb6c4afd3b3a4dca006b81594c6d16f7a04be0184b03f44291085a2`.
- The generic node image reuses the repository's existing digest-pinned Rust
  base without adding another package dependency.

## Validate without privileged execution

```sh
python3 tools/aster_path_lab.py \
  docker/path-lab/scenarios/netem-readback-smoke.json
```

Validation is platform-independent and prints a canonical command plan. It does
not execute Containerlab.

## Execute on Linux

The execution host must provide Docker, Linux `netem`, root privileges, and the
exact Containerlab release above.

```sh
docker build --pull=false --network=none --file docker/path-lab/Dockerfile \
  --tag aster-path-lab:local .
python3 tools/aster_path_lab.py \
  docker/path-lab/scenarios/netem-readback-smoke.json \
  --execute \
  --containerlab /usr/local/bin/containerlab
```

The command prints canonical JSON only after read-back and cleanup succeed.
Failures are sanitized and return status 2.

## Real-Event delivery slice

This separate slice replaces **delivery-only** Containerlab orchestration with
fixed Docker/Linux network namespaces. The original smoke above, its topology,
and its CI lane are unchanged. No Rust or Event-helper protocol changes are made.

```
node-a eth0 (10.77.1.2/29) -- veth -- wan1 (10.77.1.1/29)
                                      WAN (forwarding)
node-b eth0 (10.77.2.2/29) -- veth -- wan2 (10.77.2.1/29)
```

All three holders use Docker `--network none`. Two veth pairs are created directly
in their network namespaces; neither end is placed in the host network namespace.
There are no Docker bridges or bridge gateways in this path, so Docker's internal-
bridge forwarding policy is not bypassed or weakened. Endpoints install the other
segment and default routes through WAN's `.1`, with exact gateway/source/device
`ip route get` read-back. WAN has no external interface or default route.
There is no common endpoint management network, host networking,
port publication, external relay, or Internet path. Real `aster-agent` mesh
sockets bind to the endpoint `.2:4433` addresses; the existing Event helper uses
the local `127.0.0.1:8181` API inside each endpoint.

### Privilege and ownership boundary

- Every container uses explicit `--cap-drop ALL`, numeric UID/GID, and
  `--security-opt no-new-privileges`; Docker log storage is disabled.
- Three namespace holders run as `10001:10001`, with a 600-second lifetime and
  no added capabilities. Both agents run under the same nonroot capability-free
  identity. The live oracle reads `/proc/1/status` on all three holders and the
  actual `aster-agent` PID's status on each endpoint; all five capability sets
  must be zero and `NoNewPrivs` must be one.
- The networkless, transient provisioner uses `0:0` plus **CHOWN only**. It creates
  owner-only reference credentials and hands each private mount root and state
  subtree to UID 10001. Only the provisioner sees both endpoint directories;
  it exits and is removed before application operations.
- Three transient route/netem helpers use `0:0` plus **NET_ADMIN only**, sharing
  only the target holder's network namespace. No long-lived container retains
  NET_ADMIN, CHOWN, or other capabilities. Helpers have bounded commands, an
  attached start deadline, explicit exit-code checks, removal, and absence checks.
- The already-root Linux controller runs exactly two bounded host `ip link add`
  commands (five seconds each), with both `netns` targets explicit in each command.
  Target namespace files are pinned by open descriptors after exact owned CID,
  random run label, running state, `none` network mode, nsfs type, and distinct
  non-host inode checks. Docker metadata is rechecked before use. Descriptor paths,
  not reusable container PIDs or names, target link creation; descriptors close on
  success and failure before container cleanup. This requires host NET_ADMIN and
  access to Docker's namespace files under the existing root-controller boundary.
  It adds no SYS_ADMIN, host PID namespace, privileged container, namespace mount,
  host route, host forwarding sysctl, or firewall change. Unsupported namespace
  layout/nsfs or denied link creation fails closed; there is no privilege fallback.
- Each run owns a private `0700` directory. Docker creates `0600` cidfiles under
  an explicit `077` child umask. Only bounded, regular, non-symlink, single-link,
  owner-matching files containing full 64-lowercase-hex IDs authorize operations.
  A partial create's valid cidfile is recovered even when the CLI fails.
  Historical network IDs remain cleanup-only state; this path creates no Docker
  network. Per-run labels permit
  residue detection, **not** name-authorized deletion. Existing cidfiles are
  refused before contacting Docker; no global prune or name-based removal exists.

### Oracle and limits

Both WAN egress interfaces are resolved by their assigned IPs, never interface
order. Each receives `tc netem limit 1000 delay 40ms 5ms loss 1% rate 100mbit`.
Strict `tc qdisc show` read-back must match the ordered configured fields before
publication. A pass additionally requires node B to observe the
exact Event ID, logical key, and payload published by node A.

The receipt distinguishes **configured state read-back** from measured packet
behavior. It records the one-host container limitation and does not claim recovery,
actual packet-loss occurrence, measured latency, resource qualification, physical
readiness, NAT, relay behavior, or the full P1 profile. The fixed seed `104729`
identifies this scenario; it does not seed the kernel's packet selection.
No requirement evidence status or retained-receipt baseline moves.

Scenario input must be a regular non-symlink file and is capped at 16 KiB.
Scenario and command read-back JSON allow at most 64 nested arrays/objects,
counting the root container as one. A non-recursive scan enforces this before
JSON decoding, independent of the Python version's decoder recursion threshold;
brackets inside strings (including escaped quotes/backslashes) do not count.
Over-depth input fails with a sanitized nesting-bound error. Existing UTF-8,
syntax, duplicate-field, and nonfinite-constant rejection remains in force.
Command output (stdout plus stderr) is capped at 2 MiB,
peer input at 200 bytes, PID input at 16 bytes, and each process-status read at
8 KiB. Provisioning accepts only two generated credential files, each at most
64 KiB, and stops directory inventory on a third entry. Commands have explicit
deadlines (at most 90 seconds plus a five-second failure-reap bound); readiness
has at most 40 two-second attempts per endpoint. Endpoint/network helpers also bound
individual `ip`/`tc` calls to five seconds. This is a smoke, not a general scenario
scheduler or a resource benchmark.

Cleanup attempts every owned container and any previously captured network ID independently,
checks exact-ID absence after each removal, and checks run-label residue. Removing
all holders/helpers releases the namespaces, veth pairs, and qdiscs; there is no
separate privileged netem reset container. Only after these attempts does it
remove and check absence of the credential directory **if absence is confirmed**.
Any removal/read-back
failure prevents a pass. A create whose returned ID/cidfile cannot be validated
is **not** deleted by a guessed name; labelled residue is reported as a failure.
Errors expose fixed stage/code/cleanup tokens, not daemon output or credentials.

Private recovery state lives at `/run/lock/aster-path-delivery/recovery` (`0700`),
with a `0600` ownership manifest and original cidfiles/data. Manifest replacement
uses an exclusive unique temporary, file fsync, atomic replacement, and directory
fsync. An interrupted temporary does not block the next ownership checkpoint.
Persistence failures cannot skip owned-container cleanup and retain the fixed
recovery locator instead of exposing raw filesystem errors. A Docker create or
veth setup timeout is not proof that creation stopped: the manifest stays
ambiguous even after an immediately empty daemon listing. Daemon outages or
unconfirmed absence also retain the directory, and a new run refuses to overwrite it.

There is no automatic recovery/delete command. An operator must resolve any
in-flight creation, validate retained private CID ownership and run-label residue,
and verify absence of every owned resource before retiring the original data.
Never delete by guessed names or remove the recovery directory to bypass this gate.
`/run` is volatile: this supports investigation after controller interruption or
daemon failure, **not host reboot or power-loss recovery**. A killed controller
may print no locator; the fixed path above and the next run's `recovery-pending`
diagnostic identify the retained state.

### Validate and execute

```sh
python3 tools/test_aster_path_delivery.py
mise run path-delivery-plan
```

Execution requires a rootful, non-user-remapped **local Linux Docker Engine** at
`unix:///var/run/docker.sock`, root controller privileges, host `iproute2`, Linux
nsfs `NS_GET_NSTYPE`, and kernel veth/netem support.
Remote contexts, rootless Docker, and macOS execution are rejected. The fixed
subnets exist only in the fresh isolated namespaces, not host Docker networks.
A private advisory lock serializes this fixed scenario. Existing recovery state
blocks another run rather than touching unrelated resources.

```sh
docker build --file docker/path-lab/Dockerfile.delivery \
  --tag aster-path-delivery:local .
sudo python3 tools/aster_path_delivery.py \
  docker/path-lab/scenarios/event-delivery-netem.json \
  --execute --docker /usr/bin/docker
```

The delivery CI lane runs controller contracts and the plan before building and
executing the real image. Unit tests use an explicit fake daemon because they run
without Linux/Docker: **they do not prove Docker or network execution**. A live
Linux run is still required to validate Docker capability application, runtime
package formatting, nsfs pinning, cross-namespace veth creation, forwarding, and
real Event delivery. No such Linux execution is implied by the Python regressions.

### Tool provenance for this slice

The implementation uses only Clean Team repository code and standard tooling:
Docker Engine/CLI ([Moby](https://github.com/moby/moby)), Linux network namespaces
and netem, and Debian `iproute2`/Python. No new package resolver or topology
framework is introduced. The image retains the repository's exact Rust base
SHA-256 and the existing Debian bookworm snapshot `20260803T000000Z` from
[`lab/debian.sources`](../../lab/debian.sources). Exact installed iproute2 and
Python versions are written to
`/usr/share/licenses/aster/runtime-package-inventory.tsv` during image build.
Docker Engine and kernel versions are printed by the delivery CI job; they are
host tooling, not falsely presented as version-pinned product dependencies.
No live image package or host version is asserted by a plan-only run.

Public interface references checked for the veth revision (2026-09-10):
[ip-link(8)](https://man7.org/linux/man-pages/man8/ip-link.8.html),
[veth(4)](https://man7.org/linux/man-pages/man4/veth.4.html), and
[NS_GET_NSTYPE(2const)](https://man7.org/linux/man-pages/man2/NS_GET_NSTYPE.2const.html).
The Linux man-pages references identify version 6.19; these are interface
references, not a claim about the execution host version. Host iproute2 and Linux
remain FOSS lab tooling (GPL-2.0 family), not newly linked product dependencies.
