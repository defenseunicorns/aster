# Aster OrbStack laboratory controller

`orchestrate.py` is the reproducible host-side controller for the task-created
`aster-lab` executable. It uses only the Python standard library and invokes
Docker with argument arrays; it never invokes a command shell.

The controller is a dry run unless `--execute` is present. A dry run is a
**structural preview**, not a byte-for-byte command transcript: run IDs,
ownership labels, immutable image IDs, isolated mounts, and collision-preflight
results exist only during execution. No controller command intentionally pulls
an image. Every `docker run` includes `--pull=never`, and `build` always uses
`--pull=false` after proving that the pinned base image is local.

## Safety model

- Docker context must be exactly `orbstack`.
- Docker and the inspected runtime image must normalize to ARM64; other
  architectures fail preflight instead of being compared as equivalent runs.
- Names are fixed under `aster-lab-`; concurrent reuse fails preflight.
- Fixed CIDRs are checked for mutual overlap and against custom Docker IPAM
  configurations before creation. Docker performs the final atomic overlap
  check at creation time.
- Networks use `--internal`; no host port is published.
- Application scenarios use a read-only root filesystem, a private cgroup
  namespace, `no-new-privileges`, and `--cap-drop=ALL`.
- NAT endpoint scaffolds receive `NET_ADMIN` so the controller can replace their
  default routes. The two NAT routers are also the capture points and receive
  exactly `NET_ADMIN`, `NET_RAW`, `SETUID`, and `SETGID`: the last two permit
  the packaged tcpdump process to drop explicitly to its `tcpdump` account
  after opening the capture socket and output file. Infrastructure receives no
  added capability. All other scenarios receive no added capability.
- Every execution creates a new mode-0700 evidence directory. Existing scenario
  directories are never reused.
- For `self-contained`, `resource`, and `scale`, the controller creates only the
  isolated writable role directory mounted at `/output`; it deliberately leaves
  `/output/run` absent so `aster-lab` can atomically claim that scenario root.
  Standalone simulation commands likewise require `--root` not to exist. They
  reject any pre-existing path without modifying it, then retain
  `.aster-lab-invocation` and canonical success or failure metrics in a root they
  own. Provisioning and live-node commands are different: their `/output` root
  is intentionally durable and may already exist.
- The controller receipt area is never mounted into a container. Each role sees
  only its assigned mode-0700 writable directory beneath `outputs/`. Most roles
  mount `outputs/<role>/` at `/output`; each selected live node instead mounts
  only `outputs/provision/node-a` or `outputs/provision/node-b` at exactly
  `/output/node-a` or `/output/node-b`, matching the canonical path used by
  stopped provisioning and preserving the Store's Blob owner binding. Each
  selected live node additionally sees only its own owner-only bundle as the
  exact writable file `/run/secrets/node.bundle`.
  This narrow exception is required because the production loader retains one
  read/write, exclusively locked descriptor for optional exact-inode software
  erasure. The node cannot see the peer state, peer bundle, parent provisioning
  directory, another role's output, or controller receipts; relay certificate
  mounts remain read-only.
- Preflight validates image provenance labels against the current admitted
  source hashes, resolves the tag to one `sha256:` image ID, and every container
  runs that immutable ID. Post-start inspection verifies the image, limits,
  capabilities, user, network, and exact bind-mount set.
- Cleanup reads the run manifest, accepts only an exact allowlist, verifies the
  run/role/ownership labels on each live object, removes containers before
  networks, and never removes an image, volume, or evidence directory. Cleanup
  re-verifies the OrbStack daemon; a failed list/inspect is an error, never
  interpreted as "absent".
- The build preflight requires both deny-all policies, `.dockerignore` and
  `lab/Dockerfile.dockerignore`, to match the reviewed form byte-for-byte. It
  rejects symbolic links and `.git`, `.agents`, or `.codex` anywhere in admitted
  `crates/` inputs, records SHA-256 for every admitted file, then copies those
  exact bytes into a new sealed context inside the evidence directory. Docker
  never rereads the live workspace for that build.

OrbStack currently reports `DOCKER_INSECURE_NO_IPTABLES_RAW`. Consequently, the
lab does not use Docker-published ports or treat Docker's bridge firewall as a
NAT/security oracle. NAT rules live explicitly inside the two router network
namespaces, and captures occur on their WAN interfaces.

## Validate the controller

These checks do not contact Docker:

```sh
python3 -m py_compile lab/orchestrate.py
python3 -m unittest discover -s lab/tests -v
```

## Build

Preview the operation's structure:

```sh
python3 lab/orchestrate.py build
```

Attempt a build whose Dockerfile `RUN` steps receive BuildKit
`--network=none`. This succeeds only if every required build layer is already
cached:

```sh
python3 lab/orchestrate.py build --execute
```

For a first clean build, explicitly authorize dependency acquisition:

```sh
python3 lab/orchestrate.py build --allow-build-network --execute
```

Connected mode uses `--network=default --no-cache --pull=false`. The pinned base
must still exist locally, while Cargo crates locked by `Cargo.lock` and Debian
packages from the task-provided snapshot source may be acquired. The sealed
input manifest, aggregate digest, full plain build stream, metadata, base-image
identity, and final image identity are retained as acquisition/build receipts.
If the fixed image tag already exists, rebuilding also requires the explicit
`--replace-image` option.

The final image contains
`/usr/share/aster-lab/runtime-package-inventory.tsv`, generated by `dpkg-query`
for the five admitted runtime utilities: `iproute2`, `iputils-ping`, `nftables`,
`procps`, and `tcpdump`. After resolving the final immutable image ID, the
controller reads that file in an offline, read-only, capability-free container,
validates the exact package set and canonical row format, and preserves it as
`runtime-package-inventory.tsv` in the build evidence directory with its SHA-256
in `events.jsonl`. This is a version receipt for the explicitly installed
runtime utilities, not a complete transitive package SBOM.

`--network=none` constrains declared Dockerfile `RUN` networking. Together with
the local pinned base, `--pull=false`, and no remote frontend, it is a materially
offline build path for this Dockerfile; it is not packet-level proof that the
Docker/BuildKit daemon emitted no traffic. Such a claim requires an independently
isolated or captured daemon egress boundary.

## Deterministic self-contained scenarios

The following 3,000-bit/s/50%-loss run is a virtual deterministic carrier, not a
live Linux qdisc result:

```sh
python3 lab/orchestrate.py self-contained transfer \
  --bps 3000 --loss-per-mille 500 --mtu 96 --seed 41

python3 lab/orchestrate.py self-contained transfer \
  --bps 3000 --loss-per-mille 500 --mtu 96 --seed 41 --execute
```

The initial bounded experiment at these exact settings did not converge within
120 seconds and was terminated. Preserve that negative result: this command is
for diagnosis, not a passing acceptance recipe. Kernel-shaped live IP is the
authoritative path for the 3 kbps gate; success still requires the declared
priority, expiry, convergence, fairness, and wire-accounting assertions.

The Blob default is exactly 105,906,176 bytes (101 MiB). It stages a partial
transfer from one peer, durably reopens the receiver, completes from another
peer, and verifies generated plaintext without retaining a second source copy:

```sh
python3 lab/orchestrate.py self-contained blob-recovery
python3 lab/orchestrate.py self-contained blob-recovery --execute
```

For either command the controller requires `metrics.json` with schema
`aster-lab-metrics/v1` and `converged=true`. Blob recovery additionally requires
`partial_restart_observed=true`, `durable_progress_preserved=true`, a nonzero
`partial_durable_blob_bytes`, and the same value in
`reopened_durable_blob_bytes`. These fields mean the receiver was still unable
to open the incomplete Blob, had committed encrypted transfer-store progress,
reopened with the same durable byte/chunk usage, and then completed and verified
the generated plaintext through the alternate peer. They do not expose Blob
plaintext or credential material.

## Two real UDP processes

This command creates one internal bridge, provisions two fresh identities from
OS entropy in an offline container, and runs two unprivileged `node-udp`
containers on fixed addresses. Both publishers send identity-distinct Events through the actual
`aster-ip` UDP adapter; each must observe the complete two-publisher set,
authenticate, and report convergence. The higher NodeID responder starts first
and receives a bounded settle interval before the initiator starts.

```sh
python3 lab/orchestrate.py two-node --items 4 --payload-bytes 1024
python3 lab/orchestrate.py two-node --items 4 --payload-bytes 1024 --execute
```

The topology is removed automatically after logs and both metrics records are
captured. Its evidence directory remains.

Each live-node invocation first consumes one append-only
`live-invocation-NNNN.slot`. That single ordinal binds
`live-result-NNNN.json` to its aggregate metrics file (`metrics.json` for slot
0001, then `metrics-NNNN.json`). A failed invocation may have metrics without a
live result, and a process interruption may leave only part of the pair; the
slot is never reused, so later artifacts cannot drift onto its suffix. The
two-node controller uses a fresh role directory, therefore discovers the first
invocation at `metrics.json`; the entire role tree, including the slot and live
result, remains in evidence.

The public `--seed` controls only deterministic canary content. It is not used
for identity or capability material, and credential bytes never appear in a
command argument, public manifest, controller receipt, or peer mount. This is
still reference-to-reference simulation evidence; it is not adversarial
credential-secrecy, cryptographic-strength, or independent-implementation
interoperability evidence.

## Route-only Event custody control

`route-only-event` is Proposal 0001's Phase-0 prerequisite. It provisions an
A publisher, a route-only durable B intermediate, and a C consumer. A and C
never receive a carrier path. B receives the stable source envelope, closes,
is inspected and reopened from the same durable store, and then forwards the
unchanged A-authored Event to C. C application-acknowledges it and a second poll
must be empty.

Each run requires exact provenance for the uncommitted experiment build:

```sh
target/release/aster-lab route-only-event \
  --root lab/runs/phase0-route-only-event-01 \
  --seed 1001 --payload-bytes 1024 --max-pumps 50000 \
  --source-revision 9a8a87e11785c98fd1069cb2338c4076f4c728cb \
  --source-diff-sha256 796fac56ef87b1b16062ebfb1514bc0a15135fd72b01c51582a29dcbe2256ad8 \
  --binary-sha256 ebb712065ce2006bdf6c112c989977b854ed51dfae445c02cc602d4d35294bad
```

Those exact values identify the retained 2026-08-21 Phase-0 run; a new build
must supply its own revision, `git diff --binary` digest, and binary digest.
The command creates `metrics.json`, `receipt.json`, and three independent node
stores without overwriting an existing root. The receipt separates durable
custody, application readability, exact ItemID/EnvelopeID continuity, and
application acknowledgement. A raw-store scan requires payload and payload
SHA-256 canaries to be absent at B. It separately reports whether the logical
key is retained as protected mesh forwarding metadata.

This control uses the deterministic in-memory fault carrier. It proves the
data-plane prerequisite, not IP discovery, NAT traversal, concurrent contacts,
or an operational mesh.

## Automatic three-process LAN mesh demo

Proposal 0001's shared controller runs the complete local A→B→C demonstration
with three independent processes and stores. It is a dry run unless
`--execute` is present. Given a Linux release binary, one command provisions
the nodes, publishes a random command Event, discovers A↔B without peer
locators, stops A, restarts route-only B, discovers B↔C, delivers and
application-acknowledges the exact source item, reconnects A to check duplicate
suppression, writes the receipt, and removes only its temporary networks and
containers:

```sh
python3 lab/ip_mesh_experiment.py \
  --arm native --scenario primary \
  --binary target-linux/release/aster-lab \
  --root lab/runs/manual-native-ip-mesh \
  --trials 1 --execute
```

The final human-checkable result is
`lab/runs/manual-native-ip-mesh/trial-01/result.json`. A passing receipt must
show `passed=true`, the same ItemID and EnvelopeID through custody and delivery,
application acknowledgement, no post-ack redelivery, duplicate suppression,
internal-only networks, and `a_c_contact_count=0`.

This is the retained native LAN oracle governed by
[Decision 0022](../docs/decisions/0022-ip-mesh-experiment-no-selection.md).
It deliberately does not claim manual peering, NAT traversal, connectivity
relay fallback, or fair large-peer scheduling. The historical Iroh and
rust-libp2p comparison binaries and exact commands are bound to experiment
checkpoint `117770259680d89e5fbd1ff1f6c3df9f3e646e6c`; they are not continuing
production dependencies.

## Cgroup-v2 resource capture

The default workload creates one logical node with a 10,000-item metadata set
under one CPU, 64 MiB memory, and no swap:

```sh
python3 lab/orchestrate.py resource
python3 lab/orchestrate.py resource --execute
```

While the container is live, the controller samples:

- `memory.current`, `memory.max`, `memory.peak`, `memory.events`, `memory.stat`,
  `memory.swap.current`, and `memory.swap.max`;
- mandatory `cpu.stat` and `io.stat`, plus `cpu.pressure` when the runtime
  exposes Linux Pressure Stall Information in the private cgroup;
- `pids.current` and `pids.events`;
- Docker's cgroup statistics;
- the `aster-lab` process `smaps_rollup` and `status`.

Every mandatory read, including structured `io.stat` device counters, must
succeed and parse under cgroup v2. Because Pressure Stall Information is a
kernel/configuration capability rather than a cgroups-v2 invariant, the
controller records an explicit `cpu.pressure_available` marker and the command
receipt when it is absent. The controller
verifies `memory.max`, zero swap allowance, and zero `oom`/`oom_kill` counters;
missing Docker stats, cgroup counters, the exact `aster-lab` PID, `smaps_rollup`,
or process status fails the run. Samples are appended to
`resource-samples.jsonl`. A small `sleep` process keeps the container/cgroup
alive while the controller runs the workload as one foreground, receipt-bearing
`docker exec`. After that exact command exits, the controller takes a mandatory
`phase=terminal-cgroup` snapshot before stopping the container; the workload's
exit status and uncombined output are retained. The `scale` coordinator forks
one worker even for a one-node shard, so cgroup memory is authoritative for the
complete workload while PID-specific RSS covers the coordinator only. This run
is a constrained ARM64/OrbStack measurement, not representative mobile hardware
or battery evidence. The sleep supervisor and the controller's short-lived
`docker exec` readers share the measured cgroup and therefore add conservative
observer overhead; do not present the samples as observer-free profiling. A
fresh run with measurement headroom should accompany the hard 64 MiB enforcement
run when diagnosing a failure.

## Five-unit NAT topology

Fixed networks and addresses:

| Segment | Network | Addresses |
|---|---|---|
| LAN A | `aster-lab-lan-a`, `10.250.1.0/24` | node A `.10`, NAT A `.1` |
| WAN | `aster-lab-wan`, `10.250.0.0/24` | NAT A `.11`, NAT B `.12`, infra `.20` |
| LAN B | `aster-lab-lan-b`, `10.250.2.0/24` | node B `.10`, NAT B `.1` |

### Selected Iroh NAT acceptance

`selected-iroh-nat-run` is the fail-closed selected-runtime acceptance path for
this topology. A preview is mutation-free; execution builds the dedicated
locked selected image, runs its Linux helper tests, then executes the direct
and controlled-relay cells into a fresh external evidence root:

```sh
python3 lab/orchestrate.py selected-iroh-nat-run --profile all

python3 lab/orchestrate.py selected-iroh-nat-run --profile all --execute \
  --allow-build-network \
  --evidence-root /private/tmp/aster-selected-iroh-nat
```

Each live node has a fixed 30-second run budget established before endpoint
setup and READY. The selected acceptance command requests an immediate contact
and, when startup leaves enough budget, one nominal repeat at 15.001 seconds;
the next nominal interval falls after the terminal deadline.
Acceptance remains semantic rather than count-based: each endpoint must record
one exact role-bound Event transfer followed by an exact zero-difference
contact, empty stderr, zero contact errors, the expected Direct or Relay path,
and a complete terminal inventory. The remaining quiet portion of the run
budget also lets both WAN capture streams retire their final packet batches
before bounded capture shutdown. A slow or failed contact still fails the
existing deadline, stderr, transfer, no-op, counter, or capture checks; it is
never reclassified as planned-shutdown success.

Both WAN captures request tcpdump `--immediate-mode` delivery and
packet-buffered pcap writes. Finalization requires exactly one terminal
captured, received-by-filter, and dropped counter per capture, captured equal to
received, zero drops, and the parsed pcap packet count equal to captured. Exact
nft-to-pcap equality remains mandatory; no capture-tail discount is permitted.

The direct cell's lower-carrier-ID node is the runtime-selected contact
initiator. Stateful nftables therefore has complementary first-flow evidence:
the initiator router must record positive SNAT and exact-zero DNAT, while the
responder router must record positive DNAT and exact-zero SNAT. Both routers
must independently record positive forward-in and forward-out counters exactly
equal to their parsed WAN packet directions. The controller derives the active
NAT hook from the exact homogeneous `CONTACT direction` receipts instead of
requiring both conntrack creation hooks to fire on reply traffic.

This is bounded one-host Linux-network-namespace evidence with operator-known
static external mappings. It does not prove endpoint discovery or hole
punching, physical or public-internet NAT behavior, a temporal direct-first
fallback, an independently operated relay, mixed implementations, BTLE, or
target-device resource limits. The restrictive cell separately proves use of
the explicitly pinned local HTTPS relay while direct UDP is blocked; it is not
relabeled as physical relay deployment.

Create a deterministic full-cone mapping scaffold:

```sh
python3 lab/orchestrate.py nat-up --profile cone
python3 lab/orchestrate.py nat-up --profile cone --execute
```

Or create a relay-only restrictive scaffold and shape each router's WAN egress:

```sh
python3 lab/orchestrate.py nat-up --profile restrictive \
  --shape-bps 3000 --loss-percent 50 --seed 424242

python3 lab/orchestrate.py nat-up --profile restrictive \
  --shape-bps 3000 --loss-percent 50 --seed 424242 --execute
```

`--seed` is a requested netem seed, not an unconditional determinism claim.
The controller first attempts the seeded form and records whether the installed
`tc` accepted it. The pinned Debian `iproute2` 6.1.0 build rejects the `seed`
token; only that exact unsupported-token response permits a retry without the
token, after which `nat-runtime.json` records `netem_seed_status=unsupported`
and `netem_seed=null`. That kernel loss process is stochastic. The separately
seeded self-contained carrier remains the exact deterministic loss model.

`nat-up` resolves interface names by assigned address rather than assuming
`eth0`/`eth1`, installs namespace-owned nftables rules, records qdisc statistics,
starts pcap capture on both WAN interfaces, and runs the combined unprivileged
UDP-rendezvous/TCP-relay service on WAN `.20`. It intentionally leaves the five
units running and prints the evidence directory used for cleanup.

Readiness is fail-closed: infrastructure must remain running and emit
`ASTER_LAB_INFRA_READY`, and each router must have a live `tcpdump` process plus
a complete pcap global header before `nat-topology-ready` is recorded. On
cleanup, the controller sends `SIGINT` to both capture processes, waits for them
to exit, validates both pcap headers, captures terminal qdisc and nftables
counters, preserves final infrastructure/container logs, gracefully stops the
five units, and only then removes them. A host/VM crash before cleanup can still
leave an incomplete capture and is not claimed as finalized evidence.
If normal finalization fails, cleanup fails closed and retains the resources so
the evidence can be inspected or finalization retried.

Finalization is two-phase and retryable. Before signaling either capture, the
controller atomically publishes a start marker that binds the terminal qdisc,
nftables, and infrastructure-log receipts by SHA-256. The final marker also
binds each flushed pcap by path, size, and SHA-256. A retry accepts an
already-stopped capture only after validating those bound receipts; cleanup
revalidates the final marker before it can authorize resource removal.

At present this command proves only that the controlled topology was created.
It does **not** claim NAT acceptance: although the combined infrastructure is
live, a full result additionally requires live nodes using `node-rendezvous` and
`node-relay`, negative direct-path probes in restrictive mode, authenticated
application convergence, and capture assertions. Do not relabel a topology-only
run as direct traversal or relay-fallback evidence.

Remove the exact owned objects later with:

```sh
python3 lab/orchestrate.py cleanup /absolute/path/to/the/nat-run
python3 lab/orchestrate.py cleanup /absolute/path/to/the/nat-run --execute
```

The second command refuses any object whose current ownership labels differ
from that run's immutable controller manifest.

## Scale cohorts

One hundred nodes across four worker processes:

```sh
python3 lab/orchestrate.py scale --nodes 100 --shards 4
python3 lab/orchestrate.py scale --nodes 100 --shards 4 --execute
```

One thousand nodes across ten worker processes, using the current OrbStack
allocation conservatively:

```sh
python3 lab/orchestrate.py scale --nodes 1000 --shards 10 \
  --cpus 15 --memory 32g --timeout 3600

python3 lab/orchestrate.py scale --nodes 1000 --shards 10 \
  --cpus 15 --memory 32g --timeout 3600 --execute
```

The current `aster-lab scale` command creates independent, process-sharded
store-and-forward chains. It is valuable for node-count, bounded-state, process,
and deterministic-fault stress. It does not yet create cross-shard bridge edges,
heterogeneous live-IP segments, or the exact authorized-delivery matrix required
to close the 100-node or 1,000-node bridged acceptance gates.

## Evidence layout

Every executed operation creates a directory named approximately:

```text
lab/runs/20260818T190000Z-two-node-0123456789abcdef/
```

It contains:

- `controller.json`: immutable run identity and exact planned resources;
- `commands.jsonl`: ordered argument arrays, timings, return codes, and hashes
  of any standard input;
- `command-NNNN.stdout` / `.stderr`: uncombined command output;
- `events.jsonl`: append-only creation, assertion, and cleanup events;
- Docker capability and exact image-identity receipts;
- for builds, the canonical `runtime-package-inventory.tsv` receipt from the
  final immutable image;
- `scenario-request.json`, followed by parameter-specific host cross-checks of
  the scenario and live-node metrics;
- isolated `outputs/<role>/` trees containing only that role's scenario state,
  ownership/invocation slots, metrics, live results, or capture;
- logs, initial/final qdisc data, final nftables counters, NAT finalization, or
  parsed resource samples as applicable.

Evidence directories are never deleted by cleanup. External archival/signature
of a receipt root remains a separate gate.
The provisioning output contains mode-0600 **simulation** bundles and capability
files; archive and disclose that output as protected test material even though
it is not production credential material.

## Claim boundaries

Passing these commands can support controlled reference-to-reference software
evidence. It cannot establish physical BTLE/RF behavior, battery behavior, FIPS
validation, independent-SUT interoperability, signed downgrade policy,
representative embedded hardware, universal NAT traversal, or external evidence
anchoring.
