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

The separate delivery image, topology, controller, and scenario send exactly one
Event between two real `aster-agent` processes. Mesh sockets bind only to
`10.77.1.2:4433` and `10.77.2.2:4433`; fixed authenticated peers route through
the two-interface WAN namespace. The endpoint containers drop all capabilities.
Short-lived, fixed network-setup helpers receive `NET_ADMIN`, then are removed;
only the retained WAN process has `NET_ADMIN`. A networkless provisioner sees
both endpoint directories only while generating state, and is removed before
application operations. Each endpoint receives only its own node directory and
credential subtree.

The pass oracle requires Containerlab read-back of the configured 40 ms delay,
5 ms jitter, 1% loss, and 100000 kbit rate, followed by observation at node B of
the exact Event ID, logical key, and payload. The receipt records configured and
observed emulation, not measured network behavior. The receipt explicitly marks
the one-host container limitation and does not claim recovery, actual packet-loss
occurrence, measured latency, resource bounds, NAT, relay behavior, physical
readiness, or the full P1 profile.
The fixed seed `104729` identifies the canonical scenario; Containerlab `0.79.0`
does not expose a packet-loss RNG seed through this netem command, so the seed is
not claimed to make packet selection deterministic.
Cleanup resets netem, destroys the lab, confirms the lab is absent, and removes
the temporary credential-bearing lab directory before a pass receipt is emitted.

Validate anywhere:

```sh
mise run path-delivery-plan
```

Execute only on a privileged Linux Docker host with Containerlab `0.79.0`:

```sh
docker build --file docker/path-lab/Dockerfile.delivery \
  --tag aster-path-delivery:local .
sudo mise run path-delivery-smoke
```
