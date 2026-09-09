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
