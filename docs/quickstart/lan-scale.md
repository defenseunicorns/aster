# Concurrent LAN scale baseline


This opt-in diagnostic puts 8, 16, or 32 authorized Aster nodes and one
different-authority outsider on a generated private Docker bridge. It answers a
narrow question: can the current rosterless LAN building block form a connected,
mission-authenticated mesh and converge exact offline Events while every process
is running concurrently?

It does not test the intended thousand-node architecture. Larger networks use
bounded propagation through topics, scopes, relays, and filtered hierarchical
bridges. Thirty-two authorized members is the deliberate last flat-LAN baseline
before that work.

## Prerequisites

- Native Linux with Docker Engine and the Compose plugin. Docker Desktop and
  non-Linux virtualized multicast paths are outside this diagnostic.
- Enough memory and process capacity for 33 simultaneous Rust agents at the
  32-node tier.
- Permission to use the Docker daemon. If Docker group membership was added in
  the current login session, start a fresh login shell before running the test.
- The repository toolchain installed with `mise install`.

The runner creates only randomly named `aster-lan-scale-*` projects and one
uniquely named image. It has no keep mode and performs no broad Docker prune.

## Start with eight nodes

Validate the generated model without starting containers:

```sh
mise run lan-scale-compose -- --nodes 8 --config-only
```

Then run the functional canary:

```sh
mise run lan-scale-compose -- --nodes 8
```

Advance explicitly after inspecting each result:

```sh
mise run lan-scale-compose -- --nodes 16
mise run lan-scale-compose -- --nodes 32
```

The tool does not silently retry a failed tier or launch all three tiers by
default. Image layers remain eligible for Docker's ordinary build cache, but
the test's image tag, containers, volumes, and network are removed after every
run.

## What one run does

1. Generate a complete Compose model with one distinct credential, carrier
   identity, store, client token, and volume per process.
2. Start every process with discovery disabled. Every authorized node creates a
   durable subscription and publishes one unique 1-KiB Event while it has no
   route to a peer.
3. Stop the cohort cleanly, then start all authorized nodes and the outsider
   together with `--discover-lan`. No peer identity or address is configured.
4. Query nodes concurrently until one current batch shows every authorized
   store contains the exact complete Event set with no extra identity. A
   successful partial response after a node first reports the complete set is a
   hard regression failure; only an unavailable local query is retried. Build
   the time-unioned graph from carrier-correlated, mission-authenticated
   `CONTACT` receipts and require it to be connected.
5. Require the outsider to complete no authorized contact and return an empty
   application query. Candidate-limit and authenticated-member-capacity drops
   fail the run.
6. Observe a short post-convergence window, require another exact no-extra
   inventory, and stop every process with a successful `STOP` receipt.
7. Restart all authorized nodes with discovery disabled and require the same
   complete durable Event set.
8. Remove the exact project resources and audit that cleanup completed.

The synchronization interval is deliberately scaled with the tier: 5 seconds
at 8 nodes, 10 seconds at 16, and 20 seconds at 32. A transient local query
command failure is retried only within the bounded exact-inventory deadline and
is reported in `transientQueryErrors` plus `diagnosticWarnings`; it is not
silently discarded. A successful but malformed, extra, changed, or regressed
inventory fails immediately.

At 32 authorized nodes, every member has 31 authorized remotes plus the outsider:
exactly 32 possible remote carrier candidates. The diagnostic intentionally does
not raise the product's current candidate or authenticated-member bounds.

## Reading the result

Progress is written to standard error. A successful run writes one bounded JSON
document to standard output. It includes:

- first-exact per-node timing, the later all-exact batch timing, and container
  start skew;
- candidate/contact/error counts and authenticated graph degree;
- exact Event and outsider-negative check counts;
- sampled Docker container memory, CPU, PID, network, and block-I/O counters,
  plus apparent state bytes;
- restart persistence outcomes; and
- the host, workload, runtime-control, and claim-boundary configuration needed
  to interpret those measurements.

Any correctness failure, disconnected graph, unauthorized pass, capacity drop,
unexpected/nonzero exit, exhausted enclosing deadline, restart mismatch, or
leaked project resource is a failed run. Resource values are diagnostic rather
than thresholds:

- a large CPU/network jump between 8→16 or 16→32 is a warning to fix contact
  scheduling before increasing membership;
- sharply growing per-node memory suggests peer-related state is not effectively
  bounded; and
- a clean 32-node result means the local building block is ready to be composed
  through hierarchy, not that 100- or 1,000-node operation has been proven.

Container-accounted memory is not target-device RSS, interface counters are not
physical-wire measurements, sampled CPU is not energy, and one Docker host is
not a physical multicast or independent-failure-domain test. Convergence polling
also launches concurrent short-lived `docker compose exec` Python clients, so
sampled container CPU, memory, and PID peaks include that diagnostic overhead.

## Evidence boundary

This runner is development tooling aligned with roadmap action `P2-2`. Adding or
running it does not move a requirement status and does not create retained
evidence automatically. In particular it does not satisfy the provisional
100-node-per-scope or 1,000-node-across-bridges targets, any hierarchical bridge
row, Tier-2 resource brackets, hostile-LAN qualification, or release acceptance.
