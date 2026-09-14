# Iroh and Patchbay: historical connectivity observation

- Experiment date: 2026-08-23
- Public summary revised: 2026-09-27
- Scope: upstream Iroh 1.0.3 with Patchbay 0.6.0, one Linux kernel,
  simulated NAT configurations, and a local relay
- Result: 13 ordinary cases passed; three upstream-ignored cases failed their
  direct-path deadline and remained relayed

## What was tested

[Iroh](https://docs.rs/iroh/1.0.3/iroh/) is the public peer-to-peer QUIC
connectivity library. [Patchbay](https://github.com/n0-computer/patchbay) is
n0-computer's public network-testing library built on Linux network namespaces.
The experiment compiled Iroh's upstream `tests/patchbay` integration tests.

The test image was assembled locally in two stages:

1. A pinned public Rust image plus eight Debian networking/tool packages
   provided the compiler, namespace, traffic-control, and nftables environment.
2. The registered Iroh and Patchbay archives and the checksummed dependency
   graph were built with `cargo test --locked --offline --test patchbay nat::
   --no-run`. The resulting binary and an experiment runner were copied into
   the runtime image.

The recorded build inputs are the public components above and locally authored
packaging/test scripts. This was an upstream-component test, not an execution
of the Aster application. The image identities below describe the local
experiment; registry publication is not established.

The first build attempted to resolve a local image by `name@digest` through
Docker Hub and failed before compilation. The successful build used the local
base tag after checking its image ID and platform. An initial runtime then
failed before topology setup because its scratch directory was read-only.
The final runtime copied the same test binary into writable temporary storage.
Neither earlier attempt contributes a topology result.

## Retained source and build identities

| Input or output | SHA-256 identity |
|---|---|
| [Iroh 1.0.3 archive](https://static.crates.io/crates/iroh/iroh-1.0.3.crate) | `460de6bc52163b41b1646931f2897e5ab986f0966ade444467fec25024751a72` |
| [Patchbay 0.6.0 archive](https://static.crates.io/crates/patchbay/patchbay-0.6.0.crate) | `543b9acbe630f7745965d8243d3af809370cfad7b12d801b63e085e606349852` |
| Public Rust base image | `0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97` |
| Locally built tool image | `d40d7ed6fc1250fac79a3e8d7988446500c3bd990d57b5e40f4a52909f727a8d` |
| Locally built test image | `0c5c65557da6dd58952c8dccf1280e05b7bb3b46fe58b761bd4ff08d0ad12d6d` |
| Executed test binary | `b4f8c83b8e8c57496c0425f744f54693861ced7ad7807aac75e8c799fb2bd411` |
| Archived successful build log | `442885822ad5a7797c6bccb678e9a2a677b6bf5709aaa3d28bf30b95974d8bcd` |
| Archived final run log | `3a1d9fb1fff0098882f811e044737d155a5c8b5d1bf7e49e68dc1c9a21d92042` |

These are historical identities, not newly built or published images. The
original logs, recipes, and setup records are retained separately. This public
record is a derived summary, not the original log or a complete reproduction
bundle. The [machine-readable summary](results/iroh-patchbay.json)
retains all 16 case names, durations, exits, observations, and claim limits.

## Observation and decision relevance

Every case began with an established local relay connection. All 13 ordinary
cases upgraded to direct paths at both endpoints and completed the paired ping
and close sequence. There were 26 direct-transition log entries in total.

The three upstream-ignored pairings—Easy × Hard, Hard × Easy, and Hard × Hard—
failed their 15-second direct-path waits and retained a relay path. They remain
failures in this summary. Consequently the aggregate Docker exit was `1`,
with `normal_pass=13`, `normal_fail=0`, `upstream_ignored_pass=0`, and
`upstream_ignored_fail=3`. The final run reported no infrastructure failures.

The observation supports Iroh as a connectivity component with a known direct
connection limit. It appears in the [final evaluation conclusions](final-frontier.md)
and is explicitly retained as bounded evidence in
[Proposal 0006](../../proposals/0006-selected-foss-reference-stack.md).
It was not the decisive stack comparison: the
[separate integrated bakeoff](final-stack-bakeoff.md) selected Iroh + Negentropy
+ redb based on reconciliation, restart, temporal transfer, crash recovery,
and duplicate-effect results. [Decision 0028](../../decisions/0028-selected-stack-implementation-boundary.md)
subsequently authorized implementation of that composition.

## Limits

The test relay trusted server certificates without verification. This
experiment establishes no relay-TLS or mission-security result. It establishes
no physical NAT, public Internet, ISP/CGN, relay-outage, performance, endurance,
independent-interoperability, or target-fleet result. It does not test Aster's
replication, reconciliation, application semantics, membership, or security
profile. Its historical dependency graph did not receive production admission
from this experiment. The three direct-path failures are not evidence that a
secure, operational relay deployment has been qualified.
