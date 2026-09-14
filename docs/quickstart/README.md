# Aster quickstarts

Choose one runnable experience or one application API. Detailed acceptance
evidence belongs under [`docs/validation`](../validation/); these guides focus
on using the current product surface.

## Choose a runnable experience

| Goal | Command or interface | Guide |
|---|---|---|
| Learn the offline-first model through a three-node story | `mise run hello` | [Aster Field Notes](hello.md) |
| Run deterministic local capability demonstrations | `mise run tour` | [Capability tour](capability-tour.md) |
| Keep 2–32 local Event agents running interactively | `mise run playground -- --nodes N` | [Message playground](message-playground.md) |
| Rehearse automatic LAN discovery on one host | `mise run lan-mvp-compose` | [LAN MVP](lan-mvp.md#fast-one-host-docker-rehearsal) |
| Exercise automatic discovery across three trusted-LAN hosts | `aster-agent --discover-lan` | [LAN MVP](lan-mvp.md) |
| Measure the bounded 8/16/32-node LAN diagnostic | `mise run lan-scale-compose -- --nodes N` | [LAN scale](lan-scale.md) |
| Run a five-node static Event hierarchy | `mise run hierarchy-mvp-compose` | [Hierarchy MVP](../../docker/hierarchy-mvp/README.md) |
| Measure the 8/32/64-publisher hierarchy diagnostic | `mise run hierarchy-scale-compose -- --publishers-per-leaf N` | [Hierarchy scale](hierarchy-scale.md) |
| Rehearse a built Debian package with two static peers | `mise run deb-compose -- --deb /path/to/aster.deb` | [Package Compose smoke](../../docker/deb-test/README.md) |
| Operate the bounded Linux Event evaluation slice | Operator procedures | [Linux Event MVP runbook](../mvp/linux-event-mvp-runbook.md) |

These experiences are evaluation and development paths. A successful local,
Compose, or trusted-LAN run does not establish production readiness, physical
transport qualification, independent interoperability, requirement-scale
capacity, or release authorization.

## Choose an application API

| Application boundary | API | Guide |
|---|---|---|
| Local Connect, gRPC, or gRPC-Web client | Authenticated Event-only `aster.application.v1alpha1` service | [ConnectRPC agent](connect-agent.md) |
| Selected live or stopped Event in Rust | `SelectedEventHandle` or `SelectedEventNode` | [Event API](selected-event-api.md) |
| Selected live or stopped control administration in Rust | `SelectedControlHandle` or `SelectedControlAdmin` | [Event control operations](selected-event-api.md#publish-controls-through-the-live-actor) |
| Selected live or stopped State in Rust | `SelectedStateHandle` or `SelectedStateNode` | [State API](selected-state-api.md) |
| Selected live or stopped Record in Rust | `SelectedRecordHandle` or `SelectedRecordNode` | [Record API](selected-record-api.md) |
| Selected live or stopped Blob in Rust | `RunningNode::selected_blobs()` or `SelectedBlobNode` | [Blob API](selected-blob-api.md) |
| Broader semantic Rust API | `ApplicationNode` | [Rust](rust.md) |
| Broader semantic Python API | Dependency-free `ctypes` wrapper | [Python](python.md) |
| Broader semantic Go API | cgo wrapper | [Go](go.md) |
| Stable C-compatible interface | C ABI v1 | [C](c.md) |

The selected Rust handles share the running node’s bounded actor and store
authority. The broader Rust/C/Go/Python examples are offline semantic API
exercises and are not selected-live-node bindings. The local agent currently
exposes Event and local status; State, Record, and Blob RPCs remain open.

For operation selection and cross-language names, use
[Application recipes](../application-recipes.md).

## What the examples establish

All application quickstarts use disposable, non-production provisioning. They
show a bounded subset of the following behavior:

- publication commits locally before any delivery claim;
- queries read bounded local state and do not contact peers;
- durable subscriptions can redeliver until acknowledged;
- State exposes deterministic current-value projection;
- Record keeps concurrent heads explicit and resolves against an exact guard;
- Blob uses bounded streaming or file-backed publication and authenticated
  reads; and
- selected Event supports gap and peer/contact status without treating status
  as convergence proof.

The class-specific guides state their exact live, stopped, restart, transport,
and evidence limits. Do not generalize one guide’s result to another data
class, binding, platform, or deployment profile.

## Shared toolchain prerequisite

The repository pins Rust 1.97.1, installed with `mise install`. The crates’
minimum supported Rust version is Rust 1.91. Each language quickstart uses the
pinned toolchain to build the Rust core or native library.

## Shared vocabulary

- A **topic** identifies what the data is.
- A **scope** limits where it may propagate.
- A **logical key** identifies an entity or stream within the selected data
  class.
- A **data class** selects convergence behavior.
- **Priority** and **TTL** are independent scheduling and lifecycle inputs.
- A **publish result** identifies a durable local commit, not peer delivery.

Read [Core concepts](../concepts.md) before adapting an example to operational
data. Then use [Carriers and contacts](../transports.md) for live
synchronization and [Security](../security.md) for provisioning and deployment
boundaries.
