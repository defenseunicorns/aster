# Rust quickstart

Embed `aster-node` to use the same actor and redb store as the local agent and
C, Python, and Go bindings. The former `aster-core::ApplicationNode` API and
its SQLite store have been removed; there is no SQLite data migration.

## Choose a data class

Use the runnable examples and live-handle instructions in these guides:

- [State](selected-state-api.md): publish a current value, query its projection,
  and acknowledge durable deliveries.
- [Event](selected-event-api.md): publish immutable Events and recover numbered
  publication operations.
- [Record](selected-record-api.md): query concurrent heads and resolve an exact
  projection with a fresh guard.
- [Blob](selected-blob-api.md): stream immutable content and read authenticated
  pages.

Install the [pinned toolchain](README.md#shared-toolchain-prerequisite) before
running the examples. Each guide describes its disposable provisioning and
state-directory setup. Do not reuse a demonstration identity operationally.

## Runtime ownership

`RunningNode` owns the actor and its store. Obtain class-specific handles from
it; cloning a handle does not open another writer. Publish and query calls are
async. Shut down the running node to drain work and release the store.

For an application that does not need a running actor, the class-specific
stopped facades open the state exclusively. Do not open a stopped facade while
a running node owns that state directory.

A successful publication means committed locally, not delivered to a peer.
Networking is configured at node startup, not by individual publish calls.
See [Carriers and contacts](../transports.md) and
[Application recipes](../application-recipes.md).
