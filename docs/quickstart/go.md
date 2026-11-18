# Go: local State publication

Clean Room — Privileged.

The cgo binding embeds the redb-backed `aster-node` runtime through C ABI v2:

```sh
mise exec -- sh tools/with-test-resources.sh cargo build --locked -p aster-ffi
example_root=$(mktemp -d /tmp/aster-go-example.XXXXXX)
install -m 600 bindings/testdata/non-production-provisioning.bundle "$example_root/mission.bundle"
GOCACHE=/tmp/aster-mesh-go-cache mise exec -- go -C bindings/go run \
  -tags aster_workspace ../../examples/go_basic.go \
  "$example_root/mission.bundle" "$example_root/state"
```

The sample explicitly closes the node and query result. It uses an operation key
for retryable publication and an exact State logical key. State/Record do not
accept finite TTL. `Result.Entries` preserves whole Record conflicts; retain the
query result for guarded resolution. Event calls require a recovered client and
numbered sequence. Blob writers/readers implement `io.Writer`/`io.Reader`.

The workspace build tag adds native library search paths. Downstream applications
must package the matching library and set their own cgo linker paths. See the
[Go guide](../../bindings/go/README.md) and [full ABI contract](../../bindings/c/README.md)
for recovery, ownership, streaming and failure behavior.

The sample fixture is public disposable test material, copied to an owner-only
artifact. This embedding opens no transport or signal handler. Its local tests
are not production or network qualification.

```sh
mise exec -- sh tools/with-test-resources.sh sh tools/test-ffi-bindings.sh
```
