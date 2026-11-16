# C: local State publication

Clean Room — Privileged.

Compile the ABI v2 example and use a private copy of the disposable fixture:

```sh
mise exec -- sh tools/with-test-resources.sh cargo build --locked -p aster-ffi
example_root=$(mktemp -d /tmp/aster-c-example.XXXXXX)
install -m 600 bindings/testdata/non-production-provisioning.bundle "$example_root/mission.bundle"
cc -std=c11 -Wall -Wextra -Werror -pedantic -Ibindings/c examples/c_basic.c \
  -Ltarget/debug -laster_ffi -Wl,-rpath,"$(pwd)/target/debug" -o "$example_root/example"
"$example_root/example" "$example_root/mission.bundle" "$example_root/state"
```

`state_path` is an absolute redb state directory. `provisioning_path` names an
absolute owner-only reference artifact; treat its bytes as opaque. Each
versioned structure begins with ABI version and size. Inputs are borrowed for
the call. Results, copied entries/items, and buffers have explicit destructors.

The sample publishes with an operation key and queries one exact State key.
The same operation and payload are retryable after reopen. State/Record finite
TTL is unsupported. Record resolution requires the exact opaque query result;
complete Record deliveries do not substitute for a query guard. Events require
numbered-client recovery. Blob streams retain bounded writes/reads and explicit
length/resume semantics.

See [the C reference](../../bindings/c/README.md) for every operation, ownership
rule and status. ABI v1 batch and dynamic bridge contracts have been removed.
The selected local runtime binds no sockets or process signal handlers. Its
reference provisioning and local tests do not establish release qualification.

```sh
mise exec -- sh tools/with-test-resources.sh sh tools/test-ffi-bindings.sh
```
