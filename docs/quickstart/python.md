# Python: local State publication

Clean Room — Privileged.

The Python binding embeds the selected node using C ABI v2 and redb. Build and
run the shipped example with a private copy of the disposable public fixture:

```sh
mise exec -- sh tools/with-test-resources.sh cargo build --locked -p aster-ffi
example_root=$(mktemp -d /tmp/aster-python-example.XXXXXX)
install -m 600 bindings/testdata/non-production-provisioning.bundle "$example_root/mission.bundle"
PYTHONPATH=bindings/python mise exec -- python3 examples/python_basic.py \
  "$example_root/mission.bundle" "$example_root/state"
```

The sample publishes State under an explicit operation key and queries its
exact topic/scope/logical key. Repeating it returns the same durable publication.
A changed intent requires a new operation key. State/Record have no finite TTL.

Nodes and results are context managers. Close results promptly; retain a Record
query result while using its opaque resolution guard. Subscription polls expose
complete entries with attempt numbers and acknowledgement tokens. Event
publication additionally requires durable numbered-client recovery. Blob writers
require declared length and support bounded checkpoint resume.

Use [the wrapper guide](../../bindings/python/README.md) for signatures and
[the ABI contract](../../bindings/c/README.md) for limits, error/ownership rules,
recovery and zeroization. The example's unprotected reference credentials are
only disposable test inputs. This local embedding opens no transport or signal
handler and makes no remote-delivery or production qualification claim.

Run all real bindings with:

```sh
mise exec -- sh tools/with-test-resources.sh sh tools/test-ffi-bindings.sh
```
