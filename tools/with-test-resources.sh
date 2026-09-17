#!/bin/sh
# Keep capacity fixtures runnable without inheriting unbounded host parallelism.
set -eu
if [ "$#" -eq 0 ]; then
    echo "usage: with-test-resources.sh command [argument ...]" >&2
    exit 2
fi

# Several security fixtures create owner-only state and deliberately validate
# it. Match the CI shell instead of inheriting a collaborative login umask.
umask 077

# Cargo otherwise scales compilation and the Rust test harness to every host
# CPU. Large all-feature test binaries can exhaust memory and grow incremental
# artifacts by tens of GiB on high-core developer systems. Keep the established
# full-check defaults while allowing an explicit caller override.
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}"
export CARGO_PROFILE_TEST_DEBUG="${CARGO_PROFILE_TEST_DEBUG:-0}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-4}"

# The 256-pair TCP relay fixture alone holds 1,024 socket descriptors (both
# clients and both accepted sockets per pair), plus its listener/runtime files.
# Leave room for the other parallel fixtures. Change only this process's soft
# limit; never lower a larger existing limit or modify the hard limit.
minimum=4096
current=$(ulimit -S -n)
if [ "$current" != unlimited ] && [ "$current" -lt "$minimum" ]; then
    if ! ulimit -S -n "$minimum"; then
        echo "network tests require at least $minimum open files; soft=$current hard=$(ulimit -H -n)" >&2
        exit 1
    fi
fi
exec "$@"
