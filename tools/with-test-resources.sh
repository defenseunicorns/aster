#!/bin/sh
# Keep capacity fixtures runnable alongside other tests without changing their scale.
set -eu
if [ "$#" -eq 0 ]; then
    echo "usage: with-test-resources.sh command [argument ...]" >&2
    exit 2
fi
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
