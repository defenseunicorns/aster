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
default_test_threads=4
online_cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
case "$online_cpus" in
    ''|*[!0-9]*) ;;
    *)
        if [ "$online_cpus" -gt 0 ] && [ "$online_cpus" -lt "$default_test_threads" ]; then
            default_test_threads=$online_cpus
        fi
        ;;
esac
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-$default_test_threads}"

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

# Both provider packages intentionally deliver a binary named `aster-agent`.
# Classify only the repository's bounded workspace-test grammar, then give the
# systemd workspace and Compose package distinct output roots.
classify_workspace_test() (
    [ "$1" = cargo ] || exit 1
    shift
    toolchain=
    case "${1:-}" in
        +*) toolchain=$1; shift ;;
    esac
    [ "${1:-}" = test ] || exit 1
    shift
    locked=0
    workspace=0
    all_features=0
    offline=0
    no_run=0
    for argument in "$@"; do
        case "$argument" in
            --locked) [ "$locked" -eq 0 ] || exit 1; locked=1 ;;
            --workspace) [ "$workspace" -eq 0 ] || exit 1; workspace=1 ;;
            --all-features) [ "$all_features" -eq 0 ] || exit 1; all_features=1 ;;
            --offline) [ "$offline" -eq 0 ] || exit 1; offline=1 ;;
            --no-run) [ "$no_run" -eq 0 ] || exit 1; no_run=1 ;;
            *) exit 1 ;;
        esac
    done
    [ "$locked" -eq 1 ] || exit 1
    [ "$workspace" -eq 1 ] || exit 1
    [ "$all_features" -eq 1 ] || exit 1
    printf '%s %s %s\n' "${toolchain:-none}" "$offline" "$no_run"
)

classification=$(classify_workspace_test "$@" || true)
if [ -n "$classification" ]; then
    set -- $classification
    toolchain=$1
    [ "$toolchain" != none ] || toolchain=
    offline=${2:-0}
    no_run=${3:-0}
    target_root=${CARGO_TARGET_DIR:-target}

    set -- test --locked
    [ "$offline" -eq 0 ] || set -- "$@" --offline
    [ "$no_run" -eq 0 ] || set -- "$@" --no-run
    if [ -n "$toolchain" ]; then
        CARGO_TARGET_DIR="$target_root/systemd-workspace" \
            cargo "$toolchain" "$@" --workspace --all-features \
            --exclude aster-compose-credentials
        CARGO_TARGET_DIR="$target_root/compose-package" \
            exec cargo "$toolchain" "$@" -p aster-compose-credentials --all-features
    else
        CARGO_TARGET_DIR="$target_root/systemd-workspace" \
            cargo "$@" --workspace --all-features --exclude aster-compose-credentials
        CARGO_TARGET_DIR="$target_root/compose-package" \
            exec cargo "$@" -p aster-compose-credentials --all-features
    fi
fi
exec "$@"
