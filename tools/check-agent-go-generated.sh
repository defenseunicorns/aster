#!/bin/sh
set -eu

temporary_root=""
cleanup() {
  case "$temporary_root" in
    "") return 0 ;;
    "${TMPDIR:-/tmp}"/aster-agent-go-generated.*)
      find "$temporary_root" -depth -delete
      temporary_root=""
      ;;
    *) return 1 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

command -v buf >/dev/null 2>&1 || {
  echo "ERROR agent Go generation requires Buf" >&2
  exit 1
}
command -v protoc-gen-go >/dev/null 2>&1 || {
  echo "ERROR agent Go generation requires protoc-gen-go" >&2
  exit 1
}
command -v protoc-gen-connect-go >/dev/null 2>&1 || {
  echo "ERROR agent Go generation requires protoc-gen-connect-go" >&2
  exit 1
}

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/aster-agent-go-generated.XXXXXX")"
chmod 700 "$temporary_root"
cp -a conformance/agent-go/gen "$temporary_root/expected"

: "${BUF_CACHE_DIR:=$temporary_root/buf-cache}"
export BUF_CACHE_DIR
buf generate --template conformance/agent-go/buf.gen.yaml

diff -ru --no-dereference "$temporary_root/expected" conformance/agent-go/gen >/dev/null || {
  echo "ERROR checked-in agent Go client is not reproducible" >&2
  exit 1
}

echo "AGENT_GO_GENERATED status=pass"
