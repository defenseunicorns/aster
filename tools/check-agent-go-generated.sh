#!/bin/sh
set -eu

temporary_root=""
cleanup() {
  case "$temporary_root" in
    "") return 0 ;;
    /tmp/aster-agent-go-generated.*)
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
  echo "ERROR agent Go generation requires Buf 1.72.0" >&2
  exit 1
}
command -v protoc-gen-go >/dev/null 2>&1 || {
  echo "ERROR agent Go generation requires protoc-gen-go v1.36.11" >&2
  exit 1
}
command -v protoc-gen-connect-go >/dev/null 2>&1 || {
  echo "ERROR agent Go generation requires protoc-gen-connect-go v1.20.0" >&2
  exit 1
}

test "$(buf --version)" = "1.72.0" || {
  echo "ERROR agent Go generation found an unsupported Buf version" >&2
  exit 1
}
test "$(protoc-gen-go --version)" = "protoc-gen-go v1.36.11" || {
  echo "ERROR agent Go generation found an unsupported protobuf-go generator" >&2
  exit 1
}
test "$(protoc-gen-connect-go --version)" = "1.20.0" || {
  echo "ERROR agent Go generation found an unsupported ConnectRPC generator" >&2
  exit 1
}

if grep -Eq '^[[:space:]]*remote:' conformance/agent-go/buf.gen.yaml; then
  echo "ERROR agent Go generation must use local plugins only" >&2
  exit 1
fi
test "$(grep -Ec '^[[:space:]]*- local: protoc-gen-(go|connect-go)$' conformance/agent-go/buf.gen.yaml)" = "2" || {
  echo "ERROR agent Go generation local plugin configuration is incomplete" >&2
  exit 1
}

temporary_root="$(mktemp -d /tmp/aster-agent-go-generated.XXXXXX)"
chmod 700 "$temporary_root"
cp -a conformance/agent-go/gen "$temporary_root/expected"

: "${BUF_CACHE_DIR:=$temporary_root/buf-cache}"
export BUF_CACHE_DIR
buf generate --template conformance/agent-go/buf.gen.yaml

diff -ru --no-dereference "$temporary_root/expected" conformance/agent-go/gen >/dev/null || {
  echo "ERROR checked-in agent Go client is not reproducible" >&2
  exit 1
}

echo "AGENT_GO_GENERATED status=pass buf=1.72.0 protobuf_go=1.36.11 connect_go=1.20.0 plugins=local"
