#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Test an existing Aster .deb on two disposable Ubuntu containers."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
HELPER = "/opt/aster-test/aster_lan_mvp.py"


class SmokeError(RuntimeError):
    pass


def prepare(stage, package):
    subnet = "172.29.240.0/24"
    a_ip, b_ip = "172.29.240.2", "172.29.240.3"
    staged = stage / "aster.deb"
    # Copy once, then inspect/hash/build the same bytes even if the source changes.
    shutil.copyfile(package, staged)
    metadata = {}
    for field in ("Package", "Version", "Architecture"):
        result = subprocess.run(["dpkg-deb", "-f", str(staged), field],
                                capture_output=True, text=True, check=False)
        if result.returncode:
            raise SmokeError("input is not a readable Debian package")
        metadata[field.lower()] = result.stdout.strip()
    with staged.open("rb") as stream:
        metadata["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
    for name in ("Dockerfile", "node.py"):
        shutil.copyfile(ROOT / "docker/deb-test" / name, stage / name)
    shutil.copyfile(ROOT / "tools/aster_lan_mvp.py", stage / "aster_lan_mvp.py")
    project = stage.name
    image = f"{project}:local"
    platform = "linux/" + metadata["architecture"]
    services = {}
    for name, address in (("a", a_ip), ("b", b_ip)):
        services[name] = {
            "image": image, "platform": platform, "command": ["run"],
            "user": "aster:aster", "init": True, "read_only": True,
            "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
            "environment": {"ASTER_DEB_PEERS": "${ASTER_DEB_PEERS:-1}"},
            "tmpfs": ["/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777"],
            "volumes": [f"{name}-state:/state"],
            "networks": {"mesh": {"ipv4_address": address}},
            "stop_signal": "SIGINT", "stop_grace_period": "15s",
            "logging": {"driver": "json-file", "options": {"max-size": "2m", "max-file": "2"}},
        }
    services["init"] = {
        "image": image, "platform": platform, "build": {"context": "."},
        "profiles": ["setup"], "command": ["init"], "user": "0:0",
        "network_mode": "none", "read_only": True,
        "tmpfs": ["/seed:rw,nosuid,nodev,noexec,size=16m,mode=0700", "/tmp"],
        "environment": {"A_IP": a_ip, "B_IP": b_ip},
        "volumes": ["a-state:/nodes/a", "b-state:/nodes/b"],
        "cap_drop": ["ALL"], "cap_add": ["CHOWN", "DAC_OVERRIDE", "FOWNER"],
        "security_opt": ["no-new-privileges:true"],
    }
    config = {
        "name": project, "services": services,
        "networks": {"mesh": {"internal": True, "ipam": {"config": [{"subnet": subnet}]}}},
        "volumes": {"a-state": {}, "b-state": {}},
    }
    (stage / "compose.json").write_text(json.dumps(config, indent=2) + "\n")
    wrapper = stage / "compose.sh"
    wrapper.write_text(
        '#!/bin/sh\nset -eu\nexec docker compose --project-name '
        + shlex.quote(project)
        + ' --file "$(dirname -- "$0")/compose.json" "$@"\n'
    )
    wrapper.chmod(0o700)
    (stage / ".dockerignore").write_text(
        "*\n!Dockerfile\n!aster.deb\n!node.py\n!aster_lan_mvp.py\n"
    )
    (stage / "package.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return metadata


def check_event(raw, event_id, key, payload):
    event = json.loads(raw)
    expected = {"id": event_id, "logicalKey": base64.b64encode(key.encode()).decode(),
                "payload": base64.b64encode(payload.encode()).decode()}
    if not isinstance(event, dict) or any(event.get(k) != v for k, v in expected.items()):
        raise SmokeError("received Event identity, logical key, or payload differs")


class Compose:
    def __init__(self, stage):
        self.stage = stage
        self.prefix = ["docker", "compose", "--project-name", stage.name,
                       "-f", str(stage / "compose.json")]

    def run(self, *args, timeout=90, peers=True):
        env = dict(os.environ, ASTER_DEB_PEERS="1" if peers else "0")
        # Disk-backed output avoids holding an unbounded build log in memory.
        with tempfile.TemporaryFile() as output:
            try:
                result = subprocess.run(self.prefix + list(args), cwd=self.stage, env=env,
                                        stdin=subprocess.DEVNULL, stdout=output,
                                        stderr=subprocess.STDOUT, timeout=timeout, check=False)
            except subprocess.TimeoutExpired as error:
                raise SmokeError(f"Compose {args[0]} timed out after {timeout}s") from error
            size = output.tell()
            output.seek(max(0, size - 2 * 1024 * 1024))
            raw = output.read().decode(errors="replace")
        if result.returncode:
            (self.stage / "last-error.log").write_text(raw)
            raise SmokeError(f"Compose {args[0]} failed; see {self.stage / 'last-error.log'}")
        return raw

    def helper(self, node, *args):
        return self.run("exec", "-T", node, "python3", HELPER, *args,
                        "--token-file", "/state/client.token", "--url", "http://127.0.0.1:8181")

    def up(self, *nodes, peers=True):
        self.run("up", "-d", "--no-build", "--force-recreate", *nodes, peers=peers)
        for node in nodes:
            deadline = time.monotonic() + 45
            while True:
                try:
                    self.helper(node, "status")
                    break
                except SmokeError:
                    if time.monotonic() >= deadline:
                        raise SmokeError(f"node {node} did not become ready") from None
                    time.sleep(0.5)

    def stop(self, *nodes):
        self.run("stop", "--timeout", "15", *nodes)
        # Reuse the existing runtime exit/STOP validator, not the discovery flow.
        from aster_lan_mvp_compose import receipt_fields, validate_stopped_services
        validate_stopped_services(self.run("ps", "--all", "--format", "json", *nodes), nodes)
        for node in nodes:
            logs = self.run("logs", "--no-color", "--tail", "500", node)
            if not any(r.get("lifecycle") == "complete" for r in receipt_fields(logs, "STOP")):
                raise SmokeError(f"node {node} did not stop cleanly")

    def transfer(self, key, payload, target="b", event_id=None):
        if event_id is None:
            from aster_lan_mvp import canonical_event_id
            event_id = canonical_event_id(self.helper(
                "a", "publish", "--operation-key", key, "--logical-key", key,
                "--payload", payload, "--id-only").strip())
        if target is not None:
            raw = self.helper(target, "wait", "--event-id", event_id,
                              "--logical-key", key, "--wait-seconds", "45")
            check_event(raw, event_id, key, payload)
        return event_id


def smoke(compose, metadata, keep):
    def progress(message):
        print(f"aster-deb-compose: {message}", file=sys.stderr, flush=True)

    progress("installing the supplied .deb into the Ubuntu image")
    compose.run("build", "init", timeout=900)
    compose.run("run", "--rm", "--no-deps", "init")
    compose.up("a", "b")
    for node in ("a", "b"):
        installed = compose.run("exec", "-T", node, "dpkg-query", "-W",
                               "-f=${Package} ${Version} ${Architecture}", "aster").strip()
        if installed != f"aster {metadata['version']} {metadata['architecture']}":
            raise SmokeError(f"node {node} has a different installed package")
        compose.helper(node, "subscribe", "--operation-key", "deb/subscribe/" + node)
    progress("checking direct Event A -> B")
    first = compose.transfer("deb/online", "hello from packaged A")
    progress("stopping B and publishing two offline Events at A")
    compose.stop("b")
    offline = [(f"deb/offline/{i}", f"offline message {i}") for i in (1, 2)]
    saved = [(key, payload, compose.transfer(key, payload, target=None)) for key, payload in offline]
    # Restart the sender while B remains absent: backlog must survive on disk.
    compose.stop("a")
    compose.up("a")
    for key, payload, event_id in saved:
        compose.transfer(key, payload, target="a", event_id=event_id)
    progress("restoring B and checking delivery of the retained backlog")
    compose.up("b")
    for key, payload, event_id in saved:
        compose.transfer(key, payload, event_id=event_id)
    progress("recreating B with peers disabled; verifying its retained Events")
    compose.stop("a", "b")
    compose.up("b", peers=False)
    compose.transfer("deb/online", "hello from packaged A", event_id=first)
    for key, payload, event_id in saved:
        compose.transfer(key, payload, event_id=event_id)
    compose.stop("b")
    if keep:
        compose.up("a", "b")
    return {"schema": "aster-deb-compose/v1", "status": "pass", "package": metadata,
            "checks": ["package-install", "direct-event-transfer", "offline-sender-restart",
                       "backlog-delivery", "peerless-receiver-recreate"],
            "boundary": "two Docker containers; static peers; reference provisioning; no systemd qualification"}


def interrupt(_signum, _frame):
    raise KeyboardInterrupt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deb", type=Path, required=True, help="existing native amd64/arm64 Aster package")
    parser.add_argument("--keep", action="store_true", help="leave the successful two-node stand running")
    parser.add_argument("--config-only", action="store_true", help="stage/validate without accessing the daemon")
    args = parser.parse_args(argv)
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    stage = Path(tempfile.mkdtemp(prefix="aster-deb-test-"))
    print(f"aster-deb-compose: run directory {stage}", file=sys.stderr, flush=True)
    compose = Compose(stage)
    started = success = False
    result = {"schema": "aster-deb-compose/v1", "status": "fail"}
    code = 2
    try:
        metadata = prepare(stage, args.deb.resolve(strict=True))
        result["package"] = metadata
        compose.run("config", "--quiet")
        if args.config_only:
            result.update(status="config-only", compose_file=str(stage / "compose.json"))
            code = 0
        else:
            server = subprocess.run(["docker", "info", "--format", "{{.Architecture}}"],
                                    capture_output=True, text=True, timeout=15, check=True)
            architecture = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(server.stdout.strip())
            if architecture != metadata["architecture"]:
                raise SmokeError("package architecture must match the Docker daemon; emulation is not qualified")
            started = True
            result = smoke(compose, metadata, args.keep)
            success = True
            code = 0
    except KeyboardInterrupt:
        result["error"] = "interrupted"
        code = 130
    except (SmokeError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result["error"] = str(error)
        print(f"aster-deb-compose: {error}", file=sys.stderr)
    finally:
        if started:
            try:
                (stage / "containers.log").write_text(compose.run("logs", "--no-color", "--tail", "500", "a", "b"))
            except (SmokeError, OSError) as error:
                print(f"aster-deb-compose: log collection: {error}", file=sys.stderr)
            if not (success and args.keep):
                try:
                    compose.run("down", "--volumes", "--remove-orphans", "--rmi", "all", "--timeout", "15")
                except (SmokeError, OSError) as error:
                    result.update(status="fail", cleanup_error=str(error))
                    code = 2
        result["kept_running"] = success and args.keep
        (stage / "receipt.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if success and args.keep:
        prefix = shlex.quote(str(stage / "compose.sh"))
        print(f"Logs: {prefix} logs -f\nCleanup: {prefix} down --volumes --rmi all", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
