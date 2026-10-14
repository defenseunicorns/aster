#!/usr/bin/env python3
"""Clean Room — Privileged: bounded numbered Go/Rust interoperability smoke.

This test retains no qualification or physical-performance evidence. It uses
only the repository's explicitly unprotected acceptance provisioning provider.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def run(fixture: Path, client: Path, load: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="aster-numbered-go-") as temporary:
        root = Path(temporary).resolve()
        subprocess.run([str(fixture), "prepare", "--root", str(root)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        config_path = root / "agent.json"
        config = json.loads(config_path.read_text())
        application = "http://" + config["application"]["listen"]
        health = "http://" + config["health"]["listen"] + "/readyz"
        token = config["credentials"]["client_token_file"]
        process = None
        output = (root / "agent.stdout").open("wb")
        errors = (root / "agent.stderr").open("wb")

        def start() -> None:
            nonlocal process
            process = subprocess.Popen([str(fixture), "--config", str(config_path)],
                                       stdin=subprocess.DEVNULL, stdout=output, stderr=errors)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("acceptance agent exited before readiness")
                try:
                    with urllib.request.urlopen(health, timeout=0.5) as response:
                        if response.status == 200:
                            return
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(0.1)
            raise RuntimeError("acceptance agent readiness deadline elapsed")

        def stop(kill: bool = False) -> None:
            nonlocal process
            if process is not None:
                process.send_signal(signal.SIGKILL if kill else signal.SIGTERM)
                code = process.wait(timeout=30)
                if code != (-signal.SIGKILL if kill else 0):
                    raise RuntimeError("acceptance agent stop status changed")
                process = None

        def call(command: str, request: dict, *, rejected: bool = False) -> dict:
            completed = subprocess.run(
                [str(client), command, "--url", application, "--token-file", token,
                 "--timeout-seconds", "15"], input=json.dumps(request).encode(),
                capture_output=True, timeout=20)
            if rejected:
                if completed.returncode == 0:
                    raise RuntimeError("changed retained numbered intent was accepted")
                result = json.loads(completed.stderr)
                if result.get("code") != "aborted":
                    raise RuntimeError("numbered intent conflict was not a public rejection")
                return result
            if completed.returncode != 0:
                raise RuntimeError("generated Go client failed")
            result = json.loads(completed.stdout)
            if result.get("status") != "ok":
                raise RuntimeError("generated Go client receipt was invalid")
            return result

        try:
            start()
            identity = {"client_id_hex": b"go-real-numbered-source-v1".hex(),
                        "journal_path": str(root / "source-publication.json")}
            call("publication-init", identity)
            intent = dict(identity, topic="chat.events", scope="mission/team/alpha",
                          priority="immediate", logical_key_hex=b"go-real-numbered".hex(),
                          payload_hex=b"original intent".hex())
            first = call("publish", intent)
            if first.get("inserted") is not True or first.get("operation_sequence") != 1:
                raise RuntimeError("fresh numbered publication did not commit sequence one")
            stop(kill=True)
            start()
            replay = call("publish", dict(intent, operation_sequence=1))
            if replay.get("inserted") is not False:
                raise RuntimeError("recovered publication was inserted again")
            for field in ("event_id_hex", "publisher_id_hex", "publisher_counter", "event_sequence", "acceptance_marker"):
                if replay.get(field) != first.get(field):
                    raise RuntimeError("recovered publication receipt changed")
            call("publish", dict(intent, operation_sequence=1, payload_hex=b"changed intent".hex()), rejected=True)
            call("publication-ack", dict(identity, operation_sequence=1))
            second = call("publish", dict(intent, payload_hex=b"next intent".hex()))
            if second.get("inserted") is not True or second.get("operation_sequence") != 2:
                raise RuntimeError("application sequence did not advance after acknowledgement")
            call("publication-ack", dict(identity, operation_sequence=2))

            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
            journals = root / "load-journals"
            for index, initialize in enumerate((True, False)):
                receipt_path = root / ("load-%d.json" % index)
                arguments = [str(load), "--url", application, "--token-file", token,
                    "--count", "8", "--rate", "1", "--payload-bytes", "256",
                    "--topic", "chat.events", "--scope", "mission/team/alpha",
                    "--operation-prefix", "go-real-fixed-workers", "--concurrency", "2",
                    "--timeout-seconds", "15", "--output", str(receipt_path),
                    "--source-commit", commit, "--binary-sha256", hashlib.sha256(load.read_bytes()).hexdigest(),
                    "--config-sha256", hashlib.sha256(config_path.read_bytes()).hexdigest(),
                    "--sample-every", "2", "--journal-dir", str(journals),
                    "--initialize-journals", str(initialize).lower()]
                completed = subprocess.run(arguments, capture_output=True, timeout=30)
                if completed.returncode != 0:
                    if receipt_path.exists():
                        failed = json.loads(receipt_path.read_text())
                        diagnostic = {name: failed.get(name) for name in ("stop_reason", "counts", "probes")}
                        raise RuntimeError("journaled Go load or probe failed: " + json.dumps(diagnostic))
                    raise RuntimeError("journaled Go load failed before an observation receipt")
                receipt = json.loads(receipt_path.read_text())
                if receipt["schema"] != "aster-agent-load/v2" or receipt["counts"]["inserted"] != 8:
                    raise RuntimeError("numbered workload observation changed")
                for checkpoint in journals.glob("worker-*.json"):
                    if json.loads(checkpoint.read_text())["Entries"]:
                        raise RuntimeError("completed workload retained acknowledged results")
                if initialize:
                    stop()
                    start()
            stop()
        finally:
            if process is not None:
                process.kill()
                process.wait(timeout=10)
            output.close()
            errors.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--load", type=Path, required=True)
    options = parser.parse_args()
    run(options.fixture.resolve(), options.client.resolve(), options.load.resolve())
    print("NUMBERED_GO_REAL status=pass restart=pass exact-retry=pass conflict=pass acknowledgement=pass bounded-load=pass")
