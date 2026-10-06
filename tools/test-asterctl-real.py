#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Clean Room — Privileged: asterctl smoke against the real test-only agent.

Build first with:
  cargo build --locked -p asterctl -p aster-agent \
    --bin asterctl --bin aster-agent-acceptance-fixture \
    --features aster-agent/client,aster-agent/acceptance-test-provider

This uses only ephemeral, unprotected test provisioning, never a deployed node.
"""

import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
TARGET = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
if not TARGET.is_absolute():
    TARGET = ROOT / TARGET
CLI = TARGET / "debug/asterctl"
FIXTURE = TARGET / "debug/aster-agent-acceptance-fixture"


class RealAgentTest(unittest.TestCase):
    def test_status_publish_query_and_subscribe(self):
        self.assertTrue(CLI.is_file(), "build asterctl first")
        self.assertTrue(FIXTURE.is_file(), "build the test-only agent fixture first")
        with tempfile.TemporaryDirectory(prefix="asterctl-real-") as directory:
            root = Path(directory)
            subprocess.run(
                [str(FIXTURE), "prepare", "--root", str(root)],
                check=True, capture_output=True, timeout=30,
            )
            config_path = root / "agent.json"
            config = json.loads(config_path.read_text())
            host, port = config["application"]["listen"].rsplit(":", 1)
            common = [str(CLI), "--host", host, "--port", port, "--timeout", "2",
                      "--token-file", config["credentials"]["client_token_file"]]

            def cli(*arguments, success=True):
                result = subprocess.run(common + list(arguments), capture_output=True, timeout=10)
                if success:
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                return result

            with (root / "agent.log").open("wb") as log:
                agent = subprocess.Popen([str(FIXTURE), "--config", str(config_path)],
                                         stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 30
                    while True:
                        status = cli("--json", "status", success=False)
                        if status.returncode == 0:
                            break
                        self.assertIsNone(agent.poll(), "test agent exited during startup")
                        self.assertLess(time.monotonic(), deadline, "test agent did not become ready")
                        time.sleep(0.1)
                    self.assertEqual(len(base64.b64decode(json.loads(status.stdout)["identity"])), 32)
                    self.assertTrue(cli("status").stdout)
                    self.assertEqual(cli("subscriptions").stdout, b"")
                    self.assertEqual(json.loads(cli("subscriptions", "--json").stdout), [])
                    publish = ["--json", "publish", "--topic", "chat.events",
                               "--scope", "mission/team/alpha", "--operation-key", "cli-smoke-publish",
                               "--ttl-ms", "60000", "asterctl upstream smoke"]
                    first = json.loads(cli(*publish).stdout)
                    replay = json.loads(cli(*publish).stdout)
                    self.assertTrue(first["inserted"])
                    self.assertFalse(replay["inserted"])
                    self.assertEqual(first["id"], replay["id"])
                    self.assertEqual(first["ttlMs"], "60000")
                    self.assertEqual(first["operation_key"], "cli-smoke-publish")
                    events = json.loads(cli("--json", "query", "--topic", "chat.events",
                                            "--scope", "mission/team/*", "--limit", "1").stdout)
                    self.assertEqual(len(events), 1)
                    self.assertEqual(base64.b64decode(events[0]["payload"]), b"asterctl upstream smoke")
                    subscription = ["--json", "subscribe", "--scope", "mission/team/alpha",
                                    "--operation-key", "cli-smoke-subscribe", "chat.events"]
                    created = json.loads(cli(*subscription).stdout)
                    repeated = json.loads(cli(*subscription).stdout)
                    self.assertTrue(created["inserted"])
                    self.assertFalse(repeated["inserted"])
                    self.assertEqual(created["subscriptionId"], repeated["subscriptionId"])
                    self.assertEqual(len(base64.b64decode(created["subscriptionId"])), 32)
                    self.assertEqual(created["operation_key"], "cli-smoke-subscribe")
                    descendant = json.loads(cli(
                        "subscribe", "chat.events", "--scope=mission/team/alpha/*",
                        "--operation-key=cli-smoke-descendant", "--json").stdout)
                    listed = json.loads(cli("subscriptions", "--json").stdout)
                    expected = [
                        {"subscriptionId": created["subscriptionId"], "topic": "chat.events",
                         "scope": "mission/team/alpha", "includeDescendantScopes": False,
                         "operationKey": base64.b64encode(b"cli-smoke-subscribe").decode()},
                        {"subscriptionId": descendant["subscriptionId"], "topic": "chat.events",
                         "scope": "mission/team/alpha", "includeDescendantScopes": True,
                         "operationKey": base64.b64encode(b"cli-smoke-descendant").decode()},
                    ]
                    expected.sort(key=lambda row: base64.b64decode(row["subscriptionId"]))
                    self.assertEqual(listed, expected)
                    text = cli("subscriptions").stdout.decode()
                    self.assertEqual(text.count("SUBSCRIPTION:\n"), 2)
                    self.assertIn('"mission/team/alpha"', text)
                    self.assertIn('"mission/team/alpha/*"', text)
                    self.assertIn('"cli-smoke-subscribe"', text)
                    self.assertIn('"cli-smoke-descendant"', text)
                    for row in expected:
                        self.assertIn(row["subscriptionId"], text)
                    removed = cli("unsubscribe", created["subscriptionId"])
                    self.assertEqual(removed.stdout, b"Subscription removed\n")
                    remaining = json.loads(cli("subscriptions", "--json").stdout)
                    self.assertEqual(remaining, [row for row in expected
                                                if row["subscriptionId"] != created["subscriptionId"]])
                    self.assertEqual(json.loads(cli("unsubscribe", created["subscriptionId"],
                                                    "--json").stdout), {"alreadyAbsent": True})
                    self.assertEqual(json.loads(cli("unsubscribe", descendant["subscriptionId"],
                                                    "--json").stdout), {"alreadyAbsent": False})
                    self.assertEqual(cli("unsubscribe", descendant["subscriptionId"]).stdout,
                                     b"Subscription already absent\n")
                    self.assertEqual(json.loads(cli("subscriptions", "--json").stdout), [])
                    # Replace only the temporary fixture token file, not the agent's in-memory token.
                    Path(config["credentials"]["client_token_file"]).write_text("incorrect-test-token-" * 3)
                    for arguments in (("status",), ("subscriptions",),
                                      ("unsubscribe", created["subscriptionId"])):
                        denied = cli(*arguments, success=False)
                        self.assertEqual(denied.returncode, 1)
                        self.assertEqual(denied.stdout, b"")
                        self.assertIn(b"unauthenticated", denied.stderr)
                        self.assertNotIn(b"incorrect-test-token-", denied.stderr)
                finally:
                    agent.terminate()
                    try:
                        agent.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        agent.kill()
                        agent.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
