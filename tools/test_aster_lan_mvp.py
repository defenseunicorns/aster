#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Focused tests for the bounded Aster LAN MVP operator client."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("aster_lan_mvp.py")
SPEC = importlib.util.spec_from_file_location("aster_lan_mvp_under_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
client_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = client_module
SPEC.loader.exec_module(client_module)


TOKEN = "ab" * client_module.TOKEN_BYTES


def event_id(number: int) -> str:
    return base64.b64encode(bytes([number]) * 32).decode("ascii")


class FakeResponse:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status = status_code
        if isinstance(payload, bytes):
            self.body = payload
        else:
            self.body = json.dumps(payload).encode("utf-8")
        self.read_bound = None

    def read(self, bound: int) -> bytes:
        self.read_bound = bound
        return self.body[:bound]


class FakeConnection:
    requests = []
    responder = None

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.request_record = None
        self.closed = False

    def request(self, verb: str, path: str, body: bytes, headers: dict) -> None:
        decoded = json.loads(body.decode("utf-8"))
        self.request_record = (verb, path, decoded, dict(headers))
        self.requests.append(self.request_record)

    def getresponse(self) -> FakeResponse:
        assert self.request_record is not None
        responder = type(self).responder
        assert responder is not None
        return responder(self.request_record)

    def close(self) -> None:
        self.closed = True


class TokenTests(unittest.TestCase):
    def test_token_creation_is_exclusive_private_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "client.token"
            client_module.create_token_file(path)
            self.assertRegex(path.read_text(encoding="ascii"), r"^[0-9a-f]{64}\n$")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(client_module.read_token_file(path), path.read_text().strip())
            with self.assertRaisesRegex(client_module.OperatorError, "already exists"):
                client_module.create_token_file(path)

    def test_token_reader_rejects_broad_permissions_and_non_hex(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "client.token"
            path.write_text(TOKEN + "\n", encoding="ascii")
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(client_module.OperatorError, "group or others"):
                client_module.read_token_file(path)
            os.chmod(path, 0o600)
            path.write_text("not-a-token\n", encoding="ascii")
            with self.assertRaisesRegex(client_module.OperatorError, "64 lowercase hexadecimal"):
                client_module.read_token_file(path)
            path.write_text("AB" * client_module.TOKEN_BYTES + "\n", encoding="ascii")
            with self.assertRaisesRegex(client_module.OperatorError, "lowercase"):
                client_module.read_token_file(path)


class ClientTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeConnection.requests = []
        FakeConnection.responder = None
        self.patcher = mock.patch.object(client_module.http.client, "HTTPConnection", FakeConnection)
        self.patcher.start()

    def tearDown(self) -> None:
        self.patcher.stop()

    def test_status_subscribe_and_paginated_query_use_connect_json(self) -> None:
        query_calls = 0

        def responder(request):
            nonlocal query_calls
            _verb, path, payload, _headers = request
            method = path.rsplit("/", 1)[-1]
            if method == "GetStatus":
                return FakeResponse(200, {"authenticatedContacts": "2"})
            if method == "CreateEventSubscription":
                return FakeResponse(200, {"subscriptionId": event_id(8), "inserted": True})
            if method == "QueryEvents":
                query_calls += 1
                marker = int(payload["afterAcceptanceMarker"])
                if marker == 0:
                    return FakeResponse(
                        200,
                        {"events": [{"id": event_id(1)}], "scannedThrough": "1", "hasMore": True},
                    )
                return FakeResponse(
                    200,
                    {"events": [{"id": event_id(2)}], "scannedThrough": "2", "hasMore": False},
                )
            raise AssertionError("unexpected method")

        FakeConnection.responder = responder
        client = client_module.ConnectJsonClient("http://127.0.0.1:8181", TOKEN)
        self.assertEqual(client.status()["authenticatedContacts"], "2")
        self.assertTrue(client.subscribe(b"sub-op", "mesh.messages", "demo/playground")["inserted"])
        events, marker = client.query_events("mesh.messages", "demo/playground")
        self.assertEqual([event["id"] for event in events], [event_id(1), event_id(2)])
        self.assertEqual(marker, 2)
        self.assertEqual(query_calls, 2)
        self.assertTrue(
            all(
                request[1].startswith("/aster.application.v1alpha1.AsterApplicationService/")
                for request in FakeConnection.requests
            )
        )
        self.assertTrue(
            all(request[3]["Authorization"] == "Bearer " + TOKEN for request in FakeConnection.requests)
        )

    def test_client_rejects_non_loopback_or_ambiguous_urls(self) -> None:
        for url in (
            "https://127.0.0.1:8181",
            "http://192.0.2.1:8181",
            "http://localhost:8181",
            "http://127.0.0.1:8181/prefix",
            "http://user@127.0.0.1:8181",
        ):
            with self.subTest(url=url):
                with self.assertRaisesRegex(client_module.OperatorError, "loopback"):
                    client_module.ConnectJsonClient(url, TOKEN)

    def test_response_and_page_shape_bounds_fail_closed(self) -> None:
        def oversized(_request):
            return FakeResponse(200, b"x" * (client_module.MAX_RPC_RESPONSE_BYTES + 1))

        FakeConnection.responder = oversized
        client = client_module.ConnectJsonClient("http://[::1]:8181", TOKEN)
        with self.assertRaisesRegex(client_module.RpcError, "2 MiB"):
            client.status()

        def malformed_page(_request):
            return FakeResponse(
                200,
                {
                    "events": [{"id": "not-base64"}],
                    "scannedThrough": "1",
                    "hasMore": False,
                },
            )

        FakeConnection.responder = malformed_page
        with self.assertRaisesRegex(client_module.RpcError, "malformed Event ID"):
            client.query_events("mesh.messages", "demo/playground")


class WaitTests(unittest.TestCase):
    def test_wait_advances_marker_and_returns_only_the_exact_id(self) -> None:
        expected = event_id(4)

        class Client:
            def __init__(self) -> None:
                self.markers = []

            def query_events(self, _topic, _scope, _logical_key, *, after_marker=0):
                self.markers.append(after_marker)
                if len(self.markers) == 1:
                    return [{"id": event_id(3)}], 10
                return [{"id": expected}], 11

        client = Client()
        with mock.patch.object(client_module.time, "sleep", return_value=None):
            result = client_module.wait_for_exact_event(
                client,
                expected,
                "mesh.messages",
                "demo/playground",
                None,
                1.0,
                0.1,
            )
        self.assertEqual(result["id"], expected)
        self.assertEqual(client.markers, [0, 10])

    def test_event_id_and_route_bounds_are_enforced_locally(self) -> None:
        with self.assertRaisesRegex(client_module.OperatorError, "canonical base64"):
            client_module.canonical_event_id(base64.b64encode(b"short").decode("ascii"))
        with self.assertRaisesRegex(client_module.OperatorError, "noncanonical"):
            client_module._canonical_route_name("../secret", "scope")
        with self.assertRaisesRegex(client_module.OperatorError, "1..=256"):
            client_module._bounded_utf8("x" * 257, "operation key", 256)

    def test_publish_delegates_to_durable_cli_without_bearer_arguments(self) -> None:
        arguments = client_module.build_parser().parse_args([
            "publish", "--token-file", "/tmp/example.token", "--journal", "/tmp/publication.redb",
            "--client-id", "lan-source", "--logical-key", "message/1", "--payload", "hello", "--id-only"])
        response = {"result": {"operationSequence": "1", "receipt": {"eventId": event_id(7)}}, "inserted": True}
        completed = type("Completed", (), {"returncode": 0, "stdout": json.dumps(response).encode(), "stderr": b""})()
        with mock.patch.object(client_module.subprocess, "run", return_value=completed) as execute:
            observed = client_module._numbered_cli(arguments)
        self.assertEqual(observed, response)
        command = execute.call_args.args[0]
        self.assertIn("--journal", command)
        self.assertIn("--client-id", command)
        self.assertNotIn(TOKEN, command)
        self.assertEqual(execute.call_args.kwargs["input"], b"hello")

    def test_publish_has_stable_id_only_capture_flag(self) -> None:
        arguments = client_module.build_parser().parse_args(
            [
                "publish",
                "--token-file",
                "/tmp/example.token",
                "--journal", "/tmp/publication.redb",
                "--client-id", "lan-source",
                "--logical-key",
                "message/1",
                "--payload",
                "hello",
                "--id-only",
            ]
        )
        self.assertTrue(arguments.id_only)


if __name__ == "__main__":
    unittest.main()
