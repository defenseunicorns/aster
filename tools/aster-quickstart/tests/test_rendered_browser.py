from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import urlsplit


TAB = "\ue004"
ENTER = "\ue007"
SHIFT = "\ue008"


class _Marionette:
    """Small local Firefox WebDriver client for real native input coverage."""

    def __init__(self, firefox: str):
        self.firefox = firefox
        self.profile = tempfile.TemporaryDirectory()
        self.process: subprocess.Popen[bytes] | None = None
        self.connection: socket.socket | None = None
        self.message_id = 0

    def __enter__(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        profile = Path(self.profile.name)
        (profile / "user.js").write_text(f'user_pref("marionette.port", {port});\n')
        self.process = subprocess.Popen(
            [
                self.firefox,
                "--headless",
                "--no-remote",
                "--profile",
                str(profile),
                "--marionette",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 5
        while True:
            try:
                self.connection = socket.create_connection(("127.0.0.1", port), timeout=0.2)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
        self.connection.settimeout(5)
        self._read_message()
        self.command("WebDriver:NewSession", {"capabilities": {}})
        return self

    def __exit__(self, *_args):
        if self.connection is not None:
            self.connection.close()
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=1)
        self.profile.cleanup()

    def command(self, name: str, arguments: dict[str, object]):
        assert self.connection is not None
        self.message_id += 1
        request = [0, self.message_id, name, arguments]
        encoded = json.dumps(request, separators=(",", ":")).encode()
        self.connection.sendall(str(len(encoded)).encode() + b":" + encoded)
        response = self._read_message()
        if response[2] is not None:
            raise RuntimeError(f"Marionette command failed: {response[2]}")
        return response[3].get("value")

    def navigate(self, url: str) -> None:
        self.command("WebDriver:Navigate", {"url": url})

    def script(self, source: str):
        return self.command("WebDriver:ExecuteScript", {"script": source, "args": []})

    def key(self, value: str, *, shift: bool = False) -> None:
        actions = []
        if shift:
            actions.append({"type": "keyDown", "value": SHIFT})
        actions.extend([
            {"type": "keyDown", "value": value},
            {"type": "keyUp", "value": value},
        ])
        if shift:
            actions.append({"type": "keyUp", "value": SHIFT})
        self.command(
            "WebDriver:PerformActions",
            {"actions": [{"type": "key", "id": "keyboard", "actions": actions}]},
        )

    def _read_message(self):
        assert self.connection is not None
        length = bytearray()
        while True:
            byte = self.connection.recv(1)
            if byte == b":":
                break
            if not byte:
                raise EOFError("Marionette connection closed")
            length.extend(byte)
        remaining = int(length)
        payload = bytearray()
        while len(payload) < remaining:
            payload.extend(self.connection.recv(remaining - len(payload)))
        return json.loads(payload)


def _workbench_state(
    *, authenticated: bool = False, transcript: list[dict[str, object]] | None = None
) -> dict[str, object]:
    running = authenticated
    return {
        "revision": 1,
        "initialized": True,
        "cleanup": None,
        "operation": None,
        "nodes": {
            "publisher": {"state": "running" if running else "stopped", "identity_fingerprint": "1" * 64},
            "receiver": {"state": "running" if running else "stopped", "identity_fingerprint": "2" * 64},
        },
        "authentication": {"state": "authenticated" if authenticated else "unauthenticated"},
        "pair_transition": None,
        "failed_stage": None,
        "available_actions": ["publish_event", "stop_publisher", "stop_receiver", "cleanup"]
        if authenticated
        else ["start_publisher", "start_receiver", "cleanup"],
        "message": None,
        "commit": None,
        "receipt": None,
        "first_delivery": None,
        "experiment": None,
        "error": None,
        "records": [],
        "transcript": [] if transcript is None else transcript,
    }


class _WorkbenchHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            content = (self.server.static / "index.html").read_text().replace(
                "__TOKEN__", "render-test"
            ).encode()
            self._send(HTTPStatus.OK, "text/html; charset=utf-8", content)
        elif path == "/static/styles.css":
            self._send(
                HTTPStatus.OK,
                "text/css",
                (self.server.static / "styles.css").read_bytes(),
            )
        elif path == "/static/app.js":
            self._send(
                HTTPStatus.OK,
                "application/javascript",
                (self.server.static / "app.js").read_bytes(),
            )
        elif path == "/api/state":
            self._json(self.server.state)
        elif path == "/api/events":
            if not self.server.sse_after_post:
                self._send(HTTPStatus.NO_CONTENT, "text/plain", b"")
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.server.post_completed.wait(1):
                time.sleep(0.02)
                payload = json.dumps(self.server.state, separators=(",", ":")).encode()
                self.wfile.write(b"event: state\ndata: " + payload + b"\n\n")
                self.wfile.flush()
                self.server.sse_sent.set()
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self):
        path = urlsplit(self.path).path
        size = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(size)
        state = dict(self.server.state)
        state["revision"] = int(state["revision"]) + 1
        if path == "/api/nodes/publisher/start":
            nodes = {name: dict(value) for name, value in state["nodes"].items()}
            nodes["publisher"]["state"] = "running"
            state["nodes"] = nodes
            state["available_actions"] = [
                "stop_publisher",
                "start_receiver",
                "cleanup",
            ]
        elif path == "/api/events":
            event_id = "e" * 64
            state["commit"] = {
                "event_id": event_id,
                "text": "Hello from the Aster quickstart.",
                "status": "committed",
                "durable": True,
                "node": "atlas",
            }
            state["receipt"] = {
                "event_id": event_id,
                "text": "Hello from the Aster quickstart.",
                "status": "received",
                "observed": True,
                "node": "beacon",
            }
            state["first_delivery"] = dict(state["receipt"])
            state["available_actions"] = [
                "publish_event",
                "offline_experiment",
                "stop_publisher",
                "stop_receiver",
                "cleanup",
            ]
        else:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.server.state = state
        self._json(state)
        if self.server.sse_after_post:
            self.server.post_completed.set()

    def _json(self, value):
        self._send(
            HTTPStatus.OK,
            "application/json",
            json.dumps(value, separators=(",", ":")).encode(),
        )

    def _send(self, status, content_type, content):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, _format, *_args):
        return


class RenderedBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.firefox = os.environ.get("ASTER_QUICKSTART_FIREFOX") or shutil.which("firefox")
        if cls.firefox is None:
            raise unittest.SkipTest("Firefox is unavailable for rendered-browser coverage")
        cls.root = Path(__file__).resolve().parents[1]
        cls.static = cls.root / "aster_quickstart" / "static"

    def workbench(
        self,
        *,
        authenticated: bool = False,
        sse_after_post: bool = False,
        transcript: list[dict[str, object]] | None = None,
    ):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _WorkbenchHandler)
        server.static = self.static
        server.state = _workbench_state(authenticated=authenticated, transcript=transcript)
        server.sse_after_post = sse_after_post
        server.post_completed = threading.Event()
        server.sse_sent = threading.Event()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def close():
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

        self.addCleanup(close)
        return f"http://127.0.0.1:{server.server_port}/?token=render-test", server

    def wait_for(self, browser: _Marionette, source: str, timeout: float = 2):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = browser.script(source)
            if value:
                return value
            time.sleep(0.01)
        self.fail("rendered browser state did not converge")

    def test_responsive_layout_and_disabled_controls_at_three_widths(self):
        reports: list[dict[str, object]] = []
        reported = threading.Event()
        static = self.static

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                path = self.path.split("?", 1)[0]
                if path == "/":
                    content = (static / "index.html").read_text().replace("__TOKEN__", "render-test")
                    content = content.replace(
                        "</body>",
                        '<script src="/audit.js" defer></script>'
                        '<img src="/audit-gate" alt="" hidden></body>',
                    ).encode()
                    self._send(HTTPStatus.OK, "text/html; charset=utf-8", content)
                elif path == "/static/styles.css":
                    self._send(HTTPStatus.OK, "text/css", (static / "styles.css").read_bytes())
                elif path == "/static/app.js":
                    self._send(HTTPStatus.OK, "application/javascript", (static / "app.js").read_bytes())
                elif path == "/audit.js":
                    self._send(HTTPStatus.OK, "application/javascript", self.server.audit_source)
                elif path == "/audit-gate":
                    reported.wait(4)
                    self._send(HTTPStatus.NO_CONTENT, "image/gif", b"")
                elif path == "/api/state":
                    self._send(HTTPStatus.OK, "application/json", self.server.state_payload)
                elif path == "/api/events":
                    self._send(HTTPStatus.NO_CONTENT, "text/plain", b"")
                else:
                    self.send_error(HTTPStatus.NOT_FOUND)

            def do_POST(self):
                if self.path != "/report":
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                size = int(self.headers.get("Content-Length", "0"))
                reports.append(json.loads(self.rfile.read(size)))
                reported.set()
                self._send(HTTPStatus.NO_CONTENT, "text/plain", b"")

            def _send(self, status, content_type, content):
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)

            def log_message(self, _format, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.audit_source = b"""
(async () => {
  await new Promise(requestAnimationFrame);
  await new Promise(requestAnimationFrame);
  for (let attempt = 0; document.getElementById("publisher-start").disabled && attempt < 100; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  const publisher = document.getElementById("publisher-card").getBoundingClientRect();
  const receiver = document.getElementById("receiver-card").getBoundingClientRect();
  const start = document.getElementById("publisher-start");
  const transcriptGroup = document.querySelector(".transcript-group:not([hidden])");
  const transcriptRow = document.getElementById("transcript-entry-1");
  transcriptGroup.open = true;
  transcriptRow.open = true;
  const transcriptPre = transcriptRow.querySelector('[data-transcript-field="command"] pre');
  const transcriptCopy = transcriptRow.querySelector('[data-transcript-field="command"] button');
  const transcriptCopyBox = transcriptCopy.getBoundingClientRect();
  const disclosure = getComputedStyle(transcriptGroup.querySelector("summary"), "::before").content;
  const report = {
    width: innerWidth,
    overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
    cardsContained: [publisher, receiver].every((box) => box.left >= 0 && box.right <= innerWidth),
    columns: Math.abs(publisher.top - receiver.top) < 4 ? 2 : 1,
    nativeButton: start.tagName === "BUTTON" && start.tabIndex >= 0,
    transcript: {
      disclosure,
      preScrollsLocally: transcriptPre.scrollWidth > transcriptPre.clientWidth,
      preContained: transcriptPre.getBoundingClientRect().right <= innerWidth,
      copyUsable: transcriptCopyBox.width >= 44 && transcriptCopyBox.right <= innerWidth
    },
    disabled: {
      publisherStart: start.disabled,
      publisherStop: document.getElementById("publisher-stop").disabled,
      authenticate: document.getElementById("authenticate").disabled,
      send: document.getElementById("send-event").disabled
    }
  };
  await fetch("/report", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(report)});
})();
"""
        server.state_payload = json.dumps({
            "revision": 1,
            "initialized": True,
            "cleanup": None,
            "operation": None,
            "nodes": {
                "publisher": {"state": "stopped", "identity_fingerprint": "1" * 64},
                "receiver": {"state": "stopped", "identity_fingerprint": "2" * 64},
            },
            "authentication": {"state": "unauthenticated"},
            "pair_transition": None,
            "failed_stage": None,
            "available_actions": ["start_publisher", "start_receiver", "cleanup"],
            "message": None,
            "commit": None,
            "receipt": None,
            "first_delivery": None,
            "experiment": None,
            "error": None,
            "records": [],
            "transcript": [{
                "id": 1,
                "kind": "command",
                "step": "publisher",
                "title": None,
                "outcome": "succeeded",
                "status": "succeeded",
                "detail": None,
                "command": "asterctl " + "very-long-command-argument-" * 20,
                "cwd": "/tmp/quickstart",
                "stdin": None,
                "stdout": "very-long-stream-token-" * 30,
                "stderr": "",
                "returncode": 0,
                "duration_ms": 1,
                "replayable": True,
            }],
        }).encode()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for width in (360, 760, 1440):
                with self.subTest(width=width), tempfile.TemporaryDirectory() as profile:
                    reported.clear()
                    before = len(reports)
                    screenshot = Path(profile) / "page.png"
                    subprocess.run(
                        [
                            self.firefox,
                            "--headless",
                            "--no-remote",
                            "--profile",
                            profile,
                            "--window-size",
                            f"{width},900",
                            "--screenshot",
                            str(screenshot),
                            f"http://127.0.0.1:{server.server_port}/?token=render-test",
                        ],
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=8,
                    )
                    self.assertTrue(reported.is_set(), "rendered browser did not report")
                    self.assertEqual(len(reports), before + 1)
                    report = reports[-1]
                    self.assertEqual(report["width"], width)
                    self.assertFalse(report["overflow"])
                    self.assertTrue(report["cardsContained"])
                    self.assertEqual(report["columns"], 1 if width <= 700 else 2)
                    self.assertTrue(report["nativeButton"])
                    self.assertNotIn(
                        report["transcript"]["disclosure"],
                        {"none", "normal", '\"\"'},
                    )
                    self.assertTrue(report["transcript"]["preScrollsLocally"])
                    self.assertTrue(report["transcript"]["preContained"])
                    self.assertTrue(report["transcript"]["copyUsable"])
                    self.assertEqual(report["disabled"], {
                        "publisherStart": False,
                        "publisherStop": True,
                        "authenticate": True,
                        "send": True,
                    })
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

    def test_native_tab_order_focus_visible_and_live_button_state(self):
        url, _ = self.workbench()
        with _Marionette(self.firefox) as browser:
            browser.navigate(url)
            self.wait_for(
                browser,
                'return document.getElementById("publisher-start").disabled === false;',
            )

            browser.key(TAB)
            focus = browser.script("""
const target = document.activeElement;
const style = getComputedStyle(target);
return {id: target.id, outlineStyle: style.outlineStyle, outlineWidth: parseFloat(style.outlineWidth)};
""")
            self.assertEqual(focus["id"], "publisher-start")
            self.assertNotEqual(focus["outlineStyle"], "none")
            self.assertGreaterEqual(focus["outlineWidth"], 3)

            browser.key(TAB)
            self.assertEqual(
                browser.script("return document.activeElement.id;"),
                "publisher-terminal",
            )
            browser.key(TAB, shift=True)
            self.assertEqual(
                browser.script("return document.activeElement.id;"),
                "publisher-start",
            )

            browser.key(ENTER)
            state = self.wait_for(
                browser,
                """
const start = document.getElementById("publisher-start");
const stop = document.getElementById("publisher-stop");
const receiver = document.getElementById("receiver-start");
return start.disabled && !stop.disabled && !receiver.disabled
  ? {start: start.disabled, stop: stop.disabled, receiver: receiver.disabled}
  : null;
""",
            )
            self.assertEqual(state, {"start": True, "stop": False, "receiver": False})

    def test_lagging_sse_cannot_preempt_visible_commit_before_receipt(self):
        url, server = self.workbench(authenticated=True, sse_after_post=True)
        with _Marionette(self.firefox) as browser:
            browser.navigate(url)
            self.wait_for(
                browser,
                'return document.getElementById("send-event").disabled === false;',
            )
            browser.script("""
window.__deliveryTimeline = [];
let previous = "";
const capture = () => {
  const panel = document.getElementById("delivery-result");
  const commit = document.getElementById("commit-result").textContent;
  const receipt = document.getElementById("receipt-result").textContent;
  const combined = commit + "|" + receipt;
  if (combined === previous) return;
  previous = combined;
  const box = panel.getBoundingClientRect();
  const style = getComputedStyle(panel);
  window.__deliveryTimeline.push({
    time: performance.now(), commit, receipt,
    visible: !panel.hidden && box.width > 0 && box.height > 0 &&
      style.display !== "none" && style.visibility === "visible" && style.opacity !== "0"
  });
};
new MutationObserver(capture).observe(document.getElementById("delivery-result"), {
  attributes: true, childList: true, subtree: true
});
capture();
return true;
""")
            browser.script('document.getElementById("send-event").click(); return true;')

            observed_commit = None
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                state = browser.script("""
const commit = document.getElementById("commit-result").textContent;
const receipt = document.getElementById("receipt-result").textContent;
const panel = document.getElementById("delivery-result");
const box = panel.getBoundingClientRect();
const style = getComputedStyle(panel);
return commit.startsWith("committed") && receipt === "Waiting for receiver…"
  ? {commit, receipt, visible: !panel.hidden && box.width > 0 && box.height > 0 &&
      style.display !== "none" && style.visibility === "visible" && style.opacity !== "0"}
  : null;
""")
                if state:
                    observed_commit = state
                    break
                time.sleep(0.005)

            self.assertIsNotNone(observed_commit)
            self.assertTrue(observed_commit["visible"])
            self.assertTrue(server.sse_sent.wait(0.5), "lagging SSE was not delivered")
            self.assertEqual(
                browser.script(
                    'return document.getElementById("receipt-result").textContent;'
                ),
                "Waiting for receiver…",
            )
            timeline = self.wait_for(
                browser,
                """
return document.getElementById("receipt-result").textContent.startsWith("received")
  ? window.__deliveryTimeline : null;
""",
            )
            commit_only = next(
                item
                for item in timeline
                if item["commit"].startswith("committed")
                and item["receipt"] == "Waiting for receiver…"
            )
            received = next(
                item for item in timeline if item["receipt"].startswith("received")
            )
            self.assertTrue(commit_only["visible"])
            self.assertGreaterEqual(received["time"] - commit_only["time"], 50)

    def test_transcript_groups_copy_and_focused_rows_survive_an_sse_update(self):
        transcript = [
            {"id": 1, "kind": "internal", "step": "setup", "title": "Workspace ready", "outcome": "succeeded", "status": "succeeded", "detail": "ready", "command": None, "cwd": None, "stdin": None, "stdout": None, "stderr": None, "returncode": None, "duration_ms": 3, "replayable": None},
            {"id": 2, "kind": "command", "step": "publisher", "title": None, "outcome": "running", "status": "running", "detail": None, "command": "aster-agent --role publisher", "cwd": "/tmp/quickstart", "stdin": None, "stdout": "starting\n", "stderr": "", "returncode": None, "duration_ms": 8, "replayable": True},
            {"id": 3, "kind": "command", "step": "receiver", "title": None, "outcome": "failed", "status": "failed", "detail": None, "command": "aster-agent --role receiver", "cwd": "/tmp/quickstart", "stdin": None, "stdout": "", "stderr": "bind failed\n", "returncode": 1, "duration_ms": 9, "replayable": True},
            {"id": 4, "kind": "command", "step": "event", "title": None, "outcome": "succeeded", "status": "succeeded", "detail": None, "command": "asterctl publish --message 'Hello world'", "cwd": "/tmp/quickstart", "stdin": "Hello world\n", "stdout": "committed\n<truncated: 9 bytes retained>", "stderr": "warning: retry\n", "returncode": 0, "duration_ms": 11, "replayable": False},
            {"id": 5, "kind": "internal", "step": "authentication", "title": "Authenticate nodes", "outcome": "succeeded", "status": "succeeded", "detail": "verified", "command": None, "cwd": None, "stdin": None, "stdout": None, "stderr": None, "returncode": None, "duration_ms": 4, "replayable": None},
            {"id": 6, "kind": "internal", "step": "experiment", "title": "Optional experiment", "outcome": "succeeded", "status": "succeeded", "detail": "restored", "command": None, "cwd": None, "stdin": None, "stdout": None, "stderr": None, "returncode": None, "duration_ms": 2, "replayable": None},
            {"id": 7, "kind": "internal", "step": "cleanup", "title": "Cleanup", "outcome": "succeeded", "status": "succeeded", "detail": "removed", "command": None, "cwd": None, "stdin": None, "stdout": None, "stderr": None, "returncode": None, "duration_ms": 2, "replayable": None},
        ]
        url, server = self.workbench(sse_after_post=True, transcript=transcript)
        with _Marionette(self.firefox) as browser:
            browser.navigate(url)
            report = self.wait_for(browser, """
const eventRow = document.getElementById("transcript-entry-4");
if (!eventRow) return null;
return {
  groups: Array.from(document.querySelectorAll(".transcript-group:not([hidden]) summary h3")).map((node) => node.textContent),
  groupTags: Array.from(document.querySelectorAll(".transcript-group:not([hidden])")).map((node) => node.tagName),
  groupOpen: ["setup", "publisher", "receiver", "event"].map((step) => document.querySelector('[data-transcript-step="' + step + '"]').open),
  open: [1, 2, 3, 4].map((id) => document.getElementById("transcript-entry-" + id).open),
  command: eventRow.querySelector('[data-transcript-field="command"] pre').textContent,
  stdin: eventRow.querySelector('[data-transcript-field="stdin"] pre').textContent,
  stdout: eventRow.querySelector('[data-transcript-field="stdout"] pre').textContent,
  stderr: eventRow.querySelector('[data-transcript-field="stderr"] pre').textContent,
  labels: eventRow.textContent,
  internalKind: document.getElementById("transcript-entry-1").textContent,
  internalCommand: document.getElementById("transcript-entry-1").querySelector('[data-transcript-field="command"]'),
  copyNames: Array.from(eventRow.querySelectorAll(".transcript-copy")).map((button) => button.getAttribute("aria-label"))
};
""")
            self.assertEqual(report["groups"], ["Workspace", "Publisher", "Receiver", "Authentication", "Event", "Optional experiment", "Cleanup"])
            self.assertEqual(report["groupTags"], ["DETAILS"] * 7)
            self.assertEqual(report["groupOpen"], [False, True, True, False])
            self.assertEqual(report["open"], [False, True, True, False])
            self.assertEqual(report["command"], "asterctl publish --message 'Hello world'")
            self.assertEqual(report["stdin"], "Hello world\n")
            self.assertEqual(report["stdout"], "committed\n<truncated: 9 bytes retained>")
            self.assertEqual(report["stderr"], "warning: retry\n")
            self.assertIn("Not replayable", report["labels"])
            self.assertIn("Truncated", report["labels"])
            self.assertIn("Internal operation", report["internalKind"])
            self.assertIsNone(report["internalCommand"])
            self.assertEqual(
                report["copyNames"],
                ["Copy command", "Copy standard input", "Copy standard output", "Copy standard error"],
            )

            browser.script("""
const groupSummary = document.querySelector('[data-transcript-step="event"] > summary');
groupSummary.focus();
return document.activeElement === groupSummary;
""")
            browser.key(ENTER)
            self.assertTrue(
                browser.script(
                    'return document.querySelector(\'[data-transcript-step="event"]\').open;'
                )
            )

            browser.script("""
Object.defineProperty(navigator, "clipboard", {configurable: true, value: {
  writeText(value) {
    (window.__copiedTranscript || (window.__copiedTranscript = [])).push(value);
    return Promise.resolve();
  }
}});
const row = document.getElementById("transcript-entry-4");
row.open = true;
for (const field of ["command", "stdin", "stdout"]) {
  row.querySelector('[data-transcript-field="' + field + '"] button').click();
}
window.__focusedTranscriptCopy = row.querySelector('[data-transcript-field="stderr"] button');
window.__focusedTranscriptCopy.focus();
return document.activeElement === window.__focusedTranscriptCopy;
""")
            browser.key(ENTER)
            self.assertEqual(
                self.wait_for(browser, """
return window.__copiedTranscript && window.__copiedTranscript.length === 4
  ? window.__copiedTranscript : null;
"""),
                [
                    "asterctl publish --message 'Hello world'",
                    "Hello world\n",
                    "committed\n<truncated: 9 bytes retained>",
                    "warning: retry\n",
                ],
            )
            self.assertEqual(
                browser.script(
                    "return window.__focusedTranscriptCopy.parentElement"
                    ".querySelector('.transcript-copy-feedback').textContent;"
                ),
                "Copied",
            )
            browser.script('document.getElementById("publisher-start").click(); return true;')
            self.assertTrue(server.sse_sent.wait(1), "transcript SSE update was not delivered")
            self.assertTrue(self.wait_for(
                browser,
                "return document.activeElement === window.__focusedTranscriptCopy"
                " && document.getElementById('transcript-entry-4').open"
                " && document.querySelector('[data-transcript-step=\"event\"]').open;",
            ))

    def test_running_rows_auto_collapse_after_success_and_intentional_stop(self):
        transcript = [
            {"id": 1, "kind": "command", "step": "publisher", "title": None, "outcome": "running", "status": "running", "detail": None, "command": "aster-agent one", "cwd": "/tmp/quickstart", "stdin": None, "stdout": "", "stderr": "", "returncode": None, "duration_ms": None, "replayable": True},
            {"id": 2, "kind": "command", "step": "publisher", "title": None, "outcome": "running", "status": "running", "detail": None, "command": "aster-agent two", "cwd": "/tmp/quickstart", "stdin": None, "stdout": "", "stderr": "", "returncode": None, "duration_ms": None, "replayable": True},
        ]
        url, server = self.workbench(transcript=transcript)
        with _Marionette(self.firefox) as browser:
            browser.navigate(url)
            self.wait_for(
                browser,
                "return document.getElementById('transcript-entry-1')"
                " && document.getElementById('transcript-entry-1').open;",
            )
            server.state["transcript"][0].update(
                outcome="succeeded", status="succeeded", returncode=0, duration_ms=12
            )
            server.state["transcript"][1].update(
                outcome="stopped", status="stopped", returncode=-9, duration_ms=13
            )
            browser.script('document.getElementById("publisher-start").click(); return true;')

            result = self.wait_for(browser, """
const first = document.getElementById("transcript-entry-1");
const second = document.getElementById("transcript-entry-2");
const group = document.querySelector('[data-transcript-step="publisher"]');
return first.querySelector(".transcript-badges").textContent.includes("succeeded")
  ? {rows: [first.open, second.open], group: group.open,
     failing: [first.classList.contains("is-failing"), second.classList.contains("is-failing")]}
  : null;
""")
            self.assertEqual(result, {
                "rows": [False, False],
                "group": False,
                "failing": [False, False],
            })

    def test_focused_completed_auto_disclosures_collapse_after_focus_leaves_without_another_sse(self):
        transcript = [{
            "id": 1,
            "kind": "command",
            "step": "publisher",
            "title": None,
            "outcome": "running",
            "status": "running",
            "detail": None,
            "command": "aster-agent --role publisher",
            "cwd": "/tmp/quickstart",
            "stdin": None,
            "stdout": "starting\\n",
            "stderr": "",
            "returncode": None,
            "duration_ms": None,
            "replayable": True,
        }]
        url, server = self.workbench(sse_after_post=True, transcript=transcript)
        with _Marionette(self.firefox) as browser:
            browser.navigate(url)
            self.wait_for(browser, """
const row = document.getElementById("transcript-entry-1");
const group = document.querySelector('[data-transcript-step="publisher"]');
const focus = row && row.querySelector('[data-transcript-field="stdout"] pre');
if (!row || !group || !focus || !row.open || !group.open) return null;
focus.focus();
return document.activeElement === focus;
""")
            server.state["transcript"][0].update(
                outcome="succeeded", status="succeeded", returncode=0, duration_ms=12
            )
            browser.script('document.getElementById("publisher-start").click(); return true;')
            self.assertTrue(server.sse_sent.wait(1), "completion SSE update was not delivered")
            self.assertTrue(self.wait_for(browser, """
const row = document.getElementById("transcript-entry-1");
const group = document.querySelector('[data-transcript-step="publisher"]');
return row.querySelector(".transcript-badges").textContent.includes("succeeded")
  && document.activeElement === row.querySelector('[data-transcript-field="stdout"] pre')
  && row.open && group.open;
"""))

            self.assertTrue(browser.script("""
document.getElementById("detail-level").focus();
return document.activeElement === document.getElementById("detail-level");
"""))
            self.assertTrue(self.wait_for(browser, """
const row = document.getElementById("transcript-entry-1");
const group = document.querySelector('[data-transcript-step="publisher"]');
return !row.open && !group.open;
"""))

    def test_transcript_copy_reports_clipboard_failure_and_selects_the_text(self):
        transcript = [{
            "id": 1,
            "kind": "command",
            "step": "event",
            "title": None,
            "outcome": "succeeded",
            "status": "succeeded",
            "detail": None,
            "command": "asterctl publish --message 'copy this exactly'",
            "cwd": "/tmp/quickstart",
            "stdin": None,
            "stdout": "",
            "stderr": "",
            "returncode": 0,
            "duration_ms": 1,
            "replayable": True,
        }]
        url, _ = self.workbench(transcript=transcript)
        with _Marionette(self.firefox) as browser:
            browser.navigate(url)
            browser.script(
                'Object.defineProperty(navigator, "clipboard", '
                '{configurable: true, value: undefined}); return true;'
            )
            self.wait_for(
                browser,
                "return document.querySelector('[data-transcript-field=\"command\"] button');",
            )
            browser.script("""
const row = document.getElementById("transcript-entry-1");
document.querySelector('[data-transcript-step="event"]').open = true;
row.open = true;
const button = row.querySelector('[data-transcript-field="command"] button');
button.focus();
return document.activeElement === button;
""")
            browser.key(ENTER)
            result = self.wait_for(browser, """
const row = document.getElementById("transcript-entry-1");
const feedback = row.querySelector(".transcript-copy-feedback").textContent;
const selection = window.getSelection().toString();
return feedback ? {feedback, selection} : null;
""")
            self.assertEqual(result, {
                "feedback": "Copy failed — text selected.",
                "selection": "asterctl publish --message 'copy this exactly'",
            })


if __name__ == "__main__":
    unittest.main()
