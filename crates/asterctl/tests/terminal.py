"""Exercise the real CLI with a POSIX terminal, without unsafe Rust or dependencies."""

import os
import pty
import select
import signal
import socket
import subprocess
import sys
import tempfile


def check(extra, terminal, expect_hint):
    with tempfile.TemporaryDirectory(prefix="asterctl-terminal-") as temporary, socket.socket() as listener:
        journal = os.path.join(temporary, "publication.redb")
        subprocess.run([sys.argv[1], "publication-init", "--journal", journal, "--client-id", "terminal-test"], check=True, capture_output=True)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        master, slave = pty.openpty()
        process = None
        try:
            process = subprocess.Popen(
                [sys.argv[1], "--token", "asterctl-test-token-00000000000000",
                 "--port", str(listener.getsockname()[1]), "publish", "--topic=x",
                 "--scope=x", "--journal", journal, "--client-id", "terminal-test", *extra],
                stdin=slave if terminal else subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            os.close(slave)
            slave = None
            readable, _, _ = select.select([process.stderr, listener], [], [], 2)
            if expect_hint:
                assert process.stderr in readable, "missing hint before terminal input"
                message = os.read(process.stderr.fileno(), 4096)
                assert b"Reading payload from stdin." in message, message
                assert b"Ctrl-D" in message and b"Ctrl-C" in message, message
                assert not select.select([listener], [], [], 0)[0], "RPC before EOF"
            else:
                assert process.stderr not in readable, "unexpected stdin hint"
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=2)
            assert not stdout, stdout
            assert b"Reading payload" not in stderr, stderr
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=2)
            if slave is not None:
                os.close(slave)
            os.close(master)


check([], True, True)
check(["--json"], True, True)
check([], False, False)
check(["hello"], True, False)
check(["--tombstone"], True, False)
