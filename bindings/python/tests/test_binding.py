from array import array
import concurrent.futures
import ctypes as C
import pathlib
import sys
import subprocess
import time
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from aster_mesh import AsterError, Client, DataClass, EmissionThreshold, Node, Priority
from aster_mesh import _abi as A, _lib, _new, _bytes

FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "testdata/non-production-provisioning.bundle"
TOPIC, SCOPE = "position.current", "mission/team/alpha"


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.bundle = self.root / "mission.bundle"
        self.bundle.write_bytes(FIXTURE.read_bytes())
        self.bundle.chmod(0o600)
        self.state = self.root / "state"

    def open(self):
        node = Node(self.state, self.bundle)
        self.addCleanup(node.close)
        return node

    def publish(self, node, kind=DataClass.STATE, operation=b"first", payload=b"north\0binary", **kwargs):
        return node.publish(kind, TOPIC, SCOPE, payload, logical_key=b"unit-7", operation_key=operation, **kwargs)

    def query(self, node, kind=DataClass.STATE, **kwargs):
        return node.query(kind, topic=TOPIC, scope=SCOPE, logical_key=b"unit-7", **kwargs)

    def test_state_exact_query_retry_tombstone_reopen_and_no_ttl(self):
        node = self.open()
        first = self.publish(node)
        replay = self.publish(node)
        self.assertEqual(first.item_id, replay.item_id)
        self.assertFalse(replay.inserted)
        with self.assertRaises(AsterError) as caught:
            self.publish(node, payload=b"different")
        self.assertEqual(caught.exception.status, 8)
        with self.assertRaises(AsterError):
            self.publish(node, operation=b"ttl", ttl_ms=1000)
        with self.assertRaises(AsterError):
            node.query(DataClass.STATE, topic=TOPIC, scope=SCOPE)
        with self.assertRaises(AsterError):
            self.query(node, limit=1)
        with self.query(node) as page:
            self.assertEqual(page[0].payload, b"north\0binary")
            self.assertEqual(page[0].item_id, first.item_id)
        self.publish(node, operation=b"delete", payload=b"", tombstone=True)
        node.close()
        node = self.open()
        with self.query(node, include_recoverable=True) as page:
            self.assertEqual(len(page), 2)
            self.assertTrue(page[0].tombstone)
            self.assertEqual(page[1].disposition, 2)

    def test_all_class_delivery_ack_and_selector_ownership(self):
        node = self.open()
        for kind in (DataClass.STATE, DataClass.RECORD):
            sub = node.subscribe(kind, TOPIC, SCOPE, operation_key=b"subscription")
            other = node.subscribe(kind, TOPIC, SCOPE, operation_key=b"other")
            self.publish(node, kind=kind)
            with sub.poll(1) as page:
                first = page.entries[0]
                self.assertEqual(len(first.items), 1)
                self.assertEqual(first.attempt, 1)
                self.assertFalse(first.has_guard)
            with sub.poll(1) as page:
                again = page.entries[0]
                self.assertGreater(again.attempt, first.attempt)
                with self.assertRaises(AsterError): other.acknowledge(again)
                sub.acknowledge(again)
                sub.acknowledge(again)
            with sub.poll() as page: self.assertEqual(page.entries, [])
            self.assertEqual(node.delivery_status(kind)["subscriptions"], 2)
            sub.unsubscribe()
            sub.unsubscribe()

    def test_numbered_event_recovery_pagination_fencing_and_ack(self):
        node = self.open()
        c, allocated, revision, outstanding = node.begin_recovery(b"application", 0, b"n" * 32)
        self.assertEqual((allocated, outstanding), (0, ()))
        with self.assertRaises(AsterError):
            self.publish(node, kind=DataClass.EVENT, operation=b"", client=c, sequence=1)
        node.complete_recovery(c, revision)
        sub = node.subscribe(DataClass.EVENT, TOPIC, SCOPE, operation_key=b"events", client=c)
        receipts = []
        for seq in range(1, 4):
            receipts.append(self.publish(node, kind=DataClass.EVENT, operation=b"", client=c, sequence=seq, payload=str(seq).encode()))
        retry = self.publish(node, kind=DataClass.EVENT, operation=b"", client=c, sequence=3, payload=b"3")
        self.assertEqual(retry.item_id, receipts[-1].item_id)
        self.assertFalse(retry.inserted)
        with node.query(DataClass.EVENT, topic="absent.topic", limit=1) as page:
            self.assertTrue(page.has_more)
            self.assertEqual(len(page), 0)
            self.assertGreater(page.scanned_through, 0)
        with sub.poll() as page:
            self.assertEqual(len(page.entries), 3)
            sub.acknowledge(page.entries[0])
        node.close()
        node = self.open()
        recovered, allocated, revision, outstanding = node.begin_recovery(b"application", c.session, b"m" * 32)
        self.assertEqual(allocated, 3)
        self.assertEqual([r.item_id for r in outstanding], [r.item_id for r in receipts])
        node.complete_recovery(recovered, revision)
        stale = node.restore_subscription(DataClass.EVENT, sub.subscription_id, client=c)
        with self.assertRaises(AsterError) as caught: stale.poll()
        self.assertEqual(caught.exception.status, 13)
        fresh = node.restore_subscription(DataClass.EVENT, sub.subscription_id, client=recovered)
        with fresh.poll() as page: self.assertEqual(len(page.entries), 2)
        for seq in range(1, 4): node.acknowledge_publication(recovered, seq)
        node.abandon_publication(recovered, 4)
        with self.assertRaises(AsterError):
            self.publish(node, kind=DataClass.EVENT, operation=b"", client=recovered, sequence=6)

    def test_blob_stream_finish_retry_reopen_metadata_delivery_and_empty(self):
        node = self.open()
        payload = b"blob\0binary" * 3000
        sub = node.subscribe(DataClass.BLOB, TOPIC, SCOPE, operation_key=b"blobs")
        with node.blob_writer(TOPIC, SCOPE, operation_key=b"blob-1", total_len=len(payload), media_type="application/octet-stream") as writer:
            with self.assertRaises(AsterError): writer.finish()
            self.assertEqual(writer.write(payload), len(payload))
            receipt = writer.finish()
            self.assertEqual(writer.finish(), receipt)
            with self.assertRaises(AsterError): writer.write(b"extra")
        with node.blob_reader(TOPIC, SCOPE, receipt.blob_id) as reader:
            buffer = bytearray(len(payload))
            count = reader.readinto(buffer)
            self.assertEqual(bytes(buffer[:count]) + reader.read(), payload)
            self.assertEqual(reader.read(), b"")
        with node.query(DataClass.BLOB, topic=TOPIC, scope=SCOPE, logical_key=receipt.blob_id) as page:
            self.assertEqual(page[0].total_len, len(payload))
            self.assertEqual(page[0].payload, b"")
        with sub.poll() as page:
            delivery = page.entries[0]
            self.assertFalse(delivery.retirement)
            self.assertEqual(delivery.items[0].blob_id, receipt.blob_id)
            sub.acknowledge(delivery)
        node.close()
        node = self.open()
        with node.blob_reader(TOPIC, SCOPE, receipt.blob_id) as reader: self.assertEqual(reader.read(), payload)
        with node.blob_writer(TOPIC, SCOPE, operation_key=b"empty", total_len=0) as writer: empty = writer.finish()
        with node.blob_reader(TOPIC, SCOPE, empty.blob_id) as reader: self.assertEqual(reader.read(), b"")

    def test_blob_readinto_buffer_protocol_and_rejection_preserves_offset(self):
        node = self.open()
        payload = bytes(range(64))
        with node.blob_writer(TOPIC, SCOPE, operation_key=b"readinto", total_len=len(payload)) as writer:
            writer.write(payload)
            receipt = writer.finish()
        for wrap in (lambda value: value, memoryview):
            with self.subTest(buffer=wrap.__name__):
                storage = array("I", [0] * 4)
                output = wrap(storage)
                with node.blob_reader(TOPIC, SCOPE, receipt.blob_id) as reader:
                    count = reader.readinto(output)
                    self.assertEqual(count, memoryview(storage).nbytes)
                    self.assertEqual(memoryview(storage).cast("B").tobytes(), payload[:count])
                    self.assertEqual(reader.read(), payload[count:])
        invalid_buffers = (
            b"readonly", memoryview(b"readonly"),
            memoryview(bytearray(16))[::2],
            memoryview(array("I", [0] * 4))[::2],
            b"", memoryview(bytearray())[::2].toreadonly(),
        )
        for output in invalid_buffers:
            with self.subTest(format=memoryview(output).format, readonly=memoryview(output).readonly, size=len(output)):
                with node.blob_reader(TOPIC, SCOPE, receipt.blob_id) as reader:
                    self.assertEqual(reader.read(3), payload[:3])
                    with self.assertRaises(TypeError):
                        reader.readinto(output)
                    self.assertEqual(reader.read(), payload[3:])

    def test_blob_unaligned_writes_and_checkpoint_resume_after_reopen(self):
        node = self.open()
        payload = bytes(range(256)) * 8192 + b"last partial page"
        options = dict(operation_key=b"resume", total_len=len(payload))
        writer = node.blob_writer(TOPIC, SCOPE, **options)
        writer.write(payload[:19])
        writer.write(payload[19:1024 * 1024 + 47])
        node.close()
        writer.close()
        node = self.open()
        writer = node.blob_writer(TOPIC, SCOPE, **options)
        # Partial checkpoints are not assumed durable. Replay from the native offset.
        self.assertEqual(writer.offset, 0)
        writer.write(payload[:31])
        writer.write(payload[31:])
        node.close()
        writer.close()
        node = self.open()
        with node.blob_writer(TOPIC, SCOPE, **options) as writer:
            self.assertEqual(writer.offset, len(payload))
            receipt = writer.finish()
        with node.blob_reader(TOPIC, SCOPE, receipt.blob_id) as reader:
            buffer = bytearray(len(payload))
            count = reader.readinto(buffer)
            self.assertEqual(count, 512 * 1024)
            self.assertEqual(bytes(buffer[:count]) + reader.read(), payload)

    def test_close_zeroize_children_and_owned_copy(self):
        node = self.open()
        self.publish(node)
        page = self.query(node)
        writer = node.blob_writer(TOPIC, SCOPE, operation_key=b"unfinished", total_len=10)
        writer.write(b"123")
        node.zeroize()
        self.assertEqual(page[0].payload, b"north\0binary")
        page.close()
        with self.assertRaises(AsterError): writer.finish()
        writer.close()
        with self.assertRaises(AsterError): self.open()

    def test_emission_peer_rekey_and_concurrent_close(self):
        node = self.open()
        node.emission_threshold = EmissionThreshold.RECEIVE_ONLY
        self.assertEqual(node.emission_threshold, EmissionThreshold.RECEIVE_ONLY)
        self.assertEqual(node.peers(), [])
        with self.assertRaises(AsterError) as caught: node.peer_status(bytes(32))
        self.assertEqual(caught.exception.status, 4)
        with self.assertRaises(AsterError): node.rekey_scope(b"invalid", 1, SCOPE, 2, [(bytes(32), [])])
        def operation(i):
            try:
                if i == 5: node.close()
                else: self.publish(node, operation=str(i).encode())
            except AsterError as error: self.assertEqual(error.status, 5)
        with concurrent.futures.ThreadPoolExecutor(4) as pool: list(pool.map(operation, range(20)))

    def test_real_record_guard_complete_projection_and_rekey(self):
        root = self.root / "testdata"
        binary = pathlib.Path(__file__).resolve().parents[3] / "target/debug/examples/prepare_binding_test_state"
        subprocess.run([str(binary), str(root)], check=True)
        with Node(root / "state", root / "mission.bundle") as node:
            with self.query(node, DataClass.RECORD) as projection:
                self.assertEqual(len(projection), 3)
                self.assertEqual(len(projection.entries[0].sibling_ids), 3)
                self.assertEqual(sum(item.tombstone for item in projection), 1)
                sub = node.subscribe(DataClass.RECORD, TOPIC, SCOPE, operation_key=b"whole-conflict")
                with sub.poll(1) as page:
                    self.assertEqual(len(page.entries), 1)
                    self.assertEqual(len(page.entries[0].items), 3)
                    with self.assertRaises(AsterError): node.resolve(page, b"bad", operation_key=b"no-delivery-guard")
                    sub.acknowledge(page.entries[0])
                resolved = node.resolve(projection, b"joined", operation_key=b"resolution")
                retry = node.resolve(projection, b"joined", operation_key=b"resolution")
                self.assertEqual(resolved.item_id, retry.item_id)
                self.assertFalse(retry.inserted)
                with self.assertRaises(AsterError): node.resolve(projection, b"changed", operation_key=b"stale")
            with self.query(node, DataClass.RECORD, include_recoverable=True) as page:
                self.assertEqual(len(page), 4)
                self.assertEqual(page[0].payload, b"joined")
            registry = (root / "registry.public").read_bytes()
            identity = (root / "identity.public").read_bytes()
            first = node.rekey_scope(registry, 1, SCOPE, 2, [(identity, [TOPIC])])
            again = node.rekey_scope(registry, 1, SCOPE, 2, [(identity, [TOPIC])])
            self.assertEqual(first[:2], again[:2])
            self.assertTrue(first[3])
            self.assertFalse(again[3])

    def test_blob_retirement_and_writer_replacement(self):
        node = self.open()
        options = dict(operation_key=b"replace-stream", total_len=4)
        old = node.blob_writer(TOPIC, SCOPE, **options)
        old.write(b"ab")
        with node.blob_writer(TOPIC, SCOPE, **options) as replacement:
            self.assertEqual(replacement.offset, 0)
            with self.assertRaises(AsterError): old.write(b"cd")
            replacement.write(b"abcd")
            replacement.finish()
        old.close()
        sub = node.subscribe(DataClass.BLOB, TOPIC, SCOPE, operation_key=b"finite-sub")
        with sub.poll() as page:
            for delivery in page.entries: sub.acknowledge(delivery)
        with node.blob_writer(TOPIC, SCOPE, operation_key=b"finite", total_len=4, ttl_ms=2000) as writer:
            writer.write(b"life")
            receipt = writer.finish()
        with sub.poll() as page:
            self.assertEqual(page.entries[0].items[0].ttl_ms, 2000)
            content = page.entries[0]
            # Retirement supersedes an outstanding delivery, not an acknowledged one.
        # Bounded maintenance rotates across multiple work classes and yields to
        # application commands. Allow several complete rotations after expiry.
        deadline = time.monotonic() + 30
        while True:
            with sub.poll() as page:
                retirements = [d for d in page.entries if d.retirement]
                if retirements:
                    self.assertEqual(retirements[0].items[0].blob_id, receipt.blob_id)
                    self.assertEqual(retirements[0].retirement_reason, 1)
                    with self.assertRaises(AsterError): sub.acknowledge(content)
                    sub.acknowledge(retirements[0])
                    break
            self.assertLess(time.monotonic(), deadline, "finite Blob retirement was not delivered")
            time.sleep(0.2)
        with self.assertRaises(AsterError): node.blob_reader(TOPIC, SCOPE, receipt.blob_id)

    def test_invalid_output_abi_precedes_publication_and_invalid_handles(self):
        node = self.open()
        r = _new(A.PublishRequest, data_class=0, operation_key=_bytes(b"invalid-output"), topic=_bytes(TOPIC), scope=_bytes(SCOPE), logical_key=_bytes(b"unit-7"), payload=_bytes(b"must not commit"))
        receipt = _new(A.PublishReceipt)
        receipt.abi_version = 1
        self.assertEqual(_lib.aster_node_publish(node._handle, C.byref(r), C.byref(receipt)), 2)
        with self.query(node) as page: self.assertEqual(len(page), 0)
        output = _new(A.ResultInfo)
        self.assertEqual(_lib.aster_result_info(node._handle, 999999999, C.byref(output)), 5)
        self.assertEqual(_lib.aster_node_publish(node._handle, None, C.byref(receipt)), 1)
        with self.assertRaises(AsterError): Node(self.root / "invalid", self.root / "missing")


if __name__ == "__main__": unittest.main()
