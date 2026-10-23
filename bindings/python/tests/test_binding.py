import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from aster_mesh import (
    AsterError, BatchPublicationPolicy, BatchPublishItem,
    BridgeAuthorizationPolicy, BridgeNarrowingPolicy, DEFAULT_SEMANTIC_VERSION,
    DataClass, EmissionThreshold,
    HIGHEST_SUPPORTED_SEMANTIC_VERSION, Node, PROTOCOL_VERSION, Priority,
    PriorityMask, REPLICATION_WIRE_VERSION, RekeyAccess, RekeyRecipient,
)

BUNDLE = (pathlib.Path(__file__).resolve().parents[2] / "testdata" /
          "non-production-provisioning.bundle").read_bytes()


class BindingTests(unittest.TestCase):
    def test_version_surfaces_distinguish_wire_from_semantics(self):
        self.assertEqual(PROTOCOL_VERSION, 1)
        self.assertEqual(REPLICATION_WIRE_VERSION, 1)
        self.assertEqual(DEFAULT_SEMANTIC_VERSION, 9)
        self.assertEqual(HIGHEST_SUPPORTED_SEMANTIC_VERSION, 9)

    def test_format_three_bundle_opens_and_legacy_format_two_is_rejected(self):
        self.assertEqual(BUNDLE[:8], b"ASTRPB03")
        with Node(":memory:", BUNDLE):
            pass
        legacy = b"ASTRPB02" + BUNDLE[8:]
        with self.assertRaises(AsterError) as caught:
            Node(":memory:", legacy)
        self.assertEqual(caught.exception.status, 9)

    def test_offline_publish_query_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            with Node(str(pathlib.Path(directory) / "mesh.db"), BUNDLE) as node:
                subscription = node.subscribe("position.current", "mission/team/alpha")
                receipt = node.publish(
                    DataClass.STATE, "position.current", "mission/team/alpha",
                    b"north\0binary", logical_key=b"unit-7", priority=Priority.IMMEDIATE,
                )
                items = node.query(topic="position.current", scope="mission/team/alpha")
                self.assertEqual(items[0].item_id, receipt.item_id)
                self.assertEqual(items[0].payload, b"north\0binary")
                self.assertEqual(items[0].scope, "mission/team/alpha")
                self.assertEqual(items[0].origin_scope, items[0].scope)
                self.assertEqual(items[0].current_scope, items[0].scope)
                first = subscription.poll()[0]
                again = subscription.poll()[0]
                self.assertEqual(first.item.item_id, again.item.item_id)
                self.assertGreater(again.attempt, first.attempt)
                subscription.acknowledge(again)
                self.assertEqual(subscription.poll(), [])
                node.emission_threshold = EmissionThreshold.RECEIVE_ONLY
                self.assertEqual(node.emission_threshold, EmissionThreshold.RECEIVE_ONLY)

    def test_explicit_batch_is_ordered_atomic_and_reports_metadata(self):
        with Node(":memory:", BUNDLE) as node:
            result = node.publish_batch((
                BatchPublishItem(
                    DataClass.EVENT, "position.current", "mission/team/alpha",
                    b"first", priority=Priority.IMMEDIATE,
                ),
                BatchPublishItem(
                    DataClass.EVENT, "position.current", "mission/team/alpha",
                    b"second", priority=Priority.IMMEDIATE,
                ),
            ), BatchPublicationPolicy.BATCH_ONLY)
            self.assertEqual(len(result.items), 2)
            self.assertEqual(result.evicted, ())
            self.assertEqual([item.causal_counter for item in result.items], [1, 2])
            self.assertEqual([item.event_sequence for item in result.items], [1, 2])

        with Node(":memory:", BUNDLE) as node:
            with self.assertRaises(AsterError):
                node.publish_batch((
                    BatchPublishItem(
                        DataClass.STATE, "position.current", "mission/team/alpha",
                        b"first", logical_key=b"unit-1",
                    ),
                    BatchPublishItem(
                        DataClass.STATE, "position.history", "mission/team/alpha",
                        b"second", logical_key=b"unit-2",
                    ),
                ), BatchPublicationPolicy.RETAINED_DUAL)
            receipt = node.publish(
                DataClass.STATE, "position.current", "mission/team/alpha",
                b"after rejection", logical_key=b"unit-1",
            )
            self.assertEqual(receipt.causal_counter, 1)
            with self.assertRaises(ValueError):
                node.publish_batch((BatchPublishItem(
                    DataClass.EVENT, "position.current", "mission/team/alpha", b"only",
                ),))

    def test_same_key_event_stream_preserves_every_entry(self):
        with Node(":memory:", BUNDLE) as node:
            subscription = node.subscribe(
                "position.current", "mission/team/alpha", data_class=DataClass.EVENT,
            )
            for payload in (b"first", b"second", b"third"):
                node.publish(
                    DataClass.EVENT, "position.current", "mission/team/alpha", payload,
                    logical_key=b"operations-chat",
                )

            queried = node.query(
                topic="position.current", scope="mission/team/alpha",
                logical_key=b"operations-chat", data_class=DataClass.EVENT,
            )
            self.assertEqual([item.payload for item in queried],
                             [b"first", b"second", b"third"])
            deliveries = subscription.poll()
            self.assertEqual([delivery.item.payload for delivery in deliveries],
                             [b"first", b"second", b"third"])

    def test_acknowledging_projected_heads_does_not_reveal_ancestors(self):
        with Node(":memory:", BUNDLE) as node:
            subscription = node.subscribe(
                "position.current", "mission/team/alpha",
            )
            for data_class, logical_key in (
                (DataClass.STATE, b"state-key"),
                (DataClass.RECORD, b"record-key"),
            ):
                node.publish(
                    data_class, "position.current", "mission/team/alpha",
                    b"old", logical_key=logical_key,
                )
                node.publish(
                    data_class, "position.current", "mission/team/alpha",
                    b"new", logical_key=logical_key,
                )

            deliveries = subscription.poll()
            self.assertEqual(
                {delivery.item.data_class for delivery in deliveries},
                {DataClass.STATE, DataClass.RECORD},
            )
            self.assertEqual(
                [delivery.item.payload for delivery in deliveries],
                [b"new", b"new"],
            )
            for delivery in deliveries:
                subscription.acknowledge(delivery)
            self.assertEqual(subscription.poll(), [])

            recoverable = node.query(
                topic="position.current", scope="mission/team/alpha",
                include_recoverable=True,
            )
            self.assertEqual(len(recoverable), 4)
            self.assertEqual(
                [item.payload for item in recoverable].count(b"old"), 2,
            )

    def test_error_and_repeated_lifecycle(self):
        with self.assertRaises(AsterError):
            Node(":memory:", b"not a provisioning bundle")
        for value in range(12):
            node = Node(":memory:", BUNDLE)
            if value % 2:
                node.close()
            else:
                node.zeroize()
            with self.assertRaises(AsterError):
                node.query()

    def test_blob_streaming_round_trip_and_finish_retry(self):
        payload = b"streamed\0blob-data" * 1700
        with tempfile.TemporaryDirectory() as directory:
            with Node(str(pathlib.Path(directory) / "mesh.db"), BUNDLE) as node:
                writer = node.blob_writer(
                    "position.current", "mission/team/alpha", chunk_size=4096,
                    media_type="application/octet-stream", schema_id=b"test/blob/v1",
                )
                for offset in range(0, len(payload), 3001):
                    self.assertEqual(writer.write(payload[offset:offset + 3001]),
                                     len(payload[offset:offset + 3001]))
                finished = writer.finish()
                self.assertEqual(writer.finish(), finished)
                writer.close()

                items = node.query(
                    topic="position.current", scope="mission/team/alpha",
                    logical_key=finished.blob_id, data_class=DataClass.BLOB,
                )
                self.assertEqual(len(items), 1)
                self.assertNotEqual(items[0].payload, payload)

                reader = node.blob_reader(
                    "position.current", "mission/team/alpha", finished.blob_id,
                )
                restored = bytearray()
                transfer = bytearray(2111)
                while True:
                    count = reader.readinto(transfer)
                    if count == 0:
                        break
                    restored.extend(transfer[:count])
                reader.close()
                self.assertEqual(bytes(restored), payload)

    def test_finalized_blob_writers_publish_as_one_batch(self):
        with Node(":memory:", BUNDLE) as node:
            first_writer = node.blob_writer(
                "position.current", "mission/team/alpha", chunk_size=4096,
            )
            second_writer = node.blob_writer(
                "position.current", "mission/team/alpha", chunk_size=4096,
            )
            first_writer.write(b"first finalized Blob")
            second_writer.write(b"second finalized Blob")
            result = node.publish_blob_batch(
                (first_writer, second_writer),
                BatchPublicationPolicy.RETAINED_DUAL,
            )
            self.assertEqual(len(result.items), 2)
            self.assertEqual(result.evicted, ())
            self.assertEqual([item.causal_counter for item in result.items], [1, 2])
            first = first_writer.finish()
            second = second_writer.finish()
            self.assertEqual(first.receipt.item_id, result.items[0].item_id)
            self.assertEqual(second.receipt.item_id, result.items[1].item_id)
            self.assertNotEqual(first.blob_id, second.blob_id)
            with self.assertRaises(AsterError):
                node.publish_blob_batch(
                    (first_writer, second_writer),
                    BatchPublicationPolicy.BATCH_ONLY,
                )
            first_writer.close()
            second_writer.close()

    def test_invalid_name_and_enum(self):
        with Node(":memory:", BUNDLE) as node:
            with self.assertRaises(AsterError):
                node.publish(DataClass.STATE, "bad/topic", "scope", b"x", logical_key=b"k")
            with self.assertRaises(AsterError):
                node.publish(DataClass.BLOB, "document.attachment", "scope", b"not streamed",
                             logical_key=b"blob")

    def test_rekey_binding_validates_borrowed_nested_inputs(self):
        node_id = bytes(range(32))
        with Node(":memory:", BUNDLE) as node:
            with self.assertRaises(ValueError):
                node.rekey_scope(b"", 1, "mission/team/alpha", 1,
                                 [RekeyRecipient.route_only(node_id)])
            with self.assertRaises(ValueError):
                node.rekey_scope(b"opaque", 1, "mission/team/alpha", 1, [])
            with self.assertRaises(ValueError):
                node.rekey_scope(
                    b"opaque", 1, "mission/team/alpha", 1,
                    [RekeyRecipient(node_id, RekeyAccess.ROUTE_ONLY, ("position.current",))],
                )
            with self.assertRaises(ValueError):
                node.rekey_scope(
                    b"opaque", 1, "mission/team/alpha", 1,
                    [RekeyRecipient(node_id, RekeyAccess.READ_TOPICS)],
                )
            with self.assertRaises(ValueError):
                node.rekey_scope(
                    b"opaque", 1, "mission/team/alpha", 1,
                    [RekeyRecipient.read_topics(b"short", ("position.current",))],
                )
            with self.assertRaises(ValueError):
                node.rekey_scope(
                    b"opaque", 1, "mission/team/alpha", 1,
                    [RekeyRecipient.read_topics(node_id, ("x" * 129,))],
                )
            with self.assertRaises(AsterError):
                node.rekey_scope(
                    b"opaque", 1, "mission/team/alpha", 1,
                    [RekeyRecipient.read_topics(node_id, ("position.current",))],
                )

    def test_bridge_binding_bounds_status_pages_and_opaque_errors(self):
        with Node(":memory:", BUNDLE) as node:
            self.assertEqual(node.bridge_authorizations(), [])
            self.assertEqual(node.bridge_routes(), [])
            with self.assertRaises(ValueError):
                node.bridge_authorization_status(b"short")
            with self.assertRaises(ValueError):
                node.bridge_routes(limit=4097)
            with self.assertRaises(TypeError):
                node.enable_bridge(
                    object(),
                    BridgeAuthorizationPolicy(
                        ("position.current",), PriorityMask.IMMEDIATE, 8,
                    ),
                )
            with self.assertRaises(ValueError):
                node.bridge_item(
                    bytes(32), bytes(32),
                    BridgeNarrowingPolicy((), PriorityMask(0)),
                )
            with self.assertRaises(ValueError):
                node.bridge_item(
                    bytes(31), bytes(32),
                    BridgeNarrowingPolicy((), PriorityMask.IMMEDIATE),
                )
            with self.assertRaises(AsterError):
                node.create_bridge_enrollment(
                    "mission/team/alpha", 1, "mission/team/alpha", 1,
                )


if __name__ == "__main__":
    unittest.main()
