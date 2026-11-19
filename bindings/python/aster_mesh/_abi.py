"""ABI v2 ctypes layouts; matches bindings/c/aster_mesh.h."""
from ctypes import *
ABI_VERSION = 2
BLOB_SEGMENT_BYTES = 1024 * 1024
BLOB_READ_PAGE_BYTES = 512 * 1024

class Bytes(Structure):
    _fields_ = [("data", POINTER(c_uint8)), ("len", c_size_t)]

class OwnedBuffer(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("allocation", c_uint64), ("data", POINTER(c_uint8)), ("len", c_size_t)]

class NodeOptions(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("state_path", Bytes), ("provisioning_path", Bytes), ("max_items", c_uint64), ("max_bytes", c_uint64), ("max_blob_bytes", c_uint64), ("max_blob_chunks", c_uint64), ("max_blob_variants", c_uint64), ("emission_threshold", c_uint32)]

class Client(Structure):
    _fields_ = [("client_id", Bytes), ("session", c_uint64)]

class RecoveryRequest(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("client", Client), ("claim_nonce", Bytes)]

class Recovery(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("session", c_uint64), ("allocated_through", c_uint64), ("snapshot_revision", c_uint64), ("results", c_uint64)]

class CompleteRecoveryRequest(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("client", Client), ("snapshot_revision", c_uint64)]

class EventResultRequest(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("client", Client), ("sequence", c_uint64)]

class PublishRequest(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("data_class", c_uint32), ("priority", c_uint32), ("operation_key", Bytes), ("client", Client), ("sequence", c_uint64), ("topic", Bytes), ("scope", Bytes), ("logical_key", Bytes), ("payload", Bytes), ("predecessor", c_uint8 * 32), ("has_predecessor", c_uint8), ("tombstone", c_uint8), ("has_ttl", c_uint8), ("ttl_ms", c_uint64)]

class PublishReceipt(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("item_id", c_uint8 * 32), ("blob_id", c_uint8 * 32), ("publisher", c_uint8 * 32), ("publisher_counter", c_uint64), ("sequence", c_uint64), ("acceptance_marker", c_uint64), ("total_len", c_uint64), ("ttl_ms", c_uint64), ("has_ttl", c_uint8), ("inserted", c_uint8), ("content_retired", c_uint8)]

class QueryRequest(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("data_class", c_uint32), ("topic", Bytes), ("scope", Bytes), ("logical_key", Bytes), ("include_descendant_scopes", c_uint8), ("include_recoverable_versions", c_uint8), ("after_acceptance_marker", c_uint64), ("before_acceptance_marker", c_uint64), ("limit", c_uint64)]

class ResultInfo(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("len", c_uint64), ("scanned_through", c_uint64), ("has_more", c_uint8)]

class Entry(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("item_count", c_uint64), ("id", c_uint8 * 32), ("attempt", c_uint64), ("kind", c_uint32), ("retirement_reason", c_uint32), ("retirement_generation", c_uint64), ("has_guard", c_uint8), ("topic", OwnedBuffer), ("scope", OwnedBuffer), ("logical_key", OwnedBuffer), ("sibling_ids", OwnedBuffer), ("token", OwnedBuffer)]

class Item(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("id", c_uint8 * 32), ("blob_id", c_uint8 * 32), ("publisher", c_uint8 * 32), ("publisher_counter", c_uint64), ("data_class", c_uint32), ("priority", c_uint32), ("disposition", c_uint32), ("event_sequence", c_uint64), ("acceptance_marker", c_uint64), ("total_len", c_uint64), ("ttl_ms", c_uint64), ("has_ttl", c_uint8), ("tombstone", c_uint8), ("topic", OwnedBuffer), ("scope", OwnedBuffer), ("logical_key", OwnedBuffer), ("payload", OwnedBuffer), ("media_type", OwnedBuffer), ("schema_id", OwnedBuffer)]

class SubscribeRequest(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("data_class", c_uint32), ("client", Client), ("operation_key", Bytes), ("topic", Bytes), ("scope", Bytes), ("include_descendant_scopes", c_uint8)]

class Subscription(Structure):
    _fields_ = [("id", c_uint8 * 32), ("data_class", c_uint32)]

class PollRequest(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("subscription", Subscription), ("client", Client), ("delivery_limit", c_uint64), ("scan_limit", c_uint64)]

class AckRequest(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("subscription", Subscription), ("client", Client), ("id", c_uint8 * 32), ("token", Bytes)]

class UnsubscribeRequest(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("subscription", Subscription), ("client", Client)]

class ResolveRequest(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("guard", c_uint64), ("entry", c_uint64), ("operation_key", Bytes), ("payload", Bytes), ("priority", c_uint32), ("tombstone", c_uint8)]

class BlobPublishOptions(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("operation_key", Bytes), ("topic", Bytes), ("scope", Bytes), ("media_type", Bytes), ("schema_id", Bytes), ("priority", c_uint32), ("total_len", c_uint64), ("ttl_ms", c_uint64), ("has_ttl", c_uint8)]

class BlobWriterInfo(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("writer", c_uint64), ("durable_offset", c_uint64)]

class BlobReadRequest(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("topic", Bytes), ("scope", Bytes), ("blob_id", c_uint8 * 32)]

class PeerSnapshot(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("peer", c_uint8 * 32), ("contacts", c_uint64), ("authorization", c_uint32), ("last_contact", c_uint32)]

class PeerRequest(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("peer", c_uint8 * 32)]

class DeliveryStatus(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("subscriptions", c_uint64), ("pending_deliveries", c_uint64), ("acknowledged_deliveries", c_uint64), ("delivery_cursors", c_uint64), ("selector_generation", c_uint64)]

class RekeyRecipient(Structure):
    _fields_ = [("node_id", c_uint8 * 32), ("topics", POINTER(Bytes)), ("topic_count", c_size_t)]

class RekeyRequest(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("signed_public_registry", Bytes), ("minimum_registry_generation", c_uint64), ("scope", Bytes), ("epoch", c_uint64), ("recipients", POINTER(RekeyRecipient)), ("recipient_count", c_size_t)]

class ControlReceipt(Structure):
    _fields_ = [("abi_version", c_uint32), ("struct_size", c_uint32), ("transfer_id", c_uint8 * 32), ("sequence", c_uint64), ("activated", c_uint64), ("emitted", c_uint8)]

def configure(lib):
    lib.aster_abi_version.argtypes = []
    lib.aster_abi_version.restype = c_uint32
    lib.aster_protocol_version.argtypes = []
    lib.aster_protocol_version.restype = c_uint16
    lib.aster_replication_wire_version.argtypes = []
    lib.aster_replication_wire_version.restype = c_uint16
    lib.aster_default_semantic_version.argtypes = []
    lib.aster_default_semantic_version.restype = c_uint16
    lib.aster_highest_supported_semantic_version.argtypes = []
    lib.aster_highest_supported_semantic_version.restype = c_uint16
    lib.aster_last_error.argtypes = [POINTER(OwnedBuffer)]
    lib.aster_last_error.restype = c_uint32
    lib.aster_buffer_free.argtypes = [POINTER(OwnedBuffer)]
    lib.aster_buffer_free.restype = c_uint32
    lib.aster_node_options_init.argtypes = [POINTER(NodeOptions)]
    lib.aster_node_options_init.restype = c_uint32
    lib.aster_node_open.argtypes = [POINTER(NodeOptions), POINTER(c_uint64)]
    lib.aster_node_open.restype = c_uint32
    lib.aster_node_close.argtypes = [POINTER(c_uint64)]
    lib.aster_node_close.restype = c_uint32
    lib.aster_node_zeroize.argtypes = [POINTER(c_uint64)]
    lib.aster_node_zeroize.restype = c_uint32
    lib.aster_node_begin_recovery.argtypes = [c_uint64, POINTER(RecoveryRequest), POINTER(Recovery)]
    lib.aster_node_begin_recovery.restype = c_uint32
    lib.aster_node_complete_recovery.argtypes = [c_uint64, POINTER(CompleteRecoveryRequest)]
    lib.aster_node_complete_recovery.restype = c_uint32
    lib.aster_node_acknowledge_publication.argtypes = [c_uint64, POINTER(EventResultRequest)]
    lib.aster_node_acknowledge_publication.restype = c_uint32
    lib.aster_node_abandon_publication.argtypes = [c_uint64, POINTER(EventResultRequest)]
    lib.aster_node_abandon_publication.restype = c_uint32
    lib.aster_node_publish.argtypes = [c_uint64, POINTER(PublishRequest), POINTER(PublishReceipt)]
    lib.aster_node_publish.restype = c_uint32
    lib.aster_node_query.argtypes = [c_uint64, POINTER(QueryRequest), POINTER(c_uint64)]
    lib.aster_node_query.restype = c_uint32
    lib.aster_node_conflicts.argtypes = [c_uint64, POINTER(QueryRequest), POINTER(c_uint64)]
    lib.aster_node_conflicts.restype = c_uint32
    lib.aster_node_resolve.argtypes = [c_uint64, POINTER(ResolveRequest), POINTER(PublishReceipt)]
    lib.aster_node_resolve.restype = c_uint32
    lib.aster_node_subscribe.argtypes = [c_uint64, POINTER(SubscribeRequest), POINTER(Subscription)]
    lib.aster_node_subscribe.restype = c_uint32
    lib.aster_node_poll.argtypes = [c_uint64, POINTER(PollRequest), POINTER(c_uint64)]
    lib.aster_node_poll.restype = c_uint32
    lib.aster_node_acknowledge.argtypes = [c_uint64, POINTER(AckRequest)]
    lib.aster_node_acknowledge.restype = c_uint32
    lib.aster_node_unsubscribe.argtypes = [c_uint64, POINTER(UnsubscribeRequest)]
    lib.aster_node_unsubscribe.restype = c_uint32
    lib.aster_node_delivery_status.argtypes = [c_uint64, c_uint32, POINTER(DeliveryStatus)]
    lib.aster_node_delivery_status.restype = c_uint32
    lib.aster_node_blob_writer_open.argtypes = [c_uint64, POINTER(BlobPublishOptions), POINTER(BlobWriterInfo)]
    lib.aster_node_blob_writer_open.restype = c_uint32
    lib.aster_blob_writer_write.argtypes = [c_uint64, c_uint64, c_uint64, Bytes]
    lib.aster_blob_writer_write.restype = c_uint32
    lib.aster_blob_writer_finish.argtypes = [c_uint64, c_uint64, POINTER(PublishReceipt)]
    lib.aster_blob_writer_finish.restype = c_uint32
    lib.aster_blob_writer_close.argtypes = [c_uint64, POINTER(c_uint64)]
    lib.aster_blob_writer_close.restype = c_uint32
    lib.aster_node_blob_reader_open.argtypes = [c_uint64, POINTER(BlobReadRequest), POINTER(c_uint64)]
    lib.aster_node_blob_reader_open.restype = c_uint32
    lib.aster_blob_reader_read.argtypes = [c_uint64, c_uint64, c_uint64, POINTER(OwnedBuffer)]
    lib.aster_blob_reader_read.restype = c_uint32
    lib.aster_blob_reader_close.argtypes = [c_uint64, POINTER(c_uint64)]
    lib.aster_blob_reader_close.restype = c_uint32
    lib.aster_result_info.argtypes = [c_uint64, c_uint64, POINTER(ResultInfo)]
    lib.aster_result_info.restype = c_uint32
    lib.aster_result_entry.argtypes = [c_uint64, c_uint64, c_uint64, POINTER(Entry)]
    lib.aster_result_entry.restype = c_uint32
    lib.aster_result_item.argtypes = [c_uint64, c_uint64, c_uint64, c_uint64, POINTER(Item)]
    lib.aster_result_item.restype = c_uint32
    lib.aster_result_receipt.argtypes = [c_uint64, c_uint64, c_uint64, POINTER(PublishReceipt)]
    lib.aster_result_receipt.restype = c_uint32
    lib.aster_result_peer.argtypes = [c_uint64, c_uint64, c_uint64, POINTER(PeerSnapshot)]
    lib.aster_result_peer.restype = c_uint32
    lib.aster_result_close.argtypes = [c_uint64, POINTER(c_uint64)]
    lib.aster_result_close.restype = c_uint32
    lib.aster_item_free.argtypes = [POINTER(Item)]
    lib.aster_item_free.restype = c_uint32
    lib.aster_entry_free.argtypes = [POINTER(Entry)]
    lib.aster_entry_free.restype = c_uint32
    lib.aster_node_set_emission.argtypes = [c_uint64, c_uint32]
    lib.aster_node_set_emission.restype = c_uint32
    lib.aster_node_get_emission.argtypes = [c_uint64, POINTER(c_uint32)]
    lib.aster_node_get_emission.restype = c_uint32
    lib.aster_node_peers.argtypes = [c_uint64, POINTER(c_uint64)]
    lib.aster_node_peers.restype = c_uint32
    lib.aster_node_peer_status.argtypes = [c_uint64, POINTER(PeerRequest), POINTER(PeerSnapshot)]
    lib.aster_node_peer_status.restype = c_uint32
    lib.aster_node_rekey_scope.argtypes = [c_uint64, POINTER(RekeyRequest), POINTER(ControlReceipt)]
    lib.aster_node_rekey_scope.restype = c_uint32
