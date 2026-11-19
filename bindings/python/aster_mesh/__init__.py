"""Synchronous ABI v2 bindings for the selected local Aster node.

Use absolute state/provisioning paths. Provisioning is an owner-only reference
artifact. Event callers persist client/session/sequence and recovery state.
State/Record calls require operation keys; queries require exact logical keys.
"""
import ctypes as C
import enum
import io
import os
import pathlib
import threading
from dataclasses import dataclass
from . import _abi as A


class DataClass(enum.IntEnum):
    STATE = 0
    EVENT = 1
    RECORD = 2
    BLOB = 3


class Priority(enum.IntEnum):
    ROUTINE = 0
    PRIORITY = 1
    IMMEDIATE = 2
    FLASH = 3


class EmissionThreshold(enum.IntEnum):
    ROUTINE = 0
    PRIORITY = 1
    IMMEDIATE = 2
    FLASH = 3
    RECEIVE_ONLY = 4


class AsterError(RuntimeError):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


def _library():
    path = os.environ.get("ASTER_MESH_LIBRARY") or os.environ.get("ASTER_LIBRARY")
    if not path:
        root = pathlib.Path(__file__).resolve().parents[3]
        path = root / "target" / "debug" / ("libaster_ffi.dylib" if os.sys.platform == "darwin" else "aster_ffi.dll" if os.name == "nt" else "libaster_ffi.so")
    lib = C.CDLL(str(path))
    lib.aster_abi_version.restype = C.c_uint32
    if lib.aster_abi_version() != A.ABI_VERSION:
        raise RuntimeError("Aster ABI v2 required")
    A.configure(lib)
    return lib


_lib = _library()
ABI_VERSION = A.ABI_VERSION
PROTOCOL_VERSION = _lib.aster_protocol_version()
REPLICATION_WIRE_VERSION = _lib.aster_replication_wire_version()
DEFAULT_SEMANTIC_VERSION = _lib.aster_default_semantic_version()
HIGHEST_SUPPORTED_SEMANTIC_VERSION = _lib.aster_highest_supported_semantic_version()


def _new(cls, **kwargs):
    value = cls()
    for name, typ in cls._fields_:
        if isinstance(typ, type) and issubclass(typ, C.Structure):
            setattr(value, name, _new(typ))
    if hasattr(value, "abi_version"):
        value.abi_version = A.ABI_VERSION
        value.struct_size = C.sizeof(cls)
    for name, val in kwargs.items():
        setattr(value, name, val)
    return value


def _u64(value):
    if not isinstance(value, int) or not 0 <= value < 2**64:
        raise ValueError("expected an unsigned 64-bit integer")
    return value


def _bytes(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    value = bytes(value)
    backing = (C.c_uint8 * len(value)).from_buffer_copy(value)
    return A.Bytes(C.cast(backing, C.POINTER(C.c_uint8)), len(value))


def _id(value):
    value = bytes(value)
    if len(value) != 32:
        raise ValueError("identifier must contain exactly 32 bytes")
    return (C.c_uint8 * 32).from_buffer_copy(value)


def _copy(buf):
    return C.string_at(buf.data, buf.len) if buf.len else b""


def _check(status):
    if status:
        error = _new(A.OwnedBuffer)
        message = "Aster operation failed"
        if _lib.aster_last_error(C.byref(error)) == 0:
            message = _copy(error).decode("utf-8", "replace")
            _lib.aster_buffer_free(C.byref(error))
        raise AsterError(status, message)


@dataclass(frozen=True)
class Client:
    client_id: bytes
    session: int

    def _native(self):
        return A.Client(_bytes(self.client_id), _u64(self.session))


@dataclass(frozen=True)
class Receipt:
    item_id: bytes
    blob_id: bytes
    publisher: bytes
    publisher_counter: int
    sequence: int
    acceptance_marker: int
    total_len: int
    ttl_ms: int | None
    inserted: bool
    content_retired: bool

    @classmethod
    def _from(cls, r):
        return cls(bytes(r.item_id), bytes(r.blob_id), bytes(r.publisher), r.publisher_counter,
                   r.sequence, r.acceptance_marker, r.total_len,
                   r.ttl_ms if r.has_ttl else None, bool(r.inserted), bool(r.content_retired))


@dataclass(frozen=True)
class Item:
    item_id: bytes
    blob_id: bytes
    publisher: bytes
    publisher_counter: int
    data_class: DataClass
    priority: Priority
    disposition: int
    event_sequence: int
    acceptance_marker: int
    total_len: int
    ttl_ms: int | None
    tombstone: bool
    topic: str
    scope: str
    logical_key: bytes
    payload: bytes
    media_type: str | None
    schema_id: bytes

    @classmethod
    def _from(cls, i):
        return cls(bytes(i.id), bytes(i.blob_id), bytes(i.publisher), i.publisher_counter,
                   DataClass(i.data_class), Priority(i.priority), i.disposition,
                   i.event_sequence, i.acceptance_marker, i.total_len,
                   i.ttl_ms if i.has_ttl else None, bool(i.tombstone),
                   _copy(i.topic).decode(), _copy(i.scope).decode(), _copy(i.logical_key),
                   _copy(i.payload), _copy(i.media_type).decode() or None, _copy(i.schema_id))


@dataclass(frozen=True)
class Delivery:
    items: tuple
    delivery_id: bytes
    attempt: int
    token: bytes
    sibling_ids: tuple
    topic: str
    scope: str
    logical_key: bytes
    has_guard: bool
    retirement: bool
    retirement_reason: int
    retirement_generation: int


class Result:
    """Owned projection/page. Keep open while using a Record resolution guard."""
    def __init__(self, node, handle):
        self.node, self._handle = node, handle
        self.entries = []
        try:
            info = _new(A.ResultInfo)
            _check(_lib.aster_result_info(node._handle, handle, C.byref(info)))
            self.scanned_through, self.has_more = info.scanned_through, bool(info.has_more)
            for index in range(info.len):
                entry = _new(A.Entry)
                _check(_lib.aster_result_entry(node._handle, handle, index, C.byref(entry)))
                try:
                    items = []
                    for version in range(entry.item_count):
                        item = _new(A.Item)
                        _check(_lib.aster_result_item(node._handle, handle, index, version, C.byref(item)))
                        try:
                            items.append(Item._from(item))
                        finally:
                            _check(_lib.aster_item_free(C.byref(item)))
                    ids = _copy(entry.sibling_ids)
                    self.entries.append(Delivery(tuple(items), bytes(entry.id), entry.attempt,
                        _copy(entry.token), tuple(ids[i:i+32] for i in range(0, len(ids), 32)),
                        _copy(entry.topic).decode(), _copy(entry.scope).decode(), _copy(entry.logical_key),
                        bool(entry.has_guard), bool(entry.kind), entry.retirement_reason, entry.retirement_generation))
                finally:
                    _check(_lib.aster_entry_free(C.byref(entry)))
            self.items = tuple(item for entry in self.entries for item in entry.items)
        except BaseException:
            self.close()
            raise

    def __len__(self): return len(self.items)
    def __iter__(self): return iter(self.items)
    def __getitem__(self, index): return self.items[index]
    def __enter__(self): return self
    def __exit__(self, *_): self.close()
    def close(self):
        with self.node._lock:
            if self._handle.value:
                status = _lib.aster_result_close(self.node._handle, C.byref(self._handle))
                if status != 5: _check(status)
    def __del__(self):
        try: self.close()
        except Exception: pass


class Subscription:
    def __init__(self, node, native, client=None):
        self.node, self._native, self.client = node, native, client
    @property
    def subscription_id(self): return bytes(self._native.id)
    def poll(self, delivery_limit=64, scan_limit=1024):
        r = _new(A.PollRequest, subscription=self._native,
                 client=self.client._native() if self.client else A.Client(),
                 delivery_limit=_u64(delivery_limit), scan_limit=_u64(scan_limit))
        return self.node._result("aster_node_poll", r)
    def acknowledge(self, delivery):
        r = _new(A.AckRequest, subscription=self._native,
                 client=self.client._native() if self.client else A.Client(),
                 id=_id(delivery.delivery_id), token=_bytes(delivery.token))
        self.node._call("aster_node_acknowledge", r)
    def unsubscribe(self):
        self.node._call("aster_node_unsubscribe", _new(A.UnsubscribeRequest,
            subscription=self._native, client=self.client._native() if self.client else A.Client()))


class Node:
    def __init__(self, state_path, provisioning_path, **options):
        self._lock, self._handle = threading.RLock(), C.c_uint64()
        native = _new(A.NodeOptions)
        _check(_lib.aster_node_options_init(C.byref(native)))
        native.state_path, native.provisioning_path = _bytes(os.fspath(state_path)), _bytes(os.fspath(provisioning_path))
        allowed = {"max_items", "max_bytes", "max_blob_bytes", "max_blob_chunks", "max_blob_variants", "emission_threshold"}
        if options.keys() - allowed: raise TypeError("unknown node options")
        for name, value in options.items():
            if name == "emission_threshold": value = EmissionThreshold(value)
            setattr(native, name, _u64(value))
        _check(_lib.aster_node_open(C.byref(native), C.byref(self._handle)))
    def __enter__(self): return self
    def __exit__(self, *_): self.close()
    def __del__(self):
        try: self.close()
        except Exception: pass
    def close(self):
        with self._lock: _check(_lib.aster_node_close(C.byref(self._handle)))
    def zeroize(self):
        """Terminalize this state and destroy its selected provisioning artifact."""
        with self._lock: _check(_lib.aster_node_zeroize(C.byref(self._handle)))
    def _call(self, name, request, output=None):
        with self._lock:
            args = [self._handle, C.byref(request)]
            if output is not None: args.append(C.byref(output))
            _check(getattr(_lib, name)(*args))
        return output
    def _result(self, name, request):
        with self._lock:
            handle = C.c_uint64()
            self._call(name, request, handle)
            return Result(self, handle)
    def begin_recovery(self, client_id, expected_session, claim_nonce):
        """Persist the claim nonce before calling; reconcile results before complete_recovery."""
        r = _new(A.RecoveryRequest, client=Client(client_id, expected_session)._native(), claim_nonce=_bytes(claim_nonce))
        out = _new(A.Recovery)
        with self._lock:
            self._call("aster_node_begin_recovery", r, out)
            handle = C.c_uint64(out.results)
            try:
                info = _new(A.ResultInfo)
                _check(_lib.aster_result_info(self._handle, handle, C.byref(info)))
                receipts = []
                for i in range(info.len):
                    receipt = _new(A.PublishReceipt)
                    _check(_lib.aster_result_receipt(self._handle, handle, i, C.byref(receipt)))
                    receipts.append(Receipt._from(receipt))
                return Client(bytes(client_id), out.session), out.allocated_through, out.snapshot_revision, tuple(receipts)
            finally: _check(_lib.aster_result_close(self._handle, C.byref(handle)))
    def complete_recovery(self, client, snapshot_revision):
        self._call("aster_node_complete_recovery", _new(A.CompleteRecoveryRequest,
            client=client._native(), snapshot_revision=_u64(snapshot_revision)))
    def acknowledge_publication(self, client, sequence):
        self._call("aster_node_acknowledge_publication", _new(A.EventResultRequest, client=client._native(), sequence=_u64(sequence)))
    def abandon_publication(self, client, sequence):
        self._call("aster_node_abandon_publication", _new(A.EventResultRequest, client=client._native(), sequence=_u64(sequence)))
    def publish(self, data_class, topic, scope, payload, *, operation_key=b"", logical_key=b"", priority=Priority.ROUTINE, ttl_ms=None, tombstone=False, client=None, sequence=0, predecessor=None):
        r = _new(A.PublishRequest, data_class=DataClass(data_class), priority=Priority(priority), operation_key=_bytes(operation_key),
            client=client._native() if client else A.Client(), sequence=_u64(sequence), topic=_bytes(topic), scope=_bytes(scope),
            logical_key=_bytes(logical_key), payload=_bytes(payload), has_ttl=ttl_ms is not None, ttl_ms=_u64(ttl_ms or 0),
            tombstone=bool(tombstone), has_predecessor=predecessor is not None, predecessor=_id(predecessor or bytes(32)))
        return Receipt._from(self._call("aster_node_publish", r, _new(A.PublishReceipt)))
    def query(self, data_class, *, topic="", scope="", logical_key=b"", include_recoverable=False, include_descendants=False, after=0, before=0, limit=None):
        data_class = DataClass(data_class)
        if limit is None: limit = 128 if data_class == DataClass.EVENT else 0
        return self._result("aster_node_query", _new(A.QueryRequest, data_class=data_class, topic=_bytes(topic), scope=_bytes(scope), logical_key=_bytes(logical_key),
            include_recoverable_versions=bool(include_recoverable), include_descendant_scopes=bool(include_descendants), after_acceptance_marker=_u64(after), before_acceptance_marker=_u64(before), limit=_u64(limit)))
    def conflicts(self, **kwargs): return self.query(DataClass.RECORD, **kwargs)
    def resolve(self, projection, payload, *, operation_key, entry=0, priority=Priority.ROUTINE, tombstone=False):
        if projection.node is not self: raise ValueError("foreign resolution guard")
        return Receipt._from(self._call("aster_node_resolve", _new(A.ResolveRequest, guard=projection._handle.value, entry=_u64(entry),
            operation_key=_bytes(operation_key), payload=_bytes(payload), priority=Priority(priority), tombstone=bool(tombstone)), _new(A.PublishReceipt)))
    def subscribe(self, data_class, topic, scope, *, operation_key, client=None, include_descendants=False):
        r = _new(A.SubscribeRequest, data_class=DataClass(data_class), client=client._native() if client else A.Client(), operation_key=_bytes(operation_key),
            topic=_bytes(topic), scope=_bytes(scope), include_descendant_scopes=bool(include_descendants))
        return Subscription(self, self._call("aster_node_subscribe", r, A.Subscription()), client)
    def restore_subscription(self, data_class, subscription_id, *, client=None):
        return Subscription(self, A.Subscription(_id(subscription_id), DataClass(data_class)), client)
    @property
    def emission_threshold(self):
        with self._lock:
            out = C.c_uint32()
            _check(_lib.aster_node_get_emission(self._handle, C.byref(out)))
            return EmissionThreshold(out.value)
    @emission_threshold.setter
    def emission_threshold(self, value):
        with self._lock: _check(_lib.aster_node_set_emission(self._handle, EmissionThreshold(value)))
    def delivery_status(self, data_class):
        with self._lock:
            out = _new(A.DeliveryStatus)
            _check(_lib.aster_node_delivery_status(self._handle, DataClass(data_class), C.byref(out)))
            return {name: getattr(out, name) for name, _ in out._fields_ if name not in ("abi_version", "struct_size")}
    def peers(self):
        with self._lock:
            handle = C.c_uint64()
            _check(_lib.aster_node_peers(self._handle, C.byref(handle)))
            try:
                info = _new(A.ResultInfo)
                _check(_lib.aster_result_info(self._handle, handle, C.byref(info)))
                result = []
                for i in range(info.len):
                    peer = _new(A.PeerSnapshot)
                    _check(_lib.aster_result_peer(self._handle, handle, i, C.byref(peer)))
                    result.append(_peer(peer))
                return result
            finally: _check(_lib.aster_result_close(self._handle, C.byref(handle)))
    def peer_status(self, peer):
        return _peer(self._call("aster_node_peer_status", _new(A.PeerRequest, peer=_id(peer)), _new(A.PeerSnapshot)))
    def rekey_scope(self, signed_public_registry, minimum_registry_generation, scope, epoch, recipients):
        """Recipients are (32-byte node ID, readable topics); empty topics means route-only."""
        native = (A.RekeyRecipient * len(recipients))()
        keepalive = []
        for i, (node_id, topics) in enumerate(recipients):
            values = (A.Bytes * len(topics))(*(_bytes(topic) for topic in topics))
            keepalive.append(values)
            native[i] = A.RekeyRecipient(_id(node_id), values, len(topics))
        r = _new(A.RekeyRequest, signed_public_registry=_bytes(signed_public_registry), minimum_registry_generation=_u64(minimum_registry_generation),
            scope=_bytes(scope), epoch=_u64(epoch), recipients=native, recipient_count=len(recipients))
        out = self._call("aster_node_rekey_scope", r, _new(A.ControlReceipt))
        return bytes(out.transfer_id), out.sequence, out.activated, bool(out.emitted)
    def blob_writer(self, topic, scope, *, operation_key, total_len, priority=Priority.ROUTINE, ttl_ms=None, media_type="", schema_id=b""):
        r = _new(A.BlobPublishOptions, operation_key=_bytes(operation_key), topic=_bytes(topic), scope=_bytes(scope), priority=Priority(priority),
            total_len=_u64(total_len), ttl_ms=_u64(ttl_ms or 0), has_ttl=ttl_ms is not None, media_type=_bytes(media_type), schema_id=_bytes(schema_id))
        out = self._call("aster_node_blob_writer_open", r, _new(A.BlobWriterInfo))
        return BlobWriter(self, C.c_uint64(out.writer), out.durable_offset)
    def blob_reader(self, topic, scope, blob_id):
        out = self._call("aster_node_blob_reader_open", _new(A.BlobReadRequest, topic=_bytes(topic), scope=_bytes(scope), blob_id=_id(blob_id)), C.c_uint64())
        return BlobReader(self, out)


def _peer(p):
    return {"peer": bytes(p.peer), "contacts": p.contacts, "authorization": p.authorization, "last_contact": p.last_contact}


class BlobWriter:
    def __init__(self, node, handle, offset):
        self.node, self._handle, self.offset = node, handle, offset
    def __enter__(self): return self
    def __exit__(self, *_): self.close()
    def write(self, data):
        data = bytes(data)
        with self.node._lock:
            if not self._handle.value or not self.node._handle.value:
                raise ValueError("writer is closed")
            start = 0
            while start < len(data):
                size = A.BLOB_SEGMENT_BYTES - self.offset % A.BLOB_SEGMENT_BYTES
                part = data[start:start + size]
                _check(_lib.aster_blob_writer_write(self.node._handle, self._handle, self.offset, _bytes(part)))
                self.offset += len(part)
                start += len(part)
        return len(data)
    def finish(self):
        with self.node._lock:
            out = _new(A.PublishReceipt)
            _check(_lib.aster_blob_writer_finish(self.node._handle, self._handle, C.byref(out)))
            return Receipt._from(out)
    def close(self):
        with self.node._lock:
            status = _lib.aster_blob_writer_close(self.node._handle, C.byref(self._handle))
            if status != 5: _check(status)
    def __del__(self):
        try: self.close()
        except Exception: pass


class BlobReader(io.RawIOBase):
    def __init__(self, node, handle):
        super().__init__()
        self.node, self._handle = node, handle
    def readable(self): return True
    def readinto(self, buffer):
        if self.closed: raise ValueError("reader is closed")
        with self.node._lock:
            if not self.node._handle.value: raise ValueError("node is closed")
            view = memoryview(buffer)
            if view.readonly:
                raise TypeError("Blob reader output must be writable")
            if not view.c_contiguous:
                raise TypeError("Blob reader output must be contiguous")
            view = view.cast("B")
            if not len(view): return 0
            out = _new(A.OwnedBuffer)
            _check(_lib.aster_blob_reader_read(self.node._handle, self._handle, min(len(view), A.BLOB_READ_PAGE_BYTES), C.byref(out)))
            try:
                data = _copy(out)
                view[:len(data)] = data
                return len(data)
            finally: _check(_lib.aster_buffer_free(C.byref(out)))
    def close(self):
        if not self.closed:
            with self.node._lock:
                status = _lib.aster_blob_reader_close(self.node._handle, C.byref(self._handle))
                if status != 5: _check(status)
            super().close()
