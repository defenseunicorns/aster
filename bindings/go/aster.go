// Package aster embeds the selected redb-backed local node through ABI v2.
// Callers own durable Event client/session/sequence recovery. State and Record
// queries select exact keys; a Result owns any opaque Record resolution guard.
package aster

/*
#cgo CFLAGS: -I${SRCDIR}/../c
#cgo LDFLAGS: -laster_ffi
#include <stdlib.h>
#include "aster_mesh.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"unsafe"
)

type DataClass uint32

const (
	State DataClass = iota
	Event
	Record
	Blob
)

type Priority uint32

const (
	Routine Priority = iota
	PriorityMsg
	Immediate
	Flash
)

type EmissionThreshold uint32

const (
	EmitRoutine EmissionThreshold = iota
	EmitPriority
	EmitImmediate
	EmitFlash
	ReceiveOnly
)

func ABIVersion() uint32             { return uint32(C.aster_abi_version()) }
func ProtocolVersion() uint16        { return uint16(C.aster_protocol_version()) }
func ReplicationWireVersion() uint16 { return uint16(C.aster_replication_wire_version()) }
func DefaultSemanticVersion() uint16 { return uint16(C.aster_default_semantic_version()) }
func HighestSupportedSemanticVersion() uint16 {
	return uint16(C.aster_highest_supported_semantic_version())
}

type Error struct {
	Status  uint32
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("aster (%d): %s", e.Status, e.Message) }

// Error text is thread-local: the operation and error retrieval must execute on
// the same OS thread even if the goroutine would otherwise migrate.
func call(f func() C.uint32_t) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	status := f()
	if status == 0 {
		return nil
	}
	b := C.AsterOwnedBuffer{abi_version: 2, struct_size: C.sizeof_AsterOwnedBuffer}
	message := "Aster operation failed"
	if C.aster_last_error(&b) == 0 {
		message = string(copyBuffer(b))
		C.aster_buffer_free(&b)
	}
	return &Error{uint32(status), message}
}
func isClosed(err error) bool { var e *Error; return errors.As(err, &e) && e.Status == 5 }

// All borrowed inputs live in C storage. This also makes nested recipient arrays
// legal under cgo's pointer rules. Every operation releases them before returning.
type inputs []unsafe.Pointer

func (a *inputs) bytes(b []byte) C.AsterBytes {
	if len(b) == 0 {
		return C.AsterBytes{}
	}
	p := C.CBytes(b)
	*a = append(*a, p)
	return C.AsterBytes{data: (*C.uint8_t)(p), len: C.size_t(len(b))}
}
func (a *inputs) text(s string) C.AsterBytes { return a.bytes([]byte(s)) }
func (a inputs) free() {
	for _, p := range a {
		C.free(p)
	}
}
func copyBuffer(b C.AsterOwnedBuffer) []byte {
	if b.len == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(b.data)), int(b.len))...)
}
func id(v [32]C.uint8_t) (out [32]byte) {
	for i := range out {
		out[i] = byte(v[i])
	}
	return
}
func cid(v [32]byte) (out [32]C.uint8_t) {
	for i := range out {
		out[i] = C.uint8_t(v[i])
	}
	return
}
func flag(v bool) C.uint8_t {
	if v {
		return 1
	}
	return 0
}

type Client struct {
	ID      []byte
	Session uint64
}

func (c Client) native(a *inputs) C.AsterClient {
	return C.AsterClient{client_id: a.bytes(c.ID), session: C.uint64_t(c.Session)}
}

type Receipt struct {
	ItemID, BlobID, Publisher                              [32]byte
	PublisherCounter, Sequence, AcceptanceMarker, TotalLen uint64
	TTLMS                                                  uint64
	HasTTL, Inserted, ContentRetired                       bool
}

func receipt(r C.AsterPublishReceipt) Receipt {
	return Receipt{id(r.item_id), id(r.blob_id), id(r.publisher), uint64(r.publisher_counter), uint64(r.sequence), uint64(r.acceptance_marker), uint64(r.total_len), uint64(r.ttl_ms), r.has_ttl != 0, r.inserted != 0, r.content_retired != 0}
}

type Item struct {
	ID, BlobID, Publisher                            [32]byte
	PublisherCounter                                 uint64
	Class                                            DataClass
	Priority                                         Priority
	Disposition                                      uint32
	EventSequence, AcceptanceMarker, TotalLen, TTLMS uint64
	HasTTL, Tombstone                                bool
	Topic, Scope                                     string
	LogicalKey, Payload                              []byte
	MediaType                                        string
	SchemaID                                         []byte
}

func item(r C.AsterItem) Item {
	return Item{id(r.id), id(r.blob_id), id(r.publisher), uint64(r.publisher_counter), DataClass(r.data_class), Priority(r.priority), uint32(r.disposition), uint64(r.event_sequence), uint64(r.acceptance_marker), uint64(r.total_len), uint64(r.ttl_ms), r.has_ttl != 0, r.tombstone != 0, string(copyBuffer(r.topic)), string(copyBuffer(r.scope)), copyBuffer(r.logical_key), copyBuffer(r.payload), string(copyBuffer(r.media_type)), copyBuffer(r.schema_id)}
}

type Delivery struct {
	Items                []Item
	ID                   [32]byte
	Attempt              uint64
	Token                []byte
	Siblings             [][32]byte
	Topic, Scope         string
	LogicalKey           []byte
	HasGuard, Retirement bool
	RetirementReason     uint32
	RetirementGeneration uint64
}
type Node struct {
	mu     sync.Mutex
	handle C.uint64_t
}
type Options struct {
	MaxItems, MaxBytes, MaxBlobBytes, MaxBlobChunks, MaxBlobVariants uint64
	Emission                                                         EmissionThreshold
}

func Open(statePath, provisioningPath string) (*Node, error) {
	return OpenWithOptions(statePath, provisioningPath, Options{})
}
func OpenWithOptions(statePath, provisioningPath string, o Options) (*Node, error) {
	if ABIVersion() != 2 {
		return nil, errors.New("Aster ABI v2 required")
	}
	var a inputs
	defer func() { a.free() }()
	var r C.AsterNodeOptions
	if err := call(func() C.uint32_t { return C.aster_node_options_init(&r) }); err != nil {
		return nil, err
	}
	r.state_path = a.text(statePath)
	r.provisioning_path = a.text(provisioningPath)
	if o.MaxItems != 0 {
		r.max_items = C.uint64_t(o.MaxItems)
	}
	if o.MaxBytes != 0 {
		r.max_bytes = C.uint64_t(o.MaxBytes)
	}
	if o.MaxBlobBytes != 0 {
		r.max_blob_bytes = C.uint64_t(o.MaxBlobBytes)
	}
	if o.MaxBlobChunks != 0 {
		r.max_blob_chunks = C.uint64_t(o.MaxBlobChunks)
	}
	if o.MaxBlobVariants != 0 {
		r.max_blob_variants = C.uint64_t(o.MaxBlobVariants)
	}
	r.emission_threshold = C.uint32_t(o.Emission)
	n := &Node{}
	if err := call(func() C.uint32_t { return C.aster_node_open(&r, &n.handle) }); err != nil {
		return nil, err
	}
	runtime.SetFinalizer(n, func(n *Node) { _ = n.Close() })
	return n, nil
}
func (n *Node) Close() error {
	runtime.SetFinalizer(n, nil)
	n.mu.Lock()
	defer n.mu.Unlock()
	return call(func() C.uint32_t { return C.aster_node_close(&n.handle) })
}

// Zeroize terminalizes this state and destroys its selected provisioning artifact.
func (n *Node) Zeroize() error {
	runtime.SetFinalizer(n, nil)
	n.mu.Lock()
	defer n.mu.Unlock()
	return call(func() C.uint32_t { return C.aster_node_zeroize(&n.handle) })
}

type Recovery struct {
	Client                             Client
	AllocatedThrough, SnapshotRevision uint64
	Outstanding                        []Receipt
}

func (n *Node) BeginRecovery(clientID []byte, expectedSession uint64, claimNonce []byte) (Recovery, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var a inputs
	defer func() { a.free() }()
	r := C.AsterRecoveryRequest{abi_version: 2, struct_size: C.sizeof_AsterRecoveryRequest, client: Client{clientID, expectedSession}.native(&a), claim_nonce: a.bytes(claimNonce)}
	out := C.AsterRecovery{abi_version: 2, struct_size: C.sizeof_AsterRecovery}
	if err := call(func() C.uint32_t { return C.aster_node_begin_recovery(n.handle, &r, &out) }); err != nil {
		return Recovery{}, err
	}
	defer C.aster_result_close(n.handle, &out.results)
	result := Recovery{Client: Client{append([]byte(nil), clientID...), uint64(out.session)}, AllocatedThrough: uint64(out.allocated_through), SnapshotRevision: uint64(out.snapshot_revision)}
	info := C.AsterResultInfo{abi_version: 2, struct_size: C.sizeof_AsterResultInfo}
	if err := call(func() C.uint32_t { return C.aster_result_info(n.handle, out.results, &info) }); err != nil {
		return Recovery{}, err
	}
	for i := C.uint64_t(0); i < info.len; i++ {
		r := C.AsterPublishReceipt{abi_version: 2, struct_size: C.sizeof_AsterPublishReceipt}
		if err := call(func() C.uint32_t { return C.aster_result_receipt(n.handle, out.results, i, &r) }); err != nil {
			return Recovery{}, err
		}
		result.Outstanding = append(result.Outstanding, receipt(r))
	}
	return result, nil
}
func (n *Node) CompleteRecovery(c Client, revision uint64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	var a inputs
	defer func() { a.free() }()
	r := C.AsterCompleteRecoveryRequest{abi_version: 2, struct_size: C.sizeof_AsterCompleteRecoveryRequest, client: c.native(&a), snapshot_revision: C.uint64_t(revision)}
	return call(func() C.uint32_t { return C.aster_node_complete_recovery(n.handle, &r) })
}
func (n *Node) eventResult(c Client, seq uint64, abandon bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	var a inputs
	defer func() { a.free() }()
	r := C.AsterEventResultRequest{abi_version: 2, struct_size: C.sizeof_AsterEventResultRequest, client: c.native(&a), sequence: C.uint64_t(seq)}
	return call(func() C.uint32_t {
		if abandon {
			return C.aster_node_abandon_publication(n.handle, &r)
		}
		return C.aster_node_acknowledge_publication(n.handle, &r)
	})
}
func (n *Node) AcknowledgePublication(c Client, seq uint64) error {
	return n.eventResult(c, seq, false)
}
func (n *Node) AbandonPublication(c Client, seq uint64) error { return n.eventResult(c, seq, true) }

type PublishRequest struct {
	Class               DataClass
	Priority            Priority
	OperationKey        []byte
	Client              Client
	Sequence            uint64
	Topic, Scope        string
	LogicalKey, Payload []byte
	Predecessor         *[32]byte
	TTLMS               *uint64
	Tombstone           bool
}

func (n *Node) Publish(p PublishRequest) (Receipt, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var a inputs
	defer func() { a.free() }()
	r := C.AsterPublishRequest{abi_version: 2, struct_size: C.sizeof_AsterPublishRequest, data_class: C.uint32_t(p.Class), priority: C.uint32_t(p.Priority), operation_key: a.bytes(p.OperationKey), client: p.Client.native(&a), sequence: C.uint64_t(p.Sequence), topic: a.text(p.Topic), scope: a.text(p.Scope), logical_key: a.bytes(p.LogicalKey), payload: a.bytes(p.Payload), tombstone: flag(p.Tombstone)}
	if p.TTLMS != nil {
		r.has_ttl = 1
		r.ttl_ms = C.uint64_t(*p.TTLMS)
	}
	if p.Predecessor != nil {
		r.has_predecessor = 1
		r.predecessor = cid(*p.Predecessor)
	}
	out := C.AsterPublishReceipt{abi_version: 2, struct_size: C.sizeof_AsterPublishReceipt}
	err := call(func() C.uint32_t { return C.aster_node_publish(n.handle, &r, &out) })
	return receipt(out), err
}

type Query struct {
	Class                                  DataClass
	Topic, Scope                           string
	LogicalKey                             []byte
	IncludeDescendants, IncludeRecoverable bool
	After, Before, Limit                   uint64
}
type Result struct {
	node           *Node
	handle         C.uint64_t
	Entries        []Delivery
	Items          []Item
	ScannedThrough uint64
	HasMore        bool
}

// loadResult runs while the owning node lock is held. It frees every temporary
// native buffer, including partial reads, before returning caller-owned copies.
func (n *Node) loadResult(h C.uint64_t) (_ *Result, err error) {
	result := &Result{node: n, handle: h}
	defer func() {
		if err != nil {
			C.aster_result_close(n.handle, &result.handle)
		}
	}()
	info := C.AsterResultInfo{abi_version: 2, struct_size: C.sizeof_AsterResultInfo}
	if err = call(func() C.uint32_t { return C.aster_result_info(n.handle, h, &info) }); err != nil {
		return nil, err
	}
	result.ScannedThrough = uint64(info.scanned_through)
	result.HasMore = info.has_more != 0
	for i := C.uint64_t(0); i < info.len; i++ {
		e := C.AsterEntry{abi_version: 2, struct_size: C.sizeof_AsterEntry}
		if err = call(func() C.uint32_t { return C.aster_result_entry(n.handle, h, i, &e) }); err != nil {
			return nil, err
		}
		d := Delivery{ID: id(e.id), Attempt: uint64(e.attempt), Token: copyBuffer(e.token), Topic: string(copyBuffer(e.topic)), Scope: string(copyBuffer(e.scope)), LogicalKey: copyBuffer(e.logical_key), HasGuard: e.has_guard != 0, Retirement: e.kind != 0, RetirementReason: uint32(e.retirement_reason), RetirementGeneration: uint64(e.retirement_generation)}
		siblings := copyBuffer(e.sibling_ids)
		for j := 0; j < len(siblings); j += 32 {
			var v [32]byte
			copy(v[:], siblings[j:j+32])
			d.Siblings = append(d.Siblings, v)
		}
		count := e.item_count
		C.aster_entry_free(&e)
		for j := C.uint64_t(0); j < count; j++ {
			v := C.AsterItem{abi_version: 2, struct_size: C.sizeof_AsterItem}
			if err = call(func() C.uint32_t { return C.aster_result_item(n.handle, h, i, j, &v) }); err != nil {
				return nil, err
			}
			copied := item(v)
			C.aster_item_free(&v)
			d.Items = append(d.Items, copied)
			result.Items = append(result.Items, copied)
		}
		result.Entries = append(result.Entries, d)
	}
	runtime.SetFinalizer(result, func(r *Result) { _ = r.Close() })
	return result, nil
}
func (r *Result) Close() error {
	runtime.SetFinalizer(r, nil)
	r.node.mu.Lock()
	defer r.node.mu.Unlock()
	err := call(func() C.uint32_t { return C.aster_result_close(r.node.handle, &r.handle) })
	if isClosed(err) {
		return nil
	}
	return err
}
func (n *Node) Query(q Query) (*Result, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var a inputs
	defer func() { a.free() }()
	limit := q.Limit
	if q.Class == Event && limit == 0 {
		limit = 128
	}
	r := C.AsterQueryRequest{abi_version: 2, struct_size: C.sizeof_AsterQueryRequest, data_class: C.uint32_t(q.Class), topic: a.text(q.Topic), scope: a.text(q.Scope), logical_key: a.bytes(q.LogicalKey), include_descendant_scopes: flag(q.IncludeDescendants), include_recoverable_versions: flag(q.IncludeRecoverable), after_acceptance_marker: C.uint64_t(q.After), before_acceptance_marker: C.uint64_t(q.Before), limit: C.uint64_t(limit)}
	var h C.uint64_t
	if err := call(func() C.uint32_t { return C.aster_node_query(n.handle, &r, &h) }); err != nil {
		return nil, err
	}
	return n.loadResult(h)
}
func (n *Node) Conflicts(q Query) (*Result, error) { q.Class = Record; return n.Query(q) }
func (n *Node) Resolve(guard *Result, entry uint64, operationKey, payload []byte, priority Priority, tombstone bool) (Receipt, error) {
	defer runtime.KeepAlive(guard)
	n.mu.Lock()
	defer n.mu.Unlock()
	if guard == nil || guard.node != n {
		return Receipt{}, errors.New("foreign resolution guard")
	}
	var a inputs
	defer func() { a.free() }()
	r := C.AsterResolveRequest{abi_version: 2, struct_size: C.sizeof_AsterResolveRequest, guard: guard.handle, entry: C.uint64_t(entry), operation_key: a.bytes(operationKey), payload: a.bytes(payload), priority: C.uint32_t(priority), tombstone: flag(tombstone)}
	out := C.AsterPublishReceipt{abi_version: 2, struct_size: C.sizeof_AsterPublishReceipt}
	err := call(func() C.uint32_t { return C.aster_node_resolve(n.handle, &r, &out) })
	return receipt(out), err
}

type Subscription struct {
	node   *Node
	ID     [32]byte
	Class  DataClass
	Client Client
}

func (s *Subscription) native() C.AsterSubscription {
	return C.AsterSubscription{id: cid(s.ID), data_class: C.uint32_t(s.Class)}
}
func (n *Node) Subscribe(class DataClass, topic, scope string, operationKey []byte, client Client, descendants bool) (*Subscription, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var a inputs
	defer func() { a.free() }()
	r := C.AsterSubscribeRequest{abi_version: 2, struct_size: C.sizeof_AsterSubscribeRequest, data_class: C.uint32_t(class), topic: a.text(topic), scope: a.text(scope), operation_key: a.bytes(operationKey), client: client.native(&a), include_descendant_scopes: flag(descendants)}
	var out C.AsterSubscription
	if err := call(func() C.uint32_t { return C.aster_node_subscribe(n.handle, &r, &out) }); err != nil {
		return nil, err
	}
	return n.RestoreSubscription(class, id(out.id), client), nil
}
func (n *Node) RestoreSubscription(class DataClass, id [32]byte, c Client) *Subscription {
	c.ID = append([]byte(nil), c.ID...)
	return &Subscription{n, id, class, c}
}
func (s *Subscription) Poll(deliveryLimit, scanLimit uint64) (*Result, error) {
	n := s.node
	n.mu.Lock()
	defer n.mu.Unlock()
	var a inputs
	defer func() { a.free() }()
	r := C.AsterPollRequest{abi_version: 2, struct_size: C.sizeof_AsterPollRequest, subscription: s.native(), client: s.Client.native(&a), delivery_limit: C.uint64_t(deliveryLimit), scan_limit: C.uint64_t(scanLimit)}
	var h C.uint64_t
	if err := call(func() C.uint32_t { return C.aster_node_poll(n.handle, &r, &h) }); err != nil {
		return nil, err
	}
	return n.loadResult(h)
}
func (s *Subscription) Acknowledge(d Delivery) error {
	n := s.node
	n.mu.Lock()
	defer n.mu.Unlock()
	var a inputs
	defer func() { a.free() }()
	r := C.AsterAckRequest{abi_version: 2, struct_size: C.sizeof_AsterAckRequest, subscription: s.native(), client: s.Client.native(&a), id: cid(d.ID), token: a.bytes(d.Token)}
	return call(func() C.uint32_t { return C.aster_node_acknowledge(n.handle, &r) })
}
func (s *Subscription) Unsubscribe() error {
	n := s.node
	n.mu.Lock()
	defer n.mu.Unlock()
	var a inputs
	defer func() { a.free() }()
	r := C.AsterUnsubscribeRequest{abi_version: 2, struct_size: C.sizeof_AsterUnsubscribeRequest, subscription: s.native(), client: s.Client.native(&a)}
	return call(func() C.uint32_t { return C.aster_node_unsubscribe(n.handle, &r) })
}
func (n *Node) SetEmission(v EmissionThreshold) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return call(func() C.uint32_t { return C.aster_node_set_emission(n.handle, C.uint32_t(v)) })
}
func (n *Node) Emission() (EmissionThreshold, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out C.uint32_t
	err := call(func() C.uint32_t { return C.aster_node_get_emission(n.handle, &out) })
	return EmissionThreshold(out), err
}

type DeliveryStatus struct{ Subscriptions, PendingDeliveries, AcknowledgedDeliveries, DeliveryCursors, SelectorGeneration uint64 }

func (n *Node) DeliveryStatus(class DataClass) (DeliveryStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := C.AsterDeliveryStatus{abi_version: 2, struct_size: C.sizeof_AsterDeliveryStatus}
	err := call(func() C.uint32_t { return C.aster_node_delivery_status(n.handle, C.uint32_t(class), &out) })
	return DeliveryStatus{uint64(out.subscriptions), uint64(out.pending_deliveries), uint64(out.acknowledged_deliveries), uint64(out.delivery_cursors), uint64(out.selector_generation)}, err
}

type Peer struct {
	ID                         [32]byte
	Contacts                   uint64
	Authorization, LastContact uint32
}

func peer(p C.AsterPeerSnapshot) Peer {
	return Peer{id(p.peer), uint64(p.contacts), uint32(p.authorization), uint32(p.last_contact)}
}
func (n *Node) Peers() ([]Peer, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var h C.uint64_t
	if err := call(func() C.uint32_t { return C.aster_node_peers(n.handle, &h) }); err != nil {
		return nil, err
	}
	defer C.aster_result_close(n.handle, &h)
	info := C.AsterResultInfo{abi_version: 2, struct_size: C.sizeof_AsterResultInfo}
	if err := call(func() C.uint32_t { return C.aster_result_info(n.handle, h, &info) }); err != nil {
		return nil, err
	}
	var peers []Peer
	for i := C.uint64_t(0); i < info.len; i++ {
		out := C.AsterPeerSnapshot{abi_version: 2, struct_size: C.sizeof_AsterPeerSnapshot}
		if err := call(func() C.uint32_t { return C.aster_result_peer(n.handle, h, i, &out) }); err != nil {
			return nil, err
		}
		peers = append(peers, peer(out))
	}
	return peers, nil
}
func (n *Node) PeerStatus(id [32]byte) (Peer, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r := C.AsterPeerRequest{abi_version: 2, struct_size: C.sizeof_AsterPeerRequest, peer: cid(id)}
	out := C.AsterPeerSnapshot{abi_version: 2, struct_size: C.sizeof_AsterPeerSnapshot}
	err := call(func() C.uint32_t { return C.aster_node_peer_status(n.handle, &r, &out) })
	return peer(out), err
}

type RekeyRecipient struct {
	NodeID [32]byte
	Topics []string
}
type ControlReceipt struct {
	TransferID          [32]byte
	Sequence, Activated uint64
	Emitted             bool
}

func (n *Node) RekeyScope(registry []byte, generation uint64, scope string, epoch uint64, recipients []RekeyRecipient) (ControlReceipt, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var a inputs
	defer func() { a.free() }()
	if len(recipients) > 128 {
		return ControlReceipt{}, errors.New("too many rekey recipients")
	}
	p := C.calloc(C.size_t(len(recipients)), C.sizeof_AsterRekeyRecipient)
	if p == nil && len(recipients) > 0 {
		return ControlReceipt{}, errors.New("allocation failed")
	}
	a = append(a, p)
	native := unsafe.Slice((*C.AsterRekeyRecipient)(p), len(recipients))
	for i, r := range recipients {
		if len(r.Topics) > 256 {
			return ControlReceipt{}, errors.New("too many rekey topics")
		}
		topics := C.calloc(C.size_t(len(r.Topics)), C.sizeof_AsterBytes)
		if topics == nil && len(r.Topics) > 0 {
			return ControlReceipt{}, errors.New("allocation failed")
		}
		a = append(a, topics)
		values := unsafe.Slice((*C.AsterBytes)(topics), len(r.Topics))
		for j, t := range r.Topics {
			values[j] = a.text(t)
		}
		native[i] = C.AsterRekeyRecipient{node_id: cid(r.NodeID), topics: (*C.AsterBytes)(topics), topic_count: C.size_t(len(r.Topics))}
	}
	r := C.AsterRekeyRequest{abi_version: 2, struct_size: C.sizeof_AsterRekeyRequest, signed_public_registry: a.bytes(registry), minimum_registry_generation: C.uint64_t(generation), scope: a.text(scope), epoch: C.uint64_t(epoch), recipients: (*C.AsterRekeyRecipient)(p), recipient_count: C.size_t(len(recipients))}
	out := C.AsterControlReceipt{abi_version: 2, struct_size: C.sizeof_AsterControlReceipt}
	err := call(func() C.uint32_t { return C.aster_node_rekey_scope(n.handle, &r, &out) })
	return ControlReceipt{id(out.transfer_id), uint64(out.sequence), uint64(out.activated), out.emitted != 0}, err
}

type BlobOptions struct {
	OperationKey []byte
	TotalLen     uint64
	Priority     Priority
	TTLMS        *uint64
	MediaType    string
	SchemaID     []byte
}
type BlobWriter struct {
	node   *Node
	handle C.uint64_t
	offset uint64
}

func (n *Node) NewBlobWriter(topic, scope string, o BlobOptions) (*BlobWriter, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var a inputs
	defer func() { a.free() }()
	r := C.AsterBlobPublishOptions{abi_version: 2, struct_size: C.sizeof_AsterBlobPublishOptions, operation_key: a.bytes(o.OperationKey), topic: a.text(topic), scope: a.text(scope), media_type: a.text(o.MediaType), schema_id: a.bytes(o.SchemaID), priority: C.uint32_t(o.Priority), total_len: C.uint64_t(o.TotalLen)}
	if o.TTLMS != nil {
		r.has_ttl = 1
		r.ttl_ms = C.uint64_t(*o.TTLMS)
	}
	out := C.AsterBlobWriterInfo{abi_version: 2, struct_size: C.sizeof_AsterBlobWriterInfo}
	if err := call(func() C.uint32_t { return C.aster_node_blob_writer_open(n.handle, &r, &out) }); err != nil {
		return nil, err
	}
	writer := &BlobWriter{n, out.writer, uint64(out.durable_offset)}
	runtime.SetFinalizer(writer, func(w *BlobWriter) { _ = w.Close() })
	return writer, nil
}
func (w *BlobWriter) Offset() uint64 { w.node.mu.Lock(); defer w.node.mu.Unlock(); return w.offset }
func (w *BlobWriter) Write(data []byte) (int, error) {
	defer runtime.KeepAlive(w)
	w.node.mu.Lock()
	defer w.node.mu.Unlock()
	if w.handle == 0 || w.node.handle == 0 {
		return 0, &Error{5, "writer closed"}
	}
	written := 0
	for len(data) > 0 {
		size := min(len(data), C.ASTER_BLOB_SEGMENT_BYTES-int(w.offset%C.ASTER_BLOB_SEGMENT_BYTES))
		var a inputs
		b := a.bytes(data[:size])
		err := call(func() C.uint32_t { return C.aster_blob_writer_write(w.node.handle, w.handle, C.uint64_t(w.offset), b) })
		a.free()
		if err != nil {
			return written, err
		}
		w.offset += uint64(size)
		written += size
		data = data[size:]
	}
	return written, nil
}
func (w *BlobWriter) Finish() (Receipt, error) {
	defer runtime.KeepAlive(w)
	w.node.mu.Lock()
	defer w.node.mu.Unlock()
	out := C.AsterPublishReceipt{abi_version: 2, struct_size: C.sizeof_AsterPublishReceipt}
	err := call(func() C.uint32_t { return C.aster_blob_writer_finish(w.node.handle, w.handle, &out) })
	return receipt(out), err
}
func (w *BlobWriter) Close() error {
	runtime.SetFinalizer(w, nil)
	w.node.mu.Lock()
	defer w.node.mu.Unlock()
	err := call(func() C.uint32_t { return C.aster_blob_writer_close(w.node.handle, &w.handle) })
	if isClosed(err) {
		return nil
	}
	return err
}

type BlobReader struct {
	node   *Node
	handle C.uint64_t
}

func (n *Node) OpenBlobReader(topic, scope string, blob [32]byte) (*BlobReader, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var a inputs
	defer func() { a.free() }()
	r := C.AsterBlobReadRequest{abi_version: 2, struct_size: C.sizeof_AsterBlobReadRequest, topic: a.text(topic), scope: a.text(scope), blob_id: cid(blob)}
	out := &BlobReader{node: n}
	if err := call(func() C.uint32_t { return C.aster_node_blob_reader_open(n.handle, &r, &out.handle) }); err != nil {
		return nil, err
	}
	runtime.SetFinalizer(out, func(r *BlobReader) { _ = r.Close() })
	return out, nil
}
func (r *BlobReader) Read(p []byte) (int, error) {
	defer runtime.KeepAlive(r)
	r.node.mu.Lock()
	defer r.node.mu.Unlock()
	if r.handle == 0 || r.node.handle == 0 {
		return 0, &Error{5, "reader closed"}
	}
	if len(p) == 0 {
		return 0, nil
	}
	out := C.AsterOwnedBuffer{abi_version: 2, struct_size: C.sizeof_AsterOwnedBuffer}
	if err := call(func() C.uint32_t {
		return C.aster_blob_reader_read(r.node.handle, r.handle, C.uint64_t(min(len(p), C.ASTER_BLOB_READ_PAGE_BYTES)), &out)
	}); err != nil {
		return 0, err
	}
	defer C.aster_buffer_free(&out)
	n := copy(p, copyBuffer(out))
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}
func (r *BlobReader) Close() error {
	runtime.SetFinalizer(r, nil)
	r.node.mu.Lock()
	defer r.node.mu.Unlock()
	err := call(func() C.uint32_t { return C.aster_blob_reader_close(r.node.handle, &r.handle) })
	if isClosed(err) {
		return nil
	}
	return err
}
