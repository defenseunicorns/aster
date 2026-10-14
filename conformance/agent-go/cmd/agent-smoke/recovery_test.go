package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/defenseunicorns/aster/conformance/agent-go/internal/numbered"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	api "github.com/defenseunicorns/aster/conformance/agent-go/gen/aster/application/v1alpha1"
	"google.golang.org/protobuf/proto"
)

// A protocol peer checks client behavior, not the durability of the real agent.
// Actual process recovery is exercised separately by the process checker.
type recoveryPeer struct {
	api.UnimplementedAsterApplicationServiceHandler
	published                                              *api.PublishNumberedEventRequest
	event                                                  *api.Event
	publishes, subscriptions, attempt, quietPolls, queries int
	acknowledged                                           bool
	fault                                                  string
}

func (s *recoveryPeer) PublishNumberedEvent(_ context.Context, r *connect.Request[api.PublishNumberedEventRequest]) (*connect.Response[api.PublishNumberedEventResponse], error) {
	s.publishes++
	if s.publishes == 1 {
		s.published = proto.Clone(r.Msg).(*api.PublishNumberedEventRequest)
		s.event = &api.Event{Id: bytes.Repeat([]byte{1}, 32), Publisher: bytes.Repeat([]byte{2}, 32), PublisherCounter: 3, EventSequence: 4, Topic: r.Msg.Topic, Scope: r.Msg.Scope, Priority: r.Msg.Priority, LogicalKey: r.Msg.LogicalKey, Payload: r.Msg.Payload, AcceptanceMarker: 5}
	} else if !proto.Equal(s.published, r.Msg) {
		return nil, fmt.Errorf("publication request changed")
	}
	response := &api.PublishNumberedEventResponse{Result: &api.CommittedPublicationResult{OperationSequence: r.Msg.OperationSequence, Receipt: &api.CommittedEventReceipt{EventId: s.event.Id, TransferId: bytes.Repeat([]byte{4}, 32), AcceptanceMarker: s.event.AcceptanceMarker}, Content: api.CommittedContentStatus_COMMITTED_CONTENT_STATUS_AVAILABLE}, Inserted: s.publishes == 1}
	if s.publishes == 2 {
		switch s.fault {
		case "retry-receipt":
			response.Result.Receipt.AcceptanceMarker++
		case "retry-inserted":
			response.Inserted = true
		case "retry-priority":
			response.Result.Content = api.CommittedContentStatus_COMMITTED_CONTENT_STATUS_UNSPECIFIED
		}
	}
	return connect.NewResponse(response), nil
}
func (s *recoveryPeer) BeginEventPublicationSession(_ context.Context, _ *connect.Request[api.BeginEventPublicationSessionRequest]) (*connect.Response[api.BeginEventPublicationSessionResponse], error) {
	return connect.NewResponse(&api.BeginEventPublicationSessionResponse{Session: 1}), nil
}
func (s *recoveryPeer) CompleteEventPublicationRecovery(_ context.Context, _ *connect.Request[api.CompleteEventPublicationRecoveryRequest]) (*connect.Response[api.CompleteEventPublicationRecoveryResponse], error) {
	return connect.NewResponse(&api.CompleteEventPublicationRecoveryResponse{}), nil
}
func (s *recoveryPeer) AcknowledgeEventPublicationResult(_ context.Context, _ *connect.Request[api.AcknowledgeEventPublicationResultRequest]) (*connect.Response[api.AcknowledgeEventPublicationResultResponse], error) {
	return connect.NewResponse(&api.AcknowledgeEventPublicationResultResponse{}), nil
}
func (s *recoveryPeer) CreateEventSubscription(_ context.Context, r *connect.Request[api.CreateEventSubscriptionRequest]) (*connect.Response[api.CreateEventSubscriptionResponse], error) {
	s.subscriptions++
	if r.Msg.Topic != s.event.Topic || r.Msg.Scope != s.event.Scope || r.Msg.IncludeDescendantScopes || len(r.Msg.OperationKey) == 0 {
		return nil, fmt.Errorf("wrong selector")
	}
	return connect.NewResponse(&api.CreateEventSubscriptionResponse{SubscriptionId: bytes.Repeat([]byte{3}, 32), Inserted: true}), nil
}
func (s *recoveryPeer) PollEvents(_ context.Context, r *connect.Request[api.PollEventsRequest]) (*connect.Response[api.PollEventsResponse], error) {
	if !bytes.Equal(r.Msg.SubscriptionId, bytes.Repeat([]byte{3}, 32)) || r.Msg.DeliveryLimit != 1 || r.Msg.ScanLimit != 8 {
		return nil, fmt.Errorf("wrong poll")
	}
	if s.acknowledged {
		s.quietPolls++
		switch s.fault {
		case "missing-subscription":
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("missing"))
		case "transport":
			return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("unavailable"))
		case "has-more":
			return connect.NewResponse(&api.PollEventsResponse{HasMore: true}), nil
		case "late-delivery":
			if s.quietPolls == 3 {
				return connect.NewResponse(&api.PollEventsResponse{Deliveries: []*api.EventDelivery{{Event: s.event, Attempt: 3}}}), nil
			}
		}
		return connect.NewResponse(&api.PollEventsResponse{}), nil
	}
	s.attempt++
	event := proto.Clone(s.event).(*api.Event)
	attempt := uint64(s.attempt)
	if s.fault == "wrong-payload" {
		event.Payload = []byte("wrong")
	}
	if s.fault == "stale-attempt" {
		attempt = 1
	}
	return connect.NewResponse(&api.PollEventsResponse{Deliveries: []*api.EventDelivery{{Event: event, Attempt: attempt}}}), nil
}
func (s *recoveryPeer) AcknowledgeEvent(_ context.Context, r *connect.Request[api.AcknowledgeEventRequest]) (*connect.Response[api.AcknowledgeEventResponse], error) {
	if s.attempt != 2 || !bytes.Equal(r.Msg.EventId, s.event.Id) || !bytes.Equal(r.Msg.SubscriptionId, bytes.Repeat([]byte{3}, 32)) {
		return nil, fmt.Errorf("wrong acknowledgement")
	}
	s.acknowledged = true
	return connect.NewResponse(&api.AcknowledgeEventResponse{AlreadyAcknowledged: s.fault == "old-ack"}), nil
}
func (s *recoveryPeer) QueryEvents(_ context.Context, r *connect.Request[api.QueryEventsRequest]) (*connect.Response[api.QueryEventsResponse], error) {
	if r.Msg.Limit == 1 && r.Msg.AfterAcceptanceMarker == s.event.AcceptanceMarker-1 && bytes.Equal(r.Msg.LogicalKey, s.event.LogicalKey) {
		s.queries++
		return connect.NewResponse(&api.QueryEventsResponse{Events: []*api.Event{proto.Clone(s.event).(*api.Event)}}), nil
	}
	s.queries++
	if !s.acknowledged || r.Msg.GetTopic() != s.event.Topic || r.Msg.GetScope() != s.event.Scope || r.Msg.Limit != 2 {
		return nil, fmt.Errorf("wrong retained query")
	}
	event := proto.Clone(s.event).(*api.Event)
	if s.fault == "changed-query" {
		event.AcceptanceMarker++
	}
	if s.fault == "missing-query" {
		return connect.NewResponse(&api.QueryEventsResponse{}), nil
	}
	return connect.NewResponse(&api.QueryEventsResponse{Events: []*api.Event{event}, HasMore: s.fault == "query-has-more"}), nil
}
func recoveryTestInput(t *testing.T) map[string]any {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "publication.json")
	id := []byte("go-recovery-example-publisher")
	if err = numbered.Initialize(path, id); err != nil {
		t.Fatal(err)
	}
	return map[string]any{"publish": publishInput{ClientIDHex: hex.EncodeToString(id), JournalPath: path, Topic: "test-topic", Scope: "test-scope", Priority: "immediate", LogicalKeyHex: "6b6579", PayloadHex: "7061796c6f6164"}, "subscription_operation_key_hex": "746573742d737562736372696265"}
}

func runRecoveryTestCommand(ctx context.Context, client api.AsterApplicationServiceClient, command string, input any) (map[string]json.RawMessage, []byte, error) {
	encoded, _ := json.Marshal(input)
	var out bytes.Buffer
	err := runCommand(ctx, client, command, "test-token", bytes.NewReader(encoded), &out)
	var receipt map[string]json.RawMessage
	if err == nil {
		err = json.Unmarshal(out.Bytes(), &receipt)
	}
	return receipt, out.Bytes(), err
}
func expectedForPeer(s *recoveryPeer) expectedEventInput {
	e := s.event
	return expectedEventInput{IDHex: hex.EncodeToString(e.Id), PublisherHex: hex.EncodeToString(e.Publisher), PublisherCounter: e.PublisherCounter, EventSequence: e.EventSequence, Topic: e.Topic, Scope: e.Scope, Priority: "immediate", LogicalKeyHex: hex.EncodeToString(e.LogicalKey), PayloadHex: hex.EncodeToString(e.Payload), Tombstone: false, AcceptanceMarker: e.AcceptanceMarker}
}
func TestRecoveryExample(t *testing.T) {
	peer := new(recoveryPeer)
	_, handler := api.NewAsterApplicationServiceHandler(peer)
	server := httptest.NewServer(handler)
	defer server.Close()
	client := api.NewAsterApplicationServiceClient(server.Client(), server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first, _, err := runRecoveryTestCommand(ctx, client, "recovery-begin", recoveryTestInput(t))
	if err != nil {
		t.Fatalf("begin failed: %v", err)
	}
	if peer.publishes != 2 || peer.subscriptions != 1 || peer.attempt != 1 || peer.acknowledged {
		t.Fatal("begin did not retry and leave exact first delivery unacknowledged")
	}
	resume := map[string]any{"subscription_id_hex": first["subscription_id_hex"], "expected": expectedForPeer(peer)}
	second, _, err := runRecoveryTestCommand(ctx, client, "recovery-resume", resume)
	if err != nil {
		t.Fatalf("resume failed: %v", err)
	}
	if peer.subscriptions != 1 || peer.publishes != 2 || peer.attempt != 2 || !peer.acknowledged || peer.quietPolls < 2 || peer.queries != 2 {
		t.Fatalf("incorrect recovery phases: %+v", peer)
	}
	if string(second["attempt"]) != "2" || string(second["exact_match"]) != "true" {
		t.Fatal("missing exact attempt-two evidence")
	}
}

func TestRecoveryExampleFailsClosed(t *testing.T) {
	for _, fault := range []string{"retry-receipt", "retry-inserted", "retry-priority", "wrong-payload", "stale-attempt", "missing-subscription", "transport", "has-more", "late-delivery", "old-ack", "changed-query", "missing-query", "query-has-more"} {
		t.Run(fault, func(t *testing.T) {
			peer := new(recoveryPeer)
			_, handler := api.NewAsterApplicationServiceHandler(peer)
			server := httptest.NewServer(handler)
			defer server.Close()
			client := api.NewAsterApplicationServiceClient(server.Client(), server.URL)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			beginFault := fault == "retry-receipt" || fault == "retry-inserted" || fault == "retry-priority"
			if beginFault {
				peer.fault = fault
			}
			first, output, err := runRecoveryTestCommand(ctx, client, "recovery-begin", recoveryTestInput(t))
			if beginFault {
				if err == nil || len(output) != 0 || peer.acknowledged {
					t.Fatal("invalid retry accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			peer.fault = fault
			_, output, err = runRecoveryTestCommand(ctx, client, "recovery-resume", map[string]any{"subscription_id_hex": first["subscription_id_hex"], "expected": expectedForPeer(peer)})
			if err == nil || len(output) != 0 {
				t.Fatalf("fault emitted success: %s", output)
			}
			if (fault == "wrong-payload" || fault == "stale-attempt") && peer.acknowledged {
				t.Fatal("acknowledged invalid delivery")
			}
		})
	}
}

func TestRecoveryExampleChecksEveryEventField(t *testing.T) {
	mutations := map[string]func(*expectedEventInput){
		"id":                func(e *expectedEventInput) { e.IDHex = hex.EncodeToString(bytes.Repeat([]byte{9}, 32)) },
		"publisher":         func(e *expectedEventInput) { e.PublisherHex = hex.EncodeToString(bytes.Repeat([]byte{9}, 32)) },
		"publisher-counter": func(e *expectedEventInput) { e.PublisherCounter++ },
		"event-sequence":    func(e *expectedEventInput) { e.EventSequence++ },
		"topic":             func(e *expectedEventInput) { e.Topic += "-wrong" },
		"scope":             func(e *expectedEventInput) { e.Scope += "-wrong" },
		"priority":          func(e *expectedEventInput) { e.Priority = "flash" },
		"logical-key":       func(e *expectedEventInput) { e.LogicalKeyHex = "01" },
		"payload":           func(e *expectedEventInput) { e.PayloadHex = "01" },
		"tombstone":         func(e *expectedEventInput) { e.Tombstone = true },
		"acceptance-marker": func(e *expectedEventInput) { e.AcceptanceMarker++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			client, input := timingRecovery(t, 0)
			expected := input["expected"].(expectedEventInput)
			mutate(&expected)
			input["expected"] = expected
			_, output, err := runRecoveryTestCommand(context.Background(), client, "recovery-resume", input)
			if err == nil || len(output) != 0 || client.peer.acknowledged {
				t.Fatal("inexact Event acknowledged")
			}
		})
	}
}
