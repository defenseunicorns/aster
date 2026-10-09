package numbered

import (
	"bytes"
	"connectrpc.com/connect"
	"context"
	"errors"
	api "github.com/defenseunicorns/aster/conformance/agent-go/gen/aster/application/v1alpha1"
	"google.golang.org/protobuf/proto"
	"os"
	"path/filepath"
	"testing"
)

type fakeClient struct {
	Client
	session, allocated, revision uint64
	claimExpected                uint64
	claimNonce                   []byte
	intent                       *api.PublishNumberedEventRequest
	result                       *api.CommittedPublicationResult
	loseClaim, losePublish       bool
	commits, claims, publishes   int
}

func (f *fakeClient) BeginEventPublicationSession(_ context.Context, req *connect.Request[api.BeginEventPublicationSessionRequest]) (*connect.Response[api.BeginEventPublicationSessionResponse], error) {
	if !(f.session > 0 && req.Msg.ExpectedSession == f.claimExpected && bytes.Equal(req.Msg.ClaimNonce, f.claimNonce)) {
		if req.Msg.ExpectedSession != f.session {
			return nil, ErrJournal
		}
		f.claimExpected = f.session
		f.claimNonce = bytes.Clone(req.Msg.ClaimNonce)
		f.session++
		f.claims++
	}
	snapshot := &api.BeginEventPublicationSessionResponse{Session: f.session, AllocatedThrough: f.allocated, SnapshotRevision: f.revision}
	if f.result != nil {
		snapshot.Outstanding = []*api.CommittedPublicationResult{proto.Clone(f.result).(*api.CommittedPublicationResult)}
	}
	if f.loseClaim {
		f.loseClaim = false
		return nil, errors.New("lost claim reply")
	}
	return connect.NewResponse(snapshot), nil
}
func (f *fakeClient) CompleteEventPublicationRecovery(_ context.Context, req *connect.Request[api.CompleteEventPublicationRecoveryRequest]) (*connect.Response[api.CompleteEventPublicationRecoveryResponse], error) {
	if req.Msg.Session != f.session || req.Msg.SnapshotRevision != f.revision {
		return nil, ErrJournal
	}
	return connect.NewResponse(&api.CompleteEventPublicationRecoveryResponse{}), nil
}
func (f *fakeClient) PublishNumberedEvent(_ context.Context, req *connect.Request[api.PublishNumberedEventRequest]) (*connect.Response[api.PublishNumberedEventResponse], error) {
	f.publishes++
	if req.Msg.Session != f.session {
		return nil, ErrJournal
	}
	copy := proto.Clone(req.Msg).(*api.PublishNumberedEventRequest)
	copy.Session = 0
	inserted := false
	if req.Msg.OperationSequence == f.allocated+1 {
		f.allocated++
		f.revision++
		f.commits++
		f.intent = copy
		inserted = true
		f.result = &api.CommittedPublicationResult{OperationSequence: f.allocated, Content: api.CommittedContentStatus_COMMITTED_CONTENT_STATUS_AVAILABLE,
			Receipt: &api.CommittedEventReceipt{TransferId: bytes.Repeat([]byte{1}, 32), EventId: bytes.Repeat([]byte{2}, 32), AcceptanceMarker: f.allocated}}
	} else if f.result == nil || !proto.Equal(copy, f.intent) {
		return nil, ErrJournal
	}
	if f.losePublish {
		f.losePublish = false
		return nil, errors.New("lost committed reply")
	}
	return connect.NewResponse(&api.PublishNumberedEventResponse{Result: proto.Clone(f.result).(*api.CommittedPublicationResult), Inserted: inserted}), nil
}
func (f *fakeClient) AcknowledgeEventPublicationResult(_ context.Context, req *connect.Request[api.AcknowledgeEventPublicationResultRequest]) (*connect.Response[api.AcknowledgeEventPublicationResultResponse], error) {
	if req.Msg.Session != f.session || req.Msg.OperationSequence > f.allocated {
		return nil, ErrJournal
	}
	f.result = nil
	f.revision++
	return connect.NewResponse(&api.AcknowledgeEventPublicationResultResponse{}), nil
}
func testJournal(t *testing.T, client *fakeClient) (*Journal, string, []byte) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "publication.json")
	id := []byte("stable-go-acceptance-client")
	if err := Initialize(path, id); err != nil {
		t.Fatal(err)
	}
	journal, err := Open(path, id, client, "token")
	if err != nil {
		t.Fatal(err)
	}
	return journal, path, id
}
func TestLostClaimAndCommittedReplySurviveProcessReplacement(t *testing.T) {
	ctx := context.Background()
	client := &fakeClient{loseClaim: true, losePublish: true}
	j, path, id := testJournal(t, client)
	if j.Recover(ctx) == nil {
		t.Fatal("lost claim must remain uncertain")
	}
	j.Close()
	j, err := Open(path, id, client, "token")
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if client.claims != 1 {
		t.Fatal("replayed claim must not increment session")
	}
	seq, err := j.Retain(&api.PublishNumberedEventRequest{Topic: "mesh.messages", Scope: "test/go", LogicalKey: []byte("logical"), Payload: []byte("original")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = j.Publish(ctx, seq); err == nil {
		t.Fatal("lost publication reply must remain uncertain")
	}
	if _, err = j.Retain(&api.PublishNumberedEventRequest{Payload: []byte("new")}); err != ErrPending {
		t.Fatal("unresolved intent permitted new work")
	}
	j.Close()
	j, err = Open(path, id, client, "token")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { j.Close() }()
	if err = j.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	response, err := j.Publish(ctx, seq)
	if err != nil {
		t.Fatal(err)
	}
	if response.Inserted || client.commits != 1 || client.publishes != 1 || len(j.Entries()) != 1 || string(j.Entries()[0].Intent.Payload) != "original" {
		t.Fatal("recovery changed original intent or republished")
	}
	if j.Acknowledge(ctx, seq) == nil {
		t.Fatal("acknowledged before durable application")
	}
	if err = j.Apply(seq); err != nil {
		t.Fatal(err)
	}
	// Crash after server ack, before local deletion: a repeated recovery proves
	// retirement only because application progress was already saved.
	request := request(&api.AcknowledgeEventPublicationResultRequest{ClientId: id, Session: j.state.Session, OperationSequence: seq}, "token")
	if _, err = client.AcknowledgeEventPublicationResult(ctx, request); err != nil {
		t.Fatal(err)
	}
	j.Close()
	j, err = Open(path, id, client, "token")
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if len(j.Entries()) != 0 {
		t.Fatal("applied retired result was not reclaimed")
	}
	next, err := j.Retain(&api.PublishNumberedEventRequest{Payload: []byte("next")})
	if err != nil || next != 2 {
		t.Fatal("sequence reused after retirement")
	}
}
func TestJournalRefusesMissingCorruptIdentityAndConcurrentOwner(t *testing.T) {
	client := &fakeClient{}
	j, path, id := testJournal(t, client)
	if _, err := Open(path, id, client, "token"); err == nil {
		t.Fatal("concurrent owner accepted")
	}
	j.Close()
	if j.Recover(context.Background()) == nil {
		t.Fatal("closed owner contacted server")
	}
	if Initialize(path, id) == nil {
		t.Fatal("existing journal overwritten")
	}
	if _, err := Open(path, []byte("other-client"), client, "token"); err == nil {
		t.Fatal("identity changed")
	}
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, id, client, "token"); err == nil {
		t.Fatal("corrupt journal accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, id, client, "token"); err == nil {
		t.Fatal("missing journal recreated")
	}
	if client.claims != 0 {
		t.Fatal("invalid journals contacted server")
	}
}
