package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"

	applicationv1alpha1 "github.com/defenseunicorns/aster/conformance/agent-go/gen/aster/application/v1alpha1"
	"google.golang.org/protobuf/proto"
)

type deliveryServer struct {
	applicationv1alpha1.UnimplementedAsterApplicationServiceHandler
	event   *applicationv1alpha1.Event
	attempt uint64
}

func (s deliveryServer) StreamEvents(_ context.Context, _ *connect.Request[applicationv1alpha1.StreamEventsRequest], stream *connect.ServerStream[applicationv1alpha1.StreamEventsResponse]) error {
	return stream.Send(&applicationv1alpha1.StreamEventsResponse{Event: s.event, Attempt: s.attempt})
}

func TestStreamEvidenceRequiresExactEventAndIncreasingAttempt(t *testing.T) {
	// Break caught: counting a nonnil stream response can credit the wrong Event
	// or stale attempt without validating any of the delivered content.
	expected := expectedEventInput{
		IDHex: strings.Repeat("01", 32), PublisherHex: strings.Repeat("02", 32),
		PublisherCounter: 3, EventSequence: 4, Topic: "SECRET_TOPIC_CANARY",
		Scope: "SECRET_SCOPE_CANARY", Priority: "immediate", LogicalKeyHex: "03",
		PayloadHex: "04", AcceptanceMarker: 5,
	}
	event := &applicationv1alpha1.Event{
		Id: bytes.Repeat([]byte{1}, 32), Publisher: bytes.Repeat([]byte{2}, 32),
		PublisherCounter: 3, EventSequence: 4, Topic: expected.Topic, Scope: expected.Scope,
		Priority: applicationv1alpha1.Priority_PRIORITY_IMMEDIATE, LogicalKey: []byte{3},
		Payload: []byte{4}, AcceptanceMarker: 5,
	}
	for _, scenario := range []string{"exact", "wrong-payload", "stale-attempt", "missing-event"} {
		t.Run(scenario, func(t *testing.T) {
			message := proto.Clone(event).(*applicationv1alpha1.Event)
			attempt := uint64(3)
			switch scenario {
			case "wrong-payload":
				message.Payload = []byte{9}
			case "stale-attempt":
				attempt = 2
			case "missing-event":
				message = nil
			}
			_, handler := applicationv1alpha1.NewAsterApplicationServiceHandler(deliveryServer{event: message, attempt: attempt})
			server := httptest.NewServer(handler)
			defer server.Close()
			client := applicationv1alpha1.NewAsterApplicationServiceClient(server.Client(), server.URL)
			input, err := json.Marshal(map[string]any{
				"subscription_id_hex": strings.Repeat("05", 32), "delivery_limit": 1,
				"scan_limit": 8, "poll_backoff_ms": 100, "count": 1,
				"expected": expected, "after_attempt": 2,
			})
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = runCommand(ctx, client, "stream", "test-token", bytes.NewReader(input), &output)
			if scenario != "exact" {
				if err == nil {
					t.Fatal("invalid stream evidence accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("exact stream failed: %v", err)
			}
			if !strings.Contains(output.String(), `"exact_match":true`) || !strings.Contains(output.String(), `"attempt":3`) {
				t.Fatalf("missing stream verification receipt: %s", output.String())
			}
			if strings.Contains(output.String(), "SECRET_") {
				t.Fatal("stream receipt exposed Event content")
			}
		})
	}
}

func writeToken(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("test-token-0123456789abcdefghijkl\n"), mode); err != nil {
		t.Fatal(err)
	}
	// os.WriteFile applies the process umask. Force the requested fixture mode so
	// permission-rejection tests remain meaningful under a restrictive CI umask.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTokenIsReadFromOwnerOnlyFile(t *testing.T) {
	token := writeToken(t, 0o640)
	if err := validateTokenFile(token); err == nil {
		t.Fatal("group-readable token accepted")
	}
}

func TestResultNeverPrintsAuthorization(t *testing.T) {
	got := renderResult(resultFixture(), "Bearer SECRET_TOKEN_CANARY")
	if strings.Contains(got, "SECRET_TOKEN_CANARY") {
		t.Fatal("authorization value exposed")
	}
}

func TestTokenValidationAcceptsOnlyBoundedOwnerOnlyRegularFile(t *testing.T) {
	valid := writeToken(t, 0o600)
	if err := validateTokenFile(valid); err != nil {
		t.Fatalf("owner-only token rejected: %v", err)
	}

	short := filepath.Join(t.TempDir(), "short")
	if err := os.WriteFile(short, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateTokenFile(short); err == nil {
		t.Fatal("short token accepted")
	}

	link := filepath.Join(t.TempDir(), "token-link")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if err := validateTokenFile(link); err == nil {
		t.Fatal("token symlink accepted")
	}
}

func TestFIFOtokenIsRejectedWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token-fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- validateTokenFile(path) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO token accepted")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("FIFO token validation blocked")
	}
}

func TestInputReadHonorsCommandContext(t *testing.T) {
	reader := newBlockingReadCloser()
	defer reader.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := readInput(ctx, reader); err == nil {
		t.Fatal("blocked input outlived command context")
	}
	select {
	case <-reader.exited:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("input reader goroutine survived cancellation")
	}
}

func TestCancelledContextStopsTokenRead(t *testing.T) {
	token := writeToken(t, 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readToken(ctx, token); err == nil {
		t.Fatal("cancelled token read accepted")
	}
}

func TestFixedAndOperationIdentifiersEnforceWireBounds(t *testing.T) {
	if _, err := decodeFixedHex(strings.Repeat("01", 32), 32); err != nil {
		t.Fatalf("exact identifier rejected: %v", err)
	}
	for _, value := range []string{strings.Repeat("01", 31), strings.Repeat("01", 33), "zz"} {
		if _, err := decodeFixedHex(value, 32); err == nil {
			t.Fatalf("invalid fixed identifier accepted: length=%d", len(value))
		}
	}
	for _, value := range []string{"", strings.Repeat("01", 257)} {
		if _, err := decodeOperationKeyHex(value); err == nil {
			t.Fatalf("invalid operation key accepted: length=%d", len(value))
		}
	}
}

func TestMalformedQueryExpectationIsRejectedBeforeEvidence(t *testing.T) {
	input := queryInput{Expected: expectedEventInput{
		IDHex: "01", PublisherHex: strings.Repeat("02", 32), Priority: "immediate",
		LogicalKeyHex: "01", PayloadHex: "02",
	}}
	if _, err := queryRequest(input); err == nil {
		t.Fatal("malformed query expectation accepted")
	}
}

func TestOptionsRequireExplicitBoundedTimeoutAndKnownCommand(t *testing.T) {
	base := []string{"status", "--url", "http://127.0.0.1:1", "--token-file", "/tmp/token", "--timeout-seconds", "30"}
	if _, err := parseOptions(base); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
	for _, mutation := range [][]string{
		base[:5],
		{"status", "--url", "http://127.0.0.1:1", "--token-file", "/tmp/token", "--timeout-seconds", "31"},
		{"delete", "--url", "http://127.0.0.1:1", "--token-file", "/tmp/token", "--timeout-seconds", "30"},
		{"status", "--url", "http://127.0.0.1:1/path", "--token-file", "/tmp/token", "--timeout-seconds", "30"},
	} {
		if _, err := parseOptions(mutation); err == nil {
			t.Fatalf("invalid options accepted: %#v", mutation)
		}
	}
}

func TestInputIsBoundedStrictAndSingular(t *testing.T) {
	for _, input := range []string{
		`{"repeat_until_error":false,"unknown":true}`,
		`{} {}`,
		strings.Repeat(" ", maxInputBytes+1),
	} {
		var value statusInput
		if err := decodeInput(strings.NewReader(input), &value); err == nil {
			t.Fatalf("invalid input accepted: length=%d", len(input))
		}
	}
}

func TestRecoveredEventMatchIsSensitiveToEveryExposedField(t *testing.T) {
	expected := expectedEventInput{
		IDHex: strings.Repeat("01", 32), PublisherHex: strings.Repeat("02", 32),
		PublisherCounter: 3, EventSequence: 4, Topic: "SECRET_TOPIC_CANARY",
		Scope: "SECRET_SCOPE_CANARY", Priority: "immediate",
		LogicalKeyHex: hexOf([]byte("SECRET_LOGICAL_KEY_CANARY")),
		PayloadHex:    hexOf([]byte("SECRET_PAYLOAD_CANARY")),
		Tombstone:     false, AcceptanceMarker: 5,
	}
	event := &applicationv1alpha1.Event{
		Id: bytes.Repeat([]byte{1}, 32), Publisher: bytes.Repeat([]byte{2}, 32),
		PublisherCounter: 3, EventSequence: 4, Topic: expected.Topic, Scope: expected.Scope,
		Priority:   applicationv1alpha1.Priority_PRIORITY_IMMEDIATE,
		LogicalKey: []byte("SECRET_LOGICAL_KEY_CANARY"), Payload: []byte("SECRET_PAYLOAD_CANARY"),
		Tombstone: false, AcceptanceMarker: 5,
	}
	matched, err := eventMatches(event, expected)
	if err != nil || !matched {
		t.Fatalf("exact event rejected: matched=%v err=%v", matched, err)
	}

	mutations := []*applicationv1alpha1.Event{}
	for index := 0; index < 11; index++ {
		changed := proto.Clone(event).(*applicationv1alpha1.Event)
		switch index {
		case 0:
			changed.Id[0] ^= 1
		case 1:
			changed.Publisher[0] ^= 1
		case 2:
			changed.PublisherCounter++
		case 3:
			changed.EventSequence++
		case 4:
			changed.Topic += "x"
		case 5:
			changed.Scope += "x"
		case 6:
			changed.Priority = applicationv1alpha1.Priority_PRIORITY_FLASH
		case 7:
			changed.LogicalKey[0] ^= 1
		case 8:
			changed.Payload[0] ^= 1
		case 9:
			changed.Tombstone = true
		case 10:
			changed.AcceptanceMarker++
		}
		mutations = append(mutations, changed)
	}
	for index, changed := range mutations {
		matched, err := eventMatches(changed, expected)
		if err != nil || matched {
			t.Fatalf("mutation %d was not detected: matched=%v err=%v", index, matched, err)
		}
	}
}

func TestQueryEvidenceContainsNoEventValues(t *testing.T) {
	got := renderResult(result{"status": "ok", "exact_match": true, "count": 1, "has_more": false}, "Bearer SECRET_TOKEN_CANARY")
	for _, secret := range []string{"SECRET_TOKEN_CANARY", "SECRET_TOPIC_CANARY", "SECRET_SCOPE_CANARY", "SECRET_PAYLOAD_CANARY"} {
		if strings.Contains(got, secret) {
			t.Fatalf("query evidence exposed %s", secret)
		}
	}
}

func TestResultEncodingIsBounded(t *testing.T) {
	if _, err := encodeResult(result{"value": strings.Repeat("x", maxOutputBytes)}); err == nil {
		t.Fatal("oversized result accepted")
	}
}

func TestStatusEvidenceRequiresProfileCapacityContract(t *testing.T) {
	valid := &applicationv1alpha1.GetStatusResponse{
		ConfiguredEmissionMode: applicationv1alpha1.EmissionMode_EMISSION_MODE_NORMAL,
		EffectiveEmissionMode:  applicationv1alpha1.EmissionMode_EMISSION_MODE_RECEIVE_ONLY,
		StoreCapacity: &applicationv1alpha1.StoreCapacityStatus{
			Items: 0, ItemLimit: 10_000, PayloadBytes: 0, PayloadByteLimit: 64 * 1024 * 1024,
		},
		PublishOperationCapacity: &applicationv1alpha1.PublishOperationCapacityStatus{
			Rows: 0, Bytes: 0, RowHardLimit: 4_096, ByteHardLimit: 524_288,
			ProfileBoundary: 1_024, ProfileRemaining: 1_024,
		},
		DeliveryCapacity: &applicationv1alpha1.DeliveryCapacityStatus{
			Pending: 0, ProfileBoundary: 256, HardLimit: 262_144,
		},
	}
	receipt, err := statusEvidence(valid)
	if err != nil {
		t.Fatalf("valid profile status rejected: %v", err)
	}
	if receipt["configured_emission_mode"] != "normal" || receipt["effective_emission_mode"] != "receive_only" {
		t.Fatalf("emission modes not retained in receipt: %#v", receipt)
	}

	for name, mutate := range map[string]func(*applicationv1alpha1.GetStatusResponse){
		"missing-store": func(status *applicationv1alpha1.GetStatusResponse) { status.StoreCapacity = nil },
		"wrong-operation-boundary": func(status *applicationv1alpha1.GetStatusResponse) {
			status.PublishOperationCapacity.ProfileBoundary = 2_048
		},
		"wrong-delivery-hard-limit": func(status *applicationv1alpha1.GetStatusResponse) {
			status.DeliveryCapacity.HardLimit = 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.Clone(valid).(*applicationv1alpha1.GetStatusResponse)
			mutate(changed)
			if _, err := statusEvidence(changed); err == nil {
				t.Fatal("invalid profile status accepted")
			}
		})
	}
}

func hexOf(value []byte) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(value)*2)
	for index, item := range value {
		encoded[index*2] = alphabet[item>>4]
		encoded[index*2+1] = alphabet[item&0x0f]
	}
	return string(encoded)
}

type blockingReadCloser struct {
	closed chan struct{}
	exited chan struct{}
	once   sync.Once
}

func newBlockingReadCloser() *blockingReadCloser {
	return &blockingReadCloser{closed: make(chan struct{}), exited: make(chan struct{})}
}

func (reader *blockingReadCloser) Read(_ []byte) (int, error) {
	<-reader.closed
	close(reader.exited)
	return 0, io.ErrClosedPipe
}

func (reader *blockingReadCloser) Close() error {
	reader.once.Do(func() { close(reader.closed) })
	return nil
}
