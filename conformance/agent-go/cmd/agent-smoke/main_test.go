package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
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
			Rows: 0, Bytes: 0, RowHardLimit: 1_000_000, ByteHardLimit: 201_326_592,
			ProfileBoundary: 1_024, ProfileRemaining: 1_024,
			OrdinaryRemaining: 990_000, EmergencyRemaining: 10_000,
			WarningState: applicationv1alpha1.OperationCapacityWarning_OPERATION_CAPACITY_WARNING_OK,
			Audit:        &applicationv1alpha1.OperationLedgerAuditStatus{State: applicationv1alpha1.OperationLedgerAudit_OPERATION_LEDGER_AUDIT_PENDING},
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
	if receipt["operation_ordinary_remaining"] != uint64(990_000) || receipt["operation_audit_state"] != "pending" {
		t.Fatalf("ledger health missing from receipt: %#v", receipt)
	}

	for name, mutate := range map[string]func(*applicationv1alpha1.GetStatusResponse){
		"missing-store": func(status *applicationv1alpha1.GetStatusResponse) { status.StoreCapacity = nil },
		"wrong-operation-boundary": func(status *applicationv1alpha1.GetStatusResponse) {
			status.PublishOperationCapacity.ProfileBoundary = 2_048
		},
		"wrong-delivery-hard-limit": func(status *applicationv1alpha1.GetStatusResponse) {
			status.DeliveryCapacity.HardLimit = 1
		},
		"missing-audit":      func(status *applicationv1alpha1.GetStatusResponse) { status.PublishOperationCapacity.Audit = nil },
		"wrong-active-count": func(status *applicationv1alpha1.GetStatusResponse) { status.PublishOperationCapacity.ActiveRows = 1 },
		"wrong-headroom": func(status *applicationv1alpha1.GetStatusResponse) {
			status.PublishOperationCapacity.OrdinaryRemaining++
		},
		"wrong-warning": func(status *applicationv1alpha1.GetStatusResponse) {
			status.PublishOperationCapacity.WarningState = applicationv1alpha1.OperationCapacityWarning_OPERATION_CAPACITY_WARNING_CRITICAL
		},
		"unknown-audit": func(status *applicationv1alpha1.GetStatusResponse) { status.PublishOperationCapacity.Audit.State = 99 },
		"negative-rate": func(status *applicationv1alpha1.GetStatusResponse) {
			status.PublishOperationCapacity.RollingAcceptRate = -1
		},
		"estimate-without-rate": func(status *applicationv1alpha1.GetStatusResponse) {
			status.PublishOperationCapacity.EstimatedSecondsToExhaustion = 1
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
	for _, state := range []applicationv1alpha1.OperationLedgerAudit{
		applicationv1alpha1.OperationLedgerAudit_OPERATION_LEDGER_AUDIT_RUNNING,
		applicationv1alpha1.OperationLedgerAudit_OPERATION_LEDGER_AUDIT_COMPLETE,
		applicationv1alpha1.OperationLedgerAudit_OPERATION_LEDGER_AUDIT_FAILED,
	} {
		changed := proto.Clone(valid).(*applicationv1alpha1.GetStatusResponse)
		operations := changed.PublishOperationCapacity
		operations.Rows, operations.ActiveRows, operations.RetiredRows, operations.ReverseRows = 1_024, 24, 1_000, 24
		operations.Bytes, operations.OrdinaryRemaining = 70_888, 988_976
		operations.ProfileRemaining, operations.ProfileWarning, operations.ProfileExhausted = 0, true, true
		operations.RollingAcceptRate, operations.EstimatedSecondsToExhaustion = 2, 494_488
		operations.Audit = &applicationv1alpha1.OperationLedgerAuditStatus{State: state, Scanned: 1_048, Total: 1_048}
		receipt, err := statusEvidence(changed)
		if err != nil {
			t.Fatalf("mixed ledger/audit state %v rejected: %v", state, err)
		}
		if receipt["operation_active_rows"] != uint64(24) || receipt["operation_retired_rows"] != uint64(1_000) || receipt["operation_rolling_accept_rate"] != float64(2) || receipt["operation_estimated_seconds_to_exhaustion"] != uint64(494_488) {
			t.Fatalf("ledger observation lost: %#v", receipt)
		}
	}
}

func TestOperationHealthRequiresCoherentRateEstimate(t *testing.T) {
	for _, test := range []struct {
		name     string
		rows     uint64
		rate     float64
		estimate uint64
		valid    bool
	}{
		{"exact", 1_024, 2, 494_488, true},
		{"positive-rate-zero", 1_024, 2, 0, false},
		{"positive-rate-one", 1_024, 2, 1, false},
		{"positive-rate-max", 1_024, 2, math.MaxUint64, false},
		{"one-second-low", 1_024, 2, 494_487, false},
		{"one-second-high", 1_024, 2, 494_489, false},
		{"fraction-round-up", 1_024, 3, 329_659, true},
		{"subsecond", 1_024, 1_977_952, 1, true},
		{"subsecond-zero", 1_024, 1_977_952, 0, false},
		{"quotient-overflow", 1_024, math.SmallestNonzeroFloat64, math.MaxUint64, true},
		{"quotient-overflow-not-saturated", 1_024, math.SmallestNonzeroFloat64, math.MaxUint64 - 1, false},
		{"maximum-rate", 1_024, math.MaxFloat64, 1, true},
		{"zero-rate", 1_024, 0, 0, true},
		{"zero-rate-estimate", 1_024, 0, 1, false},
		{"negative-rate", 1_024, -1, 0, false},
		{"nan-rate", 1_024, math.NaN(), 0, false},
		{"infinite-rate", 1_024, math.Inf(1), 0, false},
		{"negative-infinite-rate", 1_024, math.Inf(-1), 0, false},
		{"non-actor-rate-below-two", 1_024, math.Nextafter(2, 0), 494_489, true},
		// 69/60 is rounded on the wire: direct floating ceil is one too high.
		{"actor-rate-exact-ceiling", 1_092, 69.0 / 60.0, 859_920, true},
		{"actor-rate-float-ceiling-rejected", 1_092, 69.0 / 60.0, 859_921, false},
		{"zero-headroom", 990_000, 2, 0, true},
		{"zero-headroom-estimate", 990_000, 2, 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			operations := &applicationv1alpha1.PublishOperationCapacityStatus{
				Rows: test.rows, ActiveRows: 24, RetiredRows: test.rows - 24, ReverseRows: 24,
				Bytes:             3_888 + (test.rows-24)*67,
				OrdinaryRemaining: 990_000 - test.rows, EmergencyRemaining: 10_000,
				RollingAcceptRate: test.rate, EstimatedSecondsToExhaustion: test.estimate,
				WarningState: applicationv1alpha1.OperationCapacityWarning_OPERATION_CAPACITY_WARNING_OK,
				Audit:        &applicationv1alpha1.OperationLedgerAuditStatus{State: applicationv1alpha1.OperationLedgerAudit_OPERATION_LEDGER_AUDIT_PENDING},
			}
			if test.rows == 990_000 {
				operations.WarningState = applicationv1alpha1.OperationCapacityWarning_OPERATION_CAPACITY_WARNING_EXHAUSTED
			}
			_, _, err := operationHealth(operations)
			if (err == nil) != test.valid {
				t.Fatalf("estimate accepted=%v; want %v", err == nil, test.valid)
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
