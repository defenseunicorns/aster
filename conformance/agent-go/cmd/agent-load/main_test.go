package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	api "github.com/defenseunicorns/aster/conformance/agent-go/gen/aster/application/v1alpha1"
)

func validArgs() []string {
	return []string{"--url", "http://127.0.0.1:8080", "--token-file", "/private/token", "--count", "5", "--rate", "50", "--payload-bytes", "256", "--topic", "load.events", "--scope", "test/load", "--operation-prefix", "fixture", "--concurrency", "2", "--timeout-seconds", "10", "--output", "/private/result.json", "--source-commit", strings.Repeat("a", 40), "--binary-sha256", strings.Repeat("b", 64), "--config-sha256", strings.Repeat("c", 64)}
}

func TestOptionsRejectAmbiguousUnboundedAndSecretBearingInputs(t *testing.T) {
	if _, err := parseOptions(validArgs()); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, value string }{
		{"--count", "0"}, {"--count", "10000001"}, {"--count", "18446744073709551616"},
		{"--rate", "0"}, {"--rate", "NaN"}, {"--rate", "Inf"}, {"--rate", "10001"},
		{"--payload-bytes", "0"}, {"--payload-bytes", "65537"}, {"--concurrency", "0"}, {"--concurrency", "65"},
		{"--timeout-seconds", "0"}, {"--timeout-seconds", "31"}, {"--operation-prefix", ""},
		{"--operation-prefix", strings.Repeat("x", 129)}, {"--topic", "bad topic"}, {"--scope", "bad//scope"},
		{"--url", "http://example.com:80"}, {"--url", "http://user:secret@127.0.0.1:8080"},
		{"--url", "http://127.0.0.1:8080/path"}, {"--output", "relative.json"}, {"--source-commit", "oops"},
		{"--binary-sha256", "oops"}, {"--config-sha256", "oops"},
	} {
		t.Run(test.name+test.value, func(t *testing.T) {
			args := validArgs()
			for i := 0; i < len(args); i += 2 {
				if args[i] == test.name {
					args[i+1] = test.value
				}
			}
			if _, err := parseOptions(args); err == nil {
				t.Fatal("invalid options accepted")
			}
		})
	}
	for _, args := range [][]string{nil, append(validArgs(), "--count", "2"), append(validArgs(), "--duration-seconds", "1"), append(validArgs(), "--token", "SECRET"), append(validArgs(), "trailing")} {
		if _, err := parseOptions(args); err == nil {
			t.Fatal("ambiguous arguments accepted")
		}
	}
	args := validArgs()
	args[4] = "--duration-seconds"
	args[5] = "2"
	o, err := parseOptions(args)
	if err != nil || o.slots != 100 {
		t.Fatalf("duration schedule: %#v %v", o, err)
	}
}

func TestOperationDerivationAndRequestMapping(t *testing.T) {
	// Removing index or domain separation would duplicate effects between slots.
	a := operationKey("fixture", 0)
	b := operationKey("fixture", 1)
	if len(a) != 32 || bytes.Equal(a, b) || bytes.Equal(a, operationKey("different", 0)) || !bytes.Equal(a, operationKey("fixture", 0)) {
		t.Fatal("operation derivation is not stable and separated")
	}
	o, _ := parseOptions(validArgs())
	r := publishRequest(o, 7, "SECRET_TOKEN_CANARY")
	if r.Msg.Topic != "load.events" || r.Msg.Scope != "test/load" || len(r.Msg.Payload) != 256 || r.Msg.Priority != api.Priority_PRIORITY_ROUTINE || r.Msg.Tombstone || len(r.Msg.PredecessorId) != 0 || len(r.Msg.LogicalKey) == 0 {
		t.Fatal("request mapping lost workload intent")
	}
	if !bytes.Equal(r.Msg.OperationKey, operationKey("fixture", 7)) || r.Header().Get("Authorization") != "Bearer SECRET_TOKEN_CANARY" {
		t.Fatal("request authentication/key mismatch")
	}
}

func TestNearestRankHistogramIncludesAllResultsAndRoundsUp(t *testing.T) {
	var h histogram
	if h.percentile(50) != 0 {
		t.Fatal("empty percentile")
	}
	for _, v := range []time.Duration{time.Microsecond, 2 * time.Millisecond, 3 * time.Millisecond, 4 * time.Millisecond, 10 * time.Millisecond} {
		h.add(v)
	}
	if h.percentile(50) != 3 || h.percentile(95) != 10 || h.percentile(99) != 10 {
		t.Fatal("wrong nearest ranks")
	}
	h.add(31 * time.Second)
	if h.percentile(100) != 31000 {
		t.Fatal("overflow bucket lost latency")
	}
}

func TestPacerSkipsMissedSlotsWithoutCatchupAndStopsAtCount(t *testing.T) {
	p := pacer{interval: 20 * time.Millisecond, limit: 6}
	first, skipped, ok := p.take(0)
	if !ok || first != 0 || skipped != 0 {
		t.Fatal("initial slot")
	}
	if _, _, ok = p.take(19 * time.Millisecond); ok {
		t.Fatal("early dispatch")
	}
	index, skipped, ok := p.take(85 * time.Millisecond)
	if !ok || index != 4 || skipped != 3 {
		t.Fatalf("catchup accounting: %d %d %v", index, skipped, ok)
	}
	if _, _, ok = p.take(85 * time.Millisecond); ok {
		t.Fatal("catchup burst")
	}
	index, skipped, ok = p.take(3 * time.Second)
	if ok || skipped != 1 || index != 0 || p.scheduled != 6 {
		t.Fatal("late end must skip expired schedule")
	}
}

func TestResultClassificationStopsOnTerminalAndKeepsUnknownOutcomes(t *testing.T) {
	for _, test := range []struct {
		reason   api.PublicErrorReason
		retry    bool
		terminal bool
	}{
		{api.PublicErrorReason_PUBLIC_ERROR_REASON_OPERATION_CAPACITY_EXHAUSTED, false, true},
		{api.PublicErrorReason_PUBLIC_ERROR_REASON_STATE_UNAVAILABLE, true, true},
		{api.PublicErrorReason_PUBLIC_ERROR_REASON_DRAINING, true, true},
		{api.PublicErrorReason_PUBLIC_ERROR_REASON_RESOURCE_EXHAUSTION, true, false},
	} {
		e := connect.NewError(connect.CodeResourceExhausted, errors.New("SECRET_ERROR"))
		d, _ := connect.NewErrorDetail(&api.PublicErrorDetail{Reason: test.reason, Retryable: test.retry})
		e.AddDetail(d)
		r := classify(nil, e)
		if r.kind != "rejected" || r.terminal != test.terminal {
			t.Fatalf("wrong classification for %v", test.reason)
		}
	}
	if r := classify(nil, errors.New("SECRET_TRANSPORT")); r.kind != "transport" || r.terminal {
		t.Fatal("transport outcome")
	}
	if r := classify(nil, nil); r.kind != "protocol" || !r.terminal {
		t.Fatal("malformed response accepted")
	}
	if r := classify(success(), nil); r.kind != "accepted" || r.terminal {
		t.Fatal("success rejected")
	}
}

func success() *connect.Response[api.PublishEventResponse] {
	return connect.NewResponse(&api.PublishEventResponse{Id: bytes.Repeat([]byte{1}, 32), Publisher: bytes.Repeat([]byte{2}, 32), PublisherCounter: 1, EventSequence: 1, AcceptanceMarker: 1, Priority: api.Priority_PRIORITY_ROUTINE, Inserted: true})
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGeneratedClientUsesPublicRequestAndDoesNotLeakTransportError(t *testing.T) {
	o, _ := parseOptions(validArgs())
	o.slots = 1
	client := api.NewAsterApplicationServiceClient(&http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/aster.application.v1alpha1.AsterApplicationService/PublishEvent" || r.Header.Get("Authorization") != "Bearer SECRET_TOKEN_CANARY" {
			t.Error("public API request mismatch")
		}
		return nil, errors.New("SECRET_TRANSPORT_CANARY")
	})}, o.url)
	receipt := execute(context.Background(), o, realClock{}, func(ctx context.Context, i uint64) result { return call(ctx, client, o, i, "SECRET_TOKEN_CANARY") })
	if receipt.Counts.Transport != 1 || receipt.Counts.Completed != 1 {
		t.Fatal("transport call not accounted")
	}
	raw, _ := json.Marshal(receipt)
	if bytes.Contains(raw, []byte("SECRET")) {
		t.Fatal("transport secret exposed")
	}
}

type manualTimer struct{ ch chan time.Time }

func (t *manualTimer) C() <-chan time.Time { return t.ch }
func (t *manualTimer) Stop()               {}

type manualClock struct {
	mu      sync.Mutex
	now     time.Time
	waiting chan *manualTimer
}

func (c *manualClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *manualClock) NewTimer(_ time.Duration) timer {
	t := &manualTimer{make(chan time.Time, 1)}
	c.waiting <- t
	return t
}
func (c *manualClock) advance(t *manualTimer, d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	c.mu.Unlock()
	t.ch <- now
}

func TestExecutionBoundsConcurrencyAndDrainsAfterTerminal(t *testing.T) {
	o, _ := parseOptions(validArgs())
	o.slots = 100
	c := &manualClock{now: time.Unix(0, 0), waiting: make(chan *manualTimer, 10)}
	started := make(chan uint64, 10)
	release := make(chan result, 10)
	done := make(chan receipt, 1)
	go func() {
		done <- execute(context.Background(), o, c, func(_ context.Context, i uint64) result { started <- i; return <-release })
	}()
	<-started
	t0 := <-c.waiting
	c.advance(t0, 20*time.Millisecond)
	<-started
	t1 := <-c.waiting
	c.advance(t1, 20*time.Millisecond)
	t2 := <-c.waiting
	select {
	case <-started:
		t.Fatal("concurrency exceeded")
	default:
	}
	release <- result{kind: "rejected", reason: "operation_capacity_exhausted", terminal: true}
	// The scheduler must process terminal completion even while pacing waits.
	release <- result{kind: "accepted", inserted: true}
	r := <-done
	_ = t2
	if r.Counts.Attempted != 2 || r.Counts.Completed != 2 || r.Counts.Accepted != 1 || r.Counts.Rejected != 1 || r.Counts.Terminal != 1 || r.Counts.Skipped != 1 || r.Counts.Scheduled != 3 || r.Counts.Unscheduled != 97 || r.PeakInflight != 2 || r.StopReason != "operation_capacity_exhausted" {
		t.Fatalf("incoherent terminal drain: %#v", r)
	}
}

func TestReceiptStableVersionedAndContainsOnlySanitizedConfiguration(t *testing.T) {
	o, _ := parseOptions(validArgs())
	o.prefix = "SECRET_PREFIX_CANARY"
	o.topic = "SECRET_TOPIC_CANARY"
	o.scope = "SECRET_SCOPE_CANARY"
	o.slots = 1
	r := execute(context.Background(), o, realClock{}, func(context.Context, uint64) result { return result{kind: "accepted", inserted: true} })
	a, _ := json.Marshal(r)
	b, _ := json.Marshal(r)
	if !bytes.Equal(a, b) || r.Schema != "aster-agent-load/v1" || r.Claim != "public-connect-workload-observation" || r.Qualification || r.Counts.Scheduled != 1 || r.Counts.Inserted != 1 {
		t.Fatal("receipt contract")
	}
	for _, secret := range []string{"SECRET", hex.EncodeToString(operationKey(o.prefix, 0)), o.url, o.tokenFile, o.output} {
		if bytes.Contains(a, []byte(secret)) {
			t.Fatal("receipt contains private input")
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(a, &decoded); err != nil || len(decoded) == 0 {
		t.Fatal("invalid receipt JSON")
	}
}

func TestTokenRejectsSymlinkFIFOAndWorldReadable(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "token")
	token := strings.Repeat("a", 32)
	if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readToken(path); err != nil || got != token {
		t.Fatal("valid token rejected")
	}
	link := filepath.Join(root, "link")
	_ = os.Symlink(path, link)
	if _, err := readToken(link); err == nil {
		t.Fatal("symlink accepted")
	}
	fifo := filepath.Join(root, "fifo")
	_ = syscall.Mkfifo(fifo, 0600)
	if _, err := readToken(fifo); err == nil {
		t.Fatal("FIFO accepted")
	}
	_ = os.Chmod(path, 0644)
	if _, err := readToken(path); err == nil {
		t.Fatal("public token accepted")
	}
}

func TestOutputIsPrivateAtomicAndNeverOverwrites(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	path := filepath.Join(root, "receipt.json")
	out, err := prepareOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	defer out.abort()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial receipt visible")
	}
	if err := out.finish([]byte("{\"ok\":true}\n")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("public receipt")
	}
	if _, err := prepareOutput(path); err == nil {
		t.Fatal("overwrite allowed")
	}
	failedPath := filepath.Join(root, "failed.json")
	failed, _ := prepareOutput(failedPath)
	_ = failed.file.Close()
	if err := failed.finish([]byte("partial")); err == nil {
		t.Fatal("write failure ignored")
	}
	failed.abort()
	if _, err := os.Stat(failedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed output published")
	}
	racePath := filepath.Join(root, "race.json")
	raced, _ := prepareOutput(racePath)
	_ = os.WriteFile(racePath, []byte("existing"), 0600)
	if err := raced.finish([]byte("new")); err == nil {
		t.Fatal("concurrent output overwritten")
	}
	raced.abort()
	got, _ := os.ReadFile(racePath)
	if string(got) != "existing" {
		t.Fatal("existing output changed")
	}
	_ = os.Chmod(root, 0755)
	if _, err := prepareOutput(filepath.Join(root, "public.json")); err == nil {
		t.Fatal("unprotected directory accepted")
	}
}
