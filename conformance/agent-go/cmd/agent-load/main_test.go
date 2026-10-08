package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	api "github.com/defenseunicorns/aster/conformance/agent-go/gen/aster/application/v1alpha1"
	"google.golang.org/protobuf/proto"
)

// Resolve only the fixture root: macOS's default temporary path contains /var,
// a symlink to /private/var. Links introduced by rejection tests stay intact.
func canonicalTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func validArgs() []string {
	return []string{"--url", "http://127.0.0.1:8080", "--token-file", "/private/token", "--count", "5", "--rate", "50", "--payload-bytes", "256", "--topic", "load.events", "--scope", "test/load", "--operation-prefix", "fixture", "--concurrency", "2", "--timeout-seconds", "10", "--output", "/private/result.json", "--source-commit", strings.Repeat("a", 40), "--binary-sha256", strings.Repeat("b", 64), "--config-sha256", strings.Repeat("c", 64), "--sample-every", "0", "--journal-dir", "/private/publications", "--initialize-journals", "true"}
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
		{"--binary-sha256", "oops"}, {"--config-sha256", "oops"}, {"--sample-every", "-1"}, {"--sample-every", "10000001"},
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
	a := publisherID("fixture", 0)
	b := publisherID("fixture", 1)
	if len(a) != 32 || bytes.Equal(a, b) || bytes.Equal(a, publisherID("different", 0)) || !bytes.Equal(a, publisherID("fixture", 0)) {
		t.Fatal("operation derivation is not stable and separated")
	}
	o, _ := parseOptions(validArgs())
	r := publishRequest(o, 7)
	if r.Topic != "load.events" || r.Scope != "test/load" || len(r.Payload) != 256 || r.Priority != api.Priority_PRIORITY_ROUTINE || r.Tombstone || len(r.PredecessorId) != 0 || len(r.LogicalKey) == 0 || r.Session != 0 || r.OperationSequence != 0 || len(r.ClientId) != 0 {
		t.Fatal("request mapping lost journal-owned sequence or workload intent")
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

func success() *connect.Response[api.PublishNumberedEventResponse] {
	return connect.NewResponse(&api.PublishNumberedEventResponse{Result: &api.CommittedPublicationResult{OperationSequence: 1, Receipt: &api.CommittedEventReceipt{EventId: bytes.Repeat([]byte{1}, 32), TransferId: bytes.Repeat([]byte{2}, 32), AcceptanceMarker: 1}, Content: api.CommittedContentStatus_COMMITTED_CONTENT_STATUS_AVAILABLE}, Inserted: true})
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGeneratedClientUsesPublicRequestAndDoesNotLeakTransportError(t *testing.T) {
	o, _ := parseOptions(validArgs())
	o.slots = 1
	client := api.NewAsterApplicationServiceClient(&http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/aster.application.v1alpha1.AsterApplicationService/PublishNumberedEvent" || r.Header.Get("Authorization") != "Bearer SECRET_TOKEN_CANARY" {
			t.Error("public API request mismatch")
		}
		return nil, errors.New("SECRET_TRANSPORT_CANARY")
	})}, o.url)
	receipt := execute(context.Background(), o, realClock{}, func(ctx context.Context, i uint64) result {
		message := publishRequest(o, i)
		message.ClientId = publisherID(o.prefix, 0)
		message.Session = 1
		message.OperationSequence = 1
		req := connect.NewRequest(message)
		req.Header().Set("Authorization", "Bearer SECRET_TOKEN_CANARY")
		response, err := client.PublishNumberedEvent(ctx, req)
		return classify(response, err)
	})
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
	if !bytes.Equal(a, b) || r.Schema != "aster-agent-load/v2" || r.Claim != "public-connect-workload-observation" || r.Qualification || r.Counts.Scheduled != 1 || r.Counts.Inserted != 1 {
		t.Fatal("receipt contract")
	}
	for _, secret := range []string{"SECRET", hex.EncodeToString(publisherID(o.prefix, 0)), o.url, o.tokenFile, o.output} {
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
	root := canonicalTempDir(t)
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
	root := canonicalTempDir(t)
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

func TestDurationLateWakeDoesNotDispatchAfterDeclaredEnd(t *testing.T) {
	o, _ := parseOptions(validArgs())
	o.duration = 6 * time.Second
	o.interval = 5 * time.Second
	o.slots = 2
	c := &manualClock{now: time.Unix(0, 0), waiting: make(chan *manualTimer, 10)}
	started := make(chan uint64, 2)
	release := make(chan struct{})
	done := make(chan receipt, 1)
	go func() {
		done <- execute(context.Background(), o, c, func(_ context.Context, i uint64) result {
			started <- i
			if i == 0 {
				<-release
			}
			return result{kind: "accepted", inserted: true}
		})
	}()
	<-started
	tick := <-c.waiting
	c.advance(tick, 8*time.Second)
	close(release)
	r := <-done
	if r.Counts.Attempted != 1 || r.Counts.Completed != 1 || r.Counts.Scheduled != 2 || r.Counts.Skipped != 1 || r.Counts.Unscheduled != 0 || r.StopReason != "duration_elapsed" {
		t.Fatalf("late dispatch or incoherent deadline receipt: %+v", r.Counts)
	}
}

// Hold a worker at its pre-dispatch clock read. Once the scheduler has admitted
// its final slot it drains without reading the clock, so the gate is unambiguous.
type dispatchGateClock struct {
	*manualClock
	gateMu           sync.Mutex
	armed            bool
	skip             int
	entered, release chan struct{}
}

func (c *dispatchGateClock) Now() time.Time {
	c.gateMu.Lock()
	block := false
	if c.armed {
		if c.skip > 0 {
			c.skip--
		} else {
			c.armed = false
			block = true
		}
	}
	c.gateMu.Unlock()
	if block {
		close(c.entered)
		<-c.release
	}
	return c.manualClock.Now()
}

func TestTerminalCauseSurvivesAdmittedWorkerWakingAfterDuration(t *testing.T) {
	o, _ := parseOptions(validArgs())
	o.duration = 6 * time.Second
	o.interval = 2 * time.Second
	o.slots = 3
	o.concurrency = 3
	c := &dispatchGateClock{manualClock: &manualClock{now: time.Unix(0, 0), waiting: make(chan *manualTimer, 10)}, entered: make(chan struct{}), release: make(chan struct{})}
	started := make(chan uint64, 3)
	terminal := make(chan struct{})
	cancelled := make(chan struct{})
	done := make(chan receipt, 1)
	go func() {
		done <- execute(context.Background(), o, c, func(ctx context.Context, i uint64) result {
			started <- i
			if i == 0 {
				<-terminal
				return result{kind: "rejected", reason: "state_unavailable", terminal: true, measured: true}
			}
			if i == 1 {
				<-ctx.Done()
				close(cancelled)
				return result{kind: "transport", measured: true}
			}
			return result{kind: "accepted", inserted: true, measured: true}
		})
	}()
	if <-started != 0 {
		t.Fatal("first slot")
	}
	c.advance(<-c.waiting, 2*time.Second)
	if <-started != 1 {
		t.Fatal("second slot")
	}
	tick := <-c.waiting
	c.gateMu.Lock()
	c.armed = true
	c.skip = 1
	c.gateMu.Unlock()
	c.advance(tick, 2*time.Second)
	<-c.entered
	close(terminal)
	// Worker 1 cannot observe this cancellation until execute has accounted
	// worker 0's terminal result and cancelled the shared execution context.
	<-cancelled
	c.manualClock.mu.Lock()
	c.manualClock.now = c.manualClock.now.Add(4 * time.Second)
	c.manualClock.mu.Unlock()
	close(c.release)
	r := <-done
	if r.StopReason != "state_unavailable" || r.Counts.Terminal != 1 || r.Counts.Rejected != 1 || r.Counts.Transport != 1 || r.Counts.Attempted != 2 || r.Counts.Completed != 2 || r.Counts.Skipped != 1 || r.Counts.Scheduled != 3 || r.Counts.Unscheduled != 0 {
		t.Fatalf("late worker replaced first terminal cause or accounting: reason=%s counts=%+v", r.StopReason, r.Counts)
	}
	select {
	case <-started:
		t.Fatal("late worker dispatched a request")
	default:
	}
	if r.Counts.Scheduled+r.Counts.Unscheduled != 3 || r.Counts.Skipped+r.Counts.Attempted != r.Counts.Scheduled {
		t.Fatal("schedule equation failed")
	}
}

func TestLateNotDispatchedResultPreservesTerminalUnscheduledSlots(t *testing.T) {
	o, _ := parseOptions(validArgs())
	o.slots = 5
	c := &manualClock{now: time.Unix(0, 0), waiting: make(chan *manualTimer, 10)}
	started := make(chan uint64, 2)
	terminal := make(chan struct{})
	done := make(chan receipt, 1)
	go func() {
		done <- execute(context.Background(), o, c, func(ctx context.Context, i uint64) result {
			started <- i
			if i == 0 {
				<-terminal
				return result{kind: "rejected", reason: "state_unavailable", terminal: true, measured: true}
			}
			<-ctx.Done()
			return result{kind: "not_dispatched", reason: "duration_elapsed", measured: true}
		})
	}()
	<-started
	c.advance(<-c.waiting, o.interval)
	<-started
	close(terminal)
	r := <-done
	if r.StopReason != "state_unavailable" || r.Counts.Terminal != 1 || r.Counts.Scheduled != 2 || r.Counts.Unscheduled != 3 || r.Counts.Skipped != 1 || r.Counts.Attempted != 1 || r.Counts.Completed != 1 {
		t.Fatalf("drained non-dispatch changed terminal schedule: reason=%s counts=%+v", r.StopReason, r.Counts)
	}
	if r.Counts.Scheduled+r.Counts.Unscheduled != 5 || r.Counts.Skipped+r.Counts.Attempted != r.Counts.Scheduled {
		t.Fatal("schedule equation failed")
	}
}

func TestOutputRejectsUnsafeAncestorAndSubstitutedStaging(t *testing.T) {
	root := canonicalTempDir(t)
	_ = os.Chmod(root, 0777)
	child := filepath.Join(root, "private")
	_ = os.Mkdir(child, 0700)
	if out, err := prepareOutput(filepath.Join(child, "receipt.json")); err == nil {
		out.abort()
		t.Fatal("writable ancestor accepted")
	}
	_ = os.Chmod(root, 0700)
	out, err := prepareOutput(filepath.Join(child, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.abort()
	_ = os.Rename(out.file.Name(), out.file.Name()+".original")
	_ = os.Symlink("target", out.file.Name())
	if err := out.finish([]byte("{}")); err == nil {
		t.Fatal("substituted staging symlink published")
	}
	if _, err := os.Lstat(out.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid output visible")
	}
}

func TestOutputRejectsDirectorySwap(t *testing.T) {
	root := canonicalTempDir(t)
	_ = os.Chmod(root, 0700)
	child := filepath.Join(root, "private")
	_ = os.Mkdir(child, 0700)
	out, err := prepareOutput(filepath.Join(child, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.abort()
	_ = os.Rename(child, child+"-old")
	_ = os.Mkdir(child, 0700)
	_ = os.WriteFile(out.file.Name(), []byte("substitution"), 0600)
	if err := out.finish([]byte("{}")); err == nil {
		t.Fatal("swapped directory published substituted receipt")
	}
}

func TestNewLoadOperationsUseDistinctEventIntent(t *testing.T) {
	o, _ := parseOptions(validArgs())
	if bytes.Equal(publishRequest(o, 0).LogicalKey, publishRequest(o, 1).LogicalKey) {
		t.Fatal("unique load operations share identical Event intent")
	}
}

func TestUniqueEventFeasibilityStopsBeforeTraffic(t *testing.T) {
	o, _ := parseOptions(validArgs())
	o.slots = 1_000_000
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := execute(ctx, o, realClock{}, func(context.Context, uint64) result { cancel(); return result{kind: "accepted", inserted: true} })
	if r.Counts.Attempted != 0 || r.Counts.Unscheduled != 1_000_000 || r.StopReason != "custody_ceiling" {
		t.Fatal("impossible unique-Event workload was dispatched")
	}
}

func TestCancellationAndExpiredAttemptDrainCoherently(t *testing.T) {
	o, _ := parseOptions(validArgs())
	o.slots = 1
	for _, cancelled := range []bool{false, true} {
		o.timeout = time.Second
		ctx, cancel := context.WithCancel(context.Background())
		started := make(chan struct{})
		done := make(chan receipt, 1)
		if !cancelled {
			o.timeout = -time.Nanosecond
		}
		go func() {
			done <- execute(ctx, o, realClock{}, func(ctx context.Context, _ uint64) result {
				close(started)
				<-ctx.Done()
				return classify(nil, ctx.Err())
			})
		}()
		<-started
		if cancelled {
			cancel()
		}
		r := <-done
		cancel()
		if r.Counts.Attempted != 1 || r.Counts.Completed != 1 || r.Counts.Transport != 1 {
			t.Fatal("cancelled/deadline request was not drained")
		}
	}
}

func TestTerminalCompletionCancelsInFlightProbeWorker(t *testing.T) {
	o, _ := parseOptions(validArgs())
	o.slots = 3
	c := &manualClock{now: time.Unix(0, 0), waiting: make(chan *manualTimer, 10)}
	started := make(chan uint64, 2)
	release := make(chan struct{})
	cancelled := make(chan bool, 1)
	done := make(chan receipt, 1)
	go func() {
		done <- execute(context.Background(), o, c, func(ctx context.Context, i uint64) result {
			started <- i
			if i == 0 {
				<-release
				return result{kind: "rejected", reason: "state_unavailable", terminal: true}
			}
			// This timeout is a deadlock guard, not a workload pacing sleep.
			guard, stop := context.WithTimeout(ctx, time.Second)
			defer stop()
			<-guard.Done()
			cancelled <- ctx.Err() != nil
			return result{kind: "transport"}
		})
	}()
	<-started
	c.advance(<-c.waiting, o.interval)
	<-started
	close(release)
	r := <-done
	if !<-cancelled || r.Counts.Completed != 2 {
		t.Fatal("terminal state did not cancel pending probe dispatch")
	}
}

type probeServer struct {
	api.UnimplementedAsterApplicationServiceHandler
	mu    sync.Mutex
	mode  string
	calls int
	key   []byte
	h2    bool
}

type stubPublicClient struct {
	api.AsterApplicationServiceClient
	publish func(context.Context, *connect.Request[api.PublishNumberedEventRequest]) (*connect.Response[api.PublishNumberedEventResponse], error)
}

func (s stubPublicClient) PublishNumberedEvent(ctx context.Context, r *connect.Request[api.PublishNumberedEventRequest]) (*connect.Response[api.PublishNumberedEventResponse], error) {
	return s.publish(ctx, r)
}

func (s stubPublicClient) BeginEventPublicationSession(_ context.Context, _ *connect.Request[api.BeginEventPublicationSessionRequest]) (*connect.Response[api.BeginEventPublicationSessionResponse], error) {
	return connect.NewResponse(&api.BeginEventPublicationSessionResponse{Session: 1}), nil
}
func (s stubPublicClient) CompleteEventPublicationRecovery(_ context.Context, _ *connect.Request[api.CompleteEventPublicationRecoveryRequest]) (*connect.Response[api.CompleteEventPublicationRecoveryResponse], error) {
	return connect.NewResponse(&api.CompleteEventPublicationRecoveryResponse{}), nil
}
func (s stubPublicClient) AcknowledgeEventPublicationResult(_ context.Context, _ *connect.Request[api.AcknowledgeEventPublicationResultRequest]) (*connect.Response[api.AcknowledgeEventPublicationResultResponse], error) {
	return connect.NewResponse(&api.AcknowledgeEventPublicationResultResponse{}), nil
}
func fixtureOperation(message *api.PublishNumberedEventRequest) []byte {
	return []byte(fmt.Sprintf("%x/%d", message.ClientId, message.OperationSequence))
}

func TestPeriodicProbesRetainBoundedOlderOriginalsAndExplicitDisable(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		o, _ := parseOptions(validArgs())
		o.slots = 20
		if enabled {
			o.sampleEvery = 1
		}
		seen := map[string]*api.PublishNumberedEventResponse{}
		older := false
		current := uint64(0)
		client := stubPublicClient{publish: func(_ context.Context, req *connect.Request[api.PublishNumberedEventRequest]) (*connect.Response[api.PublishNumberedEventResponse], error) {
			key := string(fixtureOperation(req.Msg))
			original, ok := seen[key]
			if !ok {
				r := success()
				r.Msg.Result.Receipt.AcceptanceMarker = current + 1
				r.Msg.Result.OperationSequence = req.Msg.OperationSequence
				seen[key] = r.Msg
				return r, nil
			}
			if current > 10 && bytes.Equal(req.Msg.ClientId, publisherID(o.prefix, 0)) && req.Msg.OperationSequence == 1 {
				older = true
			}
			if req.Msg.Payload[0] != 0x61 {
				e := connect.NewError(connect.CodeFailedPrecondition, errors.New("PRIVATE"))
				d, _ := connect.NewErrorDetail(&api.PublicErrorDetail{Reason: api.PublicErrorReason_PUBLIC_ERROR_REASON_OPERATION_KEY_CONFLICT})
				e.AddDetail(d)
				return nil, e
			}
			r := proto.Clone(original).(*api.PublishNumberedEventResponse)
			r.Inserted = false
			return connect.NewResponse(r), nil
		}}
		o.journalDir = filepath.Join(canonicalTempDir(t), "journals")
		lanes, err := openPublishers(context.Background(), o, client, "token")
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			for _, lane := range lanes {
				lane.journal.Close()
			}
		}()
		work := publicWork(o, realClock{}, client, "token", lanes)
		for current = 0; current < o.slots; current++ {
			v := work(context.Background(), current)
			if v.probeStop != "" || v.probes.Scheduled > 8 || v.probes.Completed != v.probes.Scheduled {
				t.Fatal("unbounded or incomplete periodic probes")
			}
			if !enabled && v.probes.Scheduled != 0 {
				t.Fatal("disabled sampling dispatched probes")
			}
		}
		if older != enabled {
			t.Fatal("older original sampling did not follow configuration")
		}
	}
}

func (s *probeServer) BeginEventPublicationSession(ctx context.Context, req *connect.Request[api.BeginEventPublicationSessionRequest]) (*connect.Response[api.BeginEventPublicationSessionResponse], error) {
	return stubPublicClient{}.BeginEventPublicationSession(ctx, req)
}
func (s *probeServer) CompleteEventPublicationRecovery(ctx context.Context, req *connect.Request[api.CompleteEventPublicationRecoveryRequest]) (*connect.Response[api.CompleteEventPublicationRecoveryResponse], error) {
	return stubPublicClient{}.CompleteEventPublicationRecovery(ctx, req)
}
func (s *probeServer) AcknowledgeEventPublicationResult(ctx context.Context, req *connect.Request[api.AcknowledgeEventPublicationResultRequest]) (*connect.Response[api.AcknowledgeEventPublicationResultResponse], error) {
	return stubPublicClient{}.AcknowledgeEventPublicationResult(ctx, req)
}
func (s *probeServer) PublishNumberedEvent(_ context.Context, req *connect.Request[api.PublishNumberedEventRequest]) (*connect.Response[api.PublishNumberedEventResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if req.Header().Get("Authorization") != "Bearer "+strings.Repeat("t", 32) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("SECRET_TOKEN_ERROR"))
	}
	if s.calls == 1 {
		s.key = append([]byte(nil), fixtureOperation(req.Msg)...)
		return success(), nil
	}
	if !bytes.Equal(fixtureOperation(req.Msg), s.key) {
		return nil, errors.New("wrong probe operation")
	}
	reason := api.PublicErrorReason_PUBLIC_ERROR_REASON_OPERATION_KEY_CONFLICT
	if req.Msg.Payload[0] != 0x61 {
		if s.mode == "changed-accepted" {
			return success(), nil
		}
	} else {
		if s.mode != "terminal" {
			response := success()
			response.Msg.Inserted = false
			if s.mode == "wrong-replay" {
				response.Msg.Result.Receipt.AcceptanceMarker++
			}
			return response, nil
		}
		reason = api.PublicErrorReason_PUBLIC_ERROR_REASON_STATE_UNAVAILABLE
	}
	err := connect.NewError(connect.CodeFailedPrecondition, errors.New("SECRET_PROBE_ERROR"))
	detail, _ := connect.NewErrorDetail(&api.PublicErrorDetail{Reason: reason})
	err.AddDetail(detail)
	return nil, err
}

func TestPublicCommandPeriodicProbesOverRealH2C(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-replay", "changed-accepted", "terminal"} {
		t.Run(mode, func(t *testing.T) {
			backend := &probeServer{mode: mode}
			_, handler := api.NewAsterApplicationServiceHandler(backend)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				backend.mu.Lock()
				backend.h2 = r.ProtoMajor == 2
				backend.mu.Unlock()
				handler.ServeHTTP(w, r)
			}))
			protocols := new(http.Protocols)
			protocols.SetUnencryptedHTTP2(true)
			server.Config.Protocols = protocols
			server.Start()
			defer server.Close()
			root := canonicalTempDir(t)
			_ = os.Chmod(root, 0700)
			token := filepath.Join(root, "token")
			_ = os.WriteFile(token, []byte(strings.Repeat("t", 32)), 0600)
			output := filepath.Join(root, "receipt.json")
			args := validArgs()
			for i := 0; i < len(args); i += 2 {
				switch args[i] {
				case "--url":
					args[i+1] = server.URL
				case "--count":
					args[i+1] = "1"
				case "--concurrency":
					args[i+1] = "1"
				case "--token-file":
					args[i+1] = token
				case "--output":
					args[i+1] = output
				case "--journal-dir":
					args[i+1] = filepath.Join(root, "publications")
				case "--sample-every":
					args[i+1] = "1"
				}
			}

			err := run(args)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("unexpected command disposition for %s: %v", mode, err)
			}
			raw, err := os.ReadFile(output)
			if err != nil {
				t.Fatal("missing probe receipt")
			}
			var r map[string]any
			if json.Unmarshal(raw, &r) != nil {
				t.Fatal("invalid receipt")
			}
			probes, ok := r["probes"].(map[string]any)
			if !ok {
				t.Fatal("probe accounting absent")
			}
			counts := r["counts"].(map[string]any)
			if counts["attempted"] != float64(1) || counts["accepted"] != float64(1) {
				t.Fatal("probes counted as load")
			}
			if mode == "valid" && (probes["exact_matched"] != float64(1) || probes["conflict_matched"] != float64(1) || probes["completed"] != float64(2)) {
				t.Fatal("missing verified public probes")
			}
			if mode != "valid" && probes["terminal_results"] != float64(1) {
				t.Fatal("probe mismatch did not stop workload")
			}
			backend.mu.Lock()
			defer backend.mu.Unlock()
			if !backend.h2 {
				t.Fatal("test did not use production h2c options")
			}
			for _, secret := range []string{strings.Repeat("t", 32), "SECRET", hex.EncodeToString(backend.key)} {
				if secret != "" && bytes.Contains(raw, []byte(secret)) {
					t.Fatal("probe receipt exposed private input")
				}
			}
		})
	}
}
