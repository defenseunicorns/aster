// agent-load produces a bounded workload observation through the generated
// public client. It neither qualifies a rate nor configures Event retention.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"
	api "github.com/defenseunicorns/aster/conformance/agent-go/gen/aster/application/v1alpha1"
	"google.golang.org/protobuf/proto"
)

const maxSlots = 10_000_000
const custodyCeiling = 262_144

type options struct {
	url, tokenFile, topic, scope, prefix, output, commit, binaryHash, configHash string
	slots                                                                        uint64
	sampleEvery                                                                  uint64
	duration, interval, timeout                                                  time.Duration
	rate                                                                         float64
	payload, concurrency                                                         int
}

var label = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func parseOptions(args []string) (options, error) {
	bad := errors.New("invalid arguments")
	if len(args)%2 != 0 {
		return options{}, bad
	}
	values := map[string]string{}
	for i := 0; i < len(args); i += 2 {
		if args[i+1] == "" || values[args[i]] != "" {
			return options{}, bad
		}
		values[args[i]] = args[i+1]
	}
	allowed := map[string]bool{}
	for _, k := range []string{"--url", "--token-file", "--count", "--duration-seconds", "--rate", "--payload-bytes", "--topic", "--scope", "--operation-prefix", "--concurrency", "--timeout-seconds", "--output", "--source-commit", "--binary-sha256", "--config-sha256", "--sample-every"} {
		allowed[k] = true
	}
	for k := range values {
		if !allowed[k] {
			return options{}, bad
		}
	}
	for k := range allowed {
		if k != "--count" && k != "--duration-seconds" && values[k] == "" {
			return options{}, bad
		}
	}
	if (values["--count"] == "") == (values["--duration-seconds"] == "") {
		return options{}, bad
	}
	o := options{url: values["--url"], tokenFile: values["--token-file"], topic: values["--topic"], scope: values["--scope"], prefix: values["--operation-prefix"], output: values["--output"], commit: values["--source-commit"], binaryHash: values["--binary-sha256"], configHash: values["--config-sha256"]}
	u, err := url.Parse(o.url)
	// The agent is process-local. Literal loopback avoids DNS rebinding and
	// accidental bearer disclosure to a remote plaintext endpoint.
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || !net.ParseIP(u.Hostname()).IsLoopback() {
		return options{}, bad
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 {
		return options{}, bad
	}
	if !filepath.IsAbs(o.tokenFile) || !filepath.IsAbs(o.output) || filepath.Clean(o.output) != o.output || o.output == o.tokenFile || len(o.prefix) > 128 || !label.MatchString(o.prefix) || len(o.topic) > 128 || !label.MatchString(o.topic) || len(o.scope) > 256 {
		return options{}, bad
	}
	for _, segment := range strings.Split(o.scope, "/") {
		if !label.MatchString(segment) || segment == "." || segment == ".." {
			return options{}, bad
		}
	}
	for _, v := range []struct {
		s string
		n int
	}{{o.commit, 40}, {o.binaryHash, 64}, {o.configHash, 64}} {
		decoded, e := hex.DecodeString(v.s)
		if e != nil || len(decoded)*2 != v.n || strings.ToLower(v.s) != v.s {
			return options{}, bad
		}
	}
	o.rate, err = strconv.ParseFloat(values["--rate"], 64)
	if err != nil || math.IsNaN(o.rate) || math.IsInf(o.rate, 0) || o.rate < 0.01 || o.rate > 10000 {
		return options{}, bad
	}
	o.interval = time.Duration(math.Ceil(float64(time.Second) / o.rate))
	o.sampleEvery, err = strconv.ParseUint(values["--sample-every"], 10, 64)
	if err != nil || o.sampleEvery > maxSlots {
		return options{}, bad
	}
	number := func(key string, max uint64) (uint64, error) {
		v, e := strconv.ParseUint(values[key], 10, 64)
		if e != nil || v == 0 || v > max {
			return 0, bad
		}
		return v, nil
	}
	payload, e := number("--payload-bytes", 65536)
	if e != nil {
		return options{}, bad
	}
	o.payload = int(payload)
	concurrency, e := number("--concurrency", 64)
	if e != nil {
		return options{}, bad
	}
	o.concurrency = int(concurrency)
	seconds, e := number("--timeout-seconds", 30)
	if e != nil {
		return options{}, bad
	}
	o.timeout = time.Duration(seconds) * time.Second
	if values["--count"] != "" {
		o.slots, err = number("--count", maxSlots)
	} else {
		seconds, err = number("--duration-seconds", 604800)
		o.duration = time.Duration(seconds) * time.Second
		o.slots = uint64((o.duration-1)/o.interval) + 1
	}
	if err != nil || o.slots > maxSlots || o.slots == 0 || o.slots > uint64(math.MaxInt64/int64(o.interval)) {
		return options{}, bad
	}
	return o, nil
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// SHA-256("aster/agent-load/key/v1\0" || u16be(prefix length) || prefix || u64be(index)).
// Only this algorithm label and the prefix digest are retained in receipts.
func operationKey(prefix string, index uint64) []byte {
	h := sha256.New()
	h.Write([]byte("aster/agent-load/key/v1\x00"))
	var b [8]byte
	binary.BigEndian.PutUint16(b[:2], uint16(len(prefix)))
	h.Write(b[:2])
	h.Write([]byte(prefix))
	binary.BigEndian.PutUint64(b[:], index)
	h.Write(b[:])
	return h.Sum(nil)
}

func publishRequest(o options, index uint64, token string) *connect.Request[api.PublishEventRequest] {
	logical := append([]byte("agent-load/v1:"), make([]byte, 8)...)
	binary.BigEndian.PutUint64(logical[len(logical)-8:], index)
	req := connect.NewRequest(&api.PublishEventRequest{OperationKey: operationKey(o.prefix, index), Topic: o.topic, Scope: o.scope, Priority: api.Priority_PRIORITY_ROUTINE, LogicalKey: logical, Payload: bytes.Repeat([]byte{0x61}, o.payload)})
	req.Header().Set("Authorization", "Bearer "+token)
	return req
}

type result struct {
	kind, reason       string
	terminal, inserted bool
	elapsed            time.Duration
	measured           bool
	original           *api.PublishEventResponse
	probes             probeCounts
	probeStop          string
}

func classify(response *connect.Response[api.PublishEventResponse], err error) result {
	if err == nil {
		if response == nil || response.Msg == nil || len(response.Msg.Id) != 32 || len(response.Msg.Publisher) != 32 || response.Msg.PublisherCounter == 0 || response.Msg.EventSequence == 0 || response.Msg.AcceptanceMarker == 0 || response.Msg.Priority != api.Priority_PRIORITY_ROUTINE {
			return result{kind: "protocol", reason: "invalid_response", terminal: true}
		}
		return result{kind: "accepted", inserted: response.Msg.Inserted, original: response.Msg}
	}
	var e *connect.Error
	if errors.As(err, &e) {
		for _, d := range e.Details() {
			value, de := d.Value()
			if de != nil {
				continue
			}
			detail, ok := value.(*api.PublicErrorDetail)
			if !ok {
				continue
			}
			// Never render server-provided strings, unknown enum values or error text.
			names := []string{"unspecified", "malformed_input", "unsupported_value", "operation_key_conflict", "missing_durable_object", "failed_precondition", "deadline", "resource_exhaustion", "draining", "state_unavailable", "authentication_failed", "internal", "operation_capacity_exhausted"}
			n := int(detail.Reason)
			if n < 1 || n >= len(names) {
				return result{kind: "protocol", reason: "invalid_error_detail", terminal: true}
			}
			terminal := !detail.Retryable || n == 8 || n == 9 || n == 10 || n == 11 || n == 12
			return result{kind: "rejected", reason: names[n], terminal: terminal}
		}
		if e.Code() == connect.CodeUnauthenticated || e.Code() == connect.CodePermissionDenied {
			return result{kind: "rejected", reason: "authentication_failed", terminal: true}
		}
	}
	// No confirmed application rejection: a commit may have occurred. Do not
	// retry with a fresh key and never count this as accepted or rejected.
	return result{kind: "transport", reason: "indeterminate_transport"}
}

func call(ctx context.Context, client api.AsterApplicationServiceClient, o options, index uint64, token string) result {
	response, err := client.PublishEvent(ctx, publishRequest(o, index, token))
	return classify(response, err)
}

type probeCounts struct {
	Scheduled  uint64 `json:"scheduled"`
	Skipped    uint64 `json:"skipped"`
	Attempted  uint64 `json:"attempted"`
	Completed  uint64 `json:"completed"`
	Exact      uint64 `json:"exact_matched"`
	Conflict   uint64 `json:"conflict_matched"`
	Transport  uint64 `json:"transport_indeterminate"`
	Unexpected uint64 `json:"unexpected_result"`
	Terminal   uint64 `json:"terminal_results"`
}

func (p *probeCounts) add(v probeCounts) {
	p.Scheduled += v.Scheduled
	p.Skipped += v.Skipped
	p.Attempted += v.Attempted
	p.Completed += v.Completed
	p.Exact += v.Exact
	p.Conflict += v.Conflict
	p.Transport += v.Transport
	p.Unexpected += v.Unexpected
	p.Terminal += v.Terminal
}

// Fixed planned indices retain at most four original public results. Each
// checkpoint visits these in fixed order; no raw operation keys are retained.
func sampleIndices(n uint64) []uint64 {
	if n == 0 {
		return nil
	}
	x := n + 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	x ^= x >> 31
	var indices []uint64
	for _, i := range []uint64{0, n / 2, n - 1, x % n} {
		found := false
		for _, j := range indices {
			found = found || i == j
		}
		if !found {
			indices = append(indices, i)
		}
	}
	return indices
}

// Probes execute sequentially inside the same bounded worker as the triggering
// new publication. They cannot add in-flight workers or a pending work queue.
// The registry contains at most four result objects and each snapshot at most
// eight requests. Checkpoints are triggered by completed planned slot indices,
// not by the number of accepted load publications.
func publicWork(o options, c clock, client api.AsterApplicationServiceClient, token string) func(context.Context, uint64) result {
	start := c.Now()
	indices := sampleIndices(o.slots)
	var mu sync.Mutex
	originals := make(map[uint64]*api.PublishEventResponse)
	return func(ctx context.Context, index uint64) result {
		began := c.Now()
		v := call(ctx, client, o, index, token)
		v.elapsed = c.Now().Sub(began)
		v.measured = true
		if o.sampleEvery == 0 || v.kind != "accepted" || !v.inserted {
			return v
		}
		mu.Lock()
		for _, i := range indices {
			if i == index {
				originals[i] = proto.Clone(v.original).(*api.PublishEventResponse)
			}
		}
		snapshot := make(map[uint64]*api.PublishEventResponse)
		if (index+1)%o.sampleEvery == 0 || index+1 == o.slots {
			for i, original := range originals {
				snapshot[i] = original
			}
		}
		mu.Unlock()
		v.probes.Scheduled = uint64(2 * len(snapshot))
		for _, i := range indices {
			original, ok := snapshot[i]
			if !ok {
				continue
			}
			for _, changed := range []bool{false, true} {
				if ctx.Err() != nil || (o.duration > 0 && c.Now().Sub(start) >= o.duration) {
					v.probes.Skipped = v.probes.Scheduled - v.probes.Attempted
					if ctx.Err() != nil {
						v.probeStop = "probe_deadline_or_cancelled"
					} else {
						v.probeStop = "duration_elapsed"
					}
					return v
				}
				req := publishRequest(o, i, token)
				if changed {
					req.Msg.Payload[0] ^= 1
				}
				v.probes.Attempted++
				response, err := client.PublishEvent(ctx, req)
				observed := classify(response, err)
				v.probes.Completed++
				if changed && observed.kind == "rejected" && observed.reason == "operation_key_conflict" {
					v.probes.Conflict++
					continue
				}
				if !changed && observed.kind == "accepted" {
					expected := proto.Clone(original).(*api.PublishEventResponse)
					expected.Inserted = false
					if proto.Equal(expected, observed.original) {
						v.probes.Exact++
						continue
					}
				}
				if observed.kind == "transport" {
					v.probes.Transport++
				} else {
					v.probes.Unexpected++
				}
				v.probes.Terminal++
				v.probeStop = "probe_mismatch"
				v.probes.Skipped = v.probes.Scheduled - v.probes.Attempted
				return v
			}
		}
		return v
	}
}

// One-millisecond upper-edge histogram, with a final >30,999ms overflow bucket.
// Memory is 248,016 bytes independent of workload size. Nearest-rank quantiles
// select ceil(p*N/100), never interpolate, and include every completed attempt.
type histogram struct {
	buckets [31001]uint64
	total   uint64
}

func (h *histogram) add(d time.Duration) {
	bucket := int64((d + time.Millisecond - 1) / time.Millisecond)
	if bucket < 0 {
		bucket = 0
	}
	if bucket > 31000 {
		bucket = 31000
	}
	h.buckets[bucket]++
	h.total++
}
func (h *histogram) percentile(p uint64) uint64 {
	if h.total == 0 {
		return 0
	}
	rank := (h.total*p + 99) / 100
	var seen uint64
	for i, n := range h.buckets {
		seen += n
		if seen >= rank {
			return uint64(i)
		}
	}
	return 31000
}

// Slots are anchored to a monotonic start. Late slots are skipped, never queued.
type pacer struct {
	interval         time.Duration
	limit, scheduled uint64
}

func (p *pacer) take(elapsed time.Duration) (index, skipped uint64, ok bool) {
	if p.scheduled >= p.limit || elapsed < time.Duration(p.scheduled)*p.interval {
		return 0, 0, false
	}
	due := uint64(elapsed / p.interval)
	if due >= p.limit {
		skipped = p.limit - p.scheduled
		p.scheduled = p.limit
		return 0, skipped, false
	}
	skipped = due - p.scheduled
	p.scheduled = due + 1
	return due, skipped, true
}

type timer interface {
	C() <-chan time.Time
	Stop()
}
type clock interface {
	Now() time.Time
	NewTimer(time.Duration) timer
}
type realClock struct{}

func (realClock) Now() time.Time                 { return time.Now() }
func (realClock) NewTimer(d time.Duration) timer { return realTimer{time.NewTimer(d)} }

type realTimer struct{ t *time.Timer }

func (t realTimer) C() <-chan time.Time { return t.t.C }
func (t realTimer) Stop()               { t.t.Stop() }

type counts struct {
	Scheduled   uint64 `json:"scheduled"`
	Skipped     uint64 `json:"skipped"`
	Unscheduled uint64 `json:"unscheduled"`
	Attempted   uint64 `json:"attempted"`
	Completed   uint64 `json:"completed"`
	Accepted    uint64 `json:"accepted"`
	Inserted    uint64 `json:"inserted"`
	Replayed    uint64 `json:"replayed"`
	Rejected    uint64 `json:"rejected"`
	Transport   uint64 `json:"transport_indeterminate"`
	Protocol    uint64 `json:"protocol_invalid"`
	Terminal    uint64 `json:"terminal_results"`
}
type workloadConfig struct {
	Slots          uint64  `json:"planned_slots"`
	DurationNS     int64   `json:"requested_duration_ns"`
	Rate           float64 `json:"offered_per_second"`
	IntervalNS     int64   `json:"pacing_interval_ns"`
	Payload        int     `json:"payload_bytes"`
	Concurrency    int     `json:"concurrency"`
	TimeoutNS      int64   `json:"attempt_timeout_ns"`
	EndpointHash   string  `json:"endpoint_sha256"`
	TopicHash      string  `json:"topic_sha256"`
	ScopeHash      string  `json:"scope_sha256"`
	PrefixHash     string  `json:"operation_prefix_sha256"`
	KeyAlgorithm   string  `json:"operation_key_algorithm"`
	SampleEvery    uint64  `json:"sample_every_planned_slots_zero_disabled"`
	SampleRule     string  `json:"sample_rule"`
	CustodyCeiling uint64  `json:"unique_event_custody_ceiling"`
}
type receipt struct {
	Schema            string         `json:"schema"`
	Claim             string         `json:"claim"`
	Qualification     bool           `json:"qualification"`
	SourceCommit      string         `json:"source_commit_supplied"`
	BinarySHA256      string         `json:"binary_sha256_supplied"`
	AgentConfigSHA256 string         `json:"agent_config_sha256_supplied"`
	Config            workloadConfig `json:"workload"`
	ConfigSHA256      string         `json:"workload_sha256"`
	Started           string         `json:"started_utc"`
	Ended             string         `json:"ended_utc"`
	DurationNS        int64          `json:"elapsed_ns"`
	StopReason        string         `json:"stop_reason"`
	Counts            counts         `json:"counts"`
	Probes            probeCounts    `json:"probes"`
	PeakInflight      int            `json:"peak_inflight"`
	LatencyRule       string         `json:"latency_rule"`
	P50               uint64         `json:"p50_ms"`
	P95               uint64         `json:"p95_ms"`
	P99               uint64         `json:"p99_ms"`
	LatencyOverflow   uint64         `json:"latency_overflow_bucket_samples"`
}

func execute(ctx context.Context, o options, c clock, publish func(context.Context, uint64) result) receipt {
	ctx, stopWorkers := context.WithCancel(ctx)
	defer stopWorkers()
	start := c.Now()
	r := receipt{Schema: "aster-agent-load/v1", Claim: "public-connect-workload-observation", SourceCommit: o.commit, BinarySHA256: o.binaryHash, AgentConfigSHA256: o.configHash, Started: start.UTC().Format(time.RFC3339Nano), StopReason: "schedule_complete", LatencyRule: "completed new-load attempts only, excludes probes; nearest rank ceil(p*N/100); 1ms upper edges; >30999ms overflow returns 31000 sentinel; zero for no samples"}
	r.Config = workloadConfig{o.slots, int64(o.duration), o.rate, int64(o.interval), o.payload, o.concurrency, int64(o.timeout), digest([]byte(o.url)), digest([]byte(o.topic)), digest([]byte(o.scope)), digest([]byte(o.prefix)), "sha256:aster/agent-load/key/v1:u16be-prefix-length:prefix:u64be-index", o.sampleEvery, "fixed first/middle/last/splitmix64(count); at most 4 original results; exact then changed; zero disables; final slot also samples; worker timeout includes probes", custodyCeiling}
	encoded, _ := json.Marshal(r.Config)
	r.ConfigSHA256 = digest(encoded)
	p := pacer{interval: o.interval, limit: o.slots}
	var h histogram
	completed := make(chan result, o.concurrency)
	inflight := 0
	stopped := false
	if o.slots > custodyCeiling {
		stopped = true
		r.StopReason = "custody_ceiling"
	}
	account := func(v result) {
		inflight--
		if v.kind == "not_dispatched" {
			r.Counts.Attempted--
			r.Counts.Skipped++
			if !stopped {
				stopped = true
				r.StopReason = v.reason
				stopWorkers()
				r.Counts.Skipped += p.limit - p.scheduled
				p.scheduled = p.limit
			}
			return
		}
		r.Counts.Completed++
		r.Probes.add(v.probes)
		h.add(v.elapsed)
		switch v.kind {
		case "accepted":
			r.Counts.Accepted++
			if v.inserted {
				r.Counts.Inserted++
			} else {
				r.Counts.Replayed++
			}
		case "rejected":
			r.Counts.Rejected++
		case "transport":
			r.Counts.Transport++
		default:
			r.Counts.Protocol++
		}
		if v.terminal {
			r.Counts.Terminal++
			if !stopped {
				stopped = true
				r.StopReason = v.reason
				stopWorkers()
			}
		}
		if v.probeStop != "" && !stopped {
			stopped = true
			r.StopReason = v.probeStop
			stopWorkers()
		}
	}
	for {
		// Terminal completions already queued take precedence over another slot.
		for {
			select {
			case v := <-completed:
				account(v)
			default:
				goto drained
			}
		}
	drained:
		if ctx.Err() != nil && !stopped {
			stopped = true
			r.StopReason = "cancelled"
		}
		if stopped || p.scheduled == p.limit {
			if inflight == 0 {
				break
			}
			account(<-completed)
			continue
		}
		elapsed := c.Now().Sub(start)
		if o.duration > 0 && elapsed >= o.duration {
			r.Counts.Skipped += p.limit - p.scheduled
			p.scheduled = p.limit
			stopped = true
			r.StopReason = "duration_elapsed"
			stopWorkers()
			continue
		}
		index, skipped, due := p.take(elapsed)
		r.Counts.Skipped += skipped
		if due {
			if inflight >= o.concurrency {
				r.Counts.Skipped++
			} else {
				inflight++
				r.Counts.Attempted++
				if inflight > r.PeakInflight {
					r.PeakInflight = inflight
				}
				go func(i uint64) {
					if o.duration > 0 && c.Now().Sub(start) >= o.duration {
						completed <- result{kind: "not_dispatched", reason: "duration_elapsed"}
						return
					}
					attemptCtx, cancel := context.WithTimeout(ctx, o.timeout)
					defer cancel()
					began := c.Now()
					v := publish(attemptCtx, i)
					if !v.measured {
						v.elapsed = c.Now().Sub(began)
					}
					completed <- v
				}(index)
			}
			continue
		}
		if p.scheduled == p.limit {
			continue
		}
		wait := c.NewTimer(time.Duration(p.scheduled)*o.interval - elapsed)
		select {
		case v := <-completed:
			account(v)
		case <-ctx.Done():
			stopped = true
			r.StopReason = "cancelled"
		case <-wait.C():
		}
		wait.Stop()
	}
	r.Counts.Scheduled = p.scheduled
	r.Counts.Unscheduled = o.slots - p.scheduled
	end := c.Now()
	r.Ended = end.UTC().Format(time.RFC3339Nano)
	r.DurationNS = int64(end.Sub(start))
	r.P50 = h.percentile(50)
	r.P95 = h.percentile(95)
	r.P99 = h.percentile(99)
	r.LatencyOverflow = h.buckets[31000]
	return r
}

func readToken(path string) (string, error) {
	bad := errors.New("invalid token file")
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", bad
	}
	f := os.NewFile(uintptr(fd), "token")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 257 {
		return "", bad
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return "", bad
	}
	b, err := io.ReadAll(io.LimitReader(f, 258))
	if err != nil || len(b) > 257 {
		return "", bad
	}
	b = bytes.TrimRight(b, "\r\n")
	if len(b) < 32 || len(b) > 256 {
		return "", bad
	}
	for _, v := range b {
		if !((v >= 'a' && v <= 'z') || (v >= 'A' && v <= 'Z') || (v >= '0' && v <= '9') || strings.ContainsRune("-._~", rune(v))) {
			return "", bad
		}
	}
	return string(b), nil
}

type atomicOutput struct {
	file      *os.File
	path      string
	directory os.FileInfo
}

// The pathname algorithm is safe only when no other UID can replace an
// ancestor. The sole writable-root exception is root-owned sticky /tmp.
func trustedAncestors(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() {
			return errors.New("unsafe output ancestor")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
			return errors.New("unsafe output ancestor")
		}
		stickyTmp := current == "/tmp" && stat.Uid == 0 && info.Mode()&os.ModeSticky != 0
		if info.Mode().Perm()&0022 != 0 && !stickyTmp {
			return errors.New("unsafe output ancestor")
		}
		if current == "/" {
			return nil
		}
	}
}

func prepareOutput(path string) (*atomicOutput, error) {
	bad := errors.New("invalid output")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, bad
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return nil, bad
	}
	if trustedAncestors(parent) != nil {
		return nil, bad
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, bad
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, bad
	}
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return nil, bad
	}
	f, err := os.CreateTemp(parent, ".agent-load-*.tmp")
	if err != nil {
		return nil, bad
	}
	return &atomicOutput{file: f, path: path, directory: info}, nil
}
func (o *atomicOutput) validStage() bool {
	parent := filepath.Dir(o.path)
	info, err := os.Lstat(parent)
	if err != nil || !os.SameFile(info, o.directory) || trustedAncestors(parent) != nil {
		return false
	}
	opened, err := o.file.Stat()
	if err != nil {
		return false
	}
	named, err := os.Lstat(o.file.Name())
	if err != nil || !os.SameFile(opened, named) || !named.Mode().IsRegular() || named.Mode().Perm() != 0600 {
		return false
	}
	stat, ok := named.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}
func (o *atomicOutput) abort() {
	if o.validStage() {
		_ = os.Remove(o.file.Name())
	}
	_ = o.file.Close()
}
func (o *atomicOutput) finish(data []byte) error {
	bad := errors.New("output commit failed")
	if !o.validStage() {
		return bad
	}
	if n, err := o.file.Write(data); err != nil || n != len(data) {
		return bad
	}
	if o.file.Sync() != nil {
		return bad
	}
	if !o.validStage() {
		return bad
	}
	// link is atomic and fails if a destination appeared since preflight.
	if os.Link(o.file.Name(), o.path) != nil {
		return bad
	}
	_ = os.Remove(o.file.Name())
	dir, err := os.Open(filepath.Dir(o.path))
	if err != nil {
		return bad
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return bad
	}
	return nil
}

func run(args []string) error {
	o, err := parseOptions(args)
	if err != nil {
		return err
	}
	token, err := readToken(o.tokenFile)
	if err != nil {
		return err
	}
	output, err := prepareOutput(o.output)
	if err != nil {
		return err
	}
	defer output.abort()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{Protocols: protocols, MaxConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := api.NewAsterApplicationServiceClient(&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, o.url, connect.WithGRPC(), connect.WithReadMaxBytes(1<<20))
	r := execute(ctx, o, realClock{}, publicWork(o, realClock{}, client, token))
	encoded, err := json.Marshal(r)
	if err != nil {
		return errors.New("receipt encoding failed")
	}
	if err = output.finish(append(encoded, '\n')); err != nil {
		return err
	}
	if r.StopReason != "schedule_complete" || r.Counts.Rejected+r.Counts.Transport+r.Counts.Protocol+r.Counts.Skipped != 0 {
		return errors.New("workload incomplete")
	}
	return nil
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "{\"status\":\"error\",\"reason\":\"load_failed\"}")
		os.Exit(1)
	}
}
