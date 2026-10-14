package main

import (
	"context"
	"errors"

	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	api "github.com/defenseunicorns/aster/conformance/agent-go/gen/aster/application/v1alpha1"
)

type recoveryTimingClient struct {
	api.AsterApplicationServiceClient
	peer         *recoveryPeer
	delayPoll    int
	starts, ends []time.Time
	cancel       context.CancelFunc
	cancelPhase  string
}

func (c *recoveryTimingClient) PollEvents(ctx context.Context, r *connect.Request[api.PollEventsRequest]) (*connect.Response[api.PollEventsResponse], error) {
	if !c.peer.acknowledged {
		return c.peer.PollEvents(ctx, r)
	}
	c.starts = append(c.starts, time.Now())
	poll := len(c.starts)
	if c.cancelPhase == "waiting" && poll == 1 {
		time.AfterFunc(25*time.Millisecond, c.cancel)
	}
	if c.cancelPhase == "in-flight" && poll == 2 {
		time.AfterFunc(25*time.Millisecond, c.cancel)
	}
	if poll == c.delayPoll || (c.cancelPhase == "in-flight" && poll == 2) {
		select {
		case <-time.After(550 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	response, err := c.peer.PollEvents(ctx, r)
	c.ends = append(c.ends, time.Now())
	return response, err
}
func (c *recoveryTimingClient) AcknowledgeEvent(ctx context.Context, r *connect.Request[api.AcknowledgeEventRequest]) (*connect.Response[api.AcknowledgeEventResponse], error) {
	return c.peer.AcknowledgeEvent(ctx, r)
}
func (c *recoveryTimingClient) QueryEvents(ctx context.Context, r *connect.Request[api.QueryEventsRequest]) (*connect.Response[api.QueryEventsResponse], error) {
	return c.peer.QueryEvents(ctx, r)
}
func timingRecovery(t *testing.T, delay int) (*recoveryTimingClient, map[string]any) {
	t.Helper()
	peer := new(recoveryPeer)
	_, err := peer.PublishNumberedEvent(context.Background(), connect.NewRequest(&api.PublishNumberedEventRequest{ClientId: []byte("go-timing-publisher"), Session: 1, OperationSequence: 1, Topic: "test-topic", Scope: "test-scope", Priority: api.Priority_PRIORITY_IMMEDIATE, LogicalKey: []byte("key"), Payload: []byte("payload")}))
	if err != nil {
		t.Fatal(err)
	}
	peer.attempt = 1
	return &recoveryTimingClient{peer: peer, delayPoll: delay}, map[string]any{"subscription_id_hex": "0303030303030303030303030303030303030303030303030303030303030303", "expected": expectedForPeer(peer)}
}
func TestRecoveryExampleDelayedFirstQuietPoll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, input := timingRecovery(t, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _, err := runRecoveryTestCommand(ctx, client, "recovery-resume", input)
		if err != nil {
			t.Fatal(err)
		}
		if len(client.starts) < 2 || client.starts[len(client.starts)-1].Before(client.ends[0].Add(500*time.Millisecond)) {
			t.Fatalf("slow first response consumed observation window: %d quiet polls", len(client.starts))
		}
	})
}

func TestRecoveryExampleDelayedCrossBoundaryQuietPoll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, input := timingRecovery(t, 2)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _, err := runRecoveryTestCommand(ctx, client, "recovery-resume", input)
		if err != nil {
			t.Fatal(err)
		}
		if len(client.starts) < 3 || client.starts[len(client.starts)-1].Before(client.ends[0].Add(500*time.Millisecond)) {
			t.Fatalf("response crossing boundary replaced fresh final poll: %d quiet polls", len(client.starts))
		}
	})
}

func TestRecoveryExampleCancellationDuringQuietWindow(t *testing.T) {
	for _, phase := range []string{"waiting", "in-flight"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, input := timingRecovery(t, 0)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				client.cancel = cancel
				client.cancelPhase = phase
				_, output, err := runRecoveryTestCommand(ctx, client, "recovery-resume", input)
				if !errors.Is(err, context.Canceled) || len(output) != 0 || client.peer.queries != 0 {
					t.Fatalf("cancellation emitted success or query: err=%v output=%s", err, output)
				}
			})
		})
	}
}
func TestRecoveryExampleQuietDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, input := timingRecovery(t, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
		defer cancel()
		_, output, err := runRecoveryTestCommand(ctx, client, "recovery-resume", input)
		if !errors.Is(err, context.DeadlineExceeded) || len(output) != 0 || client.peer.queries != 0 {
			t.Fatalf("deadline emitted success or query: %v", err)
		}
	})
}
