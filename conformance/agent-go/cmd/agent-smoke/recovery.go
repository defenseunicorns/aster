package main

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"

	api "github.com/defenseunicorns/aster/conformance/agent-go/gen/aster/application/v1alpha1"
	"google.golang.org/protobuf/proto"
)

const recoveryQuietWindow = 500 * time.Millisecond
const recoveryPollInterval = 50 * time.Millisecond

type recoveryBeginInput struct {
	Publish                     publishInput `json:"publish"`
	SubscriptionOperationKeyHex string       `json:"subscription_operation_key_hex"`
}
type recoveryResumeInput struct {
	SubscriptionIDHex string             `json:"subscription_id_hex"`
	Expected          expectedEventInput `json:"expected"`
}

// recoveryBegin intentionally leaves the validated first delivery unacknowledged.
// The caller must preserve the input and receipt before launching another process.
func recoveryBegin(ctx context.Context, client api.AsterApplicationServiceClient, token string, input io.Reader, output io.Writer) error {
	var value recoveryBeginInput
	if err := decodeInput(input, &value); err != nil {
		return err
	}
	subscriptionKey, err := decodeOperationKeyHex(value.SubscriptionOperationKeyHex)
	if err != nil {
		return err
	}
	journal, err := openPublication(ctx, client, token, value.Publish)
	if err != nil {
		return err
	}
	defer journal.Close()
	sequence, err := retainPublication(journal, value.Publish)
	if err != nil {
		return err
	}
	first, err := journal.Publish(ctx, sequence)
	if err != nil {
		return err
	}
	message, err := journal.Request(sequence)
	if err != nil {
		return err
	}
	second, err := client.PublishNumberedEvent(ctx, request(message, token))
	if err != nil {
		return err
	}
	if first == nil || first.Result == nil || second == nil || second.Msg == nil || !first.Inserted || second.Msg.Inserted || !proto.Equal(first.Result, second.Msg.Result) {
		return errors.New("publication retry changed committed result")
	}
	event, err := publicationEvent(ctx, client, token, message, first.Result)
	if err != nil {
		return err
	}
	expected := expectedEventInput{IDHex: hex.EncodeToString(event.Id), PublisherHex: hex.EncodeToString(event.Publisher), PublisherCounter: event.PublisherCounter, EventSequence: event.EventSequence, Topic: message.Topic, Scope: message.Scope, Priority: value.Publish.Priority, LogicalKeyHex: value.Publish.LogicalKeyHex, PayloadHex: value.Publish.PayloadHex, AcceptanceMarker: event.AcceptanceMarker}
	subscription, err := client.CreateEventSubscription(ctx, request(&api.CreateEventSubscriptionRequest{OperationKey: subscriptionKey, Topic: message.Topic, Scope: message.Scope}, token))
	if err != nil {
		return err
	}
	if subscription == nil || subscription.Msg == nil || !subscription.Msg.Inserted || len(subscription.Msg.SubscriptionId) != 32 {
		return errors.New("expected fresh durable subscription")
	}
	id := subscription.Msg.SubscriptionId
	if err := recoveryDelivery(ctx, client, token, id, expected, 1); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err = writeResult(output, result{"status": "ok", "client_pid": os.Getpid(), "subscription_id_hex": hex.EncodeToString(id), "event_id_hex": expected.IDHex, "publisher_id_hex": expected.PublisherHex, "publisher_counter": expected.PublisherCounter, "event_sequence": expected.EventSequence, "acceptance_marker": expected.AcceptanceMarker, "attempt": 1, "exact_match": true, "retry_same_effect": true, "first_inserted": true, "retry_inserted": false}); err != nil {
		return err
	}
	if err = journal.Apply(sequence); err != nil {
		return err
	}
	return journal.Acknowledge(ctx, sequence)
}

func recoveryDelivery(ctx context.Context, client api.AsterApplicationServiceClient, token string, id []byte, expected expectedEventInput, attempt uint64) error {
	response, err := client.PollEvents(ctx, request(&api.PollEventsRequest{SubscriptionId: id, DeliveryLimit: 1, ScanLimit: 8}, token))
	if err != nil {
		return err
	}
	if response == nil || response.Msg == nil || response.Msg.HasMore || len(response.Msg.Deliveries) != 1 || response.Msg.Deliveries[0] == nil {
		return errors.New("expected one caught-up delivery")
	}
	delivery := response.Msg.Deliveries[0]
	exact, err := eventMatches(delivery.Event, expected)
	if err != nil || !exact || delivery.Attempt != attempt {
		return errors.New("delivery did not match exact Event and attempt")
	}
	return ctx.Err()
}

func recoveryResume(ctx context.Context, client api.AsterApplicationServiceClient, token string, input io.Reader, output io.Writer) error {
	var value recoveryResumeInput
	if err := decodeInput(input, &value); err != nil {
		return err
	}
	id, err := decodeFixedHex(value.SubscriptionIDHex, 32)
	if err != nil {
		return err
	}
	query, err := queryRequest(queryInput{Expected: value.Expected})
	if err != nil {
		return err
	}
	eventID, err := decodeFixedHex(value.Expected.IDHex, 32)
	if err != nil {
		return err
	}
	if err := recoveryDelivery(ctx, client, token, id, value.Expected, 2); err != nil {
		return err
	}
	ack, err := client.AcknowledgeEvent(ctx, request(&api.AcknowledgeEventRequest{SubscriptionId: id, EventId: eventID}, token))
	if err != nil {
		return err
	}
	if ack == nil || ack.Msg == nil || ack.Msg.AlreadyAcknowledged {
		return errors.New("expected fresh acknowledgement")
	}
	// A slow response is not a quiet observation interval. Start only after
	// the first successful empty response, and require a successful final poll
	// initiated at or after the window end on this unchanged subscription.
	var started time.Time
	polls := 0
	for {
		pollStarted := time.Now()
		response, err := client.PollEvents(ctx, request(&api.PollEventsRequest{SubscriptionId: id, DeliveryLimit: 1, ScanLimit: 8}, token))
		if err != nil {
			return err
		}
		if response == nil || response.Msg == nil || response.Msg.HasMore || len(response.Msg.Deliveries) != 0 {
			return errors.New("acknowledged subscription was not empty and caught up")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		polls++
		if started.IsZero() {
			started = time.Now()
		}
		if !pollStarted.Before(started.Add(recoveryQuietWindow)) {
			break
		}
		timer := time.NewTimer(recoveryPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	retained, err := client.QueryEvents(ctx, request(query, token))
	if err != nil {
		return err
	}
	if retained == nil || retained.Msg == nil || retained.Msg.HasMore || len(retained.Msg.Events) != 1 {
		return errors.New("retained Event was not uniquely queryable")
	}
	exact, err := eventMatches(retained.Msg.Events[0], value.Expected)
	if err != nil || !exact {
		return errors.New("retained Event changed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return writeResult(output, result{"status": "ok", "client_pid": os.Getpid(), "subscription_id_hex": value.SubscriptionIDHex, "event_id_hex": value.Expected.IDHex, "acceptance_marker": value.Expected.AcceptanceMarker, "attempt": 2, "exact_match": true, "acknowledged": true, "quiet_polls": polls, "quiet_window_ms": recoveryQuietWindow.Milliseconds(), "retained_query_exact": true})
}
