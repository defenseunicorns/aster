package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	api "github.com/defenseunicorns/aster/conformance/agent-go/gen/aster/application/v1alpha1"
	"github.com/defenseunicorns/aster/conformance/agent-go/internal/numbered"
	"google.golang.org/protobuf/proto"
	"io"
)

type publicationIdentity struct {
	JournalPath string `json:"journal_path"`
	ClientIDHex string `json:"client_id_hex"`
}

func openPublication(ctx context.Context, client api.AsterApplicationServiceClient, token string, value publishInput) (*numbered.Journal, error) {
	id, err := decodeOperationKeyHex(value.ClientIDHex)
	if err != nil {
		return nil, err
	}
	journal, err := numbered.Open(value.JournalPath, id, client, token)
	if err != nil {
		return nil, err
	}
	if err = journal.Recover(ctx); err != nil {
		journal.Close()
		return nil, err
	}
	return journal, nil
}
func publicationIntent(value publishInput) (*api.PublishNumberedEventRequest, error) {
	logical, err := decodeHex(value.LogicalKeyHex)
	if err != nil {
		return nil, err
	}
	payload, err := decodeHex(value.PayloadHex)
	if err != nil {
		return nil, err
	}
	priority, err := priority(value.Priority)
	if err != nil {
		return nil, err
	}
	return &api.PublishNumberedEventRequest{Topic: value.Topic, Scope: value.Scope, Priority: priority, LogicalKey: logical, Payload: payload}, nil
}
func retainPublication(journal *numbered.Journal, value publishInput) (uint64, error) {
	intent, err := publicationIntent(value)
	if err != nil {
		return 0, err
	}
	if len(journal.Entries()) != 0 {
		return 0, numbered.ErrPending
	}
	return journal.Retain(intent)
}
func publicationEvent(ctx context.Context, client api.AsterApplicationServiceClient, token string, intent *api.PublishNumberedEventRequest, result *api.CommittedPublicationResult) (*api.Event, error) {
	if result == nil || result.Receipt == nil || result.Receipt.AcceptanceMarker == 0 || result.Content != api.CommittedContentStatus_COMMITTED_CONTENT_STATUS_AVAILABLE {
		return nil, errors.New("invalid committed publication result")
	}
	receipt := result.Receipt
	response, err := client.QueryEvents(ctx, request(&api.QueryEventsRequest{Topic: &intent.Topic, Scope: &intent.Scope, LogicalKey: intent.LogicalKey, AfterAcceptanceMarker: receipt.AcceptanceMarker - 1, Limit: 1}, token))
	if err != nil {
		return nil, err
	}
	if response == nil || response.Msg == nil || len(response.Msg.Events) != 1 || response.Msg.Events[0] == nil {
		return nil, errors.New("publication content unavailable")
	}
	event := response.Msg.Events[0]
	if !bytes.Equal(event.Id, receipt.EventId) || event.AcceptanceMarker != receipt.AcceptanceMarker || len(event.Publisher) != 32 || event.PublisherCounter == 0 || event.EventSequence == 0 || event.Topic != intent.Topic || event.Scope != intent.Scope || event.Priority != intent.Priority || !bytes.Equal(event.LogicalKey, intent.LogicalKey) || !bytes.Equal(event.Payload, intent.Payload) || event.Tombstone != intent.Tombstone {
		return nil, errors.New("publication content does not match retained intent")
	}
	return event, nil
}
func publishCommand(ctx context.Context, client api.AsterApplicationServiceClient, token string, input io.Reader, output io.Writer) error {
	var value publishInput
	if err := decodeInput(input, &value); err != nil {
		return err
	}
	intent, err := publicationIntent(value)
	if err != nil {
		return err
	}
	journal, err := openPublication(ctx, client, token, value)
	if err != nil {
		return err
	}
	defer journal.Close()
	sequence := value.OperationSequence
	if sequence != 0 {
		retained, err := journal.Request(sequence)
		if err != nil {
			return err
		}
		changed := proto.Clone(retained).(*api.PublishNumberedEventRequest)
		changed.Topic = intent.Topic
		changed.Scope = intent.Scope
		changed.Priority = intent.Priority
		changed.LogicalKey = intent.LogicalKey
		changed.Payload = intent.Payload
		// An explicit retained-sequence probe may exercise remote intent-conflict
		// rejection, but cannot overwrite or abandon the durable original intent.
		if !proto.Equal(changed, retained) {
			_, err = client.PublishNumberedEvent(ctx, request(changed, token))
			if err != nil {
				return err
			}
			return errors.New("changed numbered intent unexpectedly accepted")
		}
	} else {
		sequence, err = retainPublication(journal, value)
		if err != nil {
			return err
		}
	}
	response, err := journal.Publish(ctx, sequence)
	if err != nil {
		return err
	}
	event, err := publicationEvent(ctx, client, token, intent, response.Result)
	if err != nil {
		return err
	}
	return writeResult(output, result{"status": "ok", "operation_sequence": sequence, "event_id_hex": hex.EncodeToString(event.Id), "publisher_id_hex": hex.EncodeToString(event.Publisher), "publisher_counter": event.PublisherCounter, "event_sequence": event.EventSequence, "acceptance_marker": event.AcceptanceMarker, "inserted": response.Inserted})
}

func acknowledgePublicationCommand(ctx context.Context, client api.AsterApplicationServiceClient, token string, input io.Reader, output io.Writer) error {
	var value publishInput
	if err := decodeInput(input, &value); err != nil {
		return err
	}
	if value.OperationSequence == 0 {
		return errors.New("positive publication sequence required")
	}
	journal, err := openPublication(ctx, client, token, value)
	if err != nil {
		return err
	}
	defer journal.Close()
	if err = journal.Apply(value.OperationSequence); err != nil {
		return err
	}
	if err = journal.Acknowledge(ctx, value.OperationSequence); err != nil {
		return err
	}
	return writeResult(output, result{"status": "ok"})
}
