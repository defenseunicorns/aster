package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	applicationv1alpha1 "github.com/defenseunicorns/aster/conformance/agent-go/gen/aster/application/v1alpha1"
)

const (
	maxInputBytes        = 1024 * 1024
	maxOutputBytes       = 2 * 1024 * 1024
	maxTokenFileBytes    = 257
	maxTimeoutSeconds    = 30
	maxStreamDeliveries  = 32
	profileStoreItems    = 10_000
	profileStoreBytes    = 64 * 1024 * 1024
	operationHardRows    = 4_096
	operationHardBytes   = 512 * 1024
	operationWarnRows    = 512
	operationProfileRows = 1_024
	deliveryProfileRows  = 256
	deliveryHardRows     = 262_144
)

type options struct {
	command   string
	baseURL   string
	tokenFile string
	timeout   time.Duration
}

type result map[string]any

type statusInput struct {
	RepeatUntilError bool `json:"repeat_until_error"`
}

type publishInput struct {
	OperationKeyHex string `json:"operation_key_hex"`
	Topic           string `json:"topic"`
	Scope           string `json:"scope"`
	Priority        string `json:"priority"`
	LogicalKeyHex   string `json:"logical_key_hex"`
	PayloadHex      string `json:"payload_hex"`
}

type expectedEventInput struct {
	IDHex            string `json:"id_hex"`
	PublisherHex     string `json:"publisher_hex"`
	PublisherCounter uint64 `json:"publisher_counter"`
	EventSequence    uint64 `json:"event_sequence"`
	Topic            string `json:"topic"`
	Scope            string `json:"scope"`
	Priority         string `json:"priority"`
	LogicalKeyHex    string `json:"logical_key_hex"`
	PayloadHex       string `json:"payload_hex"`
	Tombstone        bool   `json:"tombstone"`
	AcceptanceMarker uint64 `json:"acceptance_marker"`
}

type queryInput struct {
	Expected expectedEventInput `json:"expected"`
}

type subscribeInput struct {
	OperationKeyHex string `json:"operation_key_hex"`
	Topic           string `json:"topic"`
	Scope           string `json:"scope"`
}

type pollInput struct {
	SubscriptionIDHex string `json:"subscription_id_hex"`
	DeliveryLimit     uint32 `json:"delivery_limit"`
	ScanLimit         uint32 `json:"scan_limit"`
}

type streamInput struct {
	SubscriptionIDHex string              `json:"subscription_id_hex"`
	DeliveryLimit     uint32              `json:"delivery_limit"`
	ScanLimit         uint32              `json:"scan_limit"`
	PollBackoffMS     uint32              `json:"poll_backoff_ms"`
	Count             uint32              `json:"count"`
	Expected          *expectedEventInput `json:"expected,omitempty"`
	AfterAttempt      uint64              `json:"after_attempt,omitempty"`
}

type ackInput struct {
	SubscriptionIDHex string `json:"subscription_id_hex"`
	EventIDHex        string `json:"event_id_hex"`
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		code := "internal"
		var connectErr *connect.Error
		if errors.As(err, &connectErr) {
			code = connectErr.Code().String()
		}
		_, _ = fmt.Fprintf(os.Stderr, "{\"status\":\"error\",\"code\":%q}\n", code)
		os.Exit(1)
	}
}

func run(args []string, input io.ReadCloser, output io.Writer) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	token, err := readToken(ctx, opts.tokenFile)
	if err != nil {
		return err
	}
	inputBytes, err := readInput(ctx, input)
	if err != nil {
		return err
	}

	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{Protocols: protocols}
	defer transport.CloseIdleConnections()
	client := applicationv1alpha1.NewAsterApplicationServiceClient(
		&http.Client{Transport: transport},
		opts.baseURL,
		connect.WithGRPC(),
	)
	return runCommand(ctx, client, opts.command, token, bytes.NewReader(inputBytes), output)
}

func parseOptions(args []string) (options, error) {
	if len(args) != 7 {
		return options{}, errors.New("invalid arguments")
	}
	opts := options{command: args[0]}
	seen := make(map[string]bool, 3)
	for index := 1; index < len(args); index += 2 {
		name, value := args[index], args[index+1]
		if seen[name] {
			return options{}, errors.New("invalid arguments")
		}
		seen[name] = true
		switch name {
		case "--url":
			parsed, err := url.Parse(value)
			if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
				return options{}, errors.New("invalid arguments")
			}
			opts.baseURL = value
		case "--token-file":
			if value == "" {
				return options{}, errors.New("invalid arguments")
			}
			opts.tokenFile = value
		case "--timeout-seconds":
			seconds, err := strconv.Atoi(value)
			if err != nil || seconds < 1 || seconds > maxTimeoutSeconds {
				return options{}, errors.New("invalid arguments")
			}
			opts.timeout = time.Duration(seconds) * time.Second
		default:
			return options{}, errors.New("invalid arguments")
		}
	}
	if opts.baseURL == "" || opts.tokenFile == "" || opts.timeout == 0 {
		return options{}, errors.New("invalid arguments")
	}
	switch opts.command {
	case "status", "publish", "query", "subscribe", "poll", "stream", "ack":
		return opts, nil
	default:
		return options{}, errors.New("invalid arguments")
	}
}

func validateTokenFile(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := readToken(ctx, path)
	return err
}

func readToken(ctx context.Context, path string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	file, err := openToken(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := readBounded(ctx, file, maxTokenFileBytes)
	if err != nil || len(data) > maxTokenFileBytes {
		return "", errors.New("invalid token file")
	}
	data = bytes.TrimRight(data, "\r\n")
	if len(data) < 32 || len(data) > 256 {
		return "", errors.New("invalid token file")
	}
	for _, value := range data {
		if !((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || strings.ContainsRune("-._~", rune(value))) {
			return "", errors.New("invalid token file")
		}
	}
	return string(data), nil
}

func openToken(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("invalid token file")
	}
	file := os.NewFile(uintptr(fd), "token")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("invalid token file")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxTokenFileBytes {
		file.Close()
		return nil, errors.New("invalid token file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		file.Close()
		return nil, errors.New("invalid token file")
	}
	return file, nil
}

func decodeInput(input io.Reader, destination any) error {
	data, err := io.ReadAll(io.LimitReader(input, maxInputBytes+1))
	if err != nil || len(data) > maxInputBytes {
		return errors.New("invalid input")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid input")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid input")
	}
	return nil
}

func readInput(ctx context.Context, input io.ReadCloser) ([]byte, error) {
	return readBounded(ctx, input, maxInputBytes)
}

func readBounded(ctx context.Context, input io.ReadCloser, maximum int) ([]byte, error) {
	type readResult struct {
		data []byte
		err  error
	}
	finished := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(input, int64(maximum)+1))
		finished <- readResult{data: data, err: err}
	}()
	select {
	case <-ctx.Done():
		_ = input.Close()
		<-finished
		return nil, ctx.Err()
	case result := <-finished:
		if result.err != nil || len(result.data) > maximum {
			return nil, errors.New("invalid input")
		}
		return result.data, nil
	}
}

func decodeHex(value string) ([]byte, error) {
	if value == "" || len(value)%2 != 0 {
		return nil, errors.New("invalid input")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, errors.New("invalid input")
	}
	return decoded, nil
}

func decodeFixedHex(value string, size int) ([]byte, error) {
	decoded, err := decodeHex(value)
	if err != nil || len(decoded) != size {
		return nil, errors.New("invalid input")
	}
	return decoded, nil
}

func decodeOperationKeyHex(value string) ([]byte, error) {
	decoded, err := decodeHex(value)
	if err != nil || len(decoded) > 256 {
		return nil, errors.New("invalid input")
	}
	return decoded, nil
}

func priority(value string) (applicationv1alpha1.Priority, error) {
	switch value {
	case "routine":
		return applicationv1alpha1.Priority_PRIORITY_ROUTINE, nil
	case "priority":
		return applicationv1alpha1.Priority_PRIORITY_PRIORITY, nil
	case "immediate":
		return applicationv1alpha1.Priority_PRIORITY_IMMEDIATE, nil
	case "flash":
		return applicationv1alpha1.Priority_PRIORITY_FLASH, nil
	default:
		return applicationv1alpha1.Priority_PRIORITY_UNSPECIFIED, errors.New("invalid input")
	}
}

func request[T any](message *T, token string) *connect.Request[T] {
	req := connect.NewRequest(message)
	req.Header().Set("Authorization", "Bearer "+token)
	return req
}

func writeResult(output io.Writer, value result) error {
	encoded, err := encodeResult(value)
	if err != nil {
		return err
	}
	payload := append(encoded, '\n')
	written, err := output.Write(payload)
	if err != nil {
		return err
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}
	return nil
}

func renderResult(value result, _ string) string {
	encoded, err := encodeResult(value)
	if err != nil {
		return "{\"status\":\"error\",\"code\":\"internal\"}"
	}
	return string(encoded)
}

func encodeResult(value result) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maxOutputBytes {
		return nil, errors.New("invalid result")
	}
	return encoded, nil
}

func resultFixture() result {
	return result{"status": "ok"}
}

func emissionMode(value applicationv1alpha1.EmissionMode) (string, error) {
	switch value {
	case applicationv1alpha1.EmissionMode_EMISSION_MODE_NORMAL:
		return "normal", nil
	case applicationv1alpha1.EmissionMode_EMISSION_MODE_RECEIVE_ONLY:
		return "receive_only", nil
	default:
		return "", errors.New("invalid status response")
	}
}

func statusEvidence(message *applicationv1alpha1.GetStatusResponse) (result, error) {
	if message == nil {
		return nil, errors.New("invalid status response")
	}
	configured, err := emissionMode(message.ConfiguredEmissionMode)
	if err != nil {
		return nil, err
	}
	effective, err := emissionMode(message.EffectiveEmissionMode)
	if err != nil {
		return nil, err
	}
	store := message.StoreCapacity
	operations := message.PublishOperationCapacity
	deliveries := message.DeliveryCapacity
	if store == nil || operations == nil || deliveries == nil {
		return nil, errors.New("invalid status response")
	}
	if store.ItemLimit != profileStoreItems || store.PayloadByteLimit != profileStoreBytes ||
		store.Items > store.ItemLimit || store.PayloadBytes > store.PayloadByteLimit {
		return nil, errors.New("invalid status response")
	}
	remaining := uint64(0)
	if operations.Rows < operationProfileRows {
		remaining = operationProfileRows - operations.Rows
	}
	if operations.RowHardLimit != operationHardRows || operations.ByteHardLimit != operationHardBytes ||
		operations.ProfileBoundary != operationProfileRows || operations.ProfileRemaining != remaining ||
		operations.ProfileWarning != (operations.Rows >= operationWarnRows) ||
		operations.ProfileExhausted != (operations.Rows >= operationProfileRows) ||
		operations.Rows > operations.RowHardLimit || operations.Bytes > operations.ByteHardLimit {
		return nil, errors.New("invalid status response")
	}
	if deliveries.ProfileBoundary != deliveryProfileRows || deliveries.HardLimit != deliveryHardRows ||
		deliveries.ProfileSaturated != (deliveries.Pending >= deliveryProfileRows) ||
		deliveries.Pending > deliveries.HardLimit {
		return nil, errors.New("invalid status response")
	}
	return result{
		"status":                      "ok",
		"configured_emission_mode":    configured,
		"effective_emission_mode":     effective,
		"store_items":                 store.Items,
		"store_item_limit":            store.ItemLimit,
		"store_payload_bytes":         store.PayloadBytes,
		"store_payload_byte_limit":    store.PayloadByteLimit,
		"operation_rows":              operations.Rows,
		"operation_bytes":             operations.Bytes,
		"operation_profile_remaining": operations.ProfileRemaining,
		"operation_profile_warning":   operations.ProfileWarning,
		"operation_profile_exhausted": operations.ProfileExhausted,
		"pending_deliveries":          deliveries.Pending,
		"delivery_profile_saturated":  deliveries.ProfileSaturated,
	}, nil
}

func runCommand(ctx context.Context, client applicationv1alpha1.AsterApplicationServiceClient, command, token string, input io.Reader, output io.Writer) error {
	switch command {
	case "status":
		var value statusInput
		if err := decodeInput(input, &value); err != nil {
			return err
		}
		response, err := client.GetStatus(ctx, request(&applicationv1alpha1.GetStatusRequest{}, token))
		if err != nil {
			return err
		}
		receipt, err := statusEvidence(response.Msg)
		if err != nil {
			return err
		}
		if !value.RepeatUntilError {
			return writeResult(output, receipt)
		}
		if err := writeResult(output, result{"status": "active", "activity": "unary"}); err != nil {
			return err
		}
		for {
			response, err := client.GetStatus(ctx, request(&applicationv1alpha1.GetStatusRequest{}, token))
			if err != nil {
				return err
			}
			if _, err := statusEvidence(response.Msg); err != nil {
				return err
			}
			time.Sleep(time.Millisecond)
		}
	case "publish":
		var value publishInput
		if err := decodeInput(input, &value); err != nil {
			return err
		}
		operationKey, err := decodeOperationKeyHex(value.OperationKeyHex)
		if err != nil {
			return err
		}
		logicalKey, err := decodeHex(value.LogicalKeyHex)
		if err != nil {
			return err
		}
		payload, err := decodeHex(value.PayloadHex)
		if err != nil {
			return err
		}
		priorityValue, err := priority(value.Priority)
		if err != nil {
			return err
		}
		response, err := client.PublishEvent(ctx, request(&applicationv1alpha1.PublishEventRequest{
			OperationKey: operationKey,
			Topic:        value.Topic,
			Scope:        value.Scope,
			Priority:     priorityValue,
			LogicalKey:   logicalKey,
			Payload:      payload,
		}, token))
		if err != nil {
			return err
		}
		message := response.Msg
		return writeResult(output, result{
			"status": "ok", "event_id_hex": hex.EncodeToString(message.Id),
			"publisher_id_hex":  hex.EncodeToString(message.Publisher),
			"publisher_counter": message.PublisherCounter, "event_sequence": message.EventSequence,
			"acceptance_marker": message.AcceptanceMarker, "inserted": message.Inserted,
		})
	case "query":
		var value queryInput
		if err := decodeInput(input, &value); err != nil {
			return err
		}
		query, err := queryRequest(value)
		if err != nil {
			return err
		}
		response, err := client.QueryEvents(ctx, request(query, token))
		if err != nil {
			return err
		}
		exact := len(response.Msg.Events) == 1
		if exact {
			exact, err = eventMatches(response.Msg.Events[0], value.Expected)
			if err != nil {
				return err
			}
		}
		return writeResult(output, result{"status": "ok", "exact_match": exact, "count": len(response.Msg.Events), "has_more": response.Msg.HasMore})
	case "subscribe":
		var value subscribeInput
		if err := decodeInput(input, &value); err != nil {
			return err
		}
		operationKey, err := decodeOperationKeyHex(value.OperationKeyHex)
		if err != nil {
			return err
		}
		response, err := client.CreateEventSubscription(ctx, request(&applicationv1alpha1.CreateEventSubscriptionRequest{
			OperationKey: operationKey, Topic: value.Topic, Scope: value.Scope,
		}, token))
		if err != nil {
			return err
		}
		return writeResult(output, result{"status": "ok", "subscription_id_hex": hex.EncodeToString(response.Msg.SubscriptionId), "inserted": response.Msg.Inserted})
	case "poll":
		var value pollInput
		if err := decodeInput(input, &value); err != nil {
			return err
		}
		subscriptionID, err := decodeFixedHex(value.SubscriptionIDHex, 32)
		if err != nil {
			return err
		}
		response, err := client.PollEvents(ctx, request(&applicationv1alpha1.PollEventsRequest{
			SubscriptionId: subscriptionID, DeliveryLimit: value.DeliveryLimit, ScanLimit: value.ScanLimit,
		}, token))
		if err != nil {
			return err
		}
		deliveries := make([]result, 0, len(response.Msg.Deliveries))
		for _, delivery := range response.Msg.Deliveries {
			if delivery == nil || delivery.Event == nil {
				return errors.New("invalid response")
			}
			deliveries = append(deliveries, result{"event_id_hex": hex.EncodeToString(delivery.Event.Id), "attempt": delivery.Attempt})
		}
		return writeResult(output, result{"status": "ok", "deliveries": deliveries, "has_more": response.Msg.HasMore})
	case "stream":
		var value streamInput
		if err := decodeInput(input, &value); err != nil || value.Count == 0 || value.Count > maxStreamDeliveries {
			return errors.New("invalid input")
		}
		subscriptionID, err := decodeFixedHex(value.SubscriptionIDHex, 32)
		if err != nil {
			return err
		}
		stream, err := client.StreamEvents(ctx, request(&applicationv1alpha1.StreamEventsRequest{
			SubscriptionId: subscriptionID, DeliveryLimit: value.DeliveryLimit, ScanLimit: value.ScanLimit, PollBackoffMs: value.PollBackoffMS,
		}, token))
		if err != nil {
			return err
		}
		if err := writeResult(output, result{"status": "active", "activity": "stream"}); err != nil {
			return err
		}
		var delivered uint32
		var attempt uint64
		defer stream.Close()
		for delivered < value.Count && stream.Receive() {
			if stream.Msg() == nil || stream.Msg().Event == nil || stream.Msg().Attempt == 0 {
				return errors.New("invalid response")
			}
			if value.Expected != nil {
				matched, err := eventMatches(stream.Msg().Event, *value.Expected)
				if err != nil || !matched || stream.Msg().Attempt <= value.AfterAttempt {
					return errors.New("invalid stream evidence")
				}
			}
			attempt = stream.Msg().Attempt
			delivered++
		}
		if err := stream.Err(); err != nil {
			return err
		}
		if value.Expected != nil {
			if delivered != value.Count {
				return errors.New("incomplete stream evidence")
			}
			return writeResult(output, result{"status": "ok", "delivered": delivered, "exact_match": true, "attempt": attempt})
		}
		return writeResult(output, result{"status": "ok", "delivered": delivered})
	case "ack":
		var value ackInput
		if err := decodeInput(input, &value); err != nil {
			return err
		}
		subscriptionID, err := decodeFixedHex(value.SubscriptionIDHex, 32)
		if err != nil {
			return err
		}
		eventID, err := decodeFixedHex(value.EventIDHex, 32)
		if err != nil {
			return err
		}
		response, err := client.AcknowledgeEvent(ctx, request(&applicationv1alpha1.AcknowledgeEventRequest{
			SubscriptionId: subscriptionID, EventId: eventID,
		}, token))
		if err != nil {
			return err
		}
		return writeResult(output, result{"status": "ok", "already_acknowledged": response.Msg.AlreadyAcknowledged})
	default:
		return errors.New("invalid command")
	}
}

func queryRequest(input queryInput) (*applicationv1alpha1.QueryEventsRequest, error) {
	if _, err := decodeFixedHex(input.Expected.IDHex, 32); err != nil {
		return nil, err
	}
	if _, err := decodeFixedHex(input.Expected.PublisherHex, 32); err != nil {
		return nil, err
	}
	if _, err := decodeHex(input.Expected.LogicalKeyHex); err != nil {
		return nil, err
	}
	if _, err := decodeHex(input.Expected.PayloadHex); err != nil {
		return nil, err
	}
	if _, err := priority(input.Expected.Priority); err != nil {
		return nil, err
	}
	return &applicationv1alpha1.QueryEventsRequest{
		Topic: &input.Expected.Topic,
		Scope: &input.Expected.Scope,
		Limit: 2,
	}, nil
}

func eventMatches(event *applicationv1alpha1.Event, expected expectedEventInput) (bool, error) {
	if event == nil {
		return false, nil
	}
	id, err := decodeFixedHex(expected.IDHex, 32)
	if err != nil {
		return false, err
	}
	publisher, err := decodeFixedHex(expected.PublisherHex, 32)
	if err != nil {
		return false, err
	}
	logicalKey, err := decodeHex(expected.LogicalKeyHex)
	if err != nil {
		return false, err
	}
	payload, err := decodeHex(expected.PayloadHex)
	if err != nil {
		return false, err
	}
	priorityValue, err := priority(expected.Priority)
	if err != nil {
		return false, err
	}
	return bytes.Equal(event.Id, id) && bytes.Equal(event.Publisher, publisher) &&
		event.PublisherCounter == expected.PublisherCounter && event.EventSequence == expected.EventSequence &&
		event.Topic == expected.Topic && event.Scope == expected.Scope && event.Priority == priorityValue &&
		bytes.Equal(event.LogicalKey, logicalKey) && bytes.Equal(event.Payload, payload) &&
		event.Tombstone == expected.Tombstone && event.AcceptanceMarker == expected.AcceptanceMarker, nil
}
