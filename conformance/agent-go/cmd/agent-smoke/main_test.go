package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	applicationv1alpha1 "github.com/defenseunicorns/aster/conformance/agent-go/gen/aster/application/v1alpha1"
	"google.golang.org/protobuf/proto"
)

func writeToken(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("test-token-0123456789abcdefghijkl\n"), mode); err != nil {
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

func hexOf(value []byte) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(value)*2)
	for index, item := range value {
		encoded[index*2] = alphabet[item>>4]
		encoded[index*2+1] = alphabet[item&0x0f]
	}
	return string(encoded)
}
