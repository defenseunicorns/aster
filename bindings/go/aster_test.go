package aster

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func testBundle(t *testing.T) []byte {
	t.Helper()
	value, err := os.ReadFile(filepath.Join("..", "testdata", "non-production-provisioning.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestVersionSurfacesDistinguishWireFromSemantics(t *testing.T) {
	if ProtocolVersion() != 1 || ReplicationWireVersion() != 1 {
		t.Fatalf("wire versions legacy=%d explicit=%d", ProtocolVersion(), ReplicationWireVersion())
	}
	if DefaultSemanticVersion() != 6 || HighestSupportedSemanticVersion() != 6 {
		t.Fatalf("semantic versions default=%d highest=%d", DefaultSemanticVersion(), HighestSupportedSemanticVersion())
	}
}

func TestFormatThreeBundleOpensAndLegacyFormatTwoIsRejected(t *testing.T) {
	bundle := testBundle(t)
	if len(bundle) < 8 || !bytes.Equal(bundle[:8], []byte("ASTRPB03")) {
		t.Fatalf("test provisioning bundle does not use format three")
	}
	node, err := Open(":memory:", bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err = node.Close(); err != nil {
		t.Fatal(err)
	}

	legacy := append([]byte(nil), bundle...)
	copy(legacy[:8], []byte("ASTRPB02"))
	rejected, err := Open(":memory:", legacy)
	if rejected != nil {
		_ = rejected.Close()
		t.Fatal("legacy format-two provisioning bundle was accepted")
	}
	native, ok := err.(*Error)
	if !ok || native.Status != 9 {
		t.Fatalf("legacy format-two rejection=%#v", err)
	}
}

func TestBlobStreamingRoundTripAndIdempotentFinish(t *testing.T) {
	node, err := Open(filepath.Join(t.TempDir(), "mesh.db"), testBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	payload := bytes.Repeat([]byte("streamed\x00blob-data"), 1700)
	writer, err := node.NewBlobWriter("position.current", "mission/team/alpha", BlobOptions{
		Priority: Immediate, ChunkSize: 4096, MediaType: "application/octet-stream",
		SchemaID: []byte("test/blob/v1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.CopyBuffer(writer, bytes.NewReader(payload), make([]byte, 3001)); err != nil {
		t.Fatal(err)
	}
	finished, err := writer.Finish()
	if err != nil {
		t.Fatal(err)
	}
	again, err := writer.Finish()
	if err != nil || again != finished {
		t.Fatalf("finish retry=%#v err=%v", again, err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	class := Blob
	items, err := node.Query(Query{
		Topic: "position.current", Scope: "mission/team/alpha",
		LogicalKey: finished.BlobID[:], Class: &class,
	})
	if err != nil || len(items) != 1 || bytes.Equal(items[0].Payload, payload) {
		t.Fatalf("Blob manifest items=%d err=%v", len(items), err)
	}
	reader, err := node.OpenBlobReader("position.current", "mission/team/alpha", finished.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	var restored bytes.Buffer
	if _, err = io.CopyBuffer(&restored, reader, make([]byte, 2111)); err != nil {
		t.Fatal(err)
	}
	if err = reader.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Bytes(), payload) {
		t.Fatal("streamed Blob plaintext changed")
	}
}

func TestFinalizedBlobWritersPublishAsOneBatch(t *testing.T) {
	node, err := Open(":memory:", testBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	firstWriter, err := node.NewBlobWriter("position.current", "mission/team/alpha", BlobOptions{ChunkSize: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer firstWriter.Close()
	secondWriter, err := node.NewBlobWriter("position.current", "mission/team/alpha", BlobOptions{ChunkSize: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer secondWriter.Close()
	if _, err = firstWriter.Write([]byte("first finalized Blob")); err != nil {
		t.Fatal(err)
	}
	if _, err = secondWriter.Write([]byte("second finalized Blob")); err != nil {
		t.Fatal(err)
	}

	result, err := node.PublishBlobBatch([]*BlobWriter{firstWriter, secondWriter}, RetainedDual)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 2 || len(result.Evicted) != 0 {
		t.Fatalf("Blob batch receipts=%d evicted=%d", len(result.Items), len(result.Evicted))
	}
	if result.Items[0].CausalCounter != 1 || result.Items[1].CausalCounter != 2 {
		t.Fatalf("unexpected Blob batch counters: %#v", result.Items)
	}
	first, err := firstWriter.Finish()
	if err != nil {
		t.Fatal(err)
	}
	second, err := secondWriter.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if first.Receipt.ItemID != result.Items[0].ItemID || second.Receipt.ItemID != result.Items[1].ItemID {
		t.Fatal("Blob writer Finish did not preserve batch receipts")
	}
	if first.BlobID == second.BlobID {
		t.Fatal("different Blob payloads produced the same identifier")
	}
	if _, err = node.PublishBlobBatch([]*BlobWriter{firstWriter, secondWriter}, BatchOnly); err == nil {
		t.Fatal("already-published Blob writers were accepted")
	}
}

func TestOfflinePublishQueryAndSubscription(t *testing.T) {
	node, err := Open(filepath.Join(t.TempDir(), "mesh.db"), testBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	subscription, err := node.Subscribe("position.current", "mission/team/alpha", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := node.Publish(State, "position.current", "mission/team/alpha", []byte("north\x00binary"), PublishOptions{LogicalKey: []byte("unit-7"), Priority: Immediate})
	if err != nil {
		t.Fatal(err)
	}
	items, err := node.Query(Query{Topic: "position.current", Scope: "mission/team/alpha"})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ItemID != receipt.ItemID || string(items[0].Payload) != "north\x00binary" {
		t.Fatalf("unexpected items: %#v", items)
	}
	if items[0].Scope != "mission/team/alpha" || items[0].OriginScope != items[0].Scope || items[0].CurrentScope != items[0].Scope {
		t.Fatalf("unexpected item scopes: %#v", items[0])
	}
	first, err := subscription.Poll(10)
	if err != nil || len(first) != 1 {
		t.Fatalf("first deliveries=%d err=%v", len(first), err)
	}
	again, err := subscription.Poll(10)
	if err != nil || len(again) != 1 || again[0].Attempt <= first[0].Attempt {
		t.Fatalf("repeat=%#v err=%v", again, err)
	}
	if err = subscription.Acknowledge(again[0].Item.ItemID); err != nil {
		t.Fatal(err)
	}
	after, err := subscription.Poll(10)
	if err != nil || len(after) != 0 {
		t.Fatalf("after ack=%d err=%v", len(after), err)
	}
	if err := node.SetEmissionThreshold(ReceiveOnly); err != nil {
		t.Fatal(err)
	}
	threshold, err := node.EmissionThreshold()
	if err != nil || threshold != ReceiveOnly {
		t.Fatalf("threshold=%v err=%v", threshold, err)
	}
}

func TestExplicitBatchIsOrderedAtomicAndReportsMetadata(t *testing.T) {
	node, err := Open(":memory:", testBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()

	result, err := node.PublishBatch([]BatchPublishItem{
		{Class: Event, Topic: "position.current", Scope: "mission/team/alpha", Payload: []byte("first"), Options: PublishOptions{Priority: Immediate}},
		{Class: Event, Topic: "position.current", Scope: "mission/team/alpha", Payload: []byte("second"), Options: PublishOptions{Priority: Immediate}},
	}, BatchOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 2 || len(result.Evicted) != 0 {
		t.Fatalf("batch receipts=%d evicted=%d", len(result.Items), len(result.Evicted))
	}
	if result.Items[0].CausalCounter != 1 || result.Items[1].CausalCounter != 2 {
		t.Fatalf("unexpected ordered counters: %#v", result.Items)
	}
	if result.Items[0].EventSequence == nil || *result.Items[0].EventSequence != 1 ||
		result.Items[1].EventSequence == nil || *result.Items[1].EventSequence != 2 {
		t.Fatalf("unexpected ordered event sequences: %#v", result.Items)
	}
	rejected, err := Open(":memory:", testBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	defer rejected.Close()
	_, err = rejected.PublishBatch([]BatchPublishItem{
		{Class: State, Topic: "position.current", Scope: "mission/team/alpha", Payload: []byte("first"), Options: PublishOptions{LogicalKey: []byte("unit-1")}},
		{Class: State, Topic: "position.history", Scope: "mission/team/alpha", Payload: []byte("second"), Options: PublishOptions{LogicalKey: []byte("unit-2")}},
	}, RetainedDual)
	if err == nil {
		t.Fatal("mixed-topic batch succeeded")
	}
	after, err := rejected.Publish(State, "position.current", "mission/team/alpha", []byte("after rejection"), PublishOptions{LogicalKey: []byte("unit-1")})
	if err != nil {
		t.Fatal(err)
	}
	if after.CausalCounter != 1 {
		t.Fatalf("rejected batch consumed publisher counters: %d", after.CausalCounter)
	}
	if _, err = rejected.PublishBatch([]BatchPublishItem{{Class: Event}}, RetainedDual); err == nil {
		t.Fatal("one-item batch succeeded")
	}
}

func TestErrorsAndRepeatedLifecycle(t *testing.T) {
	for value := byte(1); value < 12; value++ {
		node, err := Open(":memory:", testBundle(t))
		if err != nil {
			t.Fatal(err)
		}
		if value%2 == 0 {
			err = node.Zeroize()
		} else {
			err = node.Close()
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err = node.Query(Query{}); err == nil {
			t.Fatal("closed node query succeeded")
		}
	}
	node, err := Open(":memory:", testBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	if _, err = node.Publish(State, "bad/topic", "scope", nil, PublishOptions{LogicalKey: []byte("key")}); err == nil {
		t.Fatal("invalid topic accepted")
	}
	if _, err = node.Publish(Blob, "document.attachment", "scope", []byte("not streamed"), PublishOptions{LogicalKey: []byte("blob")}); err == nil {
		t.Fatal("generic Blob publish accepted")
	}
}

func TestRekeyBindingValidatesNestedBorrowedInputs(t *testing.T) {
	node, err := Open(":memory:", testBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	var id [32]byte
	for index := range id {
		id[index] = byte(index)
	}
	valid := []RekeyRecipient{ReadTopicsRecipient(id, "position.current")}
	if _, err = node.RekeyScope(nil, 1, "mission/team/alpha", 1, valid); err == nil {
		t.Fatal("empty registry accepted")
	}
	if _, err = node.RekeyScope([]byte("opaque"), 1, "mission/team/alpha", 0, valid); err == nil {
		t.Fatal("zero epoch accepted")
	}
	if _, err = node.RekeyScope([]byte("opaque"), 1, "mission/team/alpha", 1, nil); err == nil {
		t.Fatal("empty recipients accepted")
	}
	if _, err = node.RekeyScope([]byte("opaque"), 1, "mission/team/alpha", 1, []RekeyRecipient{{
		NodeID: id, Access: RekeyRouteOnly, Topics: []string{"position.current"},
	}}); err == nil {
		t.Fatal("route-only topics accepted")
	}
	if _, err = node.RekeyScope([]byte("opaque"), 1, "mission/team/alpha", 1, []RekeyRecipient{{
		NodeID: id, Access: RekeyReadTopics,
	}}); err == nil {
		t.Fatal("read access without topics accepted")
	}
	if _, err = node.RekeyScope([]byte("opaque"), 1, "mission/team/alpha", 1, []RekeyRecipient{{
		NodeID: id, Access: RekeyReadTopics, Topics: []string{string(make([]byte, 129))},
	}}); err == nil {
		t.Fatal("oversized topic accepted")
	}
	tooMany := make([]RekeyRecipient, 129)
	for index := range tooMany {
		tooMany[index] = RouteOnlyRecipient(id)
	}
	if _, err = node.RekeyScope([]byte("opaque"), 1, "mission/team/alpha", 1, tooMany); err == nil {
		t.Fatal("oversized recipient list accepted")
	}
	if _, err = node.RekeyScope([]byte("opaque"), 1, "mission/team/alpha", 1, valid); err == nil {
		t.Fatal("invalid opaque registry reached native authority boundary without error")
	}
}

func TestBridgeBindingBoundsEmptyPagesAndOpaqueErrors(t *testing.T) {
	node, err := Open(":memory:", testBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	authorizations, err := node.BridgeAuthorizations(nil, 64)
	if err != nil || len(authorizations) != 0 {
		t.Fatalf("empty bridge authorizations=%d err=%v", len(authorizations), err)
	}
	routes, err := node.BridgeRoutes(nil, 64)
	if err != nil || len(routes) != 0 {
		t.Fatalf("empty bridge routes=%d err=%v", len(routes), err)
	}
	if _, err = node.EnableBridge(nil, BridgeAuthorizationPolicy{}); err == nil {
		t.Fatal("nil bridge enrollment accepted")
	}
	if _, err = node.BridgeItem([32]byte{}, BridgeAuthorizationID{}, BridgeNarrowingPolicy{}); err == nil {
		t.Fatal("empty bridge priority mask accepted")
	}
	tooMany := make([]string, 129)
	for index := range tooMany {
		tooMany[index] = "position.current"
	}
	if _, err = node.BridgeItem(
		[32]byte{}, BridgeAuthorizationID{},
		BridgeNarrowingPolicy{Topics: tooMany, AllowedPriorities: AllowImmediate},
	); err == nil {
		t.Fatal("oversized bridge narrowing topics accepted")
	}
	if _, err = node.CreateBridgeEnrollment(
		"mission/team/alpha", 1, "mission/team/alpha", 1,
	); err == nil {
		t.Fatal("same-scope bridge enrollment accepted")
	}
}
