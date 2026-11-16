package aster

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

const testTopic = "position.current"
const testScope = "mission/team/alpha"

func fixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	bundle, err := os.ReadFile(filepath.Join("..", "testdata", "non-production-provisioning.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "mission.bundle")
	if err = os.WriteFile(path, bundle, 0600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "state"), path
}
func openTest(t *testing.T, state, mission string) *Node {
	t.Helper()
	n, err := Open(state, mission)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Close() })
	return n
}
func publishTest(t *testing.T, n *Node, class DataClass, op, payload string) Receipt {
	t.Helper()
	r, err := n.Publish(PublishRequest{Class: class, Topic: testTopic, Scope: testScope, OperationKey: []byte(op), LogicalKey: []byte("unit-7"), Payload: []byte(payload), Priority: Immediate})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func status(t *testing.T, err error, want uint32) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Status != want {
		t.Fatalf("error=%v; want status %d", err, want)
	}
}
func TestVersion(t *testing.T) {
	if ABIVersion() != 2 || ProtocolVersion() != 1 || ReplicationWireVersion() != 1 || DefaultSemanticVersion() != 9 || HighestSupportedSemanticVersion() != 9 {
		t.Fatal("version mismatch")
	}
}
func TestStateRecordDurabilityExactQueryAndDelivery(t *testing.T) {
	state, mission := fixture(t)
	n := openTest(t, state, mission)
	for _, class := range []DataClass{State, Record} {
		sub, err := n.Subscribe(class, testTopic, testScope, []byte("sub"), Client{}, false)
		if err != nil {
			t.Fatal(err)
		}
		r := publishTest(t, n, class, "first", "binary\x00payload")
		retry := publishTest(t, n, class, "first", "binary\x00payload")
		if retry.Inserted || retry.ItemID != r.ItemID {
			t.Fatal("retry changed result")
		}
		ttl := uint64(10)
		_, err = n.Publish(PublishRequest{Class: class, Topic: testTopic, Scope: testScope, OperationKey: []byte("ttl"), LogicalKey: []byte("unit-7"), TTLMS: &ttl})
		status(t, err, 1)
		_, err = n.Query(Query{Class: class, Topic: testTopic, Scope: testScope})
		status(t, err, 1)
		p, err := n.Query(Query{Class: class, Topic: testTopic, Scope: testScope, LogicalKey: []byte("unit-7")})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Items) != 1 || !bytes.Equal(p.Items[0].Payload, []byte("binary\x00payload")) {
			t.Fatal("query mismatch")
		}
		_ = p.Close()
		p, err = sub.Poll(1, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Entries) != 1 || len(p.Entries[0].Items) != 1 {
			t.Fatal("delivery mismatch")
		}
		d := p.Entries[0]
		_ = p.Close()
		if err = sub.Acknowledge(d); err != nil {
			t.Fatal(err)
		}
		if err = sub.Acknowledge(d); err != nil {
			t.Fatal(err)
		}
		p, err = sub.Poll(1, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Entries) != 0 {
			t.Fatal("acknowledged delivery returned")
		}
		_ = p.Close()
		if err = sub.Unsubscribe(); err != nil {
			t.Fatal(err)
		}
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	n = openTest(t, state, mission)
	p, err := n.Query(Query{Class: State, Topic: testTopic, Scope: testScope, LogicalKey: []byte("unit-7")})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if len(p.Items) != 1 {
		t.Fatal("lost durable state")
	}
}
func TestNumberedEventRecoveryAndFencing(t *testing.T) {
	state, mission := fixture(t)
	n := openTest(t, state, mission)
	recovered, err := n.BeginRecovery([]byte("go-client"), 0, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = n.CompleteRecovery(recovered.Client, recovered.SnapshotRevision); err != nil {
		t.Fatal(err)
	}
	p := PublishRequest{Class: Event, Client: recovered.Client, Sequence: 1, Topic: testTopic, Scope: testScope, Payload: []byte("event")}
	r, err := n.Publish(p)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := n.Publish(p)
	if err != nil || retry.Inserted || retry.ItemID != r.ItemID {
		t.Fatalf("retry %v %v", retry, err)
	}
	sub, err := n.Subscribe(Event, testTopic, testScope, []byte("events"), recovered.Client, false)
	if err != nil {
		t.Fatal(err)
	}
	page, err := sub.Poll(1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 1 {
		t.Fatal("missing Event")
	}
	d := page.Entries[0]
	_ = page.Close()
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
	n = openTest(t, state, mission)
	next, err := n.BeginRecovery([]byte("go-client"), recovered.Client.Session, bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Outstanding) != 1 || next.Outstanding[0].ItemID != r.ItemID || next.AllocatedThrough != 1 {
		t.Fatal("lost recovery result")
	}
	if err = n.CompleteRecovery(next.Client, next.SnapshotRevision); err != nil {
		t.Fatal(err)
	}
	stale := n.RestoreSubscription(Event, sub.ID, recovered.Client)
	_, err = stale.Poll(1, 100)
	status(t, err, 13)
	fresh := n.RestoreSubscription(Event, sub.ID, next.Client)
	if err = fresh.Acknowledge(d); err != nil {
		t.Fatal(err)
	}
	if err = n.AcknowledgePublication(next.Client, 1); err != nil {
		t.Fatal(err)
	}
	if err = n.AbandonPublication(next.Client, 2); err != nil {
		t.Fatal(err)
	}
}
func TestBlobStreamingLifecycleAndZeroize(t *testing.T) {
	state, mission := fixture(t)
	n := openTest(t, state, mission)
	payload := bytes.Repeat([]byte("blob\x00"), 450000)
	writer, err := n.NewBlobWriter(testTopic, testScope, BlobOptions{OperationKey: []byte("blob"), TotalLen: uint64(len(payload)), Priority: Immediate, MediaType: "application/octet-stream"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = writer.Finish()
	status(t, err, 1)
	if _, err = writer.Write(payload[:13]); err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(writer, bytes.NewReader(payload[13:])); err != nil {
		t.Fatal(err)
	}
	receipt, err := writer.Finish()
	if err != nil {
		t.Fatal(err)
	}
	again, err := writer.Finish()
	if err != nil || again != receipt {
		t.Fatal("finish retry failed")
	}
	_ = writer.Close()
	reader, err := n.OpenBlobReader(testTopic, testScope, receipt.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(restored, payload) {
		t.Fatalf("read failed %v", err)
	}
	if err = n.Zeroize(); err != nil {
		t.Fatal(err)
	}
	_, err = reader.Read(make([]byte, 1))
	status(t, err, 5)
	_ = reader.Close()
	_, err = Open(state, mission)
	if err == nil {
		t.Fatal("terminal state reopened")
	}
}
func TestConcurrentCloseEmissionPeersAndFailures(t *testing.T) {
	state, mission := fixture(t)
	n := openTest(t, state, mission)
	if err := n.SetEmission(ReceiveOnly); err != nil {
		t.Fatal(err)
	}
	if v, err := n.Emission(); err != nil || v != ReceiveOnly {
		t.Fatal("emission mismatch")
	}
	if peers, err := n.Peers(); err != nil || len(peers) != 0 {
		t.Fatal("unexpected peers")
	}
	_, err := n.PeerStatus([32]byte{})
	status(t, err, 4)
	_, err = n.RekeyScope([]byte("invalid"), 1, testScope, 2, []RekeyRecipient{{}})
	if err == nil {
		t.Fatal("invalid rekey accepted")
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i == 5 {
				_ = n.Close()
				return
			}
			_, err := n.Emission()
			if err != nil && !isClosed(err) {
				t.Errorf("concurrent operation: %v", err)
			}
		}(i)
	}
	wg.Wait()
}

func TestWholeRecordConflictGuardAndRekey(t *testing.T) {
	root := filepath.Join(t.TempDir(), "testdata")
	command := exec.Command(filepath.Join("..", "..", "target", "debug", "examples", "prepare_binding_test_state"), root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("prepare fixture: %v %s", err, output)
	}
	n := openTest(t, filepath.Join(root, "state"), filepath.Join(root, "mission.bundle"))
	projection, err := n.Query(Query{Class: Record, Topic: testTopic, Scope: testScope, LogicalKey: []byte("unit-7")})
	if err != nil {
		t.Fatal(err)
	}
	defer projection.Close()
	if len(projection.Items) != 3 || len(projection.Entries[0].Siblings) != 3 || !projection.Entries[0].HasGuard {
		t.Fatal("conflict was truncated")
	}
	sub, err := n.Subscribe(Record, testTopic, testScope, []byte("whole"), Client{}, false)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := sub.Poll(1, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer delivery.Close()
	if len(delivery.Entries) != 1 || len(delivery.Entries[0].Items) != 3 {
		t.Fatal("whole projection delivery split")
	}
	_, err = n.Resolve(delivery, 0, []byte("invalid-guard"), []byte("bad"), Routine, false)
	status(t, err, 8)
	resolved, err := n.Resolve(projection, 0, []byte("resolve"), []byte("joined"), Immediate, false)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := n.Resolve(projection, 0, []byte("resolve"), []byte("joined"), Immediate, false)
	if err != nil || retry.ItemID != resolved.ItemID || retry.Inserted {
		t.Fatal("resolution retry mismatch")
	}
	_, err = n.Resolve(projection, 0, []byte("stale"), []byte("different"), Immediate, false)
	status(t, err, 8)
	registry, err := os.ReadFile(filepath.Join(root, "registry.public"))
	if err != nil {
		t.Fatal(err)
	}
	nodeID, err := os.ReadFile(filepath.Join(root, "identity.public"))
	if err != nil {
		t.Fatal(err)
	}
	var self [32]byte
	copy(self[:], nodeID)
	recipients := []RekeyRecipient{{self, []string{testTopic}}}
	first, err := n.RekeyScope(registry, 1, testScope, 2, recipients)
	if err != nil {
		t.Fatal(err)
	}
	again, err := n.RekeyScope(registry, 1, testScope, 2, recipients)
	if err != nil || first.TransferID != again.TransferID || !first.Emitted || again.Emitted {
		t.Fatalf("rekey replay %v %v", again, err)
	}
}
