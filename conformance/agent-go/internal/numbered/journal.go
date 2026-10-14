// Package numbered owns bounded durable publication state for Go acceptance
// clients. It uses the generated public protocol independently of the Rust SDK.
package numbered

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"connectrpc.com/connect"
	api "github.com/defenseunicorns/aster/conformance/agent-go/gen/aster/application/v1alpha1"
	"google.golang.org/protobuf/proto"
)

const maxJournalBytes = 1 << 20
const maxEntries = 8

var ErrJournal = errors.New("invalid or unavailable numbered publication journal")
var ErrPending = errors.New("numbered publication intent must be recovered before new work")

type Client interface {
	BeginEventPublicationSession(context.Context, *connect.Request[api.BeginEventPublicationSessionRequest]) (*connect.Response[api.BeginEventPublicationSessionResponse], error)
	CompleteEventPublicationRecovery(context.Context, *connect.Request[api.CompleteEventPublicationRecoveryRequest]) (*connect.Response[api.CompleteEventPublicationRecoveryResponse], error)
	PublishNumberedEvent(context.Context, *connect.Request[api.PublishNumberedEventRequest]) (*connect.Response[api.PublishNumberedEventResponse], error)
	AcknowledgeEventPublicationResult(context.Context, *connect.Request[api.AcknowledgeEventPublicationResultRequest]) (*connect.Response[api.AcknowledgeEventPublicationResultResponse], error)
}

type Entry struct {
	Intent  *api.PublishNumberedEventRequest `json:"intent"`
	Result  *api.CommittedPublicationResult  `json:"result,omitempty"`
	Applied bool                             `json:"applied"`
}
type claim struct {
	Expected uint64
	Nonce    []byte
}
type state struct {
	Version                         int
	ClientID                        []byte
	Session, AllocatedThrough, Next uint64
	Claim                           *claim
	Entries                         []Entry
}

// Journal has one owner; callers serialize its method calls.
type Journal struct {
	path      string
	lock      *os.File
	state     state
	client    Client
	token     string
	recovered bool
}

func request[T any](value *T, token string) *connect.Request[T] {
	req := connect.NewRequest(value)
	req.Header().Set("Authorization", "Bearer "+token)
	return req
}
func regularOwned(file *os.File) bool {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
func openFile(path string, flags int) (*os.File, error) {
	file, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrJournal
	}
	if !regularOwned(file) {
		file.Close()
		return nil, ErrJournal
	}
	return file, nil
}
func validPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if parent == "/" {
			return true
		}
	}
}
func lockJournal(path string) (*os.File, error) {
	if !validPath(path) {
		return nil, ErrJournal
	}
	lock, err := openFile(path+".lock", os.O_RDWR|os.O_CREATE)
	if err != nil {
		return nil, err
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, ErrJournal
	}
	return lock, nil
}
func validID(id []byte) bool { return len(id) > 0 && len(id) <= 64 }

// Initialize explicitly creates a fresh journal and refuses any existing path.
func Initialize(path string, id []byte) error {
	if !validID(id) {
		return ErrJournal
	}
	lock, err := lockJournal(path)
	if err != nil {
		return err
	}
	defer lock.Close()
	file, err := openFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	defer file.Close()
	encoded, err := json.Marshal(state{Version: 1, ClientID: id, Next: 1})
	if err != nil {
		return ErrJournal
	}
	if _, err = file.Write(encoded); err != nil || file.Sync() != nil {
		return ErrJournal
	}
	return syncParent(path)
}
func syncParent(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return ErrJournal
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return ErrJournal
	}
	return nil
}

// Open refuses missing/corrupt state, mismatched identity and concurrent owners.
func Open(path string, id []byte, client Client, token string) (*Journal, error) {
	if !validID(id) {
		return nil, ErrJournal
	}
	lock, err := lockJournal(path)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			lock.Close()
		}
	}()
	file, err := openFile(path, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxJournalBytes+1))
	file.Close()
	if err != nil || len(encoded) > maxJournalBytes {
		return nil, ErrJournal
	}
	var saved state
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&saved) != nil || decoder.Decode(new(any)) != io.EOF || saved.Version != 1 || !bytes.Equal(saved.ClientID, id) || saved.Next == 0 || saved.Next <= saved.AllocatedThrough || len(saved.Entries) > maxEntries {
		return nil, ErrJournal
	}
	if saved.Claim != nil && (saved.Claim.Expected != saved.Session || len(saved.Claim.Nonce) != 32) {
		return nil, ErrJournal
	}
	seen := map[uint64]bool{}
	for _, entry := range saved.Entries {
		if entry.Intent == nil || !bytes.Equal(entry.Intent.ClientId, id) || entry.Intent.OperationSequence == 0 || entry.Intent.OperationSequence >= saved.Next || seen[entry.Intent.OperationSequence] || len(entry.Intent.Payload) > 65536 || entry.Result != nil && (entry.Result.OperationSequence != entry.Intent.OperationSequence || !validResult(entry.Result)) {
			return nil, ErrJournal
		}
		seen[entry.Intent.OperationSequence] = true
	}
	success = true
	return &Journal{path: path, lock: lock, state: saved, client: client, token: token}, nil
}
func (j *Journal) Close() error {
	j.recovered = false
	if j.lock == nil {
		return nil
	}
	lock := j.lock
	j.lock = nil
	return lock.Close()
}
func (j *Journal) save() (saveError error) {
	if j.lock == nil {
		return ErrJournal
	}
	defer func() {
		if saveError != nil {
			j.recovered = false
		}
	}()
	encoded, err := json.Marshal(j.state)
	if err != nil || len(encoded) > maxJournalBytes {
		return ErrJournal
	}
	file, err := os.CreateTemp(filepath.Dir(j.path), ".numbered-journal-")
	if err != nil {
		return ErrJournal
	}
	name := file.Name()
	defer os.Remove(name)
	if file.Chmod(0600) != nil {
		file.Close()
		return ErrJournal
	}
	if _, err = file.Write(encoded); err != nil || file.Sync() != nil {
		file.Close()
		return ErrJournal
	}
	if file.Close() != nil {
		return ErrJournal
	}
	if os.Rename(name, j.path) != nil {
		return ErrJournal
	}
	return syncParent(j.path)
}
func validResult(result *api.CommittedPublicationResult) bool {
	return result != nil && result.OperationSequence > 0 && result.Receipt != nil && len(result.Receipt.TransferId) == 32 && len(result.Receipt.EventId) == 32 && result.Receipt.AcceptanceMarker > 0 && (result.Content == api.CommittedContentStatus_COMMITTED_CONTENT_STATUS_AVAILABLE && result.RetirementReason == nil || result.Content == api.CommittedContentStatus_COMMITTED_CONTENT_STATUS_RETIRED && result.RetirementReason != nil && (*result.RetirementReason == api.RetirementReason_RETIREMENT_REASON_EXPIRED || *result.RetirementReason == api.RetirementReason_RETIREMENT_REASON_QUOTA_PRESSURE))
}
func (j *Journal) entry(sequence uint64) *Entry {
	for i := range j.state.Entries {
		if j.state.Entries[i].Intent.OperationSequence == sequence {
			return &j.state.Entries[i]
		}
	}
	return nil
}

// Recover fences the prior process and durably reconciles the complete snapshot.
// Retained committed results remain available for application before ack.
func (j *Journal) Recover(ctx context.Context) error {
	if j.lock == nil {
		return ErrJournal
	}
	j.recovered = false
	if j.state.Claim == nil {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return ErrJournal
		}
		j.state.Claim = &claim{Expected: j.state.Session, Nonce: nonce}
		if err := j.save(); err != nil {
			return err
		}
	}
	claimed, err := j.client.BeginEventPublicationSession(ctx, request(&api.BeginEventPublicationSessionRequest{ClientId: j.state.ClientID, ExpectedSession: j.state.Claim.Expected, ClaimNonce: j.state.Claim.Nonce}, j.token))
	if err != nil {
		return err
	}
	if claimed == nil || claimed.Msg == nil || claimed.Msg.Session == 0 || claimed.Msg.AllocatedThrough >= j.state.Next || claimed.Msg.AllocatedThrough < j.state.AllocatedThrough || len(claimed.Msg.Outstanding) > maxEntries {
		return ErrJournal
	}
	snapshot := claimed.Msg
	found := map[uint64]bool{}
	for _, result := range snapshot.Outstanding {
		if !validResult(result) || result.OperationSequence > snapshot.AllocatedThrough || found[result.OperationSequence] {
			return ErrJournal
		}
		entry := j.entry(result.OperationSequence)
		if entry == nil {
			return ErrJournal
		}
		if entry.Result != nil && (!proto.Equal(entry.Result.Receipt, result.Receipt) || entry.Result.OperationSequence != result.OperationSequence) {
			return ErrJournal
		}
		entry.Result = proto.Clone(result).(*api.CommittedPublicationResult)
		found[result.OperationSequence] = true
	}
	retained := make([]Entry, 0, len(j.state.Entries))
	for _, entry := range j.state.Entries {
		if entry.Intent.OperationSequence <= snapshot.AllocatedThrough && !found[entry.Intent.OperationSequence] {
			if !entry.Applied {
				return ErrJournal
			}
			continue
		}
		retained = append(retained, entry)
	}
	j.state.Entries = retained
	j.state.AllocatedThrough = snapshot.AllocatedThrough
	if err = j.save(); err != nil {
		return err
	}
	_, err = j.client.CompleteEventPublicationRecovery(ctx, request(&api.CompleteEventPublicationRecoveryRequest{ClientId: j.state.ClientID, Session: snapshot.Session, SnapshotRevision: snapshot.SnapshotRevision}, j.token))
	if err != nil {
		return err
	}
	j.state.Session = snapshot.Session
	j.state.Claim = nil
	if err = j.save(); err != nil {
		return err
	}
	j.recovered = true
	return nil
}
func (j *Journal) Entries() []Entry {
	entries := make([]Entry, len(j.state.Entries))
	for i, entry := range j.state.Entries {
		entries[i] = Entry{Intent: proto.Clone(entry.Intent).(*api.PublishNumberedEventRequest), Applied: entry.Applied}
		if entry.Result != nil {
			entries[i].Result = proto.Clone(entry.Result).(*api.CommittedPublicationResult)
		}
	}
	return entries
}

// Retain allocates one contiguous sequence only after prior intent is resolved.
func (j *Journal) Retain(intent *api.PublishNumberedEventRequest) (uint64, error) {
	if !j.recovered || len(j.state.Entries) >= maxEntries || j.state.Next == ^uint64(0) {
		return 0, ErrPending
	}
	for _, entry := range j.state.Entries {
		if entry.Result == nil {
			return 0, ErrPending
		}
	}
	if intent == nil || len(intent.Payload) > 65536 {
		return 0, ErrJournal
	}
	copy := proto.Clone(intent).(*api.PublishNumberedEventRequest)
	copy.ClientId = bytes.Clone(j.state.ClientID)
	copy.Session = 0
	copy.OperationSequence = j.state.Next
	j.state.Next++
	j.state.Entries = append(j.state.Entries, Entry{Intent: copy})
	if err := j.save(); err != nil {
		j.recovered = false
		return 0, err
	}
	return copy.OperationSequence, nil
}
func (j *Journal) Request(sequence uint64) (*api.PublishNumberedEventRequest, error) {
	entry := j.entry(sequence)
	if !j.recovered || entry == nil {
		return nil, ErrJournal
	}
	copy := proto.Clone(entry.Intent).(*api.PublishNumberedEventRequest)
	copy.Session = j.state.Session
	return copy, nil
}

// Publish retains the validated result before returning, and never discards a
// failed or ambiguous intent. Recovery uses the exact retained request.
func (j *Journal) Publish(ctx context.Context, sequence uint64) (*api.PublishNumberedEventResponse, error) {
	entry := j.entry(sequence)
	if !j.recovered || entry == nil {
		return nil, ErrJournal
	}
	if entry.Result != nil {
		return &api.PublishNumberedEventResponse{Result: proto.Clone(entry.Result).(*api.CommittedPublicationResult)}, nil
	}
	message, err := j.Request(sequence)
	if err != nil {
		return nil, err
	}
	response, err := j.client.PublishNumberedEvent(ctx, request(message, j.token))
	if err != nil {
		return nil, err
	}
	if response == nil || response.Msg == nil || !validResult(response.Msg.Result) || response.Msg.Result.OperationSequence != sequence || sequence != j.state.AllocatedThrough+1 {
		return nil, ErrJournal
	}
	entry.Result = proto.Clone(response.Msg.Result).(*api.CommittedPublicationResult)
	j.state.AllocatedThrough = sequence
	if err = j.save(); err != nil {
		j.recovered = false
		return nil, err
	}
	return response.Msg, nil
}

// Apply persists caller progress before making result acknowledgement possible.
func (j *Journal) Apply(sequence uint64) error {
	entry := j.entry(sequence)
	if !j.recovered || entry == nil || entry.Result == nil {
		return ErrJournal
	}
	entry.Applied = true
	return j.save()
}
func (j *Journal) Acknowledge(ctx context.Context, sequence uint64) error {
	entry := j.entry(sequence)
	if !j.recovered || entry == nil || !entry.Applied {
		return ErrJournal
	}
	_, err := j.client.AcknowledgeEventPublicationResult(ctx, request(&api.AcknowledgeEventPublicationResultRequest{ClientId: j.state.ClientID, Session: j.state.Session, OperationSequence: sequence}, j.token))
	if err != nil {
		return err
	}
	for i, entry := range j.state.Entries {
		if entry.Intent.OperationSequence == sequence {
			j.state.Entries = append(j.state.Entries[:i], j.state.Entries[i+1:]...)
			break
		}
	}
	return j.save()
}
