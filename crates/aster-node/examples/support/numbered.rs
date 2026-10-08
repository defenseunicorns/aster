//! Clean Room — Privileged.
//! Bounded, application-owned journal used by the native example programs.
//! One configured producer owns one redb writer and one pending full intent.
//! Opening never creates state; callers explicitly initialize a fresh journal.
#![allow(dead_code)] // Each example uses a different part of the fixture API.

use aster_node::application::{
    EventClientId, EventId, EventOperationSequence, EventPublicationSession, EventPublishOptions,
    EventPublishResult, EventQuery, EventRecoverySnapshot, NumberedEventPublishOutcome,
    NumberedEventPublishRequest, Priority, Scope, SelectedEventHandle, SelectedEventNode, Topic,
};
use redb::{Database, Durability, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fs::{File, OpenOptions},
    path::Path,
};

type Failure = Box<dyn Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Failure>;
const CHECKPOINT: TableDefinition<&str, &[u8]> =
    TableDefinition::new("native.example.publication.v1");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub predecessor: Option<[u8; 32]>,
    pub topic: String,
    pub scope: String,
    pub priority: u8,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
    pub ttl_ms: Option<u64>,
}
impl Intent {
    fn request(
        &self,
        client: EventClientId,
        session: u64,
        sequence: u64,
    ) -> Result<(NumberedEventPublishRequest, EventPublishOptions)> {
        if self.logical_key.len() > 64 || self.payload.len() > 4096 {
            return Err("native example intent exceeds its bounds".into());
        }
        Ok((
            NumberedEventPublishRequest {
                client_id: client,
                session: EventPublicationSession::new(session)?,
                sequence: EventOperationSequence::new(sequence)?,
                predecessor: self.predecessor.map(EventId::from_bytes),
                topic: Topic::new(self.topic.clone())?,
                scope: Scope::new(self.scope.clone())?,
                priority: Priority::from_wire(self.priority).ok_or("invalid priority")?,
                logical_key: self.logical_key.clone(),
                payload: self.payload.clone(),
                tombstone: self.tombstone,
            },
            match self.ttl_ms {
                Some(ttl) => EventPublishOptions::finite_ttl_ms(ttl)?,
                None => EventPublishOptions::durable(),
            },
        ))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    transfer: [u8; 32],
    semantic: [u8; 32],
    marker: u64,
}
impl Receipt {
    fn matches(&self, outcome: &aster_node::application::NumberedEventResult) -> bool {
        self.transfer == *outcome.receipt.transfer_id.as_bytes()
            && self.semantic == *outcome.receipt.semantic_id.as_bytes()
            && self.marker == outcome.receipt.acceptance_marker
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    sequence: u64,
    intent: Intent,
    receipt: Option<Receipt>,
    applied: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    client: Vec<u8>,
    session: u64,
    claim: Option<(u64, [u8; 32])>,
    next: u64,
    allocated: u64,
    pending: Option<Pending>,
}
pub struct Journal {
    poisoned: std::cell::Cell<bool>,
    database: Database,
    state: State,
    recovered: bool,
}

pub enum Backend<'a> {
    Stopped(&'a mut SelectedEventNode),
    Live(&'a SelectedEventHandle),
}
impl Backend<'_> {
    async fn begin(
        &mut self,
        client: EventClientId,
        expected: u64,
        nonce: [u8; 32],
    ) -> Result<EventRecoverySnapshot> {
        Ok(match self {
            Self::Stopped(node) => node.begin_publication_session(&client, expected, &nonce)?,
            Self::Live(node) => {
                node.begin_publication_session(client, expected, nonce.to_vec())
                    .await?
            }
        })
    }
    async fn complete(
        &mut self,
        client: EventClientId,
        snapshot: &EventRecoverySnapshot,
    ) -> Result<()> {
        match self {
            Self::Stopped(node) => node.complete_publication_recovery(
                &client,
                snapshot.session,
                snapshot.snapshot_revision,
            )?,
            Self::Live(node) => {
                node.complete_publication_recovery(
                    client,
                    snapshot.session,
                    snapshot.snapshot_revision,
                )
                .await?
            }
        }
        Ok(())
    }
    pub async fn publish(
        &mut self,
        request: NumberedEventPublishRequest,
        options: EventPublishOptions,
    ) -> Result<NumberedEventPublishOutcome> {
        Ok(match self {
            Self::Stopped(node) => node.publish_numbered(request, options)?,
            Self::Live(node) => node.publish_numbered(request, options).await?,
        })
    }
    async fn ack(&mut self, client: EventClientId, session: u64, sequence: u64) -> Result<()> {
        let session = EventPublicationSession::new(session)?;
        let sequence = EventOperationSequence::new(sequence)?;
        match self {
            Self::Stopped(node) => {
                node.acknowledge_publication_result(&client, session, sequence)?;
            }
            Self::Live(node) => {
                node.acknowledge_publication_result(client, session, sequence)
                    .await?;
            }
        }
        Ok(())
    }
    pub async fn metadata(
        &mut self,
        intent: &Intent,
        result: &NumberedEventPublishOutcome,
    ) -> Result<EventPublishResult> {
        let query = EventQuery {
            topic: Some(Topic::new(intent.topic.clone())?),
            scope: Some(Scope::new(intent.scope.clone())?),
            logical_key: Some(intent.logical_key.clone()),
            limit: 128,
            ..EventQuery::default()
        };
        let id = EventId::from_bytes(*result.result.receipt.semantic_id.as_bytes());
        let mut query = query;
        loop {
            let page = match self {
                Self::Stopped(node) => node.query(query.clone())?,
                Self::Live(node) => node.query(query.clone()).await?,
            };
            if let Some(event) = page.items.into_iter().find(|event| event.id == id) {
                return Ok(EventPublishResult {
                    id,
                    publisher: event.publisher,
                    publisher_counter: event.publisher_counter,
                    event_sequence: event.event_sequence,
                    priority: event.priority,
                    ttl_ms: event.ttl_ms,
                    acceptance_marker: result.result.receipt.acceptance_marker,
                    inserted: result.inserted,
                });
            }
            if !page.has_more {
                return Err("committed content is unavailable; retain its numbered receipt".into());
            }
            query.after_acceptance_marker = page.scanned_through;
        }
    }
}

fn file(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    if create {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let metadata = file.metadata()?;
    if !metadata.is_file() || (!create && metadata.len() == 0) {
        return Err("journal must be an existing nonempty regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err("journal must be owned and private".into());
        }
    }
    Ok(file)
}
impl Journal {
    pub fn initialize(path: &Path, client: &[u8]) -> Result<()> {
        EventClientId::new(client.to_vec())?;
        let parent = path.parent().ok_or("journal parent missing")?;
        if !parent.exists() {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder.create(parent)?;
        }
        let database = redb::Builder::new().create_file(file(path, true)?)?;
        let journal = Self {
            poisoned: std::cell::Cell::new(false),
            database,
            recovered: false,
            state: State {
                version: 1,
                client: client.to_vec(),
                session: 0,
                claim: None,
                next: 1,
                allocated: 0,
                pending: None,
            },
        };
        journal.save()?;
        File::open(path.parent().ok_or("journal parent missing")?)?.sync_all()?;
        Ok(())
    }
    pub fn open(path: &Path, client: &[u8]) -> Result<Self> {
        let database = redb::Builder::new().create_file(file(path, false)?)?;
        let read = database.begin_read()?;
        let table = read.open_table(CHECKPOINT)?;
        let raw = table.get("state")?.ok_or("journal metadata missing")?;
        if raw.value().len() > 16 * 1024 {
            return Err("journal metadata exceeds bound".into());
        }
        let state: State = serde_json::from_slice(raw.value())?;
        let client_id = EventClientId::new(client.to_vec())?;
        if state.version != 1
            || state.client != client
            || state.next == 0
            || state.allocated >= state.next
            || state
                .claim
                .is_some_and(|(expected, _)| expected != state.session)
            || state.pending.as_ref().is_some_and(|pending| {
                pending.sequence == 0
                    || pending.sequence.checked_add(1) != Some(state.next)
                    || (pending.applied && pending.receipt.is_none())
            })
            || (state.pending.is_none() && state.allocated.checked_add(1) != Some(state.next))
        {
            return Err("native journal state is inconsistent".into());
        }
        if let Some(pending) = &state.pending {
            pending
                .intent
                .request(client_id, state.session.max(1), pending.sequence)?;
        }
        drop(raw);
        drop(table);
        drop(read);
        Ok(Self {
            poisoned: std::cell::Cell::new(false),
            database,
            state,
            recovered: false,
        })
    }
    fn ensure_usable(&self) -> Result<()> {
        if self.poisoned.get() {
            return Err("journal persistence failed; close and recover before further RPCs".into());
        }
        Ok(())
    }
    fn save(&self) -> Result<()> {
        self.ensure_usable()?;
        let result = self.persist();
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }
    fn persist(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.state)?;
        if bytes.len() > 16 * 1024 {
            return Err("native journal exceeds bound".into());
        }
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        {
            write
                .open_table(CHECKPOINT)?
                .insert("state", bytes.as_slice())?;
        }
        write.commit()?;
        Ok(())
    }
    fn client(&self) -> Result<EventClientId> {
        Ok(EventClientId::new(self.state.client.clone())?)
    }
    pub fn pending(&self) -> Option<(u64, &Intent)> {
        self.state.pending.as_ref().map(|p| (p.sequence, &p.intent))
    }
    pub async fn recover(&mut self, backend: &mut Backend<'_>) -> Result<()> {
        self.ensure_usable()?;
        if self.state.claim.is_none() {
            let mut nonce = [0; 32];
            getrandom::fill(&mut nonce)?;
            self.state.claim = Some((self.state.session, nonce));
            self.save()?;
        }
        let (expected, nonce) = self.state.claim.ok_or("missing claim")?;
        let snapshot = backend.begin(self.client()?, expected, nonce).await?;
        if snapshot.allocated_through < self.state.allocated
            || snapshot.allocated_through >= self.state.next
            || snapshot.outstanding.iter().any(|result| {
                self.state.pending.as_ref().is_none_or(|p| {
                    p.sequence != result.sequence.get()
                        || p.receipt.as_ref().is_some_and(|r| !r.matches(result))
                })
            })
            || self.state.pending.as_ref().is_some_and(|p| {
                p.sequence <= snapshot.allocated_through
                    && !p.applied
                    && !snapshot
                        .outstanding
                        .iter()
                        .any(|r| r.sequence.get() == p.sequence)
            })
            || (self.state.pending.is_none()
                && snapshot.allocated_through.checked_add(1) != Some(self.state.next))
        {
            return Err("native recovery does not match retained intent and receipt".into());
        }
        backend.complete(self.client()?, &snapshot).await?;
        self.state.session = snapshot.session.get();
        self.state.allocated = snapshot.allocated_through;
        self.state.claim = None;
        self.save()?;
        self.recovered = true;
        if self.state.pending.as_ref().is_some_and(|p| p.applied) {
            self.acknowledge(backend).await?;
        }
        Ok(())
    }
    pub async fn publish(
        &mut self,
        backend: &mut Backend<'_>,
        intent: Intent,
    ) -> Result<NumberedEventPublishOutcome> {
        self.ensure_usable()?;
        if !self.recovered {
            return Err("native publication requires recovery".into());
        }
        if let Some(pending) = &self.state.pending {
            if pending.intent != intent {
                return Err("pending intent must be resolved before new work".into());
            }
        } else {
            intent.request(self.client()?, self.state.session, self.state.next)?;
            let sequence = self.state.next;
            self.state.next = sequence.checked_add(1).ok_or("sequence exhausted")?;
            self.state.pending = Some(Pending {
                sequence,
                intent,
                receipt: None,
                applied: false,
            });
            self.save()?;
        }
        let pending = self
            .state
            .pending
            .as_ref()
            .ok_or("pending intent missing")?;
        let (request, options) =
            pending
                .intent
                .request(self.client()?, self.state.session, pending.sequence)?;
        let result = backend.publish(request, options).await?;
        if result.result.sequence.get() != pending.sequence
            || pending
                .receipt
                .as_ref()
                .is_some_and(|r| !r.matches(&result.result))
        {
            return Err("publication changed its immutable receipt".into());
        }
        self.state.allocated = pending.sequence;
        self.state
            .pending
            .as_mut()
            .ok_or("pending intent missing")?
            .receipt = Some(Receipt {
            transfer: *result.result.receipt.transfer_id.as_bytes(),
            semantic: *result.result.receipt.semantic_id.as_bytes(),
            marker: result.result.receipt.acceptance_marker,
        });
        self.save()?;
        Ok(result)
    }
    pub async fn publish_metadata(
        &mut self,
        backend: &mut Backend<'_>,
        intent: Intent,
    ) -> Result<EventPublishResult> {
        let result = self.publish(backend, intent.clone()).await?;
        backend.metadata(&intent, &result).await
    }

    /// Caller has applied/retained the result. Persist that fact before releasing it.
    pub async fn acknowledge(&mut self, backend: &mut Backend<'_>) -> Result<()> {
        self.ensure_usable()?;
        if !self.recovered {
            return Err("acknowledgement requires recovery".into());
        }
        let pending = self.state.pending.as_mut().ok_or("no pending result")?;
        if pending.receipt.is_none() {
            return Err("pending publication has no observed receipt".into());
        }
        pending.applied = true;
        let sequence = pending.sequence;
        self.save()?;
        backend
            .ack(self.client()?, self.state.session, sequence)
            .await?;
        self.state.pending = None;
        self.save()
    }
    /// Explicit negative-test probe, never overwrites the journaled original intent.
    pub async fn probe_changed(
        &self,
        backend: &mut Backend<'_>,
        intent: &Intent,
    ) -> Result<NumberedEventPublishOutcome> {
        let pending = self
            .state
            .pending
            .as_ref()
            .ok_or("no retained operation to probe")?;
        self.ensure_usable()?;
        if !self.recovered {
            return Err("probe requires recovery".into());
        }
        let (request, options) =
            intent.request(self.client()?, self.state.session, pending.sequence)?;
        backend.publish(request, options).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
    use aster_node::mission::UnprotectedReferenceMission;
    struct Root(std::path::PathBuf);
    impl Root {
        fn new() -> Self {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).unwrap();
            let name: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("aster-native-publication-{name}"));
            std::fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn fixture(root: &Root) -> (std::path::PathBuf, std::path::PathBuf, Intent) {
        let scope = Scope::new("native/journal").unwrap();
        let topic = Topic::new("native.journal").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()]).unwrap();
        let mut seed = [0; 32];
        getrandom::fill(&mut seed).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed(seed).unwrap();
        let bundle = root.0.join("mission.bundle");
        UnprotectedReferenceMission::persist(
            &bundle,
            provisioner
                .issue_node(1, &[access])
                .unwrap()
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        (
            root.0.join("state"),
            bundle,
            Intent {
                predecessor: None,
                topic: topic.as_str().into(),
                scope: scope.as_str().into(),
                priority: 1,
                logical_key: b"key".to_vec(),
                payload: b"original\0intent".to_vec(),
                tombstone: false,
                ttl_ms: None,
            },
        )
    }
    #[tokio::test]
    async fn lost_commit_reply_recovers_original_before_next_allocation() {
        let root = Root::new();
        let (state, bundle, intent) = fixture(&root);
        let path = root.0.join("publication.redb");
        let client = b"native-journal-test";
        Journal::initialize(&path, client).unwrap();
        let mut journal = Journal::open(&path, client).unwrap();
        let mut node = SelectedEventNode::open_unprotected_reference(&state, &bundle).unwrap();
        journal
            .recover(&mut Backend::Stopped(&mut node))
            .await
            .unwrap();
        // Durable assignment precedes the RPC. Simulate process loss after the
        // node commits, before the journal observes the reply.
        journal.state.next = 2;
        journal.state.pending = Some(Pending {
            sequence: 1,
            intent: intent.clone(),
            receipt: None,
            applied: false,
        });
        journal.save().unwrap();
        let (request, options) = intent
            .request(journal.client().unwrap(), journal.state.session, 1)
            .unwrap();
        let original = node.publish_numbered(request, options).unwrap();
        assert!(original.inserted);
        drop(journal);
        drop(node);
        let mut journal = Journal::open(&path, client).unwrap();
        let mut node = SelectedEventNode::open_unprotected_reference(&state, &bundle).unwrap();
        journal
            .recover(&mut Backend::Stopped(&mut node))
            .await
            .unwrap();
        let mut changed = intent.clone();
        changed.payload = b"different".to_vec();
        assert!(
            journal
                .publish(&mut Backend::Stopped(&mut node), changed.clone())
                .await
                .is_err()
        );
        let recovered = journal
            .publish(&mut Backend::Stopped(&mut node), intent.clone())
            .await
            .unwrap();
        assert!(!recovered.inserted);
        assert_eq!(original.result, recovered.result);
        let metadata = Backend::Stopped(&mut node)
            .metadata(&intent, &recovered)
            .await
            .unwrap();
        assert_eq!(
            metadata.id.as_bytes(),
            recovered.result.receipt.semantic_id.as_bytes()
        );
        assert_eq!(metadata.event_sequence, 1);
        assert!(
            journal
                .probe_changed(&mut Backend::Stopped(&mut node), &changed)
                .await
                .is_err()
        );
        // Applied result was acknowledged remotely, but its local cleanup was lost.
        journal.state.pending.as_mut().unwrap().applied = true;
        journal.save().unwrap();
        Backend::Stopped(&mut node)
            .ack(journal.client().unwrap(), journal.state.session, 1)
            .await
            .unwrap();
        drop(journal);
        drop(node);
        let mut journal = Journal::open(&path, client).unwrap();
        let mut node = SelectedEventNode::open_unprotected_reference(&state, &bundle).unwrap();
        journal
            .recover(&mut Backend::Stopped(&mut node))
            .await
            .unwrap();
        assert!(journal.pending().is_none());
        let next = journal
            .publish(&mut Backend::Stopped(&mut node), changed)
            .await
            .unwrap();
        assert_eq!(next.result.sequence.get(), 2);
        assert!(next.inserted);
        journal
            .acknowledge(&mut Backend::Stopped(&mut node))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn invalid_missing_busy_and_failed_persistence_never_claim() {
        let root = Root::new();
        let path = root.0.join("publication.redb");
        let client = b"native-journal-test";
        assert!(Journal::open(&path, client).is_err());
        assert!(!path.exists());
        Journal::initialize(&path, client).unwrap();
        assert!(Journal::initialize(&path, client).is_err());
        assert!(Journal::open(&path, b"wrong-client").is_err());
        let mut journal = Journal::open(&path, client).unwrap();
        assert!(Journal::open(&path, client).is_err());
        let (state, bundle, intent) = fixture(&root);
        let mut node = SelectedEventNode::open_unprotected_reference(&state, &bundle).unwrap();
        journal.state.pending = Some(Pending {
            sequence: 1,
            intent,
            receipt: None,
            applied: false,
        });
        journal
            .state
            .pending
            .as_mut()
            .unwrap()
            .intent
            .payload
            .resize(20_000, 0);
        assert!(journal.save().is_err());
        assert!(
            journal
                .recover(&mut Backend::Stopped(&mut node))
                .await
                .is_err()
        );
        // Failure poisons this owner. The durable state remains the last good
        // initialization, and another owner can safely recover it.
        drop(journal);
        let mut reopened = Journal::open(&path, client).unwrap();
        assert!(reopened.pending().is_none());
        reopened
            .recover(&mut Backend::Stopped(&mut node))
            .await
            .unwrap();
        assert_eq!(reopened.state.session, 1);
        drop(reopened);
        std::fs::write(&path, b"not redb").unwrap();
        assert!(Journal::open(&path, client).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"not redb");
    }
}
