//! Crash-safe client support for numbered Event publication.
//!
//! The journal is protocol state rather than a cache. It must be explicitly
//! initialized once and is then opened exclusively. Opening never creates or
//! repairs a missing or corrupt journal.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use connectrpc::client::{ClientTransport, UnaryResponse};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::proto::aster::application::v1alpha1 as api;

const JOURNAL_META: TableDefinition<&str, &[u8]> =
    TableDefinition::new("aster.event-publication-journal.meta.v1");
const JOURNAL_ENTRIES: TableDefinition<u64, &[u8]> =
    TableDefinition::new("aster.event-publication-journal.entries.v1");
const STATE_KEY: &str = "state";
const JOURNAL_VERSION: u32 = 1;
const CLAIM_NONCE_BYTES: usize = 32;

/// An error that prevents the SDK from safely changing publication state.
#[derive(Debug)]
pub enum NumberedEventSdkError {
    Journal(String),
    Protocol(String),
    Transport(connectrpc::ConnectError),
}

impl fmt::Display for NumberedEventSdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(message) => write!(formatter, "publication journal: {message}"),
            Self::Protocol(message) => write!(formatter, "publication protocol: {message}"),
            Self::Transport(error) => write!(formatter, "publication transport: {error}"),
        }
    }
}

impl std::error::Error for NumberedEventSdkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Journal(_) | Self::Protocol(_) => None,
        }
    }
}

impl From<connectrpc::ConnectError> for NumberedEventSdkError {
    fn from(value: connectrpc::ConnectError) -> Self {
        Self::Transport(value)
    }
}

/// A publication failure that says whether durable sequence assignment happened.
#[derive(Debug)]
pub enum PublicationError {
    /// The journal could not assign a sequence; there is no operation to resume.
    BeforeAssignment(NumberedEventSdkError),
    /// The intent is journaled at sequence; recover or resume that operation.
    Assigned {
        sequence: u64,
        source: NumberedEventSdkError,
    },
}

impl PublicationError {
    /// Returns the durable sequence when an intent was assigned.
    pub fn assigned_sequence(&self) -> Option<u64> {
        match self {
            Self::BeforeAssignment(_) => None,
            Self::Assigned { sequence, .. } => Some(*sequence),
        }
    }

    /// Returns the underlying journal, protocol, or transport error.
    pub fn sdk_error(&self) -> &NumberedEventSdkError {
        match self {
            Self::BeforeAssignment(error) | Self::Assigned { source: error, .. } => error,
        }
    }
}

impl fmt::Display for PublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeAssignment(error) => {
                write!(formatter, "publication was not assigned: {error}")
            }
            Self::Assigned { sequence, source } => {
                write!(
                    formatter,
                    "publication sequence {sequence} was assigned: {source}"
                )
            }
        }
    }
}

impl std::error::Error for PublicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.sdk_error())
    }
}
type Result<T> = std::result::Result<T, NumberedEventSdkError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JournalState {
    version: u32,
    client_id: Vec<u8>,
    session: u64,
    allocated_through: u64,
    snapshot_revision: u64,
    recovery_complete: bool,
    pending_claim: Option<PendingClaim>,
    next_sequence: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingClaim {
    expected_session: u64,
    nonce: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JournalEntry {
    intent: api::PublishNumberedEventRequest,
    result: Option<api::CommittedPublicationResult>,
    abandoned: bool,
}
/// State discovered while reconciling a durable publication journal.
#[derive(Clone, Debug, PartialEq)]
pub enum RecoveredState {
    /// The intent is journaled above the server frontier; publish or abandon it.
    Pending,
    /// The server retains a committed result; apply it idempotently, then acknowledge.
    Committed(api::CommittedPublicationResult),
    /// The server has permanently consumed the sequence; no action is required.
    Retired,
}

/// One locally journaled operation found during recovery.
#[derive(Clone, Debug, PartialEq)]
pub struct RecoveredOperation {
    /// The positive operation sequence assigned by the journal.
    pub sequence: u64,
    /// The one action state proved by the recovered server snapshot.
    pub state: RecoveredState,
}

/// Ordered recovery result returned only after durable reconciliation and completion.
#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryReport {
    /// The fenced publication session completed by this recovery.
    pub session: u64,
    /// The server's durable allocated sequence frontier.
    pub allocated_through: u64,
    /// Locally journaled operations in ascending sequence order.
    pub operations: Vec<RecoveredOperation>,
}

/// Exclusive, transactional publication state for one stable client ID.
pub struct PublicationJournal {
    database: Database,
    path: PathBuf,
}

impl PublicationJournal {
    /// Creates a new journal. Existing paths are refused instead of reused.
    pub fn initialize(path: impl AsRef<Path>, client_id: &[u8]) -> Result<()> {
        validate_client_id(client_id)?;
        let path = path.as_ref();
        let file = open_journal_file(path, true)?;
        let database = redb::Builder::new()
            .create_file(file)
            .map_err(|error| journal_error(path, "initialize", error))?;
        let state = JournalState {
            version: JOURNAL_VERSION,
            client_id: client_id.to_vec(),
            session: 0,
            allocated_through: 0,
            snapshot_revision: 0,
            recovery_complete: false,
            pending_claim: None,
            next_sequence: Some(1),
        };
        let mut write = database
            .begin_write()
            .map_err(|error| journal_error(path, "begin initialization", error))?;
        write
            .set_durability(Durability::Immediate)
            .map_err(|error| journal_error(path, "set durability", error))?;
        {
            let mut meta = write
                .open_table(JOURNAL_META)
                .map_err(|error| journal_error(path, "create metadata", error))?;
            let encoded = encode_json(&state)?;
            meta.insert(STATE_KEY, encoded.as_slice())
                .map_err(|error| journal_error(path, "write metadata", error))?;
            write
                .open_table(JOURNAL_ENTRIES)
                .map_err(|error| journal_error(path, "create entries", error))?;
        }
        write
            .commit()
            .map_err(|error| journal_error(path, "commit initialization", error))
    }

    /// Opens an existing journal and acquires redb's exclusive writer lock.
    pub fn open(path: impl AsRef<Path>, client_id: &[u8]) -> Result<Self> {
        validate_client_id(client_id)?;
        let path = path.as_ref().to_path_buf();
        let file = open_journal_file(&path, false)?;
        // create_file keeps the already validated descriptor and redb's writer
        // exclusion. Empty existing files are refused by open_journal_file, so
        // this cannot silently initialize a missing or empty journal.
        let database = redb::Builder::new()
            .create_file(file)
            .map_err(|error| journal_error(&path, "open exclusively", error))?;
        let journal = Self { database, path };
        let state = journal.read_state()?;
        if state.version != JOURNAL_VERSION {
            return Err(NumberedEventSdkError::Journal(format!(
                "unsupported journal version {}",
                state.version
            )));
        }
        if state.client_id != client_id {
            return Err(NumberedEventSdkError::Journal(
                "configured client_id does not match the durable journal".to_owned(),
            ));
        }
        journal.audit_entries(&state)?;
        journal.update_state(|state| {
            state.recovery_complete = false;
            Ok(())
        })?;
        Ok(journal)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_state(&self) -> Result<JournalState> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| journal_error(&self.path, "read metadata", error))?;
        let table = read
            .open_table(JOURNAL_META)
            .map_err(|error| journal_error(&self.path, "open metadata", error))?;
        let value = table
            .get(STATE_KEY)
            .map_err(|error| journal_error(&self.path, "get metadata", error))?
            .ok_or_else(|| NumberedEventSdkError::Journal("metadata is missing".to_owned()))?;
        decode_json(value.value(), "metadata")
    }

    fn update_state(&self, update: impl FnOnce(&mut JournalState) -> Result<()>) -> Result<()> {
        self.write(|state, _entries| update(state))
    }

    fn write(
        &self,
        update: impl FnOnce(&mut JournalState, &mut redb::Table<'_, u64, &[u8]>) -> Result<()>,
    ) -> Result<()> {
        let mut write = self
            .database
            .begin_write()
            .map_err(|error| journal_error(&self.path, "begin transaction", error))?;
        write
            .set_durability(Durability::Immediate)
            .map_err(|error| journal_error(&self.path, "set durability", error))?;
        {
            let mut meta = write
                .open_table(JOURNAL_META)
                .map_err(|error| journal_error(&self.path, "open metadata", error))?;
            let value = meta
                .get(STATE_KEY)
                .map_err(|error| journal_error(&self.path, "get metadata", error))?
                .ok_or_else(|| NumberedEventSdkError::Journal("metadata is missing".to_owned()))?;
            let mut state: JournalState = decode_json(value.value(), "metadata")?;
            drop(value);
            let mut entries = write
                .open_table(JOURNAL_ENTRIES)
                .map_err(|error| journal_error(&self.path, "open entries", error))?;
            update(&mut state, &mut entries)?;
            let encoded = encode_json(&state)?;
            meta.insert(STATE_KEY, encoded.as_slice())
                .map_err(|error| journal_error(&self.path, "write metadata", error))?;
        }
        write
            .commit()
            .map_err(|error| journal_error(&self.path, "commit transaction", error))
    }

    fn audit_entries(&self, state: &JournalState) -> Result<()> {
        if state
            .next_sequence
            .is_some_and(|next| next == 0 || next <= state.allocated_through)
        {
            return Err(NumberedEventSdkError::Journal(
                "sequence frontier is invalid".to_owned(),
            ));
        }
        if let Some(claim) = &state.pending_claim
            && (claim.nonce.len() != CLAIM_NONCE_BYTES || claim.expected_session != state.session)
        {
            return Err(NumberedEventSdkError::Journal(
                "pending session claim is invalid".to_owned(),
            ));
        }
        let read = self
            .database
            .begin_read()
            .map_err(|error| journal_error(&self.path, "audit", error))?;
        let table = read
            .open_table(JOURNAL_ENTRIES)
            .map_err(|error| journal_error(&self.path, "open entries", error))?;
        let iter = table
            .iter()
            .map_err(|error| journal_error(&self.path, "iterate entries", error))?;
        for row in iter {
            let (key, value) =
                row.map_err(|error| journal_error(&self.path, "read entry", error))?;
            let sequence = key.value();
            let entry: JournalEntry = decode_json(value.value(), "entry")?;
            if sequence == 0
                || state.next_sequence.is_some_and(|next| sequence >= next)
                || entry.intent.operation_sequence != sequence
                || entry.intent.client_id != state.client_id
                || entry
                    .result
                    .as_ref()
                    .is_some_and(|result| result.operation_sequence != sequence)
                || (entry.abandoned && entry.result.is_some())
            {
                return Err(NumberedEventSdkError::Journal(format!(
                    "entry {sequence} is inconsistent"
                )));
            }
        }
        Ok(())
    }

    fn entry(&self, sequence: u64) -> Result<Option<JournalEntry>> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| journal_error(&self.path, "read entry", error))?;
        let table = read
            .open_table(JOURNAL_ENTRIES)
            .map_err(|error| journal_error(&self.path, "open entries", error))?;
        table
            .get(sequence)
            .map_err(|error| journal_error(&self.path, "get entry", error))?
            .map(|value| decode_json(value.value(), "entry"))
            .transpose()
    }
}

fn open_journal_file(path: &Path, create: bool) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|error| journal_error(path, "open journal", error))?;
    #[cfg(unix)]
    if create {
        use std::os::unix::fs::PermissionsExt as _;
        // Creation mode is filtered by umask. Restore owner read/write on the
        // same descriptor before initializing the journal, without granting
        // group/other access or changing permissions on existing journals.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| journal_error(path, "set journal permissions", error))?;
    }
    let metadata = file
        .metadata()
        .map_err(|error| journal_error(path, "inspect journal", error))?;
    if !metadata.is_file() || (!create && metadata.len() == 0) {
        return Err(NumberedEventSdkError::Journal("journal must be a regular, nonempty existing file; explicit initialization is required".to_owned()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(NumberedEventSdkError::Journal(
                "journal must be owned by the current user with no group or other permissions"
                    .to_owned(),
            ));
        }
    }
    Ok(file)
}

/// A generated Connect client paired with its durable numbered-operation journal.
pub struct NumberedEventSdk<T> {
    client: api::AsterApplicationServiceClient<T>,
    journal: PublicationJournal,
}

impl<T> NumberedEventSdk<T>
where
    T: ClientTransport,
    <T::ResponseBody as connectrpc::http_body::Body>::Error: fmt::Display,
{
    /// Opens durable state without contacting the agent. Call [`Self::recover`]
    /// before allocating, publishing, abandoning, or acknowledging work.
    pub fn open(
        client: api::AsterApplicationServiceClient<T>,
        journal_path: impl AsRef<Path>,
        client_id: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            client,
            journal: PublicationJournal::open(journal_path, client_id)?,
        })
    }

    pub fn journal_path(&self) -> &Path {
        self.journal.path()
    }

    pub fn session(&self) -> Result<u64> {
        Ok(self.journal.read_state()?.session)
    }

    /// Claims or idempotently resumes this process session and persists the
    /// complete recovery snapshot before returning.
    pub async fn begin_recovery(&self) -> Result<()> {
        self.begin_recovery_report().await.map(|_| ())
    }

    async fn begin_recovery_report(&self) -> Result<RecoveryReport> {
        let mut state = self.journal.read_state()?;
        let claim = if let Some(claim) = state.pending_claim.clone() {
            claim
        } else {
            let mut nonce = vec![0; CLAIM_NONCE_BYTES];
            getrandom::fill(&mut nonce).map_err(|error| {
                NumberedEventSdkError::Journal(format!("generate claim nonce: {error}"))
            })?;
            let claim = PendingClaim {
                expected_session: state.session,
                nonce,
            };
            self.journal.update_state(|state| {
                state.pending_claim = Some(claim.clone());
                state.recovery_complete = false;
                Ok(())
            })?;
            claim
        };
        let response = self
            .client
            .begin_event_publication_session(api::BeginEventPublicationSessionRequest {
                client_id: state.client_id.clone(),
                expected_session: claim.expected_session,
                claim_nonce: claim.nonce.clone(),
                ..Default::default()
            })
            .await?
            .into_owned();
        if claim.expected_session.checked_add(1) != Some(response.session)
            || response.allocated_through < state.allocated_through
            || response.snapshot_revision == 0
            || response.snapshot_revision < state.snapshot_revision
            || (response.snapshot_revision == state.snapshot_revision
                && response.allocated_through != state.allocated_through)
        {
            return Err(NumberedEventSdkError::Protocol(
                "recovery snapshot has an invalid session, frontier, or revision".to_owned(),
            ));
        }
        // Validate the complete snapshot against durable rows before opening a
        // write transaction. A rejected response changes only the prior claim.
        let mut outstanding = BTreeMap::new();
        for result in &response.outstanding {
            let sequence = result.operation_sequence;
            if sequence == 0
                || sequence > response.allocated_through
                || outstanding.insert(sequence, result).is_some()
            {
                return Err(NumberedEventSdkError::Protocol(format!(
                    "recovery snapshot has an invalid or duplicate sequence {sequence}"
                )));
            }
            validate_committed_result(result)?;
            let entry = self.journal.entry(sequence)?.ok_or_else(|| {
                NumberedEventSdkError::Protocol(format!(
                    "agent returned unknown journal sequence {sequence}"
                ))
            })?;
            if entry.abandoned {
                return Err(NumberedEventSdkError::Protocol(format!(
                    "agent resurrected abandoned sequence {sequence}"
                )));
            }
            if let Some(previous) = &entry.result {
                validate_committed_result(previous)?;
                let same = previous == result;
                let retirement = previous.content == api::CommittedContentStatus::Available
                    && result.content == api::CommittedContentStatus::Retired
                    && previous.receipt == result.receipt;
                if !same && !retirement {
                    return Err(NumberedEventSdkError::Protocol(format!(
                        "agent replaced committed result for sequence {sequence}"
                    )));
                }
            }
        }
        if response.snapshot_revision == state.snapshot_revision {
            // An unchanged server revision proves an unchanged server image.
            // Old abandoned rows are local cleanup residue, not server results.
            let read = self.journal.database.begin_read().map_err(|error| {
                journal_error(self.journal.path(), "read equal-revision entries", error)
            })?;
            let entries = read.open_table(JOURNAL_ENTRIES).map_err(|error| {
                journal_error(self.journal.path(), "open equal-revision entries", error)
            })?;
            let iter = entries.iter().map_err(|error| {
                journal_error(self.journal.path(), "scan equal-revision entries", error)
            })?;
            for row in iter {
                let (key, value) = row.map_err(|error| {
                    journal_error(self.journal.path(), "read equal-revision entry", error)
                })?;
                let sequence = key.value();
                if sequence > state.allocated_through {
                    break;
                }
                let entry: JournalEntry = decode_json(value.value(), "entry")?;
                if entry.abandoned && !outstanding.contains_key(&sequence) {
                    continue;
                }
                if !entry.result.as_ref().is_some_and(|saved| {
                    outstanding
                        .get(&sequence)
                        .is_some_and(|current| *current == saved)
                }) {
                    return Err(NumberedEventSdkError::Protocol(format!(
                        "equal-revision recovery changed sequence {sequence}"
                    )));
                }
            }
        }
        let mut operations = Vec::new();
        self.journal.write(|journal_state, entries| {
            if journal_state.pending_claim.as_ref().is_none_or(|pending| {
                pending.expected_session != claim.expected_session || pending.nonce != claim.nonce
            }) {
                return Err(NumberedEventSdkError::Journal(
                    "session claim changed while an RPC was in flight".to_owned(),
                ));
            }
            for result in &response.outstanding {
                let sequence = result.operation_sequence;
                let value = entries
                    .get(sequence)
                    .map_err(|error| {
                        journal_error(self.journal.path(), "get recovered entry", error)
                    })?
                    .ok_or_else(|| {
                        NumberedEventSdkError::Protocol(format!(
                            "agent returned unknown journal sequence {sequence}"
                        ))
                    })?;
                let mut entry: JournalEntry = decode_json(value.value(), "entry")?;
                drop(value);
                entry.result = Some(result.clone());
                entry.abandoned = false;
                let encoded = encode_json(&entry)?;
                entries
                    .insert(sequence, encoded.as_slice())
                    .map_err(|error| {
                        journal_error(self.journal.path(), "store recovered result", error)
                    })?;
            }
            let mut retired = Vec::new();
            let iter = entries.iter().map_err(|error| {
                journal_error(self.journal.path(), "scan recovered entries", error)
            })?;
            for row in iter {
                let (key, _value) = row.map_err(|error| {
                    journal_error(self.journal.path(), "read recovered entry", error)
                })?;
                let sequence = key.value();
                let state = if let Some(result) = outstanding.get(&sequence) {
                    RecoveredState::Committed((*result).clone())
                } else if sequence <= response.allocated_through {
                    retired.push(sequence);
                    RecoveredState::Retired
                } else {
                    RecoveredState::Pending
                };
                operations.push(RecoveredOperation { sequence, state });
            }
            for sequence in retired {
                entries.remove(sequence).map_err(|error| {
                    journal_error(self.journal.path(), "remove consumed entry", error)
                })?;
            }
            journal_state.session = response.session;
            journal_state.allocated_through = response.allocated_through;
            journal_state.snapshot_revision = response.snapshot_revision;
            journal_state.pending_claim = None;
            journal_state.recovery_complete = false;
            journal_state.next_sequence = match (
                journal_state.next_sequence,
                response.allocated_through.checked_add(1),
            ) {
                (Some(local), Some(agent)) => Some(local.max(agent)),
                (None, _) | (_, None) => None,
            };
            Ok(())
        })?;
        state = self.journal.read_state()?;
        if state.session != response.session {
            return Err(NumberedEventSdkError::Journal(
                "recovered session was not persisted".to_owned(),
            ));
        }
        Ok(RecoveryReport {
            session: response.session,
            allocated_through: response.allocated_through,
            operations,
        })
    }

    /// Completes the saved snapshot. Repeating this after a lost response is
    /// safe because the same session and snapshot revision remain journaled.
    pub async fn complete_recovery(&self) -> Result<()> {
        let state = self.journal.read_state()?;
        if state.session == 0 || state.pending_claim.is_some() {
            return Err(NumberedEventSdkError::Protocol(
                "begin_recovery has not durably completed".to_owned(),
            ));
        }
        self.client
            .complete_event_publication_recovery(api::CompleteEventPublicationRecoveryRequest {
                client_id: state.client_id.clone(),
                session: state.session,
                snapshot_revision: state.snapshot_revision,
                ..Default::default()
            })
            .await?;
        self.journal.update_state(|current| {
            if current.session != state.session
                || current.snapshot_revision != state.snapshot_revision
            {
                return Err(NumberedEventSdkError::Journal(
                    "recovery state changed while completion was in flight".to_owned(),
                ));
            }
            current.recovery_complete = true;
            Ok(())
        })
    }

    /// Reconciles the journal and returns ordered work only after completion
    /// succeeds and is durably marked complete.
    pub async fn recover(&self) -> Result<RecoveryReport> {
        let report = self.begin_recovery_report().await?;
        self.complete_recovery().await?;
        Ok(report)
    }

    /// Durably assigns the next positive sequence before any request can be sent.
    pub fn journal_publication(&self, mut intent: api::PublishNumberedEventRequest) -> Result<u64> {
        let mut assigned = 0;
        self.journal.write(|state, entries| {
            require_recovered(state)?;
            assigned = state.next_sequence.ok_or_else(|| {
                NumberedEventSdkError::Protocol("operation sequence exhausted".to_owned())
            })?;
            intent.client_id.clone_from(&state.client_id);
            intent.session = state.session;
            intent.operation_sequence = assigned;
            let entry = JournalEntry {
                intent: intent.clone(),
                result: None,
                abandoned: false,
            };
            let encoded = encode_json(&entry)?;
            entries
                .insert(assigned, encoded.as_slice())
                .map_err(|error| {
                    journal_error(self.journal.path(), "journal publication", error)
                })?;
            state.next_sequence = assigned.checked_add(1);
            Ok(())
        })?;
        Ok(assigned)
    }

    /// Sends only a previously journaled intent and persists its result before
    /// exposing it to the caller.
    pub async fn publish_journaled(
        &self,
        sequence: u64,
    ) -> Result<api::CommittedPublicationResult> {
        let state = self.journal.read_state()?;
        require_recovered(&state)?;
        let mut entry = self.journal.entry(sequence)?.ok_or_else(|| {
            NumberedEventSdkError::Journal(format!("sequence {sequence} is not journaled"))
        })?;
        if entry.abandoned {
            return Err(NumberedEventSdkError::Protocol(format!(
                "sequence {sequence} is permanently retired"
            )));
        }
        if let Some(result) = entry.result {
            return Ok(result);
        }
        if sequence != state.allocated_through + 1 {
            return Err(NumberedEventSdkError::Protocol(format!(
                "sequence {sequence} is not the next first admission"
            )));
        }
        entry.intent.client_id.clone_from(&state.client_id);
        entry.intent.session = state.session;
        let response = self
            .client
            .publish_numbered_event(entry.intent.clone())
            .await?
            .into_owned();
        let result = response.result.as_option().cloned().ok_or_else(|| {
            NumberedEventSdkError::Protocol(
                "publication response omitted its committed result".to_owned(),
            )
        })?;
        if result.operation_sequence != sequence {
            return Err(NumberedEventSdkError::Protocol(
                "publication response returned a different sequence".to_owned(),
            ));
        }
        self.journal.write(|current, entries| {
            require_recovered(current)?;
            if current.session != state.session || current.allocated_through + 1 != sequence {
                return Err(NumberedEventSdkError::Journal(
                    "publication frontier changed while an RPC was in flight".to_owned(),
                ));
            }
            let value = entries
                .get(sequence)
                .map_err(|error| journal_error(self.journal.path(), "get publication", error))?
                .ok_or_else(|| {
                    NumberedEventSdkError::Journal("publication disappeared".to_owned())
                })?;
            let mut saved: JournalEntry = decode_json(value.value(), "entry")?;
            drop(value);
            saved.result = Some(result.clone());
            let encoded = encode_json(&saved)?;
            entries
                .insert(sequence, encoded.as_slice())
                .map_err(|error| {
                    journal_error(self.journal.path(), "store publication result", error)
                })?;
            current.allocated_through = sequence;
            Ok(())
        })?;
        Ok(result)
    }

    pub async fn publish(
        &self,
        intent: api::PublishNumberedEventRequest,
    ) -> std::result::Result<(u64, api::CommittedPublicationResult), PublicationError> {
        let sequence = self
            .journal_publication(intent)
            .map_err(PublicationError::BeforeAssignment)?;
        let result = self
            .publish_journaled(sequence)
            .await
            .map_err(|source| PublicationError::Assigned { sequence, source })?;
        Ok((sequence, result))
    }

    /// Permanently consumes the next journaled but unadmitted sequence.
    pub async fn abandon(&self, sequence: u64) -> Result<()> {
        let state = self.journal.read_state()?;
        require_recovered(&state)?;
        let entry = match self.journal.entry(sequence)? {
            Some(entry) => entry,
            None if sequence > 0 && sequence <= state.allocated_through => return Ok(()),
            None => {
                return Err(NumberedEventSdkError::Journal(format!(
                    "sequence {sequence} is not journaled"
                )));
            }
        };
        if entry.abandoned {
            if sequence > state.allocated_through {
                return Err(NumberedEventSdkError::Protocol(
                    "abandoned sequence is above the durable frontier".to_owned(),
                ));
            }
            return self.journal.write(|_, entries| {
                entries.remove(sequence).map_err(|error| {
                    journal_error(self.journal.path(), "remove old abandoned entry", error)
                })?;
                Ok(())
            });
        }
        if entry.result.is_some() || sequence != state.allocated_through + 1 {
            return Err(NumberedEventSdkError::Protocol(
                "only the next unadmitted sequence may be abandoned".to_owned(),
            ));
        }
        self.client
            .abandon_event_publication(api::AbandonEventPublicationRequest {
                client_id: state.client_id.clone(),
                session: state.session,
                operation_sequence: sequence,
                ..Default::default()
            })
            .await?;
        self.journal.write(|current, entries| {
            require_recovered(current)?;
            if current.session != state.session || current.allocated_through + 1 != sequence {
                return Err(NumberedEventSdkError::Journal(
                    "abandonment frontier changed while an RPC was in flight".to_owned(),
                ));
            }
            if entries
                .remove(sequence)
                .map_err(|error| {
                    journal_error(self.journal.path(), "remove abandoned entry", error)
                })?
                .is_none()
            {
                return Err(NumberedEventSdkError::Journal(
                    "publication disappeared".to_owned(),
                ));
            }
            current.allocated_through = sequence;
            Ok(())
        })
    }

    /// Acknowledges a committed result, then removes its journal row.
    pub async fn acknowledge(&self, sequence: u64) -> Result<()> {
        let state = self.journal.read_state()?;
        require_recovered(&state)?;
        let entry = match self.journal.entry(sequence)? {
            Some(entry) => entry,
            None if sequence > 0 && sequence <= state.allocated_through => return Ok(()),
            None => {
                return Err(NumberedEventSdkError::Journal(format!(
                    "sequence {sequence} is not journaled"
                )));
            }
        };
        if entry.result.is_none() || entry.abandoned {
            return Err(NumberedEventSdkError::Protocol(
                "only a durably saved committed result may be acknowledged".to_owned(),
            ));
        }
        self.client
            .acknowledge_event_publication_result(api::AcknowledgeEventPublicationResultRequest {
                client_id: state.client_id.clone(),
                session: state.session,
                operation_sequence: sequence,
                ..Default::default()
            })
            .await?;
        self.journal.write(|current, entries| {
            require_recovered(current)?;
            if current.session != state.session {
                return Err(NumberedEventSdkError::Journal(
                    "session changed while acknowledgement was in flight".to_owned(),
                ));
            }
            entries.remove(sequence).map_err(|error| {
                journal_error(self.journal.path(), "remove acknowledged result", error)
            })?;
            Ok(())
        })
    }
}

fn validate_committed_result(result: &api::CommittedPublicationResult) -> Result<()> {
    let sequence = result.operation_sequence;
    let receipt = result.receipt.as_option().ok_or_else(|| {
        NumberedEventSdkError::Protocol(format!("sequence {sequence} omitted its receipt"))
    })?;
    if sequence == 0
        || receipt.transfer_id.len() != 32
        || receipt.event_id.len() != 32
        || receipt.acceptance_marker == 0
    {
        return Err(NumberedEventSdkError::Protocol(format!(
            "sequence {sequence} has an invalid receipt"
        )));
    }
    let content_valid = match result.content.as_known() {
        Some(api::CommittedContentStatus::Available) => result.retirement_reason.is_none(),
        Some(api::CommittedContentStatus::Retired) => matches!(
            result
                .retirement_reason
                .as_ref()
                .and_then(|reason| reason.as_known()),
            Some(api::RetirementReason::Expired | api::RetirementReason::QuotaPressure)
        ),
        _ => false,
    };
    if !content_valid {
        return Err(NumberedEventSdkError::Protocol(format!(
            "sequence {sequence} has an invalid content status or retirement reason"
        )));
    }
    Ok(())
}

fn require_recovered(state: &JournalState) -> Result<()> {
    if state.recovery_complete {
        Ok(())
    } else {
        Err(NumberedEventSdkError::Protocol(
            "publication recovery is not complete".to_owned(),
        ))
    }
}

fn validate_client_id(client_id: &[u8]) -> Result<()> {
    if client_id.is_empty() || client_id.len() > 64 {
        return Err(NumberedEventSdkError::Journal(
            "client_id must contain 1 to 64 bytes".to_owned(),
        ));
    }
    Ok(())
}

fn encode_json(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|error| NumberedEventSdkError::Journal(format!("encode state: {error}")))
}

fn decode_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], name: &str) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|error| {
        NumberedEventSdkError::Journal(format!("decode {name}; journal is corrupt: {error}"))
    })
}

fn journal_error(path: &Path, operation: &str, error: impl fmt::Display) -> NumberedEventSdkError {
    NumberedEventSdkError::Journal(format!("{operation} {}: {error}", path.display()))
}

// Keep the concrete response type visible in rustdoc for SDK callers using
// generated transports, and make accidental response-shape drift a compile error.
#[allow(dead_code)]
fn _response_shape<T>(response: UnaryResponse<T>) -> UnaryResponse<T> {
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use connectrpc::client::{ClientBody, ClientConfig};
    use futures::future::BoxFuture;
    use http::{Request, Response};
    use http_body_util::Full;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct ScriptedTransport(Arc<Mutex<VecDeque<Step>>>);

    struct Step {
        procedure: &'static str,
        body: Option<Vec<u8>>,
    }

    impl ClientTransport for ScriptedTransport {
        type ResponseBody = Full<Bytes>;
        type Error = std::io::Error;

        fn send(
            &self,
            request: Request<ClientBody>,
        ) -> BoxFuture<'static, std::result::Result<Response<Self::ResponseBody>, Self::Error>>
        {
            let step = self
                .0
                .lock()
                .expect("script lock")
                .pop_front()
                .expect("script step");
            assert!(
                request.uri().path().ends_with(step.procedure),
                "wrong RPC: {}",
                request.uri()
            );
            Box::pin(async move {
                let body = step
                    .body
                    .ok_or_else(|| std::io::Error::other("scripted lost response"))?;
                Ok(Response::builder()
                    .status(200)
                    .header("content-type", "application/proto")
                    .body(Full::new(Bytes::from(body)))
                    .expect("scripted response"))
            })
        }
    }

    fn step<M: buffa::Message>(procedure: &'static str, response: M) -> Step {
        Step {
            procedure,
            body: Some(response.encode_to_vec()),
        }
    }

    fn lost(procedure: &'static str) -> Step {
        Step {
            procedure,
            body: None,
        }
    }

    fn scripted(
        steps: Vec<Step>,
    ) -> (
        ScriptedTransport,
        api::AsterApplicationServiceClient<ScriptedTransport>,
    ) {
        let transport = ScriptedTransport(Arc::new(Mutex::new(steps.into())));
        let client = api::AsterApplicationServiceClient::new(
            transport.clone(),
            ClientConfig::new("http://localhost".parse().expect("URI")),
        );
        (transport, client)
    }

    fn begin(
        session: u64,
        frontier: u64,
        outstanding: Vec<api::CommittedPublicationResult>,
    ) -> Step {
        begin_revision(session, frontier, 1, outstanding)
    }

    fn begin_revision(
        session: u64,
        frontier: u64,
        revision: u64,
        outstanding: Vec<api::CommittedPublicationResult>,
    ) -> Step {
        step(
            "/BeginEventPublicationSession",
            api::BeginEventPublicationSessionResponse {
                session,
                allocated_through: frontier,
                snapshot_revision: revision,
                outstanding,
                ..Default::default()
            },
        )
    }

    fn complete() -> Step {
        step(
            "/CompleteEventPublicationRecovery",
            api::CompleteEventPublicationRecoveryResponse::default(),
        )
    }

    fn result(sequence: u64) -> api::CommittedPublicationResult {
        api::CommittedPublicationResult {
            operation_sequence: sequence,
            receipt: api::CommittedEventReceipt {
                transfer_id: vec![1; 32],
                event_id: vec![2; 32],
                acceptance_marker: 7,
                ..Default::default()
            }
            .into(),
            content: api::CommittedContentStatus::Available.into(),
            ..Default::default()
        }
    }

    fn intent() -> api::PublishNumberedEventRequest {
        api::PublishNumberedEventRequest {
            payload: b"secret payload".to_vec(),
            ..Default::default()
        }
    }

    fn raw_journal_snapshot(journal: &PublicationJournal, sequence: u64) -> (Vec<u8>, Vec<u8>) {
        let read = journal.database.begin_read().expect("read journal");
        let meta = read.open_table(JOURNAL_META).expect("metadata table");
        let state = meta
            .get(STATE_KEY)
            .expect("state read")
            .expect("state")
            .value()
            .to_vec();
        let entries = read.open_table(JOURNAL_ENTRIES).expect("entries table");
        let row = entries
            .get(sequence)
            .expect("row read")
            .expect("row")
            .value()
            .to_vec();
        (state, row)
    }

    fn seed_equal_revision_journal(
        path: &Path,
        saved: Option<api::CommittedPublicationResult>,
        abandoned: bool,
    ) {
        PublicationJournal::initialize(path, b"client").expect("initialize");
        let journal = PublicationJournal::open(path, b"client").expect("open");
        journal
            .write(|state, entries| {
                state.session = 1;
                state.allocated_through = 1;
                state.snapshot_revision = 3;
                state.next_sequence = Some(2);
                let mut publication = intent();
                publication.client_id = b"client".to_vec();
                publication.operation_sequence = 1;
                publication.session = 1;
                let encoded = encode_json(&JournalEntry {
                    intent: publication,
                    result: saved,
                    abandoned,
                })?;
                entries
                    .insert(1, encoded.as_slice())
                    .map_err(|error| journal_error(journal.path(), "seed row", error))?;
                Ok(())
            })
            .expect("seed journal");
    }

    #[tokio::test]
    async fn publish_error_exposes_assigned_sequence_after_rpc_loss() {
        let path = journal_path("publish-loss");
        let _ = std::fs::remove_file(&path);
        PublicationJournal::initialize(&path, b"client").expect("initialize");
        let (_transport, client) = scripted(vec![
            begin(1, 0, vec![]),
            complete(),
            lost("/PublishNumberedEvent"),
        ]);
        let sdk = NumberedEventSdk::open(client, &path, b"client").expect("open");
        sdk.recover().await.expect("recover");
        let error = sdk.publish(intent()).await.expect_err("lost response");
        assert_eq!(error.assigned_sequence(), Some(1));
        drop(sdk);
        std::fs::remove_file(path).expect("remove journal");
    }
    #[tokio::test]
    async fn restart_report_lists_pending_committed_and_consumed_in_sequence_order() {
        let path = journal_path("mixed-recovery");
        let _ = std::fs::remove_file(&path);
        PublicationJournal::initialize(&path, b"client").expect("initialize");
        let (_transport, client) = scripted(vec![
            begin(1, 0, vec![]),
            complete(),
            step(
                "/PublishNumberedEvent",
                api::PublishNumberedEventResponse {
                    result: result(1).into(),
                    ..Default::default()
                },
            ),
            lost("/AbandonEventPublication"),
        ]);
        let sdk = NumberedEventSdk::open(client, &path, b"client").expect("open");
        sdk.recover().await.expect("recover");
        let first = sdk.journal_publication(intent()).expect("first intent");
        assert_eq!(first, 1);
        sdk.publish_journaled(first).await.expect("commit first");
        let consumed = sdk.journal_publication(intent()).expect("second intent");
        assert_eq!(consumed, 2);
        sdk.abandon(consumed)
            .await
            .expect_err("lost abandonment response");
        let pending = sdk.journal_publication(intent()).expect("third intent");
        assert_eq!(pending, 3);
        drop(sdk);

        let (_transport, client) =
            scripted(vec![begin_revision(2, 2, 3, vec![result(1)]), complete()]);
        let sdk = NumberedEventSdk::open(client, &path, b"client").expect("restart");
        let report = sdk.recover().await.expect("restart recovery");
        assert_eq!(report.session, 2);
        assert_eq!(report.allocated_through, 2);
        assert_eq!(report.operations.len(), 3);
        assert_eq!(report.operations[0].sequence, 1);
        assert!(
            matches!(&report.operations[0].state, RecoveredState::Committed(recovered) if recovered == &result(1))
        );
        assert_eq!(report.operations[1].sequence, 2);
        assert!(matches!(
            report.operations[1].state,
            RecoveredState::Retired
        ));
        assert_eq!(report.operations[2].sequence, 3);
        assert!(matches!(
            report.operations[2].state,
            RecoveredState::Pending
        ));
        assert!(sdk.journal.entry(2).expect("row lookup").is_none());
        assert!(sdk.journal.entry(1).expect("row lookup").is_some());
        assert!(sdk.journal.entry(3).expect("row lookup").is_some());
        drop(sdk);
        std::fs::remove_file(path).expect("remove journal");
    }
    #[tokio::test]
    async fn recovery_rejects_changed_receipt_without_touching_journal() {
        let path = journal_path("receipt-replacement");
        let _ = std::fs::remove_file(&path);
        PublicationJournal::initialize(&path, b"client").expect("initialize");
        let journal = PublicationJournal::open(&path, b"client").expect("open");
        journal
            .write(|state, entries| {
                state.session = 1;
                state.allocated_through = 1;
                state.snapshot_revision = 1;
                state.next_sequence = Some(2);
                let mut publication = intent();
                publication.client_id = b"client".to_vec();
                publication.operation_sequence = 1;
                publication.session = 1;
                let encoded = encode_json(&JournalEntry {
                    intent: publication,
                    result: Some(result(1)),
                    abandoned: false,
                })?;
                entries
                    .insert(1, encoded.as_slice())
                    .map_err(|error| journal_error(journal.path(), "seed result", error))?;
                Ok(())
            })
            .expect("seed journal");
        drop(journal);
        let mut changed = result(1);
        let mut receipt = changed.receipt.as_option().cloned().expect("receipt");
        receipt.transfer_id = vec![9; 32];
        changed.receipt = receipt.into();
        let (_transport, client) = scripted(vec![begin(2, 1, vec![changed])]);
        let sdk = NumberedEventSdk::open(client, &path, b"client").expect("restart");
        sdk.journal
            .update_state(|state| {
                state.pending_claim = Some(PendingClaim {
                    expected_session: 1,
                    nonce: vec![8; CLAIM_NONCE_BYTES],
                });
                Ok(())
            })
            .expect("seed claim");
        let before_state =
            encode_json(&sdk.journal.read_state().expect("state")).expect("encode state");
        let before_entry =
            encode_json(&sdk.journal.entry(1).expect("entry").expect("row")).expect("encode row");
        assert!(matches!(
            sdk.begin_recovery().await,
            Err(NumberedEventSdkError::Protocol(_))
        ));
        assert_eq!(
            encode_json(&sdk.journal.read_state().expect("state")).expect("encode state"),
            before_state
        );
        assert_eq!(
            encode_json(&sdk.journal.entry(1).expect("entry").expect("row")).expect("encode row"),
            before_entry
        );
        drop(sdk);
        std::fs::remove_file(path).expect("remove journal");
    }
    #[tokio::test]
    async fn malformed_snapshots_leave_claim_and_rows_unchanged() {
        fn base() -> api::BeginEventPublicationSessionResponse {
            api::BeginEventPublicationSessionResponse {
                session: 2,
                allocated_through: 1,
                snapshot_revision: 1,
                outstanding: vec![result(1)],
                ..Default::default()
            }
        }
        fn bad(
            change: impl FnOnce(&mut api::BeginEventPublicationSessionResponse),
        ) -> api::BeginEventPublicationSessionResponse {
            let mut snapshot = base();
            change(&mut snapshot);
            snapshot
        }
        fn receipt_bad(
            change: impl FnOnce(&mut api::CommittedEventReceipt),
        ) -> api::BeginEventPublicationSessionResponse {
            bad(|snapshot| {
                let mut receipt = snapshot.outstanding[0]
                    .receipt
                    .as_option()
                    .cloned()
                    .expect("receipt");
                change(&mut receipt);
                snapshot.outstanding[0].receipt = receipt.into();
            })
        }
        let retired = {
            let mut value = result(1);
            value.content = api::CommittedContentStatus::Retired.into();
            value.retirement_reason = Some(api::RetirementReason::Expired.into());
            value
        };
        let mut cases = vec![
            ("zero-session", bad(|s| s.session = 0), result(1), false),
            (
                "regressed-frontier",
                bad(|s| s.allocated_through = 0),
                result(1),
                false,
            ),
            (
                "zero-revision",
                bad(|s| s.snapshot_revision = 0),
                result(1),
                false,
            ),
            (
                "zero-sequence",
                bad(|s| s.outstanding[0].operation_sequence = 0),
                result(1),
                false,
            ),
            (
                "duplicate-sequence",
                bad(|s| s.outstanding.push(result(1))),
                result(1),
                false,
            ),
            (
                "above-frontier",
                bad(|s| s.outstanding[0].operation_sequence = 2),
                result(1),
                false,
            ),
            (
                "unknown-sequence",
                bad(|s| {
                    s.allocated_through = 3;
                    s.outstanding[0].operation_sequence = 3;
                }),
                result(1),
                false,
            ),
            (
                "missing-receipt",
                bad(|s| s.outstanding[0].receipt = Default::default()),
                result(1),
                false,
            ),
            (
                "short-transfer-id",
                receipt_bad(|r| r.transfer_id.pop().map(drop).unwrap_or(())),
                result(1),
                false,
            ),
            (
                "short-event-id",
                receipt_bad(|r| r.event_id.pop().map(drop).unwrap_or(())),
                result(1),
                false,
            ),
            (
                "zero-marker",
                receipt_bad(|r| r.acceptance_marker = 0),
                result(1),
                false,
            ),
            (
                "unspecified-content",
                bad(|s| s.outstanding[0].content = api::CommittedContentStatus::Unspecified.into()),
                result(1),
                false,
            ),
            (
                "unknown-content",
                bad(|s| s.outstanding[0].content = 99.into()),
                result(1),
                false,
            ),
            (
                "available-with-reason",
                bad(|s| {
                    s.outstanding[0].retirement_reason = Some(api::RetirementReason::Expired.into())
                }),
                result(1),
                false,
            ),
            (
                "retired-without-reason",
                bad(|s| s.outstanding[0].content = api::CommittedContentStatus::Retired.into()),
                result(1),
                false,
            ),
            (
                "retired-unspecified-reason",
                bad(|s| {
                    s.outstanding[0].content = api::CommittedContentStatus::Retired.into();
                    s.outstanding[0].retirement_reason =
                        Some(api::RetirementReason::Unspecified.into());
                }),
                result(1),
                false,
            ),
            (
                "retired-unknown-reason",
                bad(|s| {
                    s.outstanding[0].content = api::CommittedContentStatus::Retired.into();
                    s.outstanding[0].retirement_reason = Some(99.into());
                }),
                result(1),
                false,
            ),
            (
                "changed-transfer-id",
                receipt_bad(|r| r.transfer_id = vec![9; 32]),
                result(1),
                false,
            ),
            (
                "changed-event-id",
                receipt_bad(|r| r.event_id = vec![9; 32]),
                result(1),
                false,
            ),
            (
                "changed-marker",
                receipt_bad(|r| r.acceptance_marker = 9),
                result(1),
                false,
            ),
            ("retired-to-available", base(), retired.clone(), false),
            (
                "changed-retired-reason",
                bad(|s| {
                    s.outstanding[0].content = api::CommittedContentStatus::Retired.into();
                    s.outstanding[0].retirement_reason =
                        Some(api::RetirementReason::QuotaPressure.into());
                }),
                retired,
                false,
            ),
        ];
        cases.push((
            "abandoned-resurrection",
            bad(|s| {
                s.allocated_through = 2;
                s.outstanding.push(result(2));
            }),
            result(1),
            true,
        ));

        for (name, snapshot, stored, abandoned) in cases {
            let path = journal_path(name);
            let _ = std::fs::remove_file(&path);
            PublicationJournal::initialize(&path, b"client").expect("initialize");
            let journal = PublicationJournal::open(&path, b"client").expect("open");
            journal
                .write(|state, entries| {
                    state.session = 1;
                    state.allocated_through = 1;
                    state.snapshot_revision = 1;
                    state.next_sequence = Some(3);
                    for (sequence, saved_result, is_abandoned) in
                        [(1, Some(stored.clone()), false), (2, None, abandoned)]
                    {
                        let mut publication = intent();
                        publication.client_id = b"client".to_vec();
                        publication.operation_sequence = sequence;
                        publication.session = 1;
                        let encoded = encode_json(&JournalEntry {
                            intent: publication,
                            result: saved_result,
                            abandoned: is_abandoned,
                        })?;
                        entries
                            .insert(sequence, encoded.as_slice())
                            .map_err(|error| journal_error(journal.path(), "seed entry", error))?;
                    }
                    Ok(())
                })
                .expect("seed journal");
            drop(journal);
            let (_transport, client) =
                scripted(vec![step("/BeginEventPublicationSession", snapshot)]);
            let sdk = NumberedEventSdk::open(client, &path, b"client").expect("restart");
            sdk.journal
                .update_state(|state| {
                    state.pending_claim = Some(PendingClaim {
                        expected_session: 1,
                        nonce: vec![8; CLAIM_NONCE_BYTES],
                    });
                    Ok(())
                })
                .expect("seed claim");
            let before_state =
                encode_json(&sdk.journal.read_state().expect("state")).expect("encode state");
            let before_first = encode_json(&sdk.journal.entry(1).expect("entry").expect("row"))
                .expect("encode row");
            let before_second = encode_json(&sdk.journal.entry(2).expect("entry").expect("row"))
                .expect("encode row");
            assert!(
                matches!(
                    sdk.begin_recovery().await,
                    Err(NumberedEventSdkError::Protocol(_))
                ),
                "{name}"
            );
            assert_eq!(
                encode_json(&sdk.journal.read_state().expect("state")).expect("encode state"),
                before_state,
                "{name}: state"
            );
            assert_eq!(
                encode_json(&sdk.journal.entry(1).expect("entry").expect("row"))
                    .expect("encode row"),
                before_first,
                "{name}: first row"
            );
            assert_eq!(
                encode_json(&sdk.journal.entry(2).expect("entry").expect("row"))
                    .expect("encode row"),
                before_second,
                "{name}: second row"
            );
            drop(sdk);
            std::fs::remove_file(path).expect("remove journal");
        }
    }

    #[tokio::test]
    async fn successful_abandon_deletes_payload_and_repeat_is_bounded() {
        let path = journal_path("abandon-cleanup");
        let _ = std::fs::remove_file(&path);
        PublicationJournal::initialize(&path, b"client").expect("initialize");
        let (_transport, client) = scripted(vec![
            begin(1, 0, vec![]),
            complete(),
            step(
                "/AbandonEventPublication",
                api::AbandonEventPublicationResponse::default(),
            ),
        ]);
        let sdk = NumberedEventSdk::open(client, &path, b"client").expect("open");
        sdk.recover().await.expect("recover");
        let sequence = sdk.journal_publication(intent()).expect("journal");
        sdk.abandon(sequence).await.expect("abandon");
        assert!(sdk.journal.entry(sequence).expect("row lookup").is_none());
        sdk.abandon(sequence).await.expect("repeat abandon");
        assert!(
            sdk.abandon(sequence + 1).await.is_err(),
            "absent above frontier"
        );
        drop(sdk);
        std::fs::remove_file(path).expect("remove journal");
    }

    #[tokio::test]
    async fn lost_acknowledgement_response_is_cleaned_by_recovery() {
        let path = journal_path("ack-loss");
        let _ = std::fs::remove_file(&path);
        PublicationJournal::initialize(&path, b"client").expect("initialize");
        let (_transport, client) = scripted(vec![
            begin(1, 0, vec![]),
            complete(),
            step(
                "/PublishNumberedEvent",
                api::PublishNumberedEventResponse {
                    result: result(1).into(),
                    ..Default::default()
                },
            ),
            lost("/AcknowledgeEventPublicationResult"),
        ]);
        let sdk = NumberedEventSdk::open(client, &path, b"client").expect("open");
        sdk.recover().await.expect("recover");
        let (sequence, _) = sdk.publish(intent()).await.expect("publish");
        sdk.acknowledge(sequence)
            .await
            .expect_err("lost acknowledgement response");
        assert!(sdk.journal.entry(sequence).expect("row lookup").is_some());
        drop(sdk);
        let (_transport, client) = scripted(vec![begin_revision(2, 1, 3, vec![]), complete()]);
        let sdk = NumberedEventSdk::open(client, &path, b"client").expect("restart");
        let report = sdk.recover().await.expect("recover consumed result");
        assert!(matches!(
            report.operations[0].state,
            RecoveredState::Retired
        ));
        assert!(sdk.journal.entry(sequence).expect("row lookup").is_none());
        sdk.acknowledge(sequence)
            .await
            .expect("repeat acknowledgement");
        drop(sdk);
        std::fs::remove_file(path).expect("remove journal");
    }
    #[tokio::test]
    async fn publish_before_assignment_has_no_sequence() {
        let path = journal_path("preassignment");
        let _ = std::fs::remove_file(&path);
        PublicationJournal::initialize(&path, b"client").expect("initialize");
        let (_transport, client) = scripted(vec![]);
        let sdk = NumberedEventSdk::open(client, &path, b"client").expect("open");
        let error = sdk.publish(intent()).await.expect_err("recovery required");
        assert!(matches!(error, PublicationError::BeforeAssignment(_)));
        assert_eq!(error.assigned_sequence(), None);
        assert!(sdk.journal.entry(1).expect("row lookup").is_none());
        drop(sdk);
        std::fs::remove_file(path).expect("remove journal");
    }

    #[tokio::test]
    async fn identical_replay_and_monotonic_content_retirement_succeed() {
        let path = journal_path("content-transition");
        let _ = std::fs::remove_file(&path);
        PublicationJournal::initialize(&path, b"client").expect("initialize");
        let (_transport, client) = scripted(vec![
            begin(1, 0, vec![]),
            complete(),
            step(
                "/PublishNumberedEvent",
                api::PublishNumberedEventResponse {
                    result: result(1).into(),
                    ..Default::default()
                },
            ),
        ]);
        let sdk = NumberedEventSdk::open(client, &path, b"client").expect("open");
        sdk.recover().await.expect("recover");
        sdk.publish(intent()).await.expect("publish");
        drop(sdk);

        let (_transport, client) =
            scripted(vec![begin_revision(2, 1, 2, vec![result(1)]), complete()]);
        let sdk = NumberedEventSdk::open(client, &path, b"client").expect("restart");
        let report = sdk.recover().await.expect("identical replay");
        assert!(
            matches!(&report.operations[0].state, RecoveredState::Committed(replayed) if replayed == &result(1))
        );
        drop(sdk);

        let mut retired = result(1);
        retired.content = api::CommittedContentStatus::Retired.into();
        retired.retirement_reason = Some(api::RetirementReason::Expired.into());
        let (_transport, client) = scripted(vec![
            begin_revision(3, 1, 3, vec![retired.clone()]),
            complete(),
        ]);
        let sdk = NumberedEventSdk::open(client, &path, b"client").expect("restart");
        let report = sdk.recover().await.expect("monotonic retirement");
        assert!(
            matches!(&report.operations[0].state, RecoveredState::Committed(replayed) if replayed == &retired)
        );
        assert_eq!(
            sdk.journal
                .entry(1)
                .expect("row lookup")
                .expect("row")
                .result,
            Some(retired)
        );
        drop(sdk);
        std::fs::remove_file(path).expect("remove journal");
    }

    #[tokio::test]
    async fn completion_failure_withholds_report_and_recovery_gate() {
        let path = journal_path("completion-loss");
        let _ = std::fs::remove_file(&path);
        PublicationJournal::initialize(&path, b"client").expect("initialize");
        let (_transport, client) = scripted(vec![
            begin(1, 0, vec![]),
            lost("/CompleteEventPublicationRecovery"),
        ]);
        let sdk = NumberedEventSdk::open(client, &path, b"client").expect("open");
        assert!(sdk.recover().await.is_err());
        assert!(!sdk.journal.read_state().expect("state").recovery_complete);
        assert!(sdk.journal_publication(intent()).is_err());
        drop(sdk);
        std::fs::remove_file(path).expect("remove journal");
    }

    #[tokio::test]
    async fn regressed_revision_or_wrong_claim_session_preserves_durable_rows() {
        fn saved_bytes(journal: &PublicationJournal) -> (Vec<u8>, Vec<u8>) {
            let read = journal.database.begin_read().expect("read journal");
            let meta = read.open_table(JOURNAL_META).expect("metadata table");
            let state = meta
                .get(STATE_KEY)
                .expect("state read")
                .expect("state")
                .value()
                .to_vec();
            let entries = read.open_table(JOURNAL_ENTRIES).expect("entries table");
            let row = entries
                .get(1)
                .expect("entry read")
                .expect("entry")
                .value()
                .to_vec();
            (state, row)
        }

        for (name, response_session, response_revision) in [
            ("regressed-positive-revision", 2, 2),
            ("nonadvancing-session", 1, 3),
            ("leaped-session", 3, 3),
        ] {
            let path = journal_path(name);
            let _ = std::fs::remove_file(&path);
            PublicationJournal::initialize(&path, b"client").expect("initialize");
            let journal = PublicationJournal::open(&path, b"client").expect("open");
            journal
                .write(|state, entries| {
                    state.session = 1;
                    state.allocated_through = 1;
                    state.snapshot_revision = 3;
                    state.next_sequence = Some(2);
                    let mut publication = intent();
                    publication.client_id = b"client".to_vec();
                    publication.operation_sequence = 1;
                    publication.session = 1;
                    let encoded = encode_json(&JournalEntry {
                        intent: publication,
                        result: Some(result(1)),
                        abandoned: false,
                    })?;
                    entries
                        .insert(1, encoded.as_slice())
                        .map_err(|error| journal_error(journal.path(), "seed result", error))?;
                    Ok(())
                })
                .expect("seed journal");
            drop(journal);

            let response = api::BeginEventPublicationSessionResponse {
                session: response_session,
                allocated_through: 1,
                snapshot_revision: response_revision,
                outstanding: vec![],
                ..Default::default()
            };
            let (_transport, client) =
                scripted(vec![step("/BeginEventPublicationSession", response)]);
            let sdk = NumberedEventSdk::open(client, &path, b"client").expect("restart");
            sdk.journal
                .update_state(|state| {
                    state.pending_claim = Some(PendingClaim {
                        expected_session: 1,
                        nonce: vec![8; CLAIM_NONCE_BYTES],
                    });
                    Ok(())
                })
                .expect("seed durable claim");
            let before = saved_bytes(&sdk.journal);
            assert!(
                matches!(
                    sdk.begin_recovery().await,
                    Err(NumberedEventSdkError::Protocol(_))
                ),
                "{name}"
            );
            assert_eq!(
                saved_bytes(&sdk.journal),
                before,
                "{name}: durable state or row changed"
            );
            drop(sdk);
            std::fs::remove_file(path).expect("remove journal");
        }
    }

    #[tokio::test]
    async fn equal_revision_cannot_change_the_durable_server_image() {
        let available = result(1);
        let mut retired = available.clone();
        retired.content = api::CommittedContentStatus::Retired.into();
        retired.retirement_reason = Some(api::RetirementReason::Expired.into());
        for (name, frontier, outstanding, saved) in [
            (
                "equal-frontier-advance",
                2,
                vec![available.clone()],
                Some(available.clone()),
            ),
            ("equal-result-omission", 1, vec![], Some(available.clone())),
            (
                "equal-content-retirement",
                1,
                vec![retired],
                Some(available.clone()),
            ),
            ("equal-result-addition", 1, vec![available.clone()], None),
        ] {
            let path = journal_path(name);
            let _ = std::fs::remove_file(&path);
            seed_equal_revision_journal(&path, saved, false);
            let (_transport, client) = scripted(vec![begin_revision(2, frontier, 3, outstanding)]);
            let sdk = NumberedEventSdk::open(client, &path, b"client").expect("restart");
            sdk.journal
                .update_state(|state| {
                    state.pending_claim = Some(PendingClaim {
                        expected_session: 1,
                        nonce: vec![8; CLAIM_NONCE_BYTES],
                    });
                    Ok(())
                })
                .expect("seed durable claim");
            let before = raw_journal_snapshot(&sdk.journal, 1);
            assert!(
                matches!(
                    sdk.begin_recovery().await,
                    Err(NumberedEventSdkError::Protocol(_))
                ),
                "{name}"
            );
            assert_eq!(
                raw_journal_snapshot(&sdk.journal, 1),
                before,
                "{name}: journal bytes changed"
            );
            drop(sdk);
            std::fs::remove_file(path).expect("remove journal");
        }
    }

    #[tokio::test]
    async fn equal_revision_replays_identical_result_and_cleans_legacy_abandoned_row() {
        let path = journal_path("equal-identical");
        let _ = std::fs::remove_file(&path);
        seed_equal_revision_journal(&path, Some(result(1)), false);
        let (_transport, client) =
            scripted(vec![begin_revision(2, 1, 3, vec![result(1)]), complete()]);
        let sdk = NumberedEventSdk::open(client, &path, b"client").expect("restart");
        let report = sdk.recover().await.expect("unchanged snapshot");
        assert!(
            matches!(&report.operations[0].state, RecoveredState::Committed(replayed) if replayed == &result(1))
        );
        assert!(sdk.journal.entry(1).expect("row lookup").is_some());
        drop(sdk);
        std::fs::remove_file(path).expect("remove journal");

        let path = journal_path("equal-legacy-abandoned");
        let _ = std::fs::remove_file(&path);
        seed_equal_revision_journal(&path, None, true);
        let (_transport, client) = scripted(vec![begin_revision(2, 1, 3, vec![]), complete()]);
        let sdk = NumberedEventSdk::open(client, &path, b"client").expect("restart");
        let report = sdk.recover().await.expect("unchanged server image");
        assert!(matches!(
            report.operations[0].state,
            RecoveredState::Retired
        ));
        assert!(sdk.journal.entry(1).expect("row lookup").is_none());
        drop(sdk);
        std::fs::remove_file(path).expect("remove journal");
    }

    fn journal_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aster-numbered-journal-{name}-{}-{:?}.redb",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    #[test]
    fn missing_wrong_identity_and_second_writer_fail_closed() {
        let path = journal_path("exclusive");
        let _ = std::fs::remove_file(&path);
        assert!(PublicationJournal::open(&path, b"client-a").is_err());
        PublicationJournal::initialize(&path, b"client-a").expect("initialize");
        assert!(PublicationJournal::open(&path, b"client-b").is_err());
        let first = PublicationJournal::open(&path, b"client-a").expect("first writer");
        assert!(PublicationJournal::open(&path, b"client-a").is_err());
        drop(first);
        std::fs::remove_file(path).expect("remove journal");
    }

    #[test]
    fn malformed_journal_does_not_get_recreated() {
        let path = journal_path("corrupt");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"not a redb database").expect("write corrupt journal");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(PublicationJournal::open(&path, b"client-a").is_err());
        assert_eq!(
            std::fs::read(&path).expect("read corrupt journal"),
            b"not a redb database"
        );
        std::fs::remove_file(path).expect("remove journal");
    }
    #[test]
    #[cfg(unix)]
    fn journal_creation_is_private_and_reopenable_regardless_of_umask() {
        use std::os::unix::fs::PermissionsExt as _;
        const CHILD: &str = "ASTER_TEST_JOURNAL_UMASK_CHILD";
        let Some(mask) = std::env::var_os(CHILD) else {
            for mask in [0o000, 0o777] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "sdk::tests::journal_creation_is_private_and_reopenable_regardless_of_umask",
                        "--test-threads=1",
                    ])
                    .env(CHILD, mask.to_string())
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "umask {mask:03o}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        };
        // Only this regression runs in each child; do not change the parallel
        // parent harness's process-wide umask.
        let mask = mask.to_str().unwrap().parse().unwrap();
        rustix::process::umask(rustix::fs::Mode::from_bits_truncate(mask));
        let path = journal_path("private-mode");
        PublicationJournal::initialize(&path, b"client").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(PublicationJournal::open(&path, b"client").unwrap());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn insecure_and_symlink_journals_are_rejected_without_modification() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let path = journal_path("insecure-mode");
        PublicationJournal::initialize(&path, b"client").unwrap();
        let before = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(PublicationJournal::open(&path, b"client").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = path.with_extension("symlink");
        symlink(&path, &link).unwrap();
        assert!(PublicationJournal::open(&link, b"client").is_err());
        assert!(PublicationJournal::initialize(&link, b"client").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn empty_existing_journal_is_not_initialized_on_open() {
        let path = journal_path("empty-existing");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        drop(file);
        assert!(PublicationJournal::open(&path, b"client").is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        std::fs::remove_file(path).unwrap();
    }
}
