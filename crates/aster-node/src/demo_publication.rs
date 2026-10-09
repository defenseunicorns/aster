//! Bounded application-owned publication progress for the native Ping/Pong demo.
//!
//! This journal is colocated with the owned node database, but is not an
//! operation-key ledger: each configured role has one client, one monotonic
//! sequence frontier, one input cursor, and at most one complete pending intent.
use aster_redb_store::{EventClientId, EventOperationSequence, EventPublicationSession, Store};
use serde::{Deserialize, Serialize};

use crate::runtime::NodeError;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    pub sequence: u64,
    pub input_marker: u64,
    pub predecessor: Option<[u8; 32]>,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub applied: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u8,
    client: Vec<u8>,
    session: u64,
    claim: Option<(u64, [u8; 32])>,
    next_sequence: u64,
    cursor: u64,
    ping_completed: bool,
    last_event: Option<[u8; 32]>,
    pending: Option<Intent>,
}

pub(crate) struct Journal {
    pub client: EventClientId,
    state: Checkpoint,
}

fn invalid(message: impl Into<String>) -> NodeError {
    NodeError::Protocol(format!(
        "native application publication journal: {}",
        message.into()
    ))
}

impl Journal {
    pub fn open(store: &Store, client: EventClientId) -> Result<Self, NodeError> {
        let state = match store.event_publication_checkpoint(&client)? {
            Some(bytes) => serde_json::from_slice::<Checkpoint>(&bytes)
                .map_err(|_| invalid("invalid checkpoint"))?,
            None => {
                if store.has_event_publication_client(&client)? {
                    return Err(invalid(
                        "checkpoint missing for a registered client; explicit repair is required",
                    ));
                }
                Checkpoint {
                    version: 1,
                    client: client.as_bytes().to_vec(),
                    session: 0,
                    claim: None,
                    next_sequence: 1,
                    cursor: 0,
                    ping_completed: false,
                    last_event: None,
                    pending: None,
                }
            }
        };
        if state.version != 1
            || state.client != client.as_bytes()
            || state.next_sequence == 0
            || state.pending.as_ref().is_some_and(|intent| {
                intent.sequence == 0
                    || intent.sequence.checked_add(1) != Some(state.next_sequence)
                    || intent.logical_key.len() > 64
                    || intent.payload.len() > 4096
                    || intent.input_marker < state.cursor
            })
        {
            return Err(invalid("checkpoint is inconsistent"));
        }
        let mut journal = Self { client, state };
        if journal.state.claim.is_none() {
            let mut nonce = [0; 32];
            getrandom::fill(&mut nonce).map_err(|_| invalid("claim nonce unavailable"))?;
            journal.state.claim = Some((journal.state.session, nonce));
            journal.save(store)?; // Persist takeover intent before claiming.
        }
        let (expected, nonce) = journal.state.claim.expect("persisted claim");
        let snapshot = store.begin_event_publication_session(&journal.client, expected, &nonce)?;
        if snapshot.allocated_through >= journal.state.next_sequence
            || (journal.state.pending.is_none()
                && snapshot.allocated_through.checked_add(1) != Some(journal.state.next_sequence))
            || journal.state.pending.as_ref().is_some_and(|intent| {
                intent.applied && snapshot.allocated_through < intent.sequence
            })
            || snapshot.outstanding.iter().any(|result| {
                journal
                    .state
                    .pending
                    .as_ref()
                    .is_none_or(|intent| intent.sequence != result.sequence.get())
            })
            || journal.state.pending.as_ref().is_some_and(|intent| {
                !intent.applied
                    && intent.sequence <= snapshot.allocated_through
                    && !snapshot
                        .outstanding
                        .iter()
                        .any(|result| result.sequence.get() == intent.sequence)
            })
        {
            return Err(invalid(
                "server recovery snapshot does not match retained intent",
            ));
        }
        store.complete_event_publication_recovery(
            &journal.client,
            snapshot.session,
            snapshot.snapshot_revision,
        )?;
        journal.state.session = snapshot.session.get();
        journal.state.claim = None;
        journal.save(store)?;
        journal.finish_acknowledgement(store)?;
        Ok(journal)
    }

    fn save(&self, store: &Store) -> Result<(), NodeError> {
        let bytes =
            serde_json::to_vec(&self.state).map_err(|_| invalid("checkpoint encoding failed"))?;
        store.save_event_publication_checkpoint(&self.client, &bytes)?;
        Ok(())
    }

    pub fn session(&self) -> Result<EventPublicationSession, NodeError> {
        EventPublicationSession::new(self.state.session).map_err(|error| invalid(error.to_string()))
    }
    pub fn cursor(&self) -> u64 {
        self.state.cursor
    }
    pub fn ping_completed(&self) -> bool {
        self.state.ping_completed
    }
    pub fn last_event(&self) -> Option<[u8; 32]> {
        self.state.last_event
    }
    pub fn pending(&self) -> Option<&Intent> {
        self.state.pending.as_ref()
    }

    pub fn retain(&mut self, store: &Store, mut intent: Intent) -> Result<(), NodeError> {
        if self.state.pending.is_some() {
            return Err(invalid("pending intent must be resolved before allocation"));
        }
        intent.sequence = self.state.next_sequence;
        self.state.next_sequence = intent
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("sequence exhausted"))?;
        self.state.pending = Some(intent);
        self.save(store)
    }

    pub fn advance_cursor(&mut self, store: &Store, marker: u64) -> Result<(), NodeError> {
        if self.state.pending.is_some() || marker < self.state.cursor {
            return Err(invalid("invalid cursor advancement"));
        }
        self.state.cursor = marker;
        self.save(store)
    }

    pub fn apply(&mut self, store: &Store, event: [u8; 32]) -> Result<(), NodeError> {
        let intent = self
            .state
            .pending
            .as_mut()
            .ok_or_else(|| invalid("no pending application result"))?;
        intent.applied = true;
        self.state.cursor = intent.input_marker;
        self.state.ping_completed |= intent.predecessor.is_none();
        self.state.last_event = Some(event);
        self.save(store)?; // Application progress precedes result acknowledgement.
        self.finish_acknowledgement(store)
    }

    fn finish_acknowledgement(&mut self, store: &Store) -> Result<(), NodeError> {
        if let Some(intent) = self.state.pending.as_ref().filter(|intent| intent.applied) {
            store.acknowledge_event_publication_result(
                &self.client,
                self.session()?,
                EventOperationSequence::new(intent.sequence)
                    .map_err(|error| invalid(error.to_string()))?,
            )?;
            self.state.pending = None;
            self.save(store)?;
        }
        Ok(())
    }
}
