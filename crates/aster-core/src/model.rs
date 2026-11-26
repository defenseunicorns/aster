//! Public data model and validated identifiers.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use sha2::{Digest, Sha256};

/// Transfer identity of one stable source-sealed envelope.
///
/// This type is deliberately distinct from [`crate::model::ItemId`].  An
/// envelope is first reassembled and checked against this SHA-256 identifier;
/// only authenticated engine ingestion may then produce the semantic item ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct EnvelopeId([u8; 32]);

impl EnvelopeId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Calculates the transfer ID over exactly the stable source-sealed bytes.
    pub fn from_sealed_bytes(sealed: &[u8]) -> Self {
        Self(Sha256::digest(sealed).into())
    }
}

impl From<[u8; 32]> for EnvelopeId {
    fn from(value: [u8; 32]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<EnvelopeId> for [u8; 32] {
    fn from(value: EnvelopeId) -> Self {
        value.into_bytes()
    }
}

/// Stable kind tag in the transfer-object namespace.
///
/// The tag occupies the first byte of every [`ObjectId`], so a source envelope
/// can never be interpreted as a Blob chunk even if an implementation routes
/// an identifier to the wrong completion handler.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ObjectKind {
    /// A stable source-sealed data or control envelope.
    SourceEnvelope = 1,
    /// A canonical encrypted Blob chunk carrier.
    BlobChunk = 2,
    /// A source-authenticated proof covering one canonical source batch.
    SourceBatchProof = 3,
    /// A source-authenticated authorization for a bridge boundary.
    BridgeAuthorization = 4,
    /// A route-bound wrapper for bridge custody metadata.
    BridgeRouteWrapper = 5,
}

impl ObjectKind {
    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::SourceEnvelope),
            2 => Some(Self::BlobChunk),
            3 => Some(Self::SourceBatchProof),
            4 => Some(Self::BridgeAuthorization),
            5 => Some(Self::BridgeRouteWrapper),
            _ => None,
        }
    }
}

/// Typed identity in the reconciliation and ranged-transfer namespace.
///
/// Its fixed 33-byte representation is `kind:u8 || id:32`. Keeping the kind
/// outside the digest gives parsers unambiguous dispatch while retaining the
/// complete SHA-256 envelope or chunk commitment without truncation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectId {
    kind: ObjectKind,
    id: [u8; 32],
}

/// Number of radix nibbles in the complete typed transfer identifier.
pub const OBJECT_ID_NIBBLES: u8 = 66;

impl ObjectId {
    pub const WIRE_LEN: usize = 33;

    pub const fn new(kind: ObjectKind, id: [u8; 32]) -> Self {
        Self { kind, id }
    }

    pub const fn kind(&self) -> ObjectKind {
        self.kind
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.id
    }

    pub fn to_wire_bytes(self) -> [u8; Self::WIRE_LEN] {
        let mut bytes = [0_u8; Self::WIRE_LEN];
        bytes[0] = self.kind as u8;
        bytes[1..].copy_from_slice(&self.id);
        bytes
    }

    pub fn from_wire_bytes(bytes: [u8; Self::WIRE_LEN]) -> Option<Self> {
        let kind = ObjectKind::from_tag(bytes[0])?;
        let mut id = [0_u8; 32];
        id.copy_from_slice(&bytes[1..]);
        Some(Self { kind, id })
    }

    /// Uses the complete SHA-256 identity of the stable source envelope.
    pub const fn for_envelope(envelope_id: EnvelopeId) -> Self {
        Self::new(ObjectKind::SourceEnvelope, envelope_id.into_bytes())
    }

    /// Uses the complete domain-separated Blob carrier commitment.
    pub(crate) const fn for_blob_chunk_digest(digest: [u8; 32]) -> Self {
        Self::new(ObjectKind::BlobChunk, digest)
    }

    /// Full stable source-envelope digest, only for the matching kind.
    pub const fn envelope_id(&self) -> Option<EnvelopeId> {
        match self.kind {
            ObjectKind::SourceEnvelope => Some(EnvelopeId::from_bytes(self.id)),
            ObjectKind::BlobChunk
            | ObjectKind::SourceBatchProof
            | ObjectKind::BridgeAuthorization
            | ObjectKind::BridgeRouteWrapper => None,
        }
    }
}

/// Stable, opaque identifier for a node identity.
pub type NodeId = [u8; 32];

/// Content-derived identifier for an item or other immutable protocol object.
pub type ItemId = [u8; 32];

/// The four protocol data classes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DataClass {
    /// Small mutable latest-value data.
    State = 0,
    /// Immutable per-publisher sequence data.
    Event = 1,
    /// Mutable documents that retain concurrent siblings.
    Record = 2,
    /// Immutable content-addressed binary data.
    Blob = 3,
}

/// Fixed message precedence used by scheduling, retry, and eviction policy.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Priority {
    /// Normal operational traffic.
    #[default]
    Routine = 0,
    /// Traffic sent ahead of routine traffic.
    Priority = 1,
    /// Time-sensitive traffic.
    Immediate = 2,
    /// Highest precedence traffic.
    Flash = 3,
}

impl Priority {
    /// Converts a wire value into a known priority.
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Routine),
            1 => Some(Self::Priority),
            2 => Some(Self::Immediate),
            3 => Some(Self::Flash),
            _ => None,
        }
    }
}

/// Error returned for a non-canonical topic or scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameError(&'static str);

impl Display for NameError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for NameError {}

fn validate_name(value: &str, hierarchical: bool) -> Result<(), NameError> {
    if value.is_empty() || value.len() > 128 {
        return Err(NameError("name length must be between 1 and 128 bytes"));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'_' | b'-')
            || (hierarchical && byte == b'/')
    }) {
        return Err(NameError("name contains a non-canonical character"));
    }
    if hierarchical
        && (value.starts_with('/')
            || value.ends_with('/')
            || value
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."))
    {
        return Err(NameError(
            "scope must contain canonical non-empty path segments",
        ));
    }
    Ok(())
}

/// A canonical content channel name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Topic(String);

impl Topic {
    /// Creates a validated topic.
    pub fn new(value: impl Into<String>) -> Result<Self, NameError> {
        let value = value.into();
        validate_name(&value, false)?;
        Ok(Self(value))
    }

    /// Returns the canonical wire name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A canonical hierarchical administrative propagation domain.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Scope(String);

impl Scope {
    /// Creates a validated scope path.
    pub fn new(value: impl Into<String>) -> Result<Self, NameError> {
        let value = value.into();
        validate_name(&value, true)?;
        Ok(Self(value))
    }

    /// Returns the canonical wire name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether `self` is the same scope as, or an ancestor of, `other`.
    pub fn contains(&self, other: &Self) -> bool {
        other.0 == self.0
            || other
                .0
                .strip_prefix(&self.0)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }
}

/// A publisher's unique logical event.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Dot {
    /// Publisher whose monotonic counter created this dot.
    pub publisher: NodeId,
    /// Nonzero per-publisher monotonic counter.
    pub counter: u64,
}

/// Compact causal context represented by the largest observed counter per node.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VersionVector(BTreeMap<NodeId, u64>);

/// Maximum number of publisher entries carried by an authenticated causal context.
pub const MAX_CAUSAL_CONTEXT_ENTRIES: usize = 4_096;

impl VersionVector {
    /// Returns the observed counter for a publisher, or zero.
    pub fn counter(&self, publisher: &NodeId) -> u64 {
        self.0.get(publisher).copied().unwrap_or(0)
    }

    /// Returns whether this context includes `dot`.
    pub fn observes(&self, dot: Dot) -> bool {
        self.counter(&dot.publisher) >= dot.counter
    }

    /// Advances this context to include `dot`.
    pub fn observe(&mut self, dot: Dot) {
        self.0
            .entry(dot.publisher)
            .and_modify(|counter| *counter = (*counter).max(dot.counter))
            .or_insert(dot.counter);
    }

    /// Joins another context into this context.
    pub fn join(&mut self, other: &Self) {
        for (&publisher, &counter) in &other.0 {
            self.observe(Dot { publisher, counter });
        }
    }

    /// Returns the number of distinct publishers in this context.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether this context contains no publisher observations.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates in canonical node identifier order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&NodeId, &u64)> {
        self.0.iter()
    }
}

/// Causal stamp for a published version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalStamp {
    /// Unique publisher event for this version.
    pub dot: Dot,
    /// Events observed before the version was produced.
    pub context: VersionVector,
}

impl CausalStamp {
    /// Returns the full context including this version's dot.
    pub fn clock(&self) -> VersionVector {
        let mut clock = self.context.clone();
        clock.observe(self.dot);
        clock
    }
}

/// A conflict visible to an application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictAnnotation {
    /// Stable logical key with multiple versions.
    pub logical_key: Vec<u8>,
    /// All retained concurrent item identifiers in canonical order.
    pub siblings: Vec<ItemId>,
    /// Process-local registered policy identifier exposed by this projection,
    /// if any. Presence does not mean the policy was executed.
    pub merge_policy: Option<String>,
}

/// Coarse peer lifecycle surfaced to applications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerStatus {
    /// Known through provisioning but not currently reachable.
    Offline,
    /// Discovered but not yet mutually authenticated.
    Authenticating,
    /// Authenticated and eligible for synchronization.
    Ready,
    /// Rejected because identity or policy validation failed.
    Rejected,
    /// Excluded by a verified revocation.
    Revoked,
}

/// Coarse synchronization lifecycle surfaced to applications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncStatus {
    /// No active reconciliation.
    Idle,
    /// Comparing authenticated inventories.
    Reconciling,
    /// Transferring missing immutable objects.
    Transferring,
    /// Both peers committed the same inventory root for the negotiated filter.
    Converged,
    /// Work is paused and can be resumed with any eligible peer.
    Suspended,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_identifiers_preserve_kind_tags_and_complete_digests() {
        let digest = std::array::from_fn(|index| index as u8);
        for (kind, tag) in [
            (ObjectKind::SourceEnvelope, 1),
            (ObjectKind::BlobChunk, 2),
            (ObjectKind::SourceBatchProof, 3),
            (ObjectKind::BridgeAuthorization, 4),
            (ObjectKind::BridgeRouteWrapper, 5),
        ] {
            let id = ObjectId::new(kind, digest);
            let encoded = id.to_wire_bytes();
            assert_eq!(encoded[0], tag);
            assert_eq!(&encoded[1..], &digest);
            assert_eq!(ObjectId::from_wire_bytes(encoded), Some(id));
            assert_eq!(id.kind(), kind);
            assert_eq!(id.digest(), &digest);
            assert_eq!(
                id.envelope_id(),
                (kind == ObjectKind::SourceEnvelope).then_some(EnvelopeId::from_bytes(digest))
            );
        }
        for tag in [0, 6, 255] {
            let mut encoded = [0; ObjectId::WIRE_LEN];
            encoded[0] = tag;
            assert_eq!(ObjectId::from_wire_bytes(encoded), None);
        }
    }

    #[test]
    fn envelope_identity_is_sha256_of_exact_sealed_bytes() {
        let sealed = b"stable source-sealed bytes";
        let expected: [u8; 32] = Sha256::digest(sealed).into();
        let id = EnvelopeId::from_sealed_bytes(sealed);
        assert_eq!(id.as_bytes(), &expected);
        assert_eq!(<[u8; 32]>::from(id), expected);
        assert_eq!(EnvelopeId::from(expected), id);
        assert_eq!(ObjectId::for_envelope(id).envelope_id(), Some(id));
    }

    #[test]
    fn names_are_canonical() {
        assert!(Topic::new("position.current").is_ok());
        assert!(Topic::new("not/a/topic").is_err());
        assert!(Scope::new("mission/team/alpha").is_ok());
        assert!(Scope::new("mission//alpha").is_err());
    }

    #[test]
    fn scope_containment_uses_segment_boundaries() {
        let team = Scope::new("mission/team").unwrap();
        assert!(team.contains(&Scope::new("mission/team/alpha").unwrap()));
        assert!(!team.contains(&Scope::new("mission/teams").unwrap()));
    }
}
