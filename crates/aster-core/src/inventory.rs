//! Exact sparse radix Merkle inventory over 264-bit typed object identifiers.
//!
//! The tree has radix 16 and exactly 66 levels.  A path is the high nibble and
//! then the low nibble of each identifier byte.  Empty branches are omitted,
//! so insertion and comparison require bounded work per differing identifier.
//!
//! Hash construction (all integers are unsigned big-endian) is deliberately
//! specified here for independent implementations:
//!
//! ```text
//! DOMAIN = UTF8("ASTER-SPARSE-RADIX-MERKLE\0V1")
//! leaf = SHA-256(DOMAIN || 0x00 || object_id[33])
//! empty(depth) = SHA-256(DOMAIN || 0x02 || depth:u8)
//! node = SHA-256(DOMAIN || 0x01 || depth:u8 || count:u64 ||
//!                   child_bitmap:u16 ||
//!                   each present child in nibble order:
//!                     nibble:u8 || child_count:u64 || child_hash[32])
//! ```
//!
//! SHA-256 here is a collision-resistant inventory commitment, not a content
//! encryption primitive.  It is supplied by the reviewed `sha2` crate.

use std::array;
use std::collections::BTreeSet;
use std::fmt;

use sha2::{Digest, Sha256};

use crate::wire::{self, Digest32, ObjectId};

const HASH_DOMAIN: &[u8] = b"ASTER-SPARSE-RADIX-MERKLE\0V1";
pub const RADIX: usize = 16;
pub const MAX_NIBBLES: u8 = 66;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InventoryError {
    InvalidPrefix,
    InvalidNibble(u8),
    PrefixIsNotIdentifier,
    InvalidNode(&'static str),
}

impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for InventoryError {}

/// Canonical packed-nibble prefix.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NibblePrefix {
    packed: Vec<u8>,
    nibbles: u8,
}

impl NibblePrefix {
    pub fn root() -> Self {
        Self {
            packed: Vec::new(),
            nibbles: 0,
        }
    }

    pub fn new(packed: Vec<u8>, nibbles: u8) -> Result<Self, InventoryError> {
        wire::validate_prefix(&packed, nibbles).map_err(|_| InventoryError::InvalidPrefix)?;
        Ok(Self { packed, nibbles })
    }

    pub fn from_id(id: &ObjectId, nibbles: u8) -> Result<Self, InventoryError> {
        if nibbles > MAX_NIBBLES {
            return Err(InventoryError::InvalidPrefix);
        }
        let byte_len = usize::from(nibbles).div_ceil(2);
        let encoded = id.to_wire_bytes();
        let mut packed = encoded[..byte_len].to_vec();
        if nibbles & 1 == 1
            && let Some(last) = packed.last_mut()
        {
            *last &= 0xf0;
        }
        Ok(Self { packed, nibbles })
    }

    pub fn child(&self, nibble: u8) -> Result<Self, InventoryError> {
        if nibble >= RADIX as u8 {
            return Err(InventoryError::InvalidNibble(nibble));
        }
        if self.nibbles == MAX_NIBBLES {
            return Err(InventoryError::InvalidPrefix);
        }
        let mut packed = self.packed.clone();
        if self.nibbles & 1 == 0 {
            packed.push(nibble << 4);
        } else if let Some(last) = packed.last_mut() {
            *last |= nibble;
        }
        Ok(Self {
            packed,
            nibbles: self.nibbles + 1,
        })
    }

    pub fn parent(&self) -> Option<Self> {
        if self.nibbles == 0 {
            return None;
        }
        let nibbles = self.nibbles - 1;
        let mut packed = self.packed.clone();
        if nibbles & 1 == 0 {
            packed.pop();
        } else if let Some(last) = packed.last_mut() {
            *last &= 0xf0;
        }
        Some(Self { packed, nibbles })
    }

    pub fn len(&self) -> u8 {
        self.nibbles
    }

    pub fn is_empty(&self) -> bool {
        self.nibbles == 0
    }

    pub fn packed(&self) -> &[u8] {
        &self.packed
    }

    pub fn nibble(&self, index: u8) -> Option<u8> {
        if index >= self.nibbles {
            return None;
        }
        let byte = self.packed[usize::from(index / 2)];
        Some(if index & 1 == 0 {
            byte >> 4
        } else {
            byte & 0x0f
        })
    }

    pub fn to_object_id(&self) -> Result<ObjectId, InventoryError> {
        if self.nibbles != MAX_NIBBLES {
            return Err(InventoryError::PrefixIsNotIdentifier);
        }
        let encoded = self
            .packed
            .as_slice()
            .try_into()
            .map_err(|_| InventoryError::PrefixIsNotIdentifier)?;
        ObjectId::from_wire_bytes(encoded).ok_or(InventoryError::PrefixIsNotIdentifier)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryChild {
    pub nibble: u8,
    pub hash: Digest32,
    pub item_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryNode {
    pub prefix: NibblePrefix,
    pub hash: Digest32,
    pub item_count: u64,
    /// Non-empty children in ascending nibble order.
    pub children: Vec<InventoryChild>,
}

impl InventoryNode {
    /// Verify count, order, and commitment without trusting a remote peer.
    pub fn verify(&self) -> Result<(), InventoryError> {
        if self.prefix.len() == MAX_NIBBLES {
            if !self.children.is_empty() || self.item_count > 1 {
                return Err(InventoryError::InvalidNode("leaf shape"));
            }
            let expected = if self.item_count == 0 {
                empty_hash(self.prefix.len())
            } else {
                leaf_hash(&self.prefix.to_object_id()?)
            };
            if expected != self.hash {
                return Err(InventoryError::InvalidNode("leaf hash"));
            }
            return Ok(());
        }

        if self.item_count == 0 {
            if !self.children.is_empty() || self.hash != empty_hash(self.prefix.len()) {
                return Err(InventoryError::InvalidNode("empty node"));
            }
            return Ok(());
        }
        let summed = self.children.iter().try_fold(0_u64, |sum, child| {
            sum.checked_add(child.item_count)
                .ok_or(InventoryError::InvalidNode("count overflow"))
        })?;
        if summed != self.item_count {
            return Err(InventoryError::InvalidNode("internal count"));
        }
        let expected = internal_hash(self.prefix.len(), &self.children)?;
        if expected != self.hash {
            return Err(InventoryError::InvalidNode("internal hash"));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct TrieNode {
    hash: Digest32,
    item_count: u64,
    leaf: Option<ObjectId>,
    children: [Option<Box<TrieNode>>; RADIX],
}

impl TrieNode {
    fn empty(depth: u8) -> Self {
        Self {
            hash: empty_hash(depth),
            item_count: 0,
            leaf: None,
            children: array::from_fn(|_| None),
        }
    }

    fn insert(&mut self, id: ObjectId, depth: u8) -> bool {
        if depth == MAX_NIBBLES {
            if self.leaf == Some(id) {
                return false;
            }
            debug_assert!(self.leaf.is_none());
            self.leaf = Some(id);
            self.item_count = 1;
            self.hash = leaf_hash(&id);
            return true;
        }
        let branch = usize::from(id_nibble(&id, depth));
        let child =
            self.children[branch].get_or_insert_with(|| Box::new(TrieNode::empty(depth + 1)));
        if !child.insert(id, depth + 1) {
            return false;
        }
        self.refresh(depth);
        true
    }

    fn remove(&mut self, id: &ObjectId, depth: u8) -> bool {
        if depth == MAX_NIBBLES {
            if self.leaf.as_ref() != Some(id) {
                return false;
            }
            self.leaf = None;
            self.item_count = 0;
            self.hash = empty_hash(depth);
            return true;
        }
        let branch = usize::from(id_nibble(id, depth));
        let Some(child) = self.children[branch].as_mut() else {
            return false;
        };
        if !child.remove(id, depth + 1) {
            return false;
        }
        if child.item_count == 0 {
            self.children[branch] = None;
        }
        self.refresh(depth);
        true
    }

    fn refresh(&mut self, depth: u8) {
        self.item_count = self
            .children
            .iter()
            .flatten()
            .map(|child| child.item_count)
            .sum();
        if self.item_count == 0 {
            self.hash = empty_hash(depth);
            return;
        }
        let children = child_summaries(&self.children);
        self.hash = internal_hash(depth, &children).expect("internal trie shape is canonical");
    }
}

/// A mutable exact inventory.  A duplicate insertion and missing removal are
/// no-ops, which makes applying durable-store notifications idempotent.
#[derive(Clone)]
pub struct SparseInventory {
    root: TrieNode,
    ids: BTreeSet<ObjectId>,
}

impl fmt::Debug for SparseInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SparseInventory")
            .field("item_count", &self.root.item_count)
            .field("root_hash", &self.root.hash)
            .finish()
    }
}

impl PartialEq for SparseInventory {
    fn eq(&self, other: &Self) -> bool {
        self.ids == other.ids
    }
}

impl Eq for SparseInventory {}

impl Default for SparseInventory {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseInventory {
    pub fn new() -> Self {
        Self {
            root: TrieNode::empty(0),
            ids: BTreeSet::new(),
        }
    }

    pub fn from_ids(ids: impl IntoIterator<Item = ObjectId>) -> Self {
        let mut inventory = Self::new();
        for id in ids {
            inventory.insert(id);
        }
        inventory
    }

    pub fn insert(&mut self, id: ObjectId) -> bool {
        if !self.ids.insert(id) {
            return false;
        }
        let inserted = self.root.insert(id, 0);
        debug_assert!(inserted);
        true
    }

    pub fn remove(&mut self, id: &ObjectId) -> bool {
        if !self.ids.remove(id) {
            return false;
        }
        let removed = self.root.remove(id, 0);
        debug_assert!(removed);
        true
    }

    pub fn contains(&self, id: &ObjectId) -> bool {
        self.ids.contains(id)
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn filtered_for_semantic_version(&self, semantic_version: u16) -> Self {
        Self::from_ids(
            self.ids
                .iter()
                .copied()
                .filter(|id| id.kind().is_allowed_in_semantic_version(semantic_version)),
        )
    }

    pub fn root_hash(&self) -> Digest32 {
        self.root.hash
    }

    pub fn item_count(&self) -> u64 {
        self.root.item_count
    }

    /// A compact correlation token.  Full correctness comparisons always use
    /// `root_hash`; this token only rejects replies from an older snapshot.
    pub fn snapshot_id(&self) -> u64 {
        u64::from_be_bytes(self.root.hash[..8].try_into().expect("fixed hash length"))
    }

    pub fn node(&self, prefix: &NibblePrefix) -> InventoryNode {
        let mut current = Some(&self.root);
        for depth in 0..prefix.len() {
            current = current.and_then(|node| {
                node.children[usize::from(prefix.nibble(depth).expect("validated prefix"))]
                    .as_deref()
            });
        }
        let Some(node) = current else {
            return InventoryNode {
                prefix: prefix.clone(),
                hash: empty_hash(prefix.len()),
                item_count: 0,
                children: Vec::new(),
            };
        };
        InventoryNode {
            prefix: prefix.clone(),
            hash: node.hash,
            item_count: node.item_count,
            children: if prefix.len() == MAX_NIBBLES {
                Vec::new()
            } else {
                child_summaries(&node.children)
            },
        }
    }

    /// Return identifiers below `prefix` in lexical order, capped without
    /// scanning unrelated branches.
    pub fn ids_under(&self, prefix: &NibblePrefix, limit: usize) -> Vec<ObjectId> {
        if limit == 0 {
            return Vec::new();
        }
        let mut current = Some(&self.root);
        for depth in 0..prefix.len() {
            current = current.and_then(|node| {
                node.children[usize::from(prefix.nibble(depth).expect("validated prefix"))]
                    .as_deref()
            });
        }
        let mut out = Vec::new();
        if let Some(node) = current {
            collect_ids(node, limit, &mut out);
        }
        out
    }

    /// Exact, hash-pruned symmetric difference.
    pub fn difference(&self, other: &Self) -> InventoryDifference {
        let mut difference = InventoryDifference::default();
        diff_nodes(Some(&self.root), Some(&other.root), 0, &mut difference);
        difference
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InventoryDifference {
    pub only_left: Vec<ObjectId>,
    pub only_right: Vec<ObjectId>,
    /// Number of unequal node pairs examined.  Equal subtrees cost one hash
    /// comparison and are not descended.
    pub visited_nodes: usize,
}

/// Public hash helpers form part of the language-neutral inventory registry.
pub fn leaf_hash(id: &ObjectId) -> Digest32 {
    let mut digest = Sha256::new();
    digest.update(HASH_DOMAIN);
    digest.update([0x00]);
    digest.update(id.to_wire_bytes());
    digest.finalize().into()
}

pub fn empty_hash(depth: u8) -> Digest32 {
    let mut digest = Sha256::new();
    digest.update(HASH_DOMAIN);
    digest.update([0x02, depth]);
    digest.finalize().into()
}

pub fn internal_hash(depth: u8, children: &[InventoryChild]) -> Result<Digest32, InventoryError> {
    if depth >= MAX_NIBBLES || children.is_empty() || children.len() > RADIX {
        return Err(InventoryError::InvalidNode("internal shape"));
    }
    let mut previous = None;
    let mut count = 0_u64;
    let mut bitmap = 0_u16;
    for child in children {
        if child.nibble >= RADIX as u8 || child.item_count == 0 {
            return Err(InventoryError::InvalidNode("child shape"));
        }
        if previous.is_some_and(|previous| previous >= child.nibble) {
            return Err(InventoryError::InvalidNode("child order"));
        }
        previous = Some(child.nibble);
        count = count
            .checked_add(child.item_count)
            .ok_or(InventoryError::InvalidNode("count overflow"))?;
        bitmap |= 1_u16 << child.nibble;
    }

    let mut digest = Sha256::new();
    digest.update(HASH_DOMAIN);
    digest.update([0x01, depth]);
    digest.update(count.to_be_bytes());
    digest.update(bitmap.to_be_bytes());
    for child in children {
        digest.update([child.nibble]);
        digest.update(child.item_count.to_be_bytes());
        digest.update(child.hash);
    }
    Ok(digest.finalize().into())
}

fn child_summaries(children: &[Option<Box<TrieNode>>; RADIX]) -> Vec<InventoryChild> {
    children
        .iter()
        .enumerate()
        .filter_map(|(nibble, child)| {
            child.as_ref().map(|child| InventoryChild {
                nibble: nibble as u8,
                hash: child.hash,
                item_count: child.item_count,
            })
        })
        .collect()
}

fn id_nibble(id: &ObjectId, depth: u8) -> u8 {
    let byte = id.to_wire_bytes()[usize::from(depth / 2)];
    if depth & 1 == 0 {
        byte >> 4
    } else {
        byte & 0x0f
    }
}

fn collect_ids(node: &TrieNode, limit: usize, out: &mut Vec<ObjectId>) {
    if out.len() >= limit {
        return;
    }
    if let Some(id) = node.leaf {
        out.push(id);
        return;
    }
    for child in node.children.iter().flatten() {
        collect_ids(child, limit, out);
        if out.len() >= limit {
            break;
        }
    }
}

fn diff_nodes(
    left: Option<&TrieNode>,
    right: Option<&TrieNode>,
    depth: u8,
    out: &mut InventoryDifference,
) {
    if left.map(|node| node.hash) == right.map(|node| node.hash) {
        return;
    }
    out.visited_nodes += 1;
    match (left, right) {
        (Some(left), None) => collect_ids(left, usize::MAX, &mut out.only_left),
        (None, Some(right)) => collect_ids(right, usize::MAX, &mut out.only_right),
        (Some(left), Some(right)) if depth == MAX_NIBBLES => {
            if let Some(id) = left.leaf {
                out.only_left.push(id);
            }
            if let Some(id) = right.leaf {
                out.only_right.push(id);
            }
        }
        (Some(left), Some(right)) => {
            for nibble in 0..RADIX {
                diff_nodes(
                    left.children[nibble].as_deref(),
                    right.children[nibble].as_deref(),
                    depth + 1,
                    out,
                );
            }
        }
        (None, None) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(number: u32) -> ObjectId {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&number.to_be_bytes());
        ObjectId::for_envelope(crate::wire::EnvelopeId::from_bytes(bytes))
    }

    #[test]
    fn insertion_order_and_duplicates_do_not_change_root() {
        let ids = [id(1), id(2), id(0x1000), id(u32::MAX)];
        let left = SparseInventory::from_ids(ids);
        let right = SparseInventory::from_ids(ids.into_iter().rev());
        assert_eq!(left.root_hash(), right.root_hash());

        let mut duplicate = left.clone();
        assert!(!duplicate.insert(id(2)));
        assert_eq!(duplicate.root_hash(), left.root_hash());
    }

    #[test]
    fn semantic_v1_filter_suppresses_extended_kinds_before_root_calculation() {
        let source = id(1);
        let blob = ObjectId::new(crate::wire::ObjectKind::BlobChunk, [2; 32]);
        let proof = ObjectId::new(crate::wire::ObjectKind::SourceBatchProof, [3; 32]);
        let bridge = ObjectId::new(crate::wire::ObjectKind::BridgeAuthorization, [4; 32]);
        let wrapper = ObjectId::new(crate::wire::ObjectKind::BridgeRouteWrapper, [5; 32]);
        let complete = SparseInventory::from_ids([source, blob, proof, bridge, wrapper]);

        let v1 = complete.filtered_for_semantic_version(crate::wire::SEMANTIC_PROTOCOL_V1);
        let expected_v1 = SparseInventory::from_ids([source, blob]);
        assert_eq!(v1, expected_v1);
        assert_eq!(v1.root_hash(), expected_v1.root_hash());
        assert_eq!(v1.item_count(), 2);

        let v2 = complete.filtered_for_semantic_version(crate::wire::SEMANTIC_PROTOCOL_V2);
        assert_eq!(v2, complete);
        assert_eq!(v2.root_hash(), complete.root_hash());
    }

    #[test]
    fn root_hash_has_stable_golden_bytes() {
        let mut object_id = [0_u8; 32];
        object_id[31] = 1;
        let inventory = SparseInventory::from_ids([ObjectId::for_envelope(
            crate::wire::EnvelopeId::from_bytes(object_id),
        )]);
        assert_eq!(
            inventory.root_hash(),
            [
                0xed, 0x7d, 0x7a, 0xac, 0xc2, 0x68, 0x42, 0x2d, 0xf6, 0x05, 0x1a, 0xae, 0x37, 0xa2,
                0x1d, 0x0c, 0x88, 0xc8, 0x3b, 0xee, 0x9c, 0x25, 0x04, 0x55, 0xc7, 0xc1, 0xd6, 0x83,
                0x80, 0x08, 0x9f, 0xd5,
            ]
        );
    }

    #[test]
    fn remove_restores_exact_previous_commitment() {
        let mut inventory = SparseInventory::from_ids([id(1), id(2)]);
        let before = inventory.root_hash();
        assert!(inventory.insert(id(3)));
        assert_ne!(inventory.root_hash(), before);
        assert!(inventory.remove(&id(3)));
        assert_eq!(inventory.root_hash(), before);
        assert!(!inventory.remove(&id(3)));
    }

    #[test]
    fn prefixes_are_canonical_and_select_exact_subtrees() {
        let inventory = SparseInventory::from_ids([id(1), id(2), id(0x1000_0000)]);
        let zero = NibblePrefix::new(vec![0x01, 0x00], 3).unwrap();
        assert_eq!(inventory.ids_under(&zero, 10), vec![id(1), id(2)]);
        assert!(NibblePrefix::new(vec![0x0f], 1).is_err());
        let full = NibblePrefix::from_id(&id(2), MAX_NIBBLES).unwrap();
        assert_eq!(full.to_object_id().unwrap(), id(2));
        inventory.node(&full).verify().unwrap();
    }

    #[test]
    fn difference_is_exact_and_prunes_equal_dataset() {
        let mut left = SparseInventory::new();
        for number in 0..4096 {
            left.insert(id(number));
        }
        let mut right = left.clone();
        right.remove(&id(2048));
        right.insert(id(50_000));

        let difference = left.difference(&right);
        assert_eq!(difference.only_left, vec![id(2048)]);
        assert_eq!(difference.only_right, vec![id(50_000)]);
        assert!(
            difference.visited_nodes <= 130,
            "{}",
            difference.visited_nodes
        );

        let identical = left.difference(&left);
        assert_eq!(identical.visited_nodes, 0);
        assert!(identical.only_left.is_empty());
    }

    #[test]
    fn internal_node_detects_tampering() {
        let inventory = SparseInventory::from_ids([id(1), id(2)]);
        let mut node = inventory.node(&NibblePrefix::root());
        node.verify().unwrap();
        node.children[0].item_count += 1;
        assert_eq!(
            node.verify(),
            Err(InventoryError::InvalidNode("internal count"))
        );
    }
}
