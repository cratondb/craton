//! B+tree node structures (leaf and internal nodes).
//!
//! # Node Types
//!
//! - **Leaf nodes**: Contain key-value pairs with MVCC versions
//! - **Internal nodes**: Contain keys and child page pointers
//!
//! Both node types are stored in pages. The node serialization format is:
//!
//! ## Leaf Node Item Format
//! ```text
//! [key_len: u16][key: bytes][version_count: u16][versions: RowVersion*]
//! ```
//!
//! ## Internal Node Item Format
//! ```text
//! [key_len: u16][key: bytes][child_page_id: u64]
//! ```

use bytes::Bytes;
use kimberlite_types::Offset;

use crate::Key;
use crate::error::StoreError;
use crate::page::{Page, PageType};
use crate::types::PageId;
use crate::version::{RowVersion, VersionChain};

// ============================================================================
// Serialization Helpers
// ============================================================================

/// Serializes a key to bytes (length-prefixed).
fn serialize_key(key: &Key) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + key.len());
    buf.extend_from_slice(&(key.len() as u16).to_le_bytes());
    buf.extend_from_slice(key.as_bytes());
    buf
}

/// Deserializes a key from bytes, returning the key and remaining bytes.
fn deserialize_key(data: &[u8]) -> Result<(Key, &[u8]), StoreError> {
    if data.len() < 2 {
        return Err(StoreError::BTreeInvariant("key length truncated".into()));
    }

    let key_len = u16::from_le_bytes(data[0..2].try_into().unwrap()) as usize;
    if data.len() < 2 + key_len {
        return Err(StoreError::BTreeInvariant("key data truncated".into()));
    }

    let key = Key::from(&data[2..2 + key_len]);
    Ok((key, &data[2 + key_len..]))
}

/// Serializes a `RowVersion` to bytes.
fn serialize_version(version: &RowVersion) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + 4 + version.data.len());
    buf.extend_from_slice(&version.created_at.as_u64().to_le_bytes());
    buf.extend_from_slice(&version.deleted_at.as_u64().to_le_bytes());
    buf.extend_from_slice(&(version.data.len() as u32).to_le_bytes());
    buf.extend_from_slice(&version.data);
    buf
}

/// Deserializes a `RowVersion` from bytes, returning the version and remaining bytes.
fn deserialize_version(data: &[u8]) -> Result<(RowVersion, &[u8]), StoreError> {
    if data.len() < 20 {
        return Err(StoreError::BTreeInvariant(
            "version header truncated".into(),
        ));
    }

    let created_at = Offset::new(u64::from_le_bytes(data[0..8].try_into().unwrap()));
    let deleted_at = Offset::new(u64::from_le_bytes(data[8..16].try_into().unwrap()));
    let data_len = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;

    if data.len() < 20 + data_len {
        return Err(StoreError::BTreeInvariant("version data truncated".into()));
    }

    let version = RowVersion {
        created_at,
        deleted_at,
        data: Bytes::copy_from_slice(&data[20..20 + data_len]),
    };

    Ok((version, &data[20 + data_len..]))
}

// ============================================================================
// Leaf Entry
// ============================================================================

/// An entry in a leaf node: key + version chain.
#[derive(Debug, Clone)]
pub struct LeafEntry {
    pub key: Key,
    pub versions: VersionChain,
}

impl LeafEntry {
    /// Creates a new leaf entry with a single version.
    pub fn new(key: Key, version: RowVersion) -> Self {
        Self {
            key,
            versions: VersionChain::single(version),
        }
    }

    /// Serializes the entry to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let versions: Vec<&RowVersion> = self.versions.iter().collect();
        let version_data: Vec<Vec<u8>> = versions.iter().map(|v| serialize_version(v)).collect();
        let version_total: usize = version_data.iter().map(Vec::len).sum();

        let mut buf = Vec::with_capacity(2 + self.key.len() + 2 + version_total);

        // Key
        buf.extend_from_slice(&serialize_key(&self.key));

        // Version count
        buf.extend_from_slice(&(versions.len() as u16).to_le_bytes());

        // Versions
        for v in version_data {
            buf.extend_from_slice(&v);
        }

        buf
    }

    /// Deserializes an entry from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, StoreError> {
        let (key, remaining) = deserialize_key(data)?;

        if remaining.len() < 2 {
            return Err(StoreError::BTreeInvariant("version count truncated".into()));
        }

        let version_count = u16::from_le_bytes(remaining[0..2].try_into().unwrap()) as usize;
        let mut remaining = &remaining[2..];

        // Collect versions (they're stored newest-first)
        let mut version_vec = Vec::with_capacity(version_count);
        for _ in 0..version_count {
            let (version, rest) = deserialize_version(remaining)?;
            version_vec.push(version);
            remaining = rest;
        }

        // Use from_vec to preserve the serialized order (newest-first)
        let versions = VersionChain::from_vec(version_vec);

        Ok(Self { key, versions })
    }

    /// Returns the size of this entry when serialized.
    pub fn serialized_size(&self) -> usize {
        2 + self.key.len() + 2 + self.versions.total_size() + (self.versions.len() * 20)
    }
}

// ============================================================================
// Internal Entry
// ============================================================================

/// An entry in an internal node: key + child page pointer.
#[derive(Debug, Clone)]
pub struct InternalEntry {
    pub key: Key,
    pub child: PageId,
}

impl InternalEntry {
    /// Creates a new internal entry.
    pub fn new(key: Key, child: PageId) -> Self {
        Self { key, child }
    }

    /// Serializes the entry to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.key.len() + 8);
        buf.extend_from_slice(&serialize_key(&self.key));
        buf.extend_from_slice(&self.child.as_u64().to_le_bytes());
        buf
    }

    /// Deserializes an entry from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, StoreError> {
        let (key, remaining) = deserialize_key(data)?;

        if remaining.len() < 8 {
            return Err(StoreError::BTreeInvariant("child page id truncated".into()));
        }

        let child = PageId::new(u64::from_le_bytes(remaining[0..8].try_into().unwrap()));

        Ok(Self { key, child })
    }

    /// Returns the size of this entry when serialized.
    #[allow(dead_code)]
    pub fn serialized_size(&self) -> usize {
        2 + self.key.len() + 8
    }
}

// ============================================================================
// Leaf Node
// ============================================================================

/// A leaf node in the B+tree containing key-value pairs.
///
/// Leaf nodes store the actual data with MVCC version chains.
/// Keys are stored in sorted order for binary search.
#[derive(Debug)]
pub struct LeafNode {
    /// Entries sorted by key.
    entries: Vec<LeafEntry>,
    /// Link to next leaf (for range scans).
    pub next_leaf: Option<PageId>,
}

impl LeafNode {
    /// Creates a new empty leaf node.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_leaf: None,
        }
    }

    /// Loads a leaf node from a page.
    pub fn from_page(page: &Page) -> Result<Self, StoreError> {
        debug_assert_eq!(page.page_type(), PageType::Leaf, "expected leaf page");

        let mut entries = Vec::with_capacity(page.item_count());

        // First item (if exists) is the next_leaf pointer
        let next_leaf = if page.item_count() > 0 {
            let first_item = page.get_item(0);
            if first_item.len() == 8 {
                let page_id = u64::from_le_bytes(first_item.try_into().unwrap());
                if page_id == u64::MAX {
                    None
                } else {
                    Some(PageId::new(page_id))
                }
            } else {
                None
            }
        } else {
            None
        };

        // Remaining items are entries
        for i in 1..page.item_count() {
            let entry = LeafEntry::deserialize(page.get_item(i))?;
            entries.push(entry);
        }

        Ok(Self { entries, next_leaf })
    }

    /// Writes the leaf node to a page.
    ///
    /// v0.9.1 — promotes the generic `PageOverflow` to a typed
    /// `EntryTooLarge` when a *single* leaf entry can't fit on a page
    /// by itself. That case happens when one key's MVCC version chain
    /// has grown so long that even an empty leaf can't hold it; the
    /// surrounding split-on-byte-budget logic in
    /// [`crate::btree::BTree::insert_into_leaf`] is unable to save
    /// it because both halves of an empty / single-entry split still
    /// contain the same fat entry. Surfacing the offending key gives
    /// the SDK / operator something to act on.
    pub fn to_page(&self, page: &mut Page) -> Result<(), StoreError> {
        // Per-page byte budget (header + CRC reserved). Hoisted to the
        // top of the function so clippy's `items_after_statements`
        // doesn't trip — these are pure compile-time constants used
        // by the overflow check below.
        const SLOT_SIZE: usize = 4;
        let page_budget =
            crate::types::PAGE_SIZE - crate::types::PAGE_HEADER_SIZE - crate::types::CRC_SIZE;
        let next_leaf_overhead = SLOT_SIZE + 8;

        debug_assert_eq!(page.page_type(), PageType::Leaf, "expected leaf page");

        // Clear existing items (rebuild from scratch)
        while page.item_count() > 0 {
            page.remove_item(page.item_count() - 1);
        }

        // First item: next_leaf pointer (u64::MAX for None)
        let next_leaf_bytes = match self.next_leaf {
            Some(id) => id.as_u64().to_le_bytes(),
            None => u64::MAX.to_le_bytes(),
        };
        page.insert_item(0, &next_leaf_bytes)?;

        // Insert entries. Detect the single-entry-too-large case up
        // front so the error carries the offending key.
        for (i, entry) in self.entries.iter().enumerate() {
            let entry_size = entry.serialized_size();
            // The largest possible budget any one entry can claim is
            // `page_budget - next_leaf_overhead - SLOT_SIZE` (its own
            // slot). If that's exceeded, no split — degenerate or
            // otherwise — can rescue this write.
            let max_entry_capacity = page_budget
                .saturating_sub(next_leaf_overhead)
                .saturating_sub(SLOT_SIZE);
            if entry_size > max_entry_capacity {
                tracing::error!(
                    key = ?entry.key,
                    entry_size,
                    page_budget,
                    "B+tree leaf entry exceeds page byte budget; MVCC version chain has grown unbounded"
                );
                return Err(StoreError::EntryTooLarge {
                    key: entry.key.clone(),
                    entry_size,
                    page_budget,
                });
            }
            let data = entry.serialize();
            page.insert_item(i + 1, &data)?;
        }

        Ok(())
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the node is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Estimates the serialized size on a page — `SLOT_SIZE + 8` for the
    /// leading `next_leaf` pointer plus `SLOT_SIZE + entry.serialized_size()`
    /// per entry. The B+tree splits when this exceeds the page's usable
    /// byte capacity, so a small handful of very wide rows (say, a Better
    /// Auth session row with a JWT-sized token) still fits rather than
    /// erroring with `PageOverflow`.
    pub fn size_on_page(&self) -> usize {
        // `SLOT_SIZE = 4` by construction in `page.rs`. We re-declare it
        // locally rather than cross-importing to keep `node.rs` free of
        // page-layout internals.
        const SLOT_SIZE: usize = 4;
        let mut total = SLOT_SIZE + 8; // next_leaf pointer slot + payload
        for entry in &self.entries {
            total += SLOT_SIZE + entry.serialized_size();
        }
        total
    }

    /// Finds the index where the key should be inserted (or exists).
    fn find_key_index(&self, key: &Key) -> Result<usize, usize> {
        self.entries.binary_search_by(|e| e.key.cmp(key))
    }

    /// Gets the entry for a key.
    pub fn get(&self, key: &Key) -> Option<&LeafEntry> {
        match self.find_key_index(key) {
            Ok(idx) => Some(&self.entries[idx]),
            Err(_) => None,
        }
    }

    /// Gets a mutable entry for a key.
    #[allow(dead_code)]
    pub fn get_mut(&mut self, key: &Key) -> Option<&mut LeafEntry> {
        match self.find_key_index(key) {
            Ok(idx) => Some(&mut self.entries[idx]),
            Err(_) => None,
        }
    }

    /// Inserts or updates an entry.
    ///
    /// Returns true if a new entry was inserted, false if updated.
    pub fn insert(&mut self, key: Key, version: RowVersion) -> bool {
        match self.find_key_index(&key) {
            Ok(idx) => {
                // Key exists, add new version
                self.entries[idx].versions.add(version);
                false
            }
            Err(idx) => {
                // New key, insert at sorted position
                self.entries.insert(idx, LeafEntry::new(key, version));
                true
            }
        }
    }

    /// Deletes a key by marking its current version as deleted.
    ///
    /// Returns true if the key existed and was marked deleted.
    pub fn delete(&mut self, key: &Key, pos: Offset) -> bool {
        match self.find_key_index(key) {
            Ok(idx) => self.entries[idx].versions.delete_at(pos),
            Err(_) => false,
        }
    }

    /// Returns an iterator over entries in key order.
    #[allow(dead_code)]
    pub fn iter(&self) -> impl Iterator<Item = &LeafEntry> {
        self.entries.iter()
    }

    /// Returns entries in the key range `[start, end]` inclusive at
    /// both ends when the end key is present, `[start, end)` otherwise.
    /// Callers that need strict half-open semantics filter the
    /// trailing entry with `entry.key >= range.end` themselves — see
    /// `BTree::scan` for the pattern.
    ///
    /// If the range is inverted (`start > end`) or otherwise selects
    /// no entries, returns an empty iterator. An inverted range used
    /// to panic ("slice index starts at 2 but ends at 0") when
    /// `start` was greater than every key in the node and `end`
    /// preceded them — found by the NoREC fuzz oracle within ~2
    /// seconds of fuzzing on 2026-04-18.
    pub fn range(&self, start: &Key, end: &Key) -> impl Iterator<Item = &LeafEntry> {
        let start_idx = match self.find_key_index(start) {
            Ok(i) | Err(i) => i,
        };
        let end_idx = match self.find_key_index(end) {
            Ok(i) => i + 1, // Include the end key if it exists
            Err(i) => i,
        };

        // Clamp so the slice index is always well-formed. The natural
        // interpretation of `[start, end)` when `start > end` is the
        // empty set, so the clamp matches that semantic.
        let len = self.entries.len();
        let lo = start_idx.min(end_idx).min(len);
        let hi = end_idx.min(len);
        self.entries[lo..hi].iter()
    }

    /// Splits the node at the middle, returning the right half.
    pub fn split(&mut self) -> (Key, LeafNode) {
        let mid = self.entries.len() / 2;
        let right_entries = self.entries.split_off(mid);
        let split_key = right_entries[0].key.clone();

        let right = LeafNode {
            entries: right_entries,
            next_leaf: self.next_leaf,
        };

        (split_key, right)
    }

    /// Returns the first key in this node.
    #[allow(dead_code)]
    pub fn first_key(&self) -> Option<&Key> {
        self.entries.first().map(|e| &e.key)
    }

    /// Returns the last key in this node.
    #[allow(dead_code)]
    pub fn last_key(&self) -> Option<&Key> {
        self.entries.last().map(|e| &e.key)
    }
}

impl Default for LeafNode {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Internal Node
// ============================================================================

/// An internal node in the B+tree containing keys and child pointers.
///
/// Internal nodes guide search to the appropriate leaf. They store n keys
/// and n+1 child pointers, where all keys in child[i] are < key[i] <= all keys in child[i+1].
#[derive(Debug)]
pub struct InternalNode {
    /// Keys separating children.
    keys: Vec<Key>,
    /// Child page IDs (one more than keys).
    children: Vec<PageId>,
}

impl InternalNode {
    /// Creates a new internal node with a single child.
    #[allow(dead_code)]
    pub fn new(first_child: PageId) -> Self {
        Self {
            keys: Vec::new(),
            children: vec![first_child],
        }
    }

    /// Creates an internal node from two children and a separator key.
    pub fn from_split(left: PageId, key: Key, right: PageId) -> Self {
        Self {
            keys: vec![key],
            children: vec![left, right],
        }
    }

    /// Loads an internal node from a page.
    pub fn from_page(page: &Page) -> Result<Self, StoreError> {
        debug_assert_eq!(
            page.page_type(),
            PageType::Internal,
            "expected internal page"
        );

        if page.item_count() == 0 {
            return Err(StoreError::BTreeInvariant("empty internal node".into()));
        }

        // First item is the leftmost child
        let first_item = page.get_item(0);
        if first_item.len() != 8 {
            return Err(StoreError::BTreeInvariant("invalid first child".into()));
        }
        let first_child = PageId::new(u64::from_le_bytes(first_item.try_into().unwrap()));

        let mut keys = Vec::new();
        let mut children = vec![first_child];

        // Remaining items are (key, child) pairs
        for i in 1..page.item_count() {
            let entry = InternalEntry::deserialize(page.get_item(i))?;
            keys.push(entry.key);
            children.push(entry.child);
        }

        Ok(Self { keys, children })
    }

    /// Writes the internal node to a page.
    pub fn to_page(&self, page: &mut Page) -> Result<(), StoreError> {
        debug_assert_eq!(
            page.page_type(),
            PageType::Internal,
            "expected internal page"
        );

        // Clear existing items
        while page.item_count() > 0 {
            page.remove_item(page.item_count() - 1);
        }

        // First item: leftmost child
        page.insert_item(0, &self.children[0].as_u64().to_le_bytes())?;

        // Insert (key, child) pairs
        for (i, (key, child)) in self
            .keys
            .iter()
            .zip(self.children.iter().skip(1))
            .enumerate()
        {
            let entry = InternalEntry::new(key.clone(), *child);
            page.insert_item(i + 1, &entry.serialize())?;
        }

        Ok(())
    }

    /// Returns the number of keys.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Returns the number of children.
    #[allow(dead_code)]
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Finds the child index for a key.
    pub fn find_child_index(&self, key: &Key) -> usize {
        match self.keys.binary_search_by(|k| k.cmp(key)) {
            Ok(i) => i + 1, // Key found, go to right child
            Err(i) => i,    // Key not found, go to child at insertion point
        }
    }

    /// Returns the child page ID for a key.
    pub fn find_child(&self, key: &Key) -> PageId {
        let idx = self.find_child_index(key);
        self.children[idx]
    }

    /// Inserts a new key and right child after a split.
    ///
    /// The right child goes after the key at the position where key should be inserted.
    pub fn insert(&mut self, key: Key, right_child: PageId) {
        let idx = match self.keys.binary_search_by(|k| k.cmp(&key)) {
            Ok(i) | Err(i) => i,
        };
        self.keys.insert(idx, key);
        self.children.insert(idx + 1, right_child);
    }

    /// Splits the node at the middle, returning the split key and right half.
    pub fn split(&mut self) -> (Key, InternalNode) {
        let mid = self.keys.len() / 2;

        // The middle key goes up to the parent
        let split_key = self.keys.remove(mid);

        // Right half gets keys and children after the split point
        let right_keys = self.keys.split_off(mid);
        let right_children = self.children.split_off(mid + 1);

        let right = InternalNode {
            keys: right_keys,
            children: right_children,
        };

        (split_key, right)
    }

    /// Returns the first key.
    #[allow(dead_code)]
    pub fn first_key(&self) -> Option<&Key> {
        self.keys.first()
    }

    /// Returns the leftmost child.
    #[allow(dead_code)]
    pub fn first_child(&self) -> PageId {
        self.children[0]
    }

    /// Returns all children.
    #[allow(dead_code)]
    pub fn children(&self) -> &[PageId] {
        &self.children
    }
}

#[cfg(test)]
mod node_tests {
    use super::*;

    #[test]
    fn test_leaf_entry_serialization() {
        let entry = LeafEntry::new(
            Key::from("test-key"),
            RowVersion::new(Offset::new(5), Bytes::from("test-value")),
        );

        let serialized = entry.serialize();
        let deserialized = LeafEntry::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.key, entry.key);
        assert_eq!(deserialized.versions.len(), entry.versions.len());
    }

    #[test]
    fn test_internal_entry_serialization() {
        let entry = InternalEntry::new(Key::from("separator"), PageId::new(42));

        let serialized = entry.serialize();
        let deserialized = InternalEntry::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.key, entry.key);
        assert_eq!(deserialized.child, entry.child);
    }

    #[test]
    fn test_leaf_range_inverted_returns_empty() {
        // Regression for the panic found by fuzz_sql_norec on EPYC
        // on 2026-04-18 after ~2s of fuzzing: calling
        // `LeafNode::range(start, end)` with `start > end` (where
        // `start` was greater than every key in the leaf) panicked
        // with "slice index starts at 2 but ends at 0".
        //
        // The semantically correct behaviour is an empty iterator —
        // a half-open interval `[start, end)` with `start > end` is
        // empty.
        let mut node = LeafNode::new();
        for k in ["a", "b", "c"] {
            node.insert(
                Key::from(k),
                RowVersion::new(Offset::new(1), Bytes::from(k)),
            );
        }

        // Inverted range — start greater than every key, end before them.
        let inverted: Vec<&Key> = node
            .range(&Key::from("zzz"), &Key::from("0"))
            .map(|e| &e.key)
            .collect();
        assert!(inverted.is_empty(), "inverted range must return empty");

        // Start past end but both within the key set.
        let past: Vec<&Key> = node
            .range(&Key::from("c"), &Key::from("a"))
            .map(|e| &e.key)
            .collect();
        assert!(past.is_empty(), "start > end within key set must be empty");

        // Sanity: a well-formed range still works. Inclusive-end
        // semantics mean `[a, c]` returns all three entries.
        let normal: Vec<&Key> = node
            .range(&Key::from("a"), &Key::from("c"))
            .map(|e| &e.key)
            .collect();
        assert_eq!(
            normal,
            vec![&Key::from("a"), &Key::from("b"), &Key::from("c")]
        );
    }

    #[test]
    fn test_leaf_node_operations() {
        let mut node = LeafNode::new();

        // Insert in random order
        node.insert(
            Key::from("c"),
            RowVersion::new(Offset::new(1), Bytes::from("C")),
        );
        node.insert(
            Key::from("a"),
            RowVersion::new(Offset::new(2), Bytes::from("A")),
        );
        node.insert(
            Key::from("b"),
            RowVersion::new(Offset::new(3), Bytes::from("B")),
        );

        assert_eq!(node.len(), 3);

        // Should be sorted
        let keys: Vec<&Key> = node.iter().map(|e| &e.key).collect();
        assert_eq!(keys[0], &Key::from("a"));
        assert_eq!(keys[1], &Key::from("b"));
        assert_eq!(keys[2], &Key::from("c"));

        // Get should work
        assert!(node.get(&Key::from("b")).is_some());
        assert!(node.get(&Key::from("d")).is_none());
    }

    #[test]
    fn test_internal_node_find_child() {
        let mut node = InternalNode::new(PageId::new(0));
        node.insert(Key::from("m"), PageId::new(1));
        node.insert(Key::from("t"), PageId::new(2));

        // Keys < "m" go to child 0
        assert_eq!(node.find_child(&Key::from("a")), PageId::new(0));
        // Keys >= "m" and < "t" go to child 1
        assert_eq!(node.find_child(&Key::from("m")), PageId::new(1));
        assert_eq!(node.find_child(&Key::from("n")), PageId::new(1));
        // Keys >= "t" go to child 2
        assert_eq!(node.find_child(&Key::from("t")), PageId::new(2));
        assert_eq!(node.find_child(&Key::from("z")), PageId::new(2));
    }
}
