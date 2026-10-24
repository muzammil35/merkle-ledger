//! Efficient append-only Merkle tree held in memory.
//!
//! Milestone 4 moves this structure onto disk; the public API stays the same.
//!
//! TASK 3. Implement the tree using the representation described on
//! [`MerkleTree`] (or argue for a better one in review). Targets:
//! - `push`: amortized O(1) hashes, never recomputes a stored node.
//! - `root_at` / proofs: O(log n) stored-node lookups for any historical size,
//!   with no access to the raw leaves list beyond `levels[0]`.
//!
//! Key insight to discover: every range the RFC recursion visits is either a
//! perfect, aligned subtree (already stored) or splits into one. Prove that to
//! yourself on paper for n = 13 before writing code.
//!
//! Done when: all of `cargo test -p ledger-core` passes.

use crate::{ConsistencyProof, Hash, InclusionProof, Snapshot};

/// Errors from asking the tree for something it cannot provide.
///
/// Unlike [`crate::VerifyError`], these indicate a caller bug or a request for
/// data that does not exist yet, not a cryptographic failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TreeError {
    /// Requested a tree size larger than the number of leaves.
    #[error("tree size {size} exceeds current length {len}")]
    SizeOutOfRange {
        /// Requested size.
        size: u64,
        /// Current number of leaves.
        len: u64,
    },
    /// Requested a leaf index not smaller than the tree size.
    #[error("leaf index {index} out of range for tree size {size}")]
    IndexOutOfRange {
        /// Requested index.
        index: u64,
        /// Tree size the index was checked against.
        size: u64,
    },
    /// Requested a consistency proof with `old > new`.
    #[error("old size {old} is greater than new size {new}")]
    SizeOrder {
        /// Old size.
        old: u64,
        /// New size.
        new: u64,
    },
}

/// An append-only Merkle tree that can produce roots and proofs for any
/// historical size, not just the current one.
///
/// Representation: `levels[h][i]` is the hash of the perfect subtree of `2^h`
/// leaves starting at leaf `i * 2^h`. Only *complete* subtrees are stored, so
/// they never change once written, which is what makes this append-only
/// layout easy to persist later.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    /// Creates an empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self {
            levels: vec![Vec::new()],
        }
    }

    /// Number of leaves.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.levels[0].len() as u64
    }

    /// Whether the tree has no leaves.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    /// Appends a leaf hash and returns its index. Amortized O(1) hashing.
    pub fn push(&mut self, leaf: Hash) -> u64 {
        todo!("Task 3")
    }

    /// Root of the current tree.
    #[must_use]
    pub fn root(&self) -> Hash {
        todo!("Task 3")
    }

    /// Snapshot of the current tree.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            size: self.len(),
            root: self.root(),
        }
    }

    /// Root of the tree as it was when it had `size` leaves.
    ///
    /// # Errors
    /// [`TreeError::SizeOutOfRange`] if `size > self.len()`.
    pub fn root_at(&self, size: u64) -> Result<Hash, TreeError> {
        todo!("Task 3")
    }

    /// Inclusion proof for leaf `index` in the tree of the given `size`.
    ///
    /// # Errors
    /// [`TreeError::SizeOutOfRange`] or [`TreeError::IndexOutOfRange`].
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Result<InclusionProof, TreeError> {
        todo!("Task 3")
    }

    /// Consistency proof between sizes `old` and `new`.
    ///
    /// Returns an empty proof when `old == 0` or `old == new`.
    ///
    /// # Errors
    /// [`TreeError::SizeOutOfRange`] or [`TreeError::SizeOrder`].
    pub fn consistency_proof(&self, old: u64, new: u64) -> Result<ConsistencyProof, TreeError> {
        todo!("Task 3")
    }
}
