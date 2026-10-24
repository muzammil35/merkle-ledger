//! Inclusion and consistency proofs (RFC 9162 sections 2.1.3 and 2.1.4).
//!
//! Verification is the security boundary of the whole system: proofs arrive
//! from an untrusted party, so these functions must reject *every* malformed
//! input, never panic, and do bounded work regardless of what they are fed.
//!
//! TASK 2. Implement both `verify` methods following RFC 9162 §2.1.3.2 and
//! §2.1.4.2, with two hardening requirements the RFC leaves implicit:
//!
//! 1. Compute the *exact* expected path length from the sizes/index and reject
//!    with [`VerifyError::WrongLength`] before hashing anything. (Why does this
//!    matter for a server that verifies proofs from strangers?)
//! 2. Never panic, for any `u64` inputs. Think hard about `size - 1`, shifts by
//!    64, and indexing `path[0]`. `verify_never_panics` will hunt for these.
//!
//! The edge-case conventions (empty old tree, equal sizes) are documented on
//! [`ConsistencyProof::verify`] and pinned by `consistency_edge_conventions`.
//!
//! Done when: `cargo test --test vectors verify_ inclusion_ consistency_` passes
//! (then the property tests once Task 3 is done).

use crate::{Hash, Snapshot};

/// Proof that a leaf is included in the tree described by some [`Snapshot`].
///
/// The tree size is deliberately not stored here: it comes from the snapshot
/// the proof is checked against, so the two can never disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Zero-based position of the leaf.
    pub leaf_index: u64,
    /// Sibling hashes from the leaf up to the root.
    pub path: Vec<Hash>,
}

/// Proof that one snapshot's tree is a prefix of another's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    /// Node hashes as defined by RFC 9162 `PROOF(m, D[n])`.
    pub path: Vec<Hash>,
}

/// Why a proof was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// The leaf index is not smaller than the snapshot size.
    #[error("leaf index {index} out of range for tree size {size}")]
    IndexOutOfRange {
        /// Claimed leaf index.
        index: u64,
        /// Snapshot size.
        size: u64,
    },
    /// The old snapshot is larger than the new one.
    #[error("old size {old} is greater than new size {new}")]
    SizeOrder {
        /// Old snapshot size.
        old: u64,
        /// New snapshot size.
        new: u64,
    },
    /// The proof has the wrong number of hashes for the given sizes.
    #[error("proof has {actual} hashes, expected {expected}")]
    WrongLength {
        /// Length implied by the index and sizes.
        expected: usize,
        /// Length actually supplied.
        actual: usize,
    },
    /// The recomputed root does not match the snapshot.
    #[error("recomputed root does not match snapshot")]
    RootMismatch,
}

impl InclusionProof {
    /// Checks that `leaf` (a leaf hash) is at `self.leaf_index` in `snapshot`.
    ///
    /// # Errors
    /// Returns a [`VerifyError`] describing the first check that failed.
    pub fn verify(&self, leaf: &Hash, snapshot: &Snapshot) -> Result<(), VerifyError> {
        todo!("Task 2: RFC 9162 §2.1.3.2")
    }
}

impl ConsistencyProof {
    /// Checks that `old` is a prefix of `new`.
    ///
    /// Conventions: the empty tree is consistent with every tree (empty proof),
    /// and equal sizes require an empty proof and equal roots.
    ///
    /// # Errors
    /// Returns a [`VerifyError`] describing the first check that failed.
    pub fn verify(&self, old: &Snapshot, new: &Snapshot) -> Result<(), VerifyError> {
        todo!("Task 2: RFC 9162 §2.1.4.2")
    }
}
