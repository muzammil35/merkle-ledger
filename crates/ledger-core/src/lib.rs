//! Pure cryptographic core of the ledger: no I/O, no clocks, no randomness.
//!
//! Everything here is a deterministic function of its inputs, which keeps it
//! easy to test exhaustively and lets the storage layer treat it as a black box.
//!
//! The tree follows RFC 9162 (Certificate Transparency v2), section 2.1:
//! - [`hash`]: leaf/node hashing with domain separation.
//! - [`reference`]: the RFC's recursive definitions, verbatim. Slow; used as a test oracle.
//! - [`tree`]: an efficient append-only in-memory Merkle tree.
//! - [`proof`]: inclusion and consistency proofs, and their verification.

pub mod hash;
pub mod proof;
pub mod reference;
pub mod tree;

pub use hash::{Hash, empty_root, leaf_hash, node_hash};
pub use proof::{ConsistencyProof, InclusionProof, VerifyError};
pub use tree::{MerkleTree, TreeError};

/// A commitment to the first `size` leaves of a log.
///
/// A snapshot is only as trustworthy as the channel you obtained it from.
/// The storage engine signs snapshots (milestone 5); verifiers pin them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// Number of leaves covered.
    pub size: u64,
    /// Merkle tree hash of those leaves.
    pub root: Hash,
}

/// Largest power of two strictly less than `n`. This is the RFC's `k`.
///
/// # Panics
/// Panics if `n < 2`.
#[must_use]
pub fn split_point(n: u64) -> u64 {
    assert!(n >= 2, "split_point requires n >= 2, got {n}");
    1 << (n - 1).ilog2()
}

#[cfg(test)]
mod tests {
    use super::split_point;

    #[test]
    fn split_point_matches_definition() {
        for n in 2..=1025u64 {
            let k = split_point(n);
            assert!(k.is_power_of_two() && k < n && 2 * k >= n, "n={n} k={k}");
        }
    }
}
