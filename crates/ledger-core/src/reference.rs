//! RFC 9162 section 2.1 definitions, transcribed as directly as possible.
//!
//! These functions are O(n) per call and exist to be *obviously correct*, not
//! fast. Tests compare the efficient [`crate::tree::MerkleTree`] against them.
//! Inputs are leaf hashes (already passed through [`crate::leaf_hash`]).
//!
//! TASK 1. Read RFC 9162 §2.1.1 (MTH), §2.1.3.1 (PATH), §2.1.4.1 (PROOF /
//! SUBPROOF) and transcribe them. Resist optimizing: the value of an oracle is
//! that you can check it against the RFC line by line. Use
//! [`crate::split_point`] for the RFC's `k`.
//!
//! Done when: `cargo test --test vectors reference_` passes.

use crate::{Hash, empty_root, node_hash, split_point};

/// `MTH(D[n])`: the Merkle tree hash of `leaves`.
#[must_use]
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => {
            empty_root()
        },
        1 =>{
            leaves[0]
        },
        n => {
            let k = split_point(n as u64) as usize;
            let left_root = root(&leaves[..k]);
            let right_root = root(&leaves[k..]);
            node_hash(&left_root, &right_root)            
        }
    }
}

/// `PATH(m, D[n])`: the audit path proving `leaves[index]` is in the tree.
///
/// # Panics
/// Panics if `index >= leaves.len()`.
#[must_use]
pub fn inclusion_path(leaves: &[Hash], index: usize) -> Vec<Hash> {
    todo!("Task 1: PATH")
}

/// `PROOF(m, D[n])`: proves the first `old_size` leaves are a prefix of `leaves`.
///
/// # Panics
/// Panics unless `0 < old_size <= leaves.len()`.
#[must_use]
pub fn consistency_path(leaves: &[Hash], old_size: usize) -> Vec<Hash> {
    todo!("Task 1: PROOF, via a private SUBPROOF helper")
}
