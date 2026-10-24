//! Property tests: the efficient tree must agree with the RFC reference on
//! every size, and verification must accept every honest proof and reject
//! every tampered one.

use ledger_core::{MerkleTree, Snapshot, VerifyError, leaf_hash, reference};
use proptest::prelude::*;

fn build(n: usize) -> (Vec<ledger_core::Hash>, MerkleTree) {
    let leaves: Vec<_> = (0..n as u64).map(|i| leaf_hash(&i.to_le_bytes())).collect();
    let mut tree = MerkleTree::new();
    for l in &leaves {
        tree.push(*l);
    }
    (leaves, tree)
}

fn snap(tree: &MerkleTree, size: u64) -> Snapshot {
    Snapshot {
        size,
        root: tree.root_at(size).unwrap(),
    }
}

/// Flip one bit in one hash of a proof path.
fn corrupt(path: &mut [ledger_core::Hash], which: usize, bit: u8) {
    let i = which % path.len();
    path[i].0[usize::from(bit / 8) % 32] ^= 1 << (bit % 8);
}

/// Exhaustive over every (index, size) and (old, new) pair for small trees:
/// the off-by-one bugs in this domain live at tiny sizes and powers of two.
#[test]
fn exhaustive_small_trees() {
    const N: usize = 40;
    let (leaves, tree) = build(N);
    for n in 0..=N {
        let size = n as u64;
        assert_eq!(
            tree.root_at(size).unwrap(),
            reference::root(&leaves[..n]),
            "root {n}"
        );
        for i in 0..n {
            let proof = tree.inclusion_proof(i as u64, size).unwrap();
            assert_eq!(
                proof.path,
                reference::inclusion_path(&leaves[..n], i),
                "incl {i}/{n}"
            );
            proof.verify(&leaves[i], &snap(&tree, size)).unwrap();
        }
        for m in 0..=n {
            let proof = tree.consistency_proof(m as u64, size).unwrap();
            if m > 0 {
                assert_eq!(
                    proof.path,
                    reference::consistency_path(&leaves[..n], m),
                    "cons {m}/{n}"
                );
            }
            proof
                .verify(&snap(&tree, m as u64), &snap(&tree, size))
                .unwrap();
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn honest_inclusion_verifies((size, index) in (1u64..2000).prop_flat_map(|s| (Just(s), 0..s))) {
        let (leaves, tree) = build(usize::try_from(size).unwrap());
        let proof = tree.inclusion_proof(index, size).unwrap();
        prop_assert_eq!(proof.verify(&leaves[usize::try_from(index).unwrap()], &tree.snapshot()), Ok(()));
    }

    #[test]
    fn tampered_inclusion_rejected(
        (size, index) in (2u64..2000).prop_flat_map(|s| (Just(s), 0..s)),
        which in any::<usize>(),
        bit in any::<u8>(),
        delta in 1u64..2000,
    ) {
        let (leaves, tree) = build(usize::try_from(size).unwrap());
        let leaf = leaves[usize::try_from(index).unwrap()];
        let honest = tree.inclusion_proof(index, size).unwrap();
        let snapshot = tree.snapshot();

        let mut p = honest.clone();
        corrupt(&mut p.path, which, bit);
        prop_assert!(p.verify(&leaf, &snapshot).is_err(), "corrupted path accepted");

        let mut p = honest.clone();
        p.path.pop();
        prop_assert!(p.verify(&leaf, &snapshot).is_err(), "truncated path accepted");

        let mut p = honest.clone();
        p.path.push(leaf);
        prop_assert!(matches!(p.verify(&leaf, &snapshot), Err(VerifyError::WrongLength { .. })), "extended path not rejected by length");

        let mut p = honest.clone();
        p.leaf_index = (index + 1 + delta % (size - 1)) % size; // always != index
        prop_assert!(p.verify(&leaf, &snapshot).is_err(), "moved index accepted");

        let mut p = honest;
        p.leaf_index = index + size;
        prop_assert!(matches!(p.verify(&leaf, &snapshot), Err(VerifyError::IndexOutOfRange { .. })), "out-of-range index not rejected");
    }

    #[test]
    fn honest_consistency_verifies((new, old) in (1u64..2000).prop_flat_map(|n| (Just(n), 0..=n))) {
        let (_, tree) = build(usize::try_from(new).unwrap());
        let proof = tree.consistency_proof(old, new).unwrap();
        prop_assert_eq!(proof.verify(&snap(&tree, old), &snap(&tree, new)), Ok(()));
    }

    #[test]
    fn tampered_consistency_rejected(
        (new, old) in (2u64..2000).prop_flat_map(|n| (Just(n), 1..n)),
        which in any::<usize>(),
        bit in any::<u8>(),
    ) {
        let (_, tree) = build(usize::try_from(new).unwrap());
        let honest = tree.consistency_proof(old, new).unwrap();
        let (o, n) = (snap(&tree, old), snap(&tree, new));

        if !honest.path.is_empty() {
            let mut p = honest.clone();
            corrupt(&mut p.path, which, bit);
            prop_assert!(p.verify(&o, &n).is_err(), "corrupted path accepted");

            let mut p = honest.clone();
            p.path.pop();
            prop_assert!(p.verify(&o, &n).is_err(), "truncated path accepted");
        }

        // A rewritten history: same old size, different old root.
        let mut forged_old = o;
        forged_old.root.0[0] ^= 1;
        prop_assert!(honest.verify(&forged_old, &n).is_err(), "forged old root accepted");

        // The proof is bound to the sizes it was made for.
        let shifted = snap(&tree, old - 1);
        if old > 1 {
            prop_assert!(honest.verify(&shifted, &n).is_err(), "wrong old size accepted");
        }
    }

    /// Verification must never panic, whatever garbage it is given.
    #[test]
    fn verify_never_panics(
        index in any::<u64>(),
        size in any::<u64>(),
        old in any::<u64>(),
        path in proptest::collection::vec(any::<[u8; 32]>(), 0..70),
    ) {
        let path: Vec<_> = path.into_iter().map(ledger_core::Hash).collect();
        let root = leaf_hash(b"root");
        let incl = ledger_core::InclusionProof { leaf_index: index, path: path.clone() };
        let _ = incl.verify(&root, &Snapshot { size, root });
        let cons = ledger_core::ConsistencyProof { path };
        let _ = cons.verify(&Snapshot { size: old, root }, &Snapshot { size, root });
    }
}
