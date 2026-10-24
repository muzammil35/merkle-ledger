//! Known-answer tests. Roots and proofs over the Certificate Transparency
//! 8-leaf test set, computed independently from the RFC 9162 definitions.
//! (The size-1 and size-8 roots match the published CT test vectors.)

use ledger_core::{
    ConsistencyProof, Hash, InclusionProof, MerkleTree, Snapshot, VerifyError, leaf_hash, reference,
};

const DATA: [&[u8]; 8] = [
    b"",
    b"\x00",
    b"\x10",
    b"\x20\x21",
    b"\x30\x31",
    b"\x40\x41\x42\x43",
    b"\x50\x51\x52\x53\x54\x55\x56\x57",
    b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
];

const ROOTS: [&str; 9] = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];

/// (leaf index, tree size, path)
const INCLUSION: &[(u64, u64, &[&str])] = &[
    (0, 1, &[]),
    (
        0,
        8,
        &[
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ],
    ),
    (
        5,
        8,
        &[
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ],
    ),
    (
        2,
        3,
        &["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"],
    ),
    (
        1,
        5,
        &[
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        ],
    ),
];

/// (old size, new size, path)
const CONSISTENCY: &[(u64, u64, &[&str])] = &[
    (1, 1, &[]),
    (
        1,
        8,
        &[
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ],
    ),
    (
        6,
        8,
        &[
            "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ],
    ),
    (
        2,
        5,
        &[
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        ],
    ),
    (
        3,
        7,
        &[
            "0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
            "07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "837dbb152e9b079010717e84e865da4ebc0fa198a806d59d31bf15accef22d0e",
        ],
    ),
    (
        4,
        8,
        &["6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"],
    ),
];

fn h(s: &str) -> Hash {
    Hash::from_hex(s).unwrap()
}

fn hashes(v: &[&str]) -> Vec<Hash> {
    v.iter().map(|s| h(s)).collect()
}

fn leaves() -> Vec<Hash> {
    DATA.iter().map(|d| leaf_hash(d)).collect()
}

fn snap(size: u64) -> Snapshot {
    Snapshot {
        size,
        root: h(ROOTS[usize::try_from(size).unwrap()]),
    }
}

fn idx(n: u64) -> usize {
    usize::try_from(n).unwrap()
}

// ---- Task 1: reference ---------------------------------------------------

#[test]
fn reference_roots() {
    let l = leaves();
    for (n, want) in ROOTS.iter().enumerate() {
        assert_eq!(reference::root(&l[..n]), h(want), "size {n}");
    }
}

#[test]
fn reference_inclusion_paths() {
    let l = leaves();
    for &(i, n, want) in INCLUSION {
        assert_eq!(
            reference::inclusion_path(&l[..idx(n)], idx(i)),
            hashes(want),
            "index {i} size {n}"
        );
    }
}

#[test]
fn reference_consistency_paths() {
    let l = leaves();
    for &(m, n, want) in CONSISTENCY {
        assert_eq!(
            reference::consistency_path(&l[..idx(n)], idx(m)),
            hashes(want),
            "{m} -> {n}"
        );
    }
}

// ---- Task 2: verification ------------------------------------------------

#[test]
fn verify_known_inclusion_proofs() {
    let l = leaves();
    for &(i, n, path) in INCLUSION {
        let proof = InclusionProof {
            leaf_index: i,
            path: hashes(path),
        };
        assert_eq!(
            proof.verify(&l[idx(i)], &snap(n)),
            Ok(()),
            "index {i} size {n}"
        );
    }
}

#[test]
fn verify_known_consistency_proofs() {
    for &(m, n, path) in CONSISTENCY {
        let proof = ConsistencyProof { path: hashes(path) };
        assert_eq!(proof.verify(&snap(m), &snap(n)), Ok(()), "{m} -> {n}");
    }
}

#[test]
fn inclusion_rejects_bad_requests() {
    let l = leaves();
    let empty = InclusionProof {
        leaf_index: 0,
        path: vec![],
    };
    assert_eq!(
        empty.verify(&l[0], &snap(0)),
        Err(VerifyError::IndexOutOfRange { index: 0, size: 0 })
    );
    // Right length (3 for index 5 of 8), wrong leaf.
    let (_, _, path) = INCLUSION[2];
    let proof = InclusionProof {
        leaf_index: 5,
        path: hashes(path),
    };
    assert_eq!(
        proof.verify(&l[4], &snap(8)),
        Err(VerifyError::RootMismatch)
    );
    // Same proof claimed for a 7-leaf tree, where index 5 needs 3 hashes too
    // but different ones.
    assert_eq!(
        proof.verify(&l[5], &snap(7)),
        Err(VerifyError::RootMismatch)
    );
    // Same proof, but claimed for a 6-leaf tree, where index 5 needs 2 hashes.
    assert_eq!(
        proof.verify(&l[5], &snap(6)),
        Err(VerifyError::WrongLength {
            expected: 2,
            actual: 3
        })
    );
}

#[test]
fn consistency_edge_conventions() {
    let empty = ConsistencyProof { path: vec![] };
    // The empty tree is a prefix of everything.
    assert_eq!(empty.verify(&snap(0), &snap(5)), Ok(()));
    // Equal sizes need equal roots...
    assert_eq!(empty.verify(&snap(5), &snap(5)), Ok(()));
    let forged = Snapshot {
        size: 5,
        root: h(ROOTS[4]),
    };
    assert_eq!(
        empty.verify(&snap(5), &forged),
        Err(VerifyError::RootMismatch)
    );
    // ...and an empty proof.
    let junk = ConsistencyProof {
        path: vec![h(ROOTS[1])],
    };
    assert_eq!(
        junk.verify(&snap(5), &snap(5)),
        Err(VerifyError::WrongLength {
            expected: 0,
            actual: 1
        })
    );
    assert_eq!(
        empty.verify(&snap(6), &snap(5)),
        Err(VerifyError::SizeOrder { old: 6, new: 5 })
    );
    // A non-trivial pair with no proof must be rejected, not accepted.
    assert!(empty.verify(&snap(3), &snap(7)).is_err());
}

// ---- Task 3: efficient tree ----------------------------------------------

fn full_tree() -> MerkleTree {
    let mut t = MerkleTree::new();
    for (i, leaf) in leaves().into_iter().enumerate() {
        assert_eq!(t.push(leaf), i as u64);
    }
    t
}

#[test]
fn tree_roots_at_every_size() {
    let t = full_tree();
    assert_eq!(t.len(), 8);
    assert_eq!(t.root(), h(ROOTS[8]));
    for n in 0..=8 {
        assert_eq!(t.root_at(n), Ok(h(ROOTS[idx(n)])), "size {n}");
    }
    assert_eq!(MerkleTree::new().root(), h(ROOTS[0]));
}

#[test]
fn tree_proofs_match_vectors() {
    let t = full_tree();
    for &(i, n, path) in INCLUSION {
        assert_eq!(t.inclusion_proof(i, n).unwrap().path, hashes(path));
    }
    for &(m, n, path) in CONSISTENCY {
        assert_eq!(t.consistency_proof(m, n).unwrap().path, hashes(path));
    }
}

#[test]
fn tree_rejects_bad_requests() {
    use ledger_core::TreeError;
    let t = full_tree();
    assert_eq!(
        t.root_at(9),
        Err(TreeError::SizeOutOfRange { size: 9, len: 8 })
    );
    assert_eq!(
        t.inclusion_proof(3, 3),
        Err(TreeError::IndexOutOfRange { index: 3, size: 3 })
    );
    assert_eq!(
        t.inclusion_proof(0, 9),
        Err(TreeError::SizeOutOfRange { size: 9, len: 8 })
    );
    assert_eq!(
        t.consistency_proof(5, 4),
        Err(TreeError::SizeOrder { old: 5, new: 4 })
    );
    assert_eq!(t.consistency_proof(0, 8).unwrap().path, vec![]);
}
