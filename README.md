# merkle-ledger

A tamper-evident, append-only storage engine in Rust.

Records are written to an append-only log, chained by hash, and committed to by
a Merkle tree following [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162)
(Certificate Transparency v2). Anyone holding a small **snapshot**
(`tree size + root hash`) can later verify, with a logarithmic-size proof, that:

- a specific record is part of that snapshot (**inclusion proof**), and
- the log has only grown since that snapshot, with no records changed,
  removed, or reordered (**consistency proof**).

> **Status:** early development. Milestone 1 (the Merkle tree and proofs) is
> in progress. See the [roadmap](#roadmap).

## Why "tamper-evident" and not "tamper-proof"

An attacker with write access to the data files can change a record and
recompute every hash after it. Hashing alone does not prevent this. What
it does is make tampering **detectable** by anyone who saved an earlier
snapshot, or who trusts a signed one: the attacker cannot produce a valid
consistency proof from the old root to the rewritten history without breaking
SHA-256.

The full threat model and design decisions are in
[`docs/DESIGN.md`](docs/DESIGN.md).

## Design highlights

- **RFC 9162 tree shape.** Supports any number of leaves, not just powers of
  two, and is checked against the published Certificate Transparency test vectors.
- **Domain-separated hashing.** Leaves are hashed as `SHA-256(0x00 || data)` and
  interior nodes as `SHA-256(0x01 || left || right)`, which blocks
  second-preimage attacks on the tree.
- **Proofs for any historical size.** Inclusion and consistency proofs can be
  produced against any past snapshot, not only the latest one.
- **Hardened verification.** Proof verification treats all input as hostile:
  it checks the exact proof length before hashing anything and never panics,
  for any input. Property tests enforce this.
- **Pure core.** `ledger-core` does no I/O, so it is deterministic and can be
  tested exhaustively and fuzzed.

## Layout

```
crates/
  ledger-core/        hashing, Merkle tree, proofs (no I/O)
    src/hash.rs       SHA-256 with leaf/node domain separation
    src/reference.rs  RFC 9162 definitions, transcribed directly (test oracle)
    src/tree.rs       efficient append-only Merkle tree
    src/proof.rs      inclusion/consistency proofs and verification
    tests/            known-answer vectors and property tests
docs/
  DESIGN.md           threat model, decisions, roadmap
```

## Building and testing

Requires a recent Rust toolchain (edition 2024).

```sh
cargo test --workspace                     # all tests
cargo clippy --workspace --all-targets     # lints (pedantic)
cargo fmt --all --check                    # formatting
```

The test suite combines:

- **Known-answer tests** against the RFC 9162 / Certificate Transparency vectors.
- **Exhaustive tests**: every leaf index and every pair of tree sizes for trees up to 40 leaves.
- **Property tests** ([proptest](https://github.com/proptest-rs/proptest)):
  honest proofs always verify, and any proof with a flipped bit, a truncated
  path, a moved index, or a forged root is always rejected.

## Roadmap

- [ ] **M1:** In-memory Merkle tree, inclusion and consistency proofs
- [ ] **M2:** On-disk append-only log: record framing, checksums, segment files, fsync policy
- [ ] **M3:** Crash recovery: torn-write detection, log truncation, fault-injection tests
- [ ] **M4:** Persistent Merkle tree: O(log n) memory for appends, proofs served from disk
- [ ] **M5:** Signed snapshots (Ed25519) and a standalone verifier CLI
- [ ] **M6:** Fuzzing, benchmarks, single-writer / multi-reader concurrency

## References

- [RFC 9162: Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162), §2.1
- Laurie, [*Certificate Transparency*](https://queue.acm.org/detail.cfm?id=2668154), ACM Queue (2014)
- Crosby & Wallach, [*Efficient Data Structures for Tamper-Evident Logging*](https://www.usenix.org/legacy/event/sec09/tech/full_papers/crosby.pdf), USENIX Security (2009)

## License

Licensed under either of MIT or Apache-2.0, at your option.
