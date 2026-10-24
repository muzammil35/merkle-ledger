# Ledger: a tamper-evident storage engine

## 1. Threat model

**Asset:** the ordered sequence of records appended to the log.

**Adversary:** has full read/write access to the data directory *after* records
are written (a compromised host, a malicious operator, a bad backup restore).
They can edit, delete, reorder, truncate, or append bytes, and recompute any
hash they like.

**Goal:** any such change is *detected* by a verifier holding a snapshot
`(size, root)` it obtained earlier through a trusted channel. We do **not**
prevent tampering, and we do not provide confidentiality.

**Consequence:** hashes alone prove nothing, because the attacker can recompute
them. All security reduces to (a) collision resistance of SHA-256 and (b) the
verifier having a snapshot the attacker could not forge: one they saw earlier,
or one signed by a key the attacker does not hold (milestone 5).

**Out of scope (for now):** a malicious writer *at write time* (it can log
whatever it wants, but it cannot later change what it committed to), and
split-view attacks, where different verifiers are shown different histories.
CT solves split views with gossip/witnesses; we will discuss this, not build it.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Tree shape | RFC 9162 §2.1 (CT v2) | Well-specified, interoperable test vectors, supports any size (not just powers of 2) |
| Hash | SHA-256 | Matches RFC vectors. BLAKE3 is faster; revisit if benchmarks say hashing dominates |
| Domain separation | `0x00` leaf / `0x01` node prefix | Blocks the second-preimage attack (see `hash.rs` test) |
| Proof API | Proofs don't carry tree size; it comes from the `Snapshot` | One source of truth; a proof can't claim a different size than the snapshot it's checked against |
| Error split | `VerifyError` (untrusted input failed) vs `TreeError` (caller asked for something impossible) | Different callers handle them differently: one is an alarm, the other a bug |
| Core purity | `ledger-core` has no I/O | Deterministic, exhaustively testable, fuzzable |
| Hash comparison | Plain `==`, not constant-time | Roots and proofs are public, so there is no secret to leak through timing |

## 3. Questions for you (answer here before milestone 2)

1. The project brief asks for both a hash chain (`record.prev_hash`) and a
   Merkle tree. Given the tree, what does the chain add? What would you lose by
   dropping it? (Hint: think about what a reader scanning the log sequentially
   can check *without* the tree, and about crash recovery.)
2. An inclusion proof for leaf 5 verifies against snapshot `(8, R)`. What
   exactly has been proven, and what has *not*? Could the record still have been
   modified on disk?
3. Why is a consistency proof necessary? Describe an attack that inclusion
   proofs alone cannot detect.
4. A verifier has snapshot `(1000, R1)` from yesterday. Today the server shows
   `(900, R2)`. What happened, and what should the verifier do?

## 4. Roadmap

- [ ] **M1** In-memory Merkle tree and proofs (`ledger-core`): Tasks 1-3
- [ ] **M2** On-disk append-only log: record framing, checksums, segments, fsync policy
- [ ] **M3** Crash recovery: torn writes, fault-injecting filesystem, recovery tests
- [ ] **M4** Persistent Merkle tree: O(log n) memory for appends, proofs served from disk
- [ ] **M5** Signed snapshots (ed25519), standalone verifier command-line tool, tamper demo
- [ ] **M6** Hardening: fuzzing, benchmarks, one writer with many readers
