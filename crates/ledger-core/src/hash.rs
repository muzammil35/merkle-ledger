//! SHA-256 hashing with RFC 9162 domain separation.
//!
//! Leaves and interior nodes are hashed with different one-byte prefixes
//! (`0x00` and `0x01`). Without this, an attacker could present the 64-byte
//! concatenation of two child hashes as if it were a leaf, and its "leaf hash"
//! would equal the parent node hash — a second-preimage attack on the tree.

use std::fmt;

use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// A 32-byte SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// Length of a digest in bytes.
    pub const LEN: usize = 32;

    /// Parses a 64-character lowercase or uppercase hex string.
    ///
    /// # Errors
    /// Returns [`HexError`] if the input is not exactly 64 hex digits.
    pub fn from_hex(s: &str) -> Result<Self, HexError> {
        let bytes = s.as_bytes();
        if bytes.len() != Self::LEN * 2 {
            return Err(HexError);
        }
        let mut out = [0u8; Self::LEN];
        for (dst, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
            *dst = (hex_val(pair[0])? << 4) | hex_val(pair[1])?;
        }
        Ok(Self(out))
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn hex_val(c: u8) -> Result<u8, HexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(HexError),
    }
}

/// Error returned by [`Hash::from_hex`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid hex digest: expected 64 hex characters")]
pub struct HexError;

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({self})")
    }
}

/// Hash of a leaf: `SHA-256(0x00 || data)`.
#[must_use]
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(data);
    Hash(h.finalize().into())
}

/// Hash of an interior node: `SHA-256(0x01 || left || right)`.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left.0);
    h.update(right.0);
    Hash(h.finalize().into())
}

/// Root of the empty tree: `SHA-256("")`.
#[must_use]
pub fn empty_root() -> Hash {
    Hash(Sha256::digest([]).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let h = leaf_hash(b"hello");
        assert_eq!(Hash::from_hex(&h.to_string()), Ok(h));
        assert_eq!(Hash::from_hex("abc"), Err(HexError));
        assert_eq!(Hash::from_hex(&"zz".repeat(32)), Err(HexError));
    }

    #[test]
    fn domain_separation_prevents_second_preimage() {
        // Present two child hashes concatenated as if they were leaf data.
        let (l, r) = (leaf_hash(b"a"), leaf_hash(b"b"));
        let mut forged = Vec::with_capacity(64);
        forged.extend_from_slice(&l.0);
        forged.extend_from_slice(&r.0);
        assert_ne!(leaf_hash(&forged), node_hash(&l, &r));
    }
}
