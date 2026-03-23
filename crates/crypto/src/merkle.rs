//! Merkle tree — parallel SHA3-256, used for state proofs.

use crate::hash::{Hash32, Hasher};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Immutable Merkle tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    nodes: Vec<Hash32>,
    leaf_count: usize,
}

impl MerkleTree {
    /// Build from pre-hashed leaves (parallel).
    ///
    /// Security fix (MK-01): pad with Hash32::ZERO instead of duplicating the
    /// last leaf.  Duplicating the last leaf enables a second-preimage attack:
    /// an attacker can append a copy of the last leaf and produce a different
    /// leaf set that hashes to the same root.  Using a sentinel value (zero)
    /// eliminates this ambiguity.
    ///
    /// Signed-off-by: Claude Opus 4.6
    pub fn from_leaves(leaves: &[Hash32]) -> Self {
        if leaves.is_empty() {
            return Self { nodes: vec![Hash32::ZERO], leaf_count: 0 };
        }
        let size = leaves.len().next_power_of_two();
        // Security fix (CK-001): apply leaf domain hash for domain separation
        // Signed-off-by: Claude Opus 4.6
        let mut level: Vec<Hash32> = leaves.iter().map(|l| Hasher::leaf_hash(l)).collect();
        // Security fix (MK-01): pad with ZERO, not last-leaf duplicate.
        while level.len() < size {
            level.push(Hash32::ZERO);
        }
        let mut all = level.clone();
        while level.len() > 1 {
            let next: Vec<Hash32> = level
                .par_chunks(2)
                .map(|pair| Hasher::combine(&pair[0], &pair[1]))
                .collect();
            all.extend_from_slice(&next);
            level = next;
        }
        Self { nodes: all, leaf_count: leaves.len() }
    }

    /// Root hash.
    pub fn root(&self) -> Hash32 {
        *self.nodes.last().unwrap_or(&Hash32::ZERO)
    }

    /// Number of original leaves.
    pub fn leaf_count(&self) -> usize { self.leaf_count }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash32> {
        (0..n).map(|i| Hasher::blake3(format!("leaf-{}", i).as_bytes())).collect()
    }

    #[test]
    fn empty_tree() {
        let t = MerkleTree::from_leaves(&[]);
        assert_eq!(t.root(), Hash32::ZERO);
        assert_eq!(t.leaf_count(), 0);
    }

    #[test]
    fn single_leaf() {
        let l = leaves(1);
        let t = MerkleTree::from_leaves(&l);
        assert_eq!(t.leaf_count(), 1);
        assert_ne!(t.root(), Hash32::ZERO);
    }

    #[test]
    fn root_deterministic() {
        let l = leaves(8);
        assert_eq!(
            MerkleTree::from_leaves(&l).root(),
            MerkleTree::from_leaves(&l).root()
        );
    }

    #[test]
    fn different_leaves_different_roots() {
        let a = leaves(4);
        let b: Vec<Hash32> = (10..14).map(|i| Hasher::blake3(format!("x-{}", i).as_bytes())).collect();
        assert_ne!(MerkleTree::from_leaves(&a).root(), MerkleTree::from_leaves(&b).root());
    }

    #[test]
    fn non_power_of_two_leaves() {
        // 3 leaves → padded to 4 internally
        let l = leaves(3);
        let t = MerkleTree::from_leaves(&l);
        assert_eq!(t.leaf_count(), 3);
        assert_ne!(t.root(), Hash32::ZERO);
    }
}
