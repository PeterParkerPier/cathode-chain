//! Merkle proof for cross-chain verification.
//!
//! Signed-off-by: Claude Opus 4.6

use cathode_crypto::hash::{Hash32, Hasher};
use serde::{Deserialize, Serialize};

/// Merkle inclusion proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeMerkleProof {
    /// Root of the Merkle tree.
    pub root: Hash32,
    /// The leaf being proved.
    pub leaf: Hash32,
    /// Sibling hashes along the path from leaf to root.
    pub siblings: Vec<Hash32>,
    /// Path direction bits: false = left child, true = right child.
    pub path_bits: Vec<bool>,
}

/// Compute the Merkle root from a list of leaves.
///
/// Uses SHA3-256 via `Hasher::combine` for internal nodes.
///
/// Security fix (BRG-MERKLE): pad with Hash32::ZERO instead of duplicating
/// the last leaf.  Duplicating the last leaf enables a second-preimage
/// attack: an attacker can append a copy of the last leaf and produce a
/// different leaf set that hashes to the same root.
/// Signed-off-by: Claude Opus 4.6
pub fn compute_root(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return Hash32::ZERO;
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_level: Vec<Hash32> = leaves.to_vec();

    while current_level.len() > 1 {
        // Security fix: pad with ZERO, not last-leaf duplicate.
        if current_level.len() % 2 != 0 {
            current_level.push(Hash32::ZERO);
        }

        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for pair in current_level.chunks(2) {
            next_level.push(Hasher::combine(&pair[0], &pair[1]));
        }
        current_level = next_level;
    }

    current_level[0]
}

/// Generate a Merkle inclusion proof for the leaf at `index`.
///
/// # Panics
/// Panics if `index >= leaves.len()` or if `leaves` is empty.
pub fn generate_proof(leaves: &[Hash32], index: usize) -> BridgeMerkleProof {
    assert!(!leaves.is_empty(), "cannot generate proof for empty tree");
    assert!(index < leaves.len(), "index out of bounds");

    let leaf = leaves[index];
    let root = compute_root(leaves);

    let mut siblings = Vec::new();
    let mut path_bits = Vec::new();
    let mut current_level: Vec<Hash32> = leaves.to_vec();
    let mut idx = index;

    while current_level.len() > 1 {
        // Security fix: pad with ZERO, not last-leaf duplicate.
        if current_level.len() % 2 != 0 {
            current_level.push(Hash32::ZERO);
        }

        // Determine sibling
        let is_right = idx % 2 == 1;
        let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
        siblings.push(current_level[sibling_idx]);
        path_bits.push(is_right);

        // Move to parent level
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for pair in current_level.chunks(2) {
            next_level.push(Hasher::combine(&pair[0], &pair[1]));
        }
        current_level = next_level;
        idx /= 2;
    }

    BridgeMerkleProof {
        root,
        leaf,
        siblings,
        path_bits,
    }
}

/// Verify a Merkle inclusion proof.
pub fn verify_proof(proof: &BridgeMerkleProof) -> bool {
    if proof.siblings.len() != proof.path_bits.len() {
        return false;
    }

    let mut current = proof.leaf;

    for (sibling, &is_right) in proof.siblings.iter().zip(proof.path_bits.iter()) {
        if is_right {
            // current node is the right child
            current = Hasher::combine(sibling, &current);
        } else {
            // current node is the left child
            current = Hasher::combine(&current, sibling);
        }
    }

    current == proof.root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_leaf(n: u8) -> Hash32 {
        Hasher::blake3(&[n])
    }

    #[test]
    fn single_leaf() {
        let leaves = vec![make_leaf(1)];
        assert_eq!(compute_root(&leaves), leaves[0]);
    }

    #[test]
    fn two_leaves() {
        let leaves = vec![make_leaf(1), make_leaf(2)];
        let root = compute_root(&leaves);
        let expected = Hasher::combine(&leaves[0], &leaves[1]);
        assert_eq!(root, expected);
    }

    #[test]
    fn empty_leaves() {
        assert_eq!(compute_root(&[]), Hash32::ZERO);
    }
}
