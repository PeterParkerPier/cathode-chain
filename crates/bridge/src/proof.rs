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
        // Security fix (CK-001): Apply leaf domain separation (RFC 6962).
        // Signed-off-by: Claude Opus 4.6
        return Hasher::leaf_hash(&leaves[0]);
    }

    // Security fix (CK-001): Apply leaf domain separation (RFC 6962).
    // Signed-off-by: Claude Opus 4.6
    let mut current_level: Vec<Hash32> = leaves.iter()
        .map(|l| Hasher::leaf_hash(l))
        .collect();

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
    // Security fix (CK-001): Apply leaf domain separation (RFC 6962).
    // Signed-off-by: Claude Opus 4.6
    let mut current_level: Vec<Hash32> = leaves.iter()
        .map(|l| Hasher::leaf_hash(l))
        .collect();
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

    // Security fix (CK-001): Start verification with leaf domain separation (RFC 6962).
    // Signed-off-by: Claude Opus 4.6
    let mut current = Hasher::leaf_hash(&proof.leaf);

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
        // After CK-001 fix: single leaf returns leaf_hash, not raw leaf.
        assert_eq!(compute_root(&leaves), Hasher::leaf_hash(&leaves[0]));
    }

    #[test]
    fn two_leaves() {
        let leaves = vec![make_leaf(1), make_leaf(2)];
        let root = compute_root(&leaves);
        // After CK-001 fix: leaves are domain-separated before combine.
        let lh0 = Hasher::leaf_hash(&leaves[0]);
        let lh1 = Hasher::leaf_hash(&leaves[1]);
        let expected = Hasher::combine(&lh0, &lh1);
        assert_eq!(root, expected);
    }

    #[test]
    fn proof_round_trip() {
        let leaves = vec![make_leaf(1), make_leaf(2), make_leaf(3)];
        for i in 0..leaves.len() {
            let proof = generate_proof(&leaves, i);
            assert!(verify_proof(&proof), "proof failed for index {}", i);
        }
    }

    #[test]
    fn empty_leaves() {
        assert_eq!(compute_root(&[]), Hash32::ZERO);
    }
}
