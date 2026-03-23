//! Relayer/validator bridge logic — manages the trusted relay set.
//!
//! Security fix — Signed-off-by: Claude Opus 4.6

use cathode_crypto::hash::Hash32;
use cathode_crypto::signature::{Ed25519PublicKey, Ed25519Signature, verify_ed25519};
use cathode_types::address::Address;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Errors from bridge relayer operations.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("threshold must be >= 1")]
    InvalidThreshold,
    #[error("threshold ({threshold}) exceeds relayer count ({count})")]
    ThresholdExceedsRelayers { threshold: usize, count: usize },
    #[error("cannot remove relayer: remaining count ({remaining}) would be below threshold ({threshold})")]
    RemovalBelowThreshold { remaining: usize, threshold: usize },
    /// Caller is not in the authorized admin set for RelayerManager mutations.
    #[error("caller {0} is not an authorized admin for relayer management")]
    UnauthorizedAdmin(Address),
}

/// The set of trusted relayers and the signature threshold.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayerSet {
    pub relayers: Vec<Address>,
    pub threshold: usize,
}

impl RelayerSet {
    /// Create a new relayer set with the given threshold.
    /// Panics if threshold == 0 or threshold > relayers.len().
    pub fn new(relayers: Vec<Address>, threshold: usize) -> Self {
        assert!(threshold >= 1, "threshold must be >= 1");
        assert!(threshold <= relayers.len(), "threshold ({}) must be <= relayer count ({})", threshold, relayers.len());
        Self { relayers, threshold }
    }

    /// Check if an address is a registered relayer.
    pub fn contains(&self, addr: &Address) -> bool {
        self.relayers.contains(addr)
    }
}

/// Proof that a relay was performed, signed by relayers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayProof {
    pub lock_id: Hash32,
    pub target_chain_tx: String,
    pub signatures: Vec<(Address, Vec<u8>)>,
}

/// Verify that a relay proof meets the threshold requirements.
///
/// Security fix (BRG-C-03): The signed message now includes domain separation
/// with the lock_id, target_chain_tx, and a fixed domain tag. Previously only
/// lock_id was signed, allowing cross-chain replay of relay proofs between
/// bridge instances (Poly Network attack pattern).
///
/// Signed-off-by: Claude Opus 4.6
///
/// Checks:
/// - Each signature is a valid Ed25519 signature over domain-separated message
/// - All signers are in the relayer set
/// - No duplicate signers
/// - Number of valid signatures >= threshold
pub fn verify_relay_proof(proof: &RelayProof, relayer_set: &RelayerSet) -> bool {
    let mut seen = HashSet::new();
    let mut valid_count = 0usize;
    // BRG-C-03: Domain-separated message prevents cross-chain replay.
    // msg = BLAKE3("cathode-relay-v1" || lock_id || target_chain_tx)
    let domain_msg = {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"cathode-relay-v1:");
        buf.extend_from_slice(proof.lock_id.as_bytes());
        buf.extend_from_slice(b":");
        buf.extend_from_slice(proof.target_chain_tx.as_bytes());
        cathode_crypto::hash::Hasher::blake3(&buf)
    };
    let msg = domain_msg.as_bytes();

    for (addr, sig_bytes) in &proof.signatures {
        // Skip duplicates
        if !seen.insert(*addr) {
            continue;
        }
        // Must be a known relayer
        if !relayer_set.contains(addr) {
            continue;
        }
        // Verify Ed25519 signature against lock_id bytes
        if sig_bytes.len() != 64 {
            continue;
        }
        let pubkey = Ed25519PublicKey(addr.0);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(sig_bytes);
        let signature = Ed25519Signature(sig_arr);
        if verify_ed25519(&pubkey, msg, &signature).is_ok() {
            valid_count = valid_count.saturating_add(1);
        }
    }

    valid_count >= relayer_set.threshold
}

/// Manages the relayer set with concurrent read/write access.
///
/// # Access control
/// Mutating operations (`add_relayer`, `remove_relayer`, `set_threshold`) require
/// the caller address to be present in the `authorized_admins` set established at
/// construction time.  Read-only queries (`is_relayer`, `get_threshold`, `snapshot`,
/// `len`, `is_empty`) are unrestricted.
pub struct RelayerManager {
    inner: RwLock<RelayerSet>,
    /// Set of addresses permitted to mutate the relayer set and threshold.
    /// Protected by the same RwLock as `inner` to avoid separate lock ordering issues.
    authorized_admins: RwLock<HashSet<Address>>,
}

impl RelayerManager {
    /// Create a new manager with the given initial relayer set, threshold, and admin set.
    ///
    /// `admins` — addresses allowed to call `add_relayer`, `remove_relayer`,
    ///            and `set_threshold`.  Must be non-empty.
    ///
    /// Panics if threshold == 0, threshold > relayers.len(), or admins is empty.
    pub fn new(relayers: Vec<Address>, threshold: usize, admins: Vec<Address>) -> Self {
        assert!(!admins.is_empty(), "RelayerManager requires at least one authorized admin");
        Self {
            inner: RwLock::new(RelayerSet::new(relayers, threshold)),
            authorized_admins: RwLock::new(admins.into_iter().collect()),
        }
    }

    /// Check whether `caller` is an authorized admin.
    fn check_admin(&self, caller: &Address) -> Result<(), BridgeError> {
        if !self.authorized_admins.read().contains(caller) {
            return Err(BridgeError::UnauthorizedAdmin(*caller));
        }
        Ok(())
    }

    /// Add an admin address. Only existing admins may call this.
    pub fn add_admin(&self, caller: &Address, new_admin: Address) -> Result<bool, BridgeError> {
        self.check_admin(caller)?;
        Ok(self.authorized_admins.write().insert(new_admin))
    }

    /// Remove an admin address. Only existing admins may call this.
    /// Returns error if removing would leave zero admins.
    pub fn remove_admin(&self, caller: &Address, target: &Address) -> Result<bool, BridgeError> {
        self.check_admin(caller)?;
        let mut admins = self.authorized_admins.write();
        if admins.len() == 1 && admins.contains(target) {
            return Err(BridgeError::UnauthorizedAdmin(*caller)); // would remove last admin
        }
        Ok(admins.remove(target))
    }

    /// Add a relayer. `caller` must be an authorized admin.
    /// Returns false if the address is already present.
    pub fn add_relayer(&self, caller: &Address, addr: Address) -> Result<bool, BridgeError> {
        self.check_admin(caller)?;
        let mut set = self.inner.write();
        if set.relayers.contains(&addr) {
            return Ok(false);
        }
        set.relayers.push(addr);
        Ok(true)
    }

    /// Remove a relayer. `caller` must be an authorized admin.
    /// Returns error if removal would drop count below threshold.
    /// Returns false if not found.
    pub fn remove_relayer(&self, caller: &Address, addr: &Address) -> Result<bool, BridgeError> {
        self.check_admin(caller)?;
        let mut set = self.inner.write();
        if !set.relayers.contains(addr) {
            return Ok(false);
        }
        let remaining = set.relayers.len() - 1;
        if remaining < set.threshold {
            return Err(BridgeError::RemovalBelowThreshold {
                remaining,
                threshold: set.threshold,
            });
        }
        set.relayers.retain(|a| a != addr);
        Ok(true)
    }

    /// Check if an address is a relayer.
    pub fn is_relayer(&self, addr: &Address) -> bool {
        self.inner.read().contains(addr)
    }

    /// Get the current threshold.
    pub fn get_threshold(&self) -> usize {
        self.inner.read().threshold
    }

    /// Set a new threshold. `caller` must be an authorized admin.
    /// Returns error if threshold == 0 or threshold > relayer count.
    pub fn set_threshold(&self, caller: &Address, threshold: usize) -> Result<(), BridgeError> {
        self.check_admin(caller)?;
        if threshold == 0 {
            return Err(BridgeError::InvalidThreshold);
        }
        let mut set = self.inner.write();
        if threshold > set.relayers.len() {
            return Err(BridgeError::ThresholdExceedsRelayers {
                threshold,
                count: set.relayers.len(),
            });
        }
        set.threshold = threshold;
        Ok(())
    }

    /// Get a snapshot of the current relayer set.
    pub fn snapshot(&self) -> RelayerSet {
        self.inner.read().clone()
    }

    /// Number of relayers.
    pub fn len(&self) -> usize {
        self.inner.read().relayers.len()
    }

    /// Is empty?
    pub fn is_empty(&self) -> bool {
        self.inner.read().relayers.is_empty()
    }
}
