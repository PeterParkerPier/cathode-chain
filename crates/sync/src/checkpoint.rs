//! State checkpoints — periodic snapshots of world state.

use cathode_crypto::hash::{Hash32, Hasher};
use cathode_executor::state::{AccountState, StateDB};
use cathode_types::address::Address;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

/// A state checkpoint — snapshot of all account states at a given consensus height.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateCheckpoint {
    /// The consensus order at which this checkpoint was taken.
    pub height: u64,
    /// Merkle root of all account states at this height.
    pub state_root: Hash32,
    /// Number of accounts.
    pub account_count: usize,
    /// All account states (sorted by address for determinism).
    pub accounts: Vec<(Address, AccountState)>,
    /// BLAKE3 hash of the serialized checkpoint (for integrity verification).
    pub checkpoint_hash: Hash32,
}

impl StateCheckpoint {
    /// Create a new checkpoint from the current state.
    ///
    /// Security fix (CHECKPOINT-NONATOMIC): capture accounts FIRST, then
    /// compute merkle root FROM the captured snapshot.  Previously,
    /// `merkle_root()` and `all_accounts_sorted()` were separate DashMap
    /// iterations — a concurrent transaction between them could make the
    /// root inconsistent with the account data.
    /// Signed-off-by: Claude Opus 4.6
    pub fn from_state(state: &StateDB, height: u64) -> Self {
        // Security fix (H-02): always populate accounts so verify() can
        // validate the full checkpoint, preventing state-poisoning attacks.
        // Signed-off-by: Claude Opus 4.6
        let accounts = state.all_accounts_sorted();
        let account_count = accounts.len();

        // Compute merkle root from the captured snapshot, not from live state.
        // Security fix (C-02): leaf hash must match StateDB::merkle_root() exactly —
        // same serialisation format (addr.0 bytes ++ bincode(state)) and same hash
        // function (sha3_256).  Previously used bincode(&(addr, acc)) + blake3,
        // which meant checkpoint roots NEVER matched live state roots.
        // Security fix (C-02) — Signed-off-by: Claude Opus 4.6
        let leaves: Vec<Hash32> = accounts.iter().map(|(addr, acc)| {
            let mut buf = Vec::with_capacity(128);
            buf.extend_from_slice(&addr.0);
            buf.extend_from_slice(&bincode::serialize(acc).expect("serialize account"));
            Hasher::sha3_256(&buf)
        }).collect();
        let state_root = if leaves.is_empty() {
            Hash32::ZERO
        } else {
            cathode_crypto::merkle::MerkleTree::from_leaves(&leaves).root()
        };

        let mut cp = Self {
            height,
            state_root,
            account_count,
            accounts,
            checkpoint_hash: Hash32::ZERO,
        };

        // Compute checkpoint hash — includes accounts in pre-image
        let data = bincode::serialize(&(height, &state_root, account_count, &cp.accounts))
            .expect("serialize checkpoint data");
        cp.checkpoint_hash = Hasher::sha3_256(&data);
        cp
    }

    /// Verify the checkpoint hash and account data integrity.
    ///
    /// Security fix (H-02): include accounts in hash pre-image so a malicious
    /// peer cannot serve arbitrary account balances with a valid checkpoint_hash.
    /// Signed-off-by: Claude Opus 4.6
    pub fn verify(&self) -> bool {
        let data = bincode::serialize(&(
            self.height,
            &self.state_root,
            self.account_count,
            &self.accounts,
        )).expect("serialize checkpoint data");
        let expected = Hasher::sha3_256(&data);
        expected == self.checkpoint_hash
    }

    /// Encode to bytes.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("StateCheckpoint::encode")
    }

    /// Decode from bytes.
    ///
    /// Security fix (CF-006/HB-007): bincode size limit prevents OOM from
    /// malicious checkpoint payloads during sync.
    /// Signed-off-by: Claude Opus 4.6
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        use bincode::Options;
        const MAX_CHECKPOINT_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB
        anyhow::ensure!(
            (bytes.len() as u64) <= MAX_CHECKPOINT_SIZE,
            "checkpoint too large: {} bytes (max {})",
            bytes.len(),
            MAX_CHECKPOINT_SIZE
        );
        // Security fix (CF-002/HB-003): Removed allow_trailing_bytes() to prevent
        // data smuggling via trailing bytes in checkpoint payloads.
        // Signed-off-by: Claude Opus 4.6
        let opts = bincode::options()
            .with_limit(MAX_CHECKPOINT_SIZE)
            .with_fixint_encoding();
        Ok(opts.deserialize(bytes)?)
    }
}

/// Maximum number of checkpoints retained in memory.
/// Older checkpoints are evicted to prevent unbounded memory growth.
/// Production deployments should persist checkpoints to disk before eviction.
///
/// Security fix (CP-01) — Signed-off-by: Claude Opus 4.6
const MAX_CHECKPOINT_HISTORY: usize = 100;

/// Manages periodic checkpoint creation.
pub struct CheckpointManager {
    state: Arc<StateDB>,
    /// How often to create checkpoints (every N consensus orders).
    interval: u64,
    /// Latest checkpoint.
    latest: Mutex<Option<StateCheckpoint>>,
    /// Bounded checkpoint history (capped at MAX_CHECKPOINT_HISTORY).
    /// Security fix (CP-01) — Signed-off-by: Claude Opus 4.6
    history: Mutex<Vec<StateCheckpoint>>,
}

impl CheckpointManager {
    /// Create a new checkpoint manager.
    /// `interval` = how many consensus-ordered events between checkpoints.
    pub fn new(state: Arc<StateDB>, interval: u64) -> Self {
        Self {
            state,
            interval,
            latest: Mutex::new(None),
            history: Mutex::new(Vec::new()),
        }
    }

    /// Maybe create a checkpoint if we've reached the interval.
    /// Call this after processing consensus-ordered events.
    pub fn maybe_checkpoint(&self, current_height: u64) -> Option<StateCheckpoint> {
        if current_height == 0 || current_height % self.interval != 0 {
            return None;
        }

        let cp = StateCheckpoint::from_state(&self.state, current_height);
        info!(
            height = cp.height,
            root = %cp.state_root.short(),
            accounts = cp.account_count,
            "checkpoint created"
        );

        let mut latest = self.latest.lock();
        let mut history = self.history.lock();
        *latest = Some(cp.clone());
        // Security fix (CP-01): cap history to prevent unbounded memory growth.
        // Signed-off-by: Claude Opus 4.6
        if history.len() >= MAX_CHECKPOINT_HISTORY {
            history.remove(0);
        }
        history.push(cp.clone());

        Some(cp)
    }

    /// Get the latest checkpoint.
    pub fn latest(&self) -> Option<StateCheckpoint> {
        self.latest.lock().clone()
    }

    /// Get checkpoint at specific height.
    pub fn at_height(&self, height: u64) -> Option<StateCheckpoint> {
        self.history.lock().iter().find(|cp| cp.height == height).cloned()
    }

    /// Number of checkpoints stored.
    pub fn checkpoint_count(&self) -> usize {
        self.history.lock().len()
    }

    /// Get the checkpoint interval.
    pub fn interval(&self) -> u64 {
        self.interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_types::token::TokenAmount;

    #[test]
    fn checkpoint_from_empty_state() {
        let state = Arc::new(StateDB::new());
        let cp = StateCheckpoint::from_state(&state, 0);
        assert_eq!(cp.height, 0);
        assert_eq!(cp.account_count, 0);
        assert!(cp.verify());
    }

    #[test]
    fn checkpoint_from_populated_state() {
        let state = Arc::new(StateDB::new());
        state.mint(Address::from_bytes([1; 32]), TokenAmount::from_tokens(1000)).unwrap();
        state.mint(Address::from_bytes([2; 32]), TokenAmount::from_tokens(500)).unwrap();

        let cp = StateCheckpoint::from_state(&state, 100);
        assert_eq!(cp.height, 100);
        assert_eq!(cp.account_count, 2);
        assert_ne!(cp.state_root, Hash32::ZERO);
        assert!(cp.verify());
    }

    #[test]
    fn checkpoint_encode_decode() {
        let state = Arc::new(StateDB::new());
        state.mint(Address::from_bytes([1; 32]), TokenAmount::from_tokens(42)).unwrap();

        let cp = StateCheckpoint::from_state(&state, 50);
        let bytes = cp.encode();
        let decoded = StateCheckpoint::decode(&bytes).unwrap();
        assert_eq!(decoded.height, 50);
        assert_eq!(decoded.state_root, cp.state_root);
        assert!(decoded.verify());
    }

    #[test]
    fn checkpoint_manager_interval() {
        let state = Arc::new(StateDB::new());
        state.mint(Address::from_bytes([1; 32]), TokenAmount::from_tokens(100)).unwrap();

        let mgr = CheckpointManager::new(state, 10);

        // Heights 1-9 should not trigger
        for h in 1..10 {
            assert!(mgr.maybe_checkpoint(h).is_none());
        }

        // Height 10 should trigger
        let cp = mgr.maybe_checkpoint(10);
        assert!(cp.is_some());
        assert_eq!(cp.unwrap().height, 10);

        // Height 20 should trigger again
        assert!(mgr.maybe_checkpoint(20).is_some());
        assert_eq!(mgr.checkpoint_count(), 2);
    }

    #[test]
    fn checkpoint_manager_latest() {
        let state = Arc::new(StateDB::new());
        let mgr = CheckpointManager::new(state, 5);

        assert!(mgr.latest().is_none());
        mgr.maybe_checkpoint(5);
        assert_eq!(mgr.latest().unwrap().height, 5);
        mgr.maybe_checkpoint(10);
        assert_eq!(mgr.latest().unwrap().height, 10);
    }

    #[test]
    fn checkpoint_deterministic() {
        let state = Arc::new(StateDB::new());
        state.mint(Address::from_bytes([1; 32]), TokenAmount::from_tokens(100)).unwrap();
        state.mint(Address::from_bytes([2; 32]), TokenAmount::from_tokens(200)).unwrap();

        let cp1 = StateCheckpoint::from_state(&state, 42);
        let cp2 = StateCheckpoint::from_state(&state, 42);
        assert_eq!(cp1.state_root, cp2.state_root);
        assert_eq!(cp1.checkpoint_hash, cp2.checkpoint_hash);
    }
}
