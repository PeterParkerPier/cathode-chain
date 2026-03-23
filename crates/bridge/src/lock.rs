//! Lock mechanism — locks assets on Cathode for bridging out.
//!
//! Security fix — Signed-off-by: Claude Opus 4.6

use crate::chains::{ChainId, SupportedChains};
use crate::relayer::{RelayProof, RelayerSet, verify_relay_proof};
use cathode_crypto::hash::{Hash32, Hasher};
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// Default timeout: 1000 blocks (~50 minutes at 3s blocks).
pub const DEFAULT_LOCK_TIMEOUT_BLOCKS: u64 = 1000;

/// Maximum lock extension in blocks per call.
///
/// Without this cap, a relayer (or attacker who controls a lock before it is
/// relayed) could call a hypothetical `extend_lock()` in a loop, keeping a
/// lock alive indefinitely and preventing the locked funds from ever expiring
/// back to the sender.  The cap limits each extension to ≤ 2× the default
/// timeout (≈ 100 minutes), and callers must wait for the new deadline to
/// approach before extending again.
// Security fix — Signed-off-by: Claude Opus 4.6
pub const MAX_LOCK_EXTENSION_BLOCKS: u64 = DEFAULT_LOCK_TIMEOUT_BLOCKS * 2;

/// Maximum total timeout in blocks (including extensions).
///
/// Even with repeated `extend_lock()` calls, the lock cannot exceed this
/// absolute cap.  Set to 10× the default timeout (~500 minutes / ~8 hours).
/// This prevents indefinite fund locking via repeated extensions.
// Security fix (BRG-H-01) — Signed-off-by: Claude Opus 4.6
pub const MAX_TOTAL_LOCK_TIMEOUT_BLOCKS: u64 = DEFAULT_LOCK_TIMEOUT_BLOCKS * 10;

/// Liquidity pool cap: maximum total token value that may be locked at once.
///
/// This bounds the total systemic risk exposure.  If every pending lock were
/// to fail simultaneously (relay set outage, consensus halt), at most
/// MAX_LIQUIDITY_CAP base units would be at risk.  Chosen as 100 million CATH
/// (100_000_000 * 10^18); adjust via governance for mainnet.
// Security fix — Signed-off-by: Claude Opus 4.6
pub const MAX_LIQUIDITY_CAP: u128 = 100_000_000 * 1_000_000_000_000_000_000u128; // 100M CATH

/// Lock lifecycle status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockStatus {
    /// Assets locked, waiting for relay.
    Locked,
    /// Relayer confirmed the target-chain transaction.
    Relayed,
    /// Bridge fully completed.
    Completed,
    /// Lock timed out without relay.
    Expired,
    /// Assets refunded after expiry.
    Refunded,
}

/// A bridge lock: assets frozen on Cathode destined for another chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeLock {
    pub id: Hash32,
    pub sender: Address,
    pub target_chain: ChainId,
    pub target_address: String,
    pub amount: TokenAmount,
    pub fee: TokenAmount,
    pub status: LockStatus,
    pub created_block: u64,
    pub lock_timeout_blocks: u64,
}

/// Errors from the lock manager.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("chain {0} is not enabled for bridging")]
    ChainDisabled(ChainId),
    #[error("chain {0} not found in registry")]
    ChainNotFound(ChainId),
    #[error("amount {0} below minimum bridge amount {1}")]
    BelowMinimum(TokenAmount, TokenAmount),
    #[error("amount {0} above maximum bridge amount {1}")]
    AboveMaximum(TokenAmount, TokenAmount),
    #[error("invalid target address: {0}")]
    InvalidTargetAddress(String),
    #[error("lock {0} not found")]
    LockNotFound(Hash32),
    #[error("lock {0} is not in Locked status")]
    InvalidStatus(Hash32),
    #[error("arithmetic overflow")]
    Overflow,
    #[error("invalid relay proof for lock {0}")]
    InvalidRelayProof(Hash32),
    #[error("caller {0} is not authorized for this operation")]
    Unauthorized(Address),
    /// Locking this amount would push total locked value past MAX_LIQUIDITY_CAP.
    // Security fix — Signed-off-by: Claude Opus 4.6
    #[error("liquidity cap exceeded: locked={locked}, cap={cap}, requested={requested}")]
    LiquidityCapExceeded {
        locked: u128,
        cap: u128,
        requested: u128,
    },
    /// Lock extension exceeds MAX_LOCK_EXTENSION_BLOCKS.
    // Security fix — Signed-off-by: Claude Opus 4.6
    #[error("lock extension {requested} blocks exceeds maximum {max} blocks")]
    ExtensionTooLarge { requested: u64, max: u64 },
}

/// Manages active bridge locks using a concurrent DashMap.
pub struct LockManager {
    locks: DashMap<Hash32, BridgeLock>,
    chains: SupportedChains,
    next_nonce: parking_lot::Mutex<u64>,
    /// Running sum of locked base units across all active (Locked/Relayed) locks.
    ///
    /// Guarded by a Mutex so that the check-and-increment in `lock()` is atomic,
    /// preventing concurrent callers from racing past MAX_LIQUIDITY_CAP.
    // Security fix — Signed-off-by: Claude Opus 4.6
    total_locked: parking_lot::Mutex<u128>,
}

impl LockManager {
    /// Create a new lock manager with the default chain registry.
    pub fn new() -> Self {
        Self {
            locks: DashMap::new(),
            chains: SupportedChains::new(),
            next_nonce: parking_lot::Mutex::new(0),
            total_locked: parking_lot::Mutex::new(0),
        }
    }

    /// Create a new lock manager with a custom chain registry.
    pub fn with_chains(chains: SupportedChains) -> Self {
        Self {
            locks: DashMap::new(),
            chains,
            next_nonce: parking_lot::Mutex::new(0),
            total_locked: parking_lot::Mutex::new(0),
        }
    }

    /// Lock assets for bridging to a target chain.
    pub fn lock(
        &self,
        sender: Address,
        target_chain: ChainId,
        target_address: String,
        amount: TokenAmount,
        fee: TokenAmount,
        current_block: u64,
    ) -> Result<BridgeLock, LockError> {
        // Validate chain
        let config = self.chains.get_config(target_chain)
            .ok_or(LockError::ChainNotFound(target_chain))?;
        if !config.enabled {
            return Err(LockError::ChainDisabled(target_chain));
        }

        // Validate amount
        if amount < config.min_bridge_amount {
            return Err(LockError::BelowMinimum(amount, config.min_bridge_amount));
        }
        if amount > config.max_bridge_amount {
            return Err(LockError::AboveMaximum(amount, config.max_bridge_amount));
        }

        // Validate target address (basic: non-empty, reasonable length)
        if target_address.is_empty() || target_address.len() > 256 {
            return Err(LockError::InvalidTargetAddress(target_address));
        }

        // Security fix: validate amount against available liquidity budget.
        // Hold the total_locked mutex for the check-and-increment so no concurrent
        // lock() call can race past MAX_LIQUIDITY_CAP.
        // Signed-off-by: Claude Opus 4.6
        {
            let mut locked = self.total_locked.lock();
            let requested = amount.base();
            let new_total = locked.checked_add(requested).ok_or(LockError::Overflow)?;
            if new_total > MAX_LIQUIDITY_CAP {
                return Err(LockError::LiquidityCapExceeded {
                    locked: *locked,
                    cap: MAX_LIQUIDITY_CAP,
                    requested,
                });
            }
            *locked = new_total;
        }

        // Generate unique lock ID
        let nonce = {
            let mut n = self.next_nonce.lock();
            let val = *n;
            *n = val.checked_add(1).ok_or(LockError::Overflow)?;
            val
        };
        let mut id_preimage = Vec::with_capacity(32 + 8 + 8);
        id_preimage.extend_from_slice(sender.as_bytes());
        id_preimage.extend_from_slice(&current_block.to_be_bytes());
        id_preimage.extend_from_slice(&nonce.to_be_bytes());
        let id = Hasher::blake3(&id_preimage);

        let lock = BridgeLock {
            id,
            sender,
            target_chain,
            target_address,
            amount,
            fee,
            status: LockStatus::Locked,
            created_block: current_block,
            lock_timeout_blocks: DEFAULT_LOCK_TIMEOUT_BLOCKS,
        };

        self.locks.insert(id, lock.clone());
        Ok(lock)
    }

    /// Confirm that the relay has been performed on the target chain.
    /// The caller must be in the relayer set. The relay proof must be valid.
    pub fn confirm_relay(
        &self,
        lock_id: Hash32,
        relay_proof: &RelayProof,
        relayer_set: &RelayerSet,
        caller: Address,
    ) -> Result<(), LockError> {
        // Caller must be a registered relayer
        if !relayer_set.contains(&caller) {
            return Err(LockError::Unauthorized(caller));
        }
        // Verify the relay proof signatures
        if !verify_relay_proof(relay_proof, relayer_set) {
            return Err(LockError::InvalidRelayProof(lock_id));
        }
        let mut entry = self.locks.get_mut(&lock_id)
            .ok_or(LockError::LockNotFound(lock_id))?;
        if entry.status != LockStatus::Locked {
            return Err(LockError::InvalidStatus(lock_id));
        }
        entry.status = LockStatus::Relayed;
        Ok(())
    }

    /// Mark a relayed lock as fully completed.
    /// M-01: Caller must be in the relayer set.
    /// Security fix (BRG-DEADLOCK): drop DashMap ref before acquiring total_locked
    /// Mutex, preventing lock ordering inversion with lock().
    /// Signed-off-by: Claude Opus 4.6
    pub fn complete(&self, lock_id: Hash32, caller: Address, relayers: &RelayerSet) -> Result<(), LockError> {
        if !relayers.contains(&caller) {
            return Err(LockError::Unauthorized(caller));
        }
        let release_amount = {
            let mut entry = self.locks.get_mut(&lock_id)
                .ok_or(LockError::LockNotFound(lock_id))?;
            if entry.status != LockStatus::Relayed {
                return Err(LockError::InvalidStatus(lock_id));
            }
            entry.status = LockStatus::Completed;
            entry.amount.base()
        }; // DashMap ref dropped here
        // Now safe to acquire total_locked — no DashMap shard held.
        let mut locked = self.total_locked.lock();
        *locked = locked.saturating_sub(release_amount);
        Ok(())
    }

    /// Scan for expired locks and mark them. Returns IDs eligible for refund.
    ///
    /// Security fix (BRG-01): also expire Relayed locks that exceed the timeout.
    /// Previously, a Relayed lock could persist indefinitely if the relayer never
    /// called `complete()`, permanently consuming liquidity cap budget.
    /// Signed-off-by: Claude Opus 4.6
    /// Security fix (BRG-DEADLOCK): collect expired amounts during DashMap iteration,
    /// then update total_locked AFTER the iterator is dropped.  The previous code
    /// acquired total_locked Mutex inside iter_mut(), creating an ABBA deadlock
    /// with lock() which acquires total_locked first, then DashMap shard.
    /// Signed-off-by: Claude Opus 4.6
    pub fn expire_locks(&self, current_block: u64) -> Vec<Hash32> {
        let mut expired = Vec::new();
        let mut released_amount: u128 = 0;
        for mut entry in self.locks.iter_mut() {
            if entry.status == LockStatus::Locked || entry.status == LockStatus::Relayed {
                let deadline = entry.created_block.saturating_add(entry.lock_timeout_blocks);
                if current_block >= deadline {
                    entry.status = LockStatus::Expired;
                    expired.push(entry.id);
                    released_amount = released_amount.saturating_add(entry.amount.base());
                }
            }
        }
        // Update total_locked AFTER DashMap iterator is dropped — no deadlock.
        if released_amount > 0 {
            let mut locked = self.total_locked.lock();
            *locked = locked.saturating_sub(released_amount);
        }
        expired
    }

    /// Mark an expired lock as refunded.
    /// M-02: Caller must be the original lock sender.
    pub fn refund(&self, lock_id: Hash32, caller: Address) -> Result<(), LockError> {
        let mut entry = self.locks.get_mut(&lock_id)
            .ok_or(LockError::LockNotFound(lock_id))?;
        if entry.sender != caller {
            return Err(LockError::Unauthorized(caller));
        }
        if entry.status != LockStatus::Expired {
            return Err(LockError::InvalidStatus(lock_id));
        }
        entry.status = LockStatus::Refunded;
        Ok(())
    }

    /// Extend the timeout of a Locked (not yet relayed) lock.
    ///
    /// Caps the extension at MAX_LOCK_EXTENSION_BLOCKS per call to prevent
    /// indefinite extension attacks.  Only the original sender may extend.
    // Security fix — Signed-off-by: Claude Opus 4.6
    pub fn extend_lock(
        &self,
        lock_id: Hash32,
        additional_blocks: u64,
        caller: Address,
    ) -> Result<(), LockError> {
        if additional_blocks > MAX_LOCK_EXTENSION_BLOCKS {
            return Err(LockError::ExtensionTooLarge {
                requested: additional_blocks,
                max: MAX_LOCK_EXTENSION_BLOCKS,
            });
        }
        let mut entry = self.locks.get_mut(&lock_id)
            .ok_or(LockError::LockNotFound(lock_id))?;
        if entry.sender != caller {
            return Err(LockError::Unauthorized(caller));
        }
        if entry.status != LockStatus::Locked {
            return Err(LockError::InvalidStatus(lock_id));
        }
        let new_timeout = entry.lock_timeout_blocks
            .checked_add(additional_blocks)
            .ok_or(LockError::Overflow)?;
        if new_timeout > MAX_TOTAL_LOCK_TIMEOUT_BLOCKS {
            return Err(LockError::ExtensionTooLarge {
                requested: additional_blocks,
                max: MAX_TOTAL_LOCK_TIMEOUT_BLOCKS.saturating_sub(entry.lock_timeout_blocks),
            });
        }
        entry.lock_timeout_blocks = new_timeout;
        Ok(())
    }

    /// Return the total locked base units currently at risk (Locked + Relayed).
    pub fn total_locked(&self) -> u128 {
        *self.total_locked.lock()
    }

    /// Get a lock by ID.
    pub fn get_lock(&self, id: &Hash32) -> Option<BridgeLock> {
        self.locks.get(id).map(|e| e.clone())
    }

    /// Total number of locks.
    pub fn len(&self) -> usize {
        self.locks.len()
    }

    /// Is empty?
    pub fn is_empty(&self) -> bool {
        self.locks.is_empty()
    }
}

impl Default for LockManager {
    fn default() -> Self {
        Self::new()
    }
}
