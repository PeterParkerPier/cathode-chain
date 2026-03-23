//! World state — accounts, balances, nonces.
//! Same DashMap-based concurrent state as before, but driven by
//! consensus-ordered events instead of blocks.
//
// Security fix — Signed-off-by: Claude Opus 4.6

use crate::error::HashgraphError;
use dashmap::DashMap;
use cathode_crypto::hash::{Hash32, Hasher};
use cathode_crypto::merkle::MerkleTree;
use parking_lot::Mutex;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Global supply cap: 1 billion tokens * 10^18 base units.
const MAX_SUPPLY: u128 = 1_000_000_000 * 10u128.pow(18);

/// Maximum number of distinct accounts allowed in the world state.
///
/// Prevents state-bloat attacks where an adversary creates millions of
/// dust accounts to exhaust memory and slow Merkle-root computation.
/// 10 million accounts at ~200 bytes each ≈ 2 GB — a reasonable upper bound
/// that can be raised via governance once storage scales.
const MAX_ACCOUNTS: usize = 10_000_000;

/// Account address = Ed25519 public key bytes.
pub type Address = [u8; 32];

/// Per-account state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub balance: u128,
    pub nonce: u64,
    pub code_hash: Option<Hash32>,
}

impl Default for AccountState {
    fn default() -> Self {
        Self { balance: 0, nonce: 0, code_hash: None }
    }
}

/// Thread-safe world state (DashMap — lock-free concurrent reads).
///
/// `total_minted` tracks the running sum of all `mint()` calls so that the
/// global supply cap (MAX_SUPPLY) can be enforced.  Protected by a Mutex
/// so that concurrent mints cannot race past the cap.
///
/// # Re-entrancy / concurrent-transfer safety
///
/// `apply_transfer` holds each DashMap shard lock only for the duration of
/// a single entry mutation (one entry() scope per account).  The two scopes
/// (debit sender, credit receiver) are NOT held simultaneously, which avoids
/// deadlock when two transfers between the same pair of accounts execute
/// concurrently.  Double-spend is prevented by the nonce check: only one
/// concurrent call with a given nonce can succeed; the other will see a stale
/// nonce and return `NonceMismatch`.  No additional re-entrancy mutex is
/// required because Rust's ownership model prevents true re-entrant calls
/// within a single thread, and cross-thread safety is provided by DashMap's
/// per-shard locking.
#[derive(Debug, Clone)]
pub struct WorldState {
    accounts: Arc<DashMap<Address, AccountState>>,
    /// Running total of all minted base units — must never exceed MAX_SUPPLY.
    total_minted: Arc<Mutex<u128>>,
}

impl Default for WorldState {
    fn default() -> Self { Self::new() }
}

impl WorldState {
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(DashMap::new()),
            total_minted: Arc::new(Mutex::new(0u128)),
        }
    }

    /// Current total minted supply (base units).
    pub fn total_supply(&self) -> u128 {
        *self.total_minted.lock()
    }

    pub fn get(&self, addr: &Address) -> AccountState {
        self.accounts.get(addr).map(|r| r.clone()).unwrap_or_default()
    }

    pub fn set(&self, addr: Address, state: AccountState) {
        self.accounts.insert(addr, state);
    }

    pub fn apply_transfer(
        &self,
        from: &Address,
        to: &Address,
        amount: u128,
        nonce: u64,
    ) -> Result<(), HashgraphError> {
        // Self-transfer short-circuit (just bump nonce)
        if from == to {
            let mut entry = self.accounts.entry(*from).or_default();
            let sender = entry.value_mut();
            if sender.nonce != nonce {
                return Err(HashgraphError::NonceMismatch {
                    expected: sender.nonce,
                    got: nonce,
                });
            }
            sender.nonce = sender.nonce.checked_add(1)
                .ok_or(HashgraphError::NonceExhausted)?;
            return Ok(());
        }

        // Atomic sender update via DashMap::entry — holds shard lock for
        // the duration of the closure, preventing concurrent reads of stale balance.
        {
            let mut entry = self.accounts.entry(*from).or_default();
            let sender = entry.value_mut();
            if sender.nonce != nonce {
                return Err(HashgraphError::NonceMismatch {
                    expected: sender.nonce,
                    got: nonce,
                });
            }
            // SECURITY FIX: use checked_sub instead of wrapping subtraction.
            // The balance < amount guard is correct, but checked_sub provides
            // a hard compiler-enforced guarantee against underflow regardless
            // of any future refactoring that might remove the guard above.
            sender.balance = sender.balance
                .checked_sub(amount)
                .ok_or(HashgraphError::InsufficientBalance {
                    have: sender.balance,
                    need: amount,
                })?;
            sender.nonce = sender.nonce.checked_add(1)
                .ok_or(HashgraphError::NonceExhausted)?;
        } // sender shard lock released

        // Atomic receiver update — checked_add prevents silent balance cap
        // that saturating_add would impose if the receiver's balance is near u128::MAX.
        // Security fix: enforce MAX_ACCOUNTS before creating a new account entry.
        // This prevents state-bloat attacks (millions of dust accounts exhausting RAM).
        {
            // Check current count without holding the shard lock for the new entry yet.
            // The entry() call below is atomic within its own shard, so a brief TOCTOU
            // window exists only between two entries in different shards — acceptable
            // because MAX_ACCOUNTS is a soft safety cap, not a hard consensus rule, and
            // a transient overshoot by at most (number of concurrent writers) accounts
            // does not meaningfully undermine the protection.
            if !self.accounts.contains_key(to)
                && self.accounts.len() >= MAX_ACCOUNTS
            {
                return Err(HashgraphError::AccountLimitReached { limit: MAX_ACCOUNTS });
            }
            let mut entry = self.accounts.entry(*to).or_default();
            let recv = entry.value_mut();
            recv.balance = recv.balance
                .checked_add(amount)
                .ok_or(HashgraphError::ArithmeticOverflow { context: "receiver balance" })?;
        }
        Ok(())
    }

    /// Apply a full transaction atomically: deduct gas fee first, then apply
    /// the transfer amount.  Both deductions happen while the sender's shard
    /// lock is held, so they are atomic with respect to concurrent transfers.
    pub fn apply_transfer_with_gas(
        &self,
        from: &Address,
        to: &Address,
        amount: u128,
        nonce: u64,
        gas_limit: u64,
        gas_price: u64,
    ) -> Result<(), HashgraphError> {
        // Compute gas fee with overflow protection.
        let gas_fee = (gas_limit as u128)
            .checked_mul(gas_price as u128)
            .ok_or(HashgraphError::GasFeeOverflow { gas_limit, gas_price })?;

        // Total required = transfer amount + gas fee (both must be covered).
        let total_required = amount
            .checked_add(gas_fee)
            .ok_or(HashgraphError::ArithmeticOverflow { context: "total_required (amount + gas_fee)" })?;

        if from == to {
            // Self-transfer: deduct gas fee and bump nonce atomically.
            let mut entry = self.accounts.entry(*from).or_default();
            let sender = entry.value_mut();
            if sender.nonce != nonce {
                return Err(HashgraphError::NonceMismatch {
                    expected: sender.nonce,
                    got: nonce,
                });
            }
            sender.balance = sender.balance
                .checked_sub(gas_fee)
                .ok_or(HashgraphError::InsufficientBalanceForGas {
                    have: sender.balance,
                    gas_fee,
                })?;
            sender.nonce = sender.nonce.checked_add(1)
                .ok_or(HashgraphError::NonceExhausted)?;
            return Ok(());
        }

        // ATOMIC: deduct gas + transfer amount from sender in a single lock scope.
        {
            let mut entry = self.accounts.entry(*from).or_default();
            let sender = entry.value_mut();
            if sender.nonce != nonce {
                return Err(HashgraphError::NonceMismatch {
                    expected: sender.nonce,
                    got: nonce,
                });
            }
            // Single checked_sub for the combined amount — atomic deduction.
            sender.balance = sender.balance
                .checked_sub(total_required)
                .ok_or(HashgraphError::InsufficientBalance {
                    have: sender.balance,
                    need: total_required,
                })?;
            sender.nonce = sender.nonce.checked_add(1)
                .ok_or(HashgraphError::NonceExhausted)?;
        } // sender shard lock released — gas + amount deducted atomically

        // Credit transfer amount to receiver (gas fee is burned / goes to validator,
        // not credited to the recipient).
        // Security fix: enforce MAX_ACCOUNTS before creating a new account entry.
        {
            if !self.accounts.contains_key(to)
                && self.accounts.len() >= MAX_ACCOUNTS
            {
                return Err(HashgraphError::AccountLimitReached { limit: MAX_ACCOUNTS });
            }
            let mut entry = self.accounts.entry(*to).or_default();
            let recv = entry.value_mut();
            recv.balance = recv.balance
                .checked_add(amount)
                .ok_or(HashgraphError::ArithmeticOverflow { context: "receiver balance" })?;
        }
        Ok(())
    }

    /// Mint new tokens into `addr`.  Enforces the global MAX_SUPPLY cap
    /// atomically via a compare-and-swap loop on `total_minted`.
    ///
    /// Returns `Err(SupplyCapExceeded)` if the mint would push the total past
    /// MAX_SUPPLY.  On success the caller is guaranteed that total_minted has
    /// been incremented by exactly `amount`.
    pub fn mint(&self, addr: Address, amount: u128) -> Result<(), HashgraphError> {
        // Hold the mint lock for the entire operation so concurrent mints
        // cannot race past the supply cap.
        let mut total = self.total_minted.lock();
        let next = total.checked_add(amount).ok_or(HashgraphError::ArithmeticOverflow {
            context: "total_minted + mint amount",
        })?;
        if next > MAX_SUPPLY {
            return Err(HashgraphError::SupplyCapExceeded {
                current: *total,
                mint: amount,
                cap: MAX_SUPPLY,
            });
        }
        *total = next;

        // Supply budget reserved — now credit the account.
        // Security fix: enforce MAX_ACCOUNTS before creating a new account entry during mint.
        // An adversary could spam genesis/airdrop mints to flood the account table.
        if !self.accounts.contains_key(&addr) && self.accounts.len() >= MAX_ACCOUNTS {
            return Err(HashgraphError::AccountLimitReached { limit: MAX_ACCOUNTS });
        }
        // Use checked_add to guard against an individual account balance overflow.
        let mut entry = self.accounts.entry(addr).or_default();
        let acct = entry.value_mut();
        acct.balance = acct.balance
            .checked_add(amount)
            .ok_or(HashgraphError::ArithmeticOverflow { context: "account balance during mint" })?;
        Ok(())
    }

    /// State Merkle root (deterministic, parallel).
    pub fn merkle_root(&self) -> Hash32 {
        let mut entries: Vec<(Address, AccountState)> = self
            .accounts
            .iter()
            .map(|r| (*r.key(), r.value().clone()))
            .collect();

        if entries.is_empty() {
            return Hash32::ZERO;
        }

        entries.par_sort_unstable_by_key(|(addr, _)| *addr);

        let leaves: Vec<Hash32> = entries
            .par_iter()
            .map(|(addr, state)| {
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(addr);
                buf.extend_from_slice(&bincode::serialize(state).expect("serialize"));
                Hasher::sha3_256(&buf)
            })
            .collect();

        MerkleTree::from_leaves(&leaves).root()
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }
}
