//! Account state — the upgraded WorldState that uses typed Address and TokenAmount.

use cathode_crypto::hash::{Hash32, Hasher};
use cathode_crypto::merkle::MerkleTree;
use cathode_types::address::Address;
use cathode_types::token::{TokenAmount, MAX_SUPPLY};
use dashmap::DashMap;
use parking_lot::Mutex;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Per-account state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub balance: TokenAmount,
    pub nonce: u64,
    pub code_hash: Option<Hash32>,
    pub staked: TokenAmount,
}

impl Default for AccountState {
    fn default() -> Self {
        Self {
            balance: TokenAmount::ZERO,
            nonce: 0,
            code_hash: None,
            staked: TokenAmount::ZERO,
        }
    }
}

/// Maximum number of per-address transfer locks retained in memory.
/// When exceeded, stale entries (addresses no longer in accounts) are pruned.
/// Security fix (C-05) — Signed-off-by: Claude Opus 4.6
const MAX_TRANSFER_LOCKS: usize = 100_000;

/// Thread-safe world state using DashMap.
#[derive(Clone)]
pub struct StateDB {
    accounts: Arc<DashMap<Address, AccountState>>,
    /// Total circulating supply tracker (base units, u128).
    ///
    /// Security fix (CF-05, OZ-17): replaced AtomicU64 (lossy — tracked whole
    /// tokens only, truncated amounts > 2^64) with Mutex<u128> for exact
    /// base-unit tracking.  This is used for supply cap enforcement and
    /// monitoring; correctness matters more than lock-free reads here.
    /// Signed-off-by: Claude Opus 4.6
    total_supply: Arc<Mutex<u128>>,
    /// Per-address transfer locks with deterministic ordering to prevent deadlocks.
    ///
    /// Security fix (HB-002): replaced global transfer_lock with per-address locks.
    /// The global lock serialised ALL transfers, killing parallelism.  Per-address
    /// locks allow independent transfers (A->B and C->D) to proceed in parallel.
    /// Deadlocks are prevented by always locking the smaller address first.
    ///
    /// Security fix (E-02) origin — Signed-off-by: Claude Sonnet 4.6
    /// Upgrade (HB-002) — Signed-off-by: Claude Opus 4.6
    transfer_locks: Arc<DashMap<Address, Arc<Mutex<()>>>>,
}

impl Default for StateDB {
    fn default() -> Self {
        Self::new()
    }
}

impl StateDB {
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(DashMap::new()),
            total_supply: Arc::new(Mutex::new(0u128)),
            transfer_locks: Arc::new(DashMap::new()),
        }
    }

    /// Current total supply in base units (exact).
    ///
    /// Security fix (CF-05) — Signed-off-by: Claude Opus 4.6
    pub fn total_supply(&self) -> u128 {
        *self.total_supply.lock()
    }

    /// Current total supply in whole tokens (for display).
    pub fn total_supply_tokens(&self) -> u64 {
        (*self.total_supply.lock() / cathode_types::token::ONE_TOKEN as u128) as u64
    }

    /// Get account (returns default if not found).
    pub fn get(&self, addr: &Address) -> AccountState {
        self.accounts.get(addr).map(|r| r.clone()).unwrap_or_default()
    }

    /// Set account state directly.
    pub fn set(&self, addr: Address, state: AccountState) {
        self.accounts.insert(addr, state);
    }

    /// Get current nonce for an address.
    pub fn nonce(&self, addr: &Address) -> u64 {
        self.get(addr).nonce
    }

    /// Get balance.
    pub fn balance(&self, addr: &Address) -> TokenAmount {
        self.get(addr).balance
    }

    /// Mint tokens to an address (genesis distribution, rewards).
    ///
    /// Returns `Err(StateError::SupplyCapExceeded)` if minting would push total
    /// supply past `MAX_SUPPLY`.  The supply check and credit are atomic under
    /// the `total_supply` mutex so concurrent mints cannot race past the cap.
    ///
    /// Security fix (CF-05, CF-09, OZ-03) — Signed-off-by: Claude Opus 4.6
    pub fn mint(&self, addr: Address, amount: TokenAmount) -> Result<(), StateError> {
        let mut supply = self.total_supply.lock();
        let new_supply = supply.checked_add(amount.base())
            .ok_or(StateError::SupplyCapExceeded)?;
        if new_supply > MAX_SUPPLY {
            return Err(StateError::SupplyCapExceeded);
        }
        let mut entry = self.accounts.entry(addr).or_default();
        let new_balance = entry.value().balance.checked_add(amount)
            .ok_or(StateError::SupplyCapExceeded)?;
        entry.value_mut().balance = new_balance;
        *supply = new_supply;
        Ok(())
    }

    /// Credit tokens to an address WITHOUT incrementing total_supply.
    ///
    /// Used for recycling fees: gas fees are deducted from the sender (which
    /// does NOT reduce total_supply — it's a transfer, not a burn) and then
    /// credited to the fee collector.  Using `mint()` here would inflate
    /// total_supply by the fee amount on every transaction.
    ///
    /// Security fix (FEE-MINT) — Signed-off-by: Claude Opus 4.6
    pub fn credit(&self, addr: Address, amount: TokenAmount) -> Result<(), StateError> {
        let mut entry = self.accounts.entry(addr).or_default();
        let new_balance = entry.value().balance.checked_add(amount)
            .ok_or(StateError::SupplyCapExceeded)?;
        entry.value_mut().balance = new_balance;
        Ok(())
    }

    /// Transfer tokens between accounts.
    ///
    /// # Atomicity guarantee
    ///
    /// Per-address ordered locks ensure the debit and credit are atomic for each
    /// (from, to) pair.  Independent transfers (disjoint address pairs) proceed
    /// in parallel.  Deadlocks are prevented by always acquiring the lock for the
    /// numerically smaller address first.
    ///
    /// Security fix (E-02, HB-002) — Signed-off-by: Claude Opus 4.6
    pub fn transfer(
        &self,
        from: &Address,
        to: &Address,
        amount: TokenAmount,
        nonce: u64,
    ) -> Result<(), StateError> {
        // Self-transfer: just bump nonce (no credit/debit split, no race).
        if from == to {
            let mut entry = self.accounts.entry(*from).or_default();
            let acc = entry.value_mut();
            if acc.nonce != nonce {
                return Err(StateError::NonceMismatch {
                    expected: acc.nonce,
                    got: nonce,
                });
            }
            acc.nonce = acc.nonce.checked_add(1).ok_or(StateError::NonceExhausted)?;
            return Ok(());
        }

        // Security fix (C-05): prune stale transfer locks before creating new ones
        // to prevent unbounded memory growth from dust-spam attacks.
        // Security fix (C-05) — Signed-off-by: Claude Opus 4.6
        if self.transfer_locks.len() >= MAX_TRANSFER_LOCKS {
            self.prune_transfer_locks();
        }

        // Security fix (HB-002): per-address ordered locking — lock smaller address first
        // to prevent deadlocks while allowing parallel independent transfers.
        // Supersedes global transfer_lock (E-02).
        // Signed-off-by: Claude Opus 4.6
        let (first, second) = if from.0 < to.0 { (from, to) } else { (to, from) };
        let lock1 = self.transfer_locks.entry(*first).or_insert_with(|| Arc::new(Mutex::new(()))).clone();
        let lock2 = self.transfer_locks.entry(*second).or_insert_with(|| Arc::new(Mutex::new(()))).clone();
        let _guard1 = lock1.lock();
        let _guard2 = lock2.lock();

        // Debit sender (under shard lock for *from)
        {
            let mut entry = self.accounts.entry(*from).or_default();
            let acc = entry.value_mut();
            if acc.nonce != nonce {
                return Err(StateError::NonceMismatch {
                    expected: acc.nonce,
                    got: nonce,
                });
            }
            acc.balance = acc.balance
                .checked_sub(amount)
                .ok_or(StateError::InsufficientBalance {
                    have: acc.balance,
                    need: amount,
                })?;
            acc.nonce = acc.nonce.checked_add(1).ok_or(StateError::NonceExhausted)?;
        }

        // Credit receiver (under shard lock for *to) — still inside transfer_lock
        //
        // Security fix (SAT-01): replaced saturating_add with checked_add.
        // saturating_add silently capped at u128::MAX, violating the conservation
        // invariant (sender debited more than receiver credited).
        // Signed-off-by: Claude Opus 4.6
        {
            let mut entry = self.accounts.entry(*to).or_default();
            entry.value_mut().balance = entry.value().balance.checked_add(amount)
                .ok_or(StateError::SupplyCapExceeded)?;
        }

        Ok(())
    }

    /// Add stake for an address.
    pub fn add_stake(&self, addr: &Address, amount: TokenAmount, nonce: u64) -> Result<(), StateError> {
        let mut entry = self.accounts.entry(*addr).or_default();
        let acc = entry.value_mut();
        if acc.nonce != nonce {
            return Err(StateError::NonceMismatch {
                expected: acc.nonce,
                got: nonce,
            });
        }
        acc.balance = acc.balance
            .checked_sub(amount)
            .ok_or(StateError::InsufficientBalance {
                have: acc.balance,
                need: amount,
            })?;
        // Security fix (SAT-02): checked_add for staked credit.
        // Signed-off-by: Claude Opus 4.6
        acc.staked = acc.staked.checked_add(amount)
            .ok_or(StateError::SupplyCapExceeded)?;
        acc.nonce = acc.nonce.checked_add(1).ok_or(StateError::NonceExhausted)?;
        Ok(())
    }

    /// Remove stake from an address (unstake).
    pub fn remove_stake(&self, addr: &Address, amount: TokenAmount, nonce: u64) -> Result<(), StateError> {
        let mut entry = self.accounts.entry(*addr).or_default();
        let acc = entry.value_mut();
        if acc.nonce != nonce {
            return Err(StateError::NonceMismatch {
                expected: acc.nonce,
                got: nonce,
            });
        }
        acc.staked = acc.staked
            .checked_sub(amount)
            .ok_or(StateError::InsufficientStake {
                have: acc.staked,
                need: amount,
            })?;
        // Security fix (SAT-02): checked_add for balance credit on unstake.
        // Signed-off-by: Claude Opus 4.6
        acc.balance = acc.balance.checked_add(amount)
            .ok_or(StateError::SupplyCapExceeded)?;
        acc.nonce = acc.nonce.checked_add(1).ok_or(StateError::NonceExhausted)?;
        Ok(())
    }

    /// Set contract code hash for an address.
    pub fn set_code(&self, addr: &Address, code_hash: Hash32) {
        let mut entry = self.accounts.entry(*addr).or_default();
        entry.value_mut().code_hash = Some(code_hash);
    }

    /// Compute state Merkle root (deterministic, parallel).
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
                let mut buf = Vec::with_capacity(128);
                buf.extend_from_slice(&addr.0);
                buf.extend_from_slice(&bincode::serialize(state).expect("serialize"));
                Hasher::sha3_256(&buf)
            })
            .collect();

        MerkleTree::from_leaves(&leaves).root()
    }

    /// Number of accounts.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Bump nonce only (for failed TXs that still consume gas).
    pub fn bump_nonce(&self, addr: &Address) -> Result<(), StateError> {
        let mut entry = self.accounts.entry(*addr).or_default();
        let acc = entry.value_mut();
        acc.nonce = acc.nonce.checked_add(1).ok_or(StateError::NonceExhausted)?;
        Ok(())
    }

    /// Iterate all accounts (snapshot clone for safe iteration).
    pub fn iter_accounts(&self) -> Vec<(Address, AccountState)> {
        self.accounts
            .iter()
            .map(|r| (*r.key(), r.value().clone()))
            .collect()
    }

    /// All accounts sorted by address (deterministic for checkpoint hashing).
    // Security fix (H-02) — Signed-off-by: Claude Opus 4.6
    pub fn all_accounts_sorted(&self) -> Vec<(Address, AccountState)> {
        let mut accs = self.iter_accounts();
        accs.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
        accs
    }

    /// Prune transfer locks for addresses that no longer exist in accounts.
    /// Called automatically when the lock map exceeds MAX_TRANSFER_LOCKS.
    /// Security fix (C-05): prevents unbounded memory growth from dust spam.
    /// Security fix (C-05) — Signed-off-by: Claude Opus 4.6
    pub fn prune_transfer_locks(&self) {
        self.transfer_locks.retain(|addr, _| {
            self.accounts.contains_key(addr)
        });
    }

    /// Deduct gas fee from balance.
    pub fn deduct_fee(&self, addr: &Address, fee: TokenAmount) -> Result<(), StateError> {
        let mut entry = self.accounts.entry(*addr).or_default();
        let acc = entry.value_mut();
        acc.balance = acc.balance
            .checked_sub(fee)
            .ok_or(StateError::InsufficientBalance {
                have: acc.balance,
                need: fee,
            })?;
        Ok(())
    }
}

/// State errors.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch { expected: u64, got: u64 },
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: TokenAmount, need: TokenAmount },
    #[error("insufficient stake: have {have}, need {need}")]
    InsufficientStake { have: TokenAmount, need: TokenAmount },
    #[error("nonce exhausted")]
    NonceExhausted,
    /// Minting would exceed MAX_SUPPLY.
    /// Security fix (CF-09, OZ-03) — Signed-off-by: Claude Opus 4.6
    #[error("supply cap exceeded")]
    SupplyCapExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_and_transfer() {
        let db = StateDB::new();
        let alice = Address::from_bytes([1; 32]);
        let bob = Address::from_bytes([2; 32]);

        db.mint(alice, TokenAmount::from_tokens(1000)).unwrap();
        assert_eq!(db.balance(&alice), TokenAmount::from_tokens(1000));

        db.transfer(&alice, &bob, TokenAmount::from_tokens(300), 0).unwrap();
        assert_eq!(db.balance(&alice), TokenAmount::from_tokens(700));
        assert_eq!(db.balance(&bob), TokenAmount::from_tokens(300));
        assert_eq!(db.nonce(&alice), 1);
    }

    #[test]
    fn insufficient_balance_rejected() {
        let db = StateDB::new();
        let alice = Address::from_bytes([1; 32]);
        let bob = Address::from_bytes([2; 32]);
        db.mint(alice, TokenAmount::from_tokens(100)).unwrap();
        let err = db.transfer(&alice, &bob, TokenAmount::from_tokens(200), 0);
        assert!(err.is_err());
    }

    #[test]
    fn nonce_mismatch_rejected() {
        let db = StateDB::new();
        let alice = Address::from_bytes([1; 32]);
        let bob = Address::from_bytes([2; 32]);
        db.mint(alice, TokenAmount::from_tokens(100)).unwrap();
        let err = db.transfer(&alice, &bob, TokenAmount::from_tokens(10), 5);
        assert!(err.is_err());
    }

    #[test]
    fn stake_and_unstake() {
        let db = StateDB::new();
        let alice = Address::from_bytes([1; 32]);
        db.mint(alice, TokenAmount::from_tokens(1000)).unwrap();

        db.add_stake(&alice, TokenAmount::from_tokens(500), 0).unwrap();
        assert_eq!(db.balance(&alice), TokenAmount::from_tokens(500));
        assert_eq!(db.get(&alice).staked, TokenAmount::from_tokens(500));

        db.remove_stake(&alice, TokenAmount::from_tokens(200), 1).unwrap();
        assert_eq!(db.balance(&alice), TokenAmount::from_tokens(700));
        assert_eq!(db.get(&alice).staked, TokenAmount::from_tokens(300));
    }

    #[test]
    fn merkle_root_deterministic() {
        let db = StateDB::new();
        let a = Address::from_bytes([1; 32]);
        let b = Address::from_bytes([2; 32]);
        db.mint(a, TokenAmount::from_tokens(100)).unwrap();
        db.mint(b, TokenAmount::from_tokens(200)).unwrap();
        let r1 = db.merkle_root();
        let r2 = db.merkle_root();
        assert_eq!(r1, r2);
        assert_ne!(r1, Hash32::ZERO);
    }

    /// Security fix (E-02) — Signed-off-by: Claude Sonnet 4.6
    /// Concurrent transfers from the same sender must not double-spend.
    #[test]
    fn concurrent_transfer_no_double_spend() {
        use std::sync::Arc;
        use std::thread;

        let db = Arc::new(StateDB::new());
        let alice = Address::from_bytes([1; 32]);
        let bob   = Address::from_bytes([2; 32]);
        let carol = Address::from_bytes([3; 32]);

        // Alice has exactly 100 tokens.  Two threads race to transfer 100 each.
        // Only one should succeed; the other should fail with InsufficientBalance.
        db.mint(alice, TokenAmount::from_tokens(100)).unwrap();

        let db1 = db.clone();
        let db2 = db.clone();

        let t1 = thread::spawn(move || {
            db1.transfer(&alice, &bob, TokenAmount::from_tokens(100), 0)
        });
        let t2 = thread::spawn(move || {
            db2.transfer(&alice, &carol, TokenAmount::from_tokens(100), 0)
        });

        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();

        // Exactly one must succeed and one must fail.
        let successes = [r1.is_ok(), r2.is_ok()].iter().filter(|&&b| b).count();
        assert_eq!(successes, 1, "exactly one transfer must succeed");

        // Alice's balance must be zero (she transferred everything).
        assert_eq!(db.balance(&alice), TokenAmount::ZERO);

        // Total of bob+carol = 100 tokens exactly.
        let total = db.balance(&bob).base() + db.balance(&carol).base();
        assert_eq!(total, TokenAmount::from_tokens(100).base());
    }
}
