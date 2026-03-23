//! cathode-mempool — pending transaction pool.
//!
//! Transactions arrive from RPC or gossip, get pre-validated, and wait
//! in the mempool until the node creates a new hashgraph event to include them.
//!
//! Features:
//!   - Deduplication by tx hash
//!   - Per-sender nonce ordering
//!   - Size limits (max pending TXs, max per sender)
//!   - Priority by gas price (higher gas price = picked first)

#![forbid(unsafe_code)]

use cathode_crypto::hash::Hash32;
use cathode_executor::state::StateDB;
use cathode_types::address::Address;
use cathode_types::transaction::Transaction;
use parking_lot::RwLock;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use tracing::{trace, warn};

/// Maximum transactions in the mempool.
const DEFAULT_MAX_POOL_SIZE: usize = 10_000;
/// Maximum pending transactions per sender.
const DEFAULT_MAX_PER_SENDER: usize = 100;
/// Maximum nonce gap allowed (prevents memory exhaustion from future nonces).
const MAX_NONCE_GAP: u64 = 1000;
/// Maximum size of the `known` dedup set before it is pruned.
/// Security fix (MEMPOOL-KNOWN): without a cap, `known` grows unbounded
/// (one entry per tx ever seen, even after pruning from by_hash), causing
/// OOM on long-running nodes.
/// Signed-off-by: Claude Opus 4.6
const MAX_KNOWN_SIZE: usize = 100_000;

/// Mempool configuration.
#[derive(Clone, Debug)]
pub struct MempoolConfig {
    pub max_pool_size: usize,
    pub max_per_sender: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_pool_size: DEFAULT_MAX_POOL_SIZE,
            max_per_sender: DEFAULT_MAX_PER_SENDER,
        }
    }
}

/// A pending transaction with its priority score.
#[derive(Clone, Debug)]
struct PendingTx {
    tx: Transaction,
    /// Priority = gas_price (higher = picked first).
    priority: u64,
}

/// The mempool — holds validated transactions waiting for inclusion in events.
pub struct Mempool {
    config: MempoolConfig,
    state: Arc<StateDB>,
    /// Expected chain ID — transactions for a different chain are rejected.
    /// Security fix (SP-001) — Signed-off-by: Claude Opus 4.6
    expected_chain_id: u64,
    /// All pending transactions by hash.
    by_hash: RwLock<HashMap<Hash32, PendingTx>>,
    /// Per-sender pending transaction hashes (ordered by nonce).
    by_sender: RwLock<HashMap<Address, BTreeMap<u64, Hash32>>>,
    /// Known hashes (for dedup, including already-executed).
    known: RwLock<HashSet<Hash32>>,
}

impl Mempool {
    /// Create a new mempool.
    /// Security fix (SP-001): chain_id parameter for cross-chain replay protection.
    /// Signed-off-by: Claude Opus 4.6
    pub fn new(state: Arc<StateDB>, config: MempoolConfig, chain_id: u64) -> Self {
        Self {
            config,
            state,
            expected_chain_id: chain_id,
            by_hash: RwLock::new(HashMap::new()),
            by_sender: RwLock::new(HashMap::new()),
            known: RwLock::new(HashSet::new()),
        }
    }

    /// Create with default config.
    /// Security fix (SP-001): chain_id parameter for cross-chain replay protection.
    /// Signed-off-by: Claude Opus 4.6
    pub fn with_defaults(state: Arc<StateDB>, chain_id: u64) -> Self {
        Self::new(state, MempoolConfig::default(), chain_id)
    }

    /// Submit a transaction to the mempool.
    /// Returns Ok(hash) if accepted, Err if rejected.
    pub fn submit(&self, tx: Transaction) -> Result<Hash32, MempoolError> {
        let tx_hash = tx.hash;

        // 1. Dedup check
        {
            let known = self.known.read();
            if known.contains(&tx_hash) {
                return Err(MempoolError::Duplicate);
            }
        }

        // 2. Verify signature
        tx.verify().map_err(|e| MempoolError::InvalidTx(e.to_string()))?;

        // 2b. Security fix (SP-001): reject transactions for wrong chain.
        // Signed-off-by: Claude Opus 4.6
        if tx.chain_id != self.expected_chain_id {
            return Err(MempoolError::WrongChain);
        }

        // 3. Check sender is not zero
        if tx.sender.is_zero() {
            return Err(MempoolError::InvalidTx("zero sender".to_string()));
        }

        // 4. Check nonce is >= current (allow future nonces for queuing)
        let current_nonce = self.state.nonce(&tx.sender);
        if tx.nonce < current_nonce {
            return Err(MempoolError::NonceTooLow {
                current: current_nonce,
                got: tx.nonce,
            });
        }

        // 4b. Reject nonces too far in the future (prevents memory exhaustion)
        if tx.nonce > current_nonce + MAX_NONCE_GAP {
            return Err(MempoolError::NonceTooHigh {
                current: current_nonce,
                got: tx.nonce,
                max_gap: MAX_NONCE_GAP,
            });
        }

        // 5-7. Atomic check + insert (prevents TOCTOU race on pool size)
        let pending = PendingTx {
            priority: tx.gas_price,
            tx,
        };

        {
            let mut by_hash = self.by_hash.write();
            let mut by_sender = self.by_sender.write();
            let mut known = self.known.write();

            // Security fix (E-07): second dedup check under write lock.
            //
            // The early read-lock check at the top of submit() is an optimistic
            // fast path.  Two concurrent callers can both pass that check before
            // either acquires the write lock below.  Without a second check under
            // the write lock, both callers would proceed to insert the same hash,
            // corrupting by_sender's nonce map (second BTreeMap.insert for the
            // same nonce silently overwrites the first entry).
            //
            // Fix: re-check known under the same write lock that guards insert,
            // so the check-and-insert is atomic.
            //
            // Signed-off-by: Claude Sonnet 4.6
            if known.contains(&tx_hash) {
                return Err(MempoolError::Duplicate);
            }

            // Per-sender limit under write lock — atomic with insert
            if let Some(sender_txs) = by_sender.get(&pending.tx.sender) {
                if sender_txs.len() >= self.config.max_per_sender {
                    return Err(MempoolError::SenderFull);
                }
            }

            // Security fix — Signed-off-by: Claude Opus 4.6
            //
            // Pool eviction policy: when the pool is full, evict the pending
            // transaction with the lowest gas price rather than rejecting the
            // incoming one.  If the incoming tx has an even lower gas price
            // than the current minimum, it is itself rejected — this prevents
            // memory exhaustion while maximising economic throughput.
            //
            // Without an eviction policy a mempool at capacity silently stops
            // accepting any new transactions (MempoolError::PoolFull), which
            // is exploitable by flooding with zero-fee dust to starve
            // legitimate high-fee transactions.
            if by_hash.len() >= self.config.max_pool_size {
                // Find the hash of the transaction with the lowest priority.
                let evict_hash = by_hash
                    .iter()
                    .min_by_key(|(_, ptx)| ptx.priority)
                    .map(|(h, _)| *h);

                if let Some(evict_h) = evict_hash {
                    // Capture fields before consuming the map entry.
                    let (evict_priority, evict_sender, evict_nonce) = {
                        let evict_ptx = by_hash.get(&evict_h).unwrap();
                        (evict_ptx.priority, evict_ptx.tx.sender, evict_ptx.tx.nonce)
                    };
                    // Reject incoming tx if it is not better than the worst.
                    if pending.priority <= evict_priority {
                        return Err(MempoolError::PoolFull);
                    }
                    // Evict the worst transaction.
                    by_hash.remove(&evict_h);
                    if let Some(nonce_map) = by_sender.get_mut(&evict_sender) {
                        nonce_map.remove(&evict_nonce);
                        if nonce_map.is_empty() {
                            by_sender.remove(&evict_sender);
                        }
                    }
                    warn!(
                        evicted = %evict_h.short(),
                        evicted_gas = evict_priority,
                        incoming_gas = pending.priority,
                        "mempool full — evicted lowest-gas-price tx"
                    );
                } else {
                    // Pool reported full but is actually empty — shouldn't happen.
                    return Err(MempoolError::PoolFull);
                }
            }

            by_hash.insert(tx_hash, pending.clone());
            by_sender
                .entry(pending.tx.sender)
                .or_default()
                .insert(pending.tx.nonce, tx_hash);
            known.insert(tx_hash);
        }

        trace!(hash = %tx_hash.short(), "tx added to mempool");
        Ok(tx_hash)
    }

    /// Reference to the underlying state (for nonce queries, testing).
    pub fn state(&self) -> &Arc<StateDB> {
        &self.state
    }

    /// Pick the best transactions for inclusion in an event.
    /// Returns up to `max_count` transactions, ordered by priority then nonce.
    pub fn pick(&self, max_count: usize) -> Vec<Transaction> {
        let by_hash = self.by_hash.read();
        let by_sender = self.by_sender.read();

        // Collect all "ready" transactions (nonce == current state nonce + pending count)
        let mut ready: Vec<&PendingTx> = Vec::new();

        // Security fix (MP-01): only pick transactions with consecutive nonces
        // starting from the current state nonce. Previously, non-consecutive
        // nonces (gaps) were included, but the executor would reject them for
        // nonce mismatch, wasting event payload space.
        // Signed-off-by: Claude Opus 4.6
        for (sender, nonce_map) in by_sender.iter() {
            let mut expected_nonce = self.state.nonce(sender);
            for (&nonce, hash) in nonce_map.iter() {
                if nonce != expected_nonce {
                    break; // gap detected — stop picking for this sender
                }
                if let Some(ptx) = by_hash.get(hash) {
                    ready.push(ptx);
                }
                expected_nonce += 1;
            }
        }

        // Sort by priority (desc), then nonce (asc)
        ready.sort_by(|a, b| {
            b.priority.cmp(&a.priority)
                .then_with(|| a.tx.nonce.cmp(&b.tx.nonce))
        });

        ready.into_iter()
            .take(max_count)
            .map(|ptx| ptx.tx.clone())
            .collect()
    }

    /// Remove transactions that have been executed (their nonce is now past).
    /// Call this after consensus processes events.
    pub fn prune_executed(&self) {
        let mut by_hash = self.by_hash.write();
        let mut by_sender = self.by_sender.write();

        let mut to_remove: Vec<Hash32> = Vec::new();

        for (sender, nonce_map) in by_sender.iter_mut() {
            let current_nonce = self.state.nonce(sender);
            let stale: Vec<u64> = nonce_map
                .keys()
                .copied()
                .filter(|&n| n < current_nonce)
                .collect();

            for nonce in stale {
                if let Some(hash) = nonce_map.remove(&nonce) {
                    to_remove.push(hash);
                }
            }
        }

        // Remove empty sender entries
        by_sender.retain(|_, map| !map.is_empty());

        for hash in &to_remove {
            by_hash.remove(hash);
        }

        // Security fix (MEMPOOL-KNOWN): prune the `known` dedup set when it
        // exceeds MAX_KNOWN_SIZE.  Remove entries that are no longer in by_hash
        // (already executed/evicted) to bound memory growth.
        // Signed-off-by: Claude Opus 4.6
        {
            let mut known = self.known.write();
            if known.len() > MAX_KNOWN_SIZE {
                let active: HashSet<Hash32> = by_hash.keys().copied().collect();
                known.retain(|h| active.contains(h));
            }
        }

        if !to_remove.is_empty() {
            trace!(pruned = to_remove.len(), "mempool pruned executed txs");
        }
    }

    /// Remove a specific transaction.
    pub fn remove(&self, tx_hash: &Hash32) -> bool {
        let mut by_hash = self.by_hash.write();
        let mut by_sender = self.by_sender.write();

        if let Some(ptx) = by_hash.remove(tx_hash) {
            if let Some(nonce_map) = by_sender.get_mut(&ptx.tx.sender) {
                nonce_map.remove(&ptx.tx.nonce);
                if nonce_map.is_empty() {
                    by_sender.remove(&ptx.tx.sender);
                }
            }
            true
        } else {
            false
        }
    }

    /// Mark a hash as known (e.g., received from gossip but already executed).
    pub fn mark_known(&self, hash: Hash32) {
        self.known.write().insert(hash);
    }

    /// Current pool size.
    pub fn len(&self) -> usize {
        self.by_hash.read().len()
    }

    /// Is the pool empty?
    pub fn is_empty(&self) -> bool {
        self.by_hash.read().is_empty()
    }

    /// Number of pending transactions for a sender.
    pub fn pending_count(&self, sender: &Address) -> usize {
        self.by_sender.read()
            .get(sender)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Get a transaction by hash.
    pub fn get(&self, hash: &Hash32) -> Option<Transaction> {
        self.by_hash.read().get(hash).map(|ptx| ptx.tx.clone())
    }
}

/// Mempool errors.
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("duplicate transaction")]
    Duplicate,
    #[error("invalid transaction: {0}")]
    InvalidTx(String),
    #[error("nonce too low: current {current}, got {got}")]
    NonceTooLow { current: u64, got: u64 },
    #[error("nonce too high: current {current}, got {got}, max gap {max_gap}")]
    NonceTooHigh { current: u64, got: u64, max_gap: u64 },
    #[error("mempool full")]
    PoolFull,
    #[error("per-sender limit reached")]
    SenderFull,
    /// Security fix (SP-001): transaction targets a different chain.
    /// Signed-off-by: Claude Opus 4.6
    #[error("wrong chain ID")]
    WrongChain,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_crypto::signature::Ed25519KeyPair;
    use cathode_types::token::TokenAmount;
    use cathode_types::transaction::TransactionKind;

    /// Test chain ID — must match the value used in `make_tx`.
    const TEST_CHAIN_ID: u64 = 2;

    fn setup() -> (Mempool, Ed25519KeyPair, Address) {
        let state = Arc::new(StateDB::new());
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        state.mint(sender, TokenAmount::from_tokens(100_000)).unwrap();
        let pool = Mempool::with_defaults(state, TEST_CHAIN_ID);
        (pool, kp, sender)
    }

    fn make_tx(kp: &Ed25519KeyPair, nonce: u64) -> Transaction {
        Transaction::new(
            nonce,
            TransactionKind::Transfer {
                to: Address::from_bytes([0xBB; 32]),
                amount: TokenAmount::from_tokens(10),
            },
            21000,
            1,
            2u64,
            kp,
        )
    }
    // Security fix — Signed-off-by: Claude Opus 4.6

    #[test]
    fn submit_and_pick() {
        let (pool, kp, _) = setup();

        let tx0 = make_tx(&kp, 0);
        let tx1 = make_tx(&kp, 1);
        let tx2 = make_tx(&kp, 2);

        pool.submit(tx0).unwrap();
        pool.submit(tx1).unwrap();
        pool.submit(tx2).unwrap();

        assert_eq!(pool.len(), 3);

        let picked = pool.pick(10);
        assert_eq!(picked.len(), 3);
        assert_eq!(picked[0].nonce, 0);
        assert_eq!(picked[1].nonce, 1);
        assert_eq!(picked[2].nonce, 2);
    }

    #[test]
    fn duplicate_rejected() {
        let (pool, kp, _) = setup();
        let tx = make_tx(&kp, 0);
        pool.submit(tx.clone()).unwrap();
        assert!(matches!(pool.submit(tx), Err(MempoolError::Duplicate)));
    }

    #[test]
    fn nonce_too_low_rejected() {
        let (pool, kp, sender) = setup();
        // Manually set nonce to 5
        pool.state.transfer(
            &sender,
            &Address::from_bytes([0xBB; 32]),
            TokenAmount::from_tokens(1),
            0,
        ).unwrap();
        // Nonce is now 1, trying to submit nonce=0 should fail
        let tx = make_tx(&kp, 0);
        assert!(matches!(pool.submit(tx), Err(MempoolError::NonceTooLow { .. })));
    }

    #[test]
    fn prune_executed() {
        let (pool, kp, sender) = setup();

        pool.submit(make_tx(&kp, 0)).unwrap();
        pool.submit(make_tx(&kp, 1)).unwrap();
        pool.submit(make_tx(&kp, 2)).unwrap();
        assert_eq!(pool.len(), 3);

        // Simulate execution: advance nonce to 2
        pool.state.transfer(
            &sender,
            &Address::from_bytes([0xBB; 32]),
            TokenAmount::from_tokens(1),
            0,
        ).unwrap();
        pool.state.transfer(
            &sender,
            &Address::from_bytes([0xBB; 32]),
            TokenAmount::from_tokens(1),
            1,
        ).unwrap();

        pool.prune_executed();
        assert_eq!(pool.len(), 1); // only nonce=2 remains
    }

    #[test]
    fn pool_full_rejected() {
        let state = Arc::new(StateDB::new());
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        state.mint(sender, TokenAmount::from_tokens(1_000_000)).unwrap();

        let config = MempoolConfig {
            max_pool_size: 3,
            max_per_sender: 100,
        };
        let pool = Mempool::new(state, config, TEST_CHAIN_ID);

        pool.submit(make_tx(&kp, 0)).unwrap();
        pool.submit(make_tx(&kp, 1)).unwrap();
        pool.submit(make_tx(&kp, 2)).unwrap();
        assert!(matches!(pool.submit(make_tx(&kp, 3)), Err(MempoolError::PoolFull)));
    }

    #[test]
    fn per_sender_limit() {
        let state = Arc::new(StateDB::new());
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        state.mint(sender, TokenAmount::from_tokens(1_000_000)).unwrap();

        let config = MempoolConfig {
            max_pool_size: 10_000,
            max_per_sender: 2,
        };
        let pool = Mempool::new(state, config, TEST_CHAIN_ID);

        pool.submit(make_tx(&kp, 0)).unwrap();
        pool.submit(make_tx(&kp, 1)).unwrap();
        assert!(matches!(pool.submit(make_tx(&kp, 2)), Err(MempoolError::SenderFull)));
    }

    #[test]
    fn priority_ordering() {
        let (pool, _, _) = setup();

        let kp_high = Ed25519KeyPair::generate();
        let kp_low = Ed25519KeyPair::generate();
        pool.state.mint(Address(kp_high.public_key().0), TokenAmount::from_tokens(100_000)).unwrap();
        pool.state.mint(Address(kp_low.public_key().0), TokenAmount::from_tokens(100_000)).unwrap();

        // Low priority
        let tx_low = Transaction::new(
            0,
            TransactionKind::Transfer {
                to: Address::from_bytes([0xBB; 32]),
                amount: TokenAmount::from_tokens(10),
            },
            21000,
            1, // gas_price = 1
            2u64,
            &kp_low,
        );

        // High priority
        let tx_high = Transaction::new(
            0,
            TransactionKind::Transfer {
                to: Address::from_bytes([0xBB; 32]),
                amount: TokenAmount::from_tokens(10),
            },
            21000,
            100, // gas_price = 100
            2u64,
            &kp_high,
        );

        pool.submit(tx_low).unwrap();
        pool.submit(tx_high).unwrap();

        let picked = pool.pick(10);
        assert_eq!(picked.len(), 2);
        assert_eq!(picked[0].gas_price, 100); // high priority first
        assert_eq!(picked[1].gas_price, 1);
    }

    #[test]
    fn tampered_tx_rejected() {
        let (pool, kp, _) = setup();
        let mut tx = make_tx(&kp, 0);
        tx.nonce = 999; // tamper
        assert!(matches!(pool.submit(tx), Err(MempoolError::InvalidTx(_))));
    }

    #[test]
    fn remove_tx() {
        let (pool, kp, _) = setup();
        let tx = make_tx(&kp, 0);
        let hash = pool.submit(tx).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.remove(&hash));
        assert_eq!(pool.len(), 0);
    }
}
