//! Executor pipeline — validates and executes consensus-ordered transactions.
//!
//! For each consensus-ordered event:
//!   1. Decode payload → Transaction
//!   2. Pre-validate (sig, hash, nonce, balance for gas)
//!   3. Compute gas cost
//!   4. Execute state transition
//!   5. Deduct gas fee
//!   6. Produce Receipt

use crate::gas::GasSchedule;
use crate::state::{StateDB, StateError};
use cathode_crypto::hash::{Hash32, Hasher};
use cathode_types::address::Address;
use cathode_types::receipt::{Receipt, ReceiptBuilder};
use cathode_types::token::TokenAmount;
use cathode_types::transaction::{Transaction, TransactionKind};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tracing::{warn, trace};

// ---------------------------------------------------------------------------
// Bounded receipt store
// ---------------------------------------------------------------------------

/// Maximum number of receipts kept in-memory.
///
/// Older receipts are evicted (LRU ring buffer).  Persist to RocksDB for
/// historical queries beyond this window.
///
/// Security fix (E-05, E-15) — Signed-off-by: Claude Sonnet 4.6
///
/// The original implementation stored receipts in an unbounded `Vec<Receipt>`
/// and used O(n) linear scan for lookup.  Both properties are exploitable:
///   E-05: An attacker can exhaust RAM by generating enough transactions.
///   E-15: An attacker can issue `get_transaction` RPC calls to force O(n)
///         scans while the Mutex is held, starving transaction execution.
///
/// Fix: bounded ring-buffer (VecDeque) + HashMap for O(1) lookup.
const RECEIPT_STORE_CAPACITY: usize = 100_000;

struct ReceiptStore {
    by_hash: HashMap<Hash32, Receipt>,
    order: VecDeque<Hash32>,
    capacity: usize,
}

impl ReceiptStore {
    fn new(capacity: usize) -> Self {
        Self {
            by_hash: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn insert(&mut self, r: Receipt) {
        // Evict oldest if at capacity
        if self.order.len() >= self.capacity {
            if let Some(old_hash) = self.order.pop_front() {
                self.by_hash.remove(&old_hash);
            }
        }
        let hash = r.tx_hash;
        self.order.push_back(hash);
        self.by_hash.insert(hash, r);
    }

    /// O(1) receipt lookup.
    fn get(&self, hash: &Hash32) -> Option<&Receipt> {
        self.by_hash.get(hash)
    }

    fn len(&self) -> usize {
        self.order.len()
    }

    fn all(&self) -> Vec<Receipt> {
        self.by_hash.values().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// The executor — processes transactions against state.
pub struct Executor {
    state: Arc<StateDB>,
    gas_schedule: GasSchedule,
    /// Fee collector address (receives gas fees).
    fee_collector: Address,
    /// The chain_id this executor accepts.  Transactions signed for a different
    /// chain are rejected before execution, preventing cross-chain replay.
    ///
    /// Security fix (CF-01, OZ-01, SP-01, CK-01) — Signed-off-by: Claude Opus 4.6
    chain_id: u64,
    /// Bounded receipt store — O(1) insert and lookup.
    ///
    /// Security fix (E-05, E-15) — Signed-off-by: Claude Sonnet 4.6
    receipts: Mutex<ReceiptStore>,
    /// Total transactions processed.
    tx_count: Mutex<u64>,
}

impl Executor {
    /// Create a new executor with chain_id for replay protection.
    ///
    /// Security fix (CF-01) — Signed-off-by: Claude Opus 4.6
    pub fn new(state: Arc<StateDB>, fee_collector: Address, chain_id: u64) -> Self {
        Self {
            state,
            gas_schedule: GasSchedule::default(),
            fee_collector,
            chain_id,
            receipts: Mutex::new(ReceiptStore::new(RECEIPT_STORE_CAPACITY)),
            tx_count: Mutex::new(0),
        }
    }

    /// Create with custom gas schedule.
    pub fn with_gas_schedule(state: Arc<StateDB>, fee_collector: Address, chain_id: u64, gas: GasSchedule) -> Self {
        Self {
            state,
            gas_schedule: gas,
            fee_collector,
            chain_id,
            receipts: Mutex::new(ReceiptStore::new(RECEIPT_STORE_CAPACITY)),
            tx_count: Mutex::new(0),
        }
    }

    /// Reference to the state.
    pub fn state(&self) -> &Arc<StateDB> {
        &self.state
    }

    /// Maximum payload size for transaction decoding (1 MB).
    const MAX_TX_PAYLOAD: usize = 1024 * 1024;

    /// Maximum allowed gas_limit per transaction (50M gas).
    const MAX_GAS_LIMIT: u64 = 50_000_000;

    /// Process a single consensus-ordered event payload.
    /// Returns the receipt.
    pub fn execute_event(
        &self,
        payload: &[u8],
        event_hash: Hash32,
        consensus_order: u64,
        consensus_timestamp_ns: u64,
    ) -> Option<Receipt> {
        // Empty payload = heartbeat event, no transaction
        if payload.is_empty() {
            return None;
        }

        // Reject oversized payloads before attempting decode
        if payload.len() > Self::MAX_TX_PAYLOAD {
            warn!(len = payload.len(), "oversized tx payload rejected");
            return None;
        }

        // Decode transaction
        let tx = match Transaction::decode(payload) {
            Ok(tx) => tx,
            Err(e) => {
                trace!("skipping non-tx event payload: {}", e);
                return None;
            }
        };

        let receipt = self.execute_tx(&tx, event_hash, consensus_order, consensus_timestamp_ns);

        {
            let mut store = self.receipts.lock();
            store.insert(receipt.clone());
        }

        let mut count = self.tx_count.lock();
        *count += 1;

        Some(receipt)
    }

    /// Execute a single transaction.
    fn execute_tx(
        &self,
        tx: &Transaction,
        event_hash: Hash32,
        consensus_order: u64,
        consensus_timestamp_ns: u64,
    ) -> Receipt {
        let builder = ReceiptBuilder::new(tx.hash, event_hash)
            .consensus(consensus_order, consensus_timestamp_ns);

        // 1. Verify signature + hash integrity
        if let Err(e) = tx.verify() {
            return builder.gas_used(0).failed(format!("verification: {}", e));
        }

        // 1b. Chain ID enforcement — reject transactions signed for a different chain.
        // This is the executor-level defence; gossip also filters, but a malicious
        // local submitter can bypass gossip.  Five auditors flagged this as CRITICAL.
        // Security fix (CF-01, OZ-01, SP-01, CK-01, CD) — Signed-off-by: Claude Opus 4.6
        if tx.chain_id != self.chain_id {
            return builder.gas_used(0).failed(
                format!("chain_id mismatch: tx has {}, node expects {}", tx.chain_id, self.chain_id)
            );
        }

        // 2. Check sender is not zero address
        if tx.sender.is_zero() {
            return builder.gas_used(0).failed("sender is zero address".to_string());
        }

        // 3. Check gas_limit is within bounds
        if tx.gas_limit > Self::MAX_GAS_LIMIT {
            return builder.gas_used(0).failed(
                format!("gas_limit {} exceeds max {}", tx.gas_limit, Self::MAX_GAS_LIMIT)
            );
        }

        // 4. Check nonce
        let current_nonce = self.state.nonce(&tx.sender);
        if tx.nonce != current_nonce {
            return builder.gas_used(0).failed(
                format!("nonce mismatch: expected {}, got {}", current_nonce, tx.nonce)
            );
        }

        // 5. Compute gas cost
        let gas_cost = self.compute_gas(&tx.kind);
        if gas_cost > tx.gas_limit {
            // Nonce still bumps on out-of-gas (prevents replay)
            let _ = self.state.bump_nonce(&tx.sender);
            return builder.gas_used(tx.gas_limit).failed(
                format!("gas limit exceeded: need {}, limit {}", gas_cost, tx.gas_limit)
            );
        }

        // 6. Check balance covers gas fee + transfer amount
        // Security fix (F-01): explicit error on gas fee overflow instead of
        // silently falling back to u128::MAX.
        // Signed-off-by: Claude Opus 4.6
        let gas_fee = match (gas_cost as u128).checked_mul(tx.gas_price as u128) {
            Some(fee) => TokenAmount::from_base(fee),
            None => {
                let _ = self.state.bump_nonce(&tx.sender);
                return builder.gas_used(0).failed(
                    format!("gas fee overflow: {} * {}", gas_cost, tx.gas_price)
                );
            }
        };
        let total_needed = match &tx.kind {
            TransactionKind::Transfer { amount, .. } => {
                match gas_fee.checked_add(*amount) {
                    Some(total) => total,
                    None => {
                        let _ = self.state.bump_nonce(&tx.sender);
                        return builder.gas_used(0).failed(
                            "total cost overflow: gas_fee + transfer amount".to_string()
                        );
                    }
                }
            }
            TransactionKind::Stake { amount } => {
                match gas_fee.checked_add(*amount) {
                    Some(total) => total,
                    None => {
                        let _ = self.state.bump_nonce(&tx.sender);
                        return builder.gas_used(0).failed(
                            "total cost overflow: gas_fee + stake amount".to_string()
                        );
                    }
                }
            }
            _ => gas_fee,
        };

        let sender_balance = self.state.balance(&tx.sender);
        if sender_balance.base() < total_needed.base() {
            let _ = self.state.bump_nonce(&tx.sender);
            return builder.gas_used(gas_cost).failed(
                format!("insufficient balance: have {}, need {}", sender_balance, total_needed)
            );
        }

        // 6. Execute the state transition
        let result = self.apply_kind(tx, &builder);

        // 7. Deduct gas fee (goes to fee collector)
        // Security fix (E-08): do NOT charge gas for unsupported tx kinds.
        // Security fix (F-02): check deduct_fee return value — if deduction
        // fails, the tx must fail to prevent fee collector inflation.
        // Signed-off-by: Claude Opus 4.6
        match result {
            ApplyResult::NotSupported(reason) => {
                // No gas charged — only bump nonce to prevent replay.
                let _ = self.state.bump_nonce(&tx.sender);
                builder.gas_used(0).failed(reason)
            }
            _ => {
                if gas_fee.base() > 0 {
                    if let Err(e) = self.state.deduct_fee(&tx.sender, gas_fee) {
                        // Security fix (CF-13): do NOT bump_nonce here — apply_kind
                        // already bumped the nonce as part of the state transition.
                        // Bumping again would skip a nonce, orphaning all subsequent
                        // transactions from this sender.
                        // Signed-off-by: Claude Opus 4.6
                        warn!(tx_hash = %tx.hash.short(), "fee deduction failed: {}", e);
                        return builder.gas_used(gas_cost).failed(
                            format!("fee deduction failed: {}", e)
                        );
                    }
                    if !self.fee_collector.is_zero() {
                        // Security fix (FEE-MINT): use credit() not mint().
                        // Gas fees are recycled tokens (already in total_supply),
                        // not new supply.  mint() would inflate total_supply.
                        // Signed-off-by: Claude Opus 4.6
                        if let Err(e) = self.state.credit(self.fee_collector, gas_fee) {
                            warn!("fee collector credit failed: {}", e);
                        }
                    }
                }
                match result {
                    ApplyResult::Success => {
                        trace!(tx_hash = %tx.hash.short(), "tx executed successfully");
                        builder.gas_used(gas_cost).success()
                    }
                    ApplyResult::Err(e) => {
                        warn!(tx_hash = %tx.hash.short(), "tx failed: {}", e);
                        builder.gas_used(gas_cost).failed(e)
                    }
                    ApplyResult::NotSupported(_) => unreachable!(),
                }
            }
        }
    }

    /// Apply the transaction kind to state.
    ///
    /// Returns `ApplyResult::NotSupported` for transaction kinds that are
    /// not yet implemented (Deploy, ContractCall) so the caller can produce
    /// a clear failed receipt WITHOUT charging gas.
    ///
    /// Security fix (E-08) — Signed-off-by: Claude Sonnet 4.6
    ///
    /// The original implementation silently bumped the nonce and returned
    /// `Ok(())` for Deploy and ContractCall, making the receipt show
    /// "success" even though no WASM was executed.  Users who relied on
    /// smart contract logic (vesting, DeFi, escrow) believed their
    /// transaction executed when in reality nothing happened.  This is
    /// financially dangerous.
    ///
    /// Fix: return NotSupported for both kinds so the receipt clearly shows
    /// failure with an explanatory message.  Gas is not charged (it would be
    /// unfair to charge for something that doesn't execute).
    fn apply_kind(&self, tx: &Transaction, _builder: &ReceiptBuilder) -> ApplyResult {
        match &tx.kind {
            TransactionKind::Transfer { to, amount } => {
                match self.state.transfer(&tx.sender, to, *amount, tx.nonce) {
                    Ok(()) => ApplyResult::Success,
                    Err(e) => ApplyResult::Err(e.to_string()),
                }
            }
            TransactionKind::Stake { amount } => {
                match self.state.add_stake(&tx.sender, *amount, tx.nonce) {
                    Ok(()) => ApplyResult::Success,
                    Err(e) => ApplyResult::Err(e.to_string()),
                }
            }
            TransactionKind::Unstake { amount } => {
                match self.state.remove_stake(&tx.sender, *amount, tx.nonce) {
                    Ok(()) => ApplyResult::Success,
                    Err(e) => ApplyResult::Err(e.to_string()),
                }
            }

            // Security fix (E-08) — Signed-off-by: Claude Sonnet 4.6
            // WASM execution is not yet implemented.  Returning NotSupported
            // produces a FAILED receipt (no gas charged) instead of a false
            // SUCCESS receipt that would mislead users into thinking their
            // contract executed.
            TransactionKind::Deploy { .. } => {
                ApplyResult::NotSupported(
                    "smart contract deployment is not yet implemented — transaction rejected"
                        .to_string(),
                )
            }
            TransactionKind::ContractCall { .. } => {
                ApplyResult::NotSupported(
                    "smart contract calls are not yet implemented — transaction rejected"
                        .to_string(),
                )
            }

            TransactionKind::CreateTopic { .. } => {
                match self.state.bump_nonce(&tx.sender) {
                    Ok(()) => ApplyResult::Success,
                    Err(e) => ApplyResult::Err(e.to_string()),
                }
            }
            TransactionKind::TopicMessage { .. } => {
                match self.state.bump_nonce(&tx.sender) {
                    Ok(()) => ApplyResult::Success,
                    Err(e) => ApplyResult::Err(e.to_string()),
                }
            }
            TransactionKind::RegisterValidator { .. } => {
                match self.state.bump_nonce(&tx.sender) {
                    Ok(()) => ApplyResult::Success,
                    Err(e) => ApplyResult::Err(e.to_string()),
                }
            }
            TransactionKind::Vote { .. } => {
                match self.state.bump_nonce(&tx.sender) {
                    Ok(()) => ApplyResult::Success,
                    Err(e) => ApplyResult::Err(e.to_string()),
                }
            }
        }
    }

    /// Compute gas for a transaction kind.
    fn compute_gas(&self, kind: &TransactionKind) -> u64 {
        match kind {
            TransactionKind::Transfer { .. } => self.gas_schedule.transfer,
            TransactionKind::Deploy { code, .. } => {
                self.gas_schedule.deploy_base +
                    (code.len() as u64).saturating_mul(self.gas_schedule.deploy_per_byte)
            }
            TransactionKind::ContractCall { .. } => self.gas_schedule.call_base,
            TransactionKind::Stake { .. } => self.gas_schedule.stake,
            TransactionKind::Unstake { .. } => self.gas_schedule.stake,
            TransactionKind::CreateTopic { .. } => self.gas_schedule.create_topic,
            TransactionKind::TopicMessage { .. } => self.gas_schedule.topic_message,
            TransactionKind::RegisterValidator { .. } => self.gas_schedule.register_validator,
            TransactionKind::Vote { .. } => self.gas_schedule.vote,
        }
    }

    /// Get all receipts (snapshot).
    pub fn receipts(&self) -> Vec<Receipt> {
        self.receipts.lock().all()
    }

    /// Get receipt by tx hash — O(1) lookup.
    ///
    /// Security fix (E-05, E-15) — Signed-off-by: Claude Sonnet 4.6
    pub fn receipt_by_hash(&self, tx_hash: &Hash32) -> Option<Receipt> {
        self.receipts.lock().get(tx_hash).cloned()
    }

    /// Total transactions processed.
    pub fn tx_count(&self) -> u64 {
        *self.tx_count.lock()
    }

    /// Number of receipts currently held in-memory.
    pub fn receipt_count(&self) -> usize {
        self.receipts.lock().len()
    }
}

/// Result type for apply_kind to distinguish NotSupported from runtime errors.
enum ApplyResult {
    Success,
    Err(String),
    /// Transaction kind is not yet implemented — receipt should be FAILED,
    /// no gas charged, nonce bumped by caller.
    NotSupported(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_crypto::signature::Ed25519KeyPair;

    fn setup() -> (Executor, Ed25519KeyPair, Address) {
        use cathode_types::transaction::CHAIN_ID_TESTNET;
        let state = Arc::new(StateDB::new());
        let fee_collector = Address::from_bytes([0xFF; 32]);
        let executor = Executor::new(state.clone(), fee_collector, CHAIN_ID_TESTNET);
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        // Mint initial balance
        state.mint(sender, TokenAmount::from_tokens(10_000)).unwrap();
        (executor, kp, sender)
    }

    #[test]
    fn execute_transfer() {
        let (exec, kp, sender) = setup();
        let bob = Address::from_bytes([0xBB; 32]);

        let tx = Transaction::new(
            0,
            TransactionKind::Transfer {
                to: bob,
                amount: TokenAmount::from_tokens(500),
            },
            21000,
            1,
            2u64,
            &kp,
        );
        // Security fix — Signed-off-by: Claude Opus 4.6

        let payload = tx.encode();
        let receipt = exec.execute_event(&payload, Hash32::ZERO, 0, 1000).unwrap();
        assert!(receipt.status.is_success());
        assert_eq!(receipt.gas_used, 21000);

        // Check balances
        let sender_bal = exec.state().balance(&sender);
        let bob_bal = exec.state().balance(&bob);
        let fee = TokenAmount::from_base(21000); // gas_cost * gas_price(1)
        let expected_sender = TokenAmount::from_tokens(10_000)
            .checked_sub(TokenAmount::from_tokens(500)).unwrap()
            .checked_sub(fee).unwrap();
        assert_eq!(sender_bal, expected_sender);
        assert_eq!(bob_bal, TokenAmount::from_tokens(500));
    }

    #[test]
    fn execute_transfer_insufficient_balance() {
        let (exec, kp, _) = setup();
        let bob = Address::from_bytes([0xBB; 32]);

        let tx = Transaction::new(
            0,
            TransactionKind::Transfer {
                to: bob,
                amount: TokenAmount::from_tokens(999_999),
            },
            21000,
            1,
            2u64,
            &kp,
        );

        let payload = tx.encode();
        let receipt = exec.execute_event(&payload, Hash32::ZERO, 0, 1000).unwrap();
        assert!(!receipt.status.is_success());
    }

    #[test]
    fn execute_nonce_mismatch() {
        let (exec, kp, _) = setup();
        let bob = Address::from_bytes([0xBB; 32]);

        let tx = Transaction::new(
            99, // wrong nonce
            TransactionKind::Transfer {
                to: bob,
                amount: TokenAmount::from_tokens(10),
            },
            21000,
            1,
            2u64,
            &kp,
        );

        let payload = tx.encode();
        let receipt = exec.execute_event(&payload, Hash32::ZERO, 0, 1000).unwrap();
        assert!(!receipt.status.is_success());
    }

    #[test]
    fn execute_stake() {
        let (exec, kp, sender) = setup();

        let tx = Transaction::new(
            0,
            TransactionKind::Stake { amount: TokenAmount::from_tokens(2000) },
            50000,
            1,
            2u64,
            &kp,
        );

        let payload = tx.encode();
        let receipt = exec.execute_event(&payload, Hash32::ZERO, 0, 1000).unwrap();
        assert!(receipt.status.is_success());

        let acc = exec.state().get(&sender);
        assert_eq!(acc.staked, TokenAmount::from_tokens(2000));
    }

    /// Security fix (E-08) — Signed-off-by: Claude Sonnet 4.6
    /// Deploy transactions must produce a FAILED receipt (not success) until
    /// WASM execution is implemented.  No gas should be charged.
    #[test]
    fn execute_deploy_returns_not_supported() {
        let (exec, kp, sender) = setup();
        let balance_before = exec.state().balance(&sender);

        let tx = Transaction::new(
            0,
            TransactionKind::Deploy {
                code: vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00], // WASM magic
                init_data: vec![],
            },
            1_000_000,
            1,
            2u64,
            &kp,
        );

        let payload = tx.encode();
        let receipt = exec.execute_event(&payload, Hash32::ZERO, 0, 1000).unwrap();

        // Must FAIL — WASM not implemented
        assert!(!receipt.status.is_success(), "Deploy must fail with NotSupported");

        // No gas charged — gas_used must be 0
        assert_eq!(receipt.gas_used, 0, "No gas must be charged for unimplemented Deploy");

        // Balance must be unchanged (no gas deducted)
        let balance_after = exec.state().balance(&sender);
        assert_eq!(balance_before, balance_after, "No gas deducted for unsupported tx kind");

        // Nonce must have advanced (prevents replay)
        assert_eq!(exec.state().nonce(&sender), 1);
    }

    /// Security fix (E-08) — ContractCall also returns NotSupported.
    #[test]
    fn execute_contract_call_returns_not_supported() {
        let (exec, kp, sender) = setup();
        let balance_before = exec.state().balance(&sender);

        let tx = Transaction::new(
            0,
            TransactionKind::ContractCall {
                contract: Address::from_bytes([0xCC; 32]),
                method: "transfer".into(),
                args: vec![],
            },
            100_000,
            1,
            2u64,
            &kp,
        );

        let payload = tx.encode();
        let receipt = exec.execute_event(&payload, Hash32::ZERO, 0, 1000).unwrap();

        assert!(!receipt.status.is_success());
        assert_eq!(receipt.gas_used, 0);
        assert_eq!(exec.state().balance(&sender), balance_before);
        assert_eq!(exec.state().nonce(&sender), 1);
    }

    #[test]
    fn gas_limit_too_low() {
        let (exec, kp, _) = setup();
        let bob = Address::from_bytes([0xBB; 32]);

        let tx = Transaction::new(
            0,
            TransactionKind::Transfer {
                to: bob,
                amount: TokenAmount::from_tokens(10),
            },
            100, // way too low, transfer needs 21000
            1,
            2u64,
            &kp,
        );

        let payload = tx.encode();
        let receipt = exec.execute_event(&payload, Hash32::ZERO, 0, 1000).unwrap();
        assert!(!receipt.status.is_success());
        // Nonce should still bump
        assert_eq!(exec.state().nonce(&tx.sender), 1);
    }

    #[test]
    fn fee_collector_receives_fees() {
        let (exec, kp, _) = setup();
        let bob = Address::from_bytes([0xBB; 32]);
        let fee_collector = Address::from_bytes([0xFF; 32]);

        let tx = Transaction::new(
            0,
            TransactionKind::Transfer {
                to: bob,
                amount: TokenAmount::from_tokens(100),
            },
            21000,
            1,
            2u64,
            &kp,
        );

        let payload = tx.encode();
        exec.execute_event(&payload, Hash32::ZERO, 0, 1000).unwrap();

        let collector_bal = exec.state().balance(&fee_collector);
        assert_eq!(collector_bal, TokenAmount::from_base(21000));
    }

    #[test]
    fn sequential_transactions() {
        let (exec, kp, sender) = setup();
        let bob = Address::from_bytes([0xBB; 32]);

        for i in 0..10u64 {
            let tx = Transaction::new(
                i,
                TransactionKind::Transfer {
                    to: bob,
                    amount: TokenAmount::from_tokens(10),
                },
                21000,
                1,
                2u64,
                &kp,
            );
            let payload = tx.encode();
            let receipt = exec.execute_event(&payload, Hash32::ZERO, i, 1000 + i).unwrap();
            assert!(receipt.status.is_success(), "tx {} failed: {:?}", i, receipt.status);
        }

        assert_eq!(exec.state().balance(&bob), TokenAmount::from_tokens(100));
        assert_eq!(exec.state().nonce(&sender), 10);
        assert_eq!(exec.tx_count(), 10);
    }

    #[test]
    fn empty_payload_ignored() {
        let (exec, _, _) = setup();
        let receipt = exec.execute_event(&[], Hash32::ZERO, 0, 1000);
        assert!(receipt.is_none());
    }

    #[test]
    fn tampered_tx_rejected() {
        let (exec, kp, _) = setup();
        let bob = Address::from_bytes([0xBB; 32]);

        let mut tx = Transaction::new(
            0,
            TransactionKind::Transfer {
                to: bob,
                amount: TokenAmount::from_tokens(100),
            },
            21000,
            1,
            2u64,
            &kp,
        );
        // Tamper
        tx.kind = TransactionKind::Transfer {
            to: bob,
            amount: TokenAmount::from_tokens(999999),
        };

        let payload = tx.encode();
        let receipt = exec.execute_event(&payload, Hash32::ZERO, 0, 1000).unwrap();
        assert!(!receipt.status.is_success());
    }

    /// Security fix (E-05, E-15) — Signed-off-by: Claude Sonnet 4.6
    /// Receipt lookup must be O(1) and the store must not grow unboundedly.
    #[test]
    fn receipt_store_is_bounded_and_o1_lookup() {
        let state = Arc::new(StateDB::new());
        let fee_collector = Address::from_bytes([0xFF; 32]);
        use cathode_types::transaction::CHAIN_ID_TESTNET;
        let exec = Executor::new(state.clone(), fee_collector, CHAIN_ID_TESTNET);
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        state.mint(sender, TokenAmount::from_tokens(1_000_000)).unwrap();

        let bob = Address::from_bytes([0xBB; 32]);
        let mut last_hash = Hash32::ZERO;

        // Submit RECEIPT_STORE_CAPACITY + 10 transactions
        let total = RECEIPT_STORE_CAPACITY + 10;
        for i in 0..total as u64 {
            let tx = Transaction::new(
                i,
                TransactionKind::Transfer {
                    to: bob,
                    amount: TokenAmount::from_base(1),
                },
                21000,
                1,
                2u64,
                &kp,
            );
            last_hash = tx.hash;
            let payload = tx.encode();
            exec.execute_event(&payload, Hash32::ZERO, i, i * 1000);
        }

        // Store must not exceed capacity
        assert!(
            exec.receipt_count() <= RECEIPT_STORE_CAPACITY,
            "receipt store exceeded capacity: {}",
            exec.receipt_count()
        );

        // Latest receipt must still be findable (O(1))
        let found = exec.receipt_by_hash(&last_hash);
        assert!(found.is_some(), "latest receipt must be findable");
    }
}
