//! Transaction types — the structured payload that goes into hashgraph events.
//!
//! Instead of raw `Vec<u8>` payloads, all state changes go through typed transactions.
//! Each transaction is signed by its sender and carries a nonce for replay protection.
//! A `chain_id` field is included in the signing preimage to prevent cross-chain
//! replay attacks (a transaction signed for chain A cannot be replayed on chain B).
//
// Security fix — Signed-off-by: Claude Sonnet 4.6

use crate::address::Address;
use crate::token::TokenAmount;
use cathode_crypto::hash::{Hash32, Hasher};
use cathode_crypto::signature::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature, verify_ed25519};
use serde::{Deserialize, Serialize};

/// A signed, typed transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// Sender address (= Ed25519 public key).
    pub sender: Address,
    /// Replay-protection nonce (must match sender's current nonce).
    pub nonce: u64,
    /// Chain identifier — included in the signing preimage so a signature
    /// produced for one Cathode network cannot be replayed on another.
    /// Security fix — Signed-off-by: Claude Sonnet 4.6
    pub chain_id: u64,
    /// What this transaction does.
    pub kind: TransactionKind,
    /// Maximum gas units the sender is willing to pay.
    pub gas_limit: u64,
    /// Price per gas unit in base token units.
    pub gas_price: u64,
    /// BLAKE3 hash of the canonical encoding of (sender, nonce, chain_id, kind, gas_limit, gas_price).
    pub hash: Hash32,
    /// Ed25519 signature over the hash.
    pub signature: Ed25519Signature,
}

/// The different kinds of transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransactionKind {
    /// Transfer native tokens from sender to recipient.
    Transfer {
        to: Address,
        amount: TokenAmount,
    },
    /// Deploy a smart contract (WASM bytecode).
    Deploy {
        code: Vec<u8>,
        init_data: Vec<u8>,
    },
    /// Call an existing smart contract.
    ContractCall {
        contract: Address,
        method: String,
        args: Vec<u8>,
    },
    /// Stake tokens to participate in consensus.
    Stake {
        amount: TokenAmount,
    },
    /// Unstake tokens (subject to unbonding period).
    Unstake {
        amount: TokenAmount,
    },
    /// Create an HCS topic.
    CreateTopic {
        memo: String,
        submit_key: Option<[u8; 32]>,
    },
    /// Submit a message to an HCS topic.
    TopicMessage {
        topic_id: Hash32,
        payload: Vec<u8>,
    },
    /// Register or update a validator node.
    RegisterValidator {
        endpoint: String,
    },
    /// Governance vote.
    Vote {
        proposal_id: Hash32,
        approve: bool,
    },
}

/// Well-known chain IDs.
pub const CHAIN_ID_MAINNET: u64 = 1;
pub const CHAIN_ID_TESTNET: u64 = 2;
pub const CHAIN_ID_DEVNET: u64 = 3;

impl Transaction {
    /// Create and sign a new transaction.
    ///
    /// `chain_id` must match the target network's identifier — it is bound into
    /// the signing preimage so the signature cannot be replayed on a different chain.
    pub fn new(
        nonce: u64,
        kind: TransactionKind,
        gas_limit: u64,
        gas_price: u64,
        chain_id: u64,
        keypair: &Ed25519KeyPair,
    ) -> Self {
        let sender = Address(keypair.public_key().0);

        let hash = Self::compute_hash(&sender, nonce, chain_id, &kind, gas_limit, gas_price);
        let signature = keypair.sign(hash.as_bytes());

        Self {
            sender,
            nonce,
            chain_id,
            kind,
            gas_limit,
            gas_price,
            hash,
            signature,
        }
    }

    /// Compute the canonical hash for a transaction.
    /// chain_id is included to prevent cross-chain replay attacks.
    /// Security fix — Signed-off-by: Claude Sonnet 4.6
    fn compute_hash(
        sender: &Address,
        nonce: u64,
        chain_id: u64,
        kind: &TransactionKind,
        gas_limit: u64,
        gas_price: u64,
    ) -> Hash32 {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&sender.0);
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.extend_from_slice(&chain_id.to_le_bytes()); // replay protection
        // Security fix (CK-002): canonical fixed-int encoding for deterministic hashing.
        // Default bincode uses variable-length integers which can change across versions.
        // Signed-off-by: Claude Opus 4.6
        {
            use bincode::Options;
            let kind_bytes = bincode::options()
                .with_fixint_encoding()
                .with_big_endian()
                .serialize(kind)
                .expect("serialize kind");
            buf.extend_from_slice(&kind_bytes);
        }
        buf.extend_from_slice(&gas_limit.to_le_bytes());
        buf.extend_from_slice(&gas_price.to_le_bytes());
        Hasher::sha3_256(&buf)
    }

    /// Verify the transaction signature and hash integrity.
    pub fn verify(&self) -> Result<(), TransactionError> {
        // 1. Recompute hash (chain_id is part of the preimage)
        let expected = Self::compute_hash(
            &self.sender,
            self.nonce,
            self.chain_id,
            &self.kind,
            self.gas_limit,
            self.gas_price,
        );
        if expected != self.hash {
            return Err(TransactionError::HashMismatch);
        }

        // 2. Verify signature
        let pk = Ed25519PublicKey(self.sender.0);
        verify_ed25519(&pk, self.hash.as_bytes(), &self.signature)
            .map_err(|_| TransactionError::InvalidSignature)
    }

    /// Maximum encoded transaction size (128 KB).
    /// Security fix — Signed-off-by: Claude Sonnet 4.6
    /// Keeps individual transactions small to prevent DoS via oversized payloads.
    pub const MAX_TX_SIZE: usize = 128 * 1024; // 128 KB

    /// Serialise to bytes for embedding in event payloads.
    ///
    /// Panics if the encoded size exceeds `MAX_TX_SIZE` — callers should validate
    /// inputs (e.g. contract code length) before constructing large transactions.
    pub fn encode(&self) -> Vec<u8> {
        let bytes = bincode::serialize(self).expect("Transaction::encode never fails");
        assert!(
            bytes.len() <= Self::MAX_TX_SIZE,
            "Transaction::encode: encoded size {} exceeds MAX_TX_SIZE {}",
            bytes.len(),
            Self::MAX_TX_SIZE
        );
        bytes
    }

    /// Maximum encoded transaction size for decode (kept as alias for decode path).
    const MAX_DECODE_SIZE: usize = Self::MAX_TX_SIZE;

    /// Deserialise from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransactionError> {
        if bytes.len() > Self::MAX_DECODE_SIZE {
            return Err(TransactionError::DecodeFailed(
                format!("payload too large: {} bytes, max {}", bytes.len(), Self::MAX_DECODE_SIZE)
            ));
        }
        bincode::deserialize(bytes).map_err(|e| TransactionError::DecodeFailed(e.to_string()))
    }

    /// Estimated size in bytes (for gas/fee calculation).
    pub fn size(&self) -> usize {
        self.encode().len()
    }

    /// Is this a simple transfer?
    pub fn is_transfer(&self) -> bool {
        matches!(self.kind, TransactionKind::Transfer { .. })
    }

    /// Compute the maximum gas fee in base token units (gas_limit * gas_price).
    ///
    /// Returns `None` if the multiplication overflows u128.  Callers MUST use
    /// this instead of computing `gas_limit as u128 * gas_price as u128`
    /// themselves to avoid silent overflow.
    pub fn max_gas_fee(&self) -> Option<u128> {
        // SECURITY FIX: both operands are u64; their product fits in u128 for any
        // u64 pair (max = 2^64 * 2^64 = 2^128 which is exactly u128::MAX + 1),
        // so checked_mul is required here.
        (self.gas_limit as u128).checked_mul(self.gas_price as u128)
    }

    /// Validate gas parameters: gas_limit must be non-zero and the fee must
    /// not overflow u128.
    pub fn validate_gas(&self) -> Result<u128, TransactionError> {
        if self.gas_limit == 0 {
            return Err(TransactionError::GasLimitExceeded { used: 0, limit: 0 });
        }
        self.max_gas_fee().ok_or(TransactionError::GasOverflow {
            gas_limit: self.gas_limit,
            gas_price: self.gas_price,
        })
    }
}

/// Transaction errors.
#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error("hash mismatch — transaction fields were tampered")]
    HashMismatch,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("decode failed: {0}")]
    DecodeFailed(String),
    #[error("nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch { expected: u64, got: u64 },
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: TokenAmount, need: TokenAmount },
    #[error("gas limit exceeded: used {used}, limit {limit}")]
    GasLimitExceeded { used: u64, limit: u64 },
    /// gas_limit * gas_price overflows u128.
    #[error("gas fee overflow: gas_limit={gas_limit}, gas_price={gas_price}")]
    GasOverflow { gas_limit: u64, gas_price: u64 },
    #[error("sender is zero address")]
    ZeroSender,
    #[error("transfer to self with zero amount")]
    EmptyTransaction,
    #[error("deploy code is empty")]
    EmptyCode,
    #[error("supply cap exceeded")]
    SupplyCapExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_transfer(kp: &Ed25519KeyPair, nonce: u64, to: Address, amount: u64) -> Transaction {
        Transaction::new(
            nonce,
            TransactionKind::Transfer {
                to,
                amount: TokenAmount::from_tokens(amount),
            },
            21000,
            1,
            CHAIN_ID_TESTNET,
            kp,
        )
    }

    #[test]
    fn create_and_verify_transfer() {
        let kp = Ed25519KeyPair::generate();
        let to = Address::from_bytes([0xBB; 32]);
        let tx = make_transfer(&kp, 0, to, 100);
        assert!(tx.verify().is_ok());
        assert!(tx.is_transfer());
    }

    #[test]
    fn tampered_amount_rejected() {
        let kp = Ed25519KeyPair::generate();
        let to = Address::from_bytes([0xBB; 32]);
        let mut tx = make_transfer(&kp, 0, to, 100);
        tx.kind = TransactionKind::Transfer {
            to,
            amount: TokenAmount::from_tokens(999999),
        };
        assert!(tx.verify().is_err());
    }

    #[test]
    fn tampered_nonce_rejected() {
        let kp = Ed25519KeyPair::generate();
        let to = Address::from_bytes([0xBB; 32]);
        let mut tx = make_transfer(&kp, 0, to, 100);
        tx.nonce = 999;
        assert!(tx.verify().is_err());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let kp = Ed25519KeyPair::generate();
        let to = Address::from_bytes([0xBB; 32]);
        let tx = make_transfer(&kp, 5, to, 50);
        let bytes = tx.encode();
        let decoded = Transaction::decode(&bytes).unwrap();
        assert!(decoded.verify().is_ok());
        assert_eq!(decoded.hash, tx.hash);
        assert_eq!(decoded.nonce, 5);
    }

    #[test]
    fn different_tx_types() {
        let kp = Ed25519KeyPair::generate();

        let stake = Transaction::new(
            0,
            TransactionKind::Stake { amount: TokenAmount::from_tokens(1000) },
            50000,
            1,
            CHAIN_ID_TESTNET,
            &kp,
        );
        assert!(stake.verify().is_ok());

        let deploy = Transaction::new(
            1,
            TransactionKind::Deploy {
                code: vec![0x00, 0x61, 0x73, 0x6D], // WASM magic
                init_data: vec![],
            },
            1_000_000,
            1,
            CHAIN_ID_TESTNET,
            &kp,
        );
        assert!(deploy.verify().is_ok());

        let vote = Transaction::new(
            2,
            TransactionKind::Vote {
                proposal_id: Hash32::ZERO,
                approve: true,
            },
            21000,
            1,
            CHAIN_ID_TESTNET,
            &kp,
        );
        assert!(vote.verify().is_ok());
    }

    #[test]
    fn wrong_signer_rejected() {
        let kp1 = Ed25519KeyPair::generate();
        let kp2 = Ed25519KeyPair::generate();
        let to = Address::from_bytes([0xBB; 32]);
        let mut tx = make_transfer(&kp1, 0, to, 100);
        // Swap sender to kp2 but keep kp1's signature
        tx.sender = Address(kp2.public_key().0);
        assert!(tx.verify().is_err());
    }

    /// Security fix — Signed-off-by: Claude Sonnet 4.6
    /// A transaction signed for one chain must not verify on a different chain.
    #[test]
    fn cross_chain_replay_rejected() {
        let kp = Ed25519KeyPair::generate();
        let to = Address::from_bytes([0xBB; 32]);
        // Sign for testnet
        let tx = Transaction::new(
            0,
            TransactionKind::Transfer { to, amount: TokenAmount::from_tokens(50) },
            21000,
            1,
            CHAIN_ID_TESTNET,
            &kp,
        );
        assert!(tx.verify().is_ok());

        // Forge the same tx claiming it targets mainnet
        let mut replayed = tx.clone();
        replayed.chain_id = CHAIN_ID_MAINNET;
        // Hash will no longer match the signature — must be rejected
        assert!(replayed.verify().is_err());
    }
}
