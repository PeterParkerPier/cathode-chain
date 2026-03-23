//! Escrow contracts — lock funds with buyer/seller/arbiter roles.
//!
//! Signed-off-by: Claude Opus 4.6

use cathode_crypto::hash::{Hash32, Hasher};
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Escrow status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscrowStatus {
    Locked,
    Released,
    Disputed,
    Refunded,
    TimedOut,
}

/// An escrow contract between buyer, seller, and arbiter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Escrow {
    /// Unique escrow ID.
    pub id: Hash32,
    /// Buyer (funds provider).
    pub buyer: Address,
    /// Seller (funds recipient on release).
    pub seller: Address,
    /// Arbiter (resolves disputes).
    pub arbiter: Address,
    /// Amount locked.
    pub amount: TokenAmount,
    /// Current status.
    pub status: EscrowStatus,
    /// Block height when created.
    pub created_block: u64,
    /// Number of blocks before auto-timeout.
    pub timeout_blocks: u64,
}

/// Escrow errors.
#[derive(Debug, thiserror::Error)]
pub enum EscrowError {
    #[error("escrow not found: {0}")]
    NotFound(Hash32),
    #[error("escrow not in expected state: want {expected}, got {actual}")]
    WrongStatus { expected: String, actual: String },
    #[error("unauthorised: {reason}")]
    Unauthorised { reason: String },
    #[error("invalid amount: must be > 0")]
    ZeroAmount,
    #[error("timeout_blocks must be > 0")]
    ZeroTimeout,
    #[error("arithmetic overflow")]
    Overflow,
    #[error("self-transfer: buyer and seller must differ")]
    SelfTransfer,
    #[error("arbiter conflict: arbiter must differ from buyer and seller")]
    ArbiterConflict,
}

/// Thread-safe escrow manager.
pub struct EscrowManager {
    escrows: DashMap<Hash32, Escrow>,
    nonce: AtomicU64,
}

impl EscrowManager {
    pub fn new() -> Self {
        Self {
            escrows: DashMap::new(),
            nonce: AtomicU64::new(0),
        }
    }

    /// Lock funds in a new escrow. Returns the created escrow.
    pub fn lock(
        &self,
        buyer: Address,
        seller: Address,
        arbiter: Address,
        amount: TokenAmount,
        current_block: u64,
        timeout_blocks: u64,
    ) -> Result<Escrow, EscrowError> {
        if buyer == seller {
            return Err(EscrowError::SelfTransfer);
        }
        if buyer == arbiter || seller == arbiter {
            return Err(EscrowError::ArbiterConflict);
        }
        if amount.is_zero() {
            return Err(EscrowError::ZeroAmount);
        }
        if timeout_blocks == 0 {
            return Err(EscrowError::ZeroTimeout);
        }

        let nonce = self.nonce.fetch_add(1, Ordering::SeqCst);

        let mut buf = Vec::with_capacity(32 + 32 + 32 + 16 + 8 + 8);
        buf.extend_from_slice(&buyer.0);
        buf.extend_from_slice(&seller.0);
        buf.extend_from_slice(&arbiter.0);
        buf.extend_from_slice(&amount.base().to_le_bytes());
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.extend_from_slice(&current_block.to_le_bytes());
        let id = Hasher::sha3_256(&buf);

        let escrow = Escrow {
            id,
            buyer,
            seller,
            arbiter,
            amount,
            status: EscrowStatus::Locked,
            created_block: current_block,
            timeout_blocks,
        };

        self.escrows.insert(id, escrow.clone());
        Ok(escrow)
    }

    /// Release funds to the seller. Only the buyer can release.
    pub fn release(
        &self,
        escrow_id: &Hash32,
        caller: &Address,
    ) -> Result<(Address, TokenAmount), EscrowError> {
        let mut entry = self.escrows.get_mut(escrow_id)
            .ok_or(EscrowError::NotFound(*escrow_id))?;

        let esc = entry.value_mut();

        if esc.buyer != *caller {
            return Err(EscrowError::Unauthorised {
                reason: "only buyer can release".into(),
            });
        }

        // Security fix (E-11) — Signed-off-by: Claude Sonnet 4.6
        //
        // The previous implementation accepted both Locked and Disputed in
        // release().  This allowed the buyer (or an attacker who controls the
        // buyer key) to call release() after raising a dispute, bypassing the
        // arbiter and extracting funds before the arbiter's resolve() call
        // settles the dispute.
        //
        // Fix: only allow release from Locked status.  Once an escrow is
        // Disputed, only the arbiter's resolve() may change the state.
        match esc.status {
            EscrowStatus::Locked => {}
            EscrowStatus::Disputed => {
                return Err(EscrowError::WrongStatus {
                    expected: "Locked".into(),
                    actual: "Disputed — arbiter must resolve via resolve()".into(),
                });
            }
            ref s => {
                return Err(EscrowError::WrongStatus {
                    expected: "Locked".into(),
                    actual: format!("{:?}", s),
                });
            }
        }

        esc.status = EscrowStatus::Released;
        Ok((esc.seller, esc.amount))
    }

    /// Raise a dispute. Either buyer or seller can dispute.
    pub fn dispute(
        &self,
        escrow_id: &Hash32,
        caller: &Address,
    ) -> Result<(), EscrowError> {
        let mut entry = self.escrows.get_mut(escrow_id)
            .ok_or(EscrowError::NotFound(*escrow_id))?;

        let esc = entry.value_mut();

        if esc.buyer != *caller && esc.seller != *caller {
            return Err(EscrowError::Unauthorised {
                reason: "only buyer or seller can dispute".into(),
            });
        }

        if esc.status != EscrowStatus::Locked {
            return Err(EscrowError::WrongStatus {
                expected: "Locked".into(),
                actual: format!("{:?}", esc.status),
            });
        }

        esc.status = EscrowStatus::Disputed;
        Ok(())
    }

    /// Resolve a dispute. Only the arbiter can resolve.
    /// `release_to_seller`: true = release to seller, false = refund to buyer.
    /// Returns (recipient, amount).
    pub fn resolve(
        &self,
        escrow_id: &Hash32,
        caller: &Address,
        release_to_seller: bool,
    ) -> Result<(Address, TokenAmount), EscrowError> {
        let mut entry = self.escrows.get_mut(escrow_id)
            .ok_or(EscrowError::NotFound(*escrow_id))?;

        let esc = entry.value_mut();

        if esc.arbiter != *caller {
            return Err(EscrowError::Unauthorised {
                reason: "only arbiter can resolve disputes".into(),
            });
        }

        if esc.status != EscrowStatus::Disputed {
            return Err(EscrowError::WrongStatus {
                expected: "Disputed".into(),
                actual: format!("{:?}", esc.status),
            });
        }

        if release_to_seller {
            esc.status = EscrowStatus::Released;
            Ok((esc.seller, esc.amount))
        } else {
            esc.status = EscrowStatus::Refunded;
            Ok((esc.buyer, esc.amount))
        }
    }

    /// Check for timed-out escrows. Returns list of (escrow_id, buyer, amount) for refunds.
    pub fn check_timeouts(&self, current_block: u64) -> Vec<(Hash32, Address, TokenAmount)> {
        let mut timed_out = Vec::new();

        for mut entry in self.escrows.iter_mut() {
            let esc = entry.value_mut();
            // Security fix (ESCROW-TIMEOUT): also timeout Disputed escrows.
            // Previously only Locked escrows could timeout.  A disputed escrow
            // whose arbiter never calls resolve() would stay locked forever,
            // permanently freezing the buyer's funds.
            // Signed-off-by: Claude Opus 4.6
            if esc.status == EscrowStatus::Locked || esc.status == EscrowStatus::Disputed {
                let deadline = esc.created_block.saturating_add(esc.timeout_blocks);
                if current_block >= deadline {
                    esc.status = EscrowStatus::TimedOut;
                    timed_out.push((esc.id, esc.buyer, esc.amount));
                }
            }
        }

        timed_out
    }

    /// Get an escrow by ID.
    pub fn get(&self, escrow_id: &Hash32) -> Option<Escrow> {
        self.escrows.get(escrow_id).map(|r| r.value().clone())
    }

    /// Total number of escrows.
    pub fn len(&self) -> usize {
        self.escrows.len()
    }

    /// Is the manager empty?
    pub fn is_empty(&self) -> bool {
        self.escrows.is_empty()
    }
}

impl Default for EscrowManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address::from_bytes([b; 32])
    }

    #[test]
    fn lock_and_release() {
        let mgr = EscrowManager::new();
        let esc = mgr.lock(addr(1), addr(2), addr(3),
            TokenAmount::from_tokens(500), 10, 100).unwrap();
        assert_eq!(esc.status, EscrowStatus::Locked);

        let (recipient, amount) = mgr.release(&esc.id, &addr(1)).unwrap();
        assert_eq!(recipient, addr(2));
        assert_eq!(amount, TokenAmount::from_tokens(500));
    }

    #[test]
    fn zero_amount_rejected() {
        let mgr = EscrowManager::new();
        assert!(mgr.lock(addr(1), addr(2), addr(3),
            TokenAmount::ZERO, 10, 100).is_err());
    }

    #[test]
    fn zero_timeout_rejected() {
        let mgr = EscrowManager::new();
        assert!(mgr.lock(addr(1), addr(2), addr(3),
            TokenAmount::from_tokens(10), 10, 0).is_err());
    }
}
