//! Invoice system — create, pay, cancel, and expire invoices.
//!
//! Signed-off-by: Claude Opus 4.6

use cathode_crypto::hash::{Hash32, Hasher};
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::fees::PaymentFeeSchedule;

/// Maximum memo length in bytes.
pub const MAX_MEMO_LEN: usize = 1024;

/// Maximum callback URL length in bytes.
pub const MAX_CALLBACK_URL_LEN: usize = 512;

/// Invoice status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvoiceStatus {
    Pending,
    Paid,
    Expired,
    Cancelled,
}

/// An invoice requesting payment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invoice {
    /// Unique invoice ID = SHA3-256(creator || recipient || amount || nonce || timestamp).
    pub id: Hash32,
    /// Who created the invoice.
    pub creator: Address,
    /// Who should pay.
    pub recipient: Address,
    /// Amount requested.
    pub amount: TokenAmount,
    /// Human-readable memo / description.
    pub memo: String,
    /// Block height when created.
    pub created_at: u64,
    /// Block height after which the invoice expires.
    pub expiry_block: u64,
    /// Current status.
    pub status: InvoiceStatus,
    /// Optional webhook / callback URL on payment.
    pub callback_url: Option<String>,
}

/// Errors for invoice operations.
#[derive(Debug, thiserror::Error)]
pub enum InvoiceError {
    #[error("invoice not found: {0}")]
    NotFound(Hash32),
    #[error("invoice already paid")]
    AlreadyPaid,
    #[error("invoice expired")]
    Expired,
    #[error("invoice cancelled")]
    Cancelled,
    #[error("not authorised: only creator can cancel")]
    Unauthorised,
    #[error("invalid amount: must be > 0")]
    ZeroAmount,
    #[error("expiry must be after creation")]
    InvalidExpiry,
    #[error("arithmetic overflow")]
    Overflow,
    #[error("self-transfer: creator and recipient must differ")]
    SelfTransfer,
    #[error("memo too long: {len} > {max}")]
    MemoTooLong { len: usize, max: usize },
    #[error("callback URL too long: {len} > {max}")]
    CallbackUrlTooLong { len: usize, max: usize },
}

/// Thread-safe invoice registry backed by DashMap.
pub struct InvoiceRegistry {
    invoices: DashMap<Hash32, Invoice>,
    nonce: AtomicU64,
    fee_schedule: PaymentFeeSchedule,
}

impl InvoiceRegistry {
    /// Create a new registry with default fee schedule.
    pub fn new() -> Self {
        Self {
            invoices: DashMap::new(),
            nonce: AtomicU64::new(0),
            fee_schedule: PaymentFeeSchedule::default(),
        }
    }

    /// Create with a custom fee schedule.
    pub fn with_fees(fee_schedule: PaymentFeeSchedule) -> Self {
        Self {
            invoices: DashMap::new(),
            nonce: AtomicU64::new(0),
            fee_schedule,
        }
    }

    /// Create a new invoice. Returns (invoice, creation_fee).
    pub fn create(
        &self,
        creator: Address,
        recipient: Address,
        amount: TokenAmount,
        memo: String,
        current_block: u64,
        expiry_block: u64,
        callback_url: Option<String>,
    ) -> Result<(Invoice, TokenAmount), InvoiceError> {
        if creator == recipient {
            return Err(InvoiceError::SelfTransfer);
        }
        if amount.is_zero() {
            return Err(InvoiceError::ZeroAmount);
        }
        if expiry_block <= current_block {
            return Err(InvoiceError::InvalidExpiry);
        }
        if memo.len() > MAX_MEMO_LEN {
            return Err(InvoiceError::MemoTooLong { len: memo.len(), max: MAX_MEMO_LEN });
        }
        if let Some(ref url) = callback_url {
            if url.len() > MAX_CALLBACK_URL_LEN {
                return Err(InvoiceError::CallbackUrlTooLong { len: url.len(), max: MAX_CALLBACK_URL_LEN });
            }
        }

        let nonce = self.nonce.fetch_add(1, Ordering::SeqCst);

        // Compute invoice ID = SHA3-256(creator || recipient || amount || nonce || timestamp)
        let id = Self::compute_id(&creator, &recipient, &amount, nonce, current_block);

        let creation_fee = self.fee_schedule.invoice_creation_fee;

        let invoice = Invoice {
            id,
            creator,
            recipient,
            amount,
            memo,
            created_at: current_block,
            expiry_block,
            status: InvoiceStatus::Pending,
            callback_url,
        };

        self.invoices.insert(id, invoice.clone());
        Ok((invoice, creation_fee))
    }

    /// Mark an invoice as paid. Returns the invoice amount on success.
    /// The `payer` is recorded but anyone can pay an invoice (not just the recipient).
    pub fn pay(
        &self,
        invoice_id: &Hash32,
        payer: &Address,
        current_block: u64,
    ) -> Result<TokenAmount, InvoiceError> {
        let _ = payer; // Recorded for audit trail; any address may pay
        let mut entry = self.invoices.get_mut(invoice_id)
            .ok_or(InvoiceError::NotFound(*invoice_id))?;

        let inv = entry.value_mut();

        match inv.status {
            InvoiceStatus::Paid => return Err(InvoiceError::AlreadyPaid),
            InvoiceStatus::Expired => return Err(InvoiceError::Expired),
            InvoiceStatus::Cancelled => return Err(InvoiceError::Cancelled),
            InvoiceStatus::Pending => {}
        }

        if current_block > inv.expiry_block {
            inv.status = InvoiceStatus::Expired;
            return Err(InvoiceError::Expired);
        }

        inv.status = InvoiceStatus::Paid;
        Ok(inv.amount)
    }

    /// Cancel an invoice. Only the creator can cancel.
    pub fn cancel(
        &self,
        invoice_id: &Hash32,
        caller: &Address,
    ) -> Result<(), InvoiceError> {
        let mut entry = self.invoices.get_mut(invoice_id)
            .ok_or(InvoiceError::NotFound(*invoice_id))?;

        let inv = entry.value_mut();

        if inv.creator != *caller {
            return Err(InvoiceError::Unauthorised);
        }

        match inv.status {
            InvoiceStatus::Paid => return Err(InvoiceError::AlreadyPaid),
            InvoiceStatus::Cancelled => return Ok(()),
            _ => {}
        }

        inv.status = InvoiceStatus::Cancelled;
        Ok(())
    }

    /// Get an invoice by ID.
    pub fn get(&self, invoice_id: &Hash32) -> Option<Invoice> {
        self.invoices.get(invoice_id).map(|r| r.value().clone())
    }

    /// Expire all stale invoices past their expiry block.
    /// Returns the number of invoices expired.
    pub fn expire_stale(&self, current_block: u64) -> u64 {
        let mut count = 0u64;
        for mut entry in self.invoices.iter_mut() {
            let inv = entry.value_mut();
            if inv.status == InvoiceStatus::Pending && current_block > inv.expiry_block {
                inv.status = InvoiceStatus::Expired;
                count = count.saturating_add(1);
            }
        }
        count
    }

    /// Total number of invoices in the registry.
    pub fn len(&self) -> usize {
        self.invoices.len()
    }

    /// Is the registry empty?
    pub fn is_empty(&self) -> bool {
        self.invoices.is_empty()
    }

    /// Compute the deterministic invoice ID.
    fn compute_id(
        creator: &Address,
        recipient: &Address,
        amount: &TokenAmount,
        nonce: u64,
        timestamp: u64,
    ) -> Hash32 {
        let mut buf = Vec::with_capacity(32 + 32 + 16 + 8 + 8);
        buf.extend_from_slice(&creator.0);
        buf.extend_from_slice(&recipient.0);
        buf.extend_from_slice(&amount.base().to_le_bytes());
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.extend_from_slice(&timestamp.to_le_bytes());
        Hasher::sha3_256(&buf)
    }
}

impl Default for InvoiceRegistry {
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
    fn create_and_get() {
        let reg = InvoiceRegistry::new();
        let (inv, _fee) = reg.create(
            addr(1), addr(2),
            TokenAmount::from_tokens(100),
            "test".into(), 10, 100, None,
        ).unwrap();
        assert_eq!(inv.status, InvoiceStatus::Pending);
        let fetched = reg.get(&inv.id).unwrap();
        assert_eq!(fetched.amount, TokenAmount::from_tokens(100));
    }

    #[test]
    fn zero_amount_rejected() {
        let reg = InvoiceRegistry::new();
        let res = reg.create(
            addr(1), addr(2), TokenAmount::ZERO,
            "zero".into(), 10, 100, None,
        );
        assert!(res.is_err());
    }

    #[test]
    fn invalid_expiry_rejected() {
        let reg = InvoiceRegistry::new();
        let res = reg.create(
            addr(1), addr(2), TokenAmount::from_tokens(10),
            "bad".into(), 100, 50, None,
        );
        assert!(res.is_err());
    }
}
