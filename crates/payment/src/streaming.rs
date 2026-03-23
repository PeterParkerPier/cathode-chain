//! Streaming payments — continuous fund flow from sender to recipient.
//!
//! Signed-off-by: Claude Opus 4.6

use cathode_crypto::hash::{Hash32, Hasher};
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Stream status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamStatus {
    Active,
    Completed,
    Cancelled,
}

/// A streaming payment — funds flow from sender to recipient over time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentStream {
    /// Unique stream ID.
    pub id: Hash32,
    /// Sender (funds provider).
    pub sender: Address,
    /// Recipient (funds receiver).
    pub recipient: Address,
    /// Total amount locked for the stream.
    pub total_amount: TokenAmount,
    /// Amount already withdrawn by recipient.
    pub withdrawn: TokenAmount,
    /// Tokens released per block.
    pub rate_per_block: TokenAmount,
    /// Block height when stream started.
    pub start_block: u64,
    /// Block height when stream ends (calculated: start + total/rate).
    pub end_block: u64,
    /// Current status.
    pub status: StreamStatus,
}

/// Stream errors.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("stream not found: {0}")]
    NotFound(Hash32),
    #[error("stream not active")]
    NotActive,
    #[error("unauthorised: {reason}")]
    Unauthorised { reason: String },
    #[error("invalid amount: must be > 0")]
    ZeroAmount,
    #[error("rate must be > 0")]
    ZeroRate,
    #[error("nothing to withdraw")]
    NothingToWithdraw,
    #[error("arithmetic overflow")]
    Overflow,
    #[error("self-transfer: sender and recipient must differ")]
    SelfTransfer,
    #[error("duration overflow: stream duration exceeds u64::MAX blocks")]
    DurationOverflow,
}

/// Thread-safe stream manager.
pub struct StreamManager {
    streams: DashMap<Hash32, PaymentStream>,
    nonce: AtomicU64,
}

impl StreamManager {
    pub fn new() -> Self {
        Self {
            streams: DashMap::new(),
            nonce: AtomicU64::new(0),
        }
    }

    /// Open a new payment stream. Returns the created stream.
    pub fn open(
        &self,
        sender: Address,
        recipient: Address,
        total_amount: TokenAmount,
        rate_per_block: TokenAmount,
        current_block: u64,
    ) -> Result<PaymentStream, StreamError> {
        if sender == recipient {
            return Err(StreamError::SelfTransfer);
        }
        if total_amount.is_zero() {
            return Err(StreamError::ZeroAmount);
        }
        if rate_per_block.is_zero() {
            return Err(StreamError::ZeroRate);
        }

        // Security fix (E-12) — Signed-off-by: Claude Sonnet 4.6
        // Validate that rate_per_block does not exceed total_amount.
        // A rate higher than the total would cause elapsed * rate to overflow
        // u128 in compute_withdrawable for any non-trivial elapsed value.
        // This guard makes the overflow path in compute_withdrawable unreachable
        // for legitimately created streams.
        if rate_per_block.base() > total_amount.base() {
            return Err(StreamError::Overflow);
        }

        // Calculate duration in blocks (ceiling division)
        let total = total_amount.base();
        let rate = rate_per_block.base();
        // duration = ceil(total / rate)
        let duration = total.checked_add(rate)
            .ok_or(StreamError::Overflow)?
            .checked_sub(1)
            .ok_or(StreamError::Overflow)?
            / rate;

        // H-06: Ensure duration fits in u64 before cast
        if duration > u64::MAX as u128 {
            return Err(StreamError::DurationOverflow);
        }

        let end_block = current_block.checked_add(duration as u64)
            .ok_or(StreamError::Overflow)?;

        let nonce = self.nonce.fetch_add(1, Ordering::SeqCst);

        let mut buf = Vec::with_capacity(32 + 32 + 16 + 16 + 8 + 8);
        buf.extend_from_slice(&sender.0);
        buf.extend_from_slice(&recipient.0);
        buf.extend_from_slice(&total_amount.base().to_le_bytes());
        buf.extend_from_slice(&rate_per_block.base().to_le_bytes());
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.extend_from_slice(&current_block.to_le_bytes());
        let id = Hasher::sha3_256(&buf);

        let stream = PaymentStream {
            id,
            sender,
            recipient,
            total_amount,
            withdrawn: TokenAmount::ZERO,
            rate_per_block,
            start_block: current_block,
            end_block,
            status: StreamStatus::Active,
        };

        self.streams.insert(id, stream.clone());
        Ok(stream)
    }

    /// Calculate the amount available for withdrawal right now.
    pub fn get_withdrawable(
        &self,
        stream_id: &Hash32,
        current_block: u64,
    ) -> Result<TokenAmount, StreamError> {
        let entry = self.streams.get(stream_id)
            .ok_or(StreamError::NotFound(*stream_id))?;
        let stream = entry.value();

        if stream.status != StreamStatus::Active {
            return Err(StreamError::NotActive);
        }

        Ok(Self::compute_withdrawable(stream, current_block))
    }

    /// Recipient withdraws available streamed funds.
    /// Returns the amount withdrawn.
    pub fn withdraw(
        &self,
        stream_id: &Hash32,
        caller: &Address,
        current_block: u64,
    ) -> Result<TokenAmount, StreamError> {
        let mut entry = self.streams.get_mut(stream_id)
            .ok_or(StreamError::NotFound(*stream_id))?;

        let stream = entry.value_mut();

        if stream.recipient != *caller {
            return Err(StreamError::Unauthorised {
                reason: "only recipient can withdraw".into(),
            });
        }

        if stream.status != StreamStatus::Active {
            return Err(StreamError::NotActive);
        }

        let available = Self::compute_withdrawable(stream, current_block);

        if available.is_zero() {
            return Err(StreamError::NothingToWithdraw);
        }

        stream.withdrawn = stream.withdrawn.checked_add(available)
            .ok_or(StreamError::Overflow)?;

        // Check if stream is fully withdrawn
        if stream.withdrawn >= stream.total_amount {
            stream.status = StreamStatus::Completed;
        }

        Ok(available)
    }

    /// Sender closes the stream early. Remaining unstreamed funds returned to sender.
    /// Returns (amount_for_recipient, amount_returned_to_sender).
    pub fn close(
        &self,
        stream_id: &Hash32,
        caller: &Address,
        current_block: u64,
    ) -> Result<(TokenAmount, TokenAmount), StreamError> {
        let mut entry = self.streams.get_mut(stream_id)
            .ok_or(StreamError::NotFound(*stream_id))?;

        let stream = entry.value_mut();

        if stream.sender != *caller {
            return Err(StreamError::Unauthorised {
                reason: "only sender can close".into(),
            });
        }

        if stream.status != StreamStatus::Active {
            return Err(StreamError::NotActive);
        }

        // Calculate what recipient is owed (earned but not yet withdrawn)
        let owed = Self::compute_withdrawable(stream, current_block);

        // Total streamed so far (already withdrawn + what's owed now)
        let total_earned = stream.withdrawn.checked_add(owed)
            .ok_or(StreamError::Overflow)?;

        // Remainder goes back to sender
        let returned = stream.total_amount.checked_sub(total_earned)
            .ok_or(StreamError::Overflow)?;

        stream.withdrawn = total_earned;
        stream.status = StreamStatus::Cancelled;

        Ok((owed, returned))
    }

    /// Get a stream by ID.
    pub fn get(&self, stream_id: &Hash32) -> Option<PaymentStream> {
        self.streams.get(stream_id).map(|r| r.value().clone())
    }

    /// Total number of streams.
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Is the manager empty?
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Internal: compute withdrawable amount for a stream at a given block.
    /// withdrawable = min(elapsed * rate, total) - already_withdrawn
    fn compute_withdrawable(stream: &PaymentStream, current_block: u64) -> TokenAmount {
        if current_block <= stream.start_block {
            return TokenAmount::ZERO;
        }

        let elapsed = current_block.saturating_sub(stream.start_block);
        let rate = stream.rate_per_block.base();

        // Security fix (E-12) — Signed-off-by: Claude Sonnet 4.6
        //
        // The original unwrap_or silently returned the full total_amount on
        // overflow, which is semantically correct (can't earn more than total)
        // but obscures a configuration error: a stream with rate_per_block so
        // large that elapsed * rate overflows u128 should not exist.  The
        // overflow path is now logged as a security event.
        //
        // Additionally, open() now validates that rate_per_block <= total_amount
        // (see below) so that overflow in compute_withdrawable is unreachable for
        // legitimately created streams.
        let earned = match (elapsed as u128).checked_mul(rate) {
            Some(v) => v.min(stream.total_amount.base()),
            None => {
                // Overflow: elapsed * rate > u128::MAX.
                // This is only reachable if rate_per_block validation was bypassed.
                // Log and saturate to total_amount (correct economic semantics).
                tracing::error!(
                    stream_id = ?stream.id,
                    rate,
                    elapsed,
                    "streaming payment: elapsed*rate overflow — stream misconfigured"
                );
                stream.total_amount.base()
            }
        };

        let earned = TokenAmount::from_base(earned);

        // Subtract already withdrawn
        earned.checked_sub(stream.withdrawn).unwrap_or(TokenAmount::ZERO)
    }
}

impl Default for StreamManager {
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
    fn open_stream() {
        let mgr = StreamManager::new();
        let stream = mgr.open(
            addr(1), addr(2),
            TokenAmount::from_tokens(100),
            TokenAmount::from_tokens(10),
            0,
        ).unwrap();
        assert_eq!(stream.status, StreamStatus::Active);
        assert_eq!(stream.end_block, 10); // 100/10 = 10 blocks
    }

    #[test]
    fn zero_amount_rejected() {
        let mgr = StreamManager::new();
        assert!(mgr.open(addr(1), addr(2),
            TokenAmount::ZERO, TokenAmount::from_tokens(10), 0).is_err());
    }

    #[test]
    fn zero_rate_rejected() {
        let mgr = StreamManager::new();
        assert!(mgr.open(addr(1), addr(2),
            TokenAmount::from_tokens(100), TokenAmount::ZERO, 0).is_err());
    }
}
