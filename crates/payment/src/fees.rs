//! Payment fee schedule — configurable fee calculation.
//!
//! Signed-off-by: Claude Opus 4.6

use cathode_types::token::TokenAmount;
use serde::{Deserialize, Serialize};

/// Fee type for different payment operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeeType {
    Transfer,
    Escrow,
    Bridge,
}

/// Configurable payment fee schedule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentFeeSchedule {
    /// Transfer fee in basis points (1 bp = 0.01%). Default: 10 bp = 0.1%.
    pub transfer_fee_bps: u64,
    /// Flat fee for creating an invoice.
    pub invoice_creation_fee: TokenAmount,
    /// Escrow fee in basis points.
    pub escrow_fee_bps: u64,
    /// Bridge fee in basis points.
    pub bridge_fee_bps: u64,
    /// Minimum fee for any operation.
    pub min_fee: TokenAmount,
    /// Maximum fee cap.
    pub max_fee: TokenAmount,
}

impl Default for PaymentFeeSchedule {
    fn default() -> Self {
        Self {
            transfer_fee_bps: 10, // 0.1%
            invoice_creation_fee: TokenAmount::from_base(1_000_000_000_000_000), // 0.001 CATH
            escrow_fee_bps: 25, // 0.25%
            bridge_fee_bps: 50, // 0.5%
            min_fee: TokenAmount::from_base(100_000_000_000_000), // 0.0001 CATH
            max_fee: TokenAmount::from_tokens(100), // 100 CATH
        }
    }
}

impl PaymentFeeSchedule {
    /// Calculate the fee for a given amount and fee type.
    /// Uses checked arithmetic throughout.
    pub fn calculate_fee(&self, amount: TokenAmount, fee_type: FeeType) -> TokenAmount {
        if amount.is_zero() {
            return self.min_fee;
        }

        let bps = match fee_type {
            FeeType::Transfer => self.transfer_fee_bps,
            FeeType::Escrow => self.escrow_fee_bps,
            FeeType::Bridge => self.bridge_fee_bps,
        };

        // fee = amount * bps / 10_000
        // Use checked arithmetic to prevent overflow
        let fee_base = amount
            .base()
            .checked_mul(bps as u128)
            .map(|v| v / 10_000)
            .unwrap_or(self.max_fee.base());

        let fee = TokenAmount::from_base(fee_base);

        // Clamp between min and max
        self.clamp_fee(fee)
    }

    /// Clamp a fee between min_fee and max_fee.
    fn clamp_fee(&self, fee: TokenAmount) -> TokenAmount {
        if fee.base() < self.min_fee.base() {
            self.min_fee
        } else if fee.base() > self.max_fee.base() {
            self.max_fee
        } else {
            fee
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_transfer_fee() {
        let schedule = PaymentFeeSchedule::default();
        let amount = TokenAmount::from_tokens(1000);
        let fee = schedule.calculate_fee(amount, FeeType::Transfer);
        // 1000 * 10 / 10000 = 1 CATH
        assert_eq!(fee, TokenAmount::from_tokens(1));
    }

    #[test]
    fn min_fee_applied() {
        let schedule = PaymentFeeSchedule::default();
        // Very small amount -> fee would be tiny, min_fee kicks in
        let fee = schedule.calculate_fee(TokenAmount::from_base(1), FeeType::Transfer);
        assert_eq!(fee, schedule.min_fee);
    }

    #[test]
    fn max_fee_applied() {
        let schedule = PaymentFeeSchedule::default();
        // Huge amount -> fee would be enormous, max_fee caps it
        let fee = schedule.calculate_fee(
            TokenAmount::from_tokens(100_000_000), FeeType::Bridge,
        );
        assert_eq!(fee, schedule.max_fee);
    }

    #[test]
    fn zero_amount_returns_min() {
        let schedule = PaymentFeeSchedule::default();
        let fee = schedule.calculate_fee(TokenAmount::ZERO, FeeType::Transfer);
        assert_eq!(fee, schedule.min_fee);
    }
}
