//! Native token constants and amount type.
//
// Security fix — Signed-off-by: Claude Sonnet 4.6

use serde::{Deserialize, Serialize};
use std::fmt;

/// Token name.
pub const TOKEN_NAME: &str = "Cathode";
/// Token ticker symbol.
pub const TOKEN_SYMBOL: &str = "CATH";
/// Decimal places (like ETH's 18 decimals).
pub const DECIMALS: u8 = 18;
/// Maximum supply: 1 billion CATH = 1_000_000_000 * 10^18 base units.
pub const MAX_SUPPLY: u128 = 1_000_000_000 * 10u128.pow(18);
/// One full token in base units.
pub const ONE_TOKEN: u128 = 10u128.pow(18);

/// Token amount in smallest units (1 CATH = 10^18 base units).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct TokenAmount(pub u128);

impl TokenAmount {
    pub const ZERO: Self = Self(0);

    /// Create from whole tokens (e.g., 100 CATH).
    ///
    /// Panics in debug builds and returns `TokenAmount::ZERO` in release builds
    /// if `whole * ONE_TOKEN` would overflow u128.  For a non-panicking variant
    /// use `try_from_tokens`.
    pub fn from_tokens(whole: u64) -> Self {
        // SECURITY FIX: use checked_mul — `whole as u128 * ONE_TOKEN` can overflow
        // for whole > u128::MAX / ONE_TOKEN (i.e., > ~18.4 billion whole tokens).
        Self(
            (whole as u128)
                .checked_mul(ONE_TOKEN)
                .expect("TokenAmount::from_tokens overflow — whole value too large"),
        )
    }

    /// Fallible variant of `from_tokens` — returns `None` on overflow.
    pub fn try_from_tokens(whole: u64) -> Option<Self> {
        (whole as u128).checked_mul(ONE_TOKEN).map(Self)
    }

    /// Create from base units.
    pub fn from_base(base: u128) -> Self {
        Self(base)
    }

    /// Get base units.
    pub fn base(&self) -> u128 {
        self.0
    }

    /// Checked addition.
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    /// Checked subtraction.
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }

    /// Saturating addition.
    pub fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Is zero?
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Format as human-readable "123.456 CATH".
    pub fn display_tokens(&self) -> String {
        let whole = self.0 / ONE_TOKEN;
        let frac = self.0 % ONE_TOKEN;
        if frac == 0 {
            format!("{} {}", whole, TOKEN_SYMBOL)
        } else {
            // Show up to 6 significant decimal places
            let frac_str = format!("{:018}", frac);
            let trimmed = frac_str.trim_end_matches('0');
            let trimmed = if trimmed.len() > 6 { &trimmed[..6] } else { trimmed };
            format!("{}.{} {}", whole, trimmed, TOKEN_SYMBOL)
        }
    }
}

impl fmt::Display for TokenAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_tokens())
    }
}

impl fmt::Debug for TokenAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenAmount({})", self.display_tokens())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_tokens_roundtrip() {
        let amt = TokenAmount::from_tokens(100);
        assert_eq!(amt.base(), 100 * ONE_TOKEN);
    }

    #[test]
    fn display_whole() {
        let amt = TokenAmount::from_tokens(42);
        assert_eq!(amt.display_tokens(), "42 CATH");
    }

    #[test]
    fn display_fractional() {
        let amt = TokenAmount::from_base(ONE_TOKEN + ONE_TOKEN / 2);
        assert_eq!(amt.display_tokens(), "1.5 CATH");
    }

    #[test]
    fn checked_overflow() {
        let max = TokenAmount::from_base(u128::MAX);
        assert!(max.checked_add(TokenAmount::from_base(1)).is_none());
    }

    #[test]
    fn checked_underflow() {
        let zero = TokenAmount::ZERO;
        assert!(zero.checked_sub(TokenAmount::from_base(1)).is_none());
    }

    #[test]
    fn max_supply_fits_u128() {
        assert!(MAX_SUPPLY < u128::MAX);
    }
}
