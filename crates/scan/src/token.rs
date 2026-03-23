//! TokenScan — token & account scanner for the Cathode network.
//!
//! Queries balances, supply, rich list, account details, staking info.

use crate::error::ScanError;
use cathode_executor::state::{AccountState, StateDB};
use cathode_types::address::Address;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Account information for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub address: String,
    pub balance: String,
    pub balance_base: u128,
    pub nonce: u64,
    pub staked: String,
    pub staked_base: u128,
    pub has_code: bool,
}

/// Token supply summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyInfo {
    pub total_supply_tokens: u64,
    pub account_count: usize,
    pub merkle_root: String,
}

/// Staking overview across all accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingOverview {
    pub total_staked_base: u128,
    pub staker_count: usize,
    pub total_supply_tokens: u64,
    pub staking_ratio: f64,
}

/// Token & account scanner.
pub struct TokenScan {
    state: Arc<StateDB>,
}

impl TokenScan {
    pub fn new(state: Arc<StateDB>) -> Self {
        Self { state }
    }

    /// Get account info by hex address.
    pub fn get_account(&self, addr_hex: &str) -> Result<AccountInfo, ScanError> {
        let bytes = hex::decode(addr_hex)
            .map_err(|_| ScanError::InvalidQuery("invalid hex address".into()))?;
        if bytes.len() != 32 {
            return Err(ScanError::InvalidQuery("address must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let addr = Address(arr);
        let acct = self.state.get(&addr);
        Ok(Self::account_to_info(addr, &acct))
    }

    /// Get balance for an address.
    pub fn get_balance(&self, addr_hex: &str) -> Result<String, ScanError> {
        let info = self.get_account(addr_hex)?;
        Ok(info.balance)
    }

    /// Get supply information.
    pub fn supply_info(&self) -> SupplyInfo {
        SupplyInfo {
            total_supply_tokens: self.state.total_supply_tokens(),
            account_count: self.state.account_count(),
            merkle_root: hex::encode(self.state.merkle_root().0),
        }
    }

    /// Compare two accounts.
    pub fn compare_accounts(&self, addr1_hex: &str, addr2_hex: &str) -> Result<(AccountInfo, AccountInfo), ScanError> {
        let a1 = self.get_account(addr1_hex)?;
        let a2 = self.get_account(addr2_hex)?;
        Ok((a1, a2))
    }

    /// Check if an address has a deployed contract.
    pub fn is_contract(&self, addr_hex: &str) -> Result<bool, ScanError> {
        let info = self.get_account(addr_hex)?;
        Ok(info.has_code)
    }

    /// Return top N accounts by balance (descending), inspired by
    /// Solana's `getTokenLargestAccounts` and Etherscan's rich list.
    pub fn rich_list(&self, limit: usize) -> Vec<AccountInfo> {
        let mut accounts = self.state.iter_accounts();
        accounts.sort_unstable_by(|a, b| b.1.balance.base().cmp(&a.1.balance.base()));
        accounts
            .into_iter()
            .take(limit)
            .map(|(addr, acct)| Self::account_to_info(addr, &acct))
            .collect()
    }

    /// Check if an account exists (non-zero balance or nonce > 0).
    pub fn account_exists(&self, addr_hex: &str) -> Result<bool, ScanError> {
        let info = self.get_account(addr_hex)?;
        Ok(info.balance_base > 0 || info.nonce > 0)
    }

    /// Aggregate staking data across all accounts.
    pub fn staking_info(&self) -> StakingOverview {
        let accounts = self.state.iter_accounts();
        let mut total_staked_base: u128 = 0;
        let mut staker_count: usize = 0;
        for (_addr, acct) in &accounts {
            let staked = acct.staked.base();
            if staked > 0 {
                total_staked_base = total_staked_base.saturating_add(staked);
                staker_count += 1;
            }
        }
        let total_supply_tokens = self.state.total_supply_tokens();
        let total_supply_base = (total_supply_tokens as u128)
            .saturating_mul(cathode_types::token::ONE_TOKEN);
        let staking_ratio = if total_supply_base > 0 {
            total_staked_base as f64 / total_supply_base as f64
        } else {
            0.0
        };
        StakingOverview {
            total_staked_base,
            staker_count,
            total_supply_tokens,
            staking_ratio,
        }
    }

    fn account_to_info(addr: Address, acct: &AccountState) -> AccountInfo {
        AccountInfo {
            address: hex::encode(addr.0),
            balance: format!("{}", acct.balance),
            balance_base: acct.balance.base(),
            nonce: acct.nonce,
            staked: format!("{}", acct.staked),
            staked_base: acct.staked.base(),
            has_code: acct.code_hash.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_crypto::hash::Hash32;
    use cathode_types::token::TokenAmount;

    fn setup() -> (Arc<StateDB>, TokenScan) {
        let state = Arc::new(StateDB::new());
        let scan = TokenScan::new(state.clone());
        (state, scan)
    }

    #[test]
    fn empty_supply() {
        let (_state, scan) = setup();
        let info = scan.supply_info();
        assert_eq!(info.total_supply_tokens, 0);
        assert_eq!(info.account_count, 0);
    }

    #[test]
    fn get_account_default() {
        let (_state, scan) = setup();
        let addr_hex = hex::encode([0xAA; 32]);
        let info = scan.get_account(&addr_hex).unwrap();
        assert_eq!(info.balance_base, 0);
        assert_eq!(info.nonce, 0);
        assert!(!info.has_code);
    }

    #[test]
    fn get_account_with_balance() {
        let (state, scan) = setup();
        let addr = Address::from_bytes([0xBB; 32]);
        state.mint(addr, TokenAmount::from_tokens(1000)).unwrap();
        let info = scan.get_account(&hex::encode(addr.0)).unwrap();
        assert!(info.balance_base > 0);
    }

    #[test]
    fn get_balance_formatted() {
        let (state, scan) = setup();
        let addr = Address::from_bytes([0xCC; 32]);
        state.mint(addr, TokenAmount::from_tokens(42)).unwrap();
        let balance = scan.get_balance(&hex::encode(addr.0)).unwrap();
        assert!(balance.contains("42"));
    }

    #[test]
    fn supply_after_mint() {
        let (state, scan) = setup();
        let addr = Address::from_bytes([0xDD; 32]);
        state.mint(addr, TokenAmount::from_tokens(500)).unwrap();
        let info = scan.supply_info();
        assert_eq!(info.total_supply_tokens, 500);
        assert_eq!(info.account_count, 1);
    }

    #[test]
    fn compare_accounts() {
        let (state, scan) = setup();
        let a1 = Address::from_bytes([0x11; 32]);
        let a2 = Address::from_bytes([0x22; 32]);
        state.mint(a1, TokenAmount::from_tokens(100)).unwrap();
        state.mint(a2, TokenAmount::from_tokens(200)).unwrap();
        let (info1, info2) = scan.compare_accounts(
            &hex::encode(a1.0),
            &hex::encode(a2.0),
        ).unwrap();
        assert!(info2.balance_base > info1.balance_base);
    }

    #[test]
    fn is_contract_false() {
        let (_state, scan) = setup();
        let addr_hex = hex::encode([0xEE; 32]);
        assert!(!scan.is_contract(&addr_hex).unwrap());
    }

    #[test]
    fn is_contract_true() {
        let (state, scan) = setup();
        let addr = Address::from_bytes([0xFF; 32]);
        state.set_code(&addr, Hash32([0x99; 32]));
        assert!(scan.is_contract(&hex::encode(addr.0)).unwrap());
    }

    #[test]
    fn invalid_hex_rejected() {
        let (_state, scan) = setup();
        assert!(scan.get_account("not-hex!").is_err());
    }

    #[test]
    fn wrong_length_rejected() {
        let (_state, scan) = setup();
        assert!(scan.get_account("aabb").is_err());
    }

    #[test]
    fn rich_list_empty_state() {
        let (_state, scan) = setup();
        let list = scan.rich_list(10);
        assert!(list.is_empty());
    }

    #[test]
    fn rich_list_ordering() {
        let (state, scan) = setup();
        let a1 = Address::from_bytes([0x01; 32]);
        let a2 = Address::from_bytes([0x02; 32]);
        let a3 = Address::from_bytes([0x03; 32]);
        state.mint(a1, TokenAmount::from_tokens(100)).unwrap();
        state.mint(a2, TokenAmount::from_tokens(500)).unwrap();
        state.mint(a3, TokenAmount::from_tokens(250)).unwrap();
        let list = scan.rich_list(10);
        assert_eq!(list.len(), 3);
        assert!(list[0].balance_base > list[1].balance_base);
        assert!(list[1].balance_base > list[2].balance_base);
        // Top account should be a2 (500 tokens)
        assert_eq!(list[0].address, hex::encode([0x02; 32]));
    }

    #[test]
    fn rich_list_limit() {
        let (state, scan) = setup();
        for i in 0..5u8 {
            state.mint(
                Address::from_bytes([i + 1; 32]),
                TokenAmount::from_tokens((i as u64 + 1) * 100),
            );
        }
        let list = scan.rich_list(3);
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn staking_info_empty() {
        let (_state, scan) = setup();
        let info = scan.staking_info();
        assert_eq!(info.total_staked_base, 0);
        assert_eq!(info.staker_count, 0);
        assert_eq!(info.staking_ratio, 0.0);
    }

    #[test]
    fn staking_info_with_stakers() {
        let (state, scan) = setup();
        let a1 = Address::from_bytes([0x11; 32]);
        let a2 = Address::from_bytes([0x22; 32]);
        state.mint(a1, TokenAmount::from_tokens(1000)).unwrap();
        state.mint(a2, TokenAmount::from_tokens(1000)).unwrap();
        state.add_stake(&a1, TokenAmount::from_tokens(400), 0).unwrap();
        state.add_stake(&a2, TokenAmount::from_tokens(600), 0).unwrap();
        let info = scan.staking_info();
        assert_eq!(info.staker_count, 2);
        assert!(info.total_staked_base > 0);
        assert!(info.staking_ratio > 0.0);
        assert!(info.staking_ratio <= 1.0);
    }

    #[test]
    fn account_exists_true() {
        let (state, scan) = setup();
        let addr = Address::from_bytes([0xAA; 32]);
        state.mint(addr, TokenAmount::from_tokens(1)).unwrap();
        assert!(scan.account_exists(&hex::encode(addr.0)).unwrap());
    }

    #[test]
    fn account_exists_false() {
        let (_state, scan) = setup();
        let addr_hex = hex::encode([0xBB; 32]);
        assert!(!scan.account_exists(&addr_hex).unwrap());
    }

    #[test]
    fn merkle_root_changes_on_mint() {
        let (state, scan) = setup();
        let root1 = scan.supply_info().merkle_root;
        state.mint(Address::from_bytes([0x01; 32]), TokenAmount::from_tokens(1)).unwrap();
        let root2 = scan.supply_info().merkle_root;
        assert_ne!(root1, root2);
    }
}
