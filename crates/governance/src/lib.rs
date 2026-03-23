//! cathode-governance — validator registry, proposals, and on-chain voting.
//!
//! Validators register by staking CATH tokens.
//! Proposals can change chain parameters (gas costs, limits, etc.).
//! Voting power is proportional to stake.

#![forbid(unsafe_code)]

pub mod validator;
pub mod proposal;

pub use validator::{ValidatorRegistry, ValidatorInfo};
pub use proposal::{Proposal, ProposalStatus, GovernanceEngine};
