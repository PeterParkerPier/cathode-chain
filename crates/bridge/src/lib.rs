//! cathode-bridge — cross-chain bridge for the Cathode blockchain.
//!
//! Provides lock/claim mechanisms, relayer management, Merkle proofs,
//! and safety limits for bridging assets between Cathode and external chains.
//!
//! Signed-off-by: Claude Opus 4.6

#![forbid(unsafe_code)]

pub mod chains;
pub mod lock;
pub mod claim;
pub mod relayer;
pub mod proof;
pub mod limits;

pub use chains::{ChainId, ChainConfig, SupportedChains};
pub use lock::{BridgeLock, LockStatus, LockManager};
pub use claim::{BridgeClaim, ClaimStatus, RelaySignature, ClaimManager};
pub use relayer::{RelayerSet, RelayProof, RelayerManager, BridgeError};
pub use proof::{BridgeMerkleProof, generate_proof, verify_proof, compute_root};
pub use limits::{BridgeLimits, LimitTracker};
