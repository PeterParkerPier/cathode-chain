//! cathode :: hashgraph
//!
//! Hashgraph Consensus Algorithm — Hedera-style aBFT.
//!
//! ## Core differences from blockchain
//!
//! | Blockchain               | Hashgraph                           |
//! |--------------------------|-------------------------------------|
//! | Blocks in a chain        | Events in a DAG                     |
//! | Leader proposes block    | Every node creates events           |
//! | Explicit voting rounds   | Virtual voting (computed, not sent) |
//! | Probabilistic finality   | Mathematical finality (aBFT)        |
//! | Forks possible           | **No forks possible**               |
//! | Mutable governance       | **Immutable — deploy once**         |
//!
//! ## Module layout
//!
//! - [`event`]     — Event struct (immutable, hash-linked)
//! - [`dag`]       — Append-only DAG storage
//! - [`round`]     — Round computation algorithm
//! - [`witness`]   — Witness detection + fame via virtual voting
//! - [`consensus`] — Consensus timestamp + total ordering
//! - [`state`]     — World state (accounts, balances)
//! - [`error`]     — Typed errors

#![forbid(unsafe_code)]

pub mod event;
pub mod dag;
pub mod round;
pub mod witness;
pub mod consensus;
pub mod state;
pub mod error;

pub use event::{Event, EventHash, CreatorId};
pub use dag::Hashgraph;
pub use consensus::ConsensusEngine;
pub use state::WorldState;
