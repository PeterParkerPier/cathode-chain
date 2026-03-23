//! cathode-sync — state snapshots and fast catch-up for new nodes.
//!
//! When a new node joins the network, it needs to:
//!   1. Get the latest state snapshot (accounts, balances, stakes)
//!   2. Get recent events since the snapshot
//!   3. Replay those events to catch up to current state
//!
//! This crate handles:
//!   - Creating periodic state snapshots
//!   - Serializing/deserializing snapshots
//!   - Determining which events a node is missing

#![forbid(unsafe_code)]

pub mod checkpoint;

pub use checkpoint::{StateCheckpoint, CheckpointManager};
