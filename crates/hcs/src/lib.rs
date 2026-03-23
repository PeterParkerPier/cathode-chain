//! cathode :: HCS (Hashgraph Consensus Service)
//!
//! Append-only topics where every message receives a consensus timestamp
//! that is cryptographically immutable (backed by the hashgraph DAG).
//!
//! ## Key properties
//! - **Append-only**: once a message has a consensus timestamp, it can
//!   NEVER be edited, deleted, or reordered.
//! - **Fair ordering**: messages are ordered by consensus timestamp, not
//!   by arrival time or any single node's clock.
//! - **Verifiable**: any node can independently verify the consensus
//!   timestamp by replaying the hashgraph algorithm.
//! - **No fork**: the hashgraph has mathematical BFT finality — once
//!   consensus is reached, it's permanent.

#![forbid(unsafe_code)]

pub mod topic;
pub mod message;

pub use topic::{Topic, TopicId, TopicRegistry};
pub use message::{HcsMessage, MessageSequenceNumber};
