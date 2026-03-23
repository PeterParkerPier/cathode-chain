//! cathode :: gossip
//!
//! Gossip-about-gossip protocol over libp2p.
//!
//! ## How hashgraph gossip differs from blockchain gossip
//!
//! In a blockchain, you gossip **blocks** and **transactions**.
//! In a hashgraph, you gossip **events** — and each gossip sync
//! itself creates a NEW event (with self_parent and other_parent).
//!
//! The protocol:
//!   1. Node A randomly picks a peer B.
//!   2. A sends B all events that B hasn't seen yet.
//!   3. B sends A all events that A hasn't seen yet.
//!   4. A creates a new event with:
//!      - self_parent  = A's last event
//!      - other_parent = B's last event (received in step 3)
//!   5. This new event "records" the gossip itself — gossip about gossip.
//!
//! This is what builds the DAG that the consensus algorithm operates on.

#![forbid(unsafe_code)]

pub mod protocol;
pub mod sync;
pub mod network;

pub use network::{GossipConfig, GossipNode, NodeCommand};
pub use sync::GossipSync;
