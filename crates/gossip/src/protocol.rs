//! Wire protocol messages for gossip-about-gossip.

use bincode::Options;
use cathode_crypto::hash::Hash32;
use cathode_hashgraph::event::Event;
use serde::{Deserialize, Serialize};

/// Messages exchanged during a gossip sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// "Here are the event hashes I know."
    /// Used to determine what the peer is missing.
    KnownHashes(Vec<Hash32>),

    /// "Here are the events you're missing."
    EventBatch(Vec<Event>),

    /// "I've received your events.  My latest event hash is X."
    /// The syncing node uses X as `other_parent` for its new event.
    SyncAck {
        latest_hash: Hash32,
    },

    /// "Submit this transaction to the hashgraph."
    SubmitTransaction {
        payload: Vec<u8>,
    },

    /// Peer discovery: "I know these peers."
    PeerList(Vec<String>),
}

impl GossipMessage {
    /// Encode to bincode bytes.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("GossipMessage encode")
    }

    /// Decode from bincode bytes.
    ///
    /// Security fix (C-04): Reject oversized wire messages before deserializing.
    /// bincode::deserialize on untrusted data can cause OOM if a Vec length
    /// header claims billions of elements. We enforce a 4MB hard limit on
    /// wire message size, then use bincode::Options with a size limit.
    /// Signed-off-by: Claude Opus 4.6
    const MAX_WIRE_SIZE: u64 = 4 * 1024 * 1024; // 4 MiB

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() as u64 > Self::MAX_WIRE_SIZE {
            anyhow::bail!(
                "gossip message too large: {} bytes (max {})",
                bytes.len(),
                Self::MAX_WIRE_SIZE
            );
        }
        // Security fix (CF-002/HB-003): Removed allow_trailing_bytes() to prevent
        // data smuggling via trailing bytes in gossip messages.
        // Signed-off-by: Claude Opus 4.6
        let opts = bincode::options()
            .with_limit(Self::MAX_WIRE_SIZE)
            .with_fixint_encoding();
        Ok(opts.deserialize(bytes)?)
    }
}
