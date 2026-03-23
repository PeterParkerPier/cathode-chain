//! HCS message — a single entry in a topic's append-only log.

use cathode_crypto::{
    hash::{Hash32, Hasher},
    signature::{Ed25519PublicKey, Ed25519Signature, verify_ed25519},
};
use serde::{Deserialize, Serialize};

/// Monotonically increasing sequence number within a topic.
pub type MessageSequenceNumber = u64;

/// An HCS message — immutable once consensus is reached.
///
/// ## Fields
/// - `topic_id`: which topic this message belongs to.
/// - `sequence_number`: position in the topic (1-based, monotonic).
/// - `payload`: arbitrary application data (max 1024 bytes in Hedera, we allow 4096).
/// - `consensus_timestamp_ns`: assigned by the hashgraph consensus algorithm.
///   This is the **cryptographically immutable** timestamp — nobody can change it
///   because it depends on the entire DAG structure.
/// - `running_hash`: SHA3-256(prev_running_hash ++ topic_id ++ seq ++ timestamp ++ payload).
///   This chains all messages in a topic into an immutable Merkle-like chain.
///   Changing ANY past message breaks all subsequent running hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HcsMessage {
    /// Topic this message belongs to.
    pub topic_id: Hash32,
    /// Position within the topic (starts at 1).
    pub sequence_number: MessageSequenceNumber,
    /// Application payload (max 4096 bytes).
    pub payload: Vec<u8>,
    /// Who submitted this message (Ed25519 public key).
    pub sender: Ed25519PublicKey,
    /// Ed25519 signature over (topic_id ++ payload).
    pub signature: Ed25519Signature,
    /// Consensus timestamp assigned by the hashgraph (nanoseconds).
    pub consensus_timestamp_ns: u64,
    /// SHA3-256 running hash chaining all messages in this topic.
    ///
    /// `running_hash[n] = SHA3(running_hash[n-1] ++ topic_id ++ seq ++ timestamp ++ payload)`
    ///
    /// This is the core immutability guarantee:
    /// changing message N invalidates running_hash[N], which invalidates N+1, N+2, …
    pub running_hash: Hash32,
    /// Hash of the hashgraph event that carried this message's transaction.
    pub source_event: Hash32,
}

/// Maximum payload size in bytes.
pub const MAX_PAYLOAD_BYTES: usize = 4096;

impl HcsMessage {
    /// Compute the running hash for this message.
    pub fn compute_running_hash(
        prev_running_hash: &Hash32,
        topic_id: &Hash32,
        sequence_number: MessageSequenceNumber,
        consensus_timestamp_ns: u64,
        payload: &[u8],
    ) -> Hash32 {
        let mut buf = Vec::with_capacity(32 + 32 + 8 + 8 + payload.len());
        buf.extend_from_slice(prev_running_hash.as_bytes());
        buf.extend_from_slice(topic_id.as_bytes());
        buf.extend_from_slice(&sequence_number.to_be_bytes());
        buf.extend_from_slice(&consensus_timestamp_ns.to_be_bytes());
        buf.extend_from_slice(payload);
        Hasher::sha3_256(&buf)
    }

    /// Verify the sender's signature on this message.
    pub fn verify_signature(&self) -> anyhow::Result<()> {
        let mut msg = Vec::with_capacity(32 + self.payload.len());
        msg.extend_from_slice(self.topic_id.as_bytes());
        msg.extend_from_slice(&self.payload);
        verify_ed25519(&self.sender, &msg, &self.signature)
    }

    /// Verify the running hash against the previous message's running hash.
    pub fn verify_running_hash(&self, prev_running_hash: &Hash32) -> bool {
        let expected = Self::compute_running_hash(
            prev_running_hash,
            &self.topic_id,
            self.sequence_number,
            self.consensus_timestamp_ns,
            &self.payload,
        );
        expected == self.running_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_crypto::signature::Ed25519KeyPair;

    #[test]
    fn running_hash_chain() {
        let topic_id = Hasher::blake3(b"test-topic");
        let mut prev = Hash32::ZERO;

        for i in 1..=5u64 {
            let rh = HcsMessage::compute_running_hash(
                &prev,
                &topic_id,
                i,
                1000 + i,
                format!("msg-{}", i).as_bytes(),
            );
            assert_ne!(rh, prev); // Each running hash is unique
            prev = rh;
        }
    }

    #[test]
    fn tampered_payload_breaks_chain() {
        let topic_id = Hasher::blake3(b"topic");

        let rh1 = HcsMessage::compute_running_hash(&Hash32::ZERO, &topic_id, 1, 100, b"hello");
        let rh2 = HcsMessage::compute_running_hash(&rh1, &topic_id, 2, 200, b"world");
        let rh2_tampered =
            HcsMessage::compute_running_hash(&rh1, &topic_id, 2, 200, b"TAMPERED");

        assert_ne!(rh2, rh2_tampered); // Changing payload changes running hash
    }
}
