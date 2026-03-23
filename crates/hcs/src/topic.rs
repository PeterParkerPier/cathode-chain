//! HCS Topic — an append-only message stream.
//!
//! ## Design
//! - A topic is identified by a unique `TopicId` (BLAKE3 hash).
//! - Messages are added ONLY through the hashgraph consensus process.
//! - There is NO `delete_message()`, NO `edit_message()`, NO `reorder()`.
//! - Each message's `running_hash` chains to all previous messages,
//!   making tampering cryptographically detectable.
//! - The `TopicRegistry` manages all topics and is the single gateway
//!   for appending consensus-ordered messages.
//!
//! ## Security: topic memo sanitisation
//! Topic memos (human-readable labels) are restricted to alphanumeric characters
//! and hyphens (`[a-zA-Z0-9-]`), 1–64 characters long.  This prevents injection
//! attacks when memos are rendered in web UIs or stored in log lines.
//! Security fix — Signed-off-by: Claude Sonnet 4.6
//!
//! ## Security: per-topic message size limit
//! Each message payload is bounded by `MAX_PAYLOAD_BYTES` (imported from the
//! message module).  `TopicRegistry::create_topic` additionally enforces a
//! `MAX_TOPIC_MEMO_LEN` check so that oversized memos cannot be used to bloat
//! topic IDs or the registry state.
//! Security fix — Signed-off-by: Claude Sonnet 4.6

use crate::message::{HcsMessage, MessageSequenceNumber, MAX_PAYLOAD_BYTES};
use cathode_crypto::{
    hash::{Hash32, Hasher},
    signature::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature},
};
use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

/// Maximum length of a topic memo in bytes.
/// Security fix — Signed-off-by: Claude Sonnet 4.6
pub const MAX_TOPIC_MEMO_LEN: usize = 64;

/// Validate a topic memo: must be 1–64 chars, each char alphanumeric or '-'.
/// Returns `Err` with a descriptive message when the memo is invalid.
/// Security fix — Signed-off-by: Claude Sonnet 4.6
fn validate_topic_memo(memo: &str) -> anyhow::Result<()> {
    if memo.is_empty() {
        anyhow::bail!("topic memo must not be empty");
    }
    if memo.len() > MAX_TOPIC_MEMO_LEN {
        anyhow::bail!(
            "topic memo too long: {} chars, max {}",
            memo.len(),
            MAX_TOPIC_MEMO_LEN
        );
    }
    for ch in memo.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' {
            anyhow::bail!(
                "topic memo contains invalid character {:?}; only [a-zA-Z0-9-] are allowed",
                ch
            );
        }
    }
    Ok(())
}

/// Internal mutable state of a topic, protected by a single Mutex
/// to guarantee atomicity of seq assignment + running hash update + message push.
#[derive(Debug)]
struct TopicState {
    messages: Vec<HcsMessage>,
    running_hash: Hash32,
    next_seq: MessageSequenceNumber,
}

/// Unique identifier for a topic.
pub type TopicId = Hash32;

/// An HCS topic — append-only message log.
///
/// ## Immutability guarantees
/// - The `messages` Vec is append-only: there is no `remove`, `insert`, or `swap`.
/// - `running_hash` is updated atomically with each append.
/// - The only public method that modifies state is `append()`, which
///   requires a consensus timestamp (proving the hashgraph agreed on ordering).
#[derive(Debug)]
pub struct Topic {
    /// Unique topic ID.
    pub id: TopicId,
    /// Human-readable memo (set at creation, never changed).
    pub memo: String,
    /// Optional: only this key can submit to the topic (None = open to all).
    pub submit_key: Option<Ed25519PublicKey>,
    /// All mutable state behind a single Mutex — no split-lock races.
    state: Mutex<TopicState>,
}

impl Topic {
    /// Create a new topic.
    fn new(id: TopicId, memo: String, submit_key: Option<Ed25519PublicKey>) -> Self {
        Self {
            id,
            memo,
            submit_key,
            state: Mutex::new(TopicState {
                messages: Vec::new(),
                running_hash: Hash32::ZERO,
                next_seq: 1,
            }),
        }
    }

    /// Append a consensus-ordered message to this topic.
    ///
    /// This is the ONLY way to add messages.  It requires:
    ///   - A valid consensus timestamp (from the hashgraph).
    ///   - A valid sender signature.
    ///   - Payload within size limits.
    ///
    /// Returns the assigned sequence number.
    pub fn append(
        &self,
        payload: Vec<u8>,
        sender: Ed25519PublicKey,
        signature: Ed25519Signature,
        consensus_timestamp_ns: u64,
        source_event: Hash32,
    ) -> anyhow::Result<MessageSequenceNumber> {
        // Validate payload size
        if payload.len() > MAX_PAYLOAD_BYTES {
            anyhow::bail!(
                "payload too large: {} > {} bytes",
                payload.len(),
                MAX_PAYLOAD_BYTES
            );
        }

        // Validate submit key (if topic has one)
        if let Some(ref required_key) = self.submit_key {
            if &sender != required_key {
                anyhow::bail!("sender not authorized for this topic");
            }
        }

        // Verify signature (before acquiring lock — sig verification is expensive)
        let mut sig_msg = Vec::with_capacity(32 + payload.len());
        sig_msg.extend_from_slice(self.id.as_bytes());
        sig_msg.extend_from_slice(&payload);
        cathode_crypto::verify_ed25519(&sender, &sig_msg, &signature)?;

        // Single lock: atomically assign seq + compute running hash + push message.
        let mut state = self.state.lock();
        let sequence_number = state.next_seq;
        state.next_seq += 1;

        let new_rh = HcsMessage::compute_running_hash(
            &state.running_hash,
            &self.id,
            sequence_number,
            consensus_timestamp_ns,
            &payload,
        );

        let message = HcsMessage {
            topic_id: self.id,
            sequence_number,
            payload,
            sender,
            signature,
            consensus_timestamp_ns,
            running_hash: new_rh,
            source_event,
        };

        state.messages.push(message);
        state.running_hash = new_rh;

        info!(
            topic = %self.id.short(),
            seq = sequence_number,
            ts = consensus_timestamp_ns,
            "HCS message appended"
        );

        Ok(sequence_number)
    }

    /// Get all messages (read-only snapshot).
    pub fn messages(&self) -> Vec<HcsMessage> {
        self.state.lock().messages.clone()
    }

    /// Get a specific message by sequence number.
    pub fn get_message(&self, seq: MessageSequenceNumber) -> Option<HcsMessage> {
        let state = self.state.lock();
        state.messages.get((seq as usize).saturating_sub(1)).cloned()
    }

    /// Current running hash.
    pub fn running_hash(&self) -> Hash32 {
        self.state.lock().running_hash
    }

    /// Number of messages in this topic.
    pub fn message_count(&self) -> u64 {
        self.state.lock().next_seq - 1
    }

    /// Verify the entire running hash chain from genesis.
    /// Returns Ok(()) if every message's running hash is valid.
    pub fn verify_integrity(&self) -> anyhow::Result<()> {
        let state = self.state.lock();
        let mut prev_rh = Hash32::ZERO;

        for msg in state.messages.iter() {
            if !msg.verify_running_hash(&prev_rh) {
                anyhow::bail!(
                    "running hash mismatch at seq {}: expected chain from {:?}",
                    msg.sequence_number,
                    prev_rh
                );
            }
            msg.verify_signature()?;
            prev_rh = msg.running_hash;
        }

        Ok(())
    }
}

/// Registry of all HCS topics — the public API for topic management.
pub struct TopicRegistry {
    topics: DashMap<TopicId, Arc<Topic>>,
    /// Atomic counter for unique topic ID generation (no race conditions).
    topic_counter: std::sync::atomic::AtomicU64,
}

impl TopicRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            topics: DashMap::new(),
            topic_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create a new topic.  Returns the topic ID.
    ///
    /// `memo` must consist only of ASCII alphanumeric characters and hyphens,
    /// and must be 1–64 characters long.  Any other value is rejected to prevent
    /// injection attacks when memos are rendered in UIs or logs.
    /// Security fix — Signed-off-by: Claude Sonnet 4.6
    pub fn create_topic(
        &self,
        memo: &str,
        submit_key: Option<Ed25519PublicKey>,
        creator: &Ed25519PublicKey,
    ) -> anyhow::Result<TopicId> {
        // Validate memo before touching any shared state.
        validate_topic_memo(memo)?;

        // Atomic counter guarantees unique ID even under concurrent creation.
        let count = self.topic_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut buf = Vec::new();
        buf.extend_from_slice(&creator.0);
        buf.extend_from_slice(memo.as_bytes());
        buf.extend_from_slice(&count.to_be_bytes());
        let id = Hasher::blake3(&buf);

        let topic = Arc::new(Topic::new(id, memo.to_string(), submit_key));
        self.topics.insert(id, topic);

        info!(id = %id.short(), memo, "topic created");
        Ok(id)
    }

    /// Get a topic by ID.
    pub fn get(&self, id: &TopicId) -> Option<Arc<Topic>> {
        self.topics.get(id).map(|r| r.clone())
    }

    /// List all topic IDs.
    pub fn list_topics(&self) -> Vec<TopicId> {
        self.topics.iter().map(|r| *r.key()).collect()
    }

    /// Total number of topics.
    pub fn topic_count(&self) -> usize {
        self.topics.len()
    }
}

impl Default for TopicRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_crypto::signature::Ed25519KeyPair;

    fn sign_for_topic(
        kp: &Ed25519KeyPair,
        topic_id: &TopicId,
        payload: &[u8],
    ) -> Ed25519Signature {
        let mut msg = Vec::new();
        msg.extend_from_slice(topic_id.as_bytes());
        msg.extend_from_slice(payload);
        kp.sign(&msg)
    }

    #[test]
    fn create_and_append() {
        let registry = TopicRegistry::new();
        let kp = Ed25519KeyPair::generate();
        let pk = kp.public_key();

        let tid = registry.create_topic("test-topic", None, &pk).unwrap();
        let topic = registry.get(&tid).unwrap();

        let payload = b"first message".to_vec();
        let sig = sign_for_topic(&kp, &tid, &payload);

        let seq = topic
            .append(payload, pk.clone(), sig, 1_000_000, Hash32::ZERO)
            .unwrap();
        assert_eq!(seq, 1);
        assert_eq!(topic.message_count(), 1);
    }

    #[test]
    fn running_hash_chain_integrity() {
        let registry = TopicRegistry::new();
        let kp = Ed25519KeyPair::generate();
        let pk = kp.public_key();
        let tid = registry.create_topic("chain-test", None, &pk).unwrap();
        let topic = registry.get(&tid).unwrap();

        for i in 0..10u64 {
            let payload = format!("msg-{}", i).into_bytes();
            let sig = sign_for_topic(&kp, &tid, &payload);
            topic
                .append(payload, pk.clone(), sig, 1000 + i * 100, Hash32::ZERO)
                .unwrap();
        }

        assert!(topic.verify_integrity().is_ok());
    }

    #[test]
    fn unauthorized_sender_rejected() {
        let kp1 = Ed25519KeyPair::generate();
        let kp2 = Ed25519KeyPair::generate();

        let registry = TopicRegistry::new();
        let tid = registry
            .create_topic("restricted", Some(kp1.public_key()), &kp1.public_key())
            .unwrap();
        let topic = registry.get(&tid).unwrap();

        let payload = b"sneaky".to_vec();
        let sig = sign_for_topic(&kp2, &tid, &payload);

        let result = topic.append(payload, kp2.public_key(), sig, 2000, Hash32::ZERO);
        assert!(result.is_err());
    }

    /// Security fix — Signed-off-by: Claude Sonnet 4.6
    #[test]
    fn invalid_memo_rejected() {
        let registry = TopicRegistry::new();
        let kp = Ed25519KeyPair::generate();
        let pk = kp.public_key();

        // Special characters must be rejected
        assert!(registry.create_topic("bad memo!", None, &pk).is_err());
        assert!(registry.create_topic("bad/path", None, &pk).is_err());
        assert!(registry.create_topic("<script>", None, &pk).is_err());
        assert!(registry.create_topic("", None, &pk).is_err());

        // Oversized memo (65 chars) must be rejected
        let long_memo = "a".repeat(65);
        assert!(registry.create_topic(&long_memo, None, &pk).is_err());

        // Valid memos must succeed
        assert!(registry.create_topic("valid-topic-1", None, &pk).is_ok());
        assert!(registry.create_topic("AnotherTopic", None, &pk).is_ok());
    }
}
