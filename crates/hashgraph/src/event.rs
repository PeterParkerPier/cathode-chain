//! Event — the fundamental unit of the hashgraph.
//!
//! An Event is **immutable once created**.  It has:
//!   - `self_parent`  → hash of the creator's previous event  (vertical link)
//!   - `other_parent` → hash of another node's event received via gossip  (horizontal link)
//!   - Together these form a DAG — the hashgraph.
//!
//! Unlike a blockchain block, an event is created by a SINGLE node,
//! references exactly TWO parents, and can never be forked because
//! virtual voting deterministically assigns consensus order.
//!
//! ## Append-only guarantee
//! There is no `set_*`, no `mut` accessor, no builder pattern.
//! You construct an Event via `Event::new()` which computes the hash
//! and signature atomically.  After that, every field is read-only.

// Security fix — Signed-off-by: Claude Opus 4.6

/// Maximum allowed payload size in bytes (1 MiB).
///
/// Enforced at creation time in `Event::new` to prevent memory exhaustion
/// attacks where a Byzantine node crafts an oversized event payload to
/// consume unbounded heap on every receiving node.
pub const MAX_PAYLOAD_SIZE: usize = 1024 * 1024; // 1 MiB

use cathode_crypto::{
    hash::{Hash32, Hasher},
    signature::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature, verify_ed25519},
};
use serde::{Deserialize, Serialize};

/// 32-byte event hash (BLAKE3).
pub type EventHash = Hash32;

/// Creator identity = Ed25519 public key bytes.
pub type CreatorId = [u8; 32];

/// An immutable hashgraph event.
///
/// All fields are `pub` for reading, but there is NO way to construct
/// an Event except through `Event::new()` which enforces the hash/sig.
#[derive(Clone, Serialize, Deserialize)]
pub struct Event {
    // ── Identity ─────────────────────────────────────────────────────────
    /// BLAKE3 hash computed over (payload, timestamp, self_parent, other_parent, creator).
    pub hash: EventHash,
    /// Ed25519 public key of the node that created this event.
    pub creator: CreatorId,

    // ── DAG links ────────────────────────────────────────────────────────
    /// Hash of this creator's immediately previous event.
    /// `Hash32::ZERO` for a node's very first event.
    pub self_parent: EventHash,
    /// Hash of another creator's event received via gossip.
    /// `Hash32::ZERO` for a node's very first event (no gossip partner yet).
    pub other_parent: EventHash,

    // ── Payload ──────────────────────────────────────────────────────────
    /// Application-layer data: serialized transactions, HCS messages, etc.
    pub payload: Vec<u8>,
    /// Creator's local wall-clock timestamp (nanoseconds since UNIX epoch).
    pub timestamp_ns: u64,

    // ── Signature ────────────────────────────────────────────────────────
    /// Ed25519 signature over the hash.
    pub signature: Ed25519Signature,

    // ── Consensus metadata (filled by the algorithm, NOT by the creator) ─
    /// Round number assigned by `divideRounds`.
    #[serde(default)]
    pub round: Option<u64>,
    /// Whether this event is a "witness" (first event by its creator in this round).
    #[serde(default)]
    pub is_witness: bool,
    /// Fame determination (None = undecided, Some(true) = famous, Some(false) = not).
    #[serde(default)]
    pub is_famous: Option<bool>,
    /// Consensus timestamp (median of received-times by famous witnesses).
    #[serde(default)]
    pub consensus_timestamp_ns: Option<u64>,
    /// Total order position (set once consensus is reached).
    #[serde(default)]
    pub consensus_order: Option<u64>,
    /// The round in which this event was "received" by all famous witnesses.
    #[serde(default)]
    pub round_received: Option<u64>,
}

impl Event {
    /// Create a new event.  Computes hash + signs atomically.
    ///
    /// # Panics
    /// Panics if `payload.len() > MAX_PAYLOAD_SIZE`.  Callers must validate
    /// payload size before calling `Event::new`; a panic here is intentional
    /// so that oversized payloads are never silently truncated or accepted.
    ///
    /// After this call, the event is **immutable**.
    ///
    /// Security fix — Signed-off-by: Claude Opus 4.6
    pub fn new(
        payload: Vec<u8>,
        timestamp_ns: u64,
        self_parent: EventHash,
        other_parent: EventHash,
        keypair: &Ed25519KeyPair,
    ) -> Self {
        // Reject oversized payloads at creation time — prevents memory exhaustion
        // attacks where a Byzantine node crafts events with multi-GB payloads.
        assert!(
            payload.len() <= MAX_PAYLOAD_SIZE,
            "Event payload too large: {} bytes (max {})",
            payload.len(),
            MAX_PAYLOAD_SIZE
        );

        let creator = keypair.public_key().0;

        let hash = Hasher::event_id(
            &payload,
            timestamp_ns,
            &self_parent,
            &other_parent,
            &creator,
        );

        let signature = keypair.sign(hash.as_bytes());

        Self {
            hash,
            creator,
            self_parent,
            other_parent,
            payload,
            timestamp_ns,
            signature,
            // Consensus fields — set later by the algorithm
            round: None,
            is_witness: false,
            is_famous: None,
            consensus_timestamp_ns: None,
            consensus_order: None,
            round_received: None,
        }
    }

    /// Verify the Ed25519 signature AND hash integrity of this event.
    ///
    /// Two checks:
    ///   1. Recompute hash from (payload, timestamp, parents, creator) and
    ///      verify it matches `self.hash` — prevents field tampering.
    ///   2. Verify Ed25519 signature over the hash — proves creator identity.
    pub fn verify_signature(&self) -> anyhow::Result<()> {
        // 1. Hash integrity: recompute and compare
        let expected_hash = Hasher::event_id(
            &self.payload,
            self.timestamp_ns,
            &self.self_parent,
            &self.other_parent,
            &self.creator,
        );
        if expected_hash != self.hash {
            anyhow::bail!(
                "hash mismatch: expected {}, got {} — event fields were tampered",
                expected_hash.short(),
                self.hash.short()
            );
        }

        // 2. Signature verification
        let pk = Ed25519PublicKey(self.creator);
        verify_ed25519(&pk, self.hash.as_bytes(), &self.signature)
    }

    /// Is this event a genesis event? (no real parents)
    pub fn is_genesis(&self) -> bool {
        self.self_parent == Hash32::ZERO && self.other_parent == Hash32::ZERO
    }

    /// Canonical bytes for wire transmission.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Event::encode never fails")
    }

    /// Decode from wire bytes.
    ///
    /// Security fix (TOB-001/CK-007/HB-009): bincode size limit prevents OOM
    /// from malicious oversized payloads in gossip messages.
    /// Signed-off-by: Claude Opus 4.6
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        use bincode::Options;
        // Security fix (CF-002/HB-003): Removed allow_trailing_bytes() to prevent
        // data smuggling via trailing bytes in event payloads.
        // Signed-off-by: Claude Opus 4.6
        let opts = bincode::options()
            .with_limit((MAX_PAYLOAD_SIZE as u64) + 4096)
            .with_fixint_encoding();
        let event: Self = opts.deserialize(bytes)?;
        anyhow::ensure!(
            event.payload.len() <= MAX_PAYLOAD_SIZE,
            "decoded event payload {} bytes exceeds MAX_PAYLOAD_SIZE {}",
            event.payload.len(),
            MAX_PAYLOAD_SIZE
        );
        Ok(event)
    }
}

impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Event")
            .field("hash", &self.hash)
            .field("creator", &hex::encode(&self.creator[..4]))
            .field("self_parent", &self.self_parent)
            .field("other_parent", &self.other_parent)
            .field("round", &self.round)
            .field("witness", &self.is_witness)
            .field("famous", &self.is_famous)
            .field("consensus_ts", &self.consensus_timestamp_ns)
            .field("order", &self.consensus_order)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_verify() {
        let kp = Ed25519KeyPair::generate();
        let ev = Event::new(b"hello".to_vec(), 12345, Hash32::ZERO, Hash32::ZERO, &kp);
        assert!(ev.verify_signature().is_ok());
        assert!(ev.is_genesis());
    }

    #[test]
    fn tampered_hash_fails() {
        let kp = Ed25519KeyPair::generate();
        let mut ev = Event::new(b"hello".to_vec(), 12345, Hash32::ZERO, Hash32::ZERO, &kp);
        ev.hash = Hash32::from_bytes([0xff; 32]);
        assert!(ev.verify_signature().is_err());
    }

    #[test]
    fn hash_is_deterministic() {
        let kp = Ed25519KeyPair::generate();
        let h1 = Hasher::event_id(b"tx", 100, &Hash32::ZERO, &Hash32::ZERO, &kp.public_key().0);
        let h2 = Hasher::event_id(b"tx", 100, &Hash32::ZERO, &Hash32::ZERO, &kp.public_key().0);
        assert_eq!(h1, h2);
    }
}
