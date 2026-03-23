//! Gossip sync logic — the core gossip-about-gossip procedure.
//!
//! When two nodes sync, they:
//!   1. Exchange lists of known event hashes.
//!   2. Send each other the events they're missing.
//!   3. The initiating node creates a new event recording the sync.

use crate::protocol::GossipMessage;
use cathode_crypto::{hash::Hash32, signature::Ed25519KeyPair};
use cathode_hashgraph::{
    dag::Hashgraph,
    event::{CreatorId, Event, EventHash},
};
use cathode_types::transaction::Transaction;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, trace, warn};

// Security fix — Signed-off-by: Claude Sonnet 4.6

/// Security fix — Signed-off-by: Claude Opus 4.6
///
/// Maximum sync requests a single peer may issue per window (rate limit).
const SYNC_RATE_LIMIT: usize = 10;
/// Rate-limit window for sync requests.
const SYNC_RATE_WINDOW: Duration = Duration::from_secs(60);
/// Maximum events returned in one paginated sync response (DoS protection).
const SYNC_PAGE_SIZE: usize = 500;

/// Per-peer sync request rate-limiter state.
struct SyncPeerRate {
    count: usize,
    window_start: Instant,
}

/// Manages the gossip sync process.
pub struct GossipSync {
    dag: Arc<Hashgraph>,
    keypair: Arc<Ed25519KeyPair>,
    /// Per-peer sync rate limiter — security fix: Signed-off-by: Claude Opus 4.6
    sync_rates: parking_lot::Mutex<HashMap<[u8; 32], SyncPeerRate>>,
    /// The chain_id this node belongs to.  Events carrying transactions for a
    /// different chain_id are silently dropped before DAG insertion to prevent
    /// cross-chain replay attacks.
    ///
    /// Security fix (E-01) — Signed-off-by: Claude Sonnet 4.6
    chain_id: u64,
}

impl GossipSync {
    /// Create a new gossip sync manager.
    ///
    /// # Warning
    /// Defaults to CHAIN_ID_MAINNET.  Testnet/devnet nodes MUST use
    /// `new_with_chain_id()` to avoid accidentally joining mainnet gossip.
    /// Security fix (GOSSIP-CHAINID) — Signed-off-by: Claude Opus 4.6
    pub fn new(dag: Arc<Hashgraph>, keypair: Arc<Ed25519KeyPair>) -> Self {
        tracing::warn!("GossipSync::new() defaulting to MAINNET chain_id — use new_with_chain_id() for non-mainnet");
        Self::new_with_chain_id(dag, keypair, cathode_types::transaction::CHAIN_ID_MAINNET)
    }

    /// Create a new gossip sync manager for a specific chain.
    ///
    /// Security fix (E-01) — Signed-off-by: Claude Sonnet 4.6
    pub fn new_with_chain_id(dag: Arc<Hashgraph>, keypair: Arc<Ed25519KeyPair>, chain_id: u64) -> Self {
        Self { dag, keypair, sync_rates: parking_lot::Mutex::new(HashMap::new()), chain_id }
    }

    /// Maximum number of hashes sent in a KnownHashes message.
    /// Sending the entire DAG hash set to a peer is a DoS amplification vector:
    /// an attacker asks for known_hashes and receives a multi-MB response.
    /// Cap at SYNC_PAGE_SIZE to bound the response size.
    ///
    /// Security fix (GS-01) — Signed-off-by: Claude Opus 4.6
    const MAX_KNOWN_HASHES: usize = SYNC_PAGE_SIZE;

    /// Get a bounded list of our most recent event hashes (for sending to a peer).
    ///
    /// Security fix (GS-01): previously returned ALL hashes in the DAG, enabling
    /// DoS amplification. Now returns at most MAX_KNOWN_HASHES (the most recent).
    /// Signed-off-by: Claude Opus 4.6
    pub fn known_hashes_msg(&self) -> GossipMessage {
        let all = self.dag.all_hashes();
        if all.len() <= Self::MAX_KNOWN_HASHES {
            GossipMessage::KnownHashes(all)
        } else {
            // Send the most recent hashes (tail of insertion order).
            GossipMessage::KnownHashes(all[all.len() - Self::MAX_KNOWN_HASHES..].to_vec())
        }
    }

    /// Given a peer's known hashes, compute which events they're missing.
    ///
    /// Security fix — Signed-off-by: Claude Opus 4.6
    ///
    /// Two protections added:
    ///   1. Per-peer rate limiting: `peer_id` may call this at most
    ///      `SYNC_RATE_LIMIT` times per `SYNC_RATE_WINDOW`.  Excess calls
    ///      receive an empty batch instead of being served.
    ///   2. Pagination: responses are capped at `SYNC_PAGE_SIZE` events so
    ///      a peer with a very old DAG cannot force a single huge allocation.
    ///      The caller should request the next page by supplying the hashes
    ///      it already received (standard gossip-about-gossip convergence).
    /// Maximum number of peers tracked in sync_rates before garbage collection.
    /// Security fix (GS-02): prevents unbounded HashMap growth from peer ID spoofing.
    /// Signed-off-by: Claude Opus 4.6
    const MAX_TRACKED_PEERS: usize = 10_000;

    pub fn events_for_peer(&self, peer_id: [u8; 32], peer_known: &[Hash32]) -> GossipMessage {
        // ── Rate limiting ────────────────────────────────────────────────
        {
            let mut rates = self.sync_rates.lock();

            // Security fix (GS-02): evict stale entries when map grows too large.
            // An attacker sending spoofed peer_ids would grow the map unboundedly.
            // Signed-off-by: Claude Opus 4.6
            if rates.len() > Self::MAX_TRACKED_PEERS {
                rates.retain(|_, v| v.window_start.elapsed() < SYNC_RATE_WINDOW);
            }

            let entry = rates.entry(peer_id).or_insert(SyncPeerRate {
                count: 0,
                window_start: Instant::now(),
            });
            if entry.window_start.elapsed() >= SYNC_RATE_WINDOW {
                entry.count = 0;
                entry.window_start = Instant::now();
            }
            entry.count += 1;
            if entry.count > SYNC_RATE_LIMIT {
                warn!(
                    peer_prefix = %format!("{:02x}{:02x}{:02x}{:02x}", peer_id[0], peer_id[1], peer_id[2], peer_id[3]),
                    "sync rate limit exceeded — returning empty batch"
                );
                return GossipMessage::EventBatch(vec![]);
            }
        }

        // ── Paginated response ───────────────────────────────────────────
        let peer_set: HashSet<Hash32> = peer_known.iter().copied().collect();
        let missing: Vec<Event> = self
            .dag
            .all_hashes()
            .iter()
            .filter(|h| !peer_set.contains(h))
            .filter_map(|h| self.dag.get(h).map(|e| (*e).clone()))
            .take(SYNC_PAGE_SIZE) // cap response size
            .collect();

        trace!(count = missing.len(), "events to send to peer (paginated)");
        GossipMessage::EventBatch(missing)
    }

    /// Maximum events accepted in a single batch (DoS protection).
    const MAX_BATCH_SIZE: usize = 10_000;

    /// Maximum raw byte size of a gossip message before deserialization (DoS protection).
    /// Mirrors MAX_GOSSIP_MESSAGE_SIZE in network.rs — checked here for the direct-call path.
    pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024; // 1 MB

    /// Decode and ingest a raw gossip message received from the network.
    ///
    /// Enforces MAX_MESSAGE_BYTES BEFORE deserialization to prevent allocator
    /// exhaustion from a malformed or malicious oversized payload.
    /// Returns the number of events ingested, or 0 on any error.
    pub fn receive_raw(&self, raw: &[u8]) -> usize {
        if raw.len() > Self::MAX_MESSAGE_BYTES {
            tracing::warn!(
                size = raw.len(),
                max  = Self::MAX_MESSAGE_BYTES,
                "gossip message exceeds size limit — rejected before decode"
            );
            return 0;
        }
        match GossipMessage::decode(raw) {
            Ok(GossipMessage::EventBatch(events)) => self.receive_events(&events),
            Ok(_) => 0,
            Err(e) => {
                tracing::warn!("gossip decode error: {}", e);
                0
            }
        }
    }

    /// Ingest events received from a peer.
    /// Returns the number of events successfully inserted.
    ///
    /// Events are topologically sorted by parent dependencies (Kahn's algorithm)
    /// so that parents are always inserted before children, regardless of
    /// attacker-controlled timestamps.
    ///
    /// Security fix (E-01) — Signed-off-by: Claude Sonnet 4.6
    /// Events whose payload decodes to a Transaction with a chain_id that does
    /// NOT match self.chain_id are silently dropped before DAG insertion.  This
    /// prevents a testnet node (or any adversary) from replaying transactions
    /// signed for a different network through the gossip layer.
    ///
    /// Note: events with no transaction payload (heartbeat events, raw bytes
    /// that do not decode as a Transaction) are allowed through — they carry no
    /// state change and are harmless to the DAG.
    pub fn receive_events(&self, events: &[Event]) -> usize {
        if events.is_empty() {
            return 0;
        }
        // DoS protection: reject oversized batches
        if events.len() > Self::MAX_BATCH_SIZE {
            tracing::warn!(
                batch_size = events.len(),
                max = Self::MAX_BATCH_SIZE,
                "batch too large — rejected"
            );
            return 0;
        }

        // Security fix (E-01): filter events that carry transactions belonging
        // to a foreign chain before touching the DAG.
        // Signed-off-by: Claude Sonnet 4.6
        let expected_chain_id = self.chain_id;
        let filtered: Vec<&Event> = events.iter().filter(|ev| {
            // If the payload does not decode as a Transaction, it is a
            // heartbeat / raw gossip payload — allow it.
            match Transaction::decode(&ev.payload) {
                Ok(tx) => {
                    if tx.chain_id != expected_chain_id {
                        warn!(
                            got = tx.chain_id,
                            expected = expected_chain_id,
                            "dropped gossip event: wrong chain_id"
                        );
                        false
                    } else {
                        true
                    }
                }
                Err(_) => true, // not a tx payload — pass through
            }
        }).collect();

        if filtered.len() < events.len() {
            warn!(
                dropped = events.len() - filtered.len(),
                "gossip: dropped events with wrong chain_id"
            );
        }

        // Kahn's algorithm: find insertion order respecting parent deps.
        // An event is "ready" when both its parents are either:
        //   1. Already in the DAG, or
        //   2. Already inserted from this batch, or
        //   3. Hash32::ZERO (genesis)
        let mut inserted: HashSet<Hash32> = HashSet::new();
        let mut count = 0usize;
        let mut progress = true;
        let mut remaining: Vec<usize> = (0..filtered.len()).collect();

        while progress && !remaining.is_empty() {
            progress = false;
            let mut still_remaining = Vec::new();
            for &idx in &remaining {
                let ev = filtered[idx];
                let sp_ok = ev.self_parent == Hash32::ZERO
                    || self.dag.get(&ev.self_parent).is_some()
                    || inserted.contains(&ev.self_parent);
                let op_ok = ev.other_parent == Hash32::ZERO
                    || self.dag.get(&ev.other_parent).is_some()
                    || inserted.contains(&ev.other_parent);

                if sp_ok && op_ok {
                    match self.dag.insert(ev.clone()) {
                        Ok(h) => {
                            trace!(hash = %h.short(), "ingested peer event");
                            inserted.insert(h);
                            count += 1;
                            progress = true;
                        }
                        Err(e) => {
                            trace!("skipped event: {}", e);
                            // Still count as progress (won't retry)
                            progress = true;
                        }
                    }
                } else {
                    still_remaining.push(idx);
                }
            }
            remaining = still_remaining;
        }

        if !remaining.is_empty() {
            tracing::warn!(
                orphans = remaining.len(),
                "events with missing parents — dropped"
            );
        }

        count
    }

    /// Create a new gossip event after a successful sync.
    ///
    /// This records the gossip in the DAG:
    ///   - self_parent  = our latest event
    ///   - other_parent = the peer's latest event
    ///   - payload      = any pending transactions
    pub fn create_gossip_event(
        &self,
        other_parent: EventHash,
        pending_txs: Vec<u8>,
    ) -> anyhow::Result<EventHash> {
        let creator = self.keypair.public_key().0;
        let self_parent = self
            .dag
            .latest_by_creator(&creator)
            .unwrap_or(Hash32::ZERO);

        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            // Security fix (TIMESTAMP-TRUNC): as_nanos() returns u128, casting
            // to u64 truncates after ~584 years from epoch (2554 CE).  Use
            // as_secs()*1e9 + subsec_nanos for safe u64 nanosecond timestamps.
            // Signed-off-by: Claude Opus 4.6
            .as_nanos().min(u64::MAX as u128) as u64;

        let event = Event::new(
            pending_txs,
            timestamp_ns,
            self_parent,
            other_parent,
            &self.keypair,
        );

        let hash = self.dag.insert(event)?;
        info!(hash = %hash.short(), "created gossip event");
        Ok(hash)
    }

    /// Get the current node's latest event hash.
    pub fn my_latest(&self) -> Option<EventHash> {
        let creator = self.keypair.public_key().0;
        self.dag.latest_by_creator(&creator)
    }

    /// Get the current node's creator ID.
    pub fn my_creator(&self) -> CreatorId {
        self.keypair.public_key().0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_node_sync() {
        // Node A
        let dag_a = Arc::new(Hashgraph::new());
        let kp_a = Arc::new(Ed25519KeyPair::generate());
        let sync_a = GossipSync::new(dag_a.clone(), kp_a.clone());

        // Node B
        let dag_b = Arc::new(Hashgraph::new());
        let kp_b = Arc::new(Ed25519KeyPair::generate());
        let sync_b = GossipSync::new(dag_b.clone(), kp_b.clone());

        // Both create genesis events
        let ga = Event::new(b"genesis-A".to_vec(), 1000, Hash32::ZERO, Hash32::ZERO, &kp_a);
        let ha = dag_a.insert(ga.clone()).unwrap();

        let gb = Event::new(b"genesis-B".to_vec(), 1001, Hash32::ZERO, Hash32::ZERO, &kp_b);
        let hb = dag_b.insert(gb.clone()).unwrap();

        // A sends its known hashes to B
        let a_known = match sync_a.known_hashes_msg() {
            GossipMessage::KnownHashes(h) => h,
            _ => panic!("expected KnownHashes"),
        };

        // B computes what A is missing (peer_id = A's creator bytes)
        let peer_id_a: [u8; 32] = kp_a.public_key().0;
        let for_a = match sync_b.events_for_peer(peer_id_a, &a_known) {
            GossipMessage::EventBatch(events) => events,
            _ => panic!("expected EventBatch"),
        };

        // A ingests B's events
        let received = sync_a.receive_events(&for_a);
        assert_eq!(received, 1); // B's genesis

        // A creates a gossip event recording the sync
        let gossip_hash = sync_a.create_gossip_event(hb, b"tx-from-A".to_vec()).unwrap();

        // Verify the gossip event exists with both parents
        let gossip_ev = dag_a.get(&gossip_hash).unwrap();
        assert_eq!(gossip_ev.self_parent, ha);
        assert_eq!(gossip_ev.other_parent, hb);

        assert_eq!(dag_a.len(), 3); // genesis-A, genesis-B (synced), gossip event
    }

    /// Security fix (E-01) — Signed-off-by: Claude Sonnet 4.6
    /// Events carrying transactions for a foreign chain_id must be dropped.
    #[test]
    fn foreign_chain_id_events_dropped() {
        use cathode_types::transaction::{Transaction, TransactionKind, CHAIN_ID_MAINNET, CHAIN_ID_TESTNET};
        use cathode_crypto::signature::Ed25519KeyPair;
        use cathode_types::address::Address;
        use cathode_types::token::TokenAmount;

        let dag = Arc::new(Hashgraph::new());
        let kp = Arc::new(Ed25519KeyPair::generate());
        // This node is on MAINNET
        let sync = GossipSync::new_with_chain_id(dag.clone(), kp.clone(), CHAIN_ID_MAINNET);

        let sender_kp = Ed25519KeyPair::generate();
        let bob = Address::from_bytes([0xBB; 32]);

        // Craft a transaction for TESTNET
        let testnet_tx = Transaction::new(
            0,
            TransactionKind::Transfer { to: bob, amount: TokenAmount::from_tokens(100) },
            21000,
            1,
            CHAIN_ID_TESTNET, // wrong chain!
            &sender_kp,
        );
        let tx_bytes = testnet_tx.encode();

        // Wrap in a gossip event
        let foreign_event = Event::new(tx_bytes, 1000, Hash32::ZERO, Hash32::ZERO, &kp);

        let received = sync.receive_events(&[foreign_event]);
        // Event should be dropped because chain_id = TESTNET != MAINNET
        // (Event does get inserted into DAG because it has no parent deps — only the tx is wrong.
        //  The filter drops the event at the receive_events level before dag.insert.)
        assert_eq!(received, 0, "foreign-chain-id event must be dropped at gossip layer");
    }
}
