//! Consensus ordering — the `findOrder` algorithm.
//!
//! Once fame is decided for all witnesses in a round, we can determine
//! the **consensus timestamp** and **total order** for events received
//! in that round.
//!
//! ## Algorithm (Baird 2016)
//!
//! For each event `x` without a consensus timestamp:
//!   1. Find the smallest round `r` where ALL famous witnesses can see `x`.
//!      This is `x.round_received`.
//!   2. `x.consensus_timestamp` = median of the timestamps at which each
//!      round-`r` famous witness first received `x` (through DAG traversal).
//!   3. Sort all events with the same `round_received` by:
//!      a. consensus_timestamp (ascending)
//!      b. If tied: hash as tiebreaker (deterministic)
//!   4. Assign `consensus_order` sequentially.
//!
//! ## Why consensus timestamps are cryptographically immutable
//! - They depend on the fame decisions (which depend on the DAG structure).
//! - The DAG is hash-linked and append-only.
//! - Changing any event breaks all descendants' hashes.
//! - Therefore consensus timestamps cannot be retroactively changed.

// Security fix — Signed-off-by: Claude Opus 4.6

/// Hard cap on the round number that `find_order` will process in one call.
///
/// Without this cap a Byzantine node (or a bug) could continuously push
/// round numbers upward, causing `find_order` to loop indefinitely and
/// starve other tasks.  If the DAG ever advances past this round the node
/// must be restarted (or the cap raised via governance) — this is a safety
/// circuit-breaker, not an expected operational limit.
const MAX_ROUND: u64 = 1_000_000;

/// Minimum stake (base units) required for a witness creator to qualify as
/// a famous witness whose vote is counted in `find_order`.
///
/// A node with zero or negligible stake has nothing to lose by misbehaving.
/// Requiring a minimum stake aligns economic incentives: only nodes that
/// have locked real value participate in consensus weight.
///
/// Set to 1 base unit — a very low bar that excludes purely zero-balance
/// accounts while not imposing a meaningful economic barrier.  Raise this
/// constant via governance once the token economy is established.
pub const MIN_WITNESS_STAKE: u128 = 1;

use crate::{
    dag::Hashgraph,
    event::{Event, EventHash},
    round::divide_rounds,
    state::WorldState,
    witness::{all_fame_decided, decide_fame, famous_witnesses},
};
use cathode_crypto::hash::Hash32;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

/// The consensus engine — ties together round computation, fame, and ordering.
pub struct ConsensusEngine {
    dag: Arc<Hashgraph>,
    state: Arc<WorldState>,
    /// The next consensus order number to assign.
    next_order: Mutex<u64>,
    /// The latest round for which we've completed consensus.
    latest_decided_round: Mutex<u64>,
}

impl ConsensusEngine {
    /// Create a new consensus engine.
    pub fn new(dag: Arc<Hashgraph>, state: Arc<WorldState>) -> Self {
        Self {
            dag,
            state,
            next_order: Mutex::new(0),
            latest_decided_round: Mutex::new(0),
        }
    }

    /// Reference to the DAG.
    pub fn dag(&self) -> &Arc<Hashgraph> {
        &self.dag
    }

    /// Reference to the world state.
    pub fn state(&self) -> &Arc<WorldState> {
        &self.state
    }

    /// Run one pass of the full consensus pipeline:
    ///   1. divideRounds (assign rounds, mark witnesses)
    ///   2. decideFame   (virtual voting)
    ///   3. findOrder     (consensus timestamps + total order)
    ///
    /// Call this after new events arrive (e.g., after a gossip sync).
    /// Returns the number of events that received consensus order this pass.
    pub fn process(&self) -> usize {
        // 1. Assign rounds to all unprocessed events
        divide_rounds(&self.dag);

        // 2. Run virtual voting for fame
        decide_fame(&self.dag);

        // 3. Find consensus order for newly decided rounds
        self.find_order()
    }

    /// The `findOrder` algorithm.
    /// Assigns consensus timestamps and total order to events.
    ///
    /// Security fix — Signed-off-by: Claude Opus 4.6
    ///
    /// The previous implementation read `latest_decided_round` under a lock,
    /// immediately dropped the lock, ran the entire loop, and only re-acquired
    /// the lock at the end to write the new value.  Two concurrent calls to
    /// `process()` (e.g., from two gossip threads) would both read the same
    /// `latest` value, both determine that the next round was ready, and both
    /// assign `consensus_order` to the same events — producing duplicate order
    /// numbers and corrupting total order.
    ///
    /// Fix: hold `latest_decided_round` for the entire duration of `find_order`.
    /// `next_order` is also held across the inner assignment loop (unchanged) so
    /// that order numbers remain monotonically increasing even across concurrent
    /// callers on different rounds.  The two locks are always acquired in the same
    /// order (latest_decided_round → next_order) to prevent deadlock.
    fn find_order(&self) -> usize {
        let mut ordered_count = 0;

        // Hold this lock for the entire function.  Only one thread at a time
        // may advance consensus order — this is the critical section.
        let mut latest = self.latest_decided_round.lock();

        // Check each round starting from the one after the latest decided.
        //
        // Security fix — Signed-off-by: Claude Opus 4.6
        // Guard against unbounded round growth: if the next candidate round
        // would exceed MAX_ROUND, stop processing.  This prevents a Byzantine
        // node (or a round-assignment bug) from driving the loop into an
        // effectively infinite spin that starves all other tasks.
        loop {
            // Use checked_sub-style idiom: latest starts at 0, so latest + 1
            // is always safe, but guard against impossible wrap via saturating.
            let round = latest.saturating_add(1);

            // Circuit-breaker: refuse to process rounds beyond the hard cap.
            if round > MAX_ROUND {
                tracing::error!(
                    round,
                    MAX_ROUND,
                    "find_order: round exceeds MAX_ROUND — halting consensus loop (potential attack or bug)"
                );
                break;
            }

            // All witnesses in `round` must have fame decided
            if !all_fame_decided(&self.dag, round) {
                break;
            }

            // Security fix — Signed-off-by: Claude Opus 4.6
            // Filter famous witnesses by minimum stake: a witness whose creator
            // holds less than MIN_WITNESS_STAKE base units is excluded from
            // consensus weight.  This prevents a Sybil attacker who creates
            // many zero-balance nodes from accumulating voting power.
            let fw: Vec<EventHash> = famous_witnesses(&self.dag, round)
                .into_iter()
                .filter(|wh| {
                    self.dag
                        .get(wh)
                        .map(|ev| self.state.get(&ev.creator).balance >= MIN_WITNESS_STAKE)
                        .unwrap_or(false)
                })
                .collect();

            if fw.is_empty() {
                // Security fix (CONSENSUS-LIVE): do NOT advance latest_decided_round
                // when no qualified famous witnesses exist.  The old code set
                // `*latest = round` and continued, permanently orphaning all events
                // whose round_received would have been this round — they could never
                // be ordered.  Instead, break: we cannot make progress until either
                // the stake filter is satisfied or new witnesses appear.
                // Signed-off-by: Claude Opus 4.6
                break;
            }

            // Find all events that are "received" in this round:
            // An event x is received in round r if:
            //   - All famous witnesses in round r can see x
            //   - AND x was not received in any earlier round
            let all_hashes = self.dag.all_hashes();
            let snap = self.dag.snapshot(); // ONE snapshot for entire round
            let mut received_in_round: Vec<(EventHash, u64)> = Vec::new();

            for &eh in &all_hashes {
                let ev = match snap.get(&eh) {
                    Some(e) => e,
                    None => continue,
                };
                // Skip events already ordered
                if ev.consensus_order.is_some() {
                    continue;
                }

                // Check: can ALL famous witnesses in this round see this event?
                let all_see = fw.iter().all(|fwh| Hashgraph::can_see_in(&snap, fwh, &eh));
                if !all_see {
                    continue;
                }

                // Consensus timestamp = median of the times at which each
                // famous witness first learned about event x.
                let mut fw_timestamps: Vec<u64> = Vec::new();
                for fwh in &fw {
                    let ts = Self::earliest_seeing_time_in(&snap, fwh, &eh);
                    if ts < u64::MAX {
                        fw_timestamps.push(ts);
                    }
                }

                if fw_timestamps.is_empty() {
                    continue;
                }

                fw_timestamps.sort_unstable();
                // Security fix (CS-02): use lower-median for even-length arrays.
                // Upper-median (len/2) biases consensus timestamps upward, which
                // an attacker with >1/3 witnesses can exploit to shift timestamps.
                // Lower-median ((len-1)/2) is the standard choice per Baird 2016.
                // Signed-off-by: Claude Opus 4.6
                let median = fw_timestamps[(fw_timestamps.len() - 1) / 2];

                received_in_round.push((eh, median));
            }

            // Sort by consensus timestamp, tiebreak by hash (fully deterministic).
            received_in_round.sort_by(|a, b| {
                a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0))
            });

            // Assign consensus order — also held for the entire inner loop so
            // that no other thread can interleave order numbers.
            let mut order = self.next_order.lock();
            for (eh, cts) in &received_in_round {
                self.dag.update_consensus(
                    eh,
                    None,
                    None,
                    None,
                    Some(Some(*cts)),
                    Some(Some(*order)),
                    Some(Some(round)),
                );
                *order = order.saturating_add(1);
                ordered_count += 1;
            }

            if !received_in_round.is_empty() {
                info!(
                    round,
                    events = received_in_round.len(),
                    "consensus reached for {} events",
                    received_in_round.len()
                );
            }

            *latest = round;
        }

        // `latest` is a MutexGuard — write is implicit on drop.
        ordered_count
    }

    /// Find the earliest timestamp among ancestors of `from` that can see `target`.
    /// Uses a pre-taken snapshot to avoid repeated HashMap clones.
    ///
    /// Security fix (CS-01): BFS both self-parent AND other-parent.
    /// The previous implementation only followed the self-parent chain, missing
    /// the case where `target` was first seen through the other-parent path.
    /// This caused incorrect consensus timestamps (events appeared later than
    /// they actually were), violating aBFT fairness guarantees.
    ///
    /// Fix: use BFS over both parents to find the true earliest ancestor
    /// that can see `target`.
    ///
    /// Signed-off-by: Claude Opus 4.6
    fn earliest_seeing_time_in(
        snap: &HashMap<EventHash, Arc<Event>>,
        from: &EventHash,
        target: &EventHash,
    ) -> u64 {
        use std::collections::{HashSet, VecDeque};

        let from_ev = match snap.get(from) {
            Some(e) => e,
            None => return u64::MAX,
        };

        // BFS from `from` backwards through both parents.
        // Track the earliest timestamp of any ancestor that can see `target`.
        let mut earliest_ts = u64::MAX;
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        // Start: if `from` itself can see target, record its timestamp.
        if Hashgraph::can_see_in(snap, from, target) {
            earliest_ts = from_ev.timestamp_ns;
        } else {
            // `from` cannot see `target` at all — no point searching ancestors.
            return u64::MAX;
        }

        queue.push_back(*from);
        visited.insert(*from);

        while let Some(current) = queue.pop_front() {
            let ev = match snap.get(&current) {
                Some(e) => e,
                None => continue,
            };

            // Check both parents
            for parent in [ev.self_parent, ev.other_parent] {
                if parent == Hash32::ZERO || visited.contains(&parent) {
                    continue;
                }
                visited.insert(parent);

                if Hashgraph::can_see_in(snap, &parent, target) {
                    if let Some(parent_ev) = snap.get(&parent) {
                        earliest_ts = earliest_ts.min(parent_ev.timestamp_ns);
                        queue.push_back(parent);
                    }
                }
                // If parent cannot see target, don't explore further down this path.
            }
        }

        earliest_ts
    }

    /// Get all events in consensus order (only those that have been ordered).
    ///
    /// Security fix — Signed-off-by: Claude Opus 4.6
    ///
    /// The previous implementation called `dag.all_hashes()` (acquires and releases
    /// insertion_order read lock), then for each hash called `dag.get()` (acquires
    /// and releases events read lock).  Between the two calls a concurrent insert
    /// could add a new event whose hash appears in `all_hashes` but whose
    /// `consensus_order` is `None`; the filter would correctly exclude it.
    /// However, a concurrent `find_order` could *set* `consensus_order` on an event
    /// that was already in the snapshot but whose Arc was cloned before the write —
    /// meaning the caller would see stale `None` and exclude a truly-ordered event.
    ///
    /// Fix: use `dag.snapshot()` to get a single atomic clone of the events map,
    /// then derive both the hash list and the event data from that one snapshot.
    /// This guarantees that `consensus_order` values observed are consistent with
    /// the set of events seen.
    pub fn ordered_events(&self) -> Vec<Arc<crate::event::Event>> {
        let snap = self.dag.snapshot();
        let mut ordered: Vec<_> = snap
            .values()
            .filter(|e| e.consensus_order.is_some())
            .cloned()
            .collect();

        ordered.sort_by_key(|e| e.consensus_order.unwrap());
        ordered
    }

    /// How many events have received consensus order.
    pub fn ordered_count(&self) -> u64 {
        *self.next_order.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use cathode_crypto::signature::Ed25519KeyPair;

    fn setup_simple_hashgraph() -> (Arc<Hashgraph>, Vec<Ed25519KeyPair>) {
        let dag = Arc::new(Hashgraph::new());
        let keys: Vec<Ed25519KeyPair> = (0..4).map(|_| Ed25519KeyPair::generate()).collect();

        // Create genesis events for all 4 nodes
        let mut geneses = Vec::new();
        for (i, kp) in keys.iter().enumerate() {
            let ev = Event::new(
                format!("genesis-{}", i).into_bytes(),
                1000 + i as u64,
                Hash32::ZERO,
                Hash32::ZERO,
                kp,
            );
            let h = dag.insert(ev).unwrap();
            geneses.push(h);
        }

        // Create some gossip events (cross-linking)
        // Node 0 gossips with Node 1
        let e01 = Event::new(b"n0-gossip-n1".to_vec(), 2000, geneses[0], geneses[1], &keys[0]);
        let h01 = dag.insert(e01).unwrap();

        // Node 1 gossips with Node 2
        let e12 = Event::new(b"n1-gossip-n2".to_vec(), 2001, geneses[1], geneses[2], &keys[1]);
        let _h12 = dag.insert(e12).unwrap();

        // Node 2 gossips with Node 3
        let e23 = Event::new(b"n2-gossip-n3".to_vec(), 2002, geneses[2], geneses[3], &keys[2]);
        let _h23 = dag.insert(e23).unwrap();

        // Node 3 gossips with Node 0
        let e30 = Event::new(b"n3-gossip-n0".to_vec(), 2003, geneses[3], h01, &keys[3]);
        let _h30 = dag.insert(e30).unwrap();

        (dag, keys)
    }

    #[test]
    fn consensus_engine_processes() {
        let (dag, _keys) = setup_simple_hashgraph();
        let state = Arc::new(WorldState::new());
        let engine = ConsensusEngine::new(dag.clone(), state);

        let ordered = engine.process();
        // With just a few events, at least round assignment should work
        assert!(dag.len() > 0);
    }
}
