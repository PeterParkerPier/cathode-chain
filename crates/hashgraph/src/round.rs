//! Round assignment — the `divideRounds` algorithm from the Swirlds paper.
//!
//! ## Algorithm (Baird 2016)
//!
//! For each event `x`:
//!   1. `r = max(round(self_parent), round(other_parent))`
//!   2. If `x` can **strongly see** more than floor(2n/3) round-`r` witnesses:
//!      -> `round(x) = r + 1`
//!   3. Otherwise:
//!      -> `round(x) = r`
//!   4. `x` is a **witness** if it's the first event by its creator in round `r`.
//!
//! ## Why "strongly see"?
//! Strong seeing ensures that a supermajority of nodes have "touched"
//! the path between two events.  This is what gives hashgraph its
//! asynchronous BFT property — no single bad actor can manipulate
//! which round an event falls into.

use crate::dag::Hashgraph;
use crate::event::{Event, EventHash};
use cathode_crypto::hash::Hash32;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{trace, warn};

/// Assign a round to event `x` using a pre-taken snapshot.
///
/// Parent rounds are read from the **live DAG** (cheap single read) so that
/// rounds assigned earlier in the same pass are visible.  The snapshot is
/// used only for the expensive `strongly_sees_in` BFS.
pub fn compute_round_with_snap(
    dag: &Hashgraph,
    x: &EventHash,
    snap: &HashMap<EventHash, Arc<Event>>,
) -> u64 {
    let event = match snap.get(x) {
        Some(e) => e,
        None => return 0,
    };

    // Genesis events are always round 0
    if event.is_genesis() {
        return 0;
    }

    // r = max(round(self_parent), round(other_parent))
    // Read from live DAG so that rounds assigned in this pass are visible.
    let sp_round = if event.self_parent != Hash32::ZERO {
        dag.get(&event.self_parent)
            .and_then(|e| e.round)
            .unwrap_or(0)
    } else {
        0
    };
    let op_round = if event.other_parent != Hash32::ZERO {
        dag.get(&event.other_parent)
            .and_then(|e| e.round)
            .unwrap_or(0)
    } else {
        0
    };
    let r = sp_round.max(op_round);

    // Can x strongly see a supermajority of round-r witnesses?
    let witnesses = dag.witnesses_in_round(r);
    let n = dag.node_count();
    // Security fix (BFT-THRESH): (2*n)/3+1 per Baird 2016.
    // Signed-off-by: Claude Opus 4.6
    let threshold = if n > 0 { (2 * n) / 3 + 1 } else { 1 };

    // Reuse the provided snapshot instead of creating a new one
    let strongly_seen_count = witnesses
        .iter()
        .filter(|w| Hashgraph::strongly_sees_in(snap, x, w, n))
        .count();

    if strongly_seen_count >= threshold {
        trace!(event = %x.short(), round = r + 1, "round incremented (strongly saw {} witnesses)", strongly_seen_count);
        r + 1
    } else {
        r
    }
}

/// Assign a round to event `x` (convenience wrapper that takes its own snapshot).
pub fn compute_round(dag: &Hashgraph, x: &EventHash) -> u64 {
    let snap = dag.snapshot();
    compute_round_with_snap(dag, x, &snap)
}

/// Check if event `x` is a witness (first event by its creator in its round).
pub fn is_witness(dag: &Hashgraph, x: &EventHash) -> bool {
    let event = match dag.get(x) {
        Some(e) => e,
        None => return false,
    };

    let round = match event.round {
        Some(r) => r,
        None => return false,
    };

    // Check: is there a self-parent in the same round?
    if event.self_parent != Hash32::ZERO {
        if let Some(sp) = dag.get(&event.self_parent) {
            if sp.round == Some(round) {
                return false; // Self-parent is in the same round -> not a witness
            }
        }
    }

    true
}

/// Run `divideRounds` for all events that don't have a round yet.
///
/// Takes ONE snapshot and reuses it for all round computations.
/// Events are processed in insertion order.
pub fn divide_rounds(dag: &Hashgraph) {
    let all_hashes = dag.all_hashes();
    let mut remaining: Vec<EventHash> = Vec::new();

    // Take ONE snapshot for the entire pass — avoids O(E) clones
    let snap = dag.snapshot();

    // First pass: process in insertion order
    for hash in &all_hashes {
        if let Some(ev) = snap.get(hash) {
            if ev.round.is_some() {
                continue;
            }
        }

        // Check if parents have rounds assigned
        let parents_ready = {
            if let Some(ev) = dag.get(hash) {
                let sp_ready = ev.self_parent == Hash32::ZERO
                    || dag.get(&ev.self_parent).and_then(|e| e.round).is_some();
                let op_ready = ev.other_parent == Hash32::ZERO
                    || dag.get(&ev.other_parent).and_then(|e| e.round).is_some();
                sp_ready && op_ready
            } else {
                false
            }
        };

        if parents_ready {
            let round = compute_round_with_snap(dag, hash, &snap);
            dag.update_consensus(hash, Some(round), None, None, None, None, None);
            let witness = is_witness(dag, hash);
            dag.update_consensus(hash, None, Some(witness), None, None, None, None);
            if witness {
                trace!(event = %hash.short(), round, "marked as witness");
            }
        } else {
            remaining.push(*hash);
        }
    }

    // Second pass: retry events whose parents weren't ready
    let mut max_iterations = 10;
    while !remaining.is_empty() && max_iterations > 0 {
        let mut still_remaining = Vec::new();
        for hash in &remaining {
            let parents_ready = {
                if let Some(ev) = dag.get(hash) {
                    let sp_ready = ev.self_parent == Hash32::ZERO
                        || dag.get(&ev.self_parent).and_then(|e| e.round).is_some();
                    let op_ready = ev.other_parent == Hash32::ZERO
                        || dag.get(&ev.other_parent).and_then(|e| e.round).is_some();
                    sp_ready && op_ready
                } else {
                    false
                }
            };

            if parents_ready {
                let round = compute_round(dag, hash);
                dag.update_consensus(hash, Some(round), None, None, None, None, None);
                let witness = is_witness(dag, hash);
                dag.update_consensus(hash, None, Some(witness), None, None, None, None);
                if witness {
                    trace!(event = %hash.short(), round, "marked as witness (retry)");
                }
            } else {
                still_remaining.push(*hash);
            }
        }
        if still_remaining.len() == remaining.len() {
            warn!("{} events have unresolvable parent rounds", still_remaining.len());
            break;
        }
        remaining = still_remaining;
        max_iterations -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use cathode_crypto::signature::Ed25519KeyPair;

    #[test]
    fn genesis_is_round_zero_witness() {
        let dag = Hashgraph::new();
        let kp = Ed25519KeyPair::generate();
        let ev = Event::new(b"gen".to_vec(), 1000, Hash32::ZERO, Hash32::ZERO, &kp);
        let h = dag.insert(ev).unwrap();

        divide_rounds(&dag);

        let e = dag.get(&h).unwrap();
        assert_eq!(e.round, Some(0));
        assert!(e.is_witness);
    }
}
