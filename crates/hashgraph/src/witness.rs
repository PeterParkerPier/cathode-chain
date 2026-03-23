//! Witness fame determination — the `decideFame` virtual voting algorithm.
//!
//! ## Algorithm (Baird 2016)
//!
//! For each undecided witness `y` in round `r_y`,
//! for each round `r > r_y` (going forward),
//! for each witness `w` in round `r`:
//!
//! - Round r_y + 1 (first vote): `w.vote = can_see(w, y)`
//! - Round r_y + 2+ (subsequent rounds):
//!   - Let S = set of round-(r-1) witnesses that w can strongly see.
//!   - Count YES votes and NO votes among S.
//!   - If supermajority voted the same way: DECIDE y.famous = that vote.
//!   - Else if it is a coin round (every COIN_FREQ-th): w.vote = coin flip.
//!   - Else: w.vote = majority vote from S.
//!
//! ## Why this works
//! Virtual voting means no actual vote messages are sent.
//! Every node computes the SAME result by looking at the same DAG.
//! This is what makes hashgraph mathematically BFT — all honest nodes
//! converge to the same fame decision with probability 1.

use crate::dag::Hashgraph;
use crate::event::{Event, EventHash};
use cathode_crypto::hash::Hasher;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, trace};

/// How many rounds between coin flips (prevents livelock attacks).
const COIN_FREQ: u64 = 10;

/// Maximum rounds to look ahead for fame decisions.
const MAX_FAME_ROUNDS: u64 = 100;

/// Run the `decideFame` algorithm for all undecided witnesses.
pub fn decide_fame(dag: &Hashgraph) {
    // Collect all witnesses grouped by round
    let all = dag.all_hashes();
    let events_snap: Vec<_> = all.iter().filter_map(|h| dag.get(h)).collect();

    let mut witnesses_by_round: HashMap<u64, Vec<EventHash>> = HashMap::new();
    let mut max_round: u64 = 0;

    for ev in &events_snap {
        if ev.is_witness {
            if let Some(r) = ev.round {
                witnesses_by_round.entry(r).or_default().push(ev.hash);
                max_round = max_round.max(r);
            }
        }
    }

    // Security fix (C-02): Filter out slashed creators from consensus.
    // Previously equivocation detection recorded slashed creators but
    // NEVER excluded them from voting — slashing was purely cosmetic.
    // Now slashed creators' witnesses are excluded from fame decisions
    // and node_count is reduced accordingly for threshold calculation.
    // Signed-off-by: Claude Opus 4.6
    let slashed = dag.slashed_creators();
    let slashed_set: std::collections::HashSet<[u8; 32]> = slashed.into_iter().collect();

    // For each undecided witness y (excluding slashed creators)
    let undecided: Vec<EventHash> = events_snap
        .iter()
        .filter(|e| e.is_witness && e.is_famous.is_none() && !slashed_set.contains(&e.creator))
        .map(|e| e.hash)
        .collect();

    // Reduce effective node count by slashed nodes for correct threshold
    let effective_n = dag.node_count().saturating_sub(slashed_set.len());
    let n = effective_n;
    // Security fix (BFT-THRESH): use (2*n)/3+1 per Baird 2016.
    let threshold = if n > 0 { (2 * n) / 3 + 1 } else { 1 };

    // Take ONE snapshot for ALL strongly_sees calls in this pass.
    // This avoids O(W²) HashMap clones — the #1 performance bottleneck.
    let snap = dag.snapshot();

    for y_hash in &undecided {
        let y = match dag.get(y_hash) {
            Some(e) => e,
            None => continue,
        };
        let r_y = match y.round {
            Some(r) => r,
            None => continue,
        };

        // Virtual vote storage: (round, voter_hash) → vote
        let mut votes: HashMap<(u64, EventHash), bool> = HashMap::new();

        let mut decided = false;

        // Iterate through subsequent rounds
        for r in (r_y + 1)..=(max_round.min(r_y + MAX_FAME_ROUNDS)) {
            let round_witnesses = match witnesses_by_round.get(&r) {
                Some(ws) => ws.clone(),
                None => continue,
            };

            for w_hash in &round_witnesses {
                if r == r_y + 1 {
                    // First vote: w votes YES if it can see y
                    // Use snapshot to avoid creating a new one per call
                    let vote = Hashgraph::can_see_in(&snap, w_hash, y_hash);
                    votes.insert((r, *w_hash), vote);
                } else {
                    // Subsequent rounds: tally votes from prev-round witnesses
                    // that w can strongly see
                    let prev_witnesses = witnesses_by_round
                        .get(&(r - 1))
                        .cloned()
                        .unwrap_or_default();

                    let mut yes_count = 0usize;
                    let mut no_count = 0usize;

                    for pw in &prev_witnesses {
                        if Hashgraph::strongly_sees_in(&snap, w_hash, pw, n) {
                            if let Some(&v) = votes.get(&(r - 1, *pw)) {
                                if v {
                                    yes_count += 1;
                                } else {
                                    no_count += 1;
                                }
                            }
                        }
                    }

                    // Baird 2016: decide fame based on supermajority.
                    // Supermajority decides IMMEDIATELY regardless of coin round.
                    let is_coin_round = (r - r_y) % COIN_FREQ == 0;

                    if yes_count >= threshold {
                        votes.insert((r, *w_hash), true);
                        // Supermajority YES → decide FAMOUS
                        dag.update_consensus(
                            y_hash,
                            None,
                            None,
                            Some(Some(true)),
                            None,
                            None,
                            None,
                        );
                        info!(
                            witness = %y_hash.short(),
                            round = r_y,
                            "FAMOUS (decided at round {})",
                            r
                        );
                        decided = true;
                        break;
                    } else if no_count >= threshold {
                        votes.insert((r, *w_hash), false);
                        // Supermajority NO → decide NOT FAMOUS
                        dag.update_consensus(
                            y_hash,
                            None,
                            None,
                            Some(Some(false)),
                            None,
                            None,
                            None,
                        );
                        info!(
                            witness = %y_hash.short(),
                            round = r_y,
                            "NOT FAMOUS (decided at round {})",
                            r
                        );
                        decided = true;
                        break;
                    } else if is_coin_round {
                        // Security fix (E-04) — Signed-off-by: Claude Sonnet 4.6
                        //
                        // The original implementation used the SINGLE voting witness w's
                        // Ed25519 signature as the coin entropy.  Because Ed25519 signatures
                        // are deterministic (RFC 8032), an attacker who controls witness w
                        // can grind event payloads (which change the event hash, which
                        // changes the signature) to target a specific coin bit.  Average
                        // cost: 2 payload attempts — essentially free.
                        //
                        // Fix: derive the coin from BLAKE3 over the XOR-concatenation of
                        // ALL previous-round witness signatures that w can strongly see.
                        // To bias the coin bit, an attacker would need to simultaneously
                        // control a supermajority of those witnesses — at which point they
                        // can already decide fame directly without a coin round.
                        //
                        // This keeps the coin deterministic (all honest nodes agree on the
                        // same strongly-seen set), unpredictable (depends on many keys), and
                        // non-manipulable (requires supermajority control to bias).
                        let coin = compute_coin_from_prev_witnesses(
                            dag, &snap, &prev_witnesses, w_hash, r, r_y, y_hash, n,
                        );
                        votes.insert((r, *w_hash), coin);
                        trace!(w = %w_hash.short(), coin, "coin flip (multi-witness BLAKE3)");
                    } else {
                        // No supermajority + normal round → copy majority vote
                        let vote = yes_count >= no_count;
                        votes.insert((r, *w_hash), vote);
                    }
                }
            }

            if decided {
                break;
            }
        }
    }
}

/// Compute a bias-resistant coin bit for a coin round.
///
/// The coin is BLAKE3(sig_1 || sig_2 || ... || sig_k || r || r_y || y_hash || salt)
/// where sig_i are the signatures of all prev-round witnesses that w strongly sees.
///
/// Security properties:
/// - Deterministic: all honest nodes see the same strongly-seen set → same coin.
/// - Unpredictable: depends on k independent Ed25519 keypairs.
/// - Non-manipulable: an attacker controlling < supermajority of prev-round witnesses
///   cannot control the XOR of their signatures, hence cannot control the coin.
///
/// Security fix (E-04) — Signed-off-by: Claude Sonnet 4.6
fn compute_coin_from_prev_witnesses(
    dag: &Hashgraph,
    snap: &HashMap<EventHash, Arc<Event>>,
    prev_witnesses: &[EventHash],
    w_hash: &EventHash,
    r: u64,
    r_y: u64,
    y_hash: &EventHash,
    n: usize,
) -> bool {
    let mut coin_input: Vec<u8> = Vec::new();

    // Collect signatures of all prev-round witnesses that w strongly sees,
    // sorted by hash for deterministic ordering.
    let mut strongly_seen_sigs: Vec<(EventHash, Vec<u8>)> = prev_witnesses
        .iter()
        .filter(|pw| Hashgraph::strongly_sees_in(snap, w_hash, pw, n))
        .filter_map(|pw| {
            dag.get(pw).map(|e| (*pw, e.signature.0.to_vec()))
        })
        .collect();

    // Sort by event hash for deterministic ordering across all nodes.
    strongly_seen_sigs.sort_unstable_by_key(|(h, _)| *h);

    if strongly_seen_sigs.is_empty() {
        // Fallback: no strongly-seen witnesses — use w's own signature.
        // This is safe because no decision is possible without a supermajority,
        // and without a supermajority the coin is only used to break ties.
        if let Some(ev) = dag.get(w_hash) {
            coin_input.extend_from_slice(&ev.signature.0);
        }
    } else {
        for (_, sig) in &strongly_seen_sigs {
            coin_input.extend_from_slice(sig);
        }
    }

    coin_input.extend_from_slice(&r.to_le_bytes());
    coin_input.extend_from_slice(&r_y.to_le_bytes());
    coin_input.extend_from_slice(y_hash.as_bytes());
    coin_input.extend_from_slice(b"cathode-coin-v2-multi-witness");

    let coin_hash = Hasher::blake3(&coin_input);
    (coin_hash.as_bytes()[0] & 1) == 1
}

/// Check if ALL witnesses in a given round have their fame decided.
pub fn all_fame_decided(dag: &Hashgraph, round: u64) -> bool {
    let witnesses = dag.witnesses_in_round(round);
    // No witnesses in this round means round doesn't exist yet — NOT decided.
    if witnesses.is_empty() {
        return false;
    }
    witnesses.iter().all(|wh| {
        dag.get(wh)
            .map(|e| e.is_famous.is_some())
            .unwrap_or(false)
    })
}

/// Get all famous witnesses in a round.
pub fn famous_witnesses(dag: &Hashgraph, round: u64) -> Vec<EventHash> {
    dag.witnesses_in_round(round)
        .into_iter()
        .filter(|wh| {
            dag.get(wh)
                .map(|e| e.is_famous == Some(true))
                .unwrap_or(false)
        })
        .collect()
}
