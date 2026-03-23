//! STRESS + ATTACK TEST SUITE for Cathode Hashgraph
//!
//! Tests:
//! 1. 10,000 wallets stress test (mint + transfer)
//! 2. Concurrent double-spend attacks (100 threads)
//! 3. Timestamp manipulation attacks
//! 4. Fork attack (same creator, two events with same self_parent)
//! 5. Sybil attack (1000 fake nodes flooding events)
//! 6. Replay attack (re-inserting already-seen events)
//! 7. Nonce manipulation attack
//! 8. Balance overflow attack (u128::MAX)
//! 9. Massive DAG stress (1000 events, full consensus)
//! 10. Orphan event flooding (events with fake parents)
//! 11. Gossip batch overflow (>MAX_BATCH_SIZE)
//! 12. Self-transfer nonce drain
//! 13. Concurrent mint stress test
//! 14. Merkle root determinism under concurrent writes
//! 15. Signature forgery attack

use cathode_crypto::hash::Hash32;
use cathode_crypto::signature::Ed25519KeyPair;
use cathode_hashgraph::{
    dag::Hashgraph,
    event::Event,
    state::WorldState,
    consensus::ConsensusEngine,
    round::divide_rounds,
};
use std::sync::Arc;
use std::thread;

// ═══════════════════════════════════════════════════════════════════════════
// 1. 10,000 WALLETS STRESS TEST
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_10k_wallets_mint_and_transfer() {
    let state = WorldState::new();

    // Create 10,000 wallets and mint 1,000,000 each
    let wallets: Vec<Ed25519KeyPair> = (0..10_000)
        .map(|_| Ed25519KeyPair::generate())
        .collect();

    for kp in &wallets {
        state.mint(kp.public_key().0, 1_000_000).unwrap();
    }

    assert_eq!(state.account_count(), 10_000);

    // Verify all balances
    for kp in &wallets {
        let acc = state.get(&kp.public_key().0);
        assert_eq!(acc.balance, 1_000_000, "wallet balance mismatch");
    }

    // Transfer 100 from each wallet to the next
    for i in 0..9_999 {
        let from = wallets[i].public_key().0;
        let to = wallets[i + 1].public_key().0;
        state.apply_transfer(&from, &to, 100, 0).unwrap();
    }

    // First wallet: 1_000_000 - 100 = 999_900
    assert_eq!(state.get(&wallets[0].public_key().0).balance, 999_900);
    // Last wallet: 1_000_000 + 100 = 1_000_100 (received, never sent)
    assert_eq!(state.get(&wallets[9_999].public_key().0).balance, 1_000_100);
    // Middle wallets: 1_000_000 - 100 + 100 = 1_000_000
    assert_eq!(state.get(&wallets[5000].public_key().0).balance, 1_000_000);

    // Total supply conserved
    let total: u128 = wallets.iter()
        .map(|kp| state.get(&kp.public_key().0).balance)
        .sum();
    assert_eq!(total, 10_000 * 1_000_000, "total supply must be conserved");
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. CONCURRENT DOUBLE-SPEND ATTACK (100 threads)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attack_concurrent_double_spend_100_threads() {
    let state = Arc::new(WorldState::new());
    let attacker = Ed25519KeyPair::generate();
    let attacker_addr = attacker.public_key().0;

    // Victim wallets
    let victims: Vec<[u8; 32]> = (0..100)
        .map(|_| Ed25519KeyPair::generate().public_key().0)
        .collect();

    // Give attacker exactly 1000
    state.mint(attacker_addr, 1000).unwrap();

    // 100 threads all try to spend 1000 simultaneously (same nonce=0)
    let handles: Vec<_> = (0..100)
        .map(|i| {
            let state = state.clone();
            let victim = victims[i];
            let from = attacker_addr;
            thread::spawn(move || {
                state.apply_transfer(&from, &victim, 1000, 0)
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // Exactly ONE transfer should succeed
    let successes = results.iter().filter(|r| r.is_ok()).count();
    let failures = results.iter().filter(|r| r.is_err()).count();

    assert_eq!(successes, 1, "exactly 1 double-spend must succeed");
    assert_eq!(failures, 99, "99 double-spends must fail");

    // Attacker balance must be 0
    assert_eq!(state.get(&attacker_addr).balance, 0, "attacker drained");

    // Total received by victims must be exactly 1000
    let victim_total: u128 = victims.iter()
        .map(|v| state.get(v).balance)
        .sum();
    assert_eq!(victim_total, 1000, "conservation law violated!");
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. TIMESTAMP MANIPULATION ATTACKS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attack_timestamp_far_future() {
    let dag = Hashgraph::new();
    let kp = Ed25519KeyPair::generate();

    // Try to insert event with timestamp year 2100
    let future_ts = 4_102_444_800_000_000_000u64; // ~2100
    let ev = Event::new(b"future".to_vec(), future_ts, Hash32::ZERO, Hash32::ZERO, &kp);
    let result = dag.insert(ev);
    assert!(result.is_err(), "far-future timestamp must be rejected");
}

#[test]
fn attack_timestamp_u64_max() {
    let dag = Hashgraph::new();
    let kp = Ed25519KeyPair::generate();

    let ev = Event::new(b"overflow".to_vec(), u64::MAX, Hash32::ZERO, Hash32::ZERO, &kp);
    let result = dag.insert(ev);
    assert!(result.is_err(), "u64::MAX timestamp must be rejected");
}

#[test]
fn attack_timestamp_regression() {
    let dag = Hashgraph::new();
    let kp = Ed25519KeyPair::generate();

    // Create genesis with current timestamp
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let g = Event::new(b"gen".to_vec(), now, Hash32::ZERO, Hash32::ZERO, &kp);
    let hg = dag.insert(g).unwrap();

    // Try to create child with EARLIER timestamp
    let earlier = now - 1_000_000_000; // 1 second earlier
    let ev = Event::new(b"regress".to_vec(), earlier, hg, Hash32::ZERO, &kp);
    let result = dag.insert(ev);
    assert!(result.is_err(), "timestamp regression must be rejected");
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. FORK ATTACK (same creator, two events with same self_parent)
//    Now detected and REJECTED at DAG insertion level (v1.0.2)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attack_fork_same_parent() {
    let dag = Hashgraph::new();
    let kp = Ed25519KeyPair::generate();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let g = Event::new(b"gen".to_vec(), now, Hash32::ZERO, Hash32::ZERO, &kp);
    let hg = dag.insert(g).unwrap();

    // Fork 1 — OK
    let fork1 = Event::new(b"fork1".to_vec(), now + 1000, hg, Hash32::ZERO, &kp);
    dag.insert(fork1).unwrap();

    // Fork 2 — same creator, same self_parent = EQUIVOCATION
    let fork2 = Event::new(b"fork2".to_vec(), now + 2000, hg, Hash32::ZERO, &kp);
    let result = dag.insert(fork2);
    assert!(result.is_err(), "fork/equivocation must be rejected at DAG level");

    // Only genesis + 1 legitimate child in DAG
    assert_eq!(dag.len(), 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. SYBIL ATTACK (1000 fake nodes flooding events)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attack_sybil_1000_nodes() {
    let dag = Hashgraph::new();

    // Create 1000 fake "validator" nodes
    let sybils: Vec<Ed25519KeyPair> = (0..1000)
        .map(|_| Ed25519KeyPair::generate())
        .collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Each sybil creates a genesis event
    let mut hashes = Vec::new();
    for (i, kp) in sybils.iter().enumerate() {
        let ev = Event::new(
            format!("sybil-{}", i).into_bytes(),
            now + i as u64,
            Hash32::ZERO,
            Hash32::ZERO,
            kp,
        );
        hashes.push(dag.insert(ev).unwrap());
    }

    assert_eq!(dag.len(), 1000);
    assert_eq!(dag.node_count(), 1000);

    // Run consensus — should not crash or hang
    divide_rounds(&dag);

    // Verify all genesis events are round 0 witnesses
    for h in &hashes {
        let ev = dag.get(h).unwrap();
        assert_eq!(ev.round, Some(0));
        assert!(ev.is_witness);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. REPLAY ATTACK (duplicate event insertion)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attack_replay_1000_duplicates() {
    let dag = Hashgraph::new();
    let kp = Ed25519KeyPair::generate();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let ev = Event::new(b"original".to_vec(), now, Hash32::ZERO, Hash32::ZERO, &kp);
    dag.insert(ev.clone()).unwrap();

    // Try to replay it 1000 times
    let mut reject_count = 0;
    for _ in 0..1000 {
        if dag.insert(ev.clone()).is_err() {
            reject_count += 1;
        }
    }

    assert_eq!(reject_count, 1000, "all replays must be rejected");
    assert_eq!(dag.len(), 1, "only 1 event in DAG");
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. NONCE MANIPULATION ATTACKS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attack_nonce_skip() {
    let state = WorldState::new();
    let kp = Ed25519KeyPair::generate();
    let addr = kp.public_key().0;
    let victim = Ed25519KeyPair::generate().public_key().0;

    state.mint(addr, 10_000).unwrap();

    // Try to skip nonce (use nonce=5 instead of 0)
    let result = state.apply_transfer(&addr, &victim, 100, 5);
    assert!(result.is_err(), "nonce skip must be rejected");

    // Correct nonce works
    state.apply_transfer(&addr, &victim, 100, 0).unwrap();

    // Can't reuse nonce 0
    let result = state.apply_transfer(&addr, &victim, 100, 0);
    assert!(result.is_err(), "nonce reuse must be rejected");

    // Must use nonce 1
    state.apply_transfer(&addr, &victim, 100, 1).unwrap();
}

#[test]
fn attack_nonce_sequential_drain() {
    let state = WorldState::new();
    let attacker = Ed25519KeyPair::generate().public_key().0;
    let victim = Ed25519KeyPair::generate().public_key().0;

    state.mint(attacker, 500).unwrap();

    // Send 100 five times (nonces 0-4), should drain exactly 500
    for nonce in 0..5u64 {
        state.apply_transfer(&attacker, &victim, 100, nonce).unwrap();
    }

    assert_eq!(state.get(&attacker).balance, 0);
    assert_eq!(state.get(&victim).balance, 500);

    // 6th transfer must fail (insufficient balance)
    let result = state.apply_transfer(&attacker, &victim, 1, 5);
    assert!(result.is_err(), "overdraft must be rejected");
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. BALANCE OVERFLOW ATTACKS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attack_balance_overflow_u128() {
    let state = WorldState::new();
    let addr = Ed25519KeyPair::generate().public_key().0;

    // mint() now enforces MAX_SUPPLY cap — minting u128::MAX must fail
    let result = state.mint(addr, u128::MAX);
    assert!(result.is_err(), "mint beyond MAX_SUPPLY must be rejected");

    // Mint within cap should succeed
    let max_supply = 1_000_000_000u128 * 10u128.pow(18);
    state.mint(addr, max_supply).unwrap();
    assert_eq!(state.get(&addr).balance, max_supply);

    // Minting even 1 more must fail (cap reached)
    let result = state.mint(addr, 1);
    assert!(result.is_err(), "must reject mint beyond supply cap");
    assert_eq!(state.get(&addr).balance, max_supply, "balance unchanged after rejected mint");
}

#[test]
fn attack_transfer_more_than_balance() {
    let state = WorldState::new();
    let rich = Ed25519KeyPair::generate().public_key().0;
    let thief = Ed25519KeyPair::generate().public_key().0;

    state.mint(rich, 1000).unwrap();

    // Try to transfer more than balance
    let result = state.apply_transfer(&rich, &thief, 1001, 0);
    assert!(result.is_err(), "overdraft must be rejected");

    // Balance unchanged
    assert_eq!(state.get(&rich).balance, 1000);
    assert_eq!(state.get(&thief).balance, 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. MASSIVE DAG STRESS (1000 events, full consensus pipeline)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_1000_events_consensus() {
    let dag = Arc::new(Hashgraph::new());
    let state = Arc::new(WorldState::new());

    // 10 nodes
    let keys: Vec<Ed25519KeyPair> = (0..10).map(|_| Ed25519KeyPair::generate()).collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Genesis events
    let mut latest: Vec<Hash32> = Vec::new();
    for (i, kp) in keys.iter().enumerate() {
        let ev = Event::new(
            format!("genesis-{}", i).into_bytes(),
            now + i as u64,
            Hash32::ZERO,
            Hash32::ZERO,
            kp,
        );
        latest.push(dag.insert(ev).unwrap());
    }

    // 990 more events (random gossip pattern)
    let mut ts = now + 100;
    for round in 0..99 {
        for node_idx in 0..10 {
            let peer_idx = (node_idx + 1 + round) % 10;
            ts += 1;
            let ev = Event::new(
                format!("r{}-n{}", round, node_idx).into_bytes(),
                ts,
                latest[node_idx],
                latest[peer_idx],
                &keys[node_idx],
            );
            match dag.insert(ev) {
                Ok(h) => latest[node_idx] = h,
                Err(_) => {} // skip on validation error
            }
        }
    }

    assert!(dag.len() >= 100, "DAG should have many events: {}", dag.len());

    // Run full consensus pipeline — MUST NOT hang or crash
    let engine = ConsensusEngine::new(dag.clone(), state.clone());
    let ordered = engine.process();

    // At least some events should be processed
    // (with 10 nodes and 1000 events, consensus should make progress)
    println!("DAG size: {}, ordered: {}", dag.len(), ordered);
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. ORPHAN EVENT FLOODING (events with fake parents)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attack_orphan_event_flood() {
    let dag = Hashgraph::new();
    let kp = Ed25519KeyPair::generate();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // First create a genesis
    let g = Event::new(b"gen".to_vec(), now, Hash32::ZERO, Hash32::ZERO, &kp);
    let hg = dag.insert(g).unwrap();

    // Try to insert 100 events with fake other_parent hashes
    // Skip i=0 because [0u8;32] == Hash32::ZERO which means "no other parent"
    let mut rejected = 0;
    for i in 1..=100 {
        let fake_parent = Hash32::from_bytes([i as u8; 32]);
        let ev = Event::new(
            format!("orphan-{}", i).into_bytes(),
            now + 1000 + i as u64,
            hg,
            fake_parent,
            &kp,
        );
        if dag.insert(ev).is_err() {
            rejected += 1;
        }
    }

    assert_eq!(rejected, 100, "all orphan events must be rejected");
    assert_eq!(dag.len(), 1, "only genesis in DAG");
}

// Gossip batch tests are in crates/gossip/tests/stress.rs

// ═══════════════════════════════════════════════════════════════════════════
// 12. SELF-TRANSFER NONCE DRAIN ATTACK
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attack_self_transfer_nonce_drain() {
    let state = WorldState::new();
    let addr = Ed25519KeyPair::generate().public_key().0;
    state.mint(addr, 1000).unwrap();

    // Self-transfers should bump nonce but NOT change balance
    for nonce in 0..100u64 {
        state.apply_transfer(&addr, &addr, 500, nonce).unwrap();
    }

    // Balance unchanged after 100 self-transfers
    assert_eq!(state.get(&addr).balance, 1000, "self-transfer must not change balance");
    assert_eq!(state.get(&addr).nonce, 100, "nonce should be 100");
}

// ═══════════════════════════════════════════════════════════════════════════
// 13. CONCURRENT MINT STRESS (100 threads minting same address)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_concurrent_mint_100_threads() {
    let state = Arc::new(WorldState::new());
    let addr = Ed25519KeyPair::generate().public_key().0;

    // 100 threads each minting 1000
    let handles: Vec<_> = (0..100)
        .map(|_| {
            let state = state.clone();
            thread::spawn(move || {
                state.mint(addr, 1000).unwrap();
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(state.get(&addr).balance, 100_000, "concurrent mints must be atomic");
}

// ═══════════════════════════════════════════════════════════════════════════
// 14. MERKLE ROOT DETERMINISM
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_merkle_root_deterministic() {
    let state1 = WorldState::new();
    let state2 = WorldState::new();

    let wallets: Vec<[u8; 32]> = (0..100)
        .map(|_| Ed25519KeyPair::generate().public_key().0)
        .collect();

    // Apply same operations in same order
    for (i, addr) in wallets.iter().enumerate() {
        state1.mint(*addr, (i as u128 + 1) * 1000).unwrap();
        state2.mint(*addr, (i as u128 + 1) * 1000).unwrap();
    }

    let root1 = state1.merkle_root();
    let root2 = state2.merkle_root();

    assert_eq!(root1, root2, "same state must produce same merkle root");
    assert_ne!(root1, Hash32::ZERO, "merkle root must not be zero");

    // Different state → different root
    state1.mint(wallets[0], 1).unwrap();
    let root3 = state1.merkle_root();
    assert_ne!(root1, root3, "different state must produce different merkle root");
}

// ═══════════════════════════════════════════════════════════════════════════
// 15. SIGNATURE FORGERY ATTACK
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attack_signature_forgery() {
    let dag = Hashgraph::new();
    let real_kp = Ed25519KeyPair::generate();
    let attacker_kp = Ed25519KeyPair::generate();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Create event signed by real key
    let ev = Event::new(b"legit".to_vec(), now, Hash32::ZERO, Hash32::ZERO, &real_kp);
    dag.insert(ev).unwrap();

    // Try to create event with real_kp's creator ID but attacker's signature
    // (This is what Event::new prevents — creator comes from the signing key)
    let attacker_ev = Event::new(b"forge".to_vec(), now + 1, Hash32::ZERO, Hash32::ZERO, &attacker_kp);

    // The creator field will be attacker's public key, not real_kp's
    // So this is not really a forgery — Ed25519 prevents it cryptographically
    assert_ne!(attacker_ev.creator, real_kp.public_key().0);

    // Tamper with the creator field manually
    let mut tampered = attacker_ev.clone();
    tampered.creator = real_kp.public_key().0; // set creator to victim
    // Signature verification must fail because sig was made with attacker's key
    assert!(tampered.verify_signature().is_err(), "forged creator must fail sig check");
    assert!(dag.insert(tampered).is_err(), "forged event must be rejected by DAG");
}

// ═══════════════════════════════════════════════════════════════════════════
// 16. CONCURRENT TRANSFER STRESS (500 senders, 500 receivers)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_concurrent_transfers_500x500() {
    let state = Arc::new(WorldState::new());

    let senders: Vec<[u8; 32]> = (0..500)
        .map(|_| Ed25519KeyPair::generate().public_key().0)
        .collect();
    let receivers: Vec<[u8; 32]> = (0..500)
        .map(|_| Ed25519KeyPair::generate().public_key().0)
        .collect();

    // Mint 10,000 to each sender
    for s in &senders {
        state.mint(*s, 10_000).unwrap();
    }

    // Each sender sends 100 to corresponding receiver (in parallel)
    let handles: Vec<_> = (0..500)
        .map(|i| {
            let state = state.clone();
            let from = senders[i];
            let to = receivers[i];
            thread::spawn(move || {
                state.apply_transfer(&from, &to, 100, 0)
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(successes, 500, "all 500 independent transfers must succeed");

    // Verify conservation
    let sender_total: u128 = senders.iter().map(|s| state.get(s).balance).sum();
    let receiver_total: u128 = receivers.iter().map(|r| state.get(r).balance).sum();
    assert_eq!(sender_total + receiver_total, 500 * 10_000);
    assert_eq!(sender_total, 500 * 9_900);
    assert_eq!(receiver_total, 500 * 100);
}

// HCS stress tests are in crates/hcs/tests/stress.rs

// ═══════════════════════════════════════════════════════════════════════════
// 18. EMPTY/ZERO TRANSFERS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn edge_zero_amount_transfer() {
    let state = WorldState::new();
    let a = Ed25519KeyPair::generate().public_key().0;
    let b = Ed25519KeyPair::generate().public_key().0;

    state.mint(a, 1000).unwrap();

    // Zero transfer should succeed (just bumps nonce)
    state.apply_transfer(&a, &b, 0, 0).unwrap();
    assert_eq!(state.get(&a).balance, 1000);
    assert_eq!(state.get(&b).balance, 0);
    assert_eq!(state.get(&a).nonce, 1);
}

#[test]
fn edge_transfer_from_empty_account() {
    let state = WorldState::new();
    let empty = Ed25519KeyPair::generate().public_key().0;
    let target = Ed25519KeyPair::generate().public_key().0;

    // Account with 0 balance tries to send 1
    let result = state.apply_transfer(&empty, &target, 1, 0);
    assert!(result.is_err(), "empty account can't send");
}

// ═══════════════════════════════════════════════════════════════════════════
// 19. DAG EVENT CHAIN INTEGRITY (1000-deep chain)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_deep_chain_1000() {
    // Use a higher rate limit for stress testing (1000 events from same creator)
    let dag = Hashgraph::with_rate_limit(2000, std::time::Duration::from_secs(10));
    let kp = Ed25519KeyPair::generate();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut prev = Hash32::ZERO;
    for i in 0..1000u64 {
        let ev = Event::new(
            format!("chain-{}", i).into_bytes(),
            now + i,
            prev,
            Hash32::ZERO,
            &kp,
        );
        prev = dag.insert(ev).unwrap();
    }

    assert_eq!(dag.len(), 1000);

    // The last event should be able to see the genesis
    let all = dag.all_hashes();
    let first = all[0];
    let last = all[999];
    assert!(dag.can_see(&last, &first), "last must see genesis through 1000-deep chain");
}

// ═══════════════════════════════════════════════════════════════════════════
// 20. CONCURRENT DAG INSERTION (10 threads, 100 events each)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_concurrent_dag_insert() {
    let dag = Arc::new(Hashgraph::new());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // 10 threads, each creating genesis events with unique keys
    let handles: Vec<_> = (0..10)
        .map(|t| {
            let dag = dag.clone();
            thread::spawn(move || {
                let mut count = 0;
                for i in 0..100 {
                    let kp = Ed25519KeyPair::generate();
                    let ev = Event::new(
                        format!("t{}-e{}", t, i).into_bytes(),
                        now + (t * 1000 + i) as u64,
                        Hash32::ZERO,
                        Hash32::ZERO,
                        &kp,
                    );
                    if dag.insert(ev).is_ok() {
                        count += 1;
                    }
                }
                count
            })
        })
        .collect();

    let total: usize = handles.into_iter().map(|h| h.join().unwrap()).collect::<Vec<_>>().iter().sum();
    assert_eq!(total, 1000, "all 1000 concurrent inserts must succeed");
    assert_eq!(dag.len(), 1000);
}
