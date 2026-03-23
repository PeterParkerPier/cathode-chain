//! Gossip stress + attack tests

use cathode_crypto::hash::Hash32;
use cathode_crypto::signature::Ed25519KeyPair;
use cathode_hashgraph::{dag::Hashgraph, event::Event};
use cathode_gossip::sync::GossipSync;
use std::sync::Arc;

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

#[test]
fn attack_gossip_oversized_batch() {
    let dag = Arc::new(Hashgraph::new());
    let kp = Arc::new(Ed25519KeyPair::generate());
    let sync = GossipSync::new(dag.clone(), kp.clone());

    let now = now_ns();
    let events: Vec<Event> = (0..10_001)
        .map(|i| {
            Event::new(
                format!("flood-{}", i).into_bytes(),
                now + i as u64,
                Hash32::ZERO,
                Hash32::ZERO,
                &kp,
            )
        })
        .collect();

    let received = sync.receive_events(&events);
    assert_eq!(received, 0, "oversized batch must be fully rejected");
}

#[test]
fn attack_gossip_normal_batch() {
    let dag = Arc::new(Hashgraph::new());
    let kp = Arc::new(Ed25519KeyPair::generate());
    let sync = GossipSync::new(dag.clone(), kp.clone());

    let now = now_ns();
    let keys: Vec<Ed25519KeyPair> = (0..50).map(|_| Ed25519KeyPair::generate()).collect();
    let events: Vec<Event> = keys.iter().enumerate()
        .map(|(i, k)| {
            Event::new(
                format!("normal-{}", i).into_bytes(),
                now + i as u64,
                Hash32::ZERO,
                Hash32::ZERO,
                k,
            )
        })
        .collect();

    let received = sync.receive_events(&events);
    assert_eq!(received, 50, "normal batch should be fully accepted");
}

#[test]
fn attack_gossip_orphan_events_dropped() {
    let dag = Arc::new(Hashgraph::new());
    let kp = Arc::new(Ed25519KeyPair::generate());
    let sync = GossipSync::new(dag.clone(), kp.clone());

    let now = now_ns();
    // Events with non-existent parents — should be dropped as orphans
    let fake_parent = Hash32::from_bytes([0xAA; 32]);
    let events: Vec<Event> = (0..10)
        .map(|i| {
            Event::new(
                format!("orphan-{}", i).into_bytes(),
                now + i as u64,
                fake_parent,
                Hash32::ZERO,
                &kp,
            )
        })
        .collect();

    let received = sync.receive_events(&events);
    assert_eq!(received, 0, "orphan events must be dropped");
}

#[test]
fn stress_gossip_topological_sort() {
    // Create a chain: g -> e1 -> e2 -> e3
    // Send them in REVERSE order — Kahn's algorithm must sort them correctly
    let kp = Ed25519KeyPair::generate();
    let now = now_ns();

    let g = Event::new(b"gen".to_vec(), now, Hash32::ZERO, Hash32::ZERO, &kp);
    let e1 = Event::new(b"e1".to_vec(), now + 1, g.hash, Hash32::ZERO, &kp);
    let e2 = Event::new(b"e2".to_vec(), now + 2, e1.hash, Hash32::ZERO, &kp);
    let e3 = Event::new(b"e3".to_vec(), now + 3, e2.hash, Hash32::ZERO, &kp);

    // Send in reverse order
    let dag = Arc::new(Hashgraph::new());
    let kp_arc = Arc::new(Ed25519KeyPair::generate());
    let sync = GossipSync::new(dag.clone(), kp_arc);

    let received = sync.receive_events(&[e3, e2, e1, g]);
    assert_eq!(received, 4, "toposort must handle reverse-order events");
    assert_eq!(dag.len(), 4);
}
