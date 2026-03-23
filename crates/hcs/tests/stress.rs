//! HCS stress + attack tests

use cathode_crypto::hash::Hash32;
use cathode_crypto::signature::Ed25519KeyPair;
use cathode_hcs::TopicRegistry;

fn sign_for_topic(kp: &Ed25519KeyPair, topic_id: &Hash32, payload: &[u8]) -> cathode_crypto::signature::Ed25519Signature {
    let mut msg = Vec::new();
    msg.extend_from_slice(topic_id.as_bytes());
    msg.extend_from_slice(payload);
    kp.sign(&msg)
}

#[test]
fn stress_hcs_100_messages() {
    let registry = TopicRegistry::new();
    let kp = Ed25519KeyPair::generate();
    let pk = kp.public_key();

    let tid = registry.create_topic("stress-test", None, &pk).unwrap();
    // Security fix — Signed-off-by: Claude Opus 4.6
    let topic = registry.get(&tid).unwrap();

    for i in 0..100u64 {
        let payload = format!("msg-{}", i).into_bytes();
        let sig = sign_for_topic(&kp, &tid, &payload);
        topic.append(payload, pk.clone(), sig, 1000 + i * 100, Hash32::ZERO).unwrap();
    }

    assert_eq!(topic.message_count(), 100);
    assert!(topic.verify_integrity().is_ok(), "running hash chain must be valid");
}

#[test]
fn stress_hcs_1000_messages() {
    let registry = TopicRegistry::new();
    let kp = Ed25519KeyPair::generate();
    let pk = kp.public_key();

    let tid = registry.create_topic("mega-test", None, &pk).unwrap();
    let topic = registry.get(&tid).unwrap();

    for i in 0..1000u64 {
        let payload = format!("stress-msg-{}", i).into_bytes();
        let sig = sign_for_topic(&kp, &tid, &payload);
        topic.append(payload, pk.clone(), sig, 1000 + i * 10, Hash32::ZERO).unwrap();
    }

    assert_eq!(topic.message_count(), 1000);
    assert!(topic.verify_integrity().is_ok());
}

#[test]
fn attack_hcs_unauthorized_sender() {
    let registry = TopicRegistry::new();
    let owner = Ed25519KeyPair::generate();
    let attacker = Ed25519KeyPair::generate();

    // Topic restricted to owner's key
    let tid = registry.create_topic("restricted", Some(owner.public_key()), &owner.public_key()).unwrap();
    let topic = registry.get(&tid).unwrap();

    // Attacker tries to append
    let payload = b"hacked".to_vec();
    let sig = sign_for_topic(&attacker, &tid, &payload);
    let result = topic.append(payload, attacker.public_key(), sig, 2000, Hash32::ZERO);
    assert!(result.is_err(), "unauthorized sender must be rejected");
    assert_eq!(topic.message_count(), 0);
}

#[test]
fn attack_hcs_oversized_payload() {
    let registry = TopicRegistry::new();
    let kp = Ed25519KeyPair::generate();
    let pk = kp.public_key();

    let tid = registry.create_topic("overflow", None, &pk).unwrap();
    let topic = registry.get(&tid).unwrap();

    // 2MB payload (over MAX_PAYLOAD_BYTES)
    let payload = vec![0xAA; 2 * 1024 * 1024];
    let sig = sign_for_topic(&kp, &tid, &payload);
    let result = topic.append(payload, pk, sig, 3000, Hash32::ZERO);
    assert!(result.is_err(), "oversized payload must be rejected");
}

#[test]
fn attack_hcs_wrong_signature() {
    let registry = TopicRegistry::new();
    let kp = Ed25519KeyPair::generate();
    let wrong_kp = Ed25519KeyPair::generate();
    let pk = kp.public_key();

    let tid = registry.create_topic("sig-test", None, &pk).unwrap();
    let topic = registry.get(&tid).unwrap();

    // Sign with wrong key
    let payload = b"sneaky".to_vec();
    let sig = sign_for_topic(&wrong_kp, &tid, &payload);
    let result = topic.append(payload, pk, sig, 4000, Hash32::ZERO);
    assert!(result.is_err(), "wrong signature must be rejected");
}

#[test]
fn stress_hcs_50_topics() {
    let registry = TopicRegistry::new();
    let kp = Ed25519KeyPair::generate();
    let pk = kp.public_key();

    // Create 50 topics, append 10 messages each
    for t in 0..50 {
        let tid = registry.create_topic(&format!("topic-{}", t), None, &pk).unwrap();
        let topic = registry.get(&tid).unwrap();
        for i in 0..10u64 {
            let payload = format!("t{}-m{}", t, i).into_bytes();
            let sig = sign_for_topic(&kp, &tid, &payload);
            topic.append(payload, pk.clone(), sig, 1000 + i * 100, Hash32::ZERO).unwrap();
        }
        assert_eq!(topic.message_count(), 10);
        assert!(topic.verify_integrity().is_ok());
    }

    assert_eq!(registry.topic_count(), 50);
}
