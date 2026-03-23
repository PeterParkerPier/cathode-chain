//! Persistence tests for cathode-storage (RocksDB)

use cathode_crypto::hash::Hash32;
use cathode_crypto::signature::Ed25519KeyPair;
use cathode_hashgraph::event::Event;
use cathode_storage::EventStore;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cathode-test-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn persist_and_recover_event() {
    let dir = temp_dir("event-roundtrip");

    let kp = Ed25519KeyPair::generate();
    let ev = Event::new(b"hello-persist".to_vec(), 12345, Hash32::ZERO, Hash32::ZERO, &kp);
    let hash = ev.hash;

    // Write
    {
        let store = EventStore::open(&dir).unwrap();
        store.put_event(&ev).unwrap();
    }

    // Read back from a fresh open
    {
        let store = EventStore::open(&dir).unwrap();
        let loaded = store.get_event(&hash).unwrap().expect("event must exist");
        assert_eq!(loaded.hash, hash);
        assert_eq!(loaded.payload, b"hello-persist");
        assert_eq!(loaded.timestamp_ns, 12345);
        assert_eq!(loaded.creator, kp.public_key().0);
        assert!(loaded.verify_signature().is_ok(), "recovered event sig must be valid");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persist_consensus_order() {
    let dir = temp_dir("consensus-order");

    let kp = Ed25519KeyPair::generate();
    let ev1 = Event::new(b"first".to_vec(), 100, Hash32::ZERO, Hash32::ZERO, &kp);
    let ev2 = Event::new(b"second".to_vec(), 200, Hash32::ZERO, Hash32::ZERO, &kp);

    {
        let store = EventStore::open(&dir).unwrap();
        store.put_event(&ev1).unwrap();
        store.put_event(&ev2).unwrap();
        store.put_consensus_order(0, &ev1.hash).unwrap();
        store.put_consensus_order(1, &ev2.hash).unwrap();
    }

    {
        let store = EventStore::open(&dir).unwrap();
        assert_eq!(store.get_by_order(0).unwrap().unwrap(), ev1.hash);
        assert_eq!(store.get_by_order(1).unwrap().unwrap(), ev2.hash);
        assert!(store.get_by_order(2).unwrap().is_none());
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persist_metadata() {
    let dir = temp_dir("metadata");

    {
        let store = EventStore::open(&dir).unwrap();
        store.put_meta("latest_round", &42u64.to_le_bytes()).unwrap();
        store.put_meta("version", b"1.0.2").unwrap();
    }

    {
        let store = EventStore::open(&dir).unwrap();
        let round = store.get_meta("latest_round").unwrap().unwrap();
        assert_eq!(u64::from_le_bytes(round.try_into().unwrap()), 42);
        let version = store.get_meta("version").unwrap().unwrap();
        assert_eq!(&version, b"1.0.2");
        assert!(store.get_meta("nonexistent").unwrap().is_none());
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stress_persist_1000_events() {
    let dir = temp_dir("1000-events");

    let keys: Vec<Ed25519KeyPair> = (0..10).map(|_| Ed25519KeyPair::generate()).collect();

    // Write 1000 events
    {
        let store = EventStore::open(&dir).unwrap();
        for i in 0..1000u64 {
            let kp = &keys[(i % 10) as usize];
            let ev = Event::new(
                format!("event-{}", i).into_bytes(),
                1000 + i,
                Hash32::ZERO,
                Hash32::ZERO,
                kp,
            );
            store.put_event(&ev).unwrap();
            store.put_consensus_order(i, &ev.hash).unwrap();
        }
    }

    // Verify recovery
    {
        let store = EventStore::open(&dir).unwrap();
        for i in 0..1000u64 {
            let hash = store.get_by_order(i).unwrap().expect("order must exist");
            let ev = store.get_event(&hash).unwrap().expect("event must exist");
            assert_eq!(ev.payload, format!("event-{}", i).into_bytes());
            assert!(ev.verify_signature().is_ok());
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn crash_recovery_simulation() {
    let dir = temp_dir("crash-recovery");

    let kp = Ed25519KeyPair::generate();

    // Phase 1: write some data, "crash" (just drop without flush)
    {
        let store = EventStore::open(&dir).unwrap();
        for i in 0..50u64 {
            let ev = Event::new(
                format!("pre-crash-{}", i).into_bytes(),
                1000 + i,
                Hash32::ZERO,
                Hash32::ZERO,
                &kp,
            );
            store.put_event(&ev).unwrap();
            store.put_consensus_order(i, &ev.hash).unwrap();
        }
        // Drop store — simulates crash
    }

    // Phase 2: reopen and verify data survived
    {
        let store = EventStore::open(&dir).unwrap();
        for i in 0..50u64 {
            let hash = store.get_by_order(i).unwrap();
            assert!(hash.is_some(), "event {} must survive crash", i);
        }
    }

    // Phase 3: continue writing after "recovery"
    {
        let store = EventStore::open(&dir).unwrap();
        for i in 50..100u64 {
            let ev = Event::new(
                format!("post-crash-{}", i).into_bytes(),
                2000 + i,
                Hash32::ZERO,
                Hash32::ZERO,
                &kp,
            );
            store.put_event(&ev).unwrap();
            store.put_consensus_order(i, &ev.hash).unwrap();
        }
    }

    // Phase 4: verify everything
    {
        let store = EventStore::open(&dir).unwrap();
        for i in 0..100u64 {
            assert!(store.get_by_order(i).unwrap().is_some(), "event {} must exist", i);
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}
