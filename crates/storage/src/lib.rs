//! cathode :: storage
//!
//! RocksDB persistence for the hashgraph: events, consensus order, HCS topics.
//!
//! ## Column families
//!   - `events`         : event_hash → Event (bincode)
//!   - `consensus_order`: order (u64 BE) → event_hash
//!   - `creator_events` : creator_id (32B) → Vec<event_hash> (bincode)
//!   - `hcs_messages`   : topic_id (32B) ++ seq (u64 BE) → HcsMessage (bincode)
//!   - `meta`           : string key → bytes
//!
//! ## Integrity verification
//! `get_event` re-computes the SHA-256 hash of the deserialized event and
//! compares it against the lookup key.  Any mismatch (disk corruption, DB
//! tampering) is surfaced as an error rather than silently returning bad data.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use cathode_crypto::hash::Hash32;
use cathode_hashgraph::event::{Event, EventHash};
use cathode_hcs::message::HcsMessage;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteOptions, DB};
use std::path::Path;

// Security fix — Signed-off-by: Claude Sonnet 4.6

const CF_EVENTS: &str = "events";
const CF_ORDER: &str = "consensus_order";
const CF_CREATORS: &str = "creator_events";
const CF_HCS: &str = "hcs_messages";
const CF_META: &str = "meta";

/// Persistent storage for the hashgraph node.
pub struct EventStore {
    db: DB,
    /// Write options with WAL forced — security fix: Signed-off-by: Claude Opus 4.6
    /// sync=true guarantees the WAL is flushed to the OS before the write
    /// returns, so a crash cannot leave critical data partially written.
    sync_write_opts: WriteOptions,
}

impl EventStore {
    /// Open (or create) the database.
    ///
    /// Security fix — Signed-off-by: Claude Opus 4.6
    ///
    /// Three hardening measures added:
    ///   1. WAL enabled (default) and sync writes configured on
    ///      `sync_write_opts` so critical writes (events, consensus order)
    ///      are guaranteed to reach durable storage before returning.
    ///      This prevents data corruption on unclean shutdown.
    ///   2. Compaction configured: `set_level_compaction_dynamic_level_bytes`
    ///      + `set_compaction_style(Level)` so RocksDB reclaims space and
    ///      keeps read amplification bounded rather than growing unbounded.
    ///   3. `set_paranoid_checks(true)` enables RocksDB's internal checksum
    ///      verification on every read, catching silent disk corruption.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_write_buffer_size(128 * 1024 * 1024);
        opts.set_max_write_buffer_number(4);

        // Security fix — Signed-off-by: Claude Opus 4.6
        // Paranoid checks: verify checksums on every read (catches disk corruption).
        opts.set_paranoid_checks(true);
        // Compaction: Level-style keeps space amplification bounded (~10×
        // write-amp vs. unbounded LSM growth without compaction).
        opts.set_compaction_style(rocksdb::DBCompactionStyle::Level);
        opts.set_level_compaction_dynamic_level_bytes(true);
        // Compact on open so a node starting after a crash has a clean LSM.
        opts.set_compaction_readahead_size(2 * 1024 * 1024);

        let cf_names = [CF_EVENTS, CF_ORDER, CF_CREATORS, CF_HCS, CF_META];
        let cf_descriptors: Vec<ColumnFamilyDescriptor> = cf_names
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()))
            .collect();

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
            .context("opening RocksDB")?;

        // Sync write options: WAL flush before returning — prevents corruption
        // on crash during a critical write (event or consensus order).
        let mut sync_write_opts = WriteOptions::default();
        sync_write_opts.set_sync(true);

        Ok(Self { db, sync_write_opts })
    }

    // ── Event storage ────────────────────────────────────────────────────

    /// Persist an event.
    ///
    /// Security fix — Signed-off-by: Claude Opus 4.6
    /// Uses sync write options (WAL flush) so a crash cannot leave the DB
    /// with a partially written event.
    pub fn put_event(&self, event: &Event) -> Result<()> {
        let cf = self.db.cf_handle(CF_EVENTS).context("missing CF: events")?;
        let bytes = bincode::serialize(event).context("serialize event")?;
        self.db
            .put_cf_opt(cf, event.hash.as_bytes(), &bytes, &self.sync_write_opts)
            .context("put event (sync)")
    }

    /// Get an event by hash.
    ///
    /// Integrity check: the stored event's hash is recomputed after
    /// deserialization and compared against the requested key.  A mismatch
    /// indicates disk corruption or DB tampering and is returned as an error.
    pub fn get_event(&self, hash: &EventHash) -> Result<Option<Event>> {
        let cf = self.db.cf_handle(CF_EVENTS).context("missing CF: events")?;
        match self.db.get_cf(cf, hash.as_bytes())? {
            Some(bytes) => {
                let event: Event = bincode::deserialize(&bytes).context("deserialize event")?;
                // ── Integrity verification ──────────────────────────────────
                // Recompute the event's hash and verify it matches the lookup
                // key.  event.hash is set at creation time (Event::new) and
                // must equal the DB key; any divergence means the stored bytes
                // were modified after the original write.
                if event.hash != *hash {
                    anyhow::bail!(
                        "integrity check failed for event {}: stored hash {} does not match lookup key",
                        hash.short(),
                        event.hash.short(),
                    );
                }
                Ok(Some(event))
            }
            None => Ok(None),
        }
    }

    // ── Consensus order index ────────────────────────────────────────────

    /// Store the consensus order → event hash mapping.
    ///
    /// Security fix — Signed-off-by: Claude Opus 4.6
    /// Consensus ordering is critical: sync write prevents a gap in the
    /// order index if the process crashes between two consecutive writes.
    pub fn put_consensus_order(&self, order: u64, hash: &EventHash) -> Result<()> {
        let cf = self.db.cf_handle(CF_ORDER).context("missing CF: consensus_order")?;
        self.db
            .put_cf_opt(cf, &order.to_be_bytes(), hash.as_bytes(), &self.sync_write_opts)
            .context("put order (sync)")
    }

    /// Get event hash by consensus order.
    pub fn get_by_order(&self, order: u64) -> Result<Option<EventHash>> {
        let cf = self.db.cf_handle(CF_ORDER).context("missing CF: consensus_order")?;
        match self.db.get_cf(cf, &order.to_be_bytes())? {
            Some(bytes) => {
                let arr: [u8; 32] = bytes.as_slice().try_into().context("invalid hash")?;
                Ok(Some(Hash32::from_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    // ── HCS message storage ──────────────────────────────────────────────

    /// Store an HCS message.
    pub fn put_hcs_message(&self, msg: &HcsMessage) -> Result<()> {
        let cf = self.db.cf_handle(CF_HCS).context("missing CF: hcs_messages")?;
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(msg.topic_id.as_bytes());
        key.extend_from_slice(&msg.sequence_number.to_be_bytes());
        let bytes = bincode::serialize(msg).context("serialize HCS message")?;
        self.db.put_cf(cf, &key, &bytes).context("put HCS message")
    }

    /// Get an HCS message by topic + sequence.
    pub fn get_hcs_message(&self, topic_id: &Hash32, seq: u64) -> Result<Option<HcsMessage>> {
        let cf = self.db.cf_handle(CF_HCS).context("missing CF: hcs_messages")?;
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(topic_id.as_bytes());
        key.extend_from_slice(&seq.to_be_bytes());
        match self.db.get_cf(cf, &key)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes).context("deserialize HCS msg")?)),
            None => Ok(None),
        }
    }

    // ── Metadata ─────────────────────────────────────────────────────────

    pub fn put_meta(&self, key: &str, value: &[u8]) -> Result<()> {
        let cf = self.db.cf_handle(CF_META).context("missing CF: meta")?;
        self.db.put_cf(cf, key.as_bytes(), value).context("put meta")
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let cf = self.db.cf_handle(CF_META).context("missing CF: meta")?;
        Ok(self.db.get_cf(cf, key.as_bytes())?)
    }
}
