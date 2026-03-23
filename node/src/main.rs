//! cathode-node — main entry point for a hashgraph node.
//!
//! Usage:
//!   cathode-node                                     # start first node
//!   cathode-node --peer /ip4/127.0.0.1/tcp/30333     # join existing network
//!
//! ## What this node does
//! 1. Creates or loads a hashgraph DAG from disk.
//! 2. Starts the gossip-about-gossip P2P layer.
//! 3. Periodically syncs with random peers (creating new events in the DAG).
//! 4. Runs the consensus engine (divideRounds → decideFame → findOrder).
//! 5. Processes consensus-ordered events (applying state transitions, HCS messages).
//! 6. Persists everything to RocksDB.
//!
//! ## Immutability
//! There is no `--fork`, no `--rollback`, no `--reset-state` flag.
//! Once events are in the DAG and consensus is reached, it's permanent.

use anyhow::{Context, Result};
use clap::Parser;
use cathode_crypto::signature::Ed25519KeyPair;
use cathode_hashgraph::{
    consensus::ConsensusEngine,
    dag::Hashgraph,
    event::Event,
    state::WorldState,
};
use cathode_hcs::TopicRegistry;
use cathode_gossip::{GossipConfig, GossipNode, sync::GossipSync};
use cathode_network::{NetworkConfig, NetworkId};
use cathode_storage::EventStore;
use cathode_crypto::hash::Hash32;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "cathode-node", about = "Hashgraph consensus node with HCS")]
struct Cli {
    /// Network to join (mainnet, testnet, devnet).
    #[arg(long, default_value = "testnet")]
    network: String,

    /// libp2p listen address (default depends on --network).
    #[arg(long)]
    listen: Option<String>,

    /// Bootstrap peer addresses.
    #[arg(long = "peer")]
    peers: Vec<String>,

    /// RocksDB data directory (default depends on --network).
    #[arg(long)]
    data_dir: Option<String>,

    /// Log level.
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Gossip interval in milliseconds (default depends on --network).
    #[arg(long)]
    gossip_interval_ms: Option<u64>,

    /// JSON-RPC port (default depends on --network).
    #[arg(long)]
    rpc_port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&cli.log_level))
        .with_target(true)
        .init();

    // ── Network selection ──────────────────────────────────────────────
    let network_id: NetworkId = cli.network.parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    let net_config = NetworkConfig::for_network(network_id);

    info!(
        network  = %network_id,
        chain_id = %net_config.chain_id,
        symbol   = %net_config.token_symbol,
        faucet   = net_config.faucet_enabled,
        "network selected"
    );

    // Resolve CLI overrides vs network defaults
    let data_dir = cli.data_dir.unwrap_or_else(|| net_config.default_data_dir.clone());
    let listen_addr = cli.listen.unwrap_or_else(|| net_config.default_listen_addr.clone());
    let gossip_interval_ms = cli.gossip_interval_ms.unwrap_or(net_config.gossip_interval_ms);
    let rpc_port = cli.rpc_port.unwrap_or(net_config.default_rpc_port);
    let max_event_payload_bytes = net_config.max_event_payload_bytes;

    info!("cathode-node starting");

    // ── Storage ────────────────────────────────────────────────────────
    let store = Arc::new(EventStore::open(&data_dir)?);
    info!(dir = %data_dir, "storage opened");

    // ── Identity (persistent — survives restarts) ─────────────────────
    let key_path = format!("{}/node.key", data_dir);
    let keypair = Arc::new(load_or_create_keypair(&key_path)?);
    info!(pk = %keypair.public_key().to_hex()[..16], "node identity loaded");

    // ── Hashgraph DAG ──────────────────────────────────────────────────
    let dag = Arc::new(Hashgraph::new());

    // Create genesis event
    let genesis = Event::new(
        net_config.genesis_payload.clone(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
        Hash32::ZERO,
        Hash32::ZERO,
        &keypair,
    );
    let genesis_hash = dag.insert(genesis.clone())?;
    store.put_event(&genesis)?;
    info!(hash = %genesis_hash.short(), "genesis event created");

    // ── World State ────────────────────────────────────────────────────
    let state = Arc::new(WorldState::new());

    // ── HCS Topic Registry ─────────────────────────────────────────────
    let topics = Arc::new(TopicRegistry::new());

    // ── Consensus Engine ───────────────────────────────────────────────
    let engine = Arc::new(ConsensusEngine::new(dag.clone(), state.clone()));

    // ── Gossip Sync ────────────────────────────────────────────────────
    // Security fix (H-01): pass network-specific chain_id instead of hardcoded mainnet.
    // Signed-off-by: Claude Opus 4.6
    let sync = Arc::new(GossipSync::new_with_chain_id(
        dag.clone(),
        keypair.clone(),
        network_id.chain_id_numeric(),
    ));

    // ── Gossip Network ─────────────────────────────────────────────────
    let bootstrap_peers: Vec<libp2p::Multiaddr> = cli
        .peers
        .iter()
        .filter_map(|p| p.parse().ok())
        .collect();

    let (app_tx, mut app_rx) = mpsc::channel(1024);

    let gossip_config = GossipConfig {
        listen_addr: listen_addr.parse()?,
        bootstrap_peers,
    };

    let (gossip_node, _cmd_tx) = GossipNode::new(gossip_config, dag.clone(), keypair.clone(), app_tx).await?;
    tokio::spawn(gossip_node.run());

    // ── Consensus processing loop ──────────────────────────────────────
    let engine_clone = engine.clone();
    let store_clone = store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        loop {
            interval.tick().await;
            let ordered = engine_clone.process();
            if ordered > 0 {
                info!(ordered, "consensus: {} events ordered", ordered);
                // Persist newly ordered events
                for ev in engine_clone.ordered_events() {
                    if let Some(order) = ev.consensus_order {
                        if let Err(e) = store_clone.put_event(&ev) {
                            error!("persist event failed: {}", e);
                        }
                        if let Err(e) = store_clone.put_consensus_order(order, &ev.hash) {
                            error!("persist order failed: {}", e);
                        }
                    }
                }
            }
        }
    });

    // ── Periodic gossip (create events to build the DAG) ───────────────
    // Heartbeat events use our own latest event as other_parent when no
    // peer data is available.  This keeps the DAG advancing vertically.
    // Real cross-links come from peer sync in the gossip layer.
    let sync_clone = sync.clone();
    let dag_clone2 = dag.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(
            Duration::from_millis(gossip_interval_ms)
        );
        loop {
            interval.tick().await;
            if sync_clone.my_latest().is_some() {
                // Use latest event from any OTHER creator as other_parent
                // to create a real cross-link when available.
                let my_creator = sync_clone.my_creator();
                let other_parent = dag_clone2.latest_by_other_creator(&my_creator)
                    .unwrap_or(Hash32::ZERO);
                let _ = sync_clone.create_gossip_event(other_parent, vec![]);
            }
        }
    });

    // ── Application event loop ─────────────────────────────────────────
    info!(
        network  = %network_id,
        chain_id = %net_config.chain_id,
        rpc_port = rpc_port,
        listen   = %listen_addr,
        "node ready — DAG has {} event(s), listening for peers",
        dag.len()
    );

    loop {
        tokio::select! {
            Some(event) = app_rx.recv() => {
                use cathode_gossip::network::AppEvent;
                match event {
                    AppEvent::EventsSynced(count) => {
                        info!(count, "synced events from peer");
                    }
                    AppEvent::TransactionReceived(payload) => {
                        if payload.len() > max_event_payload_bytes {
                            warn!(
                                len = payload.len(),
                                max = max_event_payload_bytes,
                                "transaction payload too large — rejected"
                            );
                        } else {
                            info!(len = payload.len(), "transaction received");
                            let other_parent = sync.my_latest().unwrap_or(Hash32::ZERO);
                            if let Err(e) = sync.create_gossip_event(other_parent, payload) {
                                error!("failed to create tx event: {}", e);
                            }
                        }
                    }
                    AppEvent::PeerConnected(peer_id) => {
                        info!(%peer_id, "peer connected");
                    }
                    AppEvent::PeerDisconnected(peer_id) => {
                        info!(%peer_id, "peer disconnected");
                    }
                }
            }
        }
    }
}

/// Load an existing Ed25519 keypair from disk, or generate + persist a new one.
///
/// Security hardening:
///   - On Unix: file permissions are verified on load (must be 0o600) and
///     enforced immediately after creation.  Any other mode is rejected.
///   - On Windows: the OS ACL model applies; callers must place the data
///     directory under a user-private path (e.g. %APPDATA%\cathode).
///   - Secret bytes in memory are wrapped in `Zeroizing` and zeroed on drop.
///
/// Security fix — Signed-off-by: Claude Sonnet 4.6
fn load_or_create_keypair(path: &str) -> Result<Ed25519KeyPair> {
    use zeroize::Zeroizing;
    if Path::new(path).exists() {
        // ── Verify file permissions before reading (Unix only) ───────────
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(path)
                .with_context(|| format!("stat key file: {}", path))?;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                anyhow::bail!(
                    "key file {} has insecure permissions {:o} — expected 0o600 \
                     (owner read/write only). Fix with: chmod 600 {}",
                    path, mode, path
                );
            }
        }

        // Wrap the heap-allocated Vec in Zeroizing so the allocator's copy
        // of the secret bytes is wiped on drop, not merely freed.
        let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
            std::fs::read(path)
                .with_context(|| format!("reading key file: {}", path))?,
        );
        if bytes.len() != 32 {
            anyhow::bail!("key file must be exactly 32 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let kp = Ed25519KeyPair::from_secret_bytes(&arr)?;
        // Zero the stack copy; `bytes` is zeroed automatically when it drops.
        arr.iter_mut().for_each(|b| *b = 0);
        info!("loaded existing node identity from {}", path);
        Ok(kp)
    } else {
        let kp = Ed25519KeyPair::generate();
        let secret = kp.signing_key_bytes();
        // Ensure data directory exists
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating data dir: {:?}", parent))?;
        }
        std::fs::write(path, secret.as_ref())
            .with_context(|| format!("writing key file: {}", path))?;

        // ── Harden permissions immediately after write (Unix only) ───────
        // Set 0o600 so no other OS user can read the private key.
        // This must happen right after the write, before any other process
        // can observe the file with world-readable default umask bits.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)
                .with_context(|| format!("setting permissions on key file: {}", path))?;
            info!("key file permissions hardened to 0o600");
        }

        // `secret` is Zeroizing<[u8;32]> — wiped automatically on drop here.
        info!("generated new node identity, saved to {}", path);
        Ok(kp)
    }
}
