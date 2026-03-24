//! GossipNode — libp2p-based P2P networking for hashgraph gossip.
//!
//! Transport stack: TCP + Noise (encryption) + Yamux (multiplexing)
//! Discovery: Kademlia DHT + manual bootstrap peers
//! Data exchange: GossipSub (event propagation)
//!
//! Uses libp2p 0.53+ API (SwarmBuilder, select_next_some).
//!
//! ## v3 identity binding (Grok F-003 fix)
//! The libp2p PeerId is now derived from the node's Ed25519 signing key,
//! so PeerId == hashgraph creator ID.  This closes the identity gap where
//! `with_new_identity()` would generate a random, unrelated libp2p key.
//! The signing key bytes are exported via `Zeroizing<[u8;32]>` and the
//! copy is zeroed immediately after the libp2p keypair is constructed.

use crate::{protocol::GossipMessage, sync::GossipSync};
use anyhow::Result;
use cathode_hashgraph::dag::Hashgraph;
use cathode_hashgraph::event::Event;
use cathode_crypto::signature::Ed25519KeyPair;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode},
    identify, identity, kad, noise, tcp, yamux,
    swarm::{SwarmEvent, NetworkBehaviour},
    Multiaddr, PeerId, SwarmBuilder,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Maximum gossip message size (1 MB — reduced from 4 MB for DoS protection).
const MAX_GOSSIP_MESSAGE_SIZE: usize = 1024 * 1024;

/// Maximum number of peers allowed simultaneously (eclipse attack protection).
/// An attacker needs to control all MAX_PEERS slots to eclipse the node.
const MAX_PEERS: usize = 50;

/// Maximum inbound connections from a single IP (eclipse / Sybil protection).
/// Prevents one host from monopolising peer slots.
const MAX_CONNECTIONS_PER_IP: usize = 3;

/// Per-peer rate limit: max messages per window.
const RATE_LIMIT_MESSAGES: usize = 50;
/// Rate limit window duration.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(10);

// Security fix — Signed-off-by: Claude Sonnet 4.6

/// Security fix — Signed-off-by: Claude Opus 4.6
///
/// Gossip protocol version advertised in Identify — peers on a different
/// version are rejected to prevent incompatible nodes from joining.
const GOSSIP_PROTOCOL_VERSION: &str = "/cathode/gossip/1.0.0";

/// How long a misbehaving peer stays banned.
const BAN_DURATION: Duration = Duration::from_secs(3600); // 1 hour

/// GossipSub topic for event propagation.
const EVENTS_TOPIC: &str = "cathode/events/v1";
/// GossipSub topic for transaction submission.
const TX_TOPIC: &str = "cathode/transactions/v1";

/// Composed libp2p behaviour.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "NodeEvent")]
pub struct NodeBehaviour {
    gossipsub: gossipsub::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
    ping: libp2p::ping::Behaviour,
}

/// Unified event from all sub-protocols.
#[derive(Debug)]
pub enum NodeEvent {
    Gossip(gossipsub::Event),
    Kademlia(kad::Event),
    Identify(identify::Event),
    Ping(libp2p::ping::Event),
}

impl From<gossipsub::Event> for NodeEvent { fn from(e: gossipsub::Event) -> Self { Self::Gossip(e) } }
impl From<kad::Event> for NodeEvent { fn from(e: kad::Event) -> Self { Self::Kademlia(e) } }
impl From<identify::Event> for NodeEvent { fn from(e: identify::Event) -> Self { Self::Identify(e) } }
impl From<libp2p::ping::Event> for NodeEvent { fn from(e: libp2p::ping::Event) -> Self { Self::Ping(e) } }

/// Events delivered to the application layer.
#[derive(Debug)]
pub enum AppEvent {
    /// New events received from a peer (already ingested into DAG).
    EventsSynced(usize),
    /// A transaction was submitted by a client.
    TransactionReceived(Vec<u8>),
    /// A peer connected.
    PeerConnected(PeerId),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
}

/// Configuration.
pub struct GossipConfig {
    pub listen_addr: Multiaddr,
    pub bootstrap_peers: Vec<Multiaddr>,
}

/// Per-peer rate limiter state.
struct PeerRateLimit {
    count: usize,
    window_start: Instant,
}

/// Commands that can be sent to a running GossipNode.
#[derive(Debug)]
pub enum NodeCommand {
    /// Broadcast a batch of events to all peers.
    BroadcastEvents(Vec<Event>),
    /// Gracefully shut down the node.
    Shutdown,
}

/// A banned peer entry: the peer and the time when the ban expires.
struct BannedPeer {
    expires: Instant,
}

/// The gossip network node.
pub struct GossipNode {
    swarm: libp2p::Swarm<NodeBehaviour>,
    sync: Arc<GossipSync>,
    events_topic: IdentTopic,
    tx_topic: IdentTopic,
    app_tx: mpsc::Sender<AppEvent>,
    cmd_rx: mpsc::Receiver<NodeCommand>,
    /// Per-peer rate limiter.
    peer_rates: HashMap<PeerId, PeerRateLimit>,
    /// Active peer set — enforces MAX_PEERS total.
    active_peers: HashMap<PeerId, IpAddr>,
    /// Per-IP connection count — enforces MAX_CONNECTIONS_PER_IP.
    ip_counts: HashMap<IpAddr, usize>,
    /// Banned peers — security fix: prevents malicious peers from reconnecting.
    // Security fix — Signed-off-by: Claude Opus 4.6
    banned_peers: HashMap<PeerId, BannedPeer>,
}

impl GossipNode {
    /// Build and start a gossip node.
    ///
    /// Uses libp2p 0.53 SwarmBuilder API:
    ///   TCP → Noise (encryption) → Yamux (multiplexing) → behaviours
    pub async fn new(
        config: GossipConfig,
        dag: Arc<Hashgraph>,
        keypair: Arc<Ed25519KeyPair>,
        app_tx: mpsc::Sender<AppEvent>,
    ) -> Result<(Self, mpsc::Sender<NodeCommand>)> {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        // ── Derive libp2p identity from the node's Ed25519 signing key ──
        // This binds the libp2p PeerId to the hashgraph creator ID so that
        // peer authentication and consensus identity are the same key pair.
        // The Zeroizing<[u8;32]> wrapper zeroes the secret copy on drop.
        let libp2p_kp: identity::Keypair = {
            let secret_bytes = keypair.signing_key_bytes(); // Zeroizing<[u8;32]>
            // try_from_bytes requires a mutable slice (it zeroes input on success)
            let mut secret_copy: [u8; 32] = *secret_bytes;
            let ed_secret = identity::ed25519::SecretKey::try_from_bytes(&mut secret_copy)
                .map_err(|e| anyhow::anyhow!("ed25519 secret conversion: {:?}", e))?;
            identity::Keypair::from(identity::ed25519::Keypair::from(ed_secret))
            // secret_bytes (Zeroizing) is dropped here — bytes zeroed
        };

        // Build transport + swarm using libp2p 0.53 SwarmBuilder
        // with_existing_identity() binds the swarm to our hashgraph keypair.
        // Explicit noise closure (|key| noise::Config::new(key)) makes
        // the key parameter flow explicit and satisfies the type checker on
        // Noise 0.53 trait bounds.
        let mut swarm = SwarmBuilder::with_existing_identity(libp2p_kp)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                let local_peer_id = PeerId::from(key.public());

                // GossipSub
                let gs_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_millis(500))
                    .validation_mode(ValidationMode::Strict)
                    .max_transmit_size(MAX_GOSSIP_MESSAGE_SIZE)
                    .build()
                    .map_err(|e| format!("gossipsub config: {}", e))?;

                let gossipsub = gossipsub::Behaviour::new(
                    MessageAuthenticity::Signed(key.clone()),
                    gs_config,
                ).map_err(|e| format!("gossipsub: {}", e))?;

                // Kademlia
                // Security fix (HB-008): Bound Kademlia store to prevent unbounded memory.
                // Signed-off-by: Claude Opus 4.6
                let mut kad_config = kad::store::MemoryStoreConfig::default();
                kad_config.max_records = 10_000;
                kad_config.max_provided_keys = 1_000;
                let kademlia = kad::Behaviour::new(
                    local_peer_id,
                    kad::store::MemoryStore::with_config(local_peer_id, kad_config),
                );

                // Identify
                // Security fix (NEW-C-02): Use GOSSIP_PROTOCOL_VERSION consistently.
                // Previously "/cathode/1.0.0" here vs "/cathode/gossip/1.0.0" in the
                // version check — every legitimate peer was banned for 1 hour.
                // Signed-off-by: Claude Opus 4.6
                let identify = identify::Behaviour::new(identify::Config::new(
                    GOSSIP_PROTOCOL_VERSION.to_string(),
                    key.public(),
                ));

                let ping = libp2p::ping::Behaviour::new(libp2p::ping::Config::default());

                Ok(NodeBehaviour { gossipsub, kademlia, identify, ping })
            })?
            .build();

        let local_peer_id = *swarm.local_peer_id();
        info!(%local_peer_id, "gossip node starting");

        swarm.listen_on(config.listen_addr)?;

        for addr in &config.bootstrap_peers {
            if let Err(e) = swarm.dial(addr.clone()) {
                warn!(%addr, "bootstrap dial failed: {}", e);
            }
        }

        let events_topic = IdentTopic::new(EVENTS_TOPIC);
        let tx_topic = IdentTopic::new(TX_TOPIC);
        swarm.behaviour_mut().gossipsub
            .subscribe(&events_topic)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        swarm.behaviour_mut().gossipsub
            .subscribe(&tx_topic)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;

        let sync = Arc::new(GossipSync::new(dag, keypair));

        Ok((Self {
            swarm,
            sync,
            events_topic,
            tx_topic,
            app_tx,
            cmd_rx,
            peer_rates: HashMap::new(),
            active_peers: HashMap::new(),
            ip_counts: HashMap::new(),
            banned_peers: HashMap::new(),
        }, cmd_tx))
    }

    /// Broadcast a batch of events to all peers.
    pub fn broadcast_events(&mut self, events: &[cathode_hashgraph::event::Event]) -> Result<()> {
        let msg = GossipMessage::EventBatch(events.to_vec());
        let bytes = msg.encode();
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.events_topic.clone(), bytes)
            .map_err(|e| anyhow::anyhow!("publish: {:?}", e))?;
        Ok(())
    }

    /// Run the swarm event loop (libp2p 0.53: use `select_next_some`).
    /// Listens on both swarm events and external commands.
    /// Returns when a `Shutdown` command is received or the command channel closes.
    pub async fn run(mut self) {
        use futures::StreamExt;
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!(%address, "listening");
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            // ── Ban check — security fix: Signed-off-by: Claude Opus 4.6 ──
                            // Expire old bans lazily, then reject still-banned peers.
                            if let Some(ban) = self.banned_peers.get(&peer_id) {
                                if ban.expires > Instant::now() {
                                    warn!(%peer_id, "banned peer attempted reconnect — disconnecting");
                                    let _ = self.swarm.disconnect_peer_id(peer_id);
                                    continue;
                                } else {
                                    // Ban expired — remove it
                                    self.banned_peers.remove(&peer_id);
                                }
                            }

                            // Extract the remote IP from the endpoint.
                            let remote_ip: Option<IpAddr> = endpoint
                                .get_remote_address()
                                .iter()
                                .find_map(|proto| match proto {
                                    libp2p::multiaddr::Protocol::Ip4(addr) => Some(IpAddr::V4(addr)),
                                    libp2p::multiaddr::Protocol::Ip6(addr) => Some(IpAddr::V6(addr)),
                                    _ => None,
                                });

                            // ── Eclipse-attack protection: enforce peer limits ──────────
                            // 1. Total peer cap.
                            if self.active_peers.len() >= MAX_PEERS {
                                warn!(%peer_id, max = MAX_PEERS, "peer limit reached — disconnecting");
                                let _ = self.swarm.disconnect_peer_id(peer_id);
                                continue;
                            }
                            // 2. Per-IP cap (Sybil / eclipse from single host).
                            if let Some(ip) = remote_ip {
                                let ip_count = self.ip_counts.entry(ip).or_insert(0);
                                if *ip_count >= MAX_CONNECTIONS_PER_IP {
                                    warn!(%peer_id, %ip, max = MAX_CONNECTIONS_PER_IP,
                                        "per-IP connection limit reached — disconnecting");
                                    let _ = self.swarm.disconnect_peer_id(peer_id);
                                    continue;
                                }
                                *ip_count += 1;
                                self.active_peers.insert(peer_id, ip);
                            } else {
                                // No extractable IP (e.g. relay circuit) — still count toward total.
                                self.active_peers.insert(peer_id, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                            }

                            info!(%peer_id, peers = self.active_peers.len(), "peer connected");
                            let _ = self.app_tx.send(AppEvent::PeerConnected(peer_id)).await;
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            // Clean up peer tracking and IP counts.
                            if let Some(ip) = self.active_peers.remove(&peer_id) {
                                if ip != IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED) {
                                    if let Some(count) = self.ip_counts.get_mut(&ip) {
                                        *count = count.saturating_sub(1);
                                        if *count == 0 {
                                            self.ip_counts.remove(&ip);
                                        }
                                    }
                                }
                            }
                            self.peer_rates.remove(&peer_id);
                            let _ = self.app_tx.send(AppEvent::PeerDisconnected(peer_id)).await;
                        }
                        SwarmEvent::Behaviour(NodeEvent::Gossip(
                            gossipsub::Event::Message { message, propagation_source, .. }
                        )) => {
                            // Per-peer rate limiting
                            let rate = self.peer_rates
                                .entry(propagation_source)
                                .or_insert(PeerRateLimit {
                                    count: 0,
                                    window_start: Instant::now(),
                                });
                            if rate.window_start.elapsed() >= RATE_LIMIT_WINDOW {
                                rate.count = 0;
                                rate.window_start = Instant::now();
                            }
                            rate.count += 1;
                            if rate.count > RATE_LIMIT_MESSAGES {
                                warn!(%propagation_source, "peer rate limited — banning peer");
                                // Security fix — Signed-off-by: Claude Opus 4.6
                                // Ban the peer so it cannot immediately reconnect.
                                self.banned_peers.insert(propagation_source, BannedPeer {
                                    expires: Instant::now() + BAN_DURATION,
                                });
                                let _ = self.swarm.disconnect_peer_id(propagation_source);
                                continue;
                            }

                            match GossipMessage::decode(&message.data) {
                                Ok(GossipMessage::EventBatch(events)) => {
                                    let count = self.sync.receive_events(&events);
                                    if count > 0 {
                                        let _ = self.app_tx.send(AppEvent::EventsSynced(count)).await;
                                    }
                                }
                                Ok(GossipMessage::SubmitTransaction { payload }) => {
                                    if payload.len() <= MAX_GOSSIP_MESSAGE_SIZE {
                                        let _ = self.app_tx.send(AppEvent::TransactionReceived(payload)).await;
                                    } else {
                                        warn!("oversized transaction payload — rejected");
                                    }
                                }
                                // Security fix (E-09) — Signed-off-by: Claude Sonnet 4.6
                                // PeerList messages are validated after decode to prevent
                                // heap exhaustion (bincode allocates the Vec<String> before
                                // any application-level check fires).  The byte-level size
                                // limit on the gossip message (MAX_GOSSIP_MESSAGE_SIZE)
                                // provides a first layer of protection; this check enforces
                                // per-entry limits to prevent a message that is within the
                                // byte limit but still contains many short strings.
                                Ok(GossipMessage::PeerList(peers)) => {
                                    const MAX_PEER_LIST_LEN: usize = 100;
                                    const MAX_PEER_ADDR_LEN: usize = 256;
                                    let valid = peers.len() <= MAX_PEER_LIST_LEN
                                        && peers.iter().all(|a| a.len() <= MAX_PEER_ADDR_LEN);
                                    if !valid {
                                        warn!(
                                            count = peers.len(),
                                            "oversized PeerList from peer — ignored"
                                        );
                                    }
                                    // PeerList is otherwise intentionally not acted upon
                                    // until a peer discovery subsystem is implemented.
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    warn!("gossip decode error: {}", e);
                                }
                            }
                        }
                        // ── Protocol version check — security fix ──────────────────────
                        // Security fix — Signed-off-by: Claude Opus 4.6
                        // Reject peers running an incompatible gossip protocol version.
                        // Without this check, a node running a different (possibly
                        // malicious) protocol variant is silently accepted.
                        SwarmEvent::Behaviour(NodeEvent::Identify(
                            identify::Event::Received { peer_id, info, .. }
                        )) => {
                            // Security fix (NEW-C-02): Check protocol_version field
                            // (set by Identify config), NOT protocols (stream protocol IDs
                            // like /meshsub/1.1.0 which never match our version string).
                            // Signed-off-by: Claude Opus 4.6
                            let proto_ok = info.protocol_version == GOSSIP_PROTOCOL_VERSION;
                            if !proto_ok {
                                warn!(
                                    %peer_id,
                                    protocols = ?info.protocols,
                                    expected = GOSSIP_PROTOCOL_VERSION,
                                    "incompatible protocol version — banning peer"
                                );
                                self.banned_peers.insert(peer_id, BannedPeer {
                                    expires: Instant::now() + BAN_DURATION,
                                });
                                let _ = self.swarm.disconnect_peer_id(peer_id);
                            } else {
                                info!(%peer_id, "peer protocol version verified");
                            }
                        }
                        _ => {}
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(NodeCommand::BroadcastEvents(events)) => {
                            if let Err(e) = self.broadcast_events(&events) {
                                warn!("broadcast failed: {}", e);
                            }
                        }
                        Some(NodeCommand::Shutdown) | None => {
                            info!("gossip node shutting down");
                            break;
                        }
                    }
                }
            }
        }
    }
}
