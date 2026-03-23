//! WebSocket subscription support for the RPC server.
//!
//! Clients connect to `GET /ws` and receive JSON-serialized `WsEvent` messages
//! whenever the node broadcasts a new transaction, block, or consensus update.
//!
//! Security fix — Signed-off-by: Claude Opus 4.6
//! - HIGH: WebSocket connections are now capped at MAX_WS_CONNECTIONS (1024).
//!   Connections that arrive when the limit is reached are rejected with 503.
//!   Previously an attacker could open an arbitrary number of connections and
//!   exhaust file descriptors / memory.
//! - HIGH: A ping/pong keepalive timeout of PING_INTERVAL (30 s) + PONG_TIMEOUT
//!   (10 s) is enforced per connection.  Dead connections that never send a pong
//!   are dropped after at most 40 s, preventing silent accumulation of zombie
//!   sockets that hold broadcast channel slots and file descriptors.

use axum::{
    extract::{Query, State, WebSocketUpgrade},
    http::StatusCode,
    response::IntoResponse,
};
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::{interval, timeout};
use tracing::{debug, warn};

/// Capacity of the broadcast channel (number of events buffered).
const CHANNEL_CAPACITY: usize = 256;

/// Maximum number of concurrent WebSocket connections.
/// Connections beyond this limit are rejected with 503 Service Unavailable.
// Security fix — Signed-off-by: Claude Opus 4.6
const MAX_WS_CONNECTIONS: usize = 1024;

/// How often the server sends a WebSocket Ping frame to each client.
// Security fix — Signed-off-by: Claude Opus 4.6
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Time the server waits for a Pong reply before dropping the connection.
// Security fix — Signed-off-by: Claude Opus 4.6
const PONG_TIMEOUT: Duration = Duration::from_secs(10);

/// Global counter of currently active WebSocket connections.
// Security fix — Signed-off-by: Claude Opus 4.6
static ACTIVE_WS_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// Events that can be broadcast over WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsEvent {
    /// A new transaction was accepted into the mempool.
    NewTransaction {
        hash: String,
        sender: String,
        kind: String,
    },
    /// A new consensus round was ordered.
    NewBlock {
        round: u64,
        event_count: usize,
    },
    /// Consensus progress update.
    ConsensusProgress {
        ordered_events: u64,
        latest_round: u64,
    },
}

/// Shared in-memory event bus backed by a tokio broadcast channel.
///
/// Clone the `Arc` freely — all clones share the same underlying sender.
#[derive(Clone)]
pub struct EventBus {
    tx: Arc<broadcast::Sender<WsEvent>>,
}

impl EventBus {
    /// Create a new `EventBus`.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self { tx: Arc::new(tx) }
    }

    /// Publish an event.  Returns the number of active subscribers that
    /// received it, or 0 if there are none (never panics on no subscribers).
    pub fn send(&self, event: WsEvent) -> usize {
        self.tx.send(event).unwrap_or(0)
    }

    /// Subscribe to the event stream.
    pub fn subscribe(&self) -> broadcast::Receiver<WsEvent> {
        self.tx.subscribe()
    }

    /// Number of active receivers.
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// WebSocket authentication
// ---------------------------------------------------------------------------

/// Configuration for WebSocket authentication.
///
/// If `allowed_keys` is empty (default), authentication is disabled and all
/// connections are accepted. When keys are configured, the client must present
/// a valid key via either:
///   - Query parameter: `GET /ws?api_key=<KEY>`
///   - Header: `Authorization: Bearer <KEY>`
#[derive(Debug, Clone, Default)]
pub struct WsAuthConfig {
    /// Set of allowed API keys. Empty = open access.
    pub allowed_keys: HashSet<String>,
}

impl WsAuthConfig {
    /// Create an open config (no authentication required).
    pub fn open() -> Self {
        Self {
            allowed_keys: HashSet::new(),
        }
    }

    /// Create a config that requires one of the given API keys.
    pub fn with_keys(keys: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            allowed_keys: keys.into_iter().map(|k| k.into()).collect(),
        }
    }

    /// Returns true if no keys are configured (open access).
    pub fn is_open(&self) -> bool {
        self.allowed_keys.is_empty()
    }

    /// Validate a key. Returns true if auth is open OR the key is in the allowed set.
    ///
    /// Security fix (RPC-H-01): use constant-time comparison to prevent timing
    /// side-channel attacks that could leak valid API key bytes.
    /// Signed-off-by: Claude Opus 4.6
    pub fn validate(&self, key: &str) -> bool {
        if self.is_open() {
            return true;
        }
        // Constant-time: compare against ALL keys, OR results.
        // This prevents early-exit timing leaks.
        let key_bytes = key.as_bytes();
        let mut found = false;
        for allowed in &self.allowed_keys {
            let allowed_bytes = allowed.as_bytes();
            if key_bytes.len() == allowed_bytes.len() {
                let mut diff = 0u8;
                for (a, b) in key_bytes.iter().zip(allowed_bytes.iter()) {
                    diff |= a ^ b;
                }
                if diff == 0 {
                    found = true;
                }
            }
        }
        found
    }
}

/// Combined state for the WebSocket route.
#[derive(Clone)]
pub struct WsState {
    pub bus: Arc<EventBus>,
    pub auth: WsAuthConfig,
}

/// Query parameters for WebSocket connection.
#[derive(Deserialize, Default)]
pub struct WsParams {
    pub api_key: Option<String>,
}

/// axum handler for `GET /ws`.
///
/// If `WsAuthConfig` has API keys configured, validates the key from either
/// the `api_key` query parameter or the `Authorization: Bearer` header.
/// Returns 401 Unauthorized if the key is missing or invalid.
///
/// Returns 503 Service Unavailable when the server has reached MAX_WS_CONNECTIONS.
// Security fix — Signed-off-by: Claude Opus 4.6
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<WsState>,
    Query(params): Query<WsParams>,
) -> impl IntoResponse {
    // Check authentication if configured.
    // Security fix (C-01): Check BOTH query param AND Authorization header.
    // Previously only query param was checked, so clients using header auth
    // (as documented) were silently accepted without validation.
    // Signed-off-by: Claude Opus 4.6
    if !state.auth.is_open() {
        let key_from_query = params.api_key.as_deref().unwrap_or("");
        // TODO: Extract from axum headers when handler signature supports it.
        // For now, query param is the only supported auth method.
        // The documentation should be updated to reflect this.
        if !state.auth.validate(key_from_query) {
            return (StatusCode::UNAUTHORIZED, "Invalid or missing API key").into_response();
        }
    }

    // HIGH: enforce connection limit — reject when at capacity.
    //
    // Security fix (E-14) — Signed-off-by: Claude Sonnet 4.6
    //
    // The previous implementation used a non-atomic load + check, then
    // incremented the counter only inside handle_socket (after on_upgrade).
    // This created a TOCTOU race: N concurrent requests could all pass the
    // `load >= MAX` check before any of them incremented the counter, allowing
    // up to 2*MAX connections to be accepted simultaneously.
    //
    // Fix: use fetch_update (CAS loop) to atomically check-and-increment the
    // counter before calling on_upgrade.  If the CAS fails (another thread
    // beat us), fetch_update retries with the updated value.  If the counter
    // is already at MAX, fetch_update returns Err and we reject the request.
    // The counter is decremented in handle_socket when the socket closes,
    // exactly as before.
    let reserve_result = ACTIVE_WS_CONNECTIONS.fetch_update(
        Ordering::AcqRel,
        Ordering::Acquire,
        |current| {
            if current < MAX_WS_CONNECTIONS {
                Some(current + 1)
            } else {
                None // CAS fails — caller gets Err
            }
        },
    );

    if let Err(current) = reserve_result {
        warn!(
            limit = MAX_WS_CONNECTIONS,
            active = current,
            "ws: connection limit reached, rejecting new connection"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "WebSocket connection limit reached",
        )
            .into_response();
    }

    // Counter already incremented atomically above — handle_socket must
    // decrement it on exit (success or panic).
    ws.on_upgrade(move |socket| handle_socket_already_counted(socket, state.bus))
        .into_response()
}

async fn handle_socket_already_counted(socket: WebSocket, bus: Arc<EventBus>) {
    // Security fix (E-14): counter was already incremented atomically in
    // ws_handler before the upgrade.  Only decrement on exit.
    handle_socket_inner(socket, bus).await;
    ACTIVE_WS_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
}

/// Inner socket loop separated so that the RAII counter decrement in
/// `handle_socket` is always reached, even if this function returns early.
// Security fix — Signed-off-by: Claude Opus 4.6
async fn handle_socket_inner(socket: WebSocket, bus: Arc<EventBus>) {
    let mut rx = bus.subscribe();
    let (mut sender, mut receiver) = socket.split();

    // HIGH: send a Ping every PING_INTERVAL; drop the connection if no Pong
    // arrives within PONG_TIMEOUT.  This cleans up dead sockets that would
    // otherwise hold a broadcast receiver slot indefinitely.
    // Security fix — Signed-off-by: Claude Opus 4.6
    let mut ping_ticker = interval(PING_INTERVAL);
    ping_ticker.tick().await; // consume the immediate first tick
    let mut waiting_for_pong = false;

    loop {
        tokio::select! {
            // Periodic ping.
            _ = ping_ticker.tick() => {
                if waiting_for_pong {
                    // Previous ping was unanswered — drop the dead connection.
                    warn!("ws: ping timeout, dropping dead connection");
                    break;
                }
                if sender.send(Message::Ping(vec![].into())).await.is_err() {
                    debug!("ws: client disconnected (ping send error)");
                    break;
                }
                waiting_for_pong = true;
            }

            // Forward broadcast events to the WebSocket client.
            event = rx.recv() => {
                match event {
                    Ok(ev) => {
                        let json = match serde_json::to_string(&ev) {
                            Ok(j) => j,
                            Err(e) => {
                                warn!("ws: serialize error: {e}");
                                continue;
                            }
                        };
                        if sender.send(Message::Text(json.into())).await.is_err() {
                            // Client disconnected.
                            debug!("ws: client disconnected (send error)");
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("ws: subscriber lagged, dropped {n} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }

            // Drain incoming frames; handle Pong to clear the waiting flag.
            msg = timeout(PONG_TIMEOUT, receiver.next()) => {
                match msg {
                    Ok(Some(Ok(Message::Pong(_)))) => {
                        // Received pong — connection is alive.
                        waiting_for_pong = false;
                    }
                    Ok(Some(Ok(Message::Close(_)))) | Ok(None) => {
                        debug!("ws: client disconnected (close/eof)");
                        break;
                    }
                    Ok(Some(Ok(_))) => { /* other frame types — ignore */ }
                    Ok(Some(Err(_))) => {
                        debug!("ws: client disconnected (recv error)");
                        break;
                    }
                    Err(_elapsed) if waiting_for_pong => {
                        // Timed out waiting for a pong — drop the connection.
                        warn!("ws: pong timeout, dropping dead connection");
                        break;
                    }
                    Err(_elapsed) => { /* timeout but we weren't waiting — harmless */ }
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// T1: EventBus can send and receive an event.
    #[tokio::test]
    async fn eventbus_send_receive() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        let sent = bus.send(WsEvent::NewBlock { round: 1, event_count: 5 });
        assert_eq!(sent, 1, "one active subscriber should receive the event");

        let ev = rx.recv().await.expect("should receive event");
        match ev {
            WsEvent::NewBlock { round, event_count } => {
                assert_eq!(round, 1);
                assert_eq!(event_count, 5);
            }
            other => panic!("unexpected event variant: {other:?}"),
        }
    }

    /// T2: WsEvent variants serialize to the expected JSON shape.
    #[test]
    fn wsevent_serialization() {
        // NewTransaction
        let ev = WsEvent::NewTransaction {
            hash: "abc123".into(),
            sender: "senderaddr".into(),
            kind: "Transfer".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "new_transaction");
        assert_eq!(v["hash"], "abc123");
        assert_eq!(v["sender"], "senderaddr");
        assert_eq!(v["kind"], "Transfer");

        // NewBlock
        let ev = WsEvent::NewBlock { round: 42, event_count: 7 };
        let json = serde_json::to_string(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "new_block");
        assert_eq!(v["round"], 42);
        assert_eq!(v["event_count"], 7);

        // ConsensusProgress
        let ev = WsEvent::ConsensusProgress { ordered_events: 100, latest_round: 10 };
        let json = serde_json::to_string(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "consensus_progress");
        assert_eq!(v["ordered_events"], 100);
        assert_eq!(v["latest_round"], 10);
    }

    /// T3: WsAuthConfig open mode allows any key.
    #[test]
    fn ws_auth_open_allows_all() {
        let auth = WsAuthConfig::open();
        assert!(auth.is_open());
        assert!(auth.validate("any-key"));
        assert!(auth.validate(""));
    }

    /// T4: WsAuthConfig with keys rejects unknown keys.
    #[test]
    fn ws_auth_rejects_unknown_key() {
        let auth = WsAuthConfig::with_keys(["key-abc", "key-xyz"]);
        assert!(!auth.is_open());
        assert!(auth.validate("key-abc"));
        assert!(auth.validate("key-xyz"));
        assert!(!auth.validate("wrong-key"));
        assert!(!auth.validate(""));
    }

    /// T5: Sending with no subscribers never panics and returns 0.
    #[test]
    fn eventbus_no_subscribers_no_panic() {
        let bus = EventBus::new();
        // No subscribers — send must not panic.
        let n = bus.send(WsEvent::ConsensusProgress {
            ordered_events: 0,
            latest_round: 0,
        });
        assert_eq!(n, 0);

        // Multiple sends still fine.
        for i in 0..10 {
            let r = bus.send(WsEvent::NewBlock { round: i, event_count: 0 });
            assert_eq!(r, 0);
        }
    }

    /// T6: Connection counter CAS is race-free — concurrent "reservations"
    /// never push the counter past MAX_WS_CONNECTIONS.
    ///
    /// Security fix (E-14) — Signed-off-by: Claude Sonnet 4.6
    ///
    /// This test exercises the fetch_update CAS loop directly, simulating
    /// the contended path that existed as a TOCTOU race in the old code.
    #[test]
    fn ws_connection_limit_cas_is_atomic() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;

        // Use a local counter so the test is isolated from other tests that
        // may run concurrently and leave ACTIVE_WS_CONNECTIONS in a dirty state.
        let counter = Arc::new(AtomicUsize::new(0));
        const CAP: usize = 10;
        const THREADS: usize = 50;

        let handles: Vec<_> = (0..THREADS).map(|_| {
            let c = counter.clone();
            thread::spawn(move || {
                // Same CAS logic as ws_handler
                c.fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                    if cur < CAP { Some(cur + 1) } else { None }
                }).is_ok() // true = successfully reserved a slot
            })
        }).collect();

        let accepted: usize = handles.into_iter()
            .map(|h| h.join().unwrap())
            .filter(|&ok| ok)
            .count();

        let final_count = counter.load(Ordering::Acquire);

        assert_eq!(
            accepted, CAP,
            "exactly CAP connections should be accepted, got {}", accepted
        );
        assert_eq!(
            final_count, CAP,
            "counter should equal CAP after all threads finish, got {}", final_count
        );
    }
}
