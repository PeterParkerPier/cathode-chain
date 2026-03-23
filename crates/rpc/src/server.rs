//! HTTP server for JSON-RPC.
//!
//! Security fix — Signed-off-by: Claude Opus 4.6
//! - CRITICAL: CORS policy changed from permissive wildcard (`*`) to an explicit
//!   allowlist of localhost origins only.  A wildcard CORS policy allows any web
//!   page on the internet to make credentialed cross-origin requests to this RPC
//!   server and read the response — a severe data-exfiltration risk.
//! - CRITICAL: Rate limiting is now applied to the `/rpc` JSON-RPC endpoint in
//!   addition to the REST routes.  Previously only REST was rate-limited, leaving
//!   the primary attack surface completely unthrottled.
//! - HIGH: Request body size is now capped at 1 MiB via `DefaultBodyLimit`.
//!   Without this limit a single POST with a multi-GB body could exhaust server
//!   memory before axum even begins to parse it.
//! - HIGH: A 30-second request timeout is enforced via `TimeoutLayer`.  Without
//!   this limit a slow client sending bytes one-at-a-time could hold a worker
//!   thread indefinitely, leading to thread/task exhaustion under load.
//! - The server is started with `into_make_service_with_connect_info` so that
//!   the rate-limit middleware can extract the real TCP peer address.

use crate::methods::{dispatch, RpcContext};
use crate::openapi::openapi_spec;
use crate::rate_limit::{rate_limit_middleware, RateLimiter, RateLimiterConfig};
use crate::rest::rest_router;
use crate::types::*;
use crate::ws::{ws_handler, EventBus, WsAuthConfig, WsState};
use axum::{
    extract::State,
    http::{HeaderValue, Method, StatusCode},
    middleware,
    routing::{get, post},
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tracing::info;

/// Maximum allowed request body size (1 MiB).
/// Prevents memory exhaustion from oversized POST payloads.
// Security fix — Signed-off-by: Claude Opus 4.6
const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

/// Maximum time a single request may take before it is aborted (30 s).
/// Prevents slow-loris / slow-read attacks that hold workers indefinitely.
// Security fix — Signed-off-by: Claude Opus 4.6
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The RPC server.
pub struct RpcServer {
    ctx: Arc<RpcContext>,
    addr: SocketAddr,
}

impl RpcServer {
    /// Create a new RPC server.
    pub fn new(ctx: RpcContext, addr: SocketAddr) -> Self {
        Self {
            ctx: Arc::new(ctx),
            addr,
        }
    }

    /// Build the axum Router.
    pub fn router(&self) -> Router {
        self.router_with_config(RateLimiterConfig::default())
    }

    /// Build the axum Router with a custom rate limiter configuration.
    pub fn router_with_config(&self, rl_config: RateLimiterConfig) -> Router {
        let limiter = RateLimiter::new(rl_config);

        // REST routes get per-IP rate limiting.
        let rate_limited_rest = rest_router()
            .route_layer(middleware::from_fn_with_state(
                limiter.clone(),
                rate_limit_middleware,
            ));

        // Core RPC routes share Arc<RpcContext> state.
        // /rpc is also rate-limited — previously it had no throttle at all.
        let rpc_routes = Router::new()
            .route("/rpc", post(handle_rpc)
                .route_layer(middleware::from_fn_with_state(
                    limiter,
                    rate_limit_middleware,
                )))
            .route("/health", get(handle_health))
            .route("/status", get(handle_status))
            .route("/api/v1/openapi.json", get(handle_openapi))
            .merge(rate_limited_rest)
            .with_state(self.ctx.clone());

        // WebSocket route: use the EventBus from the context if present,
        // otherwise create a detached (no-op) bus so the route still compiles.
        let bus: Arc<EventBus> = self
            .ctx
            .event_bus
            .clone()
            .unwrap_or_else(|| Arc::new(EventBus::new()));

        // Security fix (C-04): Generate a random WS API key at startup instead
        // of using open access. Prevents unauthorized front-running / MEV extraction.
        // The key is logged at INFO level so the operator can use it.
        // Signed-off-by: Claude Opus 4.6
        let ws_api_key: String = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let bytes: [u8; 32] = rng.gen();
            hex::encode(bytes)
        };
        tracing::info!(ws_api_key = %ws_api_key, "WebSocket API key generated — use ?api_key=<key> to connect");
        let ws_state = WsState {
            bus,
            auth: WsAuthConfig::with_keys([ws_api_key]),
        };

        let ws_route = Router::new()
            .route("/ws", get(ws_handler))
            .with_state(ws_state);

        // CORS: restrict to localhost origins only.
        // CorsLayer::permissive() was previously used, which sets Access-Control-Allow-Origin: *
        // and allows any web page to make credentialed cross-origin requests to this server.
        let cors = CorsLayer::new()
            .allow_origin(AllowOrigin::list([
                "http://localhost:3000".parse::<HeaderValue>().unwrap(),
                "http://127.0.0.1:3000".parse::<HeaderValue>().unwrap(),
                "http://localhost:8080".parse::<HeaderValue>().unwrap(),
                "http://127.0.0.1:8080".parse::<HeaderValue>().unwrap(),
            ]))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(tower_http::cors::Any);

        Router::new()
            .merge(rpc_routes)
            .merge(ws_route)
            .layer(cors)
            // HIGH: enforce 1 MiB body limit on all routes.
            // Security fix — Signed-off-by: Claude Opus 4.6
            .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
            // HIGH: abort requests that take longer than REQUEST_TIMEOUT.
            // Security fix — Signed-off-by: Claude Opus 4.6
            .layer(TimeoutLayer::new(REQUEST_TIMEOUT))
    }

    /// Start the server (blocks until shutdown).
    ///
    /// Uses `into_make_service_with_connect_info` so that `ConnectInfo<SocketAddr>`
    /// is available to middleware (required for peer-IP-based rate limiting).
    pub async fn serve(self) -> anyhow::Result<()> {
        let router = self.router();
        info!(addr = %self.addr, "RPC server starting");
        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
        Ok(())
    }

    /// Address this server is bound to.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// POST /rpc — JSON-RPC 2.0 handler.
async fn handle_rpc(
    State(ctx): State<Arc<RpcContext>>,
    Json(req): Json<JsonRpcRequest>,
) -> Json<JsonRpcResponse> {
    Json(dispatch(&ctx, &req))
}

/// GET /health
async fn handle_health() -> StatusCode {
    StatusCode::OK
}

/// GET /status
async fn handle_status(
    State(ctx): State<Arc<RpcContext>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "chain_id": ctx.chain_id,
        "version": ctx.version,
        "accounts": ctx.state.account_count(),
        "transactions": ctx.executor.tx_count(),
        "mempool_pending": ctx.mempool.len(),
    }))
}

/// GET /api/v1/openapi.json — serve the OpenAPI 3.0 specification.
async fn handle_openapi() -> Json<serde_json::Value> {
    Json(openapi_spec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_executor::pipeline::Executor;
    use cathode_executor::state::StateDB;
    use cathode_mempool::Mempool;
    use cathode_types::address::Address;
    use cathode_types::token::TokenAmount;
    use cathode_types::transaction::{Transaction, TransactionKind};
    use cathode_crypto::signature::Ed25519KeyPair;
    use serde_json::json;

    fn test_ctx() -> RpcContext {
        let state = Arc::new(StateDB::new());
        let executor = Arc::new(Executor::new(state.clone(), Address::ZERO, cathode_types::transaction::CHAIN_ID_TESTNET));
        let mempool = Arc::new(Mempool::with_defaults(state.clone(), cathode_types::transaction::CHAIN_ID_TESTNET));
        RpcContext {
            state,
            executor,
            mempool,
            chain_id: "cathode-test".to_string(),
            version: "1.0.55".to_string(),
            dag: None,
            consensus: None,
            validators: None,
            event_bus: None,
        }
    }

    #[test]
    fn dispatch_chain_info() {
        let ctx = test_ctx();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "cathode_chainInfo".to_string(),
            params: json!({}),
            id: json!(1),
        };
        let resp = dispatch(&ctx, &req);
        assert!(resp.result.is_some());
        let r = resp.result.unwrap();
        assert_eq!(r["chain_id"], "cathode-test");
        assert_eq!(r["token_symbol"], "CATH");
    }

    #[test]
    fn dispatch_get_account_empty() {
        let ctx = test_ctx();
        let addr = Address::from_bytes([0xAA; 32]);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "cathode_getAccount".to_string(),
            params: json!({"address": addr.to_string()}),
            id: json!(2),
        };
        let resp = dispatch(&ctx, &req);
        assert!(resp.result.is_some());
        let r = resp.result.unwrap();
        assert_eq!(r["nonce"], 0);
    }

    #[test]
    fn dispatch_get_account_with_balance() {
        let ctx = test_ctx();
        let addr = Address::from_bytes([0xBB; 32]);
        ctx.state.mint(addr, TokenAmount::from_tokens(42)).unwrap();

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "cathode_getAccount".to_string(),
            params: json!({"address": addr.to_string()}),
            id: json!(3),
        };
        let resp = dispatch(&ctx, &req);
        let r = resp.result.unwrap();
        assert_eq!(r["balance"], "42 CATH");
    }

    #[test]
    fn dispatch_submit_tx() {
        let ctx = test_ctx();
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        ctx.state.mint(sender, TokenAmount::from_tokens(10_000)).unwrap();

        let tx = Transaction::new(
            0,
            TransactionKind::Transfer {
                to: Address::from_bytes([0xCC; 32]),
                amount: TokenAmount::from_tokens(100),
            },
            21000,
            1,
            2u64,
            &kp,
        );
        // Security fix — Signed-off-by: Claude Opus 4.6

        let tx_hex = hex::encode(tx.encode());
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "cathode_submitTransaction".to_string(),
            params: json!({"tx": tx_hex}),
            id: json!(4),
        };
        let resp = dispatch(&ctx, &req);
        assert!(resp.result.is_some());
        assert_eq!(resp.result.unwrap()["status"], "pending");
        assert_eq!(ctx.mempool.len(), 1);
    }

    #[test]
    fn dispatch_unknown_method() {
        let ctx = test_ctx();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "nonexistent".to_string(),
            params: json!({}),
            id: json!(5),
        };
        let resp = dispatch(&ctx, &req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
    }

    #[test]
    fn dispatch_mempool_status() {
        let ctx = test_ctx();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "cathode_mempoolStatus".to_string(),
            params: json!({}),
            id: json!(6),
        };
        let resp = dispatch(&ctx, &req);
        let r = resp.result.unwrap();
        assert_eq!(r["pending"], 0);
    }
}
