//! REST API handlers for the Cathode scan endpoints.
//!
//! Provides `/api/v1/*` routes backed by `cathode-scan` modules.
//!
//! Security fix — Signed-off-by: Claude Opus 4.6
//! - HIGH: Pagination `limit` is now capped at MAX_PAGE_SIZE (100) for all
//!   list endpoints.  Previously callers could request 1 000 000+ items in a
//!   single response, causing unbounded memory allocation and CPU time.
//! - HIGH: Address path parameters are now validated before being forwarded
//!   to the state layer.  Addresses must be 64 hex characters (32-byte Ed25519
//!   public key).  Invalid inputs are rejected with 400 Bad Request, preventing
//!   malformed strings from reaching lower-level parsing code.

use crate::methods::RpcContext;
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use cathode_scan::async_scan::{AsyncTokenScan, AsyncTransactionScan};
use cathode_scan::block::BlockScan;
use cathode_scan::export;
use cathode_scan::network::NetworkScan;
use cathode_scan::search::UniversalSearch;
use cathode_scan::token::TokenScan;
use cathode_scan::transaction::TransactionScan;
use cathode_scan::util::{PaginationParams, SortOrder};
use serde::Deserialize;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Query parameter structs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ListParams {
    pub limit: Option<usize>,
    pub order: Option<String>,
    /// Filter: only return transactions with `consensus_timestamp_ns >= timestamp_from` (nanoseconds).
    pub timestamp_from: Option<u64>,
    /// Filter: only return transactions with `consensus_timestamp_ns <= timestamp_to` (nanoseconds).
    pub timestamp_to: Option<u64>,
    /// Cursor-based pagination: return items with consensus_order strictly greater than this value.
    /// The value is the consensus_order of the last item from the previous page (decimal string).
    pub after: Option<String>,
    /// Cursor-based pagination: return items with consensus_order strictly less than this value.
    pub before: Option<String>,
}

#[derive(Deserialize)]
pub struct SearchParams {
    pub q: String,
}

#[derive(Deserialize)]
pub struct LimitParams {
    pub limit: Option<usize>,
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<serde_json::Value>)>;

fn not_found(msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": msg })))
}

fn bad_request(msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg })))
}

fn service_unavailable(msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": msg })))
}

// ---------------------------------------------------------------------------
// Security constants & validation helpers
// ---------------------------------------------------------------------------

/// Maximum number of items returned by any paginated list endpoint.
/// Prevents unbounded memory allocation from large `limit` query parameters.
// Security fix — Signed-off-by: Claude Opus 4.6
const MAX_PAGE_SIZE: usize = 100;

/// Expected byte-length of a Cathode address (32-byte Ed25519 public key).
const ADDRESS_HEX_LEN: usize = 64;

/// Validate that `addr` is a well-formed Cathode address (64 lowercase hex chars).
///
/// Returns `Ok(())` when valid, or an API error response when invalid.
// Security fix — Signed-off-by: Claude Opus 4.6
fn validate_address(addr: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if addr.len() != ADDRESS_HEX_LEN {
        return Err(bad_request(&format!(
            "invalid address: expected {ADDRESS_HEX_LEN} hex characters, got {}",
            addr.len()
        )));
    }
    if !addr.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(bad_request("invalid address: contains non-hex characters"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Router builder
// ---------------------------------------------------------------------------

/// Build the REST API router for scan endpoints.
pub fn rest_router() -> Router<Arc<RpcContext>> {
    Router::new()
        .route("/api/v1/transactions/{hash}", get(get_transaction))
        .route("/api/v1/transactions", get(list_transactions))
        .route("/api/v1/accounts/{address}", get(get_account))
        .route("/api/v1/accounts/{address}/balance", get(get_balance))
        .route("/api/v1/events/{hash}", get(get_event))
        .route("/api/v1/network/health", get(network_health))
        .route("/api/v1/network/consensus", get(consensus_progress))
        .route("/api/v1/network/validators", get(validators))
        .route("/api/v1/supply", get(supply))
        .route("/api/v1/search", get(search))
        .route("/api/v1/rich-list", get(rich_list))
        .route("/api/v1/mempool", get(mempool))
        .route("/api/v1/transactions/export", get(export_transactions))
        .route("/api/v1/accounts/export", get(export_accounts))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /api/v1/transactions/:hash
async fn get_transaction(
    State(ctx): State<Arc<RpcContext>>,
    Path(hash): Path<String>,
) -> ApiResult<serde_json::Value> {
    let (dag, consensus) = require_dag_consensus(&ctx)?;
    let tx_scan = AsyncTransactionScan::new(TransactionScan::new(
        ctx.mempool.clone(),
        ctx.executor.clone(),
        consensus,
        dag,
    ));
    match tx_scan.get_transaction(hash).await {
        Ok(detail) => Ok(Json(serde_json::to_value(detail).unwrap())),
        Err(cathode_scan::error::ScanError::TxNotFound(_)) => Err(not_found("transaction not found")),
        Err(cathode_scan::error::ScanError::InvalidQuery(msg)) => Err(bad_request(&msg)),
        Err(e) => Err(bad_request(&e.to_string())),
    }
}

/// GET /api/v1/transactions
async fn list_transactions(
    State(ctx): State<Arc<RpcContext>>,
    Query(params): Query<ListParams>,
) -> ApiResult<serde_json::Value> {
    let (dag, consensus) = require_dag_consensus(&ctx)?;
    let tx_scan = TransactionScan::new(
        ctx.mempool.clone(),
        ctx.executor.clone(),
        consensus,
        dag,
    );
    let order = match params.order.as_deref() {
        Some("asc") | Some("ASC") => SortOrder::Asc,
        _ => SortOrder::Desc,
    };
    // HIGH: cap limit at MAX_PAGE_SIZE to prevent unbounded responses.
    // Security fix — Signed-off-by: Claude Opus 4.6
    let capped_limit = Some(params.limit.unwrap_or(MAX_PAGE_SIZE).min(MAX_PAGE_SIZE));
    let pagination = PaginationParams {
        limit: capped_limit,
        order,
        timestamp_from: params.timestamp_from,
        timestamp_to: params.timestamp_to,
        after_cursor: params.after,
        before_cursor: params.before,
        ..Default::default()
    };
    let resp = tx_scan.recent_transactions(&pagination);
    Ok(Json(serde_json::to_value(resp).unwrap()))
}

/// GET /api/v1/accounts/:address
async fn get_account(
    State(ctx): State<Arc<RpcContext>>,
    Path(address): Path<String>,
) -> ApiResult<serde_json::Value> {
    // HIGH: validate address format before forwarding to the state layer.
    // Security fix — Signed-off-by: Claude Opus 4.6
    validate_address(&address)?;
    let token_scan = AsyncTokenScan::new(TokenScan::new(ctx.state.clone()));
    match token_scan.get_account(address).await {
        Ok(info) => Ok(Json(serde_json::to_value(info).unwrap())),
        Err(cathode_scan::error::ScanError::InvalidQuery(msg)) => Err(bad_request(&msg)),
        Err(e) => Err(not_found(&e.to_string())),
    }
}

/// GET /api/v1/accounts/:address/balance
async fn get_balance(
    State(ctx): State<Arc<RpcContext>>,
    Path(address): Path<String>,
) -> ApiResult<serde_json::Value> {
    // HIGH: validate address format before forwarding to the state layer.
    // Security fix — Signed-off-by: Claude Opus 4.6
    validate_address(&address)?;
    let token_scan = TokenScan::new(ctx.state.clone());
    match token_scan.get_balance(&address) {
        Ok(balance) => Ok(Json(serde_json::json!({ "address": address, "balance": balance }))),
        Err(cathode_scan::error::ScanError::InvalidQuery(msg)) => Err(bad_request(&msg)),
        Err(e) => Err(not_found(&e.to_string())),
    }
}

/// GET /api/v1/events/:hash
async fn get_event(
    State(ctx): State<Arc<RpcContext>>,
    Path(hash): Path<String>,
) -> ApiResult<serde_json::Value> {
    let (dag, consensus) = require_dag_consensus(&ctx)?;
    let block_scan = BlockScan::new(dag, consensus);
    match block_scan.get_event(&hash) {
        Ok(summary) => Ok(Json(serde_json::to_value(summary).unwrap())),
        Err(cathode_scan::error::ScanError::EventNotFound(_)) => Err(not_found("event not found")),
        Err(cathode_scan::error::ScanError::InvalidQuery(msg)) => Err(bad_request(&msg)),
        Err(e) => Err(bad_request(&e.to_string())),
    }
}

/// GET /api/v1/network/health
async fn network_health(
    State(ctx): State<Arc<RpcContext>>,
) -> ApiResult<serde_json::Value> {
    let (dag, consensus, validators) = require_all(&ctx)?;
    let net_scan = NetworkScan::new(dag, consensus, validators);
    let health = net_scan.health();
    Ok(Json(serde_json::to_value(health).unwrap()))
}

/// GET /api/v1/network/consensus
async fn consensus_progress(
    State(ctx): State<Arc<RpcContext>>,
) -> ApiResult<serde_json::Value> {
    let (dag, consensus, validators) = require_all(&ctx)?;
    let net_scan = NetworkScan::new(dag, consensus, validators);
    let progress = net_scan.consensus_progress();
    Ok(Json(serde_json::to_value(progress).unwrap()))
}

/// GET /api/v1/network/validators
async fn validators(
    State(ctx): State<Arc<RpcContext>>,
) -> ApiResult<serde_json::Value> {
    let (dag, consensus, validators) = require_all(&ctx)?;
    let net_scan = NetworkScan::new(dag, consensus, validators);
    let active = net_scan.active_validators();
    Ok(Json(serde_json::to_value(active).unwrap()))
}

/// GET /api/v1/supply
async fn supply(
    State(ctx): State<Arc<RpcContext>>,
) -> ApiResult<serde_json::Value> {
    let token_scan = TokenScan::new(ctx.state.clone());
    let info = token_scan.supply_info();
    Ok(Json(serde_json::to_value(info).unwrap()))
}

/// GET /api/v1/search?q=...
async fn search(
    State(ctx): State<Arc<RpcContext>>,
    Query(params): Query<SearchParams>,
) -> ApiResult<serde_json::Value> {
    let (dag, consensus) = require_dag_consensus(&ctx)?;
    let universal = UniversalSearch::new(
        dag,
        consensus,
        ctx.state.clone(),
        ctx.mempool.clone(),
        ctx.executor.clone(),
    );
    let result = universal.search(&params.q);
    Ok(Json(serde_json::to_value(result).unwrap()))
}

/// GET /api/v1/rich-list?limit=N
async fn rich_list(
    State(ctx): State<Arc<RpcContext>>,
    Query(params): Query<LimitParams>,
) -> ApiResult<serde_json::Value> {
    let token_scan = TokenScan::new(ctx.state.clone());
    // HIGH: cap at MAX_PAGE_SIZE (100) to prevent unbounded responses.
    // Security fix — Signed-off-by: Claude Opus 4.6
    let limit = params.limit.unwrap_or(MAX_PAGE_SIZE).min(MAX_PAGE_SIZE);
    let list = token_scan.rich_list(limit);
    Ok(Json(serde_json::to_value(list).unwrap()))
}

/// GET /api/v1/mempool
async fn mempool(
    State(ctx): State<Arc<RpcContext>>,
) -> ApiResult<serde_json::Value> {
    let (dag, consensus) = require_dag_consensus(&ctx)?;
    let tx_scan = TransactionScan::new(
        ctx.mempool.clone(),
        ctx.executor.clone(),
        consensus,
        dag,
    );
    let overview = tx_scan.mempool_overview();
    Ok(Json(serde_json::to_value(overview).unwrap()))
}

/// GET /api/v1/transactions/export
///
/// Returns all recent executed transactions as a CSV download
/// (`text/csv; charset=utf-8`).  Accepts the same `limit` and `order` query
/// parameters as `GET /api/v1/transactions`.
async fn export_transactions(
    State(ctx): State<Arc<RpcContext>>,
    Query(params): Query<ListParams>,
) -> Response {
    let (dag, consensus) = match require_dag_consensus(&ctx) {
        Ok(pair) => pair,
        Err((status, body)) => return (status, body).into_response(),
    };
    let tx_scan = TransactionScan::new(
        ctx.mempool.clone(),
        ctx.executor.clone(),
        consensus,
        dag,
    );
    let order = match params.order.as_deref() {
        Some("asc") | Some("ASC") => SortOrder::Asc,
        _ => SortOrder::Desc,
    };
    // HIGH: cap limit at MAX_PAGE_SIZE to prevent unbounded CSV generation.
    // Security fix — Signed-off-by: Claude Opus 4.6
    let capped_limit = Some(params.limit.unwrap_or(MAX_PAGE_SIZE).min(MAX_PAGE_SIZE));
    let pagination = PaginationParams {
        limit: capped_limit,
        order,
        ..Default::default()
    };
    let resp = tx_scan.recent_transactions(&pagination);
    let csv = export::transactions_to_csv(&resp.items);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/csv; charset=utf-8")],
        csv,
    )
        .into_response()
}

/// GET /api/v1/accounts/export
///
/// Returns the rich list as a CSV download (`text/csv; charset=utf-8`).
/// Accepts an optional `limit` query parameter (default 100, max 100).
async fn export_accounts(
    State(ctx): State<Arc<RpcContext>>,
    Query(params): Query<LimitParams>,
) -> Response {
    let token_scan = TokenScan::new(ctx.state.clone());
    // HIGH: cap at MAX_PAGE_SIZE to prevent unbounded CSV generation.
    // Security fix — Signed-off-by: Claude Opus 4.6
    let limit = params.limit.unwrap_or(MAX_PAGE_SIZE).min(MAX_PAGE_SIZE);
    let list = token_scan.rich_list(limit);
    let csv = export::accounts_to_csv(&list);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/csv; charset=utf-8")],
        csv,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Internal helpers to extract optional context fields
// ---------------------------------------------------------------------------

fn require_dag_consensus(
    ctx: &RpcContext,
) -> Result<
    (Arc<cathode_hashgraph::dag::Hashgraph>, Arc<cathode_hashgraph::ConsensusEngine>),
    (StatusCode, Json<serde_json::Value>),
> {
    let dag = ctx.dag.clone().ok_or_else(|| service_unavailable("DAG not configured"))?;
    let consensus = ctx.consensus.clone().ok_or_else(|| service_unavailable("consensus not configured"))?;
    Ok((dag, consensus))
}

fn require_all(
    ctx: &RpcContext,
) -> Result<
    (
        Arc<cathode_hashgraph::dag::Hashgraph>,
        Arc<cathode_hashgraph::ConsensusEngine>,
        Arc<cathode_governance::ValidatorRegistry>,
    ),
    (StatusCode, Json<serde_json::Value>),
> {
    let dag = ctx.dag.clone().ok_or_else(|| service_unavailable("DAG not configured"))?;
    let consensus = ctx.consensus.clone().ok_or_else(|| service_unavailable("consensus not configured"))?;
    let validators = ctx.validators.clone().ok_or_else(|| service_unavailable("validators not configured"))?;
    Ok((dag, consensus, validators))
}
