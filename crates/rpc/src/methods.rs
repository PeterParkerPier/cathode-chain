//! RPC method implementations.

use crate::types::*;
use cathode_crypto::hash::Hash32;
use cathode_executor::pipeline::Executor;
use cathode_executor::state::StateDB;
use cathode_governance::ValidatorRegistry;
use cathode_hashgraph::dag::Hashgraph;
use cathode_hashgraph::ConsensusEngine;
use cathode_mempool::Mempool;
use cathode_types::address::Address;
use cathode_types::token::{TOKEN_NAME, TOKEN_SYMBOL, DECIMALS, MAX_SUPPLY};
use cathode_types::transaction::Transaction;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::warn;

/// Shared state for RPC handlers.
pub struct RpcContext {
    pub state: Arc<StateDB>,
    pub executor: Arc<Executor>,
    pub mempool: Arc<Mempool>,
    pub chain_id: String,
    pub version: String,
    /// Optional: hashgraph DAG (needed for scan REST endpoints).
    pub dag: Option<Arc<Hashgraph>>,
    /// Optional: consensus engine (needed for scan REST endpoints).
    pub consensus: Option<Arc<ConsensusEngine>>,
    /// Optional: validator registry (needed for scan REST endpoints).
    pub validators: Option<Arc<ValidatorRegistry>>,
    /// Optional: WebSocket event bus for real-time subscriptions.
    pub event_bus: Option<Arc<crate::ws::EventBus>>,
}

/// Dispatch a JSON-RPC request to the appropriate handler.
pub fn dispatch(ctx: &RpcContext, req: &JsonRpcRequest) -> JsonRpcResponse {
    match req.method.as_str() {
        "cathode_submitTransaction" => submit_transaction(ctx, &req.params, req.id.clone()),
        "cathode_getAccount" => get_account(ctx, &req.params, req.id.clone()),
        "cathode_getBalance" => get_balance(ctx, &req.params, req.id.clone()),
        "cathode_getNonce" => get_nonce(ctx, &req.params, req.id.clone()),
        "cathode_getTransaction" => get_transaction(ctx, &req.params, req.id.clone()),
        "cathode_chainInfo" => chain_info(ctx, req.id.clone()),
        "cathode_mempoolStatus" => mempool_status(ctx, req.id.clone()),
        _ => JsonRpcResponse::error(
            req.id.clone(),
            METHOD_NOT_FOUND,
            format!("method not found: {}", req.method),
        ),
    }
}

fn submit_transaction(ctx: &RpcContext, params: &Value, id: Value) -> JsonRpcResponse {
    // Expect params: { "tx": "<hex-encoded signed transaction>" }
    let tx_hex = match params.get("tx").and_then(|v| v.as_str()) {
        Some(h) => h,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "missing 'tx' param".into()),
    };

    let tx_bytes = match hex::decode(tx_hex) {
        Ok(b) => b,
        Err(_) => return JsonRpcResponse::error(id, INVALID_PARAMS, "invalid hex".into()),
    };

    let tx = match Transaction::decode(&tx_bytes) {
        Ok(t) => t,
        Err(e) => return JsonRpcResponse::error(id, INVALID_PARAMS, format!("decode: {}", e)),
    };

    let tx_hash = tx.hash;

    match ctx.mempool.submit(tx) {
        Ok(_) => JsonRpcResponse::success(id, json!({
            "hash": format!("{}", tx_hash),
            "status": "pending"
        })),
        Err(e) => {
            warn!("tx rejected: {}", e);
            JsonRpcResponse::error(id, TX_REJECTED, e.to_string())
        }
    }
}

fn get_account(ctx: &RpcContext, params: &Value, id: Value) -> JsonRpcResponse {
    let addr = match parse_address(params) {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let acc = ctx.state.get(&addr);
    JsonRpcResponse::success(id, json!({
        "address": addr.to_string(),
        "balance": acc.balance.display_tokens(),
        "balance_base": acc.balance.base().to_string(),
        "nonce": acc.nonce,
        "staked": acc.staked.display_tokens(),
        "has_code": acc.code_hash.is_some(),
    }))
}

fn get_balance(ctx: &RpcContext, params: &Value, id: Value) -> JsonRpcResponse {
    let addr = match parse_address(params) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let bal = ctx.state.balance(&addr);
    JsonRpcResponse::success(id, json!({
        "balance": bal.display_tokens(),
        "balance_base": bal.base().to_string(),
    }))
}

fn get_nonce(ctx: &RpcContext, params: &Value, id: Value) -> JsonRpcResponse {
    let addr = match parse_address(params) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let nonce = ctx.state.nonce(&addr);
    JsonRpcResponse::success(id, json!({ "nonce": nonce }))
}

fn get_transaction(ctx: &RpcContext, params: &Value, id: Value) -> JsonRpcResponse {
    let hash_str = match params.get("hash").and_then(|v| v.as_str()) {
        Some(h) => h,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "missing 'hash' param".into()),
    };

    let hash_bytes = match hex::decode(hash_str) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return JsonRpcResponse::error(id, INVALID_PARAMS, "invalid hash".into()),
    };

    let hash = Hash32::from_bytes(hash_bytes);

    // Check mempool first
    if let Some(tx) = ctx.mempool.get(&hash) {
        return JsonRpcResponse::success(id, json!({
            "hash": format!("{}", hash),
            "status": "pending",
            "sender": tx.sender.to_string(),
            "nonce": tx.nonce,
        }));
    }

    // Check receipts
    if let Some(receipt) = ctx.executor.receipt_by_hash(&hash) {
        let status_str = match &receipt.status {
            cathode_types::receipt::ReceiptStatus::Success => "success",
            cathode_types::receipt::ReceiptStatus::Failed(_) => "failed",
        };
        return JsonRpcResponse::success(id, json!({
            "hash": format!("{}", hash),
            "status": status_str,
            "gas_used": receipt.gas_used,
            "consensus_order": receipt.consensus_order,
        }));
    }

    JsonRpcResponse::error(id, TX_NOT_FOUND, "transaction not found".into())
}

fn chain_info(ctx: &RpcContext, id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!({
        "chain_id": ctx.chain_id,
        "version": ctx.version,
        "token_name": TOKEN_NAME,
        "token_symbol": TOKEN_SYMBOL,
        "decimals": DECIMALS,
        "max_supply": MAX_SUPPLY.to_string(),
        "accounts": ctx.state.account_count(),
        "transactions": ctx.executor.tx_count(),
    }))
}

fn mempool_status(ctx: &RpcContext, id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!({
        "pending": ctx.mempool.len(),
    }))
}

/// Parse an address from params.
fn parse_address(params: &Value) -> Result<Address, JsonRpcResponse> {
    let addr_str = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            JsonRpcResponse::error(Value::Null, INVALID_PARAMS, "missing 'address' param".into())
        })?;

    Address::from_hex(addr_str).map_err(|e| {
        JsonRpcResponse::error(Value::Null, INVALID_PARAMS, format!("invalid address: {}", e))
    })
}
