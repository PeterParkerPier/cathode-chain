//! RPC AUDIT — method dispatch, error handling, edge cases.

use cathode_crypto::hash::Hash32;
use cathode_crypto::signature::Ed25519KeyPair;
use cathode_executor::pipeline::Executor;
use cathode_executor::state::StateDB;
use cathode_mempool::Mempool;
use cathode_rpc::server::RpcServer;
use cathode_rpc::methods::{dispatch, RpcContext};
use cathode_rpc::types::*;
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use cathode_types::transaction::{Transaction, TransactionKind, CHAIN_ID_TESTNET};
use serde_json::{json, Value};
use std::sync::Arc;

fn ctx() -> RpcContext {
    let state = Arc::new(StateDB::new());
    let executor = Arc::new(Executor::new(state.clone(), Address::ZERO, CHAIN_ID_TESTNET));
    let mempool = Arc::new(Mempool::with_defaults(state.clone(), CHAIN_ID_TESTNET));
    RpcContext {
        state,
        executor,
        mempool,
        chain_id: "cathode-audit".into(),
        version: "1.0.6".into(),
        dag: None,
        consensus: None,
        validators: None,
        event_bus: None,
    }
}

fn rpc_req(method: &str, params: Value) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params,
        id: json!(1),
    }
}

// ── R1: Unknown method returns proper error ──────────────────────────────────

#[test]
fn audit_unknown_method() {
    let c = ctx();
    let resp = dispatch(&c, &rpc_req("nonexistent", json!({})));
    assert!(resp.error.is_some());
    assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
}

// ── R2: Missing params returns error ─────────────────────────────────────────

#[test]
fn audit_missing_params() {
    let c = ctx();
    let resp = dispatch(&c, &rpc_req("cathode_getBalance", json!({})));
    assert!(resp.error.is_some());
    assert_eq!(resp.error.unwrap().code, INVALID_PARAMS);
}

// ── R3: Invalid address format ───────────────────────────────────────────────

#[test]
fn audit_invalid_address() {
    let c = ctx();
    let resp = dispatch(&c, &rpc_req("cathode_getAccount", json!({"address": "not-an-address"})));
    assert!(resp.error.is_some());
}

// ── R4: Get account for nonexistent returns defaults ─────────────────────────

#[test]
fn audit_nonexistent_account() {
    let c = ctx();
    let addr = Address::from_bytes([0xAA; 32]);
    let resp = dispatch(&c, &rpc_req("cathode_getAccount", json!({"address": addr.to_string()})));
    assert!(resp.result.is_some());
    let r = resp.result.unwrap();
    assert_eq!(r["nonce"], 0);
    assert_eq!(r["balance"], "0 CATH");
}

// ── R5: Submit valid TX ──────────────────────────────────────────────────────

#[test]
fn audit_submit_valid_tx() {
    let c = ctx();
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    c.state.mint(sender, TokenAmount::from_tokens(10_000)).unwrap();

    let tx = Transaction::new(
        0, TransactionKind::Transfer { to: Address::from_bytes([0xBB; 32]), amount: TokenAmount::from_tokens(100) },
        21000, 1, 2u64, &kp,
    );
    // Security fix — Signed-off-by: Claude Opus 4.6
    let tx_hex = hex::encode(tx.encode());

    let resp = dispatch(&c, &rpc_req("cathode_submitTransaction", json!({"tx": tx_hex})));
    assert!(resp.result.is_some());
    assert_eq!(resp.result.unwrap()["status"], "pending");
    assert_eq!(c.mempool.len(), 1);
}

// ── R6: Submit tampered TX rejected ──────────────────────────────────────────

#[test]
fn audit_submit_tampered_tx() {
    let c = ctx();
    let kp = Ed25519KeyPair::generate();
    c.state.mint(Address(kp.public_key().0), TokenAmount::from_tokens(10_000)).unwrap();

    let mut tx = Transaction::new(
        0, TransactionKind::Transfer { to: Address::from_bytes([0xBB; 32]), amount: TokenAmount::from_tokens(100) },
        21000, 1, 2u64, &kp,
    );
    tx.nonce = 999; // tamper
    let tx_hex = hex::encode(tx.encode());

    let resp = dispatch(&c, &rpc_req("cathode_submitTransaction", json!({"tx": tx_hex})));
    assert!(resp.error.is_some());
    assert_eq!(c.mempool.len(), 0);
}

// ── R7: Submit duplicate rejected ────────────────────────────────────────────

#[test]
fn audit_submit_duplicate() {
    let c = ctx();
    let kp = Ed25519KeyPair::generate();
    c.state.mint(Address(kp.public_key().0), TokenAmount::from_tokens(10_000)).unwrap();

    let tx = Transaction::new(
        0, TransactionKind::Transfer { to: Address::from_bytes([0xBB; 32]), amount: TokenAmount::from_tokens(100) },
        21000, 1, 2u64, &kp,
    );
    let tx_hex = hex::encode(tx.encode());

    dispatch(&c, &rpc_req("cathode_submitTransaction", json!({"tx": tx_hex.clone()})));
    let resp = dispatch(&c, &rpc_req("cathode_submitTransaction", json!({"tx": tx_hex})));
    assert!(resp.error.is_some());
}

// ── R8: Invalid hex in submit ────────────────────────────────────────────────

#[test]
fn audit_submit_invalid_hex() {
    let c = ctx();
    let resp = dispatch(&c, &rpc_req("cathode_submitTransaction", json!({"tx": "not-hex!"})));
    assert!(resp.error.is_some());
}

// ── R9: Chain info returns correct data ──────────────────────────────────────

#[test]
fn audit_chain_info() {
    let c = ctx();
    let resp = dispatch(&c, &rpc_req("cathode_chainInfo", json!({})));
    let r = resp.result.unwrap();
    assert_eq!(r["chain_id"], "cathode-audit");
    assert_eq!(r["version"], "1.0.6");
    assert_eq!(r["token_symbol"], "CATH");
    assert_eq!(r["decimals"], 18);
}

// ── R10: Mempool status ──────────────────────────────────────────────────────

#[test]
fn audit_mempool_status() {
    let c = ctx();
    let resp = dispatch(&c, &rpc_req("cathode_mempoolStatus", json!({})));
    assert_eq!(resp.result.unwrap()["pending"], 0);
}

// ── R11: Get balance with minted funds ───────────────────────────────────────

#[test]
fn audit_get_balance_minted() {
    let c = ctx();
    let addr = Address::from_bytes([0xCC; 32]);
    c.state.mint(addr, TokenAmount::from_tokens(42)).unwrap();
    let resp = dispatch(&c, &rpc_req("cathode_getBalance", json!({"address": addr.to_string()})));
    assert_eq!(resp.result.unwrap()["balance"], "42 CATH");
}

// ── R12: Get nonce after transfers ───────────────────────────────────────────

#[test]
fn audit_get_nonce_after_transfer() {
    let c = ctx();
    let addr = Address::from_bytes([0xDD; 32]);
    c.state.mint(addr, TokenAmount::from_tokens(1000)).unwrap();
    c.state.transfer(&addr, &Address::from_bytes([0xEE; 32]), TokenAmount::from_tokens(1), 0).unwrap();

    let resp = dispatch(&c, &rpc_req("cathode_getNonce", json!({"address": addr.to_string()})));
    assert_eq!(resp.result.unwrap()["nonce"], 1);
}

// ── R13: Get TX not found ────────────────────────────────────────────────────

#[test]
fn audit_get_tx_not_found() {
    let c = ctx();
    let hash = hex::encode([0u8; 32]);
    let resp = dispatch(&c, &rpc_req("cathode_getTransaction", json!({"hash": hash})));
    assert!(resp.error.is_some());
    assert_eq!(resp.error.unwrap().code, TX_NOT_FOUND);
}

// ── R14: Invalid hash format ─────────────────────────────────────────────────

#[test]
fn audit_get_tx_invalid_hash() {
    let c = ctx();
    let resp = dispatch(&c, &rpc_req("cathode_getTransaction", json!({"hash": "short"})));
    assert!(resp.error.is_some());
}
