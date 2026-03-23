//! RPC HACK AUDIT — injection, overflow, resource abuse, edge cases.

use cathode_crypto::signature::Ed25519KeyPair;
use cathode_executor::pipeline::Executor;
use cathode_executor::state::StateDB;
use cathode_mempool::Mempool;
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
        chain_id: "cathode-hack".into(),
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

// ── RH1: SQL injection in method name ──────────────────────────────────────

#[test]
fn hack_sql_injection_method() {
    let c = ctx();
    let resp = dispatch(&c, &rpc_req("'; DROP TABLE users; --", json!({})));
    assert!(resp.error.is_some());
    assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
}

// ── RH2: XSS in address param ─────────────────────────────────────────────

#[test]
fn hack_xss_in_address() {
    let c = ctx();
    let resp = dispatch(&c, &rpc_req("cathode_getAccount", json!({
        "address": "<script>alert('xss')</script>"
    })));
    assert!(resp.error.is_some());
}

// ── RH3: Huge payload in TX submit ─────────────────────────────────────────

#[test]
fn hack_huge_tx_payload() {
    let c = ctx();
    // 1MB of hex
    let huge_hex = "aa".repeat(500_000);
    let resp = dispatch(&c, &rpc_req("cathode_submitTransaction", json!({"tx": huge_hex})));
    // Should fail to decode, not crash
    assert!(resp.error.is_some());
}

// ── RH4: Null params ──────────────────────────────────────────────────────

#[test]
fn hack_null_params() {
    let c = ctx();
    let resp = dispatch(&c, &rpc_req("cathode_getBalance", Value::Null));
    assert!(resp.error.is_some());
}

// ── RH5: Array params instead of object ────────────────────────────────────

#[test]
fn hack_array_params() {
    let c = ctx();
    let resp = dispatch(&c, &rpc_req("cathode_getBalance", json!(["address"])));
    assert!(resp.error.is_some());
}

// ── RH6: Unicode in method name ────────────────────────────────────────────

#[test]
fn hack_unicode_method() {
    let c = ctx();
    let resp = dispatch(&c, &rpc_req("cathode_getBalance_\u{200B}\u{FEFF}", json!({})));
    assert!(resp.error.is_some());
    assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
}

// ── RH7: Very long method name ─────────────────────────────────────────────

#[test]
fn hack_long_method_name() {
    let c = ctx();
    let long_method = "a".repeat(10_000);
    let resp = dispatch(&c, &rpc_req(&long_method, json!({})));
    assert!(resp.error.is_some());
}

// ── RH8: Submit empty TX hex ──────────────────────────────────────────────

#[test]
fn hack_empty_tx_hex() {
    let c = ctx();
    let resp = dispatch(&c, &rpc_req("cathode_submitTransaction", json!({"tx": ""})));
    assert!(resp.error.is_some());
}

// ── RH9: Submit with non-string tx param ───────────────────────────────────

#[test]
fn hack_tx_param_types() {
    let c = ctx();

    // Number
    let resp = dispatch(&c, &rpc_req("cathode_submitTransaction", json!({"tx": 12345})));
    assert!(resp.error.is_some());

    // Boolean
    let resp = dispatch(&c, &rpc_req("cathode_submitTransaction", json!({"tx": true})));
    assert!(resp.error.is_some());

    // Object
    let resp = dispatch(&c, &rpc_req("cathode_submitTransaction", json!({"tx": {"nested": true}})));
    assert!(resp.error.is_some());
}

// ── RH10: Get balance for zero address ─────────────────────────────────────

#[test]
fn hack_zero_address_query() {
    let c = ctx();
    let zero_addr = "00".repeat(32);
    let resp = dispatch(&c, &rpc_req("cathode_getBalance", json!({"address": zero_addr})));
    // Should return zero balance, not error
    assert!(resp.result.is_some());
    assert_eq!(resp.result.unwrap()["balance"], "0 CATH");
}

// ── RH11: TX hash all zeros ───────────────────────────────────────────────

#[test]
fn hack_zero_hash_query() {
    let c = ctx();
    let zero_hash = "00".repeat(32);
    let resp = dispatch(&c, &rpc_req("cathode_getTransaction", json!({"hash": zero_hash})));
    assert!(resp.error.is_some());
    assert_eq!(resp.error.unwrap().code, TX_NOT_FOUND);
}

// ── RH12: Rapid-fire 1000 RPC calls ───────────────────────────────────────

#[test]
fn hack_rapid_fire_rpc() {
    let c = ctx();
    let addr = Address::from_bytes([0xAA; 32]);
    c.state.mint(addr, TokenAmount::from_tokens(42)).unwrap();

    for _ in 0..1000 {
        let resp = dispatch(&c, &rpc_req("cathode_getBalance", json!({"address": addr.to_string()})));
        assert!(resp.result.is_some());
    }
}

// ── RH13: Submit valid then query ──────────────────────────────────────────

#[test]
fn hack_submit_then_query() {
    let c = ctx();
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    c.state.mint(sender, TokenAmount::from_tokens(10_000)).unwrap();

    let tx = Transaction::new(
        0, TransactionKind::Transfer {
            to: Address::from_bytes([0xBB; 32]),
            amount: TokenAmount::from_tokens(100),
        },
        21000, 1, 2u64, &kp,
    );
    // Security fix — Signed-off-by: Claude Opus 4.6
    let tx_hex = hex::encode(tx.encode());
    let tx_hash_hex = hex::encode(tx.hash.as_bytes());

    // Submit
    let resp = dispatch(&c, &rpc_req("cathode_submitTransaction", json!({"tx": tx_hex})));
    assert!(resp.result.is_some());

    // Query — should be pending in mempool
    let resp = dispatch(&c, &rpc_req("cathode_getTransaction", json!({"hash": tx_hash_hex})));
    assert!(resp.result.is_some());
    assert_eq!(resp.result.unwrap()["status"], "pending");
}

// ── RH14: Chain info consistency ───────────────────────────────────────────

#[test]
fn hack_chain_info_after_operations() {
    let c = ctx();
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    c.state.mint(sender, TokenAmount::from_tokens(10_000)).unwrap();

    // Submit 5 TXs to mempool
    for i in 0..5u64 {
        let tx = Transaction::new(
            i, TransactionKind::Transfer {
                to: Address::from_bytes([0xBB; 32]),
                amount: TokenAmount::from_tokens(1),
            },
            21000, 1, 2u64, &kp,
        );
        dispatch(&c, &rpc_req("cathode_submitTransaction", json!({"tx": hex::encode(tx.encode())})));
    }

    let resp = dispatch(&c, &rpc_req("cathode_mempoolStatus", json!({})));
    assert_eq!(resp.result.unwrap()["pending"], 5);

    let resp = dispatch(&c, &rpc_req("cathode_chainInfo", json!({})));
    let r = resp.result.unwrap();
    assert_eq!(r["chain_id"], "cathode-hack");
    assert_eq!(r["token_symbol"], "CATH");
}

// ── RH15: Path traversal in address ────────────────────────────────────────

#[test]
fn hack_path_traversal() {
    let c = ctx();
    let resp = dispatch(&c, &rpc_req("cathode_getAccount", json!({
        "address": "../../etc/passwd"
    })));
    assert!(resp.error.is_some());
}
