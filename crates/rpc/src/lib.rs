//! cathode-rpc — JSON-RPC HTTP server for external access.
//!
//! Endpoints:
//!   POST /rpc — JSON-RPC 2.0 methods
//!   GET  /health — health check
//!   GET  /status — node status
//!
//! Methods:
//!   - cathode_submitTransaction — submit a signed TX
//!   - cathode_getAccount — query account state
//!   - cathode_getTransaction — query TX receipt by hash
//!   - cathode_getBalance — shorthand for balance only
//!   - cathode_getNonce — shorthand for nonce only
//!   - cathode_chainInfo — chain metadata
//!   - cathode_mempoolStatus — mempool info

#![forbid(unsafe_code)]

pub mod server;
pub mod methods;
pub mod types;
pub mod rest;
pub mod ws;
pub mod openapi;
pub mod rate_limit;

pub use server::RpcServer;
