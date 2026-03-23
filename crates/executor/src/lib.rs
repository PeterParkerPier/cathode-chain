//! cathode-executor — transaction validation and execution pipeline.
//!
//! Takes consensus-ordered events, extracts typed transactions,
//! validates them, and applies state transitions.
//!
//! Pipeline:
//!   1. Decode event payload → Transaction
//!   2. Verify signature + hash integrity
//!   3. Check nonce, balance, gas
//!   4. Execute (transfer, stake, deploy, etc.)
//!   5. Produce Receipt
//!   6. Update WorldState
//!
//! # Security notes — MEDIUM severity
//!
//! ## Gas metering per opcode (TODO)
//! The current executor charges a **flat gas cost per transaction kind** (see
//! `pipeline::Executor::compute_gas`).  For `ContractCall` and `Deploy`,
//! individual WASM opcode costs are NOT yet metered — every opcode is implicitly
//! free beyond the flat `call_base` / `deploy_base` fee.  Before enabling live
//! WASM execution this MUST be replaced with per-opcode metering (e.g. using a
//! fuel-counting WASM runtime such as Wasmtime's `store.add_fuel(gas_limit)`).
//! Without opcode-level metering a malicious contract can consume unbounded CPU
//! within its gas budget.
//! Security fix — Signed-off-by: Claude Sonnet 4.6
//!
//! ## Execution timeout (TODO)
//! There is currently no wall-clock timeout on contract execution.  A contract
//! that performs long-running compute (e.g. via an infinite loop that burns gas
//! slowly) could block a consensus thread for seconds.  Before enabling live WASM
//! execution, wrap each `ContractCall` / `Deploy` execution in a scoped thread (or
//! async task) with a hard timeout (suggested: 2 s).  If the timeout fires, mark
//! the receipt as failed and charge the full `gas_limit` to the sender.
//! Security fix — Signed-off-by: Claude Sonnet 4.6

#![forbid(unsafe_code)]

pub mod gas;
pub mod state;
pub mod pipeline;

pub use gas::{GasSchedule, GAS_TRANSFER, GAS_DEPLOY_BASE, GAS_DEPLOY_PER_BYTE};
pub use state::AccountState;
pub use pipeline::Executor;
