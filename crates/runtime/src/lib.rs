//! cathode-runtime — smart contract execution engine.
//!
//! Currently a structured stub that defines the VM interface.
//! Future: integrate wasmer/wasmtime for WASM contract execution.

#![forbid(unsafe_code)]

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Result of executing a smart contract call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub gas_used: u64,
    pub return_value: Vec<u8>,
    pub logs: Vec<ContractLog>,
}

/// A log emitted by a smart contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractLog {
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// The VM runtime configuration.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Maximum gas per contract call.
    pub max_gas: u64,
    /// Maximum WASM memory pages (64KB each).
    pub max_memory_pages: u32,
    /// Maximum contract code size in bytes.
    pub max_code_size: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_gas: 10_000_000,
            max_memory_pages: 256, // 16 MB
            max_code_size: 1024 * 1024, // 1 MB
        }
    }
}

/// The smart contract runtime.
pub struct Runtime {
    config: RuntimeConfig,
}

impl Runtime {
    pub fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(RuntimeConfig::default())
    }

    /// Validate contract bytecode (check WASM magic, size limits).
    pub fn validate_code(&self, code: &[u8]) -> Result<()> {
        if code.len() > self.config.max_code_size {
            anyhow::bail!(
                "contract code too large: {} bytes, max {}",
                code.len(),
                self.config.max_code_size
            );
        }
        // Check WASM magic bytes
        if code.len() >= 4 && &code[..4] != b"\x00asm" {
            anyhow::bail!("invalid WASM magic bytes");
        }
        Ok(())
    }

    /// Execute a contract call.
    /// Currently a stub — returns success with zero gas.
    /// Future: WASM instantiation + execution with gas metering.
    pub fn execute(
        &self,
        _code: &[u8],
        _method: &str,
        _args: &[u8],
        gas_limit: u64,
    ) -> Result<ExecutionResult> {
        let gas_limit = gas_limit.min(self.config.max_gas);
        Ok(ExecutionResult {
            success: true,
            gas_used: 0,
            return_value: vec![],
            logs: vec![],
        })
    }

    /// Get runtime config.
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_valid_wasm() {
        let rt = Runtime::with_defaults();
        let wasm = b"\x00asm\x01\x00\x00\x00";
        assert!(rt.validate_code(wasm).is_ok());
    }

    #[test]
    fn validate_invalid_magic() {
        let rt = Runtime::with_defaults();
        assert!(rt.validate_code(b"\x00bad\x01\x00\x00\x00").is_err());
    }

    #[test]
    fn validate_too_large() {
        let rt = Runtime::new(RuntimeConfig {
            max_code_size: 10,
            ..Default::default()
        });
        let code = vec![0u8; 100];
        assert!(rt.validate_code(&code).is_err());
    }

    #[test]
    fn execute_stub() {
        let rt = Runtime::with_defaults();
        let wasm = b"\x00asm\x01\x00\x00\x00";
        let result = rt.execute(wasm, "main", &[], 1_000_000).unwrap();
        assert!(result.success);
    }
}
