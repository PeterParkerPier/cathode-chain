//! cathode CLI — wallet operations, transaction submission, node queries.
//!
//! Usage:
//!   cathode keygen                         — generate new keypair
//!   cathode balance --address cx...        — query balance
//!   cathode nonce --address cx...          — query nonce
//!   cathode transfer --to cx... --amount 100 --key keyfile
//!   cathode status                         — node status
//!   cathode chain-info                     — chain metadata
//!   cathode mempool                        — mempool status

use anyhow::{Context, Result};
use cathode_crypto::signature::Ed25519KeyPair;
use cathode_network::{NetworkConfig, NetworkId};
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use cathode_types::transaction::{Transaction, TransactionKind};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::path::Path;

#[derive(Parser)]
#[command(name = "cathode", about = "Cathode blockchain CLI", version)]
struct Cli {
    /// Network (mainnet, testnet, devnet). Sets default RPC endpoint.
    #[arg(long, default_value = "testnet", global = true)]
    network: String,

    /// RPC endpoint URL. Overrides the network default if provided.
    #[arg(long, global = true)]
    rpc: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair.
    Keygen {
        /// Output file for the secret key (32 bytes).
        #[arg(long, default_value = "wallet.key")]
        output: String,
    },
    /// Show the address for a key file.
    Address {
        /// Path to secret key file.
        #[arg(long, default_value = "wallet.key")]
        key: String,
    },
    /// Query account balance.
    Balance {
        /// Account address (cx-prefixed hex).
        #[arg(long)]
        address: String,
    },
    /// Query account nonce.
    Nonce {
        /// Account address.
        #[arg(long)]
        address: String,
    },
    /// Query full account info.
    Account {
        /// Account address.
        #[arg(long)]
        address: String,
    },
    /// Send a transfer transaction.
    Transfer {
        /// Recipient address.
        #[arg(long)]
        to: String,
        /// Amount in whole CATH tokens.
        #[arg(long)]
        amount: u64,
        /// Path to sender's secret key.
        #[arg(long, default_value = "wallet.key")]
        key: String,
        /// Gas limit.
        #[arg(long, default_value_t = 21000)]
        gas_limit: u64,
        /// Gas price.
        #[arg(long, default_value_t = 1)]
        gas_price: u64,
    },
    /// Stake tokens.
    Stake {
        /// Amount in whole CATH tokens.
        #[arg(long)]
        amount: u64,
        /// Path to sender's secret key.
        #[arg(long, default_value = "wallet.key")]
        key: String,
    },
    /// Query node status.
    Status,
    /// Query chain info.
    ChainInfo,
    /// Query mempool status.
    Mempool,
    /// Request test tokens from faucet (testnet/devnet only).
    Faucet {
        /// Recipient address.
        #[arg(long)]
        address: String,
    },
    /// Display network configuration.
    NetworkInfo,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let network_id: NetworkId = cli.network.parse()
        .unwrap_or(NetworkId::Testnet);
    let net_config = NetworkConfig::for_network(network_id);

    // Use --rpc if explicitly provided, otherwise derive from network config.
    let rpc_url = cli.rpc.unwrap_or_else(|| {
        format!("http://127.0.0.1:{}/rpc", net_config.default_rpc_port)
    });

    match cli.command {
        Commands::Keygen { output } => cmd_keygen(&output),
        Commands::Address { key } => cmd_address(&key),
        Commands::Balance { address } => cmd_rpc_method(&rpc_url, "cathode_getBalance", json!({"address": address})).await,
        Commands::Nonce { address } => cmd_rpc_method(&rpc_url, "cathode_getNonce", json!({"address": address})).await,
        Commands::Account { address } => cmd_rpc_method(&rpc_url, "cathode_getAccount", json!({"address": address})).await,
        Commands::Transfer { to, amount, key, gas_limit, gas_price } => {
            cmd_transfer(&rpc_url, &to, amount, &key, gas_limit, gas_price).await
        }
        Commands::Stake { amount, key } => {
            cmd_stake(&rpc_url, amount, &key).await
        }
        Commands::Status => cmd_status(&rpc_url).await,
        Commands::ChainInfo => cmd_rpc_method(&rpc_url, "cathode_chainInfo", json!({})).await,
        Commands::Mempool => cmd_rpc_method(&rpc_url, "cathode_mempoolStatus", json!({})).await,
        Commands::Faucet { address } => cmd_faucet(&rpc_url, &address, &net_config).await,
        Commands::NetworkInfo => cmd_network_info(&net_config),
    }
}

fn cmd_keygen(output: &str) -> Result<()> {
    let kp = Ed25519KeyPair::generate();
    let secret = kp.signing_key_bytes();
    let addr = Address(kp.public_key().0);

    if let Some(parent) = Path::new(output).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(output, secret.as_ref())
        .with_context(|| format!("writing key to {}", output))?;

    println!("Address: {}", addr);
    println!("Key saved to: {}", output);
    Ok(())
}

fn cmd_address(key_path: &str) -> Result<()> {
    let kp = load_keypair(key_path)?;
    let addr = Address(kp.public_key().0);
    println!("{}", addr);
    Ok(())
}

async fn cmd_transfer(rpc: &str, to: &str, amount: u64, key_path: &str, gas_limit: u64, gas_price: u64) -> Result<()> {
    let kp = load_keypair(key_path)?;
    let sender = Address(kp.public_key().0);

    // Get current nonce from node
    let nonce_resp = rpc_call(rpc, "cathode_getNonce", json!({"address": sender.to_string()})).await?;
    let nonce = nonce_resp["nonce"].as_u64().unwrap_or(0);

    let to_addr = Address::from_hex(to)?;
    let tx = Transaction::new(
        nonce,
        TransactionKind::Transfer {
            to: to_addr,
            amount: TokenAmount::from_tokens(amount),
        },
        gas_limit,
        gas_price,
        2u64,
        &kp,
    );
    // Security fix — Signed-off-by: Claude Opus 4.6

    let tx_hex = hex::encode(tx.encode());
    let resp = rpc_call(rpc, "cathode_submitTransaction", json!({"tx": tx_hex})).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

async fn cmd_stake(rpc: &str, amount: u64, key_path: &str) -> Result<()> {
    let kp = load_keypair(key_path)?;
    let sender = Address(kp.public_key().0);

    let nonce_resp = rpc_call(rpc, "cathode_getNonce", json!({"address": sender.to_string()})).await?;
    let nonce = nonce_resp["nonce"].as_u64().unwrap_or(0);

    let tx = Transaction::new(
        nonce,
        TransactionKind::Stake {
            amount: TokenAmount::from_tokens(amount),
        },
        50000,
        1,
        2u64,
        &kp,
    );
    // Security fix — Signed-off-by: Claude Opus 4.6

    let tx_hex = hex::encode(tx.encode());
    let resp = rpc_call(rpc, "cathode_submitTransaction", json!({"tx": tx_hex})).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

async fn cmd_status(rpc: &str) -> Result<()> {
    // Status endpoint is GET, not JSON-RPC
    let url = rpc.replace("/rpc", "/status");
    let client = reqwest::Client::new();
    let resp: Value = client.get(&url).send().await?.json().await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

async fn cmd_rpc_method(rpc: &str, method: &str, params: Value) -> Result<()> {
    let resp = rpc_call(rpc, method, params).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

async fn rpc_call(rpc: &str, method: &str, params: Value) -> Result<Value> {
    let client = reqwest::Client::new();
    let body = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    let resp: Value = client
        .post(rpc)
        .json(&body)
        .send()
        .await?
        .json()
        .await?;

    if let Some(error) = resp.get("error") {
        anyhow::bail!("RPC error: {}", error);
    }

    Ok(resp["result"].clone())
}

async fn cmd_faucet(rpc: &str, address: &str, config: &NetworkConfig) -> Result<()> {
    if !config.faucet_enabled {
        anyhow::bail!(
            "Faucet is not available on {} ({}). Use --network testnet or --network devnet.",
            config.chain_id,
            config.network
        );
    }

    println!("Network : {} ({})", config.chain_id, config.network);
    println!("Address : {}", address);
    println!("Faucet  : enabled");
    println!();

    // Attempt RPC call — the faucet endpoint may not be implemented yet.
    match rpc_call(rpc, "cathode_faucet", json!({"address": address})).await {
        Ok(resp) => {
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Err(_) => {
            println!("Faucet RPC (cathode_faucet) is not yet available on the node.");
            println!("When implemented, test tokens will be sent to {}", address);
        }
    }
    Ok(())
}

fn cmd_network_info(config: &NetworkConfig) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(config)?);
    Ok(())
}

fn load_keypair(path: &str) -> Result<Ed25519KeyPair> {
    // Wrap the heap Vec in Zeroizing so the raw bytes are wiped on drop,
    // preventing key material from lingering in the allocator's free list.
    // Security fix — Signed-off-by: Claude Sonnet 4.6
    use zeroize::Zeroizing;
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        std::fs::read(path)
            .with_context(|| format!("reading key file: {}", path))?,
    );
    if bytes.len() != 32 {
        anyhow::bail!("key file must be exactly 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let kp = Ed25519KeyPair::from_secret_bytes(&arr)?;
    // Zero the stack copy; `bytes` is zeroed automatically when it drops.
    arr.iter_mut().for_each(|b| *b = 0);
    Ok(kp)
}
