//! OpenAPI 3.0 specification for the Cathode REST API.
//!
//! Returns the full spec as a `serde_json::Value` so it can be served
//! directly from the `/api/v1/openapi.json` endpoint without any
//! compile-time code-gen dependency.
//!
//! Signed-off-by: Claude Sonnet 4.6

use serde_json::{json, Value};

/// Return the OpenAPI 3.0 specification for the Cathode Network REST API.
pub fn openapi_spec() -> Value {
    json!({
        "openapi": "3.0.3",
        "info": {
            "title": "Cathode Network API",
            "version": "1.2.0",
            "description": "REST API for the Cathode hashgraph blockchain network. Provides access to transactions, accounts, events, network status, and more.",
            "contact": {
                "name": "Cathode Network"
            },
            "license": {
                "name": "INTRA Protocol License"
            }
        },
        "servers": [
            {
                "url": "http://localhost:7900",
                "description": "Local Cathode node"
            }
        ],
        "paths": {
            "/api/v1/transactions/{hash}": {
                "get": {
                    "summary": "Get transaction by hash",
                    "description": "Retrieve full details of a single transaction identified by its hex-encoded hash.",
                    "operationId": "getTransaction",
                    "tags": ["Transactions"],
                    "parameters": [
                        {
                            "name": "hash",
                            "in": "path",
                            "required": true,
                            "description": "Hex-encoded transaction hash (64 characters).",
                            "schema": {
                                "type": "string",
                                "example": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Transaction found.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/TransactionDetail"
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Invalid hash format.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "404": {
                            "description": "Transaction not found.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "503": {
                            "description": "Node components not available.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/transactions": {
                "get": {
                    "summary": "List recent transactions",
                    "description": "Return a paginated list of recent transactions across the network, ordered by round.",
                    "operationId": "listTransactions",
                    "tags": ["Transactions"],
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "required": false,
                            "description": "Maximum number of transactions to return (default 50).",
                            "schema": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 1000,
                                "example": 50
                            }
                        },
                        {
                            "name": "order",
                            "in": "query",
                            "required": false,
                            "description": "Sort order: `asc` or `desc` (default `desc`).",
                            "schema": {
                                "type": "string",
                                "enum": ["asc", "desc"],
                                "example": "desc"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "List of transactions.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "$ref": "#/components/schemas/TransactionDetail"
                                        }
                                    }
                                }
                            }
                        },
                        "503": {
                            "description": "Node components not available.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/accounts/{address}": {
                "get": {
                    "summary": "Get account information",
                    "description": "Retrieve full account information including balance, nonce, and optional staking details.",
                    "operationId": "getAccount",
                    "tags": ["Accounts"],
                    "parameters": [
                        {
                            "name": "address",
                            "in": "path",
                            "required": true,
                            "description": "Hex-encoded account address (64 hex characters, no 0x prefix).",
                            "schema": {
                                "type": "string",
                                "example": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Account information.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/AccountInfo"
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Invalid address format.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "404": {
                            "description": "Account not found.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/accounts/{address}/balance": {
                "get": {
                    "summary": "Get account balance",
                    "description": "Return only the token balance for the given account address.",
                    "operationId": "getBalance",
                    "tags": ["Accounts"],
                    "parameters": [
                        {
                            "name": "address",
                            "in": "path",
                            "required": true,
                            "description": "Hex-encoded account address.",
                            "schema": {
                                "type": "string",
                                "example": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Balance response.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/BalanceResponse"
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Invalid address format.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "404": {
                            "description": "Account not found.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/events/{hash}": {
                "get": {
                    "summary": "Get hashgraph event by hash",
                    "description": "Retrieve a summary of a hashgraph event (gossip event) identified by its hash.",
                    "operationId": "getEvent",
                    "tags": ["Events"],
                    "parameters": [
                        {
                            "name": "hash",
                            "in": "path",
                            "required": true,
                            "description": "Hex-encoded event hash.",
                            "schema": {
                                "type": "string",
                                "example": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Event summary.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/EventSummary"
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Invalid hash format.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "404": {
                            "description": "Event not found.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "503": {
                            "description": "Node components not available.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/network/health": {
                "get": {
                    "summary": "Network health check",
                    "description": "Return the current health status of the Cathode network including peer count, round lag, and liveness.",
                    "operationId": "networkHealth",
                    "tags": ["Network"],
                    "responses": {
                        "200": {
                            "description": "Network health report.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/NetworkHealth"
                                    }
                                }
                            }
                        },
                        "503": {
                            "description": "Node components not available.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/network/consensus": {
                "get": {
                    "summary": "Consensus progress",
                    "description": "Return the current consensus round progress, including the latest finalized round and pending events.",
                    "operationId": "consensusProgress",
                    "tags": ["Network"],
                    "responses": {
                        "200": {
                            "description": "Consensus progress report.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/ConsensusProgress"
                                    }
                                }
                            }
                        },
                        "503": {
                            "description": "Node components not available.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/network/validators": {
                "get": {
                    "summary": "Active validators",
                    "description": "Return the list of currently active validators participating in consensus.",
                    "operationId": "listValidators",
                    "tags": ["Network"],
                    "responses": {
                        "200": {
                            "description": "List of active validators.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "$ref": "#/components/schemas/ValidatorInfo"
                                        }
                                    }
                                }
                            }
                        },
                        "503": {
                            "description": "Node components not available.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/supply": {
                "get": {
                    "summary": "Token supply information",
                    "description": "Return total, circulating, and staked CATH token supply figures.",
                    "operationId": "getSupply",
                    "tags": ["Token"],
                    "responses": {
                        "200": {
                            "description": "Supply information.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/SupplyInfo"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/search": {
                "get": {
                    "summary": "Universal search",
                    "description": "Search for transactions, accounts, or events by hash, address, or keyword.",
                    "operationId": "search",
                    "tags": ["Search"],
                    "parameters": [
                        {
                            "name": "q",
                            "in": "query",
                            "required": true,
                            "description": "Search query — can be a transaction hash, account address, or event hash.",
                            "schema": {
                                "type": "string",
                                "example": "a1b2c3d4"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Search result.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/SearchResult"
                                    }
                                }
                            }
                        },
                        "503": {
                            "description": "Node components not available.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/rich-list": {
                "get": {
                    "summary": "Rich list",
                    "description": "Return the top accounts ranked by CATH token balance.",
                    "operationId": "richList",
                    "tags": ["Token"],
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "required": false,
                            "description": "Maximum number of accounts to return (default 100, max 1000).",
                            "schema": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 1000,
                                "example": 100
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Ranked list of top holders.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "$ref": "#/components/schemas/RichListEntry"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/mempool": {
                "get": {
                    "summary": "Mempool overview",
                    "description": "Return an overview of the pending transaction mempool, including count, fee statistics, and top pending transactions.",
                    "operationId": "mempoolOverview",
                    "tags": ["Transactions"],
                    "responses": {
                        "200": {
                            "description": "Mempool overview.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/MempoolOverview"
                                    }
                                }
                            }
                        },
                        "503": {
                            "description": "Node components not available.",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "TransactionDetail": {
                    "type": "object",
                    "description": "Full details of a finalized or pending transaction.",
                    "properties": {
                        "hash": {
                            "type": "string",
                            "description": "Hex-encoded transaction hash.",
                            "example": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
                        },
                        "sender": {
                            "type": "string",
                            "description": "Sender account address.",
                            "example": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        },
                        "nonce": {
                            "type": "integer",
                            "description": "Transaction nonce.",
                            "example": 42
                        },
                        "kind": {
                            "type": "string",
                            "description": "Transaction kind (e.g. Transfer, Stake, Unstake, Deploy).",
                            "example": "Transfer"
                        },
                        "amount": {
                            "type": "string",
                            "description": "Token amount involved (human-readable with symbol).",
                            "example": "100 CATH"
                        },
                        "gas_limit": {
                            "type": "integer",
                            "description": "Gas limit set by the sender.",
                            "example": 21000
                        },
                        "gas_price": {
                            "type": "integer",
                            "description": "Gas price in base units.",
                            "example": 1
                        },
                        "status": {
                            "type": "string",
                            "description": "Execution status: pending, success, or failed.",
                            "enum": ["pending", "success", "failed"],
                            "example": "success"
                        },
                        "round": {
                            "type": "integer",
                            "description": "Consensus round in which the transaction was finalized.",
                            "example": 1234
                        },
                        "timestamp": {
                            "type": "integer",
                            "description": "Unix timestamp (seconds) when the event was created.",
                            "example": 1711000000
                        }
                    }
                },
                "AccountInfo": {
                    "type": "object",
                    "description": "Full account state information.",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Account address.",
                            "example": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        },
                        "balance": {
                            "type": "string",
                            "description": "Token balance (human-readable).",
                            "example": "1000 CATH"
                        },
                        "nonce": {
                            "type": "integer",
                            "description": "Current account nonce (number of sent transactions).",
                            "example": 7
                        },
                        "staked": {
                            "type": "string",
                            "description": "Amount currently staked (if any).",
                            "example": "500 CATH"
                        },
                        "tx_count": {
                            "type": "integer",
                            "description": "Total number of transactions involving this account.",
                            "example": 42
                        }
                    }
                },
                "BalanceResponse": {
                    "type": "object",
                    "description": "Simple balance response.",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Account address.",
                            "example": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        },
                        "balance": {
                            "type": "string",
                            "description": "Token balance (human-readable).",
                            "example": "1000 CATH"
                        }
                    },
                    "required": ["address", "balance"]
                },
                "EventSummary": {
                    "type": "object",
                    "description": "Summary of a hashgraph gossip event.",
                    "properties": {
                        "hash": {
                            "type": "string",
                            "description": "Hex-encoded event hash.",
                            "example": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                        },
                        "creator": {
                            "type": "string",
                            "description": "Public key of the node that created the event.",
                            "example": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        },
                        "round": {
                            "type": "integer",
                            "description": "Consensus round assigned to this event.",
                            "example": 1234
                        },
                        "timestamp": {
                            "type": "integer",
                            "description": "Event creation timestamp (Unix seconds).",
                            "example": 1711000000
                        },
                        "tx_count": {
                            "type": "integer",
                            "description": "Number of transactions contained in this event.",
                            "example": 3
                        },
                        "famous": {
                            "type": "boolean",
                            "description": "Whether this event is a famous witness.",
                            "example": true
                        }
                    }
                },
                "NetworkHealth": {
                    "type": "object",
                    "description": "Current health status of the Cathode network.",
                    "properties": {
                        "status": {
                            "type": "string",
                            "description": "Overall health status.",
                            "enum": ["healthy", "degraded", "unhealthy"],
                            "example": "healthy"
                        },
                        "peer_count": {
                            "type": "integer",
                            "description": "Number of connected peers.",
                            "example": 12
                        },
                        "latest_round": {
                            "type": "integer",
                            "description": "Latest finalized consensus round.",
                            "example": 9876
                        },
                        "round_lag": {
                            "type": "integer",
                            "description": "Number of rounds behind the network tip.",
                            "example": 0
                        },
                        "uptime_secs": {
                            "type": "integer",
                            "description": "Node uptime in seconds.",
                            "example": 86400
                        }
                    }
                },
                "ConsensusProgress": {
                    "type": "object",
                    "description": "Current consensus round progress.",
                    "properties": {
                        "latest_round": {
                            "type": "integer",
                            "description": "Latest finalized round number.",
                            "example": 9876
                        },
                        "pending_events": {
                            "type": "integer",
                            "description": "Number of events not yet assigned to a round.",
                            "example": 5
                        },
                        "famous_witnesses": {
                            "type": "integer",
                            "description": "Number of famous witness events in the latest round.",
                            "example": 4
                        },
                        "supermajority_reached": {
                            "type": "boolean",
                            "description": "Whether 2/3+ stake has voted on the current round.",
                            "example": true
                        }
                    }
                },
                "ValidatorInfo": {
                    "type": "object",
                    "description": "Information about a single active validator.",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Validator account address.",
                            "example": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        },
                        "stake": {
                            "type": "string",
                            "description": "Staked amount (human-readable).",
                            "example": "10000 CATH"
                        },
                        "stake_weight": {
                            "type": "number",
                            "description": "Fraction of total stake (0.0 – 1.0).",
                            "example": 0.125
                        },
                        "active": {
                            "type": "boolean",
                            "description": "Whether the validator is currently active.",
                            "example": true
                        }
                    }
                },
                "SupplyInfo": {
                    "type": "object",
                    "description": "CATH token supply figures.",
                    "properties": {
                        "total": {
                            "type": "string",
                            "description": "Total token supply (human-readable).",
                            "example": "1000000000 CATH"
                        },
                        "circulating": {
                            "type": "string",
                            "description": "Circulating supply (not staked or locked).",
                            "example": "600000000 CATH"
                        },
                        "staked": {
                            "type": "string",
                            "description": "Total staked supply.",
                            "example": "400000000 CATH"
                        }
                    }
                },
                "SearchResult": {
                    "type": "object",
                    "description": "Result of a universal search query.",
                    "properties": {
                        "kind": {
                            "type": "string",
                            "description": "What the query matched: transaction, account, event, or unknown.",
                            "enum": ["transaction", "account", "event", "unknown"],
                            "example": "transaction"
                        },
                        "data": {
                            "type": "object",
                            "description": "The matched entity (TransactionDetail, AccountInfo, or EventSummary depending on kind)."
                        }
                    }
                },
                "RichListEntry": {
                    "type": "object",
                    "description": "A single entry in the rich list.",
                    "properties": {
                        "rank": {
                            "type": "integer",
                            "description": "Rank by balance (1 = richest).",
                            "example": 1
                        },
                        "address": {
                            "type": "string",
                            "description": "Account address.",
                            "example": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        },
                        "balance": {
                            "type": "string",
                            "description": "Token balance (human-readable).",
                            "example": "50000000 CATH"
                        },
                        "percentage": {
                            "type": "number",
                            "description": "Percentage of total supply held.",
                            "example": 5.0
                        }
                    }
                },
                "MempoolOverview": {
                    "type": "object",
                    "description": "Overview of the pending transaction mempool.",
                    "properties": {
                        "pending": {
                            "type": "integer",
                            "description": "Number of pending transactions.",
                            "example": 42
                        },
                        "min_gas_price": {
                            "type": "integer",
                            "description": "Minimum gas price among pending transactions.",
                            "example": 1
                        },
                        "max_gas_price": {
                            "type": "integer",
                            "description": "Maximum gas price among pending transactions.",
                            "example": 10
                        },
                        "avg_gas_price": {
                            "type": "number",
                            "description": "Average gas price among pending transactions.",
                            "example": 2.5
                        },
                        "top_transactions": {
                            "type": "array",
                            "description": "Top pending transactions by gas price.",
                            "items": {
                                "$ref": "#/components/schemas/TransactionDetail"
                            }
                        }
                    }
                },
                "ErrorResponse": {
                    "type": "object",
                    "description": "Standard error response body.",
                    "properties": {
                        "error": {
                            "type": "string",
                            "description": "Human-readable error message.",
                            "example": "transaction not found"
                        }
                    },
                    "required": ["error"]
                }
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_has_correct_info() {
        let spec = openapi_spec();
        assert_eq!(spec["info"]["title"], "Cathode Network API");
        assert_eq!(spec["info"]["version"], "1.2.0");
        assert_eq!(spec["openapi"], "3.0.3");
        assert_eq!(spec["servers"][0]["url"], "http://localhost:7900");
    }

    #[test]
    fn spec_has_all_12_paths() {
        let spec = openapi_spec();
        let paths = spec["paths"].as_object().expect("paths must be an object");

        let expected_paths = [
            "/api/v1/transactions/{hash}",
            "/api/v1/transactions",
            "/api/v1/accounts/{address}",
            "/api/v1/accounts/{address}/balance",
            "/api/v1/events/{hash}",
            "/api/v1/network/health",
            "/api/v1/network/consensus",
            "/api/v1/network/validators",
            "/api/v1/supply",
            "/api/v1/search",
            "/api/v1/rich-list",
            "/api/v1/mempool",
        ];

        assert_eq!(paths.len(), 12, "expected exactly 12 paths, found {}", paths.len());

        for path in &expected_paths {
            assert!(
                paths.contains_key(*path),
                "missing expected path: {}",
                path
            );
        }
    }

    #[test]
    fn spec_has_schemas_section() {
        let spec = openapi_spec();
        let schemas = spec["components"]["schemas"]
            .as_object()
            .expect("components.schemas must be an object");

        let expected_schemas = [
            "TransactionDetail",
            "AccountInfo",
            "BalanceResponse",
            "EventSummary",
            "NetworkHealth",
            "ConsensusProgress",
            "ValidatorInfo",
            "SupplyInfo",
            "SearchResult",
            "RichListEntry",
            "MempoolOverview",
            "ErrorResponse",
        ];

        for schema in &expected_schemas {
            assert!(
                schemas.contains_key(*schema),
                "missing expected schema: {}",
                schema
            );
        }
    }
}
