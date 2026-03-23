//! CSV export helpers for the Cathode scan crate.
//!
//! Converts `TransactionSummary` and `AccountInfo` slices into RFC 4180-style
//! CSV text.  No external CSV crate is used — fields are escaped by hand:
//!   • If a field contains a comma, double-quote, or newline it is wrapped in
//!     double-quotes and any embedded double-quote is doubled ("").
//!
//! Signed-off-by: Claude Sonnet 4.6

use crate::token::AccountInfo;
use crate::transaction::TransactionSummary;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Escape a single CSV field value.
///
/// Rules (RFC 4180):
/// * If the value contains `,`, `"`, `\n`, or `\r` it must be quoted.
/// * Inside a quoted field every `"` becomes `""`.
fn escape_field(s: &str) -> String {
    let needs_quoting = s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r');
    if needs_quoting {
        let escaped = s.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        s.to_owned()
    }
}

/// Join a slice of already-escaped field strings with commas.
fn row(fields: &[String]) -> String {
    fields.join(",")
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Convert a slice of `TransactionSummary` values to CSV text.
///
/// Headers: `hash,sender,kind,status,gas_used,gas_limit,gas_price,nonce,amount,recipient,consensus_order,timestamp_ns`
pub fn transactions_to_csv(txs: &[TransactionSummary]) -> String {
    let header = "hash,sender,kind,status,gas_used,gas_limit,gas_price,nonce,amount,recipient,consensus_order,timestamp_ns";
    let mut out = String::with_capacity(header.len() + 1 + txs.len() * 120);
    out.push_str(header);
    out.push('\n');

    for tx in txs {
        let fields: Vec<String> = vec![
            escape_field(&tx.hash),
            escape_field(&tx.sender),
            escape_field(&tx.kind_name),
            escape_field(&tx.status),
            tx.gas_used.to_string(),
            tx.gas_limit.to_string(),
            tx.gas_price.to_string(),
            tx.nonce.to_string(),
            tx.amount_base.map(|v| v.to_string()).unwrap_or_default(),
            escape_field(tx.recipient.as_deref().unwrap_or("")),
            tx.consensus_order.map(|v| v.to_string()).unwrap_or_default(),
            tx.consensus_timestamp_ns.map(|v| v.to_string()).unwrap_or_default(),
        ];
        out.push_str(&row(&fields));
        out.push('\n');
    }

    out
}

/// Convert a slice of `AccountInfo` values to CSV text.
///
/// Headers: `address,balance_base,nonce,staked_base`
pub fn accounts_to_csv(accounts: &[AccountInfo]) -> String {
    let header = "address,balance_base,nonce,staked_base";
    let mut out = String::with_capacity(header.len() + 1 + accounts.len() * 80);
    out.push_str(header);
    out.push('\n');

    for acc in accounts {
        let fields: Vec<String> = vec![
            escape_field(&acc.address),
            acc.balance_base.to_string(),
            acc.nonce.to_string(),
            acc.staked_base.to_string(),
        ];
        out.push_str(&row(&fields));
        out.push('\n');
    }

    out
}

/// Convert a rich-list slice of `AccountInfo` values to CSV text.
///
/// Identical schema to `accounts_to_csv`; provided as a distinct function so
/// callers can document intent (rich-list vs generic account dump).
pub fn rich_list_to_csv(accounts: &[AccountInfo]) -> String {
    accounts_to_csv(accounts)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::AccountInfo;
    use crate::transaction::TransactionSummary;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_summary(
        hash: &str,
        sender: &str,
        kind: &str,
        status: &str,
        gas_used: u64,
        gas_limit: u64,
        gas_price: u64,
        nonce: u64,
        amount: Option<u128>,
        recipient: Option<&str>,
        order: Option<u64>,
        ts: Option<u64>,
    ) -> TransactionSummary {
        TransactionSummary {
            hash: hash.to_owned(),
            sender: sender.to_owned(),
            kind_name: kind.to_owned(),
            status: status.to_owned(),
            gas_used,
            gas_limit,
            gas_price,
            nonce,
            amount_base: amount,
            recipient: recipient.map(str::to_owned),
            consensus_order: order,
            consensus_timestamp_ns: ts,
        }
    }

    fn make_account(address: &str, balance_base: u128, nonce: u64, staked_base: u128) -> AccountInfo {
        AccountInfo {
            address: address.to_owned(),
            balance: balance_base.to_string(),
            balance_base,
            nonce,
            staked: staked_base.to_string(),
            staked_base,
            has_code: false,
        }
    }

    // -----------------------------------------------------------------------
    // 1. Empty list produces headers only
    // -----------------------------------------------------------------------

    #[test]
    fn empty_transactions_produces_header_only() {
        let csv = transactions_to_csv(&[]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0],
            "hash,sender,kind,status,gas_used,gas_limit,gas_price,nonce,amount,recipient,consensus_order,timestamp_ns"
        );
    }

    #[test]
    fn empty_accounts_produces_header_only() {
        let csv = accounts_to_csv(&[]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "address,balance_base,nonce,staked_base");
    }

    // -----------------------------------------------------------------------
    // 2. Single transaction row is correct
    // -----------------------------------------------------------------------

    #[test]
    fn single_transaction_row_correct() {
        let tx = make_summary(
            "aabbcc",
            "ddeeff",
            "Transfer",
            "success",
            21000,
            21000,
            1,
            0,
            Some(1_000_000),
            Some("112233"),
            Some(42),
            Some(999_000_000),
        );
        let csv = transactions_to_csv(&[tx]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        let data = lines[1];
        // Check every field in order
        assert_eq!(
            data,
            "aabbcc,ddeeff,Transfer,success,21000,21000,1,0,1000000,112233,42,999000000"
        );
    }

    // -----------------------------------------------------------------------
    // 3. Special characters (comma, quote, newline) are properly escaped
    // -----------------------------------------------------------------------

    #[test]
    fn special_characters_properly_escaped() {
        // A status string that contains a comma and a double-quote
        let tx = make_summary(
            "hash1",
            "sender1",
            "Transfer",
            "failed: out of gas, \"retry\"",
            0,
            21000,
            1,
            0,
            None,
            None,
            None,
            None,
        );
        let csv = transactions_to_csv(&[tx]);
        let lines: Vec<&str> = csv.lines().collect();
        let data = lines[1];

        // The status field must be wrapped in quotes and inner quotes doubled
        assert!(data.contains("\"failed: out of gas, \"\"retry\"\"\""),
            "Expected escaped status in: {}", data);

        // Parsing back: split only on top-level commas — a quick sanity check
        // that the field count is still 12 (header columns).
        let header_cols = 12;
        let parsed = parse_csv_line(data);
        assert_eq!(parsed.len(), header_cols,
            "Expected {} fields, got {} in: {}", header_cols, parsed.len(), data);
        assert_eq!(parsed[3], "failed: out of gas, \"retry\"");
    }

    // -----------------------------------------------------------------------
    // 4. Accounts CSV is correct
    // -----------------------------------------------------------------------

    #[test]
    fn accounts_csv_correct() {
        let acc = make_account("aabbccdd", 5_000_000, 3, 1_000_000);
        let csv = accounts_to_csv(&[acc]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "address,balance_base,nonce,staked_base");
        assert_eq!(lines[1], "aabbccdd,5000000,3,1000000");
    }

    // -----------------------------------------------------------------------
    // 5. Multiple rows are all present
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_rows_all_present() {
        let txs: Vec<TransactionSummary> = (0..5)
            .map(|i| make_summary(
                &format!("hash{i}"),
                &format!("sender{i}"),
                "Stake",
                "success",
                10_000 + i,
                50_000,
                2,
                i,
                Some(i as u128 * 1_000),
                None,
                Some(i),
                Some(i * 1_000_000),
            ))
            .collect();

        let csv = transactions_to_csv(&txs);
        let lines: Vec<&str> = csv.lines().collect();
        // 1 header + 5 data rows
        assert_eq!(lines.len(), 6);

        // Verify each data line starts with the correct hash
        for i in 0..5u64 {
            assert!(lines[i as usize + 1].starts_with(&format!("hash{i},")),
                "Row {i} mismatch: {}", lines[i as usize + 1]);
        }
    }

    // -----------------------------------------------------------------------
    // 6. rich_list_to_csv is identical to accounts_to_csv
    // -----------------------------------------------------------------------

    #[test]
    fn rich_list_to_csv_matches_accounts_to_csv() {
        let accounts = vec![
            make_account("addr1", 9_000, 1, 0),
            make_account("addr2", 5_000, 2, 500),
        ];
        assert_eq!(rich_list_to_csv(&accounts), accounts_to_csv(&accounts));
    }

    // -----------------------------------------------------------------------
    // 7. Optional fields (amount, recipient, order, ts) render as empty strings
    // -----------------------------------------------------------------------

    #[test]
    fn optional_fields_render_as_empty() {
        let tx = make_summary(
            "h1", "s1", "Vote", "pending",
            0, 1000, 1, 7,
            None, None, None, None,
        );
        let csv = transactions_to_csv(&[tx]);
        let line = csv.lines().nth(1).unwrap();
        let fields: Vec<&str> = line.split(',').collect();
        // amount (index 8), recipient (9), consensus_order (10), timestamp_ns (11)
        assert_eq!(fields[8], "");
        assert_eq!(fields[9], "");
        assert_eq!(fields[10], "");
        assert_eq!(fields[11], "");
    }

    // -----------------------------------------------------------------------
    // Helper: minimal RFC-4180 CSV parser for verification in tests
    // -----------------------------------------------------------------------

    fn parse_csv_line(line: &str) -> Vec<String> {
        let mut fields = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut chars = line.chars().peekable();

        while let Some(c) = chars.next() {
            match c {
                '"' if !in_quotes => {
                    in_quotes = true;
                }
                '"' if in_quotes => {
                    if chars.peek() == Some(&'"') {
                        chars.next(); // consume second quote
                        current.push('"');
                    } else {
                        in_quotes = false;
                    }
                }
                ',' if !in_quotes => {
                    fields.push(current.clone());
                    current.clear();
                }
                other => {
                    current.push(other);
                }
            }
        }
        fields.push(current);
        fields
    }
}
