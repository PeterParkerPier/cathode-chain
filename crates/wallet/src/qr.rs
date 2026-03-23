//! Cathode URI scheme for addresses and invoices.
//!
//! Format: `cathode:{address}?amount={base_units}&memo={text}&invoice={id}`

use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use serde::{Deserialize, Serialize};

/// URI parsing/encoding errors.
#[derive(Debug, thiserror::Error)]
pub enum URIError {
    /// Missing the "cathode:" prefix.
    #[error("missing 'cathode:' prefix")]
    MissingPrefix,
    /// Invalid address in URI.
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    /// Invalid amount value.
    #[error("invalid amount: {0}")]
    InvalidAmount(String),
    /// Malformed URI.
    #[error("malformed URI: {0}")]
    Malformed(String),
}

/// A structured Cathode payment URI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CathodeURI {
    /// Recipient address.
    pub address: Address,
    /// Optional payment amount (in base units).
    pub amount: Option<TokenAmount>,
    /// Optional memo/description.
    pub memo: Option<String>,
    /// Optional invoice identifier.
    pub invoice_id: Option<String>,
}

impl CathodeURI {
    /// Create a new URI with just an address.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            amount: None,
            memo: None,
            invoice_id: None,
        }
    }

    /// Set the payment amount.
    pub fn with_amount(mut self, amount: TokenAmount) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Set the memo.
    pub fn with_memo(mut self, memo: String) -> Self {
        self.memo = Some(memo);
        self
    }

    /// Set the invoice ID.
    pub fn with_invoice(mut self, invoice_id: String) -> Self {
        self.invoice_id = Some(invoice_id);
        self
    }

    /// Encode this URI to a string.
    ///
    /// Format: `cathode:{address}?amount={base_units}&memo={text}&invoice={id}`
    pub fn encode(&self) -> String {
        let mut uri = format!("cathode:{}", self.address);

        let mut params: Vec<String> = Vec::new();

        if let Some(ref amount) = self.amount {
            params.push(format!("amount={}", amount.base()));
        }
        if let Some(ref memo) = self.memo {
            params.push(format!("memo={}", uri_encode(memo)));
        }
        if let Some(ref invoice_id) = self.invoice_id {
            params.push(format!("invoice={}", uri_encode(invoice_id)));
        }

        if !params.is_empty() {
            uri.push('?');
            uri.push_str(&params.join("&"));
        }

        uri
    }

    /// Decode a Cathode URI string.
    pub fn decode(s: &str) -> Result<Self, URIError> {
        let s = s.trim();

        // Must start with "cathode:"
        let rest = s
            .strip_prefix("cathode:")
            .ok_or(URIError::MissingPrefix)?;

        if rest.is_empty() {
            return Err(URIError::Malformed("empty address".to_string()));
        }

        // Split address from query params
        let (addr_str, query) = match rest.find('?') {
            Some(pos) => (&rest[..pos], Some(&rest[pos + 1..])),
            None => (rest, None),
        };

        if addr_str.is_empty() {
            return Err(URIError::Malformed("empty address".to_string()));
        }

        let address = Address::from_hex(addr_str)
            .map_err(|e| URIError::InvalidAddress(e.to_string()))?;

        let mut uri = CathodeURI::new(address);

        // Parse query parameters
        if let Some(query) = query {
            for param in query.split('&') {
                if param.is_empty() {
                    continue;
                }
                let (key, value) = match param.find('=') {
                    Some(pos) => (&param[..pos], &param[pos + 1..]),
                    None => continue,
                };

                match key {
                    "amount" => {
                        let base: u128 = value
                            .parse()
                            .map_err(|_| URIError::InvalidAmount(value.to_string()))?;
                        uri.amount = Some(TokenAmount::from_base(base));
                    }
                    "memo" => {
                        uri.memo = Some(uri_decode(value));
                    }
                    "invoice" => {
                        uri.invoice_id = Some(uri_decode(value));
                    }
                    _ => {
                        // Unknown parameters are ignored for forward compatibility
                    }
                }
            }
        }

        Ok(uri)
    }
}

/// Simple percent-encoding for URI values (spaces and special chars).
fn uri_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ' ' => result.push_str("%20"),
            '&' => result.push_str("%26"),
            '=' => result.push_str("%3D"),
            '?' => result.push_str("%3F"),
            '%' => result.push_str("%25"),
            _ => result.push(c),
        }
    }
    result
}

/// Simple percent-decoding for URI values.
fn uri_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            // Malformed percent encoding — pass through
            result.push('%');
            result.push_str(&hex);
        } else {
            result.push(c);
        }
    }
    result
}
