//! PaymentScan — payment system scanner for the Cathode network.
//!
//! Queries invoices, escrows, streaming payments, and multisig wallets.

use crate::error::ScanError;
use cathode_payment::escrow::EscrowManager;
use cathode_payment::invoice::InvoiceRegistry;
use cathode_payment::multisig::MultisigManager;
use cathode_payment::streaming::StreamManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Invoice summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceSummary {
    pub invoice_id: String,
    pub creator: String,
    pub recipient: String,
    pub amount_base: u128,
    pub status: String,
    pub memo: String,
}

/// Escrow summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowSummary {
    pub escrow_id: String,
    pub buyer: String,
    pub seller: String,
    pub arbiter: String,
    pub amount_base: u128,
    pub status: String,
}

/// Stream summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSummary {
    pub stream_id: String,
    pub sender: String,
    pub recipient: String,
    pub total_base: u128,
    pub withdrawn_base: u128,
    pub rate_per_block_base: u128,
    pub status: String,
}

/// Multisig wallet summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigSummary {
    pub wallet_id: String,
    pub owner_count: usize,
    pub required_sigs: u8,
}

/// Payment system overview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentOverview {
    pub total_invoices: usize,
    pub total_escrows: usize,
    pub total_streams: usize,
    pub total_multisig_wallets: usize,
}

/// Payment scanner.
pub struct PaymentScanView {
    invoices: Arc<InvoiceRegistry>,
    escrows: Arc<EscrowManager>,
    streams: Arc<StreamManager>,
    multisig: Arc<MultisigManager>,
}

impl PaymentScanView {
    pub fn new(
        invoices: Arc<InvoiceRegistry>,
        escrows: Arc<EscrowManager>,
        streams: Arc<StreamManager>,
        multisig: Arc<MultisigManager>,
    ) -> Self {
        Self { invoices, escrows, streams, multisig }
    }

    /// Get payment system overview.
    pub fn overview(&self) -> PaymentOverview {
        PaymentOverview {
            total_invoices: self.invoices.len(),
            total_escrows: self.escrows.len(),
            total_streams: self.streams.len(),
            total_multisig_wallets: self.multisig.wallet_count(),
        }
    }

    /// Get invoice details.
    pub fn get_invoice(&self, id_hex: &str) -> Result<InvoiceSummary, ScanError> {
        let hash = crate::util::parse_hash(id_hex)?;
        let inv = self.invoices.get(&hash)
            .ok_or_else(|| ScanError::InvoiceNotFound(id_hex.into()))?;

        Ok(InvoiceSummary {
            invoice_id: id_hex.to_string(),
            creator: hex::encode(inv.creator.0),
            recipient: hex::encode(inv.recipient.0),
            amount_base: inv.amount.base(),
            status: format!("{:?}", inv.status),
            memo: inv.memo.clone(),
        })
    }

    /// Get escrow details.
    pub fn get_escrow(&self, id_hex: &str) -> Result<EscrowSummary, ScanError> {
        let hash = crate::util::parse_hash(id_hex)?;
        let esc = self.escrows.get(&hash)
            .ok_or_else(|| ScanError::EscrowNotFound(id_hex.into()))?;

        Ok(EscrowSummary {
            escrow_id: id_hex.to_string(),
            buyer: hex::encode(esc.buyer.0),
            seller: hex::encode(esc.seller.0),
            arbiter: hex::encode(esc.arbiter.0),
            amount_base: esc.amount.base(),
            status: format!("{:?}", esc.status),
        })
    }

    /// Get stream details.
    pub fn get_stream(&self, id_hex: &str) -> Result<StreamSummary, ScanError> {
        let hash = crate::util::parse_hash(id_hex)?;
        let stream = self.streams.get(&hash)
            .ok_or_else(|| ScanError::StreamNotFound(id_hex.into()))?;

        Ok(StreamSummary {
            stream_id: id_hex.to_string(),
            sender: hex::encode(stream.sender.0),
            recipient: hex::encode(stream.recipient.0),
            total_base: stream.total_amount.base(),
            withdrawn_base: stream.withdrawn.base(),
            rate_per_block_base: stream.rate_per_block.base(),
            status: format!("{:?}", stream.status),
        })
    }

    /// Get multisig wallet details.
    pub fn get_multisig(&self, id_hex: &str) -> Result<MultisigSummary, ScanError> {
        let hash = crate::util::parse_hash(id_hex)?;
        let wallet = self.multisig.get_wallet(&hash)
            .ok_or_else(|| ScanError::MultisigNotFound(id_hex.into()))?;

        Ok(MultisigSummary {
            wallet_id: id_hex.to_string(),
            owner_count: wallet.owners.len(),
            required_sigs: wallet.required_sigs,
        })
    }

    /// Check total invoice count.
    pub fn invoice_count(&self) -> usize {
        self.invoices.len()
    }

    /// Check total escrow count.
    pub fn escrow_count(&self) -> usize {
        self.escrows.len()
    }

    /// Check total stream count.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_types::address::Address;
    use cathode_types::token::TokenAmount;

    fn setup() -> PaymentScanView {
        PaymentScanView::new(
            Arc::new(InvoiceRegistry::new()),
            Arc::new(EscrowManager::new()),
            Arc::new(StreamManager::new()),
            Arc::new(MultisigManager::new()),
        )
    }

    #[test]
    fn overview_empty() {
        let scan = setup();
        let ov = scan.overview();
        assert_eq!(ov.total_invoices, 0);
        assert_eq!(ov.total_escrows, 0);
        assert_eq!(ov.total_streams, 0);
        assert_eq!(ov.total_multisig_wallets, 0);
    }

    #[test]
    fn invoice_not_found() {
        let scan = setup();
        assert!(scan.get_invoice(&hex::encode([0xAA; 32])).is_err());
    }

    #[test]
    fn escrow_not_found() {
        let scan = setup();
        assert!(scan.get_escrow(&hex::encode([0xBB; 32])).is_err());
    }

    #[test]
    fn stream_not_found() {
        let scan = setup();
        assert!(scan.get_stream(&hex::encode([0xCC; 32])).is_err());
    }

    #[test]
    fn multisig_not_found() {
        let scan = setup();
        assert!(scan.get_multisig(&hex::encode([0xDD; 32])).is_err());
    }

    #[test]
    fn invalid_hex_rejected() {
        let scan = setup();
        assert!(scan.get_invoice("bad-hex!!!").is_err());
        assert!(scan.get_escrow("bad-hex!!!").is_err());
        assert!(scan.get_stream("bad-hex!!!").is_err());
        assert!(scan.get_multisig("bad-hex!!!").is_err());
    }

    #[test]
    fn wrong_length_rejected() {
        let scan = setup();
        assert!(scan.get_invoice("aabb").is_err());
    }

    #[test]
    fn invoice_found_after_create() {
        let invoices = Arc::new(InvoiceRegistry::new());
        let creator = Address::from_bytes([0x11; 32]);
        let recipient = Address::from_bytes([0x22; 32]);
        let (inv, _fee) = invoices.create(
            creator,
            recipient,
            TokenAmount::from_tokens(100),
            "test".to_string(),
            0,
            1000,
            None,
        ).unwrap();

        let scan = PaymentScanView::new(
            invoices,
            Arc::new(EscrowManager::new()),
            Arc::new(StreamManager::new()),
            Arc::new(MultisigManager::new()),
        );
        let inv_hex = hex::encode(inv.id.0);
        let summary = scan.get_invoice(&inv_hex).unwrap();
        assert_eq!(summary.creator, hex::encode([0x11; 32]));
        assert_eq!(summary.amount_base, TokenAmount::from_tokens(100).base());
        assert!(summary.status.contains("Pending"));
    }

    #[test]
    fn escrow_found_after_lock() {
        let escrows = Arc::new(EscrowManager::new());
        let buyer = Address::from_bytes([0x33; 32]);
        let seller = Address::from_bytes([0x44; 32]);
        let arbiter = Address::from_bytes([0x55; 32]);
        let esc = escrows.lock(
            buyer, seller, arbiter,
            TokenAmount::from_tokens(500),
            0, 100,
        ).unwrap();

        let scan = PaymentScanView::new(
            Arc::new(InvoiceRegistry::new()),
            escrows,
            Arc::new(StreamManager::new()),
            Arc::new(MultisigManager::new()),
        );
        let summary = scan.get_escrow(&hex::encode(esc.id.0)).unwrap();
        assert_eq!(summary.buyer, hex::encode([0x33; 32]));
        assert_eq!(summary.seller, hex::encode([0x44; 32]));
    }

    #[test]
    fn stream_found_after_open() {
        let streams = Arc::new(StreamManager::new());
        let sender = Address::from_bytes([0x66; 32]);
        let recipient = Address::from_bytes([0x77; 32]);
        let stream_id = streams.open(
            sender, recipient,
            TokenAmount::from_tokens(1000),
            TokenAmount::from_tokens(10),
            0,
        ).unwrap();

        let scan = PaymentScanView::new(
            Arc::new(InvoiceRegistry::new()),
            Arc::new(EscrowManager::new()),
            streams,
            Arc::new(MultisigManager::new()),
        );
        let summary = scan.get_stream(&hex::encode(stream_id.id.0)).unwrap();
        assert_eq!(summary.sender, hex::encode([0x66; 32]));
        assert_eq!(summary.total_base, TokenAmount::from_tokens(1000).base());
    }

    #[test]
    fn multisig_found_after_create() {
        let multisig = Arc::new(MultisigManager::new());
        let owner1 = Address::from_bytes([0x88; 32]);
        let owner2 = Address::from_bytes([0x99; 32]);
        let wallet = multisig.create_wallet(vec![owner1, owner2], 2).unwrap();
        let wallet_id = wallet.address;

        let scan = PaymentScanView::new(
            Arc::new(InvoiceRegistry::new()),
            Arc::new(EscrowManager::new()),
            Arc::new(StreamManager::new()),
            multisig,
        );
        let summary = scan.get_multisig(&hex::encode(wallet_id.0)).unwrap();
        assert_eq!(summary.owner_count, 2);
        assert_eq!(summary.required_sigs, 2);
    }

    #[test]
    fn overview_after_creates() {
        let invoices = Arc::new(InvoiceRegistry::new());
        let escrows = Arc::new(EscrowManager::new());
        let streams = Arc::new(StreamManager::new());
        let multisig = Arc::new(MultisigManager::new());

        invoices.create(
            Address::from_bytes([0x01; 32]),
            Address::from_bytes([0x02; 32]),
            TokenAmount::from_tokens(10), "test".to_string(), 0, 1000, None,
        ).unwrap();
        escrows.lock(
            Address::from_bytes([0x03; 32]),
            Address::from_bytes([0x04; 32]),
            Address::from_bytes([0x05; 32]),
            TokenAmount::from_tokens(20), 0, 100,
        ).unwrap();
        streams.open(
            Address::from_bytes([0x06; 32]),
            Address::from_bytes([0x07; 32]),
            TokenAmount::from_tokens(30),
            TokenAmount::from_tokens(1), 0,
        ).unwrap();
        multisig.create_wallet(
            vec![Address::from_bytes([0x08; 32]), Address::from_bytes([0x09; 32])],
            1,
        ).unwrap();

        let scan = PaymentScanView::new(invoices, escrows, streams, multisig);
        let ov = scan.overview();
        assert_eq!(ov.total_invoices, 1);
        assert_eq!(ov.total_escrows, 1);
        assert_eq!(ov.total_streams, 1);
        assert_eq!(ov.total_multisig_wallets, 1);
    }

    #[test]
    fn counts_match() {
        let scan = setup();
        assert_eq!(scan.invoice_count(), 0);
        assert_eq!(scan.escrow_count(), 0);
        assert_eq!(scan.stream_count(), 0);
    }
}
