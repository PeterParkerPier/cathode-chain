//! Address book — named contacts for frequently used addresses.

use cathode_types::address::Address;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// A contact entry in the address book.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    /// The contact's blockchain address.
    pub address: Address,
    /// Human-readable label.
    pub label: String,
    /// Optional notes.
    pub notes: Option<String>,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

/// Thread-safe address book.
pub struct ContactBook {
    contacts: DashMap<Address, Contact>,
}

impl ContactBook {
    /// Create a new empty contact book.
    pub fn new() -> Self {
        Self {
            contacts: DashMap::new(),
        }
    }

    /// Add a contact. Overwrites if the address already exists.
    pub fn add(&self, contact: Contact) {
        self.contacts.insert(contact.address, contact);
    }

    /// Remove a contact by address. Returns the removed contact, if any.
    pub fn remove(&self, address: &Address) -> Option<Contact> {
        self.contacts.remove(address).map(|(_, c)| c)
    }

    /// Get a contact by address.
    pub fn get(&self, address: &Address) -> Option<Contact> {
        self.contacts.get(address).map(|c| c.value().clone())
    }

    /// List all contacts.
    pub fn list(&self) -> Vec<Contact> {
        self.contacts.iter().map(|e| e.value().clone()).collect()
    }

    /// Search contacts by label (case-insensitive substring match).
    pub fn search_by_label(&self, query: &str) -> Vec<Contact> {
        let query_lower = query.to_lowercase();
        self.contacts
            .iter()
            .filter(|e| e.value().label.to_lowercase().contains(&query_lower))
            .map(|e| e.value().clone())
            .collect()
    }

    /// Number of contacts.
    pub fn len(&self) -> usize {
        self.contacts.len()
    }

    /// Is the contact book empty?
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }
}

impl Default for ContactBook {
    fn default() -> Self {
        Self::new()
    }
}
