//! API Nonce Manager
//!
//! Ensures every API request to an exchange uses a strictly increasing nonce
//! value. The spec mandates `AtomicU64` counters to prevent replay attacks
//! and rejected orders due to nonce collisions.
//!
//! Some exchanges (e.g. Bitfinex, Kraken) require incrementing nonces.
//! Others (Binance, OKX) use timestamps. This module handles the incrementing
//! nonce pattern.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-exchange atomic nonce counter.
struct ExchangeNonce {
    current: AtomicU64,
    /// Exchange name for logging.
    name: String,
}

impl ExchangeNonce {
    fn new(name: &str, initial: u64) -> Self {
        Self {
            current: AtomicU64::new(initial),
            name: name.to_string(),
        }
    }

    /// Get and increment the nonce atomically.
    #[inline(always)]
    fn next(&self) -> u64 {
        self.current.fetch_add(1, Ordering::SeqCst)
    }

    /// Get current nonce without incrementing.
    #[inline(always)]
    fn peek(&self) -> u64 {
        self.current.load(Ordering::SeqCst)
    }

    /// Force-set the nonce (e.g. after syncing with exchange server).
    fn set(&self, value: u64) {
        self.current.store(value, Ordering::SeqCst);
    }

    /// Ensure nonce is at least `min_value` (used after server sync).
    fn ensure_min(&self, min_value: u64) {
        loop {
            let current = self.current.load(Ordering::SeqCst);
            if current >= min_value {
                break;
            }
            match self.current.compare_exchange_weak(
                current,
                min_value,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(_) => continue, // retry
            }
        }
    }
}

/// Manages API nonces across all exchanges.
///
/// The spec requires `AtomicU64` counters for request nonces.
pub struct ApiNonceManager {
    nonces: HashMap<String, ExchangeNonce>,
}

impl ApiNonceManager {
    /// Creates a new nonce manager.
    pub fn new() -> Self {
        Self {
            nonces: HashMap::new(),
        }
    }

    /// Registers an exchange with an initial nonce value.
    pub fn register_exchange(&mut self, exchange_id: &str, initial_nonce: u64) {
        let nonce = ExchangeNonce::new(exchange_id, initial_nonce);
        self.nonces.insert(exchange_id.to_lowercase(), nonce);
    }

    /// Get the next nonce for an exchange (atomically incrementing).
    ///
    /// Returns `None` if the exchange is not registered.  Callers MUST handle
    /// this — sending a request without a valid nonce will be rejected by
    /// the exchange and may trigger rate-limit bans.
    #[inline(always)]
    pub fn next_nonce(&self, exchange_id: &str) -> Option<u64> {
        self.nonces
            .get(&exchange_id.to_lowercase())
            .map(|n| n.next())
    }

    /// Peek at the current nonce without incrementing.
    ///
    /// Returns `None` if the exchange is not registered.
    #[inline]
    pub fn current_nonce(&self, exchange_id: &str) -> Option<u64> {
        self.nonces
            .get(&exchange_id.to_lowercase())
            .map(|n| n.peek())
    }

    /// Force-set the nonce for an exchange (e.g. after server sync).
    pub fn set_nonce(&self, exchange_id: &str, value: u64) {
        if let Some(nonce) = self.nonces.get(&exchange_id.to_lowercase()) {
            nonce.set(value);
        }
    }

    /// M-2: Force-reset the nonce to a specific value.
    /// Unlike `set_nonce`, this is a public API intended for manual
    /// operator intervention when automatic sync fails.
    pub fn force_set_nonce(&self, exchange_id: &str, value: u64) {
        if let Some(nonce) = self.nonces.get(&exchange_id.to_lowercase()) {
            nonce.current.store(value, Ordering::SeqCst);
        }
    }

    /// Synchronize nonce with exchange server value.
    /// Ensures local nonce is at least `server_nonce` to prevent collisions.
    pub fn sync_with_server(&self, exchange_id: &str, server_nonce: u64) {
        if let Some(nonce) = self.nonces.get(&exchange_id.to_lowercase()) {
            nonce.ensure_min(server_nonce);
            tracing::debug!(
                exchange = %exchange_id,
                server_nonce,
                local_nonce = nonce.peek(),
                "Nonce synced with server"
            );
        }
    }

    /// Returns the number of registered exchanges.
    pub fn exchange_count(&self) -> usize {
        self.nonces.len()
    }
}

impl Default for ApiNonceManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> ApiNonceManager {
        let mut mgr = ApiNonceManager::new();
        mgr.register_exchange("binance", 1000);
        mgr.register_exchange("bitfinex", 5000);
        mgr
    }

    #[test]
    fn test_next_nonce_increments() {
        let mgr = make_manager();
        let n1 = mgr.next_nonce("binance").unwrap();
        let n2 = mgr.next_nonce("binance").unwrap();
        assert_eq!(n1, 1000);
        assert_eq!(n2, 1001);
    }

    #[test]
    fn test_peek_does_not_increment() {
        let mgr = make_manager();
        let _ = mgr.next_nonce("binance").unwrap(); // 1000 → now 1001
        assert_eq!(mgr.current_nonce("binance").unwrap(), 1001);
        assert_eq!(mgr.current_nonce("binance").unwrap(), 1001); // still 1001
    }

    #[test]
    fn test_independent_exchanges() {
        let mgr = make_manager();
        assert_eq!(mgr.next_nonce("binance").unwrap(), 1000);
        assert_eq!(mgr.next_nonce("bitfinex").unwrap(), 5000);
        assert_eq!(mgr.next_nonce("binance").unwrap(), 1001);
        assert_eq!(mgr.next_nonce("bitfinex").unwrap(), 5001);
    }

    #[test]
    fn test_set_nonce() {
        let mgr = make_manager();
        mgr.set_nonce("binance", 9999);
        assert_eq!(mgr.next_nonce("binance").unwrap(), 9999);
        assert_eq!(mgr.next_nonce("binance").unwrap(), 10000);
    }

    #[test]
    fn test_sync_with_server_lower() {
        let mgr = make_manager();
        mgr.next_nonce("binance").unwrap(); // now at 1001
        mgr.sync_with_server("binance", 500); // server behind — no effect
        assert_eq!(mgr.current_nonce("binance").unwrap(), 1001);
    }

    #[test]
    fn test_sync_with_server_higher() {
        let mgr = make_manager();
        mgr.next_nonce("binance").unwrap(); // now at 1001
        mgr.sync_with_server("binance", 5000); // server ahead — bump up
        assert_eq!(mgr.current_nonce("binance").unwrap(), 5000);
        assert_eq!(mgr.next_nonce("binance").unwrap(), 5000); // returns 5000, now 5001
    }

    #[test]
    fn test_unregistered_exchange_returns_none() {
        let mgr = make_manager();
        assert_eq!(mgr.next_nonce("unknown_exchange"), None);
        assert_eq!(mgr.current_nonce("unknown_exchange"), None);
    }

    #[test]
    fn test_exchange_count() {
        let mgr = make_manager();
        assert_eq!(mgr.exchange_count(), 2);
    }
}