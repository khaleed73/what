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
use std::sync::RwLock;

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
    ///
    /// M-1 FIX: Uses `fetch_update` with `checked_add` to detect u64 overflow.
    /// If the counter has reached `u64::MAX`, a wrap-around would produce
    /// nonce 0 which the exchange would reject.  Returns `None` on overflow
    /// and logs a CRITICAL alert.
    #[inline(always)]
    fn next(&self) -> Option<u64> {
        match self.current.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1)) {
            Ok(val) => Some(val),
            Err(_) => {
                tracing::error!(
                    exchange = %self.name,
                    "M-1: nonce counter overflowed u64::MAX for exchange — \
                     all further nonces will be rejected until manual reset"
                );
                None
            }
        }
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
/// The internal `HashMap` is wrapped in an `RwLock` so that
/// `register_exchange` (write) and `next_nonce` / `current_nonce`
/// (read) can be used concurrently from multiple threads, e.g.
/// during dynamic exchange discovery.
pub struct ApiNonceManager {
    nonces: RwLock<HashMap<String, ExchangeNonce>>,
}

impl ApiNonceManager {
    /// Creates a new nonce manager.
    pub fn new() -> Self {
        Self {
            nonces: RwLock::new(HashMap::new()),
        }
    }

    /// Registers an exchange with an initial nonce value.
    #[cold]
    pub fn register_exchange(&self, exchange_id: &str, initial_nonce: u64) {
        let nonce = ExchangeNonce::new(exchange_id, initial_nonce);
        self.nonces
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(exchange_id.to_lowercase(), nonce);
    }

    /// Get the next nonce for an exchange (atomically incrementing).
    ///
    /// Returns `None` if the exchange is not registered **or** the nonce
    /// counter has overflowed `u64::MAX` (M-1 FIX).  Callers MUST handle
    /// this — sending a request without a valid nonce will be rejected by
    /// the exchange and may trigger rate-limit bans.
    #[inline(always)]
    pub fn next_nonce(&self, exchange_id: &str) -> Option<u64> {
        self.nonces
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&exchange_id.to_lowercase())
            .and_then(|n| n.next())
    }

    /// Peek at the current nonce without incrementing.
    ///
    /// Returns `None` if the exchange is not registered.
    #[inline]
    pub fn current_nonce(&self, exchange_id: &str) -> Option<u64> {
        self.nonces
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&exchange_id.to_lowercase())
            .map(|n| n.peek())
    }

    /// Set the nonce for an exchange, only increasing it (never moving backwards).
    ///
    /// M-2 FIX: Uses the same CAS-based `ensure_min` logic as `sync_with_server`
    /// instead of a raw `store`.  This prevents a stale persisted nonce (loaded
    /// after a task restart) from clobbering a higher in-memory value and
    /// causing nonce reuse / server rejection.
    pub fn set_nonce(&self, exchange_id: &str, value: u64) {
        if let Some(nonce) = self
            .nonces
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&exchange_id.to_lowercase())
        {
            nonce.ensure_min(value);
            tracing::debug!(
                exchange = %exchange_id,
                requested = value,
                actual = nonce.peek(),
                "set_nonce applied (clamped to max of requested and current)"
            );
        }
    }

    /// M-2: Force-reset the nonce to a specific value.
    /// Unlike `set_nonce`, this is a public API intended for manual
    /// operator intervention when automatic sync fails.
    pub fn force_set_nonce(&self, exchange_id: &str, value: u64) {
        if let Some(nonce) = self
            .nonces
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&exchange_id.to_lowercase())
        {
            nonce.current.store(value, Ordering::SeqCst);
        }
    }

    /// Synchronize nonce with exchange server value.
    /// Ensures local nonce is at least `server_nonce` to prevent collisions.
    pub fn sync_with_server(&self, exchange_id: &str, server_nonce: u64) {
        let guard = self.nonces.read().unwrap_or_else(|e| e.into_inner());
        if let Some(nonce) = guard.get(&exchange_id.to_lowercase()) {
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
        self.nonces
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
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
        let mgr = ApiNonceManager::new();
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

    #[test]
    fn test_set_nonce_monotonicity_across_restart() {
        // M-2 FIX: set_nonce must never move the counter backwards.
        let mgr = make_manager();
        mgr.next_nonce("binance").unwrap(); // now at 1001
        mgr.set_nonce("binance", 500); // stale persisted value — must NOT move back
        assert_eq!(mgr.current_nonce("binance").unwrap(), 1001);
        // But a higher value should move forward.
        mgr.set_nonce("binance", 9999);
        assert_eq!(mgr.current_nonce("binance").unwrap(), 9999);
    }
}