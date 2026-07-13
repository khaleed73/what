// live_order_tracker.rs — Live order tracking for real-time cancellation
//
// In live trading mode, every order submitted to an exchange is tracked here.
// If a timeout or partial-fill scenario occurs, the execution engine can look
// up the order by ID and issue a cancellation request.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// A tracked live order.
#[derive(Debug, Clone)]
pub struct TrackedOrder {
    pub order_id: String,
    pub exchange_id: u16,
    pub symbol: String,
    pub is_buy: bool,
    pub submitted_at: Instant,
    pub submitted_at_epoch_ms: u64,
    /// Filled quantity as reported by the exchange (updated by poller).
    pub filled_qty: rust_decimal::Decimal,
}

/// Thread-safe live order tracker.
/// Maps order_id → TrackedOrder for O(1) cancellation lookup.
pub struct LiveOrderTracker {
    pub orders: Mutex<HashMap<String, TrackedOrder>>,
    /// Maximum age (in seconds) before an order is considered stale.
    /// Stale orders are cleaned up periodically.
    pub max_age_secs: u64,
    /// Total orders tracked (monotonic).
    total_tracked: std::sync::atomic::AtomicU64,
}

impl LiveOrderTracker {
    pub fn new(max_age_secs: u64) -> Self {
        Self {
            orders: Mutex::new(HashMap::new()),
            max_age_secs,
            total_tracked: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record a newly submitted order. Called immediately after the exchange
    /// returns an order_id.
    pub fn track(&self, order_id: &str, exchange_id: u16, symbol: &str, is_buy: bool) {
        let order = TrackedOrder {
            order_id: order_id.to_string(),
            exchange_id,
            symbol: symbol.to_uppercase(),
            is_buy,
            submitted_at: Instant::now(),
            submitted_at_epoch_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            filled_qty: rust_decimal::Decimal::ZERO,
        };
        if let Ok(mut map) = self.orders.lock() {
            map.insert(order_id.to_string(), order);
            self.total_tracked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Look up a tracked order by ID.
    pub fn get(&self, order_id: &str) -> Option<TrackedOrder> {
        self.orders.lock().ok()?.get(order_id).cloned()
    }

    /// Remove a tracked order (e.g. after confirmed fill or cancellation).
    pub fn remove(&self, order_id: &str) {
        if let Ok(mut map) = self.orders.lock() {
            map.remove(order_id);
        }
    }

    /// Get all orders for a specific exchange.
    pub fn get_by_exchange(&self, exchange_id: u16) -> Vec<TrackedOrder> {
        self.orders
            .lock()
            .map(|map| {
                map.values()
                    .filter(|o| o.exchange_id == exchange_id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remove all orders older than max_age_secs.
    /// Returns the number of orders cleaned up.
    pub fn cleanup_stale(&self) -> usize {
        if let Ok(mut map) = self.orders.lock() {
            let before = map.len();
            map.retain(|_, order| {
                order.submitted_at.elapsed().as_secs() < self.max_age_secs
            });
            before - map.len()
        } else {
            0
        }
    }

    /// Return current count of tracked orders.
    pub fn len(&self) -> usize {
        self.orders.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Return total orders ever tracked.
    pub fn total_tracked(&self) -> u64 {
        self.total_tracked.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Return a snapshot of all tracked orders.
    pub fn get_all(&self) -> Vec<TrackedOrder> {
        self.orders.lock().map(|m| m.values().cloned().collect()).unwrap_or_default()
    }

    /// Update the filled_qty for a tracked order (called by the status poller).
    pub fn update_fill(&self, order_id: &str, filled_qty: rust_decimal::Decimal) {
        if let Ok(mut map) = self.orders.lock() {
            if let Some(order) = map.get_mut(order_id) {
                order.filled_qty = filled_qty;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_track_and_lookup() {
        let tracker = LiveOrderTracker::new(60);
        tracker.track("ORD-001", 0, "BTCUSDT", true);

        let order = tracker.get("ORD-001").unwrap();
        assert_eq!(order.exchange_id, 0);
        assert_eq!(order.symbol, "BTCUSDT");
        assert!(order.is_buy);
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.total_tracked(), 1);
    }

    #[test]
    fn test_remove() {
        let tracker = LiveOrderTracker::new(60);
        tracker.track("ORD-001", 0, "BTCUSDT", true);
        tracker.remove("ORD-001");
        assert_eq!(tracker.len(), 0);
        assert!(tracker.get("ORD-001").is_none());
    }

    #[test]
    fn test_get_by_exchange() {
        let tracker = LiveOrderTracker::new(60);
        tracker.track("ORD-001", 0, "BTCUSDT", true);
        tracker.track("ORD-002", 1, "ETHUSDT", false);
        tracker.track("ORD-003", 0, "SOLUSDT", true);

        let ex0 = tracker.get_by_exchange(0);
        assert_eq!(ex0.len(), 2);
    }

    #[test]
    fn test_cleanup_stale() {
        let tracker = LiveOrderTracker::new(0); // 0 seconds = everything is stale
        tracker.track("ORD-001", 0, "BTCUSDT", true);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let cleaned = tracker.cleanup_stale();
        assert!(cleaned >= 1);
        assert_eq!(tracker.len(), 0);
    }
}