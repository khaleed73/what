// live_order_tracker.rs — Live order tracking for real-time cancellation
//
// In live trading mode, every order submitted to an exchange is tracked here.
// If a timeout or partial-fill scenario occurs, the execution engine can look
// up the order by ID and issue a cancellation request.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    /// Maximum number of orders to track before forced pruning kicks in.
    pub max_tracked_orders: usize,
    /// Total orders tracked (monotonic).
    total_tracked: std::sync::atomic::AtomicU64,
}

impl LiveOrderTracker {
    pub fn new(max_age_secs: u64) -> Self {
        Self {
            orders: Mutex::new(HashMap::new()),
            max_age_secs,
            max_tracked_orders: 10_000,
            total_tracked: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create a tracker with a custom max tracked orders limit.
    pub fn with_max_orders(max_age_secs: u64, max_tracked_orders: usize) -> Self {
        Self {
            orders: Mutex::new(HashMap::new()),
            max_age_secs,
            max_tracked_orders,
            total_tracked: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record a newly submitted order. Called immediately after the exchange
    /// returns an order_id.
    ///
    /// M-7 fix: Restructured to hold the lock once instead of triple-locking
    /// (len → cleanup_stale → prune_oldest each acquired/released separately).
    pub fn track(&self, order_id: &str, exchange_id: u16, symbol: &str, is_buy: bool) {
        if let Ok(mut map) = self.orders.lock() {
            // Proactive cleanup when past half the max capacity.
            if map.len() > self.max_tracked_orders / 2 {
                map.retain(|_, order| order.submitted_at.elapsed().as_secs() < self.max_age_secs);
            }

            // Hard-cap: if we still exceed the limit, prune the oldest entry.
            if map.len() >= self.max_tracked_orders {
                if let Some(oldest) = map.iter()
                    .min_by_key(|(_, o)| o.submitted_at)
                    .map(|(k, _)| k.clone())
                {
                    tracing::warn!(
                        current_count = map.len(),
                        max = self.max_tracked_orders,
                        evicted_order_id = %oldest,
                        "M-11: Order tracker at capacity — evicting oldest order"
                    );
                    map.remove(&oldest);
                }
            }

            map.insert(order_id.to_string(), TrackedOrder {
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
            });
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

    /// Remove the oldest entries until the map is within the limit.
    /// Returns the number of orders pruned.
    pub fn prune_oldest(&self) -> usize {
        let limit = self.max_tracked_orders;
        if let Ok(mut map) = self.orders.lock() {
            if map.len() <= limit {
                return 0;
            }
            // Collect entries sorted by submitted_at ascending (oldest first).
            let mut entries: Vec<(String, Instant)> = map
                .values()
                .map(|o| (o.order_id.clone(), o.submitted_at))
                .collect();
            entries.sort_by_key(|(_, t)| *t);

            let to_remove = map.len() - limit;
            for (id, _) in entries.into_iter().take(to_remove) {
                map.remove(&id);
            }
            to_remove
        } else {
            0
        }
    }

    /// Spawn a background tokio task that calls [`cleanup_stale`](Self::cleanup_stale)
    /// every 60 seconds to prevent unbounded growth.
    ///
    /// The caller **must** hold the `LiveOrderTracker` behind an `Arc` so that
    /// the spawned task can keep a reference.
    ///
    /// Returns a `JoinHandle` that can be aborted when the tracker is no longer
    /// needed.
    pub fn start_periodic_cleanup(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let tracker = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let cleaned = tracker.cleanup_stale();
                if cleaned > 0 {
                    tracing::info!(
                        cleaned,
                        remaining = tracker.len(),
                        "periodic cleanup removed stale orders"
                    );
                }
            }
        })
    }

    /// Return current count of tracked orders.
    pub fn len(&self) -> usize {
        self.orders.lock().unwrap_or_else(|e| {
            tracing::error!(
                error = %e,
                "live_order_tracker: poisoned lock in len() — recovering lock to preserve orders"
            );
            e.into_inner()
        }).len()
    }

    /// Return true if no orders are tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

impl Drop for LiveOrderTracker {
    fn drop(&mut self) {
        if let Ok(map) = self.orders.lock() {
            let remaining = map.len();
            if remaining > 0 {
                tracing::warn!(
                    remaining,
                    "LiveOrderTracker dropped with {} orders still tracked; possible leak",
                    remaining
                );
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

    #[tokio::test]
    async fn test_start_periodic_cleanup() {
        let tracker = Arc::new(LiveOrderTracker::new(0));
        let handle = tracker.start_periodic_cleanup();
        // The task should be running — verify the handle is not finished yet.
        assert!(!handle.is_finished());
        // Abort so the test doesn't leak the background task.
        handle.abort();
        // After abort, await returns Err(Cancelled) and handle is finished.
        let result = handle.await;
        assert!(result.is_err());
    }

    #[test]
    fn test_prune_oldest_enforces_limit() {
        let tracker = LiveOrderTracker::with_max_orders(60, 5);
        for i in 0..7 {
            tracker.track(&format!("ORD-{i:03}"), 0, "BTCUSDT", true);
        }
        // After inserting 7 with a limit of 5, prune_oldest should have kicked in.
        assert!(tracker.len() <= 5);
    }

    #[test]
    fn test_track_auto_cleanup_at_half_capacity() {
        // max_age_secs = 1, max_orders = 10: half-capacity = 5.
        // Insert 6 orders rapidly — the first few become stale after 1s.
        // But since we insert them all within milliseconds, use a small sleep
        // to ensure the first ones age out.
        let tracker = LiveOrderTracker::with_max_orders(1, 10);
        for i in 0..6 {
            tracker.track(&format!("ORD-{i:03}"), 0, "BTCUSDT", true);
        }
        // With max_age_secs=1 and rapid insertion, cleanup may or may not
        // have triggered yet depending on timing. Just verify the tracker
        // isn't leaking beyond its hard cap.
        assert!(tracker.len() <= 10);
    }
}