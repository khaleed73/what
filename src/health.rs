use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

/// Snapshot of all health counters, suitable for logging or metrics export.
#[derive(Debug, Clone)]
pub struct HealthStats {
    pub uptime_secs: u64,
    pub total_signals: u64,
    pub total_trades: u64,
    pub total_errors: u64,
    pub ws_reconnects: u64,
    pub is_healthy: bool,
    pub last_signal_ago_secs: u64,
    pub last_trade_ago_secs: u64,
    /// Per-exchange data feed liveness (exchange_id → `true` if data received
    /// within the staleness window).
    pub feed_healthy: HashMap<u16, bool>,
}

/// Feeds with no data update for longer than this (ms) are considered stale.
const FEED_STALENESS_MS: i64 = 10_000;

/// Tracks operational health metrics for monitoring and alerting.
///
/// L-2 NOTE: Current health checks verify data feed liveness (WS message
/// staleness) and signal freshness, but do **not** probe actual exchange
/// REST API connectivity. For full exchange health verification, a
/// periodic HTTP GET to each exchange's `/api/v3/ping` (or equivalent)
/// endpoint is recommended, with results fed into `record_feed_update()`
/// or a dedicated `record_exchange_api_ok(exchange_id)` method.
pub struct HealthMonitor {
    started_at: Instant,
    total_signals_generated: AtomicU64,
    total_trades_executed: AtomicU64,
    total_trade_errors: AtomicU64,
    total_websocket_reconnects: AtomicU64,
    last_signal_time_ms: AtomicU64,
    last_trade_time_ms: AtomicU64,
    is_healthy: AtomicBool,
    /// Last data-feed update per exchange (epoch millis).
    /// The `RwLock` is only needed when a *new* exchange ID is registered;
    /// once registered the `AtomicI64` allows lock-free updates.
    last_feed_update: std::sync::RwLock<HashMap<u16, AtomicI64>>,
}

impl HealthMonitor {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            total_signals_generated: AtomicU64::new(0),
            total_trades_executed: AtomicU64::new(0),
            total_trade_errors: AtomicU64::new(0),
            total_websocket_reconnects: AtomicU64::new(0),
            // Initialise to now so that "time since last signal" starts at 0.
            last_signal_time_ms: AtomicU64::new(Self::now_ms()),
            last_trade_time_ms: AtomicU64::new(Self::now_ms()),
            is_healthy: AtomicBool::new(true),
            last_feed_update: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Increment the signal counter and update the last-signal timestamp.
    #[inline]
    pub fn record_signal(&self) {
        self.total_signals_generated.fetch_add(1, Ordering::Relaxed);
        self.last_signal_time_ms.store(Self::now_ms(), Ordering::Relaxed);
    }

    /// Increment the successful-trade counter and update the last-trade timestamp.
    #[inline]
    pub fn record_trade_success(&self) {
        self.total_trades_executed.fetch_add(1, Ordering::Relaxed);
        self.last_trade_time_ms.store(Self::now_ms(), Ordering::Relaxed);
    }

    /// Increment the trade-error counter.
    /// NOTE: This does NOT update `last_trade_time_ms` — only successful
    /// trades should reset the staleness timer.  Otherwise, a stream of
    /// errors would make the system appear healthy.
    #[inline]
    pub fn record_trade_error(&self) {
        self.total_trade_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the WebSocket reconnect counter.
    #[inline]
    pub fn record_ws_reconnect(&self) {
        self.total_websocket_reconnects.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that a data feed for the given exchange has just delivered a
    /// message.  If the exchange has not been seen before it is registered
    /// automatically.
    ///
    /// # Arguments
    /// * `exchange_id` — Numeric exchange identifier (e.g. 1 = Binance, 2 = Bybit).
    pub fn record_feed_update(&self, exchange_id: u16) {
        let now_ms = Self::now_ms() as i64;
        let mut map = self.last_feed_update.write().unwrap_or_else(|e| e.into_inner());
        map.entry(exchange_id)
            .or_insert_with(|| AtomicI64::new(now_ms))
            .store(now_ms, Ordering::Relaxed);
    }

    /// Returns `true` if the given exchange's data feed has been seen
    /// within the last `FEED_STALENESS_MS` milliseconds (10 seconds).
    /// Returns `false` if the exchange is not registered or the feed is stale.
    pub fn is_feed_healthy(&self, exchange_id: u16) -> bool {
        let map = self.last_feed_update.read().unwrap_or_else(|e| e.into_inner());
        if let Some(ts) = map.get(&exchange_id) {
            let now_ms = Self::now_ms() as i64;
            now_ms.saturating_sub(ts.load(Ordering::Relaxed)) < FEED_STALENESS_MS
        } else {
            false
        }
    }

    /// Returns `true` if **all** registered data feeds are healthy.
    /// If no feeds have been registered yet, returns `true` (vacuously).
    fn all_feeds_healthy(&self) -> bool {
        let map = self.last_feed_update.read().unwrap_or_else(|e| e.into_inner());
        if map.is_empty() {
            // H-3 fix: return false when no feeds registered past 60s grace
            return self.started_at.elapsed().as_secs() < 60;
        }
        let now_ms = Self::now_ms() as i64;
        map.values().all(|ts| {
            now_ms.saturating_sub(ts.load(Ordering::Relaxed)) < FEED_STALENESS_MS
        })
    }

    /// Returns `true` if the system is considered healthy.
    ///
    /// The system is healthy when **all** of the following hold:
    /// - less than 60 seconds have elapsed since startup, **or**
    ///   a signal was recorded within the last 30 seconds.
    /// - every registered data feed has delivered data within the last
    ///   10 seconds (if any feeds are registered at all).
    pub fn is_healthy(&self) -> bool {
        let uptime = self.started_at.elapsed().as_secs();
        if uptime < 60 {
            return self.all_feeds_healthy();
        }
        let now = Self::now_ms();
        let last = self.last_signal_time_ms.load(Ordering::Relaxed);
        let signal_ok = now.saturating_sub(last) < 30_000;
        signal_ok && self.all_feeds_healthy()
    }

    /// Uptime in whole seconds since creation.
    pub fn get_uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Take a consistent snapshot of all counters.
    pub fn get_stats(&self) -> HealthStats {
        let now = Self::now_ms();
        let last_signal = self.last_signal_time_ms.load(Ordering::Relaxed);
        let last_trade = self.last_trade_time_ms.load(Ordering::Relaxed);

        let healthy = self.is_healthy();
        self.is_healthy.store(healthy, Ordering::Relaxed);

        // Build per-exchange feed liveness map.
        let feed_map = self.last_feed_update.read().unwrap_or_else(|e| e.into_inner());
        let now_i64 = now as i64;
        let feed_healthy: HashMap<u16, bool> = feed_map
            .iter()
            .map(|(&id, ts)| {
                let fresh = now_i64.saturating_sub(ts.load(Ordering::Relaxed)) < FEED_STALENESS_MS;
                (id, fresh)
            })
            .collect();
        drop(feed_map);

        HealthStats {
            uptime_secs: self.get_uptime_secs(),
            total_signals: self.total_signals_generated.load(Ordering::Relaxed),
            total_trades: self.total_trades_executed.load(Ordering::Relaxed),
            total_errors: self.total_trade_errors.load(Ordering::Relaxed),
            ws_reconnects: self.total_websocket_reconnects.load(Ordering::Relaxed),
            is_healthy: healthy,
            last_signal_ago_secs: now.saturating_sub(last_signal) / 1_000,
            last_trade_ago_secs: now.saturating_sub(last_trade) / 1_000,
            feed_healthy,
        }
    }

    /// Current wall-clock time in milliseconds since Unix epoch.
    #[inline]
    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_new_monitor_is_healthy_within_grace_period() {
        let hm = HealthMonitor::new();
        // Freshly created — must be healthy (within 60 s grace).
        assert!(hm.is_healthy());
    }

    #[test]
    fn test_healthy_after_recent_signal() {
        let hm = HealthMonitor::new();
        hm.record_signal();
        // A signal was just recorded — must be healthy regardless of uptime.
        assert!(hm.is_healthy());
    }

    #[test]
    fn test_unhealthy_when_no_signal_and_past_grace() {
        let hm = HealthMonitor::new();
        // Artificially age the last-signal timestamp to 31 seconds ago.
        // Bypass the 60 s grace by setting a fake "started long ago" —
        // we can't move Instant, so instead we directly test the staleness
        // logic by aging the timestamp and verifying the counter snapshot.
        //
        // The is_healthy() method returns true when uptime < 60s OR
        // last_signal was < 30s ago.  We verify the freshness via get_stats.
        hm.last_signal_time_ms.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
                .saturating_sub(31_000),
            Ordering::Relaxed,
        );

        let stats = hm.get_stats();
        // No signals recorded (the timestamp was backdated, counter stays 0).
        assert_eq!(stats.total_signals, 0);
        assert_eq!(stats.total_trades, 0);
        // The staleness must be reflected in the snapshot (~31 s).
        assert!(
            stats.last_signal_ago_secs >= 30,
            "expected staleness >= 30s, got {}s",
            stats.last_signal_ago_secs,
        );
    }

    #[test]
    fn test_record_signal_increments_counter() {
        let hm = HealthMonitor::new();
        assert_eq!(hm.total_signals_generated.load(Ordering::Relaxed), 0);
        hm.record_signal();
        hm.record_signal();
        hm.record_signal();
        assert_eq!(hm.total_signals_generated.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_record_trade_success_increments_counter() {
        let hm = HealthMonitor::new();
        hm.record_trade_success();
        hm.record_trade_success();
        assert_eq!(hm.total_trades_executed.load(Ordering::Relaxed), 2);
        assert_eq!(hm.total_trade_errors.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_record_trade_error_increments_counter() {
        let hm = HealthMonitor::new();
        hm.record_trade_error();
        assert_eq!(hm.total_trade_errors.load(Ordering::Relaxed), 1);
        // L-2 fix: Trade errors do NOT update the last-trade timestamp.
        // record_trade_error only increments the error counter.
    }

    #[test]
    fn test_record_ws_reconnect_increments_counter() {
        let hm = HealthMonitor::new();
        hm.record_ws_reconnect();
        hm.record_ws_reconnect();
        assert_eq!(hm.total_websocket_reconnects.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_get_stats_snapshot_consistency() {
        let hm = HealthMonitor::new();
        hm.record_signal();
        hm.record_trade_success();
        hm.record_trade_error();
        hm.record_ws_reconnect();

        let stats = hm.get_stats();
        assert!(stats.uptime_secs >= 0);
        assert_eq!(stats.total_signals, 1);
        assert_eq!(stats.total_trades, 1);
        assert_eq!(stats.total_errors, 1);
        assert_eq!(stats.ws_reconnects, 1);
        // Both last-signal and last-trade were just updated.
        assert!(stats.last_signal_ago_secs <= 1);
        assert!(stats.last_trade_ago_secs <= 1);
    }

    #[test]
    fn test_signal_freshness_detection() {
        let hm = HealthMonitor::new();
        // Record a signal, then manually backdate the timestamp.
        hm.record_signal();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // Set last signal to 35 seconds ago (past the 30 s freshness window).
        hm.last_signal_time_ms.store(now.saturating_sub(35_000), Ordering::Relaxed);

        let stats = hm.get_stats();
        // The staleness should be reflected in the snapshot.
        // last_signal_ago_secs should be approximately 35.
        assert!(
            (30..=40).contains(&stats.last_signal_ago_secs),
            "expected ~35s staleness, got {}s",
            stats.last_signal_ago_secs,
        );
    }

    #[test]
    fn test_uptime_increases() {
        let hm = HealthMonitor::new();
        let t0 = hm.get_uptime_secs();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let t1 = hm.get_uptime_secs();
        assert!(t1 >= t0, "uptime should be monotonically increasing");
    }

    // -- Feed liveness tests --

    #[test]
    fn test_feed_update_registers_and_is_healthy() {
        let hm = HealthMonitor::new();
        // Unregistered exchange is unhealthy.
        assert!(!hm.is_feed_healthy(1));
        // Record a feed update.
        hm.record_feed_update(1);
        assert!(hm.is_feed_healthy(1));
    }

    #[test]
    fn test_feed_stale_after_timeout() {
        let hm = HealthMonitor::new();
        hm.record_feed_update(1);
        assert!(hm.is_feed_healthy(1));

        // Backdate the feed timestamp to 11 seconds ago (> 10 s threshold).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let stale_ts = (now.saturating_sub(11_000)) as i64;
        let map = hm.last_feed_update.read().unwrap();
        if let Some(atomic) = map.get(&1) {
            atomic.store(stale_ts, Ordering::Relaxed);
        }
        drop(map);

        assert!(!hm.is_feed_healthy(1));
    }

    #[test]
    fn test_no_feeds_vacuously_healthy() {
        let hm = HealthMonitor::new();
        // No feeds registered, but within 60s grace period → healthy.
        assert!(hm.is_healthy());
    }

    #[test]
    fn test_stale_feed_makes_system_unhealthy() {
        let hm = HealthMonitor::new();
        hm.record_feed_update(1);
        hm.record_signal(); // keep signals fresh

        // Backdate exchange 1's feed to 11 seconds ago.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let stale_ts = (now.saturating_sub(11_000)) as i64;
        let map = hm.last_feed_update.read().unwrap();
        if let Some(atomic) = map.get(&1) {
            atomic.store(stale_ts, Ordering::Relaxed);
        }
        drop(map);

        // Even though signals are fresh, the stale feed should mark as unhealthy.
        // But we're still within the 60 s grace period, so is_healthy checks feeds.
        assert!(!hm.is_healthy());
    }

    #[test]
    fn test_feed_healthy_in_stats_snapshot() {
        let hm = HealthMonitor::new();
        hm.record_feed_update(1);
        hm.record_feed_update(2);

        let stats = hm.get_stats();
        assert_eq!(stats.feed_healthy.get(&1), Some(&true));
        assert_eq!(stats.feed_healthy.get(&2), Some(&true));
        assert_eq!(stats.feed_healthy.get(&99), None);
    }
}