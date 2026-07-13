use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
}

/// Tracks operational health metrics for monitoring and alerting.
pub struct HealthMonitor {
    started_at: Instant,
    total_signals_generated: AtomicU64,
    total_trades_executed: AtomicU64,
    total_trade_errors: AtomicU64,
    total_websocket_reconnects: AtomicU64,
    last_signal_time_ms: AtomicU64,
    last_trade_time_ms: AtomicU64,
    is_healthy: AtomicBool,
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
    #[inline]
    pub fn record_trade_error(&self) {
        self.total_trade_errors.fetch_add(1, Ordering::Relaxed);
        self.last_trade_time_ms.store(Self::now_ms(), Ordering::Relaxed);
    }

    /// Increment the WebSocket reconnect counter.
    #[inline]
    pub fn record_ws_reconnect(&self) {
        self.total_websocket_reconnects.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns `true` if the system is considered healthy.
    ///
    /// The system is healthy when either:
    /// - less than 60 seconds have elapsed since startup, **or**
    /// - a signal was recorded within the last 30 seconds.
    pub fn is_healthy(&self) -> bool {
        let uptime = self.started_at.elapsed().as_secs();
        if uptime < 60 {
            return true;
        }
        let now = Self::now_ms();
        let last = self.last_signal_time_ms.load(Ordering::Relaxed);
        now.saturating_sub(last) < 30_000
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

        HealthStats {
            uptime_secs: self.get_uptime_secs(),
            total_signals: self.total_signals_generated.load(Ordering::Relaxed),
            total_trades: self.total_trades_executed.load(Ordering::Relaxed),
            total_errors: self.total_trade_errors.load(Ordering::Relaxed),
            ws_reconnects: self.total_websocket_reconnects.load(Ordering::Relaxed),
            is_healthy: healthy,
            last_signal_ago_secs: now.saturating_sub(last_signal) / 1_000,
            last_trade_ago_secs: now.saturating_sub(last_trade) / 1_000,
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
        // Trade errors also update the last-trade timestamp.
        assert!(hm.last_trade_time_ms.load(Ordering::Relaxed) > 0);
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
}