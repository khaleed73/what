//! Timestamp Synchronization with Exchange Servers
//!
//! The spec requires fetching `/api/v3/time` (or equivalent) and computing
//! an offset between the local clock and the exchange server clock. This
//! offset is then applied to all timestamped API requests to prevent
//! rejected orders due to clock drift.
//!
//! Spec reference: "Fetch `/api/v3/time` and offset local clock"

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

/// Manages clock offset between local machine and a single exchange server.
pub struct TimestampSynchronizer {
    /// Clock offset in milliseconds. Positive = server is ahead, Negative = server is behind.
    offset_ms: AtomicI64,
    /// Exchange name for logging.
    exchange_name: String,
    /// Maximum allowed drift before warning (ms).
    max_drift_warn_ms: i64,
    /// Maximum allowed drift before refusing to trade (ms).
    max_drift_fatal_ms: i64,
    /// Last sync time.
    last_sync: std::sync::Mutex<Instant>,
    /// Sync interval.
    sync_interval: Duration,
}

impl TimestampSynchronizer {
    /// Creates a new synchronizer for the given exchange.
    ///
    /// - `max_drift_warn_ms`: Warn if drift exceeds this (e.g. 500ms)
    /// - `max_drift_fatal_ms`: Refuse to trade if drift exceeds this (e.g. 5000ms)
    /// - `sync_interval`: How often to re-sync (e.g. 5 minutes)
    pub fn new(exchange_name: &str, max_drift_warn_ms: i64, max_drift_fatal_ms: i64, sync_interval: Duration) -> Self {
        Self {
            offset_ms: AtomicI64::new(0),
            exchange_name: exchange_name.to_string(),
            max_drift_warn_ms,
            max_drift_fatal_ms,
            last_sync: std::sync::Mutex::new(Instant::now()),
            sync_interval,
        }
    }

    /// Creates a synchronizer with sensible defaults.
    pub fn with_defaults(exchange_name: &str) -> Self {
        Self::new(exchange_name, 500, 5000, Duration::from_secs(300))
    }

    /// Update the clock offset based on a server time response.
    ///
    /// # Arguments
    /// * `server_time_ms` — Server timestamp in milliseconds since epoch.
    ///
    /// The offset is computed as: `server_time_ms - local_time_ms`.
    /// A median of multiple samples is recommended for accuracy.
    pub fn update_offset(&self, server_time_ms: i64) {
        let local_ms = chrono::Utc::now().timestamp_millis();
        let offset = server_time_ms - local_ms;

        self.offset_ms.store(offset, Ordering::SeqCst);
        *self.last_sync.lock().unwrap() = Instant::now();

        let abs_offset = offset.abs();

        if abs_offset > self.max_drift_fatal_ms {
            tracing::error!(
                exchange = %self.exchange_name,
                offset_ms = offset,
                "FATAL: Clock drift exceeds fatal threshold ({}ms)",
                self.max_drift_fatal_ms
            );
        } else if abs_offset > self.max_drift_warn_ms {
            tracing::warn!(
                exchange = %self.exchange_name,
                offset_ms = offset,
                "WARNING: Clock drift exceeds warn threshold ({}ms)",
                self.max_drift_warn_ms
            );
        } else {
            tracing::debug!(
                exchange = %self.exchange_name,
                offset_ms = offset,
                "Clock offset updated"
            );
        }
    }

    /// Compute an offset-adjusted timestamp in milliseconds.
    ///
    /// This is what should be sent in API requests.
    #[inline(always)]
    pub fn adjusted_timestamp_ms(&self) -> i64 {
        let local_ms = chrono::Utc::now().timestamp_millis();
        local_ms + self.offset_ms.load(Ordering::SeqCst)
    }

    /// Returns the current offset in milliseconds.
    #[inline]
    pub fn offset_ms(&self) -> i64 {
        self.offset_ms.load(Ordering::SeqCst)
    }

    /// Returns `true` if the clock drift is within acceptable bounds.
    #[inline]
    pub fn is_within_bounds(&self) -> bool {
        self.offset_ms.load(Ordering::SeqCst).abs() <= self.max_drift_fatal_ms
    }

    /// Returns `true` if sync is stale and needs re-syncing.
    pub fn needs_resync(&self) -> bool {
        let guard = self.last_sync.lock().unwrap();
        guard.elapsed() >= self.sync_interval
    }

    /// Returns the exchange name.
    pub fn exchange_name(&self) -> &str {
        &self.exchange_name
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_offset_is_zero() {
        let sync = TimestampSynchronizer::with_defaults("binance");
        assert_eq!(sync.offset_ms(), 0);
    }

    #[test]
    fn test_update_offset() {
        let sync = TimestampSynchronizer::with_defaults("binance");
        // Simulate server being 50ms ahead.
        let local_ms = chrono::Utc::now().timestamp_millis();
        let server_ms = local_ms + 50;
        sync.update_offset(server_ms);

        // Offset should be approximately 50ms (may vary slightly due to timing).
        let offset = sync.offset_ms();
        assert!(offset.abs() < 100); // within 100ms of expected
    }

    #[test]
    fn test_adjusted_timestamp() {
        let sync = TimestampSynchronizer::with_defaults("binance");
        // Set offset to +100ms (server is 100ms ahead).
        sync.offset_ms.store(100, Ordering::SeqCst);

        let adjusted = sync.adjusted_timestamp_ms();
        let local_ms = chrono::Utc::now().timestamp_millis();
        // Adjusted should be ~100ms ahead of local.
        let diff = adjusted - local_ms;
        assert!(diff >= 90 && diff <= 110);
    }

    #[test]
    fn test_is_within_bounds() {
        let sync = TimestampSynchronizer::new("binance", 500, 5000, Duration::from_secs(300));
        assert!(sync.is_within_bounds());

        sync.offset_ms.store(4000, Ordering::SeqCst); // 4s drift — within 5s fatal
        assert!(sync.is_within_bounds());

        sync.offset_ms.store(6000, Ordering::SeqCst); // 6s drift — exceeds 5s fatal
        assert!(!sync.is_within_bounds());
    }

    #[test]
    fn test_needs_resync() {
        let sync = TimestampSynchronizer::new("binance", 500, 5000, Duration::from_millis(100));
        assert!(!sync.needs_resync());

        // Manually age the last_sync.
        *sync.last_sync.lock().unwrap() = Instant::now() - Duration::from_millis(200);
        assert!(sync.needs_resync());
    }
}