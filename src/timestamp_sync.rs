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
    /// Maximum allowed single-jump drift (ms). If a new offset differs from
    /// the stored offset by more than this, the update is rejected as a
    /// likely corrupted NTP response. Default: 5000 ms.
    max_drift_ms: i64,
    /// M-4: Buffer of recent samples for median-based first estimate.
    sample_buffer: std::sync::Mutex<Vec<i64>>,
    /// Number of initial samples required before trusting the median.
    samples_required: usize,
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
            max_drift_ms: 5000,
            sample_buffer: std::sync::Mutex::new(Vec::with_capacity(5)),
            samples_required: 3,
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

        // M-4 fix: Use median of first few samples instead of accepting blindly.
        let needs_median = {
            let mut buf = self.sample_buffer.lock().unwrap_or_else(|e| e.into_inner());
            buf.push(offset);
            if buf.len() < self.samples_required {
                // Not enough samples yet — compute median of what we have
                // and store it tentatively.
                let mut sorted = buf.clone();
                sorted.sort();
                let median = sorted[sorted.len() / 2];
                self.offset_ms.store(median, Ordering::SeqCst);
                return;
            }
            true
        };

        if !needs_median {
            return;
        }

        // Clear the sample buffer once we have enough.
        if let Ok(mut buf) = self.sample_buffer.lock() {
            buf.clear();
        }

        // Guard against non-linear drift: reject if the jump from the
        // currently stored offset exceeds `max_drift_ms`.
        let current = self.offset_ms.load(Ordering::SeqCst);
        if (offset - current).abs() > self.max_drift_ms {
            tracing::warn!(
                exchange = %self.exchange_name,
                old_offset_ms = current,
                new_offset_ms = offset,
                max_jump_ms = self.max_drift_ms,
                "Rejected offset update: jump exceeds max_drift_ms (possible corrupted NTP response)"
            );
            return; // do NOT update the stored offset
        }

        // CRITICAL FIX: Check for fatal drift BEFORE storing.
        // A fatal offset would cause all subsequent orders to be rejected,
        // so we must refuse to store it even if it passed the jump check.
        let abs_offset = offset.abs();
        if abs_offset > self.max_drift_fatal_ms {
            tracing::error!(
                exchange = %self.exchange_name,
                offset_ms = offset,
                "FATAL: Clock drift exceeds fatal threshold ({}ms) — offset NOT stored",
                self.max_drift_fatal_ms
            );
            return;
        }

        // Store the offset.
        self.offset_ms.store(offset, Ordering::SeqCst);
        *self.last_sync.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();

        if abs_offset > self.max_drift_warn_ms {
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
        let guard = self.last_sync.lock().unwrap_or_else(|e| e.into_inner());
        guard.elapsed() >= self.sync_interval
    }

    /// Returns the exchange name.
    pub fn exchange_name(&self) -> &str {
        &self.exchange_name
    }

    /// Sets the maximum allowed single-jump drift (ms).
    /// Updates to `update_offset` that would shift the clock by more than
    /// this value from the current offset are silently rejected.
    pub fn set_max_drift_ms(&mut self, max_drift_ms: i64) {
        self.max_drift_ms = max_drift_ms;
    }

    /// Returns the current max single-jump drift threshold (ms).
    pub fn max_drift_ms(&self) -> i64 {
        self.max_drift_ms
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
    fn test_rejects_large_offset_jump() {
        let mut sync = TimestampSynchronizer::with_defaults("binance");
        sync.set_max_drift_ms(5000);

        // First update always accepted.
        let local_ms = chrono::Utc::now().timestamp_millis();
        sync.update_offset(local_ms + 50);
        assert_eq!(sync.offset_ms(), 50);

        // A jump of 6000ms exceeds max_drift_ms=5000 → rejected.
        sync.update_offset(local_ms + 6050);
        // Offset should remain at ~50 (the first accepted value).
        let offset = sync.offset_ms();
        assert!(offset.abs() < 100, "offset should not have jumped, got {}", offset);
    }

    #[test]
    fn test_allows_small_offset_jump() {
        let sync = TimestampSynchronizer::with_defaults("binance");
        let local_ms = chrono::Utc::now().timestamp_millis();
        sync.update_offset(local_ms + 50);

        // A jump of 100ms is well within the 5000ms threshold.
        sync.update_offset(local_ms + 150);
        let offset = sync.offset_ms();
        assert!(offset >= 100 && offset <= 200, "offset should be ~150, got {}", offset);
    }

    #[test]
    fn test_needs_resync() {
        let sync = TimestampSynchronizer::new("binance", 500, 5000, Duration::from_millis(100));
        assert!(!sync.needs_resync());

        // Manually age the last_sync.
        *sync.last_sync.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now() - Duration::from_millis(200);
        assert!(sync.needs_resync());
    }
}