//! Engine Circuit Breaker — System-wide panic/freeze mechanism.
//!
//! Unlike the per-exchange RateLimitCircuitBreaker in execution.rs, this module
//! provides a global kill switch that freezes ALL trading activity when a
//! critical system invariant is violated.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Engine-level circuit breaker that can freeze the entire trading system.
///
/// This is separate from per-exchange circuit breakers. This trips when
/// a fundamental system invariant is violated (e.g., balance corruption
/// detected, unauthorized position detected, or manual kill switch).
pub struct EngineCircuitBreaker {
    /// When true, ALL trading is frozen. No orders can be dispatched.
    system_frozen: AtomicBool,
    /// Reason for the last trip (stored as static string pointer for zero-allocation).
    trip_reason: AtomicU64,
    /// Timestamp of the last trip in milliseconds since epoch.
    trip_timestamp_ms: AtomicU64,
    /// Total number of times the breaker has been tripped.
    trip_count: AtomicU64,
    /// Total number of trades rejected due to frozen state.
    rejected_count: AtomicU64,
}

/// Pre-registered trip reason codes (zero-allocation).
pub const REASON_MANUAL_KILL: u64 = 1;
pub const REASON_BALANCE_CORRUPTION: u64 = 2;
pub const REASON_UNAUTHORIZED_POSITION: u64 = 3;
pub const REASON_DRAWDOWN_BREACHED: u64 = 4;
pub const REASON_NETWORK_PARTITION: u64 = 5;
pub const REASON_EXCHANGE_MASS_FAILURE: u64 = 6;
pub const REASON_CLOCK_DRIFT: u64 = 7;
pub const REASON_UNKNOWN: u64 = 0;

impl Default for EngineCircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineCircuitBreaker {
    pub fn new() -> Self {
        Self {
            system_frozen: AtomicBool::new(false),
            trip_reason: AtomicU64::new(0),
            trip_timestamp_ms: AtomicU64::new(0),
            trip_count: AtomicU64::new(0),
            rejected_count: AtomicU64::new(0),
        }
    }

    /// Trips the breaker, freezing ALL trading activity.
    /// This is idempotent — tripping multiple times only records the first reason.
    pub fn trip(&self, reason_code: u64) {
        let was_frozen = self.system_frozen.swap(true, Ordering::SeqCst);
        if !was_frozen {
            // First trip — record details
            self.trip_reason.store(reason_code, Ordering::SeqCst);
            self.trip_timestamp_ms.store(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
                Ordering::SeqCst,
            );
            self.trip_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Resets the breaker, allowing trading to resume.
    /// Returns true if the system was actually frozen (and is now unfrozen).
    /// Clears stale trip metadata (reason, timestamp) on reset.
    pub fn reset(&self) -> bool {
        let was_frozen = self.system_frozen.swap(false, Ordering::SeqCst);
        if was_frozen {
            self.trip_reason.store(REASON_UNKNOWN, Ordering::SeqCst);
            self.trip_timestamp_ms.store(0, Ordering::SeqCst);
        }
        was_frozen
    }

    /// Returns true if the system is currently frozen.
    pub fn is_frozen(&self) -> bool {
        self.system_frozen.load(Ordering::Acquire)
    }

    /// Checks if trading is allowed. If frozen, increments rejected count.
    /// M-11: Auto-recovers from transient issues (network partition, clock
    /// drift) after a 60-second cooldown period.
    pub fn check_and_reject(&self) -> Result<(), CircuitBreakerError> {
        if self.is_frozen() {
            let reason = self.trip_reason.load(Ordering::Acquire);
            let ts = self.trip_timestamp_ms.load(Ordering::Acquire);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);

            // Auto-recover transient issues after 60s cooldown.
            const TRANSIENT_COOLDOWN_MS: u64 = 60_000;
            if matches!(reason, REASON_NETWORK_PARTITION | REASON_CLOCK_DRIFT)
                && now.saturating_sub(ts) > TRANSIENT_COOLDOWN_MS
            {
                self.reset();
                tracing::info!(
                    reason_code = reason,
                    elapsed_ms = now.saturating_sub(ts),
                    "Auto-recovered from transient circuit break"
                );
                return Ok(());
            }

            self.rejected_count.fetch_add(1, Ordering::Relaxed);
            Err(CircuitBreakerError::SystemFrozen {
                reason_code: reason,
                rejected_total: self.rejected_count.load(Ordering::Acquire),
            })
        } else {
            Ok(())
        }
    }

    /// Returns the reason code for the last trip.
    pub fn trip_reason_code(&self) -> u64 {
        self.trip_reason.load(Ordering::Acquire)
    }

    /// Returns a human-readable reason string for the last trip.
    pub fn trip_reason_string(&self) -> &'static str {
        match self.trip_reason.load(Ordering::Acquire) {
            REASON_MANUAL_KILL => "Manual kill switch activated",
            REASON_BALANCE_CORRUPTION => "Balance corruption detected",
            REASON_UNAUTHORIZED_POSITION => "Unauthorized position detected",
            REASON_DRAWDOWN_BREACHED => "Maximum drawdown breached",
            REASON_NETWORK_PARTITION => "Network partition detected",
            REASON_EXCHANGE_MASS_FAILURE => "Multiple exchanges failing simultaneously",
            REASON_CLOCK_DRIFT => "System clock drift detected",
            _ => "Unknown reason",
        }
    }

    /// Returns the timestamp of the last trip in milliseconds.
    pub fn trip_timestamp(&self) -> u64 {
        self.trip_timestamp_ms.load(Ordering::Acquire)
    }

    /// Returns the total number of times the breaker has been tripped.
    pub fn trip_count(&self) -> u64 {
        self.trip_count.load(Ordering::Acquire)
    }

    /// Returns the total number of trades rejected due to frozen state.
    pub fn rejected_count(&self) -> u64 {
        self.rejected_count.load(Ordering::Acquire)
    }
}

/// Error returned when a trade is rejected by the circuit breaker.
#[derive(Debug, Clone)]
pub enum CircuitBreakerError {
    SystemFrozen {
        reason_code: u64,
        rejected_total: u64,
    },
}

impl std::fmt::Display for CircuitBreakerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitBreakerError::SystemFrozen { reason_code, rejected_total } => {
                write!(f, "System frozen (reason code: {}), {} trades rejected", reason_code, rejected_total)
            }
        }
    }
}

impl std::error::Error for CircuitBreakerError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let breaker = EngineCircuitBreaker::new();
        assert!(!breaker.is_frozen());
        assert!(breaker.check_and_reject().is_ok());
        assert_eq!(breaker.trip_count(), 0);
        assert_eq!(breaker.rejected_count(), 0);
    }

    #[test]
    fn test_trip_and_check() {
        let breaker = EngineCircuitBreaker::new();
        breaker.trip(REASON_MANUAL_KILL);
        assert!(breaker.is_frozen());
        assert!(breaker.check_and_reject().is_err());
        assert_eq!(breaker.trip_reason_code(), REASON_MANUAL_KILL);
        assert_eq!(breaker.trip_count(), 1);
    }

    #[test]
    fn test_reset() {
        let breaker = EngineCircuitBreaker::new();
        breaker.trip(REASON_BALANCE_CORRUPTION);
        assert!(breaker.is_frozen());
        let was_frozen = breaker.reset();
        assert!(was_frozen);
        assert!(!breaker.is_frozen());
        assert!(breaker.check_and_reject().is_ok());
    }

    #[test]
    fn test_trip_is_idempotent() {
        let breaker = EngineCircuitBreaker::new();
        breaker.trip(REASON_MANUAL_KILL);
        breaker.trip(REASON_DRAWDOWN_BREACHED); // Second trip should be ignored
        assert_eq!(breaker.trip_count(), 1); // Only 1 trip recorded
        assert_eq!(breaker.trip_reason_code(), REASON_MANUAL_KILL); // First reason kept
    }

    #[test]
    fn test_rejected_count_increments() {
        let breaker = EngineCircuitBreaker::new();
        breaker.trip(REASON_MANUAL_KILL);
        assert!(breaker.check_and_reject().is_err());
        assert!(breaker.check_and_reject().is_err());
        assert!(breaker.check_and_reject().is_err());
        assert_eq!(breaker.rejected_count(), 3);
    }

    #[test]
    fn test_reason_strings() {
        let breaker = EngineCircuitBreaker::new();
        breaker.trip(REASON_EXCHANGE_MASS_FAILURE);
        assert!(breaker.trip_reason_string().contains("exchanges"));
    }

    #[test]
    fn test_trip_timestamp() {
        let breaker = EngineCircuitBreaker::new();
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        breaker.trip(REASON_UNKNOWN);
        let ts = breaker.trip_timestamp();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(ts >= before && ts <= after);
    }

    #[test]
    fn test_reset_returns_false_when_not_frozen() {
        let breaker = EngineCircuitBreaker::new();
        let was_frozen = breaker.reset();
        assert!(!was_frozen);
    }
}