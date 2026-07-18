//! Per-Exchange Rate Limit Circuit Breaker
//!
//! Tracks API weight consumption per exchange (e.g. Binance `X-MBX-USED-WEIGHT`)
//! and pauses trading when usage reaches a configurable threshold (default 80%).
//! This is the spec-mandated `RateLimitCircuitBreaker`.
//!
//! Each exchange gets its own independent rate-limit state so a rate-limit
//! event on Binance does not freeze OKX or Bybit.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Per-exchange rate limit state.
struct ExchangeRateState {
    /// Current used weight within the window.
    used_weight: AtomicU64,
    /// Maximum allowed weight within the window.
    max_weight: AtomicU64,
    /// Threshold fraction (e.g. 0.80 = pause at 80%).
    pause_threshold: AtomicU32, // stored as basis points: 80% = 8000
    /// Whether this exchange is currently paused.
    is_paused: AtomicBool,
    /// Time of last pause (for cooldown tracking).
    paused_at: std::sync::Mutex<Option<Instant>>,
    /// Required cooldown duration after a pause.
    cooldown_duration: Duration,
    /// Consecutive rate-limit violations.
    consecutive_violations: AtomicU32,
    /// Max consecutive violations before extended cooldown.
    max_violations_before_extended: u32,
    /// Start of the current time window (for automatic rotation).
    window_start: std::sync::Mutex<Instant>,
    /// Duration of each weight window.
    window_duration: Duration,
}

impl ExchangeRateState {
    fn new(max_weight: u64, pause_threshold_pct: f64, cooldown: Duration) -> Self {
        Self {
            used_weight: AtomicU64::new(0),
            max_weight: AtomicU64::new(max_weight),
            pause_threshold: AtomicU32::new((pause_threshold_pct * 10_000.0).round() as u32),
            is_paused: AtomicBool::new(false),
            paused_at: std::sync::Mutex::new(None),
            cooldown_duration: cooldown,
            consecutive_violations: AtomicU32::new(0),
            max_violations_before_extended: 3,
            window_start: std::sync::Mutex::new(Instant::now()),
            window_duration: Duration::from_secs(60), // 60-second window by default
        }
    }

    #[inline(always)]
    fn is_paused_fast(&self) -> bool {
        self.is_paused.load(Ordering::SeqCst)
    }

    fn record_weight(&self, weight: u64) -> RateLimitStatus {
        // C-2: Automatic time-window rotation.
        let _window_elapsed = {
            let mut guard = self.window_start.lock().unwrap_or_else(|e| e.into_inner());
            let elapsed = guard.elapsed();
            if elapsed >= self.window_duration {
                *guard = Instant::now();
                self.used_weight.store(weight, Ordering::SeqCst);
                return RateLimitStatus::Ok;
            }
            elapsed
        };

        if self.is_paused.load(Ordering::SeqCst) {
            // Check if cooldown has elapsed — use extended cooldown
            // when consecutive violations exceed the threshold.
            let should_resume = {
                let guard = self.paused_at.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(paused_at) = *guard {
                    let violations = self.consecutive_violations.load(Ordering::SeqCst);
                    let effective_cooldown = if violations >= self.max_violations_before_extended {
                        self.cooldown_duration * 3
                    } else {
                        self.cooldown_duration
                    };
                    paused_at.elapsed() >= effective_cooldown
                } else {
                    false
                }
            };

            if should_resume {
                self.is_paused.store(false, Ordering::SeqCst);
                *self.paused_at.lock().unwrap_or_else(|e| e.into_inner()) = None;
                // Reset weight counter and violation count for new window.
                self.used_weight.store(weight, Ordering::SeqCst);
                self.consecutive_violations.store(0, Ordering::SeqCst);
                return RateLimitStatus::Ok;
            }
            return RateLimitStatus::Paused {
                remaining_ms: {
                    let guard = self.paused_at.lock().unwrap_or_else(|e| e.into_inner());
                    let violations = self.consecutive_violations.load(Ordering::SeqCst);
                    let effective_cooldown = if violations >= self.max_violations_before_extended {
                        self.cooldown_duration * 3
                    } else {
                        self.cooldown_duration
                    };
                    guard
                        .map(|t| {
                            let remaining = effective_cooldown.saturating_sub(t.elapsed());
                            remaining.as_millis() as u64
                        })
                        .unwrap_or(0)
                },
            };
        }

        let prev = self.used_weight.fetch_add(weight, Ordering::SeqCst);
        let current = prev + weight;
        let threshold = self.pause_threshold.load(Ordering::SeqCst) as u64;
        let max = self.max_weight.load(Ordering::SeqCst);

        if current >= (max * threshold / 10_000) {
            // Trip the pause.
            self.is_paused.store(true, Ordering::SeqCst);
            *self.paused_at.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());

            let violations = self.consecutive_violations.fetch_add(1, Ordering::SeqCst) + 1;

            // Extended cooldown after multiple violations.
            let cooldown_ms = if violations >= self.max_violations_before_extended {
                self.cooldown_duration.as_millis() as u64 * 3
            } else {
                self.cooldown_duration.as_millis() as u64
            };

            RateLimitStatus::Tripped {
                used: current,
                max,
                violations,
                cooldown_ms,
            }
        } else {
            self.consecutive_violations.store(0, Ordering::SeqCst);
            RateLimitStatus::Ok
        }
    }

    fn reset_window(&self) {
        self.used_weight.store(0, Ordering::SeqCst);
        self.consecutive_violations.store(0, Ordering::SeqCst);
    }
}

/// Result of a rate-limit check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitStatus {
    /// Weight is within acceptable range.
    Ok,
    /// Exchange has been paused; contains remaining cooldown in ms.
    Paused { remaining_ms: u64 },
    /// Exchange just tripped the rate limit.
    Tripped {
        used: u64,
        max: u64,
        violations: u32,
        cooldown_ms: u64,
    },
}

/// Per-exchange rate limit circuit breaker.
///
/// The spec requires tracking `X-MBX-USED-WEIGHT` style headers and
/// pausing at 80% utilization.
pub struct RateLimitCircuitBreaker {
    exchanges: HashMap<String, Arc<ExchangeRateState>>,
    default_max_weight: u64,
    default_pause_threshold: f64,
    default_cooldown: Duration,
}

impl RateLimitCircuitBreaker {
    /// Creates a new rate limit circuit breaker with default settings.
    ///
    /// - `default_max_weight`: Max API weight per window (e.g. 2400 for Binance)
    /// - `default_pause_threshold`: Pause at this fraction (e.g. 0.80)
    /// - `default_cooldown`: Cooldown duration after tripping (e.g. 60s)
    pub fn new(default_max_weight: u64, default_pause_threshold: f64, default_cooldown: Duration) -> Self {
        Self {
            exchanges: HashMap::new(),
            default_max_weight,
            default_pause_threshold,
            default_cooldown,
        }
    }

    /// Registers an exchange with default settings.
    pub fn register_exchange(&mut self, exchange_id: &str) {
        self.register_exchange_with_config(
            exchange_id,
            self.default_max_weight,
            self.default_pause_threshold,
            self.default_cooldown,
        );
    }

    /// Registers an exchange with custom settings.
    pub fn register_exchange_with_config(
        &mut self,
        exchange_id: &str,
        max_weight: u64,
        pause_threshold: f64,
        cooldown: Duration,
    ) {
        let state = Arc::new(ExchangeRateState::new(max_weight, pause_threshold, cooldown));
        self.exchanges.insert(exchange_id.to_lowercase(), state);
    }

    /// Record API weight consumption for an exchange.
    ///
    /// Returns the current rate-limit status.
    #[inline]
    pub fn record_weight(&self, exchange_id: &str, weight: u64) -> RateLimitStatus {
        if let Some(state) = self.exchanges.get(&exchange_id.to_lowercase()) {
            state.record_weight(weight)
        } else {
            // C-3: Unregistered exchanges must be rejected to prevent
            // unbounded API usage that could trigger exchange bans.
            tracing::error!(exchange = %exchange_id, "Rate limit check for unregistered exchange — REFUSING");
            RateLimitStatus::Paused { remaining_ms: u64::MAX }
        }
    }

    /// Quick check if an exchange is currently paused (no weight update).
    #[inline(always)]
    pub fn is_paused(&self, exchange_id: &str) -> bool {
        if let Some(state) = self.exchanges.get(&exchange_id.to_lowercase()) {
            state.is_paused_fast()
        } else {
            false
        }
    }

    /// Reset the weight window for an exchange (called on window rotation).
    pub fn reset_window(&self, exchange_id: &str) {
        if let Some(state) = self.exchanges.get(&exchange_id.to_lowercase()) {
            state.reset_window();
        }
    }

    /// Reset all exchange weight windows.
    pub fn reset_all_windows(&self) {
        for state in self.exchanges.values() {
            state.reset_window();
        }
    }

    /// Get current weight usage for an exchange (used_weight, max_weight).
    pub fn get_usage(&self, exchange_id: &str) -> Option<(u64, u64)> {
        self.exchanges
            .get(&exchange_id.to_lowercase())
            .map(|s| (s.used_weight.load(Ordering::SeqCst), s.max_weight.load(Ordering::SeqCst)))
    }

    /// Returns the number of registered exchanges.
    pub fn exchange_count(&self) -> usize {
        self.exchanges.len()
    }

    /// Returns `true` if any exchange is currently paused.
    pub fn any_paused(&self) -> bool {
        self.exchanges.values().any(|s| s.is_paused_fast())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_breaker() -> RateLimitCircuitBreaker {
        let mut cb = RateLimitCircuitBreaker::new(1000, 0.80, Duration::from_secs(30));
        cb.register_exchange("binance");
        cb.register_exchange_with_config("bybit", 2000, 0.75, Duration::from_secs(60));
        cb
    }

    #[test]
    fn test_record_weight_ok() {
        let cb = make_breaker();
        let status = cb.record_weight("binance", 500);
        assert_eq!(status, RateLimitStatus::Ok);
        assert!(!cb.is_paused("binance"));
    }

    #[test]
    fn test_record_weight_trips_at_threshold() {
        let cb = make_breaker();
        // 80% of 1000 = 800. Record 801 weight → should trip.
        let status = cb.record_weight("binance", 801);
        assert!(matches!(status, RateLimitStatus::Tripped { .. }));
        assert!(cb.is_paused("binance"));
    }

    #[test]
    fn test_independent_exchanges() {
        let cb = make_breaker();
        // Trip binance
        cb.record_weight("binance", 900);
        assert!(cb.is_paused("binance"));
        // Bybit should still be OK
        assert!(!cb.is_paused("bybit"));
        assert_eq!(cb.record_weight("bybit", 100), RateLimitStatus::Ok);
    }

    #[test]
    fn test_unregistered_exchange_allowed() {
        let cb = make_breaker();
        // C-3: Unregistered exchanges are now rejected (Paused).
        assert!(matches!(cb.record_weight("unknown", 100), RateLimitStatus::Paused { .. }));
    }

    #[test]
    fn test_get_usage() {
        let cb = make_breaker();
        cb.record_weight("binance", 300);
        let (used, max) = cb.get_usage("binance").unwrap();
        assert_eq!(used, 300);
        assert_eq!(max, 1000);
    }

    #[test]
    fn test_reset_window() {
        let cb = make_breaker();
        cb.record_weight("binance", 500);
        cb.reset_window("binance");
        let (used, _) = cb.get_usage("binance").unwrap();
        assert_eq!(used, 0);
    }

    #[test]
    fn test_exchange_count() {
        let cb = make_breaker();
        assert_eq!(cb.exchange_count(), 2);
    }

    #[test]
    fn test_any_paused() {
        let cb = make_breaker();
        assert!(!cb.any_paused());
        cb.record_weight("binance", 900);
        assert!(cb.any_paused());
    }

    #[test]
    fn test_violations_counter() {
        let cb = make_breaker();
        // First trip
        let s1 = cb.record_weight("binance", 900);
        if let RateLimitStatus::Tripped { violations, .. } = s1 {
            assert_eq!(violations, 1);
        } else {
            panic!("Expected Tripped");
        }

        // Reset and trip again — violations counter resets on window reset.
        // Also need to clear the pause flag, since reset_window only resets
        // weight/violations, not the pause state.
        cb.reset_window("binance");
        if let Some(ex) = cb.exchanges.get("binance") {
            ex.is_paused.store(false, Ordering::SeqCst);
            *ex.paused_at.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
        let s2 = cb.record_weight("binance", 900);
        if let RateLimitStatus::Tripped { violations, .. } = s2 {
            assert_eq!(violations, 1);
        } else {
            panic!("Expected Tripped");
        }
    }
}