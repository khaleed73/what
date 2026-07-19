//! Volatility / Spread Ceiling Guard
//!
//! The spec requires: "Volatility / Spread Ceiling — Reject trades if
//! bid-ask spread > threshold (e.g., 0.08%)"
//!
//! This module provides a guard that rejects trading opportunities when the
//! market spread exceeds a configured maximum. Wide spreads indicate low
//! liquidity or market instability.
//!
//! NOTE (L-2): This guard is NOT fully lock-free. The EMA state and
//! per-exchange overrides use `Mutex` internally. The hot-path
//! `check_spread()` acquires two mutexes per call (EMA + overrides).
//! Only `spread_ceiling_bps`, `rejection_count`, and `ema_period` are
//! truly lock-free via `AtomicU64`.

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Default spread ceiling: 0.80% (80 basis points).
const DEFAULT_SPREAD_CEILING_BPS: u64 = 80;

/// Upper bound for a reasonable spread in basis points (1 trillion bps).
/// Values above this are considered nonsensical and rejected.
const MAX_REASONABLE_SPREAD_BPS: u64 = 1_000_000_000_000;

/// Stores a Decimal as fixed-point u64 with 9 decimal places.
#[inline]
fn decimal_to_fp(d: Decimal) -> u64 {
    match (d * Decimal::from(1_000_000_000u64)).to_u64() {
        Some(fp) if fp > 0 => fp,
        Some(_) => {
            tracing::warn!(value = %d, "volatility_guard decimal_to_fp: zero or negative result, returning 0");
            0
        }
        None => {
            tracing::error!(value = %d, "volatility_guard decimal_to_fp: overflow — returning MAX sentinel");
            u64::MAX
        }
    }
}

/// Converts a fixed-point u64 back to a Decimal.
#[inline]
fn fp_to_decimal(fp: u64) -> Decimal {
    Decimal::from(fp) / Decimal::from(1_000_000_000u64)
}

/// Volatility guard that rejects trades when the bid-ask spread
/// is too wide.
pub struct VolatilityGuard {
    /// Maximum allowed spread in basis points (1% = 100 bps).
    /// Stored as AtomicU64 for runtime reconfiguration.
    spread_ceiling_bps: AtomicU64,
    /// Per-exchange spread ceilings (exchange_id → bps).
    /// If set, overrides the global ceiling for that exchange.
    exchange_overrides: std::sync::Mutex<std::collections::HashMap<u16, u64>>,
    /// Number of rejected trades due to spread ceiling.
    rejection_count: AtomicU64,
    /// EMA of spread in basis points. `None` before the first observation.
    /// Uses exponential moving average: `ema = α * new + (1-α) * ema`
    /// where `α = 2 / (period + 1)`. This gives more weight to recent
    /// data and reacts faster to volatility spikes compared to SMA.
    ema_spread_bps: std::sync::Mutex<Option<Decimal>>,
    /// EMA period. Default: 20. Higher values produce smoother (slower)
    /// EMA; lower values make it more responsive.
    ema_period: AtomicU64,
}

impl VolatilityGuard {
    /// Default EMA period.
    const DEFAULT_EMA_PERIOD: u64 = 20;

    /// Creates a new guard with the default 0.08% (80 bps) ceiling.
    ///
    /// # Example
    /// ```
    /// use rust_hft_arb::volatility_guard::VolatilityGuard;
    /// let guard = VolatilityGuard::new();
    /// assert_eq!(guard.ceiling_bps(), 80);
    /// ```
    pub fn new() -> Self {
        Self {
            spread_ceiling_bps: AtomicU64::new(DEFAULT_SPREAD_CEILING_BPS),
            exchange_overrides: std::sync::Mutex::new(HashMap::new()),
            rejection_count: AtomicU64::new(0),
            ema_spread_bps: std::sync::Mutex::new(None),
            ema_period: AtomicU64::new(Self::DEFAULT_EMA_PERIOD),
        }
    }

    /// Creates a guard with a custom spread ceiling in basis points.
    pub fn with_ceiling_bps(ceiling_bps: u64) -> Self {
        Self {
            spread_ceiling_bps: AtomicU64::new(ceiling_bps),
            exchange_overrides: std::sync::Mutex::new(HashMap::new()),
            rejection_count: AtomicU64::new(0),
            ema_spread_bps: std::sync::Mutex::new(None),
            ema_period: AtomicU64::new(Self::DEFAULT_EMA_PERIOD),
        }
    }

    /// Set a per-exchange override for the spread ceiling.
    pub fn set_exchange_ceiling(&self, exchange_id: u16, ceiling_bps: u64) {
        self.exchange_overrides
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(exchange_id, ceiling_bps);
    }

    /// Evaluate whether a trade should be allowed based on spread.
    ///
    /// # Arguments
    /// * `exchange_id` — The exchange to check
    /// * `best_bid` — Best bid price
    /// * `best_ask` — Best ask price
    ///
    /// # Returns
    /// `true` if the spread is within bounds (trade allowed),
    /// `false` if spread exceeds ceiling (trade rejected).
    #[inline(always)]
    pub fn check_spread(&self, exchange_id: u16, best_bid: Decimal, best_ask: Decimal) -> bool {
        if best_bid <= Decimal::ZERO || best_ask <= Decimal::ZERO {
            return false;
        }

        // Compute spread in basis points.
        // spread_bps = ((ask - bid) / mid) * 10_000
        let mid = (best_bid + best_ask) / Decimal::TWO;
        let spread = best_ask - best_bid;
        let current_spread_bps = spread * Decimal::from(10_000u64) / mid;

        // Guard against unreasonable spreads that would poison the EMA.
        // 1 trillion bps (= 10 billion %) is clearly nonsensical for any real spread.
        if current_spread_bps <= Decimal::ZERO || current_spread_bps > Decimal::from(MAX_REASONABLE_SPREAD_BPS) {
            return false;
        }

        // Update EMA: ema = α * new + (1 - α) * ema
        // α = 2 / (period + 1)
        let period = self.ema_period.load(Ordering::Acquire);
        let alpha = Decimal::from(2u64) / Decimal::from(period + 1);
        let one_minus_alpha = Decimal::ONE - alpha;
        let ema_bps = {
            let mut ema_guard = self.ema_spread_bps.lock().unwrap_or_else(|e| e.into_inner());
            match *ema_guard {
                None => {
                    // Seed EMA with the first observation.
                    *ema_guard = Some(current_spread_bps);
                    current_spread_bps
                }
                Some(old_ema) => {
                    let new_ema = alpha * current_spread_bps + one_minus_alpha * old_ema;
                    *ema_guard = Some(new_ema);
                    new_ema
                }
            }
        };

        // Get the effective ceiling for this exchange.
        let ceiling_bps = {
            let overrides = self.exchange_overrides.lock().unwrap_or_else(|e| e.into_inner());
            *overrides.get(&exchange_id).unwrap_or(&self.spread_ceiling_bps.load(Ordering::Acquire))
        };

        // H-3: Compare instantaneous spread against the ceiling (not EMA).
        if current_spread_bps > Decimal::from(ceiling_bps) {
            self.rejection_count.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                exchange_id,
                spread_bps = %current_spread_bps,
                ema_bps = %ema_bps,
                ceiling_bps,
                "spread ceiling breached"
            );
            false
        } else {
            true
        }
    }

    /// Compute the current spread in basis points.
    #[inline]
    pub fn compute_spread_bps(best_bid: Decimal, best_ask: Decimal) -> Decimal {
        if best_bid <= Decimal::ZERO || best_ask <= Decimal::ZERO {
            return Decimal::MAX;
        }
        let mid = (best_bid + best_ask) / Decimal::TWO;
        (best_ask - best_bid) * Decimal::from(10_000u64) / mid
    }

    /// L-3: Observes a spread and updates the EMA without performing any
    /// rejection checks. Useful for feeding spread data from exchanges that
    /// are not currently being traded, keeping the EMA fresh and preventing
    /// it from going stale.
    #[inline]
    pub fn observe_spread(&self, best_bid: Decimal, best_ask: Decimal) {
        if best_bid <= Decimal::ZERO || best_ask <= Decimal::ZERO {
            return;
        }
        let mid = (best_bid + best_ask) / Decimal::TWO;
        let current_spread_bps = (best_ask - best_bid) * Decimal::from(10_000u64) / mid;

        // Guard against unreasonable spreads that would poison the EMA.
        if current_spread_bps <= Decimal::ZERO || current_spread_bps > Decimal::from(1_000_000_000_000u64) {
            return;
        }

        let period = self.ema_period.load(Ordering::Acquire);
        let alpha = Decimal::from(2u64) / Decimal::from(period + 1);
        let one_minus_alpha = Decimal::ONE - alpha;
        let mut ema_guard = self.ema_spread_bps.lock().unwrap_or_else(|e| e.into_inner());
        match *ema_guard {
            None => {
                *ema_guard = Some(current_spread_bps);
            }
            Some(old_ema) => {
                let new_ema = alpha * current_spread_bps + one_minus_alpha * old_ema;
                *ema_guard = Some(new_ema);
            }
        }
    }

    /// Get the global spread ceiling in basis points.
    pub fn ceiling_bps(&self) -> u64 {
        self.spread_ceiling_bps.load(Ordering::Acquire)
    }

    /// Set the global spread ceiling dynamically.
    pub fn set_ceiling_bps(&self, bps: u64) {
        self.spread_ceiling_bps.store(bps, Ordering::Release);
    }

    /// Get the total rejection count since creation.
    pub fn rejection_count(&self) -> u64 {
        self.rejection_count.load(Ordering::Acquire)
    }

    /// Returns the current EMA-smoothed spread in basis points, or `None` if
    /// no spread observations have been made yet.
    pub fn spread_ema_bps(&self) -> Option<Decimal> {
        *self.ema_spread_bps.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Updates the EMA period. Higher values produce smoother (slower)
    /// EMA; lower values make it more responsive to recent changes.
    /// Note: changing the period resets the EMA so it re-seeds on the next
    /// observation.
    pub fn update_ema_period(&self, period: u64) {
        self.ema_period.store(period.max(2), Ordering::Release);
        *self.ema_spread_bps.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// M-5: Resets the EMA state, forcing re-seeding on the next observation.
    ///
    /// Useful when an exchange-specific override is removed or after a
    /// prolonged market disconnection where the EMA would be stale.
    pub fn reset_ema(&self) {
        *self.ema_spread_bps.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

impl Default for VolatilityGuard {
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
    use rust_decimal_macros::dec;

    #[test]
    fn test_normal_spread_allowed() {
        let guard = VolatilityGuard::new(); // 80 bps
        // bid=100, ask=100.05 → spread = 0.05% = 5 bps → allowed
        assert!(guard.check_spread(1, dec!(100), dec!(100.05)));
    }

    #[test]
    fn test_wide_spread_rejected() {
        let guard = VolatilityGuard::new(); // 80 bps
        // bid=100, ask=101 → spread = 1% = 100 bps → rejected
        assert!(!guard.check_spread(1, dec!(100), dec!(101)));
    }

    #[test]
    fn test_exact_boundary() {
        let guard = VolatilityGuard::with_ceiling_bps(100); // 1%
        // bid=100, ask=101 → exactly 100 bps → should be allowed (not >)
        assert!(guard.check_spread(1, dec!(100), dec!(101)));
    }

    #[test]
    fn test_exchange_override() {
        let guard = VolatilityGuard::with_ceiling_bps(100); // 1% global
        guard.set_exchange_ceiling(1, 20); // 0.2% for exchange 1
        // 0.5% spread — OK globally, rejected for exchange 1
        assert!(!guard.check_spread(1, dec!(100), dec!(100.5)));
        assert!(guard.check_spread(2, dec!(100), dec!(100.5))); // no override
    }

    #[test]
    fn test_zero_prices_rejected() {
        let guard = VolatilityGuard::new();
        assert!(!guard.check_spread(1, dec!(0), dec!(100)));
    }

    #[test]
    fn test_rejection_count() {
        let guard = VolatilityGuard::new();
        guard.check_spread(1, dec!(100), dec!(101)); // rejected
        guard.check_spread(1, dec!(100), dec!(101)); // rejected
        assert_eq!(guard.rejection_count(), 2);
    }

    #[test]
    fn test_compute_spread_bps() {
        let bps = VolatilityGuard::compute_spread_bps(dec!(100), dec!(100.05));
        assert!((bps - dec!(4.9975)).abs() < dec!(0.01));
    }
}