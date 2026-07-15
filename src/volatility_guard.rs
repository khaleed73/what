//! Volatility / Spread Ceiling Guard
//!
//! The spec requires: "Volatility / Spread Ceiling — Reject trades if
//! bid-ask spread > threshold (e.g., 0.08%)"
//!
//! This module provides a fast, lock-free guard that rejects trading
//! opportunities when the market spread exceeds a configured maximum.
//! Wide spreads indicate low liquidity or market instability.

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Default spread ceiling: 0.08% (80 basis points).
const DEFAULT_SPREAD_CEILING_BPS: u64 = 80;

/// Stores a Decimal as fixed-point u64 with 9 decimal places.
fn decimal_to_fp(d: Decimal) -> u64 {
    (d * Decimal::from(1_000_000_000u64)).to_u64().unwrap_or(0)
}

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
}

impl VolatilityGuard {
    /// Creates a new guard with the default 0.08% (80 bps) ceiling.
    pub fn new() -> Self {
        Self {
            spread_ceiling_bps: AtomicU64::new(DEFAULT_SPREAD_CEILING_BPS),
            exchange_overrides: std::sync::Mutex::new(HashMap::new()),
            rejection_count: AtomicU64::new(0),
        }
    }

    /// Creates with a custom spread ceiling in basis points.
    pub fn with_ceiling_bps(ceiling_bps: u64) -> Self {
        Self {
            spread_ceiling_bps: AtomicU64::new(ceiling_bps),
            exchange_overrides: std::sync::Mutex::new(HashMap::new()),
            rejection_count: AtomicU64::new(0),
        }
    }

    /// Set a per-exchange override for the spread ceiling.
    pub fn set_exchange_ceiling(&self, exchange_id: u16, ceiling_bps: u64) {
        self.exchange_overrides
            .lock()
            .unwrap()
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
        let spread_bps_fp = decimal_to_fp(spread * Decimal::from(10_000u64) / mid);

        // Get the effective ceiling for this exchange.
        let ceiling_bps = {
            let overrides = self.exchange_overrides.lock().unwrap();
            *overrides.get(&exchange_id).unwrap_or(&self.spread_ceiling_bps.load(Ordering::SeqCst))
        };

        // Convert ceiling to same fixed-point scale.
        let ceiling_fp = ceiling_bps * 1_000_000_000;

        if spread_bps_fp > ceiling_fp {
            self.rejection_count.fetch_add(1, Ordering::SeqCst);
            tracing::debug!(
                exchange_id,
                spread_bps = spread_bps_fp / 1_000_000_000,
                ceiling_bps,
                "Trade rejected: spread exceeds ceiling"
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

    /// Get the global spread ceiling in basis points.
    pub fn ceiling_bps(&self) -> u64 {
        self.spread_ceiling_bps.load(Ordering::SeqCst)
    }

    /// Set the global spread ceiling dynamically.
    pub fn set_ceiling_bps(&self, bps: u64) {
        self.spread_ceiling_bps.store(bps, Ordering::SeqCst);
    }

    /// Get the total rejection count.
    pub fn rejection_count(&self) -> u64 {
        self.rejection_count.load(Ordering::SeqCst)
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