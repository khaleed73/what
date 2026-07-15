//! Atomic Stablecoin Depeg Protection Circuit
//!
//! Lock-free depeg detection using `AtomicBool`. When a monitored stablecoin
//! (e.g. USDT) deviates from its $1.00 peg by more than the configured
//! threshold, the circuit trips and blocks all trading until the peg is
//! restored. This is the spec-mandated `StablecoinProtectionCircuit`.
//!
//! The spec defines three methods:
//! - `new(symbol)` — creates a circuit for a target stablecoin
//! - `check_safety()` — returns `!is_depegged` (true = safe to trade)
//! - `set_depeg_state(state)` — atomically sets the depegged flag

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Atomic depeg detection circuit for a single stablecoin symbol.
///
/// Usage:
/// ```ignore
/// let circuit = StablecoinProtectionCircuit::new("USDT");
/// if circuit.check_safety() {
///     // safe to trade
/// }
/// ```
pub struct StablecoinProtectionCircuit {
    /// Target stablecoin symbol (e.g. "USDT", "USDC").
    target_symbol: String,
    /// `true` when the stablecoin has depegged beyond threshold.
    is_depegged: AtomicBool,
    /// Depeg detection threshold — if `|price - 1.0| > threshold`, trip.
    /// Default: 0.005 (0.5% off peg).
    threshold: Decimal,
    /// Last known price of the stablecoin.
    last_price: std::sync::atomic::AtomicU64,
    /// Volatility multiplier in fixed-point (10000 = 1.0x). The effective
    /// threshold is `base_threshold * volatility_multiplier`. Allows callers
    /// to increase sensitivity during high-volatility periods.
    volatility_multiplier: AtomicU64,
}

impl StablecoinProtectionCircuit {
    /// Creates a new depeg protection circuit for the given stablecoin symbol.
    ///
    /// Default threshold is 0.5% (0.005). Use `with_threshold` to customize.
    #[inline]
    pub fn new(symbol: &str) -> Self {
        Self {
            target_symbol: symbol.to_uppercase(),
            is_depegged: AtomicBool::new(false),
            threshold: dec!(0.005),
            last_price: std::sync::atomic::AtomicU64::new(1_000_000u64), // $1.00 in fixed-point (6 decimals)
            volatility_multiplier: AtomicU64::new(10_000), // 1.0x in fixed-point
        }
    }

    /// Creates a circuit with a custom depeg threshold.
    #[inline]
    pub fn with_threshold(symbol: &str, threshold: Decimal) -> Self {
        Self {
            target_symbol: symbol.to_uppercase(),
            is_depegged: AtomicBool::new(false),
            threshold,
            last_price: std::sync::atomic::AtomicU64::new(1_000_000u64),
            volatility_multiplier: AtomicU64::new(10_000), // 1.0x in fixed-point
        }
    }

    /// Returns the monitored symbol name.
    #[inline]
    pub fn symbol(&self) -> &str {
        &self.target_symbol
    }

    /// Returns `true` if the stablecoin is **NOT** depegged (safe to trade).
    /// Returns `false` if the circuit has been tripped.
    ///
    /// This is the spec-mandated safety check method.
    #[inline(always)]
    pub fn check_safety(&self) -> bool {
        !self.is_depegged.load(Ordering::SeqCst)
    }

    /// Atomically sets the depegged state.
    ///
    /// # Arguments
    /// * `depegged` — `true` to trip the circuit (freeze trading),
    ///   `false` to clear it (resume trading).
    #[inline]
    pub fn set_depeg_state(&self, depegged: bool) {
        self.is_depegged.store(depegged, Ordering::SeqCst);
    }

    /// Ingests a new price and automatically evaluates depeg status.
    ///
    /// If `|price - 1.0| > threshold`, the circuit trips.
    /// If the price returns within bounds, the circuit clears.
    #[inline]
    pub fn update_price(&self, price: Decimal) {
        // Store price as fixed-point u64 (6 decimal places) for atomic reads.
        let fixed_price = (price * Decimal::from(1_000_000u64))
            .to_u64()
            .unwrap_or(1_000_000u64);
        self.last_price.store(fixed_price, Ordering::SeqCst);

        let deviation = if price > Decimal::ONE {
            price - Decimal::ONE
        } else {
            Decimal::ONE - price
        };

        // Effective threshold = base_threshold * volatility_multiplier
        let multiplier_fp = self.volatility_multiplier.load(Ordering::SeqCst);
        let effective_threshold =
            self.threshold * Decimal::from(multiplier_fp) / Decimal::from(10_000u64);

        let should_depeg = deviation > effective_threshold;
        let was_depegged = self.is_depegged.load(Ordering::SeqCst);

        if should_depeg && !was_depegged {
            tracing::warn!(
                symbol = %self.target_symbol,
                price = %price,
                deviation = %deviation,
                threshold = %self.threshold,
                "DEPEG detected — trading frozen for {}",
                self.target_symbol
            );
        } else if !should_depeg && was_depegged {
            tracing::info!(
                symbol = %self.target_symbol,
                price = %price,
                "Peg restored — trading resumed for {}",
                self.target_symbol
            );
        }

        self.is_depegged.store(should_depeg, Ordering::SeqCst);
    }

    /// Returns the current depeg state.
    #[inline]
    pub fn is_depegged(&self) -> bool {
        self.is_depegged.load(Ordering::SeqCst)
    }

    /// Returns the last known price as a Decimal.
    #[inline]
    pub fn last_price(&self) -> Decimal {
        let fixed = self.last_price.load(Ordering::SeqCst);
        Decimal::from(fixed) / Decimal::from(1_000_000u64)
    }

    /// Returns the configured depeg threshold.
    #[inline]
    pub fn threshold(&self) -> Decimal {
        self.threshold
    }

    /// Updates the volatility multiplier. This scales the effective depeg
    /// threshold: `effective = base_threshold * multiplier`.
    ///
    /// # Arguments
    /// * `multiplier` — A float where 1.0 means no change, 2.0 doubles the
    ///   threshold (more lenient), 0.5 halves it (more sensitive).
    ///   Stored internally as fixed-point (10000 = 1.0x).
    #[inline]
    pub fn update_volatility_multiplier(&self, multiplier: f64) {
        let fp = (multiplier * 10_000.0).round() as u64;
        self.volatility_multiplier.store(fp, Ordering::SeqCst);
    }

    /// Returns the current volatility multiplier as an f64.
    #[inline]
    pub fn volatility_multiplier(&self) -> f64 {
        let fp = self.volatility_multiplier.load(Ordering::SeqCst);
        fp as f64 / 10_000.0
    }

    /// Returns the effective (multiplier-scaled) depeg threshold.
    #[inline]
    pub fn effective_threshold(&self) -> Decimal {
        let multiplier_fp = self.volatility_multiplier.load(Ordering::SeqCst);
        self.threshold * Decimal::from(multiplier_fp) / Decimal::from(10_000u64)
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
    fn test_new_circuit_is_safe() {
        let circuit = StablecoinProtectionCircuit::new("USDT");
        assert!(circuit.check_safety());
        assert!(!circuit.is_depegged());
        assert_eq!(circuit.symbol(), "USDT");
    }

    #[test]
    fn test_set_depeg_state_trips_circuit() {
        let circuit = StablecoinProtectionCircuit::new("USDT");
        assert!(circuit.check_safety());

        circuit.set_depeg_state(true);
        assert!(!circuit.check_safety());
        assert!(circuit.is_depegged());

        circuit.set_depeg_state(false);
        assert!(circuit.check_safety());
        assert!(!circuit.is_depegged());
    }

    #[test]
    fn test_update_price_normal() {
        let circuit = StablecoinProtectionCircuit::with_threshold("USDT", dec!(0.005));
        circuit.update_price(dec!(1.0001));
        assert!(circuit.check_safety());
    }

    #[test]
    fn test_update_price_trips_on_depeg() {
        let circuit = StablecoinProtectionCircuit::with_threshold("USDT", dec!(0.005));
        circuit.update_price(dec!(0.993)); // 0.7% off peg — exceeds 0.5%
        assert!(!circuit.check_safety());
        assert!(circuit.is_depegged());
    }

    #[test]
    fn test_update_price_clears_on_recovery() {
        let circuit = StablecoinProtectionCircuit::with_threshold("USDT", dec!(0.005));
        circuit.update_price(dec!(0.993));
        assert!(!circuit.check_safety());

        circuit.update_price(dec!(0.999)); // back within 0.5%
        assert!(circuit.check_safety());
    }

    #[test]
    fn test_last_price_tracking() {
        let circuit = StablecoinProtectionCircuit::new("USDC");
        circuit.update_price(dec!(0.9995));
        let price = circuit.last_price();
        assert!((price - dec!(0.9995)).abs() < dec!(0.0001));
    }

    #[test]
    fn test_custom_threshold() {
        // Tight 0.1% threshold
        let circuit = StablecoinProtectionCircuit::with_threshold("DAI", dec!(0.001));
        circuit.update_price(dec!(0.998)); // 0.2% off — exceeds 0.1%
        assert!(!circuit.check_safety());
    }

    #[test]
    fn test_multiple_circuits_independent() {
        let usdt = StablecoinProtectionCircuit::new("USDT");
        let usdc = StablecoinProtectionCircuit::new("USDC");

        usdt.update_price(dec!(0.993)); // trips USDT
        assert!(!usdt.check_safety());
        assert!(usdc.check_safety()); // USDC still safe
    }
}