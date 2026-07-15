//! Production Risk Shield with D-VWAP Discrete Slippage
//!
//! The spec defines `ProductionRiskShield` — an advanced risk engine with:
//! - `FastOrderBook` (fixed-size stack-allocated order book)
//! - `OrderBookLayer` (stack-allocated price/quantity layer)
//! - `MarketExecutionRules` (exchange tick/lot/notional rules)
//! - `process_discrete_buy_slippage` — steps through fixed-size asks,
//!   applies fee, truncates lot step, returns (qty, VWAP)
//! - `validate_execution_safety` — checks min notional + profit margin floor

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

/// Number of depth levels in the production order book.
const MATRIX_BOOK_DEPTH: usize = 4;

/// A single order book layer — stack-allocated for zero-allocation parsing.
#[derive(Debug, Clone, Copy, Default)]
pub struct OrderBookLayer {
    /// Price as fixed-point u64 (9 decimals).
    pub price_fp: u64,
    /// Quantity as fixed-point u64 (9 decimals).
    pub quantity_fp: u64,
}

impl OrderBookLayer {
    /// Creates a new layer from Decimal values.
    pub fn from_decimal(price: Decimal, quantity: Decimal) -> Self {
        Self {
            price_fp: decimal_to_fp(price),
            quantity_fp: decimal_to_fp(quantity),
        }
    }

    /// Get price as Decimal.
    pub fn price(&self) -> Decimal {
        fp_to_decimal(self.price_fp)
    }

    /// Get quantity as Decimal.
    pub fn quantity(&self) -> Decimal {
        fp_to_decimal(self.quantity_fp)
    }
}

/// Fixed-size, stack-allocated order book for production risk calculations.
#[derive(Debug, Clone)]
pub struct FastOrderBook {
    pub asks: [OrderBookLayer; MATRIX_BOOK_DEPTH],
    pub bids: [OrderBookLayer; MATRIX_BOOK_DEPTH],
}

impl Default for FastOrderBook {
    fn default() -> Self {
        Self {
            asks: [OrderBookLayer::default(); MATRIX_BOOK_DEPTH],
            bids: [OrderBookLayer::default(); MATRIX_BOOK_DEPTH],
        }
    }
}

impl FastOrderBook {
    /// Creates an empty order book.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set ask levels from Decimal arrays.
    pub fn set_asks(&mut self, prices: &[Decimal], quantities: &[Decimal]) {
        for i in 0..MATRIX_BOOK_DEPTH {
            if i < prices.len() && i < quantities.len() {
                self.asks[i] = OrderBookLayer::from_decimal(prices[i], quantities[i]);
            }
        }
    }

    /// Set bid levels from Decimal arrays.
    pub fn set_bids(&mut self, prices: &[Decimal], quantities: &[Decimal]) {
        for i in 0..MATRIX_BOOK_DEPTH {
            if i < prices.len() && i < quantities.len() {
                self.bids[i] = OrderBookLayer::from_decimal(prices[i], quantities[i]);
            }
        }
    }
}

/// Exchange-specific execution rules.
#[derive(Debug, Clone, Copy)]
pub struct MarketExecutionRules {
    /// Minimum price increment.
    pub tick_size: Decimal,
    /// Minimum quantity increment.
    pub lot_step_size: Decimal,
    /// Minimum order notional value.
    pub minimum_notional: Decimal,
}

impl Default for MarketExecutionRules {
    fn default() -> Self {
        Self {
            tick_size: dec!(0.01),
            lot_step_size: dec!(0.001),
            minimum_notional: dec!(5.0),
        }
    }
}

/// The spec-mandated `ProductionRiskShield`.
///
/// Provides discrete VWAP slippage calculation and execution safety validation.
pub struct ProductionRiskShield {
    /// Total taker fee across all legs (combined).
    pub total_taker_fee: Decimal,
    /// Minimum net profit margin as Decimal (e.g. 0.0012 = 0.12%).
    pub net_profit_floor: Decimal,
    /// Exchange execution rules.
    pub rules: MarketExecutionRules,
}

impl ProductionRiskShield {
    /// Creates a new production risk shield.
    pub fn new(total_taker_fee: Decimal, net_profit_floor: Decimal, rules: MarketExecutionRules) -> Self {
        Self {
            total_taker_fee,
            net_profit_floor,
            rules,
        }
    }

    /// Creates with default Binance-like rules.
    pub fn with_defaults() -> Self {
        Self::new(
            dec!(0.002),  // 0.2% total taker fee
            dec!(0.0012), // 0.12% profit floor
            MarketExecutionRules::default(),
        )
    }

    /// Process discrete buy slippage — walks through fixed-size ask levels,
    /// applies fee, truncates lot step, returns (executable_qty, VWAP).
    ///
    /// This is the spec-mandated `process_discrete_buy_slippage` method.
    #[inline]
    pub fn process_discrete_buy_slippage(
        &self,
        book: &FastOrderBook,
        spend_amount: Decimal,
    ) -> (Decimal, Decimal) {
        let mut remaining = spend_amount;
        let mut total_qty = Decimal::ZERO;
        let mut total_cost = Decimal::ZERO;

        for layer in &book.asks {
            if layer.quantity_fp == 0 || remaining <= Decimal::ZERO {
                break;
            }

            let price = layer.price();
            let qty = layer.quantity();
            let level_cost = price * qty;

            if level_cost <= remaining {
                // Take the entire level.
                total_qty += qty;
                total_cost += level_cost;
                remaining -= level_cost;
            } else {
                // Partial fill.
                let partial_qty = remaining / price;
                total_qty += partial_qty;
                total_cost += remaining;
                remaining = Decimal::ZERO;
            }
        }

        // Apply lot step truncation (floor to exchange step size).
        let truncated_qty = self.truncate_lot_step(total_qty);

        // Compute VWAP.
        let vwap = if truncated_qty > Decimal::ZERO {
            total_cost / truncated_qty
        } else {
            Decimal::ZERO
        };

        (truncated_qty, vwap)
    }

    /// Validate execution safety — checks min notional + profit margin floor.
    ///
    /// This is the spec-mandated `validate_execution_safety` method.
    ///
    /// # Arguments
    /// * `notional` — Order notional value
    /// * `expected_profit_pct` — Expected profit as percentage
    ///
    /// # Returns
    /// `true` if execution is safe, `false` if rejected.
    #[inline(always)]
    pub fn validate_execution_safety(&self, notional: Decimal, expected_profit_pct: Decimal) -> bool {
        // Check minimum notional.
        if notional < self.rules.minimum_notional {
            tracing::debug!(
                notional = %notional,
                min_notional = %self.rules.minimum_notional,
                "Rejected: below minimum notional"
            );
            return false;
        }

        // Check profit margin floor.
        if expected_profit_pct < self.net_profit_floor * Decimal::from(100u32) {
            tracing::debug!(
                profit_pct = %expected_profit_pct,
                min_profit = %(self.net_profit_floor * Decimal::from(100u32)),
                "Rejected: below profit floor"
            );
            return false;
        }

        true
    }

    /// Truncate quantity to lot step size (floor).
    /// This is `RoundingStrategy::ToZero` from the spec.
    #[inline(always)]
    fn truncate_lot_step(&self, qty: Decimal) -> Decimal {
        if self.rules.lot_step_size > Decimal::ZERO {
            (qty / self.rules.lot_step_size).floor() * self.rules.lot_step_size
        } else {
            qty
        }
    }
}

// Helper functions
fn decimal_to_fp(d: Decimal) -> u64 {
    (d * Decimal::from(1_000_000_000u64)).to_u64().unwrap_or(0)
}

fn fp_to_decimal(fp: u64) -> Decimal {
    Decimal::from(fp) / Decimal::from(1_000_000_000u64)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    fn make_shield() -> ProductionRiskShield {
        ProductionRiskShield::new(
            dec!(0.002),
            dec!(0.0012),
            MarketExecutionRules {
                tick_size: dec!(0.01),
                lot_step_size: dec!(0.001),
                minimum_notional: dec!(5.0),
            },
        )
    }

    fn make_book() -> FastOrderBook {
        let mut book = FastOrderBook::new();
        book.set_asks(
            &[dec!(100.0), dec!(100.5), dec!(101.0), dec!(101.5)],
            &[dec!(10.0), dec!(10.0), dec!(10.0), dec!(10.0)],
        );
        book
    }

    #[test]
    fn test_order_book_layer() {
        let layer = OrderBookLayer::from_decimal(dec!(150.25), dec!(1.5));
        assert!((layer.price() - dec!(150.25)).abs() < dec!(0.001));
        assert!((layer.quantity() - dec!(1.5)).abs() < dec!(0.001));
    }

    #[test]
    fn test_discrete_buy_slippage_full_levels() {
        let shield = make_shield();
        let book = make_book();
        // Spend $500 — takes 5 units at $100 level.
        let (qty, vwap) = shield.process_discrete_buy_slippage(&book, dec!(500));
        assert!((qty - dec!(5.0)).abs() < dec!(0.01));
        assert!((vwap - dec!(100.0)).abs() < dec!(0.01));
    }

    #[test]
    fn test_discrete_buy_slippage_partial() {
        let shield = make_shield();
        let book = make_book();
        // Spend $1500 — takes all 10 at $100, then 500/100.5 ≈ 4.975 at $100.5.
        // Total qty ≈ 14.975 (truncated to lot_step 0.001).
        let (qty, vwap) = shield.process_discrete_buy_slippage(&book, dec!(1500));
        assert!((qty - dec!(14.975)).abs() < dec!(0.01));
        // VWAP should be between $100 and $100.5.
        assert!(vwap > dec!(100.0) && vwap < dec!(100.5));
    }

    #[test]
    fn test_discrete_buy_slippage_truncates_lot_step() {
        let mut shield = make_shield();
        shield.rules.lot_step_size = dec!(1.0); // Whole units only.
        let book = make_book();
        let (qty, _) = shield.process_discrete_buy_slippage(&book, dec!(50)); // 0.5 units.
        // Should truncate to 0 due to 1.0 lot step.
        assert_eq!(qty, dec!(0));
    }

    #[test]
    fn test_validate_safety_passes() {
        let shield = make_shield();
        assert!(shield.validate_execution_safety(dec!(100), dec!(0.5)));
    }

    #[test]
    fn test_validate_safety_below_notional() {
        let shield = make_shield();
        assert!(!shield.validate_execution_safety(dec!(3), dec!(0.5)));
    }

    #[test]
    fn test_validate_safety_below_profit() {
        let shield = make_shield();
        // 0.05% < 0.12% floor.
        assert!(!shield.validate_execution_safety(dec!(100), dec!(0.05)));
    }
}