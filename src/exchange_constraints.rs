//! Exchange Constraints Module — Enforces per-exchange trading rules.
//!
//! Each exchange has specific rules for:
//!   - Price tick size (minimum price increment)
//!   - Lot/step size (minimum quantity increment)
//!   - Minimum notional value (minimum order value in quote currency)
//!
//! This module also provides VWAP slippage calculation through order book depth.

use rust_decimal::prelude::*;
use rust_decimal_macros::dec;

/// Per-exchange trading constraints loaded from exchange info APIs.
#[derive(Debug, Clone)]
pub struct ExchangeConstraints {
    /// Minimum price increment (e.g., 0.01 for two decimal places)
    pub price_tick_size: Decimal,
    /// Minimum quantity increment (e.g., 0.0001)
    pub base_step_size: Decimal,
    /// Minimum order value in quote currency (e.g., $5.00 or $10.00)
    pub min_notional: Decimal,
    /// Maximum quantity per order (if enforced by exchange)
    pub max_quantity: Option<Decimal>,
    /// Minimum quantity per order
    pub min_quantity: Decimal,
}

impl Default for ExchangeConstraints {
    fn default() -> Self {
        Self {
            price_tick_size: dec!(0.01),
            base_step_size: dec!(0.00001),
            min_notional: dec!(5.0),
            max_quantity: None,
            min_quantity: dec!(0.00001),
        }
    }
}

impl ExchangeConstraints {
    /// Creates constraints with explicit values.
    pub fn new(
        price_tick_size: Decimal,
        base_step_size: Decimal,
        min_notional: Decimal,
        max_quantity: Option<Decimal>,
        min_quantity: Decimal,
    ) -> Self {
        Self {
            price_tick_size,
            base_step_size,
            min_notional,
            max_quantity,
            min_quantity,
        }
    }

    /// Rounds a price DOWN to the nearest valid tick for BUY orders.
    /// For buy limit orders, rounding down gives a better fill price.
    pub fn round_price_buy(&self, price: Decimal) -> Decimal {
        if self.price_tick_size <= Decimal::ZERO {
            return price;
        }
        let ticks = (price / self.price_tick_size).floor();
        ticks * self.price_tick_size
    }

    /// Rounds a price UP to the nearest valid tick for SELL orders.
    /// For sell limit orders, rounding up gives a better fill price.
    pub fn round_price_sell(&self, price: Decimal) -> Decimal {
        if self.price_tick_size <= Decimal::ZERO {
            return price;
        }
        let ticks = (price / self.price_tick_size).ceil();
        ticks * self.price_tick_size
    }

    /// Rounds a quantity DOWN to the nearest valid step.
    /// Rounding down ensures we don't exceed available balance.
    pub fn round_quantity_down(&self, quantity: Decimal) -> Decimal {
        if self.base_step_size <= Decimal::ZERO {
            return quantity;
        }
        let steps = (quantity / self.base_step_size).floor();
        steps * self.base_step_size
    }

    /// Validates that a quantity meets minimum requirements.
    pub fn validate_quantity(&self, quantity: Decimal) -> Result<Decimal, String> {
        if quantity < self.min_quantity {
            return Err(format!(
                "Quantity {} below minimum {}",
                quantity, self.min_quantity
            ));
        }
        if let Some(max_qty) = self.max_quantity {
            if quantity > max_qty {
                return Err(format!(
                    "Quantity {} exceeds maximum {}",
                    quantity, max_qty
                ));
            }
        }
        Ok(self.round_quantity_down(quantity))
    }

    /// Validates that a notional value meets minimum requirements.
    pub fn validate_notional(&self, price: Decimal, quantity: Decimal) -> Result<Decimal, String> {
        let notional = price * quantity;
        if notional < self.min_notional {
            return Err(format!(
                "Notional {} below minimum {}",
                notional, self.min_notional
            ));
        }
        Ok(notional)
    }
}

/// A single depth level in the order book.
#[derive(Debug, Clone)]
pub struct DepthLevel {
    pub price: Decimal,
    pub quantity: Decimal,
}

/// Order book depth for slippage calculation.
#[derive(Debug, Clone)]
pub struct MarketDepth {
    /// Asks sorted ascending (lowest to highest) — for buying
    pub asks: Vec<DepthLevel>,
    /// Bids sorted descending (highest to lowest) — for selling
    pub bids: Vec<DepthLevel>,
}

/// Absolute Math Engine — calculates slippage through order book depth.
///
/// This engine walks through order book levels simulating a market order
/// to determine the actual average execution price (VWAP) for a given size.
pub struct AbsoluteMathEngine;

impl AbsoluteMathEngine {
    /// Calculates the VWAP buy price for a given spend amount through ask levels.
    ///
    /// Walks through ask levels (lowest first), consuming available liquidity
    /// until the entire spend amount is allocated or the book is exhausted.
    ///
    /// # Returns
    /// * `Ok(total_acquired)` - Total quantity of the base asset acquired
    /// * `Err` - If the book depth is insufficient to fill the full amount
    pub fn calculate_slippage_buy(
        depth: &MarketDepth,
        mut spend_allocated: Decimal,
    ) -> Result<Decimal, String> {
        if spend_allocated <= Decimal::ZERO {
            return Err("Spend amount must be positive".to_string());
        }

        let mut total_acquired = Decimal::ZERO;

        for level in &depth.asks {
            if level.price <= Decimal::ZERO {
                continue; // Skip invalid levels
            }
            let level_value = level.price * level.quantity;
            if spend_allocated <= level_value {
                // Partially consume this level
                let qty_from_level = spend_allocated / level.price;
                total_acquired += qty_from_level;
                spend_allocated = Decimal::ZERO;
                break;
            } else {
                // Fully consume this level
                total_acquired += level.quantity;
                spend_allocated -= level_value;
            }
        }

        if spend_allocated > Decimal::ZERO {
            return Err(format!(
                "Insufficient ask depth to fill ${:.2} — ${:.2} unfilled",
                spend_allocated + (depth.asks.iter().map(|l| l.price * l.quantity).sum::<Decimal>() - spend_allocated),
                spend_allocated
            ));
        }

        Ok(total_acquired)
    }

    /// Calculates the VWAP sell price for a given asset quantity through bid levels.
    ///
    /// Walks through bid levels (highest first), consuming available liquidity
    /// until the entire quantity is sold or the book is exhausted.
    ///
    /// # Returns
    /// * `Ok(total_received)` - Total quote currency received from the sale
    /// * `Err` - If the book depth is insufficient
    pub fn calculate_slippage_sell(
        depth: &MarketDepth,
        mut asset_quantity: Decimal,
    ) -> Result<Decimal, String> {
        if asset_quantity <= Decimal::ZERO {
            return Err("Asset quantity must be positive".to_string());
        }

        let mut total_received = Decimal::ZERO;

        for level in &depth.bids {
            if level.price <= Decimal::ZERO {
                continue;
            }
            if asset_quantity <= level.quantity {
                // Partially consume this level
                total_received += asset_quantity * level.price;
                asset_quantity = Decimal::ZERO;
                break;
            } else {
                // Fully consume this level
                total_received += level.quantity * level.price;
                asset_quantity -= level.quantity;
            }
        }

        if asset_quantity > Decimal::ZERO {
            return Err(format!(
                "Insufficient bid depth to sell {:.8} units — {:.8} unfilled",
                asset_quantity + (depth.bids.iter().map(|l| l.quantity).sum::<Decimal>() - asset_quantity),
                asset_quantity
            ));
        }

        Ok(total_received)
    }

    /// Applies exchange constraints to a raw price and quantity.
    ///
    /// # Arguments
    /// * `raw_price` - The calculated price from the strategy
    /// * `raw_quantity` - The calculated quantity from the strategy
    /// * `is_buy` - Whether this is a buy order (determines rounding direction)
    /// * `constraints` - Exchange-specific constraints
    ///
    /// # Returns
    /// * Adjusted (price, quantity) that comply with exchange rules
    pub fn apply_exchange_constraints(
        raw_price: Decimal,
        raw_quantity: Decimal,
        is_buy: bool,
        constraints: &ExchangeConstraints,
    ) -> (Decimal, Decimal) {
        let price = if is_buy {
            constraints.round_price_buy(raw_price)
        } else {
            constraints.round_price_sell(raw_price)
        };
        let quantity = constraints.round_quantity_down(raw_quantity);
        (price, quantity)
    }

    /// Calculates the VWAP (Volume-Weighted Average Price) for a buy order.
    ///
    /// # Returns
    /// * `Ok(vwap_price)` - The average price per unit acquired
    /// * `Err` - If insufficient depth
    pub fn calculate_vwap_buy(
        depth: &MarketDepth,
        spend_amount: Decimal,
    ) -> Result<Decimal, String> {
        let total_acquired = Self::calculate_slippage_buy(depth, spend_amount)?;
        if total_acquired <= Decimal::ZERO {
            return Err("Acquired zero quantity — cannot compute VWAP".to_string());
        }
        Ok(spend_amount / total_acquired)
    }

    /// Calculates the VWAP for a sell order.
    ///
    /// # Returns
    /// * `Ok(vwap_price)` - The average price per unit sold
    /// * `Err` - If insufficient depth
    pub fn calculate_vwap_sell(
        depth: &MarketDepth,
        asset_quantity: Decimal,
    ) -> Result<Decimal, String> {
        let total_received = Self::calculate_slippage_sell(depth, asset_quantity)?;
        if asset_quantity <= Decimal::ZERO {
            return Err("Zero quantity — cannot compute VWAP".to_string());
        }
        Ok(total_received / asset_quantity)
    }
}

// ---------------------------------------------------------------------------
// Exchange-specific constraint checks
// ---------------------------------------------------------------------------

/// Validates that a Bybit order does not violate hedging-mode rules.
///
/// In Bybit's **hedge mode** a single instrument cannot hold both a long
/// and a short position simultaneously.  Call this before placing an order
/// that would open the opposing side.
///
/// # Arguments
/// * `symbol` — Trading pair (e.g. `"BTCUSDT"`).
/// * `current_side` — The side of the position/order already held (`"Long"` or `"Short"`).
/// * `new_side` — The side of the incoming order (`"Long"` or `"Short"`).
/// * `hedging_mode` — `true` if the account is in hedge mode.
///
/// # Returns
/// `Ok(())` if the order is allowed, `Err(description)` otherwise.
pub fn validate_bybit_hedging_mode(
    symbol: &str,
    current_side: &str,
    new_side: &str,
    hedging_mode: bool,
) -> Result<(), String> {
    if !hedging_mode {
        return Ok(());
    }
    if current_side.to_lowercase() == new_side.to_lowercase() {
        return Ok(());
    }
    Err(format!(
        "Bybit hedge mode violation on {}: cannot open {} position while {} is held",
        symbol, new_side, current_side
    ))
}

/// Margin mode for OKX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OkxMarginMode {
    /// Cross margin: entire account balance is available as collateral.
    Cross,
    /// Isolated margin: only the position's allocated margin is at risk.
    Isolated,
}

/// Validates that an OKX order is compatible with the account's margin mode.
///
/// In **cross** margin the full wallet balance may be used, so the
/// `available_balance` argument should reflect the cross-margin available
/// amount.  In **isolated** margin only the `position_margin` allocated to
/// that specific position may be used.
///
/// # Arguments
/// * `symbol` — Trading pair (e.g. `"BTC-USDT-SWAP"`).
/// * `required_margin` — Margin needed for the order.
/// * `available_balance` — Account- or position-level available balance.
/// * `margin_mode` — Current margin mode.
///
/// # Returns
/// `Ok(())` if the order can be margined, `Err(description)` otherwise.
pub fn validate_okx_margin_mode(
    symbol: &str,
    required_margin: Decimal,
    available_balance: Decimal,
    margin_mode: OkxMarginMode,
) -> Result<(), String> {
    if required_margin > available_balance {
        return Err(format!(
            "OKX {} margin insufficient: required {} but only {} available ({:?} mode)",
            symbol, required_margin, available_balance, margin_mode
        ));
    }
    Ok(())
}

/// Validates that a Coinbase limit order is submitted as post-only.
///
/// Coinbase charges a **taker fee** for orders that execute immediately.
/// To avoid this, limit orders should be placed with `post_only: true`
/// so they are only added to the order book and never cross the spread.
///
/// # Arguments
/// * `symbol` — Trading pair (e.g. `"BTC-USD"`).
/// * `is_limit_order` — Whether the order is a limit order (as opposed to market).
/// * `post_only` — Whether the `post_only` flag is set on the order.
///
/// # Returns
/// `Ok(())` if the order is correctly configured, `Err(description)` otherwise.
pub fn validate_coinbase_post_only(
    symbol: &str,
    is_limit_order: bool,
    post_only: bool,
) -> Result<(), String> {
    if is_limit_order && !post_only {
        return Err(format!(
            "Coinbase {} limit order must be post-only to avoid taker fees",
            symbol
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_constraints() -> ExchangeConstraints {
        ExchangeConstraints::new(
            dec!(0.01),     // tick size
            dec!(0.001),    // step size
            dec!(5.0),      // min notional
            Some(dec!(100.0)), // max quantity
            dec!(0.001),    // min quantity
        )
    }

    #[test]
    fn test_round_price_buy_down() {
        let c = sample_constraints();
        assert_eq!(c.round_price_buy(dec!(50000.057)), dec!(50000.05));
        assert_eq!(c.round_price_buy(dec!(50000.009)), dec!(50000.0));
    }

    #[test]
    fn test_round_price_sell_up() {
        let c = sample_constraints();
        assert_eq!(c.round_price_sell(dec!(50000.051)), dec!(50000.06));
        assert_eq!(c.round_price_sell(dec!(50000.0)), dec!(50000.0));
    }

    #[test]
    fn test_round_quantity_down() {
        let c = sample_constraints();
        assert_eq!(c.round_quantity_down(dec!(1.23456)), dec!(1.234));
        assert_eq!(c.round_quantity_down(dec!(0.0005)), Decimal::ZERO);
    }

    #[test]
    fn test_validate_quantity_ok() {
        let c = sample_constraints();
        assert!(c.validate_quantity(dec!(1.0)).is_ok());
        assert!(c.validate_quantity(dec!(0.001)).is_ok());
    }

    #[test]
    fn test_validate_quantity_below_min() {
        let c = sample_constraints();
        assert!(c.validate_quantity(dec!(0.0001)).is_err());
    }

    #[test]
    fn test_validate_quantity_above_max() {
        let c = sample_constraints();
        assert!(c.validate_quantity(dec!(200.0)).is_err());
    }

    #[test]
    fn test_validate_notional_ok() {
        let c = sample_constraints();
        assert!(c.validate_notional(dec!(50000.0), dec!(0.001)).is_ok()); // $50
    }

    #[test]
    fn test_validate_notional_below_min() {
        let c = sample_constraints();
        assert!(c.validate_notional(dec!(100.0), dec!(0.001)).is_err()); // $0.10
    }

    #[test]
    fn test_slippage_buy_single_level() {
        let depth = MarketDepth {
            asks: vec![DepthLevel { price: dec!(50000.0), quantity: dec!(1.0) }],
            bids: vec![],
        };
        // Spend $25000 → should get 0.5 BTC
        let result = AbsoluteMathEngine::calculate_slippage_buy(&depth, dec!(25000.0));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), dec!(0.5));
    }

    #[test]
    fn test_slippage_buy_multiple_levels() {
        let depth = MarketDepth {
            asks: vec![
                DepthLevel { price: dec!(50000.0), quantity: dec!(0.5) },  // $25000 at this level
                DepthLevel { price: dec!(50100.0), quantity: dec!(0.5) },  // $25050 at this level
            ],
            bids: vec![],
        };
        // Spend $50000 → 0.5 at 50000 + (25000/50100) at 50100 ≈ 0.999 BTC
        let result = AbsoluteMathEngine::calculate_slippage_buy(&depth, dec!(50000.0));
        assert!(result.is_ok());
        let expected = dec!(0.5) + dec!(25000) / dec!(50100);
        assert!((result.unwrap() - expected).abs() < dec!(0.0000001));
    }

    #[test]
    fn test_slippage_buy_insufficient_depth() {
        let depth = MarketDepth {
            asks: vec![DepthLevel { price: dec!(50000.0), quantity: dec!(0.1) }], // Only $5000 depth
            bids: vec![],
        };
        let result = AbsoluteMathEngine::calculate_slippage_buy(&depth, dec!(10000.0));
        assert!(result.is_err());
    }

    #[test]
    fn test_slippage_sell_single_level() {
        let depth = MarketDepth {
            asks: vec![],
            bids: vec![DepthLevel { price: dec!(50000.0), quantity: dec!(1.0) }],
        };
        // Sell 0.5 BTC → should get $25000
        let result = AbsoluteMathEngine::calculate_slippage_sell(&depth, dec!(0.5));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), dec!(25000.0));
    }

    #[test]
    fn test_vwap_buy() {
        let depth = MarketDepth {
            asks: vec![
                DepthLevel { price: dec!(50000.0), quantity: dec!(0.5) },
                DepthLevel { price: dec!(50200.0), quantity: dec!(0.5) },
            ],
            bids: vec![],
        };
        // Spend $50000 → VWAP = 50000 / (0.5 + 0.4980079681) ≈ 50100
        let vwap = AbsoluteMathEngine::calculate_vwap_buy(&depth, dec!(50000.0));
        assert!(vwap.is_ok());
        // 0.5 @ 50000 = $25000, then 0.498007... @ 50200 = $24999.6...
        // Total qty ≈ 0.998008, VWAP ≈ 50000/0.998008 ≈ 50100
        let price = vwap.unwrap();
        assert!(price >= dec!(50000.0) && price <= dec!(50200.0));
    }

    #[test]
    fn test_apply_constraints_buy() {
        let c = sample_constraints();
        let (price, qty) = AbsoluteMathEngine::apply_exchange_constraints(
            dec!(50000.057), dec!(1.2345), true, &c,
        );
        assert_eq!(price, dec!(50000.05)); // Rounded down for buy
        assert_eq!(qty, dec!(1.234));       // Rounded down
    }

    #[test]
    fn test_apply_constraints_sell() {
        let c = sample_constraints();
        let (price, qty) = AbsoluteMathEngine::apply_exchange_constraints(
            dec!(50000.051), dec!(1.2345), false, &c,
        );
        assert_eq!(price, dec!(50000.06)); // Rounded up for sell
        assert_eq!(qty, dec!(1.234));       // Rounded down
    }

    #[test]
    fn test_zero_price_level_skipped() {
        let depth = MarketDepth {
            asks: vec![
                DepthLevel { price: Decimal::ZERO, quantity: dec!(1.0) }, // Invalid — skipped
                DepthLevel { price: dec!(50000.0), quantity: dec!(1.0) },
            ],
            bids: vec![],
        };
        let result = AbsoluteMathEngine::calculate_slippage_buy(&depth, dec!(10000.0));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), dec!(0.2));
    }

    #[test]
    fn test_zero_spend_rejected() {
        let depth = MarketDepth { asks: vec![], bids: vec![] };
        assert!(AbsoluteMathEngine::calculate_slippage_buy(&depth, Decimal::ZERO).is_err());
    }

    // -- Exchange-specific constraint tests --

    #[test]
    fn test_bybit_hedging_same_side_ok() {
        assert!(validate_bybit_hedging_mode("BTCUSDT", "Long", "Long", true).is_ok());
        assert!(validate_bybit_hedging_mode("BTCUSDT", "Short", "short", true).is_ok());
    }

    #[test]
    fn test_bybit_hedging_opposing_side_rejected() {
        let err = validate_bybit_hedging_mode("BTCUSDT", "Long", "Short", true);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("hedge mode violation"));
    }

    #[test]
    fn test_bybit_one_way_mode_always_ok() {
        // In one-way mode hedging rules don't apply.
        assert!(validate_bybit_hedging_mode("BTCUSDT", "Long", "Short", false).is_ok());
    }

    #[test]
    fn test_okx_margin_sufficient() {
        assert!(validate_okx_margin_mode(
            "BTC-USDT-SWAP", dec!(100.0), dec!(200.0), OkxMarginMode::Cross
        ).is_ok());
        assert!(validate_okx_margin_mode(
            "BTC-USDT-SWAP", dec!(100.0), dec!(100.0), OkxMarginMode::Isolated
        ).is_ok());
    }

    #[test]
    fn test_okx_margin_insufficient() {
        let err = validate_okx_margin_mode(
            "BTC-USDT-SWAP", dec!(200.0), dec!(100.0), OkxMarginMode::Isolated
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("margin insufficient"));
    }

    #[test]
    fn test_coinbase_post_only_limit_ok() {
        assert!(validate_coinbase_post_only("BTC-USD", true, true).is_ok());
    }

    #[test]
    fn test_coinbase_post_only_limit_missing_flag() {
        let err = validate_coinbase_post_only("BTC-USD", true, false);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("post-only"));
    }

    #[test]
    fn test_coinbase_market_order_no_flag_needed() {
        // Market orders don't need post-only.
        assert!(validate_coinbase_post_only("BTC-USD", false, false).is_ok());
    }
}