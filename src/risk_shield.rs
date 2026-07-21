//! Risk Shield Module — Strict mathematical verification for triangular and cross-exchange arbitrage.
//!
//! This module provides two core risk shields:
//!   1. `RiskShield` — Verifies triangular loops with fee-adjusted net return > 1.0
//!   2. `CrossExchangeRiskShield` — Validates cross-exchange windows with min notional, fee, and profit floor

use rust_decimal::prelude::*;
use rust_decimal_macros::dec;

/// Minimum order notional for triangular loops (in base currency).
const MIN_ORDER_NOTIONAL: Decimal = dec!(10.0);

/// Minimum order book depth required per leg.
const MIN_LEG_LIQUIDITY: Decimal = dec!(1.0);

/// Market ticker snapshot with best bid/ask and available quantity.
#[derive(Debug, Clone)]
pub struct MarketTicker {
    pub ask_price: Decimal,
    pub ask_qty: Decimal,
    pub bid_price: Decimal,
    pub bid_qty: Decimal,
}

/// Verifies triangular arbitrage loops with strict mathematical safety.
///
/// A profitable loop exists if:
///   Net Return = (1 - f1) * (1 - f2) * (1 - f3) * Product(Rate_i) > 1.0
///
/// Where Rate_i is the exchange rate per leg and f_i is the trading fee per leg.
pub struct RiskShield {
    pub min_capital_requirement: Decimal,
    pub standard_fee_rate: Decimal,
    pub execution_safety_buffer: Decimal,
}

impl RiskShield {
    /// Creates a new risk shield with the given configuration.
    pub fn new(
        min_capital: Decimal,
        fee_rate: Decimal,
        safety_buffer: Decimal,
    ) -> Self {
        Self {
            min_capital_requirement: min_capital,
            standard_fee_rate: fee_rate,
            execution_safety_buffer: safety_buffer,
        }
    }

    /// Evaluates a 3-leg triangular loop with order book depth simulation and fee deduction.
    ///
    /// # Arguments
    /// * `capital` - Starting capital in base currency (e.g., USDT)
    /// * `leg1` - Ticker for first leg (e.g., USDT→BTC buy at ask)
    /// * `leg2` - Ticker for second leg (e.g., BTC→ETH buy at ask)
    /// * `leg3` - Ticker for third leg (e.g., ETH→USDT sell at bid)
    /// * `fee_rate` - Per-leg taker fee (e.g., 0.001 = 0.1%)
    ///
    /// # Returns
    /// * `Some(profit)` - Net profit after all fees if loop is profitable
    /// * `None` - Loop is unprofitable or unsafe
    #[inline]
    pub fn verify_triangular_loop(
        &self,
        capital: Decimal,
        leg1: &MarketTicker,
        leg2: &MarketTicker,
        leg3: &MarketTicker,
        fee_rate: Decimal,
    ) -> Option<Decimal> {
        // M-3: Validate fee_rate is in [0, 1). Negative or >= 100% fees are nonsensical.
        if fee_rate < Decimal::ZERO || fee_rate >= Decimal::ONE {
            return None;
        }

        // Safety Guard 1: Minimum capital requirement
        if capital < MIN_ORDER_NOTIONAL {
            return None;
        }
        if capital < self.min_capital_requirement {
            return None;
        }

        // Safety Guard 2: Validate all prices are positive and non-zero
        if leg1.ask_price <= Decimal::ZERO
            || leg2.ask_price <= Decimal::ZERO
            || leg3.bid_price <= Decimal::ZERO
        {
            return None;
        }

        // Safety Guard 3: Validate minimum liquidity on each leg
        if leg1.ask_qty < MIN_LEG_LIQUIDITY || leg2.ask_qty < MIN_LEG_LIQUIDITY || leg3.bid_qty < MIN_LEG_LIQUIDITY {
            return None;
        }

        // Leg 1: Buy asset B with capital (pay ask price, incur fee)
        let leg1_qty_before_fee = capital / leg1.ask_price;
        let leg1_fee = leg1_qty_before_fee * fee_rate;
        let leg1_qty = leg1_qty_before_fee - leg1_fee;

        // Guard: Cannot buy zero units
        if leg1_qty <= Decimal::ZERO {
            return None;
        }

        // Safety Guard 4: Verify sufficient order book depth for leg 1
        if leg1_qty > leg1.ask_qty {
            return None;
        }

        // Leg 2: Buy asset C with asset B (pay ask price, incur fee)
        let leg2_qty_before_fee = leg1_qty / leg2.ask_price;
        let leg2_fee = leg2_qty_before_fee * fee_rate;
        let leg2_qty = leg2_qty_before_fee - leg2_fee;

        // Guard: Cannot buy zero units
        if leg2_qty <= Decimal::ZERO {
            return None;
        }

        // Safety Guard 5: Verify sufficient order book depth for leg 2
        if leg2_qty > leg2.ask_qty {
            return None;
        }

        // Leg 3: Sell asset C back to base currency (receive bid price, incur fee)
        let leg3_proceeds_before_fee = leg2_qty * leg3.bid_price;
        let leg3_fee = leg3_proceeds_before_fee * fee_rate;
        let leg3_proceeds = leg3_proceeds_before_fee - leg3_fee;

        // Safety Guard 6: Verify sufficient order book depth for leg 3 (sell side)
        if leg2_qty > leg3.bid_qty {
            return None;
        }

        // Calculate net return multiplier
        let net_return = leg3_proceeds / capital;

        // Must exceed 1.0 by the execution safety buffer
        let threshold = Decimal::ONE + self.execution_safety_buffer;
        if net_return <= threshold {
            return None;
        }

        let profit = leg3_proceeds - capital;

        // Final guard: profit must be strictly positive
        if profit <= Decimal::ZERO {
            return None;
        }

        Some(profit)
    }

    /// Mathematical verification: (1-f1)*(1-f2)*(1-f3)*product(rates) > 1.0
    /// This is the pure mathematical formulation without order book depth.
    #[inline]
    pub fn verify_triangular_math(
        &self,
        rate1: Decimal,
        rate2: Decimal,
        rate3: Decimal,
        f1: Decimal,
        f2: Decimal,
        f3: Decimal,
    ) -> bool {
        // Validate all rates are positive
        if rate1 <= Decimal::ZERO || rate2 <= Decimal::ZERO || rate3 <= Decimal::ZERO {
            return false;
        }
        // M-3: Validate all fee rates are in [0, 1).
        if f1 < Decimal::ZERO || f1 >= Decimal::ONE
            || f2 < Decimal::ZERO || f2 >= Decimal::ONE
            || f3 < Decimal::ZERO || f3 >= Decimal::ONE
        {
            return false;
        }
        let fee_factor = (Decimal::ONE - f1) * (Decimal::ONE - f2) * (Decimal::ONE - f3);
        let product_rates = rate1 * rate2 * rate3;
        let net_return = fee_factor * product_rates;
        net_return > (Decimal::ONE + self.execution_safety_buffer)
    }
}

/// Cross-exchange risk shield for CEX-to-CEX arbitrage validation.
pub struct CrossExchangeRiskShield {
    pub min_trade_notional: Decimal,
    pub exchange_x_fee: Decimal,
    pub exchange_y_fee: Decimal,
    pub absolute_profit_floor: Decimal,
}

impl CrossExchangeRiskShield {
    pub fn new(
        min_notional: Decimal,
        fee_x: Decimal,
        fee_y: Decimal,
        profit_floor: Decimal,
    ) -> Self {
        Self {
            min_trade_notional: min_notional,
            exchange_x_fee: fee_x,
            exchange_y_fee: fee_y,
            absolute_profit_floor: profit_floor,
        }
    }

    /// Evaluates a cross-exchange arbitrage window.
    ///
    /// # Arguments
    /// * `bid_x` - Best bid on exchange X (where we sell)
    /// * `ask_y` - Best ask on exchange Y (where we buy)
    /// * `bid_depth_x` - Available volume at best bid on X
    /// * `ask_depth_y` - Available volume at best ask on Y
    /// * `capital` - Available capital for the trade
    ///
    /// # Returns
    /// * `Some((qty, profit))` - Trade quantity and expected profit if profitable
    /// * `None` - Not profitable or unsafe
    #[inline]
    pub fn evaluate_window(
        &self,
        bid_x: Decimal,
        ask_y: Decimal,
        bid_depth_x: Decimal,
        ask_depth_y: Decimal,
        capital: Decimal,
    ) -> Option<(Decimal, Decimal)> {
        // Guard: Both prices must be positive
        if bid_x <= Decimal::ZERO || ask_y <= Decimal::ZERO {
            return None;
        }

        // Guard: Ask must be lower than bid (spread exists)
        if ask_y >= bid_x {
            return None;
        }

        // Calculate gross spread
        let spread = bid_x - ask_y;
        let spread_pct = spread / ask_y;

        // Deduct fees from both legs.
        // NOTE: This is a first-order approximation that assumes fees are a simple
        // additive rate on each leg. It does not account for maker/taker fee tiers,
        // volume-based discounts, or fee rebates that may apply at execution time.
        let total_fee_rate = self.exchange_x_fee + self.exchange_y_fee;
        let net_spread_pct = spread_pct - total_fee_rate;

        // Must be positive after fees
        if net_spread_pct <= Decimal::ZERO {
            return None;
        }

        // Determine trade quantity: min of available capital, depth on both sides
        let max_qty_from_capital = capital / ask_y;
        let max_qty = if max_qty_from_capital <= bid_depth_x && max_qty_from_capital <= ask_depth_y {
            max_qty_from_capital
        } else {
            bid_depth_x.min(ask_depth_y)
        };

        // Check minimum notional
        let notional = max_qty * ask_y;
        if notional < self.min_trade_notional {
            return None;
        }

        // Calculate profit
        let buy_cost = max_qty * ask_y;
        let sell_proceeds = max_qty * bid_x;
        let buy_fee = buy_cost * self.exchange_y_fee;
        let sell_fee = sell_proceeds * self.exchange_x_fee;
        let total_cost = buy_cost + buy_fee;
        let total_revenue = sell_proceeds - sell_fee;
        let profit = total_revenue - total_cost;

        // Check absolute profit floor
        if profit < self.absolute_profit_floor {
            return None;
        }

        // Final check: profit must be positive
        if profit <= Decimal::ZERO {
            return None;
        }

        Some((max_qty, profit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn test_triangular_profitable_loop() {
        let shield = RiskShield::new(dec!(10.0), dec!(0.001), dec!(0.001));
        let leg1 = MarketTicker {
            ask_price: dec!(50000.0), // 1 BTC = 50000 USDT
            ask_qty: dec!(1.0),
            bid_price: dec!(49990.0),
            bid_qty: dec!(1.0),
        };
        let leg2 = MarketTicker {
            ask_price: dec!(0.065), // 1 ETH = 0.065 BTC
            ask_qty: dec!(100.0),
            bid_price: dec!(0.0649),
            bid_qty: dec!(100.0),
        };
        let leg3 = MarketTicker {
            ask_price: dec!(3300.0), // 1 ETH = 3300 USDT
            ask_qty: dec!(100.0),
            bid_price: dec!(3320.0), // Sell ETH at 3320
            bid_qty: dec!(100.0),
        };

        // USDT -> BTC: 100/50000 = 0.002 BTC (fee: 0.000002) => 0.001998 BTC
        // BTC -> ETH: 0.001998/0.065 = 0.030738 ETH (fee: 0.000030738) => 0.030708 ETH
        // ETH -> USDT: 0.030708 * 3320 = 101.95 USDT (fee: 0.10195) => 101.85 USDT
        let result = shield.verify_triangular_loop(dec!(100.0), &leg1, &leg2, &leg3, dec!(0.001));
        assert!(result.is_some());
        let profit = result.unwrap();
        assert!(profit > Decimal::ZERO);
    }

    #[test]
    fn test_triangular_unprofitable_loop() {
        let shield = RiskShield::new(dec!(10.0), dec!(0.001), dec!(0.001));
        let leg1 = MarketTicker {
            ask_price: dec!(50000.0),
            ask_qty: dec!(1.0),
            bid_price: dec!(49990.0),
            bid_qty: dec!(1.0),
        };
        let leg2 = MarketTicker {
            ask_price: dec!(0.07),
            ask_qty: dec!(100.0),
            bid_price: dec!(0.0699),
            bid_qty: dec!(100.0),
        };
        let leg3 = MarketTicker {
            ask_price: dec!(3300.0),
            ask_qty: dec!(100.0),
            bid_price: dec!(3250.0), // Much lower — unprofitable
            bid_qty: dec!(100.0),
        };

        let result = shield.verify_triangular_loop(dec!(100.0), &leg1, &leg2, &leg3, dec!(0.001));
        assert!(result.is_none());
    }

    #[test]
    fn test_triangular_insufficient_capital() {
        let shield = RiskShield::new(dec!(50.0), dec!(0.001), dec!(0.001));
        let ticker = MarketTicker {
            ask_price: dec!(50000.0),
            ask_qty: dec!(1.0),
            bid_price: dec!(49990.0),
            bid_qty: dec!(1.0),
        };
        let result = shield.verify_triangular_loop(dec!(5.0), &ticker, &ticker, &ticker, dec!(0.001));
        assert!(result.is_none());
    }

    #[test]
    fn test_triangular_zero_price_rejected() {
        let shield = RiskShield::new(dec!(10.0), dec!(0.001), dec!(0.001));
        let bad_ticker = MarketTicker {
            ask_price: Decimal::ZERO,
            ask_qty: dec!(1.0),
            bid_price: dec!(1.0),
            bid_qty: dec!(1.0),
        };
        let good_ticker = MarketTicker {
            ask_price: dec!(100.0),
            ask_qty: dec!(1.0),
            bid_price: dec!(100.0),
            bid_qty: dec!(1.0),
        };
        let result = shield.verify_triangular_loop(dec!(100.0), &bad_ticker, &good_ticker, &good_ticker, dec!(0.001));
        assert!(result.is_none());
    }

    #[test]
    fn test_cross_exchange_profitable() {
        let shield = CrossExchangeRiskShield::new(dec!(5.0), dec!(0.001), dec!(0.001), dec!(0.01));
        // Buy on Y at 50000, sell on X at 50100 — 0.2% spread, fees 0.2%, net ~0% — but above floor
        let _result = shield.evaluate_window(dec!(50100.0), dec!(50000.0), dec!(1.0), dec!(1.0), dec!(50000.0));
        // spread = 100, buy cost = 50000, sell = 50100, buy_fee = 50, sell_fee = 50.1
        // profit = 50100 - 50.1 - 50000 - 50 = -0.1 — actually negative with these fees
        // Need bigger spread
        let result = shield.evaluate_window(dec!(50200.0), dec!(50000.0), dec!(1.0), dec!(1.0), dec!(50000.0));
        // spread = 200, buy_cost = 50000, sell = 50200, buy_fee = 50, sell_fee = 50.2
        // profit = 50200 - 50.2 - 50000 - 50 = 99.8
        assert!(result.is_some());
        let (qty, profit) = result.unwrap();
        assert_eq!(qty, dec!(1.0));
        assert!(profit > dec!(0.01));
    }

    #[test]
    fn test_cross_exchange_no_spread() {
        let shield = CrossExchangeRiskShield::new(dec!(5.0), dec!(0.001), dec!(0.001), dec!(0.01));
        // ask >= bid means no spread
        let result = shield.evaluate_window(dec!(50000.0), dec!(50000.0), dec!(1.0), dec!(1.0), dec!(50000.0));
        assert!(result.is_none());
    }

    #[test]
    fn test_cross_exchange_below_profit_floor() {
        let shield = CrossExchangeRiskShield::new(dec!(5.0), dec!(0.001), dec!(0.001), dec!(100.0));
        // Small spread — profit will be tiny
        let result = shield.evaluate_window(dec!(50010.0), dec!(50000.0), dec!(1.0), dec!(1.0), dec!(50000.0));
        // profit = 10 - 50 - 50.05 = -90.05 — negative
        assert!(result.is_none());
    }

    #[test]
    fn test_verify_triangular_math_profitable() {
        let shield = RiskShield::new(dec!(10.0), dec!(0.001), dec!(0.001));
        // USDT->BTC: 1/50000, BTC->ETH: 1/0.065, ETH->USDT: 3320
        // product = (1/50000) * (1/0.065) * 3320 = 3320 / (50000 * 0.065) = 3320 / 3250 = 1.02154
        // fees = (0.999)^3 = 0.997003
        // net = 0.997003 * 1.02154 = 1.01853 > 1.001
        let result = shield.verify_triangular_math(
            Decimal::ONE / dec!(50000.0),
            Decimal::ONE / dec!(0.065),
            dec!(3320.0),
            dec!(0.001),
            dec!(0.001),
            dec!(0.001),
        );
        assert!(result);
    }

    #[test]
    fn test_verify_triangular_math_unprofitable() {
        let shield = RiskShield::new(dec!(10.0), dec!(0.001), dec!(0.001));
        // Product = (1/50000) * (1/0.07) * 3250 = 3250/3500 = 0.9286
        // fees = 0.997003
        // net = 0.9286 * 0.997003 = 0.9258 < 1.001
        let result = shield.verify_triangular_math(
            Decimal::ONE / dec!(50000.0),
            Decimal::ONE / dec!(0.07),
            dec!(3250.0),
            dec!(0.001),
            dec!(0.001),
            dec!(0.001),
        );
        assert!(!result);
    }
}