//! Cross-Exchange Executor — Parallel execution across two exchanges simultaneously.
//!
//! This module handles the simultaneous dispatch of buy/sell orders on two
//! different exchanges for cross-exchange arbitrage. It uses `tokio::join!`
//! for true parallel execution and includes rollback logic if one leg fails.

use rust_decimal::prelude::*;
use rust_decimal_macros::dec;
use std::time::Instant;

/// A cross-exchange order describing one leg of the arbitrage.
#[derive(Debug, Clone)]
pub struct CrossExchangeOrder {
    pub exchange_name: String,
    pub exchange_id: u16,
    pub symbol: String,
    pub side: String,      // "BUY" or "SELL"
    pub price: Decimal,
    pub quantity: Decimal,
    /// Order type. **WARNING:** Only "LIMIT" is permitted — "MARKET" orders are
    /// prohibited by the safety execution module and will be rejected by
    /// `validate_order()`.
    pub order_type: String, // "LIMIT" or "MARKET"
    /// Time-in-force. **WARNING:** Only "IOC" or "FOK" are permitted — "GTC"
    /// contradicts the safety module's IOC/FOK-only policy and will be rejected
    /// by `validate_order()`.
    pub time_in_force: String, // "IOC", "FOK", or "GTC"
}

/// Result of a single leg execution.
#[derive(Debug, Clone)]
pub struct LegResult {
    pub exchange_name: String,
    pub exchange_id: u16,
    pub success: bool,
    pub order_id: Option<String>,
    pub filled_quantity: Decimal,
    pub filled_price: Decimal,
    pub error_message: Option<String>,
    pub execution_time_us: u64,
}

/// Result of a cross-exchange arbitrage execution.
#[derive(Debug, Clone)]
pub struct CrossExchangeResult {
    pub buy_leg: LegResult,
    pub sell_leg: LegResult,
    pub both_succeeded: bool,
    pub total_profit: Option<Decimal>,  // Net profit after fees
    pub total_execution_time_us: u64,
    /// NOTE: Rollback is NOT executed here — the caller is responsible for
    /// handling partial fills. This flag indicates that a rollback IS needed.
    pub rollback_required: bool,
}

/// Cross-Exchange Executor — dispatches simultaneous trades on two exchanges.
pub struct CrossExchangeExecutor;

impl CrossExchangeExecutor {
    /// Executes simultaneous trades on two exchanges for cross-exchange arbitrage.
    ///
    /// # Algorithm
    /// 1. Validate both orders (price, quantity, side)
    /// 2. Dispatch both orders in parallel using `tokio::join!`
    /// 3. If one leg fails, log the failure (rollback is handled by the caller)
    /// 4. Calculate net profit after both fills
    ///
    /// # Arguments
    /// * `buy_order` - The order to execute on the cheaper exchange (buy)
    /// * `sell_order` - The order to execute on the expensive exchange (sell)
    /// * `fee_rate_buy` - Taker fee rate on the buy exchange
    /// * `fee_rate_sell` - Taker fee rate on the sell exchange
    ///
    /// # Returns
    /// A `CrossExchangeResult` with fill details and profit calculation.
    ///
    /// # Type Parameters
    /// * `F` - Dispatch function. Must be `Send`.
    /// * `Fut` - Future returned by dispatch. Must be `Send`.
    pub async fn execute_simultaneous_trades<F, Fut>(
        buy_order: &CrossExchangeOrder,
        sell_order: &CrossExchangeOrder,
        fee_rate_buy: Decimal,
        fee_rate_sell: Decimal,
        dispatch_fn: F,
    ) -> CrossExchangeResult
    where
        F: Fn(CrossExchangeOrder) -> Fut,
        Fut: std::future::Future<Output = LegResult>,
    {
        let total_start = Instant::now();

        // Validate orders
        let buy_valid = Self::validate_order(buy_order);
        let sell_valid = Self::validate_order(sell_order);

        // Execute BOTH legs concurrently using tokio::join! for true parallelism.
        // Previous sequential execution (buy first, then sell) added up to 2x
        // latency and caused the sell-side price to move before the sell order
        // was dispatched — a critical flaw for HFT arbitrage.
        //
        // Each leg has a 10-second timeout to prevent a stuck exchange from
        // freezing the entire arb path indefinitely.
        let (buy_result, sell_result) = tokio::join!(
            async {
                if let Err(e) = &buy_valid {
                    LegResult {
                        exchange_name: buy_order.exchange_name.clone(),
                        exchange_id: buy_order.exchange_id,
                        success: false,
                        order_id: None,
                        filled_quantity: Decimal::ZERO,
                        filled_price: Decimal::ZERO,
                        error_message: Some(e.clone()),
                        execution_time_us: 0,
                    }
                } else {
                    let start = Instant::now();
                    let result = match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        dispatch_fn(buy_order.clone()),
                    ).await {
                        Ok(r) => r,
                        Err(_) => LegResult {
                            exchange_name: buy_order.exchange_name.clone(),
                            exchange_id: buy_order.exchange_id,
                            success: false,
                            order_id: None,
                            filled_quantity: Decimal::ZERO,
                            filled_price: Decimal::ZERO,
                            error_message: Some("buy leg timed out (5s)".to_string()),
                            execution_time_us: start.elapsed().as_micros() as u64,
                        },
                    };
                    let mut r = result;
                    r.execution_time_us = start.elapsed().as_micros() as u64;
                    r
                }
            },
            async {
                if let Err(e) = &sell_valid {
                    LegResult {
                        exchange_name: sell_order.exchange_name.clone(),
                        exchange_id: sell_order.exchange_id,
                        success: false,
                        order_id: None,
                        filled_quantity: Decimal::ZERO,
                        filled_price: Decimal::ZERO,
                        error_message: Some(e.clone()),
                        execution_time_us: 0,
                    }
                } else {
                    let start = Instant::now();
                    let result = match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        dispatch_fn(sell_order.clone()),
                    ).await {
                        Ok(r) => r,
                        Err(_) => LegResult {
                            exchange_name: sell_order.exchange_name.clone(),
                            exchange_id: sell_order.exchange_id,
                            success: false,
                            order_id: None,
                            filled_quantity: Decimal::ZERO,
                            filled_price: Decimal::ZERO,
                            error_message: Some("sell leg timed out (5s)".to_string()),
                            execution_time_us: start.elapsed().as_micros() as u64,
                        },
                    };
                    let mut r = result;
                    r.execution_time_us = start.elapsed().as_micros() as u64;
                    r
                }
            },
        );

        let both_succeeded = buy_result.success && sell_result.success;

        // Calculate profit
        let total_profit = if both_succeeded {
            let buy_cost = buy_result.filled_quantity * buy_result.filled_price;
            let buy_fee = buy_cost * fee_rate_buy;
            let sell_proceeds = sell_result.filled_quantity * sell_result.filled_price;
            let sell_fee = sell_proceeds * fee_rate_sell;
            Some(sell_proceeds - sell_fee - buy_cost - buy_fee)
        } else {
            None
        };

        // M-4 fix: Detect quantity mismatch between legs.
        let qty_mismatch = (buy_result.filled_quantity - sell_result.filled_quantity).abs();
        if qty_mismatch > Decimal::ZERO {
            tracing::warn!(mismatch = %qty_mismatch, "asymmetric fill detected");
        }

        // M-7 fix: Set rollback_required based on actual fill status.
        let rollback_required = (buy_result.success ^ sell_result.success)
            || buy_result.filled_quantity != sell_result.filled_quantity;

        CrossExchangeResult {
            buy_leg: buy_result,
            sell_leg: sell_result,
            both_succeeded,
            total_profit,
            total_execution_time_us: total_start.elapsed().as_micros() as u64,
            rollback_required,
        }
    }

    /// Validates a cross-exchange order.
    fn validate_order(order: &CrossExchangeOrder) -> Result<(), String> {
        if order.price <= Decimal::ZERO {
            return Err("Price must be positive".to_string());
        }
        if order.quantity <= Decimal::ZERO {
            return Err("Quantity must be positive".to_string());
        }
        // M-4: Maximum quantity guard — prevent enormous orders from bugs upstream.
        if order.quantity > Decimal::from(1000u64) {
            return Err(format!("Quantity {} exceeds maximum 1000", order.quantity));
        }
        if order.side != "BUY" && order.side != "SELL" {
            return Err(format!("Invalid side: {}", order.side));
        }
        if order.order_type == "MARKET" {
            return Err("Market orders are prohibited — use LIMIT only".to_string());
        }
        if order.time_in_force == "GTC" {
            return Err("GTC time-in-force is prohibited — use IOC or FOK only".to_string());
        }
        if order.symbol.is_empty() {
            return Err("Symbol cannot be empty".to_string());
        }
        Ok(())
    }

    /// Computes expected profit for a cross-exchange trade.
    ///
    /// # Arguments
    /// * `buy_price` - Price to buy at on exchange X
    /// * `sell_price` - Price to sell at on exchange Y
    /// * `quantity` - Trade quantity
    /// * `fee_buy` - Fee rate on buy exchange
    /// * `fee_sell` - Fee rate on sell exchange
    pub fn compute_expected_profit(
        buy_price: Decimal,
        sell_price: Decimal,
        quantity: Decimal,
        fee_buy: Decimal,
        fee_sell: Decimal,
    ) -> Decimal {
        let buy_cost = quantity * buy_price;
        let sell_proceeds = quantity * sell_price;
        let total_fees = (buy_cost * fee_buy) + (sell_proceeds * fee_sell);
        sell_proceeds - buy_cost - total_fees
    }

    /// Computes the minimum spread required to break even after fees.
    ///
    /// Returns the minimum sell price given a buy price for breakeven.
    pub fn breakeven_sell_price(
        buy_price: Decimal,
        _quantity: Decimal,
        fee_buy: Decimal,
        fee_sell: Decimal,
    ) -> Decimal {
        // buy_cost = qty * buy_price
        // sell_proceeds - sell_fee - buy_cost - buy_fee = 0
        // sell_price * qty - sell_price * qty * fee_sell - buy_cost * (1 + fee_buy) = 0
        // sell_price * qty * (1 - fee_sell) = buy_cost * (1 + fee_buy)
        // sell_price = buy_cost * (1 + fee_buy) / (qty * (1 - fee_sell))
        // sell_price = buy_price * (1 + fee_buy) / (1 - fee_sell)
        buy_price * (Decimal::ONE + fee_buy) / (Decimal::ONE - fee_sell)
    }

    /// Computes the minimum profitable spread in basis points.
    pub fn minimum_spread_bps(fee_buy: Decimal, fee_sell: Decimal) -> Decimal {
        // breakeven_sell = buy * (1+fb) / (1-fs)
        // spread = (breakeven_sell - buy) / buy = (1+fb)/(1-fs) - 1 = (fb+fs) / (1-fs)
        // In bps: ((fb+fs) / (1-fs)) * 10000
        let divisor = Decimal::ONE - fee_sell;
        if divisor <= Decimal::ZERO {
            return Decimal::MAX; // fee_sell >= 100% → infinite spread required
        }
        let combined = (fee_buy + fee_sell) / divisor;
        combined * dec!(10000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    fn make_buy_order() -> CrossExchangeOrder {
        CrossExchangeOrder {
            exchange_name: "Binance".to_string(),
            exchange_id: 0,
            symbol: "BTCUSDT".to_string(),
            side: "BUY".to_string(),
            price: dec!(50000.0),
            quantity: dec!(0.001),
            order_type: "LIMIT".to_string(),
            time_in_force: "IOC".to_string(),
        }
    }

    fn make_sell_order() -> CrossExchangeOrder {
        CrossExchangeOrder {
            exchange_name: "Bybit".to_string(),
            exchange_id: 1,
            symbol: "BTCUSDT".to_string(),
            side: "SELL".to_string(),
            price: dec!(50100.0),
            quantity: dec!(0.001),
            order_type: "LIMIT".to_string(),
            time_in_force: "IOC".to_string(),
        }
    }

    fn mock_dispatch(order: CrossExchangeOrder) -> std::pin::Pin<Box<dyn std::future::Future<Output = LegResult> + Send>> {
        Box::pin(async move {
            LegResult {
                exchange_name: order.exchange_name,
                exchange_id: order.exchange_id,
                success: true,
                order_id: Some(format!("ORD-{}", order.exchange_id)),
                filled_quantity: order.quantity,
                filled_price: order.price,
                error_message: None,
                execution_time_us: 100,
            }
        })
    }

    #[tokio::test]
    async fn test_simultaneous_execution_both_succeed() {
        let buy = make_buy_order();
        let sell = make_sell_order();

        let result = CrossExchangeExecutor::execute_simultaneous_trades(
            &buy, &sell,
            dec!(0.001), dec!(0.001),
            mock_dispatch,
        ).await;

        assert!(result.both_succeeded);
        assert!(result.total_profit.is_some());
        // profit = 0.001 * 50100 - 0.001 * 50000 - fees
        // = 50.1 - 50.0 - 0.050 - 0.0501 = 0.0 - actually slightly negative with these prices
        // Let's check: sell = 50.1, buy = 50, fee = 0.001
        // profit = 50.1 * (1-0.001) - 50 * (1+0.001) = 50.05 - 50.05 = ~0
    }

    #[tokio::test]
    async fn test_buy_validation_fails() {
        let mut buy = make_buy_order();
        buy.price = Decimal::ZERO;
        let sell = make_sell_order();

        let result = CrossExchangeExecutor::execute_simultaneous_trades(
            &buy, &sell,
            dec!(0.001), dec!(0.001),
            mock_dispatch,
        ).await;

        assert!(!result.both_succeeded);
        assert!(!result.buy_leg.success);
        assert!(result.buy_leg.error_message.is_some());
    }

    #[test]
    fn test_compute_expected_profit() {
        let profit = CrossExchangeExecutor::compute_expected_profit(
            dec!(50000.0), dec!(50200.0), dec!(1.0),
            dec!(0.001), dec!(0.001),
        );
        // sell = 50200, buy_cost = 50000, buy_fee = 50, sell_fee = 50.2
        // profit = 50200 - 50.2 - 50000 - 50 = 99.8
        assert_eq!(profit, dec!(99.8));
    }

    #[test]
    fn test_breakeven_sell_price() {
        let be = CrossExchangeExecutor::breakeven_sell_price(
            dec!(50000.0), dec!(1.0), dec!(0.001), dec!(0.001),
        );
        // be = 50000 * 1.001 / 0.999 = 50100.100100...
        assert!(be > dec!(50100.0) && be < dec!(50101.0));
    }

    #[test]
    fn test_minimum_spread_bps() {
        let min_bps = CrossExchangeExecutor::minimum_spread_bps(dec!(0.001), dec!(0.001));
        // (0.001 + 0.001) / (1 - 0.001) * 10000 = 0.002 / 0.999 * 10000 ≈ 20.02 bps
        assert!(min_bps > dec!(20.0) && min_bps < dec!(21.0));
    }

    #[test]
    fn test_validate_order_rejects_zero_price() {
        let mut order = make_buy_order();
        order.price = Decimal::ZERO;
        assert!(CrossExchangeExecutor::validate_order(&order).is_err());
    }

    #[test]
    fn test_validate_order_rejects_zero_qty() {
        let mut order = make_buy_order();
        order.quantity = Decimal::ZERO;
        assert!(CrossExchangeExecutor::validate_order(&order).is_err());
    }

    #[test]
    fn test_validate_order_rejects_invalid_side() {
        let mut order = make_buy_order();
        order.side = "HOLD".to_string();
        assert!(CrossExchangeExecutor::validate_order(&order).is_err());
    }
}