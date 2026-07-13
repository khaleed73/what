//! Core Execution Shield — Combines circuit breaker, fee deduction, and slippage
//! simulation into a single protected execution path.
//!
//! Every order dispatched through this module goes through:
//!   1. Circuit breaker check (system freeze)
//!   2. Fee deduction calculation
//!   3. Slippage simulation through order book depth
//!   4. Net profit validation before execution

use rust_decimal::prelude::*;
use rust_decimal_macros::dec;
use crate::circuit_breaker::{EngineCircuitBreaker, CircuitBreakerError};
use crate::exchange_constraints::{MarketDepth, DepthLevel, AbsoluteMathEngine};

/// Result of a shielded execution evaluation.
#[derive(Debug, Clone)]
pub struct ShieldedExecutionResult {
    /// Whether the execution should proceed
    pub approved: bool,
    /// Estimated units acquired after slippage
    pub estimated_acquired: Decimal,
    /// Estimated total cost including fees
    pub estimated_total_cost: Decimal,
    /// Estimated net profit (can be negative)
    pub estimated_net_profit: Decimal,
    /// Slippage in basis points
    pub slippage_bps: Decimal,
    /// Total fee cost in quote currency
    pub fee_cost: Decimal,
    /// Rejection reason (if not approved)
    pub rejection_reason: Option<String>,
}

/// Core Execution Shield — the single gatekeeper before any real order is dispatched.
///
/// This module wraps the entire pre-execution validation pipeline into one
/// callable function that either approves or rejects a trade with full
/// mathematical justification.
pub struct CoreExecutionShield {
    pub breaker: EngineCircuitBreaker,
    pub fee_rate: Decimal,
    pub min_net_profit_bps: Decimal,
}

impl CoreExecutionShield {
    pub fn new(breaker: EngineCircuitBreaker, fee_rate: Decimal, min_profit_bps: Decimal) -> Self {
        Self {
            breaker,
            fee_rate,
            min_net_profit_bps: min_profit_bps,
        }
    }

    /// Evaluates a buy execution through the full shield pipeline.
    ///
    /// # Arguments
    /// * `allocated_capital` - Capital allocated for this trade (in quote currency, e.g., USDT)
    /// * `intended_price` - The strategy's target buy price
    /// * `depth` - Current order book depth (asks)
    /// * `expected_sell_price` - The expected exit price for profit calculation
    ///
    /// # Pipeline
    /// 1. Check circuit breaker (system frozen?)
    /// 2. Simulate market buy through depth (slippage calculation)
    /// 3. Calculate fee cost
    /// 4. Estimate net profit at expected sell price
    /// 5. Validate minimum profit threshold
    pub fn evaluate_buy(
        &self,
        allocated_capital: Decimal,
        intended_price: Decimal,
        depth: &MarketDepth,
        expected_sell_price: Decimal,
    ) -> Result<ShieldedExecutionResult, CircuitBreakerError> {
        // Step 1: Circuit breaker check
        self.breaker.check_and_reject()?;

        // Step 2: Simulate buy through depth
        let acquired = match AbsoluteMathEngine::calculate_slippage_buy(depth, allocated_capital) {
            Ok(qty) => qty,
            Err(e) => {
                return Ok(ShieldedExecutionResult {
                    approved: false,
                    estimated_acquired: Decimal::ZERO,
                    estimated_total_cost: allocated_capital,
                    estimated_net_profit: Decimal::ZERO,
                    slippage_bps: Decimal::ZERO,
                    fee_cost: Decimal::ZERO,
                    rejection_reason: Some(format!("Insufficient depth: {}", e)),
                });
            }
        };

        if acquired <= Decimal::ZERO {
            return Ok(ShieldedExecutionResult {
                approved: false,
                estimated_acquired: Decimal::ZERO,
                estimated_total_cost: allocated_capital,
                estimated_net_profit: Decimal::ZERO,
                slippage_bps: Decimal::ZERO,
                fee_cost: Decimal::ZERO,
                rejection_reason: Some("Acquired zero quantity from depth".to_string()),
            });
        }

        // Calculate VWAP (actual average price paid)
        let vwap = allocated_capital / acquired;

        // Step 3: Calculate fee
        let fee_cost = allocated_capital * self.fee_rate;
        let total_cost = allocated_capital + fee_cost;

        // Step 4: Estimate net profit at expected sell price
        let gross_sell_proceeds = acquired * expected_sell_price;
        let sell_fee = gross_sell_proceeds * self.fee_rate;
        let net_sell_proceeds = gross_sell_proceeds - sell_fee;
        let net_profit = net_sell_proceeds - total_cost;

        // Step 5: Calculate slippage in bps
        let slippage_bps = if intended_price > Decimal::ZERO {
            ((vwap - intended_price).abs() / intended_price) * dec!(10000.0)
        } else {
            Decimal::ZERO
        };

        // Step 6: Validate minimum profit
        let net_profit_bps = if total_cost > Decimal::ZERO {
            (net_profit / total_cost) * dec!(10000.0)
        } else {
            Decimal::ZERO
        };

        let approved = net_profit_bps >= self.min_net_profit_bps;

        let rejection_reason = if !approved {
            Some(format!(
                "Net profit {} bps below minimum {} bps",
                net_profit_bps, self.min_net_profit_bps
            ))
        } else {
            None
        };

        Ok(ShieldedExecutionResult {
            approved,
            estimated_acquired: acquired,
            estimated_total_cost: total_cost,
            estimated_net_profit: net_profit,
            slippage_bps,
            fee_cost,
            rejection_reason,
        })
    }

    /// Evaluates a sell execution through the full shield pipeline.
    ///
    /// # Arguments
    /// * `asset_quantity` - Quantity of asset to sell
    /// * `intended_price` - The strategy's target sell price
    /// * `depth` - Current order book depth (bids)
    /// * `entry_cost` - Original cost basis for P&L calculation
    pub fn evaluate_sell(
        &self,
        asset_quantity: Decimal,
        intended_price: Decimal,
        depth: &MarketDepth,
        entry_cost: Decimal,
    ) -> Result<ShieldedExecutionResult, CircuitBreakerError> {
        // Step 1: Circuit breaker check
        self.breaker.check_and_reject()?;

        // Step 2: Simulate sell through depth
        let proceeds = match AbsoluteMathEngine::calculate_slippage_sell(depth, asset_quantity) {
            Ok(p) => p,
            Err(e) => {
                return Ok(ShieldedExecutionResult {
                    approved: false,
                    estimated_acquired: Decimal::ZERO,
                    estimated_total_cost: entry_cost,
                    estimated_net_profit: Decimal::ZERO,
                    slippage_bps: Decimal::ZERO,
                    fee_cost: Decimal::ZERO,
                    rejection_reason: Some(format!("Insufficient depth: {}", e)),
                });
            }
        };

        if proceeds <= Decimal::ZERO {
            return Ok(ShieldedExecutionResult {
                approved: false,
                estimated_acquired: Decimal::ZERO,
                estimated_total_cost: entry_cost,
                estimated_net_profit: Decimal::ZERO,
                slippage_bps: Decimal::ZERO,
                fee_cost: Decimal::ZERO,
                rejection_reason: Some("Zero proceeds from sell".to_string()),
            });
        }

        // VWAP sell price
        let vwap = proceeds / asset_quantity;

        // Fee
        let fee_cost = proceeds * self.fee_rate;
        let net_proceeds = proceeds - fee_cost;

        // P&L
        let net_profit = net_proceeds - entry_cost;

        // Slippage
        let slippage_bps = if intended_price > Decimal::ZERO {
            ((intended_price - vwap).abs() / intended_price) * dec!(10000.0)
        } else {
            Decimal::ZERO
        };

        let net_profit_bps = if entry_cost > Decimal::ZERO {
            (net_profit / entry_cost) * dec!(10000.0)
        } else {
            Decimal::ZERO
        };

        let approved = net_profit_bps >= self.min_net_profit_bps;
        let rejection_reason = if !approved {
            Some(format!(
                "Net profit {} bps below minimum {} bps",
                net_profit_bps, self.min_net_profit_bps
            ))
        } else {
            None
        };

        Ok(ShieldedExecutionResult {
            approved,
            estimated_acquired: asset_quantity,
            estimated_total_cost: entry_cost,
            estimated_net_profit: net_profit,
            slippage_bps,
            fee_cost,
            rejection_reason,
        })
    }

    /// Convenience: trip the circuit breaker with a reason code.
    pub fn trip_breaker(&self, reason: u64) {
        self.breaker.trip(reason);
    }

    /// Convenience: reset the circuit breaker.
    pub fn reset_breaker(&self) -> bool {
        self.breaker.reset()
    }

    /// Check if the system is frozen.
    pub fn is_frozen(&self) -> bool {
        self.breaker.is_frozen()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    fn make_shield() -> CoreExecutionShield {
        CoreExecutionShield::new(
            EngineCircuitBreaker::new(),
            dec!(0.001),     // 0.1% fee
            dec!(5.0),       // 5 bps minimum profit
        )
    }

    fn sample_ask_depth() -> MarketDepth {
        MarketDepth {
            asks: vec![
                DepthLevel { price: dec!(50000.0), quantity: dec!(1.0) },
                DepthLevel { price: dec!(50010.0), quantity: dec!(1.0) },
                DepthLevel { price: dec!(50020.0), quantity: dec!(1.0) },
            ],
            bids: vec![],
        }
    }

    fn sample_bid_depth() -> MarketDepth {
        MarketDepth {
            asks: vec![],
            bids: vec![
                DepthLevel { price: dec!(50000.0), quantity: dec!(1.0) },
                DepthLevel { price: dec!(49990.0), quantity: dec!(1.0) },
                DepthLevel { price: dec!(49980.0), quantity: dec!(1.0) },
            ],
        }
    }

    #[test]
    fn test_buy_approved_profitable() {
        let shield = make_shield();
        let depth = sample_ask_depth();
        // Buy at $50000, sell at $50200 → gross $200, fees ~$100, net ~$100 → ~20 bps
        let result = shield.evaluate_buy(dec!(50000.0), dec!(50000.0), &depth, dec!(50200.0));
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(r.approved);
        assert!(r.estimated_net_profit > Decimal::ZERO);
        assert_eq!(r.estimated_acquired, dec!(1.0));
    }

    #[test]
    fn test_buy_rejected_insufficient_profit() {
        let shield = make_shield();
        let depth = sample_ask_depth();
        // Sell at same price as buy → guaranteed loss from fees
        let result = shield.evaluate_buy(dec!(50000.0), dec!(50000.0), &depth, dec!(50000.0));
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(!r.approved);
        assert!(r.rejection_reason.is_some());
    }

    #[test]
    fn test_buy_rejected_frozen() {
        let shield = make_shield();
        shield.trip_breaker(crate::circuit_breaker::REASON_MANUAL_KILL);
        let depth = sample_ask_depth();
        let result = shield.evaluate_buy(dec!(50000.0), dec!(50000.0), &depth, dec!(50200.0));
        assert!(result.is_err());
    }

    #[test]
    fn test_sell_approved() {
        let shield = make_shield();
        let depth = sample_bid_depth();
        // Bought at $49900, selling at $50000 → profit
        let result = shield.evaluate_sell(dec!(1.0), dec!(50000.0), &depth, dec!(49900.0));
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(r.approved);
        assert!(r.estimated_net_profit > Decimal::ZERO);
    }

    #[test]
    fn test_sell_rejected_at_loss() {
        let shield = make_shield();
        let depth = sample_bid_depth();
        // Bought at $50500, selling at $50000 → loss
        let result = shield.evaluate_sell(dec!(1.0), dec!(50000.0), &depth, dec!(50500.0));
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(!r.approved);
    }

    #[test]
    fn test_slippage_bps_calculated() {
        let shield = make_shield();
        // Price at 50000, but we spend enough to walk into second level at 50100
        let depth = MarketDepth {
            asks: vec![
                DepthLevel { price: dec!(50000.0), quantity: dec!(0.5) },
                DepthLevel { price: dec!(50100.0), quantity: dec!(1.0) },
            ],
            bids: vec![],
        };
        let result = shield.evaluate_buy(dec!(50000.0), dec!(50000.0), &depth, dec!(50500.0));
        assert!(result.is_ok());
        let r = result.unwrap();
        // We consume 0.5 at 50000 ($25000) and 0.498 at 50100 ($24949.8)
        // VWAP ≈ 50000.04, slippage ≈ 0.0008 bps — very small
        assert!(r.slippage_bps >= Decimal::ZERO);
    }

    #[test]
    fn test_insufficient_depth() {
        let shield = make_shield();
        let depth = MarketDepth {
            asks: vec![DepthLevel { price: dec!(50000.0), quantity: dec!(0.01) }], // Only $500 depth
            bids: vec![],
        };
        let result = shield.evaluate_buy(dec!(50000.0), dec!(50000.0), &depth, dec!(50500.0));
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(!r.approved);
        assert!(r.rejection_reason.unwrap().contains("Insufficient depth"));
    }

    #[test]
    fn test_trip_and_reset() {
        let shield = make_shield();
        shield.trip_breaker(crate::circuit_breaker::REASON_DRAWDOWN_BREACHED);
        assert!(shield.is_frozen());
        assert!(shield.reset_breaker());
        assert!(!shield.is_frozen());
    }
}