//! Triangular Executor — Parallel 3-leg triangular arbitrage execution.
//!
//! This module provides a dedicated executor for triangular arbitrage,
//! parallel to `CrossExchangeExecutor` for 2-leg cross-exchange arb. It
//! dispatches all three legs concurrently via `tokio::join!`, validates
//! each leg before dispatch, and handles partial-fill rollback.

use rust_decimal::prelude::*;
use rust_decimal_macros::dec;
use std::time::Instant;

/// A single leg of a triangular arbitrage.
#[derive(Debug, Clone)]
pub struct TriangularLeg {
    pub exchange_id: u16,
    pub token_id: u16,
    pub symbol: String,
    pub side: String,       // "BUY" or "SELL"
    pub price: Decimal,
    pub quantity: Decimal,
    pub order_type: String, // "LIMIT" or "MARKET"
    pub time_in_force: String, // "IOC", "FOK", or "GTC"
}

/// Result of a single triangular leg execution.
#[derive(Debug, Clone)]
pub struct TriLegResult {
    pub exchange_id: u16,
    pub symbol: String,
    pub success: bool,
    pub order_id: Option<String>,
    pub filled_quantity: Decimal,
    pub filled_price: Decimal,
    pub error_message: Option<String>,
    pub execution_time_us: u64,
}

/// Result of a triangular arbitrage execution.
#[derive(Debug, Clone)]
pub struct TriangularResult {
    pub legs: [TriLegResult; 3],
    pub all_succeeded: bool,
    pub rollback_required: bool,
    pub total_execution_time_us: u64,
}

/// Triangular Executor — dispatches three legs concurrently.
pub struct TriangularExecutor;

impl TriangularExecutor {
    /// Per-leg timeout in seconds.
    const LEG_TIMEOUT_SECS: u64 = 5;

    /// Dispatches all three legs of a triangular arbitrage concurrently.
    ///
    /// # Arguments
    /// * `legs` — Array of exactly 3 `TriangularLeg` structs.
    /// * `dispatch_fn` — Async function that executes a single leg and
    ///   returns a `TriLegResult`.
    ///
    /// # Returns
    /// A `TriangularResult` with per-leg fill details and rollback flag.
    pub async fn execute_simultaneous_trades<F, Fut>(
        legs: [TriangularLeg; 3],
        dispatch_fn: F,
    ) -> TriangularResult
    where
        F: Fn(TriangularLeg) -> Fut + Clone + Send,
        Fut: std::future::Future<Output = TriLegResult> + Send,
    {
        let total_start = Instant::now();

        // Validate all legs before dispatch.
        let validated: Vec<Result<(), String>> = legs.iter().map(Self::validate_leg).collect();
        for (i, v) in validated.iter().enumerate() {
            if v.is_err() {
                return TriangularResult {
                    legs: [
                        TriLegResult::validation_failed(&legs[0], validated[0].as_ref().err()),
                        TriLegResult::validation_failed(&legs[1], validated[1].as_ref().err()),
                        TriLegResult::validation_failed(&legs[2], validated[2].as_ref().err()),
                    ],
                    all_succeeded: false,
                    rollback_required: false,
                    total_execution_time_us: 0,
                };
            }
        }

        let dispatch = dispatch_fn.clone();
        let (r0, r1, r2) = tokio::join!(
            Self::dispatch_leg(&legs[0], dispatch.clone(), total_start),
            Self::dispatch_leg(&legs[1], dispatch.clone(), total_start),
            Self::dispatch_leg(&legs[2], dispatch, total_start),
        );

        let all_succeeded = r0.success && r1.success && r2.success;

        // Detect rollback: (a) any leg failed → partial position, or
        // (b) any leg's fill qty differs from intent → asymmetric position.
        // NOTE: we compare each leg's filled qty against its OWN intent qty
        // — NOT against other legs' quantities (which are in different units).
        // Original bug: leading `all_succeeded &&` meant that when any leg
        // failed (all_succeeded = false), rollback was NEVER triggered,
        // leaving open positions on the successful legs.
        let rollback_required = !all_succeeded
            || r0.filled_quantity != legs[0].quantity
                || r1.filled_quantity != legs[1].quantity
                || r2.filled_quantity != legs[2].quantity;

        TriangularResult {
            legs: [r0, r1, r2],
            all_succeeded,
            rollback_required,
            total_execution_time_us: total_start.elapsed().as_micros() as u64,
        }
    }

    /// Dispatches a single leg with timeout and validation.
    async fn dispatch_leg<F, Fut>(
        leg: &TriangularLeg,
        dispatch_fn: F,
        _total_start: Instant,
    ) -> TriLegResult
    where
        F: Fn(TriangularLeg) -> Fut,
        Fut: std::future::Future<Output = TriLegResult> + Send,
    {
        let start = Instant::now();
        match tokio::time::timeout(
            std::time::Duration::from_secs(Self::LEG_TIMEOUT_SECS),
            dispatch_fn(leg.clone()),
        ).await {
            Ok(mut r) => {
                r.execution_time_us = start.elapsed().as_micros() as u64;
                r
            }
            Err(_) => TriLegResult {
                exchange_id: leg.exchange_id,
                symbol: leg.symbol.clone(),
                success: false,
                order_id: None,
                filled_quantity: Decimal::ZERO,
                filled_price: Decimal::ZERO,
                error_message: Some(format!("leg timed out ({}s)", Self::LEG_TIMEOUT_SECS)),
                execution_time_us: start.elapsed().as_micros() as u64,
            },
        }
    }

    /// Validates a triangular leg.
    fn validate_leg(leg: &TriangularLeg) -> Result<(), String> {
        if leg.price <= Decimal::ZERO {
            return Err(format!("[leg ex={}] Price must be positive", leg.exchange_id));
        }
        if leg.quantity <= Decimal::ZERO {
            return Err(format!("[leg ex={}] Quantity must be positive", leg.exchange_id));
        }
        if leg.quantity > Decimal::from(1000u64) {
            return Err(format!(
                "[leg ex={}] Quantity {} exceeds maximum 1000",
                leg.exchange_id, leg.quantity
            ));
        }
        if leg.side != "BUY" && leg.side != "SELL" {
            return Err(format!("[leg ex={}] Invalid side: {}", leg.exchange_id, leg.side));
        }
        if leg.order_type == "MARKET" {
            return Err(format!(
                "[leg ex={}] Market orders prohibited — use LIMIT only",
                leg.exchange_id
            ));
        }
        if leg.time_in_force == "GTC" {
            return Err(format!(
                "[leg ex={}] GTC time-in-force prohibited — use IOC or FOK only",
                leg.exchange_id
            ));
        }
        if leg.symbol.is_empty() {
            return Err(format!("[leg ex={}] Symbol cannot be empty", leg.exchange_id));
        }
        Ok(())
    }

    /// Computes the minimum sell price for a triangular loop to break even.
    ///
    /// For a 3-leg loop: buy A with USDT, sell A→B, sell B→USDT.
    /// Each leg incurs a taker fee at `per_leg_fee_rate`.
    ///
    /// Derivation (starting with `capital` in USDT):
    ///   Leg 1: buy A at price P → receive capital*(1-f)/P units of A
    ///   Leg 2: sell A→B at rate R → receive capital*(1-f)/P * R*(1-f) units of B
    ///   Leg 3: sell B→USDT at price X → receive capital*(1-f)³ * R * X / P
    ///
    /// Breakeven when leg-3 proceeds = capital:
    ///   (1-f)³ * R * X / P = 1
    ///   X = P / (R * (1-f)³)
    ///
    /// # Arguments
    /// * `leg1_price` — Price of leg 1 (P in the derivation above).
    /// * `leg2_rate`   — Exchange rate of leg 2 (R in the derivation above).
    /// * `per_leg_fee_rate` — Taker fee rate per leg (f), e.g. 0.001 for 0.1%.
    ///
    /// Returns `Decimal::MAX` if the divisor is zero or negative.
    pub fn breakeven_final_price(
        leg1_price: Decimal,
        leg2_rate: Decimal,
        per_leg_fee_rate: Decimal,
    ) -> Decimal {
        let fee_factor = (Decimal::ONE - per_leg_fee_rate)
            .powi(3); // compound all 3 legs' fees
        let divisor = leg2_rate * fee_factor;
        if divisor <= Decimal::ZERO {
            return Decimal::MAX;
        }
        leg1_price / divisor
    }
}

impl TriLegResult {
    /// Creates a failed result for a validation error.
    fn validation_failed(leg: &TriangularLeg, err: Option<&String>) -> Self {
        Self {
            exchange_id: leg.exchange_id,
            symbol: leg.symbol.clone(),
            success: false,
            order_id: None,
            filled_quantity: Decimal::ZERO,
            filled_price: Decimal::ZERO,
            error_message: err.cloned(),
            execution_time_us: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_legs() -> [TriangularLeg; 3] {
        [
            TriangularLeg {
                exchange_id: 0, token_id: 1, symbol: "A/USDT".to_string(),
                side: "BUY".to_string(), price: dec!(50000.0), quantity: dec!(0.001),
                order_type: "LIMIT".to_string(), time_in_force: "IOC".to_string(),
            },
            TriangularLeg {
                exchange_id: 0, token_id: 2, symbol: "B/A".to_string(),
                side: "SELL".to_string(), price: dec!(1.0), quantity: dec!(0.001),
                order_type: "LIMIT".to_string(), time_in_force: "IOC".to_string(),
            },
            TriangularLeg {
                exchange_id: 0, token_id: 2, symbol: "B/USDT".to_string(),
                side: "SELL".to_string(), price: dec!(50050.0), quantity: dec!(0.001),
                order_type: "LIMIT".to_string(), time_in_force: "IOC".to_string(),
            },
        ]
    }

    fn mock_dispatch(leg: TriangularLeg) -> std::pin::Pin<Box<dyn std::future::Future<Output = TriLegResult> + Send>> {
        Box::pin(async move {
            TriLegResult {
                exchange_id: leg.exchange_id,
                symbol: leg.symbol,
                success: true,
                order_id: Some(format!("TRI-{}", leg.exchange_id)),
                filled_quantity: leg.quantity,
                filled_price: leg.price,
                error_message: None,
                execution_time_us: 50,
            }
        })
    }

    #[tokio::test]
    async fn test_all_legs_succeed() {
        let legs = make_legs();
        let result = TriangularExecutor::execute_simultaneous_trades(legs, mock_dispatch).await;
        assert!(result.all_succeeded);
        assert!(!result.rollback_required);
        for leg in &result.legs {
            assert!(leg.success);
        }
    }

    #[test]
    fn test_validate_leg_rejects_market_order() {
        let mut legs = make_legs();
        legs[0].order_type = "MARKET".to_string();
        assert!(TriangularExecutor::validate_leg(&legs[0]).is_err());
    }

    #[test]
    fn test_validate_leg_rejects_gtc() {
        let mut legs = make_legs();
        legs[1].time_in_force = "GTC".to_string();
        assert!(TriangularExecutor::validate_leg(&legs[1]).is_err());
    }

    #[test]
    fn test_validate_leg_rejects_zero_price() {
        let mut legs = make_legs();
        legs[2].price = Decimal::ZERO;
        assert!(TriangularExecutor::validate_leg(&legs[2]).is_err());
    }

    #[test]
    fn test_breakeven_final_price() {
        // P=50000, R=1.0, f=0.001 (0.1% per leg)
        // Correct: X = 50000 / (1.0 * 0.999^3) = 50000 / 0.997002999
        //        = 50150.45...
        let be = TriangularExecutor::breakeven_final_price(
            dec!(50000.0), dec!(1.0), dec!(0.001),
        );
        // Should be slightly above 50000 due to fees
        assert!(be > dec!(50000.0), "breakeven {} should be > 50000", be);
        assert!(be < dec!(50200.0), "breakeven {} should be < 50200", be);

        // Verify with known value: 50000 / 0.999^3 ≈ 50150.45
        let expected = dec!(50000.0) / (dec!(0.999).powi(3));
        assert_eq!(be, expected);
    }

}
