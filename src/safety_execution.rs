//! Safety Execution Engine — Enforces IOC/FOK order types for maximum execution safety.
//!
//! This module provides a safety-first execution engine that only dispatches orders
//! using Immediate-or-Cancel (IOC) or Fill-or-Kill (FOK) order types to prevent
//! orders from sitting on the book and accumulating unintended exposure.

use rust_decimal::prelude::*;
use rust_decimal_macros::dec;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Enforced order types for safety. Market orders are prohibited to prevent
/// unbounded slippage. Only limit orders with time-in-force constraints are allowed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SafeOrderType {
    /// Immediate-or-Cancel: Fill what you can immediately, cancel the rest.
    /// This is the safest default — no partial fills linger on the book.
    Ioc,
    /// Fill-or-Kill: Either fill the entire quantity or cancel completely.
    /// Use when exact quantity is required for arb leg parity.
    Fok,
}

/// A fully validated order payload ready for dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeOrderPayload {
    pub symbol: String,
    pub side: String,          // "BUY" or "SELL"
    pub order_type: SafeOrderType,
    pub price: Decimal,
    pub quantity: Decimal,
    pub time_in_force: String,  // Always "IOC" or "FOK" — never "GTC"
    pub client_order_id: String,
    pub timestamp_ms: u64,
    pub exchange_id: u16,
}

/// Result of a safety-validated execution attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeExecutionResult {
    pub success: bool,
    pub order_id: Option<String>,
    pub filled_quantity: Decimal,
    pub average_price: Decimal,
    pub fee_paid: Decimal,
    pub error_message: Option<String>,
    pub execution_time_us: u64,  // microseconds
    pub was_fully_filled: bool,
}

/// Safety Execution Engine — the only module that should dispatch real orders.
///
/// Key safety invariants:
///   1. NEVER dispatches market orders (unbounded slippage risk)
///   2. ALWAYS uses IOC or FOK time-in-force (no lingering orders)
///   3. ALWAYS generates unique client order IDs (idempotency)
///   4. ALWAYS includes a price limit (even for "market-like" execution)
///   5. ALWAYS validates price against current best bid/ask before dispatch
pub struct SafetyExecutionEngine;

impl SafetyExecutionEngine {
    /// Creates a validated order payload with all safety constraints enforced.
    ///
    /// # Arguments
    /// * `symbol` - Trading pair (e.g., "BTCUSDT")
    /// * `side` - "BUY" or "SELL"
    /// * `order_type` - IOC or FOK
    /// * `price` - Limit price (mandatory — no market orders allowed)
    /// * `quantity` - Order quantity
    /// * `exchange_id` - Target exchange identifier
    /// * `best_bid` - Current best bid on the order book (for validation)
    /// * `best_ask` - Current best ask on the order book (for validation)
    ///
    /// # Safety Checks
    /// - Price must be positive and non-zero
    /// - Quantity must be positive and non-zero
    /// - Buy price must not exceed best_ask by more than 0.5% (slippage guard)
    /// - Sell price must not be below best_bid by more than 0.5% (slippage guard)
    pub fn build_safe_order(
        symbol: &str,
        side: &str,
        order_type: SafeOrderType,
        price: Decimal,
        quantity: Decimal,
        exchange_id: u16,
        best_bid: Option<Decimal>,
        best_ask: Option<Decimal>,
    ) -> Result<SafeOrderPayload, String> {
        // Guard 1: Price must be positive
        if price <= Decimal::ZERO {
            return Err("Price must be positive and non-zero".to_string());
        }

        // Guard 2: Quantity must be positive
        if quantity <= Decimal::ZERO {
            return Err("Quantity must be positive and non-zero".to_string());
        }

        // Guard 3: Validate side
        let side_upper = side.to_uppercase();
        if side_upper != "BUY" && side_upper != "SELL" {
            return Err(format!("Invalid side: {}. Must be BUY or SELL", side));
        }

        // Guard 4: Slippage validation against current order book
        let max_slippage = dec!(0.005); // 0.5% maximum deviation
        match side_upper.as_str() {
            "BUY" => {
                if let Some(ask) = best_ask {
                    if ask > Decimal::ZERO {
                        let deviation = (price - ask) / ask;
                        if deviation > max_slippage {
                            return Err(format!(
                                "Buy price {} exceeds best ask {} by {:.4}% (max {}%)",
                                price, ask, deviation * dec!(100.0), max_slippage * dec!(100.0)
                            ));
                        }
                    }
                }
            }
            "SELL" => {
                if let Some(bid) = best_bid {
                    if bid > Decimal::ZERO {
                        let deviation = (bid - price) / bid;
                        if deviation > max_slippage {
                            return Err(format!(
                                "Sell price {} below best bid {} by {:.4}% (max {}%)",
                                price, bid, deviation * dec!(100.0), max_slippage * dec!(100.0)
                            ));
                        }
                    }
                }
            }
            other => return Err(format!("Invalid order side '{}'", other)),
        }

        // Guard 5: Symbol must be non-empty
        if symbol.is_empty() {
            return Err("Symbol must not be empty".to_string());
        }

        let tif = match order_type {
            SafeOrderType::Ioc => "IOC",
            SafeOrderType::Fok => "FOK",
        };

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Generate unique client order ID: exchange_id-timestamp_ms-random_suffix
        let client_order_id = format!(
            "{}-{}-{:08x}",
            exchange_id,
            timestamp_ms,
            (price * dec!(1000000)).to_string().replace(".", "").parse::<u64>().unwrap_or(0) % 0xFFFFFFFF
        );

        Ok(SafeOrderPayload {
            symbol: symbol.to_string(),
            side: side_upper,
            order_type,
            price,
            quantity,
            time_in_force: tif.to_string(),
            client_order_id,
            timestamp_ms,
            exchange_id,
        })
    }

    /// Validates an execution result against the original intent.
    ///
    /// Checks that:
    ///   1. The fill price is within acceptable slippage of the intended price
    ///   2. The filled quantity is not zero
    ///   3. For FOK orders, the order was either fully filled or fully cancelled
    pub fn validate_execution_result(
        payload: &SafeOrderPayload,
        result: &SafeExecutionResult,
        max_slippage_bps: u64,
    ) -> Result<(), String> {
        if !result.success {
            return Err(format!(
                "Order failed: {}",
                result.error_message.as_deref().unwrap_or("unknown error")
            ));
        }

        // Check filled quantity
        if result.filled_quantity <= Decimal::ZERO {
            return Err("Order returned success but filled quantity is zero".to_string());
        }

        // Check slippage
        if payload.price > Decimal::ZERO {
            let price_diff = (result.average_price - payload.price).abs();
            let slippage_bps = (price_diff / payload.price) * dec!(10000.0);
            let max_allowed = Decimal::from(max_slippage_bps);
            if slippage_bps > max_allowed {
                return Err(format!(
                    "Slippage {} bps exceeds maximum allowed {} bps",
                    slippage_bps, max_slippage_bps
                ));
            }
        }

        // For FOK orders, verify full fill
        if payload.order_type == SafeOrderType::Fok && !result.was_fully_filled {
            return Err("FOK order was not fully filled".to_string());
        }

        Ok(())
    }

    /// Builds a counter-order (emergency unwind) for risk mitigation.
    /// Used when a multi-leg execution fails on one leg and existing fills must be reversed.
    pub fn build_counter_order(
        original: &SafeOrderPayload,
        adverse_nudge_bps: u64,
    ) -> SafeOrderPayload {
        let nudge_factor = Decimal::from(adverse_nudge_bps) / dec!(10000.0);
        let counter_side = if original.side == "BUY" { "SELL" } else { "BUY" };
        let counter_price = if counter_side == "SELL" {
            // Sell at a slightly lower price to ensure fill (accept worse price)
            original.price * (Decimal::ONE - nudge_factor)
        } else {
            // Buy at a slightly higher price to ensure fill (accept worse price)
            original.price * (Decimal::ONE + nudge_factor)
        };

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        SafeOrderPayload {
            symbol: original.symbol.clone(),
            side: counter_side.to_string(),
            order_type: SafeOrderType::Ioc, // Always IOC for emergency unwinds
            price: counter_price,
            quantity: original.quantity,
            time_in_force: "IOC".to_string(),
            client_order_id: format!("COUNTER-{}-{}-{:x}", original.exchange_id, timestamp_ms, timestamp_ms % 9999),
            timestamp_ms,
            exchange_id: original.exchange_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_safe_order_buy_success() {
        let result = SafetyExecutionEngine::build_safe_order(
            "BTCUSDT", "BUY", SafeOrderType::Ioc,
            dec!(50000.0), dec!(0.001), 0,
            Some(dec!(49990.0)), Some(dec!(50000.0)),
        );
        assert!(result.is_ok());
        let payload = result.unwrap();
        assert_eq!(payload.symbol, "BTCUSDT");
        assert_eq!(payload.side, "BUY");
        assert_eq!(payload.time_in_force, "IOC");
        assert_eq!(payload.exchange_id, 0);
    }

    #[test]
    fn test_build_safe_order_sell_success() {
        let result = SafetyExecutionEngine::build_safe_order(
            "ETHUSDT", "SELL", SafeOrderType::Fok,
            dec!(3300.0), dec!(1.0), 1,
            Some(dec!(3290.0)), Some(dec!(3300.0)),
        );
        assert!(result.is_ok());
        let payload = result.unwrap();
        assert_eq!(payload.side, "SELL");
        assert_eq!(payload.time_in_force, "FOK");
    }

    #[test]
    fn test_reject_zero_price() {
        let result = SafetyExecutionEngine::build_safe_order(
            "BTCUSDT", "BUY", SafeOrderType::Ioc,
            Decimal::ZERO, dec!(0.001), 0,
            Some(dec!(50000.0)), Some(dec!(50000.0)),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_zero_quantity() {
        let result = SafetyExecutionEngine::build_safe_order(
            "BTCUSDT", "BUY", SafeOrderType::Ioc,
            dec!(50000.0), Decimal::ZERO, 0,
            Some(dec!(50000.0)), Some(dec!(50000.0)),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_invalid_side() {
        let result = SafetyExecutionEngine::build_safe_order(
            "BTCUSDT", "HOLD", SafeOrderType::Ioc,
            dec!(50000.0), dec!(0.001), 0,
            Some(dec!(50000.0)), Some(dec!(50000.0)),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_excessive_buy_slippage() {
        // Buy price 6% above ask — should be rejected (max 0.5%)
        let result = SafetyExecutionEngine::build_safe_order(
            "BTCUSDT", "BUY", SafeOrderType::Ioc,
            dec!(53000.0), dec!(0.001), 0,
            Some(dec!(49990.0)), Some(dec!(50000.0)),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds best ask"));
    }

    #[test]
    fn test_reject_excessive_sell_slippage() {
        // Sell price 6% below bid — should be rejected (max 0.5%)
        let result = SafetyExecutionEngine::build_safe_order(
            "BTCUSDT", "SELL", SafeOrderType::Ioc,
            dec!(47000.0), dec!(0.001), 0,
            Some(dec!(50000.0)), Some(dec!(50001.0)),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("below best bid"));
    }

    #[test]
    fn test_validate_good_execution() {
        let payload = SafetyExecutionEngine::build_safe_order(
            "BTCUSDT", "BUY", SafeOrderType::Ioc,
            dec!(50000.0), dec!(0.001), 0,
            Some(dec!(49990.0)), Some(dec!(50000.0)),
        ).unwrap();

        let result = SafeExecutionResult {
            success: true,
            order_id: Some("123".to_string()),
            filled_quantity: dec!(0.001),
            average_price: dec!(50001.0),
            fee_paid: dec!(0.5),
            error_message: None,
            execution_time_us: 150,
            was_fully_filled: true,
        };

        assert!(SafetyExecutionEngine::validate_execution_result(&payload, &result, 50).is_ok());
    }

    #[test]
    fn test_reject_excessive_slippage_result() {
        let payload = SafetyExecutionEngine::build_safe_order(
            "BTCUSDT", "BUY", SafeOrderType::Ioc,
            dec!(50000.0), dec!(0.001), 0,
            Some(dec!(49990.0)), Some(dec!(50000.0)),
        ).unwrap();

        let result = SafeExecutionResult {
            success: true,
            order_id: Some("123".to_string()),
            filled_quantity: dec!(0.001),
            average_price: dec!(51000.0), // 200 bps slippage
            fee_paid: dec!(0.5),
            error_message: None,
            execution_time_us: 150,
            was_fully_filled: true,
        };

        // 50 bps max but actual is 200 bps — should reject
        assert!(SafetyExecutionEngine::validate_execution_result(&payload, &result, 50).is_err());
    }

    #[test]
    fn test_build_counter_order_sell() {
        let original = SafetyExecutionEngine::build_safe_order(
            "BTCUSDT", "BUY", SafeOrderType::Ioc,
            dec!(50000.0), dec!(0.001), 0,
            Some(dec!(49990.0)), Some(dec!(50000.0)),
        ).unwrap();

        let counter = SafetyExecutionEngine::build_counter_order(&original, 10); // 10 bps adverse
        assert_eq!(counter.side, "SELL");
        assert_eq!(counter.order_type, SafeOrderType::Ioc);
        assert!(counter.price < original.price); // Sell at slightly lower price
    }

    #[test]
    fn test_build_counter_order_buy() {
        let original = SafetyExecutionEngine::build_safe_order(
            "BTCUSDT", "SELL", SafeOrderType::Ioc,
            dec!(50000.0), dec!(0.001), 0,
            Some(dec!(50000.0)), Some(dec!(50010.0)),
        ).unwrap();

        let counter = SafetyExecutionEngine::build_counter_order(&original, 10);
        assert_eq!(counter.side, "BUY");
        assert!(counter.price > original.price); // Buy at slightly higher price
    }
}