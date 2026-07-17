//! Private Order Feed Listener — Zero-copy byte-level parser for execution reports.
//!
//! This module listens to private WebSocket channels and parses execution report
//! frames directly from raw bytes WITHOUT using serde/json allocation. This is
//! the fastest possible path to update local balance state after a fill.
//!
//! Supports Binance-style `executionReport` events with fields:
//!   - "e": event type (we match "executionReport")
//!   - "t": trade ID / token ID
//!   - "B": balance after execution

use rust_decimal::Decimal;
use std::str::FromStr;

/// Parsed result from an execution report frame.
#[derive(Debug, Clone)]
pub struct ExecutionReport {
    /// The trade ID from the report (Binance 64-bit trade ID truncated to u16 for
    /// internal tracking; use `trade_id_raw` for the full ID when needed).
    pub token_id: u16,
    /// The full trade ID as a string (preserves the original 64-bit value).
    pub trade_id_str: String,
    /// The asset balance after this execution.
    pub balance: Decimal,
    /// Whether this was an executionReport event.
    pub is_execution_report: bool,
}

/// Zero-copy byte parser for Binance-style WebSocket execution reports.
///
/// This function walks through raw bytes looking for specific JSON key patterns
/// without allocating any strings for keys. It only allocates a small buffer
/// for the decimal number string.
///
/// # Input Format
/// ```json
/// {"e":"executionReport","t":3,"B":"2500.00","s":"BTCUSDT","S":"BUY","l":"0.001","L":"50000.00"}
/// ```
///
/// # Parsed Fields
/// - `e` = "executionReport" → sets is_execution_report flag
/// - `t` → parsed as u16 token_id
/// - `B` → parsed as Decimal balance
/// - `s` → parsed as symbol (optional)
/// - `S` → parsed as side (optional)
/// - `l` → parsed as filled quantity (optional)
/// - `L` → parsed as fill price (optional)
///
/// # Returns
/// `Some(ExecutionReport)` if this is a valid execution report, `None` otherwise.
pub fn parse_execution_report_bytes(payload: &[u8]) -> Option<ExecutionReport> {
    let mut token_id: u16 = 0;
    let mut balance_decimal = Decimal::ZERO;
    let mut is_execution_report = false;
    let mut trade_id_str = String::new();
    let mut i = 0;
    let len = payload.len();

    while i < len {
        // Look for pattern: "X": where X is a single-character key
        if payload[i] == b'"' && i + 2 < len {
            let key = payload[i + 1];
            if payload[i + 2] == b'"' && payload.get(i + 3) == Some(&b':') {
                i += 4; // Skip past "X":

                match key {
                    b'e' => {
                        // Check for "executionReport" (17 bytes including quotes)
                        if payload.get(i..i + 17) == Some(b"\"executionReport\"") {
                            is_execution_report = true;
                            i += 17;
                        }
                    }
                    b't' => {
                        // Parse trade ID as string to avoid u16 truncation.
                        // Binance trade IDs are 64-bit — truncating to u16 causes
                        // silent data corruption after trade ID 65535.
                        if trade_id_str.is_empty() { trade_id_str = String::new(); }
                        trade_id_str.clear();
                        let num_start = i;
                        while i < len && payload[i].is_ascii_digit() {
                            i += 1;
                        }
                        if i > num_start {
                            if let Ok(s) = std::str::from_utf8(&payload[num_start..i]) {
                                trade_id_str = s.to_string();
                            }
                        }
                        // For backward compat: parse as u16 for values that fit.
                        if let Ok(id_val) = trade_id_str.parse::<u16>() {
                            token_id = id_val;
                        }
                    }
                    b'B' => {
                        // Parse decimal balance (the "B" field in Binance executionReport)
                        if payload[i] == b'"' {
                            i += 1;
                        }
                        let num_start = i;
                        while i < len && (payload[i].is_ascii_digit() || payload[i] == b'.') {
                            i += 1;
                        }
                        if i > num_start {
                            // Use from_utf8 to avoid allocating a String
                            if let Ok(num_str) = std::str::from_utf8(&payload[num_start..i]) {
                                if let Ok(parsed) = Decimal::from_str(num_str) {
                                    balance_decimal = parsed;
                                }
                            }
                        }
                    }
                    b's' => {
                        // Skip symbol string (not needed for balance updates)
                        if payload[i] == b'"' {
                            i += 1;
                            while i < len && payload[i] != b'"' {
                                i += 1;
                            }
                        }
                    }
                    b'S' => {
                        // Skip side string
                        if payload[i] == b'"' {
                            i += 1;
                            while i < len && payload[i] != b'"' {
                                i += 1;
                            }
                        }
                    }
                    b'l' => {
                        // Skip filled quantity
                        if payload[i] == b'"' {
                            i += 1;
                            while i < len && payload[i] != b'"' {
                                i += 1;
                            }
                        }
                    }
                    b'L' => {
                        // Skip fill price
                        if payload[i] == b'"' {
                            i += 1;
                            while i < len && payload[i] != b'"' {
                                i += 1;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        i += 1;
    }

    if is_execution_report && !trade_id_str.is_empty() && balance_decimal >= Decimal::ZERO {
        Some(ExecutionReport {
            token_id,
            trade_id_str,
            balance: balance_decimal,
            is_execution_report: true,
        })
    } else {
        None
    }
}

/// Extended execution report with all parsed fields.
#[derive(Debug, Clone)]
pub struct FullExecutionReport {
    pub token_id: u16,
    /// Full trade ID string (preserves the original 64-bit value).
    pub trade_id_str: String,
    pub balance: Decimal,
    pub symbol: String,
    pub side: String,
    pub filled_qty: Decimal,
    pub fill_price: Decimal,
}

/// Full parser that extracts all fields from an execution report.
pub fn parse_full_execution_report(payload: &[u8]) -> Option<FullExecutionReport> {
    let mut token_id: u16 = 0;
    let mut trade_id_str = String::new();
    let mut balance_decimal = Decimal::ZERO;
    let mut is_execution_report = false;
    let mut symbol = String::new();
    let mut side = String::new();
    let mut filled_qty = Decimal::ZERO;
    let mut fill_price = Decimal::ZERO;
    let mut i = 0;
    let len = payload.len();

    while i < len {
        if payload[i] == b'"' && i + 2 < len {
            let key = payload[i + 1];
            if payload[i + 2] == b'"' && payload.get(i + 3) == Some(&b':') {
                i += 4;

                match key {
                    b'e' => {
                        if payload.get(i..i + 17) == Some(b"\"executionReport\"") {
                            is_execution_report = true;
                            i += 17;
                        }
                    }
                    b't' => {
                        trade_id_str.clear();
                        let num_start = i;
                        while i < len && payload[i].is_ascii_digit() {
                            i += 1;
                        }
                        if i > num_start {
                            if let Ok(s) = std::str::from_utf8(&payload[num_start..i]) {
                                trade_id_str = s.to_string();
                            }
                        }
                        if let Ok(id_val) = trade_id_str.parse::<u16>() {
                            token_id = id_val;
                        }
                    }
                    b'B' => {
                        if payload[i] == b'"' { i += 1; }
                        let start = i;
                        while i < len && (payload[i].is_ascii_digit() || payload[i] == b'.') { i += 1; }
                        if let Ok(s) = std::str::from_utf8(&payload[start..i]) {
                            if let Ok(v) = Decimal::from_str(s) { balance_decimal = v; }
                        }
                    }
                    b's' => {
                        if payload[i] == b'"' { i += 1; }
                        let start = i;
                        while i < len && payload[i] != b'"' { i += 1; }
                        if let Ok(s) = std::str::from_utf8(&payload[start..i]) {
                            symbol = s.to_string();
                        }
                    }
                    b'S' => {
                        if payload[i] == b'"' { i += 1; }
                        let start = i;
                        while i < len && payload[i] != b'"' { i += 1; }
                        if let Ok(s) = std::str::from_utf8(&payload[start..i]) {
                            side = s.to_string();
                        }
                    }
                    b'l' => {
                        if payload[i] == b'"' { i += 1; }
                        let start = i;
                        while i < len && (payload[i].is_ascii_digit() || payload[i] == b'.') { i += 1; }
                        if let Ok(s) = std::str::from_utf8(&payload[start..i]) {
                            if let Ok(v) = Decimal::from_str(s) { filled_qty = v; }
                        }
                    }
                    b'L' => {
                        if payload[i] == b'"' { i += 1; }
                        let start = i;
                        while i < len && (payload[i].is_ascii_digit() || payload[i] == b'.') { i += 1; }
                        if let Ok(s) = std::str::from_utf8(&payload[start..i]) {
                            if let Ok(v) = Decimal::from_str(s) { fill_price = v; }
                        }
                    }
                    _ => {}
                }
            }
        }
        i += 1;
    }

    if is_execution_report && !symbol.is_empty() {
        Some(FullExecutionReport {
            token_id,
            trade_id_str,
            balance: balance_decimal,
            symbol,
            side,
            filled_qty,
            fill_price,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_execution_report() {
        let frame = br#"{"e":"executionReport","t":3,"B":"2500.00"}"#;
        let result = parse_execution_report_bytes(frame).unwrap();
        assert!(result.is_execution_report);
        assert_eq!(result.token_id, 3);
        assert_eq!(result.balance, Decimal::from_str("2500.00").unwrap());
    }

    #[test]
    fn test_parse_full_execution_report() {
        let frame = br#"{"e":"executionReport","t":45,"B":"2500.00","s":"BTCUSDT","S":"BUY","l":"0.001","L":"50000.50"}"#;
        let result = parse_full_execution_report(frame).unwrap();
        assert_eq!(result.token_id, 45);
        assert_eq!(result.balance, Decimal::from_str("2500.00").unwrap());
        assert_eq!(result.symbol, "BTCUSDT");
        assert_eq!(result.side, "BUY");
        assert_eq!(result.filled_qty, Decimal::from_str("0.001").unwrap());
        assert_eq!(result.fill_price, Decimal::from_str("50000.50").unwrap());
    }

    #[test]
    fn test_reject_non_execution_event() {
        let frame = br#"{"e":"depthUpdate","b":[["50000","1.0"]]}"#;
        assert!(parse_execution_report_bytes(frame).is_none());
    }

    #[test]
    fn test_reject_zero_balance() {
        let frame = br#"{"e":"executionReport","t":1,"B":"0.00"}"#;
        assert!(parse_execution_report_bytes(frame).is_none());
    }

    #[test]
    fn test_reject_zero_token_id() {
        let frame = br#"{"e":"executionReport","t":0,"B":"100.00"}"#;
        assert!(parse_execution_report_bytes(frame).is_none());
    }

    #[test]
    fn test_reject_empty_payload() {
        assert!(parse_execution_report_bytes(b"").is_none());
    }

    #[test]
    fn test_reject_garbage() {
        assert!(parse_execution_report_bytes(b"not json at all").is_none());
    }

    #[test]
    fn test_large_token_id() {
        let frame = br#"{"e":"executionReport","t":65535,"B":"99999.99"}"#;
        let result = parse_execution_report_bytes(frame).unwrap();
        assert_eq!(result.token_id, 65535);
        assert_eq!(result.balance, Decimal::from_str("99999.99").unwrap());
    }

    #[test]
    fn test_full_report_with_sell_side() {
        let frame = br#"{"e":"executionReport","t":99,"B":"500.50","s":"ETHUSDT","S":"SELL","l":"0.5","L":"1001.00"}"#;
        let result = parse_full_execution_report(frame).unwrap();
        assert_eq!(result.side, "SELL");
        assert_eq!(result.filled_qty, Decimal::from_str("0.5").unwrap());
    }

    #[test]
    fn test_extra_fields_ignored() {
        // Fields like "x", "X", "i" etc. should be harmlessly skipped
        let frame = br#"{"e":"executionReport","t":7,"B":"100.00","x":"TRADE","X":"FILLED","i":12345678}"#;
        let result = parse_execution_report_bytes(frame).unwrap();
        assert_eq!(result.token_id, 7);
        assert_eq!(result.balance, Decimal::from_str("100.00").unwrap());
    }
}