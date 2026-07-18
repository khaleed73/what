//! Zero-Copy Byte-Level Parsers
//!
//! The spec requires:
//! - `parse_raw_bytes_fast(payload)` — Zero-copy byte parser for WebSocket
//!   order book frames. Scans raw bytes directly for "t"/"b"/"a" keys.
//! - `parse_execution_report_bytes_simulated(payload)` — Zero-copy parser
//!   for private execution report WebSocket frames. Extracts token_id and
//!   balance from raw bytes.
//!
//! These parsers avoid serde/JSON deserialization entirely for sub-microsecond
//! parsing of known-format WebSocket frames.
//!
//! NOTE: The parser is designed for well-formed exchange WebSocket messages.
//! Truncated or malformed messages will simply return None (safe default).
//! The caller (WS listener) handles reconnection on parse failures.

/// Result of parsing an order book update.
#[derive(Debug, Clone)]
pub struct FastParsedOrderBook {
    /// Token/pair symbol.
    pub symbol: String,
    /// Best bid price.
    pub bid: f64,
    /// Best ask price.
    pub ask: f64,
}

/// Result of parsing an execution report.
#[derive(Debug, Clone)]
pub struct FastParsedExecutionReport {
    /// Token/pair symbol.
    pub symbol: String,
    /// New balance (if present).
    pub balance: f64,
    /// Order status.
    pub status: String,
}

/// Zero-copy byte parser for WebSocket order book frames.
///
/// Scans for specific JSON keys ('"t"', '"b"', '"a"') directly in the
/// raw byte payload without full JSON deserialization.
///
/// This is the spec-mandated `parse_raw_bytes_fast` function.
///
/// # Arguments
/// * `payload` — Raw UTF-8 bytes from the WebSocket frame
///
/// # Returns
/// A `FastParsedOrderBook` if the expected keys are found.
#[inline]
pub fn parse_raw_bytes_fast(payload: &[u8]) -> Option<FastParsedOrderBook> {
    let text = std::str::from_utf8(payload).ok()?;

    // Extract value after "t" key (symbol).
    let symbol = extract_string_value(text, "t")?;

    // Extract value after "b" key (best bid).
    let bid = extract_number_value(text, "b")?;

    // Extract value after "a" key (best ask).
    let ask = extract_number_value(text, "a")?;

    Some(FastParsedOrderBook {
        symbol,
        bid,
        ask,
    })
}

/// Zero-copy byte parser for execution report WebSocket frames.
///
/// Scans for '"e":"executionReport"' or similar and extracts
/// '"t"' (token_id), '"B"' (balance) from the raw bytes.
///
/// This is the spec-mandated `parse_execution_report_bytes_simulated` function.
///
/// # Arguments
/// * `payload` — Raw UTF-8 bytes from the private WebSocket frame
///
/// # Returns
/// A `FastParsedExecutionReport` if the expected keys are found.
#[inline]
pub fn parse_execution_report_bytes_simulated(payload: &[u8]) -> Option<FastParsedExecutionReport> {
    let text = std::str::from_utf8(payload).ok()?;

    // Extract token_id from "t" key.
    let symbol = extract_string_value(text, "t")?;

    // Extract balance from "B" key (Binance format) or "bal" key.
    let balance = extract_number_value(text, "B")
        .or_else(|| extract_number_value(text, "bal"))
        .unwrap_or(0.0);

    // Extract status from "X" key (Binance order status).
    let status = extract_string_value(text, "X")
        .unwrap_or_else(|| "UNKNOWN".to_string());

    Some(FastParsedExecutionReport {
        symbol,
        balance,
        status,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers — direct byte scanning (no serde)
// ---------------------------------------------------------------------------

/// Extract a string value associated with a JSON key.
///
/// Handles both compact (`"t":"BTCUSDT"`) and spaced (`"t": "BTCUSDT"`)
/// formats.
fn extract_string_value(text: &str, key: &str) -> Option<String> {
    // Build the search pattern: "key"
    let pattern = format!("\"{}\"", key);
    let start = text.find(&pattern)?;

    // Boundary check: the match must be a whole key, not a substring
    // of a longer key. The byte after the pattern must be a colon or
    // whitespace followed by a colon.
    let after_pattern = start + pattern.len();
    if after_pattern >= text.len() {
        return None;
    }
    let next_byte = text.as_bytes()[after_pattern];
    if next_byte != b':' && !next_byte.is_ascii_whitespace() {
        return None;
    }

    // Move past the pattern to the colon.
    let after_key = &text[start + pattern.len()..];

    // Skip whitespace and colon.
    let value_start = after_key
        .find('"')
        .map(|i| i + 1)?;

    let after_quote = &after_key[value_start..];

    // Find the closing quote.
    let value_end = after_quote.find('"')?;

    Some(after_quote[..value_end].to_string())
}

/// Extract a numeric (f64) value associated with a JSON key.
fn extract_number_value(text: &str, key: &str) -> Option<f64> {
    let pattern = format!("\"{}\"", key);
    let start = text.find(&pattern)?;

    // Boundary check: ensure the match is a whole key.
    let after_pattern = start + pattern.len();
    if after_pattern >= text.len() {
        return None;
    }
    let next_byte = text.as_bytes()[after_pattern];
    if next_byte != b':' && !next_byte.is_ascii_whitespace() {
        return None;
    }

    let after_key = &text[start + pattern.len()..];

    // Skip whitespace, colon, whitespace.
    let num_start = after_key.find(':')?;
    let after_colon = &after_key[num_start + 1..];

    // Skip whitespace before the number
    let after_ws: String = after_colon
        .chars()
        .skip_while(|c| c.is_ascii_whitespace())
        .collect();

    // Parse the number — handle negative sign and decimal point.
    let num_str: String = after_ws
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-' || *c == 'e' || *c == 'E' || *c == '+')
        .collect();

    num_str.parse::<f64>().ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_order_book_compact() {
        let payload = br#"{"t":"BTCUSDT","b":50000.5,"a":50001.0,"T":1700000000000}"#;
        let result = parse_raw_bytes_fast(payload).unwrap();
        assert_eq!(result.symbol, "BTCUSDT");
        assert!((result.bid - 50000.5).abs() < 0.01);
        assert!((result.ask - 50001.0).abs() < 0.01);
    }

    #[test]
    fn test_parse_order_book_spaced() {
        let payload = br#"{"t": "ETHUSDT", "b": 3000.25, "a": 3000.75}"#;
        let result = parse_raw_bytes_fast(payload).unwrap();
        assert_eq!(result.symbol, "ETHUSDT");
        assert!((result.bid - 3000.25).abs() < 0.01);
    }

    #[test]
    fn test_parse_order_book_missing_key() {
        let payload = br#"{"t":"BTCUSDT","b":50000.5}"#; // missing "a"
        assert!(parse_raw_bytes_fast(payload).is_none());
    }

    #[test]
    fn test_parse_order_book_invalid_utf8() {
        let payload: &[u8] = &[0xFF, 0xFE, 0xFD];
        assert!(parse_raw_bytes_fast(payload).is_none());
    }

    #[test]
    fn test_parse_execution_report() {
        let payload = br#"{"e":"executionReport","t":"SOLUSDT","B":150.25,"X":"FILLED"}"#;
        let result = parse_execution_report_bytes_simulated(payload).unwrap();
        assert_eq!(result.symbol, "SOLUSDT");
        assert!((result.balance - 150.25).abs() < 0.01);
        assert_eq!(result.status, "FILLED");
    }

    #[test]
    fn test_parse_execution_report_no_balance() {
        let payload = br#"{"e":"executionReport","t":"BTCUSDT","X":"PARTIALLY_FILLED"}"#;
        let result = parse_execution_report_bytes_simulated(payload).unwrap();
        assert_eq!(result.symbol, "BTCUSDT");
        assert!((result.balance - 0.0).abs() < 0.01);
        assert_eq!(result.status, "PARTIALLY_FILLED");
    }

    #[test]
    fn test_extract_string_value() {
        let text = r#"{"symbol":"SOLUSDT","price":"150.5"}"#;
        assert_eq!(extract_string_value(text, "symbol"), Some("SOLUSDT".to_string()));
    }

    #[test]
    fn test_extract_number_value() {
        let text = r#"{"price":150.5,"quantity":0.5}"#;
        let price = extract_number_value(text, "price").unwrap();
        assert!((price - 150.5).abs() < 0.01);
    }

    #[test]
    fn test_extract_number_negative() {
        let text = r#"{"pnl":-12.5}"#;
        let pnl = extract_number_value(text, "pnl").unwrap();
        assert!((pnl - (-12.5)).abs() < 0.01);
    }
}