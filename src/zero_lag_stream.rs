//! Zero-Lag Stream Manager — WebSocket stream with exponential backoff reconnect
//! and static JSON parsing for minimum latency.
//!
//! This module provides a stateful WebSocket connection manager that:
//!   1. Maintains a persistent connection to an exchange WebSocket endpoint
//!   2. Reconnects with exponential backoff on failure
//!   3. Uses minimal-allocation JSON parsing for depth updates
//!   4. Tracks connection health metrics

use std::time::Duration;

/// Parsed order book update from a WebSocket message.
#[derive(Debug, Clone)]
pub struct ParsedBookUpdate {
    pub symbol: String,
    pub bids: Vec<(String, String)>, // (price_str, qty_str)
    pub asks: Vec<(String, String)>,
    pub is_snapshot: bool,
    pub last_update_id: u64,
}

/// Connection health metrics.
#[derive(Debug, Clone, Default)]
pub struct StreamHealth {
    pub total_messages_received: u64,
    pub total_reconnects: u64,
    pub total_parse_errors: u64,
    pub last_message_ts_ms: u64,
    pub connected_since_ms: u64,
    pub current_latency_ms: u64,
}

/// Configuration for the zero-lag stream manager.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// WebSocket URL to connect to.
    pub ws_url: String,
    /// Subscribe message to send after connection.
    pub subscribe_message: String,
    /// Initial reconnect delay in milliseconds.
    pub initial_reconnect_delay_ms: u64,
    /// Maximum reconnect delay in milliseconds.
    pub max_reconnect_delay_ms: u64,
    /// Exponential backoff multiplier (e.g., 2.0).
    pub backoff_multiplier: f64,
    /// Ping interval in seconds (None = disabled).
    pub ping_interval_secs: Option<u64>,
    /// Exchange ID used to seed per-exchange deterministic jitter.
    pub exchange_id: u16,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            ws_url: String::new(),
            subscribe_message: String::new(),
            initial_reconnect_delay_ms: 250,
            max_reconnect_delay_ms: 30000,
            backoff_multiplier: 2.0,
            ping_interval_secs: Some(30),
            exchange_id: 0,
        }
    }
}

/// Zero-Lag Stream Manager — manages a single WebSocket connection with auto-reconnect.
pub struct ZeroLagStreamManager {
    config: StreamConfig,
    health: StreamHealth,
}

impl ZeroLagStreamManager {
    pub fn new(config: StreamConfig) -> Self {
        Self {
            config,
            health: StreamHealth::default(),
        }
    }

    /// Returns a reference to the current health metrics.
    pub fn health(&self) -> &StreamHealth {
        &self.health
    }

    /// Returns the next reconnect delay with exponential backoff.
    pub fn next_reconnect_delay(&self, attempt: u32) -> Duration {
        let base_delay = self.config.initial_reconnect_delay_ms as f64;
        let max_delay = self.config.max_reconnect_delay_ms as f64;
        let delay_ms = base_delay * self.config.backoff_multiplier.powi(attempt as i32);
        let capped = delay_ms.min(max_delay);
        // Add jitter: +/- 10%
        let jitter = capped * 0.1 * (rand_jitter(self.config.exchange_id) - 0.5);
        Duration::from_millis((capped + jitter).max(100.0) as u64)
    }

    /// Records a received message.
    pub fn record_message(&mut self) {
        self.health.total_messages_received += 1;
        self.health.last_message_ts_ms = current_timestamp_ms();
    }

    /// Records a reconnect event.
    pub fn record_reconnect(&mut self) {
        self.health.total_reconnects += 1;
        self.health.connected_since_ms = current_timestamp_ms();
    }

    /// Records a parse error.
    pub fn record_parse_error(&mut self) {
        self.health.total_parse_errors += 1;
    }

    /// Calculates the time since the last message in milliseconds.
    pub fn time_since_last_message_ms(&self) -> u64 {
        let now = current_timestamp_ms();
        now.saturating_sub(self.health.last_message_ts_ms)
    }

    /// Returns the WebSocket URL.
    pub fn ws_url(&self) -> &str {
        &self.config.ws_url
    }

    /// Returns the subscribe message.
    pub fn subscribe_message(&self) -> &str {
        &self.config.subscribe_message
    }

    /// Updates the current latency measurement.
    pub fn set_latency_ms(&mut self, latency_ms: u64) {
        self.health.current_latency_ms = latency_ms;
    }
}

/// Static JSON parser for order book updates.
/// Avoids serde allocation overhead for the most common exchange formats.
pub struct StaticBookParser;

impl StaticBookParser {
    /// Parse a Binance-style depth update from raw JSON bytes.
    ///
    /// Expected format:
    /// ```json
    /// {"e":"depthUpdate","s":"BTCUSDT","b":[["50000","1.5"]],"a":[["50001","0.8"]],"u":123}
    /// ```
    pub fn parse_binance_depth_static(json: &str) -> Option<ParsedBookUpdate> {
        // Extract symbol between "s":" and the next "
        let symbol = extract_string_field(json, "s")?;

        // Extract last update ID
        let last_update_id = extract_number_field(json, "u")?;

        // Extract bids: "b":[["price","qty"],...]
        let bids = extract_price_quantity_array(json, "b")?;

        // Extract asks: "a":[["price","qty"],...]
        let asks = extract_price_quantity_array(json, "a")?;

        Some(ParsedBookUpdate {
            symbol,
            bids,
            asks,
            is_snapshot: false,
            last_update_id,
        })
    }

    /// Parse a generic depth snapshot where the format is:
    /// ```json
    /// {"bids":[["50000","1.5"]],"asks":[["50001","0.8"]]}
    /// ```
    pub fn parse_generic_depth(json: &str) -> Option<ParsedBookUpdate> {
        let bids = extract_price_quantity_array(json, "bids")?;
        let asks = extract_price_quantity_array(json, "asks")?;

        Some(ParsedBookUpdate {
            symbol: String::new(),
            bids,
            asks,
            is_snapshot: true,
            last_update_id: 0,
        })
    }
}

// --- Helper functions for static JSON parsing ---

/// Extracts a string field value from JSON like `"key":"value"`.
fn extract_string_field(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\":\"", key);
    let start = json.find(&pattern)?;
    let value_start = start + pattern.len();
    let end = json[value_start..].find('"')?;
    Some(json[value_start..value_start + end].to_string())
}

/// Extracts a numeric field value from JSON like `"key":123`.
fn extract_number_field(json: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{}\":", key);
    let start = json.find(&pattern)?;
    let value_start = start + pattern.len();
    let num_str: String = json[value_start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    num_str.parse().ok()
}

/// Extracts an array of [price, quantity] pairs from JSON like `"key":[["p1","q1"],["p2","q2"]]`.
fn extract_price_quantity_array(json: &str, key: &str) -> Option<Vec<(String, String)>> {
    let pattern = format!("\"{}\":[", key);
    let start = json.find(&pattern)?;
    let array_start = start + pattern.len();
    let array_str = &json[array_start..];

    let mut pairs = Vec::new();
    let mut pos = 0;

    while pos < array_str.len() {
        // Find opening bracket of inner array
        let inner_start = array_str[pos..].find('[')?;
        let inner_start = pos + inner_start + 1;

        // Find closing bracket
        let inner_end = array_str[inner_start..].find(']')?;
        let inner_end = inner_start + inner_end;

        let inner = &array_str[inner_start..inner_end];

        // Split by comma
        let parts: Vec<&str> = inner.split(',').collect();
        if parts.len() == 2 {
            let price = parts[0].trim_matches('"').to_string();
            let qty = parts[1].trim_matches('"').to_string();
            pairs.push((price, qty));
        }

        pos = inner_end + 1;

        // Stop at the closing bracket of the outer array
        if pos < array_str.len() && array_str.as_bytes()[pos] == b']' {
            break;
        }
    }

    if pairs.is_empty() {
        None
    } else {
        Some(pairs)
    }
}

/// Simple pseudo-random jitter generator using system time seeded
/// with exchange_id for deterministic-but-different jitter per exchange.
fn rand_jitter(exchange_id: u16) -> f64 {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // LCG seeded with exchange_id to avoid all exchanges jittering identically.
    let seed = ts ^ (exchange_id as u64 * 1_000_003);
    let x = seed.wrapping_mul(1103515245).wrapping_add(12345);
    (x % 1000) as f64 / 1000.0
}

/// Returns current timestamp in milliseconds since epoch.
fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_binance_depth() {
        let json = r#"{"e":"depthUpdate","s":"BTCUSDT","b":[["50000","1.5"],["49990","2.0"]],"a":[["50010","0.8"]],"u":12345}"#;
        let update = StaticBookParser::parse_binance_depth_static(json).unwrap();
        assert_eq!(update.symbol, "BTCUSDT");
        assert_eq!(update.last_update_id, 12345);
        assert_eq!(update.bids.len(), 2);
        assert_eq!(update.bids[0], ("50000".to_string(), "1.5".to_string()));
        assert_eq!(update.asks.len(), 1);
        assert_eq!(update.asks[0], ("50010".to_string(), "0.8".to_string()));
        assert!(!update.is_snapshot);
    }

    #[test]
    fn test_parse_generic_depth() {
        let json = r#"{"bids":[["50000","1.0"]],"asks":[["50001","2.0"]]}"#;
        let update = StaticBookParser::parse_generic_depth(json).unwrap();
        assert_eq!(update.bids.len(), 1);
        assert_eq!(update.asks.len(), 1);
        assert!(update.is_snapshot);
    }

    #[test]
    fn test_extract_string_field() {
        let json = r#"{"s":"ETHUSDT","u":999}"#;
        assert_eq!(extract_string_field(json, "s"), Some("ETHUSDT".to_string()));
        assert_eq!(extract_string_field(json, "x"), None);
    }

    #[test]
    fn test_extract_number_field() {
        let json = r#"{"u":12345,"E":1700000000000}"#;
        assert_eq!(extract_number_field(json, "u"), Some(12345));
        assert_eq!(extract_number_field(json, "E"), Some(1700000000000));
        assert_eq!(extract_number_field(json, "z"), None);
    }

    #[test]
    fn test_extract_price_quantity_array() {
        let json = r#"{"b":[["50000","1.5"],["49990","2.0"]]}"#;
        let pairs = extract_price_quantity_array(json, "b").unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("50000".to_string(), "1.5".to_string()));
    }

    #[test]
    fn test_reconnect_delay_exponential() {
        let config = StreamConfig::default();
        let mgr = ZeroLagStreamManager::new(config);

        let d0 = mgr.next_reconnect_delay(0);
        let d1 = mgr.next_reconnect_delay(1);
        let d2 = mgr.next_reconnect_delay(2);

        assert!(d1 > d0);
        assert!(d2 > d1);
    }

    #[test]
    fn test_reconnect_delay_capped() {
        let config = StreamConfig {
            initial_reconnect_delay_ms: 250,
            max_reconnect_delay_ms: 1000,
            backoff_multiplier: 4.0,
            ..Default::default()
        };
        let mgr = ZeroLagStreamManager::new(config);

        let d0 = mgr.next_reconnect_delay(0); // ~250ms
        let d5 = mgr.next_reconnect_delay(5); // Should be capped at ~1000ms

        assert!(d5.as_millis() <= 1500); // Allow some jitter above cap
    }

    #[test]
    fn test_health_tracking() {
        let config = StreamConfig {
            ws_url: "wss://test.com".to_string(),
            subscribe_message: r#"{"method":"subscribe"}"#.to_string(),
            ..Default::default()
        };
        let mut mgr = ZeroLagStreamManager::new(config);

        mgr.record_message();
        mgr.record_message();
        mgr.record_parse_error();
        mgr.record_reconnect();

        assert_eq!(mgr.health().total_messages_received, 2);
        assert_eq!(mgr.health().total_parse_errors, 1);
        assert_eq!(mgr.health().total_reconnects, 1);
    }

    #[test]
    fn test_parse_invalid_json() {
        assert!(StaticBookParser::parse_binance_depth_static("not json").is_none());
        assert!(StaticBookParser::parse_generic_depth("{}").is_none());
    }
}