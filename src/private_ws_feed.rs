//! Private WebSocket Feed Listener
//!
//! The spec requires: "Private Order Feed Listener — Dedicated WebSocket
//! listener for private (authenticated) execution reports"
//!
//! This module handles authenticated WebSocket connections that receive
//! execution reports, order updates, and balance changes from exchanges.
//! It uses the zero-copy parser to process incoming frames.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use tokio::time::{sleep, Duration};

/// Maximum allowed WebSocket message size (64 KiB).
const WS_MAX_MESSAGE_SIZE: usize = 65_536;
/// Connect timeout in seconds.
const WS_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Exponential backoff constants — 1s base, 60s cap, 100 max retries.
const BASE_DELAY_SECS: u64 = 1;
const MAX_DELAY_SECS: u64 = 60;
const MAX_CONSECUTIVE_FAILURES: u32 = 100;

/// A parsed execution report from a private WebSocket feed.
#[derive(Debug, Clone)]
pub struct ExecutionReport {
    /// The order ID assigned by the exchange.
    pub order_id: String,
    /// Client order ID (if provided).
    pub client_order_id: Option<String>,
    /// Token/pair symbol.
    pub symbol: String,
    /// Trade side.
    pub side: String,
    /// Filled quantity.
    ///
    /// # Precision Note
    /// Uses f64 (~15 significant digits) for zero-copy parsing speed.
    /// Downstream consumers that need exact Decimal arithmetic should
    /// convert via `Decimal::from_f64()` with a documented tolerance.
    pub filled_quantity: f64,
    /// Average fill price.
    ///
    /// # Precision Note
    /// Same f64 precision trade-off as `filled_quantity`.
    pub avg_price: f64,
    /// Order status (e.g. "FILLED", "PARTIALLY_FILLED", "CANCELED").
    pub status: String,
    /// Trade timestamp (ms).
    pub timestamp: u64,
    /// Commission paid.
    ///
    /// # Precision Note
    /// Same f64 precision trade-off as `filled_quantity`.
    pub commission: f64,
    /// Commission asset.
    pub commission_asset: String,
}

/// A balance update from the private feed.
#[derive(Debug, Clone)]
pub struct BalanceUpdate {
    /// Asset symbol.
    pub asset: String,
    /// New free balance.
    ///
    /// # Precision Note
    /// f64 for zero-copy speed; convert to Decimal for ledger accounting.
    pub free_balance: f64,
    /// New locked balance.
    ///
    /// # Precision Note
    /// f64 for zero-copy speed; convert to Decimal for ledger accounting.
    pub locked_balance: f64,
    /// Timestamp.
    pub timestamp: u64,
}

/// Messages emitted by the private feed listener.
#[derive(Debug, Clone)]
pub enum PrivateFeedEvent {
    /// An order execution report.
    ExecutionReport(ExecutionReport),
    /// A balance update.
    BalanceUpdate(BalanceUpdate),
    /// Connection status change.
    Connected(String),
    Disconnected(String, String), // exchange, reason
}

/// Configuration for a private WebSocket feed.
#[derive(Debug, Clone)]
pub struct PrivateFeedConfig {
    /// Exchange identifier.
    pub exchange_id: u16,
    /// Exchange name.
    pub exchange_name: String,
    /// WebSocket URL for the private (user data) stream.
    pub wss_url: String,
    /// Listen key for authenticated streams (Binance-style).
    pub listen_key: Option<String>,
    /// L-10: Ping interval in seconds. The client should send a WebSocket
    /// ping frame at this interval. Default: 30 seconds.
    pub ping_interval_secs: u64,
    /// L-10: Pong timeout in seconds. If no pong is received within this
    /// duration after sending a ping, the connection should be closed and
    /// reconnected. Default: 60 seconds.
    pub pong_timeout_secs: u64,
}

/// Manages private WebSocket feeds across exchanges.
///
/// Each exchange gets its own authenticated WebSocket connection that
/// streams execution reports and balance updates.
pub struct PrivateWsFeedListener {
    configs: Vec<PrivateFeedConfig>,
    event_sender: mpsc::Sender<PrivateFeedEvent>,
    /// Track active connections.
    active_connections: Arc<RwLock<HashMap<String, bool>>>,
    /// Per-exchange mutexes that serialise token refresh attempts.
    /// Prevents one exchange's refresh from blocking another exchange's
    /// concurrent refresh (unlike a single shared mutex).
    refresh_mutexes: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl PrivateWsFeedListener {
    /// Creates a new private feed listener.
    ///
    /// # Arguments
    /// * `configs` — Per-exchange WebSocket configurations
    /// * `event_sender` — Channel to send parsed events to the strategy engine
    pub fn new(
        configs: Vec<PrivateFeedConfig>,
        event_sender: mpsc::Sender<PrivateFeedEvent>,
    ) -> Self {
        let active = configs
            .iter()
            .map(|c| (c.exchange_name.clone(), false))
            .collect();

        Self {
            configs,
            event_sender,
            active_connections: Arc::new(RwLock::new(active)),
            refresh_mutexes: Arc::new(DashMap::new()),
        }
    }

    /// Returns the exchange configurations.
    pub fn configs(&self) -> &[PrivateFeedConfig] {
        &self.configs
    }

    /// Returns a clone of the event sender for external use.
    pub fn event_sender(&self) -> mpsc::Sender<PrivateFeedEvent> {
        self.event_sender.clone()
    }

    /// Returns the number of configured exchanges.
    pub fn exchange_count(&self) -> usize {
        self.configs.len()
    }

    /// Starts listening for a specific exchange by spawning a
    /// background WebSocket task that connects, parses frames, forwards
    /// events via the event sender, and handles reconnection with
    /// exponential backoff.
    ///
    /// Returns `true` if the task was spawned successfully.
    pub async fn start_listening(&self, exchange_name: &str) -> bool {
        let config = match self.configs.iter().find(|c| c.exchange_name == exchange_name) {
            Some(c) => c.clone(),
            None => {
                tracing::error!(exchange = %exchange_name, "Exchange not found in private feed configs");
                return false;
            }
        };

        let sender = self.event_sender.clone();
        let active_connections = Arc::clone(&self.active_connections);
        let name = exchange_name.to_string();

        {
            let mut active = active_connections.write().await;
            active.insert(exchange_name.to_string(), true);
        }

        if sender
            .send(PrivateFeedEvent::Connected(exchange_name.to_string()))
            .await
            .is_err()
        {
            tracing::warn!(exchange = %exchange_name, "private_ws_feed: Connected event send failed — receiver dropped");
        }

        tokio::spawn(async move {
            let mut consecutive_failures: u32 = 0;
            let ping_interval = Duration::from_secs(config.ping_interval_secs);
            let pong_timeout = Duration::from_secs(config.pong_timeout_secs);
            let mut last_pong = std::time::Instant::now();

            loop {
                // ----------------------------------------------------------
                // Connect (with timeout)
                // ----------------------------------------------------------
                let connect_result = tokio::time::timeout(
                    Duration::from_secs(WS_CONNECT_TIMEOUT_SECS),
                    tokio_tungstenite::connect_async(&config.wss_url),
                )
                .await;

                match connect_result {
                    Ok(Ok((ws_stream, _response))) => {
                        consecutive_failures = 0;
                        last_pong = std::time::Instant::now();
                        tracing::info!(exchange = %name, url = %config.wss_url, "Private WS connected");

                        let (mut write, mut read) = ws_stream.split();

                        // If a listen_key is configured (Binance-style), send
                        // a keepalive ping as the subscription.
                        if let Some(ref _listen_key) = config.listen_key {
                            // Binance user-data streams auto-subscribe on connect.
                            // The listen_key is embedded in the URL.  Nothing extra
                            // to send here — just periodic pings keep it alive.
                        }

                        // ------------------------------------------------------
                        // Read loop with periodic ping
                        // ------------------------------------------------------
                        let mut ping_tick = tokio::time::interval(ping_interval);
                        ping_tick.tick().await; // consume immediate tick

                        loop {
                            tokio::select! {
                                frame = read.next() => {
                                    match frame {
                                        Some(Ok(Message::Text(text))) => {
                                            if text.len() > WS_MAX_MESSAGE_SIZE {
                                                tracing::warn!(exchange = %name, len = text.len(),
                                                    "Private WS message exceeds 64 KiB, dropping");
                                                continue;
                                            }

                                            // Attempt to detect event type from the JSON
                                            // "e" field and forward as the appropriate event.
                                            let payload = text.as_bytes();
                                            let event_type = extract_json_string(payload, b'e');

                                            match event_type.as_deref() {
                                                Some("executionReport") => {
                                                    if let Some(report) = parse_execution_report(payload) {
                                                        if sender.send(PrivateFeedEvent::ExecutionReport(report)).await.is_err() {
                                                            tracing::debug!(exchange = %name,
                                                                "ExecutionReport send failed — receiver dropped");
                                                            return;
                                                        }
                                                    }
                                                }
                                                Some("outboundAccountPosition") | Some("balanceUpdate") => {
                                                    if let Some(update) = parse_balance_update(payload) {
                                                        if sender.send(PrivateFeedEvent::BalanceUpdate(update)).await.is_err() {
                                                            tracing::debug!(exchange = %name,
                                                                "BalanceUpdate send failed — receiver dropped");
                                                            return;
                                                        }
                                                    }
                                                }
                                                _ => {
                                                    // Other event types (e.g. ORDER_TRADE_UPDATE on Bybit)
                                                    // — silently ignore unrecognised events.
                                                }
                                            }
                                        }
                                        Some(Ok(Message::Ping(data))) => {
                                            last_pong = std::time::Instant::now();
                                            let _ = write.send(Message::Pong(data)).await;
                                        }
                                        Some(Ok(Message::Pong(_))) => {
                                            last_pong = std::time::Instant::now();
                                        }
                                        Some(Ok(Message::Close(_))) => {
                                            tracing::info!(exchange = %name, "Private WS close received");
                                            break;
                                        }
                                        Some(Ok(_)) => { /* Binary / Frame — ignore */ }
                                        Some(Err(e)) => {
                                            tracing::error!(exchange = %name, error = %e,
                                                "Private WS read error");
                                            break;
                                        }
                                        None => {
                                            tracing::warn!(exchange = %name, "Private WS stream ended");
                                            break;
                                        }
                                    }
                                }
                                _ = ping_tick.tick() => {
                                    // Send application-level ping; if the server has
                                    // not responded with a pong within pong_timeout,
                                    // consider the connection dead.
                                    if last_pong.elapsed() > pong_timeout {
                                        tracing::warn!(exchange = %name,
                                            "Pong timeout — closing connection for reconnect");
                                        let _ = write.close().await;
                                        break;
                                    }
                                    if let Err(e) = write.send(Message::Ping(vec![])).await {
                                        tracing::error!(exchange = %name, error = %e,
                                            "Failed to send ping");
                                        break;
                                    }
                                }
                            }
                        }

                        // Mark disconnected and schedule reconnect.
                        {
                            let mut active = active_connections.write().await;
                            active.insert(name.clone(), false);
                        }
                        let _ = sender.send(
                            PrivateFeedEvent::Disconnected(name.clone(), "stream ended".to_string()),
                        ).await;
                    }
                    Ok(Err(e)) => {
                        tracing::error!(exchange = %name, error = %e,
                            "Private WS connect failed");
                    }
                    Err(e) => {
                        tracing::error!(exchange = %name, error = %e,
                            "Private WS connect timeout");
                    }
                }

                // --------------------------------------------------------------
                // Exponential backoff before reconnecting
                // --------------------------------------------------------------
                consecutive_failures += 1;
                if consecutive_failures > MAX_CONSECUTIVE_FAILURES {
                    tracing::error!(
                        exchange = %name,
                        consecutive_failures,
                        "Private WS failed {} times — giving up permanently",
                        MAX_CONSECUTIVE_FAILURES,
                    );
                    let _ = sender.send(
                        PrivateFeedEvent::Disconnected(name.clone(), "max retries exceeded".to_string()),
                    ).await;
                    return;
                }

                let base_delay = (BASE_DELAY_SECS << consecutive_failures.saturating_sub(1))
                    .min(MAX_DELAY_SECS) as f64;
                let jitter = base_delay * (0.8 + 0.4 * rand::random::<f64>());
                let delay_secs = jitter.min(MAX_DELAY_SECS as f64).max(1.0) as u64;

                tracing::warn!(
                    exchange = %name,
                    consecutive_failures,
                    delay_secs,
                    "Private WS reconnecting with exponential backoff",
                );
                sleep(Duration::from_secs(delay_secs)).await;
            }
        });

        tracing::info!(
            exchange = %exchange_name,
            url = %config.wss_url,
            "Private WebSocket feed task spawned",
        );

        true
    }

    /// Stops listening for a specific exchange.
    pub async fn stop_listening(&self, exchange_name: &str, reason: &str) {
        {
            let mut active = self.active_connections.write().await;
            active.insert(exchange_name.to_string(), false);
        }

        if self.event_sender
            .send(PrivateFeedEvent::Disconnected(exchange_name.to_string(), reason.to_string()))
            .await
            .is_err()
        {
            tracing::debug!(exchange = %exchange_name, "private_ws_feed: Disconnected event send failed — receiver dropped");
        }
    }

    /// Check if a specific exchange's feed is active.
    pub async fn is_active(&self, exchange_name: &str) -> bool {
        let active = self.active_connections.read().await;
        active.get(exchange_name).copied().unwrap_or(false)
    }

    /// Attempt to refresh the authentication token for the given exchange.
    ///
    /// Uses a non-blocking `try_lock` on a per-exchange mutex so that
    /// if a refresh is already in progress (e.g. due to a rapid reconnect),
    /// this call returns `false` immediately instead of queuing up and
    /// potentially double-refreshing.
    ///
    /// # Returns
    /// * `Ok(true)`  — this call performed the refresh
    /// * `Ok(false)` — skipped because another refresh is already in progress
    /// * `Err(_)`   — the exchange was not found in the configuration
    pub async fn refresh_token(&self, exchange_name: &str) -> Result<bool, String> {
        // Verify the exchange is configured.
        if !self.configs.iter().any(|c| c.exchange_name == exchange_name) {
            return Err(format!("Exchange '{}' not found in private feed configs", exchange_name));
        }

        // Get or create a per-exchange mutex for this refresh attempt.
        let mutex = self
            .refresh_mutexes
            .entry(exchange_name.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())));

        // Non-blocking lock: if another task is already refreshing this
        // exchange, skip.
        let result = match mutex.try_lock() {
            Ok(_guard) => {
                // In production this would call the exchange's listen-key
                // renewal or OAuth refresh endpoint.  For now, just log.
                tracing::info!(exchange = %exchange_name, "Token refresh initiated");
                // Simulate the async work (replace with real HTTP call).
                // drop(_guard) happens automatically at the end of this scope.
                Ok(true)
            }
            Err(_) => {
                tracing::debug!(
                    exchange = %exchange_name,
                    "Skipping token refresh — another refresh already in progress"
                );
                Ok(false)
            }
        };
        result
    }
}

// ---------------------------------------------------------------------------
// Minimal JSON helpers (zero-copy string extraction)
// ---------------------------------------------------------------------------

/// Extracts the string value for a single-character JSON key from raw bytes.
/// For example, given key `b'e'` and `b{"e":"executionReport",...}`
/// returns `Some("executionReport")`.
///
/// This is a lightweight alternative to full serde_json parsing for the
/// hot path where we only need the event type discriminator.
fn extract_json_string(payload: &[u8], key: u8) -> Option<String> {
    let mut i = 0;
    let len = payload.len();
    while i < len {
        if payload[i] != b'"' {
            i += 1;
            continue;
        }
        i += 1;
        if i >= len || payload[i] != key {
            continue;
        }
        i += 1;
        if i >= len || payload[i] != b'"' {
            continue;
        }
        i += 1;
        if i >= len || payload[i] != b':' {
            continue;
        }
        i += 1;
        // skip whitespace after colon
        while i < len && payload[i] == b' ' {
            i += 1;
        }
        if i >= len || payload[i] != b'"' {
            continue;
        }
        i += 1; // skip opening quote of value
        let start = i;
        while i < len && payload[i] != b'"' {
            i += 1;
        }
        if i >= len {
            return None;
        }
        return std::str::from_utf8(&payload[start..i]).ok().map(|s| s.to_string());
    }
    None
}

/// Extracts a JSON number value (as f64) for a single-character key.
fn extract_json_f64(payload: &[u8], key: u8) -> Option<f64> {
    let mut i = 0;
    let len = payload.len();
    while i < len {
        if payload[i] != b'"' {
            i += 1;
            continue;
        }
        i += 1;
        if i >= len || payload[i] != key {
            continue;
        }
        i += 1;
        if i >= len || payload[i] != b'"' {
            continue;
        }
        i += 1;
        if i >= len || payload[i] != b':' {
            continue;
        }
        i += 1;
        // skip whitespace
        while i < len && (payload[i] == b' ' || payload[i] == b'\n') {
            i += 1;
        }
        if i >= len {
            return None;
        }
        let start = i;
        if payload[i] == b'"' {
            // quoted number
            i += 1;
            while i < len && payload[i] != b'"' {
                i += 1;
            }
            if i >= len { return None; }
            let s = std::str::from_utf8(&payload[start + 1..i]).ok()?;
            return s.parse().ok();
        } else {
            // unquoted number
            while i < len && (payload[i].is_ascii_digit() || payload[i] == b'.' || payload[i] == b'-') {
                i += 1;
            }
            let s = std::str::from_utf8(&payload[start..i]).ok()?;
            return s.parse().ok();
        }
    }
    None
}

/// Parses a Binance-style `executionReport` JSON payload into an
/// [`ExecutionReport`] using the zero-copy helpers above.
fn parse_execution_report(payload: &[u8]) -> Option<ExecutionReport> {
    Some(ExecutionReport {
        order_id: extract_json_string(payload, b'i').unwrap_or_default(),
        client_order_id: extract_json_string(payload, b'c'),
        symbol: extract_json_string(payload, b's').unwrap_or_default(),
        side: extract_json_string(payload, b'S').unwrap_or_default(),
        filled_quantity: extract_json_f64(payload, b'l').unwrap_or(0.0),
        avg_price: extract_json_f64(payload, b'L').unwrap_or(0.0),
        status: extract_json_string(payload, b'X').unwrap_or_default(),
        timestamp: extract_json_f64(payload, b'T').unwrap_or(0.0) as u64,
        commission: extract_json_f64(payload, b'n').unwrap_or(0.0),
        commission_asset: extract_json_string(payload, b'N').unwrap_or_default(),
    })
}

/// Parses a Binance-style `outboundAccountPosition` JSON payload into a
/// representative [`BalanceUpdate`].  When the payload contains multiple
/// balance entries ("B" array), only the first entry is returned.
fn parse_balance_update(payload: &[u8]) -> Option<BalanceUpdate> {
    // For outboundAccountPosition, "B" is an array of balance objects.
    // This simplified parser extracts the first "a" (asset) and "f" (free)
    // string fields it can find.
    Some(BalanceUpdate {
        asset: extract_json_string(payload, b'a').unwrap_or_default(),
        free_balance: extract_json_f64(payload, b'f').unwrap_or(0.0),
        locked_balance: extract_json_f64(payload, b'l').unwrap_or(0.0),
        timestamp: extract_json_f64(payload, b'E').unwrap_or(0.0) as u64,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_listener() -> (PrivateWsFeedListener, mpsc::Receiver<PrivateFeedEvent>) {
        let (tx, rx) = mpsc::channel(100);
        let configs = vec![
            PrivateFeedConfig {
                exchange_id: 1,
                exchange_name: "binance".to_string(),
                wss_url: "wss://stream.binance.com:9443/ws".to_string(),
                listen_key: None,
                ping_interval_secs: 30,
                pong_timeout_secs: 60,
            },
            PrivateFeedConfig {
                exchange_id: 2,
                exchange_name: "bybit".to_string(),
                wss_url: "wss://stream.bybit.com/v5/private".to_string(),
                listen_key: None,
                ping_interval_secs: 30,
                pong_timeout_secs: 60,
            },
        ];
        let listener = PrivateWsFeedListener::new(configs, tx);
        (listener, rx)
    }

    #[tokio::test]
    async fn test_start_listening() {
        let (listener, _rx) = make_listener();
        assert!(listener.start_listening("binance").await);
        assert!(listener.is_active("binance").await);
    }

    #[tokio::test]
    async fn test_stop_listening() {
        let (listener, _rx) = make_listener();
        listener.start_listening("bybit").await;
        listener.stop_listening("bybit", "shutdown").await;
        assert!(!listener.is_active("bybit").await);
    }

    #[tokio::test]
    async fn test_exchange_count() {
        let (listener, _) = make_listener();
        assert_eq!(listener.exchange_count(), 2);
    }

    #[tokio::test]
    async fn test_unknown_exchange() {
        let (listener, _) = make_listener();
        assert!(!listener.start_listening("unknown").await);
    }
}