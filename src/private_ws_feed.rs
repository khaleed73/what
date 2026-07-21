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
    // TODO: These should be Decimal for exact financial arithmetic.
    pub filled_quantity: f64,
    /// Average fill price.
    pub avg_price: f64,
    /// Order status (e.g. "FILLED", "PARTIALLY_FILLED", "CANCELED").
    pub status: String,
    /// Trade timestamp (ms).
    pub timestamp: u64,
    /// Commission paid.
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
    pub free_balance: f64,
    /// New locked balance.
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

    /// Starts listening for a specific exchange (stub — actual WebSocket
    /// connection would be established here in production).
    ///
    /// In production, this would:
    /// 1. Connect to the authenticated WebSocket endpoint
    /// 2. Send keepalive pings
    /// 3. Parse incoming frames using `parse_execution_report_bytes`
    /// 4. Forward parsed events via `event_sender`
    pub async fn start_listening(&self, exchange_name: &str) -> bool {
        let config = match self.configs.iter().find(|c| c.exchange_name == exchange_name) {
            Some(c) => c,
            None => {
                tracing::error!(exchange = %exchange_name, "Exchange not found in private feed configs");
                return false;
            }
        };

        {
            let mut active = self.active_connections.write().await;
            active.insert(exchange_name.to_string(), true);
        }

        if self.event_sender
            .send(PrivateFeedEvent::Connected(exchange_name.to_string()))
            .await
            .is_err()
        {
            tracing::warn!(exchange = %exchange_name, "private_ws_feed: Connected event send failed — receiver dropped");
        }

        tracing::info!(
            exchange = %exchange_name,
            url = %config.wss_url,
            "Private WebSocket feed started (stub)"
        );

        tracing::warn!(
            exchange = %exchange_name,
            "Private WebSocket feed is a STUB — no actual connection established. Fill/execution data will be stale."
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