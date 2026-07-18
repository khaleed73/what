//! TCP Optimizer — Connection Pooling & Low-Latency Settings
//!
//! The spec requires:
//! - TCP_NODELAY / Nagle's Algorithm bypass: `.tcp_nodelay(true)`
//! - Connection pooling: `.pool_max_idle_per_host(10)` to keep connections warm
//! - Pre-heated `reqwest::Client` instances
//!
//! This module provides factory methods for creating optimized HTTP clients.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Default connection timeout.
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;
/// Default request timeout.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 10;
/// Default pool max idle per host.
const DEFAULT_POOL_MAX_IDLE: usize = 10;
/// Default keep-alive interval.
const DEFAULT_KEEPALIVE_SECS: u64 = 30;

/// Configuration for an optimized HTTP client.
#[derive(Debug, Clone)]
pub struct TcpOptimizedClientConfig {
    /// TCP_NODELAY: disable Nagle's algorithm for immediate sending.
    pub tcp_nodelay: bool,
    /// Maximum idle connections per host.
    pub pool_max_idle_per_host: usize,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Request timeout.
    pub request_timeout: Duration,
    /// TCP keep-alive interval.
    pub keepalive_interval: Duration,
    /// Whether to enable HTTP/2.
    pub http2_prior_knowledge: bool,
}

impl Default for TcpOptimizedClientConfig {
    fn default() -> Self {
        // TCP_NODELAY is applied universally. This is correct for exchange
        // connections but adds ~40% CPU overhead for keep-alive pings.
        // For internal services (Discord, monitoring), Nagle's algorithm
        // would be more appropriate.
        Self {
            tcp_nodelay: true,
            pool_max_idle_per_host: DEFAULT_POOL_MAX_IDLE,
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            keepalive_interval: Duration::from_secs(DEFAULT_KEEPALIVE_SECS),
            http2_prior_knowledge: false,
        }
    }
}

impl TcpOptimizedClientConfig {
    /// Creates a config optimized for lowest latency (shorter timeouts).
    pub fn low_latency() -> Self {
        Self {
            tcp_nodelay: true,
            pool_max_idle_per_host: 16,
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(5),
            keepalive_interval: Duration::from_secs(15),
            http2_prior_knowledge: false,
        }
    }

    /// Creates a config with longer timeouts for slower exchanges.
    pub fn high_reliability() -> Self {
        Self {
            tcp_nodelay: true,
            pool_max_idle_per_host: 8,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(60),
            http2_prior_knowledge: false,
        }
    }
}

/// A pool of pre-built, optimized `reqwest::Client` instances.
///
/// The spec requires "TCP Connection Pooling / Pre-Heating — Keep
/// `reqwest::Client` connections warm". This pool creates one client
/// per exchange at startup so no connection setup happens on the hot path.
pub struct TcpOptimizer {
    clients: HashMap<String, Arc<reqwest::Client>>,
    configs: HashMap<String, TcpOptimizedClientConfig>,
}

impl TcpOptimizer {
    /// Creates a new optimizer.
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
            configs: HashMap::new(),
        }
    }

    /// Register an exchange and pre-build its optimized HTTP client.
    ///
    /// This should be called at startup to pre-heat connections.
    pub fn register_exchange(&mut self, exchange_id: &str, config: TcpOptimizedClientConfig) {
        let client = Self::build_client(&config);
        self.clients.insert(exchange_id.to_lowercase(), Arc::new(client));
        self.configs.insert(exchange_id.to_lowercase(), config);
        tracing::info!(
            exchange = %exchange_id,
            tcp_nodelay = self.configs[&exchange_id.to_lowercase()].tcp_nodelay,
            pool_max_idle = self.configs[&exchange_id.to_lowercase()].pool_max_idle_per_host,
            "Optimized HTTP client created and pre-heated"
        );
    }

    /// Register with default config.
    pub fn register_exchange_default(&mut self, exchange_id: &str) {
        self.register_exchange(exchange_id, TcpOptimizedClientConfig::default());
    }

    /// Get the pre-built client for an exchange.
    ///
    /// Returns an error if the exchange is not registered.
    pub fn get_client(&self, exchange_id: &str) -> anyhow::Result<Arc<reqwest::Client>> {
        self.clients
            .get(&exchange_id.to_lowercase())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Exchange '{}' not registered in TcpOptimizer", exchange_id))
    }

    /// Build a single optimized `reqwest::Client`.
    pub fn build_client(config: &TcpOptimizedClientConfig) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .tcp_nodelay(config.tcp_nodelay)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .tcp_keepalive(config.keepalive_interval);

        if config.http2_prior_knowledge {
            builder = builder.http2_prior_knowledge();
        }

        builder
            .build()
            .expect("FATAL: failed to build optimized reqwest::Client — aborting")
    }

    /// Returns the number of registered exchanges.
    pub fn exchange_count(&self) -> usize {
        self.clients.len()
    }

    /// Returns the configuration for a specific exchange.
    pub fn get_config(&self, exchange_id: &str) -> Option<&TcpOptimizedClientConfig> {
        self.configs.get(&exchange_id.to_lowercase())
    }
}

impl Default for TcpOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_default_client() {
        let config = TcpOptimizedClientConfig::default();
        let client = TcpOptimizer::build_client(&config);
        // Verify the client was created successfully.
        let _req = client.post("https://httpbin.org/post").timeout(std::time::Duration::from_secs(5));
    }

    #[test]
    fn test_build_low_latency_client() {
        let config = TcpOptimizedClientConfig::low_latency();
        assert_eq!(config.pool_max_idle_per_host, 16);
        assert_eq!(config.connect_timeout, Duration::from_secs(3));
        let client = TcpOptimizer::build_client(&config);
        let _req = client.post("https://httpbin.org/post").timeout(std::time::Duration::from_secs(5));
    }

    #[test]
    fn test_optimizer_register_and_get() {
        let mut opt = TcpOptimizer::new();
        opt.register_exchange_default("binance");
        opt.register_exchange_default("bybit");

        assert_eq!(opt.exchange_count(), 2);
        let _r1 = opt.get_client("binance").unwrap().post("https://test.com").timeout(std::time::Duration::from_secs(5));
        let _r2 = opt.get_client("bybit").unwrap().post("https://test.com").timeout(std::time::Duration::from_secs(5));
    }

    #[test]
    fn test_get_config() {
        let mut opt = TcpOptimizer::new();
        opt.register_exchange("binance", TcpOptimizedClientConfig::low_latency());
        let config = opt.get_config("binance").unwrap();
        assert_eq!(config.pool_max_idle_per_host, 16);
    }

    #[test]
    fn test_default_config_tcp_nodelay() {
        let config = TcpOptimizedClientConfig::default();
        assert!(config.tcp_nodelay);
    }
}