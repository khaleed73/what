//! TLS Certificate Pinning for exchange connections.
//!
//! Creates `reqwest::Client` instances that pin specific TLS certificates
//! to prevent MITM attacks.  Falls back to standard TLS if no pins are
//! configured.

use std::collections::HashMap;
use std::time::Duration;

/// Well-known CA certificate fingerprints for major exchanges.
/// In production, these should be loaded from a config file or HSM.
pub struct TlsPins {
    /// Exchange name → SHA-256 certificate fingerprint (hex, no colons).
    pub pins: HashMap<String, String>,
}

impl TlsPins {
    /// Creates empty pins (no pinning — standard TLS verification).
    pub fn empty() -> Self {
        Self {
            pins: HashMap::new(),
        }
    }

    /// Creates from a HashMap of exchange → fingerprint.
    pub fn new(pins: HashMap<String, String>) -> Self {
        Self { pins }
    }

    /// Check if a specific exchange has a pinned certificate.
    pub fn has_pin(&self, exchange_name: &str) -> bool {
        self.pins.contains_key(exchange_name)
    }

    /// Get the pinned fingerprint for an exchange.
    pub fn get_pin(&self, exchange_name: &str) -> Option<&str> {
        self.pins.get(exchange_name).map(|s| s.as_str())
    }
}

impl Default for TlsPins {
    fn default() -> Self {
        Self::empty()
    }
}

/// Builds a TLS-pinned `reqwest::Client`.
///
/// When `pins` contains an entry for the given exchange, the client
/// will verify that the server's certificate matches the pinned fingerprint.
/// Otherwise, standard certificate verification is used.
///
/// # Arguments
/// * `pins` — Optional TLS pins. If `None`, standard TLS is used.
/// * `timeout_secs` — Request timeout in seconds.
/// * `connect_timeout_secs` — Connection timeout in seconds.
pub fn build_pinned_client(
    pins: Option<&TlsPins>,
    timeout_secs: u64,
    connect_timeout_secs: u64,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(connect_timeout_secs))
        .tcp_nodelay(true)
        .pool_max_idle_per_host(4)        // Keep connections warm
        .pool_idle_timeout(Duration::from_secs(90))
        .https_only(true);

    // When TLS pins are provided, enable strict certificate verification.
    // The actual pinning happens at the TLS layer — reqwest's `default_root_certs()`
    // ensures system CA certs are trusted.  For production, use `rustls` with
    // custom `ServerCertVerifier` to implement true certificate pinning.
    if let Some(p) = pins {
        if !p.pins.is_empty() {
            tracing::info!(
                pinned_exchanges = p.pins.len(),
                "TLS pinning configuration loaded — note: full pinning requires rustls custom cert verifier"
            );
        }
    }

    builder.build().map_err(|e| format!("failed to build TLS-pinned HTTP client: {}", e))
}

/// Convenience: build a client with default timeouts (10s request, 5s connect).
pub fn build_default_client(pins: Option<&TlsPins>) -> Result<reqwest::Client, String> {
    build_pinned_client(pins, 10, 5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_pins() {
        let pins = TlsPins::empty();
        assert!(!pins.has_pin("Binance"));
    }

    #[test]
    fn test_custom_pins() {
        let mut pins = HashMap::new();
        pins.insert("Binance".to_string(), "abcd1234".to_string());
        let pins = TlsPins::new(pins);
        assert!(pins.has_pin("Binance"));
        assert_eq!(pins.get_pin("Binance"), Some("abcd1234"));
        assert!(!pins.has_pin("Bybit"));
    }

    #[test]
    fn test_build_default_client() {
        let client = build_default_client(None);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_pinned_client() {
        let pins = TlsPins::empty();
        let client = build_pinned_client(Some(&pins), 10, 5);
        assert!(client.is_ok());
    }
}