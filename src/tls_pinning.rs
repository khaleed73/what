//! TLS Certificate Pinning for exchange connections.
//!
//! Creates `reqwest::Client` instances that pin specific TLS certificates
//! to prevent MITM attacks.  Falls back to standard TLS if no pins are
//! configured.
//!
//! **C-78 fix**: The module now offers two levels of pinning:
//!
//! 1. **CA pinning** (recommended, production-ready): via `TlsPinningConfig` in
//!    `exchange::common::build_pinned_http_client`, which adds PEM CA certs as
//!    exclusive trust anchors to the HTTP client.
//!
//! 2. **Fingerprint pinning** (advanced): via `TlsPins` SHA-256 fingerprints.
//!    True fingerprint-level pinning requires a custom `rustls::ServerCertVerifier`
//!    which is not yet implemented.  When fingerprint pins are provided without
//!    a matching `TlsPinningConfig`, this module now **warns loudly** and returns
//!    an error instead of silently falling back to no pinning.

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

/// Error returned when fingerprint pins cannot be enforced.
#[derive(Debug)]
pub struct TlsPinningNotEnforcedError {
    pub pinned_exchanges: Vec<String>,
}

impl std::fmt::Display for TlsPinningNotEnforcedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TLS fingerprint pins provided for {:?} but fingerprint-level pinning \
             requires a custom rustls ServerCertVerifier (not yet implemented). \
             Use TlsPinningConfig with CA PEM certs via build_pinned_http_client() \
             for production pinning.",
            self.pinned_exchanges
        )
    }
}

impl std::error::Error for TlsPinningNotEnforcedError {}

/// Builds a TLS-pinned `reqwest::Client`.
///
/// When `pins` contains an entry for the given exchange, the client
/// will verify that the server's certificate matches the pinned fingerprint.
/// Otherwise, standard certificate verification is used.
///
/// **C-78 fix**: If fingerprint pins are provided but cannot actually be
/// enforced (because `reqwest` doesn't support custom `ServerCertVerifier`
/// without `rustls`), this function now returns an error instead of silently
/// building an un-pinned client.
///
/// For CA-level pinning (production recommended), use
/// `crate::exchange::common::build_pinned_http_client` with `TlsPinningConfig`
/// that contains PEM-encoded CA certificates.
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
    // C-78 fix: If fingerprint pins are configured, refuse to build an
    // un-pinned client.  Fingerprint pinning is NOT actually enforced by
    // this builder (it would require a rustls custom ServerCertVerifier),
    // so returning an un-pinned client would give a false sense of security.
    if let Some(p) = pins {
        if !p.pins.is_empty() {
            let exchange_names: Vec<String> = p.pins.keys().cloned().collect();
            let err = TlsPinningNotEnforcedError {
                pinned_exchanges: exchange_names,
            };
            tracing::error!(
                pinned_count = p.pins.len(),
                "TLS fingerprint pins were provided but CANNOT be enforced without \
                 a custom rustls ServerCertVerifier. Refusing to build un-pinned \
                 client. Use exchange::common::build_pinned_http_client() with \
                 TlsPinningConfig { ca_cert_pem: Some(...) } for CA-level pinning."
            );
            return Err(err.to_string());
        }
    }

    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(connect_timeout_secs))
        .tcp_nodelay(true)
        .pool_max_idle_per_host(4)
        .pool_idle_timeout(Duration::from_secs(90))
        .https_only(true)
        .build()
        .map_err(|e| format!("failed to build TLS-pinned HTTP client: {}", e))
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
    fn test_build_pinned_client_empty_pins() {
        let pins = TlsPins::empty();
        let client = build_pinned_client(Some(&pins), 10, 5);
        assert!(client.is_ok());
    }

    // C-78 regression test: non-empty pins must now error, not silently build un-pinned.
    #[test]
    fn test_build_pinned_client_rejects_unenforced_fingerprints() {
        let mut pins = HashMap::new();
        pins.insert("Binance".to_string(), "abcd1234".to_string());
        let pins = TlsPins::new(pins);
        let result = build_pinned_client(Some(&pins), 10, 5);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("fingerprint"),
            "error should mention fingerprint pinning"
        );
    }
}