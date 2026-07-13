// exchange/common.rs — Shared signing helpers, rate limiter, error types,
// and HTTP utilities for all exchange client implementations.
//
// Every exchange client in the `exchange` module imports from here:
//   `use crate::exchange::common::*;`

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use ring::hmac;
use rust_decimal::Decimal;
use serde_json::Value;

// ---------------------------------------------------------------------------
// ExchangeError
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ExchangeError {
    ApiError {
        status: u16,
        message: String,
        is_rate_limited: bool,
    },
    ParseError(String),
    HttpError(String),
}

impl std::fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExchangeError::ApiError { status, message, .. } => {
                write!(f, "API error (HTTP {}): {}", status, message)
            }
            ExchangeError::ParseError(msg) => write!(f, "parse error: {}", msg),
            ExchangeError::HttpError(msg) => write!(f, "HTTP error: {}", msg),
        }
    }
}

impl std::error::Error for ExchangeError {}

// Manual conversion helper — avoids conflicting blanket impl.
pub fn into_anyhow(e: ExchangeError) -> anyhow::Error {
    anyhow::anyhow!("{}", e)
}

// ---------------------------------------------------------------------------
// RateLimiter — simple token-bucket throttle
// ---------------------------------------------------------------------------

pub struct RateLimiter {
    min_interval_us: u64,
    last_call: AtomicU64,
}

impl RateLimiter {
    pub fn new(requests_per_second: u64) -> Self {
        let min_interval_us = 1_000_000 / requests_per_second.max(1);
        Self {
            min_interval_us,
            last_call: AtomicU64::new(0),
        }
    }

    /// Block until at least `min_interval_us` have elapsed since the last call.
    ///
    /// Uses `SystemTime` for monotonic cross-call comparison. The initial
    /// call always proceeds immediately (last == 0 sentinel).
    pub async fn throttle(&self) {
        let now_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let last = self.last_call.load(Ordering::Relaxed);

        if last > 0 {
            if let Some(sleep_us) = (last + self.min_interval_us).checked_sub(now_us) {
                if sleep_us > 0 && sleep_us < 1_000_000 {
                    tokio::time::sleep(Duration::from_micros(sleep_us)).await;
                }
            }
        }

        self.last_call.store(now_us, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// KrakenNonce — monotonic nonce generator
// ---------------------------------------------------------------------------

pub struct KrakenNonce {
    last: std::sync::Mutex<u64>,
}

impl KrakenNonce {
    pub fn new() -> Self {
        let initial = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            last: std::sync::Mutex::new(initial),
        }
    }

    pub fn next(&self) -> u64 {
        // Poisoned mutex is unrecoverable in a nonce generator — use expect
        // to provide a clear diagnostic message rather than a bare unwrap.
        let mut last = self.last.lock().expect("KrakenNonce mutex poisoned");
        *last += 1;
        *last
    }
}

// ---------------------------------------------------------------------------
// TlsPinningConfig — optional per-exchange certificate pinning
// ---------------------------------------------------------------------------

/// Configuration for TLS certificate pinning.
///
/// When `ca_cert_pem` is `Some`, the provided PEM-encoded CA certificate(s)
/// are loaded as the *only* trust anchors for that exchange's HTTP client.
/// This prevents MITM attacks even if the system's root certificate store is
/// compromised (e.g. on a compromised VPS).
///
/// # Usage
///
/// ```ignore
/// let tls = TlsPinningConfig {
///     ca_cert_pem: Some(include_str!("certs/binance_ca.pem").to_string()),
/// };
/// let client = build_pinned_http_client(10, &tls)?;
/// ```
#[derive(Debug, Clone)]
pub struct TlsPinningConfig {
    /// Optional PEM-encoded CA certificate bundle. When set, *only* these
    /// certificates are trusted for TLS connections.
    pub ca_cert_pem: Option<String>,
}

impl Default for TlsPinningConfig {
    fn default() -> Self {
        Self { ca_cert_pem: None }
    }
}

// ---------------------------------------------------------------------------
// build_http_client
// ---------------------------------------------------------------------------

/// Build a `reqwest::Client` with sensible defaults for exchange REST APIs.
///
/// Uses system TLS trust anchors.  For certificate pinning, use
/// [`build_pinned_http_client`] instead.
pub fn build_http_client(timeout_secs: u64) -> anyhow::Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(timeout_secs))
        .pool_max_idle_per_host(4)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {}", e))?;
    Ok(client)
}

// ---------------------------------------------------------------------------
// build_pinned_http_client
// ---------------------------------------------------------------------------

/// Build a `reqwest::Client` with optional TLS certificate pinning.
///
/// When `tls.ca_cert_pem` is `Some`, the provided PEM bundle is loaded as the
/// exclusive set of trust anchors via `native_tls::TlsConnector`.  This
/// ensures that only servers presenting certificates signed by the pinned CA
/// will be trusted.
///
/// Falls back to the default system trust store when `ca_cert_pem` is `None`.
pub fn build_pinned_http_client(
    timeout_secs: u64,
    tls: &TlsPinningConfig,
) -> anyhow::Result<reqwest::Client> {
    match &tls.ca_cert_pem {
        Some(pem) => {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("failed to parse pinned CA cert: {}", e))?;

            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout_secs))
                .connect_timeout(Duration::from_secs(timeout_secs))
                .pool_max_idle_per_host(4)
                .use_native_tls()
                .add_root_certificate(cert)
                .min_tls_version(reqwest::tls::Version::TLS_1_2)
                .build()
                .map_err(|e| anyhow::anyhow!("failed to build pinned HTTP client: {}", e))?;
            Ok(client)
        }
        None => build_http_client(timeout_secs),
    }
}

// ---------------------------------------------------------------------------
// parse_exchange_response — generic JSON error checker
// ---------------------------------------------------------------------------

pub async fn parse_exchange_response(
    resp: reqwest::Response,
    exchange_name: &str,
) -> Result<Value, ExchangeError> {
    let status = resp.status();
    let is_rate_limited = status.as_u16() == 429;

    let body = resp
        .text()
        .await
        .map_err(|e| ExchangeError::HttpError(format!("failed to read body: {}", e)))?;

    if !status.is_success() {
        // Try to extract a message from JSON
        let msg = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("msg")
                    .or_else(|| v.get("message"))
                    .or_else(|| v.get("error"))
                    .and_then(|m| m.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| body.clone());

        return Err(ExchangeError::ApiError {
            status: status.as_u16(),
            message: msg,
            is_rate_limited,
        });
    }

    let json: Value = serde_json::from_str(&body)
        .map_err(|e| ExchangeError::ParseError(format!("{}: {}", exchange_name, e)))?;

    // Some exchanges return HTTP 200 with an error code in the body
    // (e.g. KuCoin {"code":"200000","msg":"success","data":...})
    // We let individual clients handle this.

    Ok(json)
}

// ---------------------------------------------------------------------------
// parse_json_decimal — extract Decimal from a JSON Value
// ---------------------------------------------------------------------------

pub fn parse_json_decimal(v: &Value) -> Decimal {
    if let Some(s) = v.as_str() {
        Decimal::from_str(s).unwrap_or(Decimal::ZERO)
    } else if let Some(n) = v.as_i64() {
        Decimal::from(n)
    } else if let Some(f) = v.as_f64() {
        Decimal::from_f64(f).unwrap_or(Decimal::ZERO)
    } else {
        Decimal::ZERO
    }
}

// Internal trait to avoid importing rust_decimal::prelude in call sites.
use std::str::FromStr;
use rust_decimal::prelude::FromPrimitive;

// ---------------------------------------------------------------------------
// extract_order_id — pull an order ID from various JSON shapes
// ---------------------------------------------------------------------------

pub fn extract_order_id(v: &Value) -> anyhow::Result<String> {
    // Try string
    if let Some(s) = v.as_str() {
        return Ok(s.to_string());
    }
    // Try i64
    if let Some(n) = v.as_i64() {
        return Ok(n.to_string());
    }
    // Try u64
    if let Some(n) = v.as_u64() {
        return Ok(n.to_string());
    }
    anyhow::bail!("cannot extract order ID from JSON value")
}

// ===========================================================================
// Signing helpers
// ===========================================================================

// ---------------------------------------------------------------------------
// sign_hmac — HMAC-SHA256 hex (Binance, Bybit, HTX, LBank style)
// ---------------------------------------------------------------------------

pub fn sign_hmac(secret: &str, payload: &str) -> anyhow::Result<String> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let sig = hmac::sign(&key, payload.as_bytes());
    Ok(hex::encode(sig.as_ref()))
}

// ---------------------------------------------------------------------------
// sign_hmac_base64 — HMAC-SHA256 base64 (KuCoin, BitMEX, Bitget style)
// ---------------------------------------------------------------------------

pub fn sign_hmac_base64(secret: &str, payload: &str) -> anyhow::Result<String> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let sig = hmac::sign(&key, payload.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.as_ref()))
}

// ---------------------------------------------------------------------------
// sign_hmac_base64_with_decoded_key — HMAC-SHA256 base64 with base64-decoded key
// (Coinbase Pro style)
// ---------------------------------------------------------------------------

pub fn sign_hmac_base64_with_decoded_key(secret: &str, payload: &str) -> anyhow::Result<String> {
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(secret)
        .map_err(|e| anyhow::anyhow!("failed to base64-decode secret: {}", e))?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
    let sig = hmac::sign(&key, payload.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.as_ref()))
}

// ---------------------------------------------------------------------------
// sign_kucoin_passphrase — HMAC-SHA256 of passphrase, base64-encoded
// ---------------------------------------------------------------------------

pub fn sign_kucoin_passphrase(secret: &str, passphrase: &str) -> anyhow::Result<String> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let sig = hmac::sign(&key, passphrase.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.as_ref()))
}

// ---------------------------------------------------------------------------
// sign_bitfinex — HMAC-SHA384 hex (Bitfinex style)
// ---------------------------------------------------------------------------

pub fn sign_bitfinex(secret: &str, path: &str, nonce: &str, body: &str) -> anyhow::Result<String> {
    let preimage = format!("/api/v2{}{}{}", path, nonce, body);
    let key = hmac::Key::new(hmac::HMAC_SHA384, secret.as_bytes());
    let sig = hmac::sign(&key, preimage.as_bytes());
    Ok(hex::encode(sig.as_ref()))
}

// ---------------------------------------------------------------------------
// sign_bitget — HMAC-SHA256 base64 (Bitget V2 style)
// ---------------------------------------------------------------------------

pub fn sign_bitget(
    secret: &str,
    timestamp: &str,
    method: &str,
    path: &str,
    body: &str,
) -> anyhow::Result<String> {
    let preimage = format!("{}{}{}{}", timestamp, method.to_uppercase(), path, body);
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let sig = hmac::sign(&key, preimage.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.as_ref()))
}

// ---------------------------------------------------------------------------
// sign_bitmex — HMAC-SHA256 hex with expires (BitMEX style)
// ---------------------------------------------------------------------------

pub fn sign_bitmex(
    secret: &str,
    verb: &str,
    path: &str,
    expires: u64,
    body: &str,
) -> anyhow::Result<String> {
    let preimage = format!("{}{}{}{}", verb, path, expires, body);
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let sig = hmac::sign(&key, preimage.as_bytes());
    Ok(hex::encode(sig.as_ref()))
}

// ---------------------------------------------------------------------------
// sign_htx — HMAC-SHA256 hex (Huobi/HTX style)
// ---------------------------------------------------------------------------

pub fn sign_htx(
    secret: &str,
    method: &str,
    host: &str,
    path: &str,
    query: &str,
) -> anyhow::Result<String> {
    let preimage = format!("{}\n{}\n{}\n{}", method, host, path, query);
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let sig = hmac::sign(&key, preimage.as_bytes());
    Ok(hex::encode(sig.as_ref()))
}

// ---------------------------------------------------------------------------
// sign_kraken — HMAC-SHA512 base64 (Kraken style)
// ---------------------------------------------------------------------------

pub fn sign_kraken(
    secret: &str,
    path: &str,
    nonce: &str,
    body: &str,
) -> anyhow::Result<String> {
    let preimage = format!("{}{}{}", nonce, path, body);
    // Decode the API secret from base64
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(secret)
        .map_err(|e| anyhow::anyhow!("failed to decode Kraken secret: {}", e))?;
    let key = hmac::Key::new(hmac::HMAC_SHA512, &key_bytes);
    let sig = hmac::sign(&key, preimage.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.as_ref()))
}

/// Extract an f64 from a JSON Value (convenience for exchange responses).
pub fn parse_json_f64(v: &Value) -> f64 {
    v.as_f64()
        .unwrap_or(0.0)
}

/// HMAC-SHA256 hex (LBank style).
pub fn sign_lbank_hmac(secret: &str, payload: &str) -> anyhow::Result<String> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let sig = hmac::sign(&key, payload.as_bytes());
    Ok(hex::encode(sig.as_ref()))
}

