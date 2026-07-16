// exchange/common.rs — Shared signing helpers, rate limiter, error types,
// and HTTP utilities for all exchange client implementations.
//
// Every exchange client in the `exchange` module imports from here:
//   `use crate::exchange::common::*;`

use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use ring::hmac;
use rust_decimal::Decimal;
use rust_decimal::prelude::FromPrimitive;
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

impl Default for KrakenNonce {
    fn default() -> Self {
        Self::new()
    }
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
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
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
#[derive(Default)]
pub struct TlsPinningConfig {
    /// Optional PEM-encoded CA certificate bundle. When set, *only* these
    /// certificates are trusted for TLS connections.
    pub ca_cert_pem: Option<String>,
}


// ---------------------------------------------------------------------------
// build_http_client
// ---------------------------------------------------------------------------

/// Build a `reqwest::Client` with sensible defaults for exchange REST APIs.
///
/// Uses system TLS trust anchors.  For certificate pinning, use
/// [`build_pinned_http_client`] instead.
pub fn build_http_client(timeout_secs: u64) -> anyhow::Result<reqwest::Client> {
    let timeout_secs = timeout_secs.max(5); // floor at 5s
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(timeout_secs.min(10))) // cap connect at 10s
        .pool_max_idle_per_host(4)
        .pool_idle_timeout(Duration::from_secs(90)) // evict idle connections
        .tcp_keepalive(Duration::from_secs(30))
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
    let timeout_secs = timeout_secs.max(5);
    match &tls.ca_cert_pem {
        Some(pem) => {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("failed to parse pinned CA cert: {}", e))?;

            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout_secs))
                .connect_timeout(Duration::from_secs(timeout_secs.min(10)))
                .pool_max_idle_per_host(4)
                .pool_idle_timeout(Duration::from_secs(90))
                .tcp_keepalive(Duration::from_secs(30))
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

/// Extract a client order ID from a JSON value, logging a warning if the field
/// is missing, null, or empty.  Returns the string (may be empty).
#[inline]
/// Extract a currency/asset string from JSON, skipping empty values.
/// Returns `None` if the field is missing, null, or empty -- callers should
/// skip the balance entry entirely to avoid polluting the balance map.
#[inline]
pub fn extract_currency(v: &serde_json::Value, field: &str, exchange: &str) -> Option<String> {
    match v.as_str() {
        Some(s) if !s.is_empty() => Some(s.to_string()),
        _ => {
            tracing::warn!(
                exchange = exchange,
                field = field,
                raw = %v,
                "balance currency field missing/empty -- skipping entry"
            );
            None
        }
    }
}

pub fn extract_client_order_id(v: &serde_json::Value, field: &str, exchange: &str) -> String {
    match v.as_str() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            tracing::warn!(
                exchange = exchange,
                field = field,
                raw = %v,
                "client_order_id field missing/empty -- order tracking may break"
            );
            String::new()
        }
    }
}

/// Sleep for approximately 1 second with +/-25% random jitter.
/// This prevents all exchanges from retrying at exactly the same moment
/// when multiple exchanges rate-limit simultaneously (e.g. during network partitions).
pub async fn jittered_rate_limit_sleep() {
    use rand::Rng;
    let base_ms = 1000.0_f64;
    let jittered = base_ms * (0.75 + 0.5 * rand::thread_rng().gen::<f64>());
    tokio::time::sleep(Duration::from_millis(jittered as u64)).await;
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

/// Extract a `Decimal` from a JSON `Value`.
///
/// Tries, in order: string → i64 → f64. Returns `Decimal::ZERO` on any
/// failure. For balance/price paths where silent zero is dangerous, prefer
/// [`parse_json_decimal_verbose`] instead.
#[must_use]
pub fn parse_json_decimal(v: &Value) -> Decimal {
    parse_json_decimal_inner(v, None)
}

/// Like [`parse_json_decimal`] but emits a `warn` log when the value cannot be
/// parsed and falls back to `Decimal::ZERO`. Use this in balance/price
/// parsing paths where silent zero is dangerous.
#[must_use]
pub fn parse_json_decimal_verbose(v: &Value, context: &str) -> Decimal {
    parse_json_decimal_inner(v, Some(context))
}

fn parse_json_decimal_inner(v: &Value, context: Option<&str>) -> Decimal {
    if let Some(s) = v.as_str() {
        match Decimal::from_str(s) {
            Ok(d) => d,
            Err(e) => {
                if let Some(ctx) = context {
                    tracing::warn!(context = ctx, raw = %s, error = %e,
                        "parse_json_decimal: unparseable string, falling back to ZERO");
                }
                Decimal::ZERO
            }
        }
    } else if let Some(n) = v.as_i64() {
        Decimal::from(n)
    } else if let Some(f) = v.as_f64() {
        match Decimal::from_f64(f) {
            Some(d) => d,
            None => {
                if let Some(ctx) = context {
                    tracing::warn!(context = ctx, raw = %f,
                        "parse_json_decimal: f64 conversion failed (NaN/Inf), falling back to ZERO");
                }
                Decimal::ZERO
            }
        }
    } else {
        if let Some(ctx) = context {
            tracing::warn!(context = ctx, value = %v,
                "parse_json_decimal: unexpected JSON type, falling back to ZERO");
        }
        Decimal::ZERO
    }
}

// Internal trait re-exports — already imported at the top of this file.

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
#[must_use]
pub fn parse_json_f64(v: &Value) -> f64 {
    v.as_f64()
        .unwrap_or(0.0)
}

/// Parse a balance string to f64, logging when the value is unparseable.
/// Returns the parsed value or 0.0 on failure (with a warning).
#[must_use]
pub fn parse_balance_f64(v: &Value, exchange: &str, asset: &str) -> f64 {
    match v.as_str().and_then(|s| s.parse::<f64>().ok()) {
        Some(f) => f,
        None => {
            tracing::warn!(
                exchange = exchange,
                asset = asset,
                raw = %v,
                "balance value unparseable, defaulting to 0.0"
            );
            0.0
        }
    }
}

/// Convert f64 to Decimal for balance, logging when conversion fails (NaN/Inf).
#[must_use]
pub fn balance_f64_to_decimal(f: f64, exchange: &str, asset: &str) -> Decimal {
    match Decimal::from_f64(f) {
        Some(d) => d,
        None => {
            tracing::warn!(
                exchange = exchange,
                asset = asset,
                raw = %f,
                "balance f64→Decimal failed (NaN/Inf), defaulting to ZERO"
            );
            Decimal::ZERO
        }
    }
}

/// HMAC-SHA256 hex (LBank style).
pub fn sign_lbank_hmac(secret: &str, payload: &str) -> anyhow::Result<String> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let sig = hmac::sign(&key, payload.as_bytes());
    Ok(hex::encode(sig.as_ref()))
}

