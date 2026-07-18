//! # signer — HFT Execution Engine Exchange Clients (Legacy)
//!
//! This module contains the original exchange client implementations used by
//! the high-frequency execution pipeline: [`PrivateApiSigner`],
//! [`BinanceClient`], [`BybitClient`], [`KucoinClient`], and the
//! [`PrivateExchangeClient`] trait.
//!
//! ## Relationship to `exchange/`
//!
//! The `exchange/` module tree provides a richer [`Exchange`](crate::exchange::Exchange)
//! trait with 12 exchange implementations, rate limiting, unified error types,
//! and built-in TLS pinning support.  It is the recommended framework for new
//! features and non-hot-path operations (balance queries, order-book fetching,
//! health checks, etc.).
//!
//! This `signer` module remains in active use by the HFT execution engine
//! (`execution::HighFrequencyExecutionEngine`) because its clients are
//! purpose-built for the low-latency order-submission hot path, with fewer
//! indirections and allocations.  Both frameworks coexist and share the same
//! underlying [`SecretString`] credential wrapper for memory safety.
//!
//! ## Migration Path
//!
//! For new exchange integrations, prefer adding them to the `exchange/` module.
//! Existing hot-path code in this module is production-hardened and should only
//! be migrated after careful latency benchmarking.

use async_trait::async_trait;
use chrono::Utc;
use hex;
use reqwest;
use ring::hmac;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use base64::Engine;
use crate::exchange::config::SecretString;
// SecretString already zeros memory on drop — API keys are safe from
// memory dumps after the signer goes out of scope.

// ---------------------------------------------------------------------------
// PrivateApiSigner
// ---------------------------------------------------------------------------

/// HMAC-SHA256 signer for private exchange API endpoints.
///
/// Holds API credentials wrapped in [`SecretString`] (memory zeroed on drop)
/// and produces signatures / auth headers for several exchanges
/// (Binance, Bybit, OKX, KuCoin).
#[derive(Clone)]
pub struct PrivateApiSigner {
    pub api_key: SecretString,
    pub api_secret: SecretString,
    pub passphrase: Option<SecretString>,
}

impl std::fmt::Debug for PrivateApiSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateApiSigner")
            .field("api_key", &self.api_key)
            .field("api_secret", &"[REDACTED]")
            .field("passphrase", &self.passphrase.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl PrivateApiSigner {
    /// Create a signer without a passphrase (Binance, Bybit, …).
    pub fn new(api_key: &str, api_secret: &str) -> Self {
        Self {
            api_key: SecretString::new(api_key),
            api_secret: SecretString::new(api_secret),
            passphrase: None,
        }
    }

    /// Create a signer with a passphrase (OKX, KuCoin, …).
    pub fn new_with_passphrase(api_key: &str, api_secret: &str, passphrase: &str) -> Self {
        Self {
            api_key: SecretString::new(api_key),
            api_secret: SecretString::new(api_secret),
            passphrase: Some(SecretString::new(passphrase)),
        }
    }

    /// Compute an HMAC-SHA256 of `payload` using `api_secret` as the key.
    ///
    /// Returns the 64-character lower-case hex-encoded signature.
    pub fn generate_hmac_signature(&self, payload: &str) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.api_secret.expose().as_bytes());
        let signature = hmac::sign(&key, payload.as_bytes());
        hex::encode(signature.as_ref())
    }

    /// Append `timestamp=epoch_millis` and `&signature=…` to `base_params`.
    ///
    /// # Example
    /// ```ignore
    /// // base_params = "symbol=BTCUSDT&side=BUY"
    /// // returns    "symbol=BTCUSDT&side=BUY&timestamp=1680000000000&signature=abc…"
    /// ```
    /// Convenience alias for `generate_hmac_signature` — used by execution pipeline.
    pub fn sign(&self, payload: &str) -> String {
        self.generate_hmac_signature(payload)
    }

    /// Return a reference to the API key (used for auth headers).
    pub fn api_key(&self) -> &str {
        self.api_key.expose()
    }

    pub fn generate_signed_query(&self, base_params: &str) -> String {
        let ts = epoch_millis();
        let query = if base_params.is_empty() {
            format!("timestamp={}", ts)
        } else {
            format!("{}&timestamp={}", base_params, ts)
        };
        let sig = self.generate_hmac_signature(&query);
        format!("{}&signature={}", query, sig)
    }

    /// Produce an OKX-style signature.
    ///
    /// OKX signs `timestamp + method + request_path + body` with HMAC-SHA256
    /// and then base64-encodes the result.
    pub fn generate_okx_signature(
        &self,
        timestamp: &str,
        method: &str,
        request_path: &str,
        body: &str,
    ) -> String {
        let preimage = format!("{}{}{}{}", timestamp, method, request_path, body);
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.api_secret.expose().as_bytes());
        let signature = hmac::sign(&key, preimage.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(signature.as_ref())
    }

    /// Return exchange-specific authorisation headers.
    ///
    /// Supported `exchange_type` values: `"binance"`, `"bybit"`, `"okx"`.
    /// For OKX the timestamp and a sample sign are computed here so that the
    /// caller can later recompute the real signature with the actual
    /// method / path / body when the request is built.
    pub fn get_auth_headers(&self, exchange_type: &str) -> Vec<(String, String)> {
        match exchange_type {
            "binance" => vec![("X-MBX-APIKEY".into(), self.api_key.expose().to_string())],

            "bybit" => vec![("X-BAPI-API-KEY".into(), self.api_key.expose().to_string())],

            "okx" => {
                let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
                // H-5 fix: DO NOT pre-compute the signature here.  The OKX
                // signature MUST be recomputed per-request with the actual
                // method, path, and body.  Returning an empty string forces
                // the caller to recompute it.
                let passphrase = self
                    .passphrase
                    .as_ref()
                    .map(|p| p.expose().to_string())
                    .unwrap_or_default();
                vec![
                    ("OK-ACCESS-KEY".into(), self.api_key.expose().to_string()),
                    // MUST be recomputed per-request
                    ("OK-ACCESS-SIGN".into(), String::new()),
                    ("OK-ACCESS-TIMESTAMP".into(), timestamp),
                    ("OK-ACCESS-PASSPHRASE".into(), passphrase),
                    ("Content-Type".into(), "application/json".into()),
                ]
            }

            _ => vec![],
        }
    }
}

/// Compute an HMAC-SHA256 signature and return the hex-encoded result.
/// Used by query_order methods that need inline signing.
pub fn hmac_signature(message: &str, secret: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let signature = hmac::sign(&key, message.as_bytes());
    hex::encode(signature.as_ref())
}

/// Return current UNIX epoch in milliseconds.
fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Order types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderSide {
    Buy,
    Sell,
}

impl std::fmt::Display for OrderSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OrderSide::Buy => write!(f, "BUY"),
            OrderSide::Sell => write!(f, "SELL"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderType {
    Limit,
    Market,
    Fok,
    IoC,
}

impl std::fmt::Display for OrderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OrderType::Limit => write!(f, "LIMIT"),
            OrderType::Market => write!(f, "MARKET"),
            OrderType::Fok => write!(f, "FOK"),
            OrderType::IoC => write!(f, "IOC"),
        }
    }
}

/// Convert our `OrderType` into the string expected by Bybit V5.
fn order_type_to_bybit(ot: OrderType) -> &'static str {
    match ot {
        OrderType::Limit => "Limit",
        OrderType::Market => "Market",
        OrderType::Fok => "FOK",
        OrderType::IoC => "IOC",
    }
}

// ---------------------------------------------------------------------------
// OrderRequest / OrderResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OrderRequest {
    pub symbol: String,
    pub side: OrderSide,
    pub order_type: OrderType,
    pub quantity: Decimal,
    pub price: Option<Decimal>,
    pub client_order_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OrderResult {
    pub success: bool,
    pub order_id: Option<String>,
    pub filled_qty: Decimal,
    pub avg_price: Decimal,
    pub error: Option<String>,
}

impl Default for OrderResult {
    fn default() -> Self {
        Self {
            success: false,
            order_id: None,
            filled_qty: Decimal::ZERO,
            avg_price: Decimal::ZERO,
            error: None,
        }
    }
}

// ---------------------------------------------------------------------------
// PrivateExchangeClient trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait PrivateExchangeClient: Send + Sync {
    /// Numeric identifier for this exchange instance (used by the arb engine).
    fn id(&self) -> u16;

    // M-1: The `http_client` passed to every method below MUST be configured
    // with explicit connect and request timeouts (e.g. connect 5s, request 10s).
    // A hung exchange without timeouts would block the execution thread
    // indefinitely.  The exchange/ module clients use `build_http_client()`
    // which sets timeouts automatically.  Legacy hot-path callers in main.rs
    // must construct their client with:
    //   reqwest::Client::builder()
    //       .connect_timeout(Duration::from_secs(5))
    //       .timeout(Duration::from_secs(10))
    //       .build()

    /// Submit an order and return the exchange's response.
    async fn submit_order(
        &self,
        http_client: &reqwest::Client,
        order: OrderRequest,
    ) -> Result<OrderResult, String>;

    /// Query the available balance of `asset` (e.g. `"USDT"`).
    async fn get_balance(
        &self,
        http_client: &reqwest::Client,
        asset: &str,
    ) -> Result<Decimal, String>;

    /// Cancel an open order on the exchange.
    /// Returns the current fill state, or Err if the cancellation request failed.
    async fn cancel_order(
        &self,
        http_client: &reqwest::Client,
        symbol: &str,
        order_id: &str,
    ) -> Result<OrderResult, String>;

    /// Query the status of an existing order by its ID.
    /// Returns the current fill state (filled_qty, avg_price, success status).
    async fn query_order(
        &self,
        http_client: &reqwest::Client,
        symbol: &str,
        order_id: &str,
    ) -> Result<OrderResult, String>;
}

// ---------------------------------------------------------------------------
// BinanceClient
// ---------------------------------------------------------------------------

pub struct BinanceClient {
    pub id: u16,
    pub api_key: SecretString,
    pub signer: PrivateApiSigner,
    pub rest_url: String,
}

impl std::fmt::Debug for BinanceClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinanceClient")
            .field("id", &self.id)
            .field("api_key", &self.api_key)
            .field("rest_url", &self.rest_url)
            .finish()
    }
}

impl BinanceClient {
    pub fn new(id: u16, api_key: &str, api_secret: &str, rest_url: &str) -> Self {
        Self {
            id,
            api_key: SecretString::new(api_key),
            signer: PrivateApiSigner::new(api_key, api_secret),
            rest_url: rest_url.to_owned(),
        }
    }
}

#[async_trait]
impl PrivateExchangeClient for BinanceClient {
    fn id(&self) -> u16 {
        self.id
    }


    async fn query_order(
        &self,
        http_client: &reqwest::Client,
        symbol: &str,
        order_id: &str,
    ) -> Result<OrderResult, String> {
        let mut params = std::collections::HashMap::new();
        params.insert("symbol", symbol.to_uppercase());
        params.insert("orderId", order_id.to_string());
        let base_params: String = params.iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>().join("&");
        let signed_query = self.signer.generate_signed_query(&base_params);
        let url = format!("{}/api/v3/order?{}", self.rest_url, signed_query);

        let resp = http_client.get(&url)
            .header("X-MBX-APIKEY", self.api_key.expose())
            .send().await
            .map_err(|e| format!("Binance query_order request failed: {}", e))?;
        let status = resp.status();
        let body = resp.text().await
            .map_err(|e| format!("Binance query_order read body failed: {}", e))?;

        if !status.is_success() {
            return Err(format!("Binance query_order HTTP {}: {}", status, body));
        }
        let v: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| format!("Binance query_order JSON parse failed: {}", e))?;

        let oid = v.get("orderId").and_then(|x| x.as_i64()).map(|id| id.to_string())
            .or_else(|| v.get("orderId").and_then(|x| x.as_str()).map(String::from));
        let filled = v.get("executedQty").or_else(|| v.get("filled"))
            .and_then(|x| x.as_str()).and_then(|s| s.parse::<Decimal>().ok()).unwrap_or(Decimal::ZERO);
        let avg = v.get("avgPrice").and_then(|x| x.as_str()).and_then(|s| s.parse::<Decimal>().ok())
            .unwrap_or(Decimal::ZERO);
        let status_str = v.get("status").and_then(|x| x.as_str()).unwrap_or("UNKNOWN");
        let success = status_str == "FILLED" || status_str == "PARTIALLY_FILLED";

        Ok(OrderResult { success, order_id: oid, filled_qty: filled, avg_price: avg, error: if success { None } else { Some(format!("unfilled: {}", status_str)) } })
    }

    async fn submit_order(
        &self,
        http_client: &reqwest::Client,
        order: OrderRequest,
    ) -> Result<OrderResult, String> {
        // Build Binance query parameters.
        let mut params = HashMap::new();
        params.insert("symbol", order.symbol.to_uppercase());
        params.insert("side", order.side.to_string());
        params.insert("type", order.order_type.to_string());
        params.insert("quantity", order.quantity.to_string());

        if let Some(price) = order.price {
            params.insert("price", price.to_string());
        }
        if let Some(ref client_id) = order.client_order_id {
            params.insert("newClientOrderId", client_id.clone());
        }
        if order.order_type == OrderType::Limit {
            params.insert("timeInForce", "GTC".to_string());
        }

        let base_params: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        let signed_query = self.signer.generate_signed_query(&base_params);

        let url = format!("{}/api/v3/order", self.rest_url);

        let response = http_client
            .post(&url)
            .header("X-MBX-APIKEY", self.api_key.expose())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(signed_query)
            .send()
            .await
            .map_err(|e| format!("Binance submit_order request failed: {}", e))?;

        let status = response.status();
        let body: String = response
            .text()
            .await
            .map_err(|e| format!("Binance submit_order read body failed: {}", e))?;

        let json_val: Value = serde_json::from_str(&body)
            .map_err(|e| format!("Binance submit_order JSON parse failed: {}", e))?;

        if status.is_success() {
            let order_id = json_val
                .get("orderId")
                .and_then(|v| v.as_i64())
                .map(|id| id.to_string())
                .or_else(|| json_val.get("orderId").and_then(|v| v.as_str()).map(String::from));

            let filled_qty = json_val
                .get("filled")
                .or_else(|| json_val.get("executedQty"))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Decimal>().ok())
                .unwrap_or(Decimal::ZERO);

            let avg_price = json_val
                .get("avgPrice")
                .or_else(|| json_val.get("fills"))
                .and_then(|fills| fills.as_array())
                .and_then(|arr| {
                    let total_qty: Decimal = arr
                        .iter()
                        .filter_map(|f| f.get("qty").and_then(|v| v.as_str()))
                        .filter_map(|s| s.parse::<Decimal>().ok())
                        .sum();
                    let total_cost: Decimal = arr
                        .iter()
                        .filter_map(|f| {
                            let qty = f
                                .get("qty")
                                .and_then(|v| v.as_str())
                                .and_then(|s| s.parse::<Decimal>().ok())?;
                            let price = f
                                .get("price")
                                .and_then(|v| v.as_str())
                                .and_then(|s| s.parse::<Decimal>().ok())?;
                            Some(qty * price)
                        })
                        .sum();
                    if total_qty > Decimal::ZERO {
                        Some(total_cost / total_qty)
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    json_val
                        .get("price")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<Decimal>().ok())
                })
                .unwrap_or(Decimal::ZERO);

            Ok(OrderResult {
                success: true,
                order_id,
                filled_qty,
                avg_price,
                error: None,
            })
        } else {
            let error_msg = json_val
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or(&body)
                .to_string();
            Ok(OrderResult {
                success: false,
                order_id: None,
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: Some(error_msg),
            })
        }
    }

    async fn get_balance(
        &self,
        http_client: &reqwest::Client,
        asset: &str,
    ) -> Result<Decimal, String> {
        let signed_query = self.signer.generate_signed_query("");
        let url = format!("{}/api/v3/account?{}", self.rest_url, signed_query);

        let response = http_client
            .get(&url)
            .header("X-MBX-APIKEY", self.api_key.expose())
            .send()
            .await
            .map_err(|e| format!("Binance get_balance request failed: {}", e))?;

        let status = response.status();
        let body: String = response
            .text()
            .await
            .map_err(|e| format!("Binance get_balance read body failed: {}", e))?;

        if !status.is_success() {
            return Err(format!("Binance get_balance HTTP {}: {}", status, body));
        }

        let json_val: Value = serde_json::from_str(&body)
            .map_err(|e| format!("Binance get_balance JSON parse failed: {}", e))?;

        let balances = json_val
            .get("balances")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "Binance get_balance: missing 'balances' array".to_string())?;

        for entry in balances {
            let a = entry.get("asset").and_then(|v| v.as_str()).unwrap_or("");
            if a.eq_ignore_ascii_case(asset) {
                let free = entry
                    .get("free")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<Decimal>().ok())
                    .unwrap_or(Decimal::ZERO);
                let locked = entry
                    .get("locked")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<Decimal>().ok())
                    .unwrap_or(Decimal::ZERO);
                return Ok(free + locked);
            }
        }

        Err(format!(
            "Binance get_balance: asset '{}' not found in account",
            asset
        ))
    }

    async fn cancel_order(
        &self,
        http_client: &reqwest::Client,
        symbol: &str,
        order_id: &str,
    ) -> Result<OrderResult, String> {
        let base_params = format!(
            "symbol={}&orderId={}",
            symbol.to_uppercase(),
            order_id
        );
        let signed_query = self.signer.generate_signed_query(&base_params);

        // Step 1: Query the order status to decide whether cancellation is needed.
        let query_url = format!("{}/api/v3/order?{}", self.rest_url, signed_query);
        let query_resp = http_client
            .get(&query_url)
            .header("X-MBX-APIKEY", self.api_key.expose())
            .send()
            .await
            .map_err(|e| format!("Binance cancel_order query request failed: {}", e))?;

        let query_status = query_resp.status();
        let query_body: String = query_resp
            .text()
            .await
            .map_err(|e| format!("Binance cancel_order query read body failed: {}", e))?;

        if !query_status.is_success() {
            return Err(format!(
                "Binance cancel_order query HTTP {}: {}",
                query_status, query_body
            ));
        }

        let query_json: Value = serde_json::from_str(&query_body)
            .map_err(|e| format!("Binance cancel_order query JSON parse failed: {}", e))?;

        let status_str = query_json
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // If already terminal, return the current fill state without cancelling.
        if status_str == "FILLED" || status_str == "CANCELED" || status_str == "EXPIRED" || status_str == "REJECTED" {
            let filled_qty = query_json
                .get("executedQty")
                .or_else(|| query_json.get("filled"))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Decimal>().ok())
                .unwrap_or(Decimal::ZERO);
            let avg_price = query_json
                .get("avgPrice")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Decimal>().ok())
                .unwrap_or(Decimal::ZERO);
            return Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty,
                avg_price,
                error: None,
            });
        }

        // Order is NEW or PARTIALLY_FILLED — proceed with cancellation.
        // Re-sign for the DELETE request (timestamp must be fresh).
        let signed_query_delete = self.signer.generate_signed_query(&base_params);
        let delete_url = format!("{}/api/v3/order?{}", self.rest_url, signed_query_delete);

        let delete_resp = http_client
            .delete(&delete_url)
            .header("X-MBX-APIKEY", self.api_key.expose())
            .send()
            .await
            .map_err(|e| format!("Binance cancel_order delete request failed: {}", e))?;

        let delete_status = delete_resp.status();
        let delete_body: String = delete_resp
            .text()
            .await
            .map_err(|e| format!("Binance cancel_order delete read body failed: {}", e))?;

        let delete_json: Value = serde_json::from_str(&delete_body)
            .map_err(|e| format!("Binance cancel_order delete JSON parse failed: {}", e))?;

        if delete_status.is_success() {
            let filled_qty = delete_json
                .get("executedQty")
                .or_else(|| delete_json.get("filled"))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Decimal>().ok())
                .unwrap_or(Decimal::ZERO);
            let avg_price = delete_json
                .get("avgPrice")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Decimal>().ok())
                .unwrap_or(Decimal::ZERO);
            Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty,
                avg_price,
                error: None,
            })
        } else {
            let error_msg = delete_json
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or(&delete_body)
                .to_string();
            Err(format!("Binance cancel_order failed: {}", error_msg))
        }
    }
}

// ---------------------------------------------------------------------------
// BybitClient
// ---------------------------------------------------------------------------

pub struct BybitClient {
    pub id: u16,
    pub api_key: SecretString,
    pub signer: PrivateApiSigner,
    pub rest_url: String,
}

impl std::fmt::Debug for BybitClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BybitClient")
            .field("id", &self.id)
            .field("api_key", &self.api_key)
            .field("rest_url", &self.rest_url)
            .finish()
    }
}

impl BybitClient {
    pub fn new(id: u16, api_key: &str, api_secret: &str, rest_url: &str) -> Self {
        Self {
            id,
            api_key: SecretString::new(api_key),
            signer: PrivateApiSigner::new(api_key, api_secret),
            rest_url: rest_url.to_owned(),
        }
    }
}

#[async_trait]
impl PrivateExchangeClient for BybitClient {
    fn id(&self) -> u16 {
        self.id
    }


    async fn query_order(
        &self,
        http_client: &reqwest::Client,
        _symbol: &str,
        order_id: &str,
    ) -> Result<OrderResult, String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
        let pre_sign = format!("{}{}{}", timestamp, self.api_key.expose(), self.signer.api_secret.expose());
        let signature = crate::signer::hmac_signature(&pre_sign, self.signer.api_secret.expose());
        let url = format!("{}/v5/order/realtime?orderId={}", self.rest_url, order_id);

        let resp = http_client.get(&url)
            .header("X-BAPI-API-KEY", self.api_key.expose())
            .header("X-BAPI-TIMESTAMP", timestamp.to_string())
            .header("X-BAPI-SIGN", signature)
            .send().await
            .map_err(|e| format!("Bybit query_order request failed: {}", e))?;
        let status = resp.status();
        let body = resp.text().await
            .map_err(|e| format!("Bybit query_order read body failed: {}", e))?;

        if !status.is_success() {
            return Err(format!("Bybit query_order HTTP {}: {}", status, body));
        }
        let v: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| format!("Bybit query_order JSON parse failed: {}", e))?;

        let order = v.get("result").and_then(|x| x.get("list")).and_then(|x| x.as_array()).and_then(|a| a.first());
        match order {
            Some(o) => {
                let filled = o.get("cumExecQty").and_then(|x| x.as_str()).and_then(|s| s.parse::<Decimal>().ok()).unwrap_or(Decimal::ZERO);
                let avg = o.get("avgPrice").and_then(|x| x.as_str()).and_then(|s| s.parse::<Decimal>().ok()).unwrap_or(Decimal::ZERO);
                let st = o.get("orderStatus").and_then(|x| x.as_str()).unwrap_or("UNKNOWN");
                let success = st == "Filled" || st == "PartiallyFilled";
                Ok(OrderResult { success, order_id: Some(order_id.to_string()), filled_qty: filled, avg_price: avg, error: if success { None } else { Some(format!("unfilled: {}", st)) } })
            }
            None => Ok(OrderResult { success: false, order_id: Some(order_id.to_string()), filled_qty: Decimal::ZERO, avg_price: Decimal::ZERO, error: Some("order not found".to_string()) }),
        }
    }

    async fn submit_order(
        &self,
        http_client: &reqwest::Client,
        order: OrderRequest,
    ) -> Result<OrderResult, String> {
        let mut body_map = serde_json::Map::new();
        body_map.insert("category".into(), json!("spot"));
        body_map.insert("symbol".into(), json!(order.symbol.to_uppercase()));
        body_map.insert("side".into(), json!(order.side.to_string()));
        body_map.insert("orderType".into(), json!(order_type_to_bybit(order.order_type)));
        body_map.insert("qty".into(), json!(order.quantity.to_string()));

        if let Some(price) = order.price {
            body_map.insert("price".into(), json!(price.to_string()));
        }
        if let Some(ref client_id) = order.client_order_id {
            body_map.insert("orderLinkId".into(), json!(client_id.clone()));
        }

        let timestamp = epoch_millis().to_string();
        let recv_window = "5000".to_string();
        let pre_sign = timestamp.clone() + self.api_key.expose() + &recv_window + &json!(body_map).to_string();
        let sign = self.signer.generate_hmac_signature(&pre_sign);

        let url = format!("{}/v5/order/create", self.rest_url);
        let body_json = json!(body_map).to_string();

        let response = http_client
            .post(&url)
            .header("X-BAPI-API-KEY", self.api_key.expose())
            .header("X-BAPI-SIGN", &sign)
            .header("X-BAPI-TIMESTAMP", &timestamp)
            .header("X-BAPI-RECV-WINDOW", &recv_window)
            .header("Content-Type", "application/json")
            .body(body_json)
            .send()
            .await
            .map_err(|e| format!("Bybit submit_order request failed: {}", e))?;

        let _status = response.status();
        let body: String = response
            .text()
            .await
            .map_err(|e| format!("Bybit submit_order read body failed: {}", e))?;

        let json_val: Value = serde_json::from_str(&body)
            .map_err(|e| format!("Bybit submit_order JSON parse failed: {}", e))?;

        // Bybit V5 always returns HTTP 200; errors are in retCode.
        let ret_code = json_val
            .get("retCode")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);

        if ret_code == 0 {
            let result = json_val.get("result");
            let order_id = result
                .and_then(|r| r.get("orderId"))
                .and_then(|v| v.as_str())
                .map(String::from);

            let filled_qty = result
                .and_then(|r| r.get("cumExecQty"))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Decimal>().ok())
                .unwrap_or(Decimal::ZERO);

            let avg_price = result
                .and_then(|r| r.get("avgPrice"))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Decimal>().ok())
                .unwrap_or(Decimal::ZERO);

            Ok(OrderResult {
                success: true,
                order_id,
                filled_qty,
                avg_price,
                error: None,
            })
        } else {
            let ret_msg = json_val
                .get("retMsg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown Bybit error")
                .to_string();
            Ok(OrderResult {
                success: false,
                order_id: None,
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: Some(ret_msg),
            })
        }
    }

    async fn get_balance(
        &self,
        http_client: &reqwest::Client,
        asset: &str,
    ) -> Result<Decimal, String> {
        let mut body_map = serde_json::Map::new();
        body_map.insert("accountType".into(), json!("UNIFIED"));

        let timestamp = epoch_millis().to_string();
        let recv_window = "5000".to_string();
        let param_str = json!(body_map).to_string();
        let pre_sign = timestamp.clone() + self.api_key.expose() + &recv_window + &param_str;
        let sign = self.signer.generate_hmac_signature(&pre_sign);

        let url = format!(
            "{}/v5/account/wallet-balance?accountType=UNIFIED",
            self.rest_url
        );

        let response = http_client
            .get(&url)
            .header("X-BAPI-API-KEY", self.api_key.expose())
            .header("X-BAPI-SIGN", &sign)
            .header("X-BAPI-TIMESTAMP", &timestamp)
            .header("X-BAPI-RECV-WINDOW", &recv_window)
            .send()
            .await
            .map_err(|e| format!("Bybit get_balance request failed: {}", e))?;

        let status = response.status();
        let body: String = response
            .text()
            .await
            .map_err(|e| format!("Bybit get_balance read body failed: {}", e))?;

        if !status.is_success() {
            return Err(format!("Bybit get_balance HTTP {}: {}", status, body));
        }

        let json_val: Value = serde_json::from_str(&body)
            .map_err(|e| format!("Bybit get_balance JSON parse failed: {}", e))?;

        let ret_code = json_val
            .get("retCode")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);

        if ret_code != 0 {
            let ret_msg = json_val
                .get("retMsg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(format!("Bybit get_balance error (retCode={}): {}", ret_code, ret_msg));
        }

        let coins = json_val
            .pointer("/result/list/0/coin")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "Bybit get_balance: cannot locate coin list".to_string())?;

        for coin in coins {
            let coin_name = coin
                .get("coin")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if coin_name.eq_ignore_ascii_case(asset) {
                let wallet_bal = coin
                    .get("walletBalance")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<Decimal>().ok())
                    .unwrap_or(Decimal::ZERO);
                return Ok(wallet_bal);
            }
        }

        Err(format!(
            "Bybit get_balance: asset '{}' not found",
            asset
        ))
    }

    async fn cancel_order(
        &self,
        http_client: &reqwest::Client,
        symbol: &str,
        order_id: &str,
    ) -> Result<OrderResult, String> {
        let mut body_map = serde_json::Map::new();
        body_map.insert("category".into(), json!("spot"));
        body_map.insert("symbol".into(), json!(symbol.to_uppercase()));
        body_map.insert("orderId".into(), json!(order_id));

        let timestamp = epoch_millis().to_string();
        let recv_window = "5000".to_string();
        let body_str = json!(body_map).to_string();
        let pre_sign = timestamp.clone() + self.api_key.expose() + &recv_window + &body_str;
        let sign = self.signer.generate_hmac_signature(&pre_sign);

        let url = format!("{}/v5/order/cancel", self.rest_url);

        let response = http_client
            .post(&url)
            .header("X-BAPI-API-KEY", self.api_key.expose())
            .header("X-BAPI-SIGN", &sign)
            .header("X-BAPI-TIMESTAMP", &timestamp)
            .header("X-BAPI-RECV-WINDOW", &recv_window)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await
            .map_err(|e| format!("Bybit cancel_order request failed: {}", e))?;

        let body: String = response
            .text()
            .await
            .map_err(|e| format!("Bybit cancel_order read body failed: {}", e))?;

        let json_val: Value = serde_json::from_str(&body)
            .map_err(|e| format!("Bybit cancel_order JSON parse failed: {}", e))?;

        let ret_code = json_val
            .get("retCode")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);

        if ret_code == 0 {
            // Bybit cancel response does not include fill info; return zeros.
            Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: None,
            })
        } else {
            let ret_msg = json_val
                .get("retMsg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown Bybit cancel error")
                .to_string();
            Err(format!("Bybit cancel_order failed (retCode={}): {}", ret_code, ret_msg))
        }
    }
}

// ---------------------------------------------------------------------------
// KucoinClient
// ---------------------------------------------------------------------------

pub struct KucoinClient {
    pub id: u16,
    pub api_key: SecretString,
    pub signer: PrivateApiSigner,
    pub rest_url: String,
}

impl std::fmt::Debug for KucoinClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KucoinClient")
            .field("id", &self.id)
            .field("api_key", &self.api_key)
            .field("rest_url", &self.rest_url)
            .finish()
    }
}

impl KucoinClient {
    pub fn new(
        id: u16,
        api_key: &str,
        api_secret: &str,
        passphrase: &str,
        rest_url: &str,
    ) -> Self {
        Self {
            id,
            api_key: SecretString::new(api_key),
            signer: PrivateApiSigner::new_with_passphrase(api_key, api_secret, passphrase),
            rest_url: rest_url.to_owned(),
        }
    }

    /// Build the KC-SIGN, KC-TIMESTAMP, KC-PASSPHRASE headers that KuCoin
    /// requires for every authenticated request.
    fn kc_auth_headers(
        &self,
        method: &str,
        path: &str,
        body: &str,
    ) -> Vec<(String, String)> {
        let timestamp = epoch_millis().to_string();
        // KuCoin signature preimage: timestamp + method + path + body
        let preimage = format!("{}{}{}{}", timestamp, method, path, body);
        let signature = self.signer.generate_hmac_signature(&preimage);
        // KuCoin passphrase is also signed with HMAC-SHA256 and then base64'd.
        let passphrase_sign = {
            let key = hmac::Key::new(
                hmac::HMAC_SHA256,
                self.signer.api_secret.expose().as_bytes(),
            );
            let sig = hmac::sign(&key, self.signer.passphrase.as_ref().map(|p| p.expose().as_bytes()).unwrap_or(b""));
            base64::engine::general_purpose::STANDARD.encode(sig.as_ref())
        };
        vec![
            ("KC-API-KEY".into(), self.api_key.expose().to_string()),
            ("KC-API-SIGN".into(), signature),
            ("KC-API-TIMESTAMP".into(), timestamp),
            ("KC-API-PASSPHRASE".into(), passphrase_sign),
            ("KC-API-KEY-VERSION".into(), "2".into()),
            ("Content-Type".into(), "application/json".into()),
        ]
    }
}

#[async_trait]
impl PrivateExchangeClient for KucoinClient {
    fn id(&self) -> u16 {
        self.id
    }


    async fn query_order(
        &self,
        http_client: &reqwest::Client,
        _symbol: &str,
        order_id: &str,
    ) -> Result<OrderResult, String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0).to_string();
        let passphrase_str = self.signer.passphrase.as_ref().map(|p| p.expose()).unwrap_or("");
        let passphrase_sign = {
            let key = hmac::Key::new(hmac::HMAC_SHA256, self.signer.api_secret.expose().as_bytes());
            let sig = hmac::sign(&key, passphrase_str.as_bytes());
            base64::engine::general_purpose::STANDARD.encode(sig.as_ref())
        };
        let query_str = format!("{}{}{}", timestamp, "GET", "/api/v1/orders/".to_string() + order_id);
        let signature = base64::engine::general_purpose::STANDARD.encode(
            ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, self.signer.api_secret.expose().as_bytes()), query_str.as_bytes()).as_ref()
        );
        let url = format!("{}/api/v1/orders/{}", self.rest_url, order_id);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("KC-API-KEY", reqwest::header::HeaderValue::from_str(self.api_key.expose()).unwrap_or_else(|_| reqwest::header::HeaderValue::from_static("")));
        headers.insert("KC-API-SIGN", reqwest::header::HeaderValue::from_str(&signature).unwrap_or_else(|_| reqwest::header::HeaderValue::from_static("")));
        headers.insert("KC-API-TIMESTAMP", reqwest::header::HeaderValue::from_str(&timestamp).unwrap_or_else(|_| reqwest::header::HeaderValue::from_static("")));
        headers.insert("KC-API-PASSPHRASE", reqwest::header::HeaderValue::from_str(&passphrase_sign).unwrap_or_else(|_| reqwest::header::HeaderValue::from_static("")));
        headers.insert("KC-API-KEY-VERSION", reqwest::header::HeaderValue::from_static("2"));

        let resp = http_client.get(&url).headers(headers)
            .send().await
            .map_err(|e| format!("KuCoin query_order request failed: {}", e))?;
        let status = resp.status();
        let body = resp.text().await
            .map_err(|e| format!("KuCoin query_order read body failed: {}", e))?;

        if !status.is_success() {
            return Err(format!("KuCoin query_order HTTP {}: {}", status, body));
        }
        let v: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| format!("KuCoin query_order JSON parse failed: {}", e))?;
        let data = match v.get("data") {
            Some(d) => d,
            None => return Ok(OrderResult { success: false, order_id: Some(order_id.to_string()), filled_qty: Decimal::ZERO, avg_price: Decimal::ZERO, error: Some("order not found".to_string()) }),
        };

        let filled = data.get("dealSize").and_then(|x| x.as_str()).and_then(|s| s.parse::<Decimal>().ok()).unwrap_or(Decimal::ZERO);
        let avg = data.get("dealFunds").and_then(|x| x.as_str()).and_then(|s| s.parse::<Decimal>().ok())
            .and_then(|funds| if filled > Decimal::ZERO { Some(funds / filled) } else { None }).unwrap_or(Decimal::ZERO);
        let is_active = data.get("isActive").and_then(|x| x.as_bool()).unwrap_or(true);
        let success = !is_active && filled > Decimal::ZERO;

        Ok(OrderResult { success, order_id: Some(order_id.to_string()), filled_qty: filled, avg_price: avg, error: if success { None } else { Some(format!("unfilled isActive={}", is_active)) } })
    }

    async fn submit_order(
        &self,
        http_client: &reqwest::Client,
        order: OrderRequest,
    ) -> Result<OrderResult, String> {
        let side_str = match order.side {
            OrderSide::Buy => "buy",
            OrderSide::Sell => "sell",
        };
        let type_str = match order.order_type {
            OrderType::Limit => "limit",
            OrderType::Market => "market",
            OrderType::Fok => "limit",
            OrderType::IoC => "limit",
        };

        let mut body_map = serde_json::Map::new();
        body_map.insert("clientOid".into(), json!(order.client_order_id.as_deref().unwrap_or("hft-oid")));
        body_map.insert("side".into(), json!(side_str));
        body_map.insert("symbol".into(), json!(order.symbol.to_uppercase()));
        body_map.insert("type".into(), json!(type_str));
        body_map.insert("size".into(), json!(order.quantity.to_string()));

        if let Some(price) = order.price {
            body_map.insert("price".into(), json!(price.to_string()));
        }

        let path = "/api/v1/orders";
        let body_str = json!(body_map).to_string();
        let headers = self.kc_auth_headers("POST", path, &body_str);

        let url = format!("{}{}", self.rest_url, path);

        let mut request = http_client
            .post(&url)
            .body(body_str.clone());
        for (k, v) in &headers {
            request = request.header(k.as_str(), v.as_str());
        }

        let response = request
            .send()
            .await
            .map_err(|e| format!("Kucoin submit_order request failed: {}", e))?;

        let status = response.status();
        let body: String = response
            .text()
            .await
            .map_err(|e| format!("Kucoin submit_order read body failed: {}", e))?;

        let json_val: Value = serde_json::from_str(&body)
            .map_err(|e| format!("Kucoin submit_order JSON parse failed: {}", e))?;

        if status.is_success() {
            let order_id = json_val
                .get("data")
                .and_then(|d| d.get("orderId"))
                .and_then(|v| v.as_str())
                .map(String::from);

            Ok(OrderResult {
                success: true,
                order_id,
                filled_qty: Decimal::ZERO, // KuCoin async – not immediately known
                avg_price: Decimal::ZERO,
                error: None,
            })
        } else {
            let err_msg = json_val
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or(&body)
                .to_string();
            Ok(OrderResult {
                success: false,
                order_id: None,
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: Some(err_msg),
            })
        }
    }

    async fn get_balance(
        &self,
        http_client: &reqwest::Client,
        asset: &str,
    ) -> Result<Decimal, String> {
        let path = format!("/api/v1/accounts?currency={}", asset.to_uppercase());
        let headers = self.kc_auth_headers("GET", &path, "");

        let url = format!("{}{}", self.rest_url, path);

        let mut request = http_client.get(&url);
        for (k, v) in &headers {
            request = request.header(k.as_str(), v.as_str());
        }

        let response = request
            .send()
            .await
            .map_err(|e| format!("Kucoin get_balance request failed: {}", e))?;

        let status = response.status();
        let body: String = response
            .text()
            .await
            .map_err(|e| format!("Kucoin get_balance read body failed: {}", e))?;

        if !status.is_success() {
            return Err(format!("Kucoin get_balance HTTP {}: {}", status, body));
        }

        let json_val: Value = serde_json::from_str(&body)
            .map_err(|e| format!("Kucoin get_balance JSON parse failed: {}", e))?;

        let accounts = json_val
            .get("data")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "Kucoin get_balance: missing data array".to_string())?;

        let mut total = Decimal::ZERO;
        for acct in accounts {
            let currency = acct
                .get("currency")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if currency.eq_ignore_ascii_case(asset) {
                let balance = acct
                    .get("balance")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<Decimal>().ok())
                    .unwrap_or(Decimal::ZERO);
                total += balance;
            }
        }

        if total > Decimal::ZERO {
            Ok(total)
        } else {
            Err(format!(
                "Kucoin get_balance: asset '{}' not found or zero",
                asset
            ))
        }
    }

    async fn cancel_order(
        &self,
        http_client: &reqwest::Client,
        _symbol: &str,
        order_id: &str,
    ) -> Result<OrderResult, String> {
        let path = format!("/api/v1/orders/{}", order_id);
        let headers = self.kc_auth_headers("DELETE", &path, "");

        let url = format!("{}{}", self.rest_url, path);

        let mut request = http_client.delete(&url);
        for (k, v) in &headers {
            request = request.header(k.as_str(), v.as_str());
        }

        let response = request
            .send()
            .await
            .map_err(|e| format!("Kucoin cancel_order request failed: {}", e))?;

        let status = response.status();
        let body: String = response
            .text()
            .await
            .map_err(|e| format!("Kucoin cancel_order read body failed: {}", e))?;

        if !status.is_success() {
            return Err(format!("Kucoin cancel_order HTTP {}: {}", status, body));
        }

        let json_val: Value = serde_json::from_str(&body)
            .map_err(|e| format!("Kucoin cancel_order JSON parse failed: {}", e))?;

        // KuCoin cancel response: {"data": {"orderId": "xxx"}}
        // No fill info is returned; caller should query separately if needed.
        let returned_id = json_val
            .pointer("/data/orderId")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| order_id.to_string());

        Ok(OrderResult {
            success: true,
            order_id: Some(returned_id),
            filled_qty: Decimal::ZERO,
            avg_price: Decimal::ZERO,
            error: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_signature_generation() {
        let signer = PrivateApiSigner::new("test-key", "test-secret");
        let sig1 = signer.generate_hmac_signature("hello");
        let sig2 = signer.generate_hmac_signature("hello");
        // Deterministic: same input ⇒ same output.
        assert_eq!(sig1, sig2);
        // HMAC-SHA256 ⇒ 32 bytes ⇒ 64 hex chars.
        assert_eq!(sig1.len(), 64);
    }

    #[test]
    fn test_signed_query_contains_params() {
        let signer = PrivateApiSigner::new("key", "secret");
        let signed = signer.generate_signed_query("symbol=BTCUSDT&side=BUY");
        // Must still contain the original params.
        assert!(signed.contains("symbol=BTCUSDT"), "missing symbol param");
        assert!(signed.contains("side=BUY"), "missing side param");
        // Must contain timestamp and signature keys.
        assert!(signed.contains("timestamp="), "missing timestamp");
        assert!(signed.contains("&signature="), "missing signature");
    }

    #[test]
    fn test_okx_signature() {
        let signer =
            PrivateApiSigner::new_with_passphrase("my-key", "my-secret", "mypassphrase");
        let headers = signer.get_auth_headers("okx");

        let header_map: HashMap<String, String> = headers.into_iter().collect();

        // Verify that all four OKX headers are present.
        assert!(
            header_map.contains_key("OK-ACCESS-KEY"),
            "missing OK-ACCESS-KEY"
        );
        assert!(
            header_map.contains_key("OK-ACCESS-SIGN"),
            "missing OK-ACCESS-SIGN"
        );
        assert!(
            header_map.contains_key("OK-ACCESS-TIMESTAMP"),
            "missing OK-ACCESS-TIMESTAMP"
        );
        assert!(
            header_map.contains_key("OK-ACCESS-PASSPHRASE"),
            "missing OK-ACCESS-PASSPHRASE"
        );

        // Verify key and passphrase values.
        assert_eq!(header_map["OK-ACCESS-KEY"], "my-key");
        assert_eq!(header_map["OK-ACCESS-PASSPHRASE"], "mypassphrase");

        // The sign should be non-empty (base64 string).
        let sign = &header_map["OK-ACCESS-SIGN"];
        assert!(!sign.is_empty(), "OK-ACCESS-SIGN should not be empty");
    }
}