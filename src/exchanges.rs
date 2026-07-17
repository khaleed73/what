//! Lightweight `PrivateExchangeClient` constructors used by the HFT execution
//! engine.
//!
//! This module provides convenience wrappers around the detailed
//! `signer::PrivateExchangeClient` implementations (Binance, Bybit, KuCoin) and
//! full new implementations for OKX and Gate.io, plus a `PaperExchangeClient`
//! for simulated fills with deterministic LCG-based slippage.
//!
//! # Credential Security
//!
//! All API keys and secrets are wrapped in [`SecretString`] (memory zeroed on
//! drop via the `secrecy` crate).  OKX additionally stores the base64-decoded
//! secret bytes in a [`SecretBytes`] wrapper that zeroes on drop.

use async_trait::async_trait;
use reqwest;
use rust_decimal::Decimal;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::exchange::config::SecretString;
use crate::signer::{
    OrderRequest, OrderResult, OrderSide, PrivateExchangeClient,
};

// ---------------------------------------------------------------------------
// SecretBytes — zero-on-drop byte buffer for sensitive key material
// ---------------------------------------------------------------------------

/// A byte buffer whose contents are overwritten with zeroes when dropped.
/// Used by the OKX client to hold the base64-decoded API secret.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Zeroise the key material before deallocating.
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
        // Don't need to shrink — Vec will deallocate the zeroed buffer.
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([REDACTED]; {} bytes)", self.0.len())
    }
}

// ---------------------------------------------------------------------------
// binance — wrapper around signer::BinanceClient
// ---------------------------------------------------------------------------

pub mod binance {
    use crate::signer::BinanceClient;

    const DEFAULT_REST_URL: &str = "https://api.binance.com";

    pub fn new(api_key: &str, api_secret: &str) -> Result<BinanceClient, String> {
        Ok(BinanceClient::new(
            0,
            api_key,
            api_secret,
            DEFAULT_REST_URL,
        ))
    }
}

// ---------------------------------------------------------------------------
// bybit — wrapper around signer::BybitClient
// ---------------------------------------------------------------------------

pub mod bybit {
    use crate::signer::BybitClient;

    const DEFAULT_REST_URL: &str = "https://api.bybit.com";

    pub fn new(api_key: &str, api_secret: &str) -> Result<BybitClient, String> {
        Ok(BybitClient::new(
            1,
            api_key,
            api_secret,
            DEFAULT_REST_URL,
        ))
    }
}

// ---------------------------------------------------------------------------
// kucoin — wrapper around signer::KucoinClient
// ---------------------------------------------------------------------------

pub mod kucoin {
    use crate::signer::KucoinClient;

    const DEFAULT_REST_URL: &str = "https://api.kucoin.com";

    pub fn new(
        api_key: &str,
        api_secret: &str,
        passphrase: &str,
    ) -> Result<KucoinClient, String> {
        Ok(KucoinClient::new(
            4,
            api_key,
            api_secret,
            passphrase,
            DEFAULT_REST_URL,
        ))
    }
}

// ---------------------------------------------------------------------------
// okx — full OKX V5 implementation
// ---------------------------------------------------------------------------

pub mod okx {
    use async_trait::async_trait;
    use base64::Engine;
    use ring::hmac;
    use rust_decimal::Decimal;
    use serde_json::{json, Value};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::exchange::config::SecretString;
    use crate::exchanges::SecretBytes;
    use crate::signer::{
        OrderRequest, OrderResult, OrderSide, OrderType, PrivateExchangeClient,
    };

    const DEFAULT_REST_URL: &str = "https://www.okx.com";

    /// OKX V5 private client.
    ///
    /// Uses HMAC-SHA256 with a base64-decoded API secret and produces
    /// base64-encoded signatures.  The `api_secret` provided to [`OkxClient::new`]
    /// must be the raw base64 string that OKX issues.
    pub struct OkxClient {
        id: u16,
        api_key: SecretString,
        /// Base64-decoded secret bytes used as the HMAC key.
        /// Wrapped in [`SecretBytes`] which zeroes memory on drop.
        api_secret_bytes: SecretBytes,
        passphrase: SecretString,
        rest_url: String,
    }

    impl std::fmt::Debug for OkxClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("OkxClient")
                .field("id", &self.id)
                .field("api_key", &self.api_key)
                .field("api_secret_bytes", &self.api_secret_bytes)
                .field("rest_url", &self.rest_url)
                .finish()
        }
    }

    impl OkxClient {
        /// Create a new OKX client.
        ///
        /// `api_secret` is expected in the base64-encoded form issued by OKX.
        /// It is decoded once at construction time and stored as raw bytes
        /// wrapped in [`SecretBytes`] (zeroed on drop).
        pub fn new(
            api_key: &str,
            api_secret: &str,
            passphrase: &str,
        ) -> Result<Self, String> {
            let secret_bytes = base64::engine::general_purpose::STANDARD
                .decode(api_secret)
                .map_err(|e| {
                    format!("OKX: failed to base64-decode api_secret: {}", e)
                })?;
            Ok(Self {
                id: 2,
                api_key: SecretString::new(api_key),
                api_secret_bytes: SecretBytes::new(secret_bytes),
                passphrase: SecretString::new(passphrase),
                rest_url: DEFAULT_REST_URL.to_string(),
            })
        }

        /// Build an OKX V5 HMAC-SHA256 signature.
        ///
        /// Preimage: `timestamp || method || request_path || body`
        /// The secret is base64-decoded (done at construction); the result is
        /// base64-encoded.
        fn sign(
            &self,
            timestamp: &str,
            method: &str,
            request_path: &str,
            body: &str,
        ) -> String {
            let preimage =
                format!("{}{}{}{}", timestamp, method, request_path, body);
            let key = hmac::Key::new(hmac::HMAC_SHA256, self.api_secret_bytes.as_bytes());
            let signature = hmac::sign(&key, preimage.as_bytes());
            base64::engine::general_purpose::STANDARD.encode(signature.as_ref())
        }

        /// Current Unix epoch in milliseconds as a string.
        fn timestamp_millis() -> String {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_millis()
                .to_string()
        }
    }

    #[async_trait]
    impl PrivateExchangeClient for OkxClient {
        fn id(&self) -> u16 {
            self.id
        }


        async fn query_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let timestamp = Self::timestamp_millis();
            let sign = self.sign(&timestamp, "GET", &format!("/api/v5/trade/order?ordId={}", order_id), "");
            let url = format!("{}/api/v5/trade/order?ordId={}", self.rest_url, order_id);

            let resp = http_client.get(&url)
                .header("OK-ACCESS-KEY", self.api_key.expose())
                .header("OK-ACCESS-SIGN", sign)
                .header("OK-ACCESS-TIMESTAMP", timestamp.to_string())
                .header("OK-ACCESS-PASSPHRASE", self.passphrase.expose())
                .send().await
                .map_err(|e| format!("OKX query_order request failed: {}", e))?;
            let status = resp.status();
            let body = resp.text().await
                .map_err(|e| format!("OKX query_order read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("OKX query_order HTTP {}: {}", status, body));
            }
            let v: serde_json::Value = serde_json::from_str(&body)
                .map_err(|e| format!("OKX query_order JSON parse failed: {}", e))?;
            let data = match v.get("data").and_then(|x| x.as_array()).and_then(|a| a.first()) {
                Some(d) => d,
                None => return Ok(OrderResult { success: false, order_id: Some(order_id.to_string()), filled_qty: Decimal::ZERO, avg_price: Decimal::ZERO, error: Some("order not found".to_string()) }),
            };

            let filled = data.get("fillSz").and_then(|x| x.as_str()).and_then(|s| s.parse::<Decimal>().ok()).unwrap_or(Decimal::ZERO);
            let avg = data.get("avgPx").and_then(|x| x.as_str()).and_then(|s| s.parse::<Decimal>().ok()).unwrap_or(Decimal::ZERO);
            let state = data.get("state").and_then(|x| x.as_str()).unwrap_or("UNKNOWN");
            let success = state == "filled" || state == "partial_fill";

            Ok(OrderResult { success, order_id: Some(order_id.to_string()), filled_qty: filled, avg_price: avg, error: if success { None } else { Some(format!("unfilled: {}", state)) } })
        }

        async fn submit_order(
            &self,
            http_client: &reqwest::Client,
            order: OrderRequest,
        ) -> Result<OrderResult, String> {
            let timestamp = Self::timestamp_millis();
            let path = "/api/v5/trade/order";
            let method = "POST";

            let side_str = match order.side {
                OrderSide::Buy => "buy",
                OrderSide::Sell => "sell",
            };
            let ord_type = match order.order_type {
                OrderType::Market => "market",
                OrderType::Limit => "limit",
                OrderType::Fok => "fok",
                OrderType::IoC => "ioc",
            };

            let mut body = json!({
                "instId": order.symbol,
                "tdMode": "cash",
                "side": side_str,
                "ordType": ord_type,
                "sz": order.quantity.to_string(),
            });

            if let Some(price) = order.price {
                body["px"] = json!(price.to_string());
            }
            if let Some(ref cl_ord_id) = order.client_order_id {
                body["clOrdId"] = json!(cl_ord_id);
            }

            let body_str = body.to_string();
            let signature = self.sign(&timestamp, method, path, &body_str);

            let resp = http_client
                .post(format!("{}{}", self.rest_url, path))
                .header("OK-ACCESS-KEY", self.api_key.expose())
                .header("OK-ACCESS-SIGN", &signature)
                .header("OK-ACCESS-TIMESTAMP", &timestamp)
                .header("OK-ACCESS-PASSPHRASE", self.passphrase.expose())
                .header("Content-Type", "application/json")
                .body(body_str)
                .send()
                .await
                .map_err(|e| format!("OKX submit_order request failed: {}", e))?;

            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("OKX submit_order read body failed: {}", e))?;
            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("OKX submit_order JSON parse failed: {}", e))?;

            // OKX V5 returns {"code": "0", "data": [...]} on success.
            if json_val["code"] != "0" {
                let msg = json_val["msg"]
                    .as_str()
                    .unwrap_or("unknown OKX error")
                    .to_string();
                return Ok(OrderResult {
                    success: false,
                    order_id: None,
                    filled_qty: Decimal::ZERO,
                    avg_price: Decimal::ZERO,
                    error: Some(msg),
                });
            }

            let order_id = json_val["data"][0]["ordId"]
                .as_str()
                .map(String::from);

            // Return ZERO for filled_qty and avg_price — actual fill data
            // is not known until a subsequent query_order call.
            Ok(OrderResult {
                success: order_id.is_some(),
                order_id,
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: None,
            })
        }

        async fn get_balance(
            &self,
            http_client: &reqwest::Client,
            asset: &str,
        ) -> Result<Decimal, String> {
            let timestamp = Self::timestamp_millis();
            let path = "/api/v5/account/balance";
            let method = "GET";
            let signature = self.sign(&timestamp, method, path, "");

            let resp = http_client
                .get(format!("{}{}", self.rest_url, path))
                .header("OK-ACCESS-KEY", self.api_key.expose())
                .header("OK-ACCESS-SIGN", &signature)
                .header("OK-ACCESS-TIMESTAMP", &timestamp)
                .header("OK-ACCESS-PASSPHRASE", self.passphrase.expose())
                .header("Content-Type", "application/json")
                .send()
                .await
                .map_err(|e| format!("OKX get_balance request failed: {}", e))?;

            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("OKX get_balance read body failed: {}", e))?;
            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("OKX get_balance JSON parse failed: {}", e))?;

            if json_val["code"] != "0" {
                let msg = json_val["msg"]
                    .as_str()
                    .unwrap_or("unknown OKX error")
                    .to_string();
                return Err(format!("OKX get_balance error: {}", msg));
            }

            // Navigate data[0].details[] to find the requested asset.
            if let Some(details) = json_val["data"][0]["details"].as_array() {
                for detail in details {
                    if detail["ccy"].as_str() == Some(asset) {
                        let bal = detail["eq"].as_str().unwrap_or("0");
                        return bal.parse::<Decimal>().map_err(|e| {
                            format!("OKX balance parse decimal error: {}", e)
                        });
                    }
                }
            }

            Err(format!("OKX: asset '{}' not found in balance", asset))
        }

        async fn cancel_order(
            &self,
            http_client: &reqwest::Client,
            symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let timestamp = Self::timestamp_millis();
            let path = "/api/v5/trade/cancel-order";
            let method = "POST";

            let body = json!({
                "instId": symbol,
                "ordId": order_id,
            });
            let body_str = body.to_string();
            let signature = self.sign(&timestamp, method, path, &body_str);

            let resp = http_client
                .post(format!("{}{}", self.rest_url, path))
                .header("OK-ACCESS-KEY", self.api_key.expose())
                .header("OK-ACCESS-SIGN", &signature)
                .header("OK-ACCESS-TIMESTAMP", &timestamp)
                .header("OK-ACCESS-PASSPHRASE", self.passphrase.expose())
                .header("Content-Type", "application/json")
                .body(body_str)
                .send()
                .await
                .map_err(|e| format!("OKX cancel_order request failed: {}", e))?;

            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("OKX cancel_order read body failed: {}", e))?;
            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("OKX cancel_order JSON parse failed: {}", e))?;

            if json_val["code"] != "0" {
                let msg = json_val["msg"]
                    .as_str()
                    .unwrap_or("unknown OKX cancel error")
                    .to_string();
                return Err(format!("OKX cancel_order error: {}", msg));
            }

            // OKX cancel response: {"code":"0","data":[{"ordId":"xxx"}]}
            // Fill info is not included; caller should query /api/v5/trade/orders-pending if needed.
            let returned_id = json_val["data"][0]["ordId"]
                .as_str()
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
}

// ---------------------------------------------------------------------------
// gateio — full Gate.io V4 implementation
// ---------------------------------------------------------------------------

pub mod gateio {
    use async_trait::async_trait;
    use base64::Engine;
    use ring::digest;
    use ring::hmac;
    use rust_decimal::Decimal;
    use serde_json::{json, Value};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::exchange::config::SecretString;
    use crate::signer::{
        OrderRequest, OrderResult, OrderSide, OrderType, PrivateExchangeClient,
    };

    use hex;

    const DEFAULT_REST_URL: &str = "https://api.gateio.ws";

    /// Gate.io V4 spot private client.
    ///
    /// Gate.io signs requests with HMAC-SHA256 over
    /// `timestamp + method + path + query + sha256_hex(body)`.
    pub struct GateioClient {
        id: u16,
        api_key: SecretString,
        api_secret: SecretString,
        rest_url: String,
    }

    impl std::fmt::Debug for GateioClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("GateioClient")
                .field("id", &self.id)
                .field("api_key", &self.api_key)
                .field("rest_url", &self.rest_url)
                .finish()
        }
    }

    impl GateioClient {
        /// Create a new Gate.io client.
        pub fn new(api_key: &str, api_secret: &str) -> Result<Self, String> {
            Ok(Self {
                id: 3,
                api_key: SecretString::new(api_key),
                api_secret: SecretString::new(api_secret),
                rest_url: DEFAULT_REST_URL.to_string(),
            })
        }

        /// Build a Gate.io V4 HMAC-SHA256 signature.
        ///
        /// 1. SHA-256 the body and hex-encode → `body_hash`
        /// 2. Concatenate `timestamp + method + path + query + body_hash`
        /// 3. HMAC-SHA256 with `api_secret` as key, hex-encode the result.
        fn sign(
            &self,
            timestamp: &str,
            method: &str,
            path: &str,
            query: &str,
            body: &str,
        ) -> String {
            let body_hash =
                hex::encode(digest::digest(&digest::SHA256, body.as_bytes()));
            let payload = format!(
                "{}{}{}{}{}",
                timestamp, method, path, query, body_hash
            );
            let key = hmac::Key::new(hmac::HMAC_SHA256, self.api_secret.expose().as_bytes());
            let signature = hmac::sign(&key, payload.as_bytes());
            hex::encode(signature.as_ref())
        }

        /// Current Unix epoch in seconds as a string.
        fn timestamp_secs() -> String {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs()
                .to_string()
        }
    }

    #[async_trait]
    impl PrivateExchangeClient for GateioClient {
        fn id(&self) -> u16 {
            self.id
        }


        async fn query_order(
            &self,
            http_client: &reqwest::Client,
            symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let timestamp = Self::timestamp_secs();
            let path = format!("/api/v4/spot/orders/{}", order_id);
            // FIX: Only currency_pair is a query parameter. order_id is in the path.
            // Previously order_id was duplicated into the query string AND the path,
            // causing signature mismatch with GateIO's expected preimage.
            let query = format!("currency_pair={}", symbol.to_uppercase());
            let signature = self.sign(&timestamp, "GET", &path, &query, "");

            // FIX: Include the query string in the URL (was missing entirely).
            let resp = http_client.get(&format!("{}{}?{}", self.rest_url, path, query))
                .header("KEY", self.api_key.expose())
                .header("SIGN", &signature)
                .header("Timestamp", &timestamp.to_string())
                .send().await
                .map_err(|e| format!("GateIO query_order request failed: {}", e))?;
            let status = resp.status();
            let body = resp.text().await
                .map_err(|e| format!("GateIO query_order read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("GateIO query_order HTTP {}: {}", status, body));
            }
            let v: serde_json::Value = serde_json::from_str(&body)
                .map_err(|e| format!("GateIO query_order JSON parse failed: {}", e))?;

            let filled = v.get("filled_total").and_then(|x| x.as_str()).and_then(|s| s.parse::<Decimal>().ok()).unwrap_or(Decimal::ZERO);
            let avg = v.get("avg_deal_price").and_then(|x| x.as_str()).and_then(|s| s.parse::<Decimal>().ok()).unwrap_or(Decimal::ZERO);
            let status_str = v.get("status").and_then(|x| x.as_str()).unwrap_or("UNKNOWN");
            let success = status_str == "closed";

            Ok(OrderResult { success, order_id: Some(order_id.to_string()), filled_qty: filled, avg_price: avg, error: if success { None } else { Some(format!("unfilled: {}", status_str)) } })
        }

        async fn submit_order(
            &self,
            http_client: &reqwest::Client,
            order: OrderRequest,
        ) -> Result<OrderResult, String> {
            let timestamp = Self::timestamp_secs();
            let path = "/api/v4/spot/orders";
            let method = "POST";
            let query = "";

            let side_str = match order.side {
                OrderSide::Buy => "buy",
                OrderSide::Sell => "sell",
            };
            let order_type_str = match order.order_type {
                OrderType::Market => "market",
                OrderType::Limit => "limit",
                OrderType::Fok => "fok",
                OrderType::IoC => "ioc",
            };

            let mut body = json!({
                "account": "spot",
                "symbol": order.symbol,
                "side": side_str,
                "type": order_type_str,
                "amount": order.quantity.to_string(),
            });

            if let Some(price) = order.price {
                body["price"] = json!(price.to_string());
            }
            if let Some(ref client_order_id) = order.client_order_id {
                body["text"] = json!(client_order_id);
            }

            let body_str = body.to_string();
            let signature =
                self.sign(&timestamp, method, path, query, &body_str);

            let resp = http_client
                .post(format!("{}{}", self.rest_url, path))
                .header("KEY", self.api_key.expose())
                .header("SIGN", &signature)
                .header("Timestamp", &timestamp)
                .header("Content-Type", "application/json")
                .body(body_str)
                .send()
                .await
                .map_err(|e| {
                    format!("Gate.io submit_order request failed: {}", e)
                })?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| {
                    format!("Gate.io submit_order read body failed: {}", e)
                })?;
            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| {
                    format!("Gate.io submit_order JSON parse failed: {}", e)
                })?;

            if status.is_success() {
                // Gate.io returns {"id": "<order_id>", ...} on success.
                let order_id = json_val["id"].as_str().map(String::from);
                Ok(OrderResult {
                    success: order_id.is_some(),
                    order_id,
                    filled_qty: order.quantity,
                    avg_price: order.price.unwrap_or(Decimal::ZERO),
                    error: None,
                })
            } else {
                let msg = json_val["label"]
                    .as_str()
                    .or_else(|| json_val["message"].as_str())
                    .unwrap_or(&resp_text)
                    .to_string();
                Ok(OrderResult {
                    success: false,
                    order_id: None,
                    filled_qty: Decimal::ZERO,
                    avg_price: Decimal::ZERO,
                    error: Some(msg),
                })
            }
        }

        async fn get_balance(
            &self,
            http_client: &reqwest::Client,
            asset: &str,
        ) -> Result<Decimal, String> {
            let timestamp = Self::timestamp_secs();
            let path = "/api/v4/spot/accounts";
            let method = "GET";
            let query = "";
            let body = "";
            let signature =
                self.sign(&timestamp, method, path, query, body);

            let resp = http_client
                .get(format!("{}{}", self.rest_url, path))
                .header("KEY", self.api_key.expose())
                .header("SIGN", &signature)
                .header("Timestamp", &timestamp)
                .header("Content-Type", "application/json")
                .send()
                .await
                .map_err(|e| {
                    format!("Gate.io get_balance request failed: {}", e)
                })?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| {
                    format!("Gate.io get_balance read body failed: {}", e)
                })?;

            if !status.is_success() {
                return Err(format!(
                    "Gate.io get_balance HTTP {}: {}",
                    status, resp_text
                ));
            }

            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| {
                    format!("Gate.io get_balance JSON parse failed: {}", e)
                })?;

            // Gate.io returns a top-level array of account objects.
            if let Some(accounts) = json_val.as_array() {
                for acct in accounts {
                    if acct["currency"].as_str() == Some(asset) {
                        let bal = acct["available"].as_str().unwrap_or("0");
                        return bal.parse::<Decimal>().map_err(|e| {
                            format!("Gate.io balance parse decimal error: {}", e)
                        });
                    }
                }
            }

            Err(format!(
                "Gate.io: asset '{}' not found in balance",
                asset
            ))
        }

        async fn cancel_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let timestamp = Self::timestamp_secs();
            let path = format!("/api/v4/spot/orders/{}", order_id);
            let method = "DELETE";
            let query = "";
            let body = "";
            let signature =
                self.sign(&timestamp, method, &path, query, body);

            let resp = http_client
                .delete(format!("{}{}", self.rest_url, path))
                .header("KEY", self.api_key.expose())
                .header("SIGN", &signature)
                .header("Timestamp", &timestamp)
                .header("Content-Type", "application/json")
                .send()
                .await
                .map_err(|e| {
                    format!("Gate.io cancel_order request failed: {}", e)
                })?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| {
                    format!("Gate.io cancel_order read body failed: {}", e)
                })?;

            if !status.is_success() {
                let json_val: Value = serde_json::from_str(&resp_text)
                    .unwrap_or(Value::Null);
                let msg = json_val["label"]
                    .as_str()
                    .or_else(|| json_val["message"].as_str())
                    .unwrap_or(&resp_text)
                    .to_string();
                return Err(format!(
                    "Gate.io cancel_order HTTP {}: {}",
                    status, msg
                ));
            }

            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| {
                    format!("Gate.io cancel_order JSON parse failed: {}", e)
                })?;

            // Gate.io returns the full order object; parse fill info.
            let filled_qty = json_val
                .get("filled_total")
                .or_else(|| json_val.get("fill_size"))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Decimal>().ok())
                .unwrap_or(Decimal::ZERO);

            let avg_price = json_val
                .get("avg_deal_price")
                .or_else(|| json_val.get("avgPrice"))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Decimal>().ok())
                .unwrap_or(Decimal::ZERO);

            let returned_id = json_val
                .get("id")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| order_id.to_string());

            Ok(OrderResult {
                success: true,
                order_id: Some(returned_id),
                filled_qty,
                avg_price,
                error: None,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// PaperExchangeClient — simulated fills with deterministic LCG slippage
// ---------------------------------------------------------------------------

/// LCG parameters (Numerical Recipes classic) — same values as `paper_trading.rs`.
const LCG_A: u64 = 1_664_525;
const LCG_C: u64 = 1_013_904_223;
const LCG_M: u64 = 1u64 << 32;

/// A no-network exchange client that simulates order fills locally.
///
/// Used as a fallback when live API keys are not configured (or during
/// integration testing).  Every [`submit_order`](PrivateExchangeClient::submit_order)
/// is "filled" immediately with a deterministic 1–3 basis-point slippage
/// applied to the order's price.  [`get_balance`](PrivateExchangeClient::get_balance)
/// always returns a fixed balance of 10 000.
pub struct PaperExchangeClient {
    id: u16,
    /// Mutable LCG state for deterministic slippage sampling.
    seed: AtomicU64,
}

impl PaperExchangeClient {
    /// Create a new paper exchange client.
    ///
    /// `id` identifies the exchange slot (0 = Binance, 1 = Bybit, etc.)
    /// and also seeds the LCG so different slots produce different slippage
    /// sequences.
    pub fn new(id: u16) -> Self {
        Self {
            id,
            // Offset by 1 to avoid a zero seed (which would be static).
            seed: AtomicU64::new(id as u64 + 1),
        }
    }

    /// Return a deterministic slippage in the range **1–3 basis points**
    /// using a Linear Congruential Generator.
    ///
    /// Thread-safe via `AtomicU64` (required because the trait takes `&self`).
    fn compute_slippage(&self) -> Decimal {
        let prev = self.seed.load(Ordering::SeqCst);
        let next = (LCG_A.wrapping_mul(prev).wrapping_add(LCG_C)) % LCG_M;
        self.seed.store(next, Ordering::SeqCst);
        // Map the 32-bit LCG output to 1, 2, or 3 bps.
        let bps = 1u64 + (next % 3u64);
        Decimal::from(bps) / Decimal::from(10000)
    }
}

#[async_trait]
impl PrivateExchangeClient for PaperExchangeClient {
    fn id(&self) -> u16 {
        self.id
    }

    /// Simulate a successful fill with LCG-based 1–3 bps slippage.
    ///
    /// * **BUY**  → filled price = `price × (1 + slippage)`
    /// * **SELL** → filled price = `price × (1 - slippage)`
    ///
    /// If the order has no price (e.g. a bare market order), the average
    /// price is reported as zero.
    async fn submit_order(
        &self,
        _http_client: &reqwest::Client,
        order: OrderRequest,
    ) -> Result<OrderResult, String> {
        let slippage = self.compute_slippage();
        let base_price = order.price.unwrap_or(Decimal::ZERO);

        let filled_price = match order.side {
            OrderSide::Buy => base_price * (Decimal::ONE + slippage),
            OrderSide::Sell => base_price * (Decimal::ONE - slippage),
        };

        Ok(OrderResult {
            success: true,
            order_id: order.client_order_id,
            filled_qty: order.quantity,
            avg_price: filled_price,
            error: None,
        })
    }

    /// Return a fixed balance of 10 000 for every asset.
    async fn get_balance(
        &self,
        _http_client: &reqwest::Client,
        _asset: &str,
    ) -> Result<Decimal, String> {
        Ok(Decimal::from(10000))
    }

    /// No-op cancellation — paper exchange always fills immediately.
    async fn cancel_order(
        &self,
        _http_client: &reqwest::Client,
        _symbol: &str,
        order_id: &str,
    ) -> Result<OrderResult, String> {
        Ok(OrderResult {
            success: true,
            order_id: Some(order_id.to_string()),
            filled_qty: Decimal::ZERO,
            avg_price: Decimal::ZERO,
            error: None,
        })
    }

    async fn query_order(
        &self,
        _http_client: &reqwest::Client,
        _symbol: &str,
        order_id: &str,
    ) -> Result<OrderResult, String> {
        Ok(OrderResult {
            success: true,
            order_id: Some(order_id.to_string()),
            filled_qty: Decimal::ZERO,
            avg_price: Decimal::ZERO,
            error: None,
        })
    }
}

// ---------------------------------------------------------------------------
// coinbase — full Coinbase Exchange (Advanced Trade) implementation
// ---------------------------------------------------------------------------

pub mod coinbase {
    use async_trait::async_trait;
    use base64::Engine;
    use ring::hmac;
    use rust_decimal::Decimal;
    use serde_json::{json, Value};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::exchange::config::SecretString;
    use crate::signer::{
        OrderRequest, OrderResult, OrderSide, OrderType, PrivateExchangeClient,
    };

    const DEFAULT_REST_URL: &str = "https://api.exchange.coinbase.com";

    /// Coinbase Exchange (Advanced Trade) private client.
    ///
    /// Uses HMAC-SHA256 with a base64-decoded API secret and produces
    /// base64-encoded signatures sent via CB-ACCESS-* headers.
    pub struct CoinbasePrivateClient {
        id: u16,
        api_key: SecretString,
        api_secret: SecretString,
        rest_url: String,
    }

    impl std::fmt::Debug for CoinbasePrivateClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CoinbasePrivateClient")
                .field("id", &self.id)
                .field("api_key", &self.api_key)
                .field("rest_url", &self.rest_url)
                .finish()
        }
    }

    impl CoinbasePrivateClient {
        /// Create a new Coinbase Exchange client.
        ///
        /// `api_secret` is expected in the base64-encoded form issued by Coinbase.
        pub fn new(api_key: &str, api_secret: &str) -> Result<Self, String> {
            Ok(Self {
                id: 8,
                api_key: SecretString::new(api_key),
                api_secret: SecretString::new(api_secret),
                rest_url: DEFAULT_REST_URL.to_string(),
            })
        }

        /// Build a Coinbase HMAC-SHA256 signature.
        ///
        /// The API secret is base64-decoded and used as the HMAC key.
        /// Preimage: `timestamp + method + path + body`.
        /// Result is base64-encoded.
        fn sign(
            &self,
            timestamp: &str,
            method: &str,
            path: &str,
            body: &str,
        ) -> Result<String, String> {
            let key_bytes = base64::engine::general_purpose::STANDARD
                .decode(self.api_secret.expose())
                .map_err(|e| format!("Coinbase: failed to base64-decode api_secret: {}", e))?;
            let preimage = format!("{}{}{}{}", timestamp, method, path, body);
            let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
            let signature = hmac::sign(&key, preimage.as_bytes());
            Ok(base64::engine::general_purpose::STANDARD.encode(signature.as_ref()))
        }

        /// Current Unix epoch in seconds as a string.
        fn timestamp_secs() -> String {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs()
                .to_string()
        }

        /// Convert a generic "BTC/USD" style symbol to Coinbase's "BTC-USD" format.
        fn coinbase_symbol(symbol: &str) -> String {
            symbol.replace('/', "-").to_uppercase()
        }
    }

    #[async_trait]
    impl PrivateExchangeClient for CoinbasePrivateClient {
        fn id(&self) -> u16 {
            self.id
        }

        async fn submit_order(
            &self,
            http_client: &reqwest::Client,
            order: OrderRequest,
        ) -> Result<OrderResult, String> {
            let timestamp = Self::timestamp_secs();
            let path = "/orders";
            let method = "POST";

            let product_id = Self::coinbase_symbol(&order.symbol);
            let side_str = match order.side {
                OrderSide::Buy => "buy",
                OrderSide::Sell => "sell",
            };

            let mut body = json!({
                "product_id": product_id,
                "side": side_str,
                "size": order.quantity.to_string(),
            });

            // Add price for limit orders
            if let Some(price) = order.price {
                body["price"] = json!(price.to_string());
            }
            if let Some(ref cl_ord_id) = order.client_order_id {
                body["client_order_id"] = json!(cl_ord_id);
            }

            let body_str = body.to_string();
            let signature = self.sign(&timestamp, method, path, &body_str)?;

            let resp = http_client
                .post(format!("{}{}", self.rest_url, path))
                .header("CB-ACCESS-KEY", self.api_key.expose())
                .header("CB-ACCESS-SIGN", &signature)
                .header("CB-ACCESS-TIMESTAMP", &timestamp)
                .header("Content-Type", "application/json")
                .body(body_str)
                .send()
                .await
                .map_err(|e| format!("Coinbase submit_order request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("Coinbase submit_order read body failed: {}", e))?;

            if !status.is_success() {
                return Ok(OrderResult {
                    success: false,
                    order_id: None,
                    filled_qty: Decimal::ZERO,
                    avg_price: Decimal::ZERO,
                    error: Some(format!("HTTP {}: {}", status, resp_text)),
                });
            }

            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("Coinbase submit_order JSON parse failed: {}", e))?;

            let order_id = json_val["id"].as_str().map(String::from);

            Ok(OrderResult {
                success: order_id.is_some(),
                order_id,
                filled_qty: order.quantity,
                avg_price: order.price.unwrap_or(Decimal::ZERO),
                error: None,
            })
        }

        async fn get_balance(
            &self,
            http_client: &reqwest::Client,
            asset: &str,
        ) -> Result<Decimal, String> {
            let timestamp = Self::timestamp_secs();
            let path = "/accounts";
            let method = "GET";
            let signature = self.sign(&timestamp, method, path, "")?;

            let resp = http_client
                .get(format!("{}{}", self.rest_url, path))
                .header("CB-ACCESS-KEY", self.api_key.expose())
                .header("CB-ACCESS-SIGN", &signature)
                .header("CB-ACCESS-TIMESTAMP", &timestamp)
                .header("Content-Type", "application/json")
                .send()
                .await
                .map_err(|e| format!("Coinbase get_balance request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("Coinbase get_balance read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("Coinbase get_balance HTTP {}: {}", status, resp_text));
            }

            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("Coinbase get_balance JSON parse failed: {}", e))?;

            // Coinbase returns an array of account objects.
            if let Some(accounts) = json_val.as_array() {
                for acct in accounts {
                    if acct["currency"].as_str().map(|c| c.eq_ignore_ascii_case(asset)) == Some(true) {
                        let bal = acct["available_balance"]["value"]
                            .as_str()
                            .unwrap_or("0");
                        return bal.parse::<Decimal>().map_err(|e| {
                            format!("Coinbase balance parse decimal error: {}", e)
                        });
                    }
                }
            }

            Err(format!("Coinbase: asset '{}' not found in balance", asset))
        }

        async fn cancel_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let timestamp = Self::timestamp_secs();
            let path = format!("/orders/{}", order_id);
            let method = "DELETE";
            let signature = self.sign(&timestamp, method, &path, "")?;

            let resp = http_client
                .delete(format!("{}{}", self.rest_url, path))
                .header("CB-ACCESS-KEY", self.api_key.expose())
                .header("CB-ACCESS-SIGN", &signature)
                .header("CB-ACCESS-TIMESTAMP", &timestamp)
                .header("Content-Type", "application/json")
                .send()
                .await
                .map_err(|e| format!("Coinbase cancel_order request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("Coinbase cancel_order read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("Coinbase cancel_order HTTP {}: {}", status, resp_text));
            }

            Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: None,
            })
        }

        async fn query_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let timestamp = Self::timestamp_secs();
            let path = format!("/orders/{}", order_id);
            let method = "GET";
            let signature = self.sign(&timestamp, method, &path, "")?;

            let resp = http_client
                .get(format!("{}{}", self.rest_url, path))
                .header("CB-ACCESS-KEY", self.api_key.expose())
                .header("CB-ACCESS-SIGN", &signature)
                .header("CB-ACCESS-TIMESTAMP", &timestamp)
                .header("Content-Type", "application/json")
                .send()
                .await
                .map_err(|e| format!("Coinbase query_order request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("Coinbase query_order read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("Coinbase query_order HTTP {}: {}", status, resp_text));
            }

            let v: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("Coinbase query_order JSON parse failed: {}", e))?;

            let filled = v.get("filled_size")
                .and_then(|x| x.as_str())
                .and_then(|s| s.parse::<Decimal>().ok())
                .unwrap_or(Decimal::ZERO);
            let avg = v.get("average_filled_price")
                .and_then(|x| x.as_str())
                .and_then(|s| s.parse::<Decimal>().ok())
                .unwrap_or(Decimal::ZERO);
            let status_str = v.get("status").and_then(|x| x.as_str()).unwrap_or("UNKNOWN");
            let success = status_str == "filled";

            Ok(OrderResult {
                success,
                order_id: Some(order_id.to_string()),
                filled_qty: filled,
                avg_price: avg,
                error: if success { None } else { Some(format!("unfilled: {}", status_str)) },
            })
        }
    }
}

// ---------------------------------------------------------------------------
// bitmex — full BitMEX implementation
// ---------------------------------------------------------------------------

pub mod bitmex {
    use async_trait::async_trait;
    use ring::hmac;
    use rust_decimal::Decimal;
    use serde_json::{json, Value};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::exchange::config::SecretString;
    use crate::signer::{
        OrderRequest, OrderResult, OrderSide, OrderType, PrivateExchangeClient,
    };

    use chrono::Utc;

    const DEFAULT_REST_URL: &str = "https://www.bitmex.com";

    /// BitMEX private client.
    ///
    /// Uses HMAC-SHA256 with expires-based authentication.
    /// Preimage: `verb + path + expires + body`.
    /// Result is hex-encoded.
    pub struct BitmexPrivateClient {
        id: u16,
        api_key: SecretString,
        api_secret: SecretString,
        rest_url: String,
    }

    impl std::fmt::Debug for BitmexPrivateClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BitmexPrivateClient")
                .field("id", &self.id)
                .field("api_key", &self.api_key)
                .field("rest_url", &self.rest_url)
                .finish()
        }
    }

    impl BitmexPrivateClient {
        /// Create a new BitMEX client.
        pub fn new(api_key: &str, api_secret: &str) -> Result<Self, String> {
            Ok(Self {
                id: 7,
                api_key: SecretString::new(api_key),
                api_secret: SecretString::new(api_secret),
                rest_url: DEFAULT_REST_URL.to_string(),
            })
        }

        /// Build a BitMEX HMAC-SHA256 signature.
        ///
        /// Preimage: `verb + path + expires + body`.
        /// Result is hex-encoded.
        fn sign(
            &self,
            verb: &str,
            path: &str,
            expires: u64,
            body: &str,
        ) -> String {
            let preimage = format!("{}{}{}{}", verb, path, expires, body);
            let key = hmac::Key::new(hmac::HMAC_SHA256, self.api_secret.expose().as_bytes());
            let signature = hmac::sign(&key, preimage.as_bytes());
            hex::encode(signature.as_ref())
        }

        /// Get current timestamp as unix seconds, plus a 60-second expiry window.
        fn expires() -> u64 {
            Utc::now().timestamp() as u64 + 60
        }

        /// Convert "BTC/USD" to BitMEX symbol format "XBTUSD".
        /// BitMEX uses XBT instead of BTC.
        fn bitmex_symbol(symbol: &str) -> String {
            symbol
                .replace('/', "")
                .to_uppercase()
                .replace("BTC", "XBT")
        }
    }

    #[async_trait]
    impl PrivateExchangeClient for BitmexPrivateClient {
        fn id(&self) -> u16 {
            self.id
        }

        async fn submit_order(
            &self,
            http_client: &reqwest::Client,
            order: OrderRequest,
        ) -> Result<OrderResult, String> {
            let expires = Self::expires();
            let path = "/api/v1/order";
            let verb = "POST";

            let side_str = match order.side {
                OrderSide::Buy => "Buy",
                OrderSide::Sell => "Sell",
            };
            let ord_type = match order.order_type {
                OrderType::Market => "Market",
                OrderType::Limit => "Limit",
                OrderType::Fok => "FillOrKill",
                OrderType::IoC => "ImmediateOrCancel",
            };

            let mut body = json!({
                "symbol": Self::bitmex_symbol(&order.symbol),
                "side": side_str,
                "orderQty": order.quantity,
                "ordType": ord_type,
            });

            if let Some(price) = order.price {
                body["price"] = json!(price);
            }
            if let Some(ref cl_ord_id) = order.client_order_id {
                if !cl_ord_id.is_empty() {
                    body["clOrdID"] = json!(cl_ord_id);
                }
            }

            let body_str = body.to_string();
            let signature = self.sign(verb, path, expires, &body_str);

            let resp = http_client
                .post(format!("{}{}", self.rest_url, path))
                .header("api-key", self.api_key.expose())
                .header("api-expires", expires.to_string())
                .header("api-signature", &signature)
                .header("Content-Type", "application/json")
                .body(body_str)
                .send()
                .await
                .map_err(|e| format!("BitMEX submit_order request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("BitMEX submit_order read body failed: {}", e))?;

            if !status.is_success() {
                return Ok(OrderResult {
                    success: false,
                    order_id: None,
                    filled_qty: Decimal::ZERO,
                    avg_price: Decimal::ZERO,
                    error: Some(format!("HTTP {}: {}", status, resp_text)),
                });
            }

            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("BitMEX submit_order JSON parse failed: {}", e))?;

            let order_id = json_val["orderID"].as_str().map(String::from);

            Ok(OrderResult {
                success: order_id.is_some(),
                order_id,
                filled_qty: order.quantity,
                avg_price: order.price.unwrap_or(Decimal::ZERO),
                error: None,
            })
        }

        async fn get_balance(
            &self,
            http_client: &reqwest::Client,
            asset: &str,
        ) -> Result<Decimal, String> {
            let expires = Self::expires();
            let path = "/api/v1/user/wallet";
            let verb = "GET";
            let signature = self.sign(verb, path, expires, "");

            let resp = http_client
                .get(format!("{}{}", self.rest_url, path))
                .header("api-key", self.api_key.expose())
                .header("api-expires", expires.to_string())
                .header("api-signature", &signature)
                .send()
                .await
                .map_err(|e| format!("BitMEX get_balance request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("BitMEX get_balance read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("BitMEX get_balance HTTP {}: {}", status, resp_text));
            }

            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("BitMEX get_balance JSON parse failed: {}", e))?;

            // BitMEX /api/v1/user/wallet returns amount in satoshis (1 BTC = 100,000,000 satoshis).
            if let Some(amount) = json_val["amount"].as_i64() {
                let btc_balance = Decimal::from(amount) / Decimal::from(100_000_000);
                // BitMEX reports XBT; accept both "XBT" and "BTC" as the asset query.
                let asset_upper = asset.to_uppercase();
                if asset_upper == "XBT" || asset_upper == "BTC" {
                    return Ok(btc_balance);
                }
            }

            Err(format!("BitMEX: asset '{}' not found in balance", asset))
        }

        async fn cancel_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let expires = Self::expires();
            let path = "/api/v1/order";
            let verb = "DELETE";

            let body = json!({ "orderID": order_id });
            let body_str = body.to_string();
            let signature = self.sign(verb, path, expires, &body_str);

            let resp = http_client
                .delete(format!("{}{}", self.rest_url, path))
                .header("api-key", self.api_key.expose())
                .header("api-expires", expires.to_string())
                .header("api-signature", &signature)
                .header("Content-Type", "application/json")
                .body(body_str)
                .send()
                .await
                .map_err(|e| format!("BitMEX cancel_order request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("BitMEX cancel_order read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("BitMEX cancel_order HTTP {}: {}", status, resp_text));
            }

            Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: None,
            })
        }

        async fn query_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let expires = Self::expires();
            let path = format!("/api/v1/order?filter={{\"orderID\":\"{}\"}}", order_id);
            let verb = "GET";
            let signature = self.sign(verb, &path, expires, "");

            let url = format!("{}{}", self.rest_url, path);

            let resp = http_client
                .get(&url)
                .header("api-key", self.api_key.expose())
                .header("api-expires", expires.to_string())
                .header("api-signature", &signature)
                .send()
                .await
                .map_err(|e| format!("BitMEX query_order request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("BitMEX query_order read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("BitMEX query_order HTTP {}: {}", status, resp_text));
            }

            let v: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("BitMEX query_order JSON parse failed: {}", e))?;

            let o = v.as_array()
                .and_then(|a| a.first())
                .ok_or_else(|| format!("BitMEX: order {} not found", order_id))?;

            let filled = parse_json_decimal(&o["cumQty"]);
            let avg = parse_json_decimal(&o["avgPx"]);
            let ord_status = o["ordStatus"].as_str().unwrap_or("UNKNOWN");
            let success = ord_status == "Filled" || ord_status == "PartiallyFilled";

            Ok(OrderResult {
                success,
                order_id: Some(order_id.to_string()),
                filled_qty: filled,
                avg_price: avg,
                error: if success { None } else { Some(format!("unfilled: {}", ord_status)) },
            })
        }
    }

    /// Parse a Decimal from a JSON Value (string, i64, or f64).
    /// WARNING: Legacy function — uses silent ZERO fallback with warning logs.
    fn parse_json_decimal(v: &Value) -> Decimal {
        use std::str::FromStr;
        if let Some(s) = v.as_str() {
            match Decimal::from_str(s) {
                Ok(d) => d,
                Err(_) => {
                    tracing::warn!(raw = %s, "legacy parse_json_decimal: string parse failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else if let Some(n) = v.as_i64() {
            Decimal::from(n)
        } else if let Some(f) = v.as_f64() {
            match rust_decimal::prelude::FromPrimitive::from_f64(f) {
                Some(d) => d,
                None => {
                    tracing::warn!(raw = %f, "legacy parse_json_decimal: f64->Decimal failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else {
            tracing::warn!(raw = %v, "legacy parse_json_decimal: unexpected JSON type, defaulting to ZERO");
            Decimal::ZERO
        }
    }
}

// ---------------------------------------------------------------------------
// bitget — full Bitget V1 implementation
// ---------------------------------------------------------------------------

pub mod bitget {
    use async_trait::async_trait;
    use base64::Engine;
    use ring::hmac;
    use rust_decimal::Decimal;
    use serde_json::{json, Value};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::exchange::config::SecretString;
    use crate::signer::{
        OrderRequest, OrderResult, OrderSide, OrderType, PrivateExchangeClient,
    };

    const DEFAULT_REST_URL: &str = "https://api.bitget.com";

    /// Bitget spot private client.
    ///
    /// Uses HMAC-SHA256 with a pre-hashed passphrase (HMAC of passphrase
    /// with secret key, base64-encoded).
    /// Preimage: `timestamp + METHOD + path + body`.
    /// Result is base64-encoded.
    pub struct BitgetPrivateClient {
        id: u16,
        api_key: SecretString,
        api_secret: SecretString,
        rest_url: String,
        /// Pre-computed encrypted passphrase (HMAC-SHA256 of passphrase
        /// with secret key, base64-encoded).
        encrypted_passphrase: String,
    }

    impl std::fmt::Debug for BitgetPrivateClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BitgetPrivateClient")
                .field("id", &self.id)
                .field("api_key", &self.api_key)
                .field("rest_url", &self.rest_url)
                .finish()
        }
    }

    impl BitgetPrivateClient {
        /// Create a new Bitget client.
        ///
        /// `passphrase` is required and will be pre-hashed at construction time.
        pub fn new(api_key: &str, api_secret: &str, passphrase: &str) -> Result<Self, String> {
            // Pre-hash the passphrase: HMAC-SHA256(passphrase, secret) → base64
            let key = hmac::Key::new(hmac::HMAC_SHA256, api_secret.as_bytes());
            let sig = hmac::sign(&key, passphrase.as_bytes());
            let encrypted_passphrase =
                base64::engine::general_purpose::STANDARD.encode(sig.as_ref());

            Ok(Self {
                id: 6,
                api_key: SecretString::new(api_key),
                api_secret: SecretString::new(api_secret),
                rest_url: DEFAULT_REST_URL.to_string(),
                encrypted_passphrase,
            })
        }

        /// Build a Bitget HMAC-SHA256 signature.
        ///
        /// Preimage: `timestamp + METHOD + path + body`.
        /// Result is base64-encoded.
        fn sign(
            &self,
            timestamp: &str,
            method: &str,
            path: &str,
            body: &str,
        ) -> String {
            let preimage = format!(
                "{}{}{}{}",
                timestamp,
                method.to_uppercase(),
                path,
                body
            );
            let key = hmac::Key::new(hmac::HMAC_SHA256, self.api_secret.expose().as_bytes());
            let signature = hmac::sign(&key, preimage.as_bytes());
            base64::engine::general_purpose::STANDARD.encode(signature.as_ref())
        }

        /// Current Unix epoch in milliseconds as a string.
        fn timestamp_millis() -> String {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_millis()
                .to_string()
        }

        /// Convert "BTC/USDT" to Bitget symbol format "BTCUSDT".
        fn bitget_symbol(symbol: &str) -> String {
            symbol.replace('/', "").to_uppercase()
        }
    }

    #[async_trait]
    impl PrivateExchangeClient for BitgetPrivateClient {
        fn id(&self) -> u16 {
            self.id
        }

        async fn submit_order(
            &self,
            http_client: &reqwest::Client,
            order: OrderRequest,
        ) -> Result<OrderResult, String> {
            let timestamp = Self::timestamp_millis();
            let path = "/api/spot/v1/trade/orders";
            let method = "POST";

            let side_str = match order.side {
                OrderSide::Buy => "buy",
                OrderSide::Sell => "sell",
            };
            let order_type_str = match order.order_type {
                OrderType::Market => "market",
                OrderType::Limit => "limit",
                OrderType::Fok => "fok",
                OrderType::IoC => "ioc",
            };
            // Bitget uses "force" field: "normal" for GTC, "ioc", "fok"
            let force = match order.order_type {
                OrderType::IoC => "ioc",
                OrderType::Fok => "fok",
                _ => "normal",
            };

            let client_oid = order.client_order_id.as_deref().unwrap_or("");

            let mut body = json!({
                "symbol": Self::bitget_symbol(&order.symbol),
                "side": side_str,
                "orderType": order_type_str,
                "force": force,
                "quantity": order.quantity.to_string(),
                "clientOid": if client_oid.is_empty() {
                    uuid::Uuid::new_v4().to_string()
                } else {
                    client_oid.to_string()
                },
            });

            if let Some(price) = order.price {
                body["price"] = json!(price.to_string());
            } else {
                body["price"] = json!("0");
            }

            let body_str = body.to_string();
            let signature = self.sign(&timestamp, method, path, &body_str);

            let resp = http_client
                .post(format!("{}{}", self.rest_url, path))
                .header("ACCESS-KEY", self.api_key.expose())
                .header("ACCESS-SIGN", &signature)
                .header("ACCESS-TIMESTAMP", &timestamp)
                .header("ACCESS-PASSPHRASE", &self.encrypted_passphrase)
                .header("Content-Type", "application/json")
                .body(body_str)
                .send()
                .await
                .map_err(|e| format!("Bitget submit_order request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("Bitget submit_order read body failed: {}", e))?;

            if !status.is_success() {
                return Ok(OrderResult {
                    success: false,
                    order_id: None,
                    filled_qty: Decimal::ZERO,
                    avg_price: Decimal::ZERO,
                    error: Some(format!("HTTP {}: {}", status, resp_text)),
                });
            }

            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("Bitget submit_order JSON parse failed: {}", e))?;

            // Bitget returns {"code":"00000","data":{"orderId":"xxx",...}}
            let order_id = json_val["data"]["orderId"].as_str().map(String::from);

            Ok(OrderResult {
                success: order_id.is_some(),
                order_id,
                filled_qty: order.quantity,
                avg_price: order.price.unwrap_or(Decimal::ZERO),
                error: None,
            })
        }

        async fn get_balance(
            &self,
            http_client: &reqwest::Client,
            asset: &str,
        ) -> Result<Decimal, String> {
            let timestamp = Self::timestamp_millis();
            let path = "/api/spot/v1/account/assets";
            let method = "GET";
            let signature = self.sign(&timestamp, method, path, "");

            let resp = http_client
                .get(format!("{}{}", self.rest_url, path))
                .header("ACCESS-KEY", self.api_key.expose())
                .header("ACCESS-SIGN", &signature)
                .header("ACCESS-TIMESTAMP", &timestamp)
                .header("ACCESS-PASSPHRASE", &self.encrypted_passphrase)
                .header("Content-Type", "application/json")
                .send()
                .await
                .map_err(|e| format!("Bitget get_balance request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("Bitget get_balance read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("Bitget get_balance HTTP {}: {}", status, resp_text));
            }

            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("Bitget get_balance JSON parse failed: {}", e))?;

            // Bitget returns {"data": [{"coinName":"BTC","available":"1.5",...}, ...]}
            if let Some(arr) = json_val["data"].as_array() {
                for item in arr {
                    let coin = item["coinName"].as_str().unwrap_or("");
                    if coin.eq_ignore_ascii_case(asset) {
                        let bal = item["available"].as_str().unwrap_or("0");
                        return bal.parse::<Decimal>().map_err(|e| {
                            format!("Bitget balance parse decimal error: {}", e)
                        });
                    }
                }
            }

            Err(format!("Bitget: asset '{}' not found in balance", asset))
        }

        async fn cancel_order(
            &self,
            http_client: &reqwest::Client,
            symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let timestamp = Self::timestamp_millis();
            let path = "/api/spot/v1/trade/cancel-order";
            let method = "POST";

            let body = json!({
                "symbol": Self::bitget_symbol(symbol),
                "orderId": order_id,
            });
            let body_str = body.to_string();
            let signature = self.sign(&timestamp, method, path, &body_str);

            let resp = http_client
                .post(format!("{}{}", self.rest_url, path))
                .header("ACCESS-KEY", self.api_key.expose())
                .header("ACCESS-SIGN", &signature)
                .header("ACCESS-TIMESTAMP", &timestamp)
                .header("ACCESS-PASSPHRASE", &self.encrypted_passphrase)
                .header("Content-Type", "application/json")
                .body(body_str)
                .send()
                .await
                .map_err(|e| format!("Bitget cancel_order request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("Bitget cancel_order read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("Bitget cancel_order HTTP {}: {}", status, resp_text));
            }

            Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: None,
            })
        }

        async fn query_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let timestamp = Self::timestamp_millis();
            let path = "/api/spot/v1/trade/order-info";
            let method = "POST";

            let body = json!({ "orderId": order_id });
            let body_str = body.to_string();
            let signature = self.sign(&timestamp, method, path, &body_str);

            let resp = http_client
                .post(format!("{}{}", self.rest_url, path))
                .header("ACCESS-KEY", self.api_key.expose())
                .header("ACCESS-SIGN", &signature)
                .header("ACCESS-TIMESTAMP", &timestamp)
                .header("ACCESS-PASSPHRASE", &self.encrypted_passphrase)
                .header("Content-Type", "application/json")
                .body(body_str)
                .send()
                .await
                .map_err(|e| format!("Bitget query_order request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("Bitget query_order read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("Bitget query_order HTTP {}: {}", status, resp_text));
            }

            let v: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("Bitget query_order JSON parse failed: {}", e))?;

            let order = &v["data"];
            let filled = parse_json_decimal(&order["fillQuantity"]);
            // Bitget uses "priceAvg" for average fill price
            let avg = if order["priceAvg"].as_str().is_some() {
                parse_json_decimal(&order["priceAvg"])
            } else {
                parse_json_decimal(&order["fillPrice"])
            };
            let status_str = order["status"].as_str().unwrap_or("UNKNOWN");
            let success = status_str == "full_fill" || status_str == "partial_fill";

            Ok(OrderResult {
                success,
                order_id: Some(order_id.to_string()),
                filled_qty: filled,
                avg_price: avg,
                error: if success { None } else { Some(format!("unfilled: {}", status_str)) },
            })
        }
    }

    /// Parse a Decimal from a JSON Value (string, i64, or f64).
    /// WARNING: Legacy function — uses silent ZERO fallback with warning logs.
    fn parse_json_decimal(v: &Value) -> Decimal {
        use std::str::FromStr;
        if let Some(s) = v.as_str() {
            match Decimal::from_str(s) {
                Ok(d) => d,
                Err(_) => {
                    tracing::warn!(raw = %s, "legacy parse_json_decimal: string parse failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else if let Some(n) = v.as_i64() {
            Decimal::from(n)
        } else if let Some(f) = v.as_f64() {
            match rust_decimal::prelude::FromPrimitive::from_f64(f) {
                Some(d) => d,
                None => {
                    tracing::warn!(raw = %f, "legacy parse_json_decimal: f64->Decimal failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else {
            tracing::warn!(raw = %v, "legacy parse_json_decimal: unexpected JSON type, defaulting to ZERO");
            Decimal::ZERO
        }
    }
}

// ---------------------------------------------------------------------------
// bitfinex — full Bitfinex V2 implementation
// ---------------------------------------------------------------------------

pub mod bitfinex {
    use async_trait::async_trait;
    use ring::hmac;
    use rust_decimal::Decimal;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::exchange::config::SecretString;
    use crate::signer::{
        OrderRequest, OrderResult, OrderSide, OrderType, PrivateExchangeClient,
    };

    use chrono::Utc;

    const DEFAULT_REST_URL: &str = "https://api.bitfinex.com";

    /// Bitfinex V2 private client.
    ///
    /// Uses HMAC-SHA384 with a monotonic nonce counter.
    /// Preimage: `/api/v2{path}{nonce}{body}`.
    /// Result is hex-encoded.
    pub struct BitfinexPrivateClient {
        id: u16,
        api_key: SecretString,
        api_secret: SecretString,
        rest_url: String,
        /// Monotonic nonce counter. Bitfinex requires each request's nonce
        /// to be strictly greater than the previous one.
        nonce_counter: AtomicU64,
    }

    impl std::fmt::Debug for BitfinexPrivateClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BitfinexPrivateClient")
                .field("id", &self.id)
                .field("api_key", &self.api_key)
                .field("rest_url", &self.rest_url)
                .finish()
        }
    }

    impl BitfinexPrivateClient {
        /// Create a new Bitfinex client.
        pub fn new(api_key: &str, api_secret: &str) -> Result<Self, String> {
            // Initialize nonce counter to current time in ms so it starts
            // higher than any previous nonce from earlier runs.
            let initial_nonce = Utc::now().timestamp_millis() as u64;
            Ok(Self {
                id: 5,
                api_key: SecretString::new(api_key),
                api_secret: SecretString::new(api_secret),
                rest_url: DEFAULT_REST_URL.to_string(),
                nonce_counter: AtomicU64::new(initial_nonce),
            })
        }

        /// Generate a strictly monotonic nonce.
        fn next_nonce(&self) -> u64 {
            self.nonce_counter.fetch_add(1, Ordering::SeqCst) + 1
        }

        /// Build a Bitfinex HMAC-SHA384 signature.
        ///
        /// Preimage: `/api/v2{path}{nonce}{body}`.
        /// Result is hex-encoded.
        fn sign(
            &self,
            path: &str,
            nonce: &str,
            body: &str,
        ) -> String {
            let preimage = format!("/api/v2{}{}{}", path, nonce, body);
            let key = hmac::Key::new(hmac::HMAC_SHA384, self.api_secret.expose().as_bytes());
            let signature = hmac::sign(&key, preimage.as_bytes());
            hex::encode(signature.as_ref())
        }

        /// Send an authenticated POST request to Bitfinex.
        async fn auth_post(
            &self,
            http_client: &reqwest::Client,
            path: &str,
            body: Value,
        ) -> Result<Value, String> {
            let nonce = self.next_nonce().to_string();
            let body_str = body.to_string();
            let signature = self.sign(path, &nonce, &body_str);

            let resp = http_client
                .post(format!("{}{}", self.rest_url, path))
                .header("bfx-nonce", &nonce)
                .header("bfx-apikey", self.api_key.expose())
                .header("bfx-signature", &signature)
                .header("Content-Type", "application/json")
                .body(body_str)
                .send()
                .await
                .map_err(|e| format!("Bitfinex auth_post request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("Bitfinex auth_post read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("Bitfinex auth_post HTTP {}: {}", status, resp_text));
            }

            serde_json::from_str(&resp_text)
                .map_err(|e| format!("Bitfinex auth_post JSON parse failed: {}", e))
        }

        /// Convert "BTC/USD" to Bitfinex trading symbol format "tBTCUSD".
        fn bitfinex_symbol(symbol: &str) -> String {
            format!("t{}", symbol.replace('/', "").to_uppercase())
        }
    }

    #[async_trait]
    impl PrivateExchangeClient for BitfinexPrivateClient {
        fn id(&self) -> u16 {
            self.id
        }

        async fn submit_order(
            &self,
            http_client: &reqwest::Client,
            order: OrderRequest,
        ) -> Result<OrderResult, String> {
            let order_type_str = match order.order_type {
                OrderType::Market => "MARKET",
                OrderType::Limit => "LIMIT",
                OrderType::Fok => "EXCHANGE LIMIT", // Bitfinex has no native FOK
                OrderType::IoC => "LIMIT",           // IOC via flags
            };

            // Bitfinex uses signed amounts: positive for buy, negative for sell
            let amount = match order.side {
                OrderSide::Buy => order.quantity,
                OrderSide::Sell => -order.quantity,
            };

            let mut order_obj = json!({
                "type": order_type_str,
                "symbol": Self::bitfinex_symbol(&order.symbol),
                "amount": amount,
            });

            if let Some(price) = order.price {
                order_obj["price"] = json!(price);
            }

            // Add IOC flags bitmask (4096 = IOC)
            if matches!(order.order_type, OrderType::IoC) {
                order_obj["flags"] = json!(4096);
            }

            // Bitfinex uses "cid" (client ID) for idempotency, must be integer
            if let Some(ref cl_ord_id) = order.client_order_id {
                if !cl_ord_id.is_empty() {
                    let cid = cl_ord_id
                        .chars()
                        .map(|c| c as u32)
                        .fold(0u64, |acc, v| acc.wrapping_add(v as u64));
                    order_obj["cid"] = json!(cid);
                }
            }

            // Bitfinex API uses [0, "on", null, {order_details}] format
            let body = json!([0, "on", null, order_obj]);

            let json_val = self
                .auth_post(http_client, "/auth/w/order/submit", body)
                .await?;

            // Parse response: [0, "on", null, [{order_obj}, ...]]
            let order_id = json_val
                .as_array()
                .and_then(|a| a.get(4))
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|o| o["id"].as_i64())
                .map(|n| n.to_string());

            Ok(OrderResult {
                success: order_id.is_some(),
                order_id,
                filled_qty: order.quantity,
                avg_price: order.price.unwrap_or(Decimal::ZERO),
                error: None,
            })
        }

        async fn get_balance(
            &self,
            http_client: &reqwest::Client,
            asset: &str,
        ) -> Result<Decimal, String> {
            let body = json!([0, "wallet", null, { "type": "exchange" }]);
            let json_val = self
                .auth_post(http_client, "/auth/r/wallets", body)
                .await?;

            // Bitfinex returns an array of wallet arrays: [["exchange", "USD", 1234.56, ...], ...]
            if let Some(wallets) = json_val.as_array() {
                for w in wallets {
                    let currency = w[1].as_str().unwrap_or("");
                    if currency.eq_ignore_ascii_case(asset) {
                        let bal = w[2].as_f64().unwrap_or(0.0);
                        return Ok(rust_decimal::prelude::FromPrimitive::from_f64(bal)
                            .unwrap_or(Decimal::ZERO));
                    }
                }
            }

            Err(format!("Bitfinex: asset '{}' not found in balance", asset))
        }

        async fn cancel_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let parsed_id = order_id
                .parse::<i64>()
                .map_err(|_| format!("Bitfinex: invalid order_id '{}'", order_id))?;

            let body = json!([0, "oc", null, { "id": parsed_id }]);
            self.auth_post(http_client, "/auth/w/order/cancel", body)
                .await?;

            Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: None,
            })
        }

        async fn query_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let parsed_id = order_id
                .parse::<i64>()
                .map_err(|_| format!("Bitfinex: invalid order_id '{}'", order_id))?;

            let body = json!([0, "order_multi", null, { "ids": [parsed_id] }]);
            let json_val = self
                .auth_post(http_client, "/auth/r/orders/hist", body)
                .await?;

            // Find the order matching our ID in the array of order arrays
            let orders = json_val
                .as_array()
                .ok_or_else(|| format!("Bitfinex: order {} not found in history", order_id))?;

            let o = orders
                .iter()
                .find(|ord| {
                    ord.as_array()
                        .map(|a| a.first().and_then(|v| v.as_i64()) == Some(parsed_id))
                        .unwrap_or(false)
                })
                .ok_or_else(|| {
                    format!("Bitfinex: order {} not found in history ({} orders returned)", order_id, orders.len())
                })?;

            // Parse array-format order:
            // [0] id, [6] amount (original, signed), [13] status,
            // [15] executed_amount, [17] avg_price
            let arr = o.as_array().ok_or_else(|| {
                format!("Bitfinex: expected array-format order for id {}, got non-array value", order_id)
            })?;
            let executed_qty = parse_json_decimal(
                arr.get(15).unwrap_or(&Value::Null),
            );
            let avg_price = parse_json_decimal(
                arr.get(17).unwrap_or(&Value::Null),
            );
            let bfx_status: &str = arr
                .get(13)
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN");
            let success = matches!(
                bfx_status.to_uppercase().as_str(),
                "EXECUTED" | "PARTIALLY FILLED" | "ACTIVE"
            );

            Ok(OrderResult {
                success,
                order_id: Some(order_id.to_string()),
                filled_qty: executed_qty.abs(),
                avg_price: avg_price.abs(),
                error: if success { None } else { Some(format!("unfilled: {}", bfx_status)) },
            })
        }
    }

    /// Parse a Decimal from a JSON Value (string, i64, or f64).
    /// WARNING: Legacy function — uses silent ZERO fallback with warning logs.
    fn parse_json_decimal(v: &Value) -> Decimal {
        use std::str::FromStr;
        if let Some(s) = v.as_str() {
            match Decimal::from_str(s) {
                Ok(d) => d,
                Err(_) => {
                    tracing::warn!(raw = %s, "legacy parse_json_decimal: string parse failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else if let Some(n) = v.as_i64() {
            Decimal::from(n)
        } else if let Some(f) = v.as_f64() {
            match rust_decimal::prelude::FromPrimitive::from_f64(f) {
                Some(d) => d,
                None => {
                    tracing::warn!(raw = %f, "legacy parse_json_decimal: f64->Decimal failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else {
            tracing::warn!(raw = %v, "legacy parse_json_decimal: unexpected JSON type, defaulting to ZERO");
            Decimal::ZERO
        }
    }
}

// ---------------------------------------------------------------------------
// kraken — Kraken private client (nonce-based HMAC-SHA512 + base64)
// ---------------------------------------------------------------------------

pub mod kraken {
    use async_trait::async_trait;
    use base64::Engine;
    use ring::hmac;
    use rust_decimal::Decimal;
    use serde_json::Value;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::exchange::config::SecretString;
    use crate::signer::{
        OrderRequest, OrderResult, OrderSide, OrderType, PrivateExchangeClient,
    };

    const DEFAULT_REST_URL: &str = "https://api.kraken.com";

    /// Kraken private client for the HFT execution engine.
    ///
    /// Uses HMAC-SHA512 with a base64-decoded API secret and produces
    /// base64-encoded signatures.  Requires a monotonic nonce counter.
    pub struct KrakenPrivateClient {
        id: u16,
        api_key: SecretString,
        api_secret: SecretString,
        rest_url: String,
        nonce_counter: AtomicU64,
    }

    impl std::fmt::Debug for KrakenPrivateClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("KrakenPrivateClient")
                .field("id", &self.id)
                .field("api_key", &self.api_key)
                .field("rest_url", &self.rest_url)
                .finish()
        }
    }

    impl KrakenPrivateClient {
        /// Create a new Kraken private client.
        ///
        /// `api_secret` is expected in the base64-encoded form issued by Kraken.
        pub fn new(api_key: &str, api_secret: &str) -> Result<Self, String> {
            let initial_nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| format!("Kraken: system clock error: {}", e))?
                .as_millis() as u64;
            Ok(Self {
                id: 10,
                api_key: SecretString::new(api_key),
                api_secret: SecretString::new(api_secret),
                rest_url: DEFAULT_REST_URL.to_string(),
                nonce_counter: AtomicU64::new(initial_nonce),
            })
        }

        /// Generate a strictly monotonic nonce.
        fn next_nonce(&self) -> u64 {
            self.nonce_counter.fetch_add(1, Ordering::SeqCst) + 1
        }

        /// Build a Kraken HMAC-SHA512 signature.
        ///
        /// Preimage: `{nonce}{path}{body}`.
        /// Secret is base64-decoded; result is base64-encoded.
        fn sign(&self, path: &str, nonce: &str, body: &str) -> Result<String, String> {
            let preimage = format!("{}{}{}", nonce, path, body);
            let key_bytes = base64::engine::general_purpose::STANDARD
                .decode(self.api_secret.expose())
                .map_err(|e| format!("Kraken: failed to decode api_secret: {}", e))?;
            let key = hmac::Key::new(hmac::HMAC_SHA512, &key_bytes);
            let sig = hmac::sign(&key, preimage.as_bytes());
            Ok(base64::engine::general_purpose::STANDARD.encode(sig.as_ref()))
        }

        /// Convert symbol like "BTC/USDT" to Kraken pair format "XBTUSDT".
        /// Kraken uses XBT instead of BTC.
        fn kraken_pair(symbol: &str) -> String {
            symbol.replace("BTC/", "XBT/").replace('/', "")
        }

        /// Derive a deterministic userref from a client_order_id using FNV-1a.
        fn derive_userref(client_order_id: Option<&String>) -> i64 {
            if let Some(coid) = client_order_id {
                if !coid.is_empty() {
                    if let Ok(n) = coid.parse::<i64>() {
                        return n;
                    }
                    let mut hash: u64 = 0xcbf29ce484222325;
                    for byte in coid.as_bytes() {
                        hash ^= *byte as u64;
                        hash = hash.wrapping_mul(0x100000001b3);
                    }
                    let masked = (hash & 0x7FFFFFFF) as i64;
                    return if masked == 0 { 1 } else { masked };
                }
            }
            0
        }

        /// Send an authenticated POST request to Kraken.
        async fn auth_post(
            &self,
            http_client: &reqwest::Client,
            path: &str,
            body: String,
        ) -> Result<Value, String> {
            let nonce = self.next_nonce().to_string();
            let body_with_nonce = if body.is_empty() {
                format!("nonce={}", nonce)
            } else {
                format!("nonce={}&{}", nonce, body)
            };
            let signature = self.sign(path, &nonce, &body_with_nonce)?;

            let resp = http_client
                .post(format!("{}{}", self.rest_url, path))
                .header("API-Key", self.api_key.expose())
                .header("API-Sign", &signature)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body_with_nonce)
                .send()
                .await
                .map_err(|e| format!("Kraken auth_post request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("Kraken auth_post read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("Kraken auth_post HTTP {}: {}", status, resp_text));
            }

            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("Kraken auth_post JSON parse failed: {}", e))?;

            // Kraken returns errors in an "error" array even with HTTP 200
            if let Some(errs) = json_val["error"].as_array() {
                if !errs.is_empty() {
                    let err_str: Vec<String> =
                        errs.iter().map(|v| v.to_string()).collect();
                    return Err(format!("Kraken API error: {}", err_str.join(", ")));
                }
            }

            Ok(json_val)
        }
    }

    #[async_trait]
    impl PrivateExchangeClient for KrakenPrivateClient {
        fn id(&self) -> u16 {
            self.id
        }

        async fn submit_order(
            &self,
            http_client: &reqwest::Client,
            order: OrderRequest,
        ) -> Result<OrderResult, String> {
            let side = match order.side {
                OrderSide::Buy => "buy",
                OrderSide::Sell => "sell",
            };
            let ordertype = match order.order_type {
                OrderType::Market => "market",
                OrderType::Limit => "limit",
                OrderType::Fok => "market", // Kraken has no native FOK; approximate with market
                OrderType::IoC => "market", // Kraken approximates IOC with market
            };
            let pair = Self::kraken_pair(&order.symbol);
            let userref = Self::derive_userref(order.client_order_id.as_ref());

            let mut body = format!(
                "ordertype={}&type={}&volume={}&pair={}",
                ordertype, side, order.quantity, pair
            );

            if order.order_type == OrderType::Limit {
                let price = order
                    .price
                    .ok_or_else(|| "Kraken: limit order requires a price".to_string())?;
                body = format!("{}&price={}", body, price);
            }

            if userref != 0 {
                body = format!("{}&userref={}", body, userref);
            }

            let json_val = self
                .auth_post(http_client, "/0/private/AddOrder", body)
                .await?;

            let txid = json_val["result"]["txid"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let has_id = txid.is_some();

            Ok(OrderResult {
                success: has_id,
                order_id: txid,
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: if has_id {
                    None
                } else {
                    Some("Kraken: missing txid in response".to_string())
                },
            })
        }

        async fn get_balance(
            &self,
            http_client: &reqwest::Client,
            asset: &str,
        ) -> Result<Decimal, String> {
            // Kraken uses XBT instead of BTC
            let kraken_asset = if asset.eq_ignore_ascii_case("BTC") {
                "XBT"
            } else {
                asset
            };

            let json_val = self
                .auth_post(http_client, "/0/private/Balance", String::new())
                .await?;

            let result = json_val["result"]
                .as_object()
                .ok_or_else(|| "Kraken: missing result in balance response".to_string())?;

            for (key, val) in result {
                if key.eq_ignore_ascii_case(kraken_asset) {
                    let bal = val
                        .as_str()
                        .and_then(|s| s.parse::<Decimal>().ok())
                        .unwrap_or(Decimal::ZERO);
                    return Ok(bal);
                }
            }

            Err(format!("Kraken: asset '{}' not found in balance", asset))
        }

        async fn cancel_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let body = format!("txid={}", order_id);
            self.auth_post(http_client, "/0/private/CancelOrder", body)
                .await?;

            Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: None,
            })
        }

        async fn query_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let body = format!("txid={}", order_id);
            let json_val = self
                .auth_post(http_client, "/0/private/QueryOrders", body)
                .await?;

            let order_data = &json_val["result"][order_id];
            if order_data.is_null() {
                return Err(format!(
                    "Kraken: order {} not found in query response",
                    order_id
                ));
            }

            let vol_exec = parse_json_decimal(&order_data["vol_exec"]);
            let avg_price = if order_data["avg_price"].as_str().is_some() {
                parse_json_decimal(&order_data["avg_price"])
            } else {
                parse_json_decimal(&order_data["price"])
            };

            // FIX: Inspect the actual order status instead of always returning
            // success=true.  Kraken statuses: "open", "closed", "canceled",
            // "expired".  Only "closed" means fully or partially filled.
            let status_str = order_data["status"].as_str().unwrap_or("UNKNOWN");
            let success = matches!(status_str, "closed" | "open" | "partially filled");

            Ok(OrderResult {
                success,
                order_id: Some(order_id.to_string()),
                filled_qty: vol_exec,
                avg_price,
                error: if success { None } else { Some(format!("status: {}", status_str)) },
            })
        }
    }

    /// Parse a Decimal from a JSON Value (string, i64, or f64).
    /// WARNING: Legacy function — uses silent ZERO fallback with warning logs.
    fn parse_json_decimal(v: &Value) -> Decimal {
        use std::str::FromStr;
        if let Some(s) = v.as_str() {
            match Decimal::from_str(s) {
                Ok(d) => d,
                Err(_) => {
                    tracing::warn!(raw = %s, "legacy parse_json_decimal: string parse failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else if let Some(n) = v.as_i64() {
            Decimal::from(n)
        } else if let Some(f) = v.as_f64() {
            match rust_decimal::prelude::FromPrimitive::from_f64(f) {
                Some(d) => d,
                None => {
                    tracing::warn!(raw = %f, "legacy parse_json_decimal: f64->Decimal failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else {
            tracing::warn!(raw = %v, "legacy parse_json_decimal: unexpected JSON type, defaulting to ZERO");
            Decimal::ZERO
        }
    }
}

// ---------------------------------------------------------------------------
// htx — HTX (Huobi) private client (HMAC-SHA256 signed URL)
// ---------------------------------------------------------------------------

pub mod htx {
    use async_trait::async_trait;
    use chrono::Utc;
    use ring::hmac;
    use rust_decimal::Decimal;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::exchange::config::SecretString;
    use crate::signer::{
        OrderRequest, OrderResult, OrderSide, OrderType, PrivateExchangeClient,
    };

    const DEFAULT_REST_URL: &str = "https://api.huobi.pro";

    /// HTX private client for the HFT execution engine.
    ///
    /// Uses HMAC-SHA256 with signed URL parameters (METHOD\nhost\npath\nquery).
    /// Requires account-id which is fetched and cached on first use.
    pub struct HtxPrivateClient {
        id: u16,
        api_key: SecretString,
        api_secret: SecretString,
        rest_url: String,
        /// Cached account-id fetched from HTX on first authenticated call.
        account_id: AtomicU64,
        /// Monotonic nonce/timestamp counter.
        nonce_counter: AtomicU64,
    }

    impl std::fmt::Debug for HtxPrivateClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HtxPrivateClient")
                .field("id", &self.id)
                .field("api_key", &self.api_key)
                .field("rest_url", &self.rest_url)
                .finish()
        }
    }

    impl HtxPrivateClient {
        /// Create a new HTX private client.
        pub fn new(api_key: &str, api_secret: &str) -> Result<Self, String> {
            let initial_nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| format!("HTX: system clock error: {}", e))?
                .as_millis() as u64;
            Ok(Self {
                id: 9,
                api_key: SecretString::new(api_key),
                api_secret: SecretString::new(api_secret),
                rest_url: DEFAULT_REST_URL.to_string(),
                account_id: AtomicU64::new(0),
                nonce_counter: AtomicU64::new(initial_nonce),
            })
        }

        /// Generate a strictly monotonic timestamp (ms).
        fn next_timestamp(&self) -> String {
            let now = Utc::now().timestamp_millis() as u64;
            let prev = self.nonce_counter.fetch_max(now, Ordering::SeqCst);
            let ts = if now > prev { now } else { prev + 1 };
            self.nonce_counter.store(ts, Ordering::SeqCst);
            ts.to_string()
        }

        /// Build an HTX HMAC-SHA256 signature.
        ///
        /// Preimage: `{method}\n{host}\n{path}\n{query}`
        fn sign(&self, method: &str, host: &str, path: &str, query: &str) -> String {
            let preimage = format!("{}\n{}\n{}\n{}", method, host, path, query);
            let key = hmac::Key::new(hmac::HMAC_SHA256, self.api_secret.expose().as_bytes());
            let sig = hmac::sign(&key, preimage.as_bytes());
            hex::encode(sig.as_ref())
        }

        /// Extract the host from the rest_url.
        fn host(&self) -> String {
            self.rest_url
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .to_string()
        }

        /// Build a signed URL with authentication parameters.
        fn signed_url(
            &self,
            method: &str,
            path: &str,
            extra_params: &[(&str, String)],
        ) -> Result<String, String> {
            let ts = self.next_timestamp();
            let mut params: Vec<(&str, String)> = vec![
                ("AccessKeyId", self.api_key.expose().to_string()),
                ("SignatureMethod", "HmacSHA256".to_string()),
                ("SignatureVersion", "2".to_string()),
                ("Timestamp", ts),
            ];
            for (k, v) in extra_params {
                params.push((k, v.clone()));
            }
            params.sort_by(|a, b| a.0.cmp(b.0));
            let query: String = params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");
            let signature = self.sign(method, &self.host(), path, &query);
            let base = self.rest_url.trim_end_matches('/');
            Ok(format!(
                "{}{}?{}&Signature={}",
                base, path, query, signature
            ))
        }

        /// Ensure we have a cached HTX account-id.
        async fn ensure_account_id(
            &self,
            http_client: &reqwest::Client,
        ) -> Result<u64, String> {
            let cached = self.account_id.load(Ordering::Relaxed);
            if cached != 0 {
                return Ok(cached);
            }
            let url = self.signed_url("GET", "/v1/account/accounts", &[])?;
            let resp = http_client
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("HTX ensure_account_id request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("HTX ensure_account_id read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!(
                    "HTX ensure_account_id HTTP {}: {}",
                    status, resp_text
                ));
            }

            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("HTX ensure_account_id JSON parse failed: {}", e))?;

            let aid = json_val["data"][0]["id"]
                .as_u64()
                .ok_or_else(|| "HTX: failed to parse account-id".to_string())?;
            self.account_id.store(aid, Ordering::Relaxed);
            Ok(aid)
        }

        /// Convert "BTC/USDT" to HTX symbol format "btcusdt".
        fn htx_symbol(symbol: &str) -> String {
            symbol.replace('/', "").to_lowercase()
        }
    }

    #[async_trait]
    impl PrivateExchangeClient for HtxPrivateClient {
        fn id(&self) -> u16 {
            self.id
        }

        async fn submit_order(
            &self,
            http_client: &reqwest::Client,
            order: OrderRequest,
        ) -> Result<OrderResult, String> {
            let account_id = self.ensure_account_id(http_client).await?;
            let side = match order.side {
                OrderSide::Buy => "buy",
                OrderSide::Sell => "sell",
            };
            let order_type_str = match order.order_type {
                OrderType::Market => format!("{}-market", side),
                OrderType::Limit => format!("{}-limit", side),
                OrderType::Fok => format!("{}-fok", side),
                OrderType::IoC => format!("{}-ioc", side),
            };

            let mut body = json!({
                "account-id": account_id.to_string(),
                "amount": order.quantity.to_string(),
                "symbol": Self::htx_symbol(&order.symbol),
                "type": order_type_str,
            });

            if let Some(price) = order.price {
                body["price"] = json!(price.to_string());
            }
            if let Some(ref cl_ord_id) = order.client_order_id {
                if !cl_ord_id.is_empty() {
                    body["client-order-id"] = json!(cl_ord_id);
                }
            }

            let body_str = body.to_string();
            let url = self.signed_url("POST", "/v1/order/orders/place", &[])?;

            let resp = http_client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(body_str)
                .send()
                .await
                .map_err(|e| format!("HTX submit_order request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("HTX submit_order read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!(
                    "HTX submit_order HTTP {}: {}",
                    status, resp_text
                ));
            }

            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("HTX submit_order JSON parse failed: {}", e))?;

            let order_id = json_val["data"].as_str().map(|s| s.to_string());
            let has_id = order_id.is_some();

            Ok(OrderResult {
                success: has_id,
                order_id,
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: if has_id {
                    None
                } else {
                    Some("HTX: missing order ID in response".to_string())
                },
            })
        }

        async fn get_balance(
            &self,
            http_client: &reqwest::Client,
            asset: &str,
        ) -> Result<Decimal, String> {
            let accts_url = self.signed_url("GET", "/v1/account/accounts", &[])?;
            let resp = http_client
                .get(&accts_url)
                .send()
                .await
                .map_err(|e| format!("HTX get_balance accounts request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!(
                    "HTX get_balance accounts read body failed: {}",
                    e
                ))?;

            if !status.is_success() {
                return Err(format!(
                    "HTX get_balance accounts HTTP {}: {}",
                    status, resp_text
                ));
            }

            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| {
                    format!(
                        "HTX get_balance accounts JSON parse failed: {}",
                        e
                    )
                })?;

            // FIX: Propagate error instead of silently defaulting to account 0.
            // Using the wrong account ID returns the wrong balance.
            let account_id = json_val["data"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|a| a["id"].as_i64())
                .ok_or_else(|| "HTX: failed to parse account-id in get_balance".to_string())?;

            let bal_url = self.signed_url(
                "GET",
                &format!("/v1/account/accounts/{}/balance", account_id),
                &[],
            )?;
            let resp = http_client
                .get(&bal_url)
                .send()
                .await
                .map_err(|e| format!(
                    "HTX get_balance balance request failed: {}",
                    e
                ))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!(
                    "HTX get_balance balance read body failed: {}",
                    e
                ))?;

            if !status.is_success() {
                return Err(format!(
                    "HTX get_balance balance HTTP {}: {}",
                    status, resp_text
                ));
            }

            let json_val: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!(
                    "HTX get_balance balance JSON parse failed: {}",
                    e
                ))?;

            if let Some(arr) = json_val["data"]["list"].as_array() {
                for b in arr {
                    let currency = b["currency"].as_str().unwrap_or("");
                    if currency.eq_ignore_ascii_case(asset) {
                        let bal: f64 = b["balance"]
                            .as_str()
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0.0);
                        return Ok(
                            rust_decimal::prelude::FromPrimitive::from_f64(bal)
                                .unwrap_or(Decimal::ZERO),
                        );
                    }
                }
            }

            Err(format!(
                "HTX: asset '{}' not found in balance",
                asset
            ))
        }

        async fn cancel_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let url = self.signed_url(
                "POST",
                &format!("/v1/order/orders/{}/submitcancel", order_id),
                &[],
            )?;

            let resp = http_client
                .post(&url)
                .send()
                .await
                .map_err(|e| format!("HTX cancel_order request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("HTX cancel_order read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!(
                    "HTX cancel_order HTTP {}: {}",
                    status, resp_text
                ));
            }

            Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: None,
            })
        }

        async fn query_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let url = self.signed_url(
                "GET",
                &format!("/v1/order/orders/{}", order_id),
                &[],
            )?;

            let resp = http_client
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("HTX query_order request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("HTX query_order read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!(
                    "HTX query_order HTTP {}: {}",
                    status, resp_text
                ));
            }

            let v: Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("HTX query_order JSON parse failed: {}", e))?;

            let o = &v["data"];
            let filled_qty = parse_json_decimal(&o["field-amount"]);
            let field_cash = parse_json_decimal(&o["field-cash-amount"]);
            let avg_price = if filled_qty > Decimal::ZERO {
                field_cash / filled_qty
            } else {
                Decimal::ZERO
            };

            let status_str = o["state"].as_str().unwrap_or("UNKNOWN");
            let success = matches!(status_str, "submitted" | "partial-filled" | "filled");

            Ok(OrderResult {
                success,
                order_id: Some(order_id.to_string()),
                filled_qty,
                avg_price,
                error: if success {
                    None
                } else {
                    Some(format!("unfilled: {}", status_str))
                },
            })
        }
    }

    /// Parse a Decimal from a JSON Value (string, i64, or f64).
    /// WARNING: Legacy function — uses silent ZERO fallback with warning logs.
    fn parse_json_decimal(v: &Value) -> Decimal {
        use std::str::FromStr;
        if let Some(s) = v.as_str() {
            match Decimal::from_str(s) {
                Ok(d) => d,
                Err(_) => {
                    tracing::warn!(raw = %s, "legacy parse_json_decimal: string parse failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else if let Some(n) = v.as_i64() {
            Decimal::from(n)
        } else if let Some(f) = v.as_f64() {
            match rust_decimal::prelude::FromPrimitive::from_f64(f) {
                Some(d) => d,
                None => {
                    tracing::warn!(raw = %f, "legacy parse_json_decimal: f64->Decimal failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else {
            tracing::warn!(raw = %v, "legacy parse_json_decimal: unexpected JSON type, defaulting to ZERO");
            Decimal::ZERO
        }
    }
}

// ---------------------------------------------------------------------------
// lbank — LBank private client (sorted-param HMAC-SHA256)
// ---------------------------------------------------------------------------

pub mod lbank {
    use async_trait::async_trait;
    use chrono::Utc;
    use ring::hmac;
    use rust_decimal::Decimal;
    use serde_json::Value;

    use crate::exchange::config::SecretString;
    use crate::signer::{
        OrderRequest, OrderResult, OrderSide, OrderType, PrivateExchangeClient,
    };

    const DEFAULT_REST_URL: &str = "https://api.lbank.info";

    /// LBank private client for the HFT execution engine.
    ///
    /// Uses HMAC-SHA256 with sorted parameter strings.
    /// Params are form-encoded, sorted, and signed; `sign` and `sign_type`
    /// are appended to the body.
    pub struct LbankPrivateClient {
        id: u16,
        api_key: SecretString,
        api_secret: SecretString,
        rest_url: String,
    }

    impl std::fmt::Debug for LbankPrivateClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LbankPrivateClient")
                .field("id", &self.id)
                .field("api_key", &self.api_key)
                .field("rest_url", &self.rest_url)
                .finish()
        }
    }

    impl LbankPrivateClient {
        /// Create a new LBank private client.
        pub fn new(api_key: &str, api_secret: &str) -> Result<Self, String> {
            Ok(Self {
                id: 11,
                api_key: SecretString::new(api_key),
                api_secret: SecretString::new(api_secret),
                rest_url: DEFAULT_REST_URL.to_string(),
            })
        }

        /// Sign LBank parameters: sort by key, HMAC-SHA256, append sign + sign_type.
        fn sign_params(&self, params: &mut Vec<(&str, String)>) -> Result<String, String> {
            params.sort_by(|a, b| a.0.cmp(b.0));
            let plain: String = params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");
            let key =
                hmac::Key::new(hmac::HMAC_SHA256, self.api_secret.expose().as_bytes());
            let sig = hmac::sign(&key, plain.as_bytes());
            let signature = hex::encode(sig.as_ref());
            Ok(format!("{}&sign={}&sign_type=1", plain, signature))
        }

        /// Convert "BTC/USDT" to LBank symbol format "btc_usdt".
        fn lbank_symbol(symbol: &str) -> String {
            symbol.replace('/', "_").to_lowercase()
        }

        /// Send an authenticated POST request to LBank.
        async fn signed_post(
            &self,
            http_client: &reqwest::Client,
            path: &str,
            mut params: Vec<(&str, String)>,
        ) -> Result<Value, String> {
            let signed_body = self.sign_params(&mut params)?;
            let url = format!(
                "{}{}",
                self.rest_url.trim_end_matches('/'),
                path
            );

            let resp = http_client
                .post(&url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(signed_body)
                .send()
                .await
                .map_err(|e| format!("LBank signed_post request failed: {}", e))?;

            let status = resp.status();
            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("LBank signed_post read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!(
                    "LBank signed_post HTTP {}: {}",
                    status, resp_text
                ));
            }

            serde_json::from_str(&resp_text)
                .map_err(|e| format!("LBank signed_post JSON parse failed: {}", e))
        }
    }

    #[async_trait]
    impl PrivateExchangeClient for LbankPrivateClient {
        fn id(&self) -> u16 {
            self.id
        }

        async fn submit_order(
            &self,
            http_client: &reqwest::Client,
            order: OrderRequest,
        ) -> Result<OrderResult, String> {
            let side = match order.side {
                OrderSide::Buy => "buy",
                OrderSide::Sell => "sell",
            };
            let order_type = match order.order_type {
                OrderType::Market => "market",
                OrderType::Limit => "limit",
                OrderType::Fok => "market", // LBank V2 has no explicit FOK
                OrderType::IoC => "market", // LBank V2 has no explicit IOC
            };

            let custom_id = order.client_order_id.as_deref().unwrap_or("");

            let mut params: Vec<(&str, String)> = vec![
                ("amount", order.quantity.to_string()),
                ("api_key", self.api_key.expose().to_string()),
                ("symbol", Self::lbank_symbol(&order.symbol)),
                ("timestamp", Utc::now().timestamp_millis().to_string()),
                ("type", side.to_string()),
            ];

            if order_type == "limit" {
                if let Some(price) = order.price {
                    params.push(("price", price.to_string()));
                }
            }
            if !custom_id.is_empty() {
                params.push(("custom_id", custom_id.to_string()));
            }

            let json_val = self
                .signed_post(http_client, "/v2/create_order.do", params)
                .await?;

            let order_id = json_val["data"].as_str().map(|s| s.to_string());
            let has_id = order_id.is_some();

            Ok(OrderResult {
                success: has_id,
                order_id,
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: if has_id {
                    None
                } else {
                    Some("LBank: missing order ID in response".to_string())
                },
            })
        }

        async fn get_balance(
            &self,
            http_client: &reqwest::Client,
            asset: &str,
        ) -> Result<Decimal, String> {
            let params: Vec<(&str, String)> = vec![
                ("api_key", self.api_key.expose().to_string()),
                ("timestamp", Utc::now().timestamp_millis().to_string()),
            ];

            let json_val = self
                .signed_post(http_client, "/v2/user_info.do", params)
                .await?;

            if let Some(funds) = json_val["data"]["funds"].as_object() {
                if let Some(free) = funds.get("free").and_then(|v| v.as_object()) {
                    for (key, val) in free {
                        if key.eq_ignore_ascii_case(asset) {
                            let amount: f64 = val
                                .as_str()
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0.0);
                            return Ok(
                                rust_decimal::prelude::FromPrimitive::from_f64(
                                    amount,
                                )
                                .unwrap_or(Decimal::ZERO),
                            );
                        }
                    }
                }
            }

            Err(format!(
                "LBank: asset '{}' not found in balance",
                asset
            ))
        }

        async fn cancel_order(
            &self,
            http_client: &reqwest::Client,
            symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let params: Vec<(&str, String)> = vec![
                ("api_key", self.api_key.expose().to_string()),
                ("order_id", order_id.to_string()),
                ("symbol", Self::lbank_symbol(symbol)),
                ("timestamp", Utc::now().timestamp_millis().to_string()),
            ];

            self.signed_post(http_client, "/v2/cancel_order.do", params)
                .await?;

            Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: None,
            })
        }

        async fn query_order(
            &self,
            http_client: &reqwest::Client,
            symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let params: Vec<(&str, String)> = vec![
                ("api_key", self.api_key.expose().to_string()),
                ("order_id", order_id.to_string()),
                ("symbol", Self::lbank_symbol(symbol)),
                ("timestamp", Utc::now().timestamp_millis().to_string()),
            ];

            let json_val = self
                .signed_post(http_client, "/v2/orders_info.do", params)
                .await?;

            let order = &json_val["data"][0];
            let filled_qty = parse_json_decimal(&order["dealQuantity"]);
            let avg_price = parse_json_decimal(&order["avgPrice"]);
            let status_code = order["status"].as_u64().unwrap_or_else(|| {
                tracing::warn!(exchange = "LBank (legacy)", raw = %order["status"],
                    "order status missing — treating as UNKNOWN to prevent phantom order");
                99 // 99 is not in 0|1|2, so success=false
            });
            let success = matches!(status_code, 0 | 1 | 2); // 0=NEW, 1=PARTIAL, 2=FILLED

            Ok(OrderResult {
                success,
                order_id: Some(order_id.to_string()),
                filled_qty,
                avg_price,
                error: if success {
                    None
                } else {
                    Some(format!("unfilled: status={}", status_code))
                },
            })
        }
    }

    /// Parse a Decimal from a JSON Value (string, i64, or f64).
    /// WARNING: Legacy function — uses silent ZERO fallback with warning logs.
    fn parse_json_decimal(v: &Value) -> Decimal {
        use std::str::FromStr;
        if let Some(s) = v.as_str() {
            match Decimal::from_str(s) {
                Ok(d) => d,
                Err(_) => {
                    tracing::warn!(raw = %s, "legacy parse_json_decimal: string parse failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else if let Some(n) = v.as_i64() {
            Decimal::from(n)
        } else if let Some(f) = v.as_f64() {
            match rust_decimal::prelude::FromPrimitive::from_f64(f) {
                Some(d) => d,
                None => {
                    tracing::warn!(raw = %f, "legacy parse_json_decimal: f64->Decimal failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else {
            tracing::warn!(raw = %v, "legacy parse_json_decimal: unexpected JSON type, defaulting to ZERO");
            Decimal::ZERO
        }
    }
}

// ---------------------------------------------------------------------------
// bitstamp — full Bitstamp implementation
// ---------------------------------------------------------------------------

pub mod bitstamp {
    use async_trait::async_trait;
    use chrono::Utc;
    use ring::hmac;
    use rust_decimal::prelude::FromPrimitive;
    use rust_decimal::Decimal;
    use serde_json::Value;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::exchange::config::SecretString;
    use crate::signer::{
        OrderRequest, OrderResult, OrderSide, OrderType, PrivateExchangeClient,
    };

    const DEFAULT_REST_URL: &str = "https://www.bitstamp.net";

    /// Bitstamp private client for the HFT execution engine.
    ///
    /// Uses HMAC-SHA256 with a monotonic nonce.  The preimage is:
    ///   nonce + api_key + "POST/api/v2/" + content_type + url_path + body
    /// Sent as hex via X-Auth-* headers plus form-encoded body containing
    /// key, signature, and nonce.
    pub struct BitstampPrivateClient {
        id: u16,
        api_key: SecretString,
        api_secret: SecretString,
        rest_url: String,
        nonce_counter: AtomicU64,
    }

    impl std::fmt::Debug for BitstampPrivateClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BitstampPrivateClient")
                .field("id", &self.id)
                .field("api_key", &self.api_key)
                .field("rest_url", &self.rest_url)
                .finish()
        }
    }

    impl BitstampPrivateClient {
        pub fn new(api_key: &str, api_secret: &str) -> Result<Self, String> {
            let initial_nonce = Utc::now().timestamp_millis() as u64;
            Ok(Self {
                id: 12,
                api_key: SecretString::new(api_key),
                api_secret: SecretString::new(api_secret),
                rest_url: DEFAULT_REST_URL.to_string(),
                nonce_counter: AtomicU64::new(initial_nonce),
            })
        }

        /// Next monotonic nonce.
        fn next_nonce(&self) -> u64 {
            self.nonce_counter.fetch_add(1, Ordering::Relaxed)
        }

        /// Convert internal symbol (BTC/USDT) to Bitstamp format (btcusdt).
        fn bitstamp_symbol(symbol: &str) -> String {
            symbol.replace('/', "").to_lowercase()
        }

        /// Sign a Bitstamp v2 request.
        ///
        /// preimage = nonce + api_key + "POST/api/v2/" + content_type + url_path + body
        fn sign(&self, nonce_str: &str, url_path: &str, body: &str) -> String {
            let content_type = "application/x-www-form-urlencoded";
            let preimage = format!(
                "{}{}POST/api/v2/{}{}{}",
                nonce_str,
                self.api_key.expose(),
                url_path,
                content_type,
                body
            );
            let key = hmac::Key::new(hmac::HMAC_SHA256, self.api_secret.expose().as_bytes());
            let sig = hmac::sign(&key, preimage.as_bytes());
            hex::encode(sig.as_ref())
        }

        /// Send a signed POST to Bitstamp.
        async fn send_signed_post(
            &self,
            http_client: &reqwest::Client,
            url_path: &str,
            body: &str,
        ) -> Result<Value, String> {
            let nonce = self.next_nonce();
            let nonce_str = nonce.to_string();
            let signature = self.sign(&nonce_str, url_path, body);

            let full_body = if body.is_empty() {
                format!(
                    "key={}&signature={}&nonce={}",
                    self.api_key.expose(),
                    signature,
                    nonce_str
                )
            } else {
                format!(
                    "key={}&signature={}&nonce={}&{}",
                    self.api_key.expose(),
                    signature,
                    nonce_str,
                    body
                )
            };

            let url = format!("{}/api/v2/{}", self.rest_url, url_path);
            let resp = http_client
                .post(&url)
                .header("X-Auth", self.api_key.expose())
                .header("X-Auth-Sign", &signature)
                .header("X-Auth-Nonce", &nonce_str)
                .header("X-Auth-Version", "2")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(full_body)
                .send()
                .await
                .map_err(|e| format!("Bitstamp request failed: {}", e))?;

            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| format!("Bitstamp read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("Bitstamp HTTP {}: {}", status, text));
            }

            serde_json::from_str(&text)
                .map_err(|e| format!("Bitstamp JSON parse failed: {}", e))
        }
    }

    #[async_trait]
    impl PrivateExchangeClient for BitstampPrivateClient {
        fn id(&self) -> u16 {
            self.id
        }

        async fn submit_order(
            &self,
            http_client: &reqwest::Client,
            order: OrderRequest,
        ) -> Result<OrderResult, String> {
            let pair = Self::bitstamp_symbol(&order.symbol);
            let side = match order.side {
                OrderSide::Buy => "buy",
                OrderSide::Sell => "sell",
            };
            let order_type = match order.order_type {
                OrderType::Market => "market",
                _ => "limit",
            };

            let mut body = format!(
                "type={}&amount={}&side={}",
                order_type, order.quantity, side
            );
            if let Some(price) = order.price {
                body.push_str(&format!("&price={}", price));
            }

            let json_val = self
                .send_signed_post(http_client, &format!("{}/order/", pair), &body)
                .await?;

            let order_id = json_val["id"].as_str().map(String::from);
            let has_id = order_id.is_some();

            Ok(OrderResult {
                success: has_id,
                order_id,
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: if has_id {
                    None
                } else {
                    Some("Bitstamp: missing order ID in response".to_string())
                },
            })
        }

        async fn get_balance(
            &self,
            http_client: &reqwest::Client,
            asset: &str,
        ) -> Result<Decimal, String> {
            let json_val = self
                .send_signed_post(http_client, "balance/", "")
                .await?;

            let asset_lower = asset.to_lowercase();
            let avail_key = format!("{}_available", asset_lower);
            let bal_key = format!("{}_balance", asset_lower);

            if let Some(val) = json_val[&avail_key].as_f64() {
                return Ok(Decimal::from_f64(val).unwrap_or(Decimal::ZERO));
            }
            if let Some(val) = json_val[&bal_key].as_f64() {
                return Ok(Decimal::from_f64(val).unwrap_or(Decimal::ZERO));
            }

            Err(format!("Bitstamp: asset '{}' not found in balance", asset))
        }

        async fn cancel_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let body = format!("id={}", order_id);
            self.send_signed_post(http_client, "order/cancel/", &body)
                .await?;

            Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: None,
            })
        }

        async fn query_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let body = format!("id={}", order_id);
            let json_val = self
                .send_signed_post(http_client, "order/status/", &body)
                .await?;

            let status_str = json_val["status"]
                .as_str()
                .or_else(|| json_val["transaction_status"].as_str())
                .unwrap_or("Unknown");
            let filled = parse_json_decimal(&json_val["amount_filled"]);
            let avg = parse_json_decimal(&json_val["price"]);

            // FIX: Only "Finished" means the order was actually filled.
            // Cancelled orders have zero fills and must not be reported as successful.
            let success = status_str == "Finished";

            Ok(OrderResult {
                success,
                order_id: Some(order_id.to_string()),
                filled_qty: filled,
                avg_price: avg,
                error: if success { None } else { Some(format!("unfilled: {}", status_str)) },
            })
        }
    }

    /// WARNING: Legacy function — uses silent ZERO fallback with warning logs.
    fn parse_json_decimal(v: &Value) -> Decimal {
        use std::str::FromStr;
        if let Some(s) = v.as_str() {
            match Decimal::from_str(s) {
                Ok(d) => d,
                Err(_) => {
                    tracing::warn!(raw = %s, "legacy parse_json_decimal: string parse failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else if let Some(n) = v.as_i64() {
            Decimal::from(n)
        } else if let Some(f) = v.as_f64() {
            match FromPrimitive::from_f64(f) {
                Some(d) => d,
                None => {
                    tracing::warn!(raw = %f, "legacy parse_json_decimal: f64->Decimal failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else {
            tracing::warn!(raw = %v, "legacy parse_json_decimal: unexpected JSON type, defaulting to ZERO");
            Decimal::ZERO
        }
    }
}

// ---------------------------------------------------------------------------
// deribit — full Deribit JSON-RPC implementation
// ---------------------------------------------------------------------------

pub mod deribit {
    use async_trait::async_trait;
    use chrono::Utc;
    use ring::hmac;
    use rust_decimal::Decimal;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::exchange::config::SecretString;
    use crate::signer::{
        OrderRequest, OrderResult, OrderSide, OrderType, PrivateExchangeClient,
    };

    const DEFAULT_REST_URL: &str = "https://www.deribit.com";

    /// Deribit private client for the HFT execution engine.
    ///
    /// Uses JSON-RPC 2.0 over HTTPS.  Authentication is done via
    /// `public/auth` which returns a Bearer token cached for subsequent
    /// private calls.  The auth signature is:
    ///   HMAC-SHA256(api_secret, nonce + api_key + timestamp)
    pub struct DeribitPrivateClient {
        id: u16,
        api_key: SecretString,
        api_secret: SecretString,
        rest_url: String,
        rpc_id: AtomicU64,
        /// Cached Bearer token (simple in-memory cache, no expiry tracking).
        access_token: tokio::sync::Mutex<Option<String>>,
    }

    impl std::fmt::Debug for DeribitPrivateClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DeribitPrivateClient")
                .field("id", &self.id)
                .field("api_key", &self.api_key)
                .field("rest_url", &self.rest_url)
                .finish()
        }
    }

    impl DeribitPrivateClient {
        pub fn new(api_key: &str, api_secret: &str) -> Result<Self, String> {
            Ok(Self {
                id: 13,
                api_key: SecretString::new(api_key),
                api_secret: SecretString::new(api_secret),
                rest_url: DEFAULT_REST_URL.to_string(),
                rpc_id: AtomicU64::new(1),
                access_token: tokio::sync::Mutex::new(None),
            })
        }

        fn next_rpc_id(&self) -> u64 {
            self.rpc_id.fetch_add(1, Ordering::Relaxed)
        }

        /// Authenticate and cache the Bearer token.
        async fn ensure_auth(
            &self,
            http_client: &reqwest::Client,
        ) -> Result<String, String> {
            {
                let guard = self.access_token.lock().await;
                if let Some(ref token) = *guard {
                    return Ok(token.clone());
                }
            }

            let id = self.next_rpc_id();
            let nonce = Utc::now().timestamp_millis().to_string();
            let timestamp = nonce.clone();

            let preimage = format!(
                "{}{}{}",
                nonce,
                self.api_key.expose(),
                timestamp
            );
            let key = hmac::Key::new(hmac::HMAC_SHA256, self.api_secret.expose().as_bytes());
            let sig = hmac::sign(&key, preimage.as_bytes());
            let signature = hex::encode(sig.as_ref());

            let body = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "public/auth",
                "params": {
                    "grant_type": "client_credentials",
                    "client_id": self.api_key.expose(),
                    "client_secret": self.api_secret.expose(),
                    "timestamp": timestamp,
                    "signature": signature,
                    "nonce": nonce,
                }
            })
            .to_string();

            let url = format!("{}/api/v2/public/auth", self.rest_url);
            let resp = http_client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(|e| format!("Deribit auth request failed: {}", e))?;

            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| format!("Deribit auth read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("Deribit auth HTTP {}: {}", status, text));
            }

            let v: Value = serde_json::from_str(&text)
                .map_err(|e| format!("Deribit auth JSON parse failed: {}", e))?;

            if let Some(err) = v.get("error") {
                let msg = err["message"].as_str().unwrap_or("unknown auth error");
                return Err(format!("Deribit auth RPC error: {}", msg));
            }

            let token = v["result"]["access_token"]
                .as_str()
                .ok_or("Deribit auth failed: no access_token in response")?
                .to_string();

            {
                let mut guard = self.access_token.lock().await;
                *guard = Some(token.clone());
            }

            Ok(token)
        }

        /// Send a JSON-RPC private call.
        async fn call_private(
            &self,
            http_client: &reqwest::Client,
            method: &str,
            params: Value,
        ) -> Result<Value, String> {
            let token = self.ensure_auth(http_client).await?;
            let id = self.next_rpc_id();
            let body = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params,
            })
            .to_string();

            let url = format!("{}/api/v2/{}", self.rest_url, method);
            let resp = http_client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(body)
                .send()
                .await
                .map_err(|e| format!("Deribit {} request failed: {}", method, e))?;

            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| format!("Deribit {} read body failed: {}", method, e))?;

            if !status.is_success() {
                return Err(format!("Deribit {} HTTP {}: {}", method, status, text));
            }

            let v: Value = serde_json::from_str(&text)
                .map_err(|e| format!("Deribit {} JSON parse failed: {}", method, e))?;

            if let Some(err) = v.get("error") {
                let msg = err["message"].as_str().unwrap_or("unknown RPC error");
                let code = err["code"].as_i64().unwrap_or(0);
                // Clear cached token on auth errors
                if code == -32602 || msg.contains("token") || msg.contains("auth") {
                    let mut guard = self.access_token.lock().await;
                    *guard = None;
                }
                return Err(format!("Deribit RPC error ({}): {}", method, msg));
            }

            Ok(v)
        }
    }

    #[async_trait]
    impl PrivateExchangeClient for DeribitPrivateClient {
        fn id(&self) -> u16 {
            self.id
        }

        async fn submit_order(
            &self,
            http_client: &reqwest::Client,
            order: OrderRequest,
        ) -> Result<OrderResult, String> {
            let rpc_method = match order.side {
                OrderSide::Buy => "private/buy",
                OrderSide::Sell => "private/sell",
            };
            let instrument = order.symbol.replace('/', "-");

            let mut params = json!({
                "instrument_name": instrument,
                "amount": order.quantity.to_string(),
                "type": "market",
            });

            if let Some(price) = order.price {
                params["type"] = json!("limit");
                params["price"] = json!(price.to_string());
            }

            let v = self
                .call_private(http_client, rpc_method, params)
                .await?;

            let order_result = &v["result"]["order"];
            let order_id = order_result["order_id"].as_str().map(String::from);
            let has_id = order_id.is_some();

            Ok(OrderResult {
                success: has_id,
                order_id,
                filled_qty: parse_json_decimal(&order_result["filled_amount"]),
                avg_price: parse_json_decimal(&order_result["average_price"]),
                error: if has_id {
                    None
                } else {
                    Some("Deribit: missing order ID in response".to_string())
                },
            })
        }

        async fn get_balance(
            &self,
            http_client: &reqwest::Client,
            asset: &str,
        ) -> Result<Decimal, String> {
            // FIX: Use the requested asset instead of hardcoding BTC.
            // Deribit uses currency names like "BTC", "ETH", "USDC", etc.
            let asset_upper = asset.to_uppercase();
            let currency = match asset_upper.as_str() {
                "USDT" => "USDC",  // Deribit uses USDC as the stablecoin name
                other => other,
            };
            let params = json!({ "currency": currency });
            let v = self
                .call_private(http_client, "private/get_account_summary", params)
                .await?;

            Ok(parse_json_decimal(&v["result"]["equity"]))
        }

        async fn cancel_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let params = json!({ "order_id": order_id });
            self.call_private(http_client, "private/cancel", params)
                .await?;

            Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: None,
            })
        }

        async fn query_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let params = json!({ "order_id": order_id });
            let v = self
                .call_private(http_client, "private/get_order_state", params)
                .await?;

            let order = &v["result"]["order"];
            let status_str = order["state"].as_str().unwrap_or("unknown");
            let success = matches!(status_str, "filled");
            let filled = parse_json_decimal(&order["filled_amount"]);
            let avg = parse_json_decimal(&order["average_price"]);

            Ok(OrderResult {
                success,
                order_id: Some(order_id.to_string()),
                filled_qty: filled,
                avg_price: avg,
                error: if success { None } else { Some(format!("unfilled: {}", status_str)) },
            })
        }
    }

    /// WARNING: Legacy function — uses silent ZERO fallback with warning logs.
    fn parse_json_decimal(v: &Value) -> Decimal {
        use std::str::FromStr;
        if let Some(s) = v.as_str() {
            match Decimal::from_str(s) {
                Ok(d) => d,
                Err(_) => {
                    tracing::warn!(raw = %s, "legacy parse_json_decimal: string parse failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else if let Some(n) = v.as_i64() {
            Decimal::from(n)
        } else if let Some(f) = v.as_f64() {
            match rust_decimal::prelude::FromPrimitive::from_f64(f) {
                Some(d) => d,
                None => {
                    tracing::warn!(raw = %f, "legacy parse_json_decimal: f64->Decimal failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else {
            tracing::warn!(raw = %v, "legacy parse_json_decimal: unexpected JSON type, defaulting to ZERO");
            Decimal::ZERO
        }
    }
}

// ---------------------------------------------------------------------------
// delta — full Delta Exchange implementation
// ---------------------------------------------------------------------------

pub mod delta {
    use async_trait::async_trait;
    use chrono::Utc;
    use ring::hmac;
    use rust_decimal::Decimal;
    use serde_json::{json, Value};

    use crate::exchange::config::SecretString;
    use crate::signer::{
        OrderRequest, OrderResult, OrderSide, OrderType, PrivateExchangeClient,
    };

    const DEFAULT_REST_URL: &str = "https://api.india.delta.exchange";

    /// Delta Exchange private client for the HFT execution engine.
    ///
    /// Uses HMAC-SHA256 with headers: `api-key`, `timestamp`, `signature`.
    /// Preimage: `timestamp + METHOD + path + body`.
    pub struct DeltaPrivateClient {
        id: u16,
        api_key: SecretString,
        api_secret: SecretString,
        rest_url: String,
    }

    impl std::fmt::Debug for DeltaPrivateClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DeltaPrivateClient")
                .field("id", &self.id)
                .field("api_key", &self.api_key)
                .field("rest_url", &self.rest_url)
                .finish()
        }
    }

    impl DeltaPrivateClient {
        pub fn new(api_key: &str, api_secret: &str) -> Result<Self, String> {
            Ok(Self {
                id: 14,
                api_key: SecretString::new(api_key),
                api_secret: SecretString::new(api_secret),
                rest_url: DEFAULT_REST_URL.to_string(),
            })
        }

        /// Sign a Delta v2 request.
        fn sign(&self, timestamp: &str, method: &str, path: &str, body: &str) -> String {
            let preimage = format!(
                "{}{}{}{}",
                timestamp,
                method.to_uppercase(),
                path,
                body
            );
            let key = hmac::Key::new(hmac::HMAC_SHA256, self.api_secret.expose().as_bytes());
            let sig = hmac::sign(&key, preimage.as_bytes());
            hex::encode(sig.as_ref())
        }

        /// Send a signed request to Delta v2.
        async fn send_signed(
            &self,
            http_client: &reqwest::Client,
            method: &str,
            path: &str,
            body: Option<&str>,
        ) -> Result<Value, String> {
            let timestamp = Utc::now().timestamp().to_string();
            let payload = body.unwrap_or("");
            let signature = self.sign(&timestamp, method, path, payload);

            let base = self.rest_url.trim_end_matches('/');
            let base = base.trim_end_matches("/v2");
            let url = format!("{}{}", base, path);

            let req_method = reqwest::Method::from_bytes(method.as_bytes())
                .unwrap_or(reqwest::Method::GET);

            let mut req = http_client
                .request(req_method, &url)
                .header("api-key", self.api_key.expose())
                .header("timestamp", &timestamp)
                .header("signature", &signature)
                .header("Content-Type", "application/json");

            if let Some(b) = body {
                req = req.body(b.to_string());
            }

            let resp = req
                .send()
                .await
                .map_err(|e| format!("Delta {} request failed: {}", method, e))?;

            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| format!("Delta {} read body failed: {}", method, e))?;

            if !status.is_success() {
                return Err(format!("Delta {} HTTP {}: {}", method, status, text));
            }

            serde_json::from_str(&text)
                .map_err(|e| format!("Delta {} JSON parse failed: {}", method, e))
        }
    }

    #[async_trait]
    impl PrivateExchangeClient for DeltaPrivateClient {
        fn id(&self) -> u16 {
            self.id
        }

        async fn submit_order(
            &self,
            http_client: &reqwest::Client,
            order: OrderRequest,
        ) -> Result<OrderResult, String> {
            let product_id = resolve_product_id(&order.symbol);
            let side = match order.side {
                OrderSide::Buy => "buy",
                OrderSide::Sell => "sell",
            };
            let order_type = match order.order_type {
                OrderType::Market => "market_order",
                _ => "limit_order",
            };

            let mut body = json!({
                "product_id": product_id,
                "size": order.quantity.to_string(),
                "side": side,
                "order_type": order_type,
            });
            if let Some(price) = order.price {
                body["limit_price"] = json!(price.to_string());
            }

            let body_str = body.to_string();
            let v = self
                .send_signed(http_client, "POST", "/v2/orders", Some(&body_str))
                .await?;

            let order_id = v["id"].as_str().map(String::from);
            let has_id = order_id.is_some();
            Ok(OrderResult {
                success: has_id,
                order_id,
                filled_qty: parse_json_decimal(&v["filled_quantity"]),
                avg_price: parse_json_decimal(&v["avg_fill_price"]),
                error: if has_id {
                    None
                } else {
                    Some("Delta: missing order ID in response".to_string())
                },
            })
        }

        async fn get_balance(
            &self,
            http_client: &reqwest::Client,
            asset: &str,
        ) -> Result<Decimal, String> {
            let v = self
                .send_signed(http_client, "GET", "/v2/wallet/balances", None)
                .await?;

            let entries: &[Value] = v["result"]
                .as_array()
                .or_else(|| v.as_array())
                .map(|a| a.as_slice())
                .unwrap_or(&[]);

            for item in entries {
                if item["asset_symbol"]
                    .as_str()
                    .map(|s| s.eq_ignore_ascii_case(asset))
                    .unwrap_or(false)
                {
                    return Ok(parse_json_decimal(&item["balance"]));
                }
            }
            Err(format!("Delta: asset '{}' not found in balance", asset))
        }

        async fn cancel_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let path = format!("/v2/orders/{}", order_id);
            self.send_signed(http_client, "DELETE", &path, None).await?;

            Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: None,
            })
        }

        async fn query_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let path = format!("/v2/orders/{}", order_id);
            let v = self
                .send_signed(http_client, "GET", &path, None)
                .await?;

            let status_str = v["state"].as_str().unwrap_or("unknown");
            let success = matches!(status_str, "filled");

            Ok(OrderResult {
                success,
                order_id: Some(order_id.to_string()),
                filled_qty: parse_json_decimal(&v["filled_quantity"]),
                avg_price: parse_json_decimal(&v["avg_fill_price"]),
                error: if success { None } else { Some(format!("unfilled: {}", status_str)) },
            })
        }
    }

    /// WARNING: Legacy function — uses silent ZERO fallback with warning logs.
    fn parse_json_decimal(v: &Value) -> Decimal {
        use std::str::FromStr;
        if let Some(s) = v.as_str() {
            match Decimal::from_str(s) {
                Ok(d) => d,
                Err(_) => {
                    tracing::warn!(raw = %s, "legacy parse_json_decimal: string parse failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else if let Some(n) = v.as_i64() {
            Decimal::from(n)
        } else if let Some(f) = v.as_f64() {
            match rust_decimal::prelude::FromPrimitive::from_f64(f) {
                Some(d) => d,
                None => {
                    tracing::warn!(raw = %f, "legacy parse_json_decimal: f64->Decimal failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else {
            tracing::warn!(raw = %v, "legacy parse_json_decimal: unexpected JSON type, defaulting to ZERO");
            Decimal::ZERO
        }
    }

    fn resolve_product_id(symbol: &str) -> String {
        if let Some(idx) = symbol.rfind(':') {
            let id_part = &symbol[idx + 1..];
            if id_part.parse::<u64>().is_ok() {
                return id_part.to_string();
            }
        }
        if symbol.parse::<u64>().is_ok() {
            return symbol.to_string();
        }
        symbol.to_string()
    }
}

// ---------------------------------------------------------------------------
// mexc — full MEXC (Binance-style) implementation
// ---------------------------------------------------------------------------

pub mod mexc {
    use async_trait::async_trait;
    use chrono::Utc;
    use ring::hmac;
    use rust_decimal::Decimal;
    use serde_json::{json, Value};

    use crate::exchange::config::SecretString;
    use crate::signer::{
        OrderRequest, OrderResult, OrderSide, OrderType, PrivateExchangeClient,
    };

    const DEFAULT_REST_URL: &str = "https://api.mexc.com";

    /// MEXC private client for the HFT execution engine.
    ///
    /// Binance-compatible: HMAC-SHA256 with signature appended as a query
    /// parameter.  Uses `X-MEXC-APIKEY` header for the API key.
    pub struct MexcPrivateClient {
        id: u16,
        api_key: SecretString,
        api_secret: SecretString,
        rest_url: String,
    }

    impl std::fmt::Debug for MexcPrivateClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MexcPrivateClient")
                .field("id", &self.id)
                .field("api_key", &self.api_key)
                .field("rest_url", &self.rest_url)
                .finish()
        }
    }

    impl MexcPrivateClient {
        pub fn new(api_key: &str, api_secret: &str) -> Result<Self, String> {
            Ok(Self {
                id: 15,
                api_key: SecretString::new(api_key),
                api_secret: SecretString::new(api_secret),
                rest_url: DEFAULT_REST_URL.to_string(),
            })
        }

        fn mexc_symbol(symbol: &str) -> String {
            symbol.replace('/', "").to_uppercase()
        }

        fn signed_query(&self, params: &[(&str, String)]) -> String {
            let timestamp = Utc::now().timestamp_millis().to_string();
            let mut all: Vec<(String, String)> = vec![("timestamp".to_string(), timestamp)];
            for (k, v) in params {
                all.push((k.to_string(), v.clone()));
            }
            let query: String = all
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");

            let key = hmac::Key::new(hmac::HMAC_SHA256, self.api_secret.expose().as_bytes());
            let sig = hmac::sign(&key, query.as_bytes());
            format!("{}&signature={}", query, hex::encode(sig.as_ref()))
        }
    }

    #[async_trait]
    impl PrivateExchangeClient for MexcPrivateClient {
        fn id(&self) -> u16 {
            self.id
        }

        async fn submit_order(
            &self,
            http_client: &reqwest::Client,
            order: OrderRequest,
        ) -> Result<OrderResult, String> {
            let mexc_sym = Self::mexc_symbol(&order.symbol);
            let side = match order.side {
                OrderSide::Buy => "BUY",
                OrderSide::Sell => "SELL",
            };
            let order_type = match order.order_type {
                OrderType::Market => "MARKET",
                _ => "LIMIT",
            };

            let query = self.signed_query(&[]);
            let mut body = json!({
                "symbol": mexc_sym,
                "side": side,
                "type": order_type,
                "quantity": order.quantity.to_string(),
            });
            if let Some(price) = order.price {
                body["price"] = json!(price.to_string());
            }
            if order_type == "LIMIT" {
                body["timeInForce"] = json!("GTC");
            }

            let url = format!("{}/api/v3/order?{}", self.rest_url, query);
            let resp = http_client
                .post(&url)
                .header("X-MEXC-APIKEY", self.api_key.expose())
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .send()
                .await
                .map_err(|e| format!("MEXC submit_order request failed: {}", e))?;

            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| format!("MEXC submit_order read body failed: {}", e))?;

            if !status.is_success() {
                return Ok(OrderResult {
                    success: false,
                    order_id: None,
                    filled_qty: Decimal::ZERO,
                    avg_price: Decimal::ZERO,
                    error: Some(format!("HTTP {}: {}", status, text)),
                });
            }

            let v: Value = serde_json::from_str(&text)
                .map_err(|e| format!("MEXC submit_order JSON parse failed: {}", e))?;

            let order_id = v["orderId"].as_str().map(String::from);
            let has_id = order_id.is_some();

            Ok(OrderResult {
                success: has_id,
                order_id,
                filled_qty: parse_json_decimal(&v["filledQty"]),
                avg_price: parse_json_decimal(&v["avgPrice"]),
                error: if has_id {
                    None
                } else {
                    Some("MEXC: missing orderId in response".to_string())
                },
            })
        }

        async fn get_balance(
            &self,
            http_client: &reqwest::Client,
            asset: &str,
        ) -> Result<Decimal, String> {
            let query = self.signed_query(&[]);
            let url = format!("{}/api/v3/account?{}", self.rest_url, query);

            let resp = http_client
                .get(&url)
                .header("X-MEXC-APIKEY", self.api_key.expose())
                .send()
                .await
                .map_err(|e| format!("MEXC get_balance request failed: {}", e))?;

            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| format!("MEXC get_balance read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("MEXC get_balance HTTP {}: {}", status, text));
            }

            let v: Value = serde_json::from_str(&text)
                .map_err(|e| format!("MEXC get_balance JSON parse failed: {}", e))?;

            if let Some(balances) = v["balances"].as_array() {
                for b in balances {
                    if b["asset"].as_str().map(|a| a.eq_ignore_ascii_case(asset)) == Some(true) {
                        let free = b["free"]
                            .as_str()
                            .and_then(|s| s.parse::<Decimal>().ok())
                            .unwrap_or(Decimal::ZERO);
                        return Ok(free);
                    }
                }
            }

            Err(format!("MEXC: asset '{}' not found in balance", asset))
        }

        async fn cancel_order(
            &self,
            http_client: &reqwest::Client,
            symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let mexc_sym = Self::mexc_symbol(symbol);
            let query = self.signed_query(&[
                ("symbol", mexc_sym),
                ("orderId", order_id.to_string()),
            ]);
            let url = format!("{}/api/v3/order?{}", self.rest_url, query);

            let resp = http_client
                .delete(&url)
                .header("X-MEXC-APIKEY", self.api_key.expose())
                .send()
                .await
                .map_err(|e| format!("MEXC cancel_order request failed: {}", e))?;

            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| format!("MEXC cancel_order read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("MEXC cancel_order HTTP {}: {}", status, text));
            }

            Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: None,
            })
        }

        async fn query_order(
            &self,
            http_client: &reqwest::Client,
            symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let mexc_sym = Self::mexc_symbol(symbol);
            let query = self.signed_query(&[
                ("symbol", mexc_sym),
                ("orderId", order_id.to_string()),
            ]);
            let url = format!("{}/api/v3/order?{}", self.rest_url, query);

            let resp = http_client
                .get(&url)
                .header("X-MEXC-APIKEY", self.api_key.expose())
                .send()
                .await
                .map_err(|e| format!("MEXC query_order request failed: {}", e))?;

            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| format!("MEXC query_order read body failed: {}", e))?;

            if !status.is_success() {
                return Err(format!("MEXC query_order HTTP {}: {}", status, text));
            }

            let v: Value = serde_json::from_str(&text)
                .map_err(|e| format!("MEXC query_order JSON parse failed: {}", e))?;

            let status_str = v["status"].as_str().unwrap_or("UNKNOWN");
            let success = matches!(status_str, "FILLED" | "PARTIALLY_FILLED");
            let filled = parse_json_decimal(&v["filledQty"]);
            let avg = parse_json_decimal(&v["avgPrice"]);

            Ok(OrderResult {
                success,
                order_id: Some(order_id.to_string()),
                filled_qty: filled,
                avg_price: avg,
                error: if success { None } else { Some(format!("unfilled: {}", status_str)) },
            })
        }
    }

    /// WARNING: Legacy function — uses silent ZERO fallback with warning logs.
    fn parse_json_decimal(v: &Value) -> Decimal {
        use std::str::FromStr;
        if let Some(s) = v.as_str() {
            match Decimal::from_str(s) {
                Ok(d) => d,
                Err(_) => {
                    tracing::warn!(raw = %s, "legacy parse_json_decimal: string parse failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else if let Some(n) = v.as_i64() {
            Decimal::from(n)
        } else if let Some(f) = v.as_f64() {
            match rust_decimal::prelude::FromPrimitive::from_f64(f) {
                Some(d) => d,
                None => {
                    tracing::warn!(raw = %f, "legacy parse_json_decimal: f64->Decimal failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else {
            tracing::warn!(raw = %v, "legacy parse_json_decimal: unexpected JSON type, defaulting to ZERO");
            Decimal::ZERO
        }
    }
}

// ---------------------------------------------------------------------------
// ibank — full Independent Reserve (HMAC-SHA512) implementation
// ---------------------------------------------------------------------------

pub mod ibank {
    use async_trait::async_trait;
    use base64::Engine;
    use chrono::Utc;
    use ring::hmac;
    use rust_decimal::Decimal;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::exchange::config::SecretString;
    use crate::signer::{
        OrderRequest, OrderResult, OrderSide, OrderType, PrivateExchangeClient,
    };

    const DEFAULT_REST_URL: &str = "https://api.independentreserve.com";

    /// Independent Reserve ("Ibank") private client for the HFT execution engine.
    ///
    /// Uses HMAC-SHA512 with a monotonic nonce.  Auth header format:
    ///   Authorization: apikey KEY:SIG:NONCE
    /// where SIG = HMAC-SHA512(secret, "nonce=" + NONCE + "&apiKey=" + KEY)
    pub struct IbankPrivateClient {
        id: u16,
        api_key: SecretString,
        api_secret: SecretString,
        rest_url: String,
        nonce_counter: AtomicU64,
    }

    impl std::fmt::Debug for IbankPrivateClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("IbankPrivateClient")
                .field("id", &self.id)
                .field("api_key", &self.api_key)
                .field("rest_url", &self.rest_url)
                .finish()
        }
    }

    impl IbankPrivateClient {
        pub fn new(api_key: &str, api_secret: &str) -> Result<Self, String> {
            let initial_nonce = Utc::now().timestamp_millis() as u64;
            Ok(Self {
                id: 16,
                api_key: SecretString::new(api_key),
                api_secret: SecretString::new(api_secret),
                rest_url: DEFAULT_REST_URL.to_string(),
                nonce_counter: AtomicU64::new(initial_nonce),
            })
        }

        fn next_nonce(&self) -> u64 {
            self.nonce_counter.fetch_add(1, Ordering::Relaxed)
        }

        /// Build the Authorization header: `apikey KEY:SIG:NONCE`.
        fn auth_header(&self, nonce: u64) -> String {
            let preimage = format!(
                "nonce={}&apiKey={}",
                nonce,
                self.api_key.expose()
            );
            let key = hmac::Key::new(hmac::HMAC_SHA512, self.api_secret.expose().as_bytes());
            let sig = hmac::sign(&key, preimage.as_bytes());
            let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.as_ref());
            format!(
                "apikey {}:{}:{}",
                self.api_key.expose(),
                sig_b64,
                nonce
            )
        }

        fn parse_pair(symbol: &str) -> (String, String) {
            let parts: Vec<&str> = symbol.split('/').collect();
            match parts.as_slice() {
                [base, quote] => (base.to_uppercase(), quote.to_uppercase()),
                _ => (symbol.to_uppercase(), "USD".to_string()),
            }
        }

        fn ir_order_type(side: OrderSide, order_type: OrderType) -> String {
            let side_suffix = match side {
                OrderSide::Buy => "Bid",
                OrderSide::Sell => "Offer",
            };
            let prefix = match order_type {
                OrderType::Market => "Market",
                _ => "Limit",
            };
            format!("{}{}", prefix, side_suffix)
        }

        async fn send_signed_post(
            &self,
            http_client: &reqwest::Client,
            path: &str,
            body: &Value,
        ) -> Result<Value, String> {
            let nonce = self.next_nonce();
            let auth = self.auth_header(nonce);
            let url = format!("{}{}", self.rest_url, path);

            let resp = http_client
                .post(&url)
                .header("Authorization", &auth)
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .send()
                .await
                .map_err(|e| format!("Ibank {} request failed: {}", path, e))?;

            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| format!("Ibank {} read body failed: {}", path, e))?;

            if !status.is_success() {
                return Err(format!("Ibank {} HTTP {}: {}", path, status, text));
            }

            serde_json::from_str(&text)
                .map_err(|e| format!("Ibank {} JSON parse failed: {}", path, e))
        }
    }

    #[async_trait]
    impl PrivateExchangeClient for IbankPrivateClient {
        fn id(&self) -> u16 {
            self.id
        }

        async fn submit_order(
            &self,
            http_client: &reqwest::Client,
            order: OrderRequest,
        ) -> Result<OrderResult, String> {
            let (primary, secondary) = Self::parse_pair(&order.symbol);
            let order_type = Self::ir_order_type(order.side, order.order_type);

            let mut body = json!({
                "PrimaryCurrencyCode": primary,
                "SecondaryCurrencyCode": secondary,
                "OrderType": order_type,
                "Volume": order.quantity.to_string(),
            });
            if let Some(price) = order.price {
                body["Price"] = json!(price.to_string());
            }

            let v = self
                .send_signed_post(http_client, "/Private/PlaceOrder", &body)
                .await?;

            let order_id = v["OrderGuid"].as_str().map(String::from);
            let has_id = order_id.is_some();

            Ok(OrderResult {
                success: has_id,
                order_id,
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: if has_id {
                    None
                } else {
                    Some("Ibank: missing OrderGuid in response".to_string())
                },
            })
        }

        async fn get_balance(
            &self,
            http_client: &reqwest::Client,
            asset: &str,
        ) -> Result<Decimal, String> {
            let body = json!({});
            let v = self
                .send_signed_post(http_client, "/Private/GetAccounts", &body)
                .await?;

            let entries = v.as_array().cloned().unwrap_or_default();
            for account in &entries {
                if account["AccountCurrencyCode"]
                    .as_str()
                    .map(|c| c.eq_ignore_ascii_case(asset))
                    .unwrap_or(false)
                {
                    return Ok(parse_json_decimal(&account["TotalBalance"]));
                }
            }

            Err(format!("Ibank: asset '{}' not found in balance", asset))
        }

        async fn cancel_order(
            &self,
            http_client: &reqwest::Client,
            _symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let body = json!({ "OrderGuid": order_id });
            self.send_signed_post(http_client, "/Private/CancelOrder", &body)
                .await?;

            Ok(OrderResult {
                success: true,
                order_id: Some(order_id.to_string()),
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                error: None,
            })
        }

        async fn query_order(
            &self,
            http_client: &reqwest::Client,
            symbol: &str,
            order_id: &str,
        ) -> Result<OrderResult, String> {
            let (primary, secondary) = Self::parse_pair(symbol);
            let body = json!({
                "PrimaryCurrencyCode": primary,
                "SecondaryCurrencyCode": secondary,
            });

            let v = self
                .send_signed_post(http_client, "/Private/GetOpenOrders", &body)
                .await?;

            let orders = v.as_array().cloned().unwrap_or_default();
            let found = orders.iter().find(|o| {
                o["OrderGuid"].as_str().map(|g| g == order_id).unwrap_or(false)
            });

            if let Some(order) = found {
                let status_str = order["Status"].as_str().unwrap_or("Unknown");
                let success = matches!(status_str, "Open" | "PartiallyFilled" | "Filled");
                return Ok(OrderResult {
                    success,
                    order_id: Some(order_id.to_string()),
                    filled_qty: parse_json_decimal(&order["VolumeFilled"]),
                    avg_price: parse_json_decimal(&order["AvgPrice"]),
                    error: if success { None } else { Some(format!("unfilled: {}", status_str)) },
                });
            }

            // FIX: Missing orders should NOT return success=true.
            // The order was not found in open orders — it may be filled or
            // cancelled.  Return an error so the caller can investigate.
            Err(format!(
                "Ibank: order {} not found in open orders (may be filled/cancelled)",
                order_id
            ))
        }
    }

    /// WARNING: Legacy function — uses silent ZERO fallback with warning logs.
    fn parse_json_decimal(v: &Value) -> Decimal {
        use std::str::FromStr;
        if let Some(s) = v.as_str() {
            match Decimal::from_str(s) {
                Ok(d) => d,
                Err(_) => {
                    tracing::warn!(raw = %s, "legacy parse_json_decimal: string parse failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else if let Some(n) = v.as_i64() {
            Decimal::from(n)
        } else if let Some(f) = v.as_f64() {
            match rust_decimal::prelude::FromPrimitive::from_f64(f) {
                Some(d) => d,
                None => {
                    tracing::warn!(raw = %f, "legacy parse_json_decimal: f64->Decimal failed, defaulting to ZERO");
                    Decimal::ZERO
                }
            }
        } else {
            tracing::warn!(raw = %v, "legacy parse_json_decimal: unexpected JSON type, defaulting to ZERO");
            Decimal::ZERO
        }
    }
}