//! Gate.io exchange implementation.
//!
//! Implements the `Exchange` trait for Gate.io V4 Spot API with HMAC-SHA256
//! request signing. Gate.io uses underscore-delimited symbols (BTC_USDT)
//! while our internal system uses slash-delimited (BTC/USDT); conversions
//! are performed in both directions.

use async_trait::async_trait;
use rust_decimal::prelude::FromPrimitive;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::time::Duration;

use crate::exchange::config::ExchangeConfig;
use crate::exchange::common::*;
use crate::exchange::exchange_trait::*;
use crate::exchange::types::*;
use anyhow::Result;

/// Gate.io exchange client with rate limiting.
pub struct GateioClient {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
}

/// Convert our internal symbol format (BTC/USDT) to Gate.io format (BTC_USDT).
fn to_gateio_symbol(symbol: &str) -> String {
    symbol.replace('/', "_")
}

/// Convert Gate.io symbol format (BTC_USDT) to our internal format (BTC/USDT).
fn from_gateio_symbol(symbol: &str) -> String {
    symbol.replace('_', "/")
}

/// Compute SHA-256 hex digest of a byte string (used for Gate.io POST body hash).
fn sha256_hex(data: &[u8]) -> String {
    use ring::digest;
    let hash = digest::digest(&digest::SHA256, data);
    hex::encode(hash.as_ref())
}

impl GateioClient {
    pub fn new(name: String, config: ExchangeConfig) -> Result<Self> {
        let timeout_secs = config.http_timeout_secs.unwrap_or(30);
        let http = build_http_client(timeout_secs)?;
        Ok(Self {
            name,
            config,
            http,
            rate_limiter: RateLimiter::new(900),
        })
    }

    /// Handle exchange response with rate limit detection and backoff.
    async fn handle_response(&self, resp: reqwest::Response) -> Result<serde_json::Value> {
        match parse_exchange_response(resp, self.name()).await {
            Ok(json) => Ok(json),
            Err(ExchangeError::ApiError {
                is_rate_limited: true,
                message,
                ..
            }) => {
                tracing::warn!("{} rate limited, backing off ~1s with jitter: {}", self.name(), message);
                jittered_rate_limit_sleep().await;
                anyhow::bail!("Rate limited by {}: {}", self.name(), message);
            }
            Err(e) => Err(into_anyhow(e)),
        }
    }

    /// Build the common Gate.io authentication headers for a signed request.
    fn auth_headers(
        &self,
        timestamp: &str,
        signature: &str,
        content_type: &str,
    ) -> reqwest::header::HeaderMap {
        let mut map = reqwest::header::HeaderMap::new();
        if let Ok(v) = reqwest::header::HeaderValue::from_str(self.config.api_key.expose()) {
            map.insert("KEY", v);
        }
        if let Ok(v) = reqwest::header::HeaderValue::from_str(signature) {
            map.insert("SIGN", v);
        }
        if let Ok(v) = reqwest::header::HeaderValue::from_str(timestamp) {
            map.insert("Timestamp", v);
        }
        if !content_type.is_empty() {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(content_type) {
                map.insert("Content-Type", v);
            }
        }
        map
    }

    /// Sign a GET request. Preimage: `timestamp + "GET" + path + query`.
    fn sign_get(&self, timestamp: &str, path: &str, query: &str) -> Result<String> {
        let payload = format!("{}GET{}{}", timestamp, path, query);
        sign_hmac(self.config.api_secret.expose(), &payload)
    }

    /// Sign a POST request. Preimage: `timestamp + "POST" + path + "" + sha256_hex(body)`.
    fn sign_post(&self, timestamp: &str, path: &str, body: &[u8]) -> Result<String> {
        let body_hash = sha256_hex(body);
        let payload = format!("{}POST{}{}", timestamp, path, body_hash);
        sign_hmac(self.config.api_secret.expose(), &payload)
    }

    /// Sign a DELETE request. Preimage: `timestamp + "DELETE" + path + query`.
    fn sign_delete(&self, timestamp: &str, path: &str, query: &str) -> Result<String> {
        let payload = format!("{}DELETE{}{}", timestamp, path, query);
        sign_hmac(self.config.api_secret.expose(), &payload)
    }

    /// Normalize Gate.io order status to our standard uppercase form.
    fn normalize_status(status: &str) -> String {
        match status.to_lowercase().as_str() {
            "open" => "NEW".to_string(),
            "closed" => "FILLED".to_string(),
            "cancelled" | "canceled" => "CANCELED".to_string(),
            _ => status.to_uppercase(),
        }
    }
}

#[async_trait]
impl Exchange for GateioClient {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> ExchangeType {
        ExchangeType::Gateio
    }

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let side = if order.side == OrderSide::Buy {
            "buy"
        } else {
            "sell"
        };
        let gate_symbol = to_gateio_symbol(&order.symbol);

        let mut body = serde_json::json!({
            "account": "spot",
            "symbol": gate_symbol,
            "side": side,
            "type": "market",
            "amount": order.quantity.to_string(),
        });
        if let Some(ref client_oid) = order.client_order_id {
            if !client_oid.is_empty() {
                body["text"] = serde_json::Value::String(client_oid.clone());
            }
        }
        let body_str = serde_json::to_string(&body)?;
        let path = "/api/v4/spot/orders";
        let signature = self.sign_post(&timestamp, path, body_str.as_bytes())?;
        let url = format!("{}{}", self.config.base_url, path);

        let resp = self
            .http
            .post(&url)
            .headers(self.auth_headers(&timestamp, &signature, "application/json"))
            .body(body_str)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let order_id = extract_order_id(&json["id"])?;
        let filled_qty = parse_json_decimal(&json["filled_total"]);
        let avg_price = parse_json_decimal(&json["avg_deal_price"]);
        let fee = parse_json_decimal(&json["fee"]);

        // If no immediate fill data, fetch order status
        let (filled_qty, avg_price, fee) = if filled_qty > Decimal::ZERO {
            (filled_qty, avg_price, fee)
        } else {
            match self.fetch_order_status(&order.symbol, &order_id).await {
                Ok(status_resp) => (
                    status_resp.filled_qty,
                    status_resp.avg_price,
                    status_resp.fee.unwrap_or(Decimal::ZERO),
                ),
                Err(e) => {
                    tracing::warn!(
                        "Gate.io: failed to fetch order status after place: {}",
                        e
                    );
                    (Decimal::ZERO, Decimal::ZERO, Decimal::ZERO)
                }
            }
        };

        Ok(OrderResponse {
            order_id,
            client_order_id: extract_client_order_id(&json["text"], "text", "GateIO"),
            status: if filled_qty > Decimal::ZERO {
                "FILLED".to_string()
            } else {
                "NEW".to_string()
            },
            filled_qty,
            avg_price,
            exchange: self.name.clone(),
            fee: Some(fee),
            fee_currency: json["fee_currency"].as_str().map(String::from),
            slippage_bps: None,
            created_at_ms: Some(now_ms),
            updated_at_ms: Some(now_ms),
            deadline_ms: None,
        })
    }

    async fn cancel_order(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let path = format!("/api/v4/spot/orders/{}", order_id);
        let signature = self.sign_delete(&timestamp, &path, "")?;
        let url = format!("{}{}", self.config.base_url, path);

        let resp = self
            .http
            .delete(&url)
            .headers(self.auth_headers(&timestamp, &signature, ""))
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let filled_qty = parse_json_decimal(&json["filled_total"]);
        let avg_price = parse_json_decimal(&json["avg_deal_price"]);

        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: extract_client_order_id(&json["text"], "text", "GateIO"),
            status: "CANCELED".to_string(),
            filled_qty,
            avg_price,
            exchange: self.name.clone(),
            fee: None,
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: None,
            updated_at_ms: None,
            deadline_ms: None,
        })
    }

    async fn fetch_balance(&self) -> Result<HashMap<String, Decimal>> {
        self.rate_limiter.throttle().await;
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let path = "/api/v4/spot/accounts";
        let signature = self.sign_get(&timestamp, path, "")?;
        let url = format!("{}{}", self.config.base_url, path);

        let resp = self
            .http
            .get(&url)
            .headers(self.auth_headers(&timestamp, &signature, ""))
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let mut balances = HashMap::new();
        if let Some(accounts) = json.as_array() {
            for account in accounts {
                let available: f64 = account["available"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        let cur = account["currency"].as_str().unwrap_or("?");
                        parse_balance_f64(&account["available"], "gateio", cur);
                        0.0
                    });
                if available > 0.0 {
                    balances.insert(
                        account["currency"]
                            .as_str()
                            .unwrap_or("")
                            .to_string(),
                        available,
                    );
                }
            }
        }
        Ok(balances
            .into_iter()
            .map(|(k, v)| {
                let bal = balance_f64_to_decimal(v, "gateio", &k);
                (k, bal)
            })
            .collect())
    }

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        let url = format!("{}/api/v4/spot/currency_pairs", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        let symbols = json
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter(|s| s["trade_status"].as_str() == Some("tradable"))
                    .filter_map(|s| {
                        s["id"]
                            .as_str()
                            .map(from_gateio_symbol)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(symbols)
    }

    async fn fetch_order_status(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let path = format!("/api/v4/spot/orders/{}", order_id);
        let signature = self.sign_get(&timestamp, &path, "")?;
        let url = format!("{}{}", self.config.base_url, path);

        let resp = self
            .http
            .get(&url)
            .headers(self.auth_headers(&timestamp, &signature, ""))
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let filled_qty = parse_json_decimal(&json["filled_total"]);
        let avg_price = parse_json_decimal(&json["avg_deal_price"]);
        let fee = parse_json_decimal(&json["fee"]);

        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: extract_client_order_id(&json["text"], "text", "GateIO"),
            status: Self::normalize_status(json["status"].as_str().unwrap_or("unknown")),
            filled_qty,
            avg_price,
            exchange: self.name.clone(),
            fee: if fee.abs() > Decimal::ZERO {
                Some(fee)
            } else {
                None
            },
            fee_currency: json["fee_currency"].as_str().map(String::from),
            slippage_bps: None,
            created_at_ms: None,
            updated_at_ms: None,
            deadline_ms: None,
        })
    }

    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        for symbol in symbols {
            let gate_symbol = to_gateio_symbol(symbol);
            let timestamp = chrono::Utc::now().timestamp_millis().to_string();
            let path = "/api/v4/spot/cancel_all_orders";
            let body = serde_json::json!({
                "symbol": gate_symbol,
            });
            let body_str = match serde_json::to_string(&body) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        "Gate.io cancel_all_orders serialize error for {}: {}",
                        gate_symbol,
                        e
                    );
                    results.push(Err(anyhow::anyhow!(
                        "Gate.io cancel_all serialize error: {}",
                        e
                    )));
                    continue;
                }
            };
            let signature = match self.sign_post(&timestamp, path, body_str.as_bytes()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        "Gate.io cancel_all_orders signing failed for {}: {}",
                        gate_symbol,
                        e
                    );
                    results.push(Err(e));
                    continue;
                }
            };
            let url = format!("{}{}", self.config.base_url, path);
            match self
                .http
                .post(&url)
                .headers(self.auth_headers(&timestamp, &signature, "application/json"))
                .body(body_str)
                .send()
                .await
            {
                Ok(resp) => match self.handle_response(resp).await {
                    Ok(_) => results.push(Ok(OrderResponse {
                        order_id: format!("cancel-all-{}", gate_symbol),
                        client_order_id: String::new(),
                        status: "CANCELED".to_string(),
                        filled_qty: Decimal::ZERO,
                        avg_price: Decimal::ZERO,
                        exchange: self.name.clone(),
                        fee: None,
                        fee_currency: None,
                        slippage_bps: None,
                        created_at_ms: None,
                        updated_at_ms: None,
                        deadline_ms: None,
                    })),
                    Err(e) => {
                        tracing::error!(
                            "Gate.io cancel_all_orders failed for {}: {}",
                            gate_symbol,
                            e
                        );
                        results.push(Err(e));
                    }
                },
                Err(e) => {
                    tracing::error!(
                        "Gate.io cancel_all_orders HTTP error for {}: {}",
                        gate_symbol,
                        e
                    );
                    results.push(Err(anyhow::anyhow!(
                        "Gate.io cancel_all HTTP error: {}",
                        e
                    )));
                }
            }
        }
        results
    }

    async fn health_check(&self) -> Result<()> {
        let url = format!("{}/api/v4/spot/currency_pairs", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!("Health check failed: {}", resp.status())
        }
    }

    async fn place_limit_order(
        &self,
        order: &OrderRequest,
        price: Decimal,
    ) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let side = if order.side == OrderSide::Buy {
            "buy"
        } else {
            "sell"
        };
        let gate_symbol = to_gateio_symbol(&order.symbol);

        let mut body = serde_json::json!({
            "account": "spot",
            "symbol": gate_symbol,
            "side": side,
            "type": "limit",
            "price": price.to_string(),
            "amount": order.quantity.to_string(),
            "time_in_force": "gtc",
        });
        if let Some(ref client_oid) = order.client_order_id {
            if !client_oid.is_empty() {
                body["text"] = serde_json::Value::String(client_oid.clone());
            }
        }
        let body_str = serde_json::to_string(&body)?;
        let path = "/api/v4/spot/orders";
        let signature = self.sign_post(&timestamp, path, body_str.as_bytes())?;
        let url = format!("{}{}", self.config.base_url, path);

        let resp = self
            .http
            .post(&url)
            .headers(self.auth_headers(&timestamp, &signature, "application/json"))
            .body(body_str)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let order_id = extract_order_id(&json["id"])?;
        let filled_qty = parse_json_decimal(&json["filled_total"]);
        let avg_price = parse_json_decimal(&json["avg_deal_price"]);

        Ok(OrderResponse {
            order_id,
            client_order_id: extract_client_order_id(&json["text"], "text", "GateIO"),
            status: if filled_qty > Decimal::ZERO {
                "PARTIALLY_FILLED".to_string()
            } else {
                "NEW".to_string()
            },
            filled_qty,
            avg_price,
            exchange: self.name.clone(),
            fee: None,
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: Some(now_ms),
            updated_at_ms: Some(now_ms),
            deadline_ms: None,
        })
    }

    async fn place_order_with_type(
        &self,
        order: &OrderRequest,
        order_type: OrderType,
        price: Option<Decimal>,
    ) -> Result<OrderResponse> {
        match order_type {
            OrderType::Market => self.place_order(order).await,
            OrderType::Limit => {
                let p = price.ok_or_else(|| {
                    anyhow::anyhow!("Limit order requires a price on {}", self.name())
                })?;
                self.place_limit_order(order, p).await
            }
            _ => anyhow::bail!(
                "Order type {:?} not supported on {}",
                order_type,
                self.name()
            ),
        }
    }

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        let gate_symbol = to_gateio_symbol(symbol);
        let limit = match depth {
            0..=5 => 5,
            6..=10 => 10,
            11..=20 => 20,
            21..=50 => 50,
            _ => 100,
        };
        let url = format!(
            "{}/api/v4/spot/order_book?currency_pair={}&limit={}",
            self.config.base_url, gate_symbol, limit
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;

        let bids = json["bids"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .take(depth as usize)
                    .filter_map(|entry| {
                        let price = parse_json_decimal(&entry[0]);
                        let quantity = parse_json_decimal(&entry[1]);
                        if price > Decimal::ZERO {
                            Some(OrderBookLevel { price, quantity })
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let asks = json["asks"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .take(depth as usize)
                    .filter_map(|entry| {
                        let price = parse_json_decimal(&entry[0]);
                        let quantity = parse_json_decimal(&entry[1]);
                        if price > Decimal::ZERO {
                            Some(OrderBookLevel { price, quantity })
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let timestamp_us = json["current"]
            .as_f64()
            .filter(|t| t.is_finite() && *t >= 0.0 && *t < (u64::MAX as f64) / 1000.0)
            .map(|t| (t * 1000.0) as u64)
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis() as u64 * 1000);

        Ok(OrderBookSnapshot {
            symbol: symbol.to_string(),
            exchange: self.name.clone(),
            bids,
            asks,
            timestamp_us,
        })
    }
}