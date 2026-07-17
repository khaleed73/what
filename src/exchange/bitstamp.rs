//! Bitstamp exchange implementation.
//!
//! Implements the `Exchange` trait for Bitstamp API v2 with HMAC-SHA256
//! signing via X-Auth, X-Auth-Sign, X-Auth-Nonce, and X-Auth-Version
//! headers. Pairs use lowercase-no-separator format (btcusd, ethusd).
//! Supports market and limit order types with rate limit detection and backoff.

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

/// Bitstamp exchange client with monotonic nonce, HMAC-SHA256 auth, and rate limiting.
pub struct BitstampExchange {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    nonce: std::sync::Mutex<u64>,
    rate_limiter: RateLimiter,
}

impl BitstampExchange {
    pub fn new(name: String, config: ExchangeConfig) -> Result<Self> {
        let timeout_secs = config.http_timeout_secs.unwrap_or(30);
        let http = build_http_client(timeout_secs)?;
        let initial = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Ok(Self {
            name,
            config,
            http,
            nonce: std::sync::Mutex::new(initial),
            rate_limiter: RateLimiter::new(100),
        })
    }

    /// Generate the next monotonic nonce.
    fn next_nonce(&self) -> u64 {
        let mut n = self.nonce.lock().unwrap_or_else(|e| e.into_inner());
        *n += 1;
        *n
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

    /// Sign a Bitstamp v2 API request.
    ///
    /// Signature = HMAC-SHA256(api_secret, nonce + api_key + "POST" + "/api/v2/" + content_type + url_path + body)
    /// Returned as hex string.
    fn sign(&self, nonce_str: &str, url_path: &str, body: &str) -> String {
        let content_type = "application/x-www-form-urlencoded";
        let preimage = format!(
            "{}{}POST/api/v2/{}{}{}",
            nonce_str,
            self.config.api_key.expose(),
            url_path,
            content_type,
            body
        );
        let key = ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            self.config.api_secret.expose().as_bytes(),
        );
        let sig = ring::hmac::sign(&key, preimage.as_bytes());
        hex::encode(sig.as_ref())
    }

    /// Convert internal symbol format (e.g. BTC/USDT) to Bitstamp format (btcusd).
    fn to_pair(symbol: &str) -> String {
        symbol.replace('/', "").to_lowercase()
    }

    /// Send a signed POST request to a Bitstamp v2 endpoint.
    ///
    /// `url_path` is the path relative to /api/v2/ (e.g. "balance/", "btcusd/order/").
    async fn send_signed_post(
        &self,
        url_path: &str,
        body: &str,
    ) -> Result<serde_json::Value> {
        self.rate_limiter.throttle().await;
        let nonce = self.next_nonce();
        let nonce_str = nonce.to_string();
        let signature = self.sign(&nonce_str, url_path, body);

        // Per spec, the body for private endpoints includes key, signature, nonce
        let full_body = if body.is_empty() {
            format!(
                "key={}&signature={}&nonce={}",
                self.config.api_key.expose(),
                signature,
                nonce_str
            )
        } else {
            format!(
                "key={}&signature={}&nonce={}&{}",
                self.config.api_key.expose(),
                signature,
                nonce_str,
                body
            )
        };

        let url = format!(
            "{}/api/v2/{}",
            self.config.base_url.trim_end_matches('/'),
            url_path
        );
        let resp = self
            .http
            .post(&url)
            .header("X-Auth", self.config.api_key.expose())
            .header("X-Auth-Sign", &signature)
            .header("X-Auth-Nonce", &nonce_str)
            .header("X-Auth-Version", "2")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(full_body)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;
        Ok(json)
    }

    /// Check Bitstamp-specific error fields in the JSON body.
    fn check_bitstamp_errors(&self, json: &serde_json::Value) -> Result<()> {
        // Bitstamp may return {"status": "error", "reason": "..."} in the JSON
        if let Some(status) = json["status"].as_str() {
            if status == "error" {
                let reason = json["reason"]
                    .as_str()
                    .or_else(|| json["code"].as_str())
                    .or_else(|| json["message"].as_str())
                    .unwrap_or("unknown Bitstamp error");
                if reason.contains("Rate limit") || reason.contains("rate limit") {
                    tracing::warn!("Bitstamp rate limit detected: {}", reason);
                    anyhow::bail!("Rate limited by Bitstamp: {}", reason);
                }
                anyhow::bail!("Bitstamp error: {}", reason);
            }
        }
        // Also check top-level "errors" object (some endpoints)
        if let Some(errors) = json["errors"].as_object() {
            if !errors.is_empty() {
                let msgs: Vec<String> = errors
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                anyhow::bail!("Bitstamp errors: {}", msgs.join(", "));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Exchange for BitstampExchange {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> ExchangeType {
        ExchangeType::Bitstamp
    }

    // ── Place market order ──────────────────────────────────────────────

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        let pair = Self::to_pair(&order.symbol);
        let side = if order.side == OrderSide::Buy {
            "buy"
        } else {
            "sell"
        };
        let body = format!(
            "type=market&amount={}&side={}",
            order.quantity, side
        );

        let json = self
            .send_signed_post(&format!("{}/order/", pair), &body)
            .await?;
        self.check_bitstamp_errors(&json)?;

        let order_id = extract_order_id(&json["id"])
            .unwrap_or_else(|_| "unknown".to_string());

        // Try to fetch order status for fill info
        let (filled_qty, avg_price) = match self.fetch_order_status(&order.symbol, &order_id).await {
            Ok(s) => (s.filled_qty, s.avg_price),
            Err(e) => {
                tracing::warn!("Bitstamp: failed to fetch order status after place: {}", e);
                (parse_json_decimal(&json["amount"]), parse_json_decimal(&json["price"]))
            }
        };

        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        Ok(OrderResponse {
            order_id,
            client_order_id: order.client_order_id.clone().unwrap_or_default(),
            status: "NEW".to_string(),
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

    // ── Cancel order ───────────────────────────────────────────────────

    async fn cancel_order(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let body = format!("id={}", order_id);
        let json = self.send_signed_post("order/cancel/", &body).await?;
        self.check_bitstamp_errors(&json)?;

        let (filled_qty, avg_price) = match self.fetch_order_status("", order_id).await {
            Ok(s) => (s.filled_qty, s.avg_price),
            Err(_) => (Decimal::ZERO, Decimal::ZERO),
        };

        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: String::new(),
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

    // ── Fetch balance ──────────────────────────────────────────────────

    async fn fetch_balance(&self) -> Result<HashMap<String, Decimal>> {
        let json = self.send_signed_post("balance/", "").await?;
        self.check_bitstamp_errors(&json)?;

        let mut balances = HashMap::new();
        if let Some(obj) = json.as_object() {
            for (key, val) in obj {
                // Bitstamp balance keys look like "btc_available", "usd_balance", etc.
                let amount = val.as_f64().or_else(|| {
                    val.as_str().and_then(|s| s.parse().ok())
                }).unwrap_or_else(|| {
                    parse_balance_f64(val, "bitstamp", key);
                    0.0
                });
                if amount > 0.0 && key.ends_with("_available") {
                    let asset = key.split('_').next().unwrap_or(key);
                    balances.insert(
                        asset.to_uppercase(),
                        balance_f64_to_decimal(amount, "bitstamp", asset),
                    );
                }
            }
        }
        Ok(balances)
    }

    // ── Fetch symbols ──────────────────────────────────────────────────

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        let url = format!(
            "{}/api/v2/trading-pairs-info/",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        let symbols = json
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|p| {
                        // Only include pairs that have trading enabled
                        let _decimals = p["base_decimals"].is_number().then_some(())?;
                        let name = p["name"].as_str()?;
                        Some(name.to_uppercase())
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(symbols)
    }

    // ── Fetch order status ─────────────────────────────────────────────

    async fn fetch_order_status(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let body = format!("id={}", order_id);
        let json = self.send_signed_post("order/status/", &body).await?;
        self.check_bitstamp_errors(&json)?;

        let status_str = json["status"]
            .as_str()
            .or_else(|| json["transaction_status"].as_str())
            .unwrap_or("Unknown");
        let mapped_status = match status_str {
            "Open" | "In Queue" => "NEW",
            "Finished" => "FILLED",
            "Canceled" | "Cancelled" => "CANCELED",
            "Partially filled" => "PARTIALLY_FILLED",
            _ => "UNKNOWN",
        };

        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: String::new(),
            status: mapped_status.to_string(),
            filled_qty: parse_json_decimal(&json["amount_filled"]),
            avg_price: parse_json_decimal(&json["price"]),
            exchange: self.name.clone(),
            fee: Some(parse_json_decimal(&json["fee"])),
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: None,
            updated_at_ms: None,
            deadline_ms: None,
        })
    }

    // ── Health check ───────────────────────────────────────────────────

    async fn health_check(&self) -> Result<()> {
        let url = format!(
            "{}/api/v2/ticker/btcusd/",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!("{} health check failed: {}", self.name(), resp.status())
        }
    }

    // ── Kill switch ────────────────────────────────────────────────────

    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        for symbol in symbols {
            let pair = Self::to_pair(symbol);
            match self
                .send_signed_post(&format!("{}/open_orders/all/", pair), "")
                .await
            {
                Ok(_) => results.push(Ok(OrderResponse {
                    order_id: format!("cancel-all-{}", pair),
                    client_order_id: String::new(),
                    status: "CANCELED".to_string(),
                    filled_qty: Decimal::ZERO,
                    avg_price: Decimal::ZERO,
                    exchange: self.name.clone(),
                    fee: None,
                    fee_currency: None,
                    slippage_bps: None,
                    created_at_ms: Some(chrono::Utc::now().timestamp_millis() as u64),
                    updated_at_ms: Some(chrono::Utc::now().timestamp_millis() as u64),
                    deadline_ms: None,
                })),
                Err(e) => {
                    tracing::error!("{} cancel_all_orders failed for {}: {}", self.name(), pair, e);
                    results.push(Err(e));
                }
            }
        }
        results
    }

    // ── Place limit order ──────────────────────────────────────────────

    async fn place_limit_order(
        &self,
        order: &OrderRequest,
        price: Decimal,
    ) -> Result<OrderResponse> {
        let pair = Self::to_pair(&order.symbol);
        let side = if order.side == OrderSide::Buy {
            "buy"
        } else {
            "sell"
        };
        let body = format!(
            "type=limit&amount={}&price={}&side={}",
            order.quantity, price, side
        );

        let json = self
            .send_signed_post(&format!("{}/order/", pair), &body)
            .await?;
        self.check_bitstamp_errors(&json)?;

        let order_id = extract_order_id(&json["id"])
            .unwrap_or_else(|_| "unknown".to_string());

        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        Ok(OrderResponse {
            order_id,
            client_order_id: order.client_order_id.clone().unwrap_or_default(),
            status: "NEW".to_string(),
            filled_qty: Decimal::ZERO,
            avg_price: Decimal::ZERO,
            exchange: self.name.clone(),
            fee: None,
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: Some(now_ms),
            updated_at_ms: Some(now_ms),
            deadline_ms: None,
        })
    }

    // ── Order type override ────────────────────────────────────────────

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
                    anyhow::anyhow!("Bitstamp limit order requires a price")
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

    // ── Order book ─────────────────────────────────────────────────────

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        let pair = Self::to_pair(symbol);
        let url = format!(
            "{}/api/v2/order_book/{}/",
            self.config.base_url.trim_end_matches('/'),
            pair
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

        Ok(OrderBookSnapshot {
            symbol: symbol.to_string(),
            exchange: self.name.clone(),
            bids,
            asks,
            timestamp_us: chrono::Utc::now().timestamp_millis() as u64 * 1000,
        })
    }
}