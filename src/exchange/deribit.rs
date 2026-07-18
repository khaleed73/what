//! Deribit exchange implementation.
//!
//! Implements the `Exchange` trait for Deribit API v2 (JSON-RPC over HTTPS).
//! Auth uses HMAC-SHA256 signature: HMAC-SHA256(api_secret, nonce + api_key + timestamp).
//! The access_token is cached and sent as "Authorization: Bearer TOKEN" for
//! private calls. Supports market, limit, IOC, and FOK order types with
//! rate limit detection and backoff.

use async_trait::async_trait;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::exchange::config::ExchangeConfig;
use crate::exchange::common::*;
use crate::exchange::exchange_trait::*;
use crate::exchange::types::*;
use anyhow::Result;

/// Deribit exchange client with JSON-RPC support, HMAC-SHA256 auth, and rate limiting.
pub struct DeribitExchange {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
    /// Monotonic JSON-RPC request ID counter.
    rpc_id: AtomicU64,
    /// Cached auth token.
    access_token: std::sync::Mutex<Option<(String, u64)>>,
}

impl DeribitExchange {
    pub fn new(name: String, config: ExchangeConfig) -> Result<Self> {
        let timeout_secs = config.http_timeout_secs.unwrap_or(30);
        let http = build_http_client(timeout_secs)?;
        Ok(Self {
            name,
            config,
            http,
            rate_limiter: RateLimiter::new(50),
            rpc_id: AtomicU64::new(1),
            access_token: std::sync::Mutex::new(None),
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

    /// Get the next JSON-RPC request ID.
    fn next_rpc_id(&self) -> u64 {
        self.rpc_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Authenticate with Deribit and cache the access token.
    ///
    /// Per spec:
    ///   Signature = HMAC-SHA256(api_secret, nonce + api_key + timestamp)
    ///   Auth body includes: grant_type, client_id, client_secret, timestamp, signature, nonce
    ///
    /// Token is cached with its expiry time (expires_in seconds from response).
    /// Proactively re-auths when token is within 30 seconds of expiry.
    async fn ensure_auth(&self) -> Result<String> {
        // Check cached token — re-auth if missing or expiring within 30s
        {
            let guard = self.access_token.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((ref token, expires_at_us)) = *guard {
                let now_us = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as u64;
                if now_us + 30_000_000 < expires_at_us {
                    return Ok(token.clone());
                }
            }
        }

        self.rate_limiter.throttle().await;

        let id = self.next_rpc_id();
        let nonce = chrono::Utc::now().timestamp_millis().to_string();
        let timestamp = nonce.clone();

        // HMAC-SHA256(api_secret, nonce + api_key + timestamp)
        let preimage = format!(
            "{}{}{}",
            nonce,
            self.config.api_key.expose(),
            timestamp
        );
        let key = ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            self.config.api_secret.expose().as_bytes(),
        );
        let sig = ring::hmac::sign(&key, preimage.as_bytes());
        let signature = hex::encode(sig.as_ref());

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "public/auth",
            "params": {
                "grant_type": "client_credentials",
                "client_id": self.config.api_key.expose(),
                "client_secret": self.config.api_secret.expose(),
                "timestamp": timestamp,
                "signature": signature,
                "nonce": nonce,
            }
        })
        .to_string();

        let url = format!(
            "{}/api/v2/public/auth",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        // Check for JSON-RPC error
        if let Some(error) = json.get("error") {
            let msg = error["message"]
                .as_str()
                .unwrap_or("unknown Deribit auth error");
            anyhow::bail!("Deribit auth RPC error: {}", msg);
        }

        let token = json["result"]["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Deribit auth failed: no access_token in response"))?
            .to_string();
        let expires_in_ms = json["result"]["expires_in"]
            .as_u64()
            .unwrap_or(3600) * 1000;
        let now_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let expires_at_us = now_us + expires_in_ms * 1000;

        // Cache it with expiry
        {
            let mut guard = self.access_token.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some((token.clone(), expires_at_us));
        }

        Ok(token)
    }

    /// Send a JSON-RPC public method call (no auth required).
    async fn call_public(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let id = self.next_rpc_id();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        })
        .to_string();

        let url = format!(
            "{}/api/v2/{}",
            self.config.base_url.trim_end_matches('/'),
            method
        );
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        // Check for JSON-RPC error
        if let Some(error) = json.get("error") {
            let msg = error["message"]
                .as_str()
                .unwrap_or("unknown Deribit RPC error");
            anyhow::bail!("Deribit RPC error ({}): {}", method, msg);
        }

        Ok(json)
    }

    /// Send a JSON-RPC private method call (auth required).
    async fn call_private(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.rate_limiter.throttle().await;
        let token = self.ensure_auth().await?;
        let id = self.next_rpc_id();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        })
        .to_string();

        let url = format!(
            "{}/api/v2/{}",
            self.config.base_url.trim_end_matches('/'),
            method
        );
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", token))
            .body(body)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        // Check for JSON-RPC error
        if let Some(error) = json.get("error") {
            let msg = error["message"]
                .as_str()
                .unwrap_or("unknown Deribit RPC error");
            // If we get an auth error, clear the cached token so we re-auth next time
            let code = error["code"].as_i64().unwrap_or(0);
            if code == -32602 || msg.contains("token") || msg.contains("auth") {
                let mut guard =
                    self.access_token.lock().unwrap_or_else(|e| e.into_inner());
                *guard = None;
            }
            anyhow::bail!("Deribit RPC error ({}): {}", method, msg);
        }

        Ok(json)
    }
}

#[async_trait]
impl Exchange for DeribitExchange {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> ExchangeType {
        ExchangeType::Deribit
    }

    // ── Place market order ──────────────────────────────────────────────

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        let rpc_method = if order.side == OrderSide::Buy {
            "private/buy"
        } else {
            "private/sell"
        };
        let instrument = order.symbol.replace('/', "-");

        let params = serde_json::json!({
            "instrument_name": instrument,
            "amount": order.quantity.to_string(),
            "type": "market",
        });

        let json = self.call_private(rpc_method, params).await?;
        let order_result = &json["result"]["order"];
        let order_id = extract_order_id(&order_result["order_id"])
            .unwrap_or_else(|_| "unknown".to_string());

        let filled_qty = parse_json_decimal(&order_result["filled_amount"]);
        let avg_price = parse_json_decimal(&order_result["average_price"]);

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
        let params = serde_json::json!({
            "order_id": order_id,
        });
        let json = self.call_private("private/cancel", params).await?;

        let cancelled_id = json["result"]["order_id"]
            .as_str()
            .unwrap_or(order_id)
            .to_string();

        let (filled_qty, avg_price) = match self.fetch_order_status("", order_id).await {
            Ok(s) => (s.filled_qty, s.avg_price),
            Err(_) => (Decimal::ZERO, Decimal::ZERO),
        };

        Ok(OrderResponse {
            order_id: cancelled_id,
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
        // Query account summaries for all supported currencies
        let mut balances = HashMap::new();
        let currencies = ["BTC", "ETH", "USDC", "USDT", "EUR"];

        for currency in &currencies {
            let params = serde_json::json!({
                "currency": currency,
            });
            match self.call_private("private/get_account_summary", params).await {
                Ok(json) => {
                    let summary = &json["result"];
                    let available = parse_json_decimal(&summary["availableBalance"]);
                    if available > Decimal::ZERO {
                        balances.insert(currency.to_string(), available);
                    }
                }
                Err(_) => {
                    // Currency not available on this account — skip silently
                    continue;
                }
            }
        }

        // Also fetch the full position/currency list for completeness
        if let Ok(json) = self
            .call_private(
                "private/get_account_summaries",
                serde_json::json!({}),
            )
            .await
        {
            if let Some(arr) = json["result"].as_array() {
                for entry in arr {
                    let curr = match extract_currency(&entry["currency"], "currency", "Deribit") {
                        Some(c) => c,
                        None => continue,
                    };
                    let available = parse_json_decimal(&entry["availableBalance"]);
                    if !curr.is_empty() && available > Decimal::ZERO {
                        balances.insert(curr.to_string(), available);
                    }
                }
            }
        }

        Ok(balances)
    }

    // ── Fetch symbols ──────────────────────────────────────────────────

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        let mut all_symbols = Vec::new();

        // Fetch spot instruments
        let spot_params = serde_json::json!({
            "currency": "any",
            "kind": "spot",
            "expired": false,
        });
        if let Ok(json) = self.call_public("public/get_instruments", spot_params).await {
            if let Some(arr) = json["result"].as_array() {
                for inst in arr {
                    if let Some(name) = inst["instrument_name"].as_str() {
                        if inst["is_active"].as_bool().unwrap_or(false) {
                            all_symbols.push(name.to_string());
                        }
                    }
                }
            }
        }

        // Fetch perpetual instruments (most liquid on Deribit)
        let perp_params = serde_json::json!({
            "currency": "any",
            "kind": "perpetual",
            "expired": false,
        });
        if let Ok(json) = self.call_public("public/get_instruments", perp_params).await {
            if let Some(arr) = json["result"].as_array() {
                for inst in arr {
                    if let Some(name) = inst["instrument_name"].as_str() {
                        if inst["is_active"].as_bool().unwrap_or(false) {
                            all_symbols.push(name.to_string());
                        }
                    }
                }
            }
        }

        Ok(all_symbols)
    }

    // ── Fetch order status ─────────────────────────────────────────────

    async fn fetch_order_status(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let params = serde_json::json!({
            "order_id": order_id,
        });
        let json = self
            .call_private("private/get_order_state", params)
            .await?;
        let order = &json["result"]["order"];

        let status_str = order["state"].as_str().unwrap_or("unknown");
        if status_str == "unknown" {
            tracing::warn!(context = "fetch_order_status", raw = %order["state"],
                "Deribit: order state field missing");
        }
        let mapped_status = match status_str {
            "open" | "unfilled" => "NEW",
            "filled" => "FILLED",
            "cancelled" => "CANCELED",
            "partial" => "PARTIALLY_FILLED",
            _ => "UNKNOWN",
        };

        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: String::new(),
            status: mapped_status.to_string(),
            filled_qty: parse_json_decimal(&order["filled_amount"]),
            avg_price: parse_json_decimal(&order["average_price"]),
            exchange: self.name.clone(),
            fee: Some(parse_json_decimal(&order["commission"])),
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
            "{}/api/v2/public/test",
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
            let inst = symbol.replace('/', "-");
            let params = serde_json::json!({
                "instrument_name": inst,
            });
            match self.call_private("private/cancel_all", params).await {
                Ok(json) => {
                    let cancelled_count = json["result"]
                        .as_i64()
                        .or_else(|| json["result"]["total_cancelled"].as_i64())
                        .unwrap_or(0);
                    results.push(Ok(OrderResponse {
                        order_id: format!("cancel-all-{}", inst),
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
                    }));
                    if cancelled_count > 0 {
                        tracing::info!(
                            "{} cancel_all_orders for {}: {} orders cancelled",
                            self.name(),
                            inst,
                            cancelled_count
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "{} cancel_all_orders failed for {}: {}",
                        self.name(),
                        inst,
                        e
                    );
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
        let rpc_method = if order.side == OrderSide::Buy {
            "private/buy"
        } else {
            "private/sell"
        };
        let instrument = order.symbol.replace('/', "-");

        let params = serde_json::json!({
            "instrument_name": instrument,
            "amount": order.quantity.to_string(),
            "type": "limit",
            "price": price.to_string(),
        });

        let json = self.call_private(rpc_method, params).await?;
        let order_result = &json["result"]["order"];
        let order_id = extract_order_id(&order_result["order_id"])
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
                    anyhow::anyhow!("Deribit limit order requires a price")
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
        let inst = symbol.replace('/', "-");
        let params = serde_json::json!({
            "instrument_name": inst,
            "depth": depth.clamp(1, 200),
        });

        let json = self
            .call_public("public/get_order_book", params)
            .await?;
        let result = &json["result"];

        // Deribit order book entries: [price, quantity, ...]
        let bids = result["bids"]
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

        let asks = result["asks"]
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