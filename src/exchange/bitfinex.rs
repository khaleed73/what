//! Bitfinex exchange implementation.
//!
//! Implements the `Exchange` trait for Bitfinex with HMAC-SHA384-style
//! signing and array-based JSON API. Supports market, limit, IOC, and
//! FOK order types with rate limit detection and backoff.

use async_trait::async_trait;
use rust_decimal::Decimal;
use std::collections::HashMap;

use crate::exchange::config::ExchangeConfig;
use crate::exchange::common::*;
use crate::exchange::exchange_trait::*;
use crate::exchange::types::*;
use anyhow::Result;

/// Bitfinex exchange client with rate limiting.
pub struct BitfinexClient {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
    /// H40 FIX (audit): Monotonic nonce counter. Bitfinex requires each
    /// request's nonce to be strictly greater than the previous one. Using
    /// `timestamp_ms` risks collision if two requests are made in the same
    /// millisecond (the second gets "Nonce is too small" and fails). This
    /// counter guarantees monotonicity — each call to `next_nonce()`
    /// returns a value strictly greater than the previous.
    nonce_counter: std::sync::atomic::AtomicU64,
}

impl BitfinexClient {
    pub fn new(name: String, config: ExchangeConfig) -> Result<Self> {
        let timeout_secs = config.http_timeout_secs.unwrap_or(30);
        let http = build_http_client(timeout_secs)?;
        // H40 FIX: initialize nonce counter to current time in ms so it
        // starts higher than any previous nonce from earlier runs.
        let initial_nonce = chrono::Utc::now().timestamp_millis() as u64;
        Ok(Self {
            name,
            config,
            http,
            rate_limiter: RateLimiter::new(100),
            nonce_counter: std::sync::atomic::AtomicU64::new(initial_nonce),
        })
    }

    /// H40 FIX: Generate a strictly monotonic nonce. Each call returns
    /// a value greater than all previous calls (within this process).
    fn next_nonce(&self) -> u64 {
        self.nonce_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
    }

    /// Handle exchange response with rate limit detection and backoff.
    async fn handle_response(&self, resp: reqwest::Response) -> Result<serde_json::Value> {
        let status = resp.status();
        if status.as_u16() == 429 {
            tracing::warn!("Bitfinex rate limited (HTTP 429), backing off ~1s with jitter");
            jittered_rate_limit_sleep().await;
            anyhow::bail!("Rate limited by Bitfinex (HTTP 429)");
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Bitfinex API error (HTTP {}): {}", status, body);
        }
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Bitfinex: failed to parse response: {}", e))?;
        Ok(json)
    }

    /// Send a signed authenticated POST request to Bitfinex.
    async fn auth_post(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        self.rate_limiter.throttle().await;
        // H40 FIX: use monotonic nonce counter instead of timestamp_ms.
        let ts = self.next_nonce().to_string();
        let body_str = body.to_string();
        let sign = sign_bitfinex(self.config.api_secret.expose(), path, &ts, &body_str)?;
        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);
        let resp = self
            .http
            .post(&url)
            .header("bfx-nonce", &ts)
            .header("bfx-apikey", self.config.api_key.expose())
            .header("bfx-signature", &sign)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Build a Bitfinex order body array with type, price, and idempotency key.
    fn build_order_body(
        order: &OrderRequest,
        order_type: &str,
        price: Option<Decimal>,
    ) -> Result<serde_json::Value> {
        let amount = if order.side == OrderSide::Buy {
            order.quantity
        } else {
            -order.quantity
        };
        let mut order_obj = serde_json::json!({
            "type": order_type,
            "symbol": format!("t{}", order.symbol.replace('/', "")),
            "amount": amount,
        });
        if let Some(p) = price {
            order_obj["price"] = serde_json::to_value(p)
                .map_err(|e| anyhow::anyhow!("failed to serialize price: {}", e))?;
        }
        // Bitfinex uses "cid" (client ID) for idempotency
        if let Some(ref client_oid) = order.client_order_id {
            if !client_oid.is_empty() {
                // cid must be an integer; hash the string to get one
                let cid = client_oid
                    .chars()
                    .map(|c| c as u32)
                    .fold(0u64, |acc, v| acc.wrapping_add(v as u64));
                order_obj["cid"] = serde_json::Value::Number(cid.into());
            }
        }
        // Bitfinex API uses [0, "on", null, {order_details}] format
        serde_json::json!([0, "on", null, order_obj])
    }

    /// Parse a Bitfinex order response.
    fn parse_order_response(&self, json: &serde_json::Value) -> Result<OrderResponse> {
        let empty: Vec<serde_json::Value> = vec![];
        let items = json
            .as_array()
            .and_then(|a| a.get(4))
            .and_then(|a| a.as_array())
            .unwrap_or(&empty);
        let order_id = items
            .iter()
            .find_map(|i| i["id"].as_i64().map(|n| n.to_string()))
            .ok_or_else(|| anyhow::anyhow!("Bitfinex: missing order ID in response"))?;
        Ok(OrderResponse {
            order_id,
            client_order_id: String::new(),
            status: "NEW".to_string(),
            filled_qty: Decimal::ZERO,
            avg_price: Decimal::ZERO,
            exchange: self.name.clone(),
            fee: None,
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: Some(chrono::Utc::now().timestamp_millis() as u64),
            updated_at_ms: None,
            deadline_ms: None,
        })
    }
}

#[async_trait]
impl Exchange for BitfinexClient {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> ExchangeType {
        ExchangeType::Bitfinex
    }

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        let body = Self::build_order_body(order, "MARKET", None)?;
        let json = self.auth_post("/auth/w/order/submit", body).await?;
        let mut resp = self.parse_order_response(&json)?;
        if resp.filled_qty == Decimal::ZERO {
            match self.fetch_order_status(&order.symbol, &resp.order_id).await {
                Ok(status_resp) => {
                    resp.filled_qty = status_resp.filled_qty;
                    resp.avg_price = status_resp.avg_price;
                    resp.fee = status_resp.fee;
                }
                Err(e) => {
                    tracing::warn!("Bitfinex: failed to fetch order status after place: {}", e);
                }
            }
        }
        Ok(resp)
    }

    async fn place_limit_order(
        &self,
        order: &OrderRequest,
        price: Decimal,
    ) -> Result<OrderResponse> {
        let order_type = match order.time_in_force {
            TimeInForce::IOC => "LIMIT",
            TimeInForce::FOK => {
                tracing::warn!("Bitfinex has no native FOK; using EXCHANGE LIMIT as fallback");
                "EXCHANGE LIMIT"
            }
            TimeInForce::GTC | TimeInForce::Day => "LIMIT",
        };
        let mut body = Self::build_order_body(order, order_type, Some(price))?;
        // Add time-in-force flags for IOC
        if matches!(order.time_in_force, TimeInForce::IOC) {
            // Bitfinex uses flags bitmask: 4096 = IOC
            if let Some(obj) = body
                .as_array_mut()
                .and_then(|a| a.get_mut(3))
                .and_then(|v| v.as_object_mut())
            {
                obj.insert("flags".to_string(), serde_json::Value::Number(4096.into()));
            }
        }
        let json = self.auth_post("/auth/w/order/submit", body).await?;
        let mut resp = self.parse_order_response(&json)?;
        if resp.filled_qty == Decimal::ZERO {
            match self.fetch_order_status(&order.symbol, &resp.order_id).await {
                Ok(status_resp) => {
                    resp.filled_qty = status_resp.filled_qty;
                    resp.avg_price = status_resp.avg_price;
                    resp.fee = status_resp.fee;
                }
                Err(e) => {
                    tracing::warn!("Bitfinex: failed to fetch order status after place: {}", e);
                }
            }
        }
        Ok(resp)
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
                let p = price
                    .ok_or_else(|| anyhow::anyhow!("Bitfinex limit order requires a price"))?;
                self.place_limit_order(order, p).await
            }
            OrderType::StopLimit | OrderType::StopMarket => {
                anyhow::bail!("Order type {:?} not supported on Bitfinex", order_type)
            }
        }
    }

    async fn cancel_order(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let parsed_id = order_id
            .parse::<i64>()
            .map_err(|_| anyhow::anyhow!("Bitfinex: invalid order_id '{}'", order_id))?;
        let body = serde_json::json!([0, "oc", null, { "id": parsed_id }]);
        self.auth_post("/auth/w/order/cancel", body).await?;

        // Fetch actual fill state after cancel — cancelled orders may have partial fills
        let (filled_qty, avg_price) = match self.fetch_order_status(symbol, order_id).await {
            Ok(status) => (status.filled_qty, status.avg_price),
            Err(e) => {
                tracing::warn!("Bitfinex: failed to fetch order status after cancel: {}", e);
                (Decimal::ZERO, Decimal::ZERO)
            }
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

    async fn fetch_balance(&self) -> Result<HashMap<String, Decimal>> {
        let body = serde_json::json!([0, "wallet", null, { "type": "exchange" }]);
        let json = self.auth_post("/auth/r/wallets", body).await?;
        let mut balances = HashMap::new();
        if let Some(arr) = json.as_array() {
            for w in arr {
                let free: f64 = w[2].as_f64().unwrap_or_else(|| {
                    let cur = w[1].as_str().unwrap_or("?");
                    let _ = parse_balance_f64(&w[2], "bitfinex", cur);
                    0.0
                });
                if free > 0.0 {
                    let currency = match extract_currency(&w[1], "currency[1]", "Bitfinex") {
                        Some(c) => c.to_uppercase(),
                        None => continue,
                    };
                    let bal = balance_f64_to_decimal(free, "bitfinex", &currency);
                    balances.insert(currency, bal);
                }
            }
        }
        Ok(balances)
    }

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        let url = format!(
            "{}/v1/symbols_details",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        // Bitfinex V1 returns [{"pair":"btcusd",...}, ...]
        // Each pair is lowercase like "btcusd", "ethusd", etc.
        Ok(json
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|entry| {
                        let sym = entry["pair"].as_str()?;
                        // Normalize lowercase pair to "BASE/QUOTE" format.
                        // Try known quote suffixes: USD, UST, BTC, EUR, GBP, JPY
                        for quote in &["USD", "UST", "BTC", "EUR", "GBP", "JPY"] {
                            if let Some(base) = sym.strip_suffix(quote.to_lowercase().as_str()) {
                                if !base.is_empty() {
                                    return Some(format!("{}/{}", base.to_uppercase(), *quote));
                                }
                            }
                        }
                        None
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn fetch_order_status(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let parsed_id = order_id
            .parse::<i64>()
            .map_err(|_| anyhow::anyhow!("Bitfinex: invalid order_id '{}'", order_id))?;
        // Try open orders first, then fall back to history.
        // Bitfinex splits orders: active ones in /auth/r/orders, closed in /auth/r/orders/hist.
        let body = serde_json::json!([0, "order_multi", null, { "ids": [parsed_id] }]);
        let json = match self.auth_post("/auth/r/orders", body.clone()).await {
            Ok(j) => {
                let arr = j.as_array();
                // If the open-orders endpoint returned a non-empty array with our order, use it.
                if let Some(orders) = arr {
                    if orders.iter().any(|ord| {
                        ord.as_array()
                            .and_then(|a| a.first())
                            .and_then(|v| v.as_i64())
                            == Some(parsed_id)
                    }) {
                        j
                    } else {
                        // Not found in open orders — try history.
                        self.auth_post("/auth/r/orders/hist", body).await?
                    }
                } else {
                    self.auth_post("/auth/r/orders/hist", body).await?
                }
            }
            Err(_) => self.auth_post("/auth/r/orders/hist", body).await?,
        };

        // Bitfinex order history returns an array of order objects.
        // Each order is itself an array with indices:
        //   [0] id, [2] symbol, [6] amount (original, signed), [7] amount_orig,
        //   [13] status, [16] price, [17] avg_price, [15] executed_amount
        // Status values: "ACTIVE", "EXECUTED", "PARTIALLY FILLED", "CANCELED"
        let empty: Vec<serde_json::Value> = vec![];
        let orders = json.as_array().unwrap_or(&empty);

        // Find the order matching our ID
        let o = orders
            .iter()
            .find(|ord| {
                ord.as_array()
                    .map(|a| a.first().and_then(|v| v.as_i64()) == Some(parsed_id))
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                tracing::warn!(
                    "Bitfinex: order {} not found in order history ({} orders returned)",
                    order_id,
                    orders.len()
                );
                anyhow::anyhow!(
                    "Bitfinex: order {} not found in order history",
                    order_id
                )
            })?;

        {
            let arr = o.as_array();
                // Try to extract fields from array format
                let executed_qty = parse_json_decimal(
                    arr.and_then(|a| a.get(15))
                        .unwrap_or(&serde_json::Value::Null),
                );
                let avg_price = parse_json_decimal(
                    arr.and_then(|a| a.get(17))
                        .unwrap_or(&serde_json::Value::Null),
                );
                let bfx_status: &str = arr
                    .and_then(|a| a.get(13))
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN");

                // Normalize Bitfinex status to standard uppercase
                let status = match bfx_status.to_uppercase().as_str() {
                    "ACTIVE" => "NEW".to_string(),
                    "PARTIALLY FILLED" => "PARTIALLY_FILLED".to_string(),
                    "EXECUTED" => "FILLED".to_string(),
                    "CANCELED" | "CANCELLED" => "CANCELED".to_string(),
                    other => other.to_uppercase(),
                };

                let filled_qty = executed_qty.abs();
                let fee = parse_json_decimal(
                    arr.and_then(|a| a.get(9))
                        .unwrap_or(&serde_json::Value::Null),
                );

                Ok(OrderResponse {
                    order_id: order_id.to_string(),
                    client_order_id: String::new(),
                    status,
                    filled_qty,
                    avg_price: avg_price.abs(),
                    exchange: self.name.clone(),
                    fee: if fee.abs() > Decimal::ZERO {
                        Some(fee.abs())
                    } else {
                        None
                    },
                    fee_currency: None,
                    slippage_bps: None,
                    created_at_ms: None,
                    updated_at_ms: None,
                    deadline_ms: None,
                })
        }
    }

    async fn health_check(&self) -> Result<()> {
        let url = format!("{}/v2/platform/status", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!("Health check failed: {}", resp.status())
        }
    }

    /// Kill switch: cancel all open orders using Bitfinex's auth/w/orders/cancel/all endpoint.
    /// POST /api/v2/auth/w/orders/cancel/all with body {"symbol": "tBTCUSD"}.
    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        for symbol in symbols {
            let bfx_symbol = format!("t{}", symbol.replace('/', ""));
            let body = serde_json::json!({ "symbol": bfx_symbol });
            match self
                .auth_post("/auth/w/orders/cancel/all", body)
                .await
            {
                Ok(_) => results.push(Ok(OrderResponse {
                    order_id: format!("cancel-all-{}", bfx_symbol),
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
                    tracing::error!(
                        "Bitfinex cancel_all_orders failed for {}: {}",
                        bfx_symbol,
                        e
                    );
                    results.push(Err(e));
                }
            }
        }
        results
    }

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        self.rate_limiter.throttle().await;
        // Bitfinex V2 public orderbook: uses "t" prefix for trading pairs.
        // e.g. BTC/USD → "tBTCUSD", ETH/USD → "tETHUSD"
        // Response: [[price, count, amount], ...] where positive amount = bid, negative = ask
        let raw = symbol.replace('/', "").to_uppercase();
        let bfx_symbol = format!("t{}", raw);
        // Bitfinex V2 book API only accepts specific len values: 1, 25, 50, 100
        let len = match depth {
            0..=1 => 1,
            2..=25 => 25,
            26..=50 => 50,
            _ => 100,
        };
        let url = format!(
            "{}/v2/book/{}/P0?len={}",
            self.config.base_url.trim_end_matches('/'),
            bfx_symbol,
            len
        );
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        if status.as_u16() == 429 {
            tracing::warn!("Bitfinex rate limited (HTTP 429) on book {}", bfx_symbol);
            jittered_rate_limit_sleep().await;
            anyhow::bail!("Rate limited by Bitfinex (HTTP 429) on {}", bfx_symbol);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Bitfinex book API error (HTTP {}): {}", status, body);
        }
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Bitfinex order book parse error: {}", e))?;

        // Bitfinex V2 returns a flat array: [[PRICE, COUNT, AMOUNT], ...]
        // Positive AMOUNT = bid, negative AMOUNT = ask
        let mut bids: Vec<OrderBookLevel> = Vec::new();
        let mut asks: Vec<OrderBookLevel> = Vec::new();

        if let Some(arr) = json.as_array() {
            for entry in arr.iter() {
                let price = parse_json_decimal(&entry[0]);
                let amount = parse_json_decimal(&entry[2]);
                if price <= Decimal::ZERO {
                    continue;
                }
                if amount > Decimal::ZERO && (bids.len() as u32) < depth {
                    bids.push(OrderBookLevel {
                        price,
                        quantity: amount,
                    });
                } else if amount < Decimal::ZERO && (asks.len() as u32) < depth {
                    asks.push(OrderBookLevel {
                        price,
                        quantity: amount.abs(),
                    });
                }
                // Stop early once we have both bids and asks at the requested depth
                if (bids.len() as u32) >= depth && (asks.len() as u32) >= depth {
                    break;
                }
            }
        }

        Ok(OrderBookSnapshot {
            symbol: symbol.to_string(),
            exchange: self.name.clone(),
            bids,
            asks,
            timestamp_us: chrono::Utc::now().timestamp_millis() as u64 * 1000,
        })
    }
}
