//! Delta Exchange API v2 implementation.
//!
//! Implements the `Exchange` trait for Delta Exchange (https://delta.exchange)
//! with HMAC-SHA256 signing. Delta uses numeric `product_id` instead of
//! symbol strings for order placement, and requires `api-key`, `timestamp`,
//! and `signature` headers on authenticated requests.
//!
//! Authentication:
//!   signature = HMAC-SHA256(api_secret, timestamp + method + path + body)

use async_trait::async_trait;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::time::Duration;

use crate::exchange::config::ExchangeConfig;
use crate::exchange::common::*;
use crate::exchange::exchange_trait::*;
use crate::exchange::types::*;
use anyhow::Result;

/// Delta Exchange client with HMAC-SHA256 signing and rate limiting.
pub struct DeltaExchange {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
}

impl DeltaExchange {
    pub fn new(name: String, config: ExchangeConfig) -> Result<Self> {
        let timeout_secs = config.http_timeout_secs.unwrap_or(30);
        let http = build_http_client(timeout_secs)?;
        Ok(Self {
            name,
            config,
            http,
            rate_limiter: RateLimiter::new(50),
        })
    }

    /// Handle exchange response with rate limit detection and backoff.
    async fn handle_response(&self, resp: reqwest::Response) -> Result<serde_json::Value> {
        match parse_exchange_response(resp, "Delta").await {
            Ok(json) => Ok(json),
            Err(ExchangeError::ApiError {
                is_rate_limited: true,
                message,
                ..
            }) => {
                tracing::warn!("Delta rate limited, backing off 1s: {}", message);
                tokio::time::sleep(Duration::from_secs(1)).await;
                anyhow::bail!("Rate limited by Delta: {}", message);
            }
            Err(e) => Err(into_anyhow(e)),
        }
    }

    /// Sign a Delta Exchange v2 request using HMAC-SHA256.
    ///
    /// Delta v2 auth:
    ///   signature = HMAC-SHA256(api_secret, timestamp + METHOD + path + body)
    ///   Headers: api-key, timestamp, signature
    fn sign_request(
        &self,
        method: &str,
        path: &str,
        timestamp: &str,
        body: &str,
    ) -> anyhow::Result<String> {
        let preimage = format!("{}{}{}{}", timestamp, method.to_uppercase(), path, body);
        sign_hmac(self.config.api_secret.expose(), &preimage)
            .ok_or_else(|| anyhow::anyhow!("HMAC signing failed for Delta request"))
    }

    /// Send a signed request to Delta v2 API.
    async fn send_signed(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.rate_limiter.throttle().await;
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let payload = body.unwrap_or("");
        let signature = self.sign_request(method, path, &timestamp, payload)?;

        let base = self.config.base_url.trim_end_matches('/');
        // Strip any /v2 prefix from base_url so we can use full /v2/... paths
        let base = base.trim_end_matches("/v2");
        let url = format!("{}{}", base, path);

        let req_method = reqwest::Method::from_bytes(method.as_bytes())
            .unwrap_or(reqwest::Method::GET);

        let mut req = self
            .http
            .request(req_method, &url)
            .header("api-key", self.config.api_key.expose())
            .header("timestamp", &timestamp)
            .header("signature", &signature)
            .header("Content-Type", "application/json");

        if let Some(b) = body {
            req = req.body(b.to_string());
        }

        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Send a public (unsigned) GET request.
    async fn send_public(&self, path: &str) -> Result<serde_json::Value> {
        self.rate_limiter.throttle().await;
        let base = self.config.base_url.trim_end_matches('/');
        let base = base.trim_end_matches("/v2");
        let url = format!("{}{}", base, path);
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("Delta public request failed: HTTP {}", status);
        }
        let text = resp.text().await?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("Delta parse error: {}", e))?;
        Ok(json)
    }

    /// Attempt to parse a symbol string as a numeric product_id.
    /// Falls back to the symbol itself if it's not a number.
    fn resolve_product_id(symbol: &str) -> String {
        // If the symbol looks like "SYMBOL:12345", extract the numeric part
        if let Some(idx) = symbol.rfind(':') {
            let id_part = &symbol[idx + 1..];
            if id_part.parse::<u64>().is_ok() {
                return id_part.to_string();
            }
        }
        // If the entire symbol is a number, use it directly
        if symbol.parse::<u64>().is_ok() {
            return symbol.to_string();
        }
        // Otherwise return the symbol as-is (may fail on the API side)
        symbol.to_string()
    }

    /// Map an internal OrderSide to the Delta API string.
    fn side_str(side: OrderSide) -> &'static str {
        match side {
            OrderSide::Buy => "buy",
            OrderSide::Sell => "sell",
        }
    }

    /// Build a standard `now_ms` timestamp for `OrderResponse`.
    fn now_ms() -> u64 {
        chrono::Utc::now().timestamp_millis() as u64
    }
}

#[async_trait]
impl Exchange for DeltaExchange {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> ExchangeType {
        ExchangeType::Delta
    }

    // ── Market order ────────────────────────────────────────────────────

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        let product_id = Self::resolve_product_id(&order.symbol);
        let body = serde_json::json!({
            "product_id": product_id,
            "size": order.quantity.to_string(),
            "side": Self::side_str(order.side),
            "order_type": "market_order",
        })
        .to_string();

        let json = self.send_signed("POST", "/v2/orders", Some(&body)).await?;

        let order_id = extract_order_id(&json["id"]).unwrap_or_else(|_| "unknown".to_string());
        let filled_qty = parse_json_decimal(&json["filled_quantity"]);
        let avg_price = parse_json_decimal(&json["avg_fill_price"]);

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
            created_at_ms: Some(Self::now_ms()),
            updated_at_ms: Some(Self::now_ms()),
            deadline_ms: None,
        })
    }

    // ── Cancel order (DELETE) ───────────────────────────────────────────

    async fn cancel_order(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let path = format!("/v2/orders/{}", order_id);
        let _json = self.send_signed("DELETE", &path, None).await?;

        // Fetch fill state before confirming cancellation
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
            updated_at_ms: Some(Self::now_ms()),
            deadline_ms: None,
        })
    }

    // ── Balance ─────────────────────────────────────────────────────────

    async fn fetch_balance(&self) -> Result<HashMap<String, Decimal>> {
        let json = self
            .send_signed("GET", "/v2/wallet/balances", None)
            .await?;

        let mut balances = HashMap::new();

        // Delta returns {"result": [...]} or a direct array
        let entries = json["result"]
            .as_array()
            .or_else(|| json.as_array())
            .map(|arr| arr.iter().collect::<Vec<_>>())
            .unwrap_or_default();

        for item in entries {
            let asset = item["asset_symbol"]
                .as_str()
                .unwrap_or("")
                .to_uppercase();
            let balance = parse_json_decimal(&item["balance"]);
            if balance > Decimal::ZERO {
                balances.insert(asset, balance);
            }
        }

        Ok(balances)
    }

    // ── Symbols (products) ──────────────────────────────────────────────

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        let json = self.send_public("/v2/products").await?;

        let products = json["result"]
            .as_array()
            .or_else(|| json.as_array())
            .map(|arr| arr.iter().collect::<Vec<_>>())
            .unwrap_or_default();

        let symbols: Vec<String> = products
            .iter()
            .filter_map(|p| {
                let sym = p["symbol"].as_str()?;
                let id = p["id"].as_u64()?;
                Some(format!("{}:{}", sym.to_uppercase(), id))
            })
            .collect();

        Ok(symbols)
    }

    // ── Order status ────────────────────────────────────────────────────

    async fn fetch_order_status(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let path = format!("/v2/orders/{}", order_id);
        let json = self.send_signed("GET", &path, None).await?;

        let status_str = json["state"].as_str().unwrap_or("unknown");
        let mapped_status = match status_str {
            "open" => "NEW",
            "filled" => "FILLED",
            "cancelled" | "canceled" => "CANCELED",
            "partially_filled" => "PARTIALLY_FILLED",
            "rejected" => "REJECTED",
            _ => "UNKNOWN",
        };

        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: String::new(),
            status: mapped_status.to_string(),
            filled_qty: parse_json_decimal(&json["filled_quantity"]),
            avg_price: parse_json_decimal(&json["avg_fill_price"]),
            exchange: self.name.clone(),
            fee: None,
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: None,
            updated_at_ms: None,
            deadline_ms: None,
        })
    }

    // ── Health check ────────────────────────────────────────────────────

    async fn health_check(&self) -> Result<()> {
        let base = self.config.base_url.trim_end_matches('/').trim_end_matches("/v2");
        // Try multiple public endpoints in order of reliability
        let endpoints = [
            format!("{}/v2/products?limit=1", base),
            format!("{}/v2/tickers", base),
        ];
        for url in &endpoints {
            match self.http.get(url).send().await {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                _ => continue,
            }
        }
        // Last resort: even a non-5xx response proves the API is reachable
        let url = format!("{}/v2/products", base);
        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_server_error() {
            Ok(())
        } else {
            anyhow::bail!("Delta health check failed: HTTP {}", resp.status())
        }
    }

    // ── Cancel all orders ───────────────────────────────────────────────

    async fn cancel_all_orders(&self, _symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        match self
            .send_signed("DELETE", "/v2/orders", None)
            .await
        {
            Ok(_) => results.push(Ok(OrderResponse {
                order_id: "cancel-all".to_string(),
                client_order_id: String::new(),
                status: "CANCELED".to_string(),
                filled_qty: Decimal::ZERO,
                avg_price: Decimal::ZERO,
                exchange: self.name.clone(),
                fee: None,
                fee_currency: None,
                slippage_bps: None,
                created_at_ms: Some(Self::now_ms()),
                updated_at_ms: Some(Self::now_ms()),
                deadline_ms: None,
            })),
            Err(e) => {
                tracing::error!("Delta cancel_all_orders failed: {}", e);
                results.push(Err(e));
            }
        }
        results
    }

    // ── Limit order ─────────────────────────────────────────────────────

    async fn place_limit_order(
        &self,
        order: &OrderRequest,
        price: Decimal,
    ) -> Result<OrderResponse> {
        let product_id = Self::resolve_product_id(&order.symbol);
        let body = serde_json::json!({
            "product_id": product_id,
            "size": order.quantity.to_string(),
            "side": Self::side_str(order.side),
            "order_type": "limit_order",
            "limit_price": price.to_string(),
        })
        .to_string();

        let json = self.send_signed("POST", "/v2/orders", Some(&body)).await?;

        let order_id = extract_order_id(&json["id"]).unwrap_or_else(|_| "unknown".to_string());

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
            created_at_ms: Some(Self::now_ms()),
            updated_at_ms: Some(Self::now_ms()),
            deadline_ms: None,
        })
    }

    // ── Order-type override ─────────────────────────────────────────────

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
                    anyhow::anyhow!("Delta limit order requires a price")
                })?;
                self.place_limit_order(order, p).await
            }
            _ => anyhow::bail!(
                "Order type {:?} not supported on Delta",
                order_type
            ),
        }
    }

    // ── Order book ──────────────────────────────────────────────────────

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        let product_id = Self::resolve_product_id(symbol);
        let url = format!(
            "{}/v2/tickers/orderbook?product_id={}&depth={}",
            self.config.base_url.trim_end_matches('/').trim_end_matches("/v2"),
            product_id,
            depth.min(50)
        );
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("Delta orderbook request failed: HTTP {}", status);
        }
        let text = resp.text().await?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("Delta orderbook parse error: {}", e))?;

        let result = &json["result"];

        let bids = result["buy_orders"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .take(depth as usize)
                    .filter_map(|entry| {
                        let price = parse_json_decimal(&entry["price"]);
                        let quantity = parse_json_decimal(&entry["size"]);
                        if price > Decimal::ZERO {
                            Some(OrderBookLevel { price, quantity })
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let asks = result["sell_orders"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .take(depth as usize)
                    .filter_map(|entry| {
                        let price = parse_json_decimal(&entry["price"]);
                        let quantity = parse_json_decimal(&entry["size"]);
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