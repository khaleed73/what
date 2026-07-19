//! BitMEX exchange implementation.
//!
//! Implements the `Exchange` trait for BitMEX with HMAC-SHA256 signing
//! using expires-based authentication. Supports market, limit, IOC,
//! and FOK order types with rate limit detection and backoff.

use async_trait::async_trait;
use rust_decimal::Decimal;
use std::collections::HashMap;

use crate::exchange::config::ExchangeConfig;
use crate::exchange::common::*;
use crate::exchange::exchange_trait::*;
use crate::exchange::types::*;
use anyhow::Result;

/// BitMEX exchange client with rate limiting.
pub struct BitmexClient {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
}

impl BitmexClient {
    pub fn new(name: String, config: ExchangeConfig) -> Result<Self> {
        let timeout_secs = config.http_timeout_secs.unwrap_or(30);
        let http = build_http_client(timeout_secs)?;
        Ok(Self {
            name,
            config,
            http,
            rate_limiter: RateLimiter::new(100),
        })
    }

    /// Handle exchange response with rate limit detection and backoff.
    async fn handle_response(&self, resp: reqwest::Response) -> Result<serde_json::Value> {
        let status = resp.status();
        if status.as_u16() == 429 {
            tracing::warn!("BitMEX rate limited (HTTP 429), backing off ~1s with jitter");
            jittered_rate_limit_sleep().await;
            anyhow::bail!("Rate limited by BitMEX (HTTP 429)");
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("BitMEX API error (HTTP {}): {}", status, body);
        }
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("BitMEX: failed to parse response: {}", e))?;
        Ok(json)
    }

    /// Build common BitMEX signed headers.
    fn build_signed_headers(
        &self,
        verb: &str,
        path: &str,
        expires: u64,
        body: &str,
    ) -> Result<(&str, String, String)> {
        let sign = sign_bitmex(self.config.api_secret.expose(), verb, path, expires, body)?;
        Ok((self.config.api_key.expose(), expires.to_string(), sign))
    }

    /// Build a BitMEX order body with type, price, and idempotency key.
    fn build_order_body(
        order: &OrderRequest,
        ord_type: &str,
        price: Option<Decimal>,
        time_in_force: Option<&str>,
    ) -> serde_json::Value {
        let mut body = serde_json::json!({
            "symbol": order.symbol.replace("/", "").to_uppercase(),
            "side": if order.side == OrderSide::Buy { "Buy" } else { "Sell" },
            "orderQty": order.quantity,
            "ordType": ord_type,
        });
        if let Some(p) = price {
            body["price"] = serde_json::to_value(p).unwrap_or(serde_json::Value::Null);
        }
        if let Some(tif) = time_in_force {
            body["timeInForce"] = serde_json::Value::String(tif.to_string());
        }
        // Add clOrdID for idempotency
        if let Some(ref client_oid) = order.client_order_id {
            if !client_oid.is_empty() {
                body["clOrdID"] = serde_json::Value::String(client_oid.clone());
            }
        }
        body
    }

    /// Send a signed POST order request to BitMEX.
    async fn send_bitmex_order(&self, body: serde_json::Value) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let expires = chrono::Utc::now().timestamp() as u64 + 300;
        let body_str = body.to_string();
        let (api_key, expires_str, sign) =
            self.build_signed_headers("POST", "/api/v1/order", expires, &body_str)?;
        let url = format!(
            "{}/api/v1/order",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .post(&url)
            .header("api-key", api_key)
            .header("api-expires", &expires_str)
            .header("api-signature", &sign)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;
        let order_id = json["orderID"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("BitMEX: missing orderID in response"))?
            .to_string();
        let cl_ord_id = json["clOrdID"].as_str().unwrap_or("").to_string();

        Ok(OrderResponse {
            order_id,
            client_order_id: cl_ord_id,
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
impl Exchange for BitmexClient {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> ExchangeType {
        ExchangeType::Bitmex
    }

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        let body = Self::build_order_body(order, "Market", None, None);
        let mut resp = self.send_bitmex_order(body).await?;
        if resp.filled_qty == Decimal::ZERO {
            match self.fetch_order_status(&order.symbol, &resp.order_id).await {
                Ok(status_resp) => {
                    resp.filled_qty = status_resp.filled_qty;
                    resp.avg_price = status_resp.avg_price;
                    resp.fee = status_resp.fee;
                }
                Err(e) => {
                    tracing::warn!("BitMEX: failed to fetch order status after place: {}", e);
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
        let tif = match order.time_in_force {
            TimeInForce::IOC => Some("ImmediateOrCancel"),
            TimeInForce::FOK => Some("FillOrKill"),
            TimeInForce::GTC => Some("GoodTillCancel"),
            TimeInForce::Day => None, // Day is BitMEX default
        };
        let body = Self::build_order_body(order, "Limit", Some(price), tif);
        let mut resp = self.send_bitmex_order(body).await?;
        if resp.filled_qty == Decimal::ZERO {
            match self.fetch_order_status(&order.symbol, &resp.order_id).await {
                Ok(status_resp) => {
                    resp.filled_qty = status_resp.filled_qty;
                    resp.avg_price = status_resp.avg_price;
                    resp.fee = status_resp.fee;
                }
                Err(e) => {
                    tracing::warn!("BitMEX: failed to fetch order status after place: {}", e);
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
                let p =
                    price.ok_or_else(|| anyhow::anyhow!("BitMEX limit order requires a price"))?;
                self.place_limit_order(order, p).await
            }
            OrderType::StopLimit => {
                let p =
                    price.ok_or_else(|| anyhow::anyhow!("BitMEX stop-limit requires a price"))?;
                let stop_price = order
                    .stop_price
                    .ok_or_else(|| anyhow::anyhow!("BitMEX stop-limit requires a stop_price"))?;
                let body = serde_json::json!({
                    "symbol": order.symbol.replace("/", "").to_uppercase(),
                    "side": if order.side == OrderSide::Buy { "Buy" } else { "Sell" },
                    "orderQty": order.quantity,
                    "ordType": "StopLimit",
                    "price": p,
                    "stopPx": stop_price,
                });
                self.send_bitmex_order(body).await
            }
            OrderType::StopMarket => {
                let stop_price = order
                    .stop_price
                    .ok_or_else(|| anyhow::anyhow!("BitMEX stop-market requires a stop_price"))?;
                let body = serde_json::json!({
                    "symbol": order.symbol.replace("/", "").to_uppercase(),
                    "side": if order.side == OrderSide::Buy { "Buy" } else { "Sell" },
                    "orderQty": order.quantity,
                    "ordType": "Stop",
                    "stopPx": stop_price,
                });
                self.send_bitmex_order(body).await
            }
        }
    }

    async fn cancel_order(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let expires = chrono::Utc::now().timestamp() as u64 + 300;
        let body = serde_json::json!({ "orderID": order_id });
        let body_str = body.to_string();
        let (api_key, expires_str, sign) =
            self.build_signed_headers("DELETE", "/api/v1/order", expires, &body_str)?;
        let url = format!(
            "{}/api/v1/order",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .delete(&url)
            .header("api-key", api_key)
            .header("api-expires", &expires_str)
            .header("api-signature", &sign)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await?;
        self.handle_response(resp).await?;

        // Fetch actual fill state after cancel — cancelled orders may have partial fills
        let (filled_qty, avg_price) = match self.fetch_order_status(symbol, order_id).await {
            Ok(status) => (status.filled_qty, status.avg_price),
            Err(e) => {
                tracing::warn!("BitMEX: failed to fetch order status after cancel: {}", e);
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
        self.rate_limiter.throttle().await;
        let expires = chrono::Utc::now().timestamp() as u64 + 300;
        let sign = sign_bitmex(
            self.config.api_secret.expose(),
            "GET",
            "/api/v1/user/wallet",
            expires,
            "",
        )?;
        let url = format!(
            "{}/api/v1/user/wallet",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .get(&url)
            .header("api-key", self.config.api_key.expose())
            .header("api-expires", expires.to_string())
            .header("api-signature", &sign)
            .send()
            .await?;
        let json = self.handle_response(resp).await?;
        let mut balances = HashMap::new();
        // B9 FIX: BitMEX /api/v1/user/wallet returns amount in satoshis (1 BTC = 100,000,000 satoshis)
        // Must convert to BTC to avoid balance being off by 10^8
        if let Some(bal) = json["amount"].as_i64() {
            let btc_balance = Decimal::from(bal) / Decimal::from(100_000_000);
            balances.insert("XBT".to_string(), btc_balance);
        }
        Ok(balances)
    }

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        let url = format!(
            "{}/api/v1/instrument/active",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        Ok(json
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s["symbol"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn fetch_order_status(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let expires = chrono::Utc::now().timestamp() as u64 + 300;
        let path = format!("/api/v1/order?filter={{\"orderID\":\"{}\"}}", order_id);
        let sign = sign_bitmex(self.config.api_secret.expose(), "GET", &path, expires, "")?;
        let url = format!(
            "{}/api/v1/order?filter={{\"orderID\":\"{}\"}}",
            self.config.base_url.trim_end_matches('/'),
            order_id
        );
        let resp = self
            .http
            .get(&url)
            .header("api-key", self.config.api_key.expose())
            .header("api-expires", expires.to_string())
            .header("api-signature", &sign)
            .send()
            .await?;
        let json = self.handle_response(resp).await?;
        let o = json
            .as_array()
            .and_then(|a| a.first())
            .ok_or_else(|| anyhow::anyhow!("BitMEX: order not found: {}", order_id))?;
        let fee = parse_json_decimal(if o["commission"].as_str().is_some() {
            &o["commission"]
        } else {
            &o["fee"]
        });
        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: extract_client_order_id(&o["clOrdID"], "clOrdID", "BitMEX"),
            status: match o["ordStatus"].as_str() {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => {
                    tracing::warn!(context = "fetch_order_status", raw = %o["ordStatus"],
                        "BitMEX: ordStatus field missing, defaulting to UNKNOWN");
                    "UNKNOWN".to_string()
                }
            },
            filled_qty: parse_json_decimal(&o["cumQty"]),
            avg_price: parse_json_decimal(&o["avgPx"]),
            exchange: self.name.clone(),
            fee: if fee.abs() > Decimal::ZERO {
                Some(fee)
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

    async fn health_check(&self) -> Result<()> {
        let url = format!("{}/api/v1/instrument?symbol=XBTUSD", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!("Health check failed: {}", resp.status())
        }
    }

    /// Kill switch: cancel all open orders using BitMEX's DELETE /api/v1/order/all endpoint.
    /// Cancels all orders, optionally filtered by symbol query param.
    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        for symbol in symbols {
            let bitmex_symbol = symbol.replace('/', "").to_uppercase();
            let expires = chrono::Utc::now().timestamp() as u64 + 300;
            let query = format!("symbol={}", bitmex_symbol);
            let path = format!("/api/v1/order/all?{}", query);
            let (api_key, expires_str, sign) =
                match self.build_signed_headers("DELETE", &path, expires, "") {
                    Ok(h) => h,
                    Err(e) => {
                        tracing::error!(
                            "BitMEX cancel_all_orders signing failed for {}: {}",
                            bitmex_symbol,
                            e
                        );
                        results.push(Err(e));
                        continue;
                    }
                };
            let url = format!(
                "{}/api/v1/order/all?{}",
                self.config.base_url.trim_end_matches('/'),
                query
            );
            match self
                .http
                .delete(&url)
                .header("api-key", api_key)
                .header("api-expires", &expires_str)
                .header("api-signature", &sign)
                .send()
                .await
            {
                Ok(resp) => match self.handle_response(resp).await {
                    Ok(_) => results.push(Ok(OrderResponse {
                        order_id: format!("cancel-all-{}", bitmex_symbol),
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
                            "BitMEX cancel_all_orders failed for {}: {}",
                            bitmex_symbol,
                            e
                        );
                        results.push(Err(e));
                    }
                },
                Err(e) => {
                    tracing::error!(
                        "BitMEX cancel_all_orders HTTP error for {}: {}",
                        bitmex_symbol,
                        e
                    );
                    results.push(Err(anyhow::anyhow!("BitMEX cancel_all HTTP error: {}", e)));
                }
            }
        }
        results
    }

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        self.rate_limiter.throttle().await;
        let bitmex_symbol = symbol.replace('/', "").to_uppercase();
        let url = format!(
            "{}/api/v1/orderBook/L2?symbol={}&depth={}",
            self.config.base_url.trim_end_matches('/'),
            bitmex_symbol,
            depth
        );
        let resp = self.http.get(&url).send().await?;
        let json = self.handle_response(resp).await?;

        let bids = json
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter(|e| e["side"].as_str() == Some("Buy"))
                    .take(depth as usize)
                    .filter_map(|entry| {
                        let price = parse_json_decimal(&entry["price"]);
                        let size_i = entry["size"].as_i64().unwrap_or(0);
                        let quantity = Decimal::from(size_i);
                        if price > Decimal::ZERO {
                            Some(OrderBookLevel { price, quantity })
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let asks = json
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter(|e| e["side"].as_str() == Some("Sell"))
                    .take(depth as usize)
                    .filter_map(|entry| {
                        let price = parse_json_decimal(&entry["price"]);
                        let size_i = entry["size"].as_i64().unwrap_or(0);
                        let quantity = Decimal::from(size_i);
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
