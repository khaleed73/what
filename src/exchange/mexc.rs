//! MEXC exchange implementation.
//!
//! Implements the `Exchange` trait for MEXC API v3 (Binance-compatible) with
//! HMAC-SHA256 signing. Signature is appended as a query parameter:
//!   signature = HMAC-SHA256(api_secret, queryString)
//! Auth uses the X-MEXC-APIKEY header. Supports market, limit, IOC, and FOK
//! order types with rate limit detection and backoff.

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

/// MEXC exchange client with HMAC-SHA256 auth and rate limiting.
pub struct MexcExchange {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
}

impl MexcExchange {
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

    /// Build a signed query string for MEXC (Binance-style).
    ///
    /// timestamp=NOW&symbol=BTCUSDT&...&signature=HMAC_HEX
    fn signed_query(&self, params: &[(String, String)]) -> Result<String> {
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let mut all_params: Vec<(String, String)> = vec![
            ("timestamp".to_string(), timestamp),
        ];
        for (k, v) in params {
            all_params.push((k.clone(), v.clone()));
        }
        let query: String = all_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        let signature = sign_hmac(self.config.api_secret.expose(), &query)?;
        Ok(format!("{}&signature={}", query, signature))
    }

    /// Convert internal symbol (BTC/USDT) to MEXC format (BTCUSDT).
    fn to_mexc_symbol(symbol: &str) -> String {
        symbol.replace('/', "").to_uppercase()
    }
}

#[async_trait]
impl Exchange for MexcExchange {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> ExchangeType {
        ExchangeType::Mexc
    }

    // ── Place market order ──────────────────────────────────────────────

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let mexc_symbol = Self::to_mexc_symbol(&order.symbol);
        let side = if order.side == OrderSide::Buy {
            "BUY"
        } else {
            "SELL"
        };

        // Signed query string for authentication (timestamp + signature)
        let query = self.signed_query(&[])?;

        // Order parameters in the request body
        let mut body = serde_json::json!({
            "symbol": mexc_symbol,
            "side": side,
            "type": "MARKET",
            "quantity": order.quantity.to_string(),
        });
        if let Some(ref client_oid) = order.client_order_id {
            if !client_oid.is_empty() {
                body["newClientOrderId"] = serde_json::Value::String(client_oid.clone());
            }
        }

        let url = format!(
            "{}/api/v3/order?{}",
            self.config.base_url.trim_end_matches('/'),
            query
        );

        let resp = self
            .http
            .post(&url)
            .header("X-MEXC-APIKEY", self.config.api_key.expose())
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let order_id = extract_order_id(&json["orderId"])
            .unwrap_or_else(|_| "unknown".to_string());

        let filled_qty = parse_json_decimal(&json["filledQty"]);
        let avg_price = parse_json_decimal(&json["avgPrice"]);

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
    //
    // DELETE /api/v3/order?timestamp=NOW&symbol=SYMBOL&orderId=ID&signature=SIG

    async fn cancel_order(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let mexc_symbol = Self::to_mexc_symbol(symbol);

        let params = vec![
            ("symbol".to_string(), mexc_symbol),
            ("orderId".to_string(), order_id.to_string()),
        ];
        let query = self.signed_query(&params)?;
        let url = format!(
            "{}/api/v3/order?{}",
            self.config.base_url.trim_end_matches('/'),
            query
        );

        let resp = self
            .http
            .delete(&url)
            .header("X-MEXC-APIKEY", self.config.api_key.expose())
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let (filled_qty, avg_price) = match self.fetch_order_status(symbol, order_id).await {
            Ok(s) => (s.filled_qty, s.avg_price),
            Err(_) => (Decimal::ZERO, Decimal::ZERO),
        };

        let cancelled_id = extract_order_id(&json["orderId"])
            .unwrap_or_else(|_| order_id.to_string());

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
        self.rate_limiter.throttle().await;
        let query = self.signed_query(&[])?;
        let url = format!(
            "{}/api/v3/account?{}",
            self.config.base_url.trim_end_matches('/'),
            query
        );

        let resp = self
            .http
            .get(&url)
            .header("X-MEXC-APIKEY", self.config.api_key.expose())
            .send()
            .await?;

        let json = self.handle_response(resp).await?;
        let mut balances = HashMap::new();

        if let Some(balances_arr) = json["balances"].as_array() {
            for b in balances_arr {
                let asset = match extract_currency(&b["asset"], "asset", "MEXC") {
                        Some(a) => a.to_uppercase(),
                        None => continue,
                    };
                let free: f64 = b["free"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        parse_balance_f64(&b["free"], "mexc", &asset);
                        0.0
                    });
                if free > 0.0 {
                    balances.insert(
                        asset,
                        balance_f64_to_decimal(free, "mexc", &asset),
                    );
                }
            }
        }

        Ok(balances)
    }

    // ── Fetch symbols ──────────────────────────────────────────────────

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        let url = format!(
            "{}/api/v3/exchangeInfo",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;

        let symbols = json["symbols"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter(|s| {
                        let st = s["status"].as_str().unwrap_or("");
                        st == "ENABLED" || st == "1" || st == "TRADING"
                    })
                    .filter_map(|s| {
                        let sym = s["symbol"].as_str()?;
                        Some(sym.to_uppercase())
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(symbols)
    }

    // ── Fetch order status ─────────────────────────────────────────────
    //
    // GET /api/v3/order?timestamp=NOW&symbol=SYMBOL&orderId=ID&signature=SIG

    async fn fetch_order_status(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let mexc_symbol = Self::to_mexc_symbol(symbol);

        let params = vec![
            ("symbol".to_string(), mexc_symbol),
            ("orderId".to_string(), order_id.to_string()),
        ];
        let query = self.signed_query(&params)?;
        let url = format!(
            "{}/api/v3/order?{}",
            self.config.base_url.trim_end_matches('/'),
            query
        );

        let resp = self
            .http
            .get(&url)
            .header("X-MEXC-APIKEY", self.config.api_key.expose())
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let status_str = json["status"].as_str().unwrap_or("UNKNOWN");
        if status_str == "UNKNOWN" && json["status"].is_null() {
            tracing::warn!(context = "fetch_order_status", raw = %json["status"],
                "MEXC: order status field missing/null");
        }
        let mapped_status = match status_str {
            "NEW" => "NEW",
            "PARTIALLY_FILLED" => "PARTIALLY_FILLED",
            "FILLED" => "FILLED",
            "CANCELED" | "CANCELLED" | "EXPIRED" => "CANCELED",
            _ => "UNKNOWN",
        };

        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: extract_client_order_id(&json["clientOrderId"], "clientOrderId", "MEXC"),
            status: mapped_status.to_string(),
            filled_qty: parse_json_decimal(&json["filledQty"]),
            avg_price: parse_json_decimal(&json["avgPrice"]),
            exchange: self.name.clone(),
            fee: None,
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
            "{}/api/v3/ping",
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
            let mexc_symbol = Self::to_mexc_symbol(symbol);
            let params = vec![("symbol".to_string(), mexc_symbol.clone())];
            let url = match self.signed_query(&params) {
                Ok(query) => format!(
                    "{}/api/v3/openOrders?{}",
                    self.config.base_url.trim_end_matches('/'),
                    query
                ),
                Err(e) => {
                    tracing::error!(
                        "{} cancel_all_orders signing failed for {}: {}",
                        self.name(),
                        mexc_symbol,
                        e
                    );
                    results.push(Err(e));
                    continue;
                }
            };

            match self
                .http
                .delete(&url)
                .header("X-MEXC-APIKEY", self.config.api_key.expose())
                .send()
                .await
            {
                Ok(resp) => match self.handle_response(resp).await {
                    Ok(_) => results.push(Ok(OrderResponse {
                        order_id: format!("cancel-all-{}", mexc_symbol),
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
                            "{} cancel_all_orders failed for {}: {}",
                            self.name(),
                            mexc_symbol,
                            e
                        );
                        results.push(Err(e));
                    }
                },
                Err(e) => {
                    tracing::error!(
                        "{} cancel_all_orders HTTP error for {}: {}",
                        self.name(),
                        mexc_symbol,
                        e
                    );
                    results.push(Err(anyhow::anyhow!("{} cancel_all HTTP error: {}", self.name(), e)));
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
        self.rate_limiter.throttle().await;
        let mexc_symbol = Self::to_mexc_symbol(&order.symbol);
        let side = if order.side == OrderSide::Buy {
            "BUY"
        } else {
            "SELL"
        };

        let query = self.signed_query(&[])?;

        let mut body = serde_json::json!({
            "symbol": mexc_symbol,
            "side": side,
            "type": "LIMIT",
            "quantity": order.quantity.to_string(),
            "price": price.to_string(),
            "timeInForce": "GTC",
        });
        if let Some(ref client_oid) = order.client_order_id {
            if !client_oid.is_empty() {
                body["newClientOrderId"] = serde_json::Value::String(client_oid.clone());
            }
        }

        let url = format!(
            "{}/api/v3/order?{}",
            self.config.base_url.trim_end_matches('/'),
            query
        );

        let resp = self
            .http
            .post(&url)
            .header("X-MEXC-APIKEY", self.config.api_key.expose())
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let order_id = extract_order_id(&json["orderId"])
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
        self.rate_limiter.throttle().await;
        let mexc_symbol = Self::to_mexc_symbol(&order.symbol);
        let side = if order.side == OrderSide::Buy {
            "BUY"
        } else {
            "SELL"
        };

        let (mexc_type, tif) = match order_type {
            OrderType::Market => ("MARKET", None),
            OrderType::Limit => ("LIMIT", Some("GTC")),
            OrderType::StopLimit => ("STOP", Some("GTC")),
            OrderType::StopMarket => ("STOP_MARKET", None),
        };

        let query = self.signed_query(&[])?;

        let mut body = serde_json::json!({
            "symbol": mexc_symbol,
            "side": side,
            "type": mexc_type,
            "quantity": order.quantity.to_string(),
        });

        if let Some(t) = tif {
            body["timeInForce"] = serde_json::Value::String(t.to_string());
        }

        // Price is required for LIMIT and STOP
        if order_type == OrderType::Limit || order_type == OrderType::StopLimit {
            let p = price.ok_or_else(|| {
                anyhow::anyhow!("MEXC {} order requires a price", mexc_type)
            })?;
            body["price"] = serde_json::Value::String(p.to_string());
        }

        // Stop price for stop orders
        if order_type == OrderType::StopLimit || order_type == OrderType::StopMarket {
            let sp = order.stop_price.ok_or_else(|| {
                anyhow::anyhow!("MEXC stop order requires a stop_price")
            })?;
            body["stopPrice"] = serde_json::Value::String(sp.to_string());
        }

        if let Some(ref client_oid) = order.client_order_id {
            if !client_oid.is_empty() {
                body["newClientOrderId"] = serde_json::Value::String(client_oid.clone());
            }
        }

        let url = format!(
            "{}/api/v3/order?{}",
            self.config.base_url.trim_end_matches('/'),
            query
        );

        let resp = self
            .http
            .post(&url)
            .header("X-MEXC-APIKEY", self.config.api_key.expose())
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let order_id = extract_order_id(&json["orderId"])
            .unwrap_or_else(|_| "unknown".to_string());

        let filled_qty = parse_json_decimal(&json["filledQty"]);
        let avg_price = parse_json_decimal(&json["avgPrice"]);

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

    // ── Order book ─────────────────────────────────────────────────────

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        let mexc_symbol = Self::to_mexc_symbol(symbol);
        let limit = depth.min(100);
        let url = format!(
            "{}/api/v3/depth?symbol={}&limit={}",
            self.config.base_url.trim_end_matches('/'),
            mexc_symbol,
            limit
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