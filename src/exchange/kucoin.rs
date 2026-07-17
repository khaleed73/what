//! KuCoin exchange implementation.
//!
//! Implements the `Exchange` trait for KuCoin V1/V2 API with HMAC-SHA256
//! signing and encrypted passphrase header. Supports market, limit, IOC,
//! and FOK order types with rate limit detection and backoff.

use async_trait::async_trait;
use rust_decimal::Decimal;
use std::collections::HashMap;

use crate::exchange::config::ExchangeConfig;
use crate::exchange::common::*;
use crate::exchange::exchange_trait::*;
use crate::exchange::types::*;
use anyhow::Result;

/// KuCoin exchange client with rate limiting.
pub struct KucoinClient {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
}

impl KucoinClient {
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

    /// Get the encrypted passphrase header value.
    fn encrypted_passphrase(&self) -> Result<String> {
        sign_kucoin_passphrase(
            self.config.api_secret.expose(),
            self.config.passphrase_str(),
        )
    }

    /// Parse a KuCoin order response from the data field.
    fn parse_order_response(&self, data: &serde_json::Value) -> Result<OrderResponse> {
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        Ok(OrderResponse {
            order_id: extract_order_id(&data["orderId"])?,
            client_order_id: extract_client_order_id(&data["clientOid"], "clientOid", "KuCoin"),
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
}

#[async_trait]
impl Exchange for KucoinClient {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> ExchangeType {
        ExchangeType::KuCoin
    }

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let side = if order.side == OrderSide::Buy {
            "buy"
        } else {
            "sell"
        };
        // Use client_order_id if provided, otherwise generate a UUID
        let client_oid = order
            .client_order_id
            .as_deref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let body = serde_json::json!({
            "clientOid": client_oid,
            "side": side,
            "symbol": order.symbol.replace('/', "-"),
            "type": "market",
            "size": order.quantity.to_string(),
        });
        let body_str = serde_json::to_string(&body)?;
        let endpoint = "/api/v1/orders";
        let sign_str = format!("{}POST{}{}", timestamp, endpoint, body_str);
        let signature = sign_hmac_base64(self.config.api_secret.expose(), &sign_str)?;
        let passphrase = self.encrypted_passphrase()?;
        let url = format!("{}/api/v1/orders", self.config.base_url);
        let resp = self
            .http
            .post(&url)
            .header("KC-API-KEY", self.config.api_key.expose())
            .header("KC-API-SIGN", &signature)
            .header("KC-API-TIMESTAMP", &timestamp)
            .header("KC-API-PASSPHRASE", &passphrase)
            .header("KC-API-KEY-VERSION", "2")
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let data = &json["data"];
        let mut resp = self.parse_order_response(data)?;
        if resp.filled_qty == Decimal::ZERO {
            match self.fetch_order_status(&order.symbol, &resp.order_id).await {
                Ok(status_resp) => {
                    resp.filled_qty = status_resp.filled_qty;
                    resp.avg_price = status_resp.avg_price;
                    resp.fee = status_resp.fee;
                }
                Err(e) => {
                    tracing::warn!("KuCoin: failed to fetch order status after place: {}", e);
                }
            }
        }
        Ok(resp)
    }

    async fn cancel_order(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let endpoint = format!("/api/v1/orders/{}", order_id);
        let sign_str = format!("{}DELETE{}", timestamp, endpoint);
        let signature = sign_hmac_base64(self.config.api_secret.expose(), &sign_str)?;
        let passphrase = self.encrypted_passphrase()?;
        let url = format!("{}{}", self.config.base_url, endpoint);
        let resp = self
            .http
            .delete(&url)
            .header("KC-API-KEY", self.config.api_key.expose())
            .header("KC-API-SIGN", &signature)
            .header("KC-API-TIMESTAMP", &timestamp)
            .header("KC-API-PASSPHRASE", &passphrase)
            .header("KC-API-KEY-VERSION", "2")
            .send()
            .await?;

        self.handle_response(resp).await?;

        // Fetch actual fill state after cancel — cancelled orders may have partial fills
        let (filled_qty, avg_price) = match self.fetch_order_status(symbol, order_id).await {
            Ok(status) => (status.filled_qty, status.avg_price),
            Err(e) => {
                tracing::warn!("KuCoin: failed to fetch order status after cancel: {}", e);
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
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let endpoint = "/api/v1/accounts";
        let sign_str = format!("{}GET{}", timestamp, endpoint);
        let signature = sign_hmac_base64(self.config.api_secret.expose(), &sign_str)?;
        let passphrase = self.encrypted_passphrase()?;
        let url = format!("{}/api/v1/accounts", self.config.base_url);
        let resp = self
            .http
            .get(&url)
            .header("KC-API-KEY", self.config.api_key.expose())
            .header("KC-API-SIGN", &signature)
            .header("KC-API-TIMESTAMP", &timestamp)
            .header("KC-API-PASSPHRASE", &passphrase)
            .header("KC-API-KEY-VERSION", "2")
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let mut balances = HashMap::new();
        if let Some(data) = json["data"].as_array() {
            for account in data {
                let available: f64 = account["available"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        let cur = account["currency"].as_str().unwrap_or("?");
                        let _ = parse_balance_f64(&account["available"], "kucoin", cur);
                        0.0
                    });
                if available > 0.0 {
                    balances.insert(
                        match extract_currency(&account["currency"], "currency", "KuCoin") {
                            Some(c) => c,
                            None => continue,
                        },
                        available,
                    );
                }
            }
        }
        Ok(balances
            .into_iter()
            .map(|(k, v)| {
                let bal = balance_f64_to_decimal(v, "kucoin", &k);
                (k, bal)
            })
            .collect())
    }

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        let url = format!("{}/api/v1/symbols", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        // Check content-type before parsing — KuCoin's Cloudflare may return
        // HTML instead of JSON when the request is flagged.
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !content_type.contains("application/json") {
            anyhow::bail!(
                "KuCoin returned non-JSON response (content-type: {}). \
                 This is usually caused by Cloudflare bot protection. \
                 The API is reachable but blocking this request.",
                content_type
            );
        }
        let json: serde_json::Value = resp.json().await?;
        let symbols = json["data"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter(|s| s["enableTrading"].as_bool() == Some(true))
                    .filter_map(|s| s["symbol"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok(symbols)
    }

    async fn fetch_order_status(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let endpoint = format!("/api/v1/orders/{}", order_id);
        let sign_str = format!("{}GET{}", timestamp, endpoint);
        let signature = sign_hmac_base64(self.config.api_secret.expose(), &sign_str)?;
        let passphrase = self.encrypted_passphrase()?;
        let url = format!("{}{}", self.config.base_url, endpoint);
        let resp = self
            .http
            .get(&url)
            .header("KC-API-KEY", self.config.api_key.expose())
            .header("KC-API-SIGN", &signature)
            .header("KC-API-TIMESTAMP", &timestamp)
            .header("KC-API-PASSPHRASE", &passphrase)
            .header("KC-API-KEY-VERSION", "2")
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let data = &json["data"];
        let filled_qty = parse_json_decimal(&data["dealSize"]);
        let fee = parse_json_decimal(&data["dealFee"]);
        let deal_funds = parse_json_decimal(&data["dealFunds"]);
        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: extract_client_order_id(&data["clientOid"], "clientOid", "KuCoin"),
            status: match data["status"].as_str() {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => {
                    tracing::warn!(context = "fetch_order_status", raw = %data["status"],
                        "KuCoin: order status field missing, defaulting to UNKNOWN");
                    "UNKNOWN".to_string()
                }
            },
            filled_qty,
            avg_price: if filled_qty > Decimal::ZERO {
                deal_funds / filled_qty
            } else {
                Decimal::ZERO
            },
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
        let url = format!("{}/api/v1/timestamp", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!("Health check failed: {}", resp.status())
        }
    }

    /// Kill switch: cancel all open orders using KuCoin's DELETE /api/v1/orders endpoint.
    /// DELETE /api/v1/orders cancels all open orders. We call per-symbol for consistency.
    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        for symbol in symbols {
            let kucoin_symbol = symbol.replace('/', "-");
            let timestamp = chrono::Utc::now().timestamp_millis().to_string();
            let endpoint = format!("/api/v1/orders?symbol={}", kucoin_symbol);
            let sign_str = format!("{}DELETE{}", timestamp, endpoint);
            let signature = match sign_hmac_base64(self.config.api_secret.expose(), &sign_str) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        "KuCoin cancel_all_orders signing failed for {}: {}",
                        kucoin_symbol,
                        e
                    );
                    results.push(Err(e));
                    continue;
                }
            };
            let passphrase = match self.encrypted_passphrase() {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(
                        "KuCoin cancel_all_orders passphrase failed for {}: {}",
                        kucoin_symbol,
                        e
                    );
                    results.push(Err(e));
                    continue;
                }
            };
            let url = format!("{}{}", self.config.base_url, endpoint);
            match self
                .http
                .delete(&url)
                .header("KC-API-KEY", self.config.api_key.expose())
                .header("KC-API-SIGN", &signature)
                .header("KC-API-TIMESTAMP", &timestamp)
                .header("KC-API-PASSPHRASE", &passphrase)
                .header("KC-API-KEY-VERSION", "2")
                .send()
                .await
            {
                Ok(resp) => match self.handle_response(resp).await {
                    Ok(_) => results.push(Ok(OrderResponse {
                        order_id: format!("cancel-all-{}", kucoin_symbol),
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
                            "KuCoin cancel_all_orders failed for {}: {}",
                            kucoin_symbol,
                            e
                        );
                        results.push(Err(e));
                    }
                },
                Err(e) => {
                    tracing::error!(
                        "KuCoin cancel_all_orders HTTP error for {}: {}",
                        kucoin_symbol,
                        e
                    );
                    results.push(Err(anyhow::anyhow!("KuCoin cancel_all HTTP error: {}", e)));
                }
            }
        }
        results
    }

    // ── Limit order support ──────────────────────────────────────────────

    async fn place_limit_order(
        &self,
        order: &OrderRequest,
        price: Decimal,
    ) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let side = if order.side == OrderSide::Buy {
            "buy"
        } else {
            "sell"
        };
        let client_oid = order
            .client_order_id
            .as_deref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let body = serde_json::json!({
            "clientOid": client_oid,
            "side": side,
            "symbol": order.symbol.replace('/', "-"),
            "type": "limit",
            "price": price.to_string(),
            "size": order.quantity.to_string(),
        });
        let body_str = serde_json::to_string(&body)?;
        let endpoint = "/api/v1/orders";
        let sign_str = format!("{}POST{}{}", timestamp, endpoint, body_str);
        let signature = sign_hmac_base64(self.config.api_secret.expose(), &sign_str)?;
        let passphrase = self.encrypted_passphrase()?;
        let url = format!("{}/api/v1/orders", self.config.base_url);
        let resp = self
            .http
            .post(&url)
            .header("KC-API-KEY", self.config.api_key.expose())
            .header("KC-API-SIGN", &signature)
            .header("KC-API-TIMESTAMP", &timestamp)
            .header("KC-API-PASSPHRASE", &passphrase)
            .header("KC-API-KEY-VERSION", "2")
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let data = &json["data"];
        let mut resp = self.parse_order_response(data)?;
        if resp.filled_qty == Decimal::ZERO {
            match self.fetch_order_status(&order.symbol, &resp.order_id).await {
                Ok(status_resp) => {
                    resp.filled_qty = status_resp.filled_qty;
                    resp.avg_price = status_resp.avg_price;
                    resp.fee = status_resp.fee;
                }
                Err(e) => {
                    tracing::warn!("KuCoin: failed to fetch order status after place: {}", e);
                }
            }
        }
        Ok(resp)
    }

    // ── Order-type override: Market / Limit / IOC / FOK ──────────────────

    async fn place_order_with_type(
        &self,
        order: &OrderRequest,
        order_type: OrderType,
        price: Option<Decimal>,
    ) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let side = if order.side == OrderSide::Buy {
            "buy"
        } else {
            "sell"
        };
        let client_oid = order
            .client_order_id
            .as_deref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // KuCoin: type=market|limit; timeInForce=GTC|GTT|IOC|FOK
        let (kc_type, time_in_force) = match order_type {
            OrderType::Market => ("market", None),
            OrderType::Limit => match order.time_in_force {
                TimeInForce::IOC => ("limit", Some("IOC")),
                TimeInForce::FOK => ("limit", Some("FOK")),
                _ => ("limit", Some("GTC")),
            },
            _ => anyhow::bail!(
                "Order type {:?} not supported on {}",
                order_type,
                self.name()
            ),
        };

        let mut body = serde_json::json!({
            "clientOid": client_oid,
            "side": side,
            "symbol": order.symbol.replace('/', "-"),
            "type": kc_type,
        });

        if order_type == OrderType::Market {
            body["size"] = serde_json::Value::String(order.quantity.to_string());
        } else {
            let p = price.ok_or_else(|| {
                anyhow::anyhow!("Limit order requires a price on {}", self.name())
            })?;
            body["price"] = serde_json::Value::String(p.to_string());
            body["size"] = serde_json::Value::String(order.quantity.to_string());
            if let Some(tif) = time_in_force {
                body["timeInForce"] = serde_json::Value::String(tif.to_string());
            }
        }

        let body_str = serde_json::to_string(&body)?;
        let endpoint = "/api/v1/orders";
        let sign_str = format!("{}POST{}{}", timestamp, endpoint, body_str);
        let signature = sign_hmac_base64(self.config.api_secret.expose(), &sign_str)?;
        let passphrase = self.encrypted_passphrase()?;
        let url = format!("{}/api/v1/orders", self.config.base_url);
        let resp = self
            .http
            .post(&url)
            .header("KC-API-KEY", self.config.api_key.expose())
            .header("KC-API-SIGN", &signature)
            .header("KC-API-TIMESTAMP", &timestamp)
            .header("KC-API-PASSPHRASE", &passphrase)
            .header("KC-API-KEY-VERSION", "2")
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let data = &json["data"];
        let mut resp = self.parse_order_response(data)?;
        if resp.filled_qty == Decimal::ZERO {
            match self.fetch_order_status(&order.symbol, &resp.order_id).await {
                Ok(status_resp) => {
                    resp.filled_qty = status_resp.filled_qty;
                    resp.avg_price = status_resp.avg_price;
                    resp.fee = status_resp.fee;
                }
                Err(e) => {
                    tracing::warn!("KuCoin: failed to fetch order status after place: {}", e);
                }
            }
        }
        Ok(resp)
    }

    // ── Order book with proper depth levels ──────────────────────────────

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        let kucoin_symbol = symbol.replace('/', "-");
        // KuCoin has different endpoints for different depth levels:
        // level2_20 = 20 levels, level2_100 = 100 levels, level3 = full book
        let (endpoint, effective_depth) = if depth <= 20 {
            ("level2_20", depth)
        } else if depth <= 100 {
            ("level2_100", depth)
        } else {
            ("level3", depth)
        };
        let url = format!(
            "{}/api/v1/market/orderbook/{}?symbol={}",
            self.config.base_url, endpoint, kucoin_symbol
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        let data = &json["data"];

        let bids = data["bids"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .take(effective_depth as usize)
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

        let asks = data["asks"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .take(effective_depth as usize)
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

        let timestamp_ms = data["time"].as_u64().unwrap_or_else(|| {
                tracing::warn!(exchange = "KuCoin", raw = %data["time"], "orderbook timestamp missing, using Poisson fallback");
                chrono::Utc::now().timestamp_millis() as u64
            });

        Ok(OrderBookSnapshot {
            symbol: symbol.to_string(),
            exchange: self.name.clone(),
            bids,
            asks,
            timestamp_us: timestamp_ms * 1000,
        })
    }
}