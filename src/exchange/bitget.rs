//! Bitget exchange implementation.
//!
//! Implements the `Exchange` trait for Bitget spot API with HMAC-SHA256
//! signing using base64-decoded secret. Supports market, limit, IOC,
//! and FOK order types with rate limit detection and backoff.

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

/// Bitget exchange client with rate limiting.
pub struct BitgetClient {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
    /// B8 FIX: Pre-computed encrypted passphrase (HMAC-SHA256 of passphrase
    /// with secret key, base64-encoded). Bitget V2 requires this.
    encrypted_passphrase: String,
}

impl BitgetClient {
    pub fn new(name: String, config: ExchangeConfig) -> Result<Self> {
        let timeout_secs = config.http_timeout_secs.unwrap_or(30);
        let http = build_http_client(timeout_secs)?;

        // B8 FIX: Bitget V2 requires passphrase to be HMAC-SHA256 encrypted
        // with the API secret, base64-encoded. Pre-compute at construction.
        let encrypted_passphrase = match &config.passphrase {
            Some(pp) if !pp.expose().is_empty() => sign_kucoin_passphrase(config.api_secret.expose(), pp.expose())?,
            _ => String::new(),
        };

        Ok(Self {
            name,
            config,
            http,
            rate_limiter: RateLimiter::new(100),
            encrypted_passphrase,
        })
    }

    /// Handle exchange response with rate limit detection and backoff.
    async fn handle_response(&self, resp: reqwest::Response) -> Result<serde_json::Value> {
        match parse_exchange_response(resp, "Bitget").await {
            Ok(json) => Ok(json),
            Err(ExchangeError::ApiError {
                is_rate_limited: true,
                message,
                ..
            }) => {
                tracing::warn!("Bitget rate limited, backing off 1s: {}", message);
                tokio::time::sleep(Duration::from_secs(1)).await;
                anyhow::bail!("Rate limited by Bitget: {}", message);
            }
            Err(e) => Err(into_anyhow(e)),
        }
    }

    /// Build the Bitget spot symbol format (e.g. "BTCUSDT").
    /// Note: V2 public market endpoints use plain symbols without suffix.
    fn bitget_symbol(symbol: &str) -> String {
        symbol.replace('/', "").to_uppercase()
    }

    /// Common signed POST to Bitget.
    async fn signed_post(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        self.rate_limiter.throttle().await;
        let ts = chrono::Utc::now().timestamp_millis().to_string();
        let body_str = body.to_string();
        let sign = sign_bitget(
            self.config.api_secret.expose(),
            &ts,
            "POST",
            path,
            &body_str,
        )?;
        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);
        let resp = self
            .http
            .post(&url)
            .header("ACCESS-KEY", self.config.api_key.expose())
            .header("ACCESS-SIGN", &sign)
            .header("ACCESS-TIMESTAMP", &ts)
            .header("ACCESS-PASSPHRASE", self.encrypted_passphrase.as_str())
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Common signed GET to Bitget.
    async fn signed_get(&self, path: &str) -> Result<serde_json::Value> {
        self.rate_limiter.throttle().await;
        let ts = chrono::Utc::now().timestamp_millis().to_string();
        let sign = sign_bitget(self.config.api_secret.expose(), &ts, "GET", path, "")?;
        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);
        let resp = self
            .http
            .get(&url)
            .header("ACCESS-KEY", self.config.api_key.expose())
            .header("ACCESS-SIGN", &sign)
            .header("ACCESS-TIMESTAMP", &ts)
            .header("ACCESS-PASSPHRASE", self.encrypted_passphrase.as_str())
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Build a Bitget order body with type, force, and idempotency key.
    fn build_order_body(
        order: &OrderRequest,
        order_type: &str,
        force: &str,
        price: Option<Decimal>,
    ) -> serde_json::Value {
        let client_oid = order.client_order_id.as_deref().unwrap_or("");
        let mut body = serde_json::json!({
            "symbol": Self::bitget_symbol(&order.symbol),
            "side": if order.side == OrderSide::Buy { "buy" } else { "sell" },
            "orderType": order_type,
            "force": force,
            "quantity": order.quantity.to_string(),
            "clientOid": if client_oid.is_empty() {
                uuid::Uuid::new_v4().to_string()
            } else {
                client_oid.to_string()
            },
        });
        if let Some(p) = price {
            body["price"] = serde_json::Value::String(p.to_string());
        } else {
            body["price"] = serde_json::Value::String("0".to_string());
        }
        body
    }

    /// Parse a Bitget order response.
    fn parse_order_response(
        &self,
        json: &serde_json::Value,
        client_oid: &str,
    ) -> Result<OrderResponse> {
        let order_id = json["data"]["orderId"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Bitget: missing orderId in response"))?
            .to_string();
        Ok(OrderResponse {
            order_id,
            client_order_id: client_oid.to_string(),
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
impl Exchange for BitgetClient {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> ExchangeType {
        ExchangeType::Bitget
    }

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        let body = Self::build_order_body(order, "market", "ioc", None);
        let json = self
            .signed_post("/api/spot/v1/trade/orders", body.clone())
            .await?;
        let client_oid = body["clientOid"].as_str().unwrap_or("").to_string();
        let mut resp = self.parse_order_response(&json, &client_oid)?;
        if resp.filled_qty == Decimal::ZERO {
            match self.fetch_order_status(&order.symbol, &resp.order_id).await {
                Ok(status_resp) => {
                    resp.filled_qty = status_resp.filled_qty;
                    resp.avg_price = status_resp.avg_price;
                    resp.fee = status_resp.fee;
                }
                Err(e) => {
                    tracing::warn!("Bitget: failed to fetch order status after place: {}", e);
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
        let force = match order.time_in_force {
            TimeInForce::IOC => "ioc",
            TimeInForce::FOK => "fok",
            TimeInForce::GTC | TimeInForce::Day => "gtc",
        };
        let body = Self::build_order_body(order, "limit", force, Some(price));
        let json = self
            .signed_post("/api/spot/v1/trade/orders", body.clone())
            .await?;
        let client_oid = body["clientOid"].as_str().unwrap_or("").to_string();
        let mut resp = self.parse_order_response(&json, &client_oid)?;
        if resp.filled_qty == Decimal::ZERO {
            match self.fetch_order_status(&order.symbol, &resp.order_id).await {
                Ok(status_resp) => {
                    resp.filled_qty = status_resp.filled_qty;
                    resp.avg_price = status_resp.avg_price;
                    resp.fee = status_resp.fee;
                }
                Err(e) => {
                    tracing::warn!("Bitget: failed to fetch order status after place: {}", e);
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
                    price.ok_or_else(|| anyhow::anyhow!("Bitget limit order requires a price"))?;
                self.place_limit_order(order, p).await
            }
            OrderType::StopLimit | OrderType::StopMarket => {
                anyhow::bail!("Order type {:?} not supported on Bitget spot", order_type)
            }
        }
    }

    async fn cancel_order(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let body = serde_json::json!({
            "symbol": Self::bitget_symbol(symbol),
            "orderId": order_id,
        });
        self.signed_post("/api/spot/v1/trade/cancel-order", body)
            .await?;

        // Fetch actual fill state after cancel — cancelled orders may have partial fills
        let (filled_qty, avg_price) = match self.fetch_order_status(symbol, order_id).await {
            Ok(status) => (status.filled_qty, status.avg_price),
            Err(e) => {
                tracing::warn!("Bitget: failed to fetch order status after cancel: {}", e);
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
        let json = self.signed_get("/api/spot/v1/account/assets").await?;
        let mut balances = HashMap::new();
        if let Some(arr) = json["data"].as_array() {
            for item in arr {
                let free: f64 = item["available"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.0);
                if free > 0.0 {
                    let coin = item["coinName"].as_str().unwrap_or("").to_uppercase();
                    balances.insert(coin, Decimal::from_f64(free).unwrap_or(Decimal::ZERO));
                }
            }
        }
        Ok(balances)
    }

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        // Bitget V2 API (V1 was decommissioned).
        let url = format!(
            "{}/api/v2/spot/public/symbols",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        Ok(json["data"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| {
                        let sym = s["symbol"].as_str()?;
                        let status = s["status"].as_str().unwrap_or("");
                        if status == "online" || status == "trading" {
                            Some(sym.to_string())
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn fetch_order_status(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let body = serde_json::json!({ "orderId": order_id });
        let json = self
            .signed_post("/api/spot/v1/trade/order-info", body)
            .await?;
        let order = &json["data"];
        let filled_qty = parse_json_decimal(&order["fillQuantity"]);
        // Bitget API uses "priceAvg" for average fill price, not "fillPrice"
        let avg_price = parse_json_decimal(if order["priceAvg"].as_str().is_some() {
            &order["priceAvg"]
        } else {
            &order["fillPrice"]
        });
        let fee = parse_json_decimal(&order["totalFee"]);
        let status = match order["status"].as_str().unwrap_or("") {
            "new" => "NEW",
            "partial_fill" => "PARTIALLY_FILLED",
            "full_fill" => "FILLED",
            "cancel" => "CANCELED",
            _ => "UNKNOWN",
        };
        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: String::new(),
            status: status.to_string(),
            filled_qty,
            avg_price,
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
        let url = format!("{}/api/v2/spot/public/symbols", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!("Health check failed: {}", resp.status())
        }
    }

    /// Kill switch: cancel all open orders using Bitget's cancel-all endpoint.
    /// POST /api/v2/spot/trade/cancel-all with symbol param.
    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        for symbol in symbols {
            let body = serde_json::json!({
                "symbol": Self::bitget_symbol(symbol),
            });
            let path = "/api/v2/spot/trade/cancel-all";
            let ts = chrono::Utc::now().timestamp_millis().to_string();
            let body_str = body.to_string();
            let sign = match sign_bitget(
                self.config.api_secret.expose(),
                &ts,
                "POST",
                path,
                &body_str,
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        "Bitget cancel_all_orders signing failed for {}: {}",
                        symbol,
                        e
                    );
                    results.push(Err(e));
                    continue;
                }
            };
            let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);
            match self
                .http
                .post(&url)
                .header("ACCESS-KEY", self.config.api_key.expose())
                .header("ACCESS-SIGN", &sign)
                .header("ACCESS-TIMESTAMP", &ts)
                .header("ACCESS-PASSPHRASE", self.encrypted_passphrase.as_str())
                .header("Content-Type", "application/json")
                .body(body_str)
                .send()
                .await
            {
                Ok(resp) => match self.handle_response(resp).await {
                    Ok(_) => results.push(Ok(OrderResponse {
                        order_id: format!("cancel-all-{}", Self::bitget_symbol(symbol)),
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
                        tracing::error!("Bitget cancel_all_orders failed for {}: {}", symbol, e);
                        results.push(Err(e));
                    }
                },
                Err(e) => {
                    tracing::error!("Bitget cancel_all_orders HTTP error for {}: {}", symbol, e);
                    results.push(Err(anyhow::anyhow!("Bitget cancel_all HTTP error: {}", e)));
                }
            }
        }
        results
    }

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        self.rate_limiter.throttle().await;
        let bitget_symbol = Self::bitget_symbol(symbol);
        let limit = depth.min(50);
        // Bitget V2 API (V1 was decommissioned).
        let url = format!(
            "{}/api/v2/spot/market/orderbook?symbol={}&limit={}",
            self.config.base_url.trim_end_matches('/'),
            bitget_symbol,
            limit
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        let data = &json["data"];

        let bids = data["bids"]
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

        let asks = data["asks"]
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
